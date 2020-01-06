use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::ffi::CString;
use std::fs::File;
use std::io::Write;
use std::os::unix::io::{FromRawFd, RawFd};
use std::time::{Duration, Instant};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use libc::pid_t;
use nix::fcntl::{fcntl, FcntlArg};
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{
    close, execve, fork, initgroups, pipe, setgid, setsid, setuid, ForkResult, Gid, Pid, Uid,
};
use pam_sys::{PamFlag, PamItemType};
use users::os::unix::UserExt;
use users::User;

use crate::pam::session::PamSession;
use crate::signals::blocked_sigset;
use crate::terminal;
use greet_proto::VtSelection;

fn dup_fd_cloexec(fd: RawFd) -> Result<RawFd, Box<dyn Error>> {
    match fcntl(fd, FcntlArg::F_DUPFD_CLOEXEC(0)) {
        Ok(fd) => Ok(fd),
        Err(e) => Err(e.into()),
    }
}

/// SessionChild tracks the processes spawned by a session
pub struct SessionChild {
    opened: Instant,
    task: Pid,
    sub_task: Pid,
}

impl SessionChild {
    /// Check if this session has this pid.
    pub fn owns_pid(&self, pid: Pid) -> bool {
        self.task == pid || self.sub_task == pid
    }

    /// Send SIGTERM to the session child.
    pub fn term(&self) {
        let _ = nix::sys::signal::kill(self.sub_task, Signal::SIGTERM);
    }

    /// Send SIGKILL to the session child.
    pub fn kill(&self) {
        let _ = nix::sys::signal::kill(self.sub_task, Signal::SIGKILL);
        let _ = nix::sys::signal::kill(self.task, Signal::SIGKILL);
    }

    /// Terminate a session. Sends SIGTERM in a loop, then sends SIGKILL in a loop.
    pub fn shoo(&self) {
        let task = self.sub_task;
        let _ = nix::sys::signal::kill(task, Signal::SIGTERM);
        let mut dead = false;
        let mut sleep = 1;
        while !dead && sleep < 1000 {
            match waitpid(task, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::Exited(..)) | Ok(WaitStatus::Signaled(..)) => {
                    dead = true;
                }
                _ => {
                    sleep *= 10;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(sleep));
        }
        if !dead {
            sleep = 1;
            let _ = nix::sys::signal::kill(task, Signal::SIGKILL);
            while !dead && sleep < 1000 {
                match waitpid(task, Some(WaitPidFlag::WNOHANG)) {
                    Ok(WaitStatus::Exited(..)) | Ok(WaitStatus::Signaled(..)) => {
                        dead = true;
                    }
                    _ => {
                        sleep *= 10;
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(sleep));
            }
        }
    }

    /// Report how long has elapsed since this session child was created.
    pub fn elapsed(&self) -> Duration {
        self.opened.elapsed()
    }
}

/// A device to initiate a logged in PAM session.
pub struct Session<'a> {
    opened: Instant,
    pam: PamSession<'a>,
    user: User,

    class: String,
    vt: VtSelection,
    env: HashMap<String, String>,
    cmd: Vec<String>,
}

impl<'a> Session<'a> {
    ///
    /// Create a Session object with details required to start the specified
    /// session. Surceeds if the service accepts the credentials.
    ///
    /// This involves creating a PAM handle which will be used to run an
    /// authentication attempt. If successful, this same PAM handle will later
    /// be used to tart the session.
    ///
    pub fn new(
        service: &'a str,
        class: &str,
        username: &str,
        password: &str,
        cmd: Vec<String>,
        provided_env: HashMap<String, String>,
        vt: VtSelection,
    ) -> Result<Session<'a>, Box<dyn Error>> {
        let mut pam_session = PamSession::start(service)?;
        pam_session.converse.set_credentials(username, password);
        pam_session.authenticate(PamFlag::NONE)?;
        pam_session.acct_mgmt(PamFlag::NONE)?;

        let pam_username = pam_session.get_user()?;

        let user = users::get_user_by_name(&pam_username).ok_or("unable to get user info")?;

        // Return our description of this session.
        Ok(Session {
            opened: Instant::now(),
            pam: pam_session,
            class: class.to_string(),
            env: provided_env,
            user,
            vt,
            cmd,
        })
    }

    /// The entry point for the session worker process. The session worker is
    /// responsible for the entirety of the session setup and execution. It is
    /// started by Session::start.
    fn session_worker(&mut self, childfd: RawFd) -> Result<(), Box<dyn Error>> {

        // Clear the signal masking that was inherited from the parent.
        blocked_sigset()
            .thread_unblock()
            .map_err(|e| format!("unable to unblock signals: {}", e))?;

        // Make this process a session leader.
        setsid().map_err(|e| format!("unable to become session leader: {}", e))?;

        // Select VT.
        let console = terminal::Terminal::open(0)?;
        let vt = match self.vt {
            VtSelection::Specific(vt) => vt,
            VtSelection::Next => console.vt_get_next()?,
            VtSelection::Current => console.vt_get_current()?,
        };

        // Opening our target terminal. This will automatically make it our
        // controlling terminal. An attempt was made to use TIOCSCTTY to do
        // this explicitly, but it neither worked nor was worth the additional
        // code.
        let mut target_vt = terminal::Terminal::open(vt)?;

        eprintln!("session worker: selecting vt {}", target_vt.terminal());

        // Hook up std(in|out|err). This allows us to run console applications.
        // Also, hooking up stdin is required, as applications otherwise fail to
        // start, both for graphical and console-based applications. I do not
        // know why this is the case.
        target_vt.term_connect_pipes()?;

        // Clear TTY so that it will be empty when we switch to it.
        target_vt.term_clear()?;

        // Set the target VT mode to text for compatibility. Other login
        // managers set this to graphics, but that disallows start of textual
        // applications, which greetd aims to support.
        target_vt.set_kdmode(terminal::KdMode::Text)?;

        // Set VT mode to VT_AUTO.
        target_vt.vt_mode_clean()?;

        // Perform a switch to the target VT if required.
        console.vt_activate(vt)?;

        // We no longer need these, so close them to avoid inheritance.
        drop(console);
        drop(target_vt);

        // Prepare some values from the user struct we gathered earlier.
        let username = self.user.name().to_str().unwrap_or("");
        let home = self.user.home_dir().to_str().unwrap_or("");
        let shell = self.user.shell().to_str().unwrap_or("");
        let uid = Uid::from_raw(self.user.uid());
        let gid = Gid::from_raw(self.user.primary_group_id());

        // PAM has to be provided a bunch of environment variables before
        // open_session. We pass any environment variables from our greeter
        // through here as well. This allows them to affect PAM (more
        // specifically, pam_systemd.so), as well as make it easier to gather
        // and set all environment variables later.
        let prepared_env = [
            "XDG_SEAT=seat0".to_string(),
            format!("XDG_SESSION_CLASS={}", self.class),
            format!("XDG_VTNR={}", vt),
            format!("USER={}", username),
            format!("LOGNAME={}", username),
            format!("HOME={}", home),
            format!("SHELL={}", shell),
        ];

        let greeter_env: Vec<String> = self
            .env
            .iter()
            .map(|(key, value)| format!("{}={}", key, value))
            .collect();

        for e in prepared_env.iter().chain(greeter_env.iter()) {
            self.pam
                .putenv(e)
                .map_err(|e| format!("unable to set PAM environment: {}", e))?;
        }

        // Tell PAM what TTY we're targetting, which is used by logind.
        self.pam
            .set_item(PamItemType::TTY, &format!("/dev/tty{}", vt))
            .map_err(|e| format!("unable to set PAM TTY item: {}", e))?;

        // Not the credentials you think.
        self.pam
            .setcred(PamFlag::ESTABLISH_CRED)
            .map_err(|e| format!("unable to establish PAM credentials: {}", e))?;

        // Session time!
        self.pam
            .open_session(PamFlag::NONE)
            .map_err(|e| format!("unable to open PAM session: {}", e))?;

        // Prepare some strings in C format that we'll need.
        let cusername = CString::new(username)?;
        let command = format!("[ -f /etc/profile ] && source /etc/profile; [ -f $HOME/.profile ] && source $HOME/.profile; exec {}", self.cmd.join(" "));

        // Change working directory
        let pwd = match env::set_current_dir(home) {
            Ok(_) => home,
            Err(_) => {
                env::set_current_dir("/")
                    .map_err(|e| format!("unable to set working directory: {}", e))?;
                "/"
            }
        };

        // Check to see if a few necessary variables are there and patch things
        // up as needed.
        let mut fixup_env = vec![
            format!("PWD={}", pwd),
            format!("GREETD_SOCK={}", env::var("GREETD_SOCK").unwrap()),
        ];
        if !self.pam.hasenv("TERM") {
            fixup_env.push("TERM=linux".to_string());
        }
        if !self.pam.hasenv("XDG_RUNTIME_DIR") {
            fixup_env.push(format!("XDG_RUNTIME_DIR=/run/user/{}", uid));
        }
        for e in fixup_env.into_iter() {
            self.pam
                .putenv(&e)
                .map_err(|e| format!("unable to set PAM environment: {}", e))?;
        }

        // Extract PAM environment for use with execve below.
        let mut pamenvlist = self
            .pam
            .getenvlist()
            .map_err(|e| format!("unable to get PAM environment: {}", e))?;
        let envvec = pamenvlist.to_vec();

        // PAM is weird and gets upset if you exec from the process that opened
        // the session, registering it automatically as a log-out. Thus, we must
        // exec in a new child.
        let child = match fork().map_err(|e| format!("unable to fork: {}", e))? {
            ForkResult::Parent { child, .. } => child,
            ForkResult::Child => {
                // It is important that we do *not* return from here by
                // accidentally using '?'. The process *must* exit from within
                // this match arm.

                // Drop privileges to target user
                initgroups(&cusername, gid).expect("unable to init groups");
                setgid(gid).expect("unable to set GID");
                setuid(uid).expect("unable to set UID");

                // Run
                close(childfd).expect("unable to close pipe");
                let cpath = CString::new("/bin/sh").unwrap();
                execve(
                    &cpath,
                    &[
                        &cpath,
                        &CString::new("-c").unwrap(),
                        &CString::new(command).unwrap(),
                    ],
                    &envvec,
                )
                .expect("unable to exec");

                unreachable!("after exec");
            }
        };

        // Signal the inner PID to the parent process.
        let mut f = unsafe { File::from_raw_fd(childfd) };
        f.write_u64::<LittleEndian>(child.as_raw() as u64)?;
        drop(f);

        // Wait for process to terminate, handling EINTR as necessary.
        loop {
            match waitpid(child, None) {
                Err(nix::Error::Sys(nix::errno::Errno::EINTR)) => continue,
                Err(e) => eprintln!("session: waitpid on inner child failed: {}", e),
                Ok(_) => break,
            }
        }

        // Close the session. This step requires root privileges to run, as it
        // will result in various forms of login teardown (including unmounting
        // home folders, telling logind that the session ended, etc.). This is
        // why we cannot drop privileges in this process, but must do it in the
        // inner-most child.
        self.pam
            .close_session(PamFlag::NONE)
            .map_err(|e| format!("unable to close PAM session: {}", e))?;
        self.pam
            .setcred(PamFlag::DELETE_CRED)
            .map_err(|e| format!("unable to clear PAM credentials: {}", e))?;
        self.pam
            .end()
            .map_err(|e| format!("unable to clear PAM credentials: {}", e))?;

        Ok(())
    }

    ///
    /// Start the session described within the Session.
    ///
    pub fn start(&mut self) -> Result<SessionChild, Box<dyn Error>> {
        // Pipe used to communicate the true PID of the final child.
        let (parentfd, childfd) = pipe().map_err(|e| format!("could not create pipe: {}", e))?;

        // PAM requires for unfathmoable reasons that we run this in a
        // subprocess. Things seem to fail otherwise.
        let child = match fork()? {
            ForkResult::Parent { child, .. } => {
                close(childfd)?;
                child
            }
            ForkResult::Child => {
                // It is important that we do *not* return from here by
                // accidentally using '?'. The process *must* exit from within
                // this match arm.

                // Close our side of the pipe.
                close(parentfd).expect("unable to close parent pipe");

                // Keep our old stderr around for logging, but CLOEXEC so that
                // we are not poluting the new child.
                let mut stderr = unsafe { File::from_raw_fd(dup_fd_cloexec(2 as RawFd).unwrap()) };

                // Run the child entrypoint.
                if let Err(e) = self.session_worker(childfd) {
                    writeln!(stderr, "session worker: {}", e)
                        .expect("could not write log output");
                    std::process::exit(1);
                }
                std::process::exit(0);
            }
        };

        // We have no use for the PAM handle in the host process anymore
        self.pam.setcred(PamFlag::DELETE_CRED)?;
        self.pam.end()?;

        // Read the true child PID.
        let mut f = unsafe { File::from_raw_fd(parentfd) };
        let raw_pid = f
            .read_u64::<LittleEndian>()
            .map_err(|_| "worker process terminated".to_string())?;
        let sub_task = Pid::from_raw(raw_pid as pid_t);
        drop(f);

        Ok(SessionChild {
            opened: Instant::now(),
            task: child,
            sub_task,
        })
    }

    /// Report how long has elapsed since this session was created.
    pub fn elapsed(&self) -> Duration {
        self.opened.elapsed()
    }
}
