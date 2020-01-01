use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::ffi::CString;
use std::fs::File;
use std::os::unix::io::{FromRawFd, RawFd};
use std::time::{Duration, Instant};

use nix::fcntl::{open, OFlag};
use nix::sys::signal::Signal;
use nix::sys::stat::Mode;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{
    close, dup2, execv, fork, initgroups, pipe, setgid, setsid, setuid, ForkResult, Gid, Pid, Uid,
};

use libc::pid_t;

use users::os::unix::UserExt;
use users::User;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use crate::pam::session::PamSession;
use crate::vt;
use pam_sys::{PamFlag, PamItemType};

/// SessionChild tracks the processes spawned by a session
pub struct SessionChild {
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
}

/// A device to initiate a logged in PAM session.
pub struct Session<'a> {
    opened: Instant,
    pam: PamSession<'a>,
    user: User,

    class: String,
    vt: usize,
    env: HashMap<String, String>,
    cmd: Vec<String>,
}

impl<'a> Session<'a> {

    /// Create a Session object with details required to start the specified
    /// session. Surceeds if the service accepts the credentials.
    ///
    /// This involves creating a PAM handle which will be used to run an
    /// authentication attempt. If successful, this same PAM handle will later
    /// be used to tart the session.
    pub fn new(
        service: &'a str,
        class: &str,
        username: &str,
        password: &str,
        cmd: Vec<String>,
        provided_env: HashMap<String, String>,
        vt: usize,
    ) -> Result<Session<'a>, Box<dyn Error>> {
        let mut pam_session = PamSession::start(service)?;
        pam_session.converse.set_credentials(username, password);
        pam_session.authenticate(PamFlag::NONE)?;
        pam_session.acct_mgmt(PamFlag::NONE)?;

        let pam_username = pam_session.get_user()?;

        let user = users::get_user_by_name(&pam_username)
            .ok_or("unable to get user info")?;

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

    /// Report how long has elapsed since this session was created.
    pub fn elapsed(&self) -> Duration {
        self.opened.elapsed()
    }

    ///
    /// Start the session described within the Session.
    ///
    /// The flow is as follows:
    ///
    ///  1. Fork a subprocess. The parent will close the PAM handle immediately
    ///     afterwards and wait to receive the final child PID over a pipe.
    ///
    ///  2. Make the child a session leader.
    ///
    ///  3. Switch VT.
    ///
    ///  4. Open the target TTY, which due to us being in a new, empty session
    ///     makes it our new controlling terminal. Duplicate the TTY fd onto
    ///     stdin, stdout and stderr to hook us up to it properly.
    ///
    ///  5. Pass target environment variables to PAM through pam_putenv. The
    ///     variables include user information like name, home folder and shell
    ///     choice, target VT, session class and anything requested by the
    ///     greeter. The TTY is also passed through pam_set_item - who liked
    ///     unified interfaces anyway?
    ///
    ///  6. Create the PAM session using our pre-authenticated PAM handle.
    ///
    ///  7. Change working directory to the home folder of our target user.
    ///
    ///  8. Read out all environment variables from PAM, and patch up some
    ///     necessary ones in case they did not end up set by PAM or the
    ///     greeter.
    ///
    ///  9. Drop privileges to target and fork. The parent will write the child
    ///     PID over a pipe to the main greetd process, wait for the child to
    ///     die and perform cleanup.
    ///
    /// 10. Exec the target process in the child.
    ///
    /// Notes:
    ///
    /// - The double-fork is necessary due to PAM. Empirical testing showed
    ///   that opening a PAM session in the main process makes PAM think that
    ///   the main process is going to be the session leader. Thus, PAM must be
    ///   handled in a forked child. However, calling exec from the process that
    ///   opened the session immediately terminates it. Thus, exec must be run
    ///   in yet another forked child.
    ///
    /// - Use of the TIOCSCTTY ioctl instead of just opening the TTY to set the
    ///   controlling terminal did not seem to work. It was also needlessly
    ///   complicated.
    ///
    /// - The TTY must be hooked up to stdin for child applications to start
    ///   correctly. Not sure why.
    ///
    /// - If the controlling terminal is not properly changed, then a DRM
    ///   session will start on the VT associated with the controlling
    ///   terminal, rather than the VT we activated.
    ///
    /// - pam_systemd.so reads a lot of PAM environment variables, affecting
    ///   the logind session. For this reason, it's best to just pass
    ///   everything through.
    ///
    /// - When handling TTY/VT, there are many devices to deal with:
    ///    - /dev/console, the kernel "console" device. This is a virtual
    ///      device representing the kernel log target, but is also the target
    ///      for VT ioctls. See `man ioctl_console`.
    ///    - /dev/tty, the controlling terminal of the current process. See
    ///      `man iotctl_tty`.
    ///    - /dev/tty0, the active terminal
    ///    - /dev/ttyN, a specific terminal.
    ///
    pub fn start(&mut self) -> Result<SessionChild, Box<dyn Error>> {
        // Pipe used to communicate the true PID of the final child.
        let (parentfd, childfd) = pipe()
            .map_err(|e| format!("could not create pipe: {}", e))?;

        // PAM requires for unfathmoable reasons that we run this in a
        // subprocess. Things seem to fail otherwise.
        let child = match fork()? {
            ForkResult::Parent { child, .. } => {
                close(childfd).expect("unable to close child pipe");
                child
            }
            ForkResult::Child => {
                close(parentfd).expect("unable to close parent pipe");

                // Make this process a session leader.
                setsid().expect("unable to set session leader");

                // Switch VT
                vt::activate(self.vt).expect("unable to activate vt");

                // Open the tty to make it our controlling terminal.
                let res = open(
                    format!("/dev/tty{}", self.vt).as_str(),
                    OFlag::O_RDWR,
                    Mode::empty(),
                )
                .expect("unable to open tty");

                // Hook up std(in|out|err).
                dup2(res, 0 as RawFd).unwrap();
                dup2(res, 1 as RawFd).unwrap();
                dup2(res, 2 as RawFd).unwrap();

                close(res).unwrap();

                // Tell logind about our VT and TTY choice.
                self.pam
                    .putenv(&format!("XDG_VTNR={}", self.vt))
                    .expect("unable to set vt");
                self.pam
                    .set_item(PamItemType::TTY, &format!("/dev/tty{}", self.vt))
                    .expect("unable to set tty");

                // PAM has to be provided a bunch of environment variables
                // before open_session. We pass any environment variables from
                // our greeter through here as well. This allows them to affect
                // PAM (more specifically, pam_systemd.so), as well as make it
                // easier to gather and set all environment variables later.
                for (key, value) in self.env.iter() {
                    self.pam
                        .putenv(&format!("{}={}", key, value))
                        .expect("unable to set environment");
                }


                let username = self.user.name().to_str().unwrap();
                let home = self.user.home_dir().to_str().unwrap();
                let shell = self.user.shell().to_str().unwrap();

                let uid = Uid::from_raw(self.user.uid());
                let gid = Gid::from_raw(self.user.primary_group_id());

                self.pam
                    .putenv(&format!("XDG_SESSION_CLASS={}", self.class))
                    .expect("unable to set session class");
                self.pam
                    .putenv("XDG_SEAT=seat0")
                    .expect("unable to set seat");
                self.pam
                    .putenv(&format!("USER={}", username))
                    .expect("unable to set environment");
                self.pam
                    .putenv(&format!("LOGNAME={}", username))
                    .expect("unable to set environment");
                self.pam
                    .putenv(&format!("HOME={}", home))
                    .expect("unable to set environment");
                self.pam
                    .putenv(&format!("SHELL={}", shell))
                    .expect("unable to set environment");

                // Not the credentials you think.
                self.pam
                    .setcred(PamFlag::ESTABLISH_CRED)
                    .expect("unable to establish PAM credentials");

                // Session time!
                self.pam
                    .open_session(PamFlag::NONE)
                    .expect("unable to open PAM session");

                // OpenSSH does this. No idea why.
                self.pam
                    .setcred(PamFlag::REINITIALIZE_CRED)
                    .expect("unable to establish PAM credentials");

                let pamenv = self
                    .pam
                    .getenvlist()
                    .expect("unable to get PAM environment")
                    .to_vec();

                // Prepare some strings in C format that we'll need.
                let cusername = CString::new(username).unwrap();
                let cpath = CString::new("/bin/sh").unwrap();
                let cargs = [
                    cpath.clone(),
                    CString::new("-c").unwrap(),
                    CString::new(format!("[ -f /etc/profile ] && source /etc/profile; [ -f $HOME/.profile ] && source $HOME/.profile; exec {}", self.cmd.join(" "))).unwrap()
                ];

                // Change working directory
                let pwd = match env::set_current_dir(home) {
                    Ok(_) => home.to_string(),
                    Err(_) => {
                        env::set_current_dir("/").expect("unable to set current dir");
                        "/".to_string()
                    }
                };

                // Transfer PAM environment to process, set some final things.
                env::set_var("PWD", &pwd);
                for (key, value) in pamenv {
                    env::set_var(key, value);
                }
                if env::var("TERM").is_err() {
                    env::set_var("TERM", "linux");
                }
                if env::var("XDG_RUNTIME_DIR").is_err() {
                    env::set_var("XDG_RUNTIME_DIR", format!("/run/user/{}", uid));
                }

                // Drop privileges to target user
                initgroups(&cusername, gid).expect("unable to init groups");
                setgid(gid).expect("unable to set GID");
                setuid(uid).expect("unable to set UID");

                // We need to fork again. PAM is weird and gets upset if you
                // exec from the process that opened the session, registering
                // it automatically as a log-out.
                let child = match fork()? {
                    ForkResult::Parent { child, .. } => child,
                    ForkResult::Child => {
                        // Run
                        close(childfd).expect("unable to close pipe");
                        execv(&cpath, &cargs).expect("unable to exec");
                        std::process::exit(0);
                    }
                };

                // Signal the inner PID to the parent process.
                let mut f = unsafe { File::from_raw_fd(childfd) };
                f.write_u64::<LittleEndian>(child.as_raw() as u64)
                    .expect("unable to write pid");
                drop(f);

                waitpid(child, None).expect("unable to wait for child");

                let _ = self.pam.close_session(PamFlag::NONE);
                let _ = self.pam.setcred(PamFlag::DELETE_CRED);
                let _ = self.pam.end();
                std::process::exit(0);
            }
        };

        // We have no use for the PAM handle in the host process anymore
        self.pam.setcred(PamFlag::DELETE_CRED).expect("unable to delete PAM credentials");
        self.pam.end().expect("unable to end PAM session");

        // Read the true child PID.
        let mut f = unsafe { File::from_raw_fd(parentfd) };
        let raw_pid = f.read_u64::<LittleEndian>()
            .map_err(|e| format!("sesssion process failed: {}", e))?;
        let sub_task = Pid::from_raw(raw_pid as pid_t);
        drop(f);

        Ok(SessionChild {
            task: child,
            sub_task,
        })
    }
}
