use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::ffi::CString;
use std::io;
use std::fs::File;
use std::time::{Duration, Instant};
use std::os::unix::io::{FromRawFd, RawFd};

use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{alarm, close, dup2, execv, fork, initgroups, setgid, setuid, ForkResult, Pid, Gid, Uid, pipe};
use nix::fcntl::{OFlag, open};
use nix::sys::stat::Mode;

use libc::pid_t;

use users::os::unix::UserExt;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use pam_sys::PamFlag;
use crate::pam::session::PamSession;
use crate::scrambler::Scrambler;
use crate::vt;

/// Session is an active session.
struct Session {
    task: Pid,
    sub_task: Pid,
}

/// PendingSession represents a successful login that is pending session
/// startup. It contains all the data necessary to start the session when the
/// greeter has finally shut down.
struct PendingSession<'a> {
    opened: Instant,
    pam: PamSession<'a>,
    uid: Uid,
    gid: Gid,
    home: String,
    shell: String,
    username: String,
    class: String,
    vt: Option<usize>,
    connect_tty: bool,
    env: HashMap<String, String>,
    cmd: Vec<String>,
}

/// Context keeps track of running sessions and start new ones.
pub struct Context<'a> {
    session: Option<Session>,
    greeter: Option<Session>,
    pending_session: Option<PendingSession<'a>>,

    greeter_bin: String,
    greeter_user: String,
    vt: usize,
}

// Terminate a session. Sends SIGTERM in a loop, then sends SIGKILL in a loop.
fn shoo(task: nix::unistd::Pid) {
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

impl<'a> Context<'a> {
    pub fn new(greeter_bin: String, greeter_user: String, vt: usize) -> Context<'a> {
        Context {
            session: None,
            greeter: None,
            pending_session: None,
            greeter_bin: greeter_bin,
            greeter_user: greeter_user,
            vt: vt,
        }
    }

    // Create a PendingSession object with details required to start the
    // specified session. Surceeds if the service accepts the credentials.
    fn create_session(
        &self,
        service: &'a str,
        class: &str,
        username: &str,
        password: &str,
        cmd: Vec<String>,
        provided_env: HashMap<String, String>,
    ) -> Result<PendingSession<'a>, Box<dyn Error>> {

        let mut pam_session = PamSession::start(service)?;
        pam_session.converse.set_credentials(username, password);
        pam_session.authenticate(PamFlag::NONE)?;
        pam_session.acct_mgmt(PamFlag::NONE)?;

        // TODO: Fetch the username from the PAM session.
        let u = users::get_user_by_name(&username).expect("unable to get user struct");
        let uid = Uid::from_raw(u.uid());
        let gid = Gid::from_raw(u.primary_group_id());

        let home =u.home_dir().to_str().unwrap().to_string();
        let shell = u.shell().to_str().unwrap().to_string();
        let username = u.name().to_str().unwrap().to_string();

        // Return our description of this session.
        Ok(PendingSession {
            opened: Instant::now(),
            pam: pam_session,
            class: class.to_string(),
            vt: Some(self.vt),
            connect_tty: true,
            env: provided_env,
            uid,
            gid,
            home,
            shell,
            username,
            cmd,
        })
    }

    // Start the session described by the PendingSession object.
    fn run_session<'b>(
        &mut self,
        mut p: PendingSession<'b>,
    ) -> Result<Session, Box<dyn Error>> {

        // Pipe used to communicate the true PID of the final child.
        let (parentfd, childfd) = pipe()?;

        // PAM requires for unfathmoable reasons that we run this in a
        // subprocess. Things seem to fail otherwise.
        let child = match fork()? {
            ForkResult::Parent { child, .. } => {
                close(childfd).expect("unable to close child pipe");
                child
            }
            ForkResult::Child => {
                close(parentfd).expect("unable to close parent pipe");

                // Not the credentials you think.
                p.pam.setcred(PamFlag::ESTABLISH_CRED).expect("unable to establish PAM credentials");

                // PAM has to be provided a bunch of environment variables
                // before open_session.
                p.pam.putenv(&format!("XDG_SESSION_CLASS={}", p.class)).expect("unable to set session class");
                p.pam.putenv("XDG_SEAT=seat0").expect("unable to set seat");
                for (key, value) in p.env.iter() {
                    p.pam.putenv(&format!("{}={}", key, value)).expect("unable to set environment");
                }
                if let Some(vt) = p.vt {
                    p.pam.putenv(&format!("XDG_VTNR={}", vt)).expect("unable to set vt");
                }

                // Session time!
                p.pam.open_session(PamFlag::NONE).expect("unable to open PAM session");

                p.pam.putenv(&format!("USER={}", &p.username)).expect("unable to set environment");
                p.pam.putenv(&format!("LOGNAME={}", &p.username)).expect("unable to set environment");
                p.pam.putenv(&format!("HOME={}", &p.home)).expect("unable to set environment");
                p.pam.putenv(&format!("SHELL={}", &p.shell)).expect("unable to set environment");

                // OpenSSH does this. No idea why.
                p.pam.setcred(PamFlag::REINITIALIZE_CRED).expect("unable to establish PAM credentials");

                let pamenv = p.pam.getenvlist().expect("unable to get PAM environment").to_vec();

                // Prepare some strings in C format that we'll need.
                let cusername =
                    CString::new(p.username.to_string()).unwrap();
                let cpath = CString::new("/bin/sh").unwrap();
                let cargs = [
                    cpath.clone(),
                    CString::new("-c").unwrap(),
                    CString::new(format!("[ -f /etc/profile ] && source /etc/profile; [ -f $HOME/.profile ] && source $HOME/.profile; exec {}", p.cmd.join(" "))).unwrap()
                ];

                // Switch VT.
                if let Some(vt) = p.vt {
                    vt::activate(vt).expect("unable to activate vt");
                }

                let console_path = match (p.vt, p.connect_tty) {
                    (Some(_), true) => "/dev/tty",
                    _ => "/dev/null",
                };

                // Hook up std(in|out|err).
                let res = open(console_path, OFlag::O_RDWR, Mode::empty()).expect("unable to open tty");
                dup2(res, 0 as RawFd).unwrap();
                dup2(res, 1 as RawFd).unwrap();
                dup2(res, 2 as RawFd).unwrap();
                close(res).unwrap();

                // Change working directory
                let pwd = match env::set_current_dir(&p.home) {
                    Ok(_) => p.home.to_string(),
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
                    env::set_var("XDG_RUNTIME_DIR", format!("/run/user/{}", p.uid));
                }

                // Drop privileges to target user
                initgroups(&cusername, p.gid).expect("unable to init groups");
                setgid(p.gid).expect("unable to set GID");
                setuid(p.uid).expect("unable to set UID");

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
                f.write_u64::<LittleEndian>(child.as_raw() as u64).expect("unable to write pid");
                drop(f);

                waitpid(child, None).expect("unable to wait for child");

                let _ = p.pam.close_session(PamFlag::NONE);
                let _ = p.pam.setcred(PamFlag::DELETE_CRED);
                let _ = p.pam.end();
                std::process::exit(0);
            }
        };

        // We have no use for the PAM handle in the host process anymore
        let _ = p.pam.setcred(PamFlag::DELETE_CRED);
        let _ = p.pam.end();

        // Read the true child PID.
        let mut f = unsafe { File::from_raw_fd(parentfd) };
        let sub_task = Pid::from_raw(f.read_u64::<LittleEndian>()? as pid_t);
        drop(f);

        Ok(Session {
            task: child,
            sub_task,
        })
    }

    /// Start a greeter session.
    pub fn greet(&mut self) -> Result<(), Box<dyn Error>> {
        if self.greeter.is_some() {
            eprintln!("greeter session already active");
            return Err(io::Error::new(io::ErrorKind::Other, "greeter already active").into());
        }

        let mut env = HashMap::new();
        env.insert("XDG_SESSION_TYPE".to_string(), "wayland".to_string());

        let pending_session = self.create_session(
            "greeter",
            "user",
            &self.greeter_user,
            "",
            vec![self.greeter_bin.to_string()],
            env,
        )?;
        let greeter = self.run_session(pending_session)?;
        self.greeter = Some(greeter);

        Ok(())
    }

    /// Start a login session.
    pub fn login(
        &mut self,
        username: String,
        mut password: String,
        cmd: Vec<String>,
        provided_env: HashMap<String, String>,
    ) -> Result<(), Box<dyn Error>> {
        if !self.greeter.is_some() {
            eprintln!("login request not valid when greeter is not active");
            return Err(io::Error::new(io::ErrorKind::Other, "greeter not active").into());
        }
        if self.session.is_some() {
            eprintln!("login session already active");
            return Err(io::Error::new(io::ErrorKind::Other, "session already active").into());
        }

        let pending_session =
            self.create_session("login", "user", &username, &password, cmd, provided_env)?;
        password.scramble();
        self.pending_session = Some(pending_session);

        // We give the greeter 5 seconds to prove itself well-behaved before
        // we lose patience and shoot it in the back repeatedly.
        alarm::set(5);

        Ok(())
    }

    /// Notify the Context of an alarm.
    pub fn alarm(&mut self) -> Result<(), Box<dyn Error>> {
        // Keep trying to terminate the greeter until it gives up.
        if let Some(p) = self.pending_session.take() {
            if let Some(g) = self.greeter.take() {
                if p.opened.elapsed() > Duration::from_secs(10) {
                    // We're out of patience.
                    let _ = nix::sys::signal::kill(g.sub_task, Signal::SIGKILL);
                    let _ = nix::sys::signal::kill(g.task, Signal::SIGKILL);
                } else {
                    // Let's try to give it a gentle nudge.
                    let _ = nix::sys::signal::kill(g.sub_task, Signal::SIGTERM);
                }
                self.greeter = Some(g);
                self.pending_session = Some(p);
                alarm::set(1);
                return Ok(())
            }

            vt::set_mode(vt::Mode::Text)?;
            let s = match self.run_session(p) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("session start failed: {:?}", e);
                    return Err(e.into());
                }
            };

            self.session = Some(s);
        }

        Ok(())
    }

    /// Notify the Context that it needs to check its children for termination.
    /// This should be called on SIGCHLD.
    pub fn check_children(&mut self) -> Result<(), Box<dyn Error>> {
        loop {
            match waitpid(None, Some(WaitPidFlag::WNOHANG)) {
                // No pending exits.
                Ok(WaitStatus::StillAlive) => break Ok(()),

                // We got an exit, see if it's something we need to clean up.
                Ok(WaitStatus::Exited(pid, ..)) | Ok(WaitStatus::Signaled(pid, ..)) => {
                    match &self.session {
                        Some(session) if session.task == pid || session.sub_task == pid => {
                            // Session task is dead, so kill the session and
                            // restart the greeter.
                            vt::set_mode(vt::Mode::Text)?;
                            self.session = None;
                            eprintln!("session exited");
                            self.greet().expect("unable to start greeter");
                        }
                        _ => (),
                    };
                    match &self.greeter {
                        Some(greeter) if greeter.task == pid || greeter.sub_task == pid => {
                            self.greeter = None;
                            vt::set_mode(vt::Mode::Text)?;
                            match self.pending_session.take() {
                                Some(pending_session) => {
                                    eprintln!("starting pending session");
                                    // Our greeter finally bit the dust so we can
                                    // start our pending session.
                                    let s = match self.run_session(pending_session) {
                                        Ok(s) => s,
                                        Err(e) => {
                                            eprintln!("session start failed: {:?}", e);
                                            return Err(e.into());
                                        }
                                    };

                                    self.session = Some(s);
                                }
                                None => {
                                    if self.session.is_none() {
                                        // Greeter died on us, let's just die with it.
                                        std::process::exit(1);
                                    }
                                }
                            }
                        }
                        _ => (),
                    };
                },

                // Useless status.
                Ok(_) => continue,

                // Uh, what?
                Err(e) => eprintln!("waitpid returned an error: {}", e),
            }
        }
    }

    /// Notify the Context that we want to terminate. This should be called on
    /// SIGTERM.
    pub fn terminate(&mut self) -> Result<(), Box<dyn Error>>  {
        if let Some(session) = self.session.take() {
            shoo(session.sub_task);
        }
        if let Some(greeter) = self.greeter.take() {
            shoo(greeter.sub_task);
        }
        vt::set_mode(vt::Mode::Text)?;

        eprintln!("terminating");
        std::process::exit(0);
    }
}
