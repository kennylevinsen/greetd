use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::ffi::CString;
use std::io;
use std::fs::File;
use std::time::{Duration, Instant};
use std::os::unix::io::{FromRawFd, RawFd};

use nix::ioctl_write_int_bad;
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

ioctl_write_int_bad!(vt_activate, 0x5606);
ioctl_write_int_bad!(vt_waitactive, 0x5607);

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

// Terminate a session
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
    // specified session.
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
            uid,
            gid,
            home,
            shell,
            username,
            class: class.to_string(),
            vt: Some(self.vt),
            connect_tty: true,
            env: provided_env,
            cmd: cmd,
        })
    }

    // Start the session described by the PendingSession object.
    fn run_session<'b>(
        &mut self,
        mut p: PendingSession<'b>,
    ) -> Result<Session, Box<dyn Error>> {

        let (parentfd, childfd) = pipe()?;

        let child = match fork()? {
            ForkResult::Parent { child, .. } => {
                close(childfd).expect("unable to close child pipe");
                child
            }
            ForkResult::Child => {
                close(parentfd).expect("unable to close parent pipe");
                p.pam.setcred(PamFlag::ESTABLISH_CRED).expect("unable to establish PAM credentials");
                p.pam.putenv(&format!("XDG_SESSION_CLASS={}", p.class)).expect("unable to set session class");
                p.pam.putenv("XDG_SEAT=seat0").expect("unable to set seat");
                for (key, value) in p.env.iter() {
                    p.pam.putenv(&format!("{}={}", key, value)).expect("unable to set environment");
                }
                if let Some(vt) = p.vt {
                    p.pam.putenv(&format!("XDG_VTNR={}", vt)).expect("unable to set vt");
                }
                p.pam.open_session(PamFlag::NONE).expect("unable to open PAM session");

                p.pam.putenv(&format!("USER={}", &p.username)).expect("unable to set environment");
                p.pam.putenv(&format!("LOGNAME={}", &p.username)).expect("unable to set environment");
                p.pam.putenv(&format!("HOME={}", &p.home)).expect("unable to set environment");
                p.pam.putenv(&format!("SHELL={}", &p.shell)).expect("unable to set environment");

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

                if let Some(vt) = p.vt {
                    let res = open("/dev/console", OFlag::O_RDWR, Mode::empty()).expect("unable to open console");
                    unsafe {
                        vt_activate(res, vt as i32).expect("unable to activate");
                        vt_waitactive(res, vt as i32).expect("unable to wait for activation");
                    }
                    close(res).unwrap();
                }

                let console_path = match (p.vt, p.connect_tty) {
                    (Some(_), true) => "/dev/tty",
                    _ => "/dev/null",
                };

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

                // Set environment
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

                let child = match fork()? {
                    ForkResult::Parent { child, .. } => child,
                    ForkResult::Child => {
                        // Run
                        close(childfd).expect("unable to close pipe");
                        execv(&cpath, &cargs).expect("unable to exec");
                        std::process::exit(0);
                    }
                };
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

        let _ = p.pam.setcred(PamFlag::DELETE_CRED);
        let _ = p.pam.end();

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
        if self.session.is_some() {
            eprintln!("login session already active");
            return Err(io::Error::new(io::ErrorKind::Other, "session already active").into());
        }

        let pending_session =
            self.create_session("login", "user", &username, &password, cmd, provided_env)?;
        password.scramble();
        alarm::set(10);
        self.pending_session = Some(pending_session);

        Ok(())
    }

    /// Notify the Context of an alarm.
    pub fn alarm(&mut self) {
        if let Some(greeter) = self.greeter.take() {
            if let Some(p) = self.pending_session.take() {
                if p.opened.elapsed() > Duration::from_secs(5) {
                    shoo(greeter.sub_task);
                    let s = match self.run_session(p) {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("session start failed: {:?}", e);
                            return;
                        }
                    };

                    self.session = Some(s);
                } else {
                    self.pending_session = Some(p);
                    self.greeter = Some(greeter);
                }
            } else {
                self.greeter = Some(greeter);
            }
        }
    }

    /// Notify the Context that it needs to check its children for termination.
    /// This should be called on SIGCHLD.
    pub fn check_children(&mut self) {
        loop {
            match waitpid(None, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::StillAlive) => break,
                Ok(WaitStatus::Exited(pid, ..)) | Ok(WaitStatus::Signaled(pid, ..)) => {
                    match &self.session {
                        Some(session) if session.task == pid || session.sub_task == pid => {
                            // Session task is dead, so kill the session and
                            // restart the greeter.
                            self.session = None;
                            eprintln!("session exited");
                            self.greet().expect("unable to start greeter");
                        }
                        _ => (),
                    };
                    match &self.greeter {
                        Some(greeter) if greeter.task == pid || greeter.sub_task == pid => {
                            self.greeter = None;
                            match self.pending_session.take() {
                                Some(pending_session) => {
                                    eprintln!("starting pending session");
                                    // Our greeter finally bit the dust so we can
                                    // start our pending session.
                                    let s = match self.run_session(pending_session) {
                                        Ok(s) => s,
                                        Err(e) => {
                                            eprintln!("session start failed: {:?}", e);
                                            return;
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
                Ok(_) => continue,
                Err(e) => eprintln!("waitpid returned an error: {}", e),
            }
        }
    }

    /// Notify the Context that we want to terminate. This should be called on
    /// SIGTERM.
    pub fn terminate(&mut self) {
        if let Some(session) = self.session.take() {
            shoo(session.sub_task);
        }
        if let Some(greeter) = self.greeter.take() {
            shoo(greeter.sub_task);
        }

        eprintln!("terminating");
        std::process::exit(0);
    }
}
