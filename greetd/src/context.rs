use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::ffi::CString;
use std::io;
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{alarm, execv, fork, initgroups, setgid, setuid, ForkResult, Gid, Uid};

use users::os::unix::UserExt;

use crate::scrambler::Scrambler;

/// Session is an active session.
struct Session<'a> {
    pam: pam::Authenticator<'a, pam::PasswordConv>,
    task: nix::unistd::Pid,
}

/// PendingSession represents a successful login that is pending session
/// startup. It contains all the data necessary to start the session when the
/// greeter has finally shut down.
struct PendingSession<'a> {
    opened: Instant,
    pam: pam::Authenticator<'a, pam::PasswordConv>,
    uid: Uid,
    gid: Gid,
    home: String,
    shell: String,
    username: String,
    class: String,
    env: HashMap<String, String>,
    cmd: Vec<String>,
}

/// Context keeps track of running sessions and start new ones.
pub struct Context<'a> {
    session: Option<Session<'a>>,
    greeter: Option<Session<'a>>,
    pending_session: Option<PendingSession<'a>>,

    greeter_bin: String,
    greeter_user: String,
    tty: usize,
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
            Ok(WaitStatus::StillAlive) => {
                sleep *= 10;
            }
            _ => panic!("waitpid on session returned unexpected status"),
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
                Ok(WaitStatus::StillAlive) => {
                    sleep *= 10;
                }
                _ => panic!("waitpid on session returned unexpected status"),
            }
            std::thread::sleep(std::time::Duration::from_millis(sleep));
        }
    }
}

impl<'a> Context<'a> {
    pub fn new(greeter_bin: String, greeter_user: String, tty: usize) -> Context<'a> {
        Context {
            session: None,
            greeter: None,
            pending_session: None,
            greeter_bin: greeter_bin,
            greeter_user: greeter_user,
            tty: tty,
        }
    }

    // Create a PendingSession object with details required to start the
    // specified session.
    fn create_session(
        &self,
        service: &str,
        class: &str,
        username: &str,
        password: &str,
        cmd: Vec<String>,
        provided_env: HashMap<String, String>,
    ) -> Result<PendingSession<'a>, Box<dyn Error>> {
        eprintln!("creating session");

        let mut auth =
            pam::Authenticator::with_password(service).expect("unable to create pam authenticator");
        auth.handler_mut()
            .set_credentials(username, password)
            .expect("unable to set credentials");
        if let Err(e) = auth.authenticate() {
            return Err(e.into());
        }

        // TODO: Fetch the username from the PAM session.
        let u = users::get_user_by_name(&username).expect("unable to get user struct");
        let uid = Uid::from_raw(u.uid());
        let gid = Gid::from_raw(u.primary_group_id());

        // Return our description of this session.
        Ok(PendingSession {
            opened: Instant::now(),
            pam: auth,
            env: provided_env,
            uid,
            gid,
            class: class.to_string(),
            home: u.home_dir().to_str().unwrap().to_string(),
            shell: u.shell().to_str().unwrap().to_string(),
            cmd: cmd,
            username: u.name().to_str().unwrap().to_string(),
        })
    }

    // Start the session described by the PendingSession object.
    fn run_session<'b>(
        &mut self,
        mut p: PendingSession<'b>,
    ) -> Result<Session<'b>, Box<dyn Error>> {
        eprintln!("running session");

        // Prepare some strings in C format that we'll need.
        let cusername =
            CString::new(p.username.to_string()).expect("unable to create username CString");
        let cpath = CString::new("/bin/sh").unwrap();
        let cargs = [
            cpath.clone(),
            CString::new("-c").unwrap(),
            CString::new(format!("[ -f /etc/profile ] && source /etc/profile; [ -f $HOME/.profile ] && source $HOME/.profile; exec {}", p.cmd.join(" "))).unwrap()
        ];

        let child = match fork()? {
            ForkResult::Parent { child, .. } => child,
            ForkResult::Child => {
                // Set environment variables before opening session. PAM needs these.
                p.pam.env("XDG_SESSION_CLASS", p.class)?;
                p.pam.env("XDG_VTNR", self.tty.to_string())?;
                p.pam.env("XDG_SEAT", "seat0")?;
                for (key, value) in p.env.iter() {
                    p.pam.env(key, value)?;
                }

                p.pam.open_session().expect("unable to open session");

                // Prepare the environment we want to launch.
                let myenv: Vec<(String, String)> = if let Some(pamenv) = p.pam.environment() {
                    pamenv
                        .iter()
                        .map(|x| {
                            let x = x.to_string_lossy().into_owned();
                            let mut parts = x.splitn(2, '=');
                            match (parts.next(), parts.next()) {
                                (Some(key), Some(value)) => {
                                    Some((key.to_string(), value.to_string()))
                                }
                                _ => None,
                            }
                        })
                        .filter(|x| x.is_some())
                        .map(|x| x.unwrap())
                        .collect()
                } else {
                    // TODO: Handle this better. Can it happen at all?
                    p.env
                        .iter()
                        .map(|(x, y)| (x.to_string(), y.to_string()))
                        .collect()
                };

                // Drop privileges to target user
                initgroups(&cusername, p.gid).expect("unable to init groups");
                setgid(p.gid).expect("unable to set GID");
                setuid(p.uid).expect("unable to set UID");

                // Change working directory
                let pwd = match env::set_current_dir(&p.home) {
                    Ok(_) => p.home.to_string(),
                    Err(_) => {
                        env::set_current_dir("/").expect("unable to set current dir");
                        "/".to_string()
                    }
                };;

                // Set environment
                for (key, value) in myenv {
                    env::set_var(key, value);
                }
                env::set_var("LOGNAME", &p.username);
                env::set_var("HOME", &p.home);
                env::set_var("PWD", &pwd);
                env::set_var("SHELL", &p.shell);
                if env::var("TERM").is_err() {
                    env::set_var("TERM", "linux");
                }
                if env::var("XDG_RUNTIME_DIR").is_err() {
                    env::set_var("XDG_RUNTIME_DIR", format!("/run/user/{}", p.uid));
                }

                // Run
                execv(&cpath, &cargs).expect("unable to exec");
                unreachable!("after exec");
            }
        };

        Ok(Session {
            task: child,
            pam: p.pam,
        })
    }

    /// Start a greeter session.
    pub fn greet(&mut self) -> Result<(), Box<dyn Error>> {
        if self.greeter.is_some() {
            eprintln!("greeter session already active");
            return Err(io::Error::new(io::ErrorKind::Other, "greeter already active").into());
        }

        eprintln!("greet");

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

        eprintln!("greeted");

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

        eprintln!("login");

        let pending_session =
            self.create_session("login", "user", &username, &password, cmd, provided_env)?;
        password.scramble();
        alarm::set(10);
        self.pending_session = Some(pending_session);
        eprintln!("logged in");

        Ok(())
    }

    /// Notify the Context of an alarm.
    pub fn alarm(&mut self) {
        if let Some(Session { pam, task }) = self.greeter.take() {
            if let Some(p) = self.pending_session.take() {
                if p.opened.elapsed() > Duration::from_secs(5) {
                    shoo(task);
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
                    self.greeter = Some(Session { pam, task });
                }
            } else {
                self.greeter = Some(Session { pam, task });
            }
        }
    }

    /// Notify the Context that it needs to check its children for termination.
    /// This should be called on SIGCHLD.
    pub fn check_children(&mut self) {
        match self.session.take() {
            Some(session) => {
                match waitpid(session.task, Some(WaitPidFlag::WNOHANG)) {
                    Ok(WaitStatus::Exited(..))
                    | Ok(WaitStatus::Signaled(..))
                    | Err(nix::Error::Sys(Errno::ECHILD)) => {
                        // Session task is dead, so kill the session and
                        // restart the greeter.
                        eprintln!("session exited");
                        drop(session.pam);
                        self.greet().expect("unable to start greeter");
                    }
                    Ok(WaitStatus::StillAlive) => self.session = Some(session),
                    v => panic!("waitpid on session returned unexpected status: {:?}", v),
                }
            }
            None => (),
        };
        match self.greeter.take() {
            Some(greeter) => {
                match waitpid(greeter.task, Some(WaitPidFlag::WNOHANG)) {
                    Ok(WaitStatus::Exited(..))
                    | Ok(WaitStatus::Signaled(..))
                    | Err(nix::Error::Sys(Errno::ECHILD)) => {
                        eprintln!("greeter exited");
                        drop(greeter.pam);

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
                    Ok(WaitStatus::StillAlive) => self.greeter = Some(greeter),
                    v => panic!("waitpid on greeter returned unexpected status: {:?}", v),
                }
            }
            None => (),
        };
    }

    /// Notify the Context that we want to terminate. This should be called on
    /// SIGTERM.
    pub fn terminate(&mut self) {
        if let Some(session) = self.session.take() {
            shoo(session.task);
            drop(session.pam);
        }
        if let Some(greeter) = self.greeter.take() {
            shoo(greeter.task);
            drop(greeter.pam);
        }

        eprintln!("terminating");
        std::process::exit(0);
    }
}
