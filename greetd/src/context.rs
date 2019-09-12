use std::env;
use std::error::Error;
use std::ffi::CString;
use std::io;
use std::collections::HashMap;
use std::time::{Instant, Duration};

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
    waited_since: Instant,
    pam: pam::Authenticator<'a, pam::PasswordConv>,
    uid: Uid,
    gid: Gid,
    home: String,
    shell: String,
    username: String,
    env: Vec<(String, String)>,
    cmd: Vec<String>,
}

// Greeter is an active greeter.
struct Greeter {
    task: nix::unistd::Pid,
}

pub struct Context<'a> {
    session: Option<Session<'a>>,
    greeter: Option<Greeter>,
    pending_session: Option<PendingSession<'a>>,

    greeter_bin: String,
    greeter_user: String,
    tty: usize,
}

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

    pub fn greet(&mut self) -> Result<(), Box<dyn Error>> {
        let u = users::get_user_by_name(&self.greeter_user).expect("unable to get user struct");

        let uid = Uid::from_raw(u.uid());
        let gid = Gid::from_raw(u.primary_group_id());

        let cusername = CString::new(u.name().to_str().expect("unable to get username"))
            .expect("unable to create username CString");
        let cpath = CString::new("/bin/sh").unwrap();
        let cargs = [
            CString::new("/bin/sh").unwrap(),
            CString::new("-c").unwrap(),
            CString::new(format!("[ -f /etc/profile ] && source /etc/profile; [ -f $HOME/.profile ] && source $HOME/.profile; exec {}", self.greeter_bin)).unwrap()
        ];

        let child = match fork()? {
            ForkResult::Parent { child, .. } => child,
            ForkResult::Child => {
                // Drop privileges to target user
                initgroups(&cusername, gid).expect("unable to init groups");
                setgid(gid).expect("unable to set GID");
                setuid(uid).expect("unable to set UID");

                // Change working directory
                let pwd = match env::set_current_dir(&u.home_dir()) {
                    Ok(_) => u.home_dir().to_str().unwrap().to_string(),
                    Err(_) => {
                        env::set_current_dir("/").expect("unable to set current dir");
                        "/".to_string()
                    }
                };;

                // Set environment

                env::set_var("XDG_SESSION_TYPE", "wayland");
                env::set_var("XDG_SESSION_CLASS", "user");
                env::set_var("XDG_VTNR", self.tty.to_string());
                env::set_var("XDG_SEAT", "seat0");
                env::set_var("LOGNAME", &u.name());
                env::set_var("HOME", &u.home_dir());
                env::set_var("PWD", &pwd);
                env::set_var("SHELL", &u.shell());
                if env::var("TERM").is_err() {
                    env::set_var("TERM", "linux");
                }
                if env::var("XDG_RUNTIME_DIR").is_err() {
                    env::set_var("XDG_RUNTIME_DIR", format!("/run/user/{}", uid));
                }

                // Run
                execv(&cpath, &cargs).expect("unable to exec");
                unreachable!("after exec");
            }
        };

        self.greeter = Some(Greeter { task: child });

        Ok(())
    }

    pub fn login(
        &mut self,
        username: String,
        mut password: String,
        cmd: Vec<String>,
        provided_env: HashMap<String, String>,
    ) -> Result<(), Box<dyn Error>> {
        if self.session.is_some() {
            return Err(io::Error::new(io::ErrorKind::Other, "session already active").into());
        }

        let mut auth =
            pam::Authenticator::with_password("login").expect("unable to create pam authenticator");
        auth.handler_mut()
            .set_credentials(username.as_str(), password.as_str())
            .expect("unable to set credentials");
        if !auth.authenticate().is_ok() {
            return Err(io::Error::new(io::ErrorKind::Other, "authentication failed").into());
        }

        // TODO: Fetch the username from the PAM session.
        let u = users::get_user_by_name(&username).expect("unable to get user struct");

        let uid = Uid::from_raw(u.uid());
        let gid = Gid::from_raw(u.primary_group_id());

        auth.env("XDG_SESSION_CLASS", "user")?;
        auth.env("XDG_VTNR", self.tty.to_string())?;
        auth.env("XDG_SEAT", "seat0")?;
        for (key, value) in provided_env.iter() {
            auth.env(key, value)?;
        }

        auth.open_session().expect("unable to open session");
        password.scramble();

        let myenv: Vec<(String, String)> = if let Some(pamenv) = auth.environment() {
            pamenv
                .iter()
                .map(|x| {
                    let x = x.to_string_lossy().into_owned();
                    let mut parts = x.splitn(2, '=');
                    match (parts.next(), parts.next()) {
                        (Some(key), Some(value)) => Some((key.to_string(), value.to_string())),
                        _ => None,
                    }
                })
                .filter(|x| x.is_some())
                .map(|x| x.unwrap())
                .collect()
        } else {
            // TODO: Handle this better. Can it happen at all?
            env::vars().chain(provided_env.iter().map(|(x, y)| (x.to_string(), y.to_string()))).collect()
        };

        self.pending_session = Some(PendingSession{
            waited_since: Instant::now(),
            pam: auth,
            env: myenv,
            uid,
            gid,
            home: u.home_dir().to_str().unwrap().to_string(),
            shell: u.shell().to_str().unwrap().to_string(),
            cmd: cmd,
            username: u.name().to_str().unwrap().to_string(),
        });

        alarm::set(10);

        Ok(())
    }

    fn start_session(&mut self, p: PendingSession<'a>) -> Result<(), Box<dyn Error>> {
        let cusername = CString::new(p.username.to_string())
            .expect("unable to create username CString");

        let cpath = CString::new("/bin/sh").unwrap();
        let cargs = [
            cpath.clone(),
            CString::new("-c").unwrap(),
            CString::new(format!("[ -f /etc/profile ] && source /etc/profile; [ -f $HOME/.profile ] && source $HOME/.profile; exec {}", p.cmd.join(" "))).unwrap()
        ];

        let child = match fork()? {
            ForkResult::Parent { child, .. } => child,
            ForkResult::Child => {
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
                for (key, value) in p.env {
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

        self.session = Some(Session {
            task: child,
            pam: p.pam,
        });

        Ok(())
    }

    pub fn alarm(&mut self) {
        if let Some(Greeter{ task }) = self.greeter.take() {

            if let Some(p) = self.pending_session.take() {
                if p.waited_since.elapsed() > Duration::from_secs(5) {
                    shoo(task);
                    if let Err(e) = self.start_session(p) {
                        eprintln!("session start failed: {:?}", e);
                    }
                } else {
                    self.pending_session = Some(p);
                    self.greeter = Some(Greeter{ task });
                }
            } else {
                self.greeter = Some(Greeter{ task });
            }
        }
    }

    pub fn check_children(&mut self) {
        match self.session.take() {
            Some(session) => {
                match waitpid(session.task, Some(WaitPidFlag::WNOHANG)) {
                    Ok(WaitStatus::Exited(..)) | Ok(WaitStatus::Signaled(..)) | Err(nix::Error::Sys(Errno::ECHILD))  => {
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
                    Ok(WaitStatus::Exited(..)) | Ok(WaitStatus::Signaled(..)) | Err(nix::Error::Sys(Errno::ECHILD)) => {
                        match self.pending_session.take() {
                            Some(pending_session) => {
                                // Our greeter finally bit the dust so we can
                                // start our pending session.
                                if let Err(e) = self.start_session(pending_session) {
                                    eprintln!("session start failed: {:?}", e);
                                }
                            }
                            None => if self.session.is_none() {
                                // Greeter died on us, let's just die with it.
                                eprintln!("greeter exited");
                                std::process::exit(1);
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

    pub fn terminate(&mut self) {
        if let Some(session) = &self.session {
            shoo(session.task);
        }
        if let Some(greeter) = &self.greeter {
            shoo(greeter.task);
        }

        eprintln!("terminating");
        std::process::exit(0);
    }
}
