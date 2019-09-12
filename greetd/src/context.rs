use std::env;
use std::error::Error;
use std::ffi::CString;
use std::io;

use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{execv, fork, initgroups, setgid, setuid, ForkResult, Gid, Uid};

use users::os::unix::UserExt;

use crate::scrambler::Scrambler;

struct Session<'a> {
    pam: pam::Authenticator<'a, pam::PasswordConv>,
    task: nix::unistd::Pid,
}

struct Greeter {
    task: nix::unistd::Pid,
}

pub struct Context<'a> {
    session: Option<Session<'a>>,
    greeter: Option<Greeter>,

    greeter_bin: String,
    greeter_user: String,
    tty: usize,
}

fn shoo(task: nix::unistd::Pid) {
    eprintln!("sending SIGTERM");
    let _ = nix::sys::signal::kill(task, Signal::SIGTERM);
    eprintln!("waitpid with exponential backoff to 1 second");
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
        eprintln!("sending SIGKILL");
        sleep = 1;
        let _ = nix::sys::signal::kill(task, Signal::SIGKILL);
        eprintln!("waitpid with exponential backoff to 1 second");
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
    eprintln!("done waiting");
}

impl<'a> Context<'a> {
    pub fn new(greeter_bin: String, greeter_user: String, tty: usize) -> Context<'a> {
        Context {
            session: None,
            greeter: None,
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
        cmd: String,
    ) -> Result<(), Box<dyn Error>> {
        eprintln!("initiating login");
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

        eprintln!("login successful");

        let u = users::get_user_by_name(&username).expect("unable to get user struct");

        let uid = Uid::from_raw(u.uid());
        let gid = Gid::from_raw(u.primary_group_id());

        let cusername = CString::new(u.name().to_str().expect("unable to get username"))
            .expect("unable to create username CString");
        let cpath = CString::new("/bin/sh").unwrap();
        let cargs = [
            cpath.clone(),
            CString::new("-c").unwrap(),
            CString::new(format!("[ -f /etc/profile ] && source /etc/profile; [ -f $HOME/.profile ] && source $HOME/.profile; exec {}", cmd)).unwrap()
        ];

        auth.env("XDG_SESSION_TYPE", "wayland")?;
        auth.env("XDG_SESSION_CLASS", "user")?;
        auth.env("XDG_VTNR", self.tty.to_string())?;
        auth.env("XDG_SEAT", "seat0")?;

        eprintln!("opening session");

        auth.open_session().expect("unable to open session");
        password.scramble();

        let myenv: Vec<String> = if let Some(pamenv) = auth.environment() {
            pamenv
                .iter()
                .map(|x| x.to_string_lossy().into_owned())
                .collect()
        } else {
            env::vars().map(|(x, y)| format!("{}={}", x, y)).collect()
        };

        eprintln!("terminating greeter");

        match self.greeter.take() {
            Some(greeter) => shoo(greeter.task),
            None => (),
        };

        eprintln!("forking session task");

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
                for e in myenv {
                    let mut parts = e.splitn(2, '=');
                    match (parts.next(), parts.next()) {
                        (Some(key), Some(value)) => env::set_var(key, value),
                        _ => (),
                    };
                }
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

                eprintln!("execing session task");

                // Run
                execv(&cpath, &cargs).expect("unable to exec");
                unreachable!("after exec");
            }
        };

        self.session = Some(Session {
            task: child,
            pam: auth,
        });

        Ok(())
    }

    pub fn check_children(&mut self) {
        match self.session.take() {
            Some(session) => {
                match waitpid(session.task, Some(WaitPidFlag::WNOHANG)) {
                    Ok(WaitStatus::Exited(..)) | Ok(WaitStatus::Signaled(..)) => {
                        // Session task is dead, so kill the session and
                        // restart the greeter.
                        drop(session.pam);
                        self.greet().expect("unable to start greeter");
                    }
                    Ok(WaitStatus::StillAlive) => self.session = Some(session),
                    _ => panic!("waitpid on session returned unexpected status"),
                }
            }
            None => (),
        };
        match self.greeter.take() {
            Some(greeter) => {
                match waitpid(greeter.task, Some(WaitPidFlag::WNOHANG)) {
                    Ok(WaitStatus::Exited(..)) | Ok(WaitStatus::Signaled(..)) => {
                        if self.session.is_none() {
                            // Greeter died on us, let's just die with it.
                            eprintln!("greeter exited");
                            std::process::exit(1);
                        }
                    }
                    Ok(WaitStatus::StillAlive) => self.greeter = Some(greeter),
                    _ => panic!("waitpid on greeter returned unexpected status"),
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
