use std::env;
use std::error::Error;
use std::ffi::CString;
use std::io;

use nix::errno::Errno;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{alarm, execv, fork, initgroups, setgid, setuid, ForkResult, Gid, Uid};

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
    tty: u32,
}

impl<'a> Context<'a> {
    pub fn new(greeter_bin: String, greeter_user: String, tty: u32) -> Context<'a> {
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
                env::set_current_dir(&u.home_dir()).expect("unable to set current directory");

                // Set environment

                env::set_var("XDG_SESSION_TYPE", "wayland");
                env::set_var("XDG_SESSION_CLASS", "user");
                env::set_var("XDG_VTNR", self.tty.to_string());
                env::set_var("XDG_SEAT", "seat0");
                env::set_var("LOGNAME", &u.name());
                env::set_var("HOME", &u.home_dir());
                env::set_var("PWD", &u.home_dir());
                env::set_var("SHELL", &u.shell());
                if env::var("TERM").is_err() {
                    env::set_var("TERM", "linux");
                }
                if env::var("XDG_RUNTIME_DIR").is_err() {
                    env::set_var("XDG_RUNTIME_DIR", format!("/run/user/{}", uid));
                }

                // Run
                execv(&cpath, &cargs).unwrap();
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

        match self.greeter.take() {
            Some(greeter) => {
                let _ = nix::sys::signal::kill(greeter.task, Signal::SIGTERM);
                alarm::set(1);
                match waitpid(greeter.task, None) {
                    Ok(_) => (),
                    Err(nix::Error::Sys(Errno::EINTR)) => {
                        let _ = nix::sys::signal::kill(greeter.task, Signal::SIGKILL);
                    }
                    Err(_) => (), // ???
                }
                alarm::cancel();
            }
            None => (),
        };

        let child = match fork()? {
            ForkResult::Parent { child, .. } => child,
            ForkResult::Child => {
                // Drop privileges to target user
                initgroups(&cusername, gid).expect("unable to init groups");
                setgid(gid).expect("unable to set GID");
                setuid(uid).expect("unable to set UID");

                // Change working directory
                env::set_current_dir(&u.home_dir()).expect("unable to set current directory");

                // Set environment
                for e in myenv {
                    let mut parts = e.splitn(2, '=');
                    env::set_var(parts.next().unwrap(), parts.next().unwrap());
                }
                env::set_var("LOGNAME", &u.name());
                env::set_var("HOME", &u.home_dir());
                env::set_var("PWD", &u.home_dir());
                env::set_var("SHELL", &u.shell());
                if env::var("TERM").is_err() {
                    env::set_var("TERM", "linux");
                }
                if env::var("XDG_RUNTIME_DIR").is_err() {
                    env::set_var("XDG_RUNTIME_DIR", format!("/run/user/{}", uid));
                }

                // Run
                execv(&cpath, &cargs).unwrap();
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
        if let Some(greeter) = &self.greeter {
            let _ = nix::sys::signal::kill(greeter.task, Signal::SIGTERM);
            alarm::set(1);
            match waitpid(greeter.task, None) {
                Ok(_) => (),
                Err(nix::Error::Sys(Errno::EINTR)) => {
                    let _ = nix::sys::signal::kill(greeter.task, Signal::SIGKILL);
                }
                Err(_) => (), // ???
            }
            alarm::cancel();
        }
        if let Some(session) = &self.session {
            let _ = nix::sys::signal::kill(session.task, Signal::SIGTERM);
            alarm::set(5);
            match waitpid(session.task, None) {
                Ok(_) => (),
                Err(nix::Error::Sys(Errno::EINTR)) => {
                    let _ = nix::sys::signal::kill(session.task, Signal::SIGKILL);
                }
                Err(_) => (), // ???
            }
            alarm::cancel();
        }

        std::process::exit(0);
    }
}
