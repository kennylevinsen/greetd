use std::collections::HashMap;
use std::error::Error;
use std::ffi::CString;
use std::io;
use std::time::Duration;

use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{alarm, execv, fork, ForkResult};

use crate::scrambler::Scrambler;
use crate::session::{Session, SessionChild};
use greet_proto::ShutdownAction;

/// Context keeps track of running sessions and start new ones.
pub struct Context<'a> {
    session: Option<SessionChild>,
    greeter: Option<SessionChild>,
    pending_session: Option<Session<'a>>,

    greeter_bin: String,
    greeter_user: String,
    vt: usize,
}

fn run(cmd: &str) -> Result<(), Box<dyn Error>> {
    match fork()? {
        ForkResult::Child => {
            let cpath = CString::new("/bin/sh").unwrap();
            execv(
                &cpath,
                &[
                    &cpath,
                    &CString::new("-c").unwrap(),
                    &CString::new(cmd).unwrap(),
                ],
            )
            .expect("unable to exec");
            unreachable!("after exec");
        }
        _ => (),
    }
    Ok(())
}

impl<'a> Context<'a> {
    pub fn new(greeter_bin: String, greeter_user: String, vt: usize) -> Context<'a> {
        Context {
            session: None,
            greeter: None,
            pending_session: None,
            greeter_bin: greeter_bin,
            greeter_user: greeter_user,
            vt,
        }
    }

    /// Start a greeter session.
    pub fn greet(&mut self) -> Result<(), Box<dyn Error>> {
        if self.greeter.is_some() {
            eprintln!("greeter session already active");
            return Err(io::Error::new(io::ErrorKind::Other, "greeter already active").into());
        }

        let mut pending_session = Session::new(
            "greeter",
            "user",
            &self.greeter_user,
            "",
            vec![self.greeter_bin.to_string()],
            HashMap::new(),
            self.vt,
        )?;
        let greeter = match pending_session.start() {
            Ok(s) => s,
            Err(e) => return Err(format!("session start failed: {}", e).into()),
        };
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

        let pending_session = Session::new(
            "login",
            "user",
            &username,
            &password,
            cmd,
            provided_env,
            self.vt,
        )?;
        password.scramble();
        self.pending_session = Some(pending_session);

        // We give the greeter 5 seconds to prove itself well-behaved before
        // we lose patience and shoot it in the back repeatedly. This is all
        // handled by our alarm handler.
        alarm::set(5);

        Ok(())
    }

    pub fn shutdown(&mut self, action: ShutdownAction) -> Result<(), Box<dyn Error>> {
        if !self.greeter.is_some() || self.session.is_some() {
            eprintln!("shutdown request not valid when greeter is not active");
            return Err(io::Error::new(io::ErrorKind::Other, "greeter not active").into());
        }

        let cmd = match action {
            ShutdownAction::Poweroff => "poweroff",
            ShutdownAction::Reboot => "reboot",
            ShutdownAction::Exit => {
                self.terminate()?;
                unreachable!("previous call must always fail");
            }
        };

        run(cmd)
    }

    /// Notify the Context of an alarm.
    pub fn alarm(&mut self) -> Result<(), Box<dyn Error>> {
        // Keep trying to terminate the greeter until it gives up.
        if let Some(mut p) = self.pending_session.take() {
            if let Some(g) = self.greeter.take() {
                if p.elapsed() > Duration::from_secs(10) {
                    // We're out of patience.
                    g.kill();
                } else {
                    // Let's try to give it a gentle nudge.
                    g.term();
                }
                self.greeter = Some(g);
                self.pending_session = Some(p);
                alarm::set(1);
                return Ok(());
            }

            let s = match p.start() {
                Ok(s) => s,
                Err(e) => return Err(format!("session start failed: {}", e).into()),
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
                        Some(session) if session.owns_pid(pid) => {
                            // Session task is dead, so kill the session and
                            // restart the greeter. However, ensure that we are
                            // not spamming th egreeter by waiting at least one
                            // one second since login was requested before
                            // restarting it.
                            if session.elapsed() < Duration::from_secs(1) {
                                std::thread::sleep(std::time::Duration::from_millis(1000));
                            }
                            self.session = None;
                            eprintln!("session exited");
                            if let Err(e) = self.greet() {
                                return Err(
                                    format!("session start failed for greeter: {}", e).into()
                                );
                            }
                        }
                        _ => (),
                    };
                    match &self.greeter {
                        Some(greeter) if greeter.owns_pid(pid) => {
                            self.greeter = None;
                            match self.pending_session.take() {
                                Some(mut pending_session) => {
                                    eprintln!("starting pending session");
                                    // Our greeter finally bit the dust so we can
                                    // start our pending session.
                                    let s = match pending_session.start() {
                                        Ok(s) => s,
                                        Err(e) => {
                                            return Err(
                                                format!("session start failed: {}", e).into()
                                            );
                                        }
                                    };

                                    self.session = Some(s);
                                }
                                None => {
                                    if self.session.is_none() {
                                        // Greeter died on us, let's just die with it.
                                        return Err("greeter died with no pending session".into());
                                    }
                                }
                            }
                        }
                        _ => (),
                    };
                }

                // Useless status.
                Ok(_) => continue,

                // Interrupted.
                Err(nix::Error::Sys(nix::errno::Errno::EINTR)) => continue,

                // Uh, what?
                Err(e) => eprintln!("waitpid returned an unexpected error: {}", e),
            }
        }
    }

    /// Notify the Context that we want to terminate. This should be called on
    /// SIGTERM.
    pub fn terminate(&mut self) -> Result<(), Box<dyn Error>> {
        if let Some(session) = self.session.take() {
            session.shoo();
        }
        if let Some(greeter) = self.greeter.take() {
            greeter.shoo();
        }
        return Err("terminating".into());
    }
}
