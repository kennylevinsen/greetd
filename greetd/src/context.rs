use std::collections::HashMap;
use std::error::Error;
use std::ffi::CString;
use std::io;
use std::time::Duration;

use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{alarm, execv, fork, ForkResult};

use greet_proto::{ShutdownAction, VtSelection};

use crate::scrambler::Scrambler;
use crate::session::{PendingSession, Session};
use crate::vt;

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

    /// Start a greeter session.
    pub fn greet(&mut self) -> Result<(), Box<dyn Error>> {
        if self.greeter.is_some() {
            eprintln!("greeter session already active");
            return Err(io::Error::new(io::ErrorKind::Other, "greeter already active").into());
        }

        let mut pending_session = PendingSession::new(
            "greeter",
            "user",
            &self.greeter_user,
            "",
            vec![self.greeter_bin.to_string()],
            HashMap::new(),
            self.vt,
        )?;
        let greeter = pending_session.start()?;
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
        vt: VtSelection,
    ) -> Result<(), Box<dyn Error>> {
        if !self.greeter.is_some() {
            eprintln!("login request not valid when greeter is not active");
            return Err(io::Error::new(io::ErrorKind::Other, "greeter not active").into());
        }
        if self.session.is_some() {
            eprintln!("login session already active");
            return Err(io::Error::new(io::ErrorKind::Other, "session already active").into());
        }

        let vt = match vt {
            VtSelection::Current => self.vt,
            VtSelection::Vt(vt) => vt,
        };

        let pending_session =
            PendingSession::new("login", "user", &username, &password, cmd, provided_env, vt)?;
        password.scramble();
        self.pending_session = Some(pending_session);

        // We give the greeter 5 seconds to prove itself well-behaved before
        // we lose patience and shoot it in the back repeatedly.
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
                self.terminate().unwrap();
                unreachable!();
            }
        };

        match fork()? {
            ForkResult::Child => {
                let cpath = CString::new("/bin/sh").unwrap();
                let cargs = [
                    cpath.clone(),
                    CString::new("-c").unwrap(),
                    CString::new(cmd).unwrap(),
                ];
                execv(&cpath, &cargs).expect("unable to exec");
                std::process::exit(0);
            }
            _ => (),
        }
        Ok(())
    }

    /// Notify the Context of an alarm.
    pub fn alarm(&mut self) -> Result<(), Box<dyn Error>> {
        // Keep trying to terminate the greeter until it gives up.
        if let Some(mut p) = self.pending_session.take() {
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
                return Ok(());
            }

            vt::set_mode(vt::Mode::Text)?;
            let s = match p.start() {
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
                                Some(mut pending_session) => {
                                    eprintln!("starting pending session");
                                    // Our greeter finally bit the dust so we can
                                    // start our pending session.
                                    let s = match pending_session.start() {
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
                }

                // Useless status.
                Ok(_) => continue,

                // Uh, what?
                Err(e) => eprintln!("waitpid returned an error: {}", e),
            }
        }
    }

    /// Notify the Context that we want to terminate. This should be called on
    /// SIGTERM.
    pub fn terminate(&mut self) -> Result<(), Box<dyn Error>> {
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
