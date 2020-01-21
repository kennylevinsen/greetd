use std::error::Error;
use std::ffi::CString;
use std::io;
use std::time::Duration;

use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{alarm, execv, fork, ForkResult};
use tokio::{sync::RwLock, time::delay_for};

use crate::session::{QuestionStyle as SessQuestionStyle, Session, SessionChild, SessionState};
use greet_proto::{Question, QuestionStyle, ShutdownAction};

pub struct ContextInner {
    current_session: Option<SessionChild>,
    pending_session: Option<Session>,
}

/// Context keeps track of running sessions and start new ones.
pub struct Context {
    inner: RwLock<ContextInner>,
    greeter_bin: String,
    greeter_user: String,
    vt: usize,
}

fn run(cmd: &str) -> Result<(), Box<dyn Error>> {
    if let ForkResult::Child = fork()? {
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
    Ok(())
}

impl Context {
    pub fn new(greeter_bin: String, greeter_user: String, vt: usize) -> Context {
        Context {
            inner: RwLock::new(ContextInner {
                current_session: None,
                pending_session: None,
            }),
            greeter_bin,
            greeter_user,
            vt,
        }
    }

    async fn create_greeter(&self) -> Result<SessionChild, Box<dyn Error>> {
        let mut pending_session = Session::new(
            "greeter",
            "user",
            &self.greeter_user,
            vec![self.greeter_bin.to_string()],
            vec![],
            self.vt,
        )
        .await?;
        match pending_session.get_state().await {
            Ok(SessionState::Ready) => (),
            Ok(SessionState::Question(_, _)) => {
                return Err("session start failed: unexpected question".into())
            }
            Err(err) => return Err(format!("session start failed: {}", err).into()),
        }
        match pending_session.start().await {
            Ok(s) => Ok(s),
            Err(e) => Err(format!("session start failed: {}", e).into()),
        }
    }

    /// Start a greeter session.
    pub async fn greet(&self) -> Result<(), Box<dyn Error>> {
        {
            let inner = self.inner.read().await;
            if inner.current_session.is_some() {
                eprintln!("session already active");
                return Err(io::Error::new(io::ErrorKind::Other, "session already active").into());
            }
        }

        self.inner.write().await.current_session = Some(self.create_greeter().await?);
        Ok(())
    }

    pub async fn initiate(
        &self,
        username: String,
        cmd: Vec<String>,
        provided_env: Vec<String>,
    ) -> Result<(), Box<dyn Error>> {
        {
            let inner = self.inner.read().await;
            if inner.current_session.is_none() {
                eprintln!("login request requires active session");
                return Err(io::Error::new(io::ErrorKind::Other, "session not active").into());
            }
        }

        let pending_session =
            Session::new("login", "user", &username, cmd, provided_env, self.vt).await?;
        self.inner.write().await.pending_session = Some(pending_session);

        Ok(())
    }

    pub async fn cancel(&self) -> Result<(), Box<dyn Error>> {
        let pending_session = self.inner.write().await.pending_session.take();
        if let Some(mut s) = pending_session {
            s.post_answer(None).await?
        }
        Ok(())
    }

    pub async fn get_question(&self) -> Result<Option<Question>, Box<dyn Error>> {
        let mut inner = self.inner.write().await;
        match &mut inner.pending_session {
            Some(s) => match s.get_state().await? {
                SessionState::Ready => Ok(None),
                SessionState::Question(style, string) => Ok(Some(Question {
                    msg: string,
                    style: match style {
                        SessQuestionStyle::Visible => QuestionStyle::Visible,
                        SessQuestionStyle::Secret => QuestionStyle::Secret,
                        SessQuestionStyle::Info => QuestionStyle::Info,
                        SessQuestionStyle::Error => QuestionStyle::Error,
                    },
                })),
            },
            None => Err("no session active".into()),
        }
    }

    pub async fn post_answer(&self, answer: Option<String>) -> Result<(), Box<dyn Error>> {
        let mut inner = self.inner.write().await;
        match &mut inner.pending_session {
            Some(s) => s.post_answer(answer).await,
            None => Err("no session active".into()),
        }
    }

    pub async fn start(&self) -> Result<(), Box<dyn Error>> {
        let mut inner = self.inner.write().await;
        match &mut inner.pending_session {
            Some(s) => {
                match s.get_state().await? {
                    SessionState::Ready => {
                        // We give the greeter 5 seconds to prove itself well-behaved before
                        // we lose patience and shoot it in the back repeatedly. This is all
                        // handled by our alarm handler.
                        alarm::set(5);

                        Ok(())
                    }
                    _ => Err("session is not ready".into()),
                }
            }
            None => Err("no session active".into()),
        }
    }

    pub async fn shutdown(&self, action: ShutdownAction) -> Result<(), Box<dyn Error>> {
        {
            let inner = self.inner.read().await;
            if inner.current_session.is_none() {
                eprintln!("shutdown request not valid when greeter is not active");
                return Err(io::Error::new(io::ErrorKind::Other, "greeter not active").into());
            }
        }

        let cmd = match action {
            ShutdownAction::Poweroff => "poweroff",
            ShutdownAction::Reboot => "reboot",
            ShutdownAction::Exit => {
                self.terminate().await?;
                unreachable!("previous call must always fail");
            }
        };

        run(cmd)
    }

    /// Notify the Context of an alarm.
    pub async fn alarm(&self) -> Result<(), Box<dyn Error>> {
        // Keep trying to terminate the greeter until it gives up.
        let mut inner = self.inner.write().await;
        if let Some(mut p) = inner.pending_session.take() {
            if let Some(g) = inner.current_session.take() {
                if p.elapsed() > Duration::from_secs(10) {
                    // We're out of patience.
                    g.kill();
                } else {
                    // Let's try to give it a gentle nudge.
                    g.term();
                }
                inner.current_session = Some(g);
                inner.pending_session = Some(p);
                alarm::set(1);
                return Ok(());
            }
            drop(inner);
            let s = match p.start().await {
                Ok(s) => s,
                Err(e) => return Err(format!("session start failed: {}", e).into()),
            };
            let mut inner = self.inner.write().await;
            inner.current_session = Some(s);
        }

        Ok(())
    }

    /// Notify the Context that it needs to check its children for termination.
    /// This should be called on SIGCHLD.
    pub async fn check_children(&self) -> Result<(), Box<dyn Error>> {
        loop {
            match waitpid(None, Some(WaitPidFlag::WNOHANG)) {
                // No pending exits.
                Ok(WaitStatus::StillAlive) => break Ok(()),

                // We got an exit, see if it's something we need to clean up.
                Ok(WaitStatus::Exited(pid, ..)) | Ok(WaitStatus::Signaled(pid, ..)) => {
                    let mut inner = self.inner.write().await;
                    let was_greeter;
                    let elapsed;
                    match &inner.current_session {
                        Some(session) if session.owns_pid(pid) => {
                            eprintln!("session exited");
                            was_greeter = session.get_service() == "greeter";
                            elapsed = session.elapsed();
                            inner.current_session = None;
                        }
                        _ => continue,
                    }

                    match inner.pending_session.take() {
                        Some(mut pending_session) => {
                            eprintln!("starting pending session");
                            // Our greeter finally bit the dust so we can
                            // start our pending session.
                            drop(inner);
                            let s = match pending_session.start().await {
                                Ok(s) => s,
                                Err(e) => {
                                    return Err(format!("session start failed: {}", e).into());
                                }
                            };
                            let mut inner = self.inner.write().await;
                            inner.current_session = Some(s);
                        }
                        None if !was_greeter => {
                            if elapsed < Duration::from_secs(1) {
                                delay_for(Duration::from_secs(1)).await;
                            }
                            inner.current_session = Some(self.create_greeter().await?);
                        }
                        None => {
                            // Greeter died on us, let's just die with it.
                            return Err("greeter died with no pending session".into());
                        }
                    }
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
    pub async fn terminate(&self) -> Result<(), Box<dyn Error>> {
        let mut inner = self.inner.write().await;
        if let Some(sess) = &inner.current_session {
            sess.shoo();
        }
        if let Some(sess) = &mut inner.pending_session {
            let _ = sess.post_answer(None).await;
        }
        Err("terminating".into())
    }
}
