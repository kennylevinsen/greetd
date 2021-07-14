use std::{
    fs::File,
    path::Path,
    time::{Duration, Instant},
};

use nix::{
    sys::wait::{waitpid, WaitPidFlag, WaitStatus},
    unistd::alarm,
};
use tokio::{sync::RwLock, time::sleep};

use crate::{
    error::Error,
    session::{
        interface::{Session, SessionChild, SessionState},
        worker::{AuthMessageType as SessAuthMessageType, TerminalMode},
    },
};
use greetd_ipc::AuthMessageType;

struct SessionChildSet {
    child: SessionChild,
    time: Instant,
    is_greeter: bool,
}

struct SessionSet {
    session: Session,
    time: Instant,
}

struct ContextInner {
    current: Option<SessionChildSet>,
    scheduled: Option<SessionSet>,
    configuring: Option<SessionSet>,
}

/// Context keeps track of running sessions and start new ones.
pub struct Context {
    inner: RwLock<ContextInner>,
    greeter_bin: String,
    greeter_user: String,
    greeter_service: String,
    pam_service: String,
    term_mode: TerminalMode,
    source_profile: bool,
    runfile: String,
}

impl Context {
    pub fn new(
        greeter_bin: String,
        greeter_user: String,
        greeter_service: String,
        pam_service: String,
        term_mode: TerminalMode,
        source_profile: bool,
        runfile: String,
    ) -> Context {
        Context {
            inner: RwLock::new(ContextInner {
                current: None,
                scheduled: None,
                configuring: None,
            }),
            greeter_bin,
            greeter_user,
            greeter_service,
            pam_service,
            term_mode,
            source_profile,
            runfile,
        }
    }

    /// Directly start an unauthenticated session, bypassing the normal
    /// scheduling. This function does not take the inner lock, and can thus
    /// be used while it is held.
    async fn start_unauthenticated_session(
        &self,
        class: &str,
        user: &str,
        service: &str,
        cmd: Vec<String>,
    ) -> Result<SessionChild, Error> {
        let mut scheduled_session = Session::new_external()?;
        scheduled_session
            .initiate(
                &service,
                class,
                user,
                false,
                &self.term_mode,
                self.source_profile,
            )
            .await?;
        loop {
            match scheduled_session.get_state().await {
                Ok(SessionState::Ready) => break,
                Ok(SessionState::Question(_, _)) => scheduled_session.post_response(None).await?,
                Err(err) => return Err(format!("session start failed: {}", err).into()),
            }
        }

        scheduled_session.send_args(cmd).await?;
        scheduled_session.start().await
    }

    /// Directly start a greeter session, bypassing the normal scheduling. This
    /// function does not take the inner lock, and can thus be used while it is
    /// held.
    async fn start_greeter(&self) -> Result<SessionChild, Error> {
        self.start_unauthenticated_session(
            "greeter",
            &self.greeter_user,
            &self.greeter_service,
            vec![self.greeter_bin.to_string()],
        )
        .await
    }

    /// Directly start a greeter session, bypassing the normal scheduling.
    pub async fn greet(&self) -> Result<(), Error> {
        {
            let inner = self.inner.read().await;
            if inner.current.is_some() {
                return Err("session already active".into());
            }
        }

        let mut inner = self.inner.write().await;
        inner.current = Some(SessionChildSet {
            child: self.start_greeter().await?,
            time: Instant::now(),
            is_greeter: true,
        });
        Ok(())
    }

    /// Check if this is the first time greetd starts since boot, or if it restarted for any reason
    pub fn is_first_run(&self) -> bool {
        !Path::new(&self.runfile).exists()
    }

    /// Create runfile used to check if greetd was already started since boot
    pub fn create_runfile(&self) {
        if let Err(err) = File::create(&self.runfile) {
            eprintln!("could not create runfile: {}", err);
        }
    }

    /// Directly start an initial session, bypassing the normal scheduling.
    pub async fn start_user_session(&self, user: &str, cmd: Vec<String>) -> Result<(), Error> {
        {
            let inner = self.inner.read().await;
            if inner.current.is_some() {
                return Err("session already active".into());
            }
        }

        let mut inner = self.inner.write().await;
        inner.current = Some(SessionChildSet {
            child: self
                .start_unauthenticated_session("user", user, &self.pam_service, cmd)
                .await?,
            time: Instant::now(),
            is_greeter: false,
        });
        Ok(())
    }

    /// Create a new session for configuration.
    pub async fn create_session(&self, username: String) -> Result<(), Error> {
        {
            let inner = self.inner.read().await;
            if inner.current.is_none() {
                return Err("session not active".into());
            }
            if inner.configuring.is_some() {
                return Err("a session is already being configured".into());
            }
            if inner.scheduled.is_some() {
                return Err("a session is already scheduled".into());
            }
        }

        let mut session_set = SessionSet {
            session: Session::new_external()?,
            time: Instant::now(),
        };
        session_set
            .session
            .initiate(
                &self.pam_service,
                "user",
                &username,
                true,
                &self.term_mode,
                self.source_profile,
            )
            .await?;

        let mut session = Some(session_set);
        let mut inner = self.inner.write().await;
        std::mem::swap(&mut session, &mut inner.configuring);
        drop(inner);

        // If there was a session under configuration, cancel it.
        if let Some(mut s) = session {
            s.session.cancel().await?;
        }

        Ok(())
    }

    /// Cancel the session being configured.
    pub async fn cancel(&self) -> Result<(), Error> {
        let mut inner = self.inner.write().await;
        if let Some(mut s) = inner.configuring.take() {
            s.session.cancel().await?;
        }
        Ok(())
    }

    /// Retrieve a question from the session under configuration.
    pub async fn get_question(&self) -> Result<Option<(AuthMessageType, String)>, Error> {
        let mut inner = self.inner.write().await;
        match &mut inner.configuring {
            Some(s) => match s.session.get_state().await? {
                SessionState::Ready => Ok(None),
                SessionState::Question(style, string) => Ok(Some((
                    match style {
                        SessAuthMessageType::Visible => AuthMessageType::Visible,
                        SessAuthMessageType::Secret => AuthMessageType::Secret,
                        SessAuthMessageType::Info => AuthMessageType::Info,
                        SessAuthMessageType::Error => AuthMessageType::Error,
                    },
                    string,
                ))),
            },
            None => Err("no session under configuration".into()),
        }
    }

    /// Answer a question to the session under configuration.
    pub async fn post_response(&self, answer: Option<String>) -> Result<(), Error> {
        let mut inner = self.inner.write().await;
        match &mut inner.configuring {
            Some(s) => s.session.post_response(answer).await,
            None => Err("no session under configuration".into()),
        }
    }

    /// Schedule the session under configuration with the provided arguments.
    pub async fn start(&self, cmd: Vec<String>) -> Result<(), Error> {
        let mut session = self.inner.write().await.configuring.take();

        match &mut session {
            Some(s) => match s.session.get_state().await? {
                SessionState::Ready => {
                    // Send our arguments to the session.
                    s.session.send_args(cmd).await?;

                    let mut inner = self.inner.write().await;
                    std::mem::swap(&mut session, &mut inner.scheduled);
                    drop(inner);

                    // If there was a scheduled session, cancel it.
                    if let Some(mut p) = session {
                        p.session.cancel().await?;
                    }

                    // We give the greeter 5 seconds to prove itself well-behaved before
                    // we lose patience and shoot it in the back repeatedly. This is all
                    // handled by our alarm handler.
                    alarm::set(5);

                    Ok(())
                }
                SessionState::Question(..) => Err("session is not ready".into()),
            },
            None => Err("no session active".into()),
        }
    }

    /// Notify the Context of an alarm.
    pub async fn alarm(&self) -> Result<(), Error> {
        // Keep trying to terminate the greeter until it gives up.
        let mut inner = self.inner.write().await;

        if let Some(mut p) = inner.scheduled.take() {
            if let Some(g) = inner.current.take() {
                if p.time.elapsed() > Duration::from_secs(10) {
                    // We're out of patience.
                    g.child.kill();
                } else {
                    // Let's try to give it a gentle nudge.
                    g.child.term();
                }
                inner.current = Some(g);
                inner.scheduled = Some(p);
                alarm::set(1);
                return Ok(());
            }
            drop(inner);
            let s = match p.session.start().await {
                Ok(s) => s,
                Err(e) => return Err(format!("session start failed: {}", e).into()),
            };
            let mut inner = self.inner.write().await;
            inner.current = Some(SessionChildSet {
                child: s,
                time: Instant::now(),
                is_greeter: false,
            });
        }

        Ok(())
    }

    /// Notify the Context that it needs to check its children for termination.
    /// This should be called on SIGCHLD.
    pub async fn check_children(&self) -> Result<(), Error> {
        loop {
            match waitpid(None, Some(WaitPidFlag::WNOHANG)) {
                // No scheduled exits.
                Ok(WaitStatus::StillAlive) => break Ok(()),

                // We got an exit, see if it's something we need to clean up.
                Ok(WaitStatus::Exited(pid, ..)) | Ok(WaitStatus::Signaled(pid, ..)) => {
                    let mut inner = self.inner.write().await;
                    let (was_greeter, sesion_length) = match &inner.current {
                        Some(s) if s.child.owns_pid(pid) => {
                            let res = (s.is_greeter, s.time.elapsed());
                            inner.current = None;
                            res
                        }
                        _ => continue,
                    };

                    match inner.scheduled.take() {
                        Some(mut scheduled) => {
                            // Our greeter finally bit the dust so we can
                            // start our scheduled session.
                            drop(inner);
                            let s = match scheduled.session.start().await {
                                Ok(s) => s,
                                Err(e) => return Err(format!("session start failed: {}", e).into()),
                            };
                            let mut inner = self.inner.write().await;
                            inner.current = Some(SessionChildSet {
                                child: s,
                                time: Instant::now(),
                                is_greeter: false,
                            });
                        }
                        None => {
                            if was_greeter {
                                return Err("greeter exited without creating a session".into());
                            }
                            if sesion_length < Duration::from_secs(1) {
                                sleep(Duration::from_secs(1)).await;
                            }
                            inner.current = Some(SessionChildSet {
                                child: self.start_greeter().await?,
                                time: Instant::now(),
                                is_greeter: true,
                            });
                        }
                    }
                }

                // Useless status.
                Ok(_) => continue,

                // Interrupted.
                Err(nix::Error::Sys(nix::errno::Errno::EINTR)) => continue,

                // We do not have any children right now.
                Err(nix::Error::Sys(nix::errno::Errno::ECHILD)) => break Ok(()),

                // Uh, what?
                Err(e) => panic!("waitpid returned an unexpected error: {}", e),
            }
        }
    }

    /// Notify the Context that we want to terminate. This should be called on
    /// SIGTERM.
    pub async fn terminate(&self) -> Result<(), Error> {
        let mut inner = self.inner.write().await;
        if let Some(mut sess) = inner.configuring.take() {
            let _ = sess.session.cancel().await;
        }
        if let Some(mut sess) = inner.scheduled.take() {
            let _ = sess.session.cancel().await;
        }
        if let Some(sess) = inner.current.take() {
            sess.child.term();
        }
        Ok(())
    }
}
