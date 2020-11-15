use std::{
    ffi::CString,
    os::unix::{io::AsRawFd, net::UnixDatagram},
};

use nix::{
    fcntl::{fcntl, FcntlArg, FdFlag},
    sys::signal::Signal,
    unistd::{execv, fork, ForkResult, Pid},
};

use async_trait::async_trait;

use tokio::net::UnixDatagram as TokioUnixDatagram;

use super::worker::{AuthMessageType, ParentToSessionChild, SessionChildToParent, TerminalMode};
use crate::error::Error;

#[async_trait]
trait AsyncRecv<T: Sized> {
    async fn recv(sock: &mut TokioUnixDatagram) -> Result<T, Error>;
}

#[async_trait]
trait AsyncSend {
    async fn send(&self, sock: &mut TokioUnixDatagram) -> Result<(), Error>;
}

#[async_trait]
impl AsyncSend for ParentToSessionChild {
    async fn send(&self, sock: &mut TokioUnixDatagram) -> Result<(), Error> {
        let out =
            serde_json::to_vec(self).map_err(|e| format!("unable to serialize message: {}", e))?;
        sock.send(&out)
            .await
            .map_err(|e| format!("unable to send message: {}", e))?;
        Ok(())
    }
}

#[async_trait]
impl AsyncRecv<SessionChildToParent> for SessionChildToParent {
    async fn recv(sock: &mut TokioUnixDatagram) -> Result<SessionChildToParent, Error> {
        let mut data = [0; 10240];
        let len = sock
            .recv(&mut data[..])
            .await
            .map_err(|e| format!("unable to recieve message: {}", e))?;
        let msg = serde_json::from_slice(&data[..len])
            .map_err(|e| format!("unable to deserialize message: {}", e))?;
        Ok(msg)
    }
}

/// SessionChild tracks the processes spawned by a session
pub struct SessionChild {
    pub task: Pid,
    pub sub_task: Pid,
}

impl SessionChild {
    /// Check if this session has this pid.
    pub fn owns_pid(&self, pid: Pid) -> bool {
        self.task == pid
    }

    /// Send SIGTERM to the session child.
    pub fn term(&self) {
        let _ = nix::sys::signal::kill(self.sub_task, Signal::SIGTERM);
    }

    /// Send SIGKILL to the session child.
    pub fn kill(&self) {
        let _ = nix::sys::signal::kill(self.sub_task, Signal::SIGKILL);
        let _ = nix::sys::signal::kill(self.task, Signal::SIGKILL);
    }
}

#[derive(Debug)]
pub enum SessionState {
    Question(AuthMessageType, String),
    Ready,
}

/// A device to initiate a logged in PAM session.
pub struct Session {
    task: Pid,
    sock: TokioUnixDatagram,
    last_msg: Option<SessionChildToParent>,
}

impl Session {
    /// Create a session started as an external process.
    pub fn new_external() -> Result<Session, Error> {
        // Pipe used to communicate the true PID of the final child.
        let (parentfd, childfd) =
            UnixDatagram::pair().map_err(|e| format!("could not create pipe: {}", e))?;

        let raw_child = childfd.as_raw_fd();
        let mut cur_flags =
            unsafe { FdFlag::from_bits_unchecked(fcntl(raw_child, FcntlArg::F_GETFD)?) };
        cur_flags.remove(FdFlag::FD_CLOEXEC);
        fcntl(raw_child, FcntlArg::F_SETFD(cur_flags))?;

        let cur_exe = std::env::current_exe()?;
        let bin = CString::new(cur_exe.to_str().expect("unable to get current exe name"))?;

        let child = match fork().map_err(|e| format!("unable to fork: {}", e))? {
            ForkResult::Parent { child, .. } => child,
            ForkResult::Child => {
                execv(
                    &bin,
                    &[
                        &bin,
                        &CString::new("--session-worker").unwrap(),
                        &CString::new(format!("{}", raw_child as usize)).unwrap(),
                    ],
                )
                .expect("unable to exec");

                unreachable!("after exec");
            }
        };

        Ok(Session {
            task: child,
            sock: TokioUnixDatagram::from_std(parentfd)?,
            last_msg: None,
        })
    }

    /// Initiates the session, which will cause authentication to begin.
    pub async fn initiate(
        &mut self,
        service: &str,
        class: &str,
        user: &str,
        authenticate: bool,
        term_mode: &TerminalMode,
        source_profile: bool,
    ) -> Result<(), Error> {
        let msg = ParentToSessionChild::InitiateLogin {
            service: service.to_string(),
            class: class.to_string(),
            user: user.to_string(),
            authenticate,
            tty: term_mode.clone(),
            source_profile,
        };
        msg.send(&mut self.sock).await?;
        Ok(())
    }

    /// Return the current state of this session.
    pub async fn get_state(&mut self) -> Result<SessionState, Error> {
        let msg = match self.last_msg.take() {
            Some(msg) => msg,
            None => SessionChildToParent::recv(&mut self.sock).await?,
        };

        self.last_msg = Some(msg.clone());

        match msg {
            SessionChildToParent::PamMessage { style, msg } => {
                Ok(SessionState::Question(style, msg))
            }
            SessionChildToParent::Success => Ok(SessionState::Ready),
            SessionChildToParent::Error(e) => Err(e),
            msg => panic!(
                "expected PamMessage, Success or Error from session worker, got: {:?}",
                msg
            ),
        }
    }

    /// Cancel the session.
    pub async fn cancel(&mut self) -> Result<(), Error> {
        self.last_msg = None;
        ParentToSessionChild::Cancel.send(&mut self.sock).await?;
        Ok(())
    }

    /// Send a response to an authentication question, or None to cancel the
    /// authentication attempt.
    pub async fn post_response(&mut self, answer: Option<String>) -> Result<(), Error> {
        self.last_msg = None;
        ParentToSessionChild::PamResponse { resp: answer }
            .send(&mut self.sock)
            .await?;
        Ok(())
    }

    ///
    /// Send the arguments that will be used to start the session.
    ///
    pub async fn send_args(&mut self, cmd: Vec<String>) -> Result<(), Error> {
        let msg = ParentToSessionChild::Args { cmd };
        msg.send(&mut self.sock).await?;

        let msg = SessionChildToParent::recv(&mut self.sock).await?;

        self.last_msg = Some(msg.clone());

        match msg {
            SessionChildToParent::Success => Ok(()),
            SessionChildToParent::Error(e) => Err(e),
            msg => panic!(
                "expected Success or Error from session worker, got: {:?}",
                msg
            ),
        }
    }

    ///
    /// Start the session.
    ///
    pub async fn start(&mut self) -> Result<SessionChild, Error> {
        let msg = ParentToSessionChild::Start;
        msg.send(&mut self.sock).await?;

        let sub_task = loop {
            match SessionChildToParent::recv(&mut self.sock).await? {
                SessionChildToParent::Error(e) => return Err(e),
                SessionChildToParent::FinalChildPid(raw_pid) => {
                    break Pid::from_raw(raw_pid as i32)
                }
                SessionChildToParent::PamMessage { .. } => {
                    // pam_conv after start, ignore
                    ParentToSessionChild::PamResponse { resp: None }
                        .send(&mut self.sock)
                        .await?;
                    continue;
                }
                msg => panic!(
                    "expected Error or FinalChildPid from session worker, got: {:?}",
                    msg
                ),
            };
        };

        self.sock.shutdown(std::net::Shutdown::Both)?;

        Ok(SessionChild {
            task: self.task,
            sub_task,
        })
    }
}
