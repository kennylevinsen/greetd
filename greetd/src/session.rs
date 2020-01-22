use std::{
    error::Error,
    os::unix::{io::AsRawFd, net::UnixDatagram},
    process::Command,
};

use nix::{
    fcntl::{fcntl, FcntlArg, FdFlag},
    sys::{
        signal::Signal,
        wait::{waitpid, WaitPidFlag, WaitStatus},
    },
    unistd::Pid,
};

use tokio::net::UnixDatagram as TokioUnixDatagram;

use crate::session_worker::{ParentToSessionChild, QuestionStyle, SessionChildToParent};

/// SessionChild tracks the processes spawned by a session
pub struct SessionChild {
    task: Pid,
    sub_task: Pid,
}

impl SessionChild {
    /// Check if this session has this pid.
    pub fn owns_pid(&self, pid: Pid) -> bool {
        self.task == pid || self.sub_task == pid
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

    /// Terminate a session. Sends SIGTERM in a loop, then sends SIGKILL in a loop.
    pub fn shoo(&self) {
        let task = self.sub_task;
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
}

pub enum SessionState {
    Question(QuestionStyle, String),
    Ready,
}

/// A device to initiate a logged in PAM session.
pub struct Session {
    task: Pid,
    sock: TokioUnixDatagram,
    last_msg: Option<SessionChildToParent>,
}

impl Session {
    pub fn new_external() -> Result<Session, Box<dyn Error>> {
        // Pipe used to communicate the true PID of the final child.
        let (parentfd, childfd) =
            UnixDatagram::pair().map_err(|e| format!("could not create pipe: {}", e))?;

        let raw_child = childfd.as_raw_fd();
        let mut cur_flags =
            unsafe { FdFlag::from_bits_unchecked(fcntl(raw_child, FcntlArg::F_GETFD)?) };
        cur_flags.remove(FdFlag::FD_CLOEXEC);
        fcntl(raw_child, FcntlArg::F_SETFD(cur_flags))?;

        let child = Command::new(std::env::args().next().unwrap())
            .arg("--session-worker")
            .arg(format!("{}", raw_child as usize))
            .spawn()?;

        Ok(Session {
            task: Pid::from_raw(child.id() as i32),
            sock: TokioUnixDatagram::from_std(parentfd)?,
            last_msg: None,
        })
    }

    pub async fn initiate(
        &mut self,
        service: &str,
        class: &str,
        user: &str,
        cmd: Vec<String>,
        env: Vec<String>,
        vt: usize,
    ) -> Result<(), Box<dyn Error>> {
        let msg = ParentToSessionChild::InitiateLogin {
            service: service.to_string(),
            class: class.to_string(),
            user: user.to_string(),
            vt,
            env,
            cmd,
        };
        let data = serde_json::to_vec(&msg)?;
        self.sock
            .send(&data)
            .await
            .map_err(|e| format!("unable to send worker process request: {}", e))?;
        Ok(())
    }

    pub async fn get_state(&mut self) -> Result<SessionState, Box<dyn Error>> {
        let msg = match self.last_msg.take() {
            Some(msg) => msg,
            None => {
                let mut data = [0u8; 1024];
                let len = self.sock.recv(&mut data[..]).await?;
                serde_json::from_slice(&data[..len])
                    .map_err(|e| format!("unable to read worker process response: {}", e))?
            }
        };

        self.last_msg = Some(msg.clone());

        match msg {
            SessionChildToParent::PamMessage { style, msg } => {
                Ok(SessionState::Question(style, msg))
            }
            SessionChildToParent::PamAuthSuccess => Ok(SessionState::Ready),
            SessionChildToParent::Error { error } => Err(error.into()),
            _ => Err("unexpected message from session worker".into()),
        }
    }

    pub async fn post_answer(&mut self, answer: Option<String>) -> Result<(), Box<dyn Error>> {
        self.last_msg = None;
        let msg = match answer {
            Some(resp) => ParentToSessionChild::PamResponse { resp },
            None => ParentToSessionChild::Cancel,
        };
        let data = serde_json::to_vec(&msg)?;
        self.sock.send(&data).await?;
        Ok(())
    }

    ///
    /// Start the session described within the Session.
    ///
    pub async fn start(&mut self) -> Result<SessionChild, Box<dyn Error>> {
        let msg = ParentToSessionChild::Start;
        let data = serde_json::to_vec(&msg)
            .map_err(|e| format!("unable to serialize worker process request: {}", e))?;
        self.sock
            .send(&data)
            .await
            .map_err(|e| format!("unable to send worker process request: {}", e))?;

        let mut data = [0u8; 1024];
        let len = self
            .sock
            .recv(&mut data[..])
            .await
            .map_err(|e| format!("unable to receive worker process response: {}", e))?;
        let msg = serde_json::from_slice(&data[..len])
            .map_err(|e| format!("unable to deserialize worker process response: {}", e))?;

        self.sock.shutdown(std::net::Shutdown::Both)?;

        let sub_task = match msg {
            SessionChildToParent::Error { error } => return Err(error.into()),
            SessionChildToParent::FinalChildPid(raw_pid) => Pid::from_raw(raw_pid as i32),
            _ => panic!("unexpected message"),
        };

        Ok(SessionChild {
            task: self.task,
            sub_task,
        })
    }
}
