use std::{
    collections::HashMap,
    env,
    error::Error,
    ffi::CString,
    fs,
    fs::File,
    io::{BufRead, BufReader},
    path::PathBuf,
    time::{Duration, Instant},
};

use nix::{
    sys::{
        signal::{SigSet, Signal},
        wait::{waitpid, WaitPidFlag, WaitStatus},
    },
    unistd::{execve, fork, initgroups, setgid, setsid, setuid, ForkResult, Gid, Pid, Uid},
};
use pam_sys::{PamFlag, PamItemType};
use serde::{Deserialize, Serialize};
use users::os::unix::UserExt;

use crate::{pam::converse::Converse, pam::session::PamSession, terminal};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum QuestionStyle {
    Visible,
    Secret,
    Info,
    Error,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum ParentToSessionChild {
    InitiateLogin {
        service: String,
        class: String,
        user: String,
        vt: usize,
        env: Vec<String>,
        cmd: Vec<String>,
    },
    PamResponse {
        resp: String,
    },
    Cancel,
    Start,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum SessionChildToParent {
    PamMessage { style: QuestionStyle, msg: String },
    PamAuthSuccess,
    Error { error: String },
    FinalChildPid(u64),
}

/// Returns a set containing the signals we want to block in the main process.
/// This is also used to unblock the same signals again before starting child
/// processes.
pub fn blocked_sigset() -> SigSet {
    let mut mask = SigSet::empty();
    mask.add(Signal::SIGALRM);
    mask.add(Signal::SIGTERM);
    mask.add(Signal::SIGCHLD);
    mask
}

/// SessionChild tracks the processes spawned by a session
pub struct SessionChild {
    service: String,
    opened: Instant,
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

    pub fn get_service(&self) -> &str {
        &self.service
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

    /// Report how long has elapsed since this session child was created.
    pub fn elapsed(&self) -> Duration {
        self.opened.elapsed()
    }
}

/// A device to initiate a logged in PAM session.
pub struct Session {
    service: String,
    opened: Instant,
    task: Pid,
    sock: tokio::net::UnixDatagram,
    last_msg: Option<SessionChildToParent>,
}

fn split_env<'a>(s: &'a str) -> Option<(&'a str, &str)> {
    let components: Vec<&str> = s.splitn(2, '=').collect();
    match components.len() {
        0 => None,
        1 => Some((components[0], "")),
        2 => Some((components[0], components[1])),
        _ => panic!("splitn returned more values than requested"),
    }
}

pub struct SessionConv<'a> {
    sock: &'a std::os::unix::net::UnixDatagram,
}

impl<'a> SessionConv<'a> {
    fn question(&self, msg: &str, style: QuestionStyle) -> Result<String, ()> {
        let msg = SessionChildToParent::PamMessage {
            style,
            msg: msg.to_string(),
        };
        let data = serde_json::to_vec(&msg).map_err(|e| eprintln!("pam_conv: {}", e))?;
        self.sock
            .send(&data)
            .map_err(|e| eprintln!("pam_conv: {}", e))?;

        let mut data = [0; 1024];
        let len = self
            .sock
            .recv(&mut data[..])
            .map_err(|e| eprintln!("pam_conv: {}", e))?;
        let msg = serde_json::from_slice(&data[..len]).map_err(|e| eprintln!("pam_conv: {}", e))?;

        match msg {
            ParentToSessionChild::PamResponse { resp, .. } => Ok(resp),
            ParentToSessionChild::Cancel => Err(()),
            _ => Err(()),
        }
    }

    /// Create a new `PasswordConv` handler
    pub fn new(sock: &'a std::os::unix::net::UnixDatagram) -> SessionConv {
        SessionConv { sock }
    }
}

impl<'a> Converse for SessionConv<'a> {
    fn prompt_echo(&self, msg: &str) -> Result<String, ()> {
        self.question(msg, QuestionStyle::Visible)
    }
    fn prompt_blind(&self, msg: &str) -> Result<String, ()> {
        self.question(msg, QuestionStyle::Secret)
    }
    fn info(&self, msg: &str) -> Result<(), ()> {
        self.question(msg, QuestionStyle::Info).map(|_| ())
    }
    fn error(&self, msg: &str) -> Result<(), ()> {
        self.question(msg, QuestionStyle::Error).map(|_| ())
    }
}

/// Process environment.d folders to generate the configured environment for
/// the session.
fn generate_user_environment(pam: &mut PamSession, home: String) -> Result<(), Box<dyn Error>> {
    let dirs = [
        "/usr/lib/environments.d/",
        "/usr/local/lib/environments.d/",
        "/run/environments.d/",
        "/etc/environments.d/",
        &format!("{}/.config/environment.d", home),
    ];

    let mut env: HashMap<String, String> = HashMap::new();
    for dir in dirs.iter() {
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => continue,
        };

        let mut filepaths: Vec<PathBuf> =
            entries.filter_map(Result::ok).map(|e| e.path()).collect();

        filepaths.sort();

        for filepath in filepaths.into_iter() {
            let reader = BufReader::new(match File::open(&filepath) {
                Ok(f) => f,
                Err(_) => continue,
            });

            for line in reader.lines().filter_map(Result::ok) {
                let (key, value) = match split_env(&line) {
                    Some(v) => v,
                    None => continue,
                };

                if key.starts_with('#') {
                    continue;
                }

                if !value.contains('$') {
                    env.insert(key.to_string(), value.to_string());
                    continue;
                }

                let reference = &value[1..];
                let value = match env.get(reference) {
                    Some(v) => v.to_string(),
                    None => match pam.getenv(reference) {
                        Some(pam_val) => match split_env(pam_val) {
                            Some((_, new_value)) => new_value.to_string(),
                            None => "".to_string(),
                        },
                        None => "".to_string(),
                    },
                };

                env.insert(key.to_string(), value);
            }
        }
    }

    let env = env
        .into_iter()
        .map(|(key, value)| format!("{}={}", key, value));

    for e in env {
        pam.putenv(&e)
            .map_err(|e| format!("unable to set PAM environment: {}", e))?;
    }

    Ok(())
}

/// The entry point for the session worker process. The session worker is
/// responsible for the entirety of the session setup and execution. It is
/// started by Session::start.
fn session_worker(sock: &std::os::unix::net::UnixDatagram) -> Result<(), Box<dyn Error>> {
    let mut data = [0; 1024];
    let len = sock
        .recv(&mut data[..])
        .map_err(|e| format!("unable to recieve message: {}", e))?;
    let msg = serde_json::from_slice(&data[..len])
        .map_err(|e| format!("unable to deserialize message: {}", e))?;
    let (service, class, user, vt, env, cmd) = match msg {
        ParentToSessionChild::InitiateLogin {
            service,
            class,
            user,
            vt,
            env,
            cmd,
        } => (service, class, user, vt, env, cmd),
        ParentToSessionChild::Cancel => return Err("cancelled".into()),
        _ => return Err("unexpected message".into()),
    };

    let conv = Box::pin(SessionConv::new(sock));
    let mut pam = PamSession::start(&service, &user, conv)
        .map_err(|e| format!("unable to initiate PAM session: {}", e))?;

    pam.authenticate(PamFlag::NONE)
        .map_err(|e| format!("unable to authenticate account: {}", e))?;
    pam.acct_mgmt(PamFlag::NONE)
        .map_err(|e| format!("unable to validate account: {}", e))?;

    let msg = SessionChildToParent::PamAuthSuccess;
    let out =
        serde_json::to_vec(&msg).map_err(|e| format!("unable to serialize message: {}", e))?;
    sock.send(&out)
        .map_err(|e| format!("unable to send message: {}", e))?;

    let len = sock
        .recv(&mut data[..])
        .map_err(|e| format!("unable to recieve message: {}", e))?;
    let msg = serde_json::from_slice(&data[..len])
        .map_err(|e| format!("unable to deserialize message: {}", e))?;
    match msg {
        ParentToSessionChild::Start => (),
        ParentToSessionChild::Cancel => return Err("cancelled".into()),
        _ => return Err("unexpected message".into()),
    }

    let pam_username = pam.get_user()?;

    let user = users::get_user_by_name(&pam_username).ok_or("unable to get user info")?;

    // Clear the signal masking that was inherited from the parent.
    blocked_sigset()
        .thread_unblock()
        .map_err(|e| format!("unable to unblock signals: {}", e))?;

    // Make this process a session leader.
    setsid().map_err(|e| format!("unable to become session leader: {}", e))?;

    // Opening our target terminal. This will automatically make it our
    // controlling terminal. An attempt was made to use TIOCSCTTY to do
    // this explicitly, but it neither worked nor was worth the additional
    // code.
    let mut target_term = terminal::Terminal::open(vt)?;

    // Clear TTY so that it will be empty when we switch to it.
    target_term.term_clear()?;

    // Set the target VT mode to text for compatibility. Other login
    // managers set this to graphics, but that disallows start of textual
    // applications, which greetd aims to support.
    target_term.kd_setmode(terminal::KdMode::Text)?;

    // A bit more work if a VT switch is required.
    if vt != target_term.vt_get_current()? {
        // Perform a switch to the target VT, simultaneously resetting it to
        // VT_AUTO.
        eprintln!("session worker: switching to VT {}", vt);
        target_term.vt_setactivate(vt)?;
        eprintln!("session worker: switch to VT {} complete", vt);
    }

    // Hook up std(in|out|err). This allows us to run console applications.
    // Also, hooking up stdin is required, as applications otherwise fail to
    // start, both for graphical and console-based applications. I do not
    // know why this is the case.
    target_term.term_connect_pipes()?;

    // We no longer need these, so close them to avoid inheritance.
    drop(target_term);

    // Prepare some values from the user struct we gathered earlier.
    let username = user.name().to_str().unwrap_or("");
    let home = user.home_dir().to_str().unwrap_or("");
    let shell = user.shell().to_str().unwrap_or("");
    let uid = Uid::from_raw(user.uid());
    let gid = Gid::from_raw(user.primary_group_id());

    // PAM has to be provided a bunch of environment variables before
    // open_session. We pass any environment variables from our greeter
    // through here as well. This allows them to affect PAM (more
    // specifically, pam_systemd.so), as well as make it easier to gather
    // and set all environment variables later.
    let prepared_env = [
        "XDG_SEAT=seat0".to_string(),
        format!("XDG_SESSION_CLASS={}", class),
        format!("XDG_VTNR={}", vt),
        format!("USER={}", username),
        format!("LOGNAME={}", username),
        format!("HOME={}", home),
        format!("SHELL={}", shell),
    ];

    for e in prepared_env.iter().chain(env.iter()) {
        pam.putenv(e)
            .map_err(|e| format!("unable to set PAM environment: {}", e))?;
    }

    // Tell PAM what TTY we're targetting, which is used by logind.
    pam.set_item(PamItemType::TTY, &format!("/dev/tty{}", vt))
        .map_err(|e| format!("unable to set PAM TTY item: {}", e))?;

    // Not the credentials you think.
    pam.setcred(PamFlag::ESTABLISH_CRED)
        .map_err(|e| format!("unable to establish PAM credentials: {}", e))?;

    // Session time!
    pam.open_session(PamFlag::NONE)
        .map_err(|e| format!("unable to open PAM session: {}", e))?;

    // Prepare some strings in C format that we'll need.
    let cusername = CString::new(username)?;
    let command = format!("[ -f /etc/profile ] && source /etc/profile; [ -f $HOME/.profile ] && source $HOME/.profile; exec {}", cmd.join(" "));

    // Change working directory
    let pwd = match env::set_current_dir(home) {
        Ok(_) => home,
        Err(_) => {
            env::set_current_dir("/")
                .map_err(|e| format!("unable to set working directory: {}", e))?;
            "/"
        }
    };

    // Check to see if a few necessary variables are there and patch things
    // up as needed.
    let mut fixup_env = vec![
        format!("PWD={}", pwd),
        format!("GREETD_SOCK={}", env::var("GREETD_SOCK").unwrap()),
    ];
    if !pam.hasenv("TERM") {
        fixup_env.push("TERM=linux".to_string());
    }
    if !pam.hasenv("XDG_RUNTIME_DIR") {
        fixup_env.push(format!("XDG_RUNTIME_DIR=/run/user/{}", uid));
    }
    for e in fixup_env.into_iter() {
        pam.putenv(&e)
            .map_err(|e| format!("unable to set PAM environment: {}", e))?;
    }

    // We're almost done with our environment. Let's go through
    // environment.d configuration to fix up the last bits.
    let home = home.to_string();
    generate_user_environment(&mut pam, home)?;

    // Extract PAM environment for use with execve below.
    let pamenvlist = pam
        .getenvlist()
        .map_err(|e| format!("unable to get PAM environment: {}", e))?;
    let envvec = pamenvlist.to_vec();

    // PAM is weird and gets upset if you exec from the process that opened
    // the session, registering it automatically as a log-out. Thus, we must
    // exec in a new child.
    let child = match fork().map_err(|e| format!("unable to fork: {}", e))? {
        ForkResult::Parent { child, .. } => child,
        ForkResult::Child => {
            // It is important that we do *not* return from here by
            // accidentally using '?'. The process *must* exit from within
            // this match arm.

            // Drop privileges to target user
            initgroups(&cusername, gid).expect("unable to init groups");
            setgid(gid).expect("unable to set GID");
            setuid(uid).expect("unable to set UID");

            // Run
            let cpath = CString::new("/bin/sh").unwrap();
            execve(
                &cpath,
                &[
                    &cpath,
                    &CString::new("-c").unwrap(),
                    &CString::new(command).unwrap(),
                ],
                &envvec,
            )
            .expect("unable to exec");

            unreachable!("after exec");
        }
    };

    // Signal the inner PID to the parent process.
    let msg = SessionChildToParent::FinalChildPid(child.as_raw() as u64);
    let data = serde_json::to_vec(&msg)?;
    sock.send(&data)
        .map_err(|e| format!("unable to send message: {}", e))?;
    sock.shutdown(std::net::Shutdown::Both)
        .map_err(|e| format!("unable to close pipe: {}", e))?;

    // Wait for process to terminate, handling EINTR as necessary.
    loop {
        match waitpid(child, None) {
            Err(nix::Error::Sys(nix::errno::Errno::EINTR)) => continue,
            Err(e) => eprintln!("session: waitpid on inner child failed: {}", e),
            Ok(_) => break,
        }
    }

    // Close the session. This step requires root privileges to run, as it
    // will result in various forms of login teardown (including unmounting
    // home folders, telling logind that the session ended, etc.). This is
    // why we cannot drop privileges in this process, but must do it in the
    // inner-most child.
    pam.close_session(PamFlag::NONE)
        .map_err(|e| format!("unable to close PAM session: {}", e))?;
    pam.setcred(PamFlag::DELETE_CRED)
        .map_err(|e| format!("unable to clear PAM credentials: {}", e))?;
    pam.end()
        .map_err(|e| format!("unable to clear PAM credentials: {}", e))?;

    Ok(())
}

pub enum SessionState {
    Question(QuestionStyle, String),
    Ready,
}

impl Session {
    ///
    /// Create a Session object with details required to start the specified
    /// session. Surceeds if the service accepts the credentials.
    ///
    /// This involves creating a PAM handle which will be used to run an
    /// authentication attempt. If successful, this same PAM handle will later
    /// be used to tart the session.
    ///
    pub async fn new(
        service: &str,
        class: &str,
        user: &str,
        cmd: Vec<String>,
        env: Vec<String>,
        vt: usize,
    ) -> Result<Session, Box<dyn Error>> {
        // Pipe used to communicate the true PID of the final child.
        let (parentfd, childfd) = std::os::unix::net::UnixDatagram::pair()
            .map_err(|e| format!("could not create pipe: {}", e))?;

        // PAM requires for unfathmoable reasons that we run this in a
        // subprocess. Things seem to fail otherwise.
        let child = match fork()? {
            ForkResult::Parent { child, .. } => child,
            ForkResult::Child => {
                // It is important that we do *not* return from here by
                // accidentally using '?'. The process *must* exit from within
                // this match arm.

                // Run the child entrypoint.
                if let Err(e) = session_worker(&childfd) {
                    let msg = SessionChildToParent::Error {
                        error: format!("{}", e),
                    };
                    let data = serde_json::to_vec(&msg).expect("unable to serialize message");
                    childfd.send(&data).expect("unable to send message");
                    std::process::exit(1);
                }
                std::process::exit(0);
            }
        };

        let mut sock = tokio::net::UnixDatagram::from_std(parentfd)?;

        let msg = ParentToSessionChild::InitiateLogin {
            service: service.to_string(),
            class: class.to_string(),
            user: user.to_string(),
            vt,
            env,
            cmd,
        };
        let data = serde_json::to_vec(&msg)?;
        sock.send(&data)
            .await
            .map_err(|e| format!("unable to send worker process request: {}", e))?;

        Ok(Session {
            service: service.to_string(),
            opened: Instant::now(),
            task: child,
            sock,
            last_msg: None,
        })
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
            service: self.service.to_string(),
            opened: Instant::now(),
            task: self.task,
            sub_task,
        })
    }

    /// Report how long has elapsed since this session was created.
    pub fn elapsed(&self) -> Duration {
        self.opened.elapsed()
    }
}
