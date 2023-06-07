use std::{env, ffi::CString, os::unix::net::UnixDatagram};

use nix::{
    sys::wait::waitpid,
    unistd::{execve, fork, initgroups, setgid, setsid, setuid, ForkResult},
};
use pam_sys::{PamFlag, PamItemType};
use serde::{Deserialize, Serialize};

use super::{
    conv::SessionConv,
    prctl::{prctl, PrctlOption},
};
use crate::{error::Error, pam::session::PamSession, terminal};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AuthMessageType {
    Visible,
    Secret,
    Info,
    Error,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TerminalMode {
    Terminal {
        path: String,
        vt: usize,
        switch: bool,
    },
    Stdin,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SessionClass {
    Greeter,
    User,
}

impl SessionClass {
    fn as_str(&self) -> &str {
        match self {
            SessionClass::Greeter => "greeter",
            SessionClass::User => "user",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ParentToSessionChild<'a> {
    InitiateLogin {
        service: &'a str,
        class: SessionClass,
        user: &'a str,
        authenticate: bool,
        tty: TerminalMode,
        source_profile: bool,
        listener_path: &'a str,
    },
    PamResponse {
        resp: Option<String>,
    },
    Args {
        env: Vec<String>,
        cmd: Vec<String>,
    },
    Start,
    Cancel,
}

impl<'a> ParentToSessionChild<'a> {
    pub fn recv(
        sock: &UnixDatagram,
        data: &'a mut [u8; 10240],
    ) -> Result<ParentToSessionChild<'a>, Error> {
        let len = sock.recv(&mut data[..])?;
        let msg = serde_json::from_slice(&data[..len])?;
        Ok(msg)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SessionChildToParent {
    Success,
    Error(Error),
    PamMessage { style: AuthMessageType, msg: String },
    FinalChildPid(u64),
}

impl SessionChildToParent {
    pub fn send(&self, sock: &UnixDatagram) -> Result<(), Error> {
        let out = serde_json::to_vec(self)?;
        sock.send(&out)?;
        Ok(())
    }
}

/// The entry point for the session worker process. The session worker is
/// responsible for the entirety of the session setup and execution. It is
/// started by Session::start.
fn worker(sock: &UnixDatagram) -> Result<(), Error> {
    let mut data = [0; 10240];
    let (service, class, user, authenticate, tty, source_profile, listener_path) =
        match ParentToSessionChild::recv(sock, &mut data)? {
            ParentToSessionChild::InitiateLogin {
                service,
                class,
                user,
                authenticate,
                tty,
                source_profile,
                listener_path,
            } => (
                service,
                class,
                user,
                authenticate,
                tty,
                source_profile,
                listener_path,
            ),
            ParentToSessionChild::Cancel => return Err("cancelled".into()),
            msg => return Err(format!("expected InitiateLogin or Cancel, got: {:?}", msg).into()),
        };

    let conv = Box::pin(SessionConv::new(sock));
    let mut pam = PamSession::start(service, user, conv)?;

    if authenticate {
        pam.authenticate(PamFlag::NONE)?;
    }
    pam.acct_mgmt(PamFlag::NONE)?;

    // Not the credentials you think.
    pam.setcred(PamFlag::ESTABLISH_CRED)?;

    // Mark authentication as a success.
    SessionChildToParent::Success.send(sock)?;

    // Add GREETD_SOCK if this is a greeter session - we do this early as we are about to reuse the
    // buffer, invalidating our borrow.
    if let SessionClass::Greeter = class {
        pam.putenv(&format!("GREETD_SOCK={}", &listener_path))?;
    }

    // Fetch our arguments from the parent.
    let (env, cmd) = match ParentToSessionChild::recv(sock, &mut data)? {
        ParentToSessionChild::Args { env, cmd } => (env, cmd),
        ParentToSessionChild::Cancel => return Err("cancelled".into()),
        msg => return Err(format!("expected Args or Cancel, got: {:?}", msg).into()),
    };

    SessionChildToParent::Success.send(sock)?;

    // Await start request from our parent.
    match ParentToSessionChild::recv(sock, &mut data)? {
        ParentToSessionChild::Start => (),
        ParentToSessionChild::Cancel => return Err("cancelled".into()),
        msg => return Err(format!("expected Start or Cancel, got: {:?}", msg).into()),
    };

    let pam_username = pam.get_user()?;

    let user = nix::unistd::User::from_name(&pam_username)?.ok_or("unable to get user info")?;

    // Make this process a session leader.
    setsid().map_err(|e| format!("unable to become session leader: {}", e))?;

    match tty {
        TerminalMode::Stdin => (),
        TerminalMode::Terminal { path, vt, switch } => {
            // Tell PAM what TTY we're targetting, which is used by logind.
            pam.set_item(PamItemType::TTY, &format!("tty{}", vt))?;
            pam.putenv(&format!("XDG_VTNR={}", vt))?;

            // Opening our target terminal.
            let target_term = terminal::Terminal::open(&path)?;

            // Set the target VT mode to text for compatibility. Other login managers
            // set this to graphics, but that disallows start of textual applications,
            // which greetd aims to support.
            target_term.kd_setmode(terminal::KdMode::Text)?;

            // Clear TTY so that it will be empty when we switch to it.
            target_term.term_clear()?;

            // A bit more work if a VT switch is required.
            if switch && vt != target_term.vt_get_current()? {
                // Perform a switch to the target VT, simultaneously resetting it to
                // VT_AUTO.
                target_term.vt_setactivate(vt)?;
            }

            // Connect std(in|out|err), and make this our controlling TTY.
            target_term.term_connect_pipes()?;
            target_term.term_take_ctty()?;
        }
    }

    // PAM has to be provided a bunch of environment variables before
    // open_session. We pass any environment variables from our greeter
    // through here as well. This allows them to affect PAM (more
    // specifically, pam_systemd.so), as well as make it easier to gather
    // and set all environment variables later.
    let prepared_env = [
        "XDG_SEAT=seat0".to_string(),
        format!("XDG_SESSION_CLASS={}", class.as_str()),
        format!("USER={}", user.name),
        format!("LOGNAME={}", user.name),
        format!("HOME={}", user.dir.to_string_lossy()),
        format!("SHELL={}", user.shell.to_string_lossy()),
        format!(
            "TERM={}",
            env::var("TERM").unwrap_or_else(|_| "linux".to_string())
        ),
    ];
    for e in env.iter().chain(prepared_env.iter()) {
        pam.putenv(e)?;
    }

    // Session time!
    pam.open_session(PamFlag::NONE)?;

    // We are done with PAM, clear variables that the child will not need.
    let cleared_env = ["XDG_SESSION_CLASS", "XDG_VTNR"];
    for e in cleared_env.iter() {
        _ = pam.putenv(e);
    }

    // Prepare some strings in C format that we'll need.
    let cusername = CString::new(user.name)?;
    let command = if source_profile {
        format!(
            "[ -f /etc/profile ] && . /etc/profile; [ -f $HOME/.profile ] && . $HOME/.profile; exec {}",
            cmd.join(" ")
        )
    } else {
        format!("exec {}", cmd.join(" "))
    };

    // Extract PAM environment for use with execve below.
    let pamenvlist = pam.getenvlist()?;
    let envvec = pamenvlist.to_vec();

    // PAM is weird and gets upset if you exec from the process that opened
    // the session, registering it automatically as a log-out. Thus, we must
    // exec in a new child.
    let child = match unsafe { fork() }.map_err(|e| format!("unable to fork: {}", e))? {
        ForkResult::Parent { child, .. } => child,
        ForkResult::Child => {
            // It is important that we do *not* return from here by
            // accidentally using '?'. The process *must* exit from within
            // this match arm.

            // Drop privileges to target user
            initgroups(&cusername, user.gid).expect("unable to init groups");
            setgid(user.gid).expect("unable to set GID");
            setuid(user.uid).expect("unable to set UID");

            // Set our parent death signal. setuid/setgid above resets the
            // death signal, which is why we do this here.
            prctl(PrctlOption::SET_PDEATHSIG(libc::SIGTERM)).expect("unable to set death signal");

            // Change working directory
            if let Err(e) = env::set_current_dir(user.dir) {
                eprintln!("unable to set working directory: {}", e);
            }

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
    SessionChildToParent::FinalChildPid(child.as_raw() as u64).send(sock)?;
    sock.shutdown(std::net::Shutdown::Both)?;

    // Set our parent death signal. setsid above resets the signal, hence our
    // late assignment, which is why we do this here.
    prctl(PrctlOption::SET_PDEATHSIG(libc::SIGTERM))?;

    // Wait for process to terminate, handling EINTR as necessary.
    loop {
        match waitpid(child, None) {
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => {
                eprintln!("session: waitpid on inner child failed: {}", e);
                break;
            }
            Ok(_) => break,
        }
    }

    // Close the session. This step requires root privileges to run, as it
    // will result in various forms of login teardown (including unmounting
    // home folders, telling logind that the session ended, etc.). This is
    // why we cannot drop privileges in this process, but must do it in the
    // inner-most child.
    pam.close_session(PamFlag::NONE)?;
    pam.setcred(PamFlag::DELETE_CRED)?;
    pam.end()?;

    Ok(())
}

pub fn main(sock: &UnixDatagram) -> Result<(), Error> {
    if let Err(e) = worker(sock) {
        SessionChildToParent::Error(e.clone()).send(sock)?;
        Err(e)
    } else {
        Ok(())
    }
}
