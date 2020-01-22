use std::{env, error::Error, ffi::CString, os::unix::net::UnixDatagram};

use nix::{
    sys::wait::waitpid,
    unistd::{execve, fork, initgroups, setgid, setsid, setuid, ForkResult, Gid, Uid},
};
use pam_sys::{PamFlag, PamItemType};
use serde::{Deserialize, Serialize};
use users::os::unix::UserExt;

use crate::{
    pam::session::PamSession, session_conv::SessionConv, terminal,
    user_environment::generate_user_environment,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum QuestionStyle {
    Visible,
    Secret,
    Info,
    Error,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ParentToSessionChild {
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
pub enum SessionChildToParent {
    PamMessage { style: QuestionStyle, msg: String },
    PamAuthSuccess,
    Error { error: String },
    FinalChildPid(u64),
}

/// The entry point for the session worker process. The session worker is
/// responsible for the entirety of the session setup and execution. It is
/// started by Session::start.
pub fn session_worker(sock: &UnixDatagram) -> Result<(), Box<dyn Error>> {
    let mut data = [0; 10240];
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
