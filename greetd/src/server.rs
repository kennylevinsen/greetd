use std::{
    convert::TryFrom,
    os::unix::net::{UnixListener, UnixStream},
    path::Path,
    rc::Rc,
};

use futures::future::FutureExt;
use nix::{
    sys::{
        signal::{self, SigSet},
        signalfd::SfdFlags,
    },
    unistd::{chown, Gid, Uid},
};
use smol::{Async, Task};

use crate::{
    config::{Config, VtSelection},
    context::Context,
    error::Error,
    signals::SignalFd,
    terminal::{self, Terminal},
};
use greetd_ipc::{
    codec::{Error as CodecError, FuturesCodec},
    ErrorType, Request, Response,
};

fn reset_vt(vt: usize) -> Result<(), Error> {
    let term = Terminal::open(vt)?;
    term.kd_setmode(terminal::KdMode::Text)?;
    term.vt_setactivate(vt)?;
    Ok(())
}

fn wrap_result<T>(res: Result<T, Error>) -> Response {
    match res {
        Ok(_) => Response::Success,
        Err(Error::AuthError(msg)) => Response::Error {
            error_type: ErrorType::AuthError,
            description: msg,
        },
        Err(e) => Response::Error {
            error_type: ErrorType::Error,
            description: format!("{}", e),
        },
    }
}

async fn client_get_question(ctx: &Context) -> Response {
    match ctx.get_question().await {
        Ok(Some((auth_message_type, auth_message))) => Response::AuthMessage {
            auth_message_type,
            auth_message,
        },
        res => wrap_result(res),
    }
}

async fn client_handler(ctx: &Context, mut s: Async<UnixStream>) -> Result<(), Error> {
    loop {
        let req = match Request::read_from(&mut s).await {
            Ok(req) => req,
            Err(CodecError::Eof) => return Ok(()),
            Err(e) => return Err(e.into()),
        };

        let resp = match req {
            Request::CreateSession { username } => match ctx.create_session(username).await {
                Ok(()) => client_get_question(&ctx).await,
                res => wrap_result(res),
            },
            Request::PostAuthMessageResponse { response } => {
                match ctx.post_response(response).await {
                    Ok(()) => client_get_question(&ctx).await,
                    res => wrap_result(res),
                }
            }
            Request::StartSession { cmd } => wrap_result(ctx.start(cmd).await),
            Request::CancelSession => wrap_result(ctx.cancel().await),
        };

        resp.write_to(&mut s).await?;
    }
}

pub async fn main(config: Config) -> Result<(), Error> {
    std::env::set_var("GREETD_SOCK", &config.internal.socket_path);

    let _ = std::fs::remove_file(&config.internal.socket_path);
    let listener = Async::<UnixListener>::bind(&config.internal.socket_path)
        .map_err(|e| format!("unable to open listener: {}", e))?;

    let service = if Path::new("/etc/pam.d/greetd").exists() {
        "greetd"
    } else if Path::new("/etc/pam.d/login").exists() {
        eprintln!("warning: PAM 'greetd' service missing, falling back to 'login'");
        "login"
    } else {
        return Err("PAM 'greetd' service missing".into());
    };

    let u = users::get_user_by_name(&config.file.default_session.user).ok_or(format!(
        "configured default session user '{}' not found",
        &config.file.default_session.user
    ))?;

    let uid = Uid::from_raw(u.uid());
    let gid = Gid::from_raw(u.primary_group_id());
    chown(config.internal.socket_path.as_str(), Some(uid), Some(gid)).map_err(|e| {
        format!(
            "unable to chown greetd socket at {}: {}",
            &config.internal.socket_path, e
        )
    })?;

    let term = Terminal::open(0).map_err(|e| format!("unable to open terminal: {}", e))?;
    let vt = match config.file.terminal.vt {
        VtSelection::Current => term
            .vt_get_current()
            .map_err(|e| format!("unable to get current VT: {}", e))?,
        VtSelection::Next => term
            .vt_get_next()
            .map_err(|e| format!("unable to get next VT: {}", e))?,
        VtSelection::None => 0,
        VtSelection::Specific(v) => v,
    };
    drop(term);

    let ctx = Rc::new(Context::new(
        config.file.default_session.command,
        config.file.default_session.user,
        vt,
        service.to_string(),
    ));

    if let Some(s) = config.file.initial_session {
        if let Err(e) = ctx.start_user_session(&s.user, vec![s.command]).await {
            eprintln!("unable to start greeter: {}", e);
            reset_vt(vt).map_err(|e| format!("unable to reset VT: {}", e))?;

            std::process::exit(1);
        }
    } else if let Err(e) = ctx.greet().await {
        eprintln!("unable to start greeter: {}", e);
        reset_vt(vt).map_err(|e| format!("unable to reset VT: {}", e))?;

        std::process::exit(1);
    }

    let mut mask = SigSet::empty();
    mask.add(signal::SIGALRM);
    mask.add(signal::SIGCHLD);
    mask.add(signal::SIGTERM);
    mask.thread_block().unwrap();

    let mut sfd = SignalFd::with_flags(&mask, SfdFlags::SFD_NONBLOCK)?;

    loop {
        futures::select! {
            signal = sfd.read_signal().fuse() => match signal {
                Ok(Some(siginfo)) => match signal::Signal::try_from(siginfo.ssi_signo as nix::libc::c_int) {
                    Ok(signal::SIGCHLD) => ctx.check_children().await.map_err(|e| format!("check_children: {}", e))?,
                    Ok(signal::SIGALRM) => ctx.alarm().await.map_err(|e| format!("alarm: {}", e))?,
                    Ok(signal::SIGTERM) => {
                        ctx.terminate().await.map_err(|e| format!("terminate: {}", e))?;
                        break;
                    },
                    _ => ()
                },
                Ok(None) => (),
                Err(err) => return Err(format!("read_signal: {}", err).into()),
            },
            stream = listener.accept().fuse() => match stream {
                Ok((stream, _)) => {
                    let client_ctx = ctx.clone();
                    Task::local(async move {
                        if let Err(e) = client_handler(&client_ctx, stream).await {
                            client_ctx.cancel().await.expect("unable to cancel session");
                            eprintln!("client loop failed: {}", e);
                        }
                    }).detach();
                },
                Err(err) => return Err(format!("accept: {}", err).into()),
            }
        }
    }

    Ok(())
}
