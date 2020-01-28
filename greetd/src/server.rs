use std::rc::Rc;

use nix::unistd::{chown, Gid, Uid};
use tokio::{
    net::{UnixListener, UnixStream},
    signal::unix::{signal, SignalKind},
    task,
};

use crate::{
    config::{Config, VtSelection},
    context::Context,
    error::Error,
    terminal,
    terminal::Terminal,
};
use greet_proto::{
    codec::{Error as CodecError, TokioCodec},
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

async fn client_handler(ctx: &Context, mut s: UnixStream) -> Result<(), Error> {
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
            Request::StartSession { cmd, env } => wrap_result(ctx.start(cmd, env).await),
            Request::CancelSession => wrap_result(ctx.cancel().await),
        };

        resp.write_to(&mut s).await?;
    }
}

pub async fn main(config: Config) -> Result<(), Error> {
    std::env::set_var("GREETD_SOCK", &config.socket_path);

    let _ = std::fs::remove_file(config.socket_path.clone());
    let mut listener = UnixListener::bind(&config.socket_path)
        .map_err(|e| format!("unable to open listener: {}", e))?;

    let u = users::get_user_by_name(&config.greeter_user).ok_or("unable to get user struct")?;

    let uid = Uid::from_raw(u.uid());
    let gid = Gid::from_raw(u.primary_group_id());
    chown(config.socket_path.as_str(), Some(uid), Some(gid))
        .map_err(|e| format!("unable to chown greetd socket: {}", e))?;

    let term = Terminal::open(0).map_err(|e| format!("unable to open terminal: {}", e))?;

    let vt = match config.vt() {
        VtSelection::Current => term
            .vt_get_current()
            .map_err(|e| format!("unable to get current VT: {}", e))?,
        VtSelection::Next => term
            .vt_get_next()
            .map_err(|e| format!("unable to get next VT: {}", e))?,
        VtSelection::Specific(v) => v,
    };
    drop(term);

    let ctx = Rc::new(Context::new(config.greeter, config.greeter_user, vt));
    if let Err(e) = ctx.greet().await {
        eprintln!("unable to start greeter: {}", e);
        reset_vt(vt).map_err(|e| format!("unable to reset VT: {}", e))?;

        std::process::exit(1);
    }

    let mut alarm = signal(SignalKind::alarm()).expect("unable to listen for SIGALRM");
    let mut child = signal(SignalKind::child()).expect("unable to listen for SIGCHLD");
    let mut term = signal(SignalKind::terminate()).expect("unable to listen for SIGTERM");

    loop {
        tokio::select! {
            _ = child.recv() => ctx.check_children().await.expect("unable to check children"),
            _ = alarm.recv() => ctx.alarm().await.expect("unable to read alarm"),
            _ = term.recv() => ctx.terminate().await.expect("unable to terminate"),
            stream = listener.accept() => match stream {
                Ok((stream, _)) => {
                    let client_ctx = ctx.clone();
                    task::spawn_local(async move {
                        if let Err(e) = client_handler(&client_ctx, stream).await {
                            client_ctx.cancel().await.expect("unable to cancel session");
                            eprintln!("client loop failed: {}", e);
                        }
                    });
                },
                Err(_) => break,
            }
        }
    }
    Ok(())
}
