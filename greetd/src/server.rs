use std::rc::Rc;

use nix::unistd::{chown, Gid, Uid};
use tokio::{
    io as tokio_io,
    net::{UnixListener, UnixStream},
    prelude::*,
    signal::unix::{signal, SignalKind},
    stream::StreamExt,
    task,
};

use crate::{
    config::{Config, VtSelection},
    context::Context,
    error::Error,
    scrambler::Scrambler,
    terminal,
    terminal::Terminal,
};
use greet_proto::{ErrorType, Header, Request, Response};

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
        Ok(Some((style, msg))) => Response::AuthQuestion {
            style,
            question: msg,
        },
        res => wrap_result(res),
    }
}

async fn client_handler(ctx: Rc<Context>, mut s: UnixStream) -> Result<(), Error> {
    loop {
        let mut header_bytes = [0; Header::len()];

        match s.read_exact(&mut header_bytes[..]).await {
            Ok(_) => Ok(()),
            Err(e @ tokio_io::Error { .. }) => match e.kind() {
                tokio_io::ErrorKind::UnexpectedEof => return Ok(()),
                _ => Err(e),
            },
        }
        .map_err(|e| format!("unable to read header: {}", e))?;

        let header = Header::from_slice(&header_bytes)
            .map_err(|e| format!("unable to deserialize header: {}", e))?;
        if header.version != 1 {
            return Err("invalid message version".into());
        }

        let mut body_bytes = vec![0; header.len as usize];
        s.read_exact(&mut body_bytes[..])
            .await
            .map_err(|e| format!("unable to read body: {}", e))?;

        let req = Request::from_slice(&body_bytes)
            .map_err(|e| format!("unable to deserialize request: {}", e))?;
        body_bytes.scramble();

        let resp = match req {
            Request::CreateSession { username } => match ctx.create_session(username).await {
                Ok(()) => client_get_question(&ctx).await,
                res => wrap_result(res),
            },
            Request::AnswerAuthQuestion { answer } => match ctx.post_answer(answer).await {
                Ok(()) => client_get_question(&ctx).await,
                res => wrap_result(res),
            },
            Request::StartSession { cmd, env } => wrap_result(ctx.start(cmd, env).await),
            Request::CancelSession => wrap_result(ctx.cancel().await),
        };

        let resp_bytes = resp
            .to_bytes()
            .map_err(|e| format!("unable to serialize response: {}", e))?;
        let header = Header::new(resp_bytes.len() as u32);
        let header_bytes = header
            .to_bytes()
            .map_err(|e| format!("unable to serialize header: {}", e))?;

        s.write_all(&header_bytes).await?;
        s.write_all(&resp_bytes).await?;
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

    let mut incoming = listener.incoming();

    let alarm_ctx = ctx.clone();
    task::spawn_local(async move {
        let mut alarm = signal(SignalKind::alarm()).expect("unable to listen for SIGALRM");
        loop {
            alarm.recv().await;
            alarm_ctx.alarm().await.expect("unable to read alarm");
        }
    });

    let child_ctx = ctx.clone();
    task::spawn_local(async move {
        let mut child = signal(SignalKind::child()).expect("unable to listen for SIGCHLD");
        loop {
            child.recv().await;
            child_ctx
                .check_children()
                .await
                .expect("unable to check children");
        }
    });

    let term_ctx = ctx.clone();
    task::spawn_local(async move {
        let mut term = signal(SignalKind::terminate()).expect("unable to listen for SIGTERM");
        loop {
            term.recv().await;
            term_ctx.terminate().await.expect("unable to terminate");
        }
    });

    while let Some(stream) = incoming.next().await {
        match stream {
            Ok(stream) => {
                let (ctx1, ctx2) = (ctx.clone(), ctx.clone());
                task::spawn_local(async move {
                    if let Err(e) = client_handler(ctx1, stream).await {
                        ctx2.cancel().await.expect("unable to cancel session");
                        eprintln!("client loop failed: {}", e);
                    }
                });
            }
            Err(e) => eprintln!("accept failed: {}", e),
        }
    }
    Ok(())
}
