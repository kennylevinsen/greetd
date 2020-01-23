mod config;
mod context;
mod pam;
mod scrambler;
mod session;
mod session_conv;
mod session_worker;
mod terminal;
mod user_environment;

use std::{
    error::Error,
    io,
    os::unix::{
        io::{FromRawFd, RawFd},
        net::UnixDatagram,
    },
    rc::Rc,
};

use nix::{
    sys::mman::{mlockall, MlockAllFlags},
    unistd::{chown, Gid, Uid},
};

use tokio::{
    net::{UnixListener, UnixStream},
    prelude::*,
    signal::unix::{signal, SignalKind},
    stream::StreamExt,
    task,
};

use greet_proto::{Header, Request, Response, ErrorType};

use crate::{
    config::VtSelection, context::Context, scrambler::Scrambler, session_worker::session_worker,
    terminal::Terminal,
};

fn reset_vt(vt: usize) -> Result<(), Box<dyn Error>> {
    let term = Terminal::open(vt)?;
    term.kd_setmode(terminal::KdMode::Text)?;
    term.vt_setactivate(vt)?;
    Ok(())
}

async fn client(ctx: Rc<Context>, mut s: UnixStream) -> Result<(), Box<dyn Error>> {
    loop {
        let mut header_bytes = [0; Header::len()];

        s.read_exact(&mut header_bytes[..]).await?;
        let header = Header::from_slice(&header_bytes)
            .map_err(|e| format!("unable to deserialize header: {}", e))?;
        if header.version != 1 {
            return Err(io::Error::new(io::ErrorKind::Other, "invalid message version").into());
        }

        let mut body_bytes = vec![0; header.len as usize];
        s.read_exact(&mut body_bytes[..]).await?;

        let req = Request::from_slice(&body_bytes)
            .map_err(|e| format!("unable to deserialize request: {}", e))?;
        body_bytes.scramble();

        let resp = match req {
            Request::CreateSession { username} => {
                match ctx.create_session(username).await {
                    Ok(()) => {
                        match ctx.get_question().await {
                            Ok(Some((style, msg))) => Response::AuthQuestion{ style, question: msg },
                            Ok(None) => Response::Success,
                            Err(e) => Response::Error{ error_type: ErrorType::AuthError, description: format!("{}", e) },
                        }
                    }
                    Err(e) => Response::Error{ error_type: ErrorType::Error, description: format!("{}", e)},
                }
            }
            Request::AnswerAuthQuestion { answer } => match ctx.post_answer(answer).await {
                Ok(()) => {
                    match ctx.get_question().await {
                        Ok(Some((style, msg))) => Response::AuthQuestion{ style, question: msg },
                        Ok(None) => Response::Success,
                        Err(e) => Response::Error{ error_type: ErrorType::AuthError, description: format!("{}", e) },
                    }
                }
                Err(e) => Response::Error{ error_type: ErrorType::Error, description: format!("{}", e)},
            },
            Request::StartSession { cmd, env } => match ctx.start(cmd, env).await {
                Ok(_) => Response::Success,
                Err(e) => Response::Error{ error_type: ErrorType::Error, description: format!("{}", e)},
            },
            Request::CancelSession => match ctx.cancel().await {
                Ok(_) => Response::Success,
                Err(e) => Response::Error{ error_type: ErrorType::Error, description: format!("{}", e)},
            },
            Request::Shutdown { action } => match ctx.shutdown(action).await {
                Ok(_) => Response::Success,
                Err(e) => Response::Error{ error_type: ErrorType::Error, description: format!("{}", e)},
            },
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

async fn server_main(config: config::Config) -> Result<(), Box<dyn Error>> {
    eprintln!("starting greetd");

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
                let ctx1 = ctx.clone();
                task::spawn_local(async move {
                    if let Err(e) = client(ctx1, stream).await {
                        eprintln!("client loop failed: {}", e);
                    }
                });
            }
            Err(e) => eprintln!("accept failed: {}", e),
        }
    }
    Ok(())
}

async fn session_worker_main(config: config::Config) -> Result<(), Box<dyn Error>> {
    let sock = unsafe { UnixDatagram::from_raw_fd(config.session_worker as RawFd) };
    session_worker(&sock)
}

#[tokio::main]
async fn main() {
    let config = config::read_config();
    mlockall(MlockAllFlags::all()).expect("unable to lock pages");
    task::LocalSet::new()
        .run_until(async move {
            if config.session_worker > 0 {
                if let Err(e) = session_worker_main(config).await {
                    eprintln!("error: {}", e);
                }
            } else if let Err(e) = server_main(config).await {
                eprintln!("error: {}", e);
            }
        })
        .await
}
