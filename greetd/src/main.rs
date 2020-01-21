mod config;
mod context;
mod pam;
mod scrambler;
mod session;
mod terminal;

use std::{error::Error, io, rc::Rc};

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

use greet_proto::{Failure, Header, Request, Response};

use crate::{config::VtSelection, context::Context, scrambler::Scrambler, terminal::Terminal};

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
            Request::Initiate { username, cmd, env } => {
                match ctx.initiate(username, cmd, env).await {
                    Ok(_) => Response::Success,
                    Err(e) => Response::Failure(Failure::InitiateError {
                        description: format!("{}", e),
                    }),
                }
            }
            Request::Start => match ctx.start().await {
                Ok(_) => Response::Success,
                Err(e) => Response::Failure(Failure::StartError {
                    description: format!("{}", e),
                }),
            },
            Request::GetQuestion => match ctx.get_question().await {
                Ok(v) => Response::Question { next_question: v },
                Err(e) => Response::Failure(Failure::GetQuestionError {
                    description: format!("{}", e),
                }),
            },
            Request::Cancel => match ctx.cancel().await {
                Ok(_) => Response::Success,
                Err(e) => Response::Failure(Failure::CancelError {
                    description: format!("{}", e),
                }),
            },
            Request::Answer { answer } => match ctx.post_answer(answer).await {
                Ok(_) => Response::Success,
                Err(e) => Response::Failure(Failure::AnswerError {
                    description: format!("{}", e),
                }),
            },
            Request::Shutdown { action } => match ctx.shutdown(action).await {
                Ok(_) => Response::Success,
                Err(e) => Response::Failure(Failure::ShutdownError {
                    action,
                    description: format!("{}", e),
                }),
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

#[tokio::main]
async fn main() {
    mlockall(MlockAllFlags::all()).expect("unable to lock pages");

    let config = config::read_config();

    eprintln!("starting greetd");

    std::env::set_var("GREETD_SOCK", &config.socket_path);

    let _ = std::fs::remove_file(config.socket_path.clone());
    let mut listener = UnixListener::bind(&config.socket_path).expect("unable to create listener");

    let u = users::get_user_by_name(&config.greeter_user).expect("unable to get user struct");
    let uid = Uid::from_raw(u.uid());
    let gid = Gid::from_raw(u.primary_group_id());
    chown(config.socket_path.as_str(), Some(uid), Some(gid))
        .expect("unable to chown greetd socket");

    let term = Terminal::open(0).expect("unable to open controlling terminal");
    let vt = match config.vt() {
        VtSelection::Current => term.vt_get_current().expect("unable to get current VT"),
        VtSelection::Next => term.vt_get_next().expect("unable to get next VT"),
        VtSelection::Specific(v) => v,
    };
    drop(term);

    let ctx = Rc::new(Context::new(config.greeter, config.greeter_user, vt));
    if let Err(e) = ctx.greet().await {
        eprintln!("unable to start greeter: {}", e);
        reset_vt(vt).expect("unable to reset vt");
        std::process::exit(1);
    }

    let mut incoming = listener.incoming();

    task::LocalSet::new()
        .run_until(async move {
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
                let mut term =
                    signal(SignalKind::terminate()).expect("unable to listen for SIGTERM");
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
        })
        .await;
}
