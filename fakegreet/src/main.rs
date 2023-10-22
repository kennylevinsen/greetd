mod error;

use std::{cell::RefCell, env, rc::Rc, time::Duration};

use tokio::{
    net::{UnixListener, UnixStream},
    process::Command,
    task,
    time::sleep,
};

use crate::error::Error;
use greetd_ipc::{
    codec::{Error as CodecError, TokioCodec},
    AuthMessageType, ErrorType, Request, Response,
};

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

struct InnerContext {
    user: Option<String>,
    password: Option<String>,
    ok: bool,
}

struct Context {
    inner: RefCell<InnerContext>,
}

impl Context {
    fn new() -> Context {
        Context {
            inner: RefCell::new(InnerContext {
                user: None,
                password: None,
                ok: false,
            }),
        }
    }

    async fn create_session(&self, username: String) -> Result<(), Error> {
        self.inner.borrow_mut().user = Some(username);
        Ok(())
    }

    async fn get_question(&self) -> Result<Option<(AuthMessageType, String)>, Error> {
        let s = self.inner.borrow();
        if s.ok {
            Ok(None)
        } else if s.user.is_none() {
            Ok(Some((AuthMessageType::Visible, "User:".to_string())))
        } else if s.password.is_none() {
            Ok(Some((AuthMessageType::Secret, "Password:".to_string())))
        } else {
            Ok(Some((AuthMessageType::Visible, "7 + 2:".to_string())))
        }
    }

    async fn post_response(&self, response: Option<String>) -> Result<(), Error> {
        let mut s = self.inner.borrow_mut();
        if s.ok {
            return Err(Error::Error("wat".to_string()));
        }
        if s.user.is_none() {
            s.user = response;
        } else if s.password.is_none() {
            s.password = response;
        } else {
            if s.user != Some("user".to_string())
                || s.password != Some("password".to_string())
                || response != Some("9".to_string())
            {
                sleep(Duration::from_millis(2000)).await;
                return Err(Error::AuthError("nope".to_string()));
            }
            s.ok = true;
        }
        Ok(())
    }

    async fn start(&self, _cmd: Vec<String>) -> Result<(), Error> {
        if !self.inner.borrow().ok {
            return Err(Error::Error("not yet dammit".to_string()));
        }
        sleep(Duration::from_millis(5000)).await;
        Ok(())
    }

    async fn cancel(&self) -> Result<(), Error> {
        let mut s = self.inner.borrow_mut();
        s.user = None;
        s.password = None;
        s.ok = false;
        Ok(())
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

        println!("req: {:?}", req);
        let resp = match req {
            Request::CreateSession { username } => match ctx.create_session(username).await {
                Ok(()) => client_get_question(ctx).await,
                res => wrap_result(res),
            },
            Request::PostAuthMessageResponse { response } => {
                match ctx.post_response(response).await {
                    Ok(()) => client_get_question(ctx).await,
                    res => wrap_result(res),
                }
            }
            Request::StartSession { cmd, env: _ } => wrap_result(ctx.start(cmd).await),
            Request::CancelSession => wrap_result(ctx.cancel().await),
        };

        if let Response::Error { .. } = resp {
            ctx.cancel().await?;
        }

        println!("resp: {:?}", resp);
        resp.write_to(&mut s).await?;
    }
}

pub async fn server() -> Result<(), Error> {
    let mut path = env::current_dir()?;
    let current_dir = format!(
        "{}/greetd.sock",
        std::fs::canonicalize(&path).unwrap().to_str().unwrap(),
    );
    path.push("greetd.sock");

    std::env::set_var("GREETD_SOCK", &current_dir);

    let _ = std::fs::remove_file(&path);
    let listener =
        UnixListener::bind(&path).map_err(|e| format!("unable to open listener: {}", e))?;

    let arg = env::args().nth(1).expect("need argument");
    let _ = Command::new("sh").arg("-c").arg(arg).spawn()?;

    let ctx = Rc::new(Context::new());

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let ctx = ctx.clone();
                task::spawn_local(async move {
                    if let Err(e) = client_handler(&ctx, stream).await {
                        eprintln!("client loop failed: {}", e);
                    }
                });
            }
            Err(err) => return Err(format!("accept: {}", err).into()),
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let res = task::LocalSet::new()
        .run_until(async move { server().await })
        .await;
    if let Err(e) = res {
        eprintln!("error: {}", e);
    }
}
