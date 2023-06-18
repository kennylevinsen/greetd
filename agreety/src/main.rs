use std::{
    env, fs,
    io::{self, BufRead},
    os::unix::net::UnixStream,
};

use enquote::unquote;
use getopts::Options;
use nix::sys::utsname::uname;
use rpassword::prompt_password_stderr;

use greetd_ipc::{codec::SyncCodec, AuthMessageType, ErrorType, Request, Response};

fn maybe_unquote(s: &str) -> Result<String, Box<dyn std::error::Error>> {
    Ok(match s.chars().next() {
        Some('"') | Some('\'') => unquote(s)?,
        _ => s.to_string(),
    })
}

fn prompt_stderr(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    let mut stdin_iter = stdin.lock().lines();
    eprint!("{}", prompt);
    Ok(stdin_iter.next().ok_or("no input")??)
}

fn get_distro_name() -> Result<String, Box<dyn std::error::Error>> {
    let os_release = fs::read_to_string("/etc/os-release")?;
    let parsed = inish::parse(&os_release)?;
    let general = parsed.get("").ok_or("no general section")?;
    maybe_unquote(general.get("PRETTY_NAME").ok_or("no pretty name")?)
}

fn get_issue() -> Result<String, Box<dyn std::error::Error>> {
    let vtnr: usize = env::var("XDG_VTNR")
        .unwrap_or_else(|_| "0".to_string())
        .parse()
        .expect("unable to parse VTNR");
    let uts = uname()?;
    Ok(fs::read_to_string("/etc/issue")?
        .replace(
            "\\S",
            &get_distro_name().unwrap_or_else(|_| "Linux".to_string()),
        )
        .replace("\\l", &format!("tty{}", vtnr))
        .replace("\\s", uts.sysname().to_str().unwrap())
        .replace("\\r", uts.release().to_str().unwrap())
        .replace("\\v", uts.version().to_str().unwrap())
        .replace("\\n", uts.nodename().to_str().unwrap())
        .replace("\\m", uts.machine().to_str().unwrap())
        .replace("\\\\", "\\"))
}

enum LoginResult {
    Success,
    Failure,
}

fn login(node: &str, cmd: &mut Option<String>) -> Result<LoginResult, Box<dyn std::error::Error>> {
    let username = loop {
        let username = prompt_stderr(&format!("{} login: ", node))?;
        if username.starts_with('!') {
            *cmd = Some(username[1..].to_string());
            eprintln!("Login command changed to: {}", &username[1..]);
            continue;
        }
        break username;
    };

    let mut stream = UnixStream::connect(env::var("GREETD_SOCK")?)?;

    let mut next_request = Request::CreateSession { username };
    let mut starting = false;
    loop {
        next_request.write_to(&mut stream)?;

        match Response::read_from(&mut stream)? {
            Response::AuthMessage {
                auth_message,
                auth_message_type,
            } => {
                let response = match auth_message_type {
                    AuthMessageType::Visible => Some(prompt_stderr(&auth_message)?),
                    AuthMessageType::Secret => Some(prompt_password_stderr(&auth_message)?),
                    AuthMessageType::Info => {
                        eprintln!("info: {}", auth_message);
                        None
                    }
                    AuthMessageType::Error => {
                        eprintln!("error: {}", auth_message);
                        None
                    }
                };

                next_request = Request::PostAuthMessageResponse { response };
            }
            Response::Success => {
                if starting {
                    return Ok(LoginResult::Success);
                } else {
                    starting = true;
                    let command = match cmd {
                        Some(cmd) => cmd.clone(),
                        None => prompt_stderr("Command: ")?,
                    };
                    next_request = Request::StartSession {
                        env: vec![],
                        cmd: vec![command.to_string()],
                    }
                }
            }
            Response::Error {
                error_type,
                description,
            } => {
                Request::CancelSession.write_to(&mut stream)?;
                match error_type {
                    ErrorType::AuthError => return Ok(LoginResult::Failure),
                    ErrorType::Error => {
                        return Err(format!("login error: {:?}", description).into())
                    }
                }
            }
        }
    }
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let mut opts = Options::new();
    opts.optflag("h", "help", "print this help menu");
    opts.optopt("c", "cmd", "command to run", "COMMAND");
    opts.optopt(
        "f",
        "max-failures",
        "maximum number of accepted failures",
        "FAILURES",
    );
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            println!("{}", f);
            print_usage(&program, opts);
            std::process::exit(1);
        }
    };
    if matches.opt_present("h") {
        print_usage(&program, opts);
        std::process::exit(0);
    }

    let mut cmd = matches.opt_default("cmd", "");
    let max_failures: usize = match matches.opt_get("max-failures") {
        Ok(v) => v.unwrap_or(5),
        Err(e) => {
            eprintln!("unable to parse max failures: {}", e);
            std::process::exit(1)
        }
    };

    if let Ok(issue) = get_issue() {
        print!("{}", issue);
    }

    let uts = uname().unwrap();
    for _ in 0..max_failures {
        match login(uts.nodename().to_str().unwrap(), &mut cmd) {
            Ok(LoginResult::Success) => break,
            Ok(LoginResult::Failure) => eprintln!("Login incorrect\n"),
            Err(e) => {
                eprintln!("error: {}", e);
                std::process::exit(1);
            }
        }
    }
}
