use std::{
    env, fs,
    io::{self, BufRead},
    os::unix::net::UnixStream,
};

use getopts::Options;
use ini::Ini;
use nix::sys::utsname::uname;
use rpassword::prompt_password_stderr;

use greet_proto::{ErrorType, QuestionStyle, Request, Response};

fn prompt_stderr(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    let mut stdin_iter = stdin.lock().lines();
    eprint!("{}", prompt);
    Ok(stdin_iter.next().unwrap()?)
}

fn get_distro_name() -> String {
    Ini::load_from_file("/etc/os-release")
        .ok()
        .and_then(|file| {
            let section = file.general_section();
            Some(
                section
                    .get("PRETTY_NAME")
                    .unwrap_or(&"Linux".to_string())
                    .to_string(),
            )
        })
        .unwrap_or_else(|| "Linux".to_string())
}

fn get_issue() -> Result<String, Box<dyn std::error::Error>> {
    let vtnr: usize = env::var("XDG_VTNR")
        .unwrap_or_else(|_| "0".to_string())
        .parse()
        .expect("unable to parse VTNR");
    let uts = uname();
    Ok(fs::read_to_string("/etc/issue")?
        .replace("\\S", &get_distro_name())
        .replace("\\l", &format!("tty{}", vtnr))
        .replace("\\s", &uts.sysname())
        .replace("\\r", &uts.release())
        .replace("\\v", &uts.version())
        .replace("\\n", &uts.nodename())
        .replace("\\m", &uts.machine())
        .replace("\\\\", "\\"))
}

enum LoginResult {
    Success,
    Failure,
}

fn login(node: &str, cmd: &Option<String>) -> Result<LoginResult, Box<dyn std::error::Error>> {
    let username = prompt_stderr(&format!("{} login: ", node))?;
    let mut stream = UnixStream::connect(env::var("GREETD_SOCK")?)?;

    let mut next_request = Request::CreateSession { username };
    let mut starting = false;
    loop {
        next_request.write_to(&mut stream)?;

        match Response::read_from(&mut stream)? {
            Response::AuthQuestion { question, style } => {
                let answer = match style {
                    QuestionStyle::Visible => prompt_stderr(&question)?,
                    QuestionStyle::Secret => prompt_password_stderr(&question)?,
                    QuestionStyle::Info => {
                        eprintln!("info: {}", question);
                        "".to_string()
                    }
                    QuestionStyle::Error => {
                        eprintln!("error: {}", question);
                        "".to_string()
                    }
                };

                next_request = Request::AnswerAuthQuestion {
                    answer: Some(answer),
                };
            }
            Response::Success => {
                if starting {
                    return Ok(LoginResult::Success);
                } else {
                    starting = true;
                    let command = match cmd {
                        Some(cmd) => cmd.to_string(),
                        None => prompt_stderr("Command: ")?,
                    };
                    next_request = Request::StartSession {
                        env: vec![
                            format!("XDG_SESSION_DESKTOP={}", &command),
                            format!("XDG_CURRENT_DESKTOP={}", &command),
                        ],
                        cmd: vec![command.to_string()],
                    }
                }
            }
            Response::Error {
                error_type,
                description,
            } => match error_type {
                ErrorType::AuthError => return Ok(LoginResult::Failure),
                ErrorType::Error => return Err(format!("login error: {:?}", description).into()),
            },
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
            println!("{}", f.to_string());
            print_usage(&program, opts);
            std::process::exit(1);
        }
    };
    if matches.opt_present("h") {
        print_usage(&program, opts);
        std::process::exit(0);
    }

    let cmd = matches.opt_default("cmd", "");
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

    let uts = uname();
    for _ in 0..max_failures {
        match login(uts.nodename(), &cmd) {
            Ok(LoginResult::Success) => break,
            Ok(LoginResult::Failure) => eprintln!("Login incorrect\n"),
            Err(e) => eprintln!("error: {}", e),
        }
    }
}
