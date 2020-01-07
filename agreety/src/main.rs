use std::env;
use std::io::{self, BufRead, Read, Write};
use std::os::unix::net::UnixStream;
use std::fs;

use clap::{crate_authors, crate_version, App, Arg};
use ini::Ini;
use nix::sys::utsname::uname;
use rpassword::prompt_password_stderr;

use greet_proto::{Header, Request, Response};

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
        .unwrap_or("Linux".to_string())
}

fn get_issue() -> Result<String, Box<dyn std::error::Error>> {
    let vtnr: usize = env::var("XDG_VTNR")
        .unwrap_or("0".to_string())
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
        .replace("\\m", &uts.machine()))
}

fn login(node: &str, cmd: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let username = prompt_stderr(&format!("{} login: ", node)).unwrap();
    let password = prompt_password_stderr("Password: ").unwrap();
    let command = match cmd {
        Some(cmd) => cmd.to_string(),
        None => prompt_stderr("Command: ").unwrap(),
    };

    let request = Request::Login {
        username,
        password,
        env: vec![
            format!("XDG_SESSION_DESKTOP={}", &command),
            format!("XDG_CURRENT_DESKTOP={}", &command),
        ],
        cmd: vec![command],
    };

    // Write request
    let req = request.to_bytes()?;

    let header = Header::new(req.len() as u32);

    let mut stream = UnixStream::connect(env::var("GREETD_SOCK")?)?;
    stream.write_all(&header.to_bytes()?)?;
    stream.write_all(&req)?;

    // Read response
    let mut header_buf = vec![0; Header::len()];
    stream.read_exact(&mut header_buf)?;
    let header = Header::from_slice(&header_buf)?;

    let mut resp_buf = vec![0; header.len as usize];
    stream.read_exact(&mut resp_buf)?;
    let resp = Response::from_slice(&resp_buf)?;

    match resp {
        Response::Success => Ok(()),
        Response::Failure(err) => {
            Err(std::io::Error::new(io::ErrorKind::Other, format!("login error: {:?}", err)).into())
        }
    }
}

fn main() {
    let matches = App::new("simple_greet")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Simple greeter for greetd")
        .arg(
            Arg::with_name("command")
                .short("c")
                .long("cmd")
                .takes_value(true)
                .help("command to run"),
        )
        .arg(
            Arg::with_name("max-failures")
                .short("f")
                .long("max-failures")
                .takes_value(true)
                .help("maximum number of accepted failures"),
        )
        .get_matches();

    let cmd = matches.value_of("command");
    let max_failures: usize = match matches.value_of("max-failures").unwrap_or("5").parse() {
        Ok(v) => v,
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
        match login(uts.nodename(), cmd) {
            Ok(()) => {
                break;
            }
            Err(_) => {
                eprintln!("");
            }
        }
    }
}
