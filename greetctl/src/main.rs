use std::env;
use std::io::{self, BufRead, Read, Write};
use std::os::unix::net::UnixStream;

use greet_proto::{Header, Request, Response};

use rpassword::prompt_password_stderr;

fn prompt_stderr(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    let mut stdin_iter = stdin.lock().lines();
    eprint!("{}", prompt);
    Ok(stdin_iter.next().unwrap()?)
}

fn login() -> Result<(), Box<dyn std::error::Error>> {
    let username = prompt_stderr("Username: ").unwrap();
    let password = prompt_password_stderr("Password: ").unwrap();
    let command = prompt_stderr("Command: ").unwrap();

    let request = Request::Login {
        username,
        password,
        cmd: vec![command],
        env: vec![],
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
    loop {
        match login() {
            Ok(()) => {
                eprintln!("authentication successful");
                break;
            }
            Err(err) => eprintln!("error: {:?}", err),
        }
    }
}
