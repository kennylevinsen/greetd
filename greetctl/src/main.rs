use std::env;
use std::io::{self, BufRead, Write};
use std::os::unix::net::UnixStream;

use byteorder::{LittleEndian, WriteBytesExt};
use rpassword::prompt_password_stderr;

fn prompt_stderr(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    let mut stdin_iter = stdin.lock().lines();
    eprint!("{}", prompt);
    Ok(stdin_iter.next().unwrap()?)
}

fn login(
    username: String,
    password: String,
    cmd: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let msg_len = username.len() + password.len() + cmd.len() + 12;
    let mut buf = Vec::with_capacity(msg_len + 16);
    buf.write_u32::<LittleEndian>(0xAFBFCFDF)?; // Proto Magic
    buf.write_u32::<LittleEndian>(1)?; // Proto version
    buf.write_u32::<LittleEndian>(1)?; // Message type
    buf.write_u32::<LittleEndian>(msg_len as u32)?; // Payload length
    buf.write_u32::<LittleEndian>(username.len() as u32)?;
    buf.extend(username.into_bytes());
    buf.write_u32::<LittleEndian>(password.len() as u32)?;
    buf.extend(password.into_bytes());
    buf.write_u32::<LittleEndian>(cmd.len() as u32)?;
    buf.extend(cmd.into_bytes());

    let mut stream = UnixStream::connect(env::var("GREETD_SOCK")?)?;
    stream.write_all(&buf)?;
    Ok(())
}

fn main() {
    let username = prompt_stderr("Username: ").unwrap();
    let password = prompt_password_stderr("Password: ").unwrap();
    let command = prompt_stderr("Command: ").unwrap();
    login(username, password, command).unwrap();
}
