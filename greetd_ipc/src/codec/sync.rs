//! Synchronous reader/writer implementation, operating on an implementor of std::io::{Read, Write}.
//!
//! # Example
//!
//! ```no_run
//! use std::env;
//! use std::os::unix::net::UnixStream;
//! use greetd_ipc::{Request, Response};
//! use greetd_ipc::codec::SyncCodec;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let mut stream = UnixStream::connect(env::var("GREETD_SOCK")?)?;
//!     Request::CreateSession { username: "john".to_string() }.write_to(&mut stream)?;
//!     let resp = Response::read_from(&mut stream)?;
//!     Ok(())
//! }
//! ```

use crate::{codec::Error, Request, Response};
use std::io::{Read, Write};

/// Reader/writer implementation over std::io::{Read,Write}.
pub trait SyncCodec {
    fn read_from<T: Read>(stream: &mut T) -> Result<Self, Error>
    where
        Self: std::marker::Sized;
    fn write_to<T: Write>(&self, stream: &mut T) -> Result<(), Error>;
}

impl SyncCodec for Request {
    fn read_from<T: Read>(stream: &mut T) -> Result<Self, Error> {
        let mut len_bytes = [0; 4];
        stream
            .read_exact(&mut len_bytes)
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::UnexpectedEof => Error::Eof,
                _ => e.into(),
            })?;
        let len = u32::from_ne_bytes(len_bytes);

        let mut resp_buf = vec![0; len as usize];
        stream.read_exact(&mut resp_buf)?;
        serde_json::from_slice(&resp_buf).map_err(|e| e.into())
    }

    fn write_to<T: Write>(&self, stream: &mut T) -> Result<(), Error> {
        let body_bytes = serde_json::to_vec(self)?;
        let len_bytes = (body_bytes.len() as u32).to_ne_bytes();
        stream.write_all(&len_bytes)?;
        stream.write_all(&body_bytes)?;
        Ok(())
    }
}

impl SyncCodec for Response {
    fn read_from<T: Read>(stream: &mut T) -> Result<Self, Error> {
        let mut len_bytes = [0; 4];
        stream
            .read_exact(&mut len_bytes)
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::UnexpectedEof => Error::Eof,
                _ => e.into(),
            })?;
        let len = u32::from_ne_bytes(len_bytes);

        let mut resp_buf = vec![0; len as usize];
        stream.read_exact(&mut resp_buf)?;
        serde_json::from_slice(&resp_buf).map_err(|e| e.into())
    }

    fn write_to<T: Write>(&self, stream: &mut T) -> Result<(), Error> {
        let body_bytes = serde_json::to_vec(self)?;
        let len_bytes = (body_bytes.len() as u32).to_ne_bytes();
        stream.write_all(&len_bytes)?;
        stream.write_all(&body_bytes)?;
        Ok(())
    }
}
