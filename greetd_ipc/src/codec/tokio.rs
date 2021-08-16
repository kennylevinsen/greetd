//! Asynchronous reader/writer implementation, operating on an implementor of tokio::io::{AsyncReadExt, AsyncWriteExt}.
//!
//! # Example
//!
//! ```no_run
//! use std::env;
//! use tokio::net::UnixStream;
//! use greetd_ipc::{Request, Response};
//! use greetd_ipc::codec::TokioCodec;
//!
//! #[tokio::main(flavor = "current_thread")]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let mut stream = UnixStream::connect(env::var("GREETD_SOCK")?).await?;
//!     Request::CreateSession { username: "john".to_string() }.write_to(&mut stream).await?;
//!     let resp = Response::read_from(&mut stream).await?;
//!     Ok(())
//! }
//! ```
use crate::{codec::Error, Request, Response};
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Reader/writer implementation over tokio::io::{AsyncReadExt, AsyncWriteExt}.
#[async_trait]
pub trait TokioCodec {
    async fn read_from<T: AsyncReadExt + std::marker::Unpin + Send>(
        stream: &mut T,
    ) -> Result<Self, Error>
    where
        Self: std::marker::Sized;
    async fn write_to<T: AsyncWriteExt + std::marker::Unpin + Send>(
        &self,
        stream: &mut T,
    ) -> Result<(), Error>;
}

#[async_trait]
impl TokioCodec for Request {
    async fn read_from<T: AsyncReadExt + std::marker::Unpin + Send>(
        stream: &mut T,
    ) -> Result<Self, Error> {
        let mut len_bytes = [0; 4];
        stream
            .read_exact(&mut len_bytes)
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::UnexpectedEof => Error::Eof,
                _ => e.into(),
            })?;
        let len = u32::from_ne_bytes(len_bytes);

        let mut body_bytes = vec![0; len as usize];
        stream.read_exact(&mut body_bytes).await?;
        let body = serde_json::from_slice(&body_bytes)?;
        Ok(body)
    }

    async fn write_to<T: AsyncWriteExt + std::marker::Unpin + Send>(
        &self,
        stream: &mut T,
    ) -> Result<(), Error> {
        let body_bytes = serde_json::to_vec(self)?;
        let len_bytes = (body_bytes.len() as u32).to_ne_bytes();
        stream.write_all(&len_bytes).await?;
        stream.write_all(&body_bytes).await?;
        Ok(())
    }
}

#[async_trait]
impl TokioCodec for Response {
    async fn read_from<T: AsyncReadExt + std::marker::Unpin + Send>(
        stream: &mut T,
    ) -> Result<Self, Error> {
        let mut len_bytes = [0; 4];
        stream
            .read_exact(&mut len_bytes)
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::UnexpectedEof => Error::Eof,
                _ => e.into(),
            })?;
        let len = u32::from_ne_bytes(len_bytes);

        let mut body_bytes = vec![0; len as usize];
        stream.read_exact(&mut body_bytes).await?;
        let body = serde_json::from_slice(&body_bytes)?;
        Ok(body)
    }

    async fn write_to<T: AsyncWriteExt + std::marker::Unpin + Send>(
        &self,
        stream: &mut T,
    ) -> Result<(), Error> {
        let body_bytes = serde_json::to_vec(self)?;
        let len_bytes = (body_bytes.len() as u32).to_ne_bytes();
        stream.write_all(&len_bytes).await?;
        stream.write_all(&body_bytes).await?;
        Ok(())
    }
}
