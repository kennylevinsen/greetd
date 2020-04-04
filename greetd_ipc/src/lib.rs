//! # `greetd` IPC protocol library
//!
//! This library implements the [greetd](https://git.sr.ht/~kennylevinsen/greetd) IPC protocol.
//!
//! The library exposes a [Request](enum.Request.html) and a
//! [Response](enum.Response.html) enum, representing the valid protocol
//! messages. Furthermore, codec implementations are available to serialize
//! these to/from both sync and async readers/writers. The availability of
//! these are controlled by feature flags.
//!
//! Additional types are part of the different request and response values.
//!
//! See `agreety` for a simple example use of this library.
//!
//! # Format
//!
//! The message format is as follows:
//!
//! ```text
//! +----------+-------------------+
//! | len: u32 | JSON payload: str |
//! +----------+-------------------+
//! ```
//!
//! Length is in native byte-order. The JSON payload is a variant of the
//! Request or Response enums.
//!
//! # Request and response types
//!
//! See [Request](enum.Request.html) and [Response](enum.Response.html) for
//! information about the request and response types, as well as their
//! serialization.
//!
use serde::{Deserialize, Serialize};

/// A request from a greeter to greetd. The request type is internally tagged
/// with the"type" field, with the type written in snake_case.
///
/// Example serialization:
///
/// ```json
/// {
///    "type": "create_session",
///    "username": "bob"
/// }
/// ```
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "type")]
pub enum Request {
    /// CreateSession initiates a login attempt for the given user.
    /// CreateSession returns either a Response::AuthMessage,
    /// Response::Success or Response::Failure.
    ///
    /// If an auth message is returned, it should be answered with a
    /// Request::PostAuthMessageResponse. If a success is returned, the session
    /// can then be started with Request::StartSession.
    ///
    /// If a login flow needs to be aborted at any point, send
    /// Request::CancelSession. Note that the session is cancelled
    /// automatically on error.
    CreateSession { username: String },

    /// PostAuthMessageResponse responds to the last auth message, and returns
    /// either a Response::AuthMessage, Response::Success or Response::Failure.
    ///
    /// If an auth message is returned, it should be answered with a
    /// Request::PostAuthMessageResponse. If a success is returned, the session
    /// can then be started with Request::StartSession.
    PostAuthMessageResponse { response: Option<String> },

    /// Start a successfully logged in session. This will fail if the session
    /// has pending messages or has encountered an error.
    StartSession { cmd: Vec<String> },

    /// Cancel a session. This can only be done if the session has not been
    /// started. Cancel does not have to be called if an error has been
    /// encountered in its setup or login flow.
    CancelSession,
}

/// An error type for Response::Error. Serialized as snake_case.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorType {
    /// A generic error. See the error description for more details.
    Error,

    /// An error caused by failed authentication.
    AuthError,
}

/// A message type for a Response::AuthMessage. Serialized as snake_case.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMessageType {
    /// A question whose answer should be visible during input.
    Visible,

    /// A question whose answer should be kept secret during input.
    Secret,

    /// An information message.
    Info,

    /// An error message.
    Error,
}

/// A response from greetd to a greeter. The request type is internally tagged
/// with the"type" field, with the type written in snake_case.
///
/// Example serialization:
///
/// ```json
/// {
///    "type": "auth_message",
///    "message": "Password:",
///    "message_type": "secret"
/// }
/// ```
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum Response {
    /// The request was successful.
    Success,

    /// The request failed. See the type and/or description for more
    /// information about this failure.
    Error {
        error_type: ErrorType,
        description: String,
    },

    /// An authentication message needs to be answered to continue through the
    /// authentication flow.
    ///
    /// An authentication message can consist of anything. While it will
    /// commonly just be a request for the users' password, it could also ask
    /// for TOTP codes, or whether or not you felt sad when Littlefoot's mother
    /// died in the original "Land Before Time". It is therefore important that
    /// no assumptions are made about the questions that will be asked, and
    /// attempts to automatically answer these questions should not be made.
    AuthMessage {
        auth_message_type: AuthMessageType,
        auth_message: String,
    },
}

/// Reader/writer codecs for Request/Response.
///
/// This is implemented in the form of two traits, SyncCodec and TokioCodec,
/// which operate on the `std` and `tokio` implementations of reader/writer
/// traits. The former is intended as the name suggests for synchronous
/// operation, while the latter is for asynchronous operation when using tokio.
///
/// These codecs are hidden behind the `sync-codec` and `tokio-codec` features,
/// respectively. These features also implicitly enable the `codec` feature,
/// which controls the entire `codec` module.
///
#[cfg(feature = "codec")]
#[cfg_attr(docsrs, doc(cfg(feature = "codec")))]
pub mod codec {
    use thiserror::Error as ThisError;

    #[derive(Debug, ThisError)]
    pub enum Error {
        #[error("serialization error: {0}")]
        Serialization(String),
        #[error("i/o error: {0}")]
        Io(String),
        #[error("EOF")]
        Eof,
    }

    impl From<serde_json::error::Error> for Error {
        fn from(error: serde_json::error::Error) -> Self {
            Error::Serialization(error.to_string())
        }
    }

    impl From<std::io::Error> for Error {
        fn from(error: std::io::Error) -> Self {
            Error::Io(format!("{}", error))
        }
    }

    /// Synchronous reader/writer implementation, operating on an implementor of std::io::{Read, Write}.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::env;
    /// use std::os::unix::net::UnixStream;
    /// use greetd_ipc::{Request, Response};
    /// use greetd_ipc::codec::SyncCodec;
    ///
    /// fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let mut stream = UnixStream::connect(env::var("GREETD_SOCK")?)?;
    ///     Request::CreateSession { username: "john".to_string() }.write_to(&mut stream)?;
    ///     let resp = Response::read_from(&mut stream)?;
    ///     Ok(())
    /// }
    /// ```
    #[cfg(feature = "sync-codec")]
    mod sync_codec {
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
    }
    #[cfg(feature = "sync-codec")]
    pub use sync_codec::SyncCodec;

    /// Asynchronous reader/writer implementation, operating on an implementor of tokio::io::{AsyncReadExt, AsyncWriteExt}.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::env;
    /// use tokio::net::UnixStream;
    /// use greetd_ipc::{Request, Response};
    /// use greetd_ipc::codec::TokioCodec;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let mut stream = UnixStream::connect(env::var("GREETD_SOCK")?).await?;
    ///     Request::CreateSession { username: "john".to_string() }.write_to(&mut stream).await?;
    ///     let resp = Response::read_from(&mut stream).await?;
    ///     Ok(())
    /// }
    /// ```
    #[cfg(feature = "tokio-codec")]
    mod tokio_codec {
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
    }

    #[cfg(feature = "tokio-codec")]
    pub use tokio_codec::TokioCodec;
}
