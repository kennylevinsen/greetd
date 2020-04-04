use std::convert::From;

use serde::{Deserialize, Serialize};
use thiserror::Error as ThisError;

#[derive(Debug, ThisError, Clone, Deserialize, Serialize)]
pub enum Error {
    #[error("{0}")]
    Error(String),

    #[error("authentication error: {0}")]
    AuthError(String),

    #[error("protocol error: {0}")]
    ProtocolError(String),

    #[error("i/o error: {0}")]
    Io(String),

    #[error("configuration error: {0}")]
    ConfigError(String),
}

impl From<Box<dyn std::error::Error>> for Error {
    fn from(error: Box<dyn std::error::Error>) -> Self {
        Error::Error(format!("{}", error))
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::Io(format!("{}", error))
    }
}

impl From<crate::pam::PamError> for Error {
    fn from(error: crate::pam::PamError) -> Self {
        Error::AuthError(error.to_string())
    }
}

impl From<greetd_ipc::codec::Error> for Error {
    fn from(error: greetd_ipc::codec::Error) -> Self {
        match error {
            greetd_ipc::codec::Error::Serialization(s) => Error::ProtocolError(s),
            greetd_ipc::codec::Error::Io(s) => Error::Io(s),
            greetd_ipc::codec::Error::Eof => Error::Io("EOF".to_string()),
        }
    }
}

impl From<String> for Error {
    fn from(error: String) -> Self {
        Error::Error(error)
    }
}

impl From<&str> for Error {
    fn from(error: &str) -> Self {
        Error::Error(error.to_string())
    }
}

impl From<serde_json::error::Error> for Error {
    fn from(error: serde_json::error::Error) -> Self {
        Error::ProtocolError(error.to_string())
    }
}

impl From<nix::Error> for Error {
    fn from(error: nix::Error) -> Self {
        Error::Error(error.to_string())
    }
}

impl From<std::ffi::NulError> for Error {
    fn from(error: std::ffi::NulError) -> Self {
        Error::Error(error.to_string())
    }
}

impl From<ini::ini::ParseError> for Error {
    fn from(error: ini::ini::ParseError) -> Self {
        Error::Error(error.to_string())
    }
}
