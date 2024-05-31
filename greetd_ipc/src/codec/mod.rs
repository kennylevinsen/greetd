//! Reader/writer codecs for Request/Response.
//!
//! This is implemented in the form of two traits, SyncCodec and TokioCodec,
//! which operate on the `std` and `tokio` implementations of reader/writer
//! traits. The former is intended as the name suggests for synchronous
//! operation, while the latter is for asynchronous operation when using tokio.
//!
//! These codecs are hidden behind the `sync-codec` and `tokio-codec` features,
//! respectively. These features also implicitly enable the `codec` feature,
//! which controls the entire `codec` module.
//!

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

#[cfg_attr(docsrs, doc(cfg(feature = "sync-codec")))]
#[cfg(feature = "sync-codec")]
mod sync;
#[cfg(feature = "sync-codec")]
pub use self::sync::SyncCodec;

#[cfg_attr(docsrs, doc(cfg(feature = "tokio-codec")))]
#[cfg(feature = "tokio-codec")]
mod tokio;
#[cfg(feature = "tokio-codec")]
pub use self::tokio::TokioCodec;
