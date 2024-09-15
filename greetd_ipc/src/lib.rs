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
#![cfg_attr(docsrs, feature(doc_cfg))]
use serde::{Deserialize, Serialize};

#[cfg(feature = "codec")]
#[cfg_attr(docsrs, doc(cfg(feature = "codec")))]
pub mod codec;

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
#[derive(Clone, Debug, Deserialize, Serialize)]
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
    StartSession {
        cmd: Vec<String>,
        #[serde(default)]
        env: Vec<String>,
    },

    /// Cancel a session. This can only be done if the session has not been
    /// started. Cancel does not have to be called if an error has been
    /// encountered in its setup or login flow.
    CancelSession,
}

/// An error type for Response::Error. Serialized as snake_case.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorType {
    /// A generic error. See the error description for more details.
    Error,

    /// An error caused by failed authentication.
    AuthError,
}

/// A message type for a Response::AuthMessage. Serialized as snake_case.
#[derive(Clone, Debug, Deserialize, Serialize)]
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
#[derive(Clone, Debug, Deserialize, Serialize)]
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
