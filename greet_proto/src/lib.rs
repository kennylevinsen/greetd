//! # `greetd` protocol library
//!
//! This library implements the greetd wire protocol.
//!
//! The library exposes a [Request](enum.Request.html) and a
//! [Response](enum.Response.html) enum, representing the valid protocol
//! messages, without the length marker.length
//!
//! Additional types are part of the different request and response values.
//!
//! See `agreety` for a simple example use of this library.
//!
//! # Format
//!
//! The message format is as follows:
//!
//! ```
//! +----------+-------------------+
//! | len: u32 | JSON payload: str |
//! +----------+-------------------+
//! ```
//!
//! Length is in native byte-order.
//!
//! # Request and response types
//!
//! See [Request](enum.Request.html) and [Response](enum.Response.html) for
//! information about the request and response types, as well as their
//! serialization.
//!
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    io::{Read, Write},
};

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
    /// CreateSession returns either a Response::AuthQuestion,
    /// Response::Success or Response::Failure.
    ///
    /// If a question is returned, it should be answered with a
    /// Request::AnswerAuthQuestion. If a success is returned, the session can
    /// then be started with Request::StartSession.
    ///
    /// If a login flow needs to be aborted at any point, send
    /// Request::CancelSession. Note that the session is cancelled
    /// automatically on error.
    CreateSession { username: String },

    /// AnswerAuthQuestion answers the last auth question, and returns either
    /// a Response::AuthQuestion, Response::Success or Response::Failure.
    ///
    /// If a question is returned, it should be answered with a
    /// Request::AnswerAuthQuestion. If a success is returned, the session can
    /// then be started with Request::StartSession.
    AnswerAuthQuestion { answer: Option<String> },

    /// Start a successfully logged in session. This will fail if the session
    /// has pending questions or has encountered an error.
    StartSession { cmd: Vec<String>, env: Vec<String> },

    /// Cancel a session. This can only be done if the session has not been
    /// started. Cancel does not have to be called if an error has been
    /// encountered in its setup or login flow.
    CancelSession,
}

impl Request {
    pub fn from_slice(bytes: &[u8]) -> Result<Request, Box<dyn Error>> {
        serde_json::from_slice(bytes).map_err(|x| x.into())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        serde_json::to_vec(self).map_err(|x| x.into())
    }

    pub fn read_from<T: Read>(stream: &mut T) -> Result<Request, Box<dyn Error>> {
        let mut len_bytes = [0; 4];
        stream.read_exact(&mut len_bytes)?;
        let len = u32::from_ne_bytes(len_bytes);

        let mut resp_buf = vec![0; len as usize];
        stream.read_exact(&mut resp_buf)?;
        Request::from_slice(&resp_buf)
    }

    pub fn write_to<T: Write>(&self, stream: &mut T) -> Result<(), Box<dyn Error>> {
        let req_bytes = self.to_bytes()?;
        let len_bytes = req_bytes.len().to_ne_bytes();
        stream.write_all(&len_bytes)?;
        stream.write_all(&req_bytes)?;
        Ok(())
    }
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

/// A question style for a Response::AuthQuestion. Serialized as snake_case.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuestionStyle {
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
///    "type": "auth_question",
///    "question": "Password:",
///    "style": "secret"
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

    /// An authentication question needs to be answered to continue through the
    /// authentication flow.
    ///
    /// An authentication question can consist of anything. While it will
    /// commonly just be a request for the users' password, it could also ask
    /// for TOTP codes, or whether or not you felt sad when Littlefoot's mother
    /// died in the original "Land Before Time". It is therefore important that
    /// no assumptions are made about the questions that will be asked, and
    /// attempts to automatically answer these questions should not be made.
    AuthQuestion {
        style: QuestionStyle,
        question: String,
    },
}

impl Response {
    pub fn from_slice(bytes: &[u8]) -> Result<Response, Box<dyn Error>> {
        serde_json::from_slice(bytes).map_err(|x| x.into())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        serde_json::to_vec(self).map_err(|x| x.into())
    }

    pub fn read_from<T: Read>(stream: &mut T) -> Result<Response, Box<dyn Error>> {
        let mut len_bytes = [0; 4];
        stream.read_exact(&mut len_bytes)?;
        let len = u32::from_ne_bytes(len_bytes);

        let mut resp_buf = vec![0; len as usize];
        stream.read_exact(&mut resp_buf)?;
        Response::from_slice(&resp_buf)
    }

    pub fn write_to<T: Write>(&self, stream: &mut T) -> Result<(), Box<dyn Error>> {
        let req_bytes = self.to_bytes()?;
        let len_bytes = req_bytes.len().to_ne_bytes();
        stream.write_all(&len_bytes)?;
        stream.write_all(&req_bytes)?;
        Ok(())
    }
}
