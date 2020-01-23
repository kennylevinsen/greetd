//! # `greetd` protocol library
//!
//! This library implements the greetd wire protocol.
//!
//! The library exposes a `Request` and a `Response` enum, together with a
//! `Header` type needed to serialize a valid protocol message. Additional
//! types are part of the different request and response values.
//!
//! See `agreety` for a simple example use of this library.

use std::error::Error;
use std::io::Cursor;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub struct Header {
    pub version: u32,
    pub len: u32,
}

impl Header {
    pub const fn len() -> usize {
        4 /* magic */ + 4 /* version */ + 4 /* payload length */
    }

    pub fn new(len: u32) -> Header {
        Header { version: 1, len }
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Header, Box<dyn Error>> {
        let mut cursor = Cursor::new(bytes);

        let proto_magic = cursor.read_u32::<LittleEndian>()?;
        if proto_magic != 0xAFBF_CFDF {
            return Err("invalid message magic".into());
        }

        let version = cursor.read_u32::<LittleEndian>()?;
        let len = cursor.read_u32::<LittleEndian>()?;

        Ok(Header { version, len })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut buf = Vec::new();
        buf.write_u32::<LittleEndian>(0xAFBF_CFDF)?;
        buf.write_u32::<LittleEndian>(self.version)?;
        buf.write_u32::<LittleEndian>(self.len)?;
        Ok(buf)
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum ShutdownAction {
    Poweroff,
    Reboot,
    Exit,
}

/// A request from a greeter to greetd.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "type")]
pub enum Request {
    /// CreateSession initiates a login attempt for the given user.
    /// CreateSession returns either a Response::Question, Response::Success or
    /// Response::Failure.
    ///
    /// If a question is returned, it should be answered with a
    /// Request::AnswerAuthQuestion. If a success is returned, the session can
    /// then be started with Request::StartSession.
    ///
    /// If a login flow needs to be aborted at any point, send
    /// Request::CancelSession. Note that the session is cancelled
    /// automatically on error.
    CreateSession {
        username: String,
    },

    /// AnswerAuthQuestion answers the last auth question, and returns either
    /// a Response::Question, Response::Success or Response::Failure.
    ///
    /// If a question is returned, it should be answered with a
    /// Request::AnswerAuthQuestion. If a success is returned, the session can
    /// then be started with Request::StartSession.
    AnswerAuthQuestion {
        answer: Option<String>,
    },

    /// Start a successfully logged in session. This will fail if the session
    /// has pending questions or has encountered an error.
    StartSession {
        cmd: Vec<String>,
        env: Vec<String>,
    },

    /// Cancel a session. This can only be done if the session has not been
    /// started. Cancel does not have to be called if an error has been
    /// encountered in its setup or login flow.
    CancelSession,

    /// Execute a machine shutdown action.
    Shutdown {
        action: ShutdownAction,
    },
}

impl Request {
    pub fn from_slice(bytes: &[u8]) -> Result<Request, Box<dyn Error>> {
        serde_json::from_slice(bytes).map_err(|x| x.into())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        serde_json::to_vec(self).map_err(|x| x.into())
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorType {
    /// A generic error. See the error description for more details.
    Error,

    /// An error caused by failed authentication.
    AuthError,
}

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

/// A response from greetd to a greeter.
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum Response {
    /// The request was successful.
    Success,

    /// The request failed. See the type and/or description for more
    /// information about this failure.
    Error { error_type: ErrorType, description: String },

    /// An authentication question needs to be answered to continue through the
    /// authentication flow.
    ///
    /// An authentication question can consist of anything. While it will
    /// commonly just be a request for the users' password, it could also ask
    /// for TOTP codes, or whether or not you felt sad when Littlefoot's mother
    /// died in the original "Land Before Time". It is therefore important that
    /// no assumptions are made about the questions that will be asked, and
    /// attempts to automatically answer these questions should not be made.
    AuthQuestion{ question: String, style: QuestionStyle },
}

impl Response {
    pub fn from_slice(bytes: &[u8]) -> Result<Response, Box<dyn Error>> {
        serde_json::from_slice(bytes).map_err(|x| x.into())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        serde_json::to_vec(self).map_err(|x| x.into())
    }
}
