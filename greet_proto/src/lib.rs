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

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "type")]
pub enum Request {
    Initiate {
        username: String,
        cmd: Vec<String>,
        env: Vec<String>,
    },
    GetQuestion,
    Answer {
        answer: Option<String>,
    },
    Cancel,
    Start,
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
#[serde(tag = "error_type")]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    InitiateError {
        description: String,
    },
    GetQuestionError {
        description: String,
    },
    AnswerError {
        description: String,
    },
    StartError {
        description: String,
    },
    CancelError {
        description: String,
    },
    ShutdownError {
        action: ShutdownAction,
        description: String,
    },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuestionStyle {
    Visible,
    Secret,
    Info,
    Error,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct Question {
    pub msg: String,
    pub style: QuestionStyle,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum Response {
    Success,
    Question { next_question: Option<Question> },
    Failure(Failure),
}

impl Response {
    pub fn from_slice(bytes: &[u8]) -> Result<Response, Box<dyn Error>> {
        serde_json::from_slice(bytes).map_err(|x| x.into())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        serde_json::to_vec(self).map_err(|x| x.into())
    }
}
