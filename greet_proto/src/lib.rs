use std::collections::HashMap;
use std::error::Error;
use std::io;

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
        Header {
            version: 1,
            len: len,
        }
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Header, Box<dyn Error>> {
        let mut cursor = std::io::Cursor::new(bytes);

        let proto_magic = cursor.read_u32::<LittleEndian>()?;
        if proto_magic != 0xAFBFCFDF {
            return Err(io::Error::new(io::ErrorKind::Other, "invalid message magic").into());
        }

        let proto_version = cursor.read_u32::<LittleEndian>()?;
        let msg_len = cursor.read_u32::<LittleEndian>()?;

        Ok(Header {
            version: proto_version,
            len: msg_len,
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut buf = Vec::new();
        buf.write_u32::<LittleEndian>(0xAFBFCFDF)?;
        buf.write_u32::<LittleEndian>(self.version)?;
        buf.write_u32::<LittleEndian>(self.len)?;
        Ok(buf)
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ExitAction {
    Poweroff,
    Reboot,
    Exit,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[serde(tag = "type")]
pub enum Request {
    Login {
        username: String,
        password: String,
        command: Vec<String>,
        env: HashMap<String, String>,
    },
    Exit {
        action: ExitAction,
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
#[serde(tag = "errorType")]
#[serde(rename_all = "camelCase")]
pub enum Failure {
    LoginError {
        description: String,
    },
    ExitError {
        description: String,
    },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
pub enum Response {
    Success,
    Failure(Failure)
}

impl Response {
    pub fn from_slice(bytes: &[u8]) -> Result<Response, Box<dyn Error>> {
        serde_json::from_slice(bytes).map_err(|x| x.into())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        serde_json::to_vec(self).map_err(|x| x.into())
    }
}
