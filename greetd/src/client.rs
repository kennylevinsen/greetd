use std::error::Error;
use std::io;
use std::io::{Read, Take};
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;

use nix::poll::PollFlags;

use byteorder::{LittleEndian, ReadBytesExt};

use crate::context::Context;
use crate::pollable::{PollRunResult, Pollable};
use crate::scrambler::Scrambler;

enum ClientState {
    AwaitingHeader,
    AwaitingPayload { typ: u32, len: u32 },
}

const IPC_HEADERLEN: usize = 16; // 4 bytes magic, 4 bytes version, 4 byte type, 4 byte len

pub struct Client {
    stream: Take<UnixStream>,
    buf: Vec<u8>,
    state: ClientState,
}

impl Client {
    fn read_header(cursor: &mut std::io::Cursor<&[u8]>) -> Result<(u32, u32), Box<dyn Error>> {
        let proto_magic = cursor.read_u32::<LittleEndian>()?;
        if proto_magic != 0xAFBFCFDF {
            return Err(io::Error::new(io::ErrorKind::Other, "invalid message magic").into());
        }

        let proto_version = cursor.read_u32::<LittleEndian>()?;
        if proto_version != 1 {
            return Err(io::Error::new(io::ErrorKind::Other, "invalid message version").into());
        }

        let msg_type = cursor.read_u32::<LittleEndian>()?;
        let msg_len = cursor.read_u32::<LittleEndian>()?;
        Ok((msg_type, msg_len))
    }

    fn read_string(cursor: &mut std::io::Cursor<&[u8]>) -> Result<String, Box<dyn Error>> {
        let len = cursor.read_u32::<LittleEndian>()?;
        let mut data: Vec<u8> = vec![0; len as usize];
        cursor.read_exact(&mut data)?;
        String::from_utf8(data).map_err(|x| x.into())
    }

    fn read_login(
        cursor: &mut std::io::Cursor<&[u8]>,
    ) -> Result<(String, String, String), Box<dyn Error>> {
        let user = Client::read_string(cursor)?;
        let pass = Client::read_string(cursor)?;
        let cmd = Client::read_string(cursor)?;
        Ok((user, pass, cmd))
    }

    pub fn new(stream: UnixStream) -> Result<Client, Box<dyn Error>> {
        stream.set_nonblocking(true)?;
        Ok(Client {
            stream: stream.take(IPC_HEADERLEN as u64),
            buf: Vec::new(),
            state: ClientState::AwaitingHeader,
        })
    }
}

impl Pollable for Client {
    fn fd(&self) -> RawFd {
        self.stream.get_ref().as_raw_fd()
    }

    fn poll_flags(&self) -> PollFlags {
        PollFlags::POLLIN
    }

    fn run(&mut self, ctx: &mut Context) -> Result<PollRunResult, Box<dyn Error>> {
        loop {
            match self.state {
                ClientState::AwaitingHeader => {
                    match self.stream.read_to_end(&mut self.buf) {
                        Ok(_) => {
                            if self.buf.len() < IPC_HEADERLEN {
                                // Got EOF before we got enough data.
                                self.buf.scramble();
                                break Ok(PollRunResult::Dead);
                            }
                            let mut rdr = std::io::Cursor::new(self.buf.as_slice());
                            let (msg_type, msg_len) = match Client::read_header(&mut rdr) {
                                Ok(v) => v,
                                Err(_) => {
                                    self.buf.scramble();
                                    break Ok(PollRunResult::Dead);
                                }
                            };

                            self.state = ClientState::AwaitingPayload {
                                typ: msg_type,
                                len: msg_len,
                            };
                            self.stream.set_limit(msg_len as u64);
                            self.buf.truncate(0);
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                            break Ok(PollRunResult::Uneventful)
                        }
                        Err(_) => {
                            self.buf.scramble();
                            break Ok(PollRunResult::Dead);
                        }
                    }
                }
                ClientState::AwaitingPayload { typ, len } => {
                    match self.stream.read_to_end(&mut self.buf) {
                        Ok(_) => {
                            if self.buf.len() < len as usize {
                                // Got EOF before we got enough data.
                                self.buf.scramble();
                                break Ok(PollRunResult::Dead);
                            }
                            self.state = ClientState::AwaitingHeader;
                            self.stream.set_limit(IPC_HEADERLEN as u64);
                            match typ {
                                1 => {
                                    // Login
                                    let mut rdr = std::io::Cursor::new(self.buf.as_slice());
                                    let (user, pass, cmd) = match Client::read_login(&mut rdr) {
                                        Ok(v) => v,
                                        Err(_) => {
                                            self.buf.scramble();
                                            break Ok(PollRunResult::Dead);
                                        }
                                    };
                                    self.buf.scramble();

                                    ctx.login(user, pass, cmd)?;
                                }
                                2 => {
                                    // Screen lock
                                    self.buf.scramble();
                                    unimplemented!("screen lock has not yet been implemented");
                                }
                                _ => {
                                    // Unknown message type
                                    self.buf.scramble();
                                    break Ok(PollRunResult::Dead);
                                }
                            }
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                            break Ok(PollRunResult::Uneventful)
                        }
                        Err(_) => {
                            self.buf.scramble();
                            break Ok(PollRunResult::Dead);
                        }
                    }
                }
            }
        }
    }
}
