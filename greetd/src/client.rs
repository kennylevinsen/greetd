use std::error::Error;
use std::io;
use std::io::{Read, Take, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;

use nix::poll::PollFlags;

use greet_proto::{Header, Request, Response};

use crate::context::Context;
use crate::pollable::{PollRunResult, Pollable};
use crate::scrambler::Scrambler;

enum ClientState {
    AwaitingHeader,
    AwaitingPayload { len: u32 },
}

pub struct Client {
    stream: Take<UnixStream>,
    buf: Vec<u8>,
    state: ClientState,
}

impl Client {
    pub fn new(stream: UnixStream) -> Result<Client, Box<dyn Error>> {
        stream.set_nonblocking(true)?;
        Ok(Client {
            stream: stream.take(Header::len() as u64),
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
                            if self.buf.len() < Header::len() {
                                // Got EOF before we got enough data.
                                self.buf.scramble();
                                break Ok(PollRunResult::Dead);
                            }
                            let header = Header::from_slice(self.buf.as_slice())?;

                            if header.version != 1 {
                                return Err(io::Error::new(
                                    io::ErrorKind::Other,
                                    "invalid message version",
                                )
                                .into());
                            }

                            self.state = ClientState::AwaitingPayload { len: header.len };
                            self.stream.set_limit(header.len as u64);
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
                ClientState::AwaitingPayload { len } => {
                    match self.stream.read_to_end(&mut self.buf) {
                        Ok(_) => {
                            if self.buf.len() < len as usize {
                                // Got EOF before we got enough data.
                                self.buf.scramble();
                                break Ok(PollRunResult::Dead);
                            }
                            self.state = ClientState::AwaitingHeader;
                            self.stream.set_limit(Header::len() as u64);

                            match Request::from_slice(&self.buf)? {
                                Request::Login {
                                    username,
                                    password,
                                    command,
                                    env,
                                } => {
                                    self.buf.scramble();

                                    let resp = match ctx.login(username, password, command, env) {
                                        Ok(_) => Response::LoginSuccess,
                                        Err(_) => Response::LoginFailure,
                                    };

                                    let resp_bytes =
                                        resp.to_bytes().expect("unable to serialize response");
                                    let header = Header::new(resp_bytes.len() as u32);
                                    let header_bytes =
                                        header.to_bytes().expect("unable to serialize header");

                                    if self.stream.get_mut().write_all(&header_bytes).is_err() {
                                        eprintln!("unable to write response header");
                                        break Ok(PollRunResult::Dead);
                                    }
                                    if self.stream.get_mut().write_all(&resp_bytes).is_err() {
                                        eprintln!("unable to write response");
                                        break Ok(PollRunResult::Dead);
                                    }
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
