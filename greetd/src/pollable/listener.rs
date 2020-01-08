use std::error::Error;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixListener;

use nix::fcntl::{fcntl, FcntlArg, FdFlag};
use nix::poll::PollFlags;

use super::client::Client;
use super::{PollRunResult, Pollable};
use crate::context::Context;

pub struct Listener {
    listener: UnixListener,
}

impl Listener {
    pub fn new(p: &str) -> Result<Listener, Box<dyn Error>> {
        let listener = UnixListener::bind(p)?;
        listener.set_nonblocking(true)?;
        let fd = listener.as_raw_fd();
        let flags = fcntl(fd, FcntlArg::F_GETFD)?;
        fcntl(
            fd,
            FcntlArg::F_SETFD(FdFlag::from_bits(flags).unwrap() | FdFlag::FD_CLOEXEC),
        )?;
        Ok(Listener { listener })
    }
}

impl Pollable for Listener {
    fn fd(&self) -> RawFd {
        self.listener.as_raw_fd()
    }

    fn poll_flags(&self) -> PollFlags {
        PollFlags::POLLIN
    }

    fn run(&mut self, _: &mut Context) -> Result<PollRunResult, Box<dyn Error>> {
        let stream = match self.listener.accept() {
            Ok((stream, _)) => stream,
            Err(_) => return Ok(PollRunResult::Uneventful),
        };

        Ok(PollRunResult::NewPollable(Box::new(Client::new(stream)?)))
    }
}
