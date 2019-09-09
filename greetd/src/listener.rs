use std::cell::RefCell;
use std::error::Error;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixListener;
use std::rc::Rc;

use nix::poll::PollFlags;

use crate::client::Client;
use crate::context::Context;
use crate::pollable::{PollRunResult, Pollable};

pub struct Listener {
    listener: UnixListener,
}

impl Listener {
    pub fn new(p: &str) -> Result<Listener, Box<dyn Error>> {
        let listener = UnixListener::bind(p)?;
        listener.set_nonblocking(true)?;
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

        Ok(PollRunResult::NewPollable(Rc::new(RefCell::new(Box::new(
            Client::new(stream)?,
        )))))
    }
}
