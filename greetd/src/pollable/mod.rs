pub mod client;
pub mod listener;
pub mod signals;

pub use client::Client;
pub use listener::Listener;
pub use signals::Signals;

use std::error::Error;
use std::os::unix::io::RawFd;

use nix::poll::PollFlags;

use crate::context::Context;

pub enum PollRunResult {
    Uneventful,
    Dead,
    NewPollable(Box<dyn Pollable>),
}

/// A Pollable is an event loop entry that will be scheduled when its fd has
/// activity matching what was subscribed for. It can optionally remove itself
/// or add another pollable to the event loop (such as in the case of pollables
/// that call accept()).
pub trait Pollable {
    fn fd(&self) -> RawFd;
    fn poll_flags(&self) -> PollFlags;
    fn run(&mut self, ctx: &mut Context) -> Result<PollRunResult, Box<dyn Error>>;
}
