use nix::sys::signalfd::{signalfd, SfdFlags, SIGNALFD_NEW, SIGNALFD_SIGINFO_SIZE};
pub use nix::{
    libc::signalfd_siginfo as siginfo,
    sys::signal::{self, SigSet},
};

use std::{error::Error, fs::File, mem, os::unix::io::FromRawFd};

use futures::io::AsyncReadExt;
use smol::Async;

pub struct SignalFd(Async<std::fs::File>);

impl SignalFd {
    pub fn with_flags(mask: &SigSet, flags: SfdFlags) -> Result<SignalFd, Box<dyn Error>> {
        let fd = signalfd(SIGNALFD_NEW, mask, flags)?;

        Ok(SignalFd(Async::new(unsafe { File::from_raw_fd(fd) })?))
    }

    pub async fn read_signal(&mut self) -> Result<Option<siginfo>, Box<dyn Error>> {
        let mut buffer: [u8; SIGNALFD_SIGINFO_SIZE] = [0; SIGNALFD_SIGINFO_SIZE];
        // let mut buffer = mem::MaybeUninit::<[u8; SIGNALFD_SIGINFO_SIZE]>::uninit();

        let res = self.0.read(&mut buffer[..]).await?;
        match res {
            SIGNALFD_SIGINFO_SIZE => Ok(Some(unsafe { mem::transmute(buffer) })),
            _ => unreachable!("partial read on signalfd"),
        }
    }
}
