mod config;
mod context;
mod error;
mod pam;
mod scrambler;
mod server;
mod session;
mod terminal;

use std::os::unix::{
    io::{FromRawFd, RawFd},
    net::UnixDatagram,
};

use nix::sys::mman::{mlockall, MlockAllFlags};
use nix::fcntl::fcntl;
use nix::fcntl::FdFlag;
use nix::fcntl::FcntlArg;
use tokio::task;

use crate::{error::Error, session::worker};

async fn session_worker_main(config: config::Config) -> Result<(), Error> {
    let raw_fd = config.session_worker as RawFd;
    let mut cur_flags =
        unsafe { FdFlag::from_bits_unchecked(fcntl(raw_fd, FcntlArg::F_GETFD)?) };
    cur_flags.insert(FdFlag::FD_CLOEXEC);
    fcntl(raw_fd, FcntlArg::F_SETFD(cur_flags))?;
    let sock = unsafe { UnixDatagram::from_raw_fd(raw_fd) };
    worker::main(&sock)
}

#[tokio::main]
async fn main() {
    let config = config::read_config();
    mlockall(MlockAllFlags::all()).expect("unable to lock pages");
    let res = task::LocalSet::new()
        .run_until(async move {
            if config.session_worker > 0 {
                session_worker_main(config).await
            } else {
                server::main(config).await
            }
        })
        .await;
    if let Err(e) = res {
        eprintln!("error: {}", e);
    }
}
