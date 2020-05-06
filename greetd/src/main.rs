#![recursion_limit = "256"]

mod config;
mod context;
mod error;
mod pam;
mod scrambler;
mod server;
mod session;
mod signals;
mod terminal;

use std::os::unix::{
    io::{FromRawFd, RawFd},
    net::UnixDatagram,
};

use nix::{
    fcntl::{fcntl, FcntlArg, FdFlag},
    sys::mman::{mlockall, MlockAllFlags},
};

use crate::{error::Error, session::worker};

async fn session_worker_main(config: config::Config) -> Result<(), Error> {
    let raw_fd = config.internal.session_worker as RawFd;
    let mut cur_flags = unsafe { FdFlag::from_bits_unchecked(fcntl(raw_fd, FcntlArg::F_GETFD)?) };
    cur_flags.insert(FdFlag::FD_CLOEXEC);
    fcntl(raw_fd, FcntlArg::F_SETFD(cur_flags))?;
    let sock = unsafe { UnixDatagram::from_raw_fd(raw_fd) };
    worker::main(&sock)
}

fn main() {
    let config = match config::read_config() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    };
    if cfg!(feature = "debug") {
        eprintln!("config: {:?}", config);
    }
    mlockall(MlockAllFlags::all()).expect("unable to lock pages");
    let res = smol::run(async {
        if config.internal.session_worker > 0 {
            session_worker_main(config).await
        } else {
            server::main(config).await
        }
    });
    if let Err(e) = res {
        eprintln!("error: {}", e);
    }
}
