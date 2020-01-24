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
use tokio::task;

use crate::{error::Error, session::worker};

async fn session_worker_main(config: config::Config) -> Result<(), Error> {
    let sock = unsafe { UnixDatagram::from_raw_fd(config.session_worker as RawFd) };
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
