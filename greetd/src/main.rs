mod config;
mod context;
mod pam;
mod pollable;
mod scrambler;
mod session;
mod terminal;

use std::error::Error;

use nix::poll::{poll, PollFd};
use nix::unistd::{chown, Gid, Uid};

use config::VtSelection;
use context::Context;
use pollable::{Listener, PollRunResult, Pollable, Signals};
use terminal::Terminal;

fn reset_vt(vt: usize) -> Result<(), Box<dyn Error>> {
    let term = Terminal::open(vt)?;
    term.kd_setmode(terminal::KdMode::Text)?;
    term.vt_setactivate(vt)?;
    Ok(())
}

fn main() {
    let config = config::read_config();

    eprintln!("starting greetd");

    std::env::set_var("GREETD_SOCK", &config.socket_path);

    let _ = std::fs::remove_file(config.socket_path.clone());
    let listener = Listener::new(&config.socket_path).expect("unable to create listener");

    let u = users::get_user_by_name(&config.greeter_user).expect("unable to get user struct");
    let uid = Uid::from_raw(u.uid());
    let gid = Gid::from_raw(u.primary_group_id());
    chown(config.socket_path.as_str(), Some(uid), Some(gid))
        .expect("unable to chown greetd socket");

    let signals = Signals::new().expect("unable to create signalfd");

    let term = Terminal::open(0).expect("unable to open controlling terminal");
    let vt = match config.vt() {
        VtSelection::Current => term.vt_get_current().expect("unable to get current VT"),
        VtSelection::Next => term.vt_get_next().expect("unable to get next VT"),
        VtSelection::Specific(v) => v,
    };
    drop(term);

    let mut ctx = Context::new(config.greeter, config.greeter_user, vt);
    if let Err(e) = ctx.greet() {
        eprintln!("unable to start greeter: {}", e);
        reset_vt(vt).expect("unable to reset vt");
        std::process::exit(1);
    }

    let mut pollables: Vec<Box<dyn Pollable>> = vec![Box::new(listener), Box::new(signals)];

    let mut fds: Vec<PollFd> = Vec::new();
    let mut fds_changed = true;

    loop {
        if fds_changed {
            fds_changed = false;
            fds = pollables
                .iter()
                .map(|x| PollFd::new(x.fd(), x.poll_flags()))
                .collect();
        }

        if let Err(e) = poll(&mut fds, -1) {
            eprintln!("poll failed: {}", e);
            reset_vt(vt).expect("unable to reset vt");
            std::process::exit(1);
        }

        let mut idx_compensation: isize = 0;
        for (idx, fd) in fds.iter().enumerate() {
            if let Some(revents) = fd.revents() {
                let pollable = &mut pollables[(idx as isize + idx_compensation) as usize];
                if revents.intersects(pollable.poll_flags()) {
                    match pollable.run(&mut ctx) {
                        Ok(PollRunResult::Uneventful) => (),
                        Ok(PollRunResult::NewPollable(p)) => {
                            // New pollables are pushed at the end, so they do
                            // not require index compensation.
                            pollables.push(p);
                            fds_changed = true;
                        }
                        Ok(PollRunResult::Dead) => {
                            // We remove a pollable at the current index, so
                            // compensate the index of future accesses.
                            idx_compensation -= 1;
                            pollables.remove(idx);
                            fds_changed = true;
                        }
                        Err(e) => {
                            eprintln!("task failed: {}", e);
                            reset_vt(vt).expect("unable to reset vt");
                            std::process::exit(1);
                        }
                    }
                }
            }
        }
    }
}
