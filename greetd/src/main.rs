use std::cell::RefCell;
use std::env;
use std::fs::remove_file;
use std::rc::Rc;

use nix::poll::{poll, PollFd};
use nix::unistd::chown;

mod config;
mod client;
mod context;
mod listener;
mod pam;
mod pollable;
mod scrambler;
mod session;
mod signals;
mod terminal;

fn main() {
    let config = config::read_config();

    eprintln!("starting greetd");

    let start_vt = terminal::Terminal::open(0)
        .expect("unable to open controlling terminal")
        .vt_get_current()
        .expect("unable to get current vt");

    env::set_var("GREETD_SOCK", &config.socket_path);

    let _ = remove_file(config.socket_path.clone());
    let listener = listener::Listener::new(&config.socket_path).expect("unable to create listener");

    let u = users::get_user_by_name(&config.greeter_user).expect("unable to get user struct");
    let uid = nix::unistd::Uid::from_raw(u.uid());
    let gid = nix::unistd::Gid::from_raw(u.primary_group_id());
    chown(config.socket_path.as_str(), Some(uid), Some(gid))
        .expect("unable to chown greetd socket");

    let signals = signals::Signals::new().expect("unable to create signalfd");

    let mut ctx = context::Context::new(config.greeter, config.greeter_user, config.vt);
    if let Err(e) = ctx.greet() {
        eprintln!("unable to start greeter: {}", e);
        std::process::exit(1);
    }

    let mut pollables: Vec<Rc<RefCell<Box<dyn pollable::Pollable>>>> = vec![
        Rc::new(RefCell::new(Box::new(listener))),
        Rc::new(RefCell::new(Box::new(signals))),
    ];

    let mut fds: Vec<PollFd> = pollables
        .iter()
        .map(|x| PollFd::new(x.borrow().fd(), x.borrow().poll_flags()))
        .collect();

    let mut new_pollables: Vec<Rc<RefCell<Box<dyn pollable::Pollable>>>> = Vec::new();
    let mut dead_pollables: Vec<usize> = Vec::new();

    loop {
        poll(&mut fds, -1).expect("poll failed");

        for (idx, fd) in fds.iter().enumerate() {
            if let Some(revents) = fd.revents() {
                let pollable = &pollables[idx];
                if revents.intersects(pollable.borrow().poll_flags()) {
                    match pollable.borrow_mut().run(&mut ctx) {
                        Ok(pollable::PollRunResult::Uneventful) => (),
                        Ok(pollable::PollRunResult::NewPollable(p)) => new_pollables.push(p),
                        Ok(pollable::PollRunResult::Dead) => dead_pollables.push(idx),
                        Err(e) => {
                            eprintln!("task failed: {}", e);
                            terminal::restore(start_vt).expect("unable to reset vt");
                            std::process::exit(0);
                        }
                    }
                }
            }
        }

        let fds_changed = dead_pollables.len() > 0 || new_pollables.len() > 0;

        if dead_pollables.len() > 0 {
            let mut removed = 0;
            for dead in dead_pollables.into_iter() {
                pollables.remove(dead - removed);
                removed += 1;
            }
            dead_pollables = Vec::new();
        }

        if new_pollables.len() > 0 {
            for pollable in new_pollables.into_iter() {
                pollables.push(pollable);
            }
            new_pollables = Vec::new();
        }

        if fds_changed {
            fds = pollables
                .iter()
                .map(|x| PollFd::new(x.borrow().fd(), x.borrow().poll_flags()))
                .collect();
        }
    }
}
