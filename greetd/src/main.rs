use std::cell::RefCell;
use std::env;
use std::os::unix::io::AsRawFd;
use std::rc::Rc;

use nix::ioctl_write_int_bad;
use nix::poll::{poll, PollFd};
use nix::unistd::chown;

mod client;
mod context;
mod listener;
mod pollable;
mod scrambler;
mod signals;

use crate::context::Context;
use crate::listener::Listener;
use crate::pollable::{PollRunResult, Pollable};
use crate::signals::Signals;

ioctl_write_int_bad!(vt_activate, 0x5606);
ioctl_write_int_bad!(vt_waitactive, 0x5607);

const GREETD_SOCK: &'static str = "/run/greetd.sock";

fn main() {
    let tty = env::var("GREETD_TTY")
        .expect("unable to get tty")
        .parse()
        .expect("unable to parse tty");

    let greeter_user = env::var("GREETD_GREETER_USER").expect("unable to get greeter user");

    let greeter_bin = env::var("GREETD_GREETER").expect("unable to get greeter");

    env::set_var("GREETD_SOCK", GREETD_SOCK);

    let listener = Listener::new(GREETD_SOCK).expect("unable to create listener");

    let u = users::get_user_by_name(&greeter_user).expect("unable to get user struct");
    let uid = nix::unistd::Uid::from_raw(u.uid());
    let gid = nix::unistd::Gid::from_raw(u.primary_group_id());
    chown(GREETD_SOCK, Some(uid), Some(gid)).expect("unable to chown greetd socket");

    let signals = Signals::new().expect("unable to create signalfd");

    let file = std::fs::OpenOptions::new()
        .write(true)
        .read(false)
        .open("/dev/console")
        .expect("unable to open console");

    unsafe {
        vt_activate(file.as_raw_fd(), tty as i32).expect("unable to activate");
        vt_waitactive(file.as_raw_fd(), tty as i32).expect("unable to wait for activation");
    }
    drop(file);

    let mut ctx = Context::new(greeter_bin, greeter_user, tty);
    ctx.greet().expect("unable to start greeter");

    let mut pollables: Vec<Rc<RefCell<Box<dyn Pollable>>>> = vec![
        Rc::new(RefCell::new(Box::new(listener))),
        Rc::new(RefCell::new(Box::new(signals))),
    ];

    let mut fds: Vec<PollFd> = pollables
        .iter()
        .map(|x| PollFd::new(x.borrow().fd(), x.borrow().poll_flags()))
        .collect();

    let mut new_pollables: Vec<Rc<RefCell<Box<dyn Pollable>>>> = Vec::new();
    let mut dead_pollables: Vec<usize> = Vec::new();

    loop {
        poll(&mut fds, -1).expect("poll failed");

        for (idx, fd) in fds.iter().enumerate() {
            if let Some(revents) = fd.revents() {
                let pollable = &pollables[idx];
                if revents.intersects(pollable.borrow().poll_flags()) {
                    match pollable
                        .borrow_mut()
                        .run(&mut ctx)
                        .expect("pollable run failed")
                    {
                        PollRunResult::Uneventful => (),
                        PollRunResult::NewPollable(p) => new_pollables.push(p),
                        PollRunResult::Dead => dead_pollables.push(idx),
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
