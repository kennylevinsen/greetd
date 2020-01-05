use std::cell::RefCell;
use std::env;
use std::fs::{read_to_string, remove_file};
use std::rc::Rc;

use clap::{crate_authors, crate_version, App, Arg};
use nix::poll::{poll, PollFd};
use nix::unistd::chown;
use serde::Deserialize;

mod client;
mod context;
mod listener;
mod pam;
mod pollable;
mod scrambler;
mod session;
mod signals;
mod terminal;

use crate::context::Context;
use crate::listener::Listener;
use crate::pollable::{PollRunResult, Pollable};
use crate::signals::Signals;

fn default_vt() -> usize {
    1
}

fn default_socket_path() -> String {
    "/run/greetd.sock".to_string()
}

#[derive(Debug, Deserialize)]
struct Config {
    #[serde(default = "default_vt")]
    vt: usize,
    greeter: String,
    greeter_user: String,

    #[serde(default = "default_socket_path")]
    socket_path: String,
}

fn main() {
    let matches = App::new("greetd")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Universal greeter daemon")
        .arg(
            Arg::with_name("vt")
                .short("t")
                .long("vt")
                .takes_value(true)
                .help("VT to run on"),
        )
        .arg(
            Arg::with_name("socket-path")
                .short("s")
                .long("socket-path")
                .takes_value(true)
                .help("socket path to use"),
        )
        .arg(
            Arg::with_name("greeter")
                .short("g")
                .long("greeter")
                .takes_value(true)
                .help("greeter to run"),
        )
        .arg(
            Arg::with_name("greeter-user")
                .short("u")
                .long("greeter-user")
                .takes_value(true)
                .help("user to run greeter as"),
        )
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("config")
                .takes_value(true)
                .help("config file to use"),
        )
        .get_matches();

    let mut config = match read_to_string(
        matches
            .value_of("config")
            .unwrap_or("/etc/greetd/config.toml"),
    ) {
        Ok(s) => match toml::from_str(&s) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Unable to parse configuration file: {:?}", e);
                eprintln!("Please fix the configuration file and try again.");
                std::process::exit(1);
            }
        },
        Err(_) => Config {
            vt: default_vt(),
            greeter: "".to_string(),
            greeter_user: "".to_string(),
            socket_path: default_socket_path(),
        },
    };

    if let Some(vt) = matches.value_of("vt") {
        config.vt = vt.parse().expect("vt parameter must be a positive integer");
    }
    if let Some(greeter) = matches.value_of("greeter") {
        config.greeter = greeter.to_string();
    }
    if let Some(user) = matches.value_of("greeter-user") {
        config.greeter_user = user.to_string();
    }
    if let Some(socket_path) = matches.value_of("socket-path") {
        config.socket_path = socket_path.to_string();
    }

    if config.greeter.len() == 0 {
        eprintln!("No greeter specified. Run with --help for more information.");
        std::process::exit(1);
    }
    if config.greeter_user.len() == 0 {
        eprintln!("No greeter user specified. Run with --help for more information.");
        std::process::exit(1);
    }

    eprintln!("starting greetd");

    let start_vt = terminal::Terminal::open(0)
        .expect("unable to open controlling terminal")
        .vt_get_current()
        .expect("unable to get current vt");

    env::set_var("GREETD_SOCK", &config.socket_path);

    let _ = remove_file(config.socket_path.clone());
    let listener = Listener::new(&config.socket_path).expect("unable to create listener");

    let u = users::get_user_by_name(&config.greeter_user).expect("unable to get user struct");
    let uid = nix::unistd::Uid::from_raw(u.uid());
    let gid = nix::unistd::Gid::from_raw(u.primary_group_id());
    chown(config.socket_path.as_str(), Some(uid), Some(gid))
        .expect("unable to chown greetd socket");

    let signals = Signals::new().expect("unable to create signalfd");

    let mut ctx = Context::new(config.greeter, config.greeter_user, config.vt);
    if let Err(e) = ctx.greet() {
        eprintln!("unable to start greeter: {}", e);
        std::process::exit(1);
    }

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
                    match pollable.borrow_mut().run(&mut ctx) {
                        Ok(PollRunResult::Uneventful) => (),
                        Ok(PollRunResult::NewPollable(p)) => new_pollables.push(p),
                        Ok(PollRunResult::Dead) => dead_pollables.push(idx),
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
