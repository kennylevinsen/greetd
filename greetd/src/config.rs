use std::env;
use std::fs::read_to_string;

use clap::{crate_authors, crate_version, App, Arg};
use serde::Deserialize;

fn default_vt() -> usize {
    1
}

fn default_socket_path() -> String {
    "/run/greetd.sock".to_string()
}

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default = "default_vt")]
    pub vt: usize,
    pub greeter: String,
    pub greeter_user: String,

    #[serde(default = "default_socket_path")]
    pub socket_path: String,
}

pub fn read_config() -> Config {
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

    config
}
