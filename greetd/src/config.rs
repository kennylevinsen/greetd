use std::{env, fs::read_to_string};

use getopts::Options;
use serde::Deserialize;

fn default_vt() -> toml::Value {
    toml::Value::String("next".to_string())
}

fn default_greeter_user() -> String {
    "greeter".to_string()
}

fn default_socket_path() -> String {
    "/run/greetd.sock".to_string()
}

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default = "default_vt")]
    pub vt: toml::Value,
    pub greeter: String,
    #[serde(default = "default_greeter_user")]
    pub greeter_user: String,

    #[serde(default = "default_socket_path")]
    pub socket_path: String,

    #[serde(skip_deserializing)]
    pub session_worker: usize,
}

pub enum VtSelection {
    Next,
    Current,
    None,
    Specific(usize),
}

impl Config {
    pub fn vt(&self) -> VtSelection {
        match &self.vt {
            toml::Value::String(s) => match s.as_str() {
                "next" => VtSelection::Next,
                "current" => VtSelection::Current,
                "none" => VtSelection::None,
                _ => panic!("unknown value of vt, expect next, current, none, or vt number"),
            },
            toml::Value::Integer(u) => VtSelection::Specific(*u as usize),
            _ => panic!("unknown value of vt, expect next, current, or vt number"),
        }
    }
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

pub fn read_config() -> Config {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let mut opts = Options::new();
    opts.optflag("h", "help", "print this help menu");
    opts.optopt("t", "vt", "VT to run on", "VT");
    opts.optopt("s", "socket-path", "socket path to use", "SOCKET_PATH");
    opts.optopt("g", "greeter", "greeter to run", "GREETER");
    opts.optopt("u", "greeter-user", "user to run greeter as", "USER");
    opts.optopt("c", "config", "config file to use", "CONFIG_FILE");
    opts.optopt("w", "session-worker", "start a session worker", "FD");
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => panic!(f.to_string()),
    };
    if matches.opt_present("h") {
        print_usage(&program, opts);
        std::process::exit(0);
    }

    let mut config = match read_to_string(
        matches
            .opt_str("config")
            .unwrap_or_else(|| "/etc/greetd/config.toml".to_string()),
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
            session_worker: 0,
        },
    };

    if let Some(vt) = matches.opt_str("vt") {
        config.vt = match vt.as_str() {
            "next" => toml::Value::String("next".to_string()),
            "current" => toml::Value::String("current".to_string()),
            "none" => toml::Value::String("none".to_string()),
            v => toml::Value::Integer(v.parse().expect("could not parse vt number")),
        }
    }
    if let Some(greeter) = matches.opt_str("greeter") {
        config.greeter = greeter;
    }
    if let Some(user) = matches.opt_str("greeter-user") {
        config.greeter_user = user;
    }
    if let Some(socket_path) = matches.opt_str("socket-path") {
        config.socket_path = socket_path;
    }
    if let Some(session_worker) = matches
        .opt_get("session-worker")
        .expect("unable to parse session-worker")
    {
        config.session_worker = session_worker
    }

    if config.greeter.is_empty() {
        eprintln!("No greeter specified. Run with --help for more information.");
        std::process::exit(1);
    }
    if config.greeter_user.is_empty() {
        eprintln!("No greeter user specified. Run with --help for more information.");
        std::process::exit(1);
    }

    config
}
