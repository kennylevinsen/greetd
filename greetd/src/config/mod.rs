mod defaults;
mod old_config;
mod types;
mod vtselection;

use std::{env, fs::read_to_string};

use getopts::Options;

use super::error::Error;
use old_config::*;

pub use types::*;
pub use vtselection::VtSelection;

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    println!("{}", opts.usage(&brief));
    println!("For more details, see greetd(1).");
}

pub fn read_config() -> Result<Config, Error> {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let mut opts = Options::new();
    opts.optflag("h", "help", "print this help menu");
    opts.optopt("s", "socket-path", "socket path to use", "SOCKET_PATH");
    opts.optopt("c", "config", "config file to use", "CONFIG_FILE");
    opts.optopt(
        "w",
        "session-worker",
        "start a session worker (internal)",
        "FD",
    );
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => return Err(format!("could not parse arguments: {}", f).into()),
    };
    if matches.opt_present("h") {
        print_usage(&program, opts);
        std::process::exit(0);
    }

    let internal = ConfigInternal {
        socket_path: matches
            .opt_str("socket-path")
            .unwrap_or_else(|| "/run/greetd.sock".to_string()),
        session_worker: matches
            .opt_get("session-worker")
            .expect("unable to parse session-worker")
            .unwrap_or(0),
    };

    let file = match read_to_string(
        matches
            .opt_str("config")
            .unwrap_or_else(|| "/etc/greetd/config.toml".to_string()),
    ) {
        Ok(s) => match toml::from_str(&s) {
            Ok(v) => v,
            Err(e) => match try_read_old_config(&s) {
                Ok(v) => {
                    eprintln!("warning: Fallback to old config format, caused by : {}", e);
                    v
                }
                Err(_e) => {
                    return Err(Error::ConfigError(
                        format!("unable to parse configuration file: {}", e).to_string(),
                    ))
                }
            },
        },
        Err(_) => ConfigFile {
            default_session: ConfigDefaultSession {
                user: "greeter".to_string(),
                command: "".to_string(),
            },
            initial_session: None,
            terminal: Default::default(),
        },
    };

    if file.default_session.command.is_empty() {
        return Err(Error::ConfigError(
            "no default session user specified".to_string(),
        ));
    }
    if file.default_session.user.is_empty() {
        return Err(Error::ConfigError(
            "no default session user specified".to_string(),
        ));
    }
    if let Some(s) = &file.initial_session {
        if s.user.is_empty() {
            return Err(Error::ConfigError(
                "initial session enabled but contained no user".to_string(),
            ));
        }
        if s.command.is_empty() {
            return Err(Error::ConfigError(
                "initial session enabled but contained no command".to_string(),
            ));
        }
    }

    Ok(Config { file, internal })
}
