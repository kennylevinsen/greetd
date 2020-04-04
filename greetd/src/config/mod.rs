mod types;

use std::{env, fs::read_to_string};

use getopts::Options;

use super::error::Error;

pub use types::*;

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    println!("{}", opts.usage(&brief));
    println!("For more details, see greetd(1).");
}

fn read_old_config(config: &ini::Ini) -> Result<ConfigFile, Error> {
    let general = config.general_section();
    let greeter = general
        .get("greeter")
        .ok_or("unable to parse configuration file: no greeter specified")?;
    let greeter_user = general.get("greeter_user").unwrap_or("greeter");
    let vt: VtSelection = match general
        .get("vt")
        .ok_or("unable to parse configuration file: no VT specified")?
    {
        "none" | "\"none\"" => VtSelection::None,
        "current" | "\"current\"" => VtSelection::Current,
        "next" | "\"next\"" => VtSelection::Next,
        v => VtSelection::Specific(
            v.parse()
                .map_err(|e| format!("could not parse vt number: {}", e))?,
        ),
    };

    Ok(ConfigFile {
        terminal: ConfigTerminal { vt: vt },
        default_session: ConfigDefaultSession {
            user: greeter_user.to_string(),
            command: greeter.to_string(),
        },
        initial_session: None,
    })
}

fn read_new_config(config: &ini::Ini) -> Result<ConfigFile, Error> {
    let default_session = match config.section(Some("default_session")) {
        Some(section) => Ok(ConfigDefaultSession {
            command: section
                .get("command")
                .ok_or("default_session contains no command")?
                .to_string(),
            user: section.get("user").unwrap_or("greeter").to_string(),
        }),
        None => Err("no default_session specified"),
    }?;

    let initial_session = match config.section(Some("initial_section")) {
        Some(section) => Some(ConfigInitialSession {
            command: section
                .get("command")
                .ok_or("initial_session contains no command")?
                .to_string(),
            user: section
                .get("user")
                .ok_or("initial_session contains no user")?
                .to_string(),
        }),
        None => None,
    };

    let terminal = match config.section(Some("terminal")) {
        Some(section) => Ok(ConfigTerminal {
            vt: match section.get("vt").ok_or("VT not specified")? {
                "none" | "\"none\"" => VtSelection::None,
                "current" | "\"current\"" => VtSelection::Current,
                "next" | "\"next\"" => VtSelection::Next,
                v => VtSelection::Specific(
                    v.parse()
                        .map_err(|e| format!("could not parse vt number: {}", e))?,
                ),
            },
        }),
        None => Err("no terminal specified"),
    }?;

    Ok(ConfigFile {
        initial_session,
        default_session,
        terminal,
    })
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

    let file_content = read_to_string(
        matches
            .opt_str("config")
            .unwrap_or_else(|| "/etc/greetd/config.toml".to_string()),
    )?;

    let config_ini = ini::Ini::load_from_str(&file_content)?;
    let file = match read_new_config(&config_ini) {
        Ok(v) => v,
        Err(e) => match read_old_config(&config_ini) {
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
