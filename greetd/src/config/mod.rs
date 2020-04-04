use std::{env, fs::read_to_string};

use getopts::Options;

use super::error::Error;

#[derive(Debug, Eq, PartialEq)]
pub enum VtSelection {
    Next,
    Current,
    None,
    Specific(usize),
}

#[derive(Debug, Eq, PartialEq)]
pub struct ConfigSession {
    pub command: String,
    pub user: String,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ConfigInternal {
    pub socket_path: String,
    pub session_worker: usize,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ConfigTerminal {
    pub vt: VtSelection,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ConfigFile {
    pub terminal: ConfigTerminal,
    pub default_session: ConfigSession,
    pub initial_session: Option<ConfigSession>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Config {
    pub file: ConfigFile,
    pub internal: ConfigInternal,
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    println!("{}", opts.usage(&brief));
    println!("For more details, see greetd(1).");
}

fn parse_old_config(config: &ini::Ini) -> Result<ConfigFile, Error> {
    let general = config.section(None::<String>).ok_or("no general section")?;
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
        terminal: ConfigTerminal { vt },
        default_session: ConfigSession {
            user: greeter_user.to_string(),
            command: greeter.to_string(),
        },
        initial_session: None,
    })
}

fn parse_new_config(config: &ini::Ini) -> Result<ConfigFile, Error> {
    let default_session = match config.section(Some("default_session")) {
        Some(section) => Ok(ConfigSession {
            command: section
                .get("command")
                .ok_or("default_session contains no command")?
                .to_string(),
            user: section.get("user").unwrap_or("greeter").to_string(),
        }),
        None => Err("no default_session specified"),
    }?;

    let initial_session = match config.section(Some("initial_session")) {
        Some(section) => Some(ConfigSession {
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

fn parse_config(config_str: &str) -> Result<ConfigFile, Error> {
    let config_ini = ini::Ini::load_from_str(config_str)?;
    match parse_new_config(&config_ini) {
        Ok(v) => Ok(v),
        Err(e) => match parse_old_config(&config_ini) {
            Ok(v) => {
                eprintln!("warning: Fallback to old config format, caused by : {}", e);
                Ok(v)
            }
            Err(_e) => Err(Error::ConfigError(format!(
                "unable to parse configuration file: {}",
                e
            ))),
        },
    }
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

    let config_str = read_to_string(
        matches
            .opt_str("config")
            .unwrap_or_else(|| "/etc/greetd/config.toml".to_string()),
    )?;
    let file = parse_config(&config_str)?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_config() {
        let config = parse_config(
            "
vt = 1
greeter = \"agreety\"
greeter_user = \"greeter\"
",
        )
        .expect("config didn't parse");
        assert_eq!(
            config,
            ConfigFile {
                terminal: ConfigTerminal {
                    vt: VtSelection::Specific(1)
                },
                default_session: ConfigSession {
                    command: "agreety".to_string(),
                    user: "greeter".to_string(),
                },
                initial_session: None,
            }
        );

        let config = parse_config(
            "
vt = \"next\"
greeter = \"agreety\"
",
        )
        .expect("config didn't parse");
        assert_eq!(
            config,
            ConfigFile {
                terminal: ConfigTerminal {
                    vt: VtSelection::Next
                },
                default_session: ConfigSession {
                    command: "agreety".to_string(),
                    user: "greeter".to_string(),
                },
                initial_session: None,
            }
        );
    }

    #[test]
    fn minimal_config() {
        let config = parse_config(
            "
[terminal]
vt = 1
[default_session]
command = \"agreety\"
",
        )
        .expect("config didn't parse");
        assert_eq!(
            config,
            ConfigFile {
                terminal: ConfigTerminal {
                    vt: VtSelection::Specific(1)
                },
                default_session: ConfigSession {
                    command: "agreety".to_string(),
                    user: "greeter".to_string(),
                },
                initial_session: None,
            }
        );
    }

    #[test]
    fn initial_session() {
        let config = parse_config(
            "
[terminal]\nvt = 1\n[default_session]\ncommand = \"agreety\"
[initial_session]
command = \"sway\"
user = \"john\"
",
        )
        .expect("config didn't parse");
        assert_eq!(
            config,
            ConfigFile {
                terminal: ConfigTerminal {
                    vt: VtSelection::Specific(1)
                },
                default_session: ConfigSession {
                    command: "agreety".to_string(),
                    user: "greeter".to_string(),
                },
                initial_session: Some(ConfigSession {
                    command: "sway".to_string(),
                    user: "john".to_string(),
                }),
            }
        );
    }

    #[test]
    fn terminal() {
        let config = parse_config(
            "
[default_session]\ncommand = \"agreety\"
[terminal]
vt = 1
",
        )
        .expect("config didn't parse");
        assert_eq!(
            config,
            ConfigFile {
                terminal: ConfigTerminal {
                    vt: VtSelection::Specific(1)
                },
                default_session: ConfigSession {
                    command: "agreety".to_string(),
                    user: "greeter".to_string(),
                },
                initial_session: None,
            }
        );
        let config = parse_config(
            "
[default_session]\ncommand = \"agreety\"
[terminal]
vt = next
",
        )
        .expect("config didn't parse");
        assert_eq!(
            config,
            ConfigFile {
                terminal: ConfigTerminal {
                    vt: VtSelection::Next
                },
                default_session: ConfigSession {
                    command: "agreety".to_string(),
                    user: "greeter".to_string(),
                },
                initial_session: None,
            }
        );
        let config = parse_config(
            "
[default_session]\ncommand = \"agreety\"
[terminal]
vt = current
",
        )
        .expect("config didn't parse");
        assert_eq!(
            config,
            ConfigFile {
                terminal: ConfigTerminal {
                    vt: VtSelection::Current
                },
                default_session: ConfigSession {
                    command: "agreety".to_string(),
                    user: "greeter".to_string(),
                },
                initial_session: None,
            }
        );
    }

    #[test]
    fn invalid_initial_session() {
        assert!(parse_config(
            "
[terminal]\nvt = 1\n[default_session]\ncommand = \"agreety\"
[initial_session]
"
        )
        .is_err());
        assert!(parse_config(
            "
[terminal]\nvt = 1\n[default_session]\ncommand = \"agreety\"
[initial_session]
command = \"sway\"
"
        )
        .is_err());
        assert!(parse_config(
            "
[terminal]\nvt = 1\n[default_session]\ncommand = \"agreety\"
[initial_session]
user = \"user\"
"
        )
        .is_err());
    }

    #[test]
    fn invalid_default_session() {
        assert!(parse_config(
            "
[terminal]\nvt = 1
[default_session]
"
        )
        .is_err());
        assert!(parse_config(
            "
[terminal]\nvt = 1
[default_session]
user = \"john\"
"
        )
        .is_err());
    }
}
