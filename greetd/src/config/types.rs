use super::{defaults::*, vtselection::VtSelection};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ConfigDefaultSession {
    pub command: String,
    #[serde(default = "default_greeter_user")]
    pub user: String,
}

pub struct ConfigInternal {
    pub socket_path: String,
    pub session_worker: usize,
}

#[derive(Debug, Deserialize)]
pub struct ConfigTerminal {
    #[serde(default = "default_vt")]
    pub vt: VtSelection,
}

impl Default for ConfigTerminal {
    fn default() -> ConfigTerminal {
        ConfigTerminal { vt: default_vt() }
    }
}

#[derive(Debug, Deserialize)]
pub struct ConfigFile {
    pub terminal: ConfigTerminal,
    pub default_session: ConfigDefaultSession,
}

pub struct Config {
    pub file: ConfigFile,
    pub internal: ConfigInternal,
}
