use serde::Deserialize;

use crate::error::Error;

use super::vtselection::VtSelection;

use super::{defaults::*, types::*};

#[derive(Debug, Deserialize)]
pub struct OldConfig {
    #[serde(default = "default_vt")]
    pub vt: VtSelection,
    pub greeter: String,
    #[serde(default = "default_greeter_user")]
    pub greeter_user: String,
}

pub fn try_read_old_config(s: &str) -> Result<super::ConfigFile, Error> {
    let oldconfig: OldConfig = match toml::from_str(&s) {
        Ok(v) => v,
        Err(e) => {
            return Err(Error::ConfigError(
                format!("unable to parse configuration file: {}", e).to_string(),
            ))
        }
    };

    Ok(ConfigFile {
        terminal: ConfigTerminal { vt: oldconfig.vt },
        default_session: ConfigDefaultSession {
            user: oldconfig.greeter_user,
            command: oldconfig.greeter,
        },
    })
}
