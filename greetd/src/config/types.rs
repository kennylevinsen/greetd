#[derive(Debug)]
pub enum VtSelection {
    Next,
    Current,
    None,
    Specific(usize),
}

#[derive(Debug)]
pub struct ConfigDefaultSession {
    pub command: String,
    pub user: String,
}

#[derive(Debug)]
pub struct ConfigInitialSession {
    pub command: String,
    pub user: String,
}

#[derive(Debug)]
pub struct ConfigInternal {
    pub socket_path: String,
    pub session_worker: usize,
}

#[derive(Debug)]
pub struct ConfigTerminal {
    pub vt: VtSelection,
}

#[derive(Debug)]
pub struct ConfigFile {
    pub terminal: ConfigTerminal,
    pub default_session: ConfigDefaultSession,
    pub initial_session: Option<ConfigInitialSession>,
}

#[derive(Debug)]
pub struct Config {
    pub file: ConfigFile,
    pub internal: ConfigInternal,
}
