use crate::{
    pam::converse::Converse,
    session_worker::{ParentToSessionChild, QuestionStyle, SessionChildToParent},
};

/// SessionConv is a PAM conversation implementation that forwards questions
/// over a socket.
pub struct SessionConv<'a> {
    sock: &'a std::os::unix::net::UnixDatagram,
}

impl<'a> SessionConv<'a> {
    fn question(&self, msg: &str, style: QuestionStyle) -> Result<String, ()> {
        let msg = SessionChildToParent::PamMessage {
            style,
            msg: msg.to_string(),
        };
        let data = serde_json::to_vec(&msg).map_err(|e| eprintln!("pam_conv: {}", e))?;
        self.sock
            .send(&data)
            .map_err(|e| eprintln!("pam_conv: {}", e))?;

        let mut data = [0; 1024];
        let len = self
            .sock
            .recv(&mut data[..])
            .map_err(|e| eprintln!("pam_conv: {}", e))?;
        let msg = serde_json::from_slice(&data[..len]).map_err(|e| eprintln!("pam_conv: {}", e))?;

        match msg {
            ParentToSessionChild::PamResponse { resp, .. } => Ok(resp),
            ParentToSessionChild::Cancel => Err(()),
            _ => Err(()),
        }
    }

    /// Create a new `PasswordConv` handler
    pub fn new(sock: &'a std::os::unix::net::UnixDatagram) -> SessionConv {
        SessionConv { sock }
    }
}

impl<'a> Converse for SessionConv<'a> {
    fn prompt_echo(&self, msg: &str) -> Result<String, ()> {
        self.question(msg, QuestionStyle::Visible)
    }
    fn prompt_blind(&self, msg: &str) -> Result<String, ()> {
        self.question(msg, QuestionStyle::Secret)
    }
    fn info(&self, msg: &str) -> Result<(), ()> {
        self.question(msg, QuestionStyle::Info).map(|_| ())
    }
    fn error(&self, msg: &str) -> Result<(), ()> {
        self.question(msg, QuestionStyle::Error).map(|_| ())
    }
}
