use super::worker::{ParentToSessionChild, QuestionStyle, SessionChildToParent};
use crate::pam::converse::Converse;

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
        msg.send(self.sock)
            .map_err(|e| eprintln!("pam_conv: {}", e))?;

        let msg = ParentToSessionChild::recv(self.sock)
            .map_err(|e| eprintln!("pam_conv: {}", e))?;

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
