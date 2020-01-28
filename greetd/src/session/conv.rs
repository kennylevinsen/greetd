use super::worker::{AuthMessageType, ParentToSessionChild, SessionChildToParent};
use crate::pam::converse::Converse;

/// SessionConv is a PAM conversation implementation that forwards questions
/// over a socket.
pub struct SessionConv<'a> {
    sock: &'a std::os::unix::net::UnixDatagram,
}

impl<'a> SessionConv<'a> {
    fn question(&self, msg: &str, style: AuthMessageType) -> Result<String, ()> {
        let msg = SessionChildToParent::PamMessage {
            style,
            msg: msg.to_string(),
        };
        msg.send(self.sock)
            .map_err(|e| eprintln!("pam_conv: {}", e))?;

        let msg =
            ParentToSessionChild::recv(self.sock).map_err(|e| eprintln!("pam_conv: {}", e))?;

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
        self.question(msg, AuthMessageType::Visible)
    }
    fn prompt_blind(&self, msg: &str) -> Result<String, ()> {
        self.question(msg, AuthMessageType::Secret)
    }
    fn info(&self, msg: &str) -> Result<(), ()> {
        self.question(msg, AuthMessageType::Info).map(|_| ())
    }
    fn error(&self, msg: &str) -> Result<(), ()> {
        self.question(msg, AuthMessageType::Error).map(|_| ())
    }
}
