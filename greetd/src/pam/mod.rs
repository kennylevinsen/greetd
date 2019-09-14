extern crate pam_sys;

pub mod session;
mod env;
mod ffi;

use pam_sys::PamReturnCode;
use std::ffi::{CStr, CString};

pub struct PamError(PamReturnCode);

impl std::fmt::Debug for PamError {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.0.fmt(fmt)
    }
}

impl std::fmt::Display for PamError {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.0.fmt(fmt)
    }
}

impl std::error::Error for PamError {
    fn description(&self) -> &str {
        "PAM returned an error code"
    }
}

impl From<PamReturnCode> for PamError {
    fn from(err: PamReturnCode) -> PamError {
        PamError(err)
    }
}

/// A trait representing the PAM authentification conversation
///
/// PAM authentification is done as a conversation mechanism, in which PAM
/// asks several questions and the client (your code) answers them. This trait
/// is a representation of such a conversation, which one method for each message
/// PAM can send you.
///
/// This is the trait to implement if you want to customize the conversation with
/// PAM. If you just want a simple login/password authentication, you can use the
/// `PasswordConv` implementation provided by this crate.
pub trait Converse {
    /// PAM requests a value that should be echoed to the user as they type it
    ///
    /// This would typically be the username. The exact question is provided as the
    /// `msg` argument if you wish to display it to your user.
    fn prompt_echo(&mut self, msg: &CStr) -> ::std::result::Result<CString, ()>;
    /// PAM requests a value that should be typed blindly by the user
    ///
    /// This would typically be the password. The exact question is provided as the
    /// `msg` argument if you wish to display it to your user.
    fn prompt_blind(&mut self, msg: &CStr) -> ::std::result::Result<CString, ()>;
    /// This is an informational message from PAM
    fn info(&mut self, msg: &CStr);
    /// This is an error message from PAM
    fn error(&mut self, msg: &CStr);
    /// Get the username that is being authenticated
    ///
    /// This method is not a PAM callback, but is rather used by the `Authenticator` to
    /// setup the environment when opening a session.
    fn username(&self) -> &str;
}

/// A minimalistic conversation handler, that uses given login and password
///
/// This conversation handler is not really interactive, but simply returns to
/// PAM the value that have been set using the `set_credentials` method.
pub struct PasswordConv {
    login: String,
    passwd: String,
}

impl PasswordConv {
    /// Create a new `PasswordConv` handler
    fn new() -> PasswordConv {
        PasswordConv {
            login: String::new(),
            passwd: String::new(),
        }
    }

    /// Set the credentials that this handler will provide to PAM
    pub fn set_credentials<U: Into<String>, V: Into<String>>(&mut self, login: U, password: V) {
        self.login = login.into();
        self.passwd = password.into();
    }
}

impl Converse for PasswordConv {
    fn prompt_echo(&mut self, _msg: &CStr) -> Result<CString, ()> {
        CString::new(self.login.clone()).map_err(|_| ())
    }
    fn prompt_blind(&mut self, _msg: &CStr) -> Result<CString, ()> {
        CString::new(self.passwd.clone()).map_err(|_| ())
    }
    fn info(&mut self, _msg: &CStr) {}
    fn error(&mut self, msg: &CStr) {
        eprintln!("[PAM ERROR] {}", msg.to_string_lossy());
    }
    fn username(&self) -> &str {
        &self.login
    }
}