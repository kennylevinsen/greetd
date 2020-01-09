use std::ffi::{CStr, CString};

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
    fn prompt_echo<'a>(&'a mut self, msg: &CStr) -> ::std::result::Result<&'a CStr, ()>;
    /// PAM requests a value that should be typed blindly by the user
    ///
    /// This would typically be the password. The exact question is provided as the
    /// `msg` argument if you wish to display it to your user.
    fn prompt_blind<'a>(&'a mut self, msg: &CStr) -> ::std::result::Result<&'a CStr, ()>;
    /// This is an informational message from PAM
    fn info(&mut self, msg: &CStr);
    /// This is an error message from PAM
    fn error(&mut self, msg: &CStr);
}

/// A minimalistic conversation handler, that uses given login and password
///
/// This conversation handler is not really interactive, but simply returns to
/// PAM the value that have been set using the `set_credentials` method.
pub struct PasswordConv {
    login: CString,
    passwd: CString,
}

impl PasswordConv {
    /// Create a new `PasswordConv` handler
    pub fn new(login: &str, password: &str) -> PasswordConv {
        PasswordConv {
            login: CString::new(login).unwrap(),
            passwd: CString::new(password).unwrap(),
        }
    }
}

impl Converse for PasswordConv {
    fn prompt_echo<'a>(&'a mut self, _msg: &CStr) -> Result<&'a CStr, ()> {
        Ok(&self.login)
    }
    fn prompt_blind<'a>(&'a mut self, _msg: &CStr) -> Result<&'a CStr, ()> {
        Ok(&self.passwd)
    }
    fn info(&mut self, _msg: &CStr) {}
    fn error(&mut self, msg: &CStr) {
        eprintln!("[PAM ERROR] {}", msg.to_string_lossy());
    }
}
