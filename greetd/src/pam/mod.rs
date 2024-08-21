pub mod converse;
mod env;
mod ffi;
pub mod session;

use thiserror::Error as ThisError;

use pam_sys::PamReturnCode;

#[derive(Debug, ThisError)]
pub enum PamError {
    #[error("{0}")]
    Error(String, PamReturnCode),
    #[error("{0}")]
    AuthError(String, PamReturnCode),
    #[error("abort error: {0}")]
    AbortError(String, PamReturnCode),
}

impl PamError {
    pub fn from_rc(prefix: &str, rc: PamReturnCode) -> PamError {
        match rc {
            PamReturnCode::ABORT => PamError::AbortError(format!("{}: {:?}", prefix, rc), rc),
            PamReturnCode::AUTH_ERR
            | PamReturnCode::MAXTRIES
            | PamReturnCode::CRED_EXPIRED
            | PamReturnCode::ACCT_EXPIRED
            | PamReturnCode::CRED_INSUFFICIENT
            | PamReturnCode::USER_UNKNOWN
            | PamReturnCode::PERM_DENIED
            | PamReturnCode::SERVICE_ERR => {
                PamError::AuthError(format!("{}: {:?}", prefix, rc), rc)
            }
            _ => PamError::Error(format!("{}: {:?}", prefix, rc), rc),
        }
    }
}
