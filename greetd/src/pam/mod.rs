pub mod converse;
mod env;
mod ffi;
pub mod session;

use thiserror::Error as ThisError;

use pam_sys::PamReturnCode;

#[derive(Debug, ThisError)]
pub enum PamError {
    #[error("{0}")]
    Error(String),
    #[error("{0}")]
    AuthError(String),
    #[error("new auth token required: {0}")]
    NewAuthTokenRequired(String),
    #[error("abort error: {0}")]
    AbortError(String),
}

impl PamError {
    pub fn from_rc(prefix: &str, rc: PamReturnCode) -> PamError {
        match rc {
            PamReturnCode::ABORT => PamError::AbortError(format!("{prefix}: {rc:?}")),
            PamReturnCode::AUTH_ERR
            | PamReturnCode::MAXTRIES
            | PamReturnCode::CRED_EXPIRED
            | PamReturnCode::ACCT_EXPIRED
            | PamReturnCode::CRED_INSUFFICIENT
            | PamReturnCode::USER_UNKNOWN
            | PamReturnCode::PERM_DENIED
            | PamReturnCode::SERVICE_ERR => PamError::AuthError(format!("{prefix}: {rc:?}")),
            PamReturnCode::NEW_AUTHTOK_REQD => {
                PamError::NewAuthTokenRequired(format!("{prefix}: {rc:?}"))
            }
            _ => PamError::Error(format!("{prefix}: {rc:?}")),
        }
    }
}
