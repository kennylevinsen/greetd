use std::{
    ffi::{CStr, CString},
    os::raw::c_char,
    pin::Pin,
    ptr,
};

use libc::c_void;
use pam_sys::{PamFlag, PamHandle, PamItemType, PamReturnCode};

use super::{
    converse::Converse,
    env::{get_pam_env, PamEnvList},
    ffi::{make_conversation, PamConvHandlerWrapper},
    PamError,
};

pub struct PamSession<'a> {
    handle: &'a mut PamHandle,
    #[allow(unused)]
    lifetime_extender: Pin<Box<PamConvHandlerWrapper<'a>>>,
    last_code: PamReturnCode,
}

impl<'a> PamSession<'a> {
    pub fn start(
        service: &str,
        user: &str,
        pam_conv: Pin<Box<dyn Converse + 'a>>,
    ) -> Result<PamSession<'a>, PamError> {
        let mut pch = Box::pin(PamConvHandlerWrapper { handler: pam_conv });
        let conv = make_conversation(&mut pch);
        let mut pam_handle: *mut PamHandle = ptr::null_mut();

        match pam_sys::start(service, Some(user), &conv, &mut pam_handle) {
            PamReturnCode::SUCCESS => Ok(PamSession {
                handle: unsafe { &mut *pam_handle },
                lifetime_extender: pch,
                last_code: PamReturnCode::SUCCESS,
            }),
            rc => Err(PamError::from_rc("pam_start", rc)),
        }
    }

    pub fn authenticate(&mut self, flags: PamFlag) -> Result<(), PamError> {
        self.last_code = pam_sys::authenticate(self.handle, flags);
        match self.last_code {
            PamReturnCode::SUCCESS => Ok(()),
            rc => Err(PamError::from_rc("pam_authenticate", rc)),
        }
    }

    pub fn change_auth_token(&mut self, flags: PamFlag) -> Result<(), PamError> {
        self.last_code = pam_sys::chauthtok(self.handle, flags);
        match self.last_code {
            PamReturnCode::SUCCESS => Ok(()),
            rc => Err(PamError::from_rc("pam_chauthtok", rc)),
        }
    }

    pub fn acct_mgmt(&mut self, flags: PamFlag) -> Result<(), PamError> {
        self.last_code = pam_sys::acct_mgmt(self.handle, flags);
        match self.last_code {
            PamReturnCode::SUCCESS => Ok(()),
            rc => Err(PamError::from_rc("pam_acct_mgmt", rc)),
        }
    }

    pub fn setcred(&mut self, flags: PamFlag) -> Result<(), PamError> {
        self.last_code = pam_sys::setcred(self.handle, flags);
        match self.last_code {
            PamReturnCode::SUCCESS => Ok(()),
            rc => Err(PamError::from_rc("pam_setcred", rc)),
        }
    }

    pub fn open_session(&mut self, flags: PamFlag) -> Result<(), PamError> {
        self.last_code = pam_sys::open_session(self.handle, flags);
        match self.last_code {
            PamReturnCode::SUCCESS => Ok(()),
            rc => Err(PamError::from_rc("pam_open_session", rc)),
        }
    }

    pub fn close_session(&mut self, flags: PamFlag) -> Result<(), PamError> {
        self.last_code = pam_sys::close_session(self.handle, flags);
        match self.last_code {
            PamReturnCode::SUCCESS => Ok(()),
            rc => Err(PamError::from_rc("pam_close_session", rc)),
        }
    }

    pub fn putenv(&mut self, v: &str) -> Result<(), PamError> {
        self.last_code = pam_sys::putenv(self.handle, v);
        match self.last_code {
            PamReturnCode::SUCCESS => Ok(()),
            rc => Err(PamError::from_rc("pam_putenv", rc)),
        }
    }

    pub fn set_item(&mut self, item: PamItemType, value: &str) -> Result<(), PamError> {
        let s = CString::new(value).unwrap();
        self.last_code = PamReturnCode::from(unsafe {
            // pam_set_item is exposed in a weird way in pam_sys::wrapped, so
            // we use the raw version here instead
            pam_sys::raw::pam_set_item(self.handle, item as i32, s.as_ptr().cast::<c_void>())
        });
        match self.last_code {
            PamReturnCode::SUCCESS => Ok(()),
            rc => Err(PamError::from_rc("pam_set_item", rc)),
        }
    }

    pub fn get_user(&mut self) -> Result<String, PamError> {
        let mut p: *const c_char = ptr::null_mut();
        self.last_code = pam_sys::get_user(self.handle, &mut p, ptr::null());
        match self.last_code {
            PamReturnCode::SUCCESS => {
                Ok((unsafe { CStr::from_ptr(p) }).to_str().unwrap().to_string())
            }
            rc => Err(PamError::from_rc("pam_get_user", rc)),
        }
    }

    pub fn getenvlist(&mut self) -> Result<PamEnvList, PamError> {
        match get_pam_env(self.handle) {
            Some(v) => Ok(v),
            None => Err(PamError::Error(
                "unable to retrieve environment".to_string(),
            )),
        }
    }

    pub fn end(&mut self) -> Result<(), PamError> {
        match pam_sys::end(self.handle, self.last_code) {
            PamReturnCode::SUCCESS => Ok(()),
            rc => Err(PamError::from_rc("pam_end", rc)),
        }
    }
}
