use std::error::Error;
use std::ffi::c_void;
use std::ffi::{CStr, CString};
use std::io;
use std::ptr;

use pam_sys::{PamFlag, PamHandle, PamItemType, PamReturnCode};

use crate::pam::env::{get_pam_env, PamEnvList};
use crate::pam::ffi::make_conversation;
use crate::pam::PasswordConv;

pub struct PamSession<'a> {
    handle: &'a mut PamHandle,
    pub converse: Box<PasswordConv>,
    last_code: PamReturnCode,
}

impl<'a> PamSession<'a> {
    pub fn start(service: &str) -> Result<PamSession, Box<dyn Error>> {
        let mut pam_conv = Box::new(PasswordConv::new());
        let conv = make_conversation(&mut *pam_conv);
        let mut pam_handle: *mut PamHandle = ptr::null_mut();

        match pam_sys::start(service, None, &conv, &mut pam_handle) {
            PamReturnCode::SUCCESS => Ok(PamSession {
                handle: unsafe { &mut *pam_handle },
                converse: pam_conv,
                last_code: PamReturnCode::SUCCESS,
            }),
            _ => Err(io::Error::new(io::ErrorKind::Other, "unable to start pam session").into()),
        }
    }

    pub fn authenticate(&mut self, flags: PamFlag) -> Result<(), Box<dyn Error>> {
        self.last_code = pam_sys::authenticate(self.handle, flags);
        match self.last_code {
            PamReturnCode::SUCCESS => Ok(()),
            _ => Err(io::Error::new(io::ErrorKind::Other, "unable to authenticate").into()),
        }
    }

    pub fn acct_mgmt(&mut self, flags: PamFlag) -> Result<(), Box<dyn Error>> {
        self.last_code = pam_sys::acct_mgmt(self.handle, flags);
        match self.last_code {
            PamReturnCode::SUCCESS => Ok(()),
            _ => Err(io::Error::new(io::ErrorKind::Other, "unable to activate account").into()),
        }
    }

    pub fn setcred(&mut self, flags: PamFlag) -> Result<(), Box<dyn Error>> {
        self.last_code = pam_sys::setcred(self.handle, flags);
        match self.last_code {
            PamReturnCode::SUCCESS => Ok(()),
            _ => Err(io::Error::new(io::ErrorKind::Other, "unable to set credentials").into()),
        }
    }

    pub fn open_session(&mut self, flags: PamFlag) -> Result<(), Box<dyn Error>> {
        self.last_code = pam_sys::open_session(self.handle, flags);
        match self.last_code {
            PamReturnCode::SUCCESS => Ok(()),
            _ => Err(io::Error::new(io::ErrorKind::Other, "unable to open session").into()),
        }
    }

    pub fn close_session(&mut self, flags: PamFlag) -> Result<(), Box<dyn Error>> {
        self.last_code = pam_sys::close_session(self.handle, flags);
        match self.last_code {
            PamReturnCode::SUCCESS => Ok(()),
            _ => Err(io::Error::new(io::ErrorKind::Other, "unable to close session").into()),
        }
    }

    pub fn putenv(&mut self, v: &str) -> Result<(), Box<dyn Error>> {
        self.last_code = pam_sys::putenv(self.handle, v);
        match self.last_code {
            PamReturnCode::SUCCESS => Ok(()),
            _ => Err(io::Error::new(io::ErrorKind::Other, "unable to put environment").into()),
        }
    }

    pub fn hasenv(&mut self, v: &str) -> bool {
        pam_sys::getenv(self.handle, v).is_some()
    }

    pub fn set_item(&mut self, item: PamItemType, value: &str) -> Result<(), Box<dyn Error>> {
        let s = CString::new(value).unwrap();
        self.last_code = PamReturnCode::from(unsafe {
            // pam_set_item is exposed in a weird way in pam_sys::wrapped, so
            // we use the raw version here instead
            pam_sys::raw::pam_set_item(self.handle, item as i32, s.as_ptr() as *const c_void)
        });
        match self.last_code {
            PamReturnCode::SUCCESS => Ok(()),
            _ => Err(io::Error::new(io::ErrorKind::Other, "unable to set item").into()),
        }
    }

    pub fn get_user(&mut self) -> Result<String, Box<dyn Error>> {
        let mut p: *const i8 = ptr::null_mut();
        self.last_code = pam_sys::get_user(self.handle, &mut p, ptr::null());
        match self.last_code {
            PamReturnCode::SUCCESS => {
                Ok((unsafe { CStr::from_ptr(p) }).to_str().unwrap().to_string())
            }
            _ => Err(io::Error::new(io::ErrorKind::Other, "unable to get user").into()),
        }
    }

    pub fn getenvlist(&mut self) -> Result<PamEnvList, Box<dyn Error>> {
        match get_pam_env(self.handle) {
            Some(v) => Ok(v),
            None => {
                Err(io::Error::new(io::ErrorKind::Other, "unable to retrieve environment").into())
            }
        }
    }

    pub fn end(&mut self) -> Result<(), Box<dyn Error>> {
        match pam_sys::end(self.handle, self.last_code) {
            PamReturnCode::SUCCESS => Ok(()),
            _ => Err(io::Error::new(io::ErrorKind::Other, "unable to end pam session").into()),
        }
    }
}
