use std::{
    error::Error,
    ffi::{CStr, CString},
    io,
    pin::Pin,
    ptr,
};

use libc::c_void;
use pam_sys::{PamFlag, PamHandle, PamItemType, PamReturnCode};

use super::{
    converse::Converse,
    env::{get_pam_env, PamEnvList},
    ffi::{make_conversation, PamConvHandlerWrapper},
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
        user: &'a str,
        pam_conv: Pin<Box<dyn Converse + 'a>>,
    ) -> Result<PamSession<'a>, Box<dyn Error>> {
        let mut pch = Box::pin(PamConvHandlerWrapper { handler: pam_conv });
        let conv = make_conversation(&mut *pch);
        let mut pam_handle: *mut PamHandle = ptr::null_mut();

        match pam_sys::start(service, Some(user), &conv, &mut pam_handle) {
            PamReturnCode::SUCCESS => Ok(PamSession {
                handle: unsafe { &mut *pam_handle },
                lifetime_extender: pch,
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

    pub fn getenv<'b>(&'b mut self, v: &str) -> Option<&'b str> {
        pam_sys::getenv(self.handle, v)
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

    pub fn strerror(&mut self) -> Option<&str> {
        pam_sys::strerror(self.handle, self.last_code)
    }
}
