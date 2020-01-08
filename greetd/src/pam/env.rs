use std::ffi::CStr;

use libc::c_char;
use pam_sys::{getenvlist, raw, PamHandle};

pub struct PamEnvList {
    ptr: *const *const c_char,
}

pub fn get_pam_env(handle: &mut PamHandle) -> Option<PamEnvList> {
    let env = getenvlist(handle);
    if !env.is_null() {
        Some(PamEnvList { ptr: env })
    } else {
        None
    }
}

impl<'a> PamEnvList {
    pub fn to_vec(&'a self) -> Vec<&'a CStr> {
        let mut vec = Vec::new();
        let mut idx = 0;
        loop {
            let env_ptr: *const *const c_char = unsafe { self.ptr.offset(idx) };
            if unsafe { !(*env_ptr).is_null() } {
                idx += 1;

                let env = unsafe { CStr::from_ptr(*env_ptr) };
                vec.push(env);
            } else {
                // Reached the end of the env array -> break out of the loop
                break;
            }
        }

        vec
    }
}

#[cfg(target_os = "linux")]
impl Drop for PamEnvList {
    fn drop(&mut self) {
        unsafe { raw::pam_misc_drop_env(self.ptr as *mut *mut c_char) };
    }
}
