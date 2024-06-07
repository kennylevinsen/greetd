use std::{ffi::CStr, mem, pin::Pin};

use libc::{c_char, c_int, c_void, calloc, free, memcpy, size_t};
use pam_sys::{PamConversation, PamMessage, PamMessageStyle, PamResponse, PamReturnCode};

use super::converse::Converse;

use crate::scrambler::Scrambler;

pub struct PamConvHandlerWrapper<'a> {
    pub handler: Pin<Box<dyn Converse + 'a>>,
}

pub fn make_conversation(conv: &mut PamConvHandlerWrapper) -> PamConversation {
    PamConversation {
        conv: Some(converse),
        data_ptr: conv as *mut PamConvHandlerWrapper as *mut c_void,
    }
}

unsafe fn to_cstr(mut s: String) -> *mut c_char {
    let a = calloc(1, s.len() + 1) as *mut c_char;
    if a.is_null() {
        panic!("unable to allocate C string");
    }
    memcpy(a as *mut c_void, s.as_ptr() as *const c_void, s.len());
    s.scramble();
    return a;
}

pub extern "C" fn converse(
    num_msg: c_int,
    msg: *mut *mut PamMessage,
    out_resp: *mut *mut PamResponse,
    appdata_ptr: *mut c_void,
) -> c_int {
    // allocate space for responses
    let resp = unsafe {
        calloc(num_msg as usize, mem::size_of::<PamResponse>() as size_t) as *mut PamResponse
    };
    if resp.is_null() {
        return PamReturnCode::BUF_ERR as c_int;
    }

    let wrapper = unsafe { &*(appdata_ptr as *const PamConvHandlerWrapper) };

    let mut result: PamReturnCode = PamReturnCode::SUCCESS;
    for i in 0..num_msg as isize {
        // get indexed values
        let m: &mut PamMessage = unsafe { &mut **(msg.offset(i)) };
        let r: &mut PamResponse = unsafe { &mut *(resp.offset(i)) };
        let msg = unsafe { CStr::from_ptr(m.msg) };
        let msg = match msg.to_str() {
            Ok(m) => m,
            Err(_) => {
                result = PamReturnCode::CONV_ERR;
                break;
            }
        };
        // match on msg_style
        match PamMessageStyle::from(m.msg_style) {
            PamMessageStyle::PROMPT_ECHO_ON => {
                if let Ok(handler_response) = wrapper.handler.prompt_echo(msg) {
                    r.resp = unsafe { to_cstr(handler_response) };
                } else {
                    result = PamReturnCode::CONV_ERR;
                }
            }
            PamMessageStyle::PROMPT_ECHO_OFF => {
                if let Ok(handler_response) = wrapper.handler.prompt_blind(msg) {
                    r.resp = unsafe { to_cstr(handler_response) };
                } else {
                    result = PamReturnCode::CONV_ERR;
                }
            }
            PamMessageStyle::ERROR_MSG => {
                if wrapper.handler.error(msg).is_err() {
                    result = PamReturnCode::CONV_ERR;
                }
            }
            PamMessageStyle::TEXT_INFO => {
                if wrapper.handler.info(msg).is_err() {
                    result = PamReturnCode::CONV_ERR;
                }
            }
        }
        if result != PamReturnCode::SUCCESS {
            break;
        }
    }

    // free allocated memory if an error occured
    if result != PamReturnCode::SUCCESS {
        // Free any strdup'd response strings
        for i in 0..num_msg as isize {
            let r: &mut PamResponse = unsafe { &mut *(resp.offset(i)) };
            if !r.resp.is_null() {
                unsafe { free(r.resp as *mut c_void) };
            }
        }

        // Free the response array
        unsafe { free(resp as *mut c_void) };
    } else {
        unsafe { *out_resp = resp };
    }

    result as c_int
}
