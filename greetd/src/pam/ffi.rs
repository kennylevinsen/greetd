use std::ffi::CStr;
use std::mem;

use libc::{c_int, c_void, calloc, free, size_t, strdup};
use pam_sys::{PamConversation, PamMessage, PamMessageStyle, PamResponse, PamReturnCode};

use super::converse::Converse;

pub fn make_conversation<C: Converse>(user_converse: &mut C) -> PamConversation {
    PamConversation {
        conv: Some(converse::<C>),
        data_ptr: user_converse as *mut C as *mut c_void,
    }
}

pub extern "C" fn converse<C: Converse>(
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

    let handler = unsafe { &mut *(appdata_ptr as *mut C) };

    let mut result: PamReturnCode = PamReturnCode::SUCCESS;
    for i in 0..num_msg as isize {
        // get indexed values
        let m: &mut PamMessage = unsafe { &mut **(msg.offset(i)) };
        let r: &mut PamResponse = unsafe { &mut *(resp.offset(i)) };
        let msg = unsafe { CStr::from_ptr(m.msg) };
        // match on msg_style
        match PamMessageStyle::from(m.msg_style) {
            PamMessageStyle::PROMPT_ECHO_ON => {
                if let Ok(handler_response) = handler.prompt_echo(msg) {
                    r.resp = unsafe { strdup(handler_response.as_ptr()) };
                } else {
                    result = PamReturnCode::CONV_ERR;
                }
            }
            PamMessageStyle::PROMPT_ECHO_OFF => {
                if let Ok(handler_response) = handler.prompt_blind(msg) {
                    r.resp = unsafe { strdup(handler_response.as_ptr()) };
                } else {
                    result = PamReturnCode::CONV_ERR;
                }
            }
            PamMessageStyle::ERROR_MSG => handler.error(msg),
            PamMessageStyle::TEXT_INFO => handler.info(msg),
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
