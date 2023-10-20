mod ioctl;

use crate::error::Error;
use nix::{
    fcntl::{open, OFlag},
    sys::stat::Mode,
    unistd::{close, dup2, fchown, write, Gid, Uid},
};
use std::{ffi::CStr, os::unix::io::RawFd};

#[allow(dead_code)]
pub enum KdMode {
    Text,
    Graphics,
}

impl KdMode {
    fn to_const(&self) -> i32 {
        match self {
            KdMode::Text => ioctl::KDTEXT,
            KdMode::Graphics => ioctl::KDGRAPHICS,
        }
    }
}

pub struct Terminal {
    fd: RawFd,
    autoclose: bool,
}

impl Drop for Terminal {
    fn drop(&mut self) {
        if self.autoclose {
            close(self.fd).unwrap();
        }
    }
}

fn ttyname_r(fd: RawFd) -> Result<String, Error> {
    let mut arr: [u8; 32] = [0; 32];
    let res = unsafe {
        libc::ttyname_r(
            fd as libc::c_int,
            &mut arr[0] as *mut u8 as *mut libc::c_char,
            31,
        )
    };
    if res != 0 {
        return Err("ttyname_r failed".into());
    }
    let len = unsafe { libc::strnlen(&arr[0] as *const u8 as *const libc::c_char, 31) };
    let s = CStr::from_bytes_with_nul(&arr[..len + 1])
        .map_err(|e| Error::Error(format!("ttyname_r result conversion failed: {}", e)))?;
    Ok(s.to_str()
        .map_err(|e| Error::Error(format!("ttyname_r result conversion failed: {}", e)))?
        .to_string())
}

impl Terminal {
    /// Open the terminal file for the specified terminal number.
    pub fn open(terminal: &str) -> Result<Terminal, Error> {
        let res = open(
            terminal,
            OFlag::O_RDWR | OFlag::O_NOCTTY,
            Mode::from_bits_truncate(0o666),
        );
        match res {
            Ok(fd) => Ok(Terminal {
                fd,
                autoclose: true,
            }),
            Err(e) => return Err(format!("terminal: unable to open: {}", e).into()),
        }
    }

    /// Open the terminal from stdin
    pub fn stdin() -> Terminal {
        Terminal {
            fd: 0 as RawFd,
            autoclose: false,
        }
    }

    /// Returns the name of the TTY
    pub fn ttyname(&self) -> Result<String, Error> {
        ttyname_r(self.fd)
    }

    /// Set the kernel display to either graphics or text mode. Graphivs mode
    /// disables the kernel console on this VT, and also disables blanking
    /// between VT switches if both source and target VT is in graphics mode.
    pub fn kd_setmode(&self, mode: KdMode) -> Result<(), Error> {
        let mode = mode.to_const();
        let ret = unsafe { ioctl::kd_setmode(self.fd, mode) };

        if let Err(v) = ret {
            Err(format!("terminal: unable to set kernel display mode: {}", v).into())
        } else {
            Ok(())
        }
    }

    /// Switches to the specified VT and waits for completion of switch.
    fn vt_activate(&self, target_vt: usize) -> Result<(), Error> {
        if let Err(v) = unsafe { ioctl::vt_activate(self.fd, target_vt as i32) } {
            return Err(format!("terminal: unable to activate: {}", v).into());
        }
        if let Err(v) = unsafe { ioctl::vt_waitactive(self.fd, target_vt as i32) } {
            return Err(format!("terminal: unable to wait for activation: {}", v).into());
        }
        Ok(())
    }

    /// Waits for specified VT to become active.
    pub fn vt_waitactive(&self, target_vt: usize) -> Result<(), Error> {
        if let Err(v) = unsafe { ioctl::vt_waitactive(self.fd, target_vt as i32) } {
            return Err(format!("terminal: unable to wait for activation: {}", v).into());
        }
        Ok(())
    }

    /// Set the VT mode to VT_AUTO with everything cleared.
    fn vt_mode_clean(&self) -> Result<(), Error> {
        let mode = ioctl::vt_mode {
            mode: ioctl::VT_AUTO,
            waitv: 0,
            relsig: 0,
            acqsig: 0,
            frsig: 0,
        };
        let res = unsafe { ioctl::vt_setmode(self.fd, &mode) };

        if let Err(v) = res {
            Err(format!("terminal: unable to set vt mode: {}", v).into())
        } else {
            Ok(())
        }
    }

    /// Set a VT mode, switch to the VT and wait for its activation. On Linux,
    /// this will use VT_SETACTIVATE, which will both set the mode and switch
    /// to the VT under the kernel console lock. On other platforms,
    /// VT_SETMODE followed by VT_ACTIVATE is used. For all platforms,
    /// VT_WAITACTIVE is used to wait for shell activation.
    pub fn vt_setactivate(&self, target_vt: usize) -> Result<(), Error> {
        if cfg!(target_os = "linux") {
            let arg = ioctl::vt_setactivate {
                console: target_vt as u64,
                mode: ioctl::vt_mode {
                    mode: ioctl::VT_AUTO,
                    waitv: 0,
                    relsig: 0,
                    acqsig: 0,
                    frsig: 0,
                },
            };
            if let Err(v) = unsafe { ioctl::vt_setactivate(self.fd, &arg) } {
                return Err(format!("terminal: unable to setactivate: {}", v).into());
            }
            if let Err(v) = unsafe { ioctl::vt_waitactive(self.fd, target_vt as i32) } {
                return Err(format!("terminal: unable to wait for activation: {}", v).into());
            }
        } else {
            self.vt_mode_clean()?;
            self.vt_activate(target_vt)?;
        }
        Ok(())
    }

    /// Retrieves the current VT number.
    pub fn vt_get_current(&self) -> Result<usize, Error> {
        let mut state = ioctl::vt_state {
            v_active: 0,
            v_signal: 0,
            v_state: 0,
        };
        let res = unsafe { ioctl::vt_getstate(self.fd, &mut state as *mut ioctl::vt_state) };

        if let Err(v) = res {
            Err(format!("terminal: unable to get current vt: {}", v).into())
        } else if state.v_active < 1 {
            Err(format!("terminal: current vt invalid: {}", state.v_active).into())
        } else {
            Ok(state.v_active as usize)
        }
    }

    /// Find the next unallocated VT, allocate it and return the number. Note
    /// that allocation does not mean exclusivity, and another process may take
    /// and use the VT before you get to it.
    pub fn vt_get_next(&self) -> Result<usize, Error> {
        let mut next_vt: i64 = 0;
        let res = unsafe { ioctl::vt_openqry(self.fd, &mut next_vt as *mut i64) };

        if let Err(v) = res {
            Err(format!("terminal: unable to get next vt: {}", v).into())
        } else if next_vt < 1 {
            Err(format!("terminal: next vt invalid: {}", next_vt).into())
        } else {
            Ok(next_vt as usize)
        }
    }

    /// Hook up stdin, stdout and stderr of the current process ot this
    /// terminal.
    pub fn term_connect_pipes(&self) -> Result<(), Error> {
        let res = dup2(self.fd, 0)
            .and_then(|_| dup2(self.fd, 1))
            .and_then(|_| dup2(self.fd, 2));

        if let Err(v) = res {
            Err(format!("terminal: unable to connect pipes: {}", v).into())
        } else {
            Ok(())
        }
    }

    /// Clear this terminal by sending the appropciate escape codes to it. Only
    /// affects text mode.
    pub fn term_clear(&self) -> Result<(), Error> {
        let res = write(self.fd, b"\x1B[H\x1B[2J");
        if let Err(v) = res {
            Err(format!("terminal: unable to clear: {}", v).into())
        } else {
            Ok(())
        }
    }

    // Forcibly take control of the terminal referred to by this fd.
    pub fn term_take_ctty(&self) -> Result<(), Error> {
        let res = unsafe { ioctl::term_tiocsctty(self.fd, 1) };

        match res {
            Err(e) => Err(format!("terminal: unable to take controlling terminal: {}", e).into()),
            Ok(_) => Ok(()),
        }
    }

    pub fn term_chown(&self, owner: Uid, group: Gid) -> Result<(), Error> {
        let res = fchown(self.fd, Some(owner), Some(group));

        match res {
            Err(e) => Err(format!("terminal: unable to set ownership of terminal: {}", e).into()),
            Ok(_) => Ok(()),
        }
    }
}
