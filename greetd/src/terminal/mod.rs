mod ioctl;

use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::io::{AsRawFd, RawFd};

use nix::unistd::dup2;

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

/// Attempt to return the user to the specified VT in a sensible state.
pub fn restore(terminal: usize) -> Result<(), Box<dyn Error>> {
    let tty_0 = Terminal::open(0)?;
    let tty_x = Terminal::open(terminal)?;
    tty_x.kd_setmode(KdMode::Text)?;
    tty_0.vt_setactivate(terminal)?;
    Ok(())
}

pub struct Terminal {
    // Note: This will close our fd when we're dropped.
    file: File,
}

impl Terminal {
    /// Open the terminal file for the specified terminal number.
    pub fn open(terminal: usize) -> Result<Terminal, Box<dyn Error>> {
        let res = OpenOptions::new()
            .read(true)
            .write(true)
            .open(format!("/dev/tty{}", terminal));

        match res {
            Ok(file) => Ok(Terminal { file }),
            Err(e) => Err(format!("terminal: unable to open: {}", e).into()),
        }
    }

    /// Set the kernel display to either graphics or text mode. Graphivs mode
    /// disables the kernel console on this VT, and also disables blanking
    /// between VT switches if both source and target VT is in graphics mode.
    pub fn kd_setmode(&self, mode: KdMode) -> Result<(), Box<dyn Error>> {
        let mode = mode.to_const();
        let ret = unsafe { ioctl::kd_setmode(self.file.as_raw_fd(), mode) };

        if let Err(v) = ret {
            Err(format!("terminal: unable to set kernel display mode: {}", v).into())
        } else {
            Ok(())
        }
    }

    /// Switches to the specified VT and waits for completion of switch.
    fn vt_activate(&self, target_vt: usize) -> Result<(), Box<dyn Error>> {
        if let Err(v) = unsafe { ioctl::vt_activate(self.file.as_raw_fd(), target_vt as i32) } {
            return Err(format!("terminal: unable to activate: {}", v).into());
        }
        if let Err(v) = unsafe { ioctl::vt_waitactive(self.file.as_raw_fd(), target_vt as i32) } {
            return Err(format!("terminal: unable to wait for activation: {}", v).into());
        }
        Ok(())
    }

    /// Set the VT mode to VT_AUTO with everything cleared.
    fn vt_mode_clean(&self) -> Result<(), Box<dyn Error>> {
        let mode = ioctl::vt_mode {
            mode: ioctl::VT_AUTO,
            waitv: 0,
            relsig: 0,
            acqsig: 0,
            frsig: 0,
        };
        let res = unsafe { ioctl::vt_setmode(self.file.as_raw_fd(), &mode) };

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
    pub fn vt_setactivate(&self, target_vt: usize) -> Result<(), Box<dyn Error>> {
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
            if let Err(v) = unsafe { ioctl::vt_setactivate(self.file.as_raw_fd(), &arg) } {
                return Err(format!("terminal: unable to setactivate: {}", v).into());
            }
            if let Err(v) = unsafe { ioctl::vt_waitactive(self.file.as_raw_fd(), target_vt as i32) }
            {
                return Err(format!("terminal: unable to wait for activation: {}", v).into());
            }
        } else {
            self.vt_mode_clean()?;
            self.vt_activate(target_vt)?;
        }
        Ok(())
    }

    /// Retrieves the current VT number.
    pub fn vt_get_current(&self) -> Result<usize, Box<dyn Error>> {
        let mut state = ioctl::vt_state {
            v_active: 0,
            v_signal: 0,
            v_state: 0,
        };
        let res = unsafe {
            ioctl::vt_getstate(self.file.as_raw_fd(), &mut state as *mut ioctl::vt_state)
        };

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
    pub fn vt_get_next(&self) -> Result<usize, Box<dyn Error>> {
        let mut next_vt: i64 = 0;
        let res = unsafe { ioctl::vt_openqry(self.file.as_raw_fd(), &mut next_vt as *mut i64) };

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
    pub fn term_connect_pipes(&self) -> Result<(), Box<dyn Error>> {
        let res = dup2(self.file.as_raw_fd(), 0 as RawFd)
            .and_then(|_| dup2(self.file.as_raw_fd(), 1 as RawFd))
            .and_then(|_| dup2(self.file.as_raw_fd(), 2 as RawFd));

        if let Err(v) = res {
            Err(format!("terminal: unable to connect pipes: {}", v).into())
        } else {
            Ok(())
        }
    }

    /// Clear this terminal by sending the appropciate escape codes to it. Only
    /// affects text mode.
    pub fn term_clear(&mut self) -> Result<(), Box<dyn Error>> {
        let res = self.file.write_all(b"\x1B[H\x1B[2J");
        if let Err(v) = res {
            Err(format!("terminal: unable to clear: {}", v).into())
        } else {
            Ok(())
        }
    }
}
