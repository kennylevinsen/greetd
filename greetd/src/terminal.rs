use std::error::Error;
use std::fs::File;
use std::io::Write;
use std::os::unix::io::{FromRawFd, RawFd};

use nix::fcntl::{open, OFlag};
use nix::sys::stat::Mode as StatMode;
use nix::unistd::dup2;
use nix::{ioctl_read_bad, ioctl_write_int_bad, ioctl_write_ptr_bad};

const KDSETMODE: u16 = 0x4B3A;
const KDTEXT: i32 = 0x00;
const KDGRAPHICS: i32 = 0x01;
const VT_OPENQRY: u16 = 0x5600;
const VT_SETMODE: u16 = 0x5602;
const VT_GETSTATE: u16 = 0x5603;
const VT_ACTIVATE: u16 = 0x5606;
const VT_WAITACTIVE: u16 = 0x5607;
const VT_AUTO: u8 = 0;

ioctl_write_int_bad!(vt_kdsetmode, KDSETMODE);
ioctl_write_int_bad!(vt_activate, VT_ACTIVATE);
ioctl_write_int_bad!(vt_waitactive, VT_WAITACTIVE);
ioctl_write_ptr_bad!(vt_setmode, VT_SETMODE, vt_mode);
ioctl_read_bad!(vt_openqry, VT_OPENQRY, i64);
ioctl_read_bad!(vt_getstate, VT_GETSTATE, vt_state);

#[allow(dead_code)]
#[repr(C)]
pub struct vt_mode {
    mode: u8,
    waitv: u8,
    relsig: u16,
    acqsig: u16,
    frsig: u16,
}

#[allow(dead_code)]
#[repr(C)]
pub struct vt_state {
    v_active: u16,
    v_signal: u16,
    v_state: u16,
}

#[allow(dead_code)]
pub enum KdMode {
    Text,
    Graphics,
}

impl KdMode {
    fn to_const(&self) -> i32 {
        match self {
            KdMode::Text => KDTEXT,
            KdMode::Graphics => KDGRAPHICS,
        }
    }
}

pub fn restore(terminal: usize) -> Result<(), Box<dyn Error>> {
    let tty_0 = Terminal::open(0)?;
    let tty_x = Terminal::open(terminal)?;
    tty_x.set_kdmode(KdMode::Text)?;
    tty_x.vt_mode_clean()?;
    tty_0.vt_activate(terminal)?;
    Ok(())
}

pub struct Terminal {
    // Note: This will close our fd when we're dropped.
    file: File,
    fd: RawFd,
    terminal: usize,
}

impl Terminal {
    pub fn open(terminal: usize) -> Result<Terminal, Box<dyn Error>> {
        match open(
            format!("/dev/tty{}", terminal).as_str(),
            OFlag::O_RDWR,
            StatMode::empty(),
        ) {
            Ok(fd) => Ok(Terminal {
                file: unsafe { File::from_raw_fd(fd) },
                fd,
                terminal,
            }),
            Err(e) => Err(format!("terminal: unable to open: {}", e).into()),
        }
    }

    pub fn terminal(&self) -> usize {
        return self.terminal;
    }

    pub fn vt_activate(&self, target_vt: usize) -> Result<(), Box<dyn Error>> {
        if let Err(v) = unsafe { vt_activate(self.fd, target_vt as i32) } {
            return Err(format!("terminal: unable to activate: {}", v).into());
        }
        if let Err(v) = unsafe { vt_waitactive(self.fd, target_vt as i32) } {
            return Err(format!("terminal: unable to wait for activation: {}", v).into());
        }
        Ok(())
    }

    pub fn set_kdmode(&self, mode: KdMode) -> Result<(), Box<dyn Error>> {
        let mode = mode.to_const();
        let ret = unsafe { vt_kdsetmode(self.fd, mode) };

        if let Err(v) = ret {
            Err(format!("terminal: unable to set kernel display mode: {}", v).into())
        } else {
            Ok(())
        }
    }

    pub fn vt_mode_clean(&self) -> Result<(), Box<dyn Error>> {
        let mode = vt_mode {
            mode: VT_AUTO,
            waitv: 0,
            relsig: 0,
            acqsig: 0,
            frsig: 0,
        };
        let res = unsafe { vt_setmode(self.fd, &mode) };

        if let Err(v) = res {
            Err(format!("terminal: unable to set vt mode: {}", v).into())
        } else {
            Ok(())
        }
    }

    pub fn vt_get_current(&self) -> Result<usize, Box<dyn Error>> {
        let mut state = vt_state {
            v_active: 0,
            v_signal: 0,
            v_state: 0,
        };
        let res = unsafe { vt_getstate(self.fd, &mut state as *mut vt_state) };

        if let Err(v) = res {
            Err(format!("terminal: unable to get current vt: {}", v).into())
        } else if state.v_active < 1 {
            Err(format!("terminal: current vt invalid: {}", state.v_active).into())
        } else {
            Ok(state.v_active as usize)
        }
    }

    pub fn vt_get_next(&self) -> Result<usize, Box<dyn Error>> {
        let mut next_vt: i64 = 0;
        let res = unsafe { vt_openqry(self.fd, &mut next_vt as *mut i64) };

        if let Err(v) = res {
            Err(format!("terminal: unable to get next vt: {}", v).into())
        } else if next_vt < 1 {
            Err(format!("terminal: next vt invalid: {}", next_vt).into())
        } else {
            Ok(next_vt as usize)
        }
    }

    pub fn term_connect_pipes(&self) -> Result<(), Box<dyn Error>> {
        let res = dup2(self.fd, 0 as RawFd)
            .and_then(|_| dup2(self.fd, 1 as RawFd))
            .and_then(|_| dup2(self.fd, 2 as RawFd));

        if let Err(v) = res {
            Err(format!("terminal: unable to connect pipes: {}", v).into())
        } else {
            Ok(())
        }
    }

    pub fn term_clear(&mut self) -> Result<(), Box<dyn Error>> {
        let res = self.file.write_all("\x1B[H\x1B[2J".as_bytes());
        if let Err(v) = res {
            Err(format!("terminal: unable to clear: {}", v).into())
        } else {
            Ok(())
        }
    }
}
