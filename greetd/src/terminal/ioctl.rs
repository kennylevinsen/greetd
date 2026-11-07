#[cfg(target_os = "freebsd")]
use nix::{ioctl_none, ioctl_read, ioctl_write_int, ioctl_write_ptr};
#[cfg(not(target_os = "freebsd"))]
use nix::{ioctl_read_bad, ioctl_write_int_bad, ioctl_write_ptr_bad};

pub const KDTEXT: i32 = 0x00;
pub const KDGRAPHICS: i32 = 0x01;
#[cfg(target_os = "freebsd")]
pub const K_XLATE: i32 = 1;
pub const VT_AUTO: u8 = 0;

#[allow(dead_code)]
#[repr(C)]
pub struct vt_mode {
    pub mode: u8,
    pub waitv: u8,
    pub relsig: u16,
    pub acqsig: u16,
    pub frsig: u16,
}

#[cfg(not(target_os = "freebsd"))]
mod platform {
    use super::*;

    const KDSETMODE: u16 = 0x4B3A;
    const VT_OPENQRY: u16 = 0x5600;
    const VT_SETMODE: u16 = 0x5602;
    const VT_GETSTATE: u16 = 0x5603;
    const VT_ACTIVATE: u16 = 0x5606;
    const VT_WAITACTIVE: u16 = 0x5607;
    const VT_SETACTIVATE: u16 = 0x560F;
    const TIOCSCTTY: u16 = 0x540E;

    ioctl_write_int_bad!(kd_setmode, KDSETMODE);
    ioctl_write_int_bad!(vt_activate, VT_ACTIVATE);
    ioctl_write_int_bad!(vt_waitactive, VT_WAITACTIVE);
    ioctl_write_ptr_bad!(vt_setmode, VT_SETMODE, vt_mode);
    ioctl_write_ptr_bad!(vt_setactivate, VT_SETACTIVATE, vt_setactivate);
    ioctl_read_bad!(vt_openqry, VT_OPENQRY, i32);
    ioctl_read_bad!(vt_getstate, VT_GETSTATE, vt_state);
    ioctl_write_int_bad!(term_tiocsctty, TIOCSCTTY);

    #[allow(dead_code)]
    #[repr(C)]
    pub struct vt_setactivate {
        pub console: u32,
        pub mode: vt_mode,
    }

    #[allow(dead_code)]
    #[repr(C)]
    pub struct vt_state {
        pub v_active: u16,
        pub v_signal: u16,
        pub v_state: u16,
    }
}

#[cfg(target_os = "freebsd")]
mod platform {
    use super::*;

    // FreeBSD encodes argument direction and size in ioctl request numbers.
    ioctl_write_int!(kd_setmode, b'K', 10);
    ioctl_write_int!(kd_setkbmode, b'K', 7);
    ioctl_read!(vt_openqry, b'v', 1, i32);
    ioctl_write_ptr!(vt_setmode, b'v', 2, vt_mode);
    ioctl_write_int!(vt_activate, b'v', 5);
    ioctl_write_int!(vt_waitactive, b'v', 6);
    ioctl_read!(vt_getactive, b'v', 7, i32);
    ioctl_none!(term_tiocsctty, b't', 97);
}

pub use platform::*;
