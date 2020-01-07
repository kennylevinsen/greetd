use nix::{ioctl_read_bad, ioctl_write_int_bad, ioctl_write_ptr_bad};

pub const KDSETMODE: u16 = 0x4B3A;
pub const KDTEXT: i32 = 0x00;
pub const KDGRAPHICS: i32 = 0x01;
pub const VT_OPENQRY: u16 = 0x5600;
pub const VT_SETMODE: u16 = 0x5602;
pub const VT_GETSTATE: u16 = 0x5603;
pub const VT_ACTIVATE: u16 = 0x5606;
pub const VT_WAITACTIVE: u16 = 0x5607;
pub const VT_SETACTIVATE: u16 = 0x560F;
pub const VT_AUTO: u8 = 0;

ioctl_write_int_bad!(kd_setmode, KDSETMODE);
ioctl_write_int_bad!(vt_activate, VT_ACTIVATE);
ioctl_write_int_bad!(vt_waitactive, VT_WAITACTIVE);
ioctl_write_ptr_bad!(vt_setmode, VT_SETMODE, vt_mode);
ioctl_write_ptr_bad!(vt_setactivate, VT_SETACTIVATE, vt_setactivate);
ioctl_read_bad!(vt_openqry, VT_OPENQRY, i64);
ioctl_read_bad!(vt_getstate, VT_GETSTATE, vt_state);

#[allow(dead_code)]
#[repr(C)]
pub struct vt_mode {
    pub mode: u8,
    pub waitv: u8,
    pub relsig: u16,
    pub acqsig: u16,
    pub frsig: u16,
}

#[allow(dead_code)]
#[repr(C)]
pub struct vt_setactivate {
    pub console: u64,
    pub mode: vt_mode,
}

#[allow(dead_code)]
#[repr(C)]
pub struct vt_state {
    pub v_active: u16,
    pub v_signal: u16,
    pub v_state: u16,
}
