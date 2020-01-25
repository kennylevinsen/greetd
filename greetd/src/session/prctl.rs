use nix::{errno::Errno, Result};

pub const PRCTL_SET_PDEATHSIG: i32 = 1;

#[allow(non_camel_case_types)]
pub enum PrctlOption {
    SET_PDEATHSIG(i32),
}

pub fn prctl(option: PrctlOption) -> Result<()> {
    Errno::result(match option {
        PrctlOption::SET_PDEATHSIG(sig) => unsafe { libc::prctl(PRCTL_SET_PDEATHSIG, sig, 0, 0, 0)},
    }).map(drop)
}
