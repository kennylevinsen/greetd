use nix::{errno::Errno, Result};

#[cfg(target_os = "linux")]
const PRCTL_SET_PDEATHSIG: i32 = 1;

#[allow(non_camel_case_types)]
pub enum PrctlOption {
    SET_PDEATHSIG(i32),
}

pub fn prctl(option: PrctlOption) -> Result<()> {
    Errno::result(match option {
        PrctlOption::SET_PDEATHSIG(sig) => set_parent_death_signal(sig),
    })
    .map(drop)
}

#[cfg(target_os = "linux")]
fn set_parent_death_signal(sig: i32) -> i32 {
    unsafe { libc::prctl(PRCTL_SET_PDEATHSIG, sig, 0, 0, 0) }
}

#[cfg(target_os = "freebsd")]
fn set_parent_death_signal(sig: i32) -> i32 {
    let mut sig = sig;
    unsafe {
        libc::procctl(
            libc::P_PID,
            0,
            libc::PROC_PDEATHSIG_CTL,
            (&raw mut sig).cast(),
        )
    }
}

#[cfg(all(test, target_os = "freebsd"))]
mod tests {
    use super::*;

    #[test]
    fn sets_parent_death_signal_with_procctl() {
        prctl(PrctlOption::SET_PDEATHSIG(libc::SIGTERM)).unwrap();

        let mut signal = 0;
        let result = unsafe {
            libc::procctl(
                libc::P_PID,
                0,
                libc::PROC_PDEATHSIG_STATUS,
                (&raw mut signal).cast(),
            )
        };
        assert_eq!(result, 0);
        assert_eq!(signal, libc::SIGTERM);

        prctl(PrctlOption::SET_PDEATHSIG(0)).unwrap();
    }
}
