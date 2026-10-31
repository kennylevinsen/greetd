use nix::{errno::Errno, Result};

#[cfg(target_os = "freebsd")]
use std::{
    ffi::c_void,
    thread::sleep,
    time::{Duration, Instant},
};

#[cfg(target_os = "freebsd")]
use nix::{
    sys::wait::{waitpid, WaitPidFlag, WaitStatus},
    unistd::Pid,
};

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

/// Make the current FreeBSD process the reaper for its descendants.
///
/// A desktop application may daemonize and leave the process group that
/// greetd originally launched.  A process reaper keeps those descendants
/// attached to the session worker so they can be cleaned up when the tracked
/// session process exits.
#[cfg(target_os = "freebsd")]
pub fn acquire_reaper() -> Result<()> {
    Errno::result(unsafe {
        libc::procctl(
            libc::P_PID,
            0,
            libc::PROC_REAP_ACQUIRE,
            std::ptr::null_mut(),
        )
    })
    .map(drop)
}

#[cfg(target_os = "freebsd")]
#[repr(C)]
struct ReaperKill {
    signal: libc::c_int,
    flags: libc::c_uint,
    subtree: libc::pid_t,
    killed: libc::c_uint,
    failed_pid: libc::pid_t,
    padding: [libc::c_uint; 15],
}

/// Signal every process still owned by the current FreeBSD reaper.
///
/// `ESRCH` means the session has no remaining descendants, which is the
/// normal case for sessions whose applications shut down with the compositor.
#[cfg(target_os = "freebsd")]
pub fn signal_reaper_descendants(signal: libc::c_int) -> Result<usize> {
    let mut request = ReaperKill {
        signal,
        flags: 0,
        subtree: 0,
        killed: 0,
        failed_pid: 0,
        padding: [0; 15],
    };
    let result = unsafe {
        libc::procctl(
            libc::P_PID,
            0,
            libc::PROC_REAP_KILL,
            (&raw mut request).cast::<c_void>(),
        )
    };

    if result == -1 {
        let error = Errno::last();
        if error == Errno::ESRCH {
            return Ok(0);
        }
        return Err(error);
    }

    Ok(request.killed as usize)
}

/// Reap children owned by the current FreeBSD process reaper.
///
/// Returns `true` once no children remain and `false` if a running child is
/// still present when the timeout expires.  Exited children are always reaped,
/// including when the timeout is zero.
#[cfg(target_os = "freebsd")]
pub fn reap_reaper_descendants(timeout: Duration) -> Result<bool> {
    let deadline = Instant::now() + timeout;

    loop {
        match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) => {
                if Instant::now() >= deadline {
                    return Ok(false);
                }
                sleep(Duration::from_millis(20));
            }
            Ok(_) => continue,
            Err(Errno::EINTR) => continue,
            Err(Errno::ECHILD) => return Ok(true),
            Err(error) => return Err(error),
        }
    }
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

    #[test]
    fn reaper_signals_and_reaps_descendants_outside_its_process_group() {
        use std::os::unix::net::UnixDatagram;

        use nix::{
            sys::wait::{waitpid, WaitStatus},
            unistd::{fork, pause, setsid, ForkResult},
        };

        let supervisor = match unsafe { fork() }.unwrap() {
            ForkResult::Parent { child } => child,
            ForkResult::Child => {
                acquire_reaper().unwrap();
                let (ready_rx, ready_tx) = UnixDatagram::pair().unwrap();

                let child = match unsafe { fork() }.unwrap() {
                    ForkResult::Parent { child } => {
                        drop(ready_tx);
                        let mut ready = [0];
                        ready_rx.recv(&mut ready).unwrap();
                        child
                    }
                    ForkResult::Child => {
                        drop(ready_rx);
                        setsid().unwrap();
                        ready_tx.send(&[1]).unwrap();
                        loop {
                            pause();
                        }
                    }
                };

                assert_eq!(signal_reaper_descendants(libc::SIGTERM).unwrap(), 1);
                assert!(reap_reaper_descendants(Duration::from_secs(1)).unwrap());
                assert_eq!(
                    waitpid(child, Some(nix::sys::wait::WaitPidFlag::WNOHANG)),
                    Err(Errno::ECHILD)
                );
                unsafe { libc::_exit(0) };
            }
        };

        assert_eq!(
            waitpid(supervisor, None).unwrap(),
            WaitStatus::Exited(supervisor, 0)
        );
    }
}
