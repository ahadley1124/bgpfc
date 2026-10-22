//! What a child inherits across `execve(2)` that std's
//! [`Command`] leaves alone: the ambient capability set
//! (`capabilities(7)`).
//!
//! A daemon granted capabilities as ambient ones, as systemd's
//! `AmbientCapabilities=` does, passes them on to every unprivileged
//! program it starts, which then holds them as effective capabilities.
//! The hook here runs in the child between `fork` and `execve`, so the
//! caller keeps its own.
//!
//! Implements the process plumbing of the supervised RPKI relying-party
//! sidecar (GitHub issues #26, #70): the validator parses data from the
//! internet and needs no capability at all.

use std::ffi::c_ulong;
use std::io;
use std::os::unix::process::CommandExt;
use std::process::Command;

use crate::ffi;

/// Clear the ambient capability set of the child that `cmd` spawns
/// (`prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL)`, `prctl(2)`) before
/// it executes the program.
///
/// Ambient capabilities (Linux 4.3) survive `execve` of a program without
/// set-user-ID or set-group-ID bits or file capabilities, and become its
/// permitted and effective capabilities (`capabilities(7)`). A daemon run
/// with `CAP_NET_ADMIN` that way would hand it to every such program it
/// starts. With the ambient set cleared, an unprivileged program starts
/// with no effective capabilities. The caller's own set is untouched.
///
/// Neither the inheritable, permitted nor bounding set changes. A child
/// that runs as root still gets the capabilities of its bounding set at
/// `execve`, and a program with file capabilities gets what those grant
/// from the inheritable set, so start the child from an unprivileged
/// process. Dropping capabilities does not clear a parent-death signal
/// ([`set_parent_death_signal`](crate::set_parent_death_signal)); only
/// gaining one or changing user does.
///
/// A kernel older than 4.3 has no ambient set and refuses the option with
/// `EINVAL`, which the hook takes as nothing to clear. Like any pre-exec
/// hook, this makes std use `fork` and `execve` instead of `posix_spawn`.
#[allow(unsafe_code, reason = "a pre-exec hook and the prctl call inside it")]
pub fn clear_ambient_capabilities(cmd: &mut Command) {
    let hook = || -> io::Result<()> {
        // SAFETY: `prctl` is variadic in `<sys/prctl.h>` and is passed the
        // four `unsigned long` arguments it reads; PR_CAP_AMBIENT with
        // PR_CAP_AMBIENT_CLEAR_ALL requires the other three to be zero.
        // The C library wrapper is a bare system call: no locks, no
        // allocation.
        let rc = unsafe {
            ffi::prctl(
                ffi::PR_CAP_AMBIENT,
                ffi::PR_CAP_AMBIENT_CLEAR_ALL,
                0 as c_ulong,
                0 as c_ulong,
                0 as c_ulong,
            )
        };
        if rc < 0 {
            let err = io::Error::last_os_error();
            // With zero arguments, EINVAL means the option itself is
            // unknown: a kernel without ambient capabilities.
            if err.raw_os_error() != Some(ffi::EINVAL) {
                return Err(err);
            }
        }
        Ok(())
    };
    // SAFETY: `pre_exec` requires the hook to be safe to run in a child of
    // a possibly multi-threaded process between `fork` and `execve`. It
    // calls `prctl`, a bare system call, reads `errno` and builds an
    // `io::Error` from an OS error code, which does not allocate. It
    // captures nothing, takes no locks, does no I/O and touches no memory
    // shared with the parent. Returning `Err` is the documented way to
    // abort: std then `_exit`s the child, never reaching `execve`, and
    // `spawn` returns the error.
    unsafe {
        cmd.pre_exec(hook);
    }
}

#[cfg(all(test, not(miri)))]
mod tests {
    use super::*;
    use std::process::{Output, Stdio};

    /// Set by [`ambient_case`] for the copy of this test binary that
    /// runs with an ambient capability and spawns the children.
    const INTERMEDIATE_ENV: &str = "BGPFC_SYS_TEST_AMBIENT";

    /// `setpriv(1)` options that raise `CAP_NET_BIND_SERVICE` (bit 10) as
    /// an ambient capability, which requires it in the inheritable set.
    const RAISE: [&str; 2] = [
        "--inh-caps=+net_bind_service",
        "--ambient-caps=+net_bind_service",
    ];

    /// `CAP_NET_BIND_SERVICE`, `<linux/capability.h>`.
    const NET_BIND_SERVICE: u64 = 1 << 10;

    /// The `CapAmb` mask in `/proc/<pid>/status` text
    /// (`proc_pid_status(5)`).
    fn ambient(status: &str) -> u64 {
        let value = status
            .lines()
            .find_map(|l| l.strip_prefix("CapAmb:"))
            .expect("a CapAmb line");
        u64::from_str_radix(value.trim(), 16).unwrap()
    }

    /// The ambient set of `/bin/sh` spawned by `cmd`, as the shell sees
    /// its own.
    fn child_ambient(mut cmd: Command) -> u64 {
        let out: Output = cmd
            .args(["-c", "cat /proc/$$/status"])
            .stdin(Stdio::null())
            .output()
            .expect("spawn /bin/sh");
        assert!(out.status.success(), "{out:?}");
        ambient(&String::from_utf8(out.stdout).unwrap())
    }

    /// Not a test on its own: [`ambient_case`] runs this test binary again
    /// under `setpriv` with [`INTERMEDIATE_ENV`] set, and this function
    /// then prints its own ambient set and those of a child spawned
    /// without and with the hook. Without the variable it returns at once.
    #[test]
    fn ambient_intermediate() {
        if std::env::var_os(INTERMEDIATE_ENV).is_none() {
            return;
        }
        let own = ambient(&std::fs::read_to_string("/proc/self/status").unwrap());
        let bare = child_ambient(Command::new("/bin/sh"));
        let mut hooked = Command::new("/bin/sh");
        clear_ambient_capabilities(&mut hooked);
        let hooked = child_ambient(hooked);
        println!("ambient {own:x} {bare:x} {hooked:x}");
    }

    /// End to end: a process with `CAP_NET_BIND_SERVICE` as an ambient
    /// capability spawns one child without the hook, the control, which
    /// inherits it, and one with the hook, which must not.
    ///
    /// Raising an ambient capability needs it in the permitted set, so
    /// this checks nothing for a test run without `CAP_NET_BIND_SERVICE`,
    /// such as an unprivileged user's; it says so on stderr. Root has it.
    #[test]
    fn ambient_capabilities_are_cleared_in_the_child() {
        let probe = Command::new("setpriv")
            .args(RAISE)
            .arg("/bin/true")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if !matches!(probe, Ok(s) if s.success()) {
            eprintln!("skipped: setpriv cannot raise an ambient capability here: {probe:?}");
            return;
        }
        let out = Command::new("setpriv")
            .args(RAISE)
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "inherit::tests::ambient_intermediate",
                "--test-threads=1",
                "--nocapture",
            ])
            .env(INTERMEDIATE_ENV, "1")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(), "{out:?}");
        // The harness prints the test's name first, on the same line.
        let line = stdout
            .lines()
            .find_map(|l| l.split_once("ambient ").map(|(_, rest)| rest))
            .unwrap_or_else(|| panic!("no result in {stdout:?}"));
        let masks: Vec<u64> = line
            .split(' ')
            .map(|m| u64::from_str_radix(m, 16).unwrap())
            .collect();
        let [own, bare, hooked] = masks[..] else {
            panic!("three masks expected: {line:?}");
        };
        assert_ne!(own & NET_BIND_SERVICE, 0, "setpriv raised nothing");
        assert_eq!(bare, own, "the control inherits the ambient set");
        assert_eq!(hooked, 0, "the hook left ambient capabilities");
    }

    /// The hook lets the program run when there is nothing to clear.
    #[test]
    fn a_child_without_ambient_capabilities_runs() {
        let mut cmd = Command::new("/bin/sh");
        clear_ambient_capabilities(&mut cmd);
        let status = cmd.args(["-c", "exit 0"]).status().expect("spawn /bin/sh");
        assert!(status.success(), "{status}");
    }
}
