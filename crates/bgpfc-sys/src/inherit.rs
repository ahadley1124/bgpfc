//! What a child inherits across `execve(2)` that std's
//! [`Command`] leaves alone: the ambient capability set
//! (`capabilities(7)`) and the file descriptors that are not
//! close-on-exec.
//!
//! A daemon granted capabilities as ambient ones, as systemd's
//! `AmbientCapabilities=` does, passes them on to every unprivileged
//! program it starts, which then holds them as effective capabilities.
//! A descriptor opened without `O_CLOEXEC` stays open in every program it
//! starts. The hooks here run in the child between `fork` and `execve`, so
//! the caller keeps its own.
//!
//! Implements the process plumbing of the supervised RPKI relying-party
//! sidecar (GitHub issues #26, #70): the validator parses data from the
//! internet and needs no capability at all.

use std::ffi::{c_int, c_ulong};
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

/// The most descriptors a process may hold unless the administrator
/// raised `fs.nr_open` (`sysctl_nr_open` in `fs/file.c`): the bound
/// [`inherit_only_standard_streams`] uses if the soft limit is unknown.
const DEFAULT_NR_OPEN: c_int = 1 << 20;

/// Mark every file descriptor from 3 up close-on-exec in the child that
/// `cmd` spawns (`fcntl(fd, F_SETFD, FD_CLOEXEC)`, `fcntl(2)`), so the
/// program starts with standard input, output and error only.
///
/// std opens its own descriptors close-on-exec, but one made otherwise,
/// such as the self-pipe of [`Signals`](crate::Signals), stays open in
/// every program the process starts, and in what those start in turn,
/// for as long as they run. A program that writes to that pipe makes
/// [`Signals::wait`](crate::Signals::wait) report a signal nobody sent.
///
/// The descriptors are marked rather than closed, so the one std uses to
/// report a failed `execve` to [`Command::spawn`] keeps working, and the
/// standard streams std has already put on 0, 1 and 2 are left alone.
/// Every number below the soft `RLIMIT_NOFILE` limit is marked, one
/// system call each; the limit is read when this is called
/// (`sysconf(_SC_OPEN_MAX)`, `sysconf(3)`). A soft limit of a million
/// makes a spawn take a fraction of a second longer. A descriptor at or
/// above the soft limit, which only a process that lowered its limit
/// after opening it can hold, is not covered. `close_range(2)` with
/// `CLOSE_RANGE_CLOEXEC` would mark them all in one call, but needs Linux
/// 5.11 and glibc 2.34, and musl lacks it.
///
/// The caller's own descriptors keep their flags. Like any pre-exec hook,
/// this makes std use `fork` and `execve` instead of `posix_spawn`.
#[allow(
    unsafe_code,
    reason = "sysconf, and a pre-exec hook with the fcntl calls inside it"
)]
pub fn inherit_only_standard_streams(cmd: &mut Command) {
    // SAFETY: `sysconf` takes an integer and has no preconditions. It runs
    // here, in the parent, where it may do whatever it needs to.
    let open_max = unsafe { ffi::sysconf(ffi::SC_OPEN_MAX) };
    // -1 means unknown; the kernel bounds RLIMIT_NOFILE by `fs.nr_open`,
    // which fits an `int`.
    let end = match c_int::try_from(open_max) {
        Ok(n) if n > 0 => n,
        _ => DEFAULT_NR_OPEN,
    };
    let hook = move || -> io::Result<()> {
        for fd in 3..end {
            // SAFETY: `fcntl` is variadic in `<fcntl.h>` and F_SETFD reads
            // one `int`, the descriptor flags. Integer arguments only: it
            // changes a flag in this child's descriptor table, which `fork`
            // copied, and fails harmlessly with EBADF for a number that is
            // not open. The C library wrapper is a bare system call: no
            // locks, no allocation.
            unsafe { ffi::fcntl(fd, ffi::F_SETFD, ffi::FD_CLOEXEC) };
        }
        Ok(())
    };
    // SAFETY: `pre_exec` requires the hook to be safe to run in a child of
    // a possibly multi-threaded process between `fork` and `execve`. It
    // only calls `fcntl`, a bare system call, in a loop over integers; it
    // captures one `c_int`, takes no locks, allocates nothing, and touches
    // no memory shared with the parent. It never fails.
    unsafe {
        cmd.pre_exec(hook);
    }
}

#[cfg(all(test, not(miri)))]
mod tests {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
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

    /// A pipe without `O_CLOEXEC`, as [`Signals`](crate::Signals) makes
    /// one: its read and write ends.
    #[allow(unsafe_code, reason = "pipe(2) for the test")]
    fn inheritable_pipe() -> (OwnedFd, OwnedFd) {
        let mut fds: [c_int; 2] = [-1, -1];
        // SAFETY: `fds` is a writable array of two ints, as `pipe(2)` wants.
        let rc = unsafe { ffi::pipe(fds.as_mut_ptr()) };
        assert_eq!(rc, 0, "{}", io::Error::last_os_error());
        // SAFETY: both descriptors were just created by `pipe` and are
        // owned by nobody else; wrapping them now closes them on drop.
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }

    /// Which of `fds` are open in `/bin/sh` spawned by `cmd`, as the
    /// shell sees its own descriptors, and whether its stdout works.
    fn open_in_child(mut cmd: Command, fds: &[&OwnedFd]) -> Vec<String> {
        let out = cmd
            .args([
                "-c",
                "for n; do [ -e /proc/$$/fd/$n ] && echo $n; done; echo end",
                "sh",
            ])
            .args(fds.iter().map(|fd| fd.as_raw_fd().to_string()))
            .stdin(Stdio::null())
            .output()
            .expect("spawn /bin/sh");
        assert!(out.status.success(), "{out:?}");
        let text = String::from_utf8(out.stdout).unwrap();
        let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
        assert_eq!(lines.pop().as_deref(), Some("end"), "stdout works");
        lines
    }

    /// A pipe this process holds without `O_CLOEXEC` reaches a child
    /// spawned without the hook, the control, and not one spawned with it.
    #[test]
    fn only_the_standard_streams_reach_the_child() {
        let (reader, writer) = inheritable_pipe();
        let numbers: Vec<String> = [&reader, &writer]
            .iter()
            .map(|fd| fd.as_raw_fd().to_string())
            .collect();
        let bare = open_in_child(Command::new("/bin/sh"), &[&reader, &writer]);
        assert_eq!(bare, numbers, "the control inherits the pipe");
        let mut hooked = Command::new("/bin/sh");
        inherit_only_standard_streams(&mut hooked);
        let hooked = open_in_child(hooked, &[&reader, &writer]);
        assert_eq!(hooked, Vec::<String>::new(), "the hook left the pipe open");
    }

    /// The descriptor std uses to report a failed `execve` is marked, not
    /// closed, so the failure still reaches `spawn`.
    #[test]
    fn a_failed_exec_is_still_reported() {
        let mut cmd = Command::new("/nonexistent/bgpfc-test-program");
        inherit_only_standard_streams(&mut cmd);
        let err = cmd.spawn().expect_err("there is no such program");
        assert_eq!(err.kind(), io::ErrorKind::NotFound, "{err}");
    }
}
