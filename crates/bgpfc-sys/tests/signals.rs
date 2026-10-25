//! The signal self-pipe (AGENTS.md §3, "Signals") is close-on-exec, so
//! that no program bgpfcd starts, such as the RPKI sidecar's version
//! check, inherits either end of it (`pipe2(2)`, `O_CLOEXEC`).
//!
//! An integration test, so that installing the handlers happens in a
//! process of its own: `Signals::install` works once per process.
#![cfg(not(miri))]

use std::collections::BTreeSet;

use bgpfc_sys::Signals;

/// `O_CLOEXEC`, `<asm-generic/fcntl.h>`: the bit `/proc/PID/fdinfo/FD`
/// shows in `flags:` for a close-on-exec descriptor (`proc_pid_fdinfo(5)`).
const O_CLOEXEC: u32 = 0o2_000_000;

/// The descriptors open in this process.
fn open_fds() -> BTreeSet<u32> {
    let listed: BTreeSet<u32> = std::fs::read_dir("/proc/self/fd")
        .expect("read /proc/self/fd")
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse().ok())
        .collect();
    // The listing holds a descriptor of its own while it runs, closed by
    // now: leave it out.
    listed
        .into_iter()
        .filter(|fd| std::path::Path::new(&format!("/proc/self/fdinfo/{fd}")).exists())
        .collect()
}

/// The `flags:` of descriptor `fd`, which `proc_pid_fdinfo(5)` gives in
/// octal.
fn flags(fd: u32) -> u32 {
    let text = std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}"))
        .unwrap_or_else(|e| panic!("fdinfo of {fd}: {e}"));
    let value = text
        .lines()
        .find_map(|l| l.strip_prefix("flags:"))
        .unwrap_or_else(|| panic!("no flags line for {fd}: {text:?}"));
    u32::from_str_radix(value.trim(), 8).unwrap_or_else(|e| panic!("flags of {fd}: {e}"))
}

#[test]
fn the_self_pipe_is_close_on_exec() {
    let before = open_fds();
    let _signals = Signals::install().expect("install the signal handlers");
    let after = open_fds();
    let new: Vec<u32> = after.difference(&before).copied().collect();
    assert_eq!(new.len(), 2, "the self-pipe's two ends: {new:?}");
    for fd in new {
        let flags = flags(fd);
        assert_ne!(flags & O_CLOEXEC, 0, "fd {fd} has flags {flags:o}");
    }
}
