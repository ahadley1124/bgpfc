//! Hand-written `extern "C"` declarations and constants (AGENTS.md §1.4):
//! only what the crate uses, with the uapi header each comes from. std
//! already links the C library, so these add no dependency.
//!
//! Everything here is private; the safe wrappers in the sibling modules
//! are the crate's interface.

#![allow(
    non_camel_case_types,
    clippy::struct_field_names,
    reason = "C names, as in the headers they are cited from"
)]

use std::ffi::{c_int, c_uint, c_ulong, c_ushort, c_void};

/// `uid_t` / `gid_t`: `__kernel_uid32_t`, `<asm-generic/posix_types.h>`.
pub(crate) type uid_t = c_uint;
/// See [`uid_t`].
pub(crate) type gid_t = c_uint;
/// `size_t`.
pub(crate) type size_t = usize;
/// `ssize_t`.
pub(crate) type ssize_t = isize;
/// `socklen_t`, `<bits/types.h>`.
pub(crate) type socklen_t = c_uint;
/// `__kernel_sa_family_t`, `<linux/socket.h>`.
pub(crate) type sa_family_t = c_ushort;

// <bits/socket.h>
pub(crate) const AF_NETLINK: c_int = 16;
// <bits/socket_type.h>
pub(crate) const SOCK_RAW: c_int = 3;
pub(crate) const SOCK_CLOEXEC: c_int = 0o2_000_000;
// <linux/netlink.h>
pub(crate) const NETLINK_ROUTE: c_int = 0;
// <asm-generic/socket.h>
pub(crate) const SOL_SOCKET: c_int = 1;
pub(crate) const SO_RCVBUF: c_int = 8;
// <asm-generic/signal.h>
pub(crate) const SIGHUP: c_int = 1;
pub(crate) const SIGINT: c_int = 2;
pub(crate) const SIGTERM: c_int = 15;

/// `struct sockaddr_nl`, `<linux/netlink.h>`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct sockaddr_nl {
    pub(crate) nl_family: sa_family_t,
    pub(crate) nl_pad: c_ushort,
    pub(crate) nl_pid: u32,
    pub(crate) nl_groups: u32,
}

/// A signal handler as `signal(2)` takes it (`<signal.h>`).
pub(crate) type sighandler_t = extern "C" fn(c_int);

#[allow(
    unsafe_code,
    reason = "AGENTS.md §1.4: the one place OS entry points are declared"
)]
unsafe extern "C" {
    // <sys/socket.h>
    pub(crate) fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int;
    pub(crate) fn bind(fd: c_int, addr: *const sockaddr_nl, len: socklen_t) -> c_int;
    pub(crate) fn sendto(
        fd: c_int,
        buf: *const c_void,
        len: size_t,
        flags: c_int,
        addr: *const sockaddr_nl,
        addrlen: socklen_t,
    ) -> ssize_t;
    pub(crate) fn recv(fd: c_int, buf: *mut c_void, len: size_t, flags: c_int) -> ssize_t;
    pub(crate) fn setsockopt(
        fd: c_int,
        level: c_int,
        name: c_int,
        value: *const c_void,
        len: socklen_t,
    ) -> c_int;
    // <unistd.h>
    pub(crate) fn pipe(fds: *mut c_int) -> c_int;
    pub(crate) fn write(fd: c_int, buf: *const c_void, count: size_t) -> ssize_t;
    pub(crate) fn getuid() -> uid_t;
    pub(crate) fn setuid(uid: uid_t) -> c_int;
    pub(crate) fn setgid(gid: gid_t) -> c_int;
    // <grp.h>
    pub(crate) fn setgroups(size: size_t, list: *const gid_t) -> c_int;
    // <signal.h>
    pub(crate) fn signal(signum: c_int, handler: sighandler_t) -> c_ulong;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{align_of, size_of};

    /// AGENTS.md §1.4: every `#[repr(C)]` struct asserts its layout.
    #[test]
    fn layouts_match_the_headers() {
        // sizeof(struct sockaddr_nl) == 12 on every Linux target.
        assert_eq!(size_of::<sockaddr_nl>(), 12);
        assert_eq!(align_of::<sockaddr_nl>(), 4);
        assert_eq!(size_of::<sa_family_t>(), 2);
        assert_eq!(size_of::<uid_t>(), 4);
        assert_eq!(size_of::<socklen_t>(), 4);
        assert_eq!(size_of::<size_t>(), size_of::<usize>());
    }
}
