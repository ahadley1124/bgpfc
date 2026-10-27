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

use std::ffi::c_long;
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
/// `pid_t`: `__kernel_pid_t`, `<asm-generic/posix_types.h>`.
pub(crate) type pid_t = c_int;
/// `id_t`: `__id_t`, an unsigned 32-bit integer (`<bits/typesizes.h>`).
pub(crate) type id_t = c_uint;
/// `idtype_t`: an enum in `<sys/wait.h>` with the values of
/// `<linux/wait.h>`, so as wide as an `unsigned int`.
pub(crate) type idtype_t = c_uint;

// <bits/socket.h>
pub(crate) const AF_NETLINK: c_int = 16;
// <bits/socket_type.h>
pub(crate) const SOCK_RAW: c_int = 3;
pub(crate) const SOCK_CLOEXEC: c_int = 0o2_000_000;
// <linux/netlink.h>
pub(crate) const NETLINK_ROUTE: c_int = 0;
// <asm-generic/socket.h>
pub(crate) const SOL_SOCKET: c_int = 1;
pub(crate) const SO_KEEPALIVE: c_int = 9;
pub(crate) const SO_RCVBUF: c_int = 8;
// <linux/in.h>
pub(crate) const IPPROTO_TCP: c_int = 6;
// <linux/tcp.h>
pub(crate) const TCP_KEEPIDLE: c_int = 4;
pub(crate) const TCP_KEEPINTVL: c_int = 5;
pub(crate) const TCP_KEEPCNT: c_int = 6;
// <asm-generic/signal.h>
pub(crate) const SIGHUP: c_int = 1;
pub(crate) const SIGINT: c_int = 2;
pub(crate) const SIGKILL: c_int = 9;
pub(crate) const SIGTERM: c_int = 15;
// <asm-generic/errno-base.h>
pub(crate) const EPERM: c_int = 1;
pub(crate) const ESRCH: c_int = 3;
pub(crate) const EINVAL: c_int = 22;
pub(crate) const ENOTTY: c_int = 25;
// <linux/sched.h>
pub(crate) const CLONE_NEWNET: c_int = 0x4000_0000;
// <linux/nsfs.h>: `NS_GET_NSTYPE` is `_IO(NSIO, 0x3)` with `NSIO` 0xb7, and
// `_IO(type, nr)` is `(type << 8) | nr` (<asm-generic/ioctl.h>: no
// direction and no size bits).
pub(crate) const NS_GET_NSTYPE: c_ulong = 0xb703;
// <linux/capability.h>
pub(crate) const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
pub(crate) const LINUX_CAPABILITY_U32S_3: usize = 2;
// <linux/prctl.h>
pub(crate) const PR_SET_PDEATHSIG: c_int = 1;
pub(crate) const PR_CAP_AMBIENT: c_int = 47;
pub(crate) const PR_CAP_AMBIENT_CLEAR_ALL: c_ulong = 4;
// <asm-generic/fcntl.h>
pub(crate) const F_SETFD: c_int = 2;
pub(crate) const FD_CLOEXEC: c_int = 1;
pub(crate) const O_CLOEXEC: c_int = 0o2_000_000;
pub(crate) const O_NONBLOCK: c_int = 0o4_000;
// `_SC_OPEN_MAX`: <bits/confname.h> in glibc, <unistd.h> in musl.
pub(crate) const SC_OPEN_MAX: c_int = 4;
// <linux/wait.h>
pub(crate) const WEXITED: c_int = 0x0000_0004;
pub(crate) const WNOWAIT: c_int = 0x0100_0000;
pub(crate) const P_PID: idtype_t = 1;
// <asm-generic/siginfo.h>
pub(crate) const SI_MAX_SIZE: usize = 128;

/// `siginfo_t`, `<asm-generic/siginfo.h>`: a union padded to
/// `SI_MAX_SIZE` bytes on every architecture, aligned like the `long` and
/// pointer members it holds. `waitid` fills it in and nothing here reads
/// it, so it is declared by size and alignment only.
#[repr(C)]
pub(crate) struct siginfo_t {
    pub(crate) opaque: [c_ulong; SI_MAX_SIZE / size_of::<c_ulong>()],
}

/// `struct sockaddr_nl`, `<linux/netlink.h>`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct sockaddr_nl {
    pub(crate) nl_family: sa_family_t,
    pub(crate) nl_pad: c_ushort,
    pub(crate) nl_pid: u32,
    pub(crate) nl_groups: u32,
}

/// `struct __user_cap_header_struct`, `<linux/capability.h>`: which
/// layout of the sets `capget(2)` and `capset(2)` use, and whose (`pid` 0:
/// the calling thread's).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct cap_user_header {
    pub(crate) version: u32,
    pub(crate) pid: c_int,
}

/// `struct __user_cap_data_struct`, `<linux/capability.h>`: 32
/// capabilities of each set. Version 3 takes
/// [`LINUX_CAPABILITY_U32S_3`] of them, bits 0-31 then 32-63.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct cap_user_data {
    pub(crate) effective: u32,
    pub(crate) permitted: u32,
    pub(crate) inheritable: u32,
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
    pub(crate) fn getsockopt(
        fd: c_int,
        level: c_int,
        name: c_int,
        value: *mut c_void,
        len: *mut socklen_t,
    ) -> c_int; // getsockopt(2)
    // <unistd.h>
    pub(crate) fn pipe2(fds: *mut c_int, flags: c_int) -> c_int; // pipe(2)
    pub(crate) fn write(fd: c_int, buf: *const c_void, count: size_t) -> ssize_t;
    pub(crate) fn getuid() -> uid_t;
    pub(crate) fn setuid(uid: uid_t) -> c_int;
    pub(crate) fn setgid(gid: gid_t) -> c_int;
    pub(crate) fn getpid() -> pid_t; // getpid(2)
    pub(crate) fn getppid() -> pid_t; // getppid(2)
    pub(crate) fn _exit(status: c_int) -> !; // _exit(2)
    // <grp.h>
    pub(crate) fn setgroups(size: size_t, list: *const gid_t) -> c_int;
    // <signal.h>
    pub(crate) fn signal(signum: c_int, handler: sighandler_t) -> c_ulong;
    pub(crate) fn kill(pid: pid_t, sig: c_int) -> c_int; // kill(2)
    // <sys/prctl.h>, prctl(2): variadic there, so variadic here; callers
    // pass all four `unsigned long` arguments the C wrapper reads.
    pub(crate) fn prctl(option: c_int, ...) -> c_int;
    // <fcntl.h>, fcntl(2): variadic there, so variadic here; F_SETFD
    // reads an `int`.
    pub(crate) fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
    // <unistd.h>, sysconf(3)
    pub(crate) fn sysconf(name: c_int) -> c_long;
    // <sched.h>, setns(2)
    pub(crate) fn setns(fd: c_int, nstype: c_int) -> c_int;
    // <sys/ioctl.h>, ioctl(2): variadic there, so variadic here. glibc
    // declares the request `unsigned long`, musl `int`; every request
    // passed here fits both. NS_GET_NSTYPE takes no third argument.
    pub(crate) fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
    // <sys/capability.h>, capget(2) and capset(2): system call wrappers
    // both glibc and musl export.
    pub(crate) fn capget(header: *mut cap_user_header, data: *mut cap_user_data) -> c_int;
    pub(crate) fn capset(header: *mut cap_user_header, data: *const cap_user_data) -> c_int;
    // <sys/wait.h>
    pub(crate) fn waitid(
        idtype: idtype_t,
        id: id_t,
        infop: *mut siginfo_t,
        options: c_int,
    ) -> c_int; // waitid(2)
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
        assert_eq!(size_of::<pid_t>(), 4);
        assert_eq!(size_of::<socklen_t>(), 4);
        assert_eq!(size_of::<size_t>(), size_of::<usize>());
    }

    /// `waitid(2)`'s types, also under AGENTS.md §1.4.
    #[test]
    fn waitid_layouts_match_the_headers() {
        // sizeof(siginfo_t) == SI_MAX_SIZE == 128 on every Linux target.
        assert_eq!(size_of::<siginfo_t>(), 128);
        assert_eq!(align_of::<siginfo_t>(), align_of::<c_ulong>());
        assert_eq!(size_of::<id_t>(), 4);
        assert_eq!(size_of::<idtype_t>(), 4);
    }

    /// `capget(2)` and `capset(2)`'s types, also under AGENTS.md §1.4.
    #[test]
    fn capability_layouts_match_the_headers() {
        // sizeof(struct __user_cap_header_struct) == 8 and
        // sizeof(struct __user_cap_data_struct) == 12 on every Linux
        // target: `__u32` and `int` fields only.
        assert_eq!(size_of::<cap_user_header>(), 8);
        assert_eq!(align_of::<cap_user_header>(), 4);
        assert_eq!(size_of::<cap_user_data>(), 12);
        assert_eq!(align_of::<cap_user_data>(), 4);
    }

    /// The ioctl number, from its parts as `<asm-generic/ioctl.h>`
    /// builds it.
    #[test]
    fn ns_get_nstype_is_io_nsio_3() {
        const NSIO: c_ulong = 0xb7;
        const IOC_TYPESHIFT: c_ulong = 8;
        assert_eq!(NS_GET_NSTYPE, (NSIO << IOC_TYPESHIFT) | 0x3);
    }
}
