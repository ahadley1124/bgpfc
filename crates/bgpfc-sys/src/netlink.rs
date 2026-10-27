//! A `NETLINK_ROUTE` socket (`<linux/netlink.h>`, `netlink(7)`). The
//! message bytes are the caller's business; `bgpfc-fib` builds and parses
//! them without `unsafe`.
//!
//! A socket either asks and is answered ([`NetlinkSocket::open`]: route
//! changes and dumps), or also hears what changes in the kernel's tables
//! as it happens ([`NetlinkSocket::open_subscribed`]: `rtnetlink(7)`
//! multicast groups, which `bgpfc-fib` follows to know the routes a next
//! hop resolves through).

use std::ffi::{c_int, c_void};
use std::io;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};

use crate::ffi;
use crate::tcp::set_int;

/// Receive buffer the kernel is asked for: a full-table dump arrives in
/// many messages, and a small buffer makes it fail with `ENOBUFS`.
const RCVBUF: c_int = 4 << 20;

/// Receive buffer a subscribed socket asks for: notifications wait here
/// while the reader is busy, and the kernel drops what does not fit,
/// which the next `recv` reports as `ENOBUFS`. A table that loads from a
/// peer changes routes faster than `ip -batch` does, so the room is
/// generous; an overflow costs the reader a fresh dump.
const SUBSCRIBED_RCVBUF: c_int = 8 << 20;

/// A bound `NETLINK_ROUTE` socket.
#[derive(Debug)]
pub struct NetlinkSocket {
    fd: OwnedFd,
}

impl NetlinkSocket {
    /// Open and bind a socket. Needs no privilege; changing routes through
    /// it needs `CAP_NET_ADMIN`.
    ///
    /// # Errors
    /// The `socket` or `bind` failure.
    pub fn open() -> io::Result<NetlinkSocket> {
        let socket = NetlinkSocket::socket()?;
        // A failure here is not fatal: the default buffer still works for
        // small tables.
        let _ = set_int(socket.fd.as_fd(), ffi::SOL_SOCKET, ffi::SO_RCVBUF, RCVBUF);
        socket.bind()?;
        Ok(socket)
    }

    /// Open and bind a socket that also receives the notifications of
    /// the multicast `groups` (`enum rtnetlink_groups`,
    /// `<linux/rtnetlink.h>`), joined with `NETLINK_ADD_MEMBERSHIP`
    /// (`netlink(7)`) after the bind. Joining needs no privilege.
    ///
    /// The receive buffer is 8 MiB, forced past `net.core.rmem_max` with
    /// `SO_RCVBUFFORCE`, which takes `CAP_NET_ADMIN`; without it the
    /// buffer is asked for with `SO_RCVBUF`, which the kernel caps at
    /// `net.core.rmem_max`. Open it before dropping privileges to keep the
    /// larger buffer. When the buffer overflows, the kernel drops
    /// notifications and [`NetlinkSocket::recv`] fails once with `ENOBUFS`
    /// (`<asm-generic/errno.h>`, 105): the reader has missed changes.
    ///
    /// # Errors
    /// The `socket` or `bind` failure, or a group the kernel refuses
    /// (`EINVAL` for 0 or one it does not have).
    pub fn open_subscribed(groups: &[u32]) -> io::Result<NetlinkSocket> {
        let socket = NetlinkSocket::socket()?;
        let fd = socket.fd.as_fd();
        if set_int(fd, ffi::SOL_SOCKET, ffi::SO_RCVBUFFORCE, SUBSCRIBED_RCVBUF).is_err() {
            // EPERM without CAP_NET_ADMIN: as much as the limit allows.
            let _ = set_int(fd, ffi::SOL_SOCKET, ffi::SO_RCVBUF, SUBSCRIBED_RCVBUF);
        }
        socket.bind()?;
        for &group in groups {
            // The kernel takes the group as an unsigned int and refuses
            // one it does not have with EINVAL; one too large for an int
            // is such a group.
            let group =
                c_int::try_from(group).map_err(|_| io::Error::from_raw_os_error(ffi::EINVAL))?;
            set_int(fd, ffi::SOL_NETLINK, ffi::NETLINK_ADD_MEMBERSHIP, group)?;
        }
        Ok(socket)
    }

    /// Ask for a receive buffer of `bytes` (`SO_RCVBUF`, `socket(7)`):
    /// the kernel doubles it for its bookkeeping, keeps it at a minimum of
    /// its own and caps it at `net.core.rmem_max`. A small buffer makes a
    /// subscribed socket lose notifications sooner; the tests that check
    /// how a reader recovers use one.
    ///
    /// # Errors
    /// The `setsockopt` failure.
    pub fn set_receive_buffer(&self, bytes: usize) -> io::Result<()> {
        let bytes = c_int::try_from(bytes).unwrap_or(c_int::MAX);
        set_int(self.fd.as_fd(), ffi::SOL_SOCKET, ffi::SO_RCVBUF, bytes)
    }

    /// `socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE)`.
    #[allow(unsafe_code, reason = "FFI call with integer arguments")]
    fn socket() -> io::Result<NetlinkSocket> {
        // SAFETY: plain integer arguments; the result is checked before use.
        let raw = unsafe {
            ffi::socket(
                ffi::AF_NETLINK,
                ffi::SOCK_RAW | ffi::SOCK_CLOEXEC,
                ffi::NETLINK_ROUTE,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a freshly created descriptor we own; wrapping it
        // at once means it is closed on every exit path.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        Ok(NetlinkSocket { fd })
    }

    /// Bind with a port id the kernel assigns and no group: groups are
    /// joined afterwards by number, which `nl_groups`, a bit mask of the
    /// first 32, is not needed for.
    #[allow(unsafe_code, reason = "FFI call with a borrowed address")]
    fn bind(&self) -> io::Result<()> {
        let addr = ffi::sockaddr_nl {
            nl_family: ffi::sa_family_t::try_from(ffi::AF_NETLINK).unwrap_or(16),
            nl_pad: 0,
            nl_pid: 0, // the kernel assigns a port id
            nl_groups: 0,
        };
        // SAFETY: `addr` is a valid, fully initialised `sockaddr_nl` that
        // outlives the call, and the length is its size: the kernel reads
        // that many bytes through the generic `sockaddr` pointer, as
        // bind(2) is meant to be called.
        let rc = unsafe {
            ffi::bind(
                self.fd.as_raw_fd(),
                (&raw const addr).cast::<ffi::sockaddr>(),
                sockaddr_len(),
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Send one or more netlink messages to the kernel.
    ///
    /// # Errors
    /// The `sendto` failure, or a short send.
    #[allow(unsafe_code, reason = "FFI call with a borrowed buffer")]
    pub fn send(&self, bytes: &[u8]) -> io::Result<()> {
        let kernel = ffi::sockaddr_nl {
            nl_family: ffi::sa_family_t::try_from(ffi::AF_NETLINK).unwrap_or(16),
            nl_pad: 0,
            nl_pid: 0,
            nl_groups: 0,
        };
        // SAFETY: `bytes` is a live slice of the given length and `kernel`
        // a valid address struct; both outlive the call.
        let n = unsafe {
            ffi::sendto(
                self.fd.as_raw_fd(),
                bytes.as_ptr().cast::<c_void>(),
                bytes.len(),
                0,
                &raw const kernel,
                sockaddr_len(),
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if usize::try_from(n).unwrap_or(0) != bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short netlink send",
            ));
        }
        Ok(())
    }

    /// Receive one datagram into `buf`; the number of bytes written.
    /// Blocks until the kernel answers, or, on a subscribed socket, until
    /// a notification comes.
    ///
    /// # Errors
    /// The `recv` failure: `ENOBUFS` on a subscribed socket that lost
    /// notifications.
    #[allow(unsafe_code, reason = "FFI call with a borrowed buffer")]
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        // SAFETY: `buf` is a live, writable slice of the given length that
        // outlives the call; the kernel writes at most that many bytes.
        let n = unsafe {
            ffi::recv(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr().cast::<c_void>(),
                buf.len(),
                0,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(usize::try_from(n).unwrap_or(0))
    }
}

fn sockaddr_len() -> ffi::socklen_t {
    // invariant: sizeof(sockaddr_nl) is 12 (ffi layout test).
    ffi::socklen_t::try_from(size_of::<ffi::sockaddr_nl>()).unwrap_or(12)
}

#[cfg(all(test, not(miri)))]
mod tests {
    use super::*;
    use crate::tcp::get_int;

    /// `RTNLGRP_LINK` and `RTNLGRP_IPV4_ROUTE`, `<linux/rtnetlink.h>`.
    const RTNLGRP_LINK: u32 = 1;
    const RTNLGRP_IPV4_ROUTE: u32 = 7;

    /// Opening and a trivial exchange need no privilege: an `RTM_GETLINK`
    /// dump with `NLM_F_DUMP` is answered by every kernel.
    #[test]
    fn open_send_and_receive() {
        let s = NetlinkSocket::open().expect("netlink socket");
        // nlmsghdr{len=20,type=RTM_GETLINK(18),flags=REQUEST|DUMP(0x301),
        // seq=1,pid=0} + ifinfomsg{family=0,...} (16 bytes)... we send the
        // minimal rtgenmsg form: 16-byte header + 4-byte family.
        let mut msg = Vec::new();
        msg.extend_from_slice(&20u32.to_ne_bytes());
        msg.extend_from_slice(&18u16.to_ne_bytes());
        msg.extend_from_slice(&0x301u16.to_ne_bytes());
        msg.extend_from_slice(&1u32.to_ne_bytes());
        msg.extend_from_slice(&0u32.to_ne_bytes());
        msg.extend_from_slice(&[0, 0, 0, 0]);
        s.send(&msg).expect("send");
        let mut buf = vec![0u8; 65536];
        let n = s.recv(&mut buf).expect("recv");
        assert!(n >= 16, "{n} bytes");
        // The reply's sequence number is ours.
        assert_eq!(u32::from_ne_bytes([buf[8], buf[9], buf[10], buf[11]]), 1);
    }

    /// Joining groups needs no privilege, and the receive buffer can be
    /// made small. Group 0 does not exist, nor does one past the last:
    /// the kernel refuses them.
    #[test]
    fn subscribed_socket_joins_groups() {
        let s = NetlinkSocket::open_subscribed(&[RTNLGRP_LINK, RTNLGRP_IPV4_ROUTE])
            .expect("subscribed socket");
        let rcvbuf = get_int(s.fd.as_fd(), ffi::SOL_SOCKET, ffi::SO_RCVBUF).unwrap();
        assert!(rcvbuf > 0, "{rcvbuf}");
        s.set_receive_buffer(4096).unwrap();
        // socket(7): the kernel doubles what it is asked for.
        let small = get_int(s.fd.as_fd(), ffi::SOL_SOCKET, ffi::SO_RCVBUF).unwrap();
        assert_eq!(small, 8192);
        for bad in [0, 1 << 20, u32::MAX] {
            let e = NetlinkSocket::open_subscribed(&[bad]).unwrap_err();
            assert_eq!(e.raw_os_error(), Some(ffi::EINVAL), "group {bad}: {e}");
        }
        assert!(NetlinkSocket::open_subscribed(&[]).is_ok());
    }
}

/// A notification read in a namespace of its own, where a route can be
/// added without touching the host's. Joining it needs `CAP_SYS_ADMIN`,
/// adding the route `CAP_NET_ADMIN` in it. Run as root:
///
/// ```sh
/// sudo -E "$(command -v cargo)" test -p bgpfc-sys -- --ignored netns
/// ```
#[cfg(all(test, not(miri)))]
mod root_tests {
    use super::*;

    use std::process::Command;
    use std::sync::mpsc;
    use std::time::Duration;

    use crate::netns::root_tests::Sleeper;

    /// `RTNLGRP_IPV4_ROUTE`, `<linux/rtnetlink.h>`.
    const RTNLGRP_IPV4_ROUTE: u32 = 7;
    /// `RTM_NEWROUTE`, `<linux/rtnetlink.h>`.
    const RTM_NEWROUTE: u16 = 24;
    /// `RTA_DST`, `<linux/rtnetlink.h>`.
    const RTA_DST: u16 = 1;

    /// `ip ARGS` in the calling thread's network namespace: a child starts
    /// in the namespace of the thread that spawns it.
    fn ip(args: &[&str]) {
        let status = Command::new("ip").args(args).status().expect("ip(8)");
        assert!(status.success(), "ip {args:?}: {status}");
    }

    fn u16_at(b: &[u8], at: usize) -> Option<u16> {
        Some(u16::from_ne_bytes(b.get(at..at + 2)?.try_into().ok()?))
    }

    /// Whether the datagram holds an `RTM_NEWROUTE` for the IPv4 prefix
    /// `dst`/`len`: just enough of `rtnetlink(7)` to tell, every read
    /// bounds-checked.
    fn has_new_route(datagram: &[u8], dst: [u8; 4], len: u8) -> bool {
        let mut rest = datagram;
        while let Some(n) = rest.get(..4).and_then(|b| b.try_into().ok()) {
            let n = usize::try_from(u32::from_ne_bytes(n)).unwrap_or(usize::MAX);
            let Some(message) = rest.get(..n).filter(|_| n >= 16) else {
                return false;
            };
            // struct rtmsg (12 octets): family, dst_len, ...; attributes.
            let rtmsg = &message[16..];
            if u16_at(message, 4) == Some(RTM_NEWROUTE)
                && rtmsg.first() == Some(&2)
                && rtmsg.get(1) == Some(&len)
            {
                let mut attrs = rtmsg.get(12..).unwrap_or_default();
                while let (Some(alen), Some(ty)) = (u16_at(attrs, 0), u16_at(attrs, 2)) {
                    let alen = usize::from(alen);
                    if ty == RTA_DST && attrs.get(4..alen) == Some(&dst[..]) {
                        return true;
                    }
                    match attrs.get(alen.div_ceil(4) * 4..) {
                        Some(next) if alen >= 4 => attrs = next,
                        _ => break,
                    }
                }
            }
            rest = rest.get(n.div_ceil(4) * 4..).unwrap_or_default();
        }
        false
    }

    /// A thread joins a namespace with only `lo` in it, subscribes to the
    /// IPv4 route group, makes a veth pair and a route through it, and
    /// reads the `RTM_NEWROUTE` the kernel sends for the route.
    #[test]
    #[ignore = "needs CAP_SYS_ADMIN and CAP_NET_ADMIN: joins a network namespace and adds a route"]
    fn netns_a_subscribed_socket_hears_a_new_route() {
        let sleeper = Sleeper::start();
        let ns = sleeper.namespace();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            if let Err(e) = ns.enter() {
                let _ = tx.send(Err(e.to_string()));
                return;
            }
            let s = NetlinkSocket::open_subscribed(&[RTNLGRP_IPV4_ROUTE]).unwrap();
            ip(&["link", "add", "nl0", "type", "veth", "peer", "name", "nl1"]);
            ip(&["addr", "add", "10.1.0.1/24", "dev", "nl0"]);
            ip(&["link", "set", "nl0", "up"]);
            ip(&["link", "set", "nl1", "up"]);
            ip(&["route", "add", "192.0.2.0/24", "via", "10.1.0.2"]);
            let mut buf = vec![0u8; 65536];
            loop {
                let n = s.recv(&mut buf).unwrap();
                if has_new_route(&buf[..n], [192, 0, 2, 0], 24) {
                    let _ = tx.send(Ok(()));
                    return;
                }
            }
        });
        // The reader blocks in recv: a notification that never comes shows
        // as a timeout here rather than as a test that never ends.
        match rx.recv_timeout(Duration::from_secs(10)) {
            Ok(Ok(())) => {}
            Ok(Err(e)) => panic!("joining the namespace: {e}"),
            Err(mpsc::RecvTimeoutError::Timeout) => panic!("no RTM_NEWROUTE for 192.0.2.0/24"),
            Err(mpsc::RecvTimeoutError::Disconnected) => panic!("the reader failed"),
        }
    }
}
