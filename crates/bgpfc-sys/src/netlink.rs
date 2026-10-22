//! A `NETLINK_ROUTE` socket (`<linux/netlink.h>`, `netlink(7)`). The
//! message bytes are the caller's business; `bgpfc-fib` builds and parses
//! them without `unsafe`.

use std::ffi::{c_int, c_void};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::ffi;

/// Receive buffer the kernel is asked for: a full-table dump arrives in
/// many messages, and a small buffer makes it fail with `ENOBUFS`.
const RCVBUF: c_int = 4 << 20;

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
    /// The `socket`, `setsockopt` or `bind` failure.
    #[allow(unsafe_code, reason = "FFI calls with checked arguments")]
    pub fn open() -> io::Result<NetlinkSocket> {
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
        // at once means it is closed on every exit path below.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let rcvbuf: c_int = RCVBUF;
        // SAFETY: `rcvbuf` outlives the call and the length matches its
        // size. A failure here is not fatal: the default buffer still works
        // for small tables.
        let _ = unsafe {
            ffi::setsockopt(
                fd.as_raw_fd(),
                ffi::SOL_SOCKET,
                ffi::SO_RCVBUF,
                (&raw const rcvbuf).cast::<c_void>(),
                ffi::socklen_t::try_from(size_of::<c_int>()).unwrap_or(4),
            )
        };
        let addr = ffi::sockaddr_nl {
            nl_family: ffi::sa_family_t::try_from(ffi::AF_NETLINK).unwrap_or(16),
            nl_pad: 0,
            nl_pid: 0, // the kernel assigns a port id
            nl_groups: 0,
        };
        // SAFETY: `addr` is a valid, fully initialised `sockaddr_nl` that
        // outlives the call, and the length is its size.
        let rc = unsafe { ffi::bind(fd.as_raw_fd(), &raw const addr, sockaddr_len()) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(NetlinkSocket { fd })
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
    /// Blocks until the kernel answers.
    ///
    /// # Errors
    /// The `recv` failure.
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
}
