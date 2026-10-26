//! TCP keep-alive on a connection (`SO_KEEPALIVE`, `socket(7)`; and
//! `TCP_KEEPIDLE`, `TCP_KEEPINTVL` and `TCP_KEEPCNT`, `tcp(7)`), which
//! std's [`TcpStream`] cannot set.
//!
//! A connection whose other end has gone without a word (a crash, a power
//! loss, a network that drops its packets rather than refusing them) stays
//! open for as long as nothing is sent on it: TCP does not probe an idle
//! connection. With keep-alive on, the kernel sends a probe once the
//! connection has been idle for a while, and again at an interval while
//! none is answered; after a number of unanswered probes it drops the
//! connection, and a blocked read fails with `ETIMEDOUT`, so the program
//! notices and can connect again.
//!
//! RFC 1122 §4.2.3.6 has keep-alives off unless the application turns
//! them on for a connection, and their idle interval "MUST be
//! configurable and MUST default to no less than two hours", which the
//! host-wide defaults of Linux follow (`net.ipv4.tcp_keepalive_time`,
//! 7200 s; then `tcp_keepalive_intvl`, 75 s, and `tcp_keepalive_probes`,
//! 9). [`set_tcp_keepalive`] configures one connection and leaves those
//! defaults alone.
//!
//! Implements the socket side of RFC 8210 §9's keep-alives for the RTR
//! client: bgpfcd sets them on each connection to a cache, since
//! `bgpfc-rtr` may not depend on this crate (AGENTS.md §2).

use std::ffi::{c_int, c_void};
use std::io;
use std::net::TcpStream;
use std::os::fd::AsRawFd;
use std::time::Duration;

use crate::ffi;

/// How the kernel probes an idle TCP connection (`tcp(7)`).
///
/// The kernel takes whole seconds, at least 1 and at most 32767 for the
/// two times, and from 1 to 127 probes (`MAX_TCP_KEEPIDLE`,
/// `MAX_TCP_KEEPINTVL` and `MAX_TCP_KEEPCNT` in the kernel's
/// `<net/tcp.h>`); it refuses other values with `EINVAL`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpKeepalive {
    /// `TCP_KEEPIDLE`: how long nothing must arrive on the connection
    /// before the first probe.
    pub idle: Duration,
    /// `TCP_KEEPINTVL`: how long to wait for an answer to a probe before
    /// the next.
    pub interval: Duration,
    /// `TCP_KEEPCNT`: how many probes in a row may go unanswered before
    /// the kernel drops the connection.
    pub probes: u32,
}

impl TcpKeepalive {
    /// The longest an idle connection to a vanished peer stays open:
    /// the idle time, then every probe's interval.
    #[must_use]
    pub fn detection_time(&self) -> Duration {
        self.interval
            .saturating_mul(self.probes)
            .saturating_add(self.idle)
    }
}

/// Turn keep-alive on for `stream`, probing as `keepalive` says.
///
/// The three times and counts are set before `SO_KEEPALIVE`, so a value
/// the kernel refuses leaves keep-alive as it was rather than on with the
/// host's two-hour default. Only this connection changes.
///
/// # Errors
/// [`io::ErrorKind::InvalidInput`] for a time that is not a whole number
/// of seconds or a value beyond what the kernel takes as an `int`; the
/// `setsockopt(2)` failure, such as `EINVAL` for a value out of the
/// kernel's range (see [`TcpKeepalive`]).
pub fn set_tcp_keepalive(stream: &TcpStream, keepalive: TcpKeepalive) -> io::Result<()> {
    let idle = seconds(keepalive.idle)?;
    let interval = seconds(keepalive.interval)?;
    let probes = c_int::try_from(keepalive.probes)
        .map_err(|_| invalid("too many keep-alive probes for the kernel"))?;
    let fd = stream.as_raw_fd();
    set_int(fd, ffi::IPPROTO_TCP, ffi::TCP_KEEPIDLE, idle)?;
    set_int(fd, ffi::IPPROTO_TCP, ffi::TCP_KEEPINTVL, interval)?;
    set_int(fd, ffi::IPPROTO_TCP, ffi::TCP_KEEPCNT, probes)?;
    set_int(fd, ffi::SOL_SOCKET, ffi::SO_KEEPALIVE, 1)
}

/// The keep-alive settings of `stream` as the kernel has them, or `None`
/// if keep-alive is off (`getsockopt(2)`).
///
/// # Errors
/// The `getsockopt(2)` failure.
pub fn tcp_keepalive(stream: &TcpStream) -> io::Result<Option<TcpKeepalive>> {
    let fd = stream.as_raw_fd();
    if get_int(fd, ffi::SOL_SOCKET, ffi::SO_KEEPALIVE)? == 0 {
        return Ok(None);
    }
    // The kernel keeps each of them between 1 and its maximum, so none is
    // negative; 0 would only stand for a value it cannot hold.
    let duration = |n: c_int| Duration::from_secs(u64::try_from(n).unwrap_or(0));
    Ok(Some(TcpKeepalive {
        idle: duration(get_int(fd, ffi::IPPROTO_TCP, ffi::TCP_KEEPIDLE)?),
        interval: duration(get_int(fd, ffi::IPPROTO_TCP, ffi::TCP_KEEPINTVL)?),
        probes: u32::try_from(get_int(fd, ffi::IPPROTO_TCP, ffi::TCP_KEEPCNT)?).unwrap_or(0),
    }))
}

/// `d` as the whole seconds the kernel takes.
fn seconds(d: Duration) -> io::Result<c_int> {
    if d.subsec_nanos() != 0 {
        return Err(invalid("keep-alive times are whole seconds"));
    }
    c_int::try_from(d.as_secs()).map_err(|_| invalid("keep-alive time too long for the kernel"))
}

fn invalid(what: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, what)
}

/// The length of an `int` option.
fn int_len() -> ffi::socklen_t {
    // invariant: sizeof(int) is 4 on every Linux target.
    ffi::socklen_t::try_from(size_of::<c_int>()).unwrap_or(4)
}

/// `setsockopt(fd, level, name, &value, sizeof(int))`.
#[allow(unsafe_code, reason = "FFI call with a borrowed int")]
fn set_int(fd: c_int, level: c_int, name: c_int, value: c_int) -> io::Result<()> {
    // SAFETY: `fd` comes from a `TcpStream` the caller borrows for the
    // whole call, so it stays open; `value` lives on this frame until the
    // call returns, and the length given is its size. The kernel only
    // reads it.
    let rc = unsafe {
        ffi::setsockopt(
            fd,
            level,
            name,
            (&raw const value).cast::<c_void>(),
            int_len(),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `getsockopt(fd, level, name, &value, &len)` for an `int` option.
#[allow(unsafe_code, reason = "FFI call with a borrowed int")]
fn get_int(fd: c_int, level: c_int, name: c_int) -> io::Result<c_int> {
    let mut value: c_int = 0;
    let mut len = int_len();
    // SAFETY: `fd` comes from a `TcpStream` the caller borrows for the
    // whole call, so it stays open; `value` and `len` live on this frame
    // until the call returns, and `len` says how many bytes `value` has
    // room for, which bounds what the kernel writes there.
    let rc = unsafe {
        ffi::getsockopt(
            fd,
            level,
            name,
            (&raw mut value).cast::<c_void>(),
            &raw mut len,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    if len != int_len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("socket option {level}/{name} is {len} bytes, not an int"),
        ));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The times go to the kernel in whole seconds, never rounded.
    #[test]
    fn times_are_whole_seconds() {
        assert_eq!(seconds(Duration::from_secs(60)).unwrap(), 60);
        assert_eq!(seconds(Duration::from_secs(1)).unwrap(), 1);
        // 0 is the kernel's to refuse.
        assert_eq!(seconds(Duration::ZERO).unwrap(), 0);
        for bad in [
            Duration::from_millis(1500),
            Duration::from_millis(1),
            Duration::from_secs(u64::from(u32::MAX)),
        ] {
            assert_eq!(
                seconds(bad).unwrap_err().kind(),
                io::ErrorKind::InvalidInput,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn detection_takes_the_idle_time_and_every_probe() {
        let k = TcpKeepalive {
            idle: Duration::from_secs(60),
            interval: Duration::from_secs(10),
            probes: 6,
        };
        assert_eq!(k.detection_time(), Duration::from_secs(120));
    }
}

/// Real sockets: none of this needs a privilege.
#[cfg(all(test, not(miri)))]
mod socket_tests {
    use super::*;

    use std::net::TcpListener;

    const SETTINGS: TcpKeepalive = TcpKeepalive {
        idle: Duration::from_secs(60),
        interval: Duration::from_secs(10),
        probes: 6,
    };

    /// A connection over the loopback of `host`, both ends.
    fn pair(host: &str) -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind(host).unwrap();
        let near = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (far, _) = listener.accept().unwrap();
        (near, far)
    }

    fn hosts() -> Vec<&'static str> {
        let mut hosts = vec!["127.0.0.1:0"];
        if TcpListener::bind("[::1]:0").is_ok() {
            hosts.push("[::1]:0");
        }
        hosts
    }

    /// RFC 1122 §4.2.3.6: off unless the application turns it on.
    #[test]
    fn keep_alive_is_off_by_default() {
        for host in hosts() {
            let (near, far) = pair(host);
            assert_eq!(tcp_keepalive(&near).unwrap(), None, "{host}");
            assert_eq!(tcp_keepalive(&far).unwrap(), None, "{host}");
        }
    }

    /// The kernel reads back what was set, on that connection alone.
    #[test]
    fn the_kernel_has_what_was_set() {
        for host in hosts() {
            let (near, far) = pair(host);
            set_tcp_keepalive(&near, SETTINGS).unwrap();
            assert_eq!(tcp_keepalive(&near).unwrap(), Some(SETTINGS), "{host}");
            // The other end, and another connection, keep the default.
            assert_eq!(tcp_keepalive(&far).unwrap(), None, "{host}");
            let (other, _) = pair(host);
            assert_eq!(tcp_keepalive(&other).unwrap(), None, "{host}");
            // Set again with other values: the new ones.
            let other_settings = TcpKeepalive {
                idle: Duration::from_secs(7_200),
                interval: Duration::from_secs(75),
                probes: 9,
            };
            set_tcp_keepalive(&far, other_settings).unwrap();
            assert_eq!(tcp_keepalive(&far).unwrap(), Some(other_settings));
            // The extremes the kernel takes.
            let extremes = TcpKeepalive {
                idle: Duration::from_secs(32_767),
                interval: Duration::from_secs(1),
                probes: 127,
            };
            set_tcp_keepalive(&near, extremes).unwrap();
            assert_eq!(tcp_keepalive(&near).unwrap(), Some(extremes));
        }
    }

    /// A value the kernel refuses leaves keep-alive off, not on with the
    /// two-hour default.
    #[test]
    fn a_refused_value_leaves_keep_alive_off() {
        let (near, _far) = pair("127.0.0.1:0");
        for bad in [
            TcpKeepalive {
                idle: Duration::ZERO,
                ..SETTINGS
            },
            TcpKeepalive {
                interval: Duration::from_secs(32_768),
                ..SETTINGS
            },
            TcpKeepalive {
                probes: 128,
                ..SETTINGS
            },
            TcpKeepalive {
                probes: u32::MAX,
                ..SETTINGS
            },
            TcpKeepalive {
                idle: Duration::from_millis(1500),
                ..SETTINGS
            },
        ] {
            let err = set_tcp_keepalive(&near, bad).unwrap_err();
            assert!(
                matches!(err.kind(), io::ErrorKind::InvalidInput)
                    || err.raw_os_error() == Some(ffi::EINVAL),
                "{bad:?}: {err}"
            );
            assert_eq!(tcp_keepalive(&near).unwrap(), None, "{bad:?}");
        }
    }
}
