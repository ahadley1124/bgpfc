//! Outgoing TCP connections with what std's [`TcpStream::connect_timeout`]
//! cannot set before the first segment: the TTL (IPv4 `IP_TTL`, `ip(7)`)
//! or hop limit (IPv6 `IPV6_UNICAST_HOPS`, `ipv6(7)`) every segment is sent
//! with, the SYN included, and the source address the socket is bound to
//! (`bind(2)`) before it connects. And the TTL of a connection already
//! made, such as an accepted one, which std can set only for IPv4.
//!
//! The connect is non-blocking and waited for with `poll(2)`, as std's own
//! `connect_timeout` does (`connect(2)`, "EINPROGRESS"), so that the wait
//! has a deadline; a signal that interrupts the wait (`EINTR`) does not end
//! it early. Once connected, the socket blocks again and becomes a std
//! [`TcpStream`].
//!
//! For bgpfcd's BGP sessions: an external neighbor is sent TTL 1 unless
//! configured `multihop`, and a session can run from a configured local
//! address (`docs/config.md`, "Neighbors").

use std::ffi::c_int;
use std::io;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::num::NonZeroU8;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

use crate::ffi;
use crate::tcp::{get_int, set_int};

/// How to open an outgoing TCP connection (`tcp(7)`, `ip(7)`, `ipv6(7)`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TcpConnect {
    /// `IP_TTL` / `IPV6_UNICAST_HOPS` for every segment the connection
    /// sends, the SYN included; `None` keeps the system default.
    pub ttl: Option<NonZeroU8>,
    /// Address bound before connecting, with port 0 (the kernel picks the
    /// port); `None` lets the kernel choose the source by route.
    pub local: Option<IpAddr>,
}

impl TcpConnect {
    /// Connect to `to`, waiting at most `timeout`.
    ///
    /// The socket is created close-on-exec and non-blocking, the TTL set,
    /// the local address bound, and the connect started; its outcome is
    /// waited for with `poll(2)` and read from `SO_ERROR`. The stream
    /// returned blocks, as one from [`TcpStream::connect`] does.
    ///
    /// # Errors
    /// [`io::ErrorKind::InvalidInput`], before any system call, when
    /// `local` is not of `to`'s family or `timeout` is zero;
    /// [`io::ErrorKind::TimedOut`] when the deadline passes; else the OS
    /// error: `EHOSTUNREACH` when an ICMP Time Exceeded answers a SYN whose
    /// TTL ran out, `EADDRNOTAVAIL` for a local address the host does not
    /// have, `ECONNREFUSED`, and so on.
    pub fn connect(&self, to: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
        if let Some(local) = self.local
            && local.is_ipv4() != to.is_ipv4()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("local address {local} is not of the family of {to}"),
            ));
        }
        if timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a connect needs a timeout above zero",
            ));
        }
        let deadline = Instant::now().checked_add(timeout);
        let target = RawAddr::of(to);
        let fd = socket(target.family())?;
        if let Some(ttl) = self.ttl {
            set_ttl_on(fd.as_fd(), to.ip(), ttl)?;
        }
        if let Some(local) = self.local {
            bind(fd.as_fd(), &RawAddr::of(SocketAddr::new(local, 0)))?;
        }
        if start_connect(fd.as_fd(), &target)? {
            wait_connected(fd.as_fd(), deadline)?;
        }
        set_blocking(fd.as_fd())?;
        Ok(TcpStream::from(fd))
    }
}

/// Set the TTL every later segment of `stream` is sent with: `IP_TTL` on
/// an IPv4 socket; `IPV6_UNICAST_HOPS` on an IPv6 one, and `IP_TTL` too
/// when its peer is an IPv4-mapped address (an IPv4 neighbor on a
/// dual-stack listener, whose traffic Linux sends with the IPv4 TTL).
///
/// # Errors
/// The `getsockname(2)` or `setsockopt(2)` failure.
pub fn set_ttl(stream: &TcpStream, ttl: NonZeroU8) -> io::Result<()> {
    set_ttl_on(stream.as_fd(), stream.local_addr()?.ip(), ttl)
}

/// The TTL the kernel sends `stream`'s segments with, chosen as
/// [`set_ttl`] chooses the option: the system default unless one was
/// set.
///
/// # Errors
/// The `getsockname(2)` or `getsockopt(2)` failure;
/// [`io::ErrorKind::InvalidData`] for a value no TTL can have.
pub fn ttl(stream: &TcpStream) -> io::Result<u8> {
    let local = stream.local_addr()?.ip();
    let fd = stream.as_fd();
    let value = match Family::of(local) {
        Family::V6 => get_int(fd, ffi::IPPROTO_IPV6, ffi::IPV6_UNICAST_HOPS)?,
        Family::V4 | Family::Mapped => get_int(fd, ffi::IPPROTO_IP, ffi::IP_TTL)?,
    };
    u8::try_from(value).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("the kernel reports a ttl of {value}"),
        )
    })
}

/// Which options carry the TTL of a socket whose own address is `local`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    /// An `AF_INET` socket: `IP_TTL`.
    V4,
    /// An `AF_INET6` socket to an IPv6 peer: `IPV6_UNICAST_HOPS`.
    V6,
    /// An `AF_INET6` socket to an IPv4-mapped peer: both, as Linux sends
    /// it as IPv4.
    Mapped,
}

impl Family {
    fn of(local: IpAddr) -> Family {
        match local {
            IpAddr::V4(_) => Family::V4,
            // The local address of a connection is mapped exactly when
            // its peer's is: one socket, one family on the wire.
            IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some() => Family::Mapped,
            IpAddr::V6(_) => Family::V6,
        }
    }
}

/// Set the TTL of the socket `fd`, of the family of `addr` (either end's
/// address: they are of one family).
fn set_ttl_on(fd: BorrowedFd<'_>, addr: IpAddr, ttl: NonZeroU8) -> io::Result<()> {
    let value = c_int::from(ttl.get());
    let family = Family::of(addr);
    if matches!(family, Family::V6 | Family::Mapped) {
        set_int(fd, ffi::IPPROTO_IPV6, ffi::IPV6_UNICAST_HOPS, value)?;
    }
    if matches!(family, Family::V4 | Family::Mapped) {
        set_int(fd, ffi::IPPROTO_IP, ffi::IP_TTL, value)?;
    }
    Ok(())
}

/// A socket address as `bind(2)` and `connect(2)` take it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RawAddr {
    V4(ffi::sockaddr_in),
    V6(ffi::sockaddr_in6),
}

impl RawAddr {
    /// `addr` in the kernel's layout: port and address in network order.
    /// An IPv6 address keeps its flow information and scope, 0 for every
    /// address built from an [`IpAddr`].
    fn of(addr: SocketAddr) -> RawAddr {
        match addr {
            SocketAddr::V4(a) => RawAddr::V4(ffi::sockaddr_in {
                sin_family: family_field(ffi::AF_INET),
                sin_port: a.port().to_be(),
                sin_addr: u32::from_ne_bytes(a.ip().octets()),
                sin_zero: [0; 8],
            }),
            SocketAddr::V6(a) => RawAddr::V6(ffi::sockaddr_in6 {
                sin6_family: family_field(ffi::AF_INET6),
                sin6_port: a.port().to_be(),
                sin6_flowinfo: a.flowinfo().to_be(),
                sin6_addr: a.ip().octets(),
                sin6_scope_id: a.scope_id(),
            }),
        }
    }

    /// The `AF_*` family, for `socket(2)`.
    fn family(&self) -> c_int {
        match self {
            RawAddr::V4(_) => ffi::AF_INET,
            RawAddr::V6(_) => ffi::AF_INET6,
        }
    }

    /// A pointer to the address as a generic `sockaddr`, valid while
    /// `self` is.
    fn as_ptr(&self) -> *const ffi::sockaddr {
        match self {
            RawAddr::V4(a) => (&raw const *a).cast::<ffi::sockaddr>(),
            RawAddr::V6(a) => (&raw const *a).cast::<ffi::sockaddr>(),
        }
    }

    /// The length of the address behind [`as_ptr`](Self::as_ptr).
    fn len(&self) -> ffi::socklen_t {
        let n = match self {
            RawAddr::V4(_) => size_of::<ffi::sockaddr_in>(),
            RawAddr::V6(_) => size_of::<ffi::sockaddr_in6>(),
        };
        // invariant: 16 or 28 octets (the ffi layout test).
        ffi::socklen_t::try_from(n).unwrap_or(0)
    }
}

/// An `AF_*` constant as the `sa_family_t` field of an address.
fn family_field(af: c_int) -> ffi::sa_family_t {
    // invariant: AF_INET and AF_INET6 are 2 and 10.
    ffi::sa_family_t::try_from(af).unwrap_or(0)
}

/// `socket(family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0)`.
#[allow(unsafe_code, reason = "FFI call with integer arguments")]
fn socket(family: c_int) -> io::Result<OwnedFd> {
    // SAFETY: plain integer arguments; the result is checked before use.
    let raw = unsafe {
        ffi::socket(
            family,
            ffi::SOCK_STREAM | ffi::SOCK_CLOEXEC | ffi::SOCK_NONBLOCK,
            0,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a freshly created descriptor nothing else owns;
    // wrapping it at once closes it on every exit path.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// `bind(fd, addr)`.
#[allow(unsafe_code, reason = "FFI call with a borrowed address")]
fn bind(fd: BorrowedFd<'_>, addr: &RawAddr) -> io::Result<()> {
    // SAFETY: `fd` is borrowed for the call, so it stays open; `addr` is
    // a fully initialised address of the length given, borrowed for the
    // call, which the kernel only reads.
    let rc = unsafe { ffi::bind(fd.as_raw_fd(), addr.as_ptr(), addr.len()) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Start connecting `fd` to `addr`: `false` if it connected at once,
/// `true` if the connection is under way (`EINPROGRESS`, or `EINTR`,
/// after which it goes on in the background: `connect(2)`).
#[allow(unsafe_code, reason = "FFI call with a borrowed address")]
fn start_connect(fd: BorrowedFd<'_>, addr: &RawAddr) -> io::Result<bool> {
    // SAFETY: as in `bind`: an open descriptor and a borrowed, fully
    // initialised address of the length given.
    let rc = unsafe { ffi::connect(fd.as_raw_fd(), addr.as_ptr(), addr.len()) };
    if rc == 0 {
        return Ok(false);
    }
    let e = io::Error::last_os_error();
    match e.raw_os_error() {
        Some(ffi::EINPROGRESS | ffi::EINTR) => Ok(true),
        _ => Err(e),
    }
}

/// Wait until the connect under way on `fd` ends or `deadline` passes
/// (`None`: no deadline), and say how it ended.
#[allow(unsafe_code, reason = "FFI call with a borrowed pollfd")]
fn wait_connected(fd: BorrowedFd<'_>, deadline: Option<Instant>) -> io::Result<()> {
    let mut pfd = ffi::pollfd {
        fd: fd.as_raw_fd(),
        events: ffi::POLLOUT,
        revents: 0,
    };
    loop {
        let wait = match deadline {
            Some(d) => {
                let left = d.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "connection timed out",
                    ));
                }
                poll_millis(left)
            }
            None => -1,
        };
        // SAFETY: `pfd` lives on this frame for the call and is the one
        // entry the count says; `fd` stays open, borrowed by the caller.
        let rc = unsafe { ffi::poll(&raw mut pfd, 1, wait) };
        if rc < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(ffi::EINTR) {
                // A signal for bgpfcd's handler: wait for the time left.
                continue;
            }
            return Err(e);
        }
        if rc == 0 {
            // The deadline passed; the loop says so.
            continue;
        }
        // Linux reports a refused connect as POLLOUT | POLLERR | POLLHUP:
        // the outcome is in SO_ERROR either way.
        let error = get_int(fd, ffi::SOL_SOCKET, ffi::SO_ERROR)?;
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error));
        }
        if pfd.revents & (ffi::POLLERR | ffi::POLLHUP) != 0 {
            return Err(io::Error::other("connect failed with no error set"));
        }
        return Ok(());
    }
}

/// `left` as `poll(2)`'s timeout: milliseconds, rounded up so that a wait
/// never ends before the deadline, and at most `c_int::MAX`.
fn poll_millis(left: Duration) -> c_int {
    let millis = left.as_nanos().div_ceil(1_000_000);
    c_int::try_from(millis).unwrap_or(c_int::MAX)
}

/// Clear `O_NONBLOCK` on `fd` (`fcntl(2)`, `F_GETFL` and `F_SETFL`).
#[allow(unsafe_code, reason = "FFI calls on a borrowed descriptor")]
fn set_blocking(fd: BorrowedFd<'_>) -> io::Result<()> {
    // SAFETY: `fd` stays open for the call; F_GETFL takes no argument.
    let flags = unsafe { ffi::fcntl(fd.as_raw_fd(), ffi::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` stays open for the call; F_SETFL reads an `int`.
    let rc = unsafe { ffi::fcntl(fd.as_raw_fd(), ffi::F_SETFL, flags & !ffi::O_NONBLOCK) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV6};

    /// The kernel's layout: family, then port and address in network
    /// order (`<linux/in.h>`, `<linux/in6.h>`).
    #[test]
    fn sockaddr_encoding() {
        let v4 = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 179));
        let RawAddr::V4(a) = RawAddr::of(v4) else {
            panic!("an IPv4 address");
        };
        assert_eq!(a.sin_family, 2);
        assert_eq!(a.sin_port.to_ne_bytes(), [0, 179]);
        assert_eq!(a.sin_addr.to_ne_bytes(), [192, 0, 2, 1]);
        assert_eq!(a.sin_zero, [0; 8]);
        assert_eq!(RawAddr::of(v4).family(), ffi::AF_INET);
        assert_eq!(RawAddr::of(v4).len(), 16);

        let ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let v6 = SocketAddr::from((ip, 0x1234));
        let RawAddr::V6(a) = RawAddr::of(v6) else {
            panic!("an IPv6 address");
        };
        assert_eq!(a.sin6_family, 10);
        assert_eq!(a.sin6_port.to_ne_bytes(), [0x12, 0x34]);
        assert_eq!(a.sin6_flowinfo, 0);
        assert_eq!(a.sin6_addr, ip.octets());
        assert_eq!(a.sin6_scope_id, 0);
        assert_eq!(RawAddr::of(v6).family(), ffi::AF_INET6);
        assert_eq!(RawAddr::of(v6).len(), 28);

        // A scoped address keeps its scope; the flow label goes in
        // network order.
        let scoped = SocketAddr::V6(SocketAddrV6::new(
            "fe80::1".parse().unwrap(),
            179,
            0x0001_2345,
            3,
        ));
        let RawAddr::V6(a) = RawAddr::of(scoped) else {
            panic!("an IPv6 address");
        };
        assert_eq!(a.sin6_flowinfo.to_ne_bytes(), [0, 1, 0x23, 0x45]);
        assert_eq!(a.sin6_scope_id, 3);

        // The pointer is the address itself.
        let raw = RawAddr::of(v4);
        let RawAddr::V4(inner) = &raw else {
            panic!("an IPv4 address");
        };
        assert_eq!(raw.as_ptr().addr(), (&raw const *inner).addr());
    }

    #[test]
    fn the_ttl_option_follows_the_family_on_the_wire() {
        assert_eq!(Family::of("192.0.2.1".parse().unwrap()), Family::V4);
        assert_eq!(Family::of("2001:db8::1".parse().unwrap()), Family::V6);
        assert_eq!(
            Family::of("::ffff:192.0.2.1".parse().unwrap()),
            Family::Mapped
        );
    }

    #[test]
    fn poll_waits_never_end_early() {
        assert_eq!(poll_millis(Duration::from_millis(250)), 250);
        assert_eq!(poll_millis(Duration::from_micros(1)), 1);
        assert_eq!(poll_millis(Duration::from_micros(1001)), 2);
        assert_eq!(poll_millis(Duration::from_secs(u64::MAX)), c_int::MAX);
    }

    /// Both refused before any system call, so Miri runs them too.
    #[test]
    fn mixed_families_and_a_zero_timeout_are_refused() {
        let to = SocketAddr::from((Ipv4Addr::LOCALHOST, 179));
        let mixed = TcpConnect {
            ttl: None,
            local: Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        };
        let e = mixed.connect(to, Duration::from_secs(1)).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput, "{e}");
        let e = TcpConnect::default()
            .connect(to, Duration::ZERO)
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput, "{e}");
    }
}

/// Real sockets: none of this needs a privilege.
#[cfg(all(test, not(miri)))]
mod socket_tests {
    use super::*;

    use std::io::Read;
    use std::net::{Ipv4Addr, TcpListener};

    const TIMEOUT: Duration = Duration::from_secs(5);

    /// `EADDRNOTAVAIL`, `<asm-generic/errno.h>`.
    const EADDRNOTAVAIL: i32 = 99;

    fn hosts() -> Vec<IpAddr> {
        let mut hosts = vec![IpAddr::V4(Ipv4Addr::LOCALHOST)];
        if TcpListener::bind("[::1]:0").is_ok() {
            hosts.push("::1".parse().unwrap());
        }
        hosts
    }

    fn ttl7() -> NonZeroU8 {
        NonZeroU8::new(7).unwrap()
    }

    #[test]
    fn connects_with_the_ttl_given_and_reads_it_back() {
        for host in hosts() {
            let listener = TcpListener::bind((host, 0)).unwrap();
            let builder = TcpConnect {
                ttl: Some(ttl7()),
                local: None,
            };
            let mut near = builder
                .connect(listener.local_addr().unwrap(), TIMEOUT)
                .unwrap();
            let (far, _) = listener.accept().unwrap();
            assert_eq!(ttl(&near).unwrap(), 7, "{host}");
            // The other end keeps the default.
            assert_ne!(ttl(&far).unwrap(), 7, "{host}");
            if host.is_ipv4() {
                assert_eq!(near.ttl().unwrap(), 7);
            }
            // The stream blocks again: a read waits for its timeout.
            near.set_read_timeout(Some(Duration::from_millis(200)))
                .unwrap();
            let started = Instant::now();
            let e = near.read(&mut [0; 1]).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::WouldBlock, "{e}");
            assert!(started.elapsed() >= Duration::from_millis(150), "{host}");
        }
    }

    #[test]
    fn without_a_ttl_the_system_default_is_used() {
        for host in hosts() {
            let listener = TcpListener::bind((host, 0)).unwrap();
            let ours = TcpConnect::default()
                .connect(listener.local_addr().unwrap(), TIMEOUT)
                .unwrap();
            let plain = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            assert_eq!(ttl(&ours).unwrap(), ttl(&plain).unwrap(), "{host}");
            if host.is_ipv4() {
                assert_eq!(u32::from(ttl(&ours).unwrap()), plain.ttl().unwrap());
            }
        }
    }

    #[test]
    fn binds_the_local_address_before_connecting() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let local: IpAddr = "127.0.0.2".parse().unwrap();
        let builder = TcpConnect {
            ttl: None,
            local: Some(local),
        };
        let near = builder
            .connect(listener.local_addr().unwrap(), TIMEOUT)
            .unwrap();
        let (_far, from) = listener.accept().unwrap();
        assert_eq!(from.ip(), local);
        assert_eq!(near.local_addr().unwrap().ip(), local);
        assert_ne!(near.local_addr().unwrap().port(), 0);
    }

    /// A listener that never accepts fills its queue (std listens with a
    /// backlog of 128); then the kernel drops the next SYN, and the
    /// connect waits until its deadline.
    #[test]
    fn a_full_accept_queue_times_out() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let to = listener.local_addr().unwrap();
        let timeout = Duration::from_millis(300);
        let mut held = Vec::new();
        for _ in 0..4100 {
            let started = Instant::now();
            match TcpConnect::default().connect(to, timeout) {
                Ok(s) => held.push(s),
                Err(e) => {
                    assert_eq!(e.kind(), io::ErrorKind::TimedOut, "{e}");
                    let took = started.elapsed();
                    assert!(took >= timeout, "{took:?}");
                    assert!(took < timeout + Duration::from_secs(1), "{took:?}");
                    assert!(held.len() >= 128, "{}", held.len());
                    return;
                }
            }
        }
        panic!("{} connections and none timed out", held.len());
    }

    #[test]
    fn refused_unassignable_and_mixed_families_fail_at_once() {
        let closed = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap()
        };
        let started = Instant::now();
        let e = TcpConnect::default().connect(closed, TIMEOUT).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::ConnectionRefused, "{e}");
        // An address this host does not have (TEST-NET-1).
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let foreign = TcpConnect {
            ttl: Some(ttl7()),
            local: Some("192.0.2.123".parse().unwrap()),
        };
        let e = foreign
            .connect(listener.local_addr().unwrap(), TIMEOUT)
            .unwrap_err();
        assert_eq!(e.raw_os_error(), Some(EADDRNOTAVAIL), "{e}");
        let mixed = TcpConnect {
            ttl: None,
            local: Some("::1".parse().unwrap()),
        };
        let e = mixed
            .connect(listener.local_addr().unwrap(), TIMEOUT)
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput, "{e}");
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn set_ttl_on_an_accepted_socket() {
        for host in hosts() {
            let listener = TcpListener::bind((host, 0)).unwrap();
            let near = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (far, _) = listener.accept().unwrap();
            let default = ttl(&far).unwrap();
            set_ttl(&far, NonZeroU8::MIN).unwrap();
            assert_eq!(ttl(&far).unwrap(), 1, "{host}");
            set_ttl(&far, NonZeroU8::MAX).unwrap();
            assert_eq!(ttl(&far).unwrap(), 255, "{host}");
            // The connecting end, and the listener's next connection,
            // keep the default.
            assert_eq!(ttl(&near).unwrap(), default, "{host}");
            let _again = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (next, _) = listener.accept().unwrap();
            assert_eq!(ttl(&next).unwrap(), default, "{host}");
        }
    }
}
