//! The kernel FIB: rtnetlink message codec (pure, Miri-tested) and the
//! reconciliation of the routes the RIB wants against the routes the
//! kernel has (AGENTS.md §3, "FIB"; README, "FIB dry-run").
//!
//! Routes carry our protocol number in one table; nothing else is ever
//! touched. In dry-run mode every operation is computed and reported but
//! not sent. The socket comes from `bgpfc-sys`; everything else here is
//! `#![forbid(unsafe_code)]`.
//!
//! Implements: `rtnetlink(7)` `RTM_NEWROUTE` / `RTM_DELROUTE` /
//! `RTM_GETROUTE`; RFC 8950 §3 (IPv6 next hop for IPv4 routes via
//! `RTA_VIA`).
#![forbid(unsafe_code)]

pub mod netlink;
pub mod reconcile;
pub mod route;

use std::fmt;
use std::net::IpAddr;

use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::Afi;

pub use reconcile::{Op, Table};
pub use route::RouteMsg;

/// Whether operations are sent to the kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Compute and report, send nothing.
    DryRun,
    /// Send.
    Install,
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Mode::DryRun => "dry-run",
            Mode::Install => "install",
        })
    }
}

/// Why an operation failed.
#[derive(Debug)]
pub enum FibError {
    /// The socket could not be used.
    Io(std::io::Error),
    /// The kernel refused with this errno (positive).
    Kernel(i32),
    /// The kernel's reply was malformed.
    Protocol(netlink::NetlinkError),
}

impl fmt::Display for FibError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FibError::Io(e) => write!(f, "netlink socket: {e}"),
            FibError::Kernel(errno) => {
                write!(
                    f,
                    "kernel refused: {}",
                    std::io::Error::from_raw_os_error(*errno)
                )
            }
            FibError::Protocol(e) => write!(f, "netlink reply: {e}"),
        }
    }
}

impl std::error::Error for FibError {}

impl From<std::io::Error> for FibError {
    fn from(e: std::io::Error) -> Self {
        FibError::Io(e)
    }
}

impl From<netlink::NetlinkError> for FibError {
    fn from(e: netlink::NetlinkError) -> Self {
        FibError::Protocol(e)
    }
}

/// What happened to one operation.
#[derive(Debug)]
pub struct Applied {
    /// The operation.
    pub op: Op,
    /// `Ok` when sent and acknowledged (or when dry-run skipped it).
    pub result: Result<(), FibError>,
    /// Whether it was only reported (dry-run).
    pub dry_run: bool,
}

/// The desired and installed tables and the socket between them.
pub struct Fib {
    mode: Mode,
    table: u32,
    protocol: u8,
    desired: Table,
    installed: Table,
    seq: u32,
    #[cfg(not(miri))]
    socket: Option<bgpfc_sys::NetlinkSocket>,
}

impl Fib {
    /// A FIB manager for `table` and `protocol`, with no socket yet.
    #[must_use]
    pub fn new(mode: Mode, table: u32, protocol: u8) -> Fib {
        Fib {
            mode,
            table,
            protocol,
            desired: Table::new(),
            installed: Table::new(),
            seq: 1,
            #[cfg(not(miri))]
            socket: None,
        }
    }

    /// The mode.
    #[must_use]
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Routes the RIB wants.
    #[must_use]
    pub fn desired(&self) -> &Table {
        &self.desired
    }

    /// Routes believed to be in the kernel with our protocol number.
    #[must_use]
    pub fn installed(&self) -> &Table {
        &self.installed
    }

    /// Open the netlink socket. Needs no privilege; install mode needs
    /// `CAP_NET_ADMIN` on top. Call before dropping privileges only if
    /// the socket should keep them (it does: netlink checks the opener).
    ///
    /// # Errors
    /// The socket error.
    #[cfg(not(miri))]
    pub fn open(&mut self) -> Result<(), FibError> {
        self.socket = Some(bgpfc_sys::NetlinkSocket::open()?);
        Ok(())
    }

    /// Learn what the kernel has with our protocol number in our table,
    /// then compute the operations that make it match `desired` (at
    /// startup: remove everything stale). The operations are applied in
    /// install mode, reported in dry-run.
    ///
    /// # Errors
    /// A dump failure; nothing is changed then.
    #[cfg(not(miri))]
    pub fn sync(&mut self) -> Result<Vec<Applied>, FibError> {
        let mut installed = Table::new();
        for afi in [Afi::Ipv4, Afi::Ipv6] {
            for r in self.dump(afi)? {
                if r.protocol == self.protocol
                    && r.table == self.table
                    && let Some(gw) = r.gateway
                {
                    installed.insert(r.dst, gw);
                }
            }
        }
        self.installed = installed;
        Ok(self.reconcile())
    }

    /// Change the desired route for `prefix` (`None` deletes) and apply
    /// what follows.
    pub fn set(&mut self, prefix: Prefix, gateway: Option<IpAddr>) -> Vec<Applied> {
        let previous = self.desired.get(&prefix).copied();
        match gateway {
            Some(gw) => {
                self.desired.insert(prefix, gw);
            }
            None => {
                self.desired.remove(&prefix);
            }
        }
        // Dry-run installs nothing, so what it reports is the change to
        // the desired table itself: what install mode would have done.
        let reference = if self.mode == Mode::DryRun {
            previous
        } else {
            self.installed.get(&prefix).copied()
        };
        // Only this prefix can differ now; a full plan is cheap enough
        // but a single-prefix plan keeps the common case O(log n).
        let ops = match (self.desired.get(&prefix), reference.as_ref()) {
            (Some(d), i) if i != Some(d) => vec![Op::Set {
                prefix,
                gateway: *d,
            }],
            (None, Some(i)) => vec![Op::Delete {
                prefix,
                gateway: *i,
            }],
            _ => Vec::new(),
        };
        self.run(ops)
    }

    /// Switch modes. Going to install performs a full reconcile (README,
    /// "FIB dry-run"); going to dry-run leaves the kernel as it is.
    pub fn set_mode(&mut self, mode: Mode) -> Vec<Applied> {
        self.mode = mode;
        if mode == Mode::Install {
            self.reconcile()
        } else {
            Vec::new()
        }
    }

    /// Forget every desired route and remove what is installed (shutdown).
    pub fn clear(&mut self) -> Vec<Applied> {
        self.desired.clear();
        self.reconcile()
    }

    /// Apply the full plan.
    pub fn reconcile(&mut self) -> Vec<Applied> {
        let ops = reconcile::plan(&self.desired, &self.installed);
        self.run(ops)
    }

    fn run(&mut self, ops: Vec<Op>) -> Vec<Applied> {
        let mut out = Vec::with_capacity(ops.len());
        for op in ops {
            if self.mode == Mode::DryRun {
                out.push(Applied {
                    op,
                    result: Ok(()),
                    dry_run: true,
                });
                continue;
            }
            let result = self.send_op(&op);
            if result.is_ok() {
                reconcile::apply(&mut self.installed, &op);
            }
            out.push(Applied {
                op,
                result,
                dry_run: false,
            });
        }
        out
    }

    fn next_seq(&mut self) -> u32 {
        self.seq = self.seq.wrapping_add(1).max(1);
        self.seq
    }

    #[cfg(not(miri))]
    fn send_op(&mut self, op: &Op) -> Result<(), FibError> {
        let seq = self.next_seq();
        let (route, bytes) = match op {
            Op::Set { prefix, gateway } => {
                let r = RouteMsg::unicast(*prefix, *gateway, self.table, self.protocol);
                let b = r.encode_set(seq);
                (r, b)
            }
            Op::Delete { prefix, gateway } => {
                let r = RouteMsg::unicast(*prefix, *gateway, self.table, self.protocol);
                let b = r.encode_delete(seq);
                (r, b)
            }
        };
        let _ = route;
        let socket = self.socket.as_ref().ok_or_else(|| {
            FibError::Io(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "netlink socket not open",
            ))
        })?;
        socket.send(&bytes)?;
        let mut buf = vec![0u8; 8192];
        loop {
            let n = socket.recv(&mut buf)?;
            for m in netlink::parse(&buf[..n])? {
                if m.header.seq != seq {
                    continue;
                }
                if m.header.ty == netlink::NLMSG_ERROR {
                    let code = netlink::parse_error(m.payload)?;
                    return if code == 0 {
                        Ok(())
                    } else {
                        Err(FibError::Kernel(-code))
                    };
                }
            }
        }
    }

    #[cfg(miri)]
    #[allow(clippy::unnecessary_wraps, reason = "mirrors the real signature")]
    fn send_op(&mut self, _: &Op) -> Result<(), FibError> {
        let _ = self.next_seq();
        Ok(())
    }

    /// Every unicast route of `afi` the kernel reports.
    #[cfg(not(miri))]
    fn dump(&mut self, afi: Afi) -> Result<Vec<RouteMsg>, FibError> {
        let seq = self.next_seq();
        let socket = self.socket.as_ref().ok_or_else(|| {
            FibError::Io(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "netlink socket not open",
            ))
        })?;
        socket.send(&RouteMsg::encode_dump(afi, seq))?;
        let mut routes = Vec::new();
        let mut buf = vec![0u8; 1 << 20];
        loop {
            let n = socket.recv(&mut buf)?;
            for m in netlink::parse(&buf[..n])? {
                if m.header.seq != seq {
                    continue;
                }
                match m.header.ty {
                    netlink::NLMSG_DONE => return Ok(routes),
                    netlink::NLMSG_ERROR => {
                        let code = netlink::parse_error(m.payload)?;
                        return Err(FibError::Kernel(-code));
                    }
                    route::RTM_NEWROUTE => {
                        if let Some(r) = RouteMsg::decode(m.payload)? {
                            routes.push(r);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn dry_run_reports_without_touching_installed() {
        let mut fib = Fib::new(Mode::DryRun, route::RT_TABLE_MAIN, route::RTPROT_BGP);
        let out = fib.set(p("192.0.2.0/24"), Some(ip("10.0.0.1")));
        assert_eq!(out.len(), 1);
        assert!(out[0].dry_run);
        assert!(out[0].result.is_ok());
        assert_eq!(
            out[0].op,
            Op::Set {
                prefix: p("192.0.2.0/24"),
                gateway: ip("10.0.0.1")
            }
        );
        assert_eq!(fib.desired().len(), 1);
        assert_eq!(fib.installed().len(), 0);
        // Same again: no change to report.
        assert_eq!(fib.set(p("192.0.2.0/24"), Some(ip("10.0.0.1"))).len(), 0);
        // A new gateway, then the delete, are each reported once.
        let out = fib.set(p("192.0.2.0/24"), Some(ip("10.0.0.2")));
        assert_eq!(out.len(), 1);
        let out = fib.set(p("192.0.2.0/24"), None);
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0].op, Op::Delete { .. }));
        assert_eq!(fib.set(p("192.0.2.0/24"), None).len(), 0);
        assert_eq!(fib.desired().len(), 0);
        assert_eq!(fib.mode(), Mode::DryRun);
        assert_eq!(Mode::Install.to_string(), "install");
        assert_eq!(fib.clear().len(), 0);
    }

    #[cfg(not(miri))]
    #[test]
    fn install_without_a_socket_fails_cleanly() {
        let mut fib = Fib::new(Mode::Install, route::RT_TABLE_MAIN, route::RTPROT_BGP);
        let out = fib.set(p("192.0.2.0/24"), Some(ip("10.0.0.1")));
        assert!(matches!(out[0].result, Err(FibError::Io(_))));
        assert!(!out[0].dry_run);
        assert_eq!(fib.installed().len(), 0);
        let e = FibError::Kernel(101).to_string();
        assert!(e.contains("kernel refused"), "{e}");
    }

    /// An unprivileged process may dump the routing table; this reads the
    /// real one and checks that nothing of ours is there.
    #[cfg(not(miri))]
    #[test]
    fn dump_the_real_table() {
        let mut fib = Fib::new(Mode::DryRun, route::RT_TABLE_MAIN, 250);
        fib.open().expect("netlink socket");
        let out = fib.sync().expect("dump");
        assert_eq!(out.len(), 0);
        assert_eq!(fib.installed().len(), 0);
        // Everything the kernel has decodes.
        let all = fib.dump(Afi::Ipv4).expect("dump v4");
        let _ = fib.dump(Afi::Ipv6).expect("dump v6");
        for r in &all {
            assert_eq!(r.dst.afi(), Afi::Ipv4);
        }
    }
}
