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

use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;

use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::Afi;

pub use reconcile::{Merge, Op, Routes, Table};
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

/// A change of the RIB's route for one prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Change {
    /// The destination.
    pub prefix: Prefix,
    /// The next hop now, or `None` when the RIB has no route.
    pub gateway: Option<IpAddr>,
    /// The next hop before, or `None` when the RIB had no route.
    pub previous: Option<IpAddr>,
}

/// Operations sent to the kernel in one netlink message at most.
pub const BATCH: usize = 256;

/// Room for a datagram of acknowledgements: errors carry the request
/// they answer, so a batch with many failures fills several.
#[cfg(not(miri))]
const ACK_BUF: usize = 8192;

/// The desired and installed tables and the socket between them.
pub struct Fib {
    mode: Mode,
    table: u32,
    protocol: u8,
    /// The desired and the installed routes.
    routes: Routes,
    seq: u32,
    #[cfg(not(miri))]
    socket: Option<bgpfc_sys::NetlinkSocket>,
    /// Operations chosen and not yet carried out.
    pending: Vec<Op>,
    /// The prefixes `pending` changes.
    touched: HashSet<Prefix>,
    /// The batch being sent, then the acknowledgements read. Like the two
    /// above, kept between batches: the FIB thread allocates nothing per
    /// batch once they have grown.
    #[cfg(not(miri))]
    buf: Vec<u8>,
}

impl Fib {
    /// A FIB manager for `table` and `protocol`, with no socket yet.
    #[must_use]
    pub fn new(mode: Mode, table: u32, protocol: u8) -> Fib {
        Fib {
            mode,
            table,
            protocol,
            routes: Routes::new(),
            seq: 1,
            #[cfg(not(miri))]
            socket: None,
            pending: Vec::new(),
            touched: HashSet::new(),
            #[cfg(not(miri))]
            buf: Vec::new(),
        }
    }

    /// The mode.
    #[must_use]
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Routes believed to be in the kernel with our protocol number, as a
    /// table built for the caller.
    #[must_use]
    pub fn installed(&self) -> Table {
        self.routes.installed_table()
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

    /// Learn what the kernel has with our protocol number in our table and
    /// remove it all: at startup the RIB wants nothing yet, so every such
    /// route is stale. The operations are applied in install mode,
    /// reported in dry-run.
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
        self.routes.set_installed(&installed);
        Ok(self.clear())
    }

    /// Apply one change of the RIB's route for a prefix: at most one
    /// operation.
    pub fn set(&mut self, change: Change) -> Option<Applied> {
        let op = self.plan_one(change)?;
        self.run(&[op]).pop()
    }

    /// Apply changes of the RIB's routes, in order, adding what was done
    /// to `out`. In install mode the operations go to the kernel together,
    /// up to [`BATCH`] in one netlink message, rather than one round trip
    /// each.
    pub fn set_all(&mut self, changes: impl IntoIterator<Item = Change>, out: &mut Vec<Applied>) {
        for change in changes {
            // An operation is chosen from what is installed, which the
            // pending ones are about to change: a prefix changed twice
            // waits for the operations before it to be carried out.
            if self.mode == Mode::Install && !self.touched.insert(change.prefix) {
                self.flush(out);
                self.touched.insert(change.prefix);
            }
            if let Some(op) = self.plan_one(change) {
                self.pending.push(op);
            }
            if self.pending.len() == BATCH {
                self.flush(out);
            }
        }
        self.flush(out);
    }

    /// Carry out the pending operations.
    fn flush(&mut self, out: &mut Vec<Applied>) {
        let ops = std::mem::take(&mut self.pending);
        self.run_into(&ops, out);
        self.pending = ops;
        self.pending.clear();
        self.touched.clear();
    }

    /// The operation a change asks for, if any.
    fn plan_one(&self, change: Change) -> Option<Op> {
        let Change {
            prefix,
            gateway,
            previous,
        } = change;
        // Dry-run installs nothing, so what it reports is the change of the
        // RIB's route itself: what install mode would have done.
        let reference = if self.mode == Mode::DryRun {
            previous
        } else {
            self.routes.installed(&prefix)
        };
        match (gateway, reference) {
            (Some(d), i) if i != Some(d) => Some(Op::Set { prefix, gateway: d }),
            (None, Some(i)) => Some(Op::Delete { prefix, gateway: i }),
            _ => None,
        }
    }

    /// Switch modes. Going to dry-run leaves the kernel as it is; going to
    /// install needs a full reconcile against the RIB's routes (README,
    /// "FIB dry-run"), which the caller runs with [`Fib::reconcile`].
    pub fn set_mode(&mut self, mode: Mode) {
        self.mode = mode;
    }

    /// Reconcile part of the RIB's routes, which continue, in prefix
    /// order, those given since `merge` was made (`Merge::default()`):
    /// install what is missing or different and remove installed routes
    /// they skip. End with [`Fib::reconcile_end`].
    pub fn reconcile(
        &mut self,
        merge: &mut Merge,
        routes: &[(Prefix, IpAddr)],
        out: &mut Vec<Applied>,
    ) {
        let mut ops = std::mem::take(&mut self.pending);
        self.routes.merge(merge, routes, &mut ops);
        self.run_into(&ops, out);
        ops.clear();
        self.pending = ops;
    }

    /// End a reconcile: remove what is installed past the RIB's last route.
    pub fn reconcile_end(&mut self, merge: Merge, out: &mut Vec<Applied>) {
        let mut ops = std::mem::take(&mut self.pending);
        self.routes.merge_end(merge, &mut ops);
        self.run_into(&ops, out);
        ops.clear();
        self.pending = ops;
    }

    /// Remove every route installed (shutdown).
    pub fn clear(&mut self) -> Vec<Applied> {
        let ops = self.routes.delete_all();
        self.run(&ops)
    }

    /// Carry out `ops`, in order.
    fn run(&mut self, ops: &[Op]) -> Vec<Applied> {
        let mut out = Vec::with_capacity(ops.len());
        self.run_into(ops, &mut out);
        out
    }

    /// Carry out `ops`, in order, adding the outcomes to `out`: report
    /// them in dry-run, send them in batches in install mode and record
    /// those that succeeded.
    fn run_into(&mut self, ops: &[Op], out: &mut Vec<Applied>) {
        let dry_run = self.mode == Mode::DryRun;
        for chunk in ops.chunks(BATCH) {
            let first = out.len();
            out.extend(chunk.iter().map(|op| Applied {
                op: op.clone(),
                result: Ok(()),
                dry_run,
            }));
            if dry_run {
                continue;
            }
            self.send_batch(chunk, &mut out[first..]);
            for a in &out[first..] {
                if a.result.is_ok() {
                    self.routes.apply(&a.op);
                }
            }
        }
    }

    fn next_seq(&mut self) -> u32 {
        self.seq = self.seq.wrapping_add(1).max(1);
        self.seq
    }

    /// `n` consecutive sequence numbers, none of them 0; the first.
    fn reserve_seqs(&mut self, n: usize) -> u32 {
        // invariant: n is at most BATCH.
        let n = u32::try_from(n).unwrap();
        if self.seq > u32::MAX - n {
            self.seq = 0;
        }
        let first = self.seq + 1;
        self.seq += n;
        first
    }

    /// Send `ops` as one netlink message and set the result of each in
    /// `out`, which holds them as successes. Only the last asks for an
    /// acknowledgement: the kernel handles requests in order and reports
    /// a failed one whether asked or not, so when the last is
    /// acknowledged, every failure has been reported and any other
    /// request succeeded.
    #[cfg(not(miri))]
    fn send_batch(&mut self, ops: &[Op], out: &mut [Applied]) {
        let n = ops.len();
        if n == 0 {
            return;
        }
        let first = self.reserve_seqs(n);
        // invariant: n is at most BATCH.
        let last = first + u32::try_from(n - 1).unwrap();
        self.buf.clear();
        for (seq, op) in (first..).zip(ops) {
            let ack = seq == last;
            self.buf.extend_from_slice(&match op {
                Op::Set { prefix, gateway } => {
                    RouteMsg::unicast(*prefix, *gateway, self.table, self.protocol)
                        .encode_set_with(seq, ack)
                }
                Op::Delete { prefix, gateway } => {
                    RouteMsg::unicast(*prefix, *gateway, self.table, self.protocol)
                        .encode_delete_with(seq, ack)
                }
            });
        }
        let fail_all = |out: &mut [Applied], e: &std::io::Error| {
            for a in out {
                a.result = Err(FibError::Io(std::io::Error::new(e.kind(), e.to_string())));
            }
        };
        let Some(socket) = self.socket.as_ref() else {
            let e =
                std::io::Error::new(std::io::ErrorKind::NotConnected, "netlink socket not open");
            return fail_all(out, &e);
        };
        if let Err(e) = socket.send(&self.buf) {
            return fail_all(out, &e);
        }
        self.buf.resize(ACK_BUF, 0);
        loop {
            let k = match socket.recv(&mut self.buf) {
                Ok(k) => k,
                Err(e) => return fail_all(out, &e),
            };
            let messages = match netlink::parse(&self.buf[..k]) {
                Ok(m) => m,
                Err(e) => {
                    for a in out {
                        a.result = Err(FibError::Protocol(e.clone()));
                    }
                    return;
                }
            };
            let mut done = false;
            for m in messages {
                if m.header.ty != netlink::NLMSG_ERROR {
                    continue;
                }
                // An answer to an earlier request is not ours.
                let Some(a) = usize::try_from(m.header.seq.wrapping_sub(first))
                    .ok()
                    .and_then(|i| out.get_mut(i))
                else {
                    continue;
                };
                match netlink::parse_error(m.payload) {
                    Ok(0) => {}
                    Ok(code) => a.result = Err(FibError::Kernel(-code)),
                    Err(e) => a.result = Err(FibError::Protocol(e)),
                }
                done |= m.header.seq == last;
            }
            if done {
                return;
            }
        }
    }

    #[cfg(miri)]
    fn send_batch(&mut self, ops: &[Op], _: &mut [Applied]) {
        let _ = self.reserve_seqs(ops.len());
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

    fn ch(prefix: &str, gateway: Option<&str>, previous: Option<&str>) -> Change {
        Change {
            prefix: p(prefix),
            gateway: gateway.map(ip),
            previous: previous.map(ip),
        }
    }

    #[test]
    fn dry_run_reports_the_change_and_keeps_nothing() {
        let mut fib = Fib::new(Mode::DryRun, route::RT_TABLE_MAIN, route::RTPROT_BGP);
        let out = fib.set(ch("192.0.2.0/24", Some("10.0.0.1"), None)).unwrap();
        assert!(out.dry_run);
        assert!(out.result.is_ok());
        assert_eq!(
            out.op,
            Op::Set {
                prefix: p("192.0.2.0/24"),
                gateway: ip("10.0.0.1")
            }
        );
        assert_eq!(fib.installed().len(), 0);
        // The same next hop again: no change to report.
        let same = ch("192.0.2.0/24", Some("10.0.0.1"), Some("10.0.0.1"));
        assert!(fib.set(same).is_none());
        // A new gateway, then the delete, are each reported once.
        let moved = ch("192.0.2.0/24", Some("10.0.0.2"), Some("10.0.0.1"));
        assert!(fib.set(moved).is_some());
        let out = fib.set(ch("192.0.2.0/24", None, Some("10.0.0.2"))).unwrap();
        assert_eq!(
            out.op,
            Op::Delete {
                prefix: p("192.0.2.0/24"),
                gateway: ip("10.0.0.2")
            }
        );
        assert!(fib.set(ch("192.0.2.0/24", None, None)).is_none());
        assert!(fib.routes.is_empty());
        assert_eq!(fib.mode(), Mode::DryRun);
        assert_eq!(Mode::Install.to_string(), "install");
        assert_eq!(fib.clear().len(), 0);
    }

    #[test]
    fn set_all_reports_what_set_would() {
        let changes = [
            ch("192.0.2.0/24", Some("10.0.0.1"), None),
            ch("2001:db8::/32", Some("fe80::1"), None),
            ch("192.0.2.0/24", Some("10.0.0.1"), Some("10.0.0.1")),
            ch("192.0.2.0/24", Some("10.0.0.2"), Some("10.0.0.1")),
            ch("198.51.100.0/24", None, None),
            ch("2001:db8::/32", None, Some("fe80::1")),
        ];
        let mut one = Fib::new(Mode::DryRun, route::RT_TABLE_MAIN, route::RTPROT_BGP);
        let expected: Vec<Op> = changes
            .iter()
            .filter_map(|&c| one.set(c))
            .map(|a| a.op)
            .collect();
        assert_eq!(expected.len(), 4);
        let mut all = Fib::new(Mode::DryRun, route::RT_TABLE_MAIN, route::RTPROT_BGP);
        let mut out = Vec::new();
        all.set_all(changes, &mut out);
        assert_eq!(
            out.iter().map(|a| a.op.clone()).collect::<Vec<_>>(),
            expected
        );
        assert!(out.iter().all(|a| a.dry_run && a.result.is_ok()));
    }

    #[test]
    fn a_dry_run_reconcile_reports_against_what_is_installed() {
        let mut fib = Fib::new(Mode::DryRun, route::RT_TABLE_MAIN, route::RTPROT_BGP);
        let mut merge = Merge::default();
        let mut out = Vec::new();
        fib.reconcile(&mut merge, &[(p("10.0.0.0/8"), ip("192.0.2.1"))], &mut out);
        fib.reconcile(&mut merge, &[(p("2001:db8::/32"), ip("fe80::1"))], &mut out);
        fib.reconcile_end(merge, &mut out);
        assert_eq!(out.len(), 2);
        assert!(
            out.iter()
                .all(|a| a.dry_run && matches!(a.op, Op::Set { .. }))
        );
        assert!(fib.routes.is_empty());
    }

    #[cfg(not(miri))]
    #[test]
    fn install_without_a_socket_fails_every_operation() {
        let mut fib = Fib::new(Mode::Install, route::RT_TABLE_MAIN, route::RTPROT_BGP);
        let changes = (0..=u8::MAX).chain(0..3).map(|i| Change {
            prefix: Prefix::new(IpAddr::from([10, i, 0, 0]), 16).unwrap(),
            gateway: Some(ip("192.0.2.1")),
            previous: None,
        });
        let mut out = Vec::new();
        fib.set_all(changes, &mut out);
        // Each change of a prefix not installed is retried: none succeeded.
        assert_eq!(out.len(), 259);
        assert!(out.iter().all(|a| matches!(a.result, Err(FibError::Io(_)))));
        assert_eq!(fib.installed().len(), 0);
    }

    /// Run in a network namespace of its own where 192.0.2.0/24 is
    /// connected, for example:
    /// `sudo unshare -n sh -c 'ip link set lo up && ip addr add 192.0.2.10/24 dev lo && cargo test -p bgpfc-fib -- --ignored'`.
    #[cfg(not(miri))]
    #[test]
    #[ignore = "needs CAP_NET_ADMIN and 192.0.2.0/24 connected; changes table 250"]
    fn batches_reach_the_kernel_with_a_result_per_operation() {
        const TABLE: u32 = 250;
        let installed = || {
            let mut f = Fib::new(Mode::DryRun, TABLE, route::RTPROT_BGP);
            f.open().unwrap();
            f.sync().unwrap();
            f.installed()
        };
        let mut fib = Fib::new(Mode::Install, TABLE, route::RTPROT_BGP);
        fib.open().unwrap();
        fib.sync().unwrap();
        let mut changes: Vec<_> = (0..300u16)
            .map(|i| {
                let [a, b] = i.to_be_bytes();
                Change {
                    prefix: Prefix::new(IpAddr::from([10, a, b, 0]), 24).unwrap(),
                    gateway: Some(ip("192.0.2.1")),
                    previous: None,
                }
            })
            .collect();
        // One request the kernel refuses, in the middle of the first
        // batch: no route to the gateway.
        changes[100].gateway = Some(ip("203.0.113.1"));
        // The same prefix twice in the second batch: the second change
        // sees the first carried out.
        changes.push(Change {
            gateway: Some(ip("192.0.2.2")),
            ..changes[260]
        });
        changes.push(Change {
            gateway: None,
            ..changes[261]
        });
        let mut out = Vec::new();
        fib.set_all(changes.clone(), &mut out);
        assert_eq!(out.len(), changes.len());
        let failed: Vec<usize> = (0..out.len()).filter(|&i| out[i].result.is_err()).collect();
        assert_eq!(failed, vec![100]);
        assert!(matches!(out[100].result, Err(FibError::Kernel(_))));
        let kernel = installed();
        assert_eq!(kernel, fib.installed());
        assert_eq!(kernel.len(), 298);
        assert_eq!(kernel.get(&changes[260].prefix), Some(&ip("192.0.2.2")));
        // A reconcile in two parts to the first ten routes, one of them
        // with another gateway: the rest are removed.
        let mut want: Table = kernel.iter().take(10).map(|(p, g)| (*p, *g)).collect();
        want.insert(changes[3].prefix, ip("192.0.2.3"));
        let want: Vec<(Prefix, IpAddr)> = want.into_iter().collect();
        let mut merge = Merge::default();
        let mut out = Vec::new();
        fib.reconcile(&mut merge, &want[..4], &mut out);
        fib.reconcile(&mut merge, &want[4..], &mut out);
        fib.reconcile_end(merge, &mut out);
        assert!(out.iter().all(|a| a.result.is_ok()));
        assert_eq!(out.len(), 1 + 288);
        let kernel = installed();
        assert_eq!(kernel.into_iter().collect::<Vec<_>>(), want);
        assert!(fib.clear().iter().all(|a| a.result.is_ok()));
        assert_eq!(installed().len(), 0);
    }

    #[cfg(not(miri))]
    #[test]
    fn install_without_a_socket_fails_cleanly() {
        let mut fib = Fib::new(Mode::Install, route::RT_TABLE_MAIN, route::RTPROT_BGP);
        let out = fib.set(ch("192.0.2.0/24", Some("10.0.0.1"), None)).unwrap();
        assert!(matches!(out.result, Err(FibError::Io(_))));
        assert!(!out.dry_run);
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
