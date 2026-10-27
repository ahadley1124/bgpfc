//! Following the kernel's routing table: a socket subscribed to the
//! route, interface and address groups ([`kernel::GROUPS`]), a snapshot
//! of what the kernel has, and the changes after it (`rtnetlink(7)`).
//! Read-only: nothing here writes to the kernel, so it works the same in
//! dry-run and install mode.
//!
//! Subscribe, then dump, on one socket. Every change after the
//! subscription has a notification, queued on the socket in the order the
//! kernel made the changes, among the dump's replies; so a snapshot that
//! applies the notifications that came during its dumps, in their order,
//! after the dumps, holds what the kernel has: for a route a change
//! touched while the dumps ran, its last notification wins, and any other
//! is as the dump read it. The notifications after the snapshot follow
//! from [`Monitor::next_events`].
//!
//! What breaks that: the kernel drops notifications that do not fit the
//! socket's receive buffer and reports it once, as `ENOBUFS`
//! (`<asm-generic/errno.h>`, 105). The reader then takes a new snapshot.
//! Within a snapshot, the notifications read before the first reply of its
//! first dump are older than every dump, which reads the kernel as it is
//! later on, and are dropped: after an overflow, those left from before it
//! would otherwise be applied over newer dump entries.

use std::collections::BTreeMap;

use bgpfc_sys::NetlinkSocket;
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::Afi;

use crate::FibError;
use crate::kernel::{self, Event, Link, Route};
use crate::netlink;
use crate::route::{RTM_NEWROUTE, RouteMsg};

/// `ENOBUFS`, `<asm-generic/errno.h>`: notifications were dropped.
pub const ENOBUFS: i32 = 105;

/// Room for a datagram: a dump reply takes at most 32 KiB (the kernel's
/// `netlink_dump`), a notification far less.
const BUF: usize = 64 << 10;

/// How many times a snapshot is taken in a row while something it cannot
/// follow happens during it (lost notifications, an interface going down
/// or away, an address going); the last is used as it is.
const TRIES: usize = 3;

/// The kernel's routes that [`kernel::relevant`] keeps, and its
/// interfaces.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    /// The routes, by destination, then metric.
    pub routes: Vec<Route>,
    /// The interfaces, by index.
    pub links: Vec<Link>,
}

/// A socket that follows the kernel's routes, interfaces and addresses.
#[derive(Debug)]
pub struct Monitor {
    socket: NetlinkSocket,
    /// The protocol number bgpfcd's own routes carry: never kept.
    protocol: u8,
    seq: u32,
    buf: Vec<u8>,
}

/// What one dump of a snapshot collects.
#[derive(Default)]
struct Dumps {
    routes: BTreeMap<(Prefix, u32), Route>,
    links: BTreeMap<u32, Link>,
    /// Notifications that came during the dumps, in order.
    events: Vec<Event>,
    /// Whether a reply of the snapshot's first dump came yet: the
    /// notifications before it are dropped.
    started: bool,
    /// Whether the kernel dropped notifications during the dumps.
    lost: bool,
}

impl Monitor {
    /// Open a socket and join [`kernel::GROUPS`]. Join before reading the
    /// table: a change after this has a notification. Open it before
    /// dropping privileges: with `CAP_NET_ADMIN` its receive buffer can be
    /// larger than `net.core.rmem_max` (`NetlinkSocket::open_subscribed`).
    ///
    /// # Errors
    /// The socket's.
    pub fn open(protocol: u8) -> Result<Monitor, FibError> {
        Ok(Monitor {
            socket: NetlinkSocket::open_subscribed(&kernel::GROUPS)?,
            protocol,
            seq: 0,
            buf: vec![0; BUF],
        })
    }

    /// What the kernel has: its interfaces, then the routes of each family
    /// that [`kernel::relevant`] keeps, dumped one at a time, with the
    /// notifications that came meanwhile applied after them. When
    /// notifications were lost, or an interface went down or away, or an
    /// address went, during the dumps, the snapshot is taken again, up to
    /// three times; the last is used as it is.
    ///
    /// # Errors
    /// The socket's, a dump the kernel refuses, or a malformed reply.
    pub fn snapshot(&mut self) -> Result<Snapshot, FibError> {
        let mut tries = 0;
        loop {
            tries += 1;
            let mut d = Dumps::default();
            let links = self.next_seq();
            self.dump(&kernel::encode_link_dump(links), links, &mut d)?;
            for afi in [Afi::Ipv4, Afi::Ipv6] {
                let seq = self.next_seq();
                self.dump(&RouteMsg::encode_dump(afi, seq), seq, &mut d)?;
            }
            let again = d.lost || disturbed(&d);
            for e in std::mem::take(&mut d.events) {
                apply(&mut d, e);
            }
            if !again || tries == TRIES {
                return Ok(Snapshot {
                    routes: d.routes.into_values().collect(),
                    links: d.links.into_values().collect(),
                });
            }
        }
    }

    /// The next notifications: one datagram's worth, decoded and filtered
    /// ([`kernel::event`]); empty when none of it matters. Blocks until the
    /// kernel sends something.
    ///
    /// # Errors
    /// [`FibError::Io`] with [`ENOBUFS`] when notifications were lost: take
    /// a new [`Monitor::snapshot`]. Any other socket error, or a malformed
    /// message.
    pub fn next_events(&mut self) -> Result<Vec<Event>, FibError> {
        let n = self.socket.recv(&mut self.buf)?;
        let mut events = Vec::new();
        for m in netlink::parse(&self.buf[..n])? {
            // Replies to a request of ours are not notifications.
            if is_reply(&m) {
                continue;
            }
            if let Some(e) = kernel::event(&m, self.protocol)? {
                events.push(e);
            }
        }
        Ok(events)
    }

    fn next_seq(&mut self) -> u32 {
        self.seq = self.seq.wrapping_add(1).max(1);
        self.seq
    }

    /// Send a dump `request` with sequence number `seq` and read until
    /// its end, keeping what it lists and the notifications in between.
    fn dump(&mut self, request: &[u8], seq: u32, d: &mut Dumps) -> Result<(), FibError> {
        self.socket.send(request)?;
        loop {
            let n = match self.socket.recv(&mut self.buf) {
                Ok(n) => n,
                // Notifications dropped; the dump goes on.
                Err(e) if e.raw_os_error() == Some(ENOBUFS) => {
                    d.lost = true;
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            for m in netlink::parse(&self.buf[..n])? {
                if m.header.seq == seq && m.header.ty == netlink::NLMSG_ERROR {
                    match netlink::parse_error(m.payload)? {
                        // The receive buffer was full when the dump was
                        // asked for: the kernel answers ENOBUFS, if the
                        // answer fits, and sends the dump as room frees up
                        // (`__netlink_dump_start`, `netlink_recvmsg`).
                        code if -code == ENOBUFS => d.lost = true,
                        code => return Err(FibError::Kernel(-code)),
                    }
                } else if m.header.seq == seq && is_reply(&m) {
                    d.started = true;
                    match m.header.ty {
                        netlink::NLMSG_DONE => return Ok(()),
                        RTM_NEWROUTE => {
                            if let Some(r) = kernel::decode_route(m.payload)?
                                && kernel::relevant(&r, self.protocol)
                            {
                                d.routes.insert((r.dst, r.metric), r);
                            }
                        }
                        kernel::RTM_NEWLINK => {
                            if let Some(l) = kernel::decode_link(m.payload)? {
                                d.links.insert(l.index, l);
                            }
                        }
                        _ => {}
                    }
                } else if d.started
                    && !is_reply(&m)
                    && let Some(e) = kernel::event(&m, self.protocol)?
                {
                    d.events.push(e);
                }
            }
        }
    }

    /// The socket, for the tests that shrink its receive buffer.
    #[cfg(test)]
    fn socket(&self) -> &NetlinkSocket {
        &self.socket
    }
}

/// Whether `m` answers a request (a dump's part, its end, or an error)
/// rather than notifying: the parts and the end of a dump carry
/// `NLM_F_MULTI`, notifications never do, and errors answer requests only.
fn is_reply(m: &netlink::Message<'_>) -> bool {
    m.header.flags & netlink::NLM_F_MULTI != 0
        || matches!(m.header.ty, netlink::NLMSG_DONE | netlink::NLMSG_ERROR)
}

/// Whether a notification of the dumps asks for another snapshot: an
/// interface that was up going down, one going away, or an address going,
/// which IPv4 removes routes for without notifications of their own.
fn disturbed(d: &Dumps) -> bool {
    let mut up: BTreeMap<u32, bool> = d.links.iter().map(|(i, l)| (*i, l.up)).collect();
    d.events.iter().any(|e| match e {
        Event::Link(l) => {
            let was = up.insert(l.index, l.up).unwrap_or(true);
            was && !l.up
        }
        Event::LinkGone(_) | Event::AddressGone(_) => true,
        Event::Route(_) | Event::RouteGone { .. } => false,
    })
}

/// Apply a notification to what the dumps listed.
fn apply(d: &mut Dumps, e: Event) {
    match e {
        Event::Route(r) => {
            d.routes.insert((r.dst, r.metric), r);
        }
        Event::RouteGone { dst, metric } => {
            d.routes.remove(&(dst, metric));
        }
        Event::Link(l) => {
            d.links.insert(l.index, l);
        }
        Event::LinkGone(index) => {
            d.links.remove(&index);
        }
        Event::AddressGone(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;
    use crate::kernel::Via;
    use crate::route::{RT_TABLE_MAIN, RTPROT_BGP};

    /// An unprivileged process may read the routing table: the snapshot
    /// lists the interfaces, `lo` among them, and only routes the filter
    /// keeps, none of them ours.
    #[test]
    fn snapshot_reads_the_real_table() {
        let mut m = Monitor::open(RTPROT_BGP).expect("subscribed socket");
        let s = m.snapshot().expect("snapshot");
        assert!(s.links.iter().any(|l| l.name == "lo"), "{:?}", s.links);
        assert!(s.links.is_sorted_by_key(|l| l.index));
        for r in &s.routes {
            assert!(kernel::relevant(r, RTPROT_BGP), "{r:?}");
            assert_eq!(r.table, RT_TABLE_MAIN);
        }
        assert!(s.routes.is_sorted_by_key(|r| (r.dst, r.metric)));
        // A second one on the same socket reads the same table, give or
        // take what changed in between, and a quiet host changes nothing.
        let again = m.snapshot().expect("second snapshot");
        assert_eq!(again.links.len(), s.links.len());
    }

    /// The replies to a request are told from notifications by their
    /// flags and type.
    #[test]
    fn replies_are_not_notifications() {
        let part = netlink::encode(RTM_NEWROUTE, netlink::NLM_F_MULTI, 3, &[0; 12]);
        let done = netlink::encode(netlink::NLMSG_DONE, netlink::NLM_F_MULTI, 3, &[0; 4]);
        let error = netlink::encode(netlink::NLMSG_ERROR, 0, 3, &[0; 20]);
        let note = netlink::encode(RTM_NEWROUTE, 0x600, 3, &[0; 12]);
        let one = |b: &[u8]| is_reply(&netlink::parse(b).unwrap()[0]);
        assert!(one(&part) && one(&done) && one(&error));
        assert!(!one(&note));
    }

    fn route(dst: &str, metric: u32) -> Route {
        Route {
            dst: dst.parse().unwrap(),
            table: RT_TABLE_MAIN,
            protocol: 4,
            kind: 1,
            tos: 0,
            flags: 0,
            metric,
            via: Via::Unicast {
                gateway: Some(IpAddr::from([10, 1, 0, 2])),
                oif: 2,
            },
        }
    }

    fn link(index: u32, up: bool) -> Link {
        Link {
            index,
            name: format!("if{index}"),
            up,
        }
    }

    /// The notifications of a snapshot apply in order over what the dumps
    /// listed: the last one for a route wins. An interface going down or
    /// away, or an address going, asks for the snapshot again.
    #[test]
    fn notifications_apply_over_the_dumps_in_order() {
        let mut d = Dumps::default();
        d.routes
            .insert((route("192.0.2.0/24", 5).dst, 5), route("192.0.2.0/24", 5));
        d.links.insert(2, link(2, true));
        let dst = route("198.51.100.0/24", 0).dst;
        d.events = vec![
            Event::Route(route("198.51.100.0/24", 0)),
            Event::RouteGone { dst, metric: 0 },
            Event::Route(route("198.51.100.0/24", 0)),
            Event::RouteGone {
                dst: route("192.0.2.0/24", 5).dst,
                metric: 5,
            },
            Event::Link(link(3, true)),
        ];
        assert!(!disturbed(&d));
        for e in std::mem::take(&mut d.events) {
            apply(&mut d, e);
        }
        assert_eq!(d.routes.len(), 1);
        assert!(d.routes.contains_key(&(dst, 0)));
        assert_eq!(d.links.len(), 2);
        for trigger in [
            Event::Link(link(2, false)),
            Event::LinkGone(2),
            Event::AddressGone(2),
        ] {
            d.events = vec![trigger.clone()];
            assert!(disturbed(&d), "{trigger:?}");
        }
        // Down to down is no change; up again neither.
        d.links.insert(4, link(4, false));
        d.events = vec![Event::Link(link(4, false)), Event::Link(link(4, true))];
        assert!(!disturbed(&d));
        // Up, then down, during the dumps: down from up.
        d.events = vec![Event::Link(link(4, true)), Event::Link(link(4, false))];
        assert!(disturbed(&d));
    }
}

/// The monitor in a network namespace of its own, where routes and
/// interfaces can be changed without touching the host's. Joining it needs
/// `CAP_SYS_ADMIN`, changing it `CAP_NET_ADMIN`. Run as root:
///
/// ```sh
/// sudo -E "$(command -v cargo)" test -p bgpfc-fib -- --ignored netns
/// ```
#[cfg(test)]
mod root_tests {
    use std::net::IpAddr;
    use std::path::Path;
    use std::process::{Child, Command, Stdio};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use bgpfc_sys::NetNs;

    use super::*;
    use crate::kernel::Via;
    use crate::route::{RT_TABLE_MAIN, RTPROT_BGP};
    use crate::{Change, Fib, Mode};

    /// `unshare --net sleep 30`, killed on drop: a process in a network
    /// namespace of its own with nothing but `lo` in it.
    struct Sleeper(Child);

    impl Sleeper {
        fn start() -> Sleeper {
            let child = Command::new("unshare")
                .args(["--net", "sleep", "30"])
                .stdin(Stdio::null())
                .spawn()
                .expect("unshare(1)");
            let sleeper = Sleeper(child);
            // unshare(1) moves itself, then executes sleep(1) in its place.
            let comm = format!("/proc/{}/comm", sleeper.0.id());
            let deadline = Instant::now() + Duration::from_secs(10);
            while std::fs::read_to_string(&comm).unwrap_or_default().trim() != "sleep" {
                assert!(Instant::now() < deadline, "unshare --net did not start");
                std::thread::sleep(Duration::from_millis(10));
            }
            sleeper
        }

        fn namespace(&self) -> NetNs {
            NetNs::open(Path::new(&format!("/proc/{}/ns/net", self.0.id()))).unwrap()
        }
    }

    impl Drop for Sleeper {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// `ip ARGS` in the calling thread's network namespace: a child starts
    /// in the namespace of the thread that spawns it.
    fn ip(args: &str) {
        let args: Vec<&str> = args.split_whitespace().collect();
        let status = Command::new("ip").args(&args).status().expect("ip(8)");
        assert!(status.success(), "ip {args:?}: {status}");
    }

    /// Run `test` on a thread in a namespace of its own, failing if it
    /// fails or takes longer than 20 s: the monitor blocks in `recv`.
    fn in_namespace(test: impl FnOnce() + Send + 'static) {
        let sleeper = Sleeper::start();
        let ns = sleeper.namespace();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            if let Err(e) = ns.enter() {
                let _ = tx.send(Err(e.to_string()));
                return;
            }
            test();
            let _ = tx.send(Ok(()));
        });
        match rx.recv_timeout(Duration::from_secs(20)) {
            Ok(Ok(())) => {}
            Ok(Err(e)) => panic!("joining the namespace: {e}"),
            Err(mpsc::RecvTimeoutError::Timeout) => panic!("timed out"),
            Err(mpsc::RecvTimeoutError::Disconnected) => panic!("the test thread failed"),
        }
    }

    /// The next event `want` accepts, skipping the others.
    fn wait_for(m: &mut Monitor, want: impl Fn(&Event) -> bool) -> Event {
        loop {
            if let Some(e) = m.next_events().unwrap().into_iter().find(|e| want(e)) {
                return e;
            }
        }
    }

    /// The index of interface `name`, from a snapshot: `/sys` shows the
    /// namespace that mounted it, not the thread's.
    fn index_of(name: &str) -> u32 {
        let mut m = Monitor::open(RTPROT_BGP).unwrap();
        let links = m.snapshot().unwrap().links;
        links.into_iter().find(|l| l.name == name).unwrap().index
    }

    /// A route added, removed, and an interface going down, as the
    /// monitor reports them; a snapshot after reads the table as it is.
    #[test]
    #[ignore = "needs CAP_SYS_ADMIN and CAP_NET_ADMIN: joins a network namespace and changes it"]
    fn netns_events_follow_route_changes() {
        in_namespace(|| {
            let mut monitor = Monitor::open(RTPROT_BGP).unwrap();
            let first = monitor.snapshot().unwrap();
            assert_eq!(first.routes, vec![], "a new namespace has no route");
            assert!(first.links.iter().any(|l| l.name == "lo"));
            ip("link add mo0 type veth peer name mo1");
            ip("addr add 10.1.0.1/24 dev mo0");
            ip("link set mo0 up");
            ip("link set mo1 up");
            ip("route add 192.0.2.0/24 via 10.1.0.2 metric 7");
            let dst: Prefix = "192.0.2.0/24".parse().unwrap();
            let oif = index_of("mo0");
            let added = wait_for(
                &mut monitor,
                |e| matches!(e, Event::Route(r) if r.dst == dst),
            );
            let Event::Route(route) = added else {
                unreachable!()
            };
            assert_eq!(route.metric, 7);
            assert_eq!(
                route.via,
                Via::Unicast {
                    gateway: Some(IpAddr::from([10, 1, 0, 2])),
                    oif
                }
            );
            // Ours is never reported.
            ip("route add 198.51.100.0/24 via 10.1.0.2 proto 186");
            ip("route del 192.0.2.0/24 via 10.1.0.2 metric 7");
            let mut seen = Vec::new();
            while !seen.contains(&Event::RouteGone { dst, metric: 7 }) {
                seen.extend(monitor.next_events().unwrap());
            }
            assert!(
                !seen
                    .iter()
                    .any(|e| matches!(e, Event::Route(r) if r.protocol == RTPROT_BGP)),
                "{seen:?}"
            );
            ip("link set mo0 down");
            let down = wait_for(
                &mut monitor,
                |e| matches!(e, Event::Link(l) if l.index == oif),
            );
            assert_eq!(
                down,
                Event::Link(Link {
                    index: oif,
                    name: "mo0".to_owned(),
                    up: false
                })
            );
            // IPv4 removed the connected route and 198.51.100.0/24, the
            // latter with no notification: a snapshot has neither.
            let after = monitor.snapshot().unwrap();
            assert_eq!(after.routes, vec![]);
            assert!(after.links.iter().any(|l| l.index == oif && !l.up));
        });
    }

    /// With a receive buffer too small for the notifications 2000 routes
    /// bring, the monitor reports `ENOBUFS`, and a snapshot afterwards
    /// reads the table as it is.
    #[test]
    #[ignore = "needs CAP_SYS_ADMIN and CAP_NET_ADMIN: joins a network namespace and changes it"]
    fn netns_lost_events_ask_for_a_resync() {
        in_namespace(|| {
            ip("link set lo up");
            ip("addr add 192.0.2.10/24 dev lo");
            // A route of someone else's, which the snapshots keep.
            ip("route add 198.51.100.0/24 via 192.0.2.1");
            let mut monitor = Monitor::open(RTPROT_BGP).unwrap();
            monitor.socket().set_receive_buffer(4096).unwrap();
            let before = monitor.snapshot().unwrap();
            let mut fib = Fib::new(Mode::Install, RT_TABLE_MAIN, RTPROT_BGP);
            fib.open().unwrap();
            let changes: Vec<Change> = (0..2000u16)
                .map(|i| {
                    let [a, b] = i.to_be_bytes();
                    Change {
                        prefix: Prefix::new(IpAddr::from([10, a, b, 0]), 24).unwrap(),
                        gateway: Some(IpAddr::from([192, 0, 2, 1])),
                        previous: None,
                    }
                })
                .collect();
            let mut out = Vec::new();
            fib.set_all(changes, &mut out);
            assert!(out.iter().all(|a| a.result.is_ok()));
            let lost = monitor.next_events().unwrap_err();
            assert!(
                matches!(&lost, FibError::Io(e) if e.raw_os_error() == Some(ENOBUFS)),
                "{lost:?}"
            );
            // Our routes are not in it; the rest is as before.
            let after = monitor.snapshot().unwrap();
            assert_eq!(after, before);
            let other: Prefix = "198.51.100.0/24".parse().unwrap();
            assert!(after.routes.iter().any(|r| r.dst == other), "{after:?}");
            assert!(fib.clear().iter().all(|a| a.result.is_ok()));
        });
    }
}
