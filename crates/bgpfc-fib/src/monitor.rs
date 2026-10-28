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
//! The routes go into a [`Mirror`]: the kernel may hold several routes
//! with one destination and metric, and a notification says where among
//! them its route went.
//!
//! What breaks that: the kernel drops notifications that do not fit the
//! socket's receive buffer and reports it once, as `ENOBUFS`
//! (`<asm-generic/errno.h>`, 105). The reader then takes a new snapshot.
//! Within a snapshot, the notifications read before the first reply of its
//! first dump are older than every dump, which reads the kernel as it is
//! later on, and are dropped: after an overflow, those left from before it
//! would otherwise be applied over newer dump entries.

use std::collections::BTreeMap;
use std::time::Duration;

use bgpfc_sys::NetlinkSocket;
use bgpfc_wire::types::Afi;

use crate::FibError;
use crate::kernel::{self, Event, Link};
use crate::mirror::{Mirror, Unclear};
use crate::netlink;
use crate::route::{RTM_NEWROUTE, RouteMsg};

/// `ENOBUFS`, `<asm-generic/errno.h>`: notifications were dropped.
pub const ENOBUFS: i32 = 105;

/// Room for a datagram: a dump reply takes at most 32 KiB (the kernel's
/// `netlink_dump`), a notification far less.
const BUF: usize = 64 << 10;

/// How many times a snapshot is taken in a row while something it cannot
/// follow happens during it (lost notifications, an interface going down
/// or away, an address going, a change of routes the copy cannot place);
/// the last is used as it is.
const TRIES: usize = 3;

/// The kernel's routes that [`kernel::relevant`] keeps, and its
/// interfaces.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    /// The routes, as the kernel holds them.
    pub mirror: Mirror,
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
    /// The family of the routes the dump under way asks for: a kernel
    /// without IPv6 (`ipv6.disable=1`) answers a dump of IPv6 routes with
    /// those of every family, IPv4's again (`rtnl_dump_all`).
    afi: Option<Afi>,
    mirror: Mirror,
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
    /// three times; so it is when a change of routes came that the copy
    /// cannot place ([`Unclear`]). The last is used as it is.
    ///
    /// # Errors
    /// The socket's, a dump the kernel refuses, or a malformed reply.
    pub fn snapshot(&mut self) -> Result<Snapshot, FibError> {
        let mut tries = 0;
        loop {
            tries += 1;
            let mut d = Dumps {
                mirror: Mirror::new(self.protocol),
                ..Dumps::default()
            };
            let links = self.next_seq();
            self.dump(&kernel::encode_link_dump(links), links, &mut d)?;
            for afi in [Afi::Ipv4, Afi::Ipv6] {
                let seq = self.next_seq();
                d.afi = Some(afi);
                self.dump(&RouteMsg::encode_dump(afi, seq), seq, &mut d)?;
            }
            d.mirror.listed_all();
            let mut again = d.lost || disturbed(&d);
            for e in std::mem::take(&mut d.events) {
                again |= apply(&mut d, &e).is_err();
            }
            if !again || tries == TRIES {
                return Ok(Snapshot {
                    mirror: d.mirror,
                    links: d.links.into_values().collect(),
                });
            }
        }
    }

    /// Wait until a notification, or an error such as `ENOBUFS`, is there
    /// to read with [`Monitor::next_events`] without blocking, or until
    /// `timeout` passes (`None`: no limit): whether one is.
    ///
    /// # Errors
    /// The socket's.
    pub fn wait(&self, timeout: Option<Duration>) -> Result<bool, FibError> {
        Ok(self.socket.wait(timeout)?)
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
                if d.take(&m, seq, self.protocol)? {
                    return Ok(());
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

impl Dumps {
    /// Take one message read while the dump `seq` runs: a part of it, its
    /// end (`true`), or a notification, kept once the dump has begun.
    ///
    /// # Errors
    /// A dump the kernel refuses, or ends with an error
    /// ([`netlink::parse_done`]): what came of it is not the whole table.
    /// A malformed message.
    fn take(&mut self, m: &netlink::Message<'_>, seq: u32, protocol: u8) -> Result<bool, FibError> {
        if m.header.seq == seq && m.header.ty == netlink::NLMSG_ERROR {
            match netlink::parse_error(m.payload)? {
                // The receive buffer was full when the dump was asked for:
                // the kernel answers ENOBUFS, if the answer fits, and sends
                // the dump as room frees up (`__netlink_dump_start`,
                // `netlink_recvmsg`).
                code if -code == ENOBUFS => self.lost = true,
                code => return Err(FibError::Kernel(-code)),
            }
        } else if m.header.seq == seq && is_reply(m) {
            self.started = true;
            match m.header.ty {
                netlink::NLMSG_DONE => {
                    return match netlink::parse_done(m.payload) {
                        code if code < 0 => Err(FibError::Kernel(-code)),
                        _ => Ok(true),
                    };
                }
                RTM_NEWROUTE => {
                    if let Some(r) = kernel::decode_route(m.payload)?
                        && Some(r.dst.afi()) == self.afi
                    {
                        self.mirror.listed(&r);
                    }
                }
                kernel::RTM_NEWLINK => {
                    if let Some(l) = kernel::decode_link(m.payload)? {
                        self.links.insert(l.index, l);
                    }
                }
                _ => {}
            }
        } else if self.started
            && !is_reply(m)
            && let Some(e) = kernel::event(m, protocol)?
        {
            self.events.push(e);
        }
        Ok(false)
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
        Event::Route { .. } | Event::RouteGone(_) | Event::Own { .. } => false,
    })
}

/// Apply a notification to what the dumps listed.
///
/// # Errors
/// [`Unclear`] when the copy cannot place a change of routes.
fn apply(d: &mut Dumps, e: &Event) -> Result<(), Unclear> {
    match e {
        Event::Route { .. } | Event::RouteGone(_) | Event::Own { .. } => {
            d.mirror.apply(e)?;
        }
        Event::Link(l) => {
            d.links.insert(l.index, l.clone());
        }
        Event::LinkGone(index) => {
            d.links.remove(index);
        }
        Event::AddressGone(_) => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;
    use crate::kernel::{NextHop, Route};
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
        let routes: Vec<_> = s.mirror.routes().collect();
        assert!(routes.iter().all(|(dst, _, _)| dst.prefix_len() > 0));
        assert!(routes.is_sorted_by_key(|(dst, metric, _)| (*dst, *metric)));
        assert!(routes.len() <= s.mirror.len());
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

    /// A kernel without IPv6 answers a dump of IPv6 routes with those of
    /// every family: the IPv4 routes it lists again are not listed twice.
    #[test]
    fn a_dump_keeps_the_family_it_asks_for() {
        let hop = crate::Hop {
            gateway: IpAddr::from([10, 1, 0, 2]),
            oif: Some(2),
            onlink: false,
        };
        let mut part =
            RouteMsg::unicast("192.0.2.0/24".parse().unwrap(), hop, RT_TABLE_MAIN, 4).encode_set(3);
        part[6..8].copy_from_slice(&netlink::NLM_F_MULTI.to_ne_bytes());
        let part = netlink::parse(&part).unwrap();
        let mut d = Dumps {
            afi: Some(Afi::Ipv4),
            mirror: Mirror::new(RTPROT_BGP),
            ..Dumps::default()
        };
        assert!(matches!(d.take(&part[0], 3, RTPROT_BGP), Ok(false)));
        d.afi = Some(Afi::Ipv6);
        assert!(matches!(d.take(&part[0], 3, RTPROT_BGP), Ok(false)));
        assert_eq!(d.mirror.len(), 1);
    }

    /// A dump ends with its `NLMSG_DONE`; one that carries an error, such
    /// as `ENOMEM` (12) from the kernel's dump of a table it could not
    /// finish, is no whole table and fails the snapshot, as a refused
    /// dump does.
    #[test]
    fn a_dump_that_ends_with_an_error_fails() {
        let done = |code: i32| {
            netlink::encode(
                netlink::NLMSG_DONE,
                netlink::NLM_F_MULTI,
                3,
                &code.to_ne_bytes(),
            )
        };
        let mut d = Dumps::default();
        let ok = done(0);
        let ok = netlink::parse(&ok).unwrap();
        assert!(matches!(d.take(&ok[0], 3, RTPROT_BGP), Ok(true)));
        assert!(d.started);
        let failed = done(-12);
        let failed = netlink::parse(&failed).unwrap();
        assert!(matches!(
            d.take(&failed[0], 3, RTPROT_BGP),
            Err(FibError::Kernel(12))
        ));
        // Another dump's end is not this one's.
        let other = done(0);
        let other = netlink::parse(&other).unwrap();
        assert!(matches!(d.take(&other[0], 4, RTPROT_BGP), Ok(false)));
        // ENOBUFS before the dump: notifications lost, the dump goes on.
        let mut nobufs = (-ENOBUFS).to_ne_bytes().to_vec();
        nobufs.extend_from_slice(&[0; 16]);
        let nobufs = netlink::encode(netlink::NLMSG_ERROR, 0, 3, &nobufs);
        let nobufs = netlink::parse(&nobufs).unwrap();
        assert!(matches!(d.take(&nobufs[0], 3, RTPROT_BGP), Ok(false)));
        assert!(d.lost);
    }

    fn route(dst: &str, metric: u32) -> Route {
        let next_hops = vec![NextHop {
            gateway: Some(IpAddr::from([10, 1, 0, 2])),
            oif: 2,
            flags: 0,
        }];
        Route {
            dst: dst.parse().unwrap(),
            table: RT_TABLE_MAIN,
            protocol: 4,
            kind: 1,
            tos: 0,
            flags: 0,
            metric,
            via: kernel::via_of(1, &next_hops),
            next_hops,
        }
    }

    /// `ip route add`: the kernel had no route with the destination and
    /// metric.
    const ADD: u16 = netlink::NLM_F_CREATE | netlink::NLM_F_EXCL;

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
        let mut d = Dumps {
            mirror: Mirror::new(RTPROT_BGP),
            ..Dumps::default()
        };
        d.mirror.listed(&route("192.0.2.0/24", 5));
        d.links.insert(2, link(2, true));
        let dst = route("198.51.100.0/24", 0).dst;
        let add = |r: Route| Event::Route {
            route: r,
            flags: ADD,
        };
        d.events = vec![
            add(route("198.51.100.0/24", 0)),
            Event::RouteGone(route("198.51.100.0/24", 0)),
            add(route("198.51.100.0/24", 0)),
            Event::RouteGone(route("192.0.2.0/24", 5)),
            Event::Link(link(3, true)),
        ];
        assert!(!disturbed(&d));
        for e in std::mem::take(&mut d.events) {
            assert_eq!(apply(&mut d, &e), Ok(()));
        }
        let keys: Vec<_> = d.mirror.routes().map(|(p, m, _)| (p, m)).collect();
        assert_eq!(keys, [(dst, 0)]);
        assert_eq!(d.links.len(), 2);
        // A removal of a route the dumps did not list cannot be placed.
        assert!(apply(&mut d, &Event::RouteGone(route("192.0.2.0/24", 5))).is_err());
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

/// The monitor, and the FIB beside it, in a network namespace of its own,
/// where routes and interfaces can be changed without touching the
/// host's. Joining it needs
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

    use bgpfc_wire::prefix::Prefix;

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
            assert!(first.mirror.is_empty(), "a new namespace has no route");
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
                |e| matches!(e, Event::Route { route: r, .. } if r.dst == dst),
            );
            let Event::Route { route, .. } = added else {
                unreachable!()
            };
            assert_eq!(route.metric, 7);
            assert_eq!(
                route.via,
                Via::Unicast {
                    gateway: Some(IpAddr::from([10, 1, 0, 2])),
                    oif,
                    onlink: false,
                }
            );
            // Ours only by destination and metric.
            ip("route add 198.51.100.0/24 via 10.1.0.2 proto 186");
            ip("route del 192.0.2.0/24 via 10.1.0.2 metric 7");
            let mut seen = Vec::new();
            while !seen
                .iter()
                .any(|e| matches!(e, Event::RouteGone(r) if r.dst == dst && r.metric == 7))
            {
                seen.extend(monitor.next_events().unwrap());
            }
            assert!(
                !seen.iter().any(
                    |e| matches!(e, Event::Route { route: r, .. } if r.protocol == RTPROT_BGP)
                ),
                "{seen:?}"
            );
            let ours: Prefix = "198.51.100.0/24".parse().unwrap();
            assert!(
                seen.iter()
                    .any(|e| matches!(e, Event::Own { dst, gone: false, .. } if *dst == ours)),
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
            assert!(after.mirror.is_empty(), "{after:?}");
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
                        hop: Some(crate::Hop {
                            gateway: IpAddr::from([192, 0, 2, 1]),
                            oif: None,
                            onlink: false,
                        }),
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
            assert!(
                after.mirror.routes().any(|(dst, _, _)| dst == other),
                "{after:?}"
            );
            assert!(fib.clear().iter().all(|a| a.result.is_ok()));
        });
    }

    /// The routes of the namespace's main table with `dst`, as `ip route`
    /// lists them.
    fn routes_to(dst: &str) -> String {
        let out = Command::new("ip")
            .args(["route", "show", dst])
            .output()
            .expect("ip(8)");
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// A static route with the destination and metric bgpfcd installs
    /// with stays: bgpfcd's is not installed, and says why; once the
    /// static route goes, it is, and a route of bgpfcd's whose hop
    /// changes replaces itself.
    #[test]
    #[ignore = "needs CAP_SYS_ADMIN and CAP_NET_ADMIN: joins a network namespace and changes it"]
    fn netns_routes_of_others_are_never_replaced() {
        in_namespace(|| {
            ip("link set lo up");
            ip("link add fo0 type veth peer name fo1");
            ip("addr add 10.1.0.1/24 dev fo0");
            ip("link set fo0 up");
            ip("link set fo1 up");
            ip("route add 192.0.2.40/30 via 10.1.0.2 proto static metric 20");
            let mut fib = Fib::new(Mode::Install, RT_TABLE_MAIN, RTPROT_BGP);
            fib.open().unwrap();
            let dst: Prefix = "192.0.2.40/30".parse().unwrap();
            let hop = |last| crate::Hop {
                gateway: IpAddr::from([10, 1, 0, last]),
                oif: None,
                onlink: false,
            };
            let set = |fib: &mut Fib, h, previous| {
                fib.set(Change {
                    prefix: dst,
                    hop: Some(h),
                    previous,
                })
                .unwrap()
            };
            let refused = set(&mut fib, hop(3), None);
            assert!(
                matches!(refused.result, Err(FibError::Occupied)),
                "{refused:?}"
            );
            assert!(fib.installed().is_empty());
            let listed = routes_to("192.0.2.40/30");
            assert!(
                listed.contains("via 10.1.0.2") && listed.contains("proto static"),
                "{listed}"
            );
            assert!(!listed.contains("proto bgp"), "{listed}");
            // The static route goes: bgpfcd's goes in, and then moves.
            ip("route del 192.0.2.40/30 via 10.1.0.2 proto static metric 20");
            assert!(set(&mut fib, hop(3), None).result.is_ok());
            assert!(set(&mut fib, hop(4), Some(hop(3))).result.is_ok());
            let listed = routes_to("192.0.2.40/30");
            assert_eq!(listed.lines().count(), 1, "{listed}");
            assert!(
                listed.contains("via 10.1.0.4") && listed.contains("proto bgp"),
                "{listed}"
            );
            assert!(fib.clear().iter().all(|a| a.result.is_ok()));
        });
    }

    /// Routes that share a destination and metric, as `ip route append`
    /// and `prepend` make them, one of them removed, and one of bgpfcd's
    /// put in place of the first: the copy kept from the notifications,
    /// with the flags the kernel really sends, is the copy a snapshot
    /// reads afterwards, and a change there once bgpfcd's sits among them
    /// cannot be placed.
    #[test]
    #[ignore = "needs CAP_SYS_ADMIN and CAP_NET_ADMIN: joins a network namespace and changes it"]
    fn netns_the_copy_follows_routes_that_share_a_destination() {
        in_namespace(|| {
            ip("link set lo up");
            ip("link add sh0 type veth peer name sh1");
            ip("addr add 10.1.0.1/24 dev sh0");
            ip("link set sh0 up");
            ip("link set sh1 up");
            let mut monitor = Monitor::open(RTPROT_BGP).unwrap();
            let mut copy = monitor.snapshot().unwrap().mirror;
            let key = ("10.255.0.30/32".parse::<Prefix>().unwrap(), 20);
            let at = |gateway: u8| {
                Some(Via::Unicast {
                    gateway: Some(IpAddr::from([10, 1, 0, gateway])),
                    oif: index_of("sh0"),
                    onlink: false,
                })
            };
            let follow = |copy: &mut Mirror, monitor: &mut Monitor, marker: &str| {
                ip(&format!("route add {marker} via 10.1.0.2"));
                let marker: Prefix = marker.parse().unwrap();
                let mut unclear = false;
                loop {
                    for e in monitor.next_events().unwrap() {
                        unclear |= copy.apply(&e).is_err();
                        if matches!(&e, Event::Route { route, .. } if route.dst == marker) {
                            return unclear;
                        }
                    }
                }
            };
            ip("route add 10.255.0.30/32 proto static metric 20 via 10.1.0.2");
            ip("route append 10.255.0.30/32 proto static metric 20 via 10.1.0.3");
            ip("route prepend 10.255.0.30/32 proto static metric 20 via 10.1.0.4");
            assert!(!follow(&mut copy, &mut monitor, "192.0.2.1/32"));
            assert_eq!(copy.via(&key), at(4));
            assert_eq!(copy.len(), 5, "three at the key, the network, the marker");
            // The prepended one goes: the first of the others is used.
            ip("route del 10.255.0.30/32 proto static metric 20 via 10.1.0.4");
            assert!(!follow(&mut copy, &mut monitor, "192.0.2.2/32"));
            assert_eq!(copy.via(&key), at(2));
            let read = monitor.snapshot().unwrap().mirror;
            assert_eq!(
                copy.routes().collect::<Vec<_>>(),
                read.routes().collect::<Vec<_>>()
            );
            assert_eq!(copy.len(), read.len());
            // bgpfcd's own in place of the first: that one is gone.
            ip("route replace 10.255.0.30/32 proto 186 metric 20 via 10.1.0.5");
            assert!(!follow(&mut copy, &mut monitor, "192.0.2.3/32"));
            assert_eq!(copy.via(&key), at(3));
            let read = monitor.snapshot().unwrap().mirror;
            assert_eq!(
                copy.routes().collect::<Vec<_>>(),
                read.routes().collect::<Vec<_>>()
            );
            // With bgpfcd's first there, another's replace there is
            // unclear: whose route it replaced, the kernel does not say.
            ip("route replace 10.255.0.30/32 proto static metric 20 via 10.1.0.6");
            assert!(follow(&mut copy, &mut monitor, "192.0.2.4/32"));
        });
    }
}
