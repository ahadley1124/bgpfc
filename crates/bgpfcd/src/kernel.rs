//! The kernel thread: follows the kernel's routing table for the RIB's
//! resolution of next hops (RFC 4271 §9.1.2, §9.1.2.1; m15 design 2.1 to
//! 2.4, 3.8).
//!
//! It owns a netlink socket of its own, subscribed to the route,
//! interface and address groups (`bgpfc_fib::monitor::Monitor`), blocks
//! in `recv`, and hands the RIB thread what matters as
//! [`RibMsg::Kernel`]: the routes of the main table that are neither
//! bgpfcd's own nor a default route (`bgpfc_fib::kernel::relevant`), and
//! interface names for display. It never writes to the kernel, so it
//! works the same in dry-run and install mode. It resolves nothing
//! itself: the set of next hops in use changes with every UPDATE, and
//! only the RIB thread knows it.
//!
//! `main` takes the first table before the RIB thread exists and before
//! any peer starts ([`open`]), and gives it to the RIB, so that no route
//! is ever judged against no table; then it starts the thread on the same
//! socket ([`spawn`]), where the notifications since that table wait.
//!
//! The thread keeps the routes as the kernel holds them
//! (`bgpfc_fib::mirror::Mirror`), several at a destination and metric
//! where the kernel has several, and hands the RIB, for each destination
//! and metric a batch of notifications touched, the route the kernel uses
//! there, if it changed: the RIB keeps one a destination and metric.
//!
//! The thread reads the whole table again, and hands it on whole
//! ([`KernelUpdate::Table`]), when the kernel dropped notifications
//! (`ENOBUFS`), when an interface goes down or away or an address is
//! removed: IPv4 then removes the routes through it without a
//! notification of their own; and when a change of routes cannot be
//! placed for sure, as where a route of bgpfcd's sits among others' at a
//! destination and metric. The RIB keeps its copy until the new one
//! arrives whole. Any other error of the socket closes it, and the thread
//! opens a new one and reads the table, after a pause that doubles up to
//! a minute while that fails.
//!
//! # Logging
//!
//! `kernel: table read`, with the routes kept, the interfaces and why: at
//! info at startup and after a new socket, at debug when read again for
//! an interface, an address or lost notifications. Lost notifications
//! have a line at warn of their own, the first at once and then at most
//! one a minute, which counts those since the line before.

use std::collections::{BTreeMap, HashMap};
use std::sync::mpsc::SyncSender;
use std::thread;
use std::time::{Duration, Instant};

use bgpfc_fib::FibError;
use bgpfc_fib::kernel::{self, Event};
use bgpfc_fib::mirror::{Key, Mirror};
use bgpfc_fib::monitor::{ENOBUFS, Monitor, Snapshot};
use bgpfc_log::Level;
use bgpfc_rib::nexthop::{KernelChange, KernelRoute, KernelUpdate, Via};
use bgpfc_wire::prefix::Prefix;

use crate::messages::RibMsg;
use crate::rib::{Line, log_line};

/// The message of the line written when the thread has read the table.
const TABLE_READ: &str = "kernel: table read";

/// The message of the line written when the kernel dropped
/// notifications.
const LOST: &str = "kernel: route events lost, reading the table again";

/// The shortest time between two [`LOST`] lines. A table that loads into
/// the kernel faster than the thread reads, such as bgpfcd's own when it
/// installs a full table, can overflow the socket again and again; each
/// costs a read of the table, not a line.
const LOST_FOLD: Duration = Duration::from_secs(60);

/// The first pause before opening a new socket after an error, doubled
/// after each failure up to [`REOPEN_MAX`].
const REOPEN_FIRST: Duration = Duration::from_secs(1);

/// The longest pause between two attempts to open a new socket.
const REOPEN_MAX: Duration = Duration::from_secs(60);

/// Why the thread reads the whole table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reason {
    /// Before the RIB thread starts.
    Startup,
    /// The kernel dropped notifications (`ENOBUFS`).
    LostEvents,
    /// An interface that was up went down.
    LinkDown,
    /// An interface went away.
    LinkGone,
    /// An address was removed from an interface.
    AddressRemoved,
    /// The socket failed and a new one was opened.
    Reopened,
    /// A change of routes that the copy cannot place for sure
    /// (`bgpfc_fib::mirror::Unclear`).
    Unclear,
}

impl Reason {
    /// The name the log lines use.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Reason::Startup => "startup",
            Reason::LostEvents => "lost-events",
            Reason::LinkDown => "link-down",
            Reason::LinkGone => "link-gone",
            Reason::AddressRemoved => "address-removed",
            Reason::Reopened => "reopened",
            Reason::Unclear => "unclear",
        }
    }
}

/// What the thread knows of each interface, by index: its name and
/// whether it is up, from the last table and the notifications since.
pub(crate) type Links = HashMap<u32, (String, bool)>;

/// The socket that follows the kernel's table, with what the thread
/// keeps of the interfaces.
#[derive(Debug)]
pub(crate) struct Tracker {
    monitor: Monitor,
    /// The protocol number of bgpfcd's own routes, which are never kept.
    protocol: u8,
    links: Links,
    /// The routes, as the kernel holds them.
    mirror: Mirror,
}

/// Open the socket and read the kernel's table: what `main` gives the
/// RIB before any route arrives (m15 design 3.8), and the socket the
/// thread then follows the table on. Called before the privilege drop:
/// with `CAP_NET_ADMIN` the socket's receive buffer may exceed
/// `net.core.rmem_max` (`bgpfc_fib::monitor::Monitor::open`).
///
/// # Errors
/// The socket's, or a dump the kernel refuses.
pub(crate) fn open(protocol: u8) -> Result<(Tracker, KernelUpdate), FibError> {
    let mut monitor = Monitor::open(protocol)?;
    let snapshot = monitor.snapshot()?;
    let (update, links, mirror) = table(snapshot);
    let line = table_line(&update, Reason::Startup);
    log_line(line.level, line.msg, &line.fields);
    Ok((
        Tracker {
            monitor,
            protocol,
            links,
            mirror,
        },
        update,
    ))
}

/// Start the thread on `tracker`, handing what changes to the RIB
/// thread on `rib`; it ends when the RIB thread is gone.
pub(crate) fn spawn(tracker: Tracker, rib: SyncSender<RibMsg>) {
    thread::Builder::new()
        .name("kernel".to_owned())
        .spawn(move || run(tracker, &rib))
        .expect("spawning the kernel thread");
}

fn run(mut t: Tracker, rib: &SyncSender<RibMsg>) {
    let mut lost = Lost::default();
    loop {
        let update = match t.monitor.next_events() {
            Ok(events) => match classify(events, &mut t.links, &mut t.mirror) {
                (_, Some(reason)) => {
                    bgpfc_log::debug!("kernel: reading the table again", reason = reason.as_str());
                    t.read(reason)
                }
                (changes, None) if changes.is_empty() => continue,
                (changes, None) => Ok(KernelUpdate::Changes(changes)),
            },
            Err(FibError::Io(e)) if e.raw_os_error() == Some(ENOBUFS) => {
                if let Some(times) = lost.note(Instant::now()) {
                    bgpfc_log::warn!(LOST, times = times);
                }
                t.read(Reason::LostEvents)
            }
            Err(e) => Err(e),
        };
        let update = update.unwrap_or_else(|e| {
            bgpfc_log::error!("kernel: route monitor failed", error = e);
            t.reopen()
        });
        if rib.send(RibMsg::Kernel(update)).is_err() {
            return;
        }
    }
}

impl Tracker {
    /// Read the whole table again on the socket, for `reason`.
    fn read(&mut self, reason: Reason) -> Result<KernelUpdate, FibError> {
        let snapshot = self.monitor.snapshot()?;
        let (update, links, mirror) = table(snapshot);
        self.links = links;
        self.mirror = mirror;
        let line = table_line(&update, reason);
        log_line(line.level, line.msg, &line.fields);
        Ok(update)
    }

    /// Open a new socket and read the table, after a pause that doubles
    /// while that fails; the RIB keeps its copy meanwhile.
    fn reopen(&mut self) -> KernelUpdate {
        let mut pause = REOPEN_FIRST;
        loop {
            thread::sleep(pause);
            pause = (pause * 2).min(REOPEN_MAX);
            match Monitor::open(self.protocol) {
                Ok(monitor) => {
                    self.monitor = monitor;
                    match self.read(Reason::Reopened) {
                        Ok(update) => return update,
                        Err(e) => bgpfc_log::error!("kernel: cannot read the table", error = e),
                    }
                }
                Err(e) => bgpfc_log::error!("kernel: cannot open the route monitor", error = e),
            }
        }
    }
}

/// A table as the RIB takes it, what the thread keeps of its interfaces,
/// and the routes as the kernel holds them: the RIB takes the one the
/// kernel uses at each destination and metric.
fn table(snapshot: Snapshot) -> (KernelUpdate, Links, Mirror) {
    let links = snapshot
        .links
        .iter()
        .map(|l| (l.index, (l.name.clone(), l.up)))
        .collect();
    let update = KernelUpdate::Table {
        routes: snapshot
            .mirror
            .routes()
            .map(|(prefix, metric, via)| kernel_route(prefix, metric, via))
            .collect(),
        links: snapshot
            .links
            .into_iter()
            .map(|l| (l.index, l.name))
            .collect(),
    };
    (update, links, snapshot.mirror)
}

/// A kernel route as the RIB takes it (`bgpfc-fib` and `bgpfc-rib` are
/// siblings, AGENTS.md §2, so their types meet here).
pub(crate) fn kernel_route(prefix: Prefix, metric: u32, via: kernel::Via) -> KernelRoute {
    KernelRoute {
        prefix,
        metric,
        via: match via {
            kernel::Via::Unicast {
                gateway,
                oif,
                onlink,
            } => Via::Unicast {
                gateway,
                oif,
                onlink,
            },
            kernel::Via::Unreachable => Via::Unreachable,
        },
    }
}

/// What one datagram of notifications means for the RIB's copy: for
/// each destination and metric whose routes they touched, the route the
/// kernel uses there now, or its absence, when that differs from before
/// them, so that a route removed and added again in one batch changes
/// nothing; and a reason to read the whole table again, which makes the
/// changes moot. Keeps `links` and `mirror` up to date.
///
/// The table is read again when an interface that was up goes down, when
/// one goes away, and when an address is removed: IPv4 then removes the
/// routes through it without a notification of their own; and when a
/// change of routes cannot be placed for sure ([`Reason::Unclear`]). An
/// interface coming up, a change of carrier and an address added need
/// nothing: the kernel notifies the routes they add. An interface not
/// seen before counts as down, as a new one starts. A name the thread did
/// not know yet goes to the RIB, for display.
pub(crate) fn classify(
    events: Vec<Event>,
    links: &mut Links,
    mirror: &mut Mirror,
) -> (Vec<KernelChange>, Option<Reason>) {
    let mut changes = Vec::new();
    let mut reason = None;
    // What the kernel used at each destination and metric the batch
    // touched, before it.
    let mut before: BTreeMap<Key, Option<kernel::Via>> = BTreeMap::new();
    for e in events {
        match &e {
            Event::Route { .. } | Event::RouteGone(_) | Event::Own { .. } => {
                let Some(key) = e.key() else { continue };
                // bgpfcd's own routes, alone at their destination and
                // metric, are most of what comes while it installs a
                // table: nothing to note of them.
                if matches!(e, Event::Own { .. }) && !mirror.has(&key) {
                    continue;
                }
                before.entry(key).or_insert_with(|| mirror.via(&key));
                if mirror.apply(&e).is_err() {
                    reason.get_or_insert(Reason::Unclear);
                }
            }
            Event::Link(l) => {
                let was = links.insert(l.index, (l.name.clone(), l.up));
                if was.as_ref().is_some_and(|(_, up)| *up) && !l.up {
                    reason.get_or_insert(Reason::LinkDown);
                }
                if was.is_none_or(|(name, _)| *name != l.name) {
                    changes.push(KernelChange::Link {
                        index: l.index,
                        name: l.name.clone(),
                    });
                }
            }
            Event::LinkGone(index) => {
                links.remove(index);
                changes.push(KernelChange::LinkGone(*index));
                reason.get_or_insert(Reason::LinkGone);
            }
            Event::AddressGone(_) => {
                reason.get_or_insert(Reason::AddressRemoved);
            }
        }
    }
    for ((prefix, metric), was) in before {
        match mirror.via(&(prefix, metric)) {
            now if now == was => {}
            Some(via) => changes.push(KernelChange::Route(kernel_route(prefix, metric, via))),
            None => changes.push(KernelChange::Gone { prefix, metric }),
        }
    }
    (changes, reason)
}

/// The line of a table read for `reason`: at info at startup and after a
/// new socket, at debug otherwise.
fn table_line(update: &KernelUpdate, reason: Reason) -> Line {
    let (routes, links) = match update {
        KernelUpdate::Table { routes, links } => (routes.len(), links.len()),
        KernelUpdate::Changes(_) => (0, 0),
    };
    Line {
        level: match reason {
            Reason::Startup | Reason::Reopened => Level::Info,
            Reason::LostEvents
            | Reason::LinkDown
            | Reason::LinkGone
            | Reason::AddressRemoved
            | Reason::Unclear => Level::Debug,
        },
        msg: TABLE_READ,
        fields: vec![
            ("routes", routes.to_string()),
            ("links", links.to_string()),
            ("reason", reason.as_str().to_owned()),
        ],
    }
}

/// The fold of the [`LOST`] lines.
#[derive(Debug, Default)]
struct Lost {
    /// When the last line was written.
    last: Option<Instant>,
    /// Losses not on a line yet.
    unlogged: u64,
}

impl Lost {
    /// Count a loss at `now`; when a line is due, the first and then once
    /// [`LOST_FOLD`] has passed since the line before, the losses it
    /// counts: this one and those since that line.
    fn note(&mut self, now: Instant) -> Option<u64> {
        self.unlogged += 1;
        if self
            .last
            .is_some_and(|last| now.saturating_duration_since(last) < LOST_FOLD)
        {
            return None;
        }
        self.last = Some(now);
        Some(std::mem::take(&mut self.unlogged))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::IpAddr;

    use bgpfc_fib::kernel::{Link, NextHop, Route};
    use bgpfc_fib::netlink::{NLM_F_APPEND, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REPLACE};
    use bgpfc_fib::route::{RT_TABLE_MAIN, RTPROT_BGP};

    /// `ip route add`: no route had the destination and metric.
    const ADD: u16 = NLM_F_CREATE | NLM_F_EXCL;

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// A static route to `dst` at `metric` through `gateway` on interface
    /// 2, or on that interface alone.
    fn route(dst: &str, metric: u32, gateway: Option<&str>) -> Route {
        let next_hops = vec![NextHop {
            gateway: gateway.map(ip),
            oif: 2,
            flags: 0,
        }];
        Route {
            dst: p(dst),
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

    fn added(r: Route, flags: u16) -> Event {
        Event::Route { route: r, flags }
    }

    /// What the RIB takes of a route through `gateway` on interface 2.
    fn rib_route(dst: &str, metric: u32, gateway: Option<&str>) -> KernelRoute {
        KernelRoute {
            prefix: p(dst),
            metric,
            via: Via::Unicast {
                gateway: gateway.map(ip),
                oif: 2,
                onlink: false,
            },
        }
    }

    fn link(index: u32, name: &str, up: bool) -> Event {
        Event::Link(Link {
            index,
            name: name.to_owned(),
            up,
        })
    }

    /// The kernel's route becomes the RIB's: destination, metric and
    /// where it goes, with or without a gateway, `onlink` or not, or
    /// nowhere.
    #[test]
    fn kernel_routes_convert_to_the_ribs() {
        let via = kernel::Via::Unicast {
            gateway: Some(ip("10.1.0.2")),
            oif: 2,
            onlink: true,
        };
        assert_eq!(
            kernel_route(p("192.0.2.128/25"), 5, via),
            KernelRoute {
                prefix: p("192.0.2.128/25"),
                metric: 5,
                via: Via::Unicast {
                    gateway: Some(ip("10.1.0.2")),
                    oif: 2,
                    onlink: true,
                },
            }
        );
        assert_eq!(
            kernel_route(p("203.0.113.0/24"), 0, kernel::Via::Unreachable).via,
            Via::Unreachable
        );
    }

    /// A snapshot is a whole table for the RIB, the route the kernel uses
    /// at each destination and metric, its interfaces named, and the
    /// thread knows which are up and keeps the routes as the kernel does.
    #[test]
    fn a_snapshot_is_a_table() {
        let mut mirror = Mirror::new(RTPROT_BGP);
        mirror.listed(&route("10.1.0.0/24", 0, None));
        mirror.listed(&route("192.0.2.0/24", 20, Some("10.1.0.2")));
        mirror.listed(&route("192.0.2.0/24", 20, Some("10.1.0.3")));
        let snapshot = Snapshot {
            mirror,
            links: vec![
                Link {
                    index: 1,
                    name: "lo".to_owned(),
                    up: true,
                },
                Link {
                    index: 2,
                    name: "ar".to_owned(),
                    up: false,
                },
            ],
        };
        let (update, links, mirror) = table(snapshot);
        assert_eq!(
            update,
            KernelUpdate::Table {
                routes: vec![
                    rib_route("10.1.0.0/24", 0, None),
                    rib_route("192.0.2.0/24", 20, Some("10.1.0.2")),
                ],
                links: vec![(1, "lo".to_owned()), (2, "ar".to_owned())],
            }
        );
        assert_eq!(links.get(&1), Some(&("lo".to_owned(), true)));
        assert_eq!(links.get(&2), Some(&("ar".to_owned(), false)));
        assert_eq!(mirror.len(), 3);
    }

    /// Routes become changes of the route the kernel uses at each
    /// destination and metric; an interface going from up to down asks
    /// for the table once, one already down asks nothing, and so does one
    /// coming up; an interface going away or an address removed asks for
    /// it too (IPv4 removes routes through them silently). Names reach
    /// the RIB when new.
    #[test]
    fn events_become_changes_or_a_resync() {
        let mut links = Links::new();
        links.insert(2, ("ar".to_owned(), true));
        links.insert(3, ("br".to_owned(), false));
        let mut mirror = Mirror::new(RTPROT_BGP);
        // A route added and gone in one batch is no change at all; a known
        // interface that stays as it was is nothing either.
        let (changes, reason) = classify(
            vec![
                added(route("192.0.2.128/25", 5, Some("10.1.0.2")), ADD),
                link(2, "ar", true),
                Event::RouteGone(route("192.0.2.128/25", 5, Some("10.1.0.2"))),
                added(route("198.51.100.0/24", 0, Some("10.1.0.2")), ADD),
            ],
            &mut links,
            &mut mirror,
        );
        assert_eq!(reason, None);
        assert_eq!(
            changes,
            vec![KernelChange::Route(rib_route(
                "198.51.100.0/24",
                0,
                Some("10.1.0.2")
            ))]
        );
        // Gone, then the same again: no change. Gone alone: gone.
        let r = route("198.51.100.0/24", 0, Some("10.1.0.2"));
        let (changes, _) = classify(
            vec![Event::RouteGone(r.clone()), added(r.clone(), ADD)],
            &mut links,
            &mut mirror,
        );
        assert_eq!(changes, vec![]);
        let (changes, _) = classify(vec![Event::RouteGone(r)], &mut links, &mut mirror);
        assert_eq!(
            changes,
            vec![KernelChange::Gone {
                prefix: p("198.51.100.0/24"),
                metric: 0
            }]
        );
        // Down to down, and down to up: nothing to read again.
        let (changes, reason) = classify(vec![link(3, "br", false)], &mut links, &mut mirror);
        assert_eq!((changes, reason), (vec![], None));
        let (changes, reason) = classify(vec![link(3, "br", true)], &mut links, &mut mirror);
        assert_eq!((changes, reason), (vec![], None));
        assert_eq!(links.get(&3), Some(&("br".to_owned(), true)));
        // Up to down, twice in one datagram: one read.
        let (_, reason) = classify(
            vec![link(2, "ar", false), link(3, "br", false)],
            &mut links,
            &mut mirror,
        );
        assert_eq!(reason, Some(Reason::LinkDown));
        // And down again is nothing.
        let (_, reason) = classify(vec![link(2, "ar", false)], &mut links, &mut mirror);
        assert_eq!(reason, None);
        // A new interface, down as it starts, and a renamed one: names
        // only.
        let (changes, reason) = classify(
            vec![link(4, "cr", false), link(3, "br0", false)],
            &mut links,
            &mut mirror,
        );
        assert_eq!(reason, None);
        assert_eq!(
            changes,
            vec![
                KernelChange::Link {
                    index: 4,
                    name: "cr".to_owned()
                },
                KernelChange::Link {
                    index: 3,
                    name: "br0".to_owned()
                },
            ]
        );
        // An address removed, an interface gone.
        let (_, reason) = classify(vec![Event::AddressGone(2)], &mut links, &mut mirror);
        assert_eq!(reason, Some(Reason::AddressRemoved));
        let (changes, reason) = classify(vec![Event::LinkGone(4)], &mut links, &mut mirror);
        assert_eq!(reason, Some(Reason::LinkGone));
        assert_eq!(changes, vec![KernelChange::LinkGone(4)]);
        assert!(!links.contains_key(&4));
        // The first reason of a datagram is the one given.
        let (_, reason) = classify(
            vec![Event::AddressGone(2), Event::LinkGone(3)],
            &mut links,
            &mut mirror,
        );
        assert_eq!(reason, Some(Reason::AddressRemoved));
    }

    /// Two routes at one destination and metric (`ip route append`), and
    /// one of them deleted: the other is what the RIB has there. A route
    /// of bgpfcd's put in place of the first (`NLM_F_REPLACE`) takes it
    /// away: the RIB's copy no longer resolves through it. A change the
    /// copy cannot place asks for the table.
    #[test]
    fn routes_at_one_destination_and_metric_follow_the_kernel() {
        let mut links = Links::new();
        let mut mirror = Mirror::new(RTPROT_BGP);
        let first = route("10.255.0.30/32", 20, Some("10.9.0.2"));
        let second = route("10.255.0.30/32", 20, Some("10.9.0.3"));
        let (changes, _) = classify(
            vec![
                added(first.clone(), ADD),
                added(second.clone(), NLM_F_CREATE | NLM_F_APPEND),
            ],
            &mut links,
            &mut mirror,
        );
        let through = |g| {
            vec![KernelChange::Route(rib_route(
                "10.255.0.30/32",
                20,
                Some(g),
            ))]
        };
        assert_eq!(changes, through("10.9.0.2"));
        let (changes, reason) = classify(vec![Event::RouteGone(first)], &mut links, &mut mirror);
        assert_eq!((changes, reason), (through("10.9.0.3"), None));
        let ours = |flags, gone| Event::Own {
            dst: p("10.255.0.30/32"),
            metric: 20,
            flags,
            gone,
        };
        let (changes, reason) = classify(vec![ours(NLM_F_REPLACE, false)], &mut links, &mut mirror);
        assert_eq!(reason, None);
        assert_eq!(
            changes,
            vec![KernelChange::Gone {
                prefix: p("10.255.0.30/32"),
                metric: 20
            }]
        );
        // Ours alone at its destination: nothing.
        let (changes, reason) = classify(vec![ours(0, true)], &mut links, &mut mirror);
        assert_eq!((changes, reason), (vec![], None));
        // Another's route put in place of a route the copy lacks, ours:
        // unclear.
        let (_, reason) = classify(vec![added(second, NLM_F_REPLACE)], &mut links, &mut mirror);
        assert_eq!(reason, Some(Reason::Unclear));
    }

    /// The line of a table read: at info at startup and after a new
    /// socket, at debug for the reads a change asks for.
    #[test]
    fn table_reads_are_logged_with_their_reason() {
        let update = KernelUpdate::Table {
            routes: vec![KernelRoute {
                prefix: p("10.1.0.0/24"),
                metric: 0,
                via: Via::Unreachable,
            }],
            links: vec![(1, "lo".to_owned())],
        };
        let line = table_line(&update, Reason::Startup);
        assert_eq!(
            line,
            Line {
                level: Level::Info,
                msg: TABLE_READ,
                fields: vec![
                    ("routes", "1".to_owned()),
                    ("links", "1".to_owned()),
                    ("reason", "startup".to_owned()),
                ],
            }
        );
        assert_eq!(table_line(&update, Reason::Reopened).level, Level::Info);
        for reason in [
            Reason::LostEvents,
            Reason::LinkDown,
            Reason::LinkGone,
            Reason::AddressRemoved,
        ] {
            let line = table_line(&update, reason);
            assert_eq!(line.level, Level::Debug);
            assert_eq!(line.fields[2], ("reason", reason.as_str().to_owned()));
        }
    }

    /// Lost notifications: a line at once, then at most one a minute,
    /// counting those since the line before.
    #[test]
    fn lost_events_are_folded_to_a_line_a_minute() {
        let t0 = Instant::now();
        let mut lost = Lost::default();
        assert_eq!(lost.note(t0), Some(1));
        assert_eq!(lost.note(t0 + Duration::from_secs(1)), None);
        assert_eq!(lost.note(t0 + Duration::from_secs(59)), None);
        assert_eq!(lost.note(t0 + Duration::from_secs(60)), Some(3));
        assert_eq!(lost.note(t0 + Duration::from_secs(61)), None);
        assert_eq!(lost.note(t0 + Duration::from_secs(200)), Some(2));
    }

    /// The thread's socket reads the real table, as an unprivileged
    /// process may, never keeping a route of bgpfcd's protocol.
    #[test]
    fn open_reads_the_real_table() {
        let (tracker, update) = open(RTPROT_BGP).expect("the kernel's table");
        let KernelUpdate::Table { links, .. } = &update else {
            panic!("{update:?}");
        };
        assert!(links.iter().any(|(_, name)| name == "lo"), "{links:?}");
        assert!(tracker.links.values().any(|(name, _)| name == "lo"));
    }
}
