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
//! The thread reads the whole table again, and hands it on whole
//! ([`KernelUpdate::Table`]), when the kernel dropped notifications
//! (`ENOBUFS`), and when an interface goes down or away or an address is
//! removed: IPv4 then removes the routes through it without a
//! notification of their own. The RIB keeps its copy until the new one
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

use std::collections::HashMap;
use std::sync::mpsc::SyncSender;
use std::thread;
use std::time::{Duration, Instant};

use bgpfc_fib::FibError;
use bgpfc_fib::kernel::{self, Event};
use bgpfc_fib::monitor::{ENOBUFS, Monitor, Snapshot};
use bgpfc_log::Level;
use bgpfc_rib::nexthop::{KernelChange, KernelRoute, KernelUpdate, Via};

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
    let (update, links) = table(snapshot);
    let line = table_line(&update, Reason::Startup);
    log_line(line.level, line.msg, &line.fields);
    Ok((
        Tracker {
            monitor,
            protocol,
            links,
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
            Ok(events) => match classify(events, &mut t.links) {
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
        let (update, links) = table(snapshot);
        self.links = links;
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

/// A table as the RIB takes it, and what the thread keeps of its
/// interfaces.
fn table(snapshot: Snapshot) -> (KernelUpdate, Links) {
    let links = snapshot
        .links
        .iter()
        .map(|l| (l.index, (l.name.clone(), l.up)))
        .collect();
    let update = KernelUpdate::Table {
        routes: snapshot.routes.iter().map(kernel_route).collect(),
        links: snapshot
            .links
            .into_iter()
            .map(|l| (l.index, l.name))
            .collect(),
    };
    (update, links)
}

/// A kernel route as the RIB takes it (`bgpfc-fib` and `bgpfc-rib` are
/// siblings, AGENTS.md §2, so their types meet here).
pub(crate) fn kernel_route(r: &kernel::Route) -> KernelRoute {
    KernelRoute {
        prefix: r.dst,
        metric: r.metric,
        via: match r.via {
            kernel::Via::Unicast { gateway, oif } => Via::Unicast { gateway, oif },
            kernel::Via::Unreachable => Via::Unreachable,
        },
    }
}

/// What one datagram of notifications means for the RIB's copy: the
/// changes, in the order the kernel made them, or a reason to read the
/// whole table again, which makes the changes moot. Keeps `links` up to
/// date.
///
/// The table is read again when an interface that was up goes down, when
/// one goes away, and when an address is removed: IPv4 then removes the
/// routes through it without a notification of their own. An interface
/// coming up, a change of carrier and an address added need nothing: the
/// kernel notifies the routes they add. An interface not seen before
/// counts as down, as a new one starts. A name the thread did not know
/// yet goes to the RIB, for display.
pub(crate) fn classify(
    events: Vec<Event>,
    links: &mut Links,
) -> (Vec<KernelChange>, Option<Reason>) {
    let mut changes = Vec::new();
    let mut reason = None;
    for e in events {
        match e {
            Event::Route(r) => changes.push(KernelChange::Route(kernel_route(&r))),
            Event::RouteGone { dst, metric } => changes.push(KernelChange::Gone {
                prefix: dst,
                metric,
            }),
            Event::Link(l) => {
                let was = links.insert(l.index, (l.name.clone(), l.up));
                if was.as_ref().is_some_and(|(_, up)| *up) && !l.up {
                    reason.get_or_insert(Reason::LinkDown);
                }
                if was.is_none_or(|(name, _)| name != l.name) {
                    changes.push(KernelChange::Link {
                        index: l.index,
                        name: l.name,
                    });
                }
            }
            Event::LinkGone(index) => {
                links.remove(&index);
                changes.push(KernelChange::LinkGone(index));
                reason.get_or_insert(Reason::LinkGone);
            }
            Event::AddressGone(_) => {
                reason.get_or_insert(Reason::AddressRemoved);
            }
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
            Reason::LostEvents | Reason::LinkDown | Reason::LinkGone | Reason::AddressRemoved => {
                Level::Debug
            }
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

    use bgpfc_fib::kernel::{Link, Route};
    use bgpfc_fib::route::{RT_TABLE_MAIN, RTPROT_BGP};
    use bgpfc_wire::prefix::Prefix;

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn route(dst: &str, metric: u32, via: kernel::Via) -> Route {
        Route {
            dst: p(dst),
            table: RT_TABLE_MAIN,
            protocol: 4,
            kind: 1,
            tos: 0,
            flags: 0,
            metric,
            via,
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
    /// where it goes, with or without a gateway, or nowhere.
    #[test]
    fn kernel_routes_convert_to_the_ribs() {
        let via = kernel::Via::Unicast {
            gateway: Some(ip("10.1.0.2")),
            oif: 2,
        };
        assert_eq!(
            kernel_route(&route("192.0.2.128/25", 5, via)),
            KernelRoute {
                prefix: p("192.0.2.128/25"),
                metric: 5,
                via: Via::Unicast {
                    gateway: Some(ip("10.1.0.2")),
                    oif: 2,
                },
            }
        );
        let dev = kernel::Via::Unicast {
            gateway: None,
            oif: 3,
        };
        assert_eq!(
            kernel_route(&route("2001:db8::/64", 256, dev)).via,
            Via::Unicast {
                gateway: None,
                oif: 3
            }
        );
        assert_eq!(
            kernel_route(&route("203.0.113.0/24", 0, kernel::Via::Unreachable)).via,
            Via::Unreachable
        );
    }

    /// A snapshot is a whole table for the RIB, its interfaces named, and
    /// the thread knows which are up.
    #[test]
    fn a_snapshot_is_a_table() {
        let via = kernel::Via::Unicast {
            gateway: None,
            oif: 2,
        };
        let snapshot = Snapshot {
            routes: vec![route("10.1.0.0/24", 0, via)],
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
        let (update, links) = table(snapshot);
        assert_eq!(
            update,
            KernelUpdate::Table {
                routes: vec![KernelRoute {
                    prefix: p("10.1.0.0/24"),
                    metric: 0,
                    via: Via::Unicast {
                        gateway: None,
                        oif: 2
                    },
                }],
                links: vec![(1, "lo".to_owned()), (2, "ar".to_owned())],
            }
        );
        assert_eq!(links.get(&1), Some(&("lo".to_owned(), true)));
        assert_eq!(links.get(&2), Some(&("ar".to_owned(), false)));
    }

    /// Routes become changes in the kernel's order; an interface going
    /// from up to down asks for the table once, one already down asks
    /// nothing, and so does one coming up; an interface going away or an
    /// address removed asks for it too (IPv4 removes routes through them
    /// silently). Names reach the RIB when new.
    #[test]
    fn events_become_changes_or_a_resync() {
        let mut links = Links::new();
        links.insert(2, ("ar".to_owned(), true));
        links.insert(3, ("br".to_owned(), false));
        let gw = kernel::Via::Unicast {
            gateway: Some(ip("10.1.0.2")),
            oif: 2,
        };
        // Routes, in order; a known interface that stays as it was is
        // nothing.
        let (changes, reason) = classify(
            vec![
                Event::Route(route("192.0.2.128/25", 5, gw)),
                link(2, "ar", true),
                Event::RouteGone {
                    dst: p("192.0.2.128/25"),
                    metric: 5,
                },
                Event::Route(route("198.51.100.0/24", 0, kernel::Via::Unreachable)),
            ],
            &mut links,
        );
        assert_eq!(reason, None);
        assert_eq!(
            changes,
            vec![
                KernelChange::Route(KernelRoute {
                    prefix: p("192.0.2.128/25"),
                    metric: 5,
                    via: Via::Unicast {
                        gateway: Some(ip("10.1.0.2")),
                        oif: 2
                    },
                }),
                KernelChange::Gone {
                    prefix: p("192.0.2.128/25"),
                    metric: 5
                },
                KernelChange::Route(KernelRoute {
                    prefix: p("198.51.100.0/24"),
                    metric: 0,
                    via: Via::Unreachable,
                }),
            ]
        );
        // Down to down, and down to up: nothing to read again.
        let (changes, reason) = classify(vec![link(3, "br", false)], &mut links);
        assert_eq!((changes, reason), (vec![], None));
        let (changes, reason) = classify(vec![link(3, "br", true)], &mut links);
        assert_eq!((changes, reason), (vec![], None));
        assert_eq!(links.get(&3), Some(&("br".to_owned(), true)));
        // Up to down, twice in one datagram: one read.
        let (_, reason) = classify(vec![link(2, "ar", false), link(3, "br", false)], &mut links);
        assert_eq!(reason, Some(Reason::LinkDown));
        // And down again is nothing.
        let (_, reason) = classify(vec![link(2, "ar", false)], &mut links);
        assert_eq!(reason, None);
        // A new interface, down as it starts, and a renamed one: names
        // only.
        let (changes, reason) = classify(
            vec![link(4, "cr", false), link(3, "br0", false)],
            &mut links,
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
        let (_, reason) = classify(vec![Event::AddressGone(2)], &mut links);
        assert_eq!(reason, Some(Reason::AddressRemoved));
        let (changes, reason) = classify(vec![Event::LinkGone(4)], &mut links);
        assert_eq!(reason, Some(Reason::LinkGone));
        assert_eq!(changes, vec![KernelChange::LinkGone(4)]);
        assert!(!links.contains_key(&4));
        // The first reason of a datagram is the one given.
        let (_, reason) = classify(vec![Event::AddressGone(2), Event::LinkGone(3)], &mut links);
        assert_eq!(reason, Some(Reason::AddressRemoved));
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
