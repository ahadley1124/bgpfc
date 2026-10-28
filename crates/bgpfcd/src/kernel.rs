//! The kernel thread: follows the kernel's routing table for the RIB's
//! resolution of next hops (RFC 4271 §9.1.2, §9.1.2.1; m15 design 2.1 to
//! 2.4, 3.8).
//!
//! It owns a netlink socket of its own, subscribed to the route,
//! interface and address groups (`bgpfc_fib::monitor::Monitor`), waits
//! on it, and hands the RIB thread what matters as [`RibMsg::Kernel`]:
//! the routes of the main table that are neither bgpfcd's own nor a
//! default route (`bgpfc_fib::kernel::relevant`), and interface names for
//! display. It gathers the notifications that come within [`GATHER`] of
//! the first and hands their net effect on together, so that a route
//! deleted and added again, as BIRD replaces an IPv6 route and an
//! operator does with `ip route del` and `ip route add`, moves nothing in
//! the RIB, the FIB or the neighbors. It never writes to the kernel, so it
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
//! (`ENOBUFS`), when an interface goes down or away or an IPv4 address is
//! removed: IPv4 then removes the routes through it without a
//! notification of their own; and when a change of routes cannot be
//! placed for sure, as where a route of bgpfcd's sits among others' at a
//! destination and metric. Such a read comes [`SETTLE`] after what asked
//! for it, and [`SPACING`] after the start of the read before at the
//! earliest, so that what else changes meanwhile, such as the rest of an
//! interface's going, is read with it, and interfaces that come and go
//! all the time cost a read a second at most; the changes that come
//! meanwhile go to the RIB as they come. A read that lost notifications
//! on the way, or met a change it could not place, is no whole table: the
//! RIB takes it, as it is nearer the kernel's than the copy it has, and
//! the thread reads again after a pause that doubles from [`RETRY_FIRST`]
//! to [`RETRY_MAX`] while that goes on. The RIB keeps its copy until a new
//! one arrives. Any other error of the socket closes it, and the thread
//! opens a new one and reads the table, after a pause that doubles up to
//! a minute while that fails.
//!
//! IPv4 removes bgpfcd's own routes through an interface that goes down,
//! or loses its address, without a notification, and the interface may be
//! back before the thread reads the table, which then changes nothing. So
//! after a whole read that such an event, lost notifications, a change it
//! could not place or a new socket asked for, the thread has the FIB check
//! its routes against the kernel's ([`RibMsg::VerifyFib`]), after the
//! RIB's changes of that table.
//!
//! # Logging
//!
//! `kernel: table read`, with the routes kept, the interfaces and why, and
//! `complete=no` for a read that is not the whole table: at info at
//! startup and after a new socket, at debug when read again for an
//! interface, an address, lost notifications, a change the copy could not
//! place, or a read before that was not whole. Lost notifications
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

/// How long the thread gathers notifications after the first of a batch
/// before it hands them on: a route deleted and then added again, as two
/// requests back to back, reaches the RIB as no change at all.
pub(crate) const GATHER: Duration = Duration::from_millis(10);

/// How long after what asks for a read of the whole table the thread
/// reads it: what else changes meanwhile, such as the rest of an
/// interface's going down, is read with it.
pub(crate) const SETTLE: Duration = Duration::from_millis(100);

/// The shortest time between the starts of two reads of the whole table:
/// each reads bgpfcd's own routes too, about half a second of the
/// thread's time per million, and interfaces that come and go several
/// times a second cost a read a second at most.
pub(crate) const SPACING: Duration = Duration::from_secs(1);

/// After a read that was not the whole table, the pause before the next,
/// doubled while reads keep not being whole, up to [`RETRY_MAX`]: a table
/// that loads into the kernel, bgpfcd's own among them, overflows the
/// socket until it is in.
pub(crate) const RETRY_FIRST: Duration = Duration::from_secs(1);

/// The longest pause between two reads that are not the whole table.
pub(crate) const RETRY_MAX: Duration = Duration::from_secs(60);

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
    /// An IPv4 address was removed from an interface.
    AddressRemoved,
    /// The socket failed and a new one was opened.
    Reopened,
    /// A change of routes that the copy cannot place for sure
    /// (`bgpfc_fib::mirror::Unclear`).
    Unclear,
    /// The read before was not the whole table.
    Incomplete,
}

impl Reason {
    /// Whether what it stands for may have removed routes of bgpfcd's from
    /// the kernel without a notification each, so that the FIB is to check
    /// them once the table is read whole: an interface down or gone, an
    /// address removed, notifications lost, a change that could not be
    /// placed, a new socket.
    pub(crate) const fn verifies(self) -> bool {
        !matches!(self, Reason::Startup | Reason::Incomplete)
    }

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
            Reason::Incomplete => "incomplete",
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
    /// The next read of the whole table.
    due: Due,
    /// Whether the FIB is to check its routes once the RIB has the table
    /// just read.
    verify_now: bool,
}

/// A read of the whole table to come.
#[derive(Debug, Default)]
pub(crate) struct Due {
    /// Why, the first reason since the read before, and when; `None`
    /// while no read is due.
    next: Option<(Reason, Instant)>,
    /// When the read before started.
    last: Option<Instant>,
    /// The pause before reading again after a read that was not the
    /// whole table; zero after one that was.
    retry: Duration,
    /// Whether the FIB is to check its routes once the table is read
    /// whole ([`Reason::verifies`]).
    verify: bool,
}

impl Due {
    /// A read for `reason`, asked at `now`: [`SETTLE`] later, and
    /// [`SPACING`] after the start of the read before at the earliest;
    /// sooner if one is due sooner already, with the reason it has.
    pub(crate) fn ask(&mut self, reason: Reason, now: Instant) {
        self.verify |= reason.verifies();
        let mut at = now + SETTLE;
        if let Some(last) = self.last {
            at = at.max(last + SPACING);
        }
        self.next = Some(match self.next {
            Some((first, due)) => (first, due.min(at)),
            None => (reason, at),
        });
    }

    /// When the next read is due.
    pub(crate) fn at(&self) -> Option<Instant> {
        self.next.map(|(_, at)| at)
    }

    /// The read due by `now`, if one is, which starts: its reason.
    pub(crate) fn start(&mut self, now: Instant) -> Option<Reason> {
        let (reason, at) = self.next?;
        if at > now {
            return None;
        }
        self.next = None;
        self.last = Some(now);
        Some(reason)
    }

    /// A read ended at `now`, the whole table or not: whether the FIB is
    /// to check its routes now, which waits for a whole read. After one
    /// that was not whole, another comes after a pause that doubles while
    /// they are not, from [`RETRY_FIRST`] to [`RETRY_MAX`], or sooner if
    /// asked for.
    pub(crate) fn ended(&mut self, whole: bool, now: Instant) -> bool {
        if whole {
            self.retry = Duration::ZERO;
            return std::mem::take(&mut self.verify);
        }
        self.retry = (self.retry * 2).clamp(RETRY_FIRST, RETRY_MAX);
        let at = now + self.retry;
        self.next = Some(match self.next {
            Some((first, due)) => (first, due.min(at)),
            None => (Reason::Incomplete, at),
        });
        false
    }
}

/// What the thread reads notifications from: the monitor's socket, and a
/// script of datagrams in the tests.
pub(crate) trait Source {
    /// Whether a datagram, or an error such as `ENOBUFS`, waits to be read,
    /// once one does or `timeout` has passed (`None`: no limit).
    fn wait(&self, timeout: Option<Duration>) -> Result<bool, FibError>;
    /// The notifications of the next datagram.
    fn next_events(&mut self) -> Result<Vec<Event>, FibError>;
}

impl Source for Monitor {
    fn wait(&self, timeout: Option<Duration>) -> Result<bool, FibError> {
        Monitor::wait(self, timeout)
    }

    fn next_events(&mut self) -> Result<Vec<Event>, FibError> {
        Monitor::next_events(self)
    }
}

/// The notifications of one batch, in the order they came, and whether
/// the kernel dropped some meanwhile (`ENOBUFS`).
#[derive(Debug, Default)]
pub(crate) struct Gathered {
    events: Vec<Event>,
    lost: bool,
}

/// The notifications on `source` that come within `window` of the first,
/// which is waited for until `until` has passed (`None`: no limit): none
/// if it has not come by then. The thread gathers for [`GATHER`].
///
/// # Errors
/// The source's, but `ENOBUFS`, which the batch notes as lost.
pub(crate) fn gather(
    source: &mut impl Source,
    until: Option<Duration>,
    window: Duration,
) -> Result<Gathered, FibError> {
    let mut batch = Gathered::default();
    if !source.wait(until)? {
        return Ok(batch);
    }
    let first = Instant::now();
    loop {
        match source.next_events() {
            Ok(events) => batch.events.extend(events),
            // Notifications dropped; the next ones are read on.
            Err(FibError::Io(e)) if e.raw_os_error() == Some(ENOBUFS) => batch.lost = true,
            Err(e) => return Err(e),
        }
        let Some(left) = window
            .checked_sub(first.elapsed())
            .filter(|left| !left.is_zero())
        else {
            break;
        };
        if !source.wait(Some(left))? {
            break;
        }
    }
    Ok(batch)
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
    let mut tracker = Tracker {
        monitor: Monitor::open(protocol)?,
        protocol,
        links: Links::new(),
        mirror: Mirror::new(protocol),
        due: Due::default(),
        verify_now: false,
    };
    let update = tracker.read(Reason::Startup)?;
    Ok((tracker, update))
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
        let update = if let Some(reason) = t.due.start(Instant::now()) {
            bgpfc_log::debug!("kernel: reading the table again", reason = reason.as_str());
            t.read(reason)
        } else {
            // Until the next read of the table is due, if one is.
            let until = t
                .due
                .at()
                .map(|at| at.saturating_duration_since(Instant::now()));
            match gather(&mut t.monitor, until, GATHER) {
                Ok(batch) => {
                    if batch.lost {
                        if let Some(times) = lost.note(Instant::now()) {
                            bgpfc_log::warn!(LOST, times = times);
                        }
                        t.due.ask(Reason::LostEvents, Instant::now());
                    }
                    let (changes, reason) = classify(batch.events, &mut t.links, &mut t.mirror);
                    if let Some(reason) = reason {
                        t.due.ask(reason, Instant::now());
                    }
                    // A read of the whole table to come makes them moot,
                    // but the RIB is nearer the kernel with them meanwhile.
                    if changes.is_empty() {
                        continue;
                    }
                    Ok(KernelUpdate::Changes(changes))
                }
                Err(e) => Err(e),
            }
        };
        let update = update.unwrap_or_else(|e| {
            bgpfc_log::error!("kernel: route monitor failed", error = e);
            t.reopen()
        });
        if rib.send(RibMsg::Kernel(update)).is_err() {
            return;
        }
        // Once the RIB has acted on the table, which may change no route
        // even though the kernel lost some of bgpfcd's, as when an
        // interface went down and came back up before the read.
        if std::mem::take(&mut t.verify_now) && rib.send(RibMsg::VerifyFib).is_err() {
            return;
        }
    }
}

impl Tracker {
    /// Read the whole table on the socket, for `reason`; one that is not
    /// whole asks for another, and a whole one says whether the FIB is to
    /// check its routes ([`Due::ended`]).
    fn read(&mut self, reason: Reason) -> Result<KernelUpdate, FibError> {
        let snapshot = self.monitor.snapshot()?;
        let complete = snapshot.complete;
        let (update, links, mirror) = table(snapshot);
        self.links = links;
        self.mirror = mirror;
        self.verify_now = self.due.ended(complete, Instant::now());
        let line = table_line(&update, reason, complete);
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
                    // What the old socket missed may have removed routes.
                    self.due.verify = true;
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

/// What a batch of notifications means for the RIB's copy: for
/// each destination and metric whose routes they touched, the route the
/// kernel uses there now, or its absence, when that differs from before
/// them, so that a route removed and added again in one batch changes
/// nothing; and a reason to read the whole table again, which makes the
/// changes moot. Keeps `links` and `mirror` up to date.
///
/// The table is read again when an interface that was up goes down, when
/// one goes away, and when an IPv4 address is removed: IPv4 then removes the
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

/// The line of a table read for `reason`, `complete` or not: at info at
/// startup and after a new socket, at debug otherwise.
fn table_line(update: &KernelUpdate, reason: Reason, complete: bool) -> Line {
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
            | Reason::Unclear
            | Reason::Incomplete => Level::Debug,
        },
        msg: TABLE_READ,
        fields: [
            ("routes", routes.to_string()),
            ("links", links.to_string()),
            ("reason", reason.as_str().to_owned()),
        ]
        .into_iter()
        .chain((!complete).then(|| ("complete", "no".to_owned())))
        .collect(),
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

    use std::collections::VecDeque;
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
            complete: true,
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
        let line = table_line(&update, Reason::Startup, true);
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
        assert_eq!(
            table_line(&update, Reason::Reopened, true).level,
            Level::Info
        );
        for reason in [
            Reason::LostEvents,
            Reason::LinkDown,
            Reason::LinkGone,
            Reason::AddressRemoved,
            Reason::Unclear,
            Reason::Incomplete,
        ] {
            let line = table_line(&update, reason, true);
            assert_eq!(line.level, Level::Debug);
            assert_eq!(line.fields[2], ("reason", reason.as_str().to_owned()));
        }
        // A read that is not the whole table says so.
        let line = table_line(&update, Reason::LostEvents, false);
        assert_eq!(line.fields[3], ("complete", "no".to_owned()));
    }

    /// Datagrams a test hands the thread, one a read, as the socket would.
    struct Script(VecDeque<Result<Vec<Event>, FibError>>);

    impl Source for Script {
        fn wait(&self, _: Option<Duration>) -> Result<bool, FibError> {
            Ok(!self.0.is_empty())
        }

        fn next_events(&mut self) -> Result<Vec<Event>, FibError> {
            self.0.pop_front().expect("a datagram waits")
        }
    }

    fn enobufs() -> FibError {
        FibError::Io(std::io::Error::from_raw_os_error(ENOBUFS))
    }

    /// A route deleted and added again, as BIRD replaces an IPv6 route,
    /// comes as two datagrams. Gathered together they change nothing; one
    /// at a time, as each read used to hand them on, they took the route
    /// away and then back, and with it every route through the next hops
    /// it resolves.
    #[test]
    fn a_route_deleted_and_added_again_together_moves_nothing() {
        let r = route("192.0.2.128/25", 5, Some("10.1.0.2"));
        let datagrams = || {
            Script(VecDeque::from([
                Ok(vec![Event::RouteGone(r.clone())]),
                Ok(vec![added(r.clone(), ADD)]),
            ]))
        };
        let with_route = || {
            let (mut links, mut mirror) = (Links::new(), Mirror::new(RTPROT_BGP));
            classify(vec![added(r.clone(), ADD)], &mut links, &mut mirror);
            (links, mirror)
        };
        let (mut links, mut mirror) = with_route();
        let mut source = datagrams();
        let batch = gather(&mut source, None, Duration::from_secs(3600)).unwrap();
        assert!(source.0.is_empty() && !batch.lost);
        assert_eq!(batch.events.len(), 2);
        let (changes, reason) = classify(batch.events, &mut links, &mut mirror);
        assert_eq!((changes, reason), (vec![], None));
        // One datagram a batch: gone, then back.
        let (mut links, mut mirror) = with_route();
        let mut source = datagrams();
        let mut each = Vec::new();
        while !source.0.is_empty() {
            let batch = gather(&mut source, None, Duration::ZERO).unwrap();
            each.push(classify(batch.events, &mut links, &mut mirror).0);
        }
        assert_eq!(
            each,
            [
                vec![KernelChange::Gone {
                    prefix: p("192.0.2.128/25"),
                    metric: 5
                }],
                vec![KernelChange::Route(rib_route(
                    "192.0.2.128/25",
                    5,
                    Some("10.1.0.2")
                ))],
            ]
        );
    }

    /// Nothing by the time given: an empty batch. Lost notifications are
    /// noted and the next datagrams read on; any other error ends the
    /// batch.
    #[test]
    fn a_batch_notes_lost_notifications_and_fails_on_other_errors() {
        let mut none = Script(VecDeque::new());
        let batch = gather(&mut none, Some(Duration::ZERO), GATHER).unwrap();
        assert!(batch.events.is_empty() && !batch.lost);
        let r = route("192.0.2.128/25", 5, Some("10.1.0.2"));
        let mut lost = Script(VecDeque::from([
            Err(enobufs()),
            Ok(vec![added(r.clone(), ADD)]),
        ]));
        let batch = gather(&mut lost, None, Duration::from_secs(3600)).unwrap();
        assert!(batch.lost);
        assert_eq!(batch.events, [added(r, ADD)]);
        let mut failed = Script(VecDeque::from([Err(FibError::Kernel(22))]));
        assert!(matches!(
            gather(&mut failed, None, GATHER),
            Err(FibError::Kernel(22))
        ));
    }

    /// A read of the whole table comes a settling pause after what asks
    /// for it, a second after the start of the one before at the
    /// earliest, and once for all that ask meanwhile, with the first
    /// reason.
    #[test]
    fn reads_of_the_table_are_settled_and_spaced() {
        let t0 = Instant::now();
        let ms = Duration::from_millis;
        let mut due = Due::default();
        assert_eq!(due.at(), None);
        assert_eq!(due.start(t0), None);
        due.ask(Reason::LinkDown, t0);
        due.ask(Reason::AddressRemoved, t0 + ms(50));
        assert_eq!(due.at(), Some(t0 + SETTLE));
        assert_eq!(due.start(t0 + ms(99)), None);
        assert_eq!(due.start(t0 + SETTLE), Some(Reason::LinkDown));
        assert_eq!(due.at(), None);
        // The next, asked at once, waits for a second after that start.
        due.ask(Reason::LinkGone, t0 + ms(500));
        assert_eq!(due.at(), Some(t0 + SETTLE + SPACING));
        assert_eq!(due.start(t0 + SETTLE + SPACING), Some(Reason::LinkGone));
        // Long after the last, the settling pause alone.
        let later = t0 + ms(5000);
        due.ask(Reason::LostEvents, later);
        assert_eq!(due.start(later + SETTLE), Some(Reason::LostEvents));
    }

    /// A read that is not the whole table asks for another, after a pause
    /// that doubles while they are not, up to a minute, and never gives up;
    /// a whole one ends that. Something that asks sooner is held back by
    /// the spacing alone, and its reason gives way to the first.
    #[test]
    fn reads_that_are_not_whole_are_read_again() {
        let t0 = Instant::now();
        let mut due = Due::default();
        due.ended(true, t0);
        assert_eq!(due.at(), None, "a whole read asks for no other");
        let mut now = t0;
        let mut pauses = Vec::new();
        for _ in 0..9 {
            due.ended(false, now);
            let at = due.at().unwrap();
            pauses.push((at - now).as_secs());
            assert_eq!(due.start(at), Some(Reason::Incomplete));
            now = at;
        }
        assert_eq!(pauses, [1, 2, 4, 8, 16, 32, 60, 60, 60]);
        due.ended(false, now);
        due.ask(Reason::AddressRemoved, now);
        assert_eq!(due.at(), Some(now + SPACING));
        assert_eq!(due.start(now + SPACING), Some(Reason::Incomplete));
        // A whole read: the next that is not starts the pauses over.
        due.ended(true, now + SPACING);
        assert_eq!(due.at(), None);
        due.ended(false, now + SPACING);
        assert_eq!(due.at(), Some(now + SPACING + RETRY_FIRST));
    }

    /// The FIB checks its routes after a whole read that something which
    /// may remove routes silently asked for: not after the startup read,
    /// not after one that is not whole, which waits for the next, and once
    /// for all that asked.
    #[test]
    fn the_fib_checks_its_routes_after_a_whole_read() {
        let t0 = Instant::now();
        let mut due = Due::default();
        assert!(!due.ended(true, t0), "startup");
        due.ask(Reason::LinkDown, t0);
        due.ask(Reason::AddressRemoved, t0);
        assert_eq!(due.start(t0 + SETTLE), Some(Reason::LinkDown));
        assert!(!due.ended(false, t0 + SETTLE));
        let retry = due.at().unwrap();
        assert_eq!(due.start(retry), Some(Reason::Incomplete));
        assert!(due.ended(true, retry));
        // Asked for once, checked once.
        let later = retry + SPACING;
        due.ask(Reason::Unclear, later);
        assert_eq!(due.start(later + SETTLE), Some(Reason::Unclear));
        assert!(due.ended(true, later + SETTLE));
        assert!(!due.ended(true, later + SETTLE));
        for reason in [
            Reason::LostEvents,
            Reason::LinkDown,
            Reason::LinkGone,
            Reason::AddressRemoved,
            Reason::Unclear,
            Reason::Reopened,
        ] {
            assert!(reason.verifies(), "{reason:?}");
        }
        assert!(!Reason::Startup.verifies() && !Reason::Incomplete.verifies());
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
