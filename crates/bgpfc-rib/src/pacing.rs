//! Pacing of advertisements: the `MinRouteAdvertisementIntervalTimer`
//! (MRAI), kept per peer and destination.
//!
//! Implements: RFC 4271 §9.2.1.1 (a minimum interval between two
//! advertisements of a destination to a peer; the last route selected
//! goes out when the interval ends; a shorter interval for internal
//! peers), §10 (the 30 s and 5 s suggested defaults, jitter in
//! [0.75, 1.0]).
//!
//! The RIB stores no Adj-RIB-Out: what a peer has is what export makes of
//! the Loc-RIB, every change of which is sent as it happens, except for
//! the destinations pacing holds back, for which `Held` keeps what the
//! peer has meanwhile. So the time of each advertisement is kept only
//! while it can still hold one back, for an interval: one `Pacing` per
//! peer and family has
//!
//! - the second the whole Adj-RIB-Out was last sent at once (the initial
//!   one, a route refresh), which stands for every destination the peer
//!   has and has heard of no later;
//! - the destinations advertised one by one in the seconds of the last
//!   interval, a sorted list per second (an IPv4 destination is five
//!   octets there), so that sending a table to a peer costs it a few
//!   megabytes for an interval and nothing after;
//! - the destinations withdrawn less than an interval after they were last
//!   advertised, with when that was, so that a route flapping through
//!   withdrawals is still paced;
//! - the destinations held back, until when, and what the peer has.
//!
//! It never reads the clock: callers pass the time in. Wake-ups go through
//! one deadline queue owned by [`crate::Rib`], so there is no timer or
//! thread per destination. A second queue there sweeps each `Pacing`
//! when what it remembers expires: the second being filled is sorted once
//! it has passed, and what can no longer hold anything back is forgotten,
//! so that a peer that hears nothing more does not keep it.
//!
//! Memory follows the destinations, not the churn (AGENTS.md §3). Each
//! destination has at most one wake-up queued, however often it changes,
//! and a held destination stays held when its route changes back, so its
//! interval is drawn once. The destinations that may wait at once, held
//! back or remembered after a withdrawal, are bounded by the most routes
//! the Adj-RIB-Out ever held, or 1024 if that is more, and the
//! advertisements remembered by twice that: past the bound, a change goes
//! out at once and a withdrawal or an advertisement is not remembered, so
//! that a peer cannot grow the RIB by announcing and withdrawing ever new
//! destinations within its prefix limit.
//!
//! Time is counted in whole seconds (`Tick`) since the first instant the
//! RIB was given. Advertisement times round up and the current time rounds
//! down, so an interval is never shortened; it can grow by up to two
//! seconds, a constant bound that RFC 4271 §9.2.1.1 accepts ("any
//! technique that ensures that the interval ... will be at least
//! `MinRouteAdvertisementIntervalTimer`, and will also ensure that a
//! constant upper bound on the interval is acceptable"). Whole seconds
//! also make destinations held back at about the same time leave
//! together, packed into as few UPDATEs as the message size allows.

use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hash;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bgpfc_wire::prefix::{Ipv4Key, Prefix};
use bgpfc_wire::update::PeerKind;

use crate::attrs::PathAttrs;

/// RFC 4271 §10: "The suggested default value for the
/// `MinRouteAdvertisementIntervalTimer` on EBGP connections is 30 seconds."
pub const EBGP_DEFAULT_INTERVAL: Duration = Duration::from_secs(30);

/// RFC 4271 §10: "The suggested default value for the
/// `MinRouteAdvertisementIntervalTimer` on IBGP connections is 5 seconds."
/// Shorter than the external one, as RFC 4271 §9.2.1.1 (a) asks.
pub const IBGP_DEFAULT_INTERVAL: Duration = Duration::from_secs(5);

/// The RFC 4271 §10 default interval for a session of `kind`.
#[must_use]
pub const fn default_interval(kind: PeerKind) -> Duration {
    match kind {
        PeerKind::External => EBGP_DEFAULT_INTERVAL,
        PeerKind::Internal => IBGP_DEFAULT_INTERVAL,
    }
}

/// Whole seconds since the RIB's epoch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Tick(u32);

impl Tick {
    /// `secs` seconds later.
    fn after(self, secs: u32) -> Tick {
        Tick(self.0.saturating_add(secs))
    }
}

/// The current time as pacing sees it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Now {
    /// The last whole second at or before the instant: what has
    /// certainly passed.
    pub(crate) floor: Tick,
    /// The first whole second at or after it: when an advertisement made
    /// now is recorded as made.
    pub(crate) ceil: Tick,
}

/// Turns instants into [`Tick`]s and back.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Clock {
    epoch: Instant,
}

impl Clock {
    /// A clock whose tick zero is `epoch`.
    pub(crate) const fn new(epoch: Instant) -> Clock {
        Clock { epoch }
    }

    /// `t` in ticks. An instant before the epoch counts as the epoch,
    /// which only makes intervals longer.
    pub(crate) fn now(&self, t: Instant) -> Now {
        let d = t.saturating_duration_since(self.epoch);
        let floor = u32::try_from(d.as_secs()).unwrap_or(u32::MAX);
        let ceil = if d.subsec_nanos() == 0 {
            floor
        } else {
            floor.saturating_add(1)
        };
        Now {
            floor: Tick(floor),
            ceil: Tick(ceil),
        }
    }

    /// The instant `tick` starts, if the platform can represent it.
    pub(crate) fn instant(&self, tick: Tick) -> Option<Instant> {
        self.epoch
            .checked_add(Duration::from_secs(u64::from(tick.0)))
    }
}

/// `d` in whole seconds, rounded up.
fn secs_ceil(d: Duration) -> u32 {
    let s = d.as_secs() + u64::from(d.subsec_nanos() != 0);
    u32::try_from(s).unwrap_or(u32::MAX)
}

/// RFC 4271 §10 jitter: a uniformly distributed factor in [0.75, 1.0],
/// freshly drawn each time a timer is set. A tiny xorshift generator
/// keeps the RIB pure and deterministic for a given seed; seed zero
/// disables jitter so that tests see exact intervals. (The FSM has the
/// same generator; the RIB does not depend on the FSM crate.)
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Jitter {
    state: u64,
}

impl Jitter {
    /// Seed zero means "no jitter".
    pub(crate) const fn new(seed: u64) -> Jitter {
        Jitter { state: seed }
    }

    /// Scale `base` by a fresh factor in [0.75, 1.0].
    pub(crate) fn apply(&mut self, base: Duration) -> Duration {
        if self.state == 0 {
            return base;
        }
        // xorshift64*; quality is irrelevant here, only spread.
        self.state ^= self.state >> 12;
        self.state ^= self.state << 25;
        self.state ^= self.state >> 27;
        let r = self.state.wrapping_mul(0x2545_f491_4f6c_dd1d);
        // Factor = 0.75 + 0.25 * (r / 2^64), in nanoseconds without
        // floating point: base * 3/4 + base/4 * fraction.
        let nanos = base.as_nanos();
        let quarter = nanos / 4;
        let fraction = u128::from(r >> 32);
        let extra = quarter * fraction / (1u128 << 32);
        let total = nanos - quarter + extra;
        Duration::from_nanos(u64::try_from(total).unwrap_or(u64::MAX))
    }
}

/// The pacing parameters of one peer at one moment.
pub(crate) struct Pace<'a> {
    /// The peer's interval; zero sends every change at once.
    pub(crate) interval: Duration,
    /// The current time.
    pub(crate) now: Now,
    /// The jitter source.
    pub(crate) jitter: &'a mut Jitter,
}

/// Whether a destination the peer is to be told about goes now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Offer {
    /// Advertise it now.
    Now,
    /// Hold it back until the tick: the caller holds it ([`Pacing::hold`])
    /// and schedules a wake-up then, and whatever the route is at that
    /// time goes out.
    Hold(Tick),
}

/// A destination held back, and what the peer has for it meanwhile: the
/// route it was last sent, or none.
#[derive(Clone, Debug)]
pub(crate) struct Held {
    /// When its interval ends.
    pub(crate) due: Tick,
    /// What the peer has.
    pub(crate) has: Option<Arc<PathAttrs>>,
    /// The peer has paths of the destination (RFC 7911) instead, which the
    /// RIB keeps itself; `has` is then empty.
    pub(crate) paths: bool,
}

impl Held {
    /// Whether the peer has anything for the destination meanwhile.
    pub(crate) fn had(&self) -> bool {
        self.has.is_some() || self.paths
    }
}

/// What a wake-up for one destination found.
#[derive(Debug, Default)]
pub(crate) struct Wake {
    /// The destination's interval ended: it is no longer held, and its
    /// route now goes out if it is not what the peer has.
    pub(crate) released: Option<Held>,
    /// Wake up again then: woken before the interval ended.
    pub(crate) again: Option<Tick>,
}

/// However few routes an Adj-RIB-Out has held, this many of its
/// destinations may wait at once (see the module documentation).
pub(crate) const MIN_WAITING: usize = 1024;

/// The destinations advertised one by one in one second, sorted.
#[derive(Debug)]
struct Second {
    at: Tick,
    v4: Box<[Ipv4Key]>,
    v6: Box<[Prefix]>,
}

/// One peer's RFC 4271 §9.2.1.1 state for one family (see the module
/// documentation).
#[derive(Debug, Default)]
pub(crate) struct Pacing {
    /// When the whole Adj-RIB-Out was last sent at once.
    bulk: Option<Tick>,
    /// The second being filled with advertisements, and what it has.
    open: Option<Tick>,
    open_v4: HashSet<Ipv4Key>,
    open_v6: HashSet<Prefix>,
    /// The seconds before, oldest first.
    seconds: VecDeque<Second>,
    /// Advertisements in `seconds` and the open second.
    logged: usize,
    /// Withdrawn destinations whose last advertisement is younger than an
    /// interval, with when that was.
    withdrawn: HashMap<Prefix, Tick>,
    /// The destinations held back.
    held: HashMap<Prefix, Held>,
    /// The one wake-up queued for each destination that has one: a queue
    /// entry for another tick is stale and ignored. Covers every
    /// destination in `held`.
    wakeups: HashMap<Prefix, Tick>,
    /// The most routes the Adj-RIB-Out has held.
    peak: usize,
    /// The longest interval the peer has had, in seconds: how long an
    /// advertisement is remembered.
    keep: u32,
    /// The sweep queued, if any ([`Self::queue_sweep`]).
    sweep: Option<Tick>,
}

impl Pacing {
    /// The Adj-RIB-Out now holds `routes` routes.
    pub(crate) fn note_routes(&mut self, routes: usize) {
        self.peak = self.peak.max(routes);
    }

    /// Whether `prefix` is held back, and what the peer has meanwhile.
    pub(crate) fn held(&self, prefix: Prefix) -> Option<&Held> {
        if self.held.is_empty() {
            return None;
        }
        self.held.get(&prefix)
    }

    /// The destinations held back, with what the peer has for each.
    pub(crate) fn all_held(&self) -> impl Iterator<Item = (Prefix, &Held)> {
        self.held.iter().map(|(p, h)| (*p, h))
    }

    /// What the destinations held back left the peer with, as the peer
    /// goes.
    pub(crate) fn into_held(self) -> impl Iterator<Item = Held> {
        self.held.into_values()
    }

    /// How many destinations are held back.
    #[cfg(test)]
    pub(crate) fn held_count(&self) -> usize {
        self.held.len()
    }

    /// How many destinations pacing remembers beyond the Adj-RIB-Out:
    /// held back, remembered after a withdrawal, or with a wake-up queued,
    /// and the advertisements of the last interval.
    #[cfg(test)]
    pub(crate) fn remembered(&self) -> usize {
        self.held.len() + self.withdrawn.len() + self.wakeups.len() + self.logged
    }

    /// Heap octets this has room for, roughly (a hash table entry costs
    /// its size and a control octet), for profiling reports.
    #[cfg(feature = "profiling")]
    pub(crate) fn heap_bytes(&self) -> usize {
        use std::mem::size_of;
        fn map<K, V>(m: &HashMap<K, V>) -> usize {
            m.capacity() * (size_of::<(K, V)>() + 1)
        }
        fn set<K>(s: &HashSet<K>) -> usize {
            s.capacity() * (size_of::<K>() + 1)
        }
        let seconds: usize = self
            .seconds
            .iter()
            .map(|s| s.v4.len() * size_of::<Ipv4Key>() + s.v6.len() * size_of::<Prefix>())
            .sum();
        map(&self.withdrawn)
            + map(&self.held)
            + map(&self.wakeups)
            + set(&self.open_v4)
            + set(&self.open_v6)
            + self.seconds.capacity() * size_of::<Second>()
            + seconds
    }

    /// The bound on destinations that may wait (module documentation).
    fn bound(&self) -> usize {
        self.peak.max(MIN_WAITING)
    }

    /// Whether `prefix` may wait for its interval to end: it waits
    /// already, or fewer destinations wait than the bound allows.
    fn may_wait(&self, prefix: Prefix) -> bool {
        self.held.len() + self.withdrawn.len() < self.bound()
            || self.held.contains_key(&prefix)
            || self.withdrawn.contains_key(&prefix)
    }

    /// When `prefix` was last advertised, as far as that can still hold
    /// it back: `had` says whether the peer has a route to it now. A
    /// destination the peer has was advertised one by one, or in the last
    /// whole Adj-RIB-Out, or so long ago that it does not matter; one it
    /// does not have was advertised before a withdrawal remembered.
    fn last(&self, prefix: Prefix, had: bool) -> Option<Tick> {
        if had {
            self.logged_at(prefix).max(self.bulk)
        } else if self.withdrawn.is_empty() {
            None
        } else {
            self.withdrawn.get(&prefix).copied()
        }
    }

    /// When `prefix` was last advertised one by one, if that is still
    /// remembered.
    fn logged_at(&self, prefix: Prefix) -> Option<Tick> {
        if self.logged == 0 {
            return None;
        }
        let key = Ipv4Key::new(prefix);
        if let Some(at) = self.open {
            let found = match key {
                Some(k) => self.open_v4.contains(&k),
                None => self.open_v6.contains(&prefix),
            };
            if found {
                return Some(at);
            }
        }
        self.seconds.iter().rev().find_map(|s| {
            let found = match key {
                Some(k) => s.v4.binary_search(&k).is_ok(),
                None => s.v6.binary_search(&prefix).is_ok(),
            };
            found.then_some(s.at)
        })
    }

    /// A destination that is not held is to be advertised to the peer;
    /// `had` says whether the peer has a route to it now.
    ///
    /// RFC 4271 §9.2.1.1: a new route to a destination goes out only once
    /// an interval has passed since the last advertisement of it, and
    /// then the latest one, so a route that changes several times while
    /// held goes out once. A destination never advertised to the peer,
    /// or not for an interval, goes out at once.
    pub(crate) fn offer(&mut self, prefix: Prefix, had: bool, pace: &mut Pace<'_>) -> Offer {
        if pace.interval.is_zero() {
            return Offer::Now;
        }
        if let Some(last) = self.last(prefix, had) {
            // RFC 4271 §10: the timer is jittered each time it is set.
            let due = last.after(secs_ceil(pace.jitter.apply(pace.interval)));
            // Past the bound on waiting destinations it goes out now.
            if due > pace.now.floor && self.may_wait(prefix) {
                return Offer::Hold(due);
            }
        }
        Offer::Now
    }

    /// Hold `prefix` back until `due`, the peer having `has` meanwhile.
    pub(crate) fn hold(&mut self, prefix: Prefix, due: Tick, has: Option<Arc<PathAttrs>>) {
        self.held.insert(
            prefix,
            Held {
                due,
                has,
                paths: false,
            },
        );
    }

    /// As [`Self::hold`], for a destination the peer has paths of, if
    /// `has_paths` (RFC 7911): the RIB works out what is to go out when
    /// the interval ends from the paths it has sent.
    pub(crate) fn hold_paths(&mut self, prefix: Prefix, due: Tick, has_paths: bool) {
        self.held.insert(
            prefix,
            Held {
                due,
                has: None,
                paths: has_paths,
            },
        );
    }

    /// Whether `prefix` is held back, and the peer has paths of it.
    pub(crate) fn holds_paths(&self, prefix: Prefix) -> Option<bool> {
        self.held(prefix).map(|h| h.paths)
    }

    /// The peer has, or has not, paths of the held destination `prefix`
    /// meanwhile (RFC 7911): some were withdrawn at once.
    pub(crate) fn set_held_paths(&mut self, prefix: Prefix, has_paths: bool) {
        if let Some(h) = self.held.get_mut(&prefix) {
            h.paths = has_paths;
        }
    }

    /// A held destination's paths were all withdrawn at once: as
    /// [`Self::withdrew_held`], for a destination of paths.
    pub(crate) fn withdrew_held_paths(&mut self, prefix: Prefix, pace: &Pace<'_>) {
        let had = self.held.get(&prefix).is_some_and(Held::had);
        let remembered = had && self.withdrew(prefix, pace);
        if remembered {
            if let Some(h) = self.held.get_mut(&prefix) {
                h.paths = false;
            }
        } else {
            self.held.remove(&prefix);
        }
    }

    /// `prefix` was advertised now: remember when, for an interval, unless
    /// the bound says otherwise. It is no longer a withdrawn destination.
    pub(crate) fn advertised(&mut self, prefix: Prefix, pace: &Pace<'_>) {
        if pace.interval.is_zero() {
            return;
        }
        if !self.withdrawn.is_empty() {
            self.withdrawn.remove(&prefix);
        }
        self.keep = self.keep.max(secs_ceil(pace.interval));
        let at = pace.now.ceil;
        if self.open != Some(at) {
            self.close_open();
            self.forget(pace.now);
            self.open = Some(at);
        }
        if self.logged >= 2 * self.bound() {
            return;
        }
        let fresh = match Ipv4Key::new(prefix) {
            Some(k) => self.open_v4.insert(k),
            None => self.open_v6.insert(prefix),
        };
        self.logged += usize::from(fresh);
    }

    /// The peer's route to `prefix` was withdrawn now, at once whatever
    /// the interval: remember when it was last advertised while that can
    /// hold back the route coming back. Whether it is remembered.
    ///
    /// NOTE(interop): RFC 4271 §9.2.1.1 paces withdrawals too ("an
    /// advertisement and/or withdrawal of routes"). Withdrawals go out at
    /// once instead, by the maintainer's decision (issue #66): holding one
    /// back prolongs a blackhole, and BIRD and FRR send withdrawals
    /// immediately. A withdrawal neither waits for nor restarts the
    /// interval; the last advertisement's time is kept so that a route
    /// flapping through withdrawals is still paced.
    pub(crate) fn withdrew(&mut self, prefix: Prefix, pace: &Pace<'_>) -> bool {
        if pace.interval.is_zero() {
            return false;
        }
        self.keep = self.keep.max(secs_ceil(pace.interval));
        let Some(last) = self.last(prefix, true) else {
            return false;
        };
        // Past the bound on waiting destinations it is not remembered.
        if last.after(secs_ceil(pace.interval)) > pace.now.floor && self.may_wait(prefix) {
            self.withdrawn.insert(prefix, last);
            true
        } else {
            if !self.withdrawn.is_empty() {
                self.withdrawn.remove(&prefix);
            }
            false
        }
    }

    /// A held destination's route went away, and the peer's was withdrawn
    /// at once. It stays held while its last advertisement is remembered,
    /// so that the route coming back waits for the same interval end; the
    /// release finds nothing to send if it does not.
    pub(crate) fn withdrew_held(
        &mut self,
        prefix: Prefix,
        pace: &Pace<'_>,
    ) -> Option<Arc<PathAttrs>> {
        let had = self.held.get(&prefix).is_some_and(Held::had);
        let remembered = had && self.withdrew(prefix, pace);
        if remembered {
            self.held.get_mut(&prefix).and_then(|h| h.has.take())
        } else {
            // Nothing to pace from: it is no longer held.
            self.held.remove(&prefix).and_then(|h| h.has)
        }
    }

    /// A wake-up for `prefix` is needed at `at`: whether the caller must
    /// queue one. Not when one is queued for then or earlier, since a
    /// wake-up that comes early finds what is left to do and asks again
    /// ([`Wake::again`]).
    pub(crate) fn queue(&mut self, prefix: Prefix, at: Tick) -> bool {
        match self.wakeups.get(&prefix) {
            Some(&queued) if queued <= at => false,
            _ => {
                self.wakeups.insert(prefix, at);
                true
            }
        }
    }

    /// A queued wake-up for `prefix` at `at` came due: whether it is the
    /// one [`Self::queue`] last asked for (then it is used up), rather
    /// than one an earlier wake-up replaced.
    pub(crate) fn fired(&mut self, prefix: Prefix, at: Tick) -> bool {
        if self.wakeups.get(&prefix) == Some(&at) {
            self.wakeups.remove(&prefix);
            true
        } else {
            false
        }
    }

    /// A wake-up for `prefix` came at `now` (after [`Self::fired`] said
    /// so).
    pub(crate) fn wake(&mut self, prefix: Prefix, now: Now) -> Wake {
        let mut wake = Wake::default();
        if let Some(h) = self.held.get(&prefix) {
            if h.due <= now.floor {
                wake.released = self.held.remove(&prefix);
            } else {
                // Woken early, by a wake-up queued for something else.
                wake.again = Some(h.due);
            }
        }
        wake
    }

    /// The peer is sent the whole Adj-RIB-Out now: the initial one (RFC
    /// 4271 §9.2) or a route refresh (RFC 2918 §4), which re-advertises
    /// held destinations as they are now and restarts every interval.
    /// Returns the destinations that were held, for the caller to
    /// withdraw those the peer has that are no longer exported. Wake-ups
    /// already queued stay, and find nothing to do.
    pub(crate) fn readvertise(&mut self, now: Now) -> Vec<(Prefix, Held)> {
        self.bulk = Some(now.ceil);
        // Every advertisement logged is at or before this one, which
        // stands for them all.
        self.open = None;
        self.open_v4 = HashSet::new();
        self.open_v6 = HashSet::new();
        self.seconds = VecDeque::new();
        self.logged = 0;
        self.held.drain().collect()
    }

    /// The peer's interval changed to `pace.interval`: move every held
    /// destination's release to its last advertisement plus the new
    /// interval (now, when that has passed). Returns the new wake-ups.
    pub(crate) fn reschedule(&mut self, pace: &mut Pace<'_>) -> Vec<(Prefix, Tick)> {
        self.keep = self.keep.max(secs_ceil(pace.interval));
        let mut held = std::mem::take(&mut self.held);
        let mut out = Vec::with_capacity(held.len());
        for (prefix, h) in &mut held {
            h.due = match self.last(*prefix, h.had()) {
                Some(l) if !pace.interval.is_zero() => {
                    l.after(secs_ceil(pace.jitter.apply(pace.interval)))
                }
                _ => pace.now.floor,
            };
            out.push((*prefix, h.due));
        }
        self.held = held;
        out
    }

    /// When a sweep has something to do, if pacing remembers anything:
    /// the open second ends, or the oldest advertisement or withdrawal
    /// expires.
    fn expiry(&self) -> Option<Tick> {
        if self.open.is_some() {
            return self.open;
        }
        let logged = self.seconds.front().map(|s| s.at);
        let withdrawn = self.withdrawn.values().min().copied();
        logged
            .into_iter()
            .chain(withdrawn)
            .min()
            .map(|at| at.after(self.keep))
    }

    /// A sweep is needed at the returned tick: none is queued for then or
    /// earlier. The open second is swept as soon as it ends; otherwise a
    /// sweep already queued asks for the next when it comes, which can be
    /// up to an interval late for a withdrawal remembered meanwhile, and
    /// spares each UPDATE a search of the withdrawals.
    pub(crate) fn queue_sweep(&mut self) -> Option<Tick> {
        let at = match self.open {
            Some(open) => open,
            None if self.sweep.is_some() => return None,
            None => self.expiry()?,
        };
        if self.sweep.is_some_and(|queued| queued <= at) {
            return None;
        }
        self.sweep = Some(at);
        self.sweep
    }

    /// A queued sweep for `at` came at `now`: forget what has expired.
    /// Returns the next sweep to queue, if any.
    pub(crate) fn swept(&mut self, at: Tick, now: Now) -> Option<Tick> {
        if self.sweep != Some(at) {
            return None;
        }
        self.sweep = None;
        if self.open.is_some_and(|open| open <= now.floor) {
            self.close_open();
        }
        self.forget(now);
        self.queue_sweep()
    }

    /// Move the open second into the sorted ones.
    fn close_open(&mut self) {
        if let Some(at) = self.open.take() {
            let mut v4: Vec<Ipv4Key> = self.open_v4.drain().collect();
            let mut v6: Vec<Prefix> = self.open_v6.drain().collect();
            if !v4.is_empty() || !v6.is_empty() {
                v4.sort_unstable();
                v6.sort_unstable();
                self.seconds.push_back(Second {
                    at,
                    v4: v4.into_boxed_slice(),
                    v6: v6.into_boxed_slice(),
                });
            }
        }
    }

    /// Forget what can no longer hold anything back at `now`.
    fn forget(&mut self, now: Now) {
        while let Some(s) = self.seconds.front()
            && s.at.after(self.keep) <= now.floor
        {
            self.logged -= s.v4.len() + s.v6.len();
            self.seconds.pop_front();
        }
        let keep = self.keep;
        self.withdrawn.retain(|_, at| at.after(keep) > now.floor);
        self.compact();
    }

    /// Give back the memory of maps that churn left mostly empty.
    pub(crate) fn compact(&mut self) {
        shrink(&mut self.withdrawn);
        shrink(&mut self.held);
        shrink(&mut self.wakeups);
        shrink_set(&mut self.open_v4);
        shrink_set(&mut self.open_v6);
        if self.seconds.capacity() > 64 && self.seconds.len() < self.seconds.capacity() / 4 {
            self.seconds.shrink_to_fit();
        }
    }
}

/// `map` with its capacity cut down once it is less than a quarter used.
fn shrink<K: Hash + Eq, V>(map: &mut HashMap<K, V>) {
    if map.capacity() > 64 && map.len() < map.capacity() / 4 {
        map.shrink_to(map.len() * 2);
    }
}

/// `set` with its capacity cut down once it is less than a quarter used.
fn shrink_set<K: Hash + Eq>(set: &mut HashSet<K>) {
    if set.capacity() > 64 && set.len() < set.capacity() / 4 {
        set.shrink_to(set.len() * 2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use bgpfc_wire::as_path::AsPath;
    use bgpfc_wire::attribute::Origin;
    use bgpfc_wire::mp::NextHop;
    use bgpfc_wire::types::Asn;

    const IV: Duration = Duration::from_secs(30);

    fn route(asn: u32) -> Arc<PathAttrs> {
        Arc::new(PathAttrs {
            origin: Origin::Igp,
            as_path: AsPath::sequence(&[Asn(asn)]),
            next_hop: NextHop::Ipv4(std::net::Ipv4Addr::new(192, 0, 2, 1)),
            med: None,
            local_pref: None,
            atomic_aggregate: false,
            aggregator: None,
            communities: Box::default(),
            ext_communities: Box::default(),
            large_communities: Box::default(),
            unknown: Box::default(),
        })
    }

    /// Exactly `secs` seconds after the epoch.
    fn at(secs: u32) -> Now {
        Now {
            floor: Tick(secs),
            ceil: Tick(secs),
        }
    }

    /// Half a second after `secs`.
    fn mid(secs: u32) -> Now {
        Now {
            floor: Tick(secs),
            ceil: Tick(secs + 1),
        }
    }

    fn pfx(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    fn pace(jitter: &mut Jitter, now: Now, interval: Duration) -> Pace<'_> {
        Pace {
            interval,
            now,
            jitter,
        }
    }

    /// What the RIB does with a destination to be advertised at `now`
    /// that is not held: advertise it, or hold it with `had` as what the
    /// peer has meanwhile.
    fn change(pc: &mut Pacing, prefix: Prefix, had: Option<&Arc<PathAttrs>>, now: Now) -> Offer {
        change_with(pc, prefix, had, now, IV)
    }

    fn change_with(
        pc: &mut Pacing,
        prefix: Prefix,
        had: Option<&Arc<PathAttrs>>,
        now: Now,
        interval: Duration,
    ) -> Offer {
        let mut j = Jitter::new(0);
        let pace = &mut pace(&mut j, now, interval);
        let offer = pc.offer(prefix, had.is_some(), pace);
        match offer {
            Offer::Now => pc.advertised(prefix, pace),
            Offer::Hold(due) => {
                pc.hold(prefix, due, had.cloned());
                pc.queue(prefix, due);
            }
        }
        offer
    }

    /// The peer's route to `prefix` is withdrawn at `now`.
    fn withdraw(pc: &mut Pacing, prefix: Prefix, now: Now) -> bool {
        let mut j = Jitter::new(0);
        pc.withdrew(prefix, &pace(&mut j, now, IV))
    }

    #[test]
    fn defaults_follow_rfc4271_section_10() {
        assert_eq!(
            default_interval(PeerKind::External),
            Duration::from_secs(30)
        );
        assert_eq!(default_interval(PeerKind::Internal), Duration::from_secs(5));
        // RFC 4271 §9.2.1.1 (a): shorter for internal peers.
        assert!(IBGP_DEFAULT_INTERVAL < EBGP_DEFAULT_INTERVAL);
    }

    #[test]
    fn clock_rounds_advertisements_up_and_now_down() {
        let t0 = Instant::now();
        let c = Clock::new(t0);
        assert_eq!(c.now(t0), at(0));
        assert_eq!(c.now(t0 + Duration::from_millis(1500)), mid(1));
        // Before the epoch counts as the epoch.
        if let Some(before) = t0.checked_sub(Duration::from_secs(5)) {
            assert_eq!(c.now(before), at(0));
        }
        assert_eq!(c.instant(Tick(7)), Some(t0 + Duration::from_secs(7)));
        assert_eq!(secs_ceil(Duration::from_millis(22_500)), 23);
        assert_eq!(secs_ceil(Duration::ZERO), 0);
    }

    #[test]
    fn first_advertisement_goes_out_at_once_then_changes_wait() {
        let mut pc = Pacing::default();
        let d = pfx("192.0.2.0/24");
        let a = route(1);
        assert_eq!(change(&mut pc, d, None, at(0)), Offer::Now);
        // RFC 4271 §9.2.1.1: the next one waits until 0 + 30, the peer
        // keeping what it has meanwhile.
        assert_eq!(change(&mut pc, d, Some(&a), at(1)), Offer::Hold(Tick(30)));
        let held = pc.held(d).unwrap();
        assert_eq!(held.due, Tick(30));
        assert!(Arc::ptr_eq(held.has.as_ref().unwrap(), &a));
        // Woken early, it asks to be woken again when it is due.
        let w = pc.wake(d, at(29));
        assert!(w.released.is_none());
        assert_eq!(w.again, Some(Tick(30)));
        assert!(pc.fired(d, Tick(30)));
        let w = pc.wake(d, at(30));
        assert_eq!(w.again, None);
        assert!(Arc::ptr_eq(&w.released.unwrap().has.unwrap(), &a));
        assert_eq!(pc.held_count(), 0);
        // The release is an advertisement too, and restarts the interval.
        let mut j = Jitter::new(0);
        pc.advertised(d, &pace(&mut j, at(30), IV));
        assert_eq!(change(&mut pc, d, Some(&a), at(45)), Offer::Hold(Tick(60)));
    }

    #[test]
    fn a_change_after_the_interval_goes_out_at_once() {
        let mut pc = Pacing::default();
        let d = pfx("192.0.2.0/24");
        change(&mut pc, d, None, at(0));
        assert_eq!(change(&mut pc, d, Some(&route(1)), at(30)), Offer::Now);
        assert_eq!(pc.held_count(), 0);
    }

    #[test]
    fn withdrawals_go_out_at_once_and_keep_pacing_the_route() {
        let mut pc = Pacing::default();
        let d = pfx("192.0.2.0/24");
        let a = route(1);
        change(&mut pc, d, None, at(0));
        // Not delayed (issue #66), even inside the interval, and the time
        // of the advertisement is kept.
        assert!(withdraw(&mut pc, d, at(1)));
        // The route comes back: still paced from the advertisement at 0,
        // with nothing at the peer meanwhile.
        assert_eq!(change(&mut pc, d, None, at(3)), Offer::Hold(Tick(30)));
        assert!(pc.held(d).unwrap().has.is_none());
        let w = pc.wake(d, at(30));
        assert!(w.released.unwrap().has.is_none());
        // Once the interval is over the withdrawal is forgotten, and the
        // route is new again.
        assert_eq!(pc.swept(Tick(0), at(31)), None);
        pc.sweep = Some(Tick(30));
        assert_eq!(pc.swept(Tick(30), at(31)), None);
        assert_eq!(pc.withdrawn.len(), 0);
        assert_eq!(change(&mut pc, d, Some(&a), at(31)), Offer::Now);
    }

    #[test]
    fn a_held_route_that_goes_stays_held_without_what_the_peer_had() {
        let mut pc = Pacing::default();
        let d = pfx("192.0.2.0/24");
        let a = route(1);
        change(&mut pc, d, None, at(0));
        assert_eq!(change(&mut pc, d, Some(&a), at(1)), Offer::Hold(Tick(30)));
        // The peer's route is withdrawn at once and handed back for the
        // interner; the destination stays held, so that the route coming
        // back waits for the same end.
        let mut j = Jitter::new(0);
        let gone = pc.withdrew_held(d, &pace(&mut j, at(2), IV));
        assert!(Arc::ptr_eq(&gone.unwrap(), &a));
        let held = pc.held(d).unwrap();
        assert_eq!((held.due, held.has.is_none()), (Tick(30), true));
        // Past the interval nothing is remembered: it is no longer held.
        change(&mut pc, d, None, at(40));
        assert_eq!(change(&mut pc, d, Some(&a), at(41)), Offer::Hold(Tick(70)));
        let gone = pc.withdrew_held(d, &pace(&mut j, at(75), IV));
        assert!(gone.is_some());
        assert_eq!(pc.held_count(), 0);
    }

    #[test]
    fn one_wake_up_is_queued_per_destination() {
        let mut pc = Pacing::default();
        let (d, e) = (pfx("192.0.2.0/24"), pfx("198.51.100.0/24"));
        assert!(pc.queue(d, Tick(30)));
        // One for then or earlier is queued already.
        assert!(!pc.queue(d, Tick(30)));
        assert!(!pc.queue(d, Tick(40)));
        // An earlier one replaces it; the replaced one is ignored.
        assert!(pc.queue(d, Tick(20)));
        assert!(pc.queue(e, Tick(40)));
        assert!(!pc.fired(d, Tick(30)));
        assert!(pc.fired(d, Tick(20)));
        assert!(!pc.fired(d, Tick(20)));
        assert!(pc.fired(e, Tick(40)));
        assert_eq!(pc.remembered(), 0);
    }

    #[test]
    fn waiting_destinations_are_bounded_by_the_adj_rib_out() {
        // A peer that has one route at a time, while ever new destinations
        // come and go: pacing remembers at most MIN_WAITING of them.
        let mut pc = Pacing::default();
        pc.note_routes(1);
        let a = route(1);
        let prefixes: Vec<Prefix> = (0..u32::try_from(MIN_WAITING).unwrap() + 10)
            .map(|i| pfx(&format!("10.{}.{}.0/24", i >> 8, i & 0xff)))
            .collect();
        for (i, &d) in prefixes.iter().enumerate() {
            assert_eq!(change(&mut pc, d, None, at(0)), Offer::Now);
            assert_eq!(withdraw(&mut pc, d, at(0)), i < MIN_WAITING, "{i}");
        }
        assert_eq!(pc.withdrawn.len(), MIN_WAITING);
        // A remembered one coming back waits; one past the bound goes out.
        let (first, last) = (prefixes[0], prefixes[prefixes.len() - 1]);
        assert_eq!(change(&mut pc, first, None, at(1)), Offer::Hold(Tick(30)));
        assert_eq!(change(&mut pc, last, None, at(1)), Offer::Now);
        // A change to it goes out at once too: nothing more may wait.
        assert_eq!(change(&mut pc, last, Some(&a), at(2)), Offer::Now);
        // When the interval is over, everything is forgotten and the
        // memory given back.
        assert!(pc.fired(first, Tick(30)));
        assert!(pc.wake(first, at(30)).released.is_some());
        let mut sweep = pc.queue_sweep();
        while let Some(s) = sweep {
            sweep = pc.swept(s, at(s.0));
        }
        assert_eq!(pc.remembered(), 0);
        assert!(
            pc.withdrawn.capacity() < MIN_WAITING,
            "{}",
            pc.withdrawn.capacity()
        );
        assert!(
            pc.wakeups.capacity() < MIN_WAITING,
            "{}",
            pc.wakeups.capacity()
        );
    }

    #[test]
    fn a_full_adj_rib_out_may_have_all_its_destinations_wait() {
        // The bound follows the most routes the Adj-RIB-Out held: a table
        // larger than MIN_WAITING withdrawn at once is remembered whole.
        let mut pc = Pacing::default();
        let n = u32::try_from(MIN_WAITING).unwrap() * 2;
        let prefixes: Vec<Prefix> = (0..n)
            .map(|i| pfx(&format!("10.{}.{}.0/24", i >> 8, i & 0xff)))
            .collect();
        for &d in &prefixes {
            change(&mut pc, d, None, at(0));
        }
        pc.note_routes(prefixes.len());
        for &d in &prefixes {
            assert!(withdraw(&mut pc, d, at(1)));
        }
        assert_eq!(pc.withdrawn.len(), prefixes.len());
    }

    #[test]
    fn advertisements_are_remembered_for_an_interval_within_twice_the_bound() {
        let mut pc = Pacing::default();
        pc.note_routes(1);
        let n = u32::try_from(MIN_WAITING).unwrap() * 2;
        let prefixes: Vec<Prefix> = (0..=n)
            .map(|i| pfx(&format!("10.{}.{}.0/24", i >> 8, i & 0xff)))
            .collect();
        for &d in &prefixes {
            change(&mut pc, d, None, at(0));
        }
        assert_eq!(pc.logged, 2 * MIN_WAITING);
        // One remembered waits, the one past the bound does not.
        let a = route(1);
        assert_eq!(
            change(&mut pc, prefixes[0], Some(&a), at(1)),
            Offer::Hold(Tick(30))
        );
        assert_eq!(
            change(&mut pc, prefixes[prefixes.len() - 1], Some(&a), at(1)),
            Offer::Now
        );
    }

    #[test]
    fn a_withdrawal_after_the_interval_is_not_remembered() {
        let mut pc = Pacing::default();
        let d = pfx("192.0.2.0/24");
        change(&mut pc, d, None, at(0));
        assert!(!withdraw(&mut pc, d, at(40)));
        assert_eq!(pc.withdrawn.len(), 0);
    }

    #[test]
    fn destinations_are_paced_independently() {
        let mut pc = Pacing::default();
        let (d, e) = (pfx("192.0.2.0/24"), pfx("2001:db8::/32"));
        let a = route(1);
        change(&mut pc, d, None, at(0));
        assert_eq!(change(&mut pc, d, Some(&a), at(1)), Offer::Hold(Tick(30)));
        // e has its own interval: its first advertisement is not held, and
        // its next change waits for e's interval, not d's.
        assert_eq!(change(&mut pc, e, None, mid(9)), Offer::Now);
        assert_eq!(change(&mut pc, e, Some(&a), at(11)), Offer::Hold(Tick(40)));
    }

    #[test]
    fn interval_zero_turns_pacing_off() {
        let mut pc = Pacing::default();
        let d = pfx("192.0.2.0/24");
        let a = route(1);
        for _ in 0..5 {
            assert_eq!(
                change_with(&mut pc, d, None, at(0), Duration::ZERO),
                Offer::Now
            );
            assert_eq!(
                change_with(&mut pc, d, Some(&a), at(0), Duration::ZERO),
                Offer::Now
            );
            let mut j = Jitter::new(0);
            assert!(!pc.withdrew(d, &pace(&mut j, at(0), Duration::ZERO)));
        }
        assert_eq!(pc.remembered(), 0);
        assert_eq!(pc.queue_sweep(), None);
    }

    #[test]
    fn jitter_shortens_the_interval_within_rfc_bounds() {
        // RFC 4271 §10: the factor is in [0.75, 1.0] and drawn anew each
        // time the timer is set.
        let mut j = Jitter::new(0x1234_5678_9abc_def0);
        let mut dues = HashSet::new();
        let d = pfx("192.0.2.0/24");
        for _ in 0..200 {
            let mut pc = Pacing::default();
            change(&mut pc, d, None, at(0));
            let Offer::Hold(Tick(due)) = pc.offer(d, true, &mut pace(&mut j, at(1), IV)) else {
                panic!("held");
            };
            assert!((23..=30).contains(&due), "{due}");
            dues.insert(due);
        }
        assert!(dues.len() > 3, "{dues:?}");
        assert_eq!(Jitter::new(0).apply(IV), IV);
    }

    #[test]
    fn readvertise_restarts_intervals_and_forgets_the_log() {
        let mut pc = Pacing::default();
        let (d, e) = (pfx("192.0.2.0/24"), pfx("198.51.100.0/24"));
        let a = route(1);
        change(&mut pc, d, None, at(0));
        change(&mut pc, e, None, at(0));
        assert_eq!(change(&mut pc, d, Some(&a), at(5)), Offer::Hold(Tick(30)));
        // A refresh at 10 hands back what was held, for the caller to
        // settle, and stands for every advertisement before it.
        let held = pc.readvertise(at(10));
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].0, d);
        assert_eq!((pc.held_count(), pc.logged), (0, 0));
        // The interval runs from the refresh, for both.
        assert_eq!(change(&mut pc, d, Some(&a), at(20)), Offer::Hold(Tick(40)));
        assert_eq!(change(&mut pc, e, Some(&a), at(20)), Offer::Hold(Tick(40)));
    }

    #[test]
    fn a_new_interval_moves_held_destinations() {
        let mut pc = Pacing::default();
        let d = pfx("192.0.2.0/24");
        change(&mut pc, d, None, at(0));
        change(&mut pc, d, Some(&route(1)), at(1));
        let mut j = Jitter::new(0);
        let mut pace = pace(&mut j, at(2), Duration::from_secs(5));
        assert_eq!(pc.reschedule(&mut pace), vec![(d, Tick(5))]);
        pace.interval = Duration::ZERO;
        assert_eq!(pc.reschedule(&mut pace), vec![(d, Tick(2))]);
        assert!(pc.wake(d, at(2)).released.is_some());
    }

    #[test]
    fn a_longer_interval_keeps_withdrawn_times_longer() {
        let mut pc = Pacing::default();
        let d = pfx("192.0.2.0/24");
        change(&mut pc, d, None, at(0));
        assert!(withdraw(&mut pc, d, at(1)));
        // The interval grows to 60 s: the withdrawal is kept until then.
        let mut j = Jitter::new(0);
        pc.reschedule(&mut pace(&mut j, at(10), Duration::from_secs(60)));
        pc.forget(at(40));
        assert_eq!(
            change_with(&mut pc, d, None, at(40), Duration::from_secs(60)),
            Offer::Hold(Tick(60))
        );
        pc.forget(at(60));
        assert_eq!(pc.withdrawn.len(), 0);
    }

    #[test]
    fn sweeps_sort_the_second_that_ended_and_forget_what_expired() {
        let mut pc = Pacing::default();
        let (d, e) = (pfx("192.0.2.0/24"), pfx("2001:db8::/32"));
        let a = route(1);
        // Advertisements in the second up to tick 1 are logged as made
        // then: the sweep comes when that second is over.
        change(&mut pc, d, None, mid(0));
        assert_eq!(pc.queue_sweep(), Some(Tick(1)));
        assert_eq!(pc.queue_sweep(), None);
        assert_eq!(pc.swept(Tick(1), at(1)), Some(Tick(31)));
        assert_eq!((pc.open, pc.seconds.len()), (None, 1));
        assert_eq!(pc.logged_at(d), Some(Tick(1)));
        // A later second is swept as soon as it ends, ahead of the queued
        // sweep, which then has nothing to do but ask again.
        change(&mut pc, e, None, mid(2));
        assert_eq!(pc.queue_sweep(), Some(Tick(3)));
        assert_eq!(pc.swept(Tick(31), at(3)), None);
        assert_eq!(pc.swept(Tick(3), at(3)), Some(Tick(31)));
        assert_eq!(pc.logged_at(e), Some(Tick(3)));
        // Each second is forgotten an interval after it.
        assert_eq!(pc.swept(Tick(31), at(31)), Some(Tick(33)));
        assert_eq!((pc.logged_at(d), pc.logged), (None, 1));
        assert_eq!(change(&mut pc, d, Some(&a), at(31)), Offer::Now);
        assert_eq!(change(&mut pc, e, Some(&a), at(32)), Offer::Hold(Tick(33)));
        assert!(pc.fired(e, Tick(33)));
        assert!(pc.wake(e, at(33)).released.is_some());
        let mut sweep = pc.queue_sweep();
        while let Some(s) = sweep {
            sweep = pc.swept(s, at(s.0.max(62)));
        }
        assert_eq!(pc.remembered(), 0);
    }
}
