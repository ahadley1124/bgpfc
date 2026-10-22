//! Pacing of advertisements: the `MinRouteAdvertisementIntervalTimer`
//! (MRAI), kept per peer and destination.
//!
//! Implements: RFC 4271 §9.2.1.1 (a minimum interval between two
//! advertisements of a destination to a peer; the last route selected
//! goes out when the interval ends; a shorter interval for internal
//! peers), §10 (the 30 s and 5 s suggested defaults, jitter in
//! [0.75, 1.0]).
//!
//! One `AdjRibOut` per peer and family holds what the peer was told and
//! when, the destinations held back and until when, and, for withdrawn
//! destinations advertised less than an interval ago, when that was. It
//! never reads the clock: callers pass the time in. Wake-ups go through one
//! deadline queue owned by [`crate::Rib`], so there is no timer or thread
//! per destination, and a destination that is not held back costs one
//! timestamp in its Adj-RIB-Out entry.
//!
//! Memory follows the destinations, not the churn (AGENTS.md §3). Each
//! destination has at most one wake-up queued, however often it changes,
//! and a held destination stays held when its route changes back, so its
//! interval is drawn once. The destinations that may wait at once, held
//! back or remembered after a withdrawal, are bounded by the most routes
//! the Adj-RIB-Out ever held, or 1024 if that is more: past the bound, a
//! change goes out at once and a withdrawal is not remembered, so that a
//! peer cannot grow the RIB by announcing and withdrawing ever new
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

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bgpfc_wire::prefix::Prefix;
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

/// What one peer was told about one destination, and when.
#[derive(Clone, Debug)]
struct Sent {
    attrs: Arc<PathAttrs>,
    /// When the advertisement went out, rounded up.
    at: Tick,
}

/// What to do about one destination for one peer, now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    /// Nothing to send.
    Quiet,
    /// Advertise these attributes now.
    Announce(Arc<PathAttrs>),
    /// Withdraw now. With `forget` set, the time of the last advertisement
    /// is remembered until then; the caller schedules a wake-up for it.
    Withdraw {
        /// When the remembered advertisement time may be dropped.
        forget: Option<Tick>,
    },
    /// Held back until the tick; the caller schedules a wake-up then, and
    /// whatever the route is at that time goes out.
    Hold(Tick),
}

/// What a wake-up for one destination found.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Wake {
    /// The destination's interval ended: compute its route now and pass
    /// it to [`AdjRibOut::release`].
    pub(crate) release: bool,
    /// Wake up again then: a remembered advertisement time outlives the
    /// wake-up because the interval grew meanwhile.
    pub(crate) again: Option<Tick>,
}

/// However few routes an Adj-RIB-Out has held, this many of its
/// destinations may wait at once (see the module documentation).
pub(crate) const MIN_WAITING: usize = 1024;

/// One peer's Adj-RIB-Out for one family (RFC 4271 §3.2) together with
/// its RFC 4271 §9.2.1.1 state.
#[derive(Debug, Default)]
pub(crate) struct AdjRibOut {
    /// What the peer was last told, and when.
    sent: HashMap<Prefix, Sent>,
    /// Withdrawn destinations whose last advertisement is younger than an
    /// interval, with its time, so that a route flapping through
    /// withdrawals is still paced.
    withdrawn: HashMap<Prefix, Tick>,
    /// Destinations whose interval runs and whose route changed during
    /// it, and when the interval ends: their route then is compared with
    /// what the peer has. Each is in `sent` or `withdrawn`.
    held: HashMap<Prefix, Tick>,
    /// The one wake-up queued for each destination that has one: a
    /// queue entry for another tick is stale and ignored. Covers every
    /// destination in `held` and `withdrawn`.
    wakeups: HashMap<Prefix, Tick>,
    /// The most routes `sent` has held.
    peak: usize,
}

impl AdjRibOut {
    /// The routes the peer was told about.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (Prefix, &Arc<PathAttrs>)> {
        self.sent.iter().map(|(p, s)| (*p, &s.attrs))
    }

    /// The destinations the peer was told about.
    pub(crate) fn prefixes(&self) -> impl Iterator<Item = Prefix> + '_ {
        self.sent.keys().copied()
    }

    /// How many routes the peer was told about.
    pub(crate) fn len(&self) -> usize {
        self.sent.len()
    }

    /// How many destinations are held back.
    #[cfg(test)]
    pub(crate) fn held(&self) -> usize {
        self.held.len()
    }

    /// How many destinations pacing remembers beyond the Adj-RIB-Out:
    /// held back, remembered after a withdrawal, or with a wake-up queued.
    #[cfg(test)]
    pub(crate) fn remembered(&self) -> usize {
        self.held.len() + self.withdrawn.len() + self.wakeups.len()
    }

    /// Whether `prefix` may wait for its interval to end: it has a wake-up
    /// queued already, or fewer destinations wait than the bound allows
    /// (see the module documentation).
    fn may_wait(&self, prefix: Prefix) -> bool {
        self.wakeups.contains_key(&prefix) || self.wakeups.len() < self.peak.max(MIN_WAITING)
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

    /// Give back the memory of maps that churn left mostly empty.
    pub(crate) fn compact(&mut self) {
        shrink(&mut self.withdrawn);
        shrink(&mut self.held);
        shrink(&mut self.wakeups);
    }

    /// The route to `prefix` should now be `desired` (`None`: no route
    /// for this peer). Decide what to send.
    ///
    /// RFC 4271 §9.2.1.1: a new route to a destination goes out only once
    /// an interval has passed since the last advertisement of it, and
    /// then the latest one, so a route that changes several times while
    /// held goes out once. A destination never advertised to the peer,
    /// or not for an interval, goes out at once.
    pub(crate) fn offer(
        &mut self,
        prefix: Prefix,
        desired: Option<Arc<PathAttrs>>,
        pace: &mut Pace<'_>,
    ) -> Step {
        let Some(attrs) = desired else {
            return self.withdraw(prefix, pace);
        };
        let last = match self.sent.get(&prefix) {
            // RFC 4271 §9.2: the peer already has this route. A held
            // change that reverted needs nothing either; the destination
            // stays held, so that its interval is not drawn again, and the
            // release finds nothing to send.
            Some(s) if Arc::ptr_eq(&s.attrs, &attrs) => return Step::Quiet,
            Some(s) => Some(s.at),
            None => self.withdrawn.get(&prefix).copied(),
        };
        if self.held.contains_key(&prefix) {
            // It goes out when its interval ends, as whatever it is then.
            return Step::Quiet;
        }
        if let Some(last) = last
            && !pace.interval.is_zero()
        {
            // RFC 4271 §10: the timer is jittered each time it is set.
            let due = last.after(secs_ceil(pace.jitter.apply(pace.interval)));
            // Past the bound on waiting destinations it goes out now.
            if due > pace.now.floor && self.may_wait(prefix) {
                self.held.insert(prefix, due);
                return Step::Hold(due);
            }
        }
        self.advertise(prefix, attrs, pace.now)
    }

    /// A wake-up for `prefix` came at `now` (after [`Self::fired`] said
    /// so), with `interval` the peer's current interval.
    pub(crate) fn wake(&mut self, prefix: Prefix, interval: Duration, now: Now) -> Wake {
        let mut wake = Wake::default();
        if let Some(&at) = self.withdrawn.get(&prefix) {
            let until = at.after(secs_ceil(interval));
            if until <= now.floor {
                self.withdrawn.remove(&prefix);
            } else {
                wake.again = Some(until);
            }
        }
        if let Some(&due) = self.held.get(&prefix) {
            if due <= now.floor {
                self.held.remove(&prefix);
                wake.release = true;
            } else {
                // Woken early, by a wake-up queued for something else.
                wake.again = Some(wake.again.map_or(due, |t| t.min(due)));
            }
        }
        wake
    }

    /// The interval of a held destination ended (after [`Self::wake`]
    /// said so): send `desired`, its route now, unless the peer already
    /// has it (RFC 4271 §9.2.1.1: "the last route selected SHALL be
    /// advertised at the end of `MinRouteAdvertisementIntervalTimer`").
    pub(crate) fn release(
        &mut self,
        prefix: Prefix,
        desired: Option<Arc<PathAttrs>>,
        pace: &mut Pace<'_>,
    ) -> Step {
        match desired {
            None => self.withdraw(prefix, pace),
            Some(attrs) => {
                if self
                    .sent
                    .get(&prefix)
                    .is_some_and(|s| Arc::ptr_eq(&s.attrs, &attrs))
                {
                    return Step::Quiet;
                }
                self.advertise(prefix, attrs, pace.now)
            }
        }
    }

    /// The peer is told `routes`, all of them, now: the initial
    /// Adj-RIB-Out (RFC 4271 §9.2) or a route refresh (RFC 2918 §4), which
    /// re-advertises held destinations as they are now and restarts every
    /// interval. Returns the destinations the peer had that are no longer
    /// in `routes`, which the caller withdraws. Wake-ups already queued
    /// stay, and find nothing to do.
    pub(crate) fn readvertise(
        &mut self,
        routes: Vec<(Prefix, Arc<PathAttrs>)>,
        now: Now,
    ) -> Vec<Prefix> {
        let mut fresh = HashMap::with_capacity(routes.len());
        for (prefix, attrs) in routes {
            if !self.withdrawn.is_empty() {
                self.withdrawn.remove(&prefix);
            }
            fresh.insert(
                prefix,
                Sent {
                    attrs,
                    at: now.ceil,
                },
            );
        }
        self.held.clear();
        let old = std::mem::replace(&mut self.sent, fresh);
        self.peak = self.peak.max(self.sent.len());
        old.into_keys()
            .filter(|p| !self.sent.contains_key(p))
            .collect()
    }

    /// The peer's interval changed to `pace.interval`: move every held
    /// destination's release to its last advertisement plus the new
    /// interval (now, when that has passed). Returns the new wake-ups.
    pub(crate) fn reschedule(&mut self, pace: &mut Pace<'_>) -> Vec<(Prefix, Tick)> {
        let mut out = Vec::with_capacity(self.held.len());
        for (prefix, due) in &mut self.held {
            let last = self
                .sent
                .get(prefix)
                .map(|s| s.at)
                .or_else(|| self.withdrawn.get(prefix).copied());
            *due = match last {
                Some(l) if !pace.interval.is_zero() => {
                    l.after(secs_ceil(pace.jitter.apply(pace.interval)))
                }
                _ => pace.now.floor,
            };
            out.push((*prefix, *due));
        }
        out
    }

    /// Record an advertisement made now.
    fn advertise(&mut self, prefix: Prefix, attrs: Arc<PathAttrs>, now: Now) -> Step {
        if !self.withdrawn.is_empty() {
            self.withdrawn.remove(&prefix);
        }
        if !self.held.is_empty() {
            self.held.remove(&prefix);
        }
        self.sent.insert(
            prefix,
            Sent {
                attrs: Arc::clone(&attrs),
                at: now.ceil,
            },
        );
        self.peak = self.peak.max(self.sent.len());
        Step::Announce(attrs)
    }

    /// The peer must no longer have a route to `prefix`. A held
    /// destination stays held while its last advertisement is remembered,
    /// so that the route coming back waits for the same interval end; the
    /// release finds nothing to send if it does not.
    fn withdraw(&mut self, prefix: Prefix, pace: &Pace<'_>) -> Step {
        let Some(old) = self.sent.remove(&prefix) else {
            // Held, if at all, from a remembered withdrawal.
            return Step::Quiet;
        };
        // NOTE(interop): RFC 4271 §9.2.1.1 paces withdrawals too ("an
        // advertisement and/or withdrawal of routes"). Withdrawals go out
        // at once instead, by the maintainer's decision (issue #66):
        // holding one back prolongs a blackhole, and BIRD and FRR send
        // withdrawals immediately. A withdrawal neither waits for nor
        // restarts the interval; the last advertisement's time is kept so
        // that a route flapping through withdrawals is still paced.
        let until = old.at.after(secs_ceil(pace.interval));
        // Past the bound on waiting destinations it is not remembered.
        if !pace.interval.is_zero() && until > pace.now.floor && self.may_wait(prefix) {
            self.withdrawn.insert(prefix, old.at);
            Step::Withdraw {
                forget: Some(until),
            }
        } else {
            // Nothing to pace from: whatever was held goes.
            self.held.remove(&prefix);
            Step::Withdraw { forget: None }
        }
    }
}

/// `map` with its capacity cut down once it is less than a quarter used.
fn shrink<K: std::hash::Hash + Eq, V>(map: &mut HashMap<K, V>) {
    if map.capacity() > 64 && map.len() < map.capacity() / 4 {
        map.shrink_to(map.len() * 2);
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
            communities: Vec::new(),
            ext_communities: Vec::new(),
            large_communities: Vec::new(),
            unknown: Vec::new(),
        })
    }

    fn at(secs: u32) -> Now {
        Now {
            floor: Tick(secs),
            ceil: Tick(secs),
        }
    }

    fn pfx(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    /// Offer `desired` at `secs` with interval `iv` and no jitter.
    fn offer(out: &mut AdjRibOut, p: Prefix, desired: Option<&Arc<PathAttrs>>, secs: u32) -> Step {
        offer_with(out, p, desired, secs, IV)
    }

    fn offer_with(
        out: &mut AdjRibOut,
        p: Prefix,
        desired: Option<&Arc<PathAttrs>>,
        secs: u32,
        interval: Duration,
    ) -> Step {
        let mut jitter = Jitter::new(0);
        let mut pace = Pace {
            interval,
            now: at(secs),
            jitter: &mut jitter,
        };
        out.offer(p, desired.cloned(), &mut pace)
    }

    fn release(
        out: &mut AdjRibOut,
        p: Prefix,
        desired: Option<&Arc<PathAttrs>>,
        secs: u32,
    ) -> Step {
        let mut jitter = Jitter::new(0);
        let mut pace = Pace {
            interval: IV,
            now: at(secs),
            jitter: &mut jitter,
        };
        out.release(p, desired.cloned(), &mut pace)
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
        let n = c.now(t0 + Duration::from_millis(1500));
        assert_eq!((n.floor, n.ceil), (Tick(1), Tick(2)));
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
        let mut out = AdjRibOut::default();
        let p = pfx("192.0.2.0/24");
        let (a, b, c) = (route(1), route(2), route(3));
        assert_eq!(offer(&mut out, p, Some(&a), 0), Step::Announce(a.clone()));
        // RFC 4271 §9.2.1.1: the next one waits until 0 + 30.
        assert_eq!(offer(&mut out, p, Some(&b), 1), Step::Hold(Tick(30)));
        // Held: later changes ride along, without a second wake-up.
        assert_eq!(offer(&mut out, p, Some(&c), 2), Step::Quiet);
        assert_eq!(out.held(), 1);
        // Woken early, it asks to be woken again when it is due.
        assert_eq!(
            out.wake(p, IV, at(29)),
            Wake {
                release: false,
                again: Some(Tick(30))
            }
        );
        assert_eq!(
            out.wake(p, IV, at(30)),
            Wake {
                release: true,
                again: None
            }
        );
        // The latest state wins.
        assert_eq!(
            release(&mut out, p, Some(&c), 30),
            Step::Announce(c.clone())
        );
        assert_eq!(out.iter().collect::<Vec<_>>(), vec![(p, &c)]);
        // And restarts the interval.
        assert_eq!(offer(&mut out, p, Some(&a), 45), Step::Hold(Tick(60)));
    }

    #[test]
    fn a_change_after_the_interval_goes_out_at_once() {
        let mut out = AdjRibOut::default();
        let p = pfx("192.0.2.0/24");
        offer(&mut out, p, Some(&route(1)), 0);
        let b = route(2);
        assert_eq!(offer(&mut out, p, Some(&b), 30), Step::Announce(b));
        assert_eq!(out.held(), 0);
    }

    #[test]
    fn a_held_change_that_reverts_sends_nothing() {
        let mut out = AdjRibOut::default();
        let p = pfx("192.0.2.0/24");
        let a = route(1);
        offer(&mut out, p, Some(&a), 0);
        assert_eq!(offer(&mut out, p, Some(&route(2)), 5), Step::Hold(Tick(30)));
        assert_eq!(offer(&mut out, p, Some(&a), 6), Step::Quiet);
        // Still held, with the interval end it has: a change back within
        // it waits for the same end, without a new wake-up...
        assert_eq!(out.held(), 1);
        assert_eq!(offer(&mut out, p, Some(&route(3)), 7), Step::Quiet);
        assert_eq!(offer(&mut out, p, Some(&a), 8), Step::Quiet);
        // ... and the release finds nothing to send.
        assert!(out.wake(p, IV, at(30)).release);
        assert_eq!(release(&mut out, p, Some(&a), 30), Step::Quiet);
        assert_eq!(out.held(), 0);
    }

    #[test]
    fn withdrawals_go_out_at_once_and_keep_pacing_the_route() {
        let mut out = AdjRibOut::default();
        let p = pfx("192.0.2.0/24");
        let a = route(1);
        offer(&mut out, p, Some(&a), 0);
        // Not delayed (issue #66), even inside the interval.
        assert_eq!(
            offer(&mut out, p, None, 1),
            Step::Withdraw {
                forget: Some(Tick(30))
            }
        );
        assert_eq!(out.len(), 0);
        // Withdrawing what the peer does not have sends nothing.
        assert_eq!(offer(&mut out, p, None, 2), Step::Quiet);
        // The route comes back: still paced from the advertisement at 0.
        assert_eq!(offer(&mut out, p, Some(&a), 3), Step::Hold(Tick(30)));
        // And goes again before the interval ends: nothing is sent, and
        // it stays held, so that coming back once more waits for the
        // same end.
        assert_eq!(offer(&mut out, p, None, 4), Step::Quiet);
        assert_eq!(out.held(), 1);
        assert_eq!(offer(&mut out, p, Some(&a), 5), Step::Quiet);
        assert_eq!(offer(&mut out, p, None, 6), Step::Quiet);
        // At the end the release has nothing to send, and the remembered
        // time is dropped.
        assert_eq!(
            out.wake(p, IV, at(30)),
            Wake {
                release: true,
                again: None
            }
        );
        assert_eq!(release(&mut out, p, None, 30), Step::Quiet);
        assert_eq!(out.withdrawn.len(), 0);
        // After that the route is new again.
        assert_eq!(offer(&mut out, p, Some(&a), 31), Step::Announce(a));
    }

    #[test]
    fn one_wake_up_is_queued_per_destination() {
        let mut out = AdjRibOut::default();
        let (p, q) = (pfx("192.0.2.0/24"), pfx("198.51.100.0/24"));
        assert!(out.queue(p, Tick(30)));
        // One for then or earlier is queued already.
        assert!(!out.queue(p, Tick(30)));
        assert!(!out.queue(p, Tick(40)));
        // An earlier one replaces it; the replaced one is ignored.
        assert!(out.queue(p, Tick(20)));
        assert!(out.queue(q, Tick(40)));
        assert!(!out.fired(p, Tick(30)));
        assert!(out.fired(p, Tick(20)));
        assert!(!out.fired(p, Tick(20)));
        assert!(out.fired(q, Tick(40)));
        assert_eq!(out.remembered(), 0);
    }

    /// [`offer`] as the RIB makes it: its wake-up queued if needed.
    fn offer_queued(
        out: &mut AdjRibOut,
        p: Prefix,
        desired: Option<&Arc<PathAttrs>>,
        secs: u32,
    ) -> Step {
        let step = offer(out, p, desired, secs);
        if let Step::Hold(at)
        | Step::Withdraw {
            forget: Some(at), ..
        } = step
        {
            out.queue(p, at);
        }
        step
    }

    #[test]
    fn waiting_destinations_are_bounded_by_the_adj_rib_out() {
        // A peer that has one route at a time, while ever new destinations
        // come and go: pacing remembers at most MIN_WAITING of them.
        let mut out = AdjRibOut::default();
        let a = route(1);
        let prefixes: Vec<Prefix> = (0..u32::try_from(MIN_WAITING).unwrap() + 10)
            .map(|i| pfx(&format!("10.{}.{}.0/24", i >> 8, i & 0xff)))
            .collect();
        for (i, &p) in prefixes.iter().enumerate() {
            assert_eq!(offer(&mut out, p, Some(&a), 0), Step::Announce(a.clone()));
            let step = offer_queued(&mut out, p, None, 0);
            let remembered = i < MIN_WAITING;
            assert_eq!(
                step,
                Step::Withdraw {
                    forget: remembered.then_some(Tick(30))
                },
                "{i}"
            );
        }
        assert_eq!(out.withdrawn.len(), MIN_WAITING);
        // A remembered one coming back waits; one past the bound goes out.
        let (first, last) = (prefixes[0], prefixes[prefixes.len() - 1]);
        assert_eq!(
            offer_queued(&mut out, first, Some(&a), 1),
            Step::Hold(Tick(30))
        );
        assert_eq!(
            offer(&mut out, last, Some(&a), 1),
            Step::Announce(a.clone())
        );
        // A change to it goes out at once too: nothing more may wait.
        assert_eq!(
            offer(&mut out, last, Some(&route(2)), 2),
            Step::Announce(route(2))
        );
        // When the interval is over, everything is forgotten and the
        // memory given back.
        for &p in &prefixes {
            if out.fired(p, Tick(30)) {
                let w = out.wake(p, IV, at(30));
                assert_eq!(w.again, None);
                if w.release {
                    release(&mut out, p, Some(&a), 30);
                }
            }
        }
        out.compact();
        assert_eq!(out.remembered(), 0);
        assert!(
            out.withdrawn.capacity() < MIN_WAITING,
            "{}",
            out.withdrawn.capacity()
        );
        assert!(
            out.wakeups.capacity() < MIN_WAITING,
            "{}",
            out.wakeups.capacity()
        );
    }

    #[test]
    fn a_full_adj_rib_out_may_have_all_its_destinations_wait() {
        // The bound follows the most routes the Adj-RIB-Out held: a table
        // larger than MIN_WAITING withdrawn at once is remembered whole.
        let mut out = AdjRibOut::default();
        let a = route(1);
        let n = u32::try_from(MIN_WAITING).unwrap() * 2;
        let prefixes: Vec<Prefix> = (0..n)
            .map(|i| pfx(&format!("10.{}.{}.0/24", i >> 8, i & 0xff)))
            .collect();
        for &p in &prefixes {
            offer(&mut out, p, Some(&a), 0);
        }
        for &p in &prefixes {
            let step = offer_queued(&mut out, p, None, 1);
            assert_eq!(
                step,
                Step::Withdraw {
                    forget: Some(Tick(30))
                }
            );
        }
        assert_eq!(out.withdrawn.len(), prefixes.len());
    }

    #[test]
    fn a_withdrawal_after_the_interval_is_not_remembered() {
        let mut out = AdjRibOut::default();
        let p = pfx("192.0.2.0/24");
        offer(&mut out, p, Some(&route(1)), 0);
        assert_eq!(
            offer(&mut out, p, None, 40),
            Step::Withdraw { forget: None }
        );
        assert_eq!(out.withdrawn.len(), 0);
    }

    #[test]
    fn destinations_are_paced_independently() {
        let mut out = AdjRibOut::default();
        let (p, q) = (pfx("192.0.2.0/24"), pfx("198.51.100.0/24"));
        offer(&mut out, p, Some(&route(1)), 0);
        assert_eq!(offer(&mut out, p, Some(&route(2)), 1), Step::Hold(Tick(30)));
        // q has its own interval: its first advertisement is not held, and
        // its next change waits for q's interval, not p's.
        let b = route(2);
        assert_eq!(offer(&mut out, q, Some(&b), 10), Step::Announce(b));
        assert_eq!(
            offer(&mut out, q, Some(&route(3)), 11),
            Step::Hold(Tick(40))
        );
    }

    #[test]
    fn interval_zero_turns_pacing_off() {
        let mut out = AdjRibOut::default();
        let p = pfx("192.0.2.0/24");
        for i in 0..5u32 {
            let r = route(i + 1);
            assert_eq!(
                offer_with(&mut out, p, Some(&r), 0, Duration::ZERO),
                Step::Announce(r)
            );
            assert_eq!(
                offer_with(&mut out, p, None, 0, Duration::ZERO),
                Step::Withdraw { forget: None }
            );
        }
        assert_eq!(out.held(), 0);
        assert_eq!(out.withdrawn.len(), 0);
    }

    #[test]
    fn jitter_shortens_the_interval_within_rfc_bounds() {
        // RFC 4271 §10: the factor is in [0.75, 1.0] and drawn anew each
        // time the timer is set.
        let mut j = Jitter::new(0x1234_5678_9abc_def0);
        let mut dues = std::collections::HashSet::new();
        for i in 0..200u32 {
            let mut out = AdjRibOut::default();
            let p = pfx("192.0.2.0/24");
            out.advertise(p, route(1), at(0));
            let mut pace = Pace {
                interval: IV,
                now: at(1),
                jitter: &mut j,
            };
            let Step::Hold(Tick(due)) = out.offer(p, Some(route(i + 2)), &mut pace) else {
                panic!("held");
            };
            assert!((23..=30).contains(&due), "{due}");
            dues.insert(due);
        }
        assert!(dues.len() > 3, "{dues:?}");
        assert_eq!(Jitter::new(0).apply(IV), IV);
    }

    #[test]
    fn readvertise_sends_everything_and_restarts_intervals() {
        let mut out = AdjRibOut::default();
        let (p, q) = (pfx("192.0.2.0/24"), pfx("198.51.100.0/24"));
        let (a, b) = (route(1), route(2));
        offer(&mut out, p, Some(&a), 0);
        offer(&mut out, q, Some(&a), 0);
        assert_eq!(offer(&mut out, p, Some(&b), 5), Step::Hold(Tick(30)));
        // A refresh at 10 carries p's latest route and drops q.
        let gone = out.readvertise(vec![(p, b.clone())], at(10));
        assert_eq!(gone, vec![q]);
        assert_eq!(out.held(), 0);
        assert_eq!(out.iter().collect::<Vec<_>>(), vec![(p, &b)]);
        // The interval runs from the refresh.
        assert_eq!(offer(&mut out, p, Some(&a), 20), Step::Hold(Tick(40)));
    }

    #[test]
    fn a_new_interval_moves_held_destinations() {
        let mut out = AdjRibOut::default();
        let p = pfx("192.0.2.0/24");
        offer(&mut out, p, Some(&route(1)), 0);
        offer(&mut out, p, Some(&route(2)), 1);
        let mut j = Jitter::new(0);
        let mut pace = Pace {
            interval: Duration::from_secs(5),
            now: at(2),
            jitter: &mut j,
        };
        assert_eq!(out.reschedule(&mut pace), vec![(p, Tick(5))]);
        pace.interval = Duration::ZERO;
        assert_eq!(out.reschedule(&mut pace), vec![(p, Tick(2))]);
        assert!(out.wake(p, Duration::ZERO, at(2)).release);
    }

    #[test]
    fn a_longer_interval_keeps_withdrawn_times_longer() {
        let mut out = AdjRibOut::default();
        let p = pfx("192.0.2.0/24");
        offer(&mut out, p, Some(&route(1)), 0);
        offer(&mut out, p, None, 1);
        // The wake-up planned for 30 finds a 60 s interval now.
        let w = out.wake(p, Duration::from_secs(60), at(30));
        assert_eq!(
            w,
            Wake {
                release: false,
                again: Some(Tick(60))
            }
        );
        assert_eq!(
            out.wake(p, Duration::from_secs(60), at(60)),
            Wake::default()
        );
        assert_eq!(out.withdrawn.len(), 0);
    }
}
