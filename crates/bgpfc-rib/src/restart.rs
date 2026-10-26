//! Graceful Restart in the RIB: the stale routes of a Receiving Speaker,
//! the deferral of route selection of a Restarting Speaker, and the
//! End-of-RIB marker that ends each family's initial update.
//!
//! Implements: RFC 4724 §2 and §4 (the End-of-RIB marker follows the
//! initial update of every family of a session whose capability we
//! advertised), §4.1 (a Restarting Speaker defers route selection for a
//! family until it has the End-of-RIB marker of every peer it waits for,
//! or a timer ends the wait, and only then updates the forwarding state and
//! advertises), §4.2 (a Receiving Speaker keeps the routes of a session
//! that ended as stale routing information, replaces them by what the peer
//! sends, removes them when the session does not come back in the Restart
//! Time, when the new session lacks the Forwarding State bit for their
//! family, and at the peer's End-of-RIB, and bounds the wait for it with a
//! timer); RFC 8538 §4.1 (routes still stale from an earlier session are
//! deleted only when the Graceful Notification bit was not exchanged, and
//! the stale timer is mandatory).
//!
//! A stale route is an ordinary route with a flag: the decision process,
//! the FIB and the other peers treat it like any other, as RFC 4724 §4.2
//! asks ("MUST NOT differentiate between stale and other routing
//! information during forwarding"). The peer keeps its slot, and so its
//! routes keep a valid owner, while its session is down.

use std::cmp::Reverse;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::AddressFamily;

use crate::store::{PeerId, Table};
use crate::{
    Destination, Output, PeerState, Phase2, Rib, Scratch, Sink, decide, drop_routes, merge_all,
    shrink_heap,
};

/// The routes of a session that ended and are kept as stale (RFC 4724
/// §4.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Retention {
    /// The families whose routes are kept: those the peer's Graceful
    /// Restart capability lists. The peer's routes of any other family go.
    pub families: Vec<AddressFamily>,
    /// The Restart Time the peer advertised: the time its session has to
    /// come back in, else the stale routes are deleted.
    pub restart_time: Duration,
    /// The Graceful Notification bit was exchanged: routes still stale from
    /// an earlier session stay so (RFC 8538 §4.1); otherwise they are
    /// deleted, "to deal with possible consecutive restarts" (RFC 4724
    /// §4.2).
    pub notification: bool,
}

/// Graceful Restart on a session for which we advertised the capability
/// (RFC 4724 §3): the End-of-RIB marker follows the initial update of each
/// family (§4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Restart {
    /// What the peer's capability said, if it advertised one.
    pub peer: Option<PeerRestart>,
    /// The longest stale routes are kept once the session is back, waiting
    /// for the peer's End-of-RIB (RFC 4724 §4.2, RFC 8538 §4.1).
    pub stale_time: Duration,
}

/// The peer's Graceful Restart capability, as far as the RIB acts on it
/// (RFC 4724 §3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerRestart {
    /// The Restart State bit: the peer has restarted, so we do not wait for
    /// its End-of-RIB before selecting routes (RFC 4724 §4.1).
    pub restarting: bool,
    /// The families it lists, each with its Forwarding State bit.
    pub families: Vec<(AddressFamily, bool)>,
}

impl PeerRestart {
    /// Whether the peer listed `family` with the Forwarding State bit.
    fn forwarding(&self, family: AddressFamily) -> bool {
        self.families.iter().any(|(f, fwd)| *f == family && *fwd)
    }
}

/// Why stale routes were removed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StaleEnd {
    /// The peer sent its End-of-RIB for the family: what it did not send
    /// again is gone (RFC 4724 §4.2).
    EndOfRib,
    /// The session did not come back in the Restart Time (RFC 4724 §4.2).
    RestartTimer,
    /// The stale timer ran out before the End-of-RIB (RFC 4724 §4.2,
    /// RFC 8538 §4.1).
    StaleTimer,
    /// The new session does not have the Forwarding State bit for the
    /// family, or lists neither it nor the capability (RFC 4724 §4.2).
    NoForwardingState,
    /// The session ended again before the End-of-RIB, and the Graceful
    /// Notification bit was not exchanged (RFC 4724 §4.2, RFC 8538 §4.1); or
    /// before the `EoRR` of a route refresh, whose routes still stale are not
    /// the up-to-date ones a restart should keep (RFC 7313 §4).
    Superseded,
    /// The peer ended a route refresh with its `EoRR`: the routes it did not
    /// send again in it go (RFC 7313 §4).
    EndOfRefresh,
    /// The time allowed for the `EoRR` of a route refresh ran out (RFC 7313
    /// §4: "MAY remove any routes from the peer that are still marked as
    /// stale for that `<AFI, SAFI>` without waiting for an `EoRR` message").
    RefreshTimer,
}

impl std::fmt::Display for StaleEnd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            StaleEnd::EndOfRib => "end-of-rib",
            StaleEnd::RestartTimer => "restart timer",
            StaleEnd::StaleTimer => "stale timer",
            StaleEnd::NoForwardingState => "no forwarding state",
            StaleEnd::Superseded => "session ended again",
            StaleEnd::EndOfRefresh => "end-of-refresh",
            StaleEnd::RefreshTimer => "refresh timer",
        })
    }
}

/// What a Restarting Speaker waits for before it selects routes (RFC 4724
/// §4.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Deferral {
    /// The peers whose End-of-RIB is waited for, with the families each is
    /// configured for. A family none of them speaks is not deferred.
    pub waiting: Vec<(IpAddr, Vec<AddressFamily>)>,
    /// When the wait ends whatever came: the `Selection_Deferral_Timer`.
    pub until: Instant,
}

/// A peer whose routes are kept as stale, for the control plane.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StalePeer {
    /// The peer.
    pub addr: IpAddr,
    /// Its session is down; otherwise it is up again and sending.
    pub down: bool,
    /// The families whose End-of-RIB is awaited.
    pub pending: Vec<AddressFamily>,
    /// Time left for the session to come back (RFC 4724 §4.2).
    pub restart_in: Option<Duration>,
    /// Time left before the stale routes go (RFC 8538 §4.1).
    pub stale_in: Option<Duration>,
}

/// A peer's stale routes and what ends them (kept in its `PeerState`).
#[derive(Debug)]
pub(crate) struct Stale {
    /// The families with stale routes whose End-of-RIB is awaited.
    pending: Vec<AddressFamily>,
    /// While the session is down, when it has to be back by.
    back_by: Option<Instant>,
    /// When the stale routes go whatever happens, once set: a session that
    /// ends and comes back does not start it again (RFC 8538 §9: repeated
    /// resets must not keep stale routes for ever).
    expires: Option<Instant>,
}

impl Stale {
    /// Whether the End-of-RIB of `family` is still awaited for its stale
    /// routes.
    pub(crate) fn awaits(&self, family: AddressFamily) -> bool {
        self.pending.contains(&family)
    }
}

/// The peers a deferred family waits for (kept in `Sessions`).
#[derive(Debug)]
pub(crate) struct Waiting {
    peers: Vec<IpAddr>,
    until: Instant,
}

/// A wake-up for Graceful Restart.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Timer {
    pub(crate) at: Instant,
    what: What,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum What {
    /// The session of the peer has to be back.
    Restart(PeerId),
    /// The stale routes of the peer go.
    Stale(PeerId),
    /// Route selection for the family stops being deferred.
    Deferral(AddressFamily),
    /// The stale routes a peer's route refresh of the family left go
    /// (RFC 7313 §4).
    Refresh(PeerId, AddressFamily),
}

impl crate::peer::PeerInfo {
    /// Whether the stale routes of `family` stay once this session is up:
    /// the peer lists the family with the Forwarding State bit, and we take
    /// its routes of it (RFC 4724 §4.2).
    fn keeps_stale(&self, family: AddressFamily) -> bool {
        self.restart
            .as_ref()
            .and_then(|r| r.peer.as_ref())
            .is_some_and(|p| p.forwarding(family))
            && self.receives(family)
    }
}

impl crate::Sessions {
    /// Whether route selection for `family` is deferred (RFC 4724 §4.1).
    pub(crate) fn deferred(&self, family: AddressFamily) -> bool {
        self.deferral.get(family).is_some()
    }

    /// Drop the wake-ups that `gone` names, so that the next deadline is
    /// the next one that will do something.
    fn cancel_timers(&mut self, gone: impl Fn(What) -> bool) {
        self.restart_timers.retain(|Reverse(t)| !gone(t.what));
        shrink_heap(&mut self.restart_timers);
    }

    /// Drop the time peer `id`'s session has to come back in.
    pub(crate) fn cancel_restart_timer(&mut self, id: PeerId) {
        self.cancel_timers(|w| w == What::Restart(id));
    }

    /// Drop the stale timer of peer `id`.
    fn cancel_stale_timer(&mut self, id: PeerId) {
        self.cancel_timers(|w| w == What::Stale(id));
    }

    /// Drop every wake-up for peer `id`, whose slot is free.
    pub(crate) fn cancel_peer_timers(&mut self, id: PeerId) {
        self.cancel_timers(
            |w| matches!(w, What::Restart(i) | What::Stale(i) | What::Refresh(i, _) if i == id),
        );
    }

    /// Wake up at `at` to remove the routes still stale from `id`'s route
    /// refresh of `family` (RFC 7313 §4).
    pub(crate) fn queue_refresh_timer(&mut self, at: Instant, id: PeerId, family: AddressFamily) {
        self.restart_timers.push(Reverse(Timer {
            at,
            what: What::Refresh(id, family),
        }));
    }

    /// Drop the wake-up for `id`'s route refresh of `family`, if there is
    /// one, or all of its refreshes' for `None`.
    pub(crate) fn cancel_refresh_timers(&mut self, id: PeerId, family: Option<AddressFamily>) {
        self.cancel_timers(
            |w| matches!(w, What::Refresh(i, f) if i == id && family.is_none_or(|g| g == f)),
        );
    }

    /// The state of `addr`, a peer that is down with its routes kept, taken
    /// out for a new session of the peer to take over (RFC 4724 §4.2). Its
    /// slot stays.
    pub(crate) fn take_retained(&mut self, addr: IpAddr) -> Option<PeerState> {
        let id = self.id(addr)?;
        let retained = self.peers[id.index()]
            .as_ref()
            .is_some_and(|p| p.leaving && p.stale.is_some());
        if retained {
            self.peers[id.index()].take()
        } else {
            None
        }
    }
}

impl Rib {
    /// The session of `addr` ended and its routes are kept as stale routing
    /// information, if it had any (RFC 4724 §4.2, RFC 8538 §4.1): those of
    /// the families in `retention`, which stay in the tables, and in the
    /// FIB, until the peer sends them again, sends its End-of-RIB, or a
    /// timer runs out. Its routes of other families go as in `peer_down`.
    /// How many routes are kept.
    ///
    /// The peer is down but for its routes; [`Rib::peer_up`] with a new
    /// session of it takes them over. Without the Graceful Notification bit
    /// in `retention`, routes still stale from an earlier session are
    /// deleted first.
    pub fn peer_retain(
        &mut self,
        addr: IpAddr,
        retention: &Retention,
        now: Instant,
        out: &mut impl Sink,
    ) -> usize {
        let Some(id) = self.s.up_id(addr) else {
            return 0;
        };
        self.s.tick(now);
        // Before anything is removed, so that nothing is sent to it.
        self.s.peer_mut(id).leaving = true;
        // RFC 7313 §4: a route refresh under way ends with the session. The
        // routes it left stale are among those kept below, where forwarding
        // goes on over them until the peer sends them again or its
        // End-of-RIB comes; none of them is a route "from an earlier
        // session" that RFC 4724 §4.2 deletes.
        if !self.s.peer(id).refreshing.is_empty() {
            self.s.peer_mut(id).refreshing.clear();
            self.s.cancel_refresh_timers(id, None);
        }
        let earlier = self.s.peer_mut(id).stale.take();
        if let Some(stale) = &earlier
            && !retention.notification
        {
            // RFC 4724 §4.2: "a route (from the peer) previously marked as
            // stale MUST be deleted." With the Graceful Notification bit
            // exchanged, RFC 8538 §4.1 keeps them: the marking below
            // leaves them stale.
            for family in stale.pending.clone() {
                self.drop_stale_family(id, family, StaleEnd::Superseded, now, out);
            }
        }
        let mut scratch = std::mem::take(&mut self.scratch);
        let mut kept = 0;
        let mut pending = Vec::new();
        for (family, table) in self.tables.iter_mut() {
            if retention.families.contains(&family) {
                let mut routes = 0;
                table.for_each_mut(|dest| routes += dest.set_stale(id, true));
                if routes > 0 {
                    pending.push(family);
                }
                kept += routes;
            } else {
                // Not a family the peer lists: nothing in RFC 4724 §4.2
                // keeps its routes.
                drop_routes(self.s.phase2(), table, family, id, &mut scratch);
            }
        }
        self.settle_counts(id, &mut scratch);
        merge_all(&mut scratch.dirty, &mut scratch.order);
        self.finish(&mut scratch, now, out);
        self.scratch = scratch;
        if kept == 0 {
            // Nothing to keep: the peer is gone as if its session had been
            // torn down.
            self.s.remove(addr);
            self.forget_waiting(addr, now, out);
            return 0;
        }
        // Whatever the session held for the peer goes, and the slot stays.
        let Some(mut state) = self.s.peers[id.index()].take() else {
            return kept;
        };
        self.s.release_session(&mut state, id);
        let back_by = now + retention.restart_time;
        state.stale = Some(Stale {
            pending,
            back_by: Some(back_by),
            expires: earlier.and_then(|s| s.expires),
        });
        self.s.peers[id.index()] = Some(state);
        self.s.restart_timers.push(Reverse(Timer {
            at: back_by,
            what: What::Restart(id),
        }));
        kept
    }

    /// The peer sent its End-of-RIB marker for `family` (RFC 4724 §2): the
    /// routes of it that are still stale go (§4.2), and a Restarting Speaker
    /// no longer waits for it (§4.1).
    pub fn end_of_rib(
        &mut self,
        addr: IpAddr,
        family: AddressFamily,
        now: Instant,
        out: &mut impl Sink,
    ) {
        let Some(id) = self.s.up_id(addr) else {
            return;
        };
        // RFC 7313 §4: from now on a BoRR for the family is taken.
        self.s
            .peer_mut(id)
            .awaiting_end_of_rib
            .retain(|f| *f != family);
        let pending = self.s.peer_mut(id).stale.as_mut().is_some_and(|stale| {
            let before = stale.pending.len();
            stale.pending.retain(|f| *f != family);
            stale.pending.len() != before
        });
        if pending {
            // RFC 4724 §4.2: "MUST immediately remove any routes from the
            // peer that are still marked as stale for that address family."
            self.drop_stale_family(id, family, StaleEnd::EndOfRib, now, out);
            let state = self.s.peer_mut(id);
            if state.stale.as_ref().is_some_and(|s| s.pending.is_empty()) {
                // Nothing stale is left to wait for or to time out.
                state.stale = None;
                self.s.cancel_stale_timer(id);
            }
        }
        let waiting = self
            .s
            .deferral
            .get_mut(family)
            .is_some_and(|w| w.peers.contains(&addr));
        if waiting {
            self.stop_waiting(addr, family, now, out);
        }
    }

    /// Start deferring route selection (RFC 4724 §4.1), as a Restarting
    /// Speaker does until the peers in `deferral` have sent their End-of-RIB
    /// or its timer ends the wait. For each family a waiting peer speaks:
    /// routes are kept in the tables, but the FIB and the peers are told
    /// nothing, and no peer is sent a table. Then [`Output::SelectionDone`]
    /// comes, and the tables go out, each followed by the End-of-RIB marker.
    pub fn defer_selection(&mut self, deferral: &Deferral) {
        let mut families: Vec<AddressFamily> = deferral
            .waiting
            .iter()
            .flat_map(|(_, f)| f.iter().copied())
            .collect();
        families.sort();
        families.dedup();
        for family in families {
            let peers: Vec<IpAddr> = deferral
                .waiting
                .iter()
                .filter(|(_, f)| f.contains(&family))
                .map(|(addr, _)| *addr)
                .collect();
            self.s.deferral.insert(
                family,
                Waiting {
                    peers,
                    until: deferral.until,
                },
            );
            self.s.restart_timers.push(Reverse(Timer {
                at: deferral.until,
                what: What::Deferral(family),
            }));
        }
    }

    /// The families whose route selection is deferred, how many peers are
    /// still waited for, and when the wait ends whatever comes, for the
    /// control plane.
    #[must_use]
    pub fn deferred(&self) -> Vec<(AddressFamily, usize, Instant)> {
        let mut v: Vec<_> = self
            .s
            .deferral
            .iter()
            .map(|(f, w)| (f, w.peers.len(), w.until))
            .collect();
        v.sort();
        v
    }

    /// Every destination's next hop in `family`, as the FIB wants it, in
    /// prefix order (what `bgpfc_fib::Routes::merge` takes).
    pub fn fib_routes_of(&self, family: AddressFamily) -> impl Iterator<Item = (Prefix, IpAddr)> {
        self.tables
            .get(family)
            .into_iter()
            .flat_map(|t| t.after(None))
            .filter_map(|(p, d)| d.best().map(|r| (p, r.attrs.next_hop_addr())))
    }

    /// The peers whose routes are kept as stale, at `now`.
    #[must_use]
    pub fn stale_peers(&self, now: Instant) -> Vec<StalePeer> {
        let left = |t: Option<Instant>| t.map(|t| t.saturating_duration_since(now));
        self.s
            .peers
            .iter()
            .flatten()
            .filter_map(|p| {
                let s = p.stale.as_ref()?;
                // In the order of the families, whatever order the tables
                // were made in.
                let mut pending = s.pending.clone();
                pending.sort();
                Some(StalePeer {
                    addr: p.info.addr,
                    down: p.leaving,
                    pending,
                    restart_in: left(s.back_by),
                    stale_in: left(s.expires),
                })
            })
            .collect()
    }

    /// How many routes of each family `addr` has that are stale. Walks the
    /// tables: for a report on a peer that is known to have some.
    #[must_use]
    pub fn stale_routes(&self, addr: IpAddr) -> Vec<(AddressFamily, usize)> {
        let Some(id) = self.s.id(addr) else {
            return Vec::new();
        };
        let mut counts: Vec<_> = self
            .tables
            .iter()
            .map(|(family, table)| {
                let n = table
                    .after(None)
                    .filter(|(_, d)| d.position_stale(id).is_some())
                    .count();
                (family, n)
            })
            .filter(|(_, n)| *n > 0)
            .collect();
        counts.sort();
        counts
    }

    /// A session came up for a peer that has stale routes from an earlier
    /// one: keep them, with a stale timer, in the families where the peer
    /// says it preserved forwarding state, and delete the rest at once
    /// (RFC 4724 §4.2).
    pub(crate) fn resume_stale(&mut self, addr: IpAddr, now: Instant, out: &mut impl Sink) {
        let Some(id) = self.s.up_id(addr) else {
            return;
        };
        let Some(stale) = self.s.peer_mut(id).stale.take() else {
            return;
        };
        // The session is back in time.
        self.s.cancel_restart_timer(id);
        let info = &self.s.peer(id).info;
        let stale_time = info.restart.as_ref().map(|r| r.stale_time);
        let (keep, gone): (Vec<_>, Vec<_>) = stale
            .pending
            .iter()
            .copied()
            .partition(|f| info.keeps_stale(*f));
        for family in gone {
            // RFC 4724 §4.2: "if the "Forwarding State" bit for a specific
            // address family is not set in the newly received Graceful
            // Restart Capability, or if a specific address family is not
            // included in the newly received Graceful Restart Capability,
            // or if the Graceful Restart Capability is not received in the
            // re-established session at all, then the Receiving Speaker
            // MUST immediately remove all the stale routes from the peer
            // that it is retaining for that address family."
            self.drop_stale_family(id, family, StaleEnd::NoForwardingState, now, out);
        }
        let Some(stale_time) = stale_time.filter(|_| !keep.is_empty()) else {
            self.s.cancel_stale_timer(id);
            return;
        };
        // RFC 8538 §4.1: a timer bounds the wait for the End-of-RIB. Set
        // once for as long as routes stay stale (RFC 8538 §9).
        let started = stale.expires.is_none();
        let expires = stale.expires.unwrap_or(now + stale_time);
        self.s.peer_mut(id).stale = Some(Stale {
            pending: keep,
            back_by: None,
            expires: Some(expires),
        });
        if started {
            self.s.restart_timers.push(Reverse(Timer {
                at: expires,
                what: What::Stale(id),
            }));
        }
    }

    /// Send `addr` the initial update of `family` and, if we advertised
    /// Graceful Restart to it, the End-of-RIB marker that ends it (RFC 4724
    /// §4: "once it completes the initial routing update (including the
    /// case when there is no update to send) for an address family after the
    /// BGP session is established").
    pub(crate) fn start_family(
        &mut self,
        addr: IpAddr,
        family: AddressFamily,
        now: Instant,
        out: &mut impl Sink,
    ) {
        let Some(id) = self.s.up_id(addr) else {
            return;
        };
        // The initial update is no route refresh, and RFC 7313 §4 has no
        // `BoRR` before it.
        if self.can_advertise(id, family) {
            self.advertise(id, family, now, out);
        }
        let info = &self.s.peer(id).info;
        if info.restart.is_none() || !info.speaks(family) {
            return;
        }
        match crate::export::end_of_rib(family, info) {
            Ok(message) => out.put(Output::Send {
                peer: addr,
                messages: vec![message],
            }),
            Err(error) => out.put(Output::EncodeFailed { peer: addr, error }),
        }
    }

    /// A session came up: a Restarting Speaker stops waiting for a peer
    /// that will not send an End-of-RIB (RFC 4724 §4.1): "excluding the ones
    /// with the "Restart State" bit set in the received capability and
    /// excluding the ones that do not advertise the graceful restart
    /// capability", and one that does not list the family.
    pub(crate) fn note_peer_up(&mut self, addr: IpAddr, now: Instant, out: &mut impl Sink) {
        if self.s.deferral.is_empty() {
            return;
        }
        let Some(id) = self.s.up_id(addr) else {
            return;
        };
        let info = &self.s.peers[id.index()]
            .as_ref()
            // invariant: `up_id` found the slot occupied.
            .unwrap()
            .info;
        let mut excluded = Vec::new();
        for (family, waiting) in self.s.deferral.iter() {
            if waiting.peers.contains(&addr) {
                // A peer that advertised the capability sends the marker of
                // every family it exchanges, whether or not its tuples
                // list the family (§4: it is "to indicate its intention of
                // generating the End-of-RIB marker").
                let waits = info.speaks(family)
                    && info
                        .restart
                        .as_ref()
                        .and_then(|r| r.peer.as_ref())
                        .is_some_and(|p| !p.restarting);
                if !waits {
                    excluded.push(family);
                }
            }
        }
        for family in excluded {
            self.stop_waiting(addr, family, now, out);
        }
    }

    /// `addr` is gone for good: nothing waits for it any more.
    pub(crate) fn forget_waiting(&mut self, addr: IpAddr, now: Instant, out: &mut impl Sink) {
        if self.s.deferral.is_empty() {
            return;
        }
        let families: Vec<AddressFamily> = self
            .s
            .deferral
            .iter()
            .filter(|(_, w)| w.peers.contains(&addr))
            .map(|(f, _)| f)
            .collect();
        for family in families {
            self.stop_waiting(addr, family, now, out);
        }
    }

    /// `addr` is no longer waited for in `family`; with nobody left to wait
    /// for, route selection goes ahead.
    fn stop_waiting(
        &mut self,
        addr: IpAddr,
        family: AddressFamily,
        now: Instant,
        out: &mut impl Sink,
    ) {
        let Some(waiting) = self.s.deferral.get_mut(family) else {
            return;
        };
        waiting.peers.retain(|p| *p != addr);
        if waiting.peers.is_empty() {
            self.end_deferral(family, now, out);
        }
    }

    /// Route selection for `family` stops being deferred (RFC 4724 §4.1):
    /// tell the caller to bring the forwarding state up to date, then send
    /// every peer its table, each ended by the End-of-RIB marker.
    fn end_deferral(&mut self, family: AddressFamily, now: Instant, out: &mut impl Sink) {
        self.s.deferral.remove(family);
        self.s.cancel_timers(|w| w == What::Deferral(family));
        out.put(Output::SelectionDone { family });
        let up: Vec<IpAddr> = self
            .s
            .peers
            .iter()
            .flatten()
            .filter(|p| !p.leaving && p.info.speaks(family))
            .map(|p| p.info.addr)
            .collect();
        for addr in up {
            self.start_family(addr, family, now, out);
        }
    }

    /// Act on the wake-ups that are due: a session that did not come back
    /// in its Restart Time, stale routes kept long enough, a deferral that
    /// has gone on long enough.
    pub(crate) fn expire_restart(&mut self, now: Instant, out: &mut impl Sink) {
        while let Some(&Reverse(timer)) = self.s.restart_timers.peek() {
            if timer.at > now {
                break;
            }
            self.s.restart_timers.pop();
            match timer.what {
                What::Restart(id) => {
                    self.restart_expired(id, timer.at, StaleEnd::RestartTimer, now, out);
                }
                What::Stale(id) => self.stale_expired(id, timer.at, now, out),
                What::Refresh(id, family) => self.refresh_expired(id, family, timer.at, now, out),
                What::Deferral(family) => {
                    if self
                        .s
                        .deferral
                        .get(family)
                        .is_some_and(|w| w.until == timer.at)
                    {
                        self.end_deferral(family, now, out);
                    }
                }
            }
        }
        shrink_heap(&mut self.s.restart_timers);
    }

    /// The session of a peer did not come back in time, or the stale routes
    /// of a peer whose session is down were kept long enough: all the
    /// peer's routes go (RFC 4724 §4.2).
    fn restart_expired(
        &mut self,
        id: PeerId,
        at: Instant,
        why: StaleEnd,
        now: Instant,
        out: &mut impl Sink,
    ) {
        let Some(Some(state)) = self.s.peers.get(id.index()) else {
            return;
        };
        let due = state.leaving
            && state
                .stale
                .as_ref()
                .is_some_and(|s| s.back_by == Some(at) || s.expires == Some(at));
        if !due {
            return;
        }
        let addr = state.info.addr;
        let routes = state.adj_in_count.values().sum();
        self.peer_down(addr, now, out);
        out.put(Output::StaleRemoved {
            peer: addr,
            family: None,
            routes,
            why,
        });
    }

    /// The stale timer of a peer ran out (RFC 8538 §4.1).
    fn stale_expired(&mut self, id: PeerId, at: Instant, now: Instant, out: &mut impl Sink) {
        let Some(Some(state)) = self.s.peers.get(id.index()) else {
            return;
        };
        let Some(kept) = state.stale.as_ref().filter(|s| s.expires == Some(at)) else {
            return;
        };
        if state.leaving {
            // The session went down again with the timer running: the
            // peer's routes go with the rest.
            self.restart_expired(id, at, StaleEnd::StaleTimer, now, out);
            return;
        }
        let pending = kept.pending.clone();
        self.s.peer_mut(id).stale = None;
        for family in pending {
            self.drop_stale_family(id, family, StaleEnd::StaleTimer, now, out);
        }
    }

    /// Remove the stale routes `id` has in `family` (RFC 4724 §4.2, RFC 7313
    /// §4), with the FIB changes and UPDATEs that follow. How many.
    pub(crate) fn drop_stale_family(
        &mut self,
        id: PeerId,
        family: AddressFamily,
        why: StaleEnd,
        now: Instant,
        out: &mut impl Sink,
    ) -> usize {
        let mut scratch = std::mem::take(&mut self.scratch);
        if let Some(table) = self.tables.get_mut(family) {
            drop_stale(self.s.phase2(), table, family, id, &mut scratch);
        }
        let routes = scratch.delta.get(family).map_or(0, |d| d.unsigned_abs());
        self.settle_counts(id, &mut scratch);
        merge_all(&mut scratch.dirty, &mut scratch.order);
        let peer = self.s.peer(id).info.addr;
        out.put(Output::StaleRemoved {
            peer,
            family: Some(family),
            routes,
            why,
        });
        self.finish(&mut scratch, now, out);
        self.scratch = scratch;
        routes
    }

    /// Add what removals counted in `scratch` to the number of routes the
    /// Adj-RIB-In holds for `id`.
    fn settle_counts(&mut self, id: PeerId, scratch: &mut Scratch) {
        let state = self.s.peer_mut(id);
        for (family, d) in scratch.delta.iter_mut() {
            let n = state.adj_in_count.or_default(family);
            *n = n.saturating_add_signed(*d);
            *d = 0;
        }
    }
}

/// Remove every stale route `id` sent from `table`, a table of `family`,
/// noting each destination's best route before and after.
fn drop_stale(
    p2: Phase2<'_>,
    table: &mut Table,
    family: AddressFamily,
    id: PeerId,
    scratch: &mut Scratch,
) {
    table.retain(|prefix, dest: &mut Destination| {
        if let Some(mut i) = dest.position_stale(id) {
            let old = dest.best().cloned();
            // A peer sent with ADD-PATH has a stale route for each path.
            loop {
                let removed = dest.remove(i);
                scratch.released.push(removed.attrs);
                scratch.released.extend(removed.received);
                *scratch.delta.or_default(family) -= 1;
                if dest.is_empty() {
                    break;
                }
                match dest.position_stale(id) {
                    Some(next) => i = next,
                    None => break,
                }
            }
            decide(p2, dest);
            scratch.dirty.push(crate::Dirty {
                family,
                prefix,
                old,
                new: dest.best().cloned(),
                merged: false,
            });
        }
        !dest.is_empty()
    });
}
