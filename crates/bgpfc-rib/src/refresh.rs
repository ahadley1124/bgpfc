//! Enhanced Route Refresh in the RIB: the routes a peer's route refresh
//! leaves behind are removed, and a route refresh we make is bracketed.
//!
//! Implements: RFC 7313 §4 (a speaker that receives a `BoRR` marks all the
//! routes of the `<AFI, SAFI>` from that peer as stale; the routes the peer
//! sends meanwhile replace their stale ones; at the `EoRR` the routes still
//! stale are removed at once, and a locally configurable upper bound may
//! remove them sooner; an `EoRR` without a `BoRR` may be ignored and
//! logged; a speaker with the Graceful Restart capability of its neighbor
//! ignores a `BoRR` for a family before that neighbor's End-of-RIB; before
//! a refresh we make, locally initiated or asked for, we send a `BoRR`,
//! and after the whole Adj-RIB-Out an `EoRR`).
//!
//! The stale marking is the one Graceful Restart introduced: a stale route
//! is an ordinary route with a flag, which the decision process, the FIB
//! and the other peers treat like any other (`restart`). The flag is what
//! a `BoRR` sets and what a route sent again clears (the announcement
//! replaces the route, ADD-PATH paths one by one under their identifiers).
//! A family is never stale for both: Graceful Restart's marks are set
//! when a session ends, a refresh's while one is up, and a refresh is not
//! begun for a family whose End-of-RIB is awaited.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use bgpfc_wire::route_refresh::RouteRefreshMessage;
use bgpfc_wire::types::AddressFamily;

use crate::restart::StaleEnd;
use crate::store::PeerId;
use crate::{Output, Rib, Sink};

/// Why a message of a route refresh was ignored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefreshIgnored {
    /// A `BoRR` from a peer that advertised Graceful Restart, before its
    /// End-of-RIB for the family: "MUST ignore", and "SHOULD log an error
    /// of the condition" (RFC 7313 §4).
    BeforeEndOfRib,
    /// An `EoRR` with no `BoRR` before it: "MAY ignore", and "MAY be
    /// logged" (RFC 7313 §4).
    NoBegin,
}

impl std::fmt::Display for RefreshIgnored {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            RefreshIgnored::BeforeEndOfRib => "BoRR before the end-of-rib",
            RefreshIgnored::NoBegin => "EoRR without a BoRR",
        })
    }
}

/// A route refresh a peer has begun and not ended (kept in its
/// `PeerState`).
#[derive(Debug)]
pub(crate) struct Refreshing {
    pub(crate) family: AddressFamily,
    /// When the routes it left stale go whether or not its `EoRR` came; the
    /// wake-up for it is in the RIB's timers. `None` when the `BoRR` found
    /// no route of the peer to mark: nothing waits for the `EoRR` then, but
    /// the refresh is still one that was begun.
    pub(crate) expires: Option<Instant>,
}

/// A route refresh a peer has begun and not ended, for the control plane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RefreshReport {
    /// The peer.
    pub addr: IpAddr,
    /// The family.
    pub family: AddressFamily,
    /// Time left before the routes it left stale go whatever happens, if
    /// any are stale.
    pub stale_in: Option<Duration>,
}

impl Rib {
    /// The peer began a route refresh of `family` with a `BoRR` (RFC 7313
    /// §4): all its routes of the family are marked as stale, and are
    /// removed at its `EoRR`, or when the session's `stale_time` has run
    /// out, unless the peer sends them again. How many routes were marked.
    ///
    /// Marking changes no best path, so nothing is sent to the FIB or the
    /// other peers. Ignored, with [`Output::RefreshIgnored`] where the RFC
    /// asks for it to be logged, when the session has no Enhanced Route
    /// Refresh, or the peer advertised Graceful Restart and its End-of-RIB
    /// for the family has not come, or its routes of the family are stale
    /// from a session that ended (§4).
    pub fn refresh_begin(
        &mut self,
        addr: IpAddr,
        family: AddressFamily,
        now: Instant,
        out: &mut impl Sink,
    ) -> usize {
        let Some(id) = self.s.up_id(addr) else {
            return 0;
        };
        let state = self.s.peer(id);
        // RFC 7313 §4: "The following procedures are applicable only if a
        // BGP speaker has received the Enhanced Route Refresh Capability
        // from a peer."
        let Some(enhanced) = &state.info.enhanced_refresh else {
            return 0;
        };
        // Of a family we take no routes of, or have disabled (RFC 4760 §7),
        // none is held.
        if !state.info.receives(family) || state.disabled.contains(&family) {
            return 0;
        }
        // RFC 7313 §4: "A BGP speaker that has received the Graceful
        // Restart Capability from its neighbor MUST ignore any BoRRs for an
        // <AFI, SAFI> from the neighbor before the speaker receives the EoR
        // for the given <AFI, SAFI> from the neighbor." Routes that are
        // stale for waiting for that End-of-RIB (RFC 4724 §4.2) are the
        // same condition, and the mark is one flag.
        let stale_from_restart = state.stale.as_ref().is_some_and(|s| s.awaits(family));
        if state.awaiting_end_of_rib.contains(&family) || stale_from_restart {
            out.put(Output::RefreshIgnored {
                peer: addr,
                family,
                why: RefreshIgnored::BeforeEndOfRib,
            });
            return 0;
        }
        let stale_time = enhanced.stale_time;
        // "It MUST mark all the routes with the given AFI and SAFI from that
        // peer as stale." A peer with none has nothing to mark.
        let mut marked = 0;
        if state.received(family) > 0
            && let Some(table) = self.tables.get_mut(family)
        {
            table.for_each_mut(|dest| marked += dest.set_stale(id, true));
        }
        // A refresh begun again marks again, and its time starts over.
        self.s.cancel_refresh_timers(id, Some(family));
        let expires = (marked > 0).then(|| now + stale_time);
        let state = self.s.peer_mut(id);
        match state.refreshing.iter_mut().find(|r| r.family == family) {
            Some(r) => r.expires = expires,
            None => state.refreshing.push(Refreshing { family, expires }),
        }
        if let Some(at) = expires {
            self.s.queue_refresh_timer(at, id, family);
        }
        marked
    }

    /// The peer ended a route refresh of `family` with an `EoRR` (RFC 7313
    /// §4): "it MUST immediately remove any routes from the peer that are
    /// still marked as stale for that `<AFI, SAFI>`". With no `BoRR` before
    /// it, it is ignored, and [`Output::RefreshIgnored`] says so.
    pub fn refresh_end(
        &mut self,
        addr: IpAddr,
        family: AddressFamily,
        now: Instant,
        out: &mut impl Sink,
    ) {
        let Some(id) = self.s.up_id(addr) else {
            return;
        };
        let state = self.s.peer_mut(id);
        if state.info.enhanced_refresh.is_none() {
            return;
        }
        let Some(i) = state.refreshing.iter().position(|r| r.family == family) else {
            // "A BGP speaker MAY ignore any EoRR message received without a
            // prior receipt of an associated BoRR message."
            out.put(Output::RefreshIgnored {
                peer: addr,
                family,
                why: RefreshIgnored::NoBegin,
            });
            return;
        };
        let done = state.refreshing.swap_remove(i);
        if done.expires.is_some() {
            self.s.cancel_refresh_timers(id, Some(family));
            self.drop_stale_family(id, family, StaleEnd::EndOfRefresh, now, out);
        }
    }

    /// The time allowed for a route refresh's `EoRR` ran out (RFC 7313 §4:
    /// "Once the upper bound is reached, the implementation MAY remove any
    /// routes from the peer that are still marked as stale for that
    /// `<AFI, SAFI>` without waiting for an `EoRR` message"). A refresh that
    /// ended or began again meanwhile is not the one `at` was set for.
    pub(crate) fn refresh_expired(
        &mut self,
        id: PeerId,
        family: AddressFamily,
        at: Instant,
        now: Instant,
        out: &mut impl Sink,
    ) {
        let Some(Some(state)) = self.s.peers.get_mut(id.index()) else {
            return;
        };
        let Some(i) = state
            .refreshing
            .iter()
            .position(|r| r.family == family && r.expires == Some(at))
        else {
            return;
        };
        // Past the bound the refresh is over: an `EoRR` that comes later is
        // one without a `BoRR`.
        state.refreshing.swap_remove(i);
        self.drop_stale_family(id, family, StaleEnd::RefreshTimer, now, out);
    }

    /// The route refreshes peers have begun and not ended, at `now`, by
    /// peer and family.
    #[must_use]
    pub fn refreshes(&self, now: Instant) -> Vec<RefreshReport> {
        let mut reports: Vec<RefreshReport> = self
            .s
            .peers
            .iter()
            .flatten()
            .flat_map(|p| {
                p.refreshing.iter().map(|r| RefreshReport {
                    addr: p.info.addr,
                    family: r.family,
                    stale_in: r.expires.map(|t| t.saturating_duration_since(now)),
                })
            })
            .collect();
        reports.sort_by_key(|r| (r.addr, r.family));
        reports
    }
}

/// Queue the `BoRR` or `EoRR` `message` for `addr`, framed, among the
/// outputs of a route refresh (RFC 7313 §4).
pub(crate) fn mark(addr: IpAddr, message: RouteRefreshMessage, out: &mut impl Sink) {
    out.put(Output::Send {
        peer: addr,
        messages: vec![message.frame()],
    });
}
