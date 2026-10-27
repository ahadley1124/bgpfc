//! Import policy run again over the routes the Adj-RIBs-In kept, after it
//! changed (a reload): no ROUTE-REFRESH is needed for them, and the peer
//! is asked again only for what import policy dropped earlier.
//!
//! Implements: RFC 4271 §3 ("To allow local policy changes to have the
//! correct effect without resetting any BGP connections, a BGP speaker
//! SHOULD either (a) retain the current version of the routes advertised
//! to it by all of its peers for the duration of the connection, or (b)
//! make use of the Route Refresh extension"): (a) for the routes kept,
//! held ones included (§3.2, RFC 6811 §2), and (b) for those a policy
//! rejects whatever their validation state, which are not kept (see
//! `judge`); RFC 2918 §4 (only a peer that advertised the capability is
//! asked, and only for a family it advertised); RFC 4271 §9.1 (the
//! decision process runs for the destinations whose routes changed, and
//! Phase 3 tells the peers, paced by §9.2.1.1 like any other change).

use std::net::IpAddr;
use std::time::Instant;

use bgpfc_wire::types::AddressFamily;

use crate::validation::{Rejudge, best_changed};
use crate::{Output, PeerState, Rib, Sink};

/// What importing routes again after a change of import policy did (see
/// [`Rib::reimport`]), for the caller to log: counts, as for a
/// [`Rejudged`](crate::Rejudged), and which families the peers are asked
/// for again.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Reimport {
    /// The peers whose routes were imported again: those named that are
    /// up, in the order named.
    pub peers: Vec<IpAddr>,
    /// Their routes held in the Adj-RIBs-In, each put through import
    /// policy again, as received, with the validation state it has.
    pub routes: usize,
    /// Routes the new policy makes something else of: other attributes,
    /// another state set, used where they were held or held where they
    /// were used, or not kept.
    pub changed: usize,
    /// Routes it took out of use: candidates before, held after.
    pub held: usize,
    /// Routes it put back into use: held before, candidates after.
    pub released: usize,
    /// Routes it rejects whatever their validation state: no longer kept,
    /// like those it rejects on arrival.
    pub dropped: usize,
    /// Destinations where the decision process then chose another route,
    /// or none.
    pub best_changed: usize,
    /// The peers and families whose Adj-RIB-In lacks routes import policy
    /// dropped earlier, which the new one may take: each peer is asked for
    /// them again with ROUTE-REFRESH ([`Output::RequestRoutes`], RFC 2918
    /// §4).
    pub refresh: Vec<(IpAddr, AddressFamily)>,
    /// Those that cannot be asked for: the peer did not advertise the
    /// Route Refresh Capability, or did not advertise the family (RFC
    /// 2918 §4). Their routes come back only when the peer sends them
    /// again, or the session starts again.
    pub missing: Vec<(IpAddr, AddressFamily)>,
}

impl Rib {
    /// The import policy of the peers in `peers` changed (a reload, after
    /// [`Rib::set_policies`] has replaced the policies and exported again
    /// to the peers whose export policy changed): put every route they
    /// sent that the Adj-RIBs-In hold, held ones included, through the
    /// policy now in use again, as received and with the validation state
    /// it has, and run the decision process for every destination whose
    /// routes changed. A route the policy now changes otherwise is used
    /// so; one it rejects for its state alone is held ([`crate::Held`]); one
    /// it rejects whatever the state is dropped, as on arrival; one it
    /// takes again is used again; all with no UPDATE and no ROUTE-REFRESH
    /// (RFC 4271 §3 (a)). What follows comes out after one
    /// [`Output::Reimported`] that counts it: FIB changes, and UPDATEs
    /// sent or held back by the RFC 4271 §9.2.1.1 pacing, as for an
    /// UPDATE.
    ///
    /// A route import policy rejected whatever its state was not kept,
    /// and only the peer can send it again (RFC 4271 §3 (b)). For each
    /// family import policy dropped a route of since the session came up,
    /// or since the peer was last asked, an [`Output::RequestRoutes`]
    /// follows, which the caller turns into a ROUTE-REFRESH (RFC 2918 §4),
    /// if the peer advertised the capability and the family; the routes it
    /// brings back meet the policy in use as they arrive. Families it
    /// cannot ask for are reported as [`Reimport::missing`].
    ///
    /// Peers that are not up are skipped; nothing happens when none is.
    /// Export changes need nothing of this: what peers are sent comes
    /// from the Loc-RIB ([`Rib::set_policies`]).
    pub fn reimport(&mut self, peers: &[IpAddr], now: Instant, out: &mut impl Sink) {
        let mut selected = vec![false; self.s.peers.len()];
        let mut report = Reimport::default();
        let mut requests = Vec::new();
        for &addr in peers {
            let Some(id) = self.s.id(addr) else {
                continue;
            };
            if std::mem::replace(&mut selected[id.index()], true) {
                continue;
            }
            report.peers.push(addr);
            let families = to_ask(self.s.peer_mut(id), &mut report);
            if !families.is_empty() {
                requests.push(Output::RequestRoutes {
                    peer: addr,
                    families,
                });
            }
        }
        if report.peers.is_empty() {
            return;
        }
        let mut scratch = std::mem::take(&mut self.scratch);
        let tally = self.walk(None, Rejudge::Import(&selected), &mut scratch);
        report.routes = tally.routes;
        report.changed = tally.changed;
        report.held = tally.held;
        report.released = tally.released;
        report.dropped = tally.dropped;
        report.best_changed = best_changed(&scratch.dirty);
        out.put(Output::Reimported(report));
        self.finish(&mut scratch, now, out);
        self.scratch = scratch;
        for r in requests {
            out.put(r);
        }
    }
}

/// The families of `state`'s peer to ask for again, before its routes
/// are imported again: those import policy dropped a route of, which the
/// peer advertised along with the Route Refresh Capability (RFC 2918 §4).
/// They are forgotten, so that a route the policy in use drops, in the
/// walk that follows or as the peer sends it again, notes the family
/// anew. Those the peer cannot be asked for stay noted, and go to
/// `report` as missing; a family disabled for the session (RFC 4760 §7)
/// takes no routes and is forgotten.
fn to_ask(state: &mut PeerState, report: &mut Reimport) -> Vec<AddressFamily> {
    let PeerState {
        info,
        disabled,
        filtered,
        ..
    } = state;
    let mut ask = Vec::new();
    filtered.retain(|&family| {
        if disabled.contains(&family) {
            false
        } else if info.route_refresh && info.speaks(family) {
            report.refresh.push((info.addr, family));
            ask.push(family);
            false
        } else {
            report.missing.push((info.addr, family));
            true
        }
    });
    ask
}
