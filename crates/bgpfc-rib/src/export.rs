//! Phase 3: what a best route looks like when sent to a peer, and how
//! routes are packed into UPDATE messages (RFC 4271 §9.1.3, §9.2).
//!
//! Implements: RFC 4271 §5.1.2 (`AS_PATH` prepend on external sessions),
//! §5.1.3 (`NEXT_HOP` to external peers), §5.1.4 (MED is not propagated to
//! other neighboring ASes), §5.1.5 (`LOCAL_PREF` only to internal peers),
//! §9.2 (no internal-to-internal redistribution), §9.2 and §4.1 (message
//! size); RFC 1997 (`NO_EXPORT`, `NO_ADVERTISE`); RFC 4360 §6
//! (non-transitive extended communities stay in the AS); RFC 2545 §3
//! (IPv6 next hops, never with a link-local address, as bgpfc cannot tell
//! whether a subnet is shared); RFC 8654 §4 (65535-octet UPDATEs); RFC
//! 8950 §4 (an IPv6 next hop for IPv4 NLRI only to a peer that advertised
//! it), §5 (our own address is of the session's protocol; a next hop
//! passed on keeps its encoding).

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::net::IpAddr;
use std::sync::Arc;

use bgpfc_wire::community::{Community, ExtendedCommunity};
use bgpfc_wire::error::EncodeError;
use bgpfc_wire::header::{HEADER_LEN, MessageType, frame};
use bgpfc_wire::mp::{MpUnreach, NextHop};
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::{AddressFamily, Asn};
use bgpfc_wire::update::{EncodeContext, PeerKind, UpdateMessage};

use crate::attrs::PathAttrs;
use crate::decision::DEFAULT_LOCAL_PREF;
use crate::peer::PeerInfo;

/// Where a Loc-RIB route came from, for the export rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Source {
    /// The peer it was learned from.
    pub peer: IpAddr,
    /// Internal or external.
    pub kind: PeerKind,
}

/// Whether a route from `source` may be advertised to `to` at all,
/// before any policy: the family is negotiated, it is not the source peer,
/// and it is not internal-to-internal.
#[must_use]
pub fn eligible(family: AddressFamily, source: Source, to: &PeerInfo) -> bool {
    if !to.speaks(family) {
        return false;
    }
    // NOTE(interop): RFC 4271 does not forbid advertising a route back to
    // the peer it came from (the receiver's AS-loop check drops it), but
    // BIRD and FRR do not, and neither do we.
    if source.peer == to.addr {
        return false;
    }
    // RFC 4271 §9.2: a route learned from an internal peer is not
    // redistributed to other internal peers (no route reflection).
    !(source.kind == PeerKind::Internal && to.kind == PeerKind::Internal)
}

/// The attributes to advertise to `to`, or `None` when the route is not
/// advertised to that peer at all. `local_as` is our AS.
#[must_use]
pub fn export(
    local_as: Asn,
    family: AddressFamily,
    source: Source,
    attrs: &PathAttrs,
    to: &PeerInfo,
) -> Option<PathAttrs> {
    if !eligible(family, source, to) || !permitted(family, attrs, to) {
        return None;
    }
    Some(rewrite(local_as, family, attrs, to))
}

/// Whether attributes allow a route of `family` to `to` at all: RFC 1997
/// `NO_ADVERTISE` goes nowhere; `NO_EXPORT` and `NO_EXPORT_SUBCONFED` stay
/// inside the AS (no confederations here). RFC 8950 §4: an IPv6 next hop
/// for IPv4 NLRI goes only to a peer that advertised the capability for
/// the family, and §5: a next hop passed on unchanged keeps its encoding,
/// so a peer that cannot take it does not get the route at all.
#[must_use]
pub fn permitted(family: AddressFamily, attrs: &PathAttrs, to: &PeerInfo) -> bool {
    if attrs.has_community(Community::NO_ADVERTISE) {
        return false;
    }
    if to.kind == PeerKind::External
        && (attrs.has_community(Community::NO_EXPORT)
            || attrs.has_community(Community::NO_EXPORT_SUBCONFED))
    {
        return false;
    }
    // Our own address, when the rewrite puts it there, is one the peer
    // takes (see `rewrite`).
    !keeps_next_hop(family, to) || to.takes_next_hop(family, &attrs.next_hop)
}

/// Whether the session rewrite leaves the `NEXT_HOP` as received: an
/// external session overwrites it with our address when that is of the
/// NLRI's family, or an IPv6 one for IPv4 NLRI under RFC 8950.
fn keeps_next_hop(family: AddressFamily, to: &PeerInfo) -> bool {
    !(to.kind == PeerKind::External
        && match (family, to.local_addr) {
            (AddressFamily::IPV4_UNICAST, IpAddr::V4(_))
            | (AddressFamily::IPV6_UNICAST, IpAddr::V6(_)) => true,
            (AddressFamily::IPV4_UNICAST, IpAddr::V6(_)) => to.extended_next_hop.contains(&family),
            _ => false,
        })
}

/// What `attrs` become on the session to `to` (RFC 4271 §5.1): the
/// attributes an UPDATE to that peer carries. `local_as` is our AS.
#[must_use]
pub fn rewrite(
    local_as: Asn,
    family: AddressFamily,
    attrs: &PathAttrs,
    to: &PeerInfo,
) -> PathAttrs {
    let mut out = attrs.clone();
    match to.kind {
        PeerKind::External => {
            // RFC 4271 §5.1.2 c): prepend our AS. RFC 9774 §5: as a
            // sequence; never a set.
            out.as_path = attrs.as_path.prepend(local_as);
            // RFC 4271 §5.1.3: the next hop is our address on the session
            // when it is of the NLRI's family (RFC 2545 §3 for IPv6). RFC
            // 8950 §5: on a session over IPv6 our own address is an IPv6
            // one, which IPv4 NLRI may carry to a peer that advertised RFC
            // 8950 §4 Extended Next Hop Encoding, where we did too.
            // NOTE(interop): otherwise, for a family the session address
            // does not belong to (IPv4 routes over an IPv6 session), the
            // next hop is left as received, as BIRD does without RFC 8950.
            out.next_hop = match (family, to.local_addr) {
                (AddressFamily::IPV4_UNICAST, IpAddr::V4(a)) => NextHop::Ipv4(a),
                (AddressFamily::IPV4_UNICAST, IpAddr::V6(a))
                    if to.extended_next_hop.contains(&family) =>
                {
                    NextHop::Ipv6 {
                        global: a,
                        link_local: None,
                    }
                }
                (AddressFamily::IPV6_UNICAST, IpAddr::V6(a)) => NextHop::Ipv6 {
                    global: a,
                    link_local: None,
                },
                _ => attrs.next_hop,
            };
            // RFC 4271 §5.1.4: a MED received from a neighboring AS is not
            // propagated to other neighboring ASes.
            out.med = None;
            // RFC 4271 §5.1.5: LOCAL_PREF is never sent to external peers.
            out.local_pref = None;
            // RFC 4360 §6: non-transitive extended communities stay in
            // the AS.
            if out.ext_communities.iter().any(|c| !c.is_transitive()) {
                out.ext_communities = out
                    .ext_communities
                    .iter()
                    .copied()
                    .filter(|c| c.is_transitive())
                    .collect();
            }
        }
        PeerKind::Internal => {
            // RFC 4271 §5.1.2 b), §5.1.3, §5.1.4: AS_PATH, NEXT_HOP and MED
            // are passed on unchanged. §5.1.5: LOCAL_PREF is included,
            // computed as the degree of preference.
            out.local_pref = Some(attrs.local_pref.unwrap_or(DEFAULT_LOCAL_PREF));
        }
    }
    // RFC 2545 §3: "The link-local address shall be included in the Next
    // Hop field if and only if the BGP speaker shares a common subnet with
    // the entity identified by the global IPv6 address ... and the peer the
    // route is being advertised to." bgpfc tracks no interfaces and cannot
    // tell, so no link-local address goes out: a next hop passed on, to an
    // internal peer or in an IPv6 route over an IPv4 session, keeps its
    // global address only, which §3 itself allows towards an internal peer
    // ("may modify the Network Address of Next Hop field by removing the
    // link-local IPv6 address"). It stays IPv6, so RFC 8950 §5 still holds.
    // NOTE(interop): FRR likewise passes a received link-local address on
    // only when configured to (`nexthop-local unchanged`).
    out.next_hop = global_only(out.next_hop);
    out
}

/// `next_hop` without its link-local address, if any (RFC 2545 §3).
fn global_only(next_hop: NextHop) -> NextHop {
    match next_hop {
        NextHop::Ipv6 { global, .. } => NextHop::Ipv6 {
            global,
            link_local: None,
        },
        v4 @ NextHop::Ipv4(_) => v4,
    }
}

/// Whether [`rewrite`] makes `a` and `b` the same for `to`, worked out
/// without making either: what the session overwrites or drops is not
/// compared. When true the rewrites are equal, so the peer needs no new
/// UPDATE; it may be false for some equal rewrites, which only costs a
/// redundant one.
#[must_use]
pub fn same_rewrite(family: AddressFamily, a: &PathAttrs, b: &PathAttrs, to: &PeerInfo) -> bool {
    let kept = a.origin == b.origin
        && a.as_path == b.as_path
        && a.atomic_aggregate == b.atomic_aggregate
        && a.aggregator == b.aggregator
        && a.communities == b.communities
        && a.large_communities == b.large_communities
        && a.unknown == b.unknown
        && (!keeps_next_hop(family, to) || global_only(a.next_hop) == global_only(b.next_hop));
    kept && match to.kind {
        PeerKind::External => {
            let transitive = |x: &&ExtendedCommunity| x.is_transitive();
            a.ext_communities
                .iter()
                .filter(transitive)
                .eq(b.ext_communities.iter().filter(transitive))
        }
        PeerKind::Internal => {
            a.med == b.med
                && a.ext_communities == b.ext_communities
                && a.local_pref.unwrap_or(DEFAULT_LOCAL_PREF)
                    == b.local_pref.unwrap_or(DEFAULT_LOCAL_PREF)
        }
    }
}

/// Announcements and withdrawals for one peer and family, grouped so that
/// routes with equal attributes share an UPDATE (RFC 4271 §9.2).
#[derive(Debug, Default)]
pub struct Batch {
    /// Prefixes to withdraw.
    pub withdraw: Vec<Prefix>,
    /// Prefixes to announce, per attribute set, in the order the sets
    /// were first announced.
    announce: Vec<(Arc<PathAttrs>, Vec<Prefix>)>,
    /// The position of each set in `announce`, by its address. A full
    /// table sent to a new peer has tens of thousands of sets, too many to
    /// search for every prefix. The batch holds every set it indexes, so
    /// no address is reused while it is in here.
    index: HashMap<usize, usize>,
}

impl Batch {
    /// Record an announcement.
    pub fn announce(&mut self, attrs: &Arc<PathAttrs>, prefix: Prefix) {
        // The prefixes of an UPDATE share a set: try the last one first.
        if let Some((last, prefixes)) = self.announce.last_mut()
            && Arc::ptr_eq(last, attrs)
        {
            prefixes.push(prefix);
            return;
        }
        match self.index.entry(Arc::as_ptr(attrs).addr()) {
            Entry::Occupied(e) => self.announce[*e.get()].1.push(prefix),
            Entry::Vacant(e) => {
                e.insert(self.announce.len());
                self.announce.push((Arc::clone(attrs), vec![prefix]));
            }
        }
    }

    /// Empty the batch, giving back the sets it announced.
    pub fn take_sets(&mut self) -> impl Iterator<Item = Arc<PathAttrs>> + '_ {
        self.withdraw.clear();
        self.index.clear();
        self.announce.drain(..).map(|(a, _)| a)
    }

    /// Whether nothing is queued.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.withdraw.is_empty() && self.announce.is_empty()
    }

    /// Encode as framed UPDATE messages no longer than the peer allows.
    /// The announced sets are as the export policy left them; each is
    /// given the session rewrite (RFC 4271 §5.1, [`rewrite`]) here, once
    /// for all its prefixes. `local_as` is our AS.
    ///
    /// # Errors
    /// [`EncodeError`] if an attribute set cannot be encoded at all.
    pub fn encode(
        &self,
        local_as: Asn,
        family: AddressFamily,
        to: &PeerInfo,
    ) -> Result<Vec<Vec<u8>>, EncodeError> {
        #[cfg(feature = "profiling")]
        let _span = bgpfc_prof::Timer::start(&bgpfc_prof::metrics::ADJ_RIB_OUT_BUILD);
        let ctx = EncodeContext {
            four_octet_as: to.four_octet_as,
            // RFC 8950 §4; export already keeps such routes from a peer
            // without it, and the encoder refuses them as well.
            extended_next_hop: to.extended_next_hop.contains(&AddressFamily::IPV4_UNICAST),
        };
        let max_body = to.max_message_len() - HEADER_LEN;
        let mut out = Vec::new();
        for chunk in chunks(&self.withdraw, max_body - WITHDRAW_OVERHEAD) {
            let m = match family {
                AddressFamily::IPV4_UNICAST => UpdateMessage {
                    withdrawn: chunk.to_vec(),
                    ..UpdateMessage::default()
                },
                _ => UpdateMessage {
                    mp_unreach: Some(MpUnreach {
                        family,
                        withdrawn: chunk.to_vec(),
                    }),
                    ..UpdateMessage::default()
                },
            };
            out.push(frame(MessageType::Update, &m.encode(&ctx)?)?);
        }
        for (attrs, prefixes) in &self.announce {
            let attrs = rewrite(local_as, family, attrs, to);
            // Size the attributes once, then fill each message with as
            // many prefixes as fit.
            let empty = attrs.to_update(family, Vec::new()).encode(&ctx)?;
            let room = max_body
                .checked_sub(empty.len() + ANNOUNCE_OVERHEAD)
                .ok_or(EncodeError::TooLong {
                    what: "path attributes",
                    len: empty.len(),
                    max: max_body,
                })?;
            for chunk in chunks(prefixes, room) {
                let m = attrs.to_update(family, chunk.to_vec());
                out.push(frame(MessageType::Update, &m.encode(&ctx)?)?);
            }
        }
        Ok(out)
    }
}

/// Octets the withdrawn-routes / `MP_UNREACH_NLRI` framing may add beyond
/// the prefixes: the length fields and the attribute header.
const WITHDRAW_OVERHEAD: usize = 16;

/// Octets an `MP_REACH_NLRI` grows by when its length field becomes
/// extended, plus slack.
const ANNOUNCE_OVERHEAD: usize = 8;

/// Split `prefixes` into runs whose encoded size stays within `room`.
fn chunks(prefixes: &[Prefix], room: usize) -> Vec<&[Prefix]> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut used = 0;
    for (i, p) in prefixes.iter().enumerate() {
        let len = 1 + usize::from(p.prefix_len().div_ceil(8));
        if used + len > room && i > start {
            out.push(&prefixes[start..i]);
            start = i;
            used = 0;
        }
        used += len;
    }
    if start < prefixes.len() {
        out.push(&prefixes[start..]);
    }
    out
}
