//! Phase 3: what a best route looks like when sent to a peer, and how
//! routes are packed into UPDATE messages (RFC 4271 §9.1.3, §9.2).
//!
//! Implements: RFC 4271 §5.1.2 (`AS_PATH` prepend on external sessions),
//! §5.1.3 (`NEXT_HOP` to external peers), §5.1.4 (MED is not propagated to
//! other neighboring ASes), §5.1.5 (`LOCAL_PREF` only to internal peers),
//! §9.2 (no internal-to-internal redistribution), §9.2 and §4.1 (message
//! size); RFC 1997 (`NO_EXPORT`, `NO_ADVERTISE`); RFC 4360 §6
//! (non-transitive extended communities stay in the AS); RFC 2545 §3
//! (IPv6 next hops); RFC 8654 §4 (65535-octet UPDATEs).

use std::net::IpAddr;
use std::sync::Arc;

use bgpfc_wire::as_path::{AsPath, AsPathSegment, SegmentType};
use bgpfc_wire::community::Community;
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
    if !eligible(family, source, to) {
        return None;
    }
    // RFC 1997: NO_ADVERTISE goes nowhere; NO_EXPORT and
    // NO_EXPORT_SUBCONFED stay inside the AS (no confederations here).
    if attrs.has_community(Community::NO_ADVERTISE) {
        return None;
    }
    if to.kind == PeerKind::External
        && (attrs.has_community(Community::NO_EXPORT)
            || attrs.has_community(Community::NO_EXPORT_SUBCONFED))
    {
        return None;
    }
    let mut out = attrs.clone();
    match to.kind {
        PeerKind::External => {
            // RFC 4271 §5.1.2 c): prepend our AS. RFC 9774 §5: as a
            // sequence; never a set.
            out.as_path = prepend(&attrs.as_path, local_as);
            // RFC 4271 §5.1.3: the next hop is our address on the session
            // when it is of the NLRI's family (RFC 2545 §3 for IPv6).
            // NOTE(interop): for a family the session address does not
            // belong to (IPv4 routes over an IPv6 session) the next hop is
            // left as received, as BIRD does without RFC 8950 negotiation.
            out.next_hop = match (family, to.local_addr) {
                (AddressFamily::IPV4_UNICAST, IpAddr::V4(a)) => NextHop::Ipv4(a),
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
            out.ext_communities.retain(|c| c.is_transitive());
        }
        PeerKind::Internal => {
            // RFC 4271 §5.1.2 b), §5.1.3, §5.1.4: AS_PATH, NEXT_HOP and MED
            // are passed on unchanged. §5.1.5: LOCAL_PREF is included,
            // computed as the degree of preference.
            out.local_pref = Some(attrs.local_pref.unwrap_or(DEFAULT_LOCAL_PREF));
        }
    }
    Some(out)
}

/// `as_path` with `asn` prepended to its leading `AS_SEQUENCE`, or as a
/// new one (RFC 4271 §5.1.2 c, RFC 4271 §4.3: at most 255 ASes per
/// segment).
#[must_use]
pub fn prepend(as_path: &AsPath, asn: Asn) -> AsPath {
    let mut path = as_path.clone();
    match path.segments.first_mut() {
        Some(seg) if seg.kind == SegmentType::Sequence && seg.asns.len() < 255 => {
            seg.asns.insert(0, asn);
        }
        _ => path.segments.insert(
            0,
            AsPathSegment {
                kind: SegmentType::Sequence,
                asns: vec![asn],
            },
        ),
    }
    path
}

/// Announcements and withdrawals for one peer and family, grouped so that
/// routes with equal attributes share an UPDATE (RFC 4271 §9.2).
#[derive(Debug, Default)]
pub struct Batch {
    /// Prefixes to withdraw.
    pub withdraw: Vec<Prefix>,
    /// Prefixes to announce, per attribute set.
    pub announce: Vec<(Arc<PathAttrs>, Vec<Prefix>)>,
}

impl Batch {
    /// Record an announcement.
    pub fn announce(&mut self, attrs: &Arc<PathAttrs>, prefix: Prefix) {
        match self
            .announce
            .iter_mut()
            .find(|(a, _)| Arc::ptr_eq(a, attrs))
        {
            Some((_, v)) => v.push(prefix),
            None => self.announce.push((Arc::clone(attrs), vec![prefix])),
        }
    }

    /// Whether nothing is queued.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.withdraw.is_empty() && self.announce.is_empty()
    }

    /// Encode as framed UPDATE messages no longer than the peer allows.
    ///
    /// # Errors
    /// [`EncodeError`] if an attribute set cannot be encoded at all.
    pub fn encode(
        &self,
        family: AddressFamily,
        to: &PeerInfo,
    ) -> Result<Vec<Vec<u8>>, EncodeError> {
        let ctx = EncodeContext {
            four_octet_as: to.four_octet_as,
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
