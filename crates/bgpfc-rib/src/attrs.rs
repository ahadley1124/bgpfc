//! The attribute set of a route, shared between every route that carries
//! the same attributes (AGENTS.md §7, "Allocation").
//!
//! Implements: RFC 4271 §4.3 (the well-known attributes), §5 (unknown
//! optional transitive attributes are carried with the Partial bit);
//! RFC 4760 §3 (the next hop of multiprotocol routes); RFC 1997, 4360,
//! 8092 (communities).

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use bgpfc_wire::as_path::AsPath;
use bgpfc_wire::attribute::{Aggregator, Origin, PathAttribute, flags};
use bgpfc_wire::community::{Community, ExtendedCommunity, LargeCommunity};
use bgpfc_wire::mp::{MpReach, NextHop};
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::{AddressFamily, Afi};
use bgpfc_wire::update::UpdateMessage;

/// An optional transitive attribute this implementation does not know,
/// kept for forwarding (RFC 4271 §5).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct UnknownAttribute {
    /// Attribute Flags, Extended Length bit cleared.
    pub flags: u8,
    /// Attribute Type Code.
    pub code: u8,
    /// Attribute value.
    pub value: Vec<u8>,
}

/// The path attributes of one route, in canonical form.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PathAttrs {
    /// ORIGIN.
    pub origin: Origin,
    /// `AS_PATH` (four-octet ASNs; RFC 6793 §4.2.3 merged any `AS4_PATH`).
    pub as_path: AsPath,
    /// `NEXT_HOP`, or the `MP_REACH_NLRI` next hop.
    pub next_hop: NextHop,
    /// `MULTI_EXIT_DISC`.
    pub med: Option<u32>,
    /// `LOCAL_PREF`; present on routes from internal peers (RFC 4271
    /// §5.1.5) and set by policy otherwise.
    pub local_pref: Option<u32>,
    /// `ATOMIC_AGGREGATE`.
    pub atomic_aggregate: bool,
    /// AGGREGATOR.
    pub aggregator: Option<Aggregator>,
    /// COMMUNITIES, sorted and unique.
    pub communities: Vec<Community>,
    /// Extended Communities, sorted and unique.
    pub ext_communities: Vec<ExtendedCommunity>,
    /// Large Communities, sorted and unique.
    pub large_communities: Vec<LargeCommunity>,
    /// Unknown optional transitive attributes, by type code.
    pub unknown: Vec<UnknownAttribute>,
}

impl PathAttrs {
    /// The attributes an UPDATE carries for routes of `family`: the
    /// `NEXT_HOP` attribute for IPv4 unicast, the `MP_REACH_NLRI` next hop
    /// otherwise. `None` when the message has no next hop for the family,
    /// which the decoder rules out for announcing messages.
    #[must_use]
    pub fn from_update(m: &UpdateMessage, family: AddressFamily) -> Option<PathAttrs> {
        let mut attrs = PathAttrs {
            origin: Origin::Incomplete,
            as_path: AsPath::empty(),
            next_hop: NextHop::Ipv4(std::net::Ipv4Addr::UNSPECIFIED),
            med: None,
            local_pref: None,
            atomic_aggregate: false,
            aggregator: None,
            communities: Vec::new(),
            ext_communities: Vec::new(),
            large_communities: Vec::new(),
            unknown: Vec::new(),
        };
        let mut next_hop = None;
        for a in &m.attributes {
            match a {
                PathAttribute::Origin(o) => attrs.origin = *o,
                PathAttribute::AsPath(p) => attrs.as_path = p.clone(),
                PathAttribute::NextHop(n) => next_hop = Some(NextHop::Ipv4(*n)),
                PathAttribute::MultiExitDisc(v) => attrs.med = Some(*v),
                PathAttribute::LocalPref(v) => attrs.local_pref = Some(*v),
                PathAttribute::AtomicAggregate => attrs.atomic_aggregate = true,
                PathAttribute::Aggregator(g) => attrs.aggregator = Some(*g),
                PathAttribute::Communities(c) => attrs.communities.clone_from(c),
                PathAttribute::ExtendedCommunities(c) => attrs.ext_communities.clone_from(c),
                PathAttribute::LargeCommunities(c) => attrs.large_communities.clone_from(c),
                PathAttribute::Unknown { flags, code, value } => {
                    attrs.unknown.push(UnknownAttribute {
                        flags: *flags,
                        code: *code,
                        value: value.clone(),
                    });
                }
                // Never in `attributes`; the decoder lifts them out.
                PathAttribute::MpReach(_) | PathAttribute::MpUnreach(_) => {}
            }
        }
        if let Some(r) = &m.mp_reach
            && r.family == family
        {
            next_hop = Some(r.next_hop);
        }
        attrs.next_hop = next_hop?;
        attrs.normalise();
        Some(attrs)
    }

    /// Sort and deduplicate the sets so equal attribute sets compare
    /// equal whatever order they arrived in.
    pub fn normalise(&mut self) {
        self.communities.sort_unstable();
        self.communities.dedup();
        self.ext_communities.sort_unstable();
        self.ext_communities.dedup();
        self.large_communities.sort_unstable();
        self.large_communities.dedup();
        self.unknown.sort_by_key(|u| u.code);
    }

    /// The next hop as an address (the global one for IPv6).
    #[must_use]
    pub fn next_hop_addr(&self) -> IpAddr {
        match &self.next_hop {
            NextHop::Ipv4(a) => IpAddr::V4(*a),
            NextHop::Ipv6 { global, .. } => IpAddr::V6(*global),
        }
    }

    /// Whether the route carries `c` (RFC 1997 well-known values among
    /// them).
    #[must_use]
    pub fn has_community(&self, c: Community) -> bool {
        self.communities.binary_search(&c).is_ok()
    }

    /// Build the UPDATE announcing `nlri` of `family` with these
    /// attributes. IPv4 unicast uses the RFC 4271 fields; every other
    /// family goes in `MP_REACH_NLRI` (RFC 4760 §3).
    #[must_use]
    pub fn to_update(&self, family: AddressFamily, nlri: Vec<Prefix>) -> UpdateMessage {
        let mut m = UpdateMessage {
            attributes: self.to_attributes(),
            ..UpdateMessage::default()
        };
        match (family, &self.next_hop) {
            (AddressFamily::IPV4_UNICAST, NextHop::Ipv4(n)) => {
                m.attributes.push(PathAttribute::NextHop(*n));
                m.nlri = nlri;
            }
            _ => {
                m.mp_reach = Some(MpReach {
                    family,
                    next_hop: self.next_hop,
                    nlri,
                });
            }
        }
        m.attributes.sort_by_key(PathAttribute::code);
        m
    }

    /// The attributes other than the next hop, in type order.
    fn to_attributes(&self) -> Vec<PathAttribute> {
        let mut out = vec![
            PathAttribute::Origin(self.origin),
            PathAttribute::AsPath(self.as_path.clone()),
        ];
        if let Some(m) = self.med {
            out.push(PathAttribute::MultiExitDisc(m));
        }
        if let Some(l) = self.local_pref {
            out.push(PathAttribute::LocalPref(l));
        }
        if self.atomic_aggregate {
            out.push(PathAttribute::AtomicAggregate);
        }
        if let Some(a) = self.aggregator {
            out.push(PathAttribute::Aggregator(a));
        }
        if !self.communities.is_empty() {
            out.push(PathAttribute::Communities(self.communities.clone()));
        }
        if !self.ext_communities.is_empty() {
            out.push(PathAttribute::ExtendedCommunities(
                self.ext_communities.clone(),
            ));
        }
        if !self.large_communities.is_empty() {
            out.push(PathAttribute::LargeCommunities(
                self.large_communities.clone(),
            ));
        }
        for u in &self.unknown {
            out.push(PathAttribute::Unknown {
                // RFC 4271 §5: an unrecognised optional transitive
                // attribute is passed on with the Partial bit set.
                flags: u.flags | flags::PARTIAL,
                code: u.code,
                value: u.value.clone(),
            });
        }
        out
    }

    /// Whether the next hop belongs to `afi`'s address family. IPv4 NLRI
    /// may carry an IPv6 next hop (RFC 8950), so this is informational.
    #[must_use]
    pub fn next_hop_afi(&self) -> Afi {
        match self.next_hop {
            NextHop::Ipv4(_) => Afi::Ipv4,
            NextHop::Ipv6 { .. } => Afi::Ipv6,
        }
    }
}

/// Shares one allocation between routes with equal attributes.
#[derive(Debug, Default)]
pub struct Interner {
    set: HashSet<Arc<PathAttrs>>,
    /// Size after the last sweep; a sweep runs when the set doubles.
    swept_at: usize,
}

impl Interner {
    /// The shared instance of `attrs`.
    pub fn intern(&mut self, attrs: PathAttrs) -> Arc<PathAttrs> {
        if let Some(a) = self.set.get(&attrs) {
            return Arc::clone(a);
        }
        if self.set.len() >= 2 * self.swept_at.max(1024) {
            self.sweep();
        }
        let a = Arc::new(attrs);
        self.set.insert(Arc::clone(&a));
        a
    }

    /// Drop entries no route uses any more.
    pub fn sweep(&mut self) {
        self.set.retain(|a| Arc::strong_count(a) > 1);
        self.swept_at = self.set.len();
    }

    /// Distinct attribute sets held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.set.len()
    }

    /// Whether nothing is interned.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }
}
