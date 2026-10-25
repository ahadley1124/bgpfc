//! What the RIB holds, for profiling builds (`docs/PROFILING.md`): table
//! sizes, how much the attributes repeat, and the size of the structures a
//! route is made of.

use std::collections::HashSet;
use std::mem::size_of;
use std::sync::Arc;

use bgpfc_wire::as_path::AsPath;
use bgpfc_wire::mp::NextHop;
use bgpfc_wire::prefix::{Ipv4Key, Prefix};

use crate::attrs::PathAttrs;
use crate::peer::PeerInfo;
use crate::store::{Destination, Route};
use crate::{PeerState, Rib};

/// Table sizes, cheap to compute: one addition per family and peer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sizes {
    /// Destinations of every family. Every destination held has a route,
    /// and so a best one: this is also the size of the Loc-RIB.
    pub destinations: usize,
    /// Routes in all Adj-RIBs-In.
    pub adj_rib_in: usize,
    /// Routes in all Adj-RIBs-Out.
    pub adj_rib_out: usize,
}

impl Rib {
    /// How many destinations and routes the RIB holds.
    #[must_use]
    pub fn sizes(&self) -> Sizes {
        Sizes {
            destinations: self.tables.values().map(crate::store::Table::len).sum(),
            adj_rib_in: self
                .s
                .peers
                .iter()
                .flatten()
                .flat_map(|p| p.adj_in_count.values())
                .sum(),
            adj_rib_out: self
                .s
                .peers
                .iter()
                .flatten()
                .flat_map(|p| p.advertised.values())
                .sum(),
        }
    }

    /// Walk every route and count how often attribute sets and `AS_PATH`s
    /// repeat. Costs one hash-set insert per route; meant for a report
    /// after a table load, not for every message.
    #[must_use]
    pub fn duplication(&self) -> Duplication {
        let mut d = Duplication {
            interned: self.s.cx.interner.len(),
            ..Duplication::default()
        };
        let mut by_ptr: HashSet<usize> = HashSet::new();
        let mut by_value: HashSet<&PathAttrs> = HashSet::new();
        let mut paths: HashSet<&AsPath> = HashSet::new();
        for table in self.tables.values() {
            d.destinations += table.len();
            for dest in table.values() {
                d.candidate_bytes += dest.heap_bytes();
                for (c, _) in dest.iter() {
                    d.routes += 1;
                    d.pre_policy += usize::from(c.received.is_some());
                    if by_ptr.insert(Arc::as_ptr(&c.attrs).addr()) {
                        by_value.insert(&c.attrs);
                        paths.insert(&c.attrs.as_path);
                        d.as_path_bytes += c.attrs.as_path.heap_size();
                    }
                }
            }
        }
        d.attr_sets = by_ptr.len();
        d.attr_values = by_value.len();
        d.as_paths = paths.len();
        d.as_path_bytes_if_interned = paths.iter().map(|p| p.heap_size()).sum();
        d.adj_rib_out = self
            .s
            .peers
            .iter()
            .flatten()
            .flat_map(|p| p.advertised.values())
            .sum();
        d.pacing_bytes = self
            .s
            .peers
            .iter()
            .flatten()
            .flat_map(|p| p.pacing.values())
            .map(crate::pacing::Pacing::heap_bytes)
            .sum();
        d
    }
}

/// How much the RIB's attributes repeat, to judge whether interning more
/// of them would pay off.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Duplication {
    /// Destinations, all families.
    pub destinations: usize,
    /// Routes in all Adj-RIBs-In: one candidate each.
    pub routes: usize,
    /// Distinct attribute sets the routes use, by allocation.
    pub attr_sets: usize,
    /// Distinct attribute sets by value. Equal to `attr_sets` while the
    /// interner works: no two allocations hold equal attributes.
    pub attr_values: usize,
    /// Attribute sets the interner holds. A set goes with its last route;
    /// one still held elsewhere at that moment (a control-plane reply,
    /// say) goes at the next sweep, when the set has doubled.
    pub interned: usize,
    /// Distinct `AS_PATH`s among the attribute sets.
    pub as_paths: usize,
    /// Heap octets of `AS_PATH`s as stored: one copy per attribute set.
    pub as_path_bytes: usize,
    /// Heap octets if every distinct `AS_PATH` were stored once.
    pub as_path_bytes_if_interned: usize,
    /// Heap octets of the per-destination route vectors: destinations
    /// with routes from two or more peers (one route is held inline).
    pub candidate_bytes: usize,
    /// Routes in all Adj-RIBs-Out, which are counted, not stored: each
    /// follows from the Loc-RIB and export.
    pub adj_rib_out: usize,
    /// Routes that keep the attributes they were received with apart
    /// from those import policy made (RFC 4271 §3.2 Adj-RIB-In): those
    /// policy changed or rejected.
    pub pre_policy: usize,
    /// Heap octets the RFC 4271 §9.2.1.1 pacing of all peers has room
    /// for: held destinations, wake-ups, and the advertisements and
    /// withdrawals of the last interval.
    pub pacing_bytes: usize,
}

/// `size_of` of the structures a route is made of, by name.
#[must_use]
pub fn type_sizes() -> Vec<(&'static str, usize)> {
    vec![
        ("Prefix", size_of::<Prefix>()),
        // A B-tree node keeps keys and values in separate arrays, so an
        // entry costs the two sizes added, without padding between.
        (
            "Ipv4Key + Destination [IPv4 Loc-RIB entry]",
            size_of::<Ipv4Key>() + size_of::<Destination>(),
        ),
        (
            "Prefix + Destination [IPv6 Loc-RIB entry]",
            size_of::<Prefix>() + size_of::<Destination>(),
        ),
        ("Destination", size_of::<Destination>()),
        ("Route [Adj-RIB-In route]", size_of::<Route>()),
        ("PathAttrs", size_of::<PathAttrs>()),
        (
            "Arc<PathAttrs> allocation",
            size_of::<PathAttrs>() + 2 * size_of::<usize>(),
        ),
        ("AsPath", size_of::<AsPath>()),
        ("NextHop", size_of::<NextHop>()),
        ("PeerInfo", size_of::<PeerInfo>()),
        ("PeerState", size_of::<PeerState>()),
        ("Rib", size_of::<Rib>()),
    ]
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, Instant};

    use bgpfc_wire::attribute::{Origin, PathAttribute};
    use bgpfc_wire::types::{AddressFamily, Asn, RouterId};
    use bgpfc_wire::update::{DecodedUpdate, PeerKind, UpdateMessage};

    use super::*;

    fn peer(i: u8, kind: PeerKind) -> PeerInfo {
        PeerInfo {
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)),
            local_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254)),
            remote_as: Asn(if kind == PeerKind::Internal {
                65_000
            } else {
                65_000 + u32::from(i)
            }),
            router_id: RouterId::new(u32::from(i)).unwrap(),
            kind,
            families: vec![AddressFamily::IPV4_UNICAST],
            receive_families: vec![AddressFamily::IPV4_UNICAST],
            four_octet_as: true,
            extended_messages: false,
            extended_next_hop: Vec::new(),
            advertisement_interval: Duration::from_secs(30),
            prefix_limits: Vec::new(),
            add_path_receive: Vec::new(),
            add_path_send: Vec::new(),
        }
    }

    fn update(path: &[u32], med: Option<u32>, nlri: &[&str]) -> DecodedUpdate {
        let mut attributes = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::sequence(
                &path.iter().map(|a| Asn(*a)).collect::<Vec<_>>(),
            )),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 1)),
        ];
        if let Some(m) = med {
            attributes.push(PathAttribute::MultiExitDisc(m));
        }
        DecodedUpdate {
            message: UpdateMessage {
                nlri: nlri.iter().map(|p| p.parse().unwrap()).collect(),
                attributes,
                ..UpdateMessage::default()
            },
            ..DecodedUpdate::default()
        }
    }

    #[test]
    fn counts_repeated_attribute_sets_and_paths() {
        let now = Instant::now();
        let mut rib = Rib::new(Asn(65_000));
        let a = peer(1, PeerKind::External);
        let b = peer(2, PeerKind::External);
        rib.peer_up(a.clone(), now, &mut Vec::new());
        rib.peer_up(b.clone(), now, &mut Vec::new());
        // Two attribute sets from A that share an AS_PATH and differ in MED.
        rib.update(
            a.addr,
            &update(&[65_001, 7], None, &["192.0.2.0/24", "198.51.100.0/24"]),
            now,
            &mut Vec::new(),
        );
        rib.update(
            a.addr,
            &update(&[65_001, 7], Some(5), &["203.0.113.0/24"]),
            now,
            &mut Vec::new(),
        );
        // One from B, for one of the same destinations.
        rib.update(
            b.addr,
            &update(&[65_002, 7], None, &["192.0.2.0/24"]),
            now,
            &mut Vec::new(),
        );
        // A change inside B's interval is held back.
        rib.update(
            a.addr,
            &update(&[65_001, 7, 8], None, &["198.51.100.0/24"]),
            now + Duration::from_secs(1),
            &mut Vec::new(),
        );

        let d = rib.duplication();
        assert_eq!(d.destinations, 3);
        assert_eq!(d.routes, 4);
        assert_eq!(d.attr_sets, 4);
        assert_eq!(d.attr_values, 4);
        assert_eq!(d.as_paths, 3);
        assert_eq!(d.pre_policy, 0);
        assert!(d.pacing_bytes > 0);
        assert!(d.as_path_bytes > d.as_path_bytes_if_interned);
        assert!(d.interned >= d.attr_sets);
        // Only 192.0.2.0/24 has two routes; the others hold theirs inline.
        assert_eq!(d.candidate_bytes, 2 * size_of::<Route>());
        // A has the lower BGP Identifier and wins all three destinations
        // (RFC 4271 §9.1.2.2 f), so only B is sent routes.
        assert_eq!(d.adj_rib_out, 3);

        let sizes = rib.sizes();
        assert_eq!(sizes.destinations, 3);
        assert_eq!(sizes.adj_rib_in, 4);
        assert_eq!(sizes.adj_rib_out, 3);
    }

    #[test]
    fn type_sizes_are_listed() {
        let sizes = type_sizes();
        for (name, size) in &sizes {
            println!("{name:48} {size:5}");
            assert!(*size > 0, "{name}");
        }
        assert!(sizes.iter().any(|(n, _)| n.starts_with("Route")));
    }
}
