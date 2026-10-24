//! A routing table to send: attribute sets and the routes that use them.

use bgpfc_wire::attribute::PathAttribute;
use bgpfc_wire::mp::NextHop;
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::{AddressFamily, Afi};

/// The path attributes routes share: everything an UPDATE carries except
/// the next hop and the NLRI.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AttrSet {
    /// Attributes other than `NEXT_HOP`, `MP_REACH_NLRI` and
    /// `MP_UNREACH_NLRI`.
    pub attributes: Vec<PathAttribute>,
    /// The next hop: the `NEXT_HOP` attribute for IPv4 unicast with an IPv4
    /// next hop, the `MP_REACH_NLRI` next hop otherwise.
    pub next_hop: NextHop,
}

/// One route: a prefix and the index of its attribute set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    /// Index into [`Table::sets`].
    pub set: u32,
    /// The destination.
    pub prefix: Prefix,
}

/// Routes and their attribute sets.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Table {
    /// Distinct attribute sets.
    pub sets: Vec<AttrSet>,
    /// Every route, each prefix at most once.
    pub routes: Vec<Route>,
}

impl Table {
    /// The families the routes belong to, IPv4 first.
    #[must_use]
    pub fn families(&self) -> Vec<AddressFamily> {
        let mut v: Vec<AddressFamily> = Vec::new();
        for r in &self.routes {
            let f = family_of(&r.prefix);
            if !v.contains(&f) {
                v.push(f);
            }
        }
        v.sort();
        v
    }

    /// The attribute sets some route uses.
    #[must_use]
    pub fn used_sets(&self) -> usize {
        let mut used = vec![false; self.sets.len()];
        for r in &self.routes {
            if let Some(u) = used.get_mut(r.set as usize) {
                *u = true;
            }
        }
        used.into_iter().filter(|u| *u).count()
    }
}

/// The unicast family of `p`.
#[must_use]
pub fn family_of(p: &Prefix) -> AddressFamily {
    match p.afi() {
        Afi::Ipv6 => AddressFamily::IPV6_UNICAST,
        _ => AddressFamily::IPV4_UNICAST,
    }
}
