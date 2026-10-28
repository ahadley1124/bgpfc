//! The kernel's routes a next hop may resolve through, kept as the kernel
//! holds them: every route at a destination and metric, in the kernel's
//! order (`rtnetlink(7)`; RFC 4271 §9.1.2.1). Pure, so Miri covers it.
//!
//! The kernel may hold several routes with one destination and metric.
//! IPv4 puts one before or after those there (`ip route prepend`, `ip
//! route append`: `NLM_F_CREATE` without `NLM_F_EXCL`); IPv6 makes the
//! gateways of one metric the next hops of one route, which come and go
//! one by one. The kernel forwards through the first that forwards, and
//! announces each removal alone. A copy with one route per destination
//! and metric would lose them all when one goes: this one keeps each,
//! takes a removal by the next hops it names, and gives the route the
//! kernel uses at each destination and metric ([`Mirror::via`]).
//!
//! A notification's `nlmsg_flags` say where its route went
//! (`<linux/netlink.h>`): `NLM_F_REPLACE`, in place of the first route
//! there; `NLM_F_EXCL`, where there was none; `NLM_F_APPEND`, after the
//! others; `NLM_F_CREATE` alone, before them (IPv4) or after them (IPv6).
//!
//! bgpfcd's own routes are not kept: nothing resolves through them (FRR's
//! default: no recursion through BGP). Where one sits among the routes of
//! others, the kernel's first route at that key may be bgpfcd's or
//! another's, so a change there cannot be placed for sure: the copy then
//! says so ([`Unclear`]) and its reader reads the whole table again.

use std::collections::BTreeMap;

use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::Afi;

use crate::kernel::{self, Event, NextHop, Route, Via};
use crate::netlink::{NLM_F_APPEND, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REPLACE};
use crate::route::RTN_UNICAST;

/// A destination and a metric: where routes compete in the kernel's
/// table, the first that forwards winning.
pub type Key = (Prefix, u32);

/// A change of the routes at a key that the copy cannot follow for sure:
/// read the whole table again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unclear {
    /// The destination.
    pub dst: Prefix,
    /// The metric.
    pub metric: u32,
}

/// One route of another than bgpfcd at a key.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    /// `rtm_type`.
    kind: u8,
    /// Its next hops, as the kernel lists them, dead ones included.
    next_hops: Vec<NextHop>,
    /// Where it sends what it matches.
    via: Via,
}

impl Entry {
    fn of(route: &Route) -> Entry {
        Entry {
            kind: route.kind,
            next_hops: route.next_hops.clone(),
            via: route.via,
        }
    }

    /// Whether it forwards or drops, as the kernel's lookup sees it: a
    /// unicast route whose next hops are all dead is passed over for the
    /// next one.
    fn decides(&self) -> bool {
        self.kind != RTN_UNICAST || matches!(self.via, Via::Unicast { .. })
    }

    /// Whether it has a next hop of `other`'s.
    fn shares_a_next_hop(&self, other: &Entry) -> bool {
        self.next_hops
            .iter()
            .any(|h| other.next_hops.iter().any(|o| same(h, o)))
    }
}

/// Whether two next hops are one: the same gateway on the same interface,
/// however their flags differ.
fn same(a: &NextHop, b: &NextHop) -> bool {
    a.gateway == b.gateway && a.oif == b.oif
}

/// The routes at a key.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Slot {
    /// Those of others than bgpfcd, in the kernel's order.
    routes: Vec<Entry>,
    /// Whether a route of bgpfcd's may sit among them.
    shared: bool,
}

/// The kernel's routes, of its main table, that a next hop may resolve
/// through ([`kernel::relevant`]), at each destination and metric as the
/// kernel holds them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Mirror {
    /// The protocol number of bgpfcd's own routes.
    protocol: u8,
    keys: BTreeMap<Key, Slot>,
    /// The key of the route of bgpfcd's that the dump being read listed
    /// last: the routes at a key come together in a dump.
    own_listed: Option<Key>,
}

impl Mirror {
    /// An empty copy, for the bgpfcd whose routes carry `protocol`.
    #[must_use]
    pub fn new(protocol: u8) -> Mirror {
        Mirror {
            protocol,
            ..Mirror::default()
        }
    }

    /// A route a dump lists, in the dump's order, which is the kernel's:
    /// those of others that [`kernel::relevant`] keeps are kept; bgpfcd's
    /// own in the main table mark their key as one where a change cannot
    /// be placed for sure; the rest are passed over.
    pub fn listed(&mut self, route: &Route) {
        if !kernel::candidate(route) {
            return;
        }
        let key = (route.dst, route.metric);
        if route.protocol == self.protocol {
            if let Some(slot) = self.keys.get_mut(&key) {
                slot.shared = true;
            }
            self.own_listed = Some(key);
            return;
        }
        let shared = self.own_listed == Some(key);
        let slot = self.keys.entry(key).or_default();
        slot.shared |= shared;
        slot.routes.push(Entry::of(route));
    }

    /// The dumps that list the routes are over: the next route of
    /// bgpfcd's a dump lists starts afresh.
    pub fn listed_all(&mut self) {
        self.own_listed = None;
    }

    /// Whether a route is held at `key`.
    #[must_use]
    pub fn has(&self, key: &Key) -> bool {
        self.keys.contains_key(key)
    }

    /// Apply a notification: the key whose routes it changed, if any.
    ///
    /// # Errors
    /// [`Unclear`] when the copy cannot tell what changed: a change at a
    /// key where a route of bgpfcd's sits among others', one that names a
    /// route the copy does not have, or one that says the kernel had one
    /// there the copy lacks. The copy is then not to be trusted at that
    /// key until the whole table is read again.
    pub fn apply(&mut self, event: &Event) -> Result<Option<Key>, Unclear> {
        match event {
            Event::Route { route, flags } => self.add(route, *flags).map(Some),
            Event::RouteGone(route) => self.remove(route).map(Some),
            Event::Own {
                dst,
                metric,
                flags,
                gone,
            } => self.own((*dst, *metric), *flags, *gone),
            Event::Link(_) | Event::LinkGone(_) | Event::AddressGone(_) => Ok(None),
        }
    }

    /// Another's route added, or put in the place of the first at its key.
    fn add(&mut self, route: &Route, flags: u16) -> Result<Key, Unclear> {
        let key = (route.dst, route.metric);
        let unclear = Err(Unclear {
            dst: key.0,
            metric: key.1,
        });
        let entry = Entry::of(route);
        let slot = self.keys.entry(key).or_default();
        if slot.shared {
            return unclear;
        }
        if flags & NLM_F_REPLACE != 0 {
            // In place of the first route there: one the copy lacks if it
            // has none, which can only be bgpfcd's.
            let Some(first) = slot.routes.first_mut() else {
                self.keys.remove(&key);
                return unclear;
            };
            *first = entry;
        } else if flags & NLM_F_EXCL != 0 {
            // The kernel had no route there.
            if !slot.routes.is_empty() {
                return unclear;
            }
            slot.routes.push(entry);
        } else if let Some(i) = slot
            .routes
            .iter()
            .position(|r| route.dst.afi() == Afi::Ipv6 && r.shares_a_next_hop(&entry))
        {
            // IPv6: a gateway joined a route of that metric, which the
            // notification lists whole, the new next hop first.
            slot.routes[i] = entry;
        } else if slot.routes.is_empty() {
            // NLM_F_CREATE without NLM_F_EXCL: the kernel had a route
            // there that the copy has not, which can only be bgpfcd's.
            slot.shared = flags & NLM_F_CREATE != 0;
            slot.routes.push(entry);
        } else if flags & NLM_F_APPEND != 0 || route.dst.afi() == Afi::Ipv6 {
            slot.routes.push(entry);
        } else {
            slot.routes.insert(0, entry);
        }
        Ok(key)
    }

    /// Another's route removed: the first at its key with every next hop
    /// the notification names loses them, and goes once it has none. An
    /// IPv6 route loses its next hops one by one, each removal announced
    /// alone; an IPv4 route goes whole.
    fn remove(&mut self, route: &Route) -> Result<Key, Unclear> {
        let key = (route.dst, route.metric);
        let unclear = Err(Unclear {
            dst: key.0,
            metric: key.1,
        });
        let Some(slot) = self.keys.get_mut(&key) else {
            return unclear;
        };
        let Some(i) = slot.routes.iter().position(|r| {
            r.kind == route.kind
                && route
                    .next_hops
                    .iter()
                    .all(|g| r.next_hops.iter().any(|h| same(g, h)))
        }) else {
            return unclear;
        };
        let entry = &mut slot.routes[i];
        entry
            .next_hops
            .retain(|h| !route.next_hops.iter().any(|g| same(g, h)));
        if route.next_hops.is_empty() || entry.next_hops.is_empty() {
            slot.routes.remove(i);
        } else {
            entry.via = kernel::via_of(entry.kind, &entry.next_hops);
        }
        if slot.routes.is_empty() {
            self.keys.remove(&key);
        }
        Ok(key)
    }

    /// One of bgpfcd's own routes added, put in place of another, or
    /// removed. Alone at its key it changes nothing here. Among others'
    /// routes, it replaced the first of them unless one of bgpfcd's might
    /// have been first; it may sit among them from now on; and once
    /// removed, none of bgpfcd's is there any more, as bgpfcd installs one
    /// route a destination.
    fn own(&mut self, key: Key, flags: u16, gone: bool) -> Result<Option<Key>, Unclear> {
        let Some(slot) = self.keys.get_mut(&key) else {
            return Ok(None);
        };
        if gone {
            slot.shared = false;
            return Ok(None);
        }
        if flags & NLM_F_REPLACE != 0 {
            if slot.shared {
                return Err(Unclear {
                    dst: key.0,
                    metric: key.1,
                });
            }
            // In place of the first of them, which is gone; bgpfcd's is
            // first now, before the others.
            slot.routes.remove(0);
            slot.shared = true;
            if slot.routes.is_empty() {
                self.keys.remove(&key);
            }
            return Ok(Some(key));
        }
        if flags & NLM_F_EXCL != 0 {
            // The kernel had no route there, the copy has one.
            return Err(Unclear {
                dst: key.0,
                metric: key.1,
            });
        }
        slot.shared = true;
        Ok(None)
    }

    /// Where the kernel sends what matches the routes at `key`: through
    /// the first of them that forwards, or nowhere if the first that
    /// decides drops (a blackhole, unreachable, prohibit or throw route),
    /// as the kernel's lookup does; nowhere too if every one there has
    /// only dead next hops. `None` when there is no route at `key`.
    #[must_use]
    pub fn via(&self, key: &Key) -> Option<Via> {
        let slot = self.keys.get(key)?;
        slot.routes.first()?;
        Some(
            slot.routes
                .iter()
                .find(|r| r.decides())
                .map_or(Via::Unreachable, |r| r.via),
        )
    }

    /// Every key with a route, and where the kernel sends what matches
    /// it ([`Mirror::via`]), by destination, then metric.
    pub fn routes(&self) -> impl Iterator<Item = (Prefix, u32, Via)> + '_ {
        self.keys
            .keys()
            .filter_map(|k| self.via(k).map(|via| (k.0, k.1, via)))
    }

    /// Routes held: every one at every key.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.values().map(|s| s.routes.len()).sum()
    }

    /// Whether no route is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::netlink::{NLM_F_APPEND, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REPLACE};
    use crate::route::{RT_TABLE_MAIN, RTPROT_BGP};

    /// `RTPROT_STATIC`.
    const STATIC: u8 = 4;
    /// `ip route add`: the kernel found no route at the key.
    const ADD: u16 = NLM_F_CREATE | NLM_F_EXCL;
    /// `ip route append`.
    const APPEND: u16 = NLM_F_CREATE | NLM_F_APPEND;
    /// `ip route prepend`, or a create among others.
    const PREPEND: u16 = NLM_F_CREATE;

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    fn hop(gateway: &str, oif: u32) -> NextHop {
        NextHop {
            gateway: Some(gateway.parse().unwrap()),
            oif,
            flags: 0,
        }
    }

    /// A route of `protocol` to `dst` at `metric` through `next_hops`.
    fn route(protocol: u8, dst: &str, metric: u32, next_hops: Vec<NextHop>) -> Route {
        let via = kernel::via_of(RTN_UNICAST, &next_hops);
        Route {
            dst: p(dst),
            table: RT_TABLE_MAIN,
            protocol,
            kind: RTN_UNICAST,
            tos: 0,
            flags: 0,
            metric,
            via,
            next_hops,
        }
    }

    /// What the routes at a key send through: `gateway` on `oif`.
    fn via(gateway: &str, oif: u32) -> Via {
        Via::Unicast {
            gateway: Some(gateway.parse().unwrap()),
            oif,
            onlink: false,
        }
    }

    fn added(r: &Route, flags: u16) -> Event {
        Event::Route {
            route: r.clone(),
            flags,
        }
    }

    fn key(dst: &str, metric: u32) -> Key {
        (p(dst), metric)
    }

    /// `ip route append` puts a second route at a destination and metric,
    /// `ip route del ... via` takes one of them away: the other stays, and
    /// is the one the kernel uses.
    #[test]
    fn deleting_one_of_two_routes_keeps_the_other() {
        let mut copy = Mirror::new(RTPROT_BGP);
        let first = route(STATIC, "10.255.0.30/32", 0, vec![hop("10.9.0.2", 3)]);
        let second = route(STATIC, "10.255.0.30/32", 0, vec![hop("10.9.0.3", 3)]);
        let at = key("10.255.0.30/32", 0);
        assert_eq!(copy.apply(&added(&first, ADD)), Ok(Some(at)));
        assert_eq!(copy.apply(&added(&second, APPEND)), Ok(Some(at)));
        assert_eq!(copy.len(), 2);
        assert_eq!(copy.via(&at), Some(via("10.9.0.2", 3)));
        assert_eq!(copy.apply(&Event::RouteGone(first.clone())), Ok(Some(at)));
        assert_eq!(copy.via(&at), Some(via("10.9.0.3", 3)));
        assert_eq!(copy.apply(&Event::RouteGone(second.clone())), Ok(Some(at)));
        assert_eq!(copy.via(&at), None);
        assert!(copy.is_empty());
        // Prepended, the new one comes first, and is used.
        copy.apply(&added(&first, ADD)).unwrap();
        copy.apply(&added(&second, PREPEND)).unwrap();
        assert_eq!(copy.via(&at), Some(via("10.9.0.3", 3)));
        // A deletion of a route the copy does not have is not followed.
        let third = route(STATIC, "10.255.0.30/32", 0, vec![hop("10.9.0.4", 3)]);
        assert_eq!(
            copy.apply(&Event::RouteGone(third)),
            Err(Unclear {
                dst: p("10.255.0.30/32"),
                metric: 0
            })
        );
    }

    /// IPv6 keeps the gateways of one metric as the next hops of one route
    /// and announces the removal of each alone: the others stay.
    #[test]
    fn an_ipv6_next_hop_goes_alone() {
        let mut copy = Mirror::new(RTPROT_BGP);
        let both = route(
            STATIC,
            "2001:db8:5::/48",
            1024,
            vec![hop("fe80::1", 3), hop("fe80::2", 4)],
        );
        let at = key("2001:db8:5::/48", 1024);
        copy.apply(&added(&both, ADD)).unwrap();
        assert_eq!(copy.via(&at), Some(via("fe80::1", 3)));
        let first = route(STATIC, "2001:db8:5::/48", 1024, vec![hop("fe80::1", 3)]);
        assert_eq!(copy.apply(&Event::RouteGone(first)), Ok(Some(at)));
        assert_eq!(copy.via(&at), Some(via("fe80::2", 4)));
        assert_eq!(copy.len(), 1);
        // A gateway joins: the notification lists the route whole.
        let again = route(
            STATIC,
            "2001:db8:5::/48",
            1024,
            vec![hop("fe80::1", 3), hop("fe80::2", 4)],
        );
        copy.apply(&added(&again, PREPEND)).unwrap();
        assert_eq!(copy.len(), 1);
        assert_eq!(copy.via(&at), Some(via("fe80::1", 3)));
    }

    /// bgpfcd's own route put in place of another's (`NLM_F_REPLACE`):
    /// the other is gone from the copy, and nothing of bgpfcd's is in it.
    #[test]
    fn our_route_in_place_of_anothers_takes_it_out() {
        let mut copy = Mirror::new(RTPROT_BGP);
        let at = key("192.0.2.40/30", 20);
        let igp = route(STATIC, "192.0.2.40/30", 20, vec![hop("10.1.0.2", 2)]);
        copy.apply(&added(&igp, ADD)).unwrap();
        let own = |flags, gone| Event::Own {
            dst: p("192.0.2.40/30"),
            metric: 20,
            flags,
            gone,
        };
        assert_eq!(copy.apply(&own(NLM_F_REPLACE, false)), Ok(Some(at)));
        assert_eq!(copy.via(&at), None);
        assert!(copy.is_empty());
        // Ours alone at a key changes nothing.
        assert_eq!(copy.apply(&own(ADD, false)), Ok(None));
        assert_eq!(copy.apply(&own(0, true)), Ok(None));
        // Another's added after ours (it finds ours, so no NLM_F_EXCL):
        // ours may be first there, so the next change there is unclear.
        assert_eq!(copy.apply(&added(&igp, APPEND)), Ok(Some(at)));
        assert_eq!(copy.via(&at), Some(via("10.1.0.2", 2)));
        let unclear = Err(Unclear {
            dst: p("192.0.2.40/30"),
            metric: 20,
        });
        assert_eq!(copy.apply(&own(NLM_F_REPLACE, false)), unclear);
        assert_eq!(copy.apply(&added(&igp, NLM_F_REPLACE)), unclear);
        // Once ours is gone, it is clear again.
        assert_eq!(copy.apply(&own(0, true)), Ok(None));
        assert_eq!(copy.apply(&added(&igp, NLM_F_REPLACE)), Ok(Some(at)));
        // Another's put in place of a route the copy lacks: bgpfcd's.
        let other = route(STATIC, "198.51.100.0/24", 20, vec![hop("10.1.0.2", 2)]);
        assert_eq!(
            copy.apply(&added(&other, NLM_F_REPLACE)),
            Err(Unclear {
                dst: p("198.51.100.0/24"),
                metric: 20
            })
        );
        assert_eq!(copy.via(&key("198.51.100.0/24", 20)), None);
        // NLM_F_EXCL where the copy has a route: it missed something.
        assert_eq!(copy.apply(&added(&igp, ADD)), unclear_at(&igp));
    }

    fn unclear_at(r: &Route) -> Result<Option<Key>, Unclear> {
        Err(Unclear {
            dst: r.dst,
            metric: r.metric,
        })
    }

    /// A dump lists the routes at a key together, in the kernel's order:
    /// one of bgpfcd's among others' marks the key, wherever it is.
    #[test]
    fn a_dump_marks_the_keys_ours_share() {
        let igp = route(STATIC, "192.0.2.40/30", 20, vec![hop("10.1.0.2", 2)]);
        let ours = route(RTPROT_BGP, "192.0.2.40/30", 20, vec![hop("10.1.0.3", 2)]);
        for order in [[&igp, &ours], [&ours, &igp]] {
            let mut copy = Mirror::new(RTPROT_BGP);
            for r in order {
                copy.listed(r);
            }
            assert_eq!(copy.len(), 1);
            assert_eq!(
                copy.via(&key("192.0.2.40/30", 20)),
                Some(via("10.1.0.2", 2))
            );
            assert!(copy.apply(&added(&igp, NLM_F_REPLACE)).is_err());
        }
        // Ours alone, and the routes of another table, are not kept.
        let mut copy = Mirror::new(RTPROT_BGP);
        copy.listed(&ours);
        let mut local = igp.clone();
        local.table = 255;
        copy.listed(&local);
        assert!(copy.is_empty());
    }

    /// The route the kernel uses at a key: the first that forwards, or a
    /// blackhole before it; one whose next hops are all dead is passed
    /// over, and a key with only such routes forwards nothing.
    #[test]
    fn the_first_route_that_decides_is_used() {
        let mut copy = Mirror::new(RTPROT_BGP);
        let at = key("198.18.0.0/24", 0);
        let mut dead = route(STATIC, "198.18.0.0/24", 0, vec![hop("10.1.0.2", 2)]);
        dead.next_hops[0].flags = 1; // RTNH_F_DEAD
        dead.via = kernel::via_of(RTN_UNICAST, &dead.next_hops);
        assert_eq!(dead.via, Via::Unreachable);
        copy.apply(&added(&dead, ADD)).unwrap();
        assert_eq!(copy.via(&at), Some(Via::Unreachable));
        let live = route(STATIC, "198.18.0.0/24", 0, vec![hop("10.1.0.4", 5)]);
        copy.apply(&added(&live, APPEND)).unwrap();
        assert_eq!(copy.via(&at), Some(via("10.1.0.4", 5)));
        let mut hole = route(STATIC, "198.18.0.0/24", 0, vec![]);
        hole.kind = 6; // RTN_BLACKHOLE
        hole.via = Via::Unreachable;
        copy.apply(&added(&hole, PREPEND)).unwrap();
        assert_eq!(copy.via(&at), Some(Via::Unreachable));
        assert_eq!(copy.apply(&Event::RouteGone(hole)), Ok(Some(at)));
        assert_eq!(copy.via(&at), Some(via("10.1.0.4", 5)));
        assert_eq!(
            copy.routes().collect::<Vec<_>>(),
            vec![(p("198.18.0.0/24"), 0, via("10.1.0.4", 5))]
        );
    }
}
