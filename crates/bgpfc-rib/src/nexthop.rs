//! Next hops resolved against the kernel's routing table (RFC 4271 §9.1.2,
//! §9.1.2.1).
//!
//! The RIB keeps a copy of the routes of the kernel's main table a next
//! hop may resolve through ([`KernelUpdate`]: what `bgpfc_fib::kernel`
//! keeps, which is never bgpfcd's own routes nor a default route), and
//! resolves every next hop its routes use against it by longest match,
//! the lowest metric among routes to the same prefix: "only the longest
//! matching route SHOULD be considered" (RFC 4271 §9.1.2.1 1)), and the
//! route the kernel itself would use. A route whose next hop does not
//! resolve stays in the Adj-RIB-In but is no candidate (RFC 4271 §9.1.2:
//! it "MUST be excluded from the Phase 2 decision function";
//! [`Held::NextHop`](crate::Held::NextHop)), and becomes one again, with
//! no UPDATE, when it resolves.
//!
//! A resolved next hop gives the hop the FIB installs a route through:
//! the immediate gateway and interface of the kernel route that resolves
//! it, or the next hop itself on the interface of a connected route
//! ([`Hop`]), as BIRD's `gateway recursive` and FRR do.
//!
//! The next hops in use are few (one per eBGP peer, tens with iBGP), and
//! each knows the destinations that have a route through it: a change of
//! the kernel's table decides again only the destinations of the next
//! hops whose resolution it changed, however large the table.
//!
//! Without a kernel table, the library's default as validation's
//! `NullSource` is, every next hop resolves to itself with no interface:
//! every route is a candidate, as before resolution existed.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::net::IpAddr;

use bgpfc_wire::prefix::{Ipv4Key, Prefix};

use crate::store::Destination;

/// A route of the kernel's main table a next hop may resolve through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelRoute {
    /// Its destination.
    pub prefix: Prefix,
    /// Its metric (`RTA_PRIORITY`): of several routes to one prefix, the
    /// kernel uses the lowest.
    pub metric: u32,
    /// Where it sends what it matches.
    pub via: Via,
}

/// Where a kernel route sends what it matches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Via {
    /// Through `gateway`, or straight to the destination on the link for
    /// a connected or device route, out of interface `oif`.
    Unicast {
        /// The gateway, if any.
        gateway: Option<IpAddr>,
        /// The interface index.
        oif: u32,
    },
    /// Nowhere: a blackhole, unreachable, prohibit or throw route, or one
    /// with no usable next hop. Nothing resolves through it, and a more
    /// specific one shadows a covering route, as in the kernel.
    Unreachable,
}

/// What the kernel's table is, or what changed in it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KernelUpdate {
    /// The whole table, replacing the copy: at startup, and after
    /// notifications were lost or an interface or address went away.
    Table {
        /// The routes.
        routes: Vec<KernelRoute>,
        /// The interfaces, index and name, for display.
        links: Vec<(u32, String)>,
    },
    /// Changes, in the order the kernel made them.
    Changes(Vec<KernelChange>),
}

/// One change of the kernel's table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KernelChange {
    /// A route added, or replacing the one with its prefix and metric.
    Route(KernelRoute),
    /// The route with this prefix and metric removed.
    Gone {
        /// Its destination.
        prefix: Prefix,
        /// Its metric.
        metric: u32,
    },
    /// An interface's name, for display.
    Link {
        /// The index.
        index: u32,
        /// The name.
        name: String,
    },
    /// An interface gone.
    LinkGone(u32),
}

/// What a FIB route goes through: the immediate next hop and the
/// interface it is reached on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hop {
    /// The gateway: the next hop itself when it is on a connected
    /// network, else the gateway of the kernel route that resolves it.
    pub gateway: IpAddr,
    /// The interface index; `None` without a kernel table.
    pub oif: Option<u32>,
}

/// What a next hop resolves to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolution {
    /// No kernel route covers it, or the one that does forwards nothing:
    /// the routes that use it are no candidates (RFC 4271 §9.1.2).
    Unresolved,
    /// Reachable through `hop`.
    Resolved {
        /// What the FIB installs its routes through.
        hop: Hop,
        /// The kernel route that resolves it; `None` without a kernel
        /// table.
        through: Option<Prefix>,
    },
}

impl Resolution {
    /// The hop, if resolved.
    #[must_use]
    pub const fn hop(&self) -> Option<Hop> {
        match self {
            Resolution::Resolved { hop, .. } => Some(*hop),
            Resolution::Unresolved => None,
        }
    }

    /// Whether the next hop resolves.
    #[must_use]
    pub const fn is_resolved(&self) -> bool {
        matches!(self, Resolution::Resolved { .. })
    }
}

/// One next hop the RIB's routes use, for the control plane and logs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NextHopReport {
    /// The next hop, as the routes have it after import policy.
    pub addr: IpAddr,
    /// What it resolves to.
    pub resolution: Resolution,
    /// The name of the interface of its hop, when known.
    pub interface: Option<String>,
    /// Routes in the Adj-RIBs-In with it, held ones included.
    pub routes: usize,
}

impl fmt::Display for NextHopReport {
    /// `ADDR unresolved`, or `ADDR via GATEWAY dev NAME` (`dev` with the
    /// index when the name is unknown, nothing without an interface).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.resolution {
            Resolution::Unresolved => write!(f, "{} unresolved", self.addr),
            Resolution::Resolved { hop, .. } => {
                write!(f, "{} via {}", self.addr, hop.gateway)?;
                match (&self.interface, hop.oif) {
                    (Some(name), _) => write!(f, " dev {name}"),
                    (None, Some(oif)) => write!(f, " dev {oif}"),
                    (None, None) => Ok(()),
                }
            }
        }
    }
}

/// What a change of the kernel's table did (see
/// [`Rib::kernel`](crate::Rib::kernel)), for the caller to log: counts,
/// as for a [`Rejudged`](crate::Rejudged), and the next hops it moved.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NextHopsChanged {
    /// Next hops that resolve now and did not.
    pub resolved: usize,
    /// Next hops that no longer resolve.
    pub unresolved: usize,
    /// Next hops that resolve through another gateway or interface.
    pub moved: usize,
    /// Each of those next hops, as it is now, in address order: as many
    /// as next hops in use at most, never one per route.
    pub next_hops: Vec<NextHopReport>,
    /// Routes the change took out of use: candidates before, held after.
    pub held: usize,
    /// Routes it put back into use: held before, candidates after.
    pub released: usize,
    /// Destinations where the decision process then chose another route,
    /// or none. A route whose next hop moved stays the best: it changes
    /// in the FIB only.
    pub best_changed: usize,
}

/// How a next hop's resolution changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Shift {
    /// It resolves and did not.
    Resolved,
    /// It no longer resolves.
    Unresolved,
    /// It resolves through another hop.
    Moved,
}

/// The kernel routes of one family, by prefix, each prefix's routes in
/// metric order.
#[derive(Debug)]
struct Family {
    routes: BTreeMap<Prefix, Vec<(u32, Via)>>,
    /// Routes per prefix length, so that a lookup tries only the lengths
    /// there are: a main table has a handful.
    lengths: [u32; 129],
}

impl Default for Family {
    fn default() -> Family {
        Family {
            routes: BTreeMap::new(),
            lengths: [0; 129],
        }
    }
}

impl Family {
    fn insert(&mut self, prefix: Prefix, metric: u32, via: Via) {
        let routes = self.routes.entry(prefix).or_default();
        match routes.binary_search_by_key(&metric, |(m, _)| *m) {
            Ok(i) => routes[i].1 = via,
            Err(i) => {
                routes.insert(i, (metric, via));
                self.lengths[usize::from(prefix.prefix_len())] += 1;
            }
        }
    }

    fn remove(&mut self, prefix: Prefix, metric: u32) {
        let Some(routes) = self.routes.get_mut(&prefix) else {
            return;
        };
        if let Ok(i) = routes.binary_search_by_key(&metric, |(m, _)| *m) {
            routes.remove(i);
            self.lengths[usize::from(prefix.prefix_len())] -= 1;
            if routes.is_empty() {
                self.routes.remove(&prefix);
            }
        }
    }

    /// The longest prefix that covers `addr`, with its lowest-metric
    /// route.
    fn lookup(&self, addr: IpAddr) -> Option<(Prefix, Via)> {
        let max = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        (0..=max)
            .rev()
            .filter(|&len| self.lengths[usize::from(len)] > 0)
            .find_map(|len| {
                let p = Prefix::new(addr, len)?;
                let (_, via) = self.routes.get(&p)?.first()?;
                Some((p, *via))
            })
    }

    fn len(&self) -> usize {
        self.routes.values().map(Vec::len).sum()
    }
}

/// The copy of the kernel's routes a next hop may resolve through.
#[derive(Debug, Default)]
pub(crate) struct Kernel {
    v4: Family,
    v6: Family,
}

impl Kernel {
    fn family(&mut self, prefix: Prefix) -> &mut Family {
        match prefix {
            Prefix::V4 { .. } => &mut self.v4,
            Prefix::V6 { .. } => &mut self.v6,
        }
    }

    /// Add `route`, or replace the one with its prefix and metric. A
    /// default route is never kept: nothing resolves through one (FRR's
    /// default, without `resolve-via-default`), whatever the caller's
    /// filter let through.
    pub(crate) fn insert(&mut self, route: KernelRoute) {
        if route.prefix.prefix_len() > 0 {
            self.family(route.prefix)
                .insert(route.prefix, route.metric, route.via);
        }
    }

    /// Remove the route with `prefix` and `metric`, if there is one.
    pub(crate) fn remove(&mut self, prefix: Prefix, metric: u32) {
        self.family(prefix).remove(prefix, metric);
    }

    /// The route `addr` matches: the longest prefix that covers it (RFC
    /// 4271 §9.1.2.1 1)), and of that prefix's routes the lowest metric,
    /// as the kernel chooses.
    pub(crate) fn lookup(&self, addr: IpAddr) -> Option<(Prefix, Via)> {
        match addr {
            IpAddr::V4(_) => self.v4.lookup(addr),
            IpAddr::V6(_) => self.v6.lookup(addr),
        }
    }

    /// What `addr` resolves to: unresolved when no route covers it or the
    /// one that does forwards nothing; else through the route's gateway,
    /// the immediate next hop, or `addr` itself for a connected or device
    /// route, on the route's interface. An IPv6 route's link-local
    /// gateway comes with the interface it is on, which is what makes it
    /// usable.
    pub(crate) fn resolve(&self, addr: IpAddr) -> Resolution {
        match self.lookup(addr) {
            Some((through, Via::Unicast { gateway, oif })) => Resolution::Resolved {
                hop: Hop {
                    gateway: gateway.unwrap_or(addr),
                    oif: Some(oif),
                },
                through: Some(through),
            },
            Some((_, Via::Unreachable)) | None => Resolution::Unresolved,
        }
    }

    /// Routes held.
    pub(crate) fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }
}

/// One next hop in use.
#[derive(Debug)]
struct Tracked {
    addr: IpAddr,
    resolution: Resolution,
    /// Routes in the Adj-RIBs-In with it, held ones included.
    routes: u32,
    /// The IPv4 destinations with such a route.
    v4: BTreeSet<Ipv4Key>,
    /// The IPv6 destinations with such a route.
    v6: BTreeSet<Prefix>,
}

/// The next hops the RIB's routes use, each with its resolution and the
/// destinations that have a route with it (`NextHops::link`), and the copy
/// of the kernel's table they resolve against.
///
/// Every route in the Adj-RIBs-In, held or not, counts under the next hop
/// of its current attributes (after import policy; the global address for
/// IPv6): the index needs to know nothing of why a route is held, and a
/// route an RPKI hold releases already sits in it.
#[derive(Debug, Default)]
pub(crate) struct NextHops {
    /// `None`: no table given, every next hop resolves to itself.
    kernel: Option<Kernel>,
    /// Interface names by index, for display.
    names: HashMap<u32, String>,
    /// The next hops, by slot; a free slot is reused.
    slots: Vec<Option<Tracked>>,
    index: HashMap<IpAddr, u32>,
    free: Vec<u32>,
    /// The slot used last: the routes of one UPDATE share their next hop,
    /// so most lookups end here without hashing.
    last: Option<u32>,
    /// Slots whose route count fell to zero during the input, removed at
    /// its end ([`NextHops::settle`]) if still unused: an UPDATE that
    /// replaces every route of a next hop does not drop and resolve it
    /// again per route.
    zeroed: Vec<u32>,
    /// The resolutions the input being handled replaced, for
    /// [`NextHops::hop_before`].
    before: Vec<(IpAddr, Resolution)>,
}

fn at(slot: u32) -> usize {
    // invariant: slots are Vec indices.
    usize::try_from(slot).unwrap()
}

impl NextHops {
    /// What `addr` resolves to against the copy, or to itself without
    /// one.
    fn resolve(&self, addr: IpAddr) -> Resolution {
        match &self.kernel {
            Some(k) => k.resolve(addr),
            None => Resolution::Resolved {
                hop: Hop {
                    gateway: addr,
                    oif: None,
                },
                through: None,
            },
        }
    }

    fn tracked(&self, addr: IpAddr) -> Option<&Tracked> {
        let slot = *self.index.get(&addr)?;
        self.slots[at(slot)].as_ref()
    }

    /// The slot of `addr`, tracked from now on, resolved when first seen.
    fn slot(&mut self, addr: IpAddr) -> u32 {
        if let Some(s) = self.last
            && self.slots[at(s)].as_ref().is_some_and(|t| t.addr == addr)
        {
            return s;
        }
        let s = if let Some(&s) = self.index.get(&addr) {
            s
        } else {
            let tracked = Tracked {
                addr,
                resolution: self.resolve(addr),
                routes: 0,
                v4: BTreeSet::new(),
                v6: BTreeSet::new(),
            };
            let s = if let Some(s) = self.free.pop() {
                self.slots[at(s)] = Some(tracked);
                s
            } else {
                self.slots.push(Some(tracked));
                // invariant: fewer than 2^32 next hops.
                u32::try_from(self.slots.len() - 1).unwrap()
            };
            self.index.insert(addr, s);
            // Unused until a route links it: removed at the end of the
            // input if none does.
            self.zeroed.push(s);
            s
        };
        self.last = Some(s);
        s
    }

    fn get_mut(&mut self, slot: u32) -> &mut Tracked {
        // invariant: slots handed out by `slot` are occupied until
        // `settle` frees them.
        self.slots[at(slot)].as_mut().unwrap()
    }

    /// Whether `addr` resolves, tracking it from now on: the decision
    /// never waits for a next hop it has not seen.
    pub(crate) fn resolved(&mut self, addr: IpAddr) -> bool {
        let s = self.slot(addr);
        self.get_mut(s).resolution.is_resolved()
    }

    /// A route with next hop `addr` came to `prefix`.
    pub(crate) fn link(&mut self, addr: IpAddr, prefix: Prefix) {
        let s = self.slot(addr);
        let t = self.get_mut(s);
        t.routes += 1;
        match Ipv4Key::new(prefix) {
            Some(k) => t.v4.insert(k),
            None => t.v6.insert(prefix),
        };
    }

    /// A route with next hop `addr` left `prefix`, whose routes are now
    /// `dest`'s: the destination stays listed while another of them has
    /// `addr`, as two peers that pass on one next hop do.
    pub(crate) fn unlink(&mut self, addr: IpAddr, prefix: Prefix, dest: &Destination) {
        let s = match self.last {
            Some(s) if self.slots[at(s)].as_ref().is_some_and(|t| t.addr == addr) => s,
            _ => match self.index.get(&addr) {
                Some(&s) => s,
                None => return,
            },
        };
        self.last = Some(s);
        let still = dest.routes().iter().any(|r| r.next_hop() == addr);
        let t = self.get_mut(s);
        t.routes = t.routes.saturating_sub(1);
        if !still {
            match Ipv4Key::new(prefix) {
                Some(k) => t.v4.remove(&k),
                None => t.v6.remove(&prefix),
            };
        }
        if t.routes == 0 {
            self.zeroed.push(s);
        }
    }

    /// The hop of `addr` now, if it resolves.
    pub(crate) fn hop(&self, addr: IpAddr) -> Option<Hop> {
        match self.tracked(addr) {
            Some(t) => t.resolution.hop(),
            None => self.resolve(addr).hop(),
        }
    }

    /// The hop of `addr` before the input being handled changed its
    /// resolution, else now: what the FIB was last given for a route with
    /// it, which a change must name as the one it replaces.
    pub(crate) fn hop_before(&self, addr: IpAddr) -> Option<Hop> {
        match self.before.iter().find(|(a, _)| *a == addr) {
            Some((_, r)) => r.hop(),
            None => self.hop(addr),
        }
    }

    /// The end of an input: forget the resolutions it replaced, and the
    /// next hops no route uses any more.
    pub(crate) fn settle(&mut self) {
        self.before.clear();
        for s in self.zeroed.drain(..) {
            let Some(t) = &self.slots[at(s)] else {
                continue;
            };
            if t.routes == 0 {
                self.index.remove(&t.addr);
                self.slots[at(s)] = None;
                self.free.push(s);
                if self.last == Some(s) {
                    self.last = None;
                }
            }
        }
    }

    /// Apply `update` to the copy and resolve again every next hop it may
    /// have changed: all of them for a whole table, else those a changed
    /// prefix covers. The next hops whose resolution moved, in address
    /// order, with how; the resolutions they had are kept until
    /// [`NextHops::settle`]. A change of the kernel route that resolves a
    /// next hop alone, through the same hop, is kept and reported nowhere
    /// but in [`NextHops::reports`].
    pub(crate) fn update(&mut self, update: KernelUpdate) -> Vec<(IpAddr, Shift)> {
        // The first table, whole or as changes to an empty one, ends the
        // default of every next hop resolving to itself: all of them are
        // resolved again.
        let first = self.kernel.is_none();
        let kernel = self.kernel.get_or_insert_default();
        let mut touched: Option<Vec<Prefix>> = (!first).then(Vec::new);
        match update {
            KernelUpdate::Table { routes, links } => {
                *kernel = Kernel::default();
                for r in routes {
                    kernel.insert(r);
                }
                self.names = links.into_iter().collect();
                touched = None;
            }
            KernelUpdate::Changes(changes) => {
                for c in changes {
                    match c {
                        KernelChange::Route(r) => {
                            kernel.insert(r);
                            if let Some(t) = &mut touched {
                                t.push(r.prefix);
                            }
                        }
                        KernelChange::Gone { prefix, metric } => {
                            kernel.remove(prefix, metric);
                            if let Some(t) = &mut touched {
                                t.push(prefix);
                            }
                        }
                        KernelChange::Link { index, name } => {
                            self.names.insert(index, name);
                        }
                        KernelChange::LinkGone(index) => {
                            self.names.remove(&index);
                        }
                    }
                }
            }
        }
        let mut shifts = Vec::new();
        for s in 0..self.slots.len() {
            let Some(t) = &self.slots[s] else {
                continue;
            };
            let addr = t.addr;
            // A changed prefix that covers the next hop may change what it
            // resolves to; no other can.
            let affected = touched.as_ref().is_none_or(|prefixes| {
                prefixes
                    .iter()
                    .any(|p| Prefix::new(addr, p.prefix_len()) == Some(*p))
            });
            if !affected {
                continue;
            }
            let new = self.resolve(addr);
            // invariant: `s` is occupied, checked above.
            let t = self.slots[s].as_mut().unwrap();
            let old = std::mem::replace(&mut t.resolution, new);
            let shift = match (old.hop(), new.hop()) {
                (None, Some(_)) => Shift::Resolved,
                (Some(_), None) => Shift::Unresolved,
                (Some(a), Some(b)) if a != b => Shift::Moved,
                _ => continue,
            };
            self.before.push((addr, old));
            shifts.push((addr, shift));
        }
        shifts.sort_unstable_by_key(|(a, _)| *a);
        shifts
    }

    /// The destinations with a route through any of `shifts`' next hops,
    /// in prefix order, each once.
    pub(crate) fn destinations(&self, shifts: &[(IpAddr, Shift)]) -> (Vec<Ipv4Key>, Vec<Prefix>) {
        let sets: Vec<&Tracked> = shifts
            .iter()
            .filter_map(|(a, _)| self.tracked(*a))
            .collect();
        let mut v4: Vec<Ipv4Key> = sets.iter().flat_map(|t| t.v4.iter().copied()).collect();
        let mut v6: Vec<Prefix> = sets.iter().flat_map(|t| t.v6.iter().copied()).collect();
        // One next hop's set is in order already; several are merged.
        if sets.len() > 1 {
            v4.sort_unstable();
            v4.dedup();
            v6.sort_unstable();
            v6.dedup();
        }
        (v4, v6)
    }

    /// The report of next hop `addr`.
    pub(crate) fn report(&self, addr: IpAddr) -> NextHopReport {
        let (resolution, routes) = match self.tracked(addr) {
            Some(t) => (
                t.resolution,
                usize::try_from(t.routes).unwrap_or(usize::MAX),
            ),
            None => (self.resolve(addr), 0),
        };
        let interface = resolution
            .hop()
            .and_then(|h| h.oif)
            .and_then(|oif| self.names.get(&oif).cloned());
        NextHopReport {
            addr,
            resolution,
            interface,
            routes,
        }
    }

    /// Every next hop in use, in address order.
    pub(crate) fn reports(&self) -> Vec<NextHopReport> {
        let mut addrs: Vec<IpAddr> = self.index.keys().copied().collect();
        addrs.sort_unstable();
        addrs.into_iter().map(|a| self.report(a)).collect()
    }

    /// Routes in the copy of the kernel's table; `None` without one.
    pub(crate) fn kernel_routes(&self) -> Option<usize> {
        self.kernel.as_ref().map(Kernel::len)
    }

    /// The next hops tracked, with their route counts and destinations,
    /// for `Rib::check_next_hops`; and that each resolution is what the
    /// copy gives now, and nothing is left of an input.
    #[cfg(test)]
    pub(crate) fn check(&self, want: &HashMap<IpAddr, (u32, BTreeSet<Ipv4Key>, BTreeSet<Prefix>)>) {
        assert!(self.before.is_empty(), "before: {:?}", self.before);
        assert!(self.zeroed.is_empty(), "zeroed: {:?}", self.zeroed);
        let mut have = HashMap::new();
        for t in self.slots.iter().flatten() {
            assert_eq!(
                self.index
                    .get(&t.addr)
                    .map(|&s| self.slots[at(s)].as_ref().map(|t| t.addr)),
                Some(Some(t.addr))
            );
            assert_eq!(t.resolution, self.resolve(t.addr), "{}", t.addr);
            have.insert(t.addr, (t.routes, t.v4.clone(), t.v6.clone()));
        }
        assert_eq!(self.index.len(), have.len());
        assert_eq!(&have, want);
    }

    /// What `addr` resolves to, for the tests' checks.
    #[cfg(test)]
    pub(crate) fn resolution(&self, addr: IpAddr) -> Resolution {
        self.tracked(addr)
            .map_or_else(|| self.resolve(addr), |t| t.resolution)
    }
}
