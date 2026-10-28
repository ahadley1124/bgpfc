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

use std::collections::{BTreeMap, HashMap};
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
        /// Whether the gateway is on the link of `oif` though no route
        /// covers it (`RTNH_F_ONLINK`): a route through it needs it too.
        onlink: bool,
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
    /// Whether the gateway is on the interface's link though no route
    /// covers it, as the kernel route that resolves the next hop says
    /// (`onlink`, such as an IGP's route over an unnumbered link): the
    /// kernel takes a route through it only so marked.
    pub onlink: bool,
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
    /// index when the name is unknown, nothing without an interface), then
    /// ` onlink` when the gateway is.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.resolution {
            Resolution::Unresolved => write!(f, "{} unresolved", self.addr),
            Resolution::Resolved { hop, .. } => {
                write!(f, "{} via {}", self.addr, hop.gateway)?;
                match (&self.interface, hop.oif) {
                    (Some(name), _) => write!(f, " dev {name}")?,
                    (None, Some(oif)) => write!(f, " dev {oif}")?,
                    (None, None) => {}
                }
                if hop.onlink {
                    f.write_str(" onlink")?;
                }
                Ok(())
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
    /// usable; a gateway the route has `onlink` goes on with it, which the
    /// kernel needs of a gateway no route covers. The next hop itself, on
    /// a connected or device route, is covered by that route.
    pub(crate) fn resolve(&self, addr: IpAddr) -> Resolution {
        match self.lookup(addr) {
            Some((
                through,
                Via::Unicast {
                    gateway,
                    oif,
                    onlink,
                },
            )) => Resolution::Resolved {
                hop: Hop {
                    gateway: gateway.unwrap_or(addr),
                    oif: Some(oif),
                    onlink: onlink && gateway.is_some(),
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

/// A set of destinations kept as a sorted base and logs of what was added
/// and removed since: adding or removing one costs a push, where a B-tree
/// insert would cost a descent of a tree as large as the table, cache
/// misses included, for every route that comes. The set is read only when
/// its next hop's resolution changes, rarely, and is sorted then; the logs
/// are folded in, at the end of an input, once they are a quarter of the
/// set, which bounds the memory they take.
///
/// The callers add a destination only when it is not a member and remove
/// it only when it is: they know from the destination's routes. So a
/// destination's count, in the base plus added minus removed, is 0 or 1.
#[derive(Clone, Debug)]
struct Members<K> {
    /// The members when the logs were last folded in, sorted, each once.
    base: Vec<K>,
    /// Added since, in order.
    added: Vec<K>,
    /// Removed since, in order.
    removed: Vec<K>,
}

impl<K> Default for Members<K> {
    fn default() -> Self {
        Members {
            base: Vec::new(),
            added: Vec::new(),
            removed: Vec::new(),
        }
    }
}

impl<K: Ord + Copy> Members<K> {
    fn insert(&mut self, k: K) {
        self.added.push(k);
    }

    fn remove(&mut self, k: K) {
        self.removed.push(k);
    }

    /// Whether the logs are a quarter of the set or more, and worth
    /// folding in.
    fn untidy(&self) -> bool {
        self.added.len() + self.removed.len() > self.base.len() / 4 + 64
    }

    /// Fold the logs into the base: the members and those added since,
    /// merged in place from the back, less one of each pair a removal
    /// cancels. The base grows by exactly what was added and nothing else
    /// is allocated: a sort's scratch space for a table's members would be
    /// the largest allocation the index makes.
    fn compact(&mut self) {
        if self.added.is_empty() && self.removed.is_empty() {
            return;
        }
        self.added.sort_unstable();
        let (mut i, mut j) = (self.base.len(), self.added.len());
        self.base.reserve_exact(j);
        // Room at the end, overwritten by the merge.
        self.base.extend_from_slice(&self.added);
        while j > 0 {
            let k = i + j - 1;
            if i > 0 && self.base[i - 1] > self.added[j - 1] {
                self.base[k] = self.base[i - 1];
                i -= 1;
            } else {
                self.base[k] = self.added[j - 1];
                j -= 1;
            }
        }
        if !self.removed.is_empty() {
            self.removed.sort_unstable();
            let mut removed = self.removed.iter().peekable();
            self.base.retain(|k| removed.next_if_eq(&k).is_none());
        }
        // The callers' discipline: a member is added only when it is not
        // one, and removed only when it is.
        debug_assert!(self.base.windows(2).all(|w| w[0] < w[1]), "a member twice");
        if self.base.capacity() > 2 * self.base.len() {
            self.base.shrink_to_fit();
        }
        // Their room goes too: a table's load would otherwise keep it.
        self.added = Vec::new();
        self.removed = Vec::new();
    }

    /// The members, in order, each once.
    fn members(&mut self) -> &[K] {
        self.compact();
        &self.base
    }

    /// The members, in order, without folding the logs in.
    #[cfg(test)]
    fn snapshot(&self) -> Vec<K> {
        let mut copy = self.clone();
        copy.compact();
        copy.base
    }
}

/// What the tests' check counts for a next hop: its routes and the IPv4
/// and IPv6 destinations they are routes to.
#[cfg(test)]
pub(crate) type Uses = (
    u32,
    std::collections::BTreeSet<Ipv4Key>,
    std::collections::BTreeSet<Prefix>,
);

/// One next hop in use.
#[derive(Debug)]
struct Tracked {
    addr: IpAddr,
    resolution: Resolution,
    /// Routes in the Adj-RIBs-In with it, held ones included.
    routes: u32,
    /// The IPv4 destinations with such a route.
    v4: Members<Ipv4Key>,
    /// The IPv6 destinations with such a route.
    v6: Members<Prefix>,
}

impl Tracked {
    /// `prefix` becomes a destination with a route through the next hop.
    fn join(&mut self, prefix: Prefix) {
        match Ipv4Key::new(prefix) {
            Some(k) => self.v4.insert(k),
            None => self.v6.insert(prefix),
        }
    }

    /// `prefix` is no longer one.
    fn leave(&mut self, prefix: Prefix) {
        match Ipv4Key::new(prefix) {
            Some(k) => self.v4.remove(k),
            None => self.v6.remove(prefix),
        }
    }
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
                    onlink: false,
                },
                through: None,
            },
        }
    }

    /// The slot of `addr`, if it is tracked: the one used last, which the
    /// routes of an UPDATE and the FIB changes they make share, without
    /// hashing.
    fn find(&self, addr: IpAddr) -> Option<u32> {
        match self.last {
            Some(s) if self.slots[at(s)].as_ref().is_some_and(|t| t.addr == addr) => Some(s),
            _ => self.index.get(&addr).copied(),
        }
    }

    fn tracked(&self, addr: IpAddr) -> Option<&Tracked> {
        self.slots[at(self.find(addr)?)].as_ref()
    }

    /// The slot of `addr`, tracked from now on, resolved when first seen.
    fn slot(&mut self, addr: IpAddr) -> u32 {
        let s = if let Some(s) = self.find(addr) {
            s
        } else {
            let tracked = Tracked {
                addr,
                resolution: self.resolve(addr),
                routes: 0,
                v4: Members::default(),
                v6: Members::default(),
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

    /// A route with next hop `addr` came to `prefix`, `first` there with
    /// it: then the destination becomes one of the next hop's.
    pub(crate) fn link(&mut self, addr: IpAddr, prefix: Prefix, first: bool) {
        let s = self.slot(addr);
        let t = self.get_mut(s);
        t.routes += 1;
        if first {
            t.join(prefix);
        }
    }

    /// A route with next hop `addr` left `prefix`, the `last` there with
    /// it: then the destination stops being one of the next hop's. While
    /// another route there has it, as when two peers pass on one next hop,
    /// it stays.
    pub(crate) fn unlink(&mut self, addr: IpAddr, prefix: Prefix, last: bool) {
        let Some(s) = self.find(addr) else {
            return;
        };
        self.last = Some(s);
        let t = self.get_mut(s);
        t.routes = t.routes.saturating_sub(1);
        if last {
            t.leave(prefix);
        }
        if t.routes == 0 {
            self.zeroed.push(s);
        }
    }

    /// One route more, or fewer, with next hop `addr`.
    pub(crate) fn count(&mut self, addr: IpAddr, more: bool) {
        let s = if more {
            self.slot(addr)
        } else {
            let Some(s) = self.find(addr) else {
                return;
            };
            self.last = Some(s);
            s
        };
        let t = self.get_mut(s);
        if more {
            t.routes += 1;
        } else {
            t.routes = t.routes.saturating_sub(1);
            if t.routes == 0 {
                self.zeroed.push(s);
            }
        }
    }

    /// `prefix` becomes, or stops being, a destination with a route through
    /// `addr`.
    fn mark(&mut self, addr: IpAddr, prefix: Prefix, member: bool) {
        let s = if member {
            self.slot(addr)
        } else {
            let Some(s) = self.find(addr) else {
                return;
            };
            s
        };
        let t = self.get_mut(s);
        if member {
            t.join(prefix);
        } else {
            t.leave(prefix);
        }
    }

    /// The routes of `prefix` were judged again, and some changed next hop
    /// (counted with [`NextHops::count`]): `before` are the next hops they
    /// had, one per route, and `dest` has the routes now. A destination is
    /// a next hop's while one of its routes has it.
    pub(crate) fn remark(&mut self, prefix: Prefix, before: &[IpAddr], dest: &Destination) {
        let routes = dest.routes();
        for (i, r) in routes.iter().enumerate() {
            let k = r.next_hop();
            if !routes[..i].iter().any(|o| o.next_hop() == k) && !before.contains(&k) {
                self.mark(k, prefix, true);
            }
        }
        for (i, &k) in before.iter().enumerate() {
            if !before[..i].contains(&k) && !dest.has_next_hop(k, None) {
                self.mark(k, prefix, false);
            }
        }
    }

    /// The hop of `addr` now, if it resolves.
    pub(crate) fn current_hop(&self, addr: IpAddr) -> Option<Hop> {
        match self.tracked(addr) {
            Some(t) => t.resolution.hop(),
            None => self.resolve(addr).hop(),
        }
    }

    /// [`NextHops::current_hop`], remembering the next hop as the one
    /// used last: the FIB changes of an input come a destination after
    /// another, most of them through one next hop.
    pub(crate) fn hop(&mut self, addr: IpAddr) -> Option<Hop> {
        match self.find(addr) {
            Some(s) => {
                self.last = Some(s);
                self.slots[at(s)].as_ref().and_then(|t| t.resolution.hop())
            }
            None => self.resolve(addr).hop(),
        }
    }

    /// The hop of `addr` before the input being handled changed its
    /// resolution, else now: what the FIB was last given for a route with
    /// it, which a change must name as the one it replaces.
    pub(crate) fn hop_before(&mut self, addr: IpAddr) -> Option<Hop> {
        match self.before.iter().find(|(a, _)| *a == addr) {
            Some((_, r)) => r.hop(),
            None => self.hop(addr),
        }
    }

    /// The end of an input: forget the resolutions it replaced, and the
    /// next hops no route uses any more.
    pub(crate) fn settle(&mut self) {
        self.before.clear();
        for t in self.slots.iter_mut().flatten() {
            if t.v4.untidy() {
                t.v4.compact();
            }
            if t.v6.untidy() {
                t.v6.compact();
            }
        }
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
    pub(crate) fn destinations(
        &mut self,
        shifts: &[(IpAddr, Shift)],
    ) -> (Vec<Ipv4Key>, Vec<Prefix>) {
        let (mut v4, mut v6) = (Vec::new(), Vec::new());
        let mut sets = 0;
        for (addr, _) in shifts {
            let Some(s) = self.find(*addr) else {
                continue;
            };
            let t = self.get_mut(s);
            v4.extend_from_slice(t.v4.members());
            v6.extend_from_slice(t.v6.members());
            sets += 1;
        }
        // One next hop's set is in order already; several are merged.
        if sets > 1 {
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
    pub(crate) fn check(&self, want: &HashMap<IpAddr, Uses>) {
        use std::collections::BTreeSet;
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
            let v4: BTreeSet<Ipv4Key> = t.v4.snapshot().into_iter().collect();
            let v6: BTreeSet<Prefix> = t.v6.snapshot().into_iter().collect();
            have.insert(t.addr, (t.routes, v4, v6));
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use proptest::prelude::*;

    use super::*;

    proptest! {
        /// Whatever members come and go, and whenever the logs are folded
        /// in, the set is the one a B-tree set would hold.
        #[test]
        fn members_are_the_set_a_btree_holds(
            ops in proptest::collection::vec((0u8..24, 0u8..8), 0..300),
        ) {
            let mut m: Members<u8> = Members::default();
            let mut model = BTreeSet::new();
            for (k, op) in ops {
                match op {
                    // Folded in now and then, as an input ends or a next
                    // hop's resolution changes.
                    0 => {
                        prop_assert_eq!(m.members(), &model.iter().copied().collect::<Vec<_>>()[..]);
                    }
                    1 if m.untidy() => m.compact(),
                    // Added when not a member, removed when one: what the
                    // destination's routes tell the callers.
                    _ if model.insert(k) => m.insert(k),
                    _ => {
                        model.remove(&k);
                        m.remove(k);
                    }
                }
                prop_assert_eq!(m.snapshot(), model.iter().copied().collect::<Vec<_>>());
            }
        }
    }

    #[test]
    fn logs_are_folded_in_once_they_are_a_quarter_of_the_set() {
        let mut m: Members<u32> = Members::default();
        for k in 0..64 {
            m.insert(k);
        }
        assert!(!m.untidy());
        m.insert(64);
        assert!(m.untidy());
        m.compact();
        assert_eq!(m.base.len(), 65);
        assert!(m.added.is_empty() && m.removed.is_empty());
        // Removals count too: 81 changes of a set of 65 are untidy.
        for k in 0..65 {
            m.remove(k);
        }
        assert!(!m.untidy());
        for k in 100..116 {
            m.insert(k);
        }
        assert!(m.untidy());
        assert_eq!(m.members(), (100..116).collect::<Vec<_>>());
    }
}
