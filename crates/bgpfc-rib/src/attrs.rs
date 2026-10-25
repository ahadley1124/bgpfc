//! The attribute set of a route, shared between every route that carries
//! the same attributes (AGENTS.md §7, "Allocation").
//!
//! Implements: RFC 4271 §4.3 (the well-known attributes), §5 (unknown
//! optional transitive attributes are carried with the Partial bit);
//! RFC 4760 §3 (the next hop of multiprotocol routes); RFC 8950 §3 (IPv4
//! routes with an IPv6 next hop); RFC 1997, 4360, 8092 (communities);
//! RFC 7911 §3 (the Path Identifiers of announced and sent prefixes).

use std::collections::HashMap;
use std::hash::{BuildHasher, BuildHasherDefault, Hash, Hasher, RandomState};
use std::net::IpAddr;
use std::sync::Arc;

use bgpfc_wire::as_path::AsPath;
use bgpfc_wire::attribute::{Aggregator, Origin, PathAttribute, flags};
use bgpfc_wire::community::{Community, ExtendedCommunity, LargeCommunity};
use bgpfc_wire::mp::{MpReach, NextHop};
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::{AddressFamily, Afi, PathId};
use bgpfc_wire::update::{DecodedUpdate, PathIds, UpdateMessage};

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
#[derive(Clone, Debug, PartialEq, Eq)]
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
    /// COMMUNITIES, sorted and unique. The lists are boxed slices, not
    /// `Vec`s: an interned set never grows, and a table has one set per
    /// path, so the capacity field would cost 32 octets a set (four
    /// lists) for nothing.
    pub communities: Box<[Community]>,
    /// Extended Communities, sorted and unique.
    pub ext_communities: Box<[ExtendedCommunity]>,
    /// Large Communities, sorted and unique.
    pub large_communities: Box<[LargeCommunity]>,
    /// Unknown optional transitive attributes, by type code.
    pub unknown: Box<[UnknownAttribute]>,
}

/// Sort `list` and drop repeats; the common case, already so, allocates
/// nothing.
fn sort_unique<T: Ord + Copy>(list: &mut Box<[T]>) {
    if list.is_sorted_by(|a, b| a < b) {
        return;
    }
    let mut v = std::mem::take(list).into_vec();
    v.sort_unstable();
    v.dedup();
    *list = v.into_boxed_slice();
}

/// What an UPDATE announces, one entry per part of the message, each with
/// the next hop that goes with it (RFC 4760 §3): `NEXT_HOP` for the
/// RFC 4271 NLRI field, the attribute's own for `MP_REACH_NLRI`. IPv4
/// unicast may come in both at once (RFC 7606 §5.1), and in the latter with
/// an IPv6 next hop (RFC 8950 §3). Empty when treated as withdraw; the
/// NLRI field is left out when `NEXT_HOP` is missing, which the decoder
/// already turned into treat-as-withdraw. Each part comes with the Path
/// Identifiers of its prefixes (RFC 7911 §3), as many as the prefixes or
/// none when its family has no ADD-PATH.
pub fn announced(
    update: &DecodedUpdate,
) -> impl Iterator<Item = (AddressFamily, NextHop, &[Prefix], &[PathId])> {
    let m = &update.message;
    let live = update.treated_as_withdraw.is_none();
    let nlri = m
        .next_hop()
        .filter(|_| live && !m.nlri.is_empty())
        .map(|n| {
            (
                AddressFamily::IPV4_UNICAST,
                NextHop::Ipv4(n),
                &m.nlri[..],
                m.nlri_ids(),
            )
        });
    let mp = m
        .mp_reach
        .as_ref()
        .filter(|r| live && !r.nlri.is_empty())
        .map(|r| (r.family, r.next_hop, &r.nlri[..], m.mp_reach_ids()));
    nlri.into_iter().chain(mp)
}

impl PathAttrs {
    /// The attributes an UPDATE gives the routes it announces with
    /// `next_hop`, which [`announced`] picks per part of the message.
    #[must_use]
    pub fn from_update(m: &UpdateMessage, next_hop: NextHop) -> PathAttrs {
        let mut attrs = PathAttrs {
            origin: Origin::Incomplete,
            as_path: AsPath::empty(),
            next_hop,
            med: None,
            local_pref: None,
            atomic_aggregate: false,
            aggregator: None,
            communities: Box::default(),
            ext_communities: Box::default(),
            large_communities: Box::default(),
            unknown: Box::default(),
        };
        let mut unknown = Vec::new();
        for a in &m.attributes {
            match a {
                PathAttribute::Origin(o) => attrs.origin = *o,
                PathAttribute::AsPath(p) => attrs.as_path = p.clone(),
                PathAttribute::MultiExitDisc(v) => attrs.med = Some(*v),
                PathAttribute::LocalPref(v) => attrs.local_pref = Some(*v),
                PathAttribute::AtomicAggregate => attrs.atomic_aggregate = true,
                PathAttribute::Aggregator(g) => attrs.aggregator = Some(*g),
                PathAttribute::Communities(c) => attrs.communities = c.as_slice().into(),
                PathAttribute::ExtendedCommunities(c) => {
                    attrs.ext_communities = c.as_slice().into();
                }
                PathAttribute::LargeCommunities(c) => attrs.large_communities = c.as_slice().into(),
                PathAttribute::Unknown { flags, code, value } => {
                    unknown.push(UnknownAttribute {
                        flags: *flags,
                        code: *code,
                        value: value.clone(),
                    });
                }
                // The caller chose the next hop for the part of the message
                // the routes came in; the MP attributes are never in
                // `attributes`, the decoder lifts them out.
                PathAttribute::NextHop(_)
                | PathAttribute::MpReach(_)
                | PathAttribute::MpUnreach(_) => {}
            }
        }
        attrs.unknown = unknown.into_boxed_slice();
        attrs.normalise();
        attrs
    }

    /// Sort and deduplicate the sets so equal attribute sets compare
    /// equal whatever order they arrived in.
    pub fn normalise(&mut self) {
        sort_unique(&mut self.communities);
        sort_unique(&mut self.ext_communities);
        sort_unique(&mut self.large_communities);
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

    /// As [`PathAttrs::to_update`], for a family sent with Path Identifiers
    /// (RFC 7911 §3): `ids[i]` goes with `nlri[i]`, in whichever field the
    /// prefixes went.
    #[must_use]
    pub fn to_update_paths(
        &self,
        family: AddressFamily,
        nlri: Vec<Prefix>,
        ids: Vec<PathId>,
    ) -> UpdateMessage {
        let mut m = self.to_update(family, nlri);
        let mut path_ids = PathIds::default();
        if m.mp_reach.is_some() {
            path_ids.mp_reach = ids;
        } else {
            path_ids.nlri = ids;
        }
        m.path_ids = Some(Box::new(path_ids));
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
            out.push(PathAttribute::Communities(self.communities.to_vec()));
        }
        if !self.ext_communities.is_empty() {
            out.push(PathAttribute::ExtendedCommunities(
                self.ext_communities.to_vec(),
            ));
        }
        if !self.large_communities.is_empty() {
            out.push(PathAttribute::LargeCommunities(
                self.large_communities.to_vec(),
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

// The interner hashes the attributes of every UPDATE. A derived Hash makes
// a hasher call per field and per AS number and community, and SipHash
// costs about as much per call as per eight octets hashed; this one
// writes the same fields as a few long runs of octets. Lists carry their
// length, so different attributes rarely meet; equal ones always hash
// alike, which is all `Eq` needs.
impl Hash for PathAttrs {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let mut w = Chunks::new(state);
        w.put(&[self.origin as u8]);
        let mut segments = 0;
        for seg in self.as_path.segments() {
            w.put(&[seg.kind as u8]);
            w.len(seg.len());
            for asn in seg.asns() {
                w.put(&asn.0.to_be_bytes());
            }
            segments += 1;
        }
        w.len(segments);
        match &self.next_hop {
            NextHop::Ipv4(a) => {
                w.put(&[4]);
                w.put(&a.octets());
            }
            NextHop::Ipv6 { global, link_local } => {
                w.put(&[6]);
                w.put(&global.octets());
                match link_local {
                    Some(l) => {
                        w.put(&[1]);
                        w.put(&l.octets());
                    }
                    None => w.put(&[0]),
                }
            }
        }
        for v in [self.med, self.local_pref] {
            match v {
                Some(v) => {
                    w.put(&[1]);
                    w.put(&v.to_be_bytes());
                }
                None => w.put(&[0]),
            }
        }
        w.put(&[u8::from(self.atomic_aggregate)]);
        match self.aggregator {
            Some(a) => {
                w.put(&[1]);
                w.put(&a.asn.0.to_be_bytes());
                w.put(&a.address.octets());
            }
            None => w.put(&[0]),
        }
        w.len(self.communities.len());
        for c in &self.communities {
            w.put(&c.0.to_be_bytes());
        }
        w.len(self.ext_communities.len());
        for c in &self.ext_communities {
            w.put(&c.0);
        }
        w.len(self.large_communities.len());
        for c in &self.large_communities {
            w.put(&c.global.to_be_bytes());
            w.put(&c.local1.to_be_bytes());
            w.put(&c.local2.to_be_bytes());
        }
        w.len(self.unknown.len());
        for u in &self.unknown {
            w.put(&[u.flags, u.code]);
            w.len(u.value.len());
            w.put(&u.value);
        }
        w.flush();
    }
}

/// Octets on their way to a hasher, passed on in long runs.
struct Chunks<'a, H: Hasher> {
    state: &'a mut H,
    buf: [u8; 128],
    used: usize,
}

impl<'a, H: Hasher> Chunks<'a, H> {
    fn new(state: &'a mut H) -> Self {
        Chunks {
            state,
            buf: [0; 128],
            used: 0,
        }
    }

    fn put(&mut self, octets: &[u8]) {
        if self.used + octets.len() > self.buf.len() {
            self.flush();
            if octets.len() > self.buf.len() {
                self.state.write(octets);
                return;
            }
        }
        self.buf[self.used..self.used + octets.len()].copy_from_slice(octets);
        self.used += octets.len();
    }

    fn len(&mut self, n: usize) {
        // invariant: no attribute list is anywhere near 2^32 long; the
        // value only has to be the same for equal lists.
        self.put(&u32::try_from(n).unwrap_or(u32::MAX).to_be_bytes());
    }

    fn flush(&mut self) {
        if self.used > 0 {
            self.state.write(&self.buf[..self.used]);
            self.used = 0;
        }
    }
}

/// Shares one allocation between routes with equal attributes.
///
/// Sets are kept by their hash, worked out once per call: hashing a whole
/// set is most of what interning costs, and a table of the sets
/// themselves hashed each one again to insert it and again every time the
/// table grew. The hash is keyed (`RandomState`), so a peer cannot choose
/// sets that collide; two different sets that collide anyway are not
/// shared, which costs memory, not correctness.
#[derive(Debug)]
pub struct Interner<S = RandomState> {
    sets: HashMap<u64, Arc<PathAttrs>, BuildHasherDefault<Prehashed>>,
    hasher: S,
    /// Size after the last sweep; a sweep runs when the set doubles.
    swept_at: usize,
}

/// The hasher of a table keyed by hashes already worked out: it passes
/// them through.
#[derive(Default)]
struct Prehashed(u64);

impl Hasher for Prehashed {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        // Only u64 keys are hashed here; this keeps any other input usable.
        for &b in bytes {
            self.0 = self.0.rotate_left(8) ^ u64::from(b);
        }
    }

    fn write_u64(&mut self, v: u64) {
        self.0 = v;
    }
}

impl Default for Interner {
    fn default() -> Self {
        Interner::with_hasher(RandomState::new())
    }
}

impl<S: BuildHasher> Interner<S> {
    /// An empty interner hashing with `hasher`.
    pub fn with_hasher(hasher: S) -> Interner<S> {
        Interner {
            sets: HashMap::default(),
            hasher,
            swept_at: 0,
        }
    }

    /// The shared instance of `attrs`.
    pub fn intern(&mut self, attrs: PathAttrs) -> Arc<PathAttrs> {
        let hash = self.hasher.hash_one(&attrs);
        if let Some(a) = self.sets.get(&hash) {
            if **a == attrs {
                return Arc::clone(a);
            }
            // A collision: this one is not shared.
            return Arc::new(attrs);
        }
        if self.sets.len() >= 2 * self.swept_at.max(1024) {
            self.sweep();
        }
        let a = Arc::new(attrs);
        self.sets.insert(hash, Arc::clone(&a));
        a
    }

    /// Give back one holder's share of `attrs`, and drop the entry as well
    /// when that was the last one outside the interner. Removing a route
    /// through here frees its attribute set with the route, rather than at
    /// the next sweep; the sweep remains for sets released otherwise.
    pub fn release(&mut self, attrs: Arc<PathAttrs>) {
        // Two holders: the interner and `attrs`. No other thread can take
        // a new one from nothing, so the count cannot rise meanwhile.
        if Arc::strong_count(&attrs) == 2 {
            let hash = self.hasher.hash_one(&*attrs);
            // Equal attributes in another allocation are not ours to drop.
            if self
                .sets
                .get(&hash)
                .is_some_and(|held| Arc::ptr_eq(held, &attrs))
            {
                self.sets.remove(&hash);
            }
        }
        drop(attrs);
        self.shrink();
    }

    /// Drop entries no route uses any more.
    pub fn sweep(&mut self) {
        self.sets.retain(|_, a| Arc::strong_count(a) > 1);
        self.swept_at = self.sets.len();
        self.shrink();
    }

    /// Give back most of the table once it is mostly empty, as after a peer
    /// with a full table goes: a hash table keeps its capacity otherwise.
    /// Halving the length each time keeps this O(1) per removal.
    fn shrink(&mut self) {
        if self.sets.capacity() > 64 && self.sets.len() < self.sets.capacity() / 4 {
            self.sets.shrink_to(self.sets.len() * 2);
        }
    }

    /// Distinct attribute sets held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sets.len()
    }

    /// Entries the table has room for without growing.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.sets.capacity()
    }

    /// Whether nothing is interned.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sets.is_empty()
    }
}
