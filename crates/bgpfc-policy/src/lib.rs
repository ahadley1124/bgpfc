//! Routing policy (AGENTS.md §3, "Policy"): ordered terms of match clauses
//! and set actions, compiled from the configuration and evaluated per
//! route on import and export.
//!
//! Implements: RFC 4271 §9.1.1 (local policy sets the degree of
//! preference), §9.1.3 (export policy); RFC 1997, 4360, 8092 (community
//! matching and setting); RFC 8950 §5 (`next-hop self` on an IPv6 session
//! gives IPv4 routes our IPv6 address once negotiated); `docs/config.md`,
//! "Policies".
#![forbid(unsafe_code)]

pub mod prefix_list;
pub mod regex;

use std::cell::Cell;
use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;

use bgpfc_config::ast::{Action, CommunityOp, Config, Match, SetAction};
use bgpfc_config::error::Pos;
use bgpfc_rib::{PathAttrs, PeerInfo, Policies, RovState, Verdict};
use bgpfc_wire::attribute::Origin;
use bgpfc_wire::community::{Community, ExtendedCommunity, LargeCommunity};
use bgpfc_wire::mp::NextHop;
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::AddressFamily;

pub use prefix_list::{PrefixList, PrefixRule};
pub use regex::{AsPathRegex, RegexError};

/// A policy that could not be compiled: `pos` points at the term.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyError {
    /// Where in the configuration file.
    pub pos: Pos,
    /// What is wrong.
    pub message: String,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.pos, self.message)
    }
}

impl std::error::Error for PolicyError {}

/// What a term matches on, with everything precompiled.
#[derive(Clone, Debug)]
enum Clause {
    Prefix(PrefixRule),
    PrefixList(usize),
    AsPath(AsPathRegex),
    Community(Community),
    ExtCommunity(ExtendedCommunity),
    LargeCommunity(LargeCommunity),
    Origin(Origin),
    Neighbor(IpAddr),
}

#[derive(Clone, Debug)]
struct Term {
    clauses: Vec<Clause>,
    sets: Vec<SetAction>,
    action: Action,
}

#[derive(Clone, Debug)]
struct Policy {
    terms: Vec<Term>,
}

/// Every policy and prefix list of a configuration, compiled.
#[derive(Clone, Debug, Default)]
pub struct PolicySet {
    prefix_lists: Vec<PrefixList>,
    policies: Vec<Policy>,
    /// Each policy's index in `policies`.
    names: HashMap<String, usize>,
}

/// The route a policy looks at.
#[derive(Clone, Copy, Debug)]
pub struct Route<'a> {
    /// The destination.
    pub prefix: Prefix,
    /// Its family.
    pub family: AddressFamily,
    /// Its attributes.
    pub attrs: &'a PathAttrs,
    /// The peer the route came from (import) or goes to (export); what
    /// `match neighbor` compares.
    pub neighbor: IpAddr,
    /// Our address on that peer's session; what `set next-hop self` uses.
    pub local_addr: IpAddr,
    /// Routes of the route's family may go to the peer with an IPv6 next
    /// hop, since it advertised Extended Next Hop Encoding for the family,
    /// and so did we (RFC 8950 §4): an IPv4 route may take an IPv6
    /// `local_addr` as its next hop.
    pub extended_next_hop: bool,
}

impl PolicySet {
    /// Compile every policy in `cfg`. The configuration has already been
    /// validated, so references resolve; only AS-path regexes can fail.
    ///
    /// # Errors
    /// One [`PolicyError`] per term whose regex does not compile.
    pub fn compile(cfg: &Config) -> Result<PolicySet, Vec<PolicyError>> {
        let mut errors = Vec::new();
        let list_index: HashMap<&str, usize> = cfg
            .prefix_lists
            .iter()
            .enumerate()
            .map(|(i, l)| (l.name.as_str(), i))
            .collect();
        let prefix_lists = cfg
            .prefix_lists
            .iter()
            .map(|l| PrefixList::new(&l.entries))
            .collect();
        let mut policies = Vec::new();
        let mut names = HashMap::new();
        for p in &cfg.policies {
            let mut terms = Vec::new();
            for t in &p.terms {
                let mut clauses = Vec::new();
                for m in &t.matches {
                    let clause = match m {
                        Match::Prefix(e) => Clause::Prefix(PrefixRule::new(e)),
                        Match::PrefixList(name) => {
                            let Some(i) = list_index.get(name.as_str()) else {
                                errors.push(PolicyError {
                                    pos: t.pos,
                                    message: format!("undefined prefix-list `{name}`"),
                                });
                                continue;
                            };
                            Clause::PrefixList(*i)
                        }
                        Match::AsPath(pattern) => match AsPathRegex::new(pattern) {
                            Ok(re) => Clause::AsPath(re),
                            Err(e) => {
                                errors.push(PolicyError {
                                    pos: t.pos,
                                    message: format!(
                                        "term `{}`: as-path regex \"{pattern}\" {e}",
                                        t.name
                                    ),
                                });
                                continue;
                            }
                        },
                        Match::Community(c) => Clause::Community(*c),
                        Match::ExtCommunity(c) => Clause::ExtCommunity(*c),
                        Match::LargeCommunity(c) => Clause::LargeCommunity(*c),
                        Match::Origin(o) => Clause::Origin(*o),
                        Match::Neighbor(a) => Clause::Neighbor(*a),
                    };
                    clauses.push(clause);
                }
                terms.push(Term {
                    clauses,
                    sets: t.sets.clone(),
                    action: t.action,
                });
            }
            names.insert(p.name.clone(), policies.len());
            policies.push(Policy { terms });
        }
        if errors.is_empty() {
            Ok(PolicySet {
                prefix_lists,
                policies,
                names,
            })
        } else {
            Err(errors)
        }
    }

    /// Whether a policy called `name` exists.
    #[must_use]
    pub fn has(&self, name: &str) -> bool {
        self.names.contains_key(name)
    }

    /// Run policy `name` on `route`. An unknown policy rejects, as does a
    /// policy no term of which decides (`docs/config.md`, "Policies").
    #[must_use]
    pub fn evaluate(&self, name: &str, route: &Route<'_>) -> Verdict {
        self.evaluate_at(self.names.get(name).copied(), route)
    }

    /// Run the policy at `index` (from `names`); `None` rejects, as an
    /// unknown policy does.
    fn evaluate_at(&self, index: Option<usize>, route: &Route<'_>) -> Verdict {
        let Some(policy) = index.and_then(|i| self.policies.get(i)) else {
            return Verdict::Reject;
        };
        let mut modified: Option<PathAttrs> = None;
        for term in &policy.terms {
            let attrs = modified.as_ref().unwrap_or(route.attrs);
            if !term.clauses.iter().all(|c| self.holds(c, route, attrs)) {
                continue;
            }
            if !term.sets.is_empty() {
                let mut a = modified.take().unwrap_or_else(|| route.attrs.clone());
                for s in &term.sets {
                    apply(s, &mut a, route);
                }
                a.normalise();
                modified = Some(a);
            }
            match term.action {
                Action::Accept => {
                    return modified.map_or(Verdict::Accept, Verdict::Modified);
                }
                Action::Reject => return Verdict::Reject,
                Action::Next => {}
            }
        }
        Verdict::Reject
    }

    fn holds(&self, clause: &Clause, route: &Route<'_>, attrs: &PathAttrs) -> bool {
        match clause {
            Clause::Prefix(r) => r.matches(route.prefix),
            Clause::PrefixList(i) => self.prefix_lists[*i].matches(route.prefix),
            Clause::AsPath(re) => re.matches(attrs.as_path.asns(), attrs.as_path.asns().count()),
            Clause::Community(c) => attrs.has_community(*c),
            Clause::ExtCommunity(c) => attrs.ext_communities.binary_search(c).is_ok(),
            Clause::LargeCommunity(c) => attrs.large_communities.binary_search(c).is_ok(),
            Clause::Origin(o) => attrs.origin == *o,
            Clause::Neighbor(a) => route.neighbor == *a,
        }
    }
}

fn apply(set: &SetAction, a: &mut PathAttrs, route: &Route<'_>) {
    match set {
        SetAction::LocalPref(v) => a.local_pref = Some(*v),
        SetAction::Med(v) => a.med = Some(*v),
        SetAction::Community(op, vals) => edit(&mut a.communities, *op, vals),
        SetAction::ExtCommunity(op, vals) => edit(&mut a.ext_communities, *op, vals),
        SetAction::LargeCommunity(op, vals) => edit(&mut a.large_communities, *op, vals),
        SetAction::AsPathPrepend(asns) => {
            // `prepend 1 2` yields `1 2 <path>`: prepend from the right.
            for asn in asns.iter().rev() {
                a.as_path = a.as_path.prepend(*asn);
            }
        }
        SetAction::NextHopSelf => {
            a.next_hop = match (route.family, route.local_addr) {
                (AddressFamily::IPV4_UNICAST, IpAddr::V4(v4)) => NextHop::Ipv4(v4),
                // RFC 8950 §5: our own address is of the session's
                // protocol, which an IPv4 route may carry once RFC 8950 §4
                // negotiated it.
                (AddressFamily::IPV4_UNICAST, IpAddr::V6(v6)) if route.extended_next_hop => {
                    NextHop::Ipv6 {
                        global: v6,
                        link_local: None,
                    }
                }
                (AddressFamily::IPV6_UNICAST, IpAddr::V6(v6)) => NextHop::Ipv6 {
                    global: v6,
                    link_local: None,
                },
                // No address of the route's family on this session: keep
                // the next hop (the RIB's export rules apply the same way).
                _ => a.next_hop,
            };
        }
    }
}

fn edit<T: Copy + Ord>(set: &mut Box<[T]>, op: CommunityOp, vals: &[T]) {
    let mut v = std::mem::take(set).into_vec();
    match op {
        CommunityOp::Add => v.extend_from_slice(vals),
        CommunityOp::Remove => v.retain(|c| !vals.contains(c)),
        CommunityOp::Replace => {
            v.clear();
            v.extend_from_slice(vals);
        }
    }
    *set = v.into_boxed_slice();
}

/// The policies of a configuration, applied per neighbor.
#[derive(Clone, Debug, Default)]
pub struct Engine {
    set: PolicySet,
    /// Import and export policy per neighbor, as indices into the set
    /// (`None`: no such policy, which rejects).
    neighbors: HashMap<IpAddr, NeighborPolicies>,
    /// The neighbor looked up last. The RIB asks about the routes of one
    /// UPDATE, one peer, in a row; this spares hashing its address for
    /// each.
    last: Cell<Option<(IpAddr, NeighborPolicies)>>,
}

/// A neighbor's import and export policies, by index.
type NeighborPolicies = (Option<usize>, Option<usize>);

impl Engine {
    /// Compile `cfg` and remember which policies each neighbor uses.
    ///
    /// # Errors
    /// As [`PolicySet::compile`].
    pub fn new(cfg: &Config) -> Result<Engine, Vec<PolicyError>> {
        let set = PolicySet::compile(cfg)?;
        let neighbors = cfg
            .neighbors
            .iter()
            .map(|n| {
                let index = |name: &str| set.names.get(name).copied();
                (n.addr, (index(&n.import), index(&n.export)))
            })
            .collect();
        Ok(Engine {
            set,
            neighbors,
            last: Cell::new(None),
        })
    }

    /// The compiled policies.
    #[must_use]
    pub fn policies(&self) -> &PolicySet {
        &self.set
    }

    fn run(
        &self,
        which: fn(NeighborPolicies) -> Option<usize>,
        peer: &PeerInfo,
        route: &Route<'_>,
    ) -> Verdict {
        let policies = match self.last.get() {
            Some((addr, p)) if addr == peer.addr => Some(p),
            _ => {
                let p = self.neighbors.get(&peer.addr).copied();
                if let Some(p) = p {
                    self.last.set(Some((peer.addr, p)));
                }
                p
            }
        };
        match policies {
            Some(p) => self.set.evaluate_at(which(p), route),
            // A peer without configured policies gets nothing and gives
            // nothing (docs/config.md: every neighbor names both).
            None => Verdict::Reject,
        }
    }
}

/// No clause matches on the validation state yet, so `rov` is accepted
/// and not read: the RFC 6811 §3 row in COMPLIANCE.md says what is left.
impl Policies for Engine {
    fn import(
        &self,
        peer: &PeerInfo,
        family: AddressFamily,
        prefix: Prefix,
        attrs: &PathAttrs,
        _rov: RovState,
    ) -> Verdict {
        let route = Route {
            prefix,
            family,
            attrs,
            neighbor: peer.addr,
            local_addr: peer.local_addr,
            extended_next_hop: peer.extended_next_hop.contains(&family),
        };
        self.run(|n| n.0, peer, &route)
    }

    fn export(
        &self,
        peer: &PeerInfo,
        family: AddressFamily,
        prefix: Prefix,
        attrs: &PathAttrs,
        _rov: RovState,
    ) -> Verdict {
        let route = Route {
            prefix,
            family,
            attrs,
            neighbor: peer.addr,
            local_addr: peer.local_addr,
            extended_next_hop: peer.extended_next_hop.contains(&family),
        };
        self.run(|n| n.1, peer, &route)
    }
}

#[cfg(test)]
mod tests;
