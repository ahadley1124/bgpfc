//! Sending several paths of a prefix to a peer that takes them (ADD-PATH).
//!
//! Implements: RFC 7911 §2 ("A BGP speaker that re-advertises a route MUST
//! generate its own Path Identifier to be associated with the re-advertised
//! route"; the identifier must make (prefix, identifier) "uniquely identify
//! a path advertised to a neighbor"), §3 (the identifiers in the NLRI), §5
//! ("a new advertisement for a given address prefix and a given Path
//! Identifier replaces a previous advertisement", "A BGP speaker SHOULD
//! include the best route when more than one path is advertised to a
//! neighbor, unless it is a path received from that neighbor"); RFC 4271
//! §9.2.1.1 (the interval paces a destination, all its paths together).
//!
//! The other peers are sent the best route of a destination whenever it
//! changes, and the RIB keeps no Adj-RIB-Out for them. A peer sent several
//! paths needs one: which of its paths are still there is not something
//! the Loc-RIB can say once a path has changed or gone, and each path
//! keeps its identifier while it is sent. So the RIB keeps, for such a
//! peer alone, what it has been sent of each prefix ([`SentPath`]), and a
//! change to a destination is a comparison of that with the paths the
//! destination should have now ([`Sessions::sync_paths`]). A peer not sent
//! several paths has none of this and pays nothing for it.

use std::cmp::Reverse;
use std::sync::Arc;

use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::{AddressFamily, Asn, PathId};

use crate::attrs::{Interner, PathAttrs};
use crate::decision::{self, Candidate};
use crate::export::{self, Batch};
use crate::pacing::{Offer, Pace, Pacing, Tick};
use crate::peer::{PathLimit, PeerInfo};
use crate::store::{Destination, PeerId, PrefixMap};
use crate::{Batches, Deadline, Exported, PeerState, Sessions, count};

/// A path sent to a peer: where it came from, the identifier we gave it,
/// and what we sent.
#[derive(Debug)]
pub(crate) struct SentPath {
    /// The peer the route came from.
    pub(crate) src: PeerId,
    /// The Path Identifier it came with; zero from a peer that sends none.
    /// Together with `src` this is what makes it the same route when its
    /// attributes change.
    pub(crate) rx: u32,
    /// The Path Identifier we sent it with (RFC 7911 §2): never zero.
    pub(crate) tx: u32,
    /// The attributes export policy left it, before the session rewrite of
    /// RFC 4271 §5.1: what a later change is compared with.
    pub(crate) attrs: Arc<PathAttrs>,
}

/// What a peer has been sent of each prefix of one family.
pub(crate) type Sent = PrefixMap<Box<[SentPath]>>;

/// Why a destination's paths are being brought up to date.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Sync {
    /// The destination changed: its interval may hold the news back.
    Change,
    /// The interval of a held destination ended.
    Release,
    /// The peer asked for everything again, or is new (RFC 2918 §4): every
    /// path goes out, changed or not.
    Full,
}

/// A path the peer may have: the route it is made of, and what export
/// makes of that.
struct Chosen {
    /// The route's place among the destination's candidates.
    route: usize,
    src: PeerId,
    rx: u32,
    exported: Exported,
}

/// The paths of a destination that export lets through to a peer. The
/// first `sent` are the ones it is to have, the best first; the rest are
/// routes it could have had that the `n` best leave out.
struct Open {
    paths: Vec<Chosen>,
    sent: usize,
}

impl Open {
    fn chosen(&self) -> &[Chosen] {
        &self.paths[..self.sent]
    }

    fn displaced(&self) -> &[Chosen] {
        &self.paths[self.sent..]
    }
}

/// One path to announce: which of the chosen, and the identifier it goes
/// with; `new` unless the peer has it already, with other attributes. A
/// plan lists them in the order of the chosen.
#[derive(Debug, PartialEq, Eq)]
struct Announce {
    chosen: usize,
    tx: u32,
    new: bool,
}

/// A path to withdraw.
#[derive(Debug, PartialEq, Eq)]
struct Withdraw {
    /// The identifier we sent it with.
    tx: u32,
    /// The route is still there and export lets it through, but the `n`
    /// best no longer include it. Such a path goes when the announcements
    /// that displace it do, not before: a peer sent the one best path
    /// would be left with none for the rest of the interval otherwise.
    displaced: bool,
}

/// What it takes to bring the paths a peer has to the ones it should.
#[derive(Debug, Default, PartialEq, Eq)]
struct Plan {
    /// The paths to withdraw.
    withdraw: Vec<Withdraw>,
    /// The paths to announce.
    announce: Vec<Announce>,
}

/// Compare what a peer has (`old`) with the paths it should have
/// (`chosen`). A path is the same route when its source and the
/// identifier it came with are; it is announced again, under the
/// identifier it has, when export makes something else of it, or for
/// every path if `how` is [`Sync::Full`]. A path not in `chosen` is
/// withdrawn, as displaced if it is in `displaced`. A new path takes the
/// smallest identifier from 1 up that no path of `old` has, the ones about
/// to be withdrawn included, so that none is handed out again while it may
/// still be on its way. `local_as` is our AS, for the rewrite's Only to
/// Customer attribute (RFC 9234 §5).
fn plan(
    old: &[SentPath],
    (chosen, displaced): (&[Chosen], &[Chosen]),
    how: Sync,
    (local_as, family): (Asn, AddressFamily),
    info: &PeerInfo,
) -> Plan {
    let mut plan = Plan::default();
    // The new paths take identifiers in increasing order, so every one
    // below `next` is taken, by `old` or by an earlier new path.
    let mut next = 1u32;
    for (c, path) in chosen.iter().enumerate() {
        let Some(sent) = old.iter().find(|s| s.src == path.src && s.rx == path.rx) else {
            // invariant: `next` stays within one of the number of paths
            // held and announced, far below 2^32.
            while old.iter().any(|s| s.tx == next) {
                next += 1;
            }
            plan.announce.push(Announce {
                chosen: c,
                tx: next,
                new: true,
            });
            next += 1;
            continue;
        };
        let same = match &path.exported {
            Exported::Own(a) if Arc::ptr_eq(a, &sent.attrs) => true,
            e => export::same_rewrite(local_as, family, &sent.attrs, e.attrs(), info),
        };
        if how == Sync::Full || !same {
            plan.announce.push(Announce {
                chosen: c,
                tx: sent.tx,
                new: false,
            });
        }
    }
    plan.withdraw = old
        .iter()
        .filter(|s| !chosen.iter().any(|c| c.src == s.src && c.rx == s.rx))
        .map(|s| Withdraw {
            tx: s.tx,
            displaced: displaced.iter().any(|c| c.src == s.src && c.rx == s.rx),
        })
        .collect();
    plan
}

impl Sessions {
    /// A candidate route for Phase 2, from route `i` of `dest`.
    fn candidate<'a>(&self, dest: &'a Destination, i: usize) -> Candidate<'a> {
        let route = dest.route(i);
        Candidate {
            from: self.peer(route.peer).neighbor,
            attrs: &route.attrs,
            path_id: dest.id(i),
        }
    }

    /// The paths of `dest` that peer `to` may have: those of its
    /// candidates that export lets through to `to`. When `limit` is `n`,
    /// the first `n` of them are the `n` best by the decision process
    /// (RFC 4271 §9.1.2), the best first, then the best of the rest, and
    /// so on, so that the best path that can be sent is always among them
    /// (RFC 7911 §5); the routes export lets through that they leave out
    /// come after.
    fn choose_paths(
        &self,
        to: PeerId,
        family: AddressFamily,
        prefix: Prefix,
        dest: Option<&Destination>,
        limit: PathLimit,
    ) -> Open {
        let Some(dest) = dest else {
            return Open {
                paths: Vec::new(),
                sent: 0,
            };
        };
        let mut paths = Vec::with_capacity(dest.candidates());
        for route in 0..dest.candidates() {
            if let Some(exported) = self.exported(None, family, prefix, Some(dest.route(route)), to)
            {
                paths.push(Chosen {
                    route,
                    src: dest.route(route).peer,
                    rx: dest.id(route),
                    exported,
                });
            }
        }
        let mut sent = paths.len();
        if let PathLimit::Best(n) = limit
            && let Ok(n) = usize::try_from(n)
            && n < sent
        {
            sent = n;
            // A selection sort, as far as `sent`: a destination has a
            // route per peer, a handful. When none is left out, the
            // candidates' order is kept: the best first, as Phase 2 left
            // it.
            for at in 0..sent {
                let rest = &paths[at..];
                let k = decision::best(rest.len(), |j| self.candidate(dest, rest[j].route))
                    .unwrap_or(0);
                paths.swap(at, at + k);
            }
        }
        Open { paths, sent }
    }

    /// Phase 3 for the peers sent several paths: bring each one's paths of
    /// `prefix` up to date with `dest`, the destination as it is now, after
    /// any change to it, not only one to its best route.
    pub(crate) fn sync_senders(
        &mut self,
        family: AddressFamily,
        prefix: Prefix,
        dest: Option<&Destination>,
        batches: &mut Batches,
    ) {
        for i in 0..self.peers.len() {
            let Some(to) = &self.peers[i] else {
                continue;
            };
            if to.leaving || to.info.path_limit(family).is_none() {
                continue;
            }
            // invariant: fewer than 2^32 peers.
            let id = PeerId(u32::try_from(i).unwrap());
            let batch = batches.get(id, family);
            self.sync_paths(id, family, prefix, dest, Sync::Change, batch);
        }
    }

    /// Bring the paths of `prefix` that peer `id` has up to date with
    /// `dest`: withdraw those it should not have, announce those it should
    /// and has not, or has with other attributes, into `batch`.
    ///
    /// A path withdrawn goes at once; the announcements wait for the
    /// interval of the destination to end, as for any peer (RFC 4271
    /// §9.2.1.1), and what goes out then is what the destination has by
    /// then, not what it had when the news was held back.
    pub(crate) fn sync_paths(
        &mut self,
        id: PeerId,
        family: AddressFamily,
        prefix: Prefix,
        dest: Option<&Destination>,
        how: Sync,
        batch: &mut Batch,
    ) {
        let Some(limit) = self.peer(id).info.path_limit(family) else {
            return;
        };
        let open = self.choose_paths(id, family, prefix, dest, limit);
        let old: &[SentPath] = self
            .peer(id)
            .sent
            .get(family)
            .and_then(|m| m.get(prefix))
            .map_or(&[], |s| &s[..]);
        let had = !old.is_empty();
        let plan = plan(
            old,
            (open.chosen(), open.displaced()),
            how,
            (self.cx.local_as, family),
            &self.peer(id).info,
        );
        if plan.withdraw.is_empty() && plan.announce.is_empty() {
            return;
        }
        self.apply(id, (family, prefix), (how, had), (open, plan), batch);
    }

    /// Carry out `plan` for peer `id`: the withdrawals now, the
    /// announcements as the interval allows.
    fn apply(
        &mut self,
        id: PeerId,
        (family, prefix): (AddressFamily, Prefix),
        (how, had): (Sync, bool),
        (mut open, plan): (Open, Plan),
        batch: &mut Batch,
    ) {
        let interval = self.peer(id).info.advertisement_interval;
        let mut pace = Pace {
            interval,
            now: self.at,
            jitter: &mut self.jitter,
        };
        // invariant: ids are only handed out for occupied slots.
        let state = self.peers[id.index()].as_mut().unwrap();
        // The interval decides when the announcements go. Held already:
        // this change joins the one that waits, and the release works out
        // what to send. Not held: the interval may hold them back now.
        let waiting = state
            .pacing
            .get(family)
            .and_then(|p| p.holds_paths(prefix))
            .is_some();
        let release = if plan.announce.is_empty() {
            Release::Nothing
        } else if how != Sync::Change {
            Release::Now
        } else if waiting {
            Release::Wait
        } else {
            match state
                .pacing
                .or_default(family)
                .offer(prefix, had, &mut pace)
            {
                Offer::Now => Release::Now,
                Offer::Hold(at) => Release::Hold(at),
            }
        };

        let mut paths: Vec<SentPath> = state
            .sent
            .or_default(family)
            .remove(prefix)
            .map(Vec::from)
            .unwrap_or_default();
        // Withdrawals go at once, but for the paths the announcements that
        // wait would displace: they stay until those go out.
        let held_back = matches!(release, Release::Wait | Release::Hold(_));
        for w in &plan.withdraw {
            if w.displaced && held_back {
                continue;
            }
            if let Some(k) = paths.iter().position(|p| p.tx == w.tx) {
                let p = paths.swap_remove(k);
                batch.withdraw_path(prefix, PathId(p.tx));
                count(state, family, -1);
                self.cx.interner.release(p.attrs);
            }
        }
        match release {
            Release::Now => {
                open.paths.truncate(open.sent);
                announce_sent(
                    (state, family, prefix),
                    &mut paths,
                    (&plan.announce, open.paths),
                    batch,
                    &mut self.cx.interner,
                );
                // A whole Adj-RIB-Out sent at once is remembered as that.
                if how != Sync::Full {
                    state.pacing.or_default(family).advertised(prefix, &pace);
                }
            }
            Release::Hold(at) => {
                let pacing = state.pacing.or_default(family);
                pacing.hold_paths(prefix, at, !paths.is_empty());
                if pacing.queue(prefix, at) {
                    self.deadlines.push(Reverse(Deadline {
                        at,
                        peer: id,
                        family,
                        prefix,
                    }));
                }
            }
            Release::Wait | Release::Nothing => {}
        }
        settle(
            state.pacing.or_default(family),
            (prefix, &pace),
            &release,
            Meanwhile {
                waiting,
                had,
                has: !paths.is_empty(),
            },
        );
        if !paths.is_empty() {
            state
                .sent
                .or_default(family)
                .insert(prefix, paths.into_boxed_slice());
        }
    }
}

/// What the interval makes of the announcements of a change.
enum Release {
    /// There are none.
    Nothing,
    /// They go out now.
    Now,
    /// Announcements are held back already: they join those.
    Wait,
    /// They are held back until then.
    Hold(Tick),
}

/// What the peer had of a destination before a change, and has after it.
#[derive(Clone, Copy)]
struct Meanwhile {
    /// Announcements were held back already.
    waiting: bool,
    /// The peer had paths of the destination.
    had: bool,
    /// And has some now.
    has: bool,
}

/// The peer has lost its paths of the prefix: that is remembered for the
/// interval, so that a route that comes back is paced (RFC 4271
/// §9.2.1.1). Not while announcements wait: the hold stays, with what the
/// peer has meanwhile.
fn settle(
    pacing: &mut Pacing,
    (prefix, pace): (Prefix, &Pace<'_>),
    release: &Release,
    m: Meanwhile,
) {
    let announcing = !matches!(release, Release::Nothing);
    if m.waiting && announcing {
        pacing.set_held_paths(prefix, m.has);
    } else if !announcing && !m.has && m.had {
        if m.waiting {
            pacing.withdrew_held_paths(prefix, pace);
        } else {
            pacing.withdrew(prefix, pace);
        }
    }
}

/// Announce the paths of `announce` into `batch` and note them in `paths`,
/// what the peer has of the prefix: a new one is added, one the peer has
/// is given its new attributes under the identifier it has (RFC 7911 §5).
/// `announce` is in the order of `chosen`, as a plan makes it.
fn announce_sent(
    (state, family, prefix): (&mut PeerState, AddressFamily, Prefix),
    paths: &mut Vec<SentPath>,
    (announce, chosen): (&[Announce], Vec<Chosen>),
    batch: &mut Batch,
    interner: &mut Interner,
) {
    let mut announce = announce.iter().peekable();
    for (n, c) in chosen.into_iter().enumerate() {
        let Some(a) = announce.next_if(|a| a.chosen == n) else {
            continue;
        };
        let attrs = c.exported.intern(interner);
        batch.announce_path(&attrs, prefix, PathId(a.tx));
        if a.new {
            paths.push(SentPath {
                src: c.src,
                rx: c.rx,
                tx: a.tx,
                attrs,
            });
            count(state, family, 1);
        } else if let Some(p) = paths.iter_mut().find(|p| p.tx == a.tx) {
            let replaced = std::mem::replace(&mut p.attrs, attrs);
            interner.release(replaced);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use bgpfc_wire::as_path::AsPath;
    use bgpfc_wire::attribute::Origin;
    use bgpfc_wire::mp::NextHop;
    use bgpfc_wire::types::RouterId;
    use bgpfc_wire::update::PeerKind;

    use super::*;

    const V4: AddressFamily = AddressFamily::IPV4_UNICAST;
    const LOCAL: Asn = Asn(65_000);

    fn attrs(asn: u32) -> Arc<PathAttrs> {
        Arc::new(PathAttrs {
            origin: Origin::Igp,
            as_path: AsPath::sequence(&[Asn(asn)]),
            next_hop: NextHop::Ipv4(Ipv4Addr::new(192, 0, 2, 1)),
            med: None,
            local_pref: None,
            atomic_aggregate: false,
            aggregator: None,
            communities: Box::default(),
            ext_communities: Box::default(),
            large_communities: Box::default(),
            unknown: Box::default(),
            otc: None,
        })
    }

    fn info() -> PeerInfo {
        PeerInfo {
            addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)),
            local_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 254)),
            remote_as: Asn(65_009),
            router_id: RouterId::new(9).unwrap(),
            kind: PeerKind::External,
            families: vec![V4],
            receive_families: vec![V4],
            four_octet_as: true,
            extended_messages: false,
            extended_next_hop: Vec::new(),
            advertisement_interval: Duration::ZERO,
            prefix_limits: Vec::new(),
            add_path_receive: Vec::new(),
            add_path_send: vec![(V4, PathLimit::All)],
            role: None,
        }
    }

    fn sent(src: u32, rx: u32, tx: u32, a: &Arc<PathAttrs>) -> SentPath {
        SentPath {
            src: PeerId(src),
            rx,
            tx,
            attrs: Arc::clone(a),
        }
    }

    fn chosen(src: u32, rx: u32, a: &Arc<PathAttrs>) -> Chosen {
        Chosen {
            route: 0,
            src: PeerId(src),
            rx,
            exported: Exported::Own(Arc::clone(a)),
        }
    }

    #[test]
    fn new_paths_take_the_smallest_unused_identifier_from_one() {
        // RFC 7911 §2: (prefix, identifier) names one path advertised.
        let a = attrs(65_001);
        let p = plan(
            &[],
            (&[chosen(1, 0, &a), chosen(2, 0, &a), chosen(1, 7, &a)], &[]),
            Sync::Change,
            (LOCAL, V4),
            &info(),
        );
        assert_eq!(
            p,
            Plan {
                withdraw: vec![],
                announce: vec![
                    Announce {
                        chosen: 0,
                        tx: 1,
                        new: true
                    },
                    Announce {
                        chosen: 1,
                        tx: 2,
                        new: true
                    },
                    Announce {
                        chosen: 2,
                        tx: 3,
                        new: true
                    },
                ],
            }
        );
    }

    #[test]
    fn several_new_paths_fill_the_gaps_in_order_and_then_go_on() {
        // The peer has 1, 3 and 4; three more take 2, 5 and 6.
        let a = attrs(65_001);
        let old = [sent(1, 0, 1, &a), sent(2, 0, 3, &a), sent(3, 0, 4, &a)];
        let new: Vec<Chosen> = (1..=6).map(|src| chosen(src, 0, &a)).collect();
        let p = plan(&old, (&new, &[]), Sync::Change, (LOCAL, V4), &info());
        assert_eq!(p.withdraw, vec![]);
        assert_eq!(
            p.announce
                .iter()
                .map(|a| (a.chosen, a.tx))
                .collect::<Vec<_>>(),
            vec![(3, 2), (4, 5), (5, 6)]
        );
    }

    #[test]
    fn a_path_keeps_its_identifier_and_the_withdrawn_ones_are_not_handed_out_again() {
        let (a, b) = (attrs(65_001), attrs(65_002));
        // The peer has (1, 0) as 1, (2, 0) as 2 and (3, 0) as 4.
        let old = [sent(1, 0, 1, &a), sent(2, 0, 2, &a), sent(3, 0, 4, &a)];
        // Now (2, 0) with other attributes, (3, 0) as it was, and a new
        // (5, 0); (1, 0) is gone.
        let new = [chosen(2, 0, &b), chosen(3, 0, &a), chosen(5, 0, &a)];
        let p = plan(&old, (&new, &[]), Sync::Change, (LOCAL, V4), &info());
        assert_eq!(
            p.withdraw,
            vec![Withdraw {
                tx: 1,
                displaced: false
            }]
        );
        assert_eq!(
            p.announce,
            vec![
                // Same identifier, new attributes: replaces (RFC 7911 §5).
                Announce {
                    chosen: 0,
                    tx: 2,
                    new: false
                },
                // 3 is free but for the one just withdrawn, which is 1.
                Announce {
                    chosen: 2,
                    tx: 3,
                    new: true
                },
            ]
        );
        // A route refresh sends them all again, under the same identifiers.
        let p = plan(&old, (&new, &[]), Sync::Full, (LOCAL, V4), &info());
        assert_eq!(
            p.withdraw,
            vec![Withdraw {
                tx: 1,
                displaced: false
            }]
        );
        assert_eq!(
            p.announce
                .iter()
                .map(|a| (a.chosen, a.tx))
                .collect::<Vec<_>>(),
            vec![(0, 2), (1, 4), (2, 3)]
        );
    }

    #[test]
    fn a_path_the_best_n_leave_out_is_displaced_not_gone() {
        let a = attrs(65_001);
        let old = [sent(1, 0, 1, &a), sent(2, 0, 2, &a)];
        // (2, 0) is still a route export lets through, (1, 0) is not.
        let p = plan(
            &old,
            (&[chosen(3, 0, &a)], &[chosen(2, 0, &a)]),
            Sync::Change,
            (LOCAL, V4),
            &info(),
        );
        assert_eq!(
            p.withdraw,
            vec![
                Withdraw {
                    tx: 1,
                    displaced: false
                },
                Withdraw {
                    tx: 2,
                    displaced: true
                }
            ]
        );
    }

    #[test]
    fn the_same_source_with_another_identifier_is_another_path() {
        let a = attrs(65_001);
        let old = [sent(1, 5, 1, &a)];
        let p = plan(
            &old,
            (&[chosen(1, 6, &a)], &[]),
            Sync::Change,
            (LOCAL, V4),
            &info(),
        );
        assert_eq!(
            p.withdraw,
            vec![Withdraw {
                tx: 1,
                displaced: false
            }]
        );
        assert_eq!(
            p.announce,
            vec![Announce {
                chosen: 0,
                tx: 2,
                new: true
            }]
        );
        // Nothing changed: nothing to do.
        let p = plan(
            &old,
            (&[chosen(1, 5, &a)], &[]),
            Sync::Change,
            (LOCAL, V4),
            &info(),
        );
        assert_eq!(p, Plan::default());
    }
}
