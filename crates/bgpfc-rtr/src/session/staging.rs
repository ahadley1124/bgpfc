//! A reply to a query, held apart from the committed data until its End
//! of Data arrives, so that the RIB never sees half a reply (issue #58).
//!
//! A reply can hold no more VRPs than the session's
//! [`max_vrps`](super::Config::max_vrps): a cache that has gone wrong,
//! or anyone on the unprotected transport of RFC 8210 §9, cannot make the
//! router's memory grow without bound.
//!
//! Implements: RFC 8210 §5.1 (a withdrawal deletes the record with the
//! same {Prefix, Len, Max-Len, ASN}), §5.3 (a reply to a Serial Query is
//! the changes since the router's serial), §5.5 (a reply to a Reset Query
//! only announces), §5.6 (one record per tuple; Duplicate Announcement
//! Received), §12 (codes 1, 6 and 7).

use std::collections::HashMap;

use bgpfc_rpki::{AffectedPrefixes, Vrp, VrpSet};

use crate::error::ErrorCode;

/// The VRPs of a reply received so far.
#[derive(Clone, Debug)]
pub(super) enum Staging {
    /// A reply to a Reset Query: the cache's whole data set, built up from
    /// nothing (RFC 8210 §5.4, §5.5).
    Full(VrpSet),
    /// A reply to a Serial Query (RFC 8210 §5.3). The committed set itself
    /// is left alone, so that a reply which fails half-way costs nothing to
    /// drop, and one that changes nothing costs no copy of the set.
    Delta {
        /// For each VRP whose presence the reply has changed from the
        /// committed set's, whether it is present. A VRP the reply brings
        /// back to how the committed set has it leaves the map, which so
        /// holds at most the committed set and the cap.
        changes: HashMap<Vrp, bool>,
        /// VRPs in the set the reply leads to.
        len: usize,
    },
    /// A reply to a Serial Query whose base, the committed data, expired
    /// while the reply was under way. There is nothing to apply it to.
    Discard,
}

/// Why a Prefix PDU cannot be applied: the Error Code to report and what
/// was wrong.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Rejected {
    /// The Error Code of the Error Report.
    pub(super) code: ErrorCode,
    /// The diagnostic text, before the VRP.
    pub(super) reason: &'static str,
}

/// RFC 8210 §12 code 7: "The received PDU has Flag=1, but a matching
/// record ... is already active in the router." §5.6: the router "SHOULD
/// raise a Duplicate Announcement Received error".
const DUPLICATE: Rejected = Rejected {
    code: ErrorCode::DuplicateAnnouncementReceived,
    reason: "duplicate announcement",
};

/// RFC 8210 §12 code 6: "The received PDU has Flag=0, but a matching
/// record ... does not exist in the receiver's database."
const UNKNOWN: Rejected = Rejected {
    code: ErrorCode::WithdrawalOfUnknownRecord,
    reason: "withdrawal of an unknown record",
};

/// RFC 8210 §12 code 1: "The party reporting the error experienced some
/// kind of internal error unrelated to protocol operation (ran out of
/// memory, ...)". The cache did nothing the protocol forbids; the router
/// has no room for more.
const TOO_MANY: Rejected = Rejected {
    code: ErrorCode::InternalError,
    reason: "the data set would exceed the router's maximum of VRPs",
};

/// RFC 8210 §5.5: in a reply to a Reset Query "the withdraw/announce
/// field in the payload PDUs MUST have the value 1 (announce)". No other
/// code of §12 covers a withdrawal there, so it is Corrupt Data, "corrupt
/// in a manner not specified by another error code".
const WITHDRAWAL_IN_RESET: Rejected = Rejected {
    code: ErrorCode::CorruptData,
    reason: "withdrawal in a reply to a Reset Query",
};

impl Staging {
    /// A reply to a Serial Query that updates `base`, the committed data.
    pub(super) fn delta(base: Option<&VrpSet>) -> Staging {
        Staging::Delta {
            changes: HashMap::new(),
            len: base.map_or(0, VrpSet::len),
        }
    }

    /// Apply one Prefix PDU: announce (Flags bit 0 set) or withdraw `vrp`.
    /// `base` is the committed data a Serial reply updates, the one
    /// [`Staging::delta`] was given; `max` the most VRPs the resulting set
    /// may hold.
    pub(super) fn apply(
        &mut self,
        announce: bool,
        vrp: Vrp,
        base: Option<&VrpSet>,
        max: usize,
    ) -> Result<(), Rejected> {
        match self {
            Staging::Full(set) => {
                if !announce {
                    return Err(WITHDRAWAL_IN_RESET);
                }
                if set.len() >= max && !set.contains(vrp) {
                    return Err(TOO_MANY);
                }
                if !set.insert(vrp) {
                    return Err(DUPLICATE);
                }
            }
            Staging::Delta { changes, len } => {
                let in_base = base.is_some_and(|b| b.contains(vrp));
                let present = changes.get(&vrp).copied().unwrap_or(in_base);
                // RFC 8210 §5.3 lets a reply withdraw a record and announce
                // it again ("at most one withdrawal followed by at most one
                // announcement"); only announcing what is there, or
                // withdrawing what is not, is an error.
                match (announce, present) {
                    (true, true) => return Err(DUPLICATE),
                    (false, false) => return Err(UNKNOWN),
                    (true, false) if *len >= max => return Err(TOO_MANY),
                    (true, false) => *len += 1,
                    // invariant: `vrp` is present, so `len` counts it.
                    (false, true) => *len = len.saturating_sub(1),
                }
                if announce == in_base {
                    changes.remove(&vrp);
                } else {
                    changes.insert(vrp, announce);
                }
            }
            Staging::Discard => {}
        }
        Ok(())
    }
}

/// The set a Serial reply's `changes` lead to from `base`, and the routes
/// they affect; `None` if the reply changes nothing.
///
/// Only the VRPs whose presence differs from `base` count, so a record
/// withdrawn and announced again affects no route.
pub(super) fn apply_delta(
    base: &VrpSet,
    changes: HashMap<Vrp, bool>,
) -> Option<(VrpSet, AffectedPrefixes)> {
    let net: Vec<(Vrp, bool)> = changes
        .into_iter()
        .filter(|&(vrp, present)| present != base.contains(vrp))
        .collect();
    if net.is_empty() {
        return None;
    }
    let mut set = base.clone();
    for &(vrp, present) in &net {
        if present {
            set.insert(vrp);
        } else {
            set.remove(vrp);
        }
    }
    let affected = AffectedPrefixes::from_vrps(net.into_iter().map(|(vrp, _)| vrp));
    Some((set, affected))
}

#[cfg(test)]
mod tests {
    use bgpfc_wire::types::Asn;

    use super::*;

    const NO_CAP: usize = usize::MAX;

    fn vrp(prefix: &str, max_len: u8, asn: u32) -> Vrp {
        Vrp::new(prefix.parse().unwrap(), max_len, Asn(asn)).unwrap()
    }

    /// The VRP 10.0.0.0/8-24 of AS `asn`: as many distinct ones as needed.
    fn nth(asn: u32) -> Vrp {
        vrp("10.0.0.0/8", 24, asn)
    }

    #[test]
    fn a_reset_reply_only_announces_and_never_twice() {
        let a = vrp("192.0.2.0/24", 24, 64_496);
        let mut s = Staging::Full(VrpSet::new());
        assert_eq!(s.apply(true, a, None, NO_CAP), Ok(()));
        assert_eq!(s.apply(true, a, None, NO_CAP), Err(DUPLICATE));
        let b = vrp("2001:db8::/32", 48, 64_497);
        assert_eq!(s.apply(false, b, None, NO_CAP), Err(WITHDRAWAL_IN_RESET));
        // Withdrawing what the reply announced is still a withdrawal in a
        // reply to a Reset Query, not a removal.
        assert_eq!(s.apply(false, a, None, NO_CAP), Err(WITHDRAWAL_IN_RESET));
        let Staging::Full(set) = s else {
            unreachable!()
        };
        assert_eq!(set, [a].into_iter().collect());
    }

    #[test]
    fn a_serial_reply_checks_against_base_and_itself() {
        let a = vrp("192.0.2.0/24", 24, 64_496);
        let b = vrp("2001:db8::/32", 48, 64_497);
        let c = vrp("198.51.100.0/24", 24, 64_498);
        let committed: VrpSet = [a, b].into_iter().collect();
        let base = Some(&committed);
        let mut s = Staging::delta(base);
        // Code 7: already in the base.
        assert_eq!(s.apply(true, a, base, NO_CAP), Err(DUPLICATE));
        // Code 6: neither in the base nor announced.
        assert_eq!(s.apply(false, c, base, NO_CAP), Err(UNKNOWN));
        // Withdraw, then announce again: allowed (RFC 8210 §5.3).
        assert_eq!(s.apply(false, a, base, NO_CAP), Ok(()));
        assert_eq!(s.apply(false, a, base, NO_CAP), Err(UNKNOWN));
        assert_eq!(s.apply(true, a, base, NO_CAP), Ok(()));
        assert_eq!(s.apply(true, a, base, NO_CAP), Err(DUPLICATE));
        // A new one, then a withdrawal of it within the same reply.
        assert_eq!(s.apply(true, c, base, NO_CAP), Ok(()));
        assert_eq!(s.apply(false, b, base, NO_CAP), Ok(()));
        let Staging::Delta { changes, len } = s else {
            unreachable!()
        };
        assert_eq!(len, 2);
        let (set, affected) = apply_delta(&committed, changes).unwrap();
        assert_eq!(set, [a, c].into_iter().collect());
        // `a` came back as it was: only b and c changed.
        assert_eq!(
            affected,
            AffectedPrefixes::from_vrps([b, c]),
            "{affected:?}"
        );
    }

    #[test]
    fn a_serial_reply_that_cancels_out_changes_nothing() {
        let a = vrp("192.0.2.0/24", 24, 64_496);
        let base: VrpSet = [a].into_iter().collect();
        let mut s = Staging::delta(Some(&base));
        s.apply(false, a, Some(&base), NO_CAP).unwrap();
        s.apply(true, a, Some(&base), NO_CAP).unwrap();
        let Staging::Delta { changes, len } = s else {
            unreachable!()
        };
        assert_eq!(len, 1);
        assert!(changes.is_empty());
        assert!(apply_delta(&base, changes).is_none());
        assert!(apply_delta(&base, HashMap::new()).is_none());
    }

    #[test]
    fn a_discarded_reply_accepts_anything() {
        let a = vrp("192.0.2.0/24", 24, 64_496);
        let mut s = Staging::Discard;
        assert_eq!(s.apply(false, a, None, 0), Ok(()));
        assert_eq!(s.apply(true, a, None, 0), Ok(()));
        assert_eq!(s.apply(true, a, None, 0), Ok(()));
    }

    #[test]
    fn a_reset_reply_holds_at_most_the_cap() {
        let mut s = Staging::Full(VrpSet::new());
        for asn in 0..3 {
            assert_eq!(s.apply(true, nth(asn), None, 3), Ok(()));
        }
        // RFC 8210 §12 code 1, not associated with the PDU.
        assert_eq!(s.apply(true, nth(3), None, 3), Err(TOO_MANY));
        assert_eq!(TOO_MANY.code, ErrorCode::InternalError);
        // A duplicate at the cap is still a duplicate.
        assert_eq!(s.apply(true, nth(0), None, 3), Err(DUPLICATE));
        let Staging::Full(set) = s else {
            unreachable!()
        };
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn a_serial_reply_counts_the_set_it_leads_to() {
        let base: VrpSet = (0..3).map(nth).collect();
        let base = Some(&base);
        let mut s = Staging::delta(base);
        // The base fills the cap: a new VRP needs room made first.
        assert_eq!(s.apply(true, nth(10), base, 3), Err(TOO_MANY));
        assert_eq!(s.apply(false, nth(0), base, 3), Ok(()));
        assert_eq!(s.apply(true, nth(10), base, 3), Ok(()));
        assert_eq!(s.apply(true, nth(11), base, 3), Err(TOO_MANY));
        // Bringing back a withdrawn one needs room too.
        assert_eq!(s.apply(true, nth(0), base, 3), Err(TOO_MANY));
        assert_eq!(s.apply(false, nth(10), base, 3), Ok(()));
        assert_eq!(s.apply(true, nth(0), base, 3), Ok(()));
        let Staging::Delta { changes, len } = s else {
            unreachable!()
        };
        assert_eq!(len, 3);
        // Back where it started: nothing is held for it.
        assert!(changes.is_empty(), "{changes:?}");
    }

    #[test]
    fn announcing_and_withdrawing_over_and_over_holds_nothing() {
        // A cache that announces a new VRP and withdraws it again, VRP after
        // VRP, never reaches the cap; the reply must not grow either.
        let base: VrpSet = [nth(0)].into_iter().collect();
        let base = Some(&base);
        let mut s = Staging::delta(base);
        for asn in 1..1_000 {
            assert_eq!(s.apply(true, nth(asn), base, 2), Ok(()));
            assert_eq!(s.apply(false, nth(asn), base, 2), Ok(()));
        }
        let Staging::Delta { changes, len } = s else {
            unreachable!()
        };
        assert_eq!(len, 1);
        assert!(changes.is_empty(), "{} held", changes.len());
    }
}
