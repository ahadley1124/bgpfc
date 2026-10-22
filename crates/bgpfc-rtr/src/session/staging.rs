//! A reply to a query, held apart from the committed data until its End
//! of Data arrives, so that the RIB never sees half a reply (issue #58).
//!
//! Implements: RFC 8210 §5.1 (a withdrawal deletes the record with the
//! same {Prefix, Len, Max-Len, ASN}), §5.3 (a reply to a Serial Query is
//! the changes since the router's serial), §5.5 (a reply to a Reset Query
//! only announces), §5.6 (one record per tuple; Duplicate Announcement
//! Received), §12 (codes 6 and 7).

use std::collections::HashMap;

use bgpfc_rpki::{AffectedPrefixes, Vrp, VrpSet};

use crate::error::ErrorCode;

/// The VRPs of a reply received so far.
#[derive(Clone, Debug)]
pub(super) enum Staging {
    /// A reply to a Reset Query: the cache's whole data set, built up from
    /// nothing (RFC 8210 §5.4, §5.5).
    Full(VrpSet),
    /// A reply to a Serial Query: for each VRP the reply has mentioned,
    /// whether it is present once the reply is applied to the committed
    /// set (RFC 8210 §5.3). The committed set itself is left alone, so
    /// that a reply which fails half-way costs nothing to drop, and one
    /// that changes nothing costs no copy of the set.
    Delta(HashMap<Vrp, bool>),
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

/// RFC 8210 §5.5: in a reply to a Reset Query "the withdraw/announce
/// field in the payload PDUs MUST have the value 1 (announce)". No other
/// code of §12 covers a withdrawal there, so it is Corrupt Data, "corrupt
/// in a manner not specified by another error code".
const WITHDRAWAL_IN_RESET: Rejected = Rejected {
    code: ErrorCode::CorruptData,
    reason: "withdrawal in a reply to a Reset Query",
};

impl Staging {
    /// Apply one Prefix PDU: announce (Flags bit 0 set) or withdraw `vrp`.
    /// `base` is the committed data a Serial reply updates.
    pub(super) fn apply(
        &mut self,
        announce: bool,
        vrp: Vrp,
        base: Option<&VrpSet>,
    ) -> Result<(), Rejected> {
        match self {
            Staging::Full(set) => {
                if !announce {
                    return Err(WITHDRAWAL_IN_RESET);
                }
                if !set.insert(vrp) {
                    return Err(DUPLICATE);
                }
            }
            Staging::Delta(changes) => {
                let present = changes
                    .get(&vrp)
                    .copied()
                    .unwrap_or_else(|| base.is_some_and(|b| b.contains(vrp)));
                // RFC 8210 §5.3 lets a reply withdraw a record and announce
                // it again ("at most one withdrawal followed by at most one
                // announcement"); only announcing what is there, or
                // withdrawing what is not, is an error.
                match (announce, present) {
                    (true, true) => return Err(DUPLICATE),
                    (false, false) => return Err(UNKNOWN),
                    _ => {
                        changes.insert(vrp, announce);
                    }
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

    fn vrp(prefix: &str, max_len: u8, asn: u32) -> Vrp {
        Vrp::new(prefix.parse().unwrap(), max_len, Asn(asn)).unwrap()
    }

    #[test]
    fn a_reset_reply_only_announces_and_never_twice() {
        let a = vrp("192.0.2.0/24", 24, 64_496);
        let mut s = Staging::Full(VrpSet::new());
        assert_eq!(s.apply(true, a, None), Ok(()));
        assert_eq!(s.apply(true, a, None), Err(DUPLICATE));
        let b = vrp("2001:db8::/32", 48, 64_497);
        assert_eq!(s.apply(false, b, None), Err(WITHDRAWAL_IN_RESET));
        // Withdrawing what the reply announced is still a withdrawal in a
        // reply to a Reset Query, not a removal.
        assert_eq!(s.apply(false, a, None), Err(WITHDRAWAL_IN_RESET));
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
        let base: VrpSet = [a, b].into_iter().collect();
        let mut s = Staging::Delta(HashMap::new());
        // Code 7: already in the base.
        assert_eq!(s.apply(true, a, Some(&base)), Err(DUPLICATE));
        // Code 6: neither in the base nor announced.
        assert_eq!(s.apply(false, c, Some(&base)), Err(UNKNOWN));
        // Withdraw, then announce again: allowed (RFC 8210 §5.3).
        assert_eq!(s.apply(false, a, Some(&base)), Ok(()));
        assert_eq!(s.apply(false, a, Some(&base)), Err(UNKNOWN));
        assert_eq!(s.apply(true, a, Some(&base)), Ok(()));
        assert_eq!(s.apply(true, a, Some(&base)), Err(DUPLICATE));
        // A new one, then a withdrawal of it within the same reply.
        assert_eq!(s.apply(true, c, Some(&base)), Ok(()));
        assert_eq!(s.apply(false, b, Some(&base)), Ok(()));
        let Staging::Delta(changes) = s else {
            unreachable!()
        };
        let (set, affected) = apply_delta(&base, changes).unwrap();
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
        let mut s = Staging::Delta(HashMap::new());
        s.apply(false, a, Some(&base)).unwrap();
        s.apply(true, a, Some(&base)).unwrap();
        let Staging::Delta(changes) = s else {
            unreachable!()
        };
        assert!(apply_delta(&base, changes).is_none());
        assert!(apply_delta(&base, HashMap::new()).is_none());
    }

    #[test]
    fn a_discarded_reply_accepts_anything() {
        let a = vrp("192.0.2.0/24", 24, 64_496);
        let mut s = Staging::Discard;
        assert_eq!(s.apply(false, a, None), Ok(()));
        assert_eq!(s.apply(true, a, None), Ok(()));
        assert_eq!(s.apply(true, a, None), Ok(()));
    }
}
