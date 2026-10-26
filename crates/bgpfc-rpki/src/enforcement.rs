//! What the router does with a route's validation state: the operator's
//! enforcement mode (issues #61, #47, #60).
//!
//! RFC 6811 §2: "An implementation MUST NOT exclude a route from the
//! Adj-RIB-In or from consideration in the decision process as a side
//! effect of its validation state, unless explicitly configured to do
//! so." RFC 6811 §5 names the two things such a configuration may do:
//! "filtering routes based on validation state (for example, rejecting
//! all "invalid" routes) or adjusting a route's degree of preference in
//! the selection algorithm based on its validation state". The modes are
//! those two, and neither ([`Enforcement::Off`], RFC 8481 §5: "Set State,
//! Don't Act").
//!
//! The type has no default: which mode applies when the operator writes
//! none is the configuration's decision, not this crate's.
//!
//! Implements: RFC 6811 §2 (no route leaves the decision process for its
//! state unless configured to: only [`Enforcement::DropInvalid`] rules
//! one out), §5 (filtering on the state, or adjusting the degree of
//! preference by it).

use std::fmt;
use std::str::FromStr;

use crate::{RovState, RpkiError};

/// The operator's enforcement mode: what a route's validation state does
/// to its use, beyond what policy does with it.
///
/// It acts on the state a route is used with, which import policy may
/// have set in place of the one the lookup gave (RFC 6811 §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Enforcement {
    /// An Invalid route is held in the Adj-RIB-In and is no candidate
    /// for the decision process, so it is neither installed nor
    /// advertised; it is used again as soon as it is no longer Invalid.
    /// RFC 6811 §5: "rejecting all "invalid" routes"; the Adj-RIB-In
    /// keeps it, as RFC 6811 §2 asks.
    DropInvalid,
    /// No route is excluded, but route selection prefers Valid over
    /// `NotFound` over Invalid before anything else. RFC 6811 §5:
    /// "adjusting a route's degree of preference in the selection
    /// algorithm based on its validation state".
    PreferValid,
    /// The state is set, shown and seen by policy, and nothing else acts
    /// on it. RFC 8481 §5: "Absent specific operator configuration,
    /// policy MUST NOT be applied."
    Off,
}

impl Enforcement {
    /// Every mode, in declaration order.
    pub const ALL: [Enforcement; 3] = [
        Enforcement::DropInvalid,
        Enforcement::PreferValid,
        Enforcement::Off,
    ];

    /// The name used in configuration, logs and control output:
    /// `drop-invalid`, `prefer-valid` or `off`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Enforcement::DropInvalid => "drop-invalid",
            Enforcement::PreferValid => "prefer-valid",
            Enforcement::Off => "off",
        }
    }

    /// Whether a route used with validation state `state` may be a
    /// candidate for the decision process: always, except an Invalid
    /// route under [`Enforcement::DropInvalid`] (RFC 6811 §5, "rejecting
    /// all "invalid" routes"). `disabled` reads as `NotFound` (RFC 6811 §2)
    /// and is admitted.
    #[must_use]
    pub const fn admits(self, state: RovState) -> bool {
        !matches!(
            (self, state.as_rfc6811()),
            (Enforcement::DropInvalid, RovState::Invalid)
        )
    }

    /// Whether route selection ranks routes by validation state, with
    /// [`Enforcement::rank`], before anything else: only under
    /// [`Enforcement::PreferValid`] (RFC 6811 §5, "adjusting a route's
    /// degree of preference ... based on its validation state").
    #[must_use]
    pub const fn ranks(self) -> bool {
        matches!(self, Enforcement::PreferValid)
    }

    /// The rank of `state` in route selection, higher preferred: Valid 2,
    /// `NotFound` 1, Invalid 0 (issue #47: "preferring Valid over `NotFound`
    /// over Invalid"). `disabled` ranks as `NotFound`, which RFC 6811 §2
    /// says a route not validated SHOULD be.
    #[must_use]
    pub const fn rank(state: RovState) -> u8 {
        match state.as_rfc6811() {
            RovState::Valid => 2,
            RovState::NotFound | RovState::Disabled => 1,
            RovState::Invalid => 0,
        }
    }
}

impl fmt::Display for Enforcement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Enforcement {
    type Err = RpkiError;

    /// Parse the name [`Enforcement::as_str`] produces; nothing else.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Enforcement::ALL
            .into_iter()
            .find(|e| e.as_str() == s)
            .ok_or_else(|| RpkiError::UnknownEnforcement(s.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforcement_names_round_trip() {
        let names: Vec<String> = Enforcement::ALL.iter().map(ToString::to_string).collect();
        assert_eq!(names, ["drop-invalid", "prefer-valid", "off"]);
        for e in Enforcement::ALL {
            assert_eq!(e.to_string().parse::<Enforcement>(), Ok(e));
            assert_eq!(e.as_str(), e.to_string());
        }
        // Exactly the three spellings.
        for bad in [
            "",
            "Off",
            "OFF",
            "none",
            "accept",
            "drop_invalid",
            "dropinvalid",
            "drop-invalid ",
            " off",
            "prefer valid",
        ] {
            assert_eq!(
                bad.parse::<Enforcement>(),
                Err(RpkiError::UnknownEnforcement(bad.to_owned())),
                "{bad:?}"
            );
        }
        assert_eq!(
            "none".parse::<Enforcement>().unwrap_err().to_string(),
            "unknown enforcement mode \"none\""
        );
    }

    #[test]
    fn admits_only_rules_out_invalid_under_drop_invalid() {
        for e in Enforcement::ALL {
            for s in RovState::ALL {
                let ruled_out = e == Enforcement::DropInvalid && s == RovState::Invalid;
                assert_eq!(e.admits(s), !ruled_out, "{e} {s}");
            }
        }
    }

    #[test]
    fn rank_orders_valid_not_found_invalid_and_disabled_as_not_found() {
        use RovState::{Disabled, Invalid, NotFound, Valid};
        assert!(Enforcement::rank(Valid) > Enforcement::rank(NotFound));
        assert!(Enforcement::rank(NotFound) > Enforcement::rank(Invalid));
        // RFC 6811 §2: a route not validated reads as NotFound.
        assert_eq!(Enforcement::rank(Disabled), Enforcement::rank(NotFound));
        assert_eq!(
            RovState::ALL.map(Enforcement::rank),
            [2, 0, 1, 1],
            "in RovState::ALL order"
        );
        // Only prefer-valid ranks.
        assert_eq!(
            Enforcement::ALL.map(Enforcement::ranks),
            [false, true, false]
        );
    }
}
