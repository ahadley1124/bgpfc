//! Validation verdicts attached to a route.
//!
//! Implements: RFC 6811 §2 (`Valid`, `Invalid`, `NotFound`; a route not
//! validated is `NotFound`), §3 (policy matching a state, see
//! [`RovState::satisfies`]); RFC 6483 §2 ("unknown", synonymously "not
//! found"). The spelling of each state in logs, configuration and control
//! output is the one [`RovState`]'s `Display` produces.

use std::fmt;
use std::str::FromStr;

use crate::RpkiError;

/// The route origin validation state of a route.
///
/// The first three are the states of RFC 6811 §2. `Disabled` is not an
/// RFC state: it records that origin validation is not being performed at
/// all, which is a different fact from "no VRP covers this route"
/// (`NotFound`). Keeping them apart lets operators see whether a
/// `not-found` route was checked. [`RovState::as_rfc6811`] folds
/// `Disabled` into `NotFound` where RFC 6811 semantics are wanted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RovState {
    /// "At least one VRP Matches the Route Prefix" (RFC 6811 §2).
    Valid,
    /// "At least one VRP Covers the Route Prefix, but no VRP Matches it"
    /// (RFC 6811 §2).
    Invalid,
    /// "No VRP Covers the Route Prefix" (RFC 6811 §2).
    NotFound,
    /// Origin validation is not being performed.
    Disabled,
}

impl RovState {
    /// Every state, in declaration order.
    pub const ALL: [RovState; 4] = [
        RovState::Valid,
        RovState::Invalid,
        RovState::NotFound,
        RovState::Disabled,
    ];

    /// The name used in logs, configuration and control output:
    /// `valid`, `invalid`, `not-found` or `disabled`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            RovState::Valid => "valid",
            RovState::Invalid => "invalid",
            RovState::NotFound => "not-found",
            RovState::Disabled => "disabled",
        }
    }

    /// The state as RFC 6811 knows it. RFC 6811 §2: "If validation is not
    /// performed on a Route, the implementation SHOULD initialize the
    /// validation state of such a route to '`NotFound`'." So `Disabled`
    /// reads as `NotFound`; the other states are unchanged.
    #[must_use]
    pub const fn as_rfc6811(self) -> RovState {
        match self {
            RovState::Disabled => RovState::NotFound,
            other => other,
        }
    }

    /// Whether a route in this state satisfies a policy's `match rpki
    /// wanted` (RFC 6811 §3: "An implementation MUST provide the ability
    /// to match and set the validation state of routes as part of its
    /// route policy filtering function").
    ///
    /// `valid`, `invalid` and `not-found` are RFC 6811 states, and for
    /// them a route not validated reads as `NotFound`, which RFC 6811 §2
    /// says it SHOULD be ("If validation is not performed on a Route, the
    /// implementation SHOULD initialize the validation state of such a
    /// route to "NotFound""): so a policy written for validation does
    /// with an unvalidated route what it does with a `NotFound` one.
    /// `disabled` holds for a route not validated only, so that policy can
    /// still tell the two apart.
    #[must_use]
    pub const fn satisfies(self, wanted: RovState) -> bool {
        match wanted {
            RovState::Disabled => matches!(self, RovState::Disabled),
            RovState::Valid => matches!(self.as_rfc6811(), RovState::Valid),
            RovState::Invalid => matches!(self.as_rfc6811(), RovState::Invalid),
            RovState::NotFound => matches!(self.as_rfc6811(), RovState::NotFound),
        }
    }
}

impl fmt::Display for RovState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RovState {
    type Err = RpkiError;

    /// Parse the name [`RovState::as_str`] produces; nothing else.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        RovState::ALL
            .into_iter()
            .find(|state| state.as_str() == s)
            .ok_or_else(|| RpkiError::UnknownState(s.to_owned()))
    }
}

/// The ASPA path verification verdict of a route.
///
/// A placeholder until ASPA lands in v1.1.0: it exists so that a route can
/// carry an ASPA verdict next to its [`RovState`] now, and the route type
/// keeps its shape when the real verdicts arrive. The only verdict today
/// is `Disabled`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AspaState {
    /// ASPA verification is not being performed.
    Disabled,
}

impl AspaState {
    /// The name used in logs, configuration and control output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            AspaState::Disabled => "disabled",
        }
    }
}

impl fmt::Display for AspaState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AspaState {
    type Err = RpkiError;

    /// Parse the name [`AspaState::as_str`] produces; nothing else.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "disabled" => Ok(AspaState::Disabled),
            _ => Err(RpkiError::UnknownState(s.to_owned())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rov_state_names_round_trip() {
        let names: Vec<String> = RovState::ALL.iter().map(ToString::to_string).collect();
        assert_eq!(names, ["valid", "invalid", "not-found", "disabled"]);
        for state in RovState::ALL {
            assert_eq!(state.to_string().parse::<RovState>(), Ok(state));
            assert_eq!(state.as_str(), state.to_string());
        }
    }

    #[test]
    fn rov_state_parse_is_exact() {
        for bad in [
            "",
            "Valid",
            "VALID",
            "notfound",
            "not_found",
            "NotFound",
            " valid",
            "valid ",
            "unknown",
        ] {
            assert_eq!(
                bad.parse::<RovState>(),
                Err(RpkiError::UnknownState(bad.to_owned())),
                "{bad:?}"
            );
        }
        assert_eq!(
            "nope".parse::<RovState>().unwrap_err().to_string(),
            "unknown validation state \"nope\""
        );
    }

    #[test]
    fn disabled_is_not_not_found() {
        // Issue #52: "we are not checking" is a different fact from "no ROA
        // covers this", so the two stay distinct states.
        assert_ne!(RovState::Disabled, RovState::NotFound);
        assert_ne!(
            RovState::Disabled.to_string(),
            RovState::NotFound.to_string()
        );
        // RFC 6811 §2: an unvalidated route SHOULD read as NotFound.
        assert_eq!(RovState::Disabled.as_rfc6811(), RovState::NotFound);
        for state in [RovState::Valid, RovState::Invalid, RovState::NotFound] {
            assert_eq!(state.as_rfc6811(), state);
        }
    }

    #[test]
    fn satisfies_reads_disabled_as_not_found_but_not_the_reverse() {
        use RovState::{Disabled, Invalid, NotFound, Valid};
        // (state, wanted) pairs that match; every other pair does not.
        let matching = [
            (Valid, Valid),
            (Invalid, Invalid),
            (NotFound, NotFound),
            // RFC 6811 §2: a route not validated reads as NotFound...
            (Disabled, NotFound),
            // ...and only it is `disabled`.
            (Disabled, Disabled),
        ];
        for state in RovState::ALL {
            for wanted in RovState::ALL {
                assert_eq!(
                    state.satisfies(wanted),
                    matching.contains(&(state, wanted)),
                    "{state} matched against {wanted}"
                );
            }
        }
        assert!(!NotFound.satisfies(Disabled));
    }

    #[test]
    fn aspa_state_names_round_trip() {
        assert_eq!(AspaState::Disabled.to_string(), "disabled");
        assert_eq!("disabled".parse::<AspaState>(), Ok(AspaState::Disabled));
        assert_eq!(
            "valid".parse::<AspaState>(),
            Err(RpkiError::UnknownState("valid".to_owned()))
        );
    }
}
