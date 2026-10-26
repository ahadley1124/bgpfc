//! What a speaker itself does with a route whose origin validation state
//! is Invalid, before any policy an operator wrote.
//!
//! Implements: RFC 6811 §5 (policy may filter routes by their state, "for
//! example, rejecting all 'invalid' routes", or adjust a route's degree of
//! preference by it; "considering invalid routes for BGP decision process
//! is a purely local policy matter and should be done with utmost care");
//! RFC 8481 §5 ("Set State, Don't Act": the operator is "in complete
//! control of any policy applied based on the evaluation state").

use std::fmt;
use std::str::FromStr;

use crate::RpkiError;

/// What the speaker does with an Invalid route on its own.
///
/// The state a route holds, after any `set rpki` of import policy
/// (RFC 6811 §3), is what these act on. Valid, `NotFound` and `Disabled`
/// routes are never touched by them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum InvalidAction {
    /// Refuse the route: it is no candidate for the decision process, so
    /// it is neither used nor passed on. RFC 6811 §2 forbids excluding it
    /// "from the Adj-RIB-In ... as a side effect of its validation state,
    /// unless explicitly configured to do so" and §4 runs the decision
    /// process again when the state changes, so the route stays in the
    /// Adj-RIB-In and becomes a candidate again once its state allows.
    Drop,
    /// Keep the route as a candidate, but let it lose to every route that
    /// is not Invalid, whatever the rest of the decision process says
    /// (RFC 6811 §5: "adjusting a route's degree of preference in the
    /// selection algorithm based on its validation state"). An Invalid
    /// route is used only when no other route to the destination exists.
    PreferValid,
    /// Do nothing of its own. Invalid routes take part in the decision
    /// process like any other, and policy alone acts on the state
    /// (RFC 8481 §5).
    Policy,
}

impl InvalidAction {
    /// Every action, in declaration order.
    pub const ALL: [InvalidAction; 3] = [
        InvalidAction::Drop,
        InvalidAction::PreferValid,
        InvalidAction::Policy,
    ];

    /// The name used in configuration and control output: `drop`,
    /// `prefer-valid` or `policy`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            InvalidAction::Drop => "drop",
            InvalidAction::PreferValid => "prefer-valid",
            InvalidAction::Policy => "policy",
        }
    }

    /// Whether Invalid routes are refused.
    #[must_use]
    pub const fn drops(self) -> bool {
        matches!(self, InvalidAction::Drop)
    }

    /// Whether Invalid routes lose to those that are not.
    #[must_use]
    pub const fn demotes(self) -> bool {
        matches!(self, InvalidAction::PreferValid)
    }
}

impl fmt::Display for InvalidAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for InvalidAction {
    type Err = RpkiError;

    /// Parse the name [`InvalidAction::as_str`] produces; nothing else.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        InvalidAction::ALL
            .into_iter()
            .find(|action| action.as_str() == s)
            .ok_or_else(|| RpkiError::UnknownAction(s.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        let names: Vec<String> = InvalidAction::ALL.iter().map(ToString::to_string).collect();
        assert_eq!(names, ["drop", "prefer-valid", "policy"]);
        for action in InvalidAction::ALL {
            assert_eq!(action.to_string().parse::<InvalidAction>(), Ok(action));
        }
    }

    #[test]
    fn parse_is_exact() {
        for bad in [
            "",
            "Drop",
            "DROP",
            "prefer_valid",
            "preferValid",
            "reject",
            " drop",
        ] {
            assert_eq!(
                bad.parse::<InvalidAction>(),
                Err(RpkiError::UnknownAction(bad.to_owned())),
                "{bad:?}"
            );
        }
        assert_eq!(
            "nope".parse::<InvalidAction>().unwrap_err().to_string(),
            "unknown action \"nope\" for Invalid routes"
        );
    }

    #[test]
    fn each_action_does_one_thing() {
        let did: Vec<(bool, bool)> = InvalidAction::ALL
            .iter()
            .map(|a| (a.drops(), a.demotes()))
            .collect();
        assert_eq!(did, [(true, false), (false, true), (false, false)]);
    }
}
