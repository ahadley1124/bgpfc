//! What the router does with routes while origin validation is on but has
//! no data yet: the operator's startup setting.
//!
//! Until the first full set of VRPs arrives, no lookup can be made, and
//! every route is [`RovState::Disabled`]. RFC 6811 §2: "An implementation
//! MUST NOT exclude a route from the Adj-RIB-In or from consideration in
//! the decision process as a side effect of its validation state, unless
//! explicitly configured to do so." So such routes are used, as received
//! ([`Startup::Accept`]), unless the operator configures them to be held
//! until the data arrives ([`Startup::Hold`]).
//!
//! The type has no default: which applies when the operator writes none
//! is the configuration's decision, not this crate's.
//!
//! Implements: RFC 6811 §2 (no route leaves the decision process for its
//! state unless configured to: only [`Startup::Hold`] rules one out while
//! no lookup can be made).

use std::fmt;
use std::str::FromStr;

use crate::{RovState, RpkiError};

/// What a route not yet validated does while validation waits for its
/// first data.
///
/// It acts on the state a route is used with, as [`crate::Enforcement`]
/// does: an import policy that sets a state (RFC 6811 §3) takes the route
/// out of its reach.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Startup {
    /// A route used with state `disabled` is a candidate for the decision
    /// process like any other: routes are used unvalidated until the
    /// first full set validates them.
    Accept,
    /// A route used with state `disabled` is held in the Adj-RIB-In and
    /// is no candidate for the decision process: no route is used before
    /// it has been validated. Configured, as RFC 6811 §2 asks ("unless
    /// explicitly configured to do so"); the Adj-RIB-In keeps it.
    Hold,
}

impl Startup {
    /// Every setting, in declaration order.
    pub const ALL: [Startup; 2] = [Startup::Accept, Startup::Hold];

    /// The name used in configuration, logs and control output: `accept`
    /// or `hold`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Startup::Accept => "accept",
            Startup::Hold => "hold",
        }
    }

    /// Whether a route used with validation state `state` may be a
    /// candidate for the decision process: always, except a `disabled`
    /// route under [`Startup::Hold`]. A route that has been validated,
    /// whatever its state, is not this setting's business.
    #[must_use]
    pub const fn admits(self, state: RovState) -> bool {
        !matches!((self, state), (Startup::Hold, RovState::Disabled))
    }
}

impl fmt::Display for Startup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Startup {
    type Err = RpkiError;

    /// Parse the name [`Startup::as_str`] produces; nothing else.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Startup::ALL
            .into_iter()
            .find(|v| v.as_str() == s)
            .ok_or_else(|| RpkiError::UnknownStartup(s.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_names_round_trip() {
        let names: Vec<String> = Startup::ALL.iter().map(ToString::to_string).collect();
        assert_eq!(names, ["accept", "hold"]);
        for v in Startup::ALL {
            assert_eq!(v.to_string().parse::<Startup>(), Ok(v));
            assert_eq!(v.as_str(), v.to_string());
        }
        for bad in [
            "", "Hold", "HOLD", "held", "use", "wait", " hold", "accept ",
        ] {
            assert_eq!(
                bad.parse::<Startup>(),
                Err(RpkiError::UnknownStartup(bad.to_owned())),
                "{bad:?}"
            );
        }
        assert_eq!(
            "wait".parse::<Startup>().unwrap_err().to_string(),
            "unknown startup setting \"wait\""
        );
    }

    #[test]
    fn hold_rules_out_only_routes_not_validated() {
        for v in Startup::ALL {
            for s in RovState::ALL {
                let ruled_out = v == Startup::Hold && s == RovState::Disabled;
                assert_eq!(v.admits(s), !ruled_out, "{v} {s}");
            }
        }
        // A route no VRP covers has been validated: `not-found` is not
        // `disabled` (issue #52), and hold leaves it alone.
        assert!(Startup::Hold.admits(RovState::NotFound));
    }
}
