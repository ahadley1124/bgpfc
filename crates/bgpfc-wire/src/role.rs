//! BGP Role values, as carried in the Role capability.
//!
//! Implements: RFC 9234 §3.1 (the peering relationships a Role names),
//! §4 (the Roles an eBGP session may have), §4.1 (Table 1: the Role Value
//! of each Role), §4.2 (Table 2: which pairs of Roles correspond).

use std::fmt;

/// A BGP Role: the relationship the speaker that advertises it has to the
/// speaker at the other end of an eBGP session (RFC 9234 §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Role {
    /// The sender is a transit provider of the receiver (value 0).
    Provider,
    /// The sender is a Route Server and the receiver its RS-Client
    /// (value 1).
    RouteServer,
    /// The sender is a Route Server Client of the receiver (value 2).
    RouteServerClient,
    /// The sender is a transit customer of the receiver (value 3).
    Customer,
    /// The sender and the receiver are lateral Peers (value 4).
    Peer,
    /// A Role Value RFC 9234 Table 1 leaves unassigned (5 to 255). It
    /// corresponds to no Role of Table 2, so a session with a speaker that
    /// advertises it cannot agree on a relationship.
    Unknown(u8),
}

impl Role {
    /// From the Role Value of the capability (RFC 9234 §4.1, Table 1).
    #[must_use]
    pub const fn from_u8(v: u8) -> Role {
        match v {
            0 => Role::Provider,
            1 => Role::RouteServer,
            2 => Role::RouteServerClient,
            3 => Role::Customer,
            4 => Role::Peer,
            v => Role::Unknown(v),
        }
    }

    /// The Role Value of the capability (RFC 9234 §4.1, Table 1).
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        match self {
            Role::Provider => 0,
            Role::RouteServer => 1,
            Role::RouteServerClient => 2,
            Role::Customer => 3,
            Role::Peer => 4,
            Role::Unknown(v) => v,
        }
    }

    /// Whether a speaker with this Role may have a session with one that
    /// advertises `remote` (RFC 9234 §4.2, Table 2): Provider with
    /// Customer, RS with RS-Client, and Peer with Peer, each way round.
    /// An unassigned value pairs with nothing.
    #[must_use]
    pub const fn pairs_with(self, remote: Role) -> bool {
        matches!(
            (self, remote),
            (Role::Provider, Role::Customer)
                | (Role::Customer, Role::Provider)
                | (Role::RouteServer, Role::RouteServerClient)
                | (Role::RouteServerClient, Role::RouteServer)
                | (Role::Peer, Role::Peer)
        )
    }
}

/// The BGP Role configured for a session and how the peer's is checked
/// (RFC 9234 §4.2): what the OPEN exchange needs to know of a neighbor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LocalRole {
    /// Our Role, advertised in the BGP Role capability (§4.1).
    pub role: Role,
    /// "Strict mode" (§4.2): the connection is rejected with Role
    /// Mismatch when the peer sends no BGP Role capability.
    pub strict: bool,
}

impl fmt::Display for Role {
    /// The name the configuration uses; an unassigned value is
    /// `unassigned(N)`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Role::Provider => f.write_str("provider"),
            Role::RouteServer => f.write_str("rs"),
            Role::RouteServerClient => f.write_str("rs-client"),
            Role::Customer => f.write_str("customer"),
            Role::Peer => f.write_str("peer"),
            Role::Unknown(v) => write!(f, "unassigned({v})"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KNOWN: [Role; 5] = [
        Role::Provider,
        Role::RouteServer,
        Role::RouteServerClient,
        Role::Customer,
        Role::Peer,
    ];

    #[test]
    fn values_follow_table_1() {
        // RFC 9234 §4.1, Table 1.
        for (v, role) in KNOWN.into_iter().enumerate() {
            let v = u8::try_from(v).unwrap();
            assert_eq!(Role::from_u8(v), role);
            assert_eq!(role.to_u8(), v);
        }
        for v in 5..=u8::MAX {
            assert_eq!(Role::from_u8(v), Role::Unknown(v));
            assert_eq!(Role::Unknown(v).to_u8(), v);
        }
    }

    #[test]
    fn allowed_pairs_follow_table_2() {
        // RFC 9234 §4.2, Table 2: five rows, so five ordered pairs hold
        // out of the twenty-five.
        let pairs: Vec<(Role, Role)> = KNOWN
            .into_iter()
            .flat_map(|a| KNOWN.into_iter().map(move |b| (a, b)))
            .filter(|(a, b)| a.pairs_with(*b))
            .collect();
        assert_eq!(
            pairs,
            vec![
                (Role::Provider, Role::Customer),
                (Role::RouteServer, Role::RouteServerClient),
                (Role::RouteServerClient, Role::RouteServer),
                (Role::Customer, Role::Provider),
                (Role::Peer, Role::Peer),
            ]
        );
        // An unassigned value corresponds to nothing, itself included.
        for a in KNOWN {
            assert!(!a.pairs_with(Role::Unknown(5)));
            assert!(!Role::Unknown(5).pairs_with(a));
        }
        assert!(!Role::Unknown(9).pairs_with(Role::Unknown(9)));
    }

    #[test]
    fn names_are_those_of_the_configuration() {
        let names: Vec<String> = KNOWN.iter().map(ToString::to_string).collect();
        assert_eq!(names, ["provider", "rs", "rs-client", "customer", "peer"]);
        assert_eq!(Role::Unknown(7).to_string(), "unassigned(7)");
    }
}
