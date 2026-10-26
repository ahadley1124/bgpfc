//! The Only to Customer procedures: what a session with a BGP Role does
//! to the OTC attribute of the routes it receives and sends.
//!
//! Implements: RFC 9234 §3.1 (the Roles and who may be sent what), §5
//! (the ingress and egress procedures), §5 last paragraph (they are for
//! IPv4 and IPv6 unicast, the families bgpfc speaks, and not for the
//! operator to change: no policy statement reaches the attribute).
//!
//! Every function takes the Role as ours on the session, as the BGP Role
//! capability does: ours `Customer` makes the neighbor a Provider.

use bgpfc_wire::role::Role;
use bgpfc_wire::types::Asn;

use crate::attrs::PathAttrs;
use crate::peer::PeerInfo;

/// What RFC 9234 §5 makes of a route received on a session with a Role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ingress {
    /// Nothing to do: the route stays as it came.
    Keep,
    /// The route came without the attribute from a neighbor whose routes
    /// must have it: add it, with the neighbor's AS.
    Set(Asn),
    /// A route leak: the route "MUST be considered ineligible".
    Leak,
}

/// The ingress procedure (RFC 9234 §5) for a route with `otc` received on
/// the session described by `from`.
#[must_use]
pub fn ingress(from: &PeerInfo, otc: Option<Asn>) -> Ingress {
    // The common case, a session with no Role, costs this one test.
    let Some(role) = from.role else {
        return Ingress::Keep;
    };
    match (role, otc) {
        // "1. If a route with the OTC Attribute is received from a Customer
        // or an RS-Client, then it is a route leak and MUST be considered
        // ineligible." We are the Provider, or the RS.
        (Role::Provider | Role::RouteServer, Some(_)) => Ingress::Leak,
        // "2. If a route with the OTC Attribute is received from a Peer
        // (i.e., remote AS with a Peer Role) and the Attribute has a value
        // that is not equal to the remote (i.e., Peer's) AS number, then it
        // is a route leak and MUST be considered ineligible."
        (Role::Peer, Some(asn)) if asn != from.remote_as => Ingress::Leak,
        // "3. If a route is received from a Provider, a Peer, or an RS and
        // the OTC Attribute is not present, then it MUST be added with a
        // value equal to the AS number of the remote AS." We are the
        // Customer, the Peer, or the RS-Client.
        (Role::Customer | Role::RouteServerClient | Role::Peer, None) => {
            Ingress::Set(from.remote_as)
        }
        // A customer's route without the attribute, a peer's with its own
        // AS, a provider's with one: as they are. An unassigned Role names
        // no relationship, so no procedure.
        _ => Ingress::Keep,
    }
}

/// Apply the ingress procedure (RFC 9234 §5) to the attributes of routes
/// received on the session described by `from`: add the attribute where it
/// is due.
///
/// # Errors
/// The AS in the attribute, if the routes are route leaks.
pub fn receive(from: &PeerInfo, attrs: &mut PathAttrs) -> Result<(), Asn> {
    match ingress(from, attrs.otc) {
        Ingress::Keep => Ok(()),
        Ingress::Set(asn) => {
            attrs.otc = Some(asn);
            Ok(())
        }
        // invariant: a leak is a route that has the attribute.
        Ingress::Leak => Err(attrs.otc.unwrap_or(from.remote_as)),
    }
}

/// Whether the egress procedure (RFC 9234 §5) keeps `attrs` from `to`
/// altogether: "2. If a route already contains the OTC Attribute, it MUST
/// NOT be propagated to Providers, Peers, or RSes." That is a session
/// where our Role is Customer (the neighbor is a Provider), Peer, or
/// RS-Client (the neighbor is an RS).
#[must_use]
pub fn blocks_egress(attrs: &PathAttrs, to: &PeerInfo) -> bool {
    attrs.otc.is_some()
        && matches!(
            to.role,
            Some(Role::Customer | Role::Peer | Role::RouteServerClient)
        )
}

/// Whether the egress procedure (RFC 9234 §5) adds our AS to a route
/// without the attribute sent to `to`: "1. If a route is to be advertised
/// to a Customer, a Peer, or an RS-Client (when the sender is an RS), and
/// the OTC Attribute is not present, then when advertising the route, an
/// OTC Attribute MUST be added with a value equal to the AS number of the
/// local AS." Our Role is Provider, Peer, or RS.
#[must_use]
pub fn marks_egress(to: &PeerInfo) -> bool {
    matches!(
        to.role,
        Some(Role::Provider | Role::Peer | Role::RouteServer)
    )
}

/// The attribute a route with `otc` carries when sent to `to`: the value
/// it has ("Once the OTC Attribute has been set, it MUST be preserved
/// unchanged"), else ours if the egress procedure adds it.
#[must_use]
pub fn egress(local_as: Asn, otc: Option<Asn>, to: &PeerInfo) -> Option<Asn> {
    otc.or_else(|| marks_egress(to).then_some(local_as))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::peer;

    const ALL: [Role; 5] = [
        Role::Provider,
        Role::RouteServer,
        Role::RouteServerClient,
        Role::Customer,
        Role::Peer,
    ];

    fn with_role(role: Option<Role>) -> PeerInfo {
        let mut p = peer("10.0.0.1", 65_001, 1);
        p.role = role;
        p
    }

    #[test]
    fn ingress_follows_section_5() {
        use Ingress::{Keep, Leak, Set};
        let theirs = Asn(65_001);
        let other = Asn(65_009);
        // (our Role, OTC received) → outcome, row by row of the RFC's
        // three rules and the cases they leave alone.
        let rows = [
            // We are the Provider: the neighbor is a Customer. Rule 1.
            (Role::Provider, None, Keep),
            (Role::Provider, Some(theirs), Leak),
            (Role::Provider, Some(other), Leak),
            // We are the RS: the neighbor is an RS-Client. Rule 1.
            (Role::RouteServer, None, Keep),
            (Role::RouteServer, Some(theirs), Leak),
            (Role::RouteServer, Some(other), Leak),
            // We are the Customer: the neighbor is a Provider. Rule 3.
            (Role::Customer, None, Set(theirs)),
            (Role::Customer, Some(theirs), Keep),
            (Role::Customer, Some(other), Keep),
            // We are the RS-Client: the neighbor is an RS. Rule 3.
            (Role::RouteServerClient, None, Set(theirs)),
            (Role::RouteServerClient, Some(theirs), Keep),
            (Role::RouteServerClient, Some(other), Keep),
            // Lateral peers. Rules 2 and 3.
            (Role::Peer, None, Set(theirs)),
            (Role::Peer, Some(theirs), Keep),
            (Role::Peer, Some(other), Leak),
            // No relationship, no procedure.
            (Role::Unknown(7), None, Keep),
            (Role::Unknown(7), Some(other), Keep),
        ];
        for (role, otc, expected) in rows {
            assert_eq!(
                ingress(&with_role(Some(role)), otc),
                expected,
                "{role} with {otc:?}"
            );
        }
        // No Role on the session: no procedure at all.
        for otc in [None, Some(theirs), Some(other)] {
            assert_eq!(ingress(&with_role(None), otc), Keep);
            let mut a = crate::tests::attrs(&[65_001], "10.0.0.1");
            a.otc = otc;
            assert_eq!(receive(&with_role(None), &mut a), Ok(()));
            assert_eq!(a.otc, otc);
        }
        // `receive` applies the outcome to the attributes.
        let from = with_role(Some(Role::Customer));
        let mut a = crate::tests::attrs(&[65_001], "10.0.0.1");
        assert_eq!(receive(&from, &mut a), Ok(()));
        assert_eq!(a.otc, Some(theirs));
        let from = with_role(Some(Role::Provider));
        a.otc = Some(other);
        assert_eq!(receive(&from, &mut a), Err(other));
        assert_eq!(a.otc, Some(other));
    }

    #[test]
    fn egress_follows_section_5() {
        let local = Asn(65_000);
        let a = |otc| {
            let mut a = crate::tests::attrs(&[65_001], "10.0.0.1");
            a.otc = otc;
            a
        };
        for role in ALL {
            let to = with_role(Some(role));
            // Rule 2: to a Provider, Peer or RS (ours: Customer, Peer,
            // RS-Client), a route with the attribute is not sent.
            let blocked = matches!(role, Role::Customer | Role::Peer | Role::RouteServerClient);
            assert_eq!(blocks_egress(&a(Some(Asn(7))), &to), blocked, "{role}");
            assert!(!blocks_egress(&a(None), &to), "{role}");
            // Rule 1: to a Customer, Peer or RS-Client (ours: Provider,
            // Peer, RS), one without it gets ours; one with it, its own.
            let marked = matches!(role, Role::Provider | Role::Peer | Role::RouteServer);
            assert_eq!(marks_egress(&to), marked, "{role}");
            assert_eq!(egress(local, None, &to), marked.then_some(local), "{role}");
            assert_eq!(egress(local, Some(Asn(7)), &to), Some(Asn(7)), "{role}");
        }
        // An unassigned Role, or none: untouched.
        for role in [Some(Role::Unknown(9)), None] {
            let to = with_role(role);
            assert!(!blocks_egress(&a(Some(Asn(7))), &to));
            assert_eq!(egress(local, None, &to), None);
            assert_eq!(egress(local, Some(Asn(7)), &to), Some(Asn(7)));
        }
    }
}
