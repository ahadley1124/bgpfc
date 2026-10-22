//! Every route carries its RFC 6811 validation state (issue #56), and
//! policy sees it (RFC 6811 §3).

use std::sync::Mutex;

use super::*;
use crate::{Policies, Verdict};

/// What a policy was asked about, and the validation state it was told.
type Seen = Arc<Mutex<Vec<(&'static str, Prefix, RovState)>>>;

/// Accepts every route and records each question it is asked.
struct Record(Seen);

impl Policies for Record {
    fn import(
        &self,
        _: &PeerInfo,
        _: AddressFamily,
        p: Prefix,
        _: &PathAttrs,
        rov: RovState,
    ) -> Verdict {
        self.0.lock().unwrap().push(("import", p, rov));
        Verdict::Accept
    }
    fn export(
        &self,
        _: &PeerInfo,
        _: AddressFamily,
        p: Prefix,
        _: &PathAttrs,
        rov: RovState,
    ) -> Verdict {
        self.0.lock().unwrap().push(("export", p, rov));
        Verdict::Accept
    }
}

#[test]
fn without_a_validation_source_every_route_is_disabled() {
    // Issue #56: the null source answers Disabled for everything, which is
    // not NotFound (issue #52).
    let mut rib = Rib::new(LOCAL_AS);
    let e1 = peer("10.0.0.1", 65_001, 1);
    let i1 = peer("10.0.0.2", 65_000, 2);
    rib.peer_up(e1.clone(), now());
    rib.peer_up(i1.clone(), now());
    rib.update(
        e1.addr,
        &announce(&["192.0.2.0/24"], &attrs(&[65_001, 64_496], "10.0.0.1")),
        now(),
    );
    rib.update(
        e1.addr,
        &announce(&["2001:db8::/32"], &attrs(&[65_001], "2001:db8::1")),
        now(),
    );
    // An empty AS_PATH from an internal peer: the route originates in our
    // own AS (RFC 6811 §2).
    rib.update(
        i1.addr,
        &announce(
            &["192.0.2.0/24", "198.51.100.0/24"],
            &attrs(&[], "10.0.0.2"),
        ),
        now(),
    );
    for (family, prefix, routes) in [
        (V4, "192.0.2.0/24", 2),
        (V4, "198.51.100.0/24", 1),
        (V6, "2001:db8::/32", 1),
    ] {
        let c = rib.candidates(family, p(prefix));
        assert_eq!(c.len(), routes, "{prefix}");
        for c in c {
            assert_eq!((c.rov, c.aspa), (RovState::Disabled, AspaState::Disabled));
        }
    }
    let best: Vec<_> = rib
        .loc_rib(V4)
        .chain(rib.loc_rib(V6))
        .map(|(_, b)| (b.rov, b.aspa))
        .collect();
    assert_eq!(best, vec![(RovState::Disabled, AspaState::Disabled); 3]);
}

#[test]
fn policy_is_told_the_validation_state() {
    let seen = Seen::default();
    let mut rib = Rib::with_policies(LOCAL_AS, Box::new(Record(Arc::clone(&seen))));
    let e1 = peer("10.0.0.1", 65_001, 1);
    let e2 = peer("10.0.0.2", 65_002, 2);
    rib.peer_up(e1.clone(), now());
    rib.peer_up(e2.clone(), now());
    rib.update(
        e1.addr,
        &announce(&["192.0.2.0/24"], &attrs(&[65_001], "10.0.0.1")),
        now(),
    );
    let seen = seen.lock().unwrap().clone();
    // Import once, then export to each peer (§9.2 then keeps it from the
    // peer it came from before export policy is asked).
    assert_eq!(
        seen,
        vec![
            ("import", p("192.0.2.0/24"), RovState::Disabled),
            ("export", p("192.0.2.0/24"), RovState::Disabled),
        ]
    );
}
