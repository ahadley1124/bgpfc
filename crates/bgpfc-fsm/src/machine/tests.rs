//! Table-driven coverage of every (state, event) pair in RFC 4271 §8.2.2
//! plus RFC 9687 event 29, with injected time (AGENTS.md §5).

use std::time::{Duration, Instant};

use bgpfc_wire::capability::{Capability, NextHopEncoding};
use bgpfc_wire::error::{CeaseSubcode, DecodeError, HeaderSubcode, OpenSubcode, UpdateSubcode};
use bgpfc_wire::notification::NotificationMessage;
use bgpfc_wire::open::OpenMessage;
use bgpfc_wire::types::{AddressFamily, Afi, Asn, HoldTime, RouterId};

use super::*;
use crate::{Damping, PeerKind};

const LOCAL_AS: Asn = Asn(65_000);
const PEER_AS: Asn = Asn(65_001);

fn rid(n: u32) -> RouterId {
    RouterId::new(n).unwrap()
}

fn hold(secs: u16) -> HoldTime {
    HoldTime::new(secs).unwrap()
}

fn config() -> Config {
    let mut c = Config::new(LOCAL_AS, rid(1), PEER_AS);
    c.capabilities = vec![
        Capability::Multiprotocol(AddressFamily::IPV4_UNICAST),
        Capability::Multiprotocol(AddressFamily::IPV6_UNICAST),
        Capability::RouteRefresh,
        Capability::ExtendedMessage,
    ];
    c
}

fn peer_open() -> OpenMessage {
    OpenMessage::new(
        PEER_AS,
        hold(30),
        rid(2),
        vec![
            Capability::Multiprotocol(AddressFamily::IPV4_UNICAST),
            Capability::RouteRefresh,
        ],
    )
}

fn cease() -> NotificationMessage {
    NotificationMessage::cease(CeaseSubcode::OtherConfigurationChange)
}

fn header_err() -> DecodeError {
    DecodeError::header(HeaderSubcode::BadMessageType, vec![9])
}

fn open_err() -> DecodeError {
    DecodeError::open(OpenSubcode::UnacceptableHoldTime, vec![])
}

fn update_err() -> DecodeError {
    DecodeError::update(UpdateSubcode::MalformedAttributeList, vec![])
}

/// Every event of RFC 4271 §8.1 and RFC 9687 §4.2, with representative
/// payloads, keyed by event number.
fn every_event() -> Vec<(u8, Event)> {
    vec![
        (1, Event::ManualStart),
        (2, Event::ManualStop),
        (3, Event::AutomaticStart),
        (4, Event::ManualStartPassive),
        (8, Event::AutomaticStop(cease())),
        (9, Event::ConnectRetryTimerExpires),
        (10, Event::HoldTimerExpires),
        (11, Event::KeepaliveTimerExpires),
        (12, Event::DelayOpenTimerExpires),
        (13, Event::IdleHoldTimerExpires),
        (14, Event::TcpConnectionValid),
        (15, Event::TcpCrInvalid),
        (16, Event::TcpCrAcked),
        (17, Event::TcpConnectionConfirmed),
        (18, Event::TcpConnectionFails),
        (19, Event::BgpOpen(peer_open())),
        (21, Event::BgpHeaderErr(header_err())),
        (22, Event::BgpOpenMsgErr(open_err())),
        (23, Event::OpenCollisionDump),
        (24, Event::NotifMsgVerErr),
        (25, Event::NotifMsg(cease())),
        (26, Event::KeepAliveMsg),
        (27, Event::UpdateMsg),
        (28, Event::UpdateMsgErr(update_err())),
        (29, Event::SendHoldTimerExpires),
        (0, Event::RouteRefreshMsg),
    ]
}

/// Compact rendering of actions for the tables.
fn tags(actions: &[Action]) -> Vec<String> {
    actions
        .iter()
        .map(|a| match a {
            Action::Connect => "connect".to_owned(),
            Action::DropConnection => "drop".to_owned(),
            Action::RejectConnection => "reject".to_owned(),
            Action::SendOpen(_) => "open".to_owned(),
            Action::SendKeepalive => "keepalive".to_owned(),
            Action::SendNotification(n) => format!("notif {}/{}", n.code.to_u8(), n.subcode),
            Action::SessionUp(_) => "up".to_owned(),
            Action::SessionDown => "down".to_owned(),
            Action::LogError(_) => "log".to_owned(),
            Action::RestartLimitReached { failures } => format!("limit {failures}"),
        })
        .collect()
}

fn t0() -> Instant {
    Instant::now()
}

/// An FSM driven to `state` along the normal path.
fn fsm_at(state: State, cfg: Config) -> (Fsm, Instant) {
    let now = t0();
    let mut f = Fsm::new(cfg);
    let steps: &[Event] = match state {
        State::Idle => &[],
        State::Connect => &[Event::ManualStart],
        State::Active => &[Event::ManualStartPassive],
        State::OpenSent => &[Event::ManualStart, Event::TcpCrAcked],
        State::OpenConfirm => &[
            Event::ManualStart,
            Event::TcpCrAcked,
            Event::BgpOpen(peer_open()),
        ],
        State::Established => &[
            Event::ManualStart,
            Event::TcpCrAcked,
            Event::BgpOpen(peer_open()),
            Event::KeepAliveMsg,
        ],
    };
    for e in steps {
        f.handle(e.clone(), now);
    }
    assert_eq!(f.state(), state);
    (f, now)
}

/// Run every event against a fresh FSM in `state` and compare with the
/// table; the table must mention every event.
fn check_table(state: State, table: &[(u8, State, &[&str])]) {
    for (n, event) in every_event() {
        let (expect_state, expect_tags) = table.iter().find(|(num, _, _)| *num == n).map_or_else(
            || panic!("{state}: event {n} missing from table"),
            |(_, s, t)| (*s, *t),
        );
        let (mut f, now) = fsm_at(state, config());
        let actions = f.handle(event.clone(), now);
        assert_eq!(f.state(), expect_state, "{state} + event {n} ({event:?})");
        assert_eq!(
            tags(&actions),
            expect_tags,
            "{state} + event {n} ({event:?})"
        );
    }
    assert_eq!(table.len(), every_event().len(), "{state}: table size");
}

#[test]
fn idle_state_table() {
    use State::{Connect, Idle};
    check_table(
        Idle,
        &[
            (1, Connect, &["connect"]),
            (2, Idle, &[]),
            (3, Connect, &["connect"]),
            (4, State::Active, &[]),
            (8, Idle, &[]),
            (9, Idle, &[]),
            (10, Idle, &[]),
            (11, Idle, &[]),
            (12, Idle, &[]),
            (13, Connect, &["connect"]),
            (14, Idle, &[]),
            (15, Idle, &[]),
            (16, Idle, &[]),
            (17, Idle, &[]),
            (18, Idle, &[]),
            (19, Idle, &[]),
            (21, Idle, &[]),
            (22, Idle, &[]),
            (23, Idle, &[]),
            (24, Idle, &[]),
            (25, Idle, &[]),
            (26, Idle, &[]),
            (27, Idle, &[]),
            (28, Idle, &[]),
            (29, Idle, &[]),
            (0, Idle, &[]),
        ],
    );
}

#[test]
fn connect_state_table() {
    use State::{Connect, Idle, OpenSent};
    check_table(
        Connect,
        &[
            (1, Connect, &[]),
            (2, Idle, &["drop"]),
            (3, Connect, &[]),
            (4, Connect, &[]),
            (8, Idle, &["drop"]),
            (9, Connect, &["drop", "connect"]),
            (10, Idle, &["drop"]),
            (11, Idle, &["drop"]),
            (12, OpenSent, &["open"]),
            (13, Idle, &["drop"]),
            (14, Connect, &[]),
            (15, Connect, &["reject"]),
            (16, OpenSent, &["open"]),
            (17, OpenSent, &["open"]),
            (18, Idle, &["drop"]),
            (19, Idle, &["drop"]),
            (21, Idle, &["drop"]),
            (22, Idle, &["drop"]),
            (23, Idle, &["drop"]),
            (24, Idle, &["drop"]),
            (25, Idle, &["drop"]),
            (26, Idle, &["drop"]),
            (27, Idle, &["drop"]),
            (28, Idle, &["drop"]),
            (29, Idle, &["drop"]),
            (0, Idle, &["drop"]),
        ],
    );
}

#[test]
fn active_state_table() {
    use State::{Active, Idle, OpenSent};
    // Reached via ManualStartPassive, so ConnectRetryTimer_Expires stays
    // passive (see the NOTE(interop) in the code); the RFC path is covered
    // by `active_retries_connect_when_not_passive`.
    check_table(
        Active,
        &[
            (1, Active, &[]),
            (2, Idle, &["drop"]),
            (3, Active, &[]),
            (4, Active, &[]),
            (8, Idle, &["drop"]),
            (9, Active, &[]),
            (10, Idle, &["drop"]),
            (11, Idle, &["drop"]),
            (12, OpenSent, &["open"]),
            (13, Idle, &["drop"]),
            (14, Active, &[]),
            (15, Active, &["reject"]),
            (16, OpenSent, &["open"]),
            (17, OpenSent, &["open"]),
            (18, Idle, &["drop"]),
            (19, Idle, &["drop"]),
            (21, Idle, &["drop"]),
            (22, Idle, &["drop"]),
            (23, Idle, &["drop"]),
            (24, Idle, &["drop"]),
            (25, Idle, &["drop"]),
            (26, Idle, &["drop"]),
            (27, Idle, &["drop"]),
            (28, Idle, &["drop"]),
            (29, Idle, &["drop"]),
            (0, Idle, &["drop"]),
        ],
    );
}

#[test]
fn open_sent_state_table() {
    use State::{Active, Idle, OpenConfirm, OpenSent};
    check_table(
        OpenSent,
        &[
            (1, OpenSent, &[]),
            (2, Idle, &["notif 6/2", "drop"]),
            (3, OpenSent, &[]),
            (4, OpenSent, &[]),
            (8, Idle, &["notif 6/6", "drop"]),
            (9, Idle, &["notif 5/0", "log", "drop"]),
            (10, Idle, &["notif 4/0", "drop"]),
            (11, Idle, &["notif 5/0", "log", "drop"]),
            (12, Idle, &["notif 5/0", "log", "drop"]),
            (13, Idle, &["notif 5/0", "log", "drop"]),
            (14, OpenSent, &[]),
            (15, OpenSent, &[]),
            (16, OpenSent, &[]),
            (17, OpenSent, &[]),
            (18, Active, &["drop"]),
            (19, OpenConfirm, &["keepalive"]),
            (21, Idle, &["notif 1/3", "drop"]),
            (22, Idle, &["notif 2/6", "drop"]),
            (23, Idle, &["notif 6/7", "drop"]),
            (24, Idle, &["drop"]),
            // NOTE(interop): no NOTIFICATION in reply to a NOTIFICATION.
            (25, Idle, &["drop"]),
            (26, Idle, &["notif 5/1", "log", "drop"]),
            (27, Idle, &["notif 5/1", "log", "drop"]),
            (28, Idle, &["notif 5/1", "log", "drop"]),
            (29, Idle, &["notif 5/0", "log", "drop"]),
            (0, Idle, &["notif 5/1", "log", "drop"]),
        ],
    );
}

#[test]
fn open_confirm_state_table() {
    use State::{Established, Idle, OpenConfirm};
    check_table(
        OpenConfirm,
        &[
            (1, OpenConfirm, &[]),
            (2, Idle, &["notif 6/2", "drop"]),
            (3, OpenConfirm, &[]),
            (4, OpenConfirm, &[]),
            (8, Idle, &["notif 6/6", "drop"]),
            (9, Idle, &["notif 5/0", "log", "drop"]),
            (10, Idle, &["notif 4/0", "drop"]),
            (11, OpenConfirm, &["keepalive"]),
            (12, Idle, &["notif 5/0", "log", "drop"]),
            (13, Idle, &["notif 5/0", "log", "drop"]),
            (14, OpenConfirm, &[]),
            (15, OpenConfirm, &[]),
            (16, OpenConfirm, &[]),
            (17, OpenConfirm, &[]),
            (18, Idle, &["drop"]),
            (19, OpenConfirm, &[]),
            (21, Idle, &["notif 1/3", "drop"]),
            (22, Idle, &["notif 2/6", "drop"]),
            (23, Idle, &["notif 6/7", "drop"]),
            (24, Idle, &["drop"]),
            (25, Idle, &["drop"]),
            (26, Established, &["up"]),
            (27, Idle, &["notif 5/2", "log", "drop"]),
            (28, Idle, &["notif 5/2", "log", "drop"]),
            (29, Idle, &["notif 5/0", "log", "drop"]),
            (0, Idle, &["notif 5/2", "log", "drop"]),
        ],
    );
}

#[test]
fn established_state_table() {
    use State::{Established, Idle};
    check_table(
        Established,
        &[
            (1, Established, &[]),
            (2, Idle, &["notif 6/2", "down", "drop"]),
            (3, Established, &[]),
            (4, Established, &[]),
            (8, Idle, &["notif 6/6", "down", "drop"]),
            (9, Idle, &["notif 5/0", "log", "down", "drop"]),
            (10, Idle, &["notif 4/0", "down", "drop"]),
            (11, Established, &["keepalive"]),
            (12, Idle, &["notif 5/0", "log", "down", "drop"]),
            (13, Idle, &["notif 5/0", "log", "down", "drop"]),
            (14, Established, &[]),
            (15, Established, &[]),
            (16, Established, &[]),
            (17, Established, &[]),
            (18, Idle, &["down", "drop"]),
            (19, Established, &[]),
            (21, Idle, &["notif 1/3", "down", "drop"]),
            (22, Idle, &["notif 5/3", "log", "down", "drop"]),
            (23, Established, &[]),
            (24, Idle, &["down", "drop"]),
            (25, Idle, &["down", "drop"]),
            (26, Established, &[]),
            (27, Established, &[]),
            (28, Idle, &["notif 3/1", "down", "drop"]),
            (29, Idle, &["notif 8/0", "log", "down", "drop"]),
            (0, Established, &[]),
        ],
    );
}

#[test]
fn fsm_error_data_names_the_unexpected_message() {
    // RFC 6608 §4: Data is the one-octet type of the unexpected message.
    let (mut f, now) = fsm_at(State::OpenSent, config());
    let a = f.handle(Event::UpdateMsg, now);
    let Action::SendNotification(n) = &a[0] else {
        panic!("{a:?}");
    };
    assert_eq!(n.data, vec![2]);
    let (mut f, now) = fsm_at(State::OpenConfirm, config());
    let a = f.handle(Event::UpdateMsgErr(update_err()), now);
    let Action::SendNotification(n) = &a[0] else {
        panic!("{a:?}");
    };
    assert_eq!((n.subcode, n.data.clone()), (2, vec![2]));
    let (mut f, now) = fsm_at(State::Established, config());
    let a = f.handle(Event::BgpOpenMsgErr(open_err()), now);
    let Action::SendNotification(n) = &a[0] else {
        panic!("{a:?}");
    };
    assert_eq!((n.subcode, n.data.clone()), (3, vec![1]));
    // ROUTE-REFRESH before Established: RFC 6608 §4 names it; type 5.
    let (mut f, now) = fsm_at(State::OpenSent, config());
    let a = f.handle(Event::RouteRefreshMsg, now);
    let Action::SendNotification(n) = &a[0] else {
        panic!("{a:?}");
    };
    assert_eq!((n.subcode, n.data.clone()), (1, vec![5]));
}

#[test]
fn open_negotiation() {
    let (mut f, now) = fsm_at(State::OpenSent, config());
    f.handle(Event::BgpOpen(peer_open()), now);
    let s = f.session().unwrap();
    assert_eq!(s.peer_as, PEER_AS);
    assert_eq!(s.peer_router_id, rid(2));
    assert_eq!(s.peer, PeerKind::External);
    // RFC 4271 §4.2: min(90, 30); §10: a third.
    assert_eq!(s.hold_time, hold(30));
    assert_eq!(s.keepalive_time, Duration::from_secs(10));
    // RFC 6793 §3: the peer advertised its four-octet capability (added by
    // OpenMessage::new).
    assert!(s.four_octet_as);
    // RFC 8654 §4: only we advertised Extended Message.
    assert!(!s.extended_messages);
    assert!(s.route_refresh);
    // RFC 4760 §8: only IPv4 unicast on both sides; we take IPv6 unicast
    // routes too, since we advertised it.
    assert_eq!(s.families, vec![AddressFamily::IPV4_UNICAST]);
    assert_eq!(
        s.receive_families,
        vec![AddressFamily::IPV4_UNICAST, AddressFamily::IPV6_UNICAST]
    );
    // RFC 8950 §4: neither side advertised Extended Next Hop Encoding.
    assert_eq!(s.extended_next_hop_receive, vec![]);
    assert_eq!(s.extended_next_hop_send, vec![]);
    // Timers: KeepaliveTimer and HoldTimer as negotiated.
    assert_eq!(
        f.timer(TimerKind::Keepalive).deadline(),
        Some(now + Duration::from_secs(10))
    );
    assert_eq!(
        f.timer(TimerKind::Hold).deadline(),
        Some(now + Duration::from_secs(30))
    );
    assert!(!f.timer(TimerKind::ConnectRetry).is_running());
    assert_eq!(
        f.expired(now + Duration::from_secs(10)),
        Some(TimerKind::Keepalive)
    );
    assert_eq!(f.next_deadline(), Some(now + Duration::from_secs(10)));
}

#[test]
fn internal_session_and_old_speaker() {
    let mut cfg = config();
    cfg.remote_as = LOCAL_AS;
    let (mut f, now) = fsm_at(State::OpenSent, cfg);
    // An OLD speaker: two-octet AS, no capabilities at all.
    let open = OpenMessage {
        my_as: 65_000,
        hold_time: hold(180),
        router_id: rid(3),
        capabilities: vec![],
    };
    f.handle(Event::BgpOpen(open), now);
    let s = f.session().unwrap();
    assert_eq!(s.peer, PeerKind::Internal);
    assert!(!s.four_octet_as);
    assert!(!s.route_refresh);
    assert_eq!(s.hold_time, hold(90));
    assert_eq!(s.families, vec![AddressFamily::IPV4_UNICAST]);
}

#[test]
fn routes_are_taken_for_every_family_we_advertised() {
    let v4 = AddressFamily::IPV4_UNICAST;
    let v6 = AddressFamily::IPV6_UNICAST;
    let session = |ours: &[AddressFamily], theirs: &[AddressFamily]| {
        let mut cfg = config();
        cfg.capabilities = ours.iter().map(|f| Capability::Multiprotocol(*f)).collect();
        let (mut f, now) = fsm_at(State::OpenSent, cfg);
        let caps = theirs
            .iter()
            .map(|f| Capability::Multiprotocol(*f))
            .collect();
        f.handle(
            Event::BgpOpen(OpenMessage::new(PEER_AS, hold(30), rid(2), caps)),
            now,
        );
        let s = f.session().unwrap();
        (s.families.clone(), s.receive_families.clone())
    };
    // RFC 4760 §8: both ways only where both sides advertised the family;
    // RFC 5492 §3: the peer may send what we advertised.
    assert_eq!(session(&[v4, v6], &[v4, v6]), (vec![v4, v6], vec![v4, v6]));
    assert_eq!(session(&[v4, v6], &[v6]), (vec![v6], vec![v4, v6]));
    assert_eq!(session(&[v6], &[v4, v6]), (vec![v6], vec![v6]));
    // No Multiprotocol capability means IPv4 unicast alone, on either side.
    assert_eq!(session(&[], &[]), (vec![v4], vec![v4]));
    assert_eq!(session(&[v4, v6], &[]), (vec![v4], vec![v4, v6]));
    assert_eq!(session(&[], &[v4, v6]), (vec![v4], vec![v4]));
}

fn enh(triples: &[NextHopEncoding]) -> Capability {
    Capability::ExtendedNextHop(triples.to_vec())
}

/// RFC 8950 §4 between `config()` with `ours` added and a peer advertising
/// `theirs`: (families taking an IPv6 next hop from the peer, families
/// sending one to it, families both ways).
fn negotiated_enh(
    ours: Vec<Capability>,
    theirs: Vec<Capability>,
) -> (Vec<AddressFamily>, Vec<AddressFamily>, Vec<AddressFamily>) {
    let mut cfg = config();
    cfg.capabilities.extend(ours);
    let (mut f, now) = fsm_at(State::OpenSent, cfg);
    f.handle(
        Event::BgpOpen(OpenMessage::new(PEER_AS, hold(30), rid(2), theirs)),
        now,
    );
    let s = f.session().unwrap();
    (
        s.extended_next_hop_receive.clone(),
        s.extended_next_hop_send.clone(),
        s.families.clone(),
    )
}

#[test]
fn extended_next_hop_is_taken_once_we_advertise_it_and_sent_once_both_do() {
    let v4_via_v6 = NextHopEncoding::IPV4_UNICAST_VIA_IPV6;
    let negotiated = negotiated_enh;
    let v4 = || vec![AddressFamily::IPV4_UNICAST];
    let mp = Capability::Multiprotocol;
    // RFC 8950 §4: both sides list <1, 1, 2>: IPv6 next hops both ways.
    assert_eq!(
        negotiated(
            vec![enh(&[v4_via_v6])],
            vec![mp(AddressFamily::IPV4_UNICAST), enh(&[v4_via_v6])]
        ),
        (v4(), v4(), v4())
    );
    // Only we list it: the peer may send us IPv6 next hops, since our
    // triple says we take them, but is sent none.
    assert_eq!(
        negotiated(
            vec![enh(&[v4_via_v6])],
            vec![mp(AddressFamily::IPV4_UNICAST)]
        ),
        (v4(), vec![], v4())
    );
    // Only the peer lists it: we did not ask for the extension, so it is
    // used neither way.
    assert_eq!(
        negotiated(
            vec![],
            vec![mp(AddressFamily::IPV4_UNICAST), enh(&[v4_via_v6])]
        ),
        (vec![], vec![], v4())
    );
    // Other triples do not stand in for <1, 1, 2>: VPN-IPv4 (§6.2), an
    // IPv4 next hop, a SAFI that does not fit one octet.
    let others = [
        NextHopEncoding {
            nlri_safi: 128,
            ..v4_via_v6
        },
        NextHopEncoding {
            next_hop_afi: Afi::Ipv4,
            ..v4_via_v6
        },
        NextHopEncoding {
            nlri_safi: 0x0101,
            ..v4_via_v6
        },
    ];
    assert_eq!(
        negotiated(
            vec![enh(&[v4_via_v6])],
            vec![mp(AddressFamily::IPV4_UNICAST), enh(&others)]
        ),
        (v4(), vec![], v4())
    );
    assert_eq!(
        negotiated(
            vec![enh(&others)],
            vec![mp(AddressFamily::IPV4_UNICAST), enh(&[v4_via_v6])]
        ),
        (vec![], vec![], v4())
    );
    // RFC 5492 §4: the triple may come in a second instance.
    assert_eq!(
        negotiated(
            vec![enh(&[v4_via_v6])],
            vec![
                mp(AddressFamily::IPV4_UNICAST),
                enh(&others),
                enh(&[v4_via_v6])
            ]
        ),
        (v4(), v4(), v4())
    );
    // A peer without any Multiprotocol capability speaks IPv4 unicast
    // implicitly (RFC 4760 §8), so the triple applies.
    assert_eq!(
        negotiated(vec![enh(&[v4_via_v6])], vec![enh(&[v4_via_v6])]),
        (v4(), v4(), v4())
    );
}

#[test]
fn extended_next_hop_follows_the_ipv4_unicast_family() {
    let v4_via_v6 = NextHopEncoding::IPV4_UNICAST_VIA_IPV6;
    let negotiated = negotiated_enh;
    let v4 = || vec![AddressFamily::IPV4_UNICAST];
    let mp = Capability::Multiprotocol;
    // RFC 8950 §4: the capability does not make IPv4 unicast usable; only
    // the Multiprotocol capability does (RFC 4760 §8). We advertised IPv4
    // unicast, so the peer may still send it to us, with IPv6 next hops.
    assert_eq!(
        negotiated(
            vec![enh(&[v4_via_v6])],
            vec![mp(AddressFamily::IPV6_UNICAST), enh(&[v4_via_v6])]
        ),
        (v4(), vec![], vec![AddressFamily::IPV6_UNICAST])
    );
    // Nor when we did not advertise IPv4 unicast.
    let mut cfg = config();
    cfg.capabilities = vec![mp(AddressFamily::IPV6_UNICAST), enh(&[v4_via_v6])];
    let (mut f, now) = fsm_at(State::OpenSent, cfg);
    let theirs = vec![
        mp(AddressFamily::IPV4_UNICAST),
        mp(AddressFamily::IPV6_UNICAST),
        enh(&[v4_via_v6]),
    ];
    f.handle(
        Event::BgpOpen(OpenMessage::new(PEER_AS, hold(30), rid(2), theirs)),
        now,
    );
    let s = f.session().unwrap();
    assert_eq!(
        (&s.extended_next_hop_receive, &s.extended_next_hop_send),
        (&vec![], &vec![])
    );
}

#[test]
fn bad_peer_as_and_unsupported_capability() {
    // RFC 4271 §6.2: Bad Peer AS.
    let (mut f, now) = fsm_at(State::OpenSent, config());
    let wrong = OpenMessage::new(Asn(65_002), hold(90), rid(2), vec![]);
    let a = f.handle(Event::BgpOpen(wrong), now);
    assert_eq!(tags(&a), ["notif 2/2", "drop"]);
    assert_eq!(f.state(), State::Idle);
    assert_eq!(f.connect_retry_counter(), 1);
    // RFC 5492 §5: no family in common → Unsupported Capability listing
    // our Multiprotocol capabilities.
    let mut cfg = config();
    cfg.capabilities = vec![Capability::Multiprotocol(AddressFamily::IPV6_UNICAST)];
    let (mut f, now) = fsm_at(State::OpenSent, cfg);
    let a = f.handle(Event::BgpOpen(peer_open()), now);
    assert_eq!(tags(&a), ["notif 2/7", "drop"]);
    let Action::SendNotification(n) = &a[0] else {
        panic!()
    };
    assert_eq!(n.data, vec![1, 4, 0, 2, 0, 1]);
}

#[test]
fn hold_time_zero_disables_timers() {
    let (mut f, now) = fsm_at(State::OpenSent, config());
    let open = OpenMessage::new(PEER_AS, HoldTime::ZERO, rid(2), vec![]);
    f.handle(Event::BgpOpen(open), now);
    assert!(!f.timer(TimerKind::Hold).is_running());
    assert!(!f.timer(TimerKind::Keepalive).is_running());
    f.handle(Event::KeepAliveMsg, now);
    assert_eq!(f.state(), State::Established);
    // RFC 9687 §4.3: no SendHoldTimer when the negotiated Hold Time is zero.
    assert!(!f.timer(TimerKind::SendHold).is_running());
    f.handle(Event::UpdateMsg, now);
    assert!(!f.timer(TimerKind::Hold).is_running());
    assert_eq!(f.next_deadline(), None);
}

#[test]
fn established_timers_and_send_hold() {
    let (mut f, now) = fsm_at(State::Established, config());
    // RFC 9687 §6: max(8 min, 2 × 30 s) = 8 min.
    assert_eq!(
        f.timer(TimerKind::SendHold).deadline(),
        Some(now + Duration::from_secs(480))
    );
    assert_eq!(
        f.timer(TimerKind::Hold).deadline(),
        Some(now + Duration::from_secs(30))
    );
    // KEEPALIVE / UPDATE restart the HoldTimer.
    let later = now + Duration::from_secs(20);
    f.handle(Event::UpdateMsg, later);
    assert_eq!(
        f.timer(TimerKind::Hold).deadline(),
        Some(later + Duration::from_secs(30))
    );
    // Sending restarts KeepaliveTimer and SendHoldTimer.
    f.message_sent(later);
    assert_eq!(
        f.timer(TimerKind::Keepalive).deadline(),
        Some(later + Duration::from_secs(10))
    );
    assert_eq!(
        f.timer(TimerKind::SendHold).deadline(),
        Some(later + Duration::from_secs(480))
    );
    // Our own KEEPALIVE counts as a sent message.
    let t2 = later + Duration::from_secs(10);
    assert_eq!(f.expired(t2), Some(TimerKind::Keepalive));
    f.handle(Event::KeepaliveTimerExpires, t2);
    assert_eq!(
        f.timer(TimerKind::SendHold).deadline(),
        Some(t2 + Duration::from_secs(480))
    );
    // The next KEEPALIVE is due first; then the HoldTimer, long before the
    // SendHoldTimer.
    let t3 = later + Duration::from_secs(30);
    assert_eq!(
        f.expired(later + Duration::from_secs(20)),
        Some(TimerKind::Keepalive)
    );
    f.handle(
        Event::KeepaliveTimerExpires,
        later + Duration::from_secs(20),
    );
    assert_eq!(f.expired(t3), Some(TimerKind::Hold));
    let a = f.handle(Event::HoldTimerExpires, t3);
    assert_eq!(tags(&a), ["notif 4/0", "down", "drop"]);
    assert!(!f.timer(TimerKind::SendHold).is_running());
}

#[test]
fn send_hold_time_configuration() {
    let mut cfg = config();
    cfg.send_hold_time = SendHoldTime::Fixed(Duration::from_secs(100));
    let (f, now) = fsm_at(State::Established, cfg.clone());
    assert_eq!(
        f.timer(TimerKind::SendHold).deadline(),
        Some(now + Duration::from_secs(100))
    );
    // RFC 9687 §4.4: a value not above the Hold Time falls back.
    cfg.send_hold_time = SendHoldTime::Fixed(Duration::from_secs(30));
    let (f, now) = fsm_at(State::Established, cfg.clone());
    assert_eq!(
        f.timer(TimerKind::SendHold).deadline(),
        Some(now + Duration::from_secs(480))
    );
    cfg.send_hold_time = SendHoldTime::Disabled;
    let (mut f, now) = fsm_at(State::Established, cfg);
    assert!(!f.timer(TimerKind::SendHold).is_running());
    f.message_sent(now);
    assert!(!f.timer(TimerKind::SendHold).is_running());
}

#[test]
fn delay_open() {
    let mut cfg = config();
    cfg.delay_open = Some(Duration::from_secs(5));
    let (mut f, now) = fsm_at(State::Connect, cfg.clone());
    // RFC 4271 §8.2.2 Connect, event 16 with DelayOpen: wait.
    let a = f.handle(Event::TcpCrAcked, now);
    assert_eq!(a, vec![]);
    assert_eq!(f.state(), State::Connect);
    assert!(!f.timer(TimerKind::ConnectRetry).is_running());
    assert_eq!(
        f.timer(TimerKind::DelayOpen).deadline(),
        Some(now + Duration::from_secs(5))
    );
    // Event 12: send OPEN.
    let a = f.handle(Event::DelayOpenTimerExpires, now + Duration::from_secs(5));
    assert_eq!(tags(&a), ["open"]);
    assert_eq!(f.state(), State::OpenSent);
    // Event 20: the peer's OPEN first → OPEN + KEEPALIVE, OpenConfirm.
    let (mut f, now) = fsm_at(State::Connect, cfg.clone());
    f.handle(Event::TcpCrAcked, now);
    let a = f.handle(Event::BgpOpen(peer_open()), now);
    assert_eq!(tags(&a), ["open", "keepalive"]);
    assert_eq!(f.state(), State::OpenConfirm);
    assert!(f.session().is_some());
    // TcpConnectionFails with the DelayOpenTimer running → Active.
    let (mut f, now) = fsm_at(State::Connect, cfg.clone());
    f.handle(Event::TcpCrAcked, now);
    let a = f.handle(Event::TcpConnectionFails, now);
    assert_eq!(a, vec![]);
    assert_eq!(f.state(), State::Active);
    assert!(f.timer(TimerKind::ConnectRetry).is_running());
    assert!(!f.timer(TimerKind::DelayOpen).is_running());
    // NotifMsgVerErr with the timer running: Idle without a counter bump.
    let (mut f, now) = fsm_at(State::Connect, cfg);
    f.handle(Event::TcpCrAcked, now);
    f.handle(Event::NotifMsgVerErr, now);
    assert_eq!(f.state(), State::Idle);
    assert_eq!(f.connect_retry_counter(), 0);
}

#[test]
fn active_retries_connect_when_not_passive() {
    // RFC 4271 §8.2.2 Active: ConnectRetryTimer_Expires → Connect.
    let mut cfg = config();
    cfg.delay_open = Some(Duration::from_secs(5));
    let (mut f, now) = fsm_at(State::Connect, cfg);
    f.handle(Event::TcpCrAcked, now);
    f.handle(Event::TcpConnectionFails, now);
    assert_eq!(f.state(), State::Active);
    let a = f.handle(Event::ConnectRetryTimerExpires, now);
    assert_eq!(tags(&a), ["connect"]);
    assert_eq!(f.state(), State::Connect);
    // A passive peer never connects.
    let mut cfg = config();
    cfg.passive = true;
    let (mut f, now) = fsm_at(State::Idle, cfg);
    let a = f.handle(Event::ManualStart, now);
    assert_eq!(a, vec![]);
    assert_eq!(f.state(), State::Active);
    let a = f.handle(Event::ConnectRetryTimerExpires, now);
    assert_eq!(a, vec![]);
    assert_eq!(f.state(), State::Active);
}

#[test]
fn send_notification_without_open() {
    let mut cfg = config();
    cfg.send_notification_without_open = true;
    cfg.delay_open = Some(Duration::from_secs(5));
    let (mut f, now) = fsm_at(State::Connect, cfg.clone());
    let a = f.handle(Event::BgpHeaderErr(header_err()), now);
    assert_eq!(tags(&a), ["notif 1/3", "drop"]);
    // Active + ManualStop with the DelayOpenTimer running: Cease.
    let (mut f, now) = fsm_at(State::Active, cfg);
    f.handle(Event::TcpConnectionConfirmed, now);
    assert!(f.timer(TimerKind::DelayOpen).is_running());
    let a = f.handle(Event::ManualStop, now);
    assert_eq!(tags(&a), ["notif 6/2", "drop"]);
}

#[test]
fn collision_dump_in_established_needs_the_option() {
    let (mut f, now) = fsm_at(State::Established, config());
    assert_eq!(f.handle(Event::OpenCollisionDump, now), vec![]);
    assert_eq!(f.state(), State::Established);
    let mut cfg = config();
    cfg.collision_detect_established = true;
    let (mut f, now) = fsm_at(State::Established, cfg);
    let a = f.handle(Event::OpenCollisionDump, now);
    assert_eq!(tags(&a), ["notif 6/7", "down", "drop"]);
    assert_eq!(f.state(), State::Idle);
}

#[test]
fn damping_doubles_the_idle_hold_and_a_session_resets_it() {
    let cfg = config();
    let mut f = Fsm::new(cfg);
    let mut now = t0();
    let mut expected = [10u64, 20, 40, 80, 120, 120];
    for wait in &mut expected {
        f.handle(Event::IdleHoldTimerExpires, now);
        assert_eq!(f.state(), State::Connect);
        f.handle(Event::TcpCrAcked, now);
        // A failure that damps.
        f.handle(Event::HoldTimerExpires, now);
        assert_eq!(f.state(), State::Idle);
        let deadline = f.timer(TimerKind::IdleHold).deadline().unwrap();
        assert_eq!(deadline - now, Duration::from_secs(*wait));
        now = deadline;
    }
    // RFC 4271 §8.2.2 Idle: every start zeroes the counter, so only the
    // last failure is counted.
    assert_eq!(f.connect_retry_counter(), 1);
    assert_eq!(f.damped_failures(), 6);
    // Establish once and stay up for `forget_after`: damping resets.
    f.handle(Event::IdleHoldTimerExpires, now);
    f.handle(Event::TcpCrAcked, now);
    f.handle(Event::BgpOpen(peer_open()), now);
    f.handle(Event::KeepAliveMsg, now);
    assert_eq!(f.state(), State::Established);
    now += Damping::default().forget_after;
    f.handle(Event::TcpConnectionFails, now);
    assert_eq!(f.damped_failures(), 0);
    assert_eq!(
        f.timer(TimerKind::IdleHold).deadline(),
        Some(now + Duration::from_secs(10))
    );
    // A failure without damping keeps the current hold.
    f.handle(Event::IdleHoldTimerExpires, now);
    f.handle(Event::TcpConnectionFails, now);
    assert_eq!(
        f.timer(TimerKind::IdleHold).deadline(),
        Some(now + Duration::from_secs(10))
    );
    // Without a damping config the restart waits ConnectRetryTime.
    let mut cfg = config();
    cfg.damping = None;
    let (mut f, now) = fsm_at(State::OpenSent, cfg);
    f.handle(Event::HoldTimerExpires, now);
    assert_eq!(
        f.timer(TimerKind::IdleHold).deadline(),
        Some(now + Duration::from_secs(120))
    );
}

#[test]
fn manual_stop_holds_the_peer_down_until_manual_start() {
    let (mut f, now) = fsm_at(State::Established, config());
    f.handle(Event::ManualStop, now);
    assert_eq!(f.state(), State::Idle);
    assert!(f.is_admin_down());
    assert_eq!(f.connect_retry_counter(), 0);
    assert!(!f.timer(TimerKind::IdleHold).is_running());
    assert_eq!(f.handle(Event::AutomaticStart, now), vec![]);
    assert_eq!(f.handle(Event::IdleHoldTimerExpires, now), vec![]);
    assert_eq!(f.state(), State::Idle);
    let a = f.handle(Event::ManualStart, now);
    assert_eq!(tags(&a), ["connect"]);
    assert!(!f.is_admin_down());
    // ManualStop in Idle cancels a pending restart.
    let (mut f, now) = fsm_at(State::OpenSent, config());
    f.handle(Event::TcpConnectionFails, now);
    f.handle(Event::NotifMsgVerErr, now);
    assert!(f.timer(TimerKind::IdleHold).is_running());
    f.handle(Event::ManualStop, now);
    assert!(!f.timer(TimerKind::IdleHold).is_running());
}

#[test]
fn connect_retry_timer_in_connect_and_open_sent() {
    let (mut f, now) = fsm_at(State::Connect, config());
    assert_eq!(
        f.timer(TimerKind::ConnectRetry).deadline(),
        Some(now + Duration::from_secs(120))
    );
    let later = now + Duration::from_secs(120);
    assert_eq!(f.expired(later), Some(TimerKind::ConnectRetry));
    f.handle(Event::ConnectRetryTimerExpires, later);
    assert_eq!(
        f.timer(TimerKind::ConnectRetry).deadline(),
        Some(later + Duration::from_secs(120))
    );
    // Connected: ConnectRetryTimer stops, HoldTimer at the large value.
    f.handle(Event::TcpConnectionConfirmed, later);
    assert!(!f.timer(TimerKind::ConnectRetry).is_running());
    assert_eq!(
        f.timer(TimerKind::Hold).deadline(),
        Some(later + Duration::from_secs(240))
    );
    // OpenSent + TcpConnectionFails: Active with the timer restarted.
    f.handle(Event::TcpConnectionFails, later);
    assert_eq!(f.state(), State::Active);
    assert!(f.timer(TimerKind::ConnectRetry).is_running());
    assert!(!f.timer(TimerKind::Hold).is_running());
}

#[test]
fn jitter_shortens_timers_within_bounds() {
    let mut cfg = config();
    cfg.jitter_seed = 42;
    let (f, now) = fsm_at(State::Connect, cfg);
    let d = f.timer(TimerKind::ConnectRetry).deadline().unwrap() - now;
    assert!(
        d >= Duration::from_secs(90) && d <= Duration::from_secs(120),
        "{d:?}"
    );
}

#[test]
fn open_message_we_send() {
    let (mut f, now) = fsm_at(State::Connect, config());
    let a = f.handle(Event::TcpCrAcked, now);
    let Action::SendOpen(open) = &a[0] else {
        panic!("{a:?}");
    };
    assert_eq!(open.asn(), LOCAL_AS);
    assert_eq!(open.hold_time, hold(90));
    assert_eq!(open.router_id, rid(1));
    assert!(open.has(&Capability::FourOctetAs(LOCAL_AS)));
    assert!(open.has(&Capability::ExtendedMessage));
}

#[test]
fn event_numbers_and_timer_events() {
    let nums: Vec<u8> = every_event().iter().map(|(_, e)| e.number()).collect();
    let expected: Vec<u8> = every_event().iter().map(|(n, _)| *n).collect();
    assert_eq!(nums, expected);
    assert_eq!(TimerKind::SendHold.event(), Event::SendHoldTimerExpires);
    assert_eq!(TimerKind::Hold.event().number(), 10);
    assert_eq!(State::OpenConfirm.to_string(), "OpenConfirm");
    assert_eq!(
        crate::remaining(t0() + Duration::from_secs(1), t0() + Duration::from_secs(5)),
        Duration::ZERO
    );
}

#[test]
fn damping_default_values() {
    assert_eq!(Damping::default().initial, Duration::from_secs(10));
    assert_eq!(Damping::default().max, Duration::from_secs(120));
    assert_eq!(Damping::default().restart_limit, Some(10));
    assert_eq!(Damping::default().forget_after, Duration::from_secs(300));
}

/// A configuration whose damping allows `limit` automatic restarts.
fn limited(limit: Option<u32>) -> Config {
    let mut cfg = config();
    cfg.damping = Some(Damping {
        restart_limit: limit,
        ..Damping::default()
    });
    cfg
}

/// One step of a scripted run: the event, the seconds since the start at
/// which it happens, the state after it, the actions it returns, and the
/// `IdleHoldTimer` it leaves (seconds after the event, or none).
type Step = (Event, u64, State, &'static [&'static str], Option<u64>);

fn run_steps(mut f: Fsm, start: Instant, steps: &[Step]) -> Fsm {
    for (i, (event, at, state, expect, idle_hold)) in steps.iter().enumerate() {
        let now = start + Duration::from_secs(*at);
        let actions = f.handle(event.clone(), now);
        assert_eq!(f.state(), *state, "step {i} ({event:?})");
        assert_eq!(tags(&actions), *expect, "step {i} ({event:?})");
        assert_eq!(
            f.timer(TimerKind::IdleHold)
                .deadline()
                .map(|d| (d - now).as_secs()),
            *idle_hold,
            "step {i} ({event:?}): IdleHoldTimer"
        );
    }
    f
}

#[test]
fn restart_limit_leaves_the_peer_idle_until_a_manual_start() {
    use Event::{
        AutomaticStart, HoldTimerExpires, IdleHoldTimerExpires, ManualStart,
        TcpConnectionConfirmed, TcpCrAcked,
    };
    use State::{Connect, Idle, OpenSent};
    // RFC 4486 §4: two automatic restarts, then the third damped failure
    // in a row leaves the peer Idle until a ManualStart.
    let start = t0();
    let f = run_steps(
        Fsm::new(limited(Some(2))),
        start,
        &[
            (ManualStart, 0, Connect, &["connect"], None),
            (TcpCrAcked, 1, OpenSent, &["open"], None),
            (HoldTimerExpires, 2, Idle, &["notif 4/0", "drop"], Some(10)),
            (IdleHoldTimerExpires, 12, Connect, &["connect"], None),
            (TcpCrAcked, 13, OpenSent, &["open"], None),
            (HoldTimerExpires, 14, Idle, &["notif 4/0", "drop"], Some(20)),
            (IdleHoldTimerExpires, 34, Connect, &["connect"], None),
            (TcpCrAcked, 35, OpenSent, &["open"], None),
            (
                HoldTimerExpires,
                36,
                Idle,
                &["notif 4/0", "drop", "limit 3"],
                None,
            ),
            // AllowAutomaticStart is FALSE: nothing starts the peer, and
            // Idle keeps refusing connections.
            (AutomaticStart, 1000, Idle, &[], None),
            (IdleHoldTimerExpires, 1001, Idle, &[], None),
            (TcpConnectionConfirmed, 1002, Idle, &[], None),
        ],
    );
    assert!(!f.automatic_start_allowed());
    assert!(!f.is_admin_down());
    assert_eq!(f.damped_failures(), 3);
    assert_eq!(f.next_deadline(), None);
    // The administrative intervention: a ManualStart starts a new run.
    let f = run_steps(
        f,
        start,
        &[
            (ManualStart, 2000, Connect, &["connect"], None),
            (TcpCrAcked, 2001, OpenSent, &["open"], None),
            (
                HoldTimerExpires,
                2002,
                Idle,
                &["notif 4/0", "drop"],
                Some(10),
            ),
        ],
    );
    assert!(f.automatic_start_allowed());
    assert_eq!(f.damped_failures(), 1);
}

#[test]
fn restart_limit_counts_short_sessions_and_forgets_stable_ones() {
    use Event::{AutomaticStop, BgpOpen, IdleHoldTimerExpires, KeepAliveMsg, TcpCrAcked};
    use State::{Connect, Established, Idle, OpenConfirm, OpenSent};
    // A peer torn down by a prefix limit right after it sends its table
    // reaches Established every time; that must not end the run, or the
    // oscillation would never be damped or bounded (RFC 4486 §4).
    let stop = || {
        AutomaticStop(NotificationMessage::max_prefixes_reached(
            AddressFamily::IPV4_UNICAST,
            100,
        ))
    };
    let (f, start) = fsm_at(State::Established, limited(Some(2)));
    let f = run_steps(
        f,
        start,
        &[
            (stop(), 1, Idle, &["notif 6/1", "down", "drop"], Some(10)),
            (IdleHoldTimerExpires, 11, Connect, &["connect"], None),
            (TcpCrAcked, 11, OpenSent, &["open"], None),
            (BgpOpen(peer_open()), 11, OpenConfirm, &["keepalive"], None),
            (KeepAliveMsg, 11, Established, &["up"], None),
            (stop(), 12, Idle, &["notif 6/1", "down", "drop"], Some(20)),
            (IdleHoldTimerExpires, 32, Connect, &["connect"], None),
            (TcpCrAcked, 32, OpenSent, &["open"], None),
            (BgpOpen(peer_open()), 32, OpenConfirm, &["keepalive"], None),
            (KeepAliveMsg, 32, Established, &["up"], None),
            (
                stop(),
                33,
                Idle,
                &["notif 6/1", "down", "drop", "limit 3"],
                None,
            ),
        ],
    );
    assert!(!f.automatic_start_allowed());
    // A session that stayed up for `forget_after` ends the run first:
    // whatever brings it down counts as the first failure of a new one.
    let (f, start) = fsm_at(State::Established, limited(Some(2)));
    let f = run_steps(
        f,
        start,
        &[
            (stop(), 1, Idle, &["notif 6/1", "down", "drop"], Some(10)),
            (IdleHoldTimerExpires, 11, Connect, &["connect"], None),
            (TcpCrAcked, 11, OpenSent, &["open"], None),
            (BgpOpen(peer_open()), 11, OpenConfirm, &["keepalive"], None),
            (KeepAliveMsg, 11, Established, &["up"], None),
            (stop(), 311, Idle, &["notif 6/1", "down", "drop"], Some(10)),
        ],
    );
    assert_eq!(f.damped_failures(), 1);
    assert!(f.automatic_start_allowed());
}

#[test]
fn restart_limit_zero_never_restarts_and_none_always_does() {
    // `Some(0)`: no automatic restart after any damped failure.
    let (mut f, now) = fsm_at(State::OpenSent, limited(Some(0)));
    let a = f.handle(Event::HoldTimerExpires, now);
    assert_eq!(tags(&a), ["notif 4/0", "drop", "limit 1"]);
    assert!(!f.timer(TimerKind::IdleHold).is_running());
    // A failure that does not damp is not bounded: a peer that refuses
    // connections is retried for as long as it takes.
    let (mut f, mut now) = fsm_at(State::Connect, limited(Some(0)));
    for _ in 0..20 {
        let a = f.handle(Event::TcpConnectionFails, now);
        assert_eq!(tags(&a), ["drop"]);
        now = f.timer(TimerKind::IdleHold).deadline().unwrap();
        f.handle(Event::IdleHoldTimerExpires, now);
        assert_eq!(f.state(), State::Connect);
    }
    assert_eq!(f.damped_failures(), 0);
    // `None`: unbounded, the hold stays at the cap.
    let (mut f, mut now) = fsm_at(State::OpenSent, limited(None));
    for _ in 0..50 {
        let a = f.handle(Event::HoldTimerExpires, now);
        assert_eq!(tags(&a), ["notif 4/0", "drop"]);
        now = f.timer(TimerKind::IdleHold).deadline().unwrap();
        f.handle(Event::IdleHoldTimerExpires, now);
        f.handle(Event::TcpCrAcked, now);
    }
    assert_eq!(f.damped_failures(), 50);
    assert!(f.automatic_start_allowed());
    // ManualStop wins over the bound: the peer stays down, no limit action.
    let (mut f, now) = fsm_at(State::OpenSent, limited(Some(0)));
    let a = f.handle(Event::ManualStop, now);
    assert_eq!(tags(&a), ["notif 6/2", "drop"]);
    assert_eq!(f.damped_failures(), 0);
}

#[test]
fn received_ceases_damp_as_rfc4486_recommends() {
    // RFC 4486 §4: damp after Administrative Shutdown, Peer De-configured,
    // Connection Rejected and Out of Resources; RFC 4271 §8.2.2 names no
    // damping for any other NOTIFICATION received while Established.
    for subcode in 0..=9u8 {
        let (mut f, now) = fsm_at(State::Established, config());
        let n = NotificationMessage {
            code: bgpfc_wire::error::ErrorCode::Cease,
            subcode,
            data: Vec::new(),
        };
        let a = f.handle(Event::NotifMsg(n), now);
        assert_eq!(tags(&a), ["down", "drop"]);
        let damped = matches!(subcode, 2 | 3 | 5 | 8);
        assert_eq!(f.damped_failures(), u32::from(damped), "subcode {subcode}");
        // The first damped failure waits the initial hold; the next one
        // waits twice as long.
        assert_eq!(
            f.timer(TimerKind::IdleHold).deadline(),
            Some(now + Duration::from_secs(10))
        );
        let later = now + Duration::from_secs(10);
        f.handle(Event::IdleHoldTimerExpires, later);
        f.handle(Event::TcpCrAcked, later);
        f.handle(Event::HoldTimerExpires, later);
        let expected = if damped { 20 } else { 10 };
        assert_eq!(
            f.timer(TimerKind::IdleHold).deadline(),
            Some(later + Duration::from_secs(expected)),
            "subcode {subcode}"
        );
    }
    // Any other NOTIFICATION while Established does not damp either.
    let (mut f, now) = fsm_at(State::Established, config());
    f.handle(
        Event::NotifMsg(NotificationMessage::hold_timer_expired()),
        now,
    );
    assert_eq!(f.damped_failures(), 0);
}
