//! UpdateMessage::decode must never panic under any session context, and a
//! message it accepts without treat-as-withdraw must encode and decode back
//! to itself. The contexts alternate RFC 8950 extended next hop on and off,
//! and some have RFC 7911 ADD-PATH on for IPv4 unicast, IPv6 unicast or
//! both.
#![no_main]

use bgpfc_wire::types::AddressFamily;
use bgpfc_wire::update::{AddPathFamilies, DecodeContext, EncodeContext, PeerKind, UpdateMessage};
use libfuzzer_sys::fuzz_target;

const PLAIN: [DecodeContext; 4] = [
    DecodeContext {
        four_octet_as: true,
        peer: PeerKind::Internal,
        allow_as_set: true,
        extended_next_hop: true,
        add_path: bgpfc_wire::update::AddPathFamilies::NONE,
    },
    DecodeContext {
        four_octet_as: false,
        peer: PeerKind::Internal,
        allow_as_set: true,
        extended_next_hop: false,
        add_path: bgpfc_wire::update::AddPathFamilies::NONE,
    },
    DecodeContext {
        four_octet_as: true,
        peer: PeerKind::External,
        allow_as_set: false,
        extended_next_hop: false,
        add_path: bgpfc_wire::update::AddPathFamilies::NONE,
    },
    DecodeContext {
        four_octet_as: false,
        peer: PeerKind::External,
        allow_as_set: false,
        extended_next_hop: true,
        add_path: bgpfc_wire::update::AddPathFamilies::NONE,
    },
];

/// The four contexts above, and each again with ADD-PATH for IPv4 unicast,
/// IPv6 unicast and both.
fn contexts() -> Vec<DecodeContext> {
    let mut all = PLAIN.to_vec();
    for families in [
        &[AddressFamily::IPV4_UNICAST][..],
        &[AddressFamily::IPV6_UNICAST][..],
        &[AddressFamily::IPV4_UNICAST, AddressFamily::IPV6_UNICAST][..],
    ] {
        let add_path = AddPathFamilies::of(families);
        all.extend(PLAIN.iter().map(|c| DecodeContext { add_path, ..*c }));
    }
    all
}

fuzz_target!(|data: &[u8]| {
    for ctx in contexts() {
        let Ok(d) = UpdateMessage::decode(data, &ctx) else {
            continue;
        };
        let _ = d.withdrawals().count();
        let _ = d.withdrawn_paths().count();
        let _ = d.announcements().count();
        if d.treated_as_withdraw.is_some() || !d.discarded.is_empty() {
            continue;
        }
        let enc = EncodeContext {
            four_octet_as: ctx.four_octet_as,
            extended_next_hop: ctx.extended_next_hop,
            add_path: ctx.add_path,
        };
        // A decoded message may hold attributes that the encoder cannot
        // write back (an unknown attribute over 65535 octets cannot occur,
        // but AS_PATH segments of one AS can): encode errors are not bugs.
        let Ok(wire) = d.message.encode(&enc) else {
            continue;
        };
        let again = UpdateMessage::decode(&wire, &ctx).unwrap();
        assert_eq!(again.message, d.message);
    }
});
