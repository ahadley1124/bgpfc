//! UpdateMessage::decode must never panic under any session context, and a
//! message it accepts without treat-as-withdraw must encode and decode back
//! to itself.
#![no_main]

use bgpfc_wire::update::{DecodeContext, EncodeContext, PeerKind, UpdateMessage};
use libfuzzer_sys::fuzz_target;

const CONTEXTS: [DecodeContext; 4] = [
    DecodeContext {
        four_octet_as: true,
        peer: PeerKind::Internal,
        allow_as_set: true,
    },
    DecodeContext {
        four_octet_as: false,
        peer: PeerKind::Internal,
        allow_as_set: true,
    },
    DecodeContext {
        four_octet_as: true,
        peer: PeerKind::External,
        allow_as_set: false,
    },
    DecodeContext {
        four_octet_as: false,
        peer: PeerKind::External,
        allow_as_set: false,
    },
];

fuzz_target!(|data: &[u8]| {
    for ctx in CONTEXTS {
        let Ok(d) = UpdateMessage::decode(data, &ctx) else {
            continue;
        };
        let _ = d.withdrawals().count();
        let _ = d.announcements().count();
        if d.treated_as_withdraw.is_some() || !d.discarded.is_empty() {
            continue;
        }
        let enc = EncodeContext {
            four_octet_as: ctx.four_octet_as,
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
