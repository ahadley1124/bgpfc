//! NotificationMessage::decode must never panic, nor may the accessors that
//! interpret the Data field.
#![no_main]

use bgpfc_wire::notification::NotificationMessage;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = NotificationMessage::decode(data) {
        let _ = m.shutdown_communication();
        let _ = m.max_prefixes();
        let _ = m.is_recognised();
        // RFC 8538 §3.1: the NOTIFICATION a Hard Reset carries.
        if let Some(inner) = m.hard_reset_inner() {
            assert!(m.is_hard_reset());
            assert_eq!(NotificationMessage::hard_reset(&inner).hard_reset_inner(), Some(inner));
        }
        let _ = m.to_string();
        let wire = m.encode(true).unwrap();
        assert_eq!(NotificationMessage::decode(&wire).unwrap(), m);
    }
});
