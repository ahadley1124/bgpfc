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
        let _ = m.to_string();
        let wire = m.encode(true).unwrap();
        assert_eq!(NotificationMessage::decode(&wire).unwrap(), m);
    }
});
