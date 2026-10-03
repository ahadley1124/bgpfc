//! OpenMessage::decode must never panic; what it accepts must survive an
//! encode/decode round trip unchanged.
#![no_main]

use bgpfc_wire::open::OpenMessage;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = OpenMessage::decode(data) {
        let wire = m.encode().unwrap();
        assert_eq!(OpenMessage::decode(&wire).unwrap(), m);
        let wire = m.encode_with(true).unwrap();
        assert_eq!(OpenMessage::decode(&wire).unwrap(), m);
    }
});
