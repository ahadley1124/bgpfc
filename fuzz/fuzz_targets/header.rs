//! Header::decode must never panic, and a header it accepts must re-encode
//! to the same octets.
#![no_main]

use bgpfc_wire::header::Header;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for extended in [false, true] {
        if let Ok(h) = Header::decode(data, extended) {
            let again = Header::encode(h.kind, h.body_len()).unwrap();
            assert_eq!(&again[..], &data[..19]);
        }
    }
});
