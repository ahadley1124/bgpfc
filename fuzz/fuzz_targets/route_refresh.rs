//! RouteRefreshMessage::decode must never panic, with the capability
//! negotiated or not (RFC 7313 §5), and what it decodes encodes back.
#![no_main]

use bgpfc_wire::route_refresh::RouteRefreshMessage;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for enhanced in [false, true] {
        if let Ok(m) = RouteRefreshMessage::decode(data, enhanced) {
            assert_eq!(m.encode(), data);
            assert_eq!(RouteRefreshMessage::decode(&m.encode(), enhanced).unwrap(), m);
        }
    }
});
