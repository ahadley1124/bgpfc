//! RouteRefreshMessage::decode must never panic, with the capability
//! negotiated or not and room for the echo of any size (RFC 7313 §5), and
//! what it decodes encodes back.
#![no_main]

use bgpfc_wire::notification::max_data_len;
use bgpfc_wire::route_refresh::RouteRefreshMessage;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for echo in [None, Some(max_data_len(false)), Some(max_data_len(true)), Some(0)] {
        if let Ok(m) = RouteRefreshMessage::decode(data, echo) {
            assert_eq!(m.encode(), data);
            assert_eq!(RouteRefreshMessage::decode(&m.encode(), echo).unwrap(), m);
        }
    }
});
