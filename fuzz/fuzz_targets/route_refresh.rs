//! RouteRefreshMessage::decode must never panic.
#![no_main]

use bgpfc_wire::route_refresh::RouteRefreshMessage;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = RouteRefreshMessage::decode(data) {
        assert_eq!(RouteRefreshMessage::decode(&m.encode()).unwrap(), m);
    }
});
