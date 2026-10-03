//! The attribute-level decoders must never panic: AS_PATH, communities,
//! MP_REACH/UNREACH, prefixes and capabilities on arbitrary bytes.
#![no_main]

use bgpfc_wire::as_path::AsPath;
use bgpfc_wire::capability::Capability;
use bgpfc_wire::community::{
    decode_communities, decode_extended_communities, decode_large_communities,
};
use bgpfc_wire::mp::{MpReach, MpUnreach};
use bgpfc_wire::prefix::decode_prefixes;
use bgpfc_wire::reader::Reader;
use bgpfc_wire::types::Afi;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for four in [false, true] {
        if let Ok(p) = AsPath::decode(data, four) {
            let mut again = Vec::new();
            p.encode(four, &mut again).unwrap();
            assert_eq!(again, data);
            let _ = p.hop_count();
            let _ = p.to_string();
        }
    }
    let _ = decode_communities(data);
    let _ = decode_extended_communities(data);
    let _ = decode_large_communities(data);
    for afi in [Afi::Ipv4, Afi::Ipv6] {
        if let Ok(ps) = decode_prefixes(data, afi) {
            let mut again = Vec::new();
            bgpfc_wire::prefix::encode_prefixes(&ps, &mut again);
            // Trailing bits are zeroed on decode, so only the length matches.
            assert_eq!(again.len(), data.len());
        }
    }
    if let Ok(m) = MpReach::decode(data) {
        let mut again = Vec::new();
        m.encode(&mut again);
        assert_eq!(MpReach::decode(&again).unwrap(), m);
    }
    if let Ok(m) = MpUnreach::decode(data) {
        let mut again = Vec::new();
        m.encode(&mut again);
        assert_eq!(MpUnreach::decode(&again).unwrap(), m);
    }
    let mut r = Reader::new(data);
    while !r.is_empty() {
        let Ok(c) = Capability::decode(&mut r) else {
            break;
        };
        let mut again = Vec::new();
        c.encode(&mut again).unwrap();
        assert_eq!(Capability::decode(&mut Reader::new(&again)).unwrap(), c);
    }
});
