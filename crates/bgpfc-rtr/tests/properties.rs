//! Property tests for the RTR codec and framer (AGENTS.md §5, as for
//! every decoder of untrusted input):
//!
//! - `decode(encode(x)) == x` for every PDU of both versions;
//! - `encode(decode(b)) == b` for canonical input, i.e. octets the encoder
//!   produced, and a stable re-encoding of the same length for anything
//!   else that decodes;
//! - no panic on arbitrary, truncated or corrupted input;
//! - the framer hands out the same PDUs, and stops at the same error,
//!   however the stream is cut into chunks.
//!
//! Not run under Miri: proptest's case counts would take hours, and the
//! unit tests cover the same code paths there.
#![cfg(not(miri))]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bgpfc_rpki::Vrp;
use bgpfc_rtr::{
    ErrorCode, ErrorReport, Framer, Intervals, MAX_PDU_LEN, Pdu, RouterKey, RtrError, Version,
};
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::Asn;
use proptest::collection::vec;
use proptest::prelude::*;

// ---------------------------------------------------------------- strategies

fn version() -> impl Strategy<Value = Version> {
    prop_oneof![Just(Version::V0), Just(Version::V1)]
}

/// Any VRP: any address and ASN, any Prefix Length, and a Max Length from
/// the Prefix Length to the address size (RFC 8210 §5.1, §5.6, §5.7).
fn vrp() -> impl Strategy<Value = Vrp> {
    let v4 = (any::<u32>(), 0u8..=32).prop_flat_map(|(a, len)| {
        let prefix = Prefix::new(IpAddr::V4(Ipv4Addr::from(a)), len).unwrap();
        (Just(prefix), len..=32)
    });
    let v6 = (any::<u128>(), 0u8..=128).prop_flat_map(|(a, len)| {
        let prefix = Prefix::new(IpAddr::V6(Ipv6Addr::from(a)), len).unwrap();
        (Just(prefix), len..=128)
    });
    (prop_oneof![v4, v6], any::<u32>())
        .prop_map(|((prefix, max_len), asn)| Vrp::new(prefix, max_len, Asn(asn)).unwrap())
}

/// Any intervals: decoding does not hold the cache to RFC 8210 §6.
fn intervals() -> impl Strategy<Value = Intervals> {
    (any::<u32>(), any::<u32>(), any::<u32>()).prop_map(|(refresh, retry, expire)| Intervals {
        refresh,
        retry,
        expire,
    })
}

fn router_key() -> impl Strategy<Value = RouterKey> {
    (
        any::<bool>(),
        any::<[u8; 20]>(),
        any::<u32>(),
        vec(any::<u8>(), 0..200),
    )
        .prop_map(|(announce, ski, asn, key)| RouterKey::new(announce, ski, Asn(asn), key).unwrap())
}

/// An Error Report of `version` with any code, encapsulated octets and
/// text, including codes outside the registry.
fn error_report(version: Version) -> impl Strategy<Value = ErrorReport> {
    (any::<u16>(), vec(any::<u8>(), 0..64), ".{0,40}").prop_map(move |(code, pdu, text)| {
        ErrorReport::new(version, ErrorCode::from_u16(code), &pdu, &text)
    })
}

/// Any PDU of `version`. Router Keys exist in version 1 only, and End of
/// Data carries intervals exactly in version 1.
fn pdu_of(version: Version) -> BoxedStrategy<Pdu> {
    let common = prop_oneof![
        1 => (any::<u16>(), any::<u32>()).prop_map(move |(session_id, serial)| {
            Pdu::SerialNotify {
                version,
                session_id,
                serial,
            }
        }),
        1 => (any::<u16>(), any::<u32>()).prop_map(move |(session_id, serial)| {
            Pdu::SerialQuery {
                version,
                session_id,
                serial,
            }
        }),
        1 => Just(Pdu::ResetQuery { version }),
        1 => any::<u16>().prop_map(move |session_id| Pdu::CacheResponse {
            version,
            session_id
        }),
        4 => (any::<bool>(), vrp()).prop_map(move |(announce, vrp)| Pdu::Prefix {
            version,
            announce,
            vrp,
        }),
        1 => Just(Pdu::CacheReset { version }),
        1 => error_report(version).prop_map(Pdu::ErrorReport),
    ];
    match version {
        Version::V0 => prop_oneof![
            6 => common,
            1 => (any::<u16>(), any::<u32>()).prop_map(|(session_id, serial)| Pdu::EndOfData {
                session_id,
                serial,
                intervals: None,
            }),
        ]
        .boxed(),
        Version::V1 => prop_oneof![
            6 => common,
            1 => (any::<u16>(), any::<u32>(), intervals()).prop_map(
                |(session_id, serial, intervals)| Pdu::EndOfData {
                    session_id,
                    serial,
                    intervals: Some(intervals),
                }
            ),
            1 => router_key().prop_map(Pdu::RouterKey),
        ]
        .boxed(),
    }
}

fn pdu() -> impl Strategy<Value = Pdu> {
    version().prop_flat_map(pdu_of)
}

/// Octets that look like a PDU: mostly version 0 or 1, a type from 0 to
/// 11, any header field, a body of any octets, often as long as some PDU
/// type's body, and a Length that is mostly right but sometimes random.
fn pdu_like() -> impl Strategy<Value = Vec<u8>> {
    // The body lengths of the fixed-size PDUs: Serial Notify and Query,
    // End of Data in version 0 (4); IPv4 Prefix (12); End of Data in
    // version 1 (16); IPv6 Prefix (24).
    let body_len = prop_oneof![
        Just(0usize),
        Just(4),
        Just(12),
        Just(16),
        Just(24),
        0usize..160
    ];
    (
        prop_oneof![4 => 0u8..2, 1 => 2u8..=u8::MAX],
        0u8..12,
        any::<u16>(),
        body_len.prop_flat_map(|n| vec(any::<u8>(), n)),
        prop::option::weighted(0.2, any::<u32>()),
    )
        .prop_map(|(version, pdu_type, field, body, length)| {
            let length = length.unwrap_or(u32::try_from(8 + body.len()).unwrap());
            let mut b = vec![version, pdu_type];
            b.extend(field.to_be_bytes());
            b.extend(length.to_be_bytes());
            b.extend(body);
            b
        })
}

/// A stream of encoded PDUs, perhaps with one octet changed.
fn stream() -> impl Strategy<Value = Vec<u8>> {
    (
        vec(pdu(), 0..12),
        prop::option::of((any::<prop::sample::Index>(), any::<u8>())),
    )
        .prop_map(|(pdus, change)| {
            let mut s = Vec::new();
            for p in &pdus {
                p.encode_into(&mut s);
            }
            if let Some((at, octet)) = change
                && !s.is_empty()
            {
                let at = at.index(s.len());
                s[at] = octet;
            }
            s
        })
}

// ---------------------------------------------------------------- helpers

/// What decoding a PDU must keep: whatever decodes re-encodes to as many
/// octets, and that encoding decodes to the same PDU.
fn assert_stable(pdu: &Pdu, octets: &[u8]) {
    let again = pdu.encode();
    assert_eq!(again.len(), octets.len());
    assert_eq!(Pdu::decode(&again).as_ref(), Ok(pdu));
}

/// What a framer hands out for `stream` fed in chunks of the sizes in
/// `cuts`, used in turn: the PDUs, then the error that stopped it, with
/// the octets of the PDU in error.
fn frame_all(
    stream: &[u8],
    cuts: &[usize],
    version: Option<Version>,
) -> (Vec<Pdu>, Option<(RtrError, Vec<u8>)>) {
    let mut framer = Framer::new();
    if let Some(v) = version {
        framer.set_version(v);
    }
    let mut pdus = Vec::new();
    let mut rest = stream;
    let mut cuts = cuts.iter().copied().cycle();
    while !rest.is_empty() {
        let n = cuts.next().unwrap_or(rest.len()).clamp(1, rest.len());
        let (chunk, tail) = rest.split_at(n);
        rest = tail;
        framer.feed(chunk);
        loop {
            match framer.next_pdu() {
                Ok(Some(pdu)) => pdus.push(pdu),
                Ok(None) => break,
                Err(error) => {
                    assert_eq!(framer.error(), Some(&error));
                    return (pdus, Some((error, framer.erroneous_pdu().to_vec())));
                }
            }
        }
        // Drained, the framer holds less than one PDU.
        assert!(framer.buffered() < usize::try_from(MAX_PDU_LEN).unwrap());
    }
    (pdus, None)
}

// ---------------------------------------------------------------- properties

proptest! {
    #[test]
    fn decode_encode_round_trip(pdu in pdu()) {
        let b = pdu.encode();
        // RFC 8210 §5.1: the Length is the whole PDU.
        let length = u32::try_from(b.len()).unwrap().to_be_bytes();
        prop_assert_eq!(b.get(4..8), Some(&length[..]));
        prop_assert!(b.len() <= usize::try_from(MAX_PDU_LEN).unwrap());
        prop_assert_eq!(b.first(), Some(&pdu.version().to_u8()));
        prop_assert_eq!(b.get(1), Some(&pdu.pdu_type().to_u8()));
        prop_assert_eq!(Pdu::decode(&b), Ok(pdu.clone()));
        prop_assert_eq!(Pdu::decode_negotiated(&b, pdu.version()), Ok(pdu.clone()));
        // Canonical octets come back unchanged.
        prop_assert_eq!(Pdu::decode(&b).unwrap().encode(), b);
    }

    #[test]
    fn other_versions_are_unexpected(pdu in pdu()) {
        let other = match pdu.version() {
            Version::V0 => Version::V1,
            Version::V1 => Version::V0,
        };
        let e = Pdu::decode_negotiated(&pdu.encode(), other).unwrap_err();
        prop_assert_eq!(e.code(), ErrorCode::UnexpectedProtocolVersion);
    }

    #[test]
    fn truncation_is_corrupt_data(pdu in pdu(), cut in any::<prop::sample::Index>()) {
        let b = pdu.encode();
        let cut = cut.index(b.len());
        let e = Pdu::decode(&b[..cut]).unwrap_err();
        prop_assert_eq!(e.code(), ErrorCode::CorruptData, "{:?}", e);
    }

    #[test]
    fn trailing_octets_are_corrupt_data(pdu in pdu(), extra in vec(any::<u8>(), 1..8)) {
        let mut b = pdu.encode();
        b.extend(extra);
        let e = Pdu::decode(&b).unwrap_err();
        prop_assert_eq!(e.code(), ErrorCode::CorruptData, "{:?}", e);
    }

    #[test]
    fn corrupted_pdus_never_panic(
        pdu in pdu(),
        at in any::<prop::sample::Index>(),
        octet in any::<u8>(),
    ) {
        let mut b = pdu.encode();
        let at = at.index(b.len());
        b[at] = octet;
        let decoded = [
            Pdu::decode(&b),
            Pdu::decode_negotiated(&b, Version::V0),
            Pdu::decode_negotiated(&b, Version::V1),
        ];
        for p in decoded.into_iter().flatten() {
            assert_stable(&p, &b);
        }
    }

    #[test]
    fn pdu_like_octets_never_panic(b in pdu_like()) {
        match Pdu::decode(&b) {
            Ok(p) => assert_stable(&p, &b),
            // Every error names a registered code.
            Err(e) => prop_assert!(!matches!(e.code(), ErrorCode::Unknown(_))),
        }
    }

    #[test]
    fn arbitrary_octets_never_panic(b in vec(any::<u8>(), 0..64)) {
        if let Ok(p) = Pdu::decode(&b) {
            assert_stable(&p, &b);
        }
    }

    #[test]
    fn framer_returns_every_pdu_however_cut(
        pdus in vec(pdu(), 0..16),
        cuts in vec(1usize..80, 1..20),
    ) {
        let mut s = Vec::new();
        for p in &pdus {
            p.encode_into(&mut s);
        }
        prop_assert_eq!(frame_all(&s, &cuts, None), (pdus, None));
    }

    #[test]
    fn framer_keeps_to_the_negotiated_version(
        version in version(),
        pdus in version().prop_flat_map(|v| vec(pdu_of(v), 0..12)),
        cuts in vec(1usize..80, 1..20),
    ) {
        let mut s = Vec::new();
        for p in &pdus {
            p.encode_into(&mut s);
        }
        let (got, error) = frame_all(&s, &cuts, Some(version));
        match pdus.first() {
            Some(first) if first.version() != version => {
                prop_assert!(got.is_empty());
                let (e, octets) = error.unwrap();
                prop_assert_eq!(e.code(), ErrorCode::UnexpectedProtocolVersion);
                prop_assert_eq!(&octets[..], &first.encode()[..8]);
            }
            _ => prop_assert_eq!((got, error), (pdus, None)),
        }
    }

    #[test]
    fn framing_does_not_depend_on_chunking(
        s in stream(),
        cuts in vec(1usize..80, 1..20),
        version in prop::option::of(version()),
    ) {
        let whole = frame_all(&s, &[s.len()], version);
        prop_assert_eq!(frame_all(&s, &cuts, version), whole.clone());
        prop_assert_eq!(frame_all(&s, &[1], version), whole.clone());
        // What the framer accepts is what decoding each PDU alone accepts.
        for p in &whole.0 {
            assert_stable(p, &p.encode());
        }
    }

    #[test]
    fn framer_never_panics_on_pdu_like_streams(
        parts in vec(pdu_like(), 0..6),
        cuts in vec(1usize..80, 1..20),
    ) {
        let s = parts.concat();
        let whole = frame_all(&s, &[s.len()], None);
        prop_assert_eq!(frame_all(&s, &cuts, None), whole);
    }
}
