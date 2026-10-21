//! What an RPKI cache sends must never make the RTR decoder or framer
//! panic. A PDU either accepts must re-encode to as many octets and decode
//! back to itself, and the framer must hand out the same PDUs, and stop at
//! the same error, however the stream is cut.
//!
//! The first octet steers the framer: its low six bits give the chunk
//! size, its top two bits the negotiated version (none, 0 or 1). The rest
//! is the stream. The whole input is also decoded as one PDU.
#![no_main]

use bgpfc_rtr::{Framer, MAX_PDU_LEN, Pdu, RtrError, Version};
use libfuzzer_sys::fuzz_target;

/// Whatever decodes re-encodes to as many octets and decodes back.
fn check(pdu: &Pdu, octets: &[u8]) {
    let again = pdu.encode();
    assert_eq!(again.len(), octets.len());
    assert_eq!(Pdu::decode(&again).as_ref(), Ok(pdu));
}

/// Feed `stream` to a framer `chunk` octets at a time, draining it after
/// each: the PDUs it hands out, then the error that stopped it with the
/// octets of the PDU in error.
fn frame(
    stream: &[u8],
    chunk: usize,
    version: Option<Version>,
) -> (Vec<Pdu>, Option<(RtrError, Vec<u8>)>) {
    let mut framer = Framer::new();
    if let Some(v) = version {
        framer.set_version(v);
    }
    let mut pdus = Vec::new();
    for piece in stream.chunks(chunk) {
        framer.feed(piece);
        loop {
            match framer.next_pdu() {
                Ok(Some(pdu)) => pdus.push(pdu),
                Ok(None) => break,
                Err(error) => {
                    let _ = (error.code(), error.may_report(), error.to_string());
                    return (pdus, Some((error, framer.erroneous_pdu().to_vec())));
                }
            }
        }
        assert!(framer.buffered() < MAX_PDU_LEN as usize);
    }
    (pdus, None)
}

fuzz_target!(|data: &[u8]| {
    for decoded in [
        Pdu::decode(data),
        Pdu::decode_negotiated(data, Version::V0),
        Pdu::decode_negotiated(data, Version::V1),
    ] {
        if let Ok(pdu) = decoded {
            check(&pdu, data);
        }
    }

    let Some((&control, stream)) = data.split_first() else {
        return;
    };
    let chunk = usize::from(control & 0x3f) + 1;
    let version = match control >> 6 {
        1 => Some(Version::V0),
        2 => Some(Version::V1),
        _ => None,
    };
    let whole = frame(stream, stream.len().max(1), version);
    assert_eq!(frame(stream, chunk, version), whole);
    for pdu in &whole.0 {
        check(pdu, &pdu.encode());
    }
});
