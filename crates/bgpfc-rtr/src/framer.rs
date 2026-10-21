//! Cutting the byte stream from a cache into PDUs.
//!
//! RTR runs over a persistent byte stream (RFC 8210 §9), and the only
//! framing is the Length field in each PDU's header (§5.1). [`Framer`]
//! collects octets as they arrive and hands out each PDU once all of it is
//! there. It checks each header as soon as its 8 octets are in, so a
//! Length the PDU's type does not allow is an error at once, not a wait
//! for octets that may never come, and no PDU longer than
//! [`MAX_PDU_LEN`](crate::pdu::MAX_PDU_LEN) is ever buffered.
//!
//! Implements: RFC 8210 §5.1 (the Length field), §7 (Serial Notify during
//! negotiation; the version once negotiated), §5.11 (the Erroneous PDU of
//! a PDU with a corrupt length), §12 (the errors are fatal).

use bgpfc_wire::reader::Reader;

use crate::error::RtrError;
use crate::pdu::{HEADER_LEN, Header, MAX_PDU_USIZE, Pdu, PduType, Version, decode_pdu};

/// Cuts a byte stream from a cache into PDUs.
///
/// Give it the octets the transport delivers with [`Framer::feed`], then
/// call [`Framer::next_pdu`] (or [`Framer::next_frame`]) until it returns
/// `Ok(None)`. Once drained, it holds less than one PDU, so reading the
/// socket into a fixed-size buffer and draining after every read keeps
/// the framer under [`MAX_PDU_LEN`](crate::pdu::MAX_PDU_LEN) octets plus
/// that buffer, whatever the cache sends.
///
/// The first error is final, since every error it reports is fatal
/// (RFC 8210 §12) and after a bad header the stream cannot be framed
/// again: later calls return the same error, and octets fed after it are
/// dropped. [`Framer::erroneous_pdu`] then gives the octets for the Error
/// Report.
#[derive(Clone, Debug, Default)]
pub struct Framer {
    /// Octets received; those before `start` have been handed out.
    buf: Vec<u8>,
    /// Index in `buf` of the first octet not yet handed out. Never more
    /// than `buf.len()`.
    start: usize,
    /// The version negotiated for the session, once it is known.
    version: Option<Version>,
    /// The first error, with the octets of the PDU in error.
    failed: Option<(RtrError, Vec<u8>)>,
}

impl Framer {
    /// A framer for a new transport session, whose version is not
    /// negotiated yet: PDUs of version 0 and 1 are both accepted.
    #[must_use]
    pub fn new() -> Framer {
        Framer::default()
    }

    /// The version negotiated for the session, if it has been set.
    #[must_use]
    pub const fn version(&self) -> Option<Version> {
        self.version
    }

    /// Record the version negotiated for the session (RFC 8210 §7). From
    /// now on, including for PDUs already fed but not yet handed out, a
    /// PDU of any other version is Unexpected Protocol Version (§12 code
    /// 8).
    pub fn set_version(&mut self, version: Version) {
        self.version = Some(version);
    }

    /// Append octets received from the cache. They are dropped once the
    /// framer has failed.
    pub fn feed(&mut self, octets: &[u8]) {
        if self.failed.is_some() {
            return;
        }
        // Let go of what has been handed out, so that the buffer holds at
        // most the incomplete PDU and `octets`.
        self.buf.drain(..self.start);
        self.start = 0;
        self.buf.extend_from_slice(octets);
    }

    /// Octets fed but not yet handed out.
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.start
    }

    /// The next PDU, decoded. `Ok(None)` if not all of it has arrived.
    ///
    /// # Errors
    /// As [`Framer::next_frame`], and the errors of
    /// [`Pdu::decode_negotiated`] (or [`Pdu::decode`] before the version
    /// is set) for the PDU it frames.
    pub fn next_pdu(&mut self) -> Result<Option<Pdu>, RtrError> {
        let version = self.version;
        let Some(frame) = self.next_frame()? else {
            return Ok(None);
        };
        match decode_pdu(frame, version) {
            Ok(pdu) => Ok(Some(pdu)),
            Err(error) => {
                let octets = frame.to_vec();
                self.fail(error.clone(), octets);
                Err(error)
            }
        }
    }

    /// The octets of the next PDU, its header checked but its body not
    /// decoded. `Ok(None)` if not all of it has arrived.
    ///
    /// # Errors
    /// The error in the PDU's header, as [`Pdu::decode_negotiated`] (or
    /// [`Pdu::decode`] before the version is set) reports it: an
    /// unexpected or unsupported version, an unsupported type, or a
    /// Length the type does not allow, which includes every Length beyond
    /// [`MAX_PDU_LEN`](crate::pdu::MAX_PDU_LEN). Or the error that stopped
    /// the framer earlier.
    pub fn next_frame(&mut self) -> Result<Option<&[u8]>, RtrError> {
        let Some(length) = self.next_length()? else {
            return Ok(None);
        };
        let pending = self.buf.get(self.start..).unwrap_or_default();
        // next_length saw all `length` octets, so this cannot run short.
        let Ok(frame) = Reader::new(pending).take(length) else {
            return Ok(None);
        };
        self.start += length;
        Ok(Some(frame))
    }

    /// The Length of the next PDU once all of it has arrived, its header
    /// checked, after skipping any Serial Notify that RFC 8210 §7 says to
    /// ignore.
    fn next_length(&mut self) -> Result<Option<usize>, RtrError> {
        if let Some((error, _)) = &self.failed {
            return Err(error.clone());
        }
        loop {
            let pending = self.buf.get(self.start..).unwrap_or_default();
            let Some(header) = Header::read(&mut Reader::new(pending)) else {
                return Ok(None);
            };
            let length = usize::try_from(header.length).unwrap_or(usize::MAX);
            let skip = match header.check(self.version) {
                // Header::check bounded the Length by MAX_PDU_LEN.
                Ok(_) => false,
                // RFC 8210 §7: "The router MUST ignore any Serial Notify
                // PDUs it might receive from the cache during this initial
                // startup period, regardless of the Protocol Version
                // field". One of a version this code does not know cannot
                // be decoded, so it is skipped here, framed by its Length,
                // which must still be one a PDU can have.
                // NOTE(interop): BIRD skips these too.
                Err(RtrError::UnsupportedVersion { pdu_type, .. })
                    if pdu_type == PduType::SerialNotify.to_u8()
                        && (HEADER_LEN..=MAX_PDU_USIZE).contains(&length) =>
                {
                    true
                }
                Err(error) => {
                    // RFC 8210 §5.11: "If the error is associated with a
                    // PDU of ... a possibly corrupt length, the Erroneous
                    // PDU field MAY be truncated." A header that fails its
                    // checks leaves its Length untrustworthy, so only the
                    // header is kept.
                    let octets = pending.get(..HEADER_LEN).unwrap_or_default().to_vec();
                    self.fail(error.clone(), octets);
                    return Err(error);
                }
            };
            if pending.len() < length {
                return Ok(None);
            }
            if !skip {
                return Ok(Some(length));
            }
            self.start += length;
        }
    }

    /// The error that stopped the framer, if one has.
    #[must_use]
    pub fn error(&self) -> Option<&RtrError> {
        self.failed.as_ref().map(|(error, _)| error)
    }

    /// The octets of the PDU in error, for the Erroneous PDU field of the
    /// Error Report (RFC 8210 §5.11): the whole PDU if its header passed
    /// and its body did not, only its 8-octet header if the header failed.
    /// Empty while there is no error.
    #[must_use]
    pub fn erroneous_pdu(&self) -> &[u8] {
        self.failed.as_ref().map_or(&[], |(_, octets)| octets)
    }

    /// Stop the framer: keep the error and the octets in error, and let
    /// the rest go, since nothing after a fatal error is read.
    fn fail(&mut self, error: RtrError, octets: Vec<u8>) {
        self.failed = Some((error, octets));
        self.buf = Vec::new();
        self.start = 0;
    }
}

#[cfg(test)]
mod tests {
    use bgpfc_rpki::Vrp;
    use bgpfc_wire::types::Asn;

    use super::*;
    use crate::error::ErrorCode;
    use crate::pdu::{ErrorReport, Intervals, MAX_PDU_LEN, RouterKey};

    fn vrp(prefix: &str, max_len: u8, asn: u32) -> Vrp {
        Vrp::new(prefix.parse().unwrap(), max_len, Asn(asn)).unwrap()
    }

    /// A session's worth of version 1 PDUs, of every size there is.
    fn pdus() -> Vec<Pdu> {
        let v = Version::V1;
        vec![
            Pdu::CacheResponse {
                version: v,
                session_id: 7,
            },
            Pdu::Prefix {
                version: v,
                announce: true,
                vrp: vrp("192.0.2.0/24", 24, 64_496),
            },
            Pdu::Prefix {
                version: v,
                announce: false,
                vrp: vrp("2001:db8::/32", 48, 64_497),
            },
            Pdu::RouterKey(RouterKey::new(true, [3; 20], Asn(64_496), vec![0x30; 91]).unwrap()),
            Pdu::EndOfData {
                session_id: 7,
                serial: 1,
                intervals: Some(Intervals::DEFAULT),
            },
            Pdu::SerialNotify {
                version: v,
                session_id: 7,
                serial: 2,
            },
            Pdu::ErrorReport(ErrorReport::new(
                v,
                ErrorCode::NoDataAvailable,
                &[],
                "no data",
            )),
        ]
    }

    fn stream(pdus: &[Pdu]) -> Vec<u8> {
        let mut out = Vec::new();
        for pdu in pdus {
            pdu.encode_into(&mut out);
        }
        out
    }

    /// Feed `chunks` one at a time, draining the framer after each, and
    /// check the buffer bound as it goes.
    fn run<'a>(
        framer: &mut Framer,
        chunks: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Vec<Pdu>, RtrError> {
        let mut out = Vec::new();
        for chunk in chunks {
            framer.feed(chunk);
            assert!(framer.buf.len() < MAX_PDU_USIZE + chunk.len());
            while let Some(pdu) = framer.next_pdu()? {
                out.push(pdu);
            }
            assert!(framer.buffered() < MAX_PDU_USIZE);
        }
        Ok(out)
    }

    #[test]
    fn one_feed_yields_every_pdu() {
        let mut f = Framer::new();
        assert_eq!(run(&mut f, [stream(&pdus()).as_slice()]), Ok(pdus()));
        assert_eq!(f.buffered(), 0);
        assert_eq!(f.next_pdu(), Ok(None));
        assert_eq!(f.error(), None);
        assert_eq!(f.erroneous_pdu(), b"");
    }

    #[test]
    fn every_split_point() {
        let s = stream(&pdus());
        for at in 0..=s.len() {
            let (a, b) = s.split_at(at);
            let mut f = Framer::new();
            assert_eq!(run(&mut f, [a, b]), Ok(pdus()), "split at {at}");
            assert_eq!(f.buffered(), 0);
        }
    }

    #[test]
    fn one_octet_at_a_time() {
        let s = stream(&pdus());
        let mut f = Framer::new();
        assert_eq!(run(&mut f, s.chunks(1)), Ok(pdus()));
    }

    #[test]
    fn uneven_chunks() {
        let s = stream(&pdus());
        for seed in 1..=20u32 {
            // xorshift32, for chunk sizes of 1 to 40 octets.
            let mut x = seed;
            let mut chunks = Vec::new();
            let mut rest = s.as_slice();
            while !rest.is_empty() {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                let n = usize::try_from(x % 40 + 1).unwrap().min(rest.len());
                let (chunk, tail) = rest.split_at(n);
                chunks.push(chunk);
                rest = tail;
            }
            let mut f = Framer::new();
            assert_eq!(run(&mut f, chunks), Ok(pdus()), "seed {seed}");
        }
    }

    #[test]
    fn frames_are_the_pdu_octets() {
        let s = stream(&pdus());
        let mut f = Framer::new();
        f.feed(&s);
        let mut frames = Vec::new();
        while let Some(frame) = f.next_frame().unwrap() {
            frames.push(frame.to_vec());
        }
        let expected: Vec<Vec<u8>> = pdus().iter().map(Pdu::encode).collect();
        assert_eq!(frames, expected);
    }

    #[test]
    fn waits_for_the_rest() {
        let s = stream(&pdus());
        let mut f = Framer::new();
        f.feed(&[]);
        assert_eq!(f.next_frame(), Ok(None));
        // Part of a header, then all but the last octet of the first PDU.
        f.feed(&s[..5]);
        assert_eq!(f.next_frame(), Ok(None));
        f.feed(&s[5..7]);
        assert_eq!(f.next_pdu(), Ok(None));
        assert_eq!(f.buffered(), 7);
        f.feed(&s[7..8]);
        assert_eq!(f.next_pdu(), Ok(Some(pdus()[0].clone())));
        assert_eq!(f.buffered(), 0);
    }

    /// Feed `header` and check that it fails at once with `error`, keeping
    /// only the header as the erroneous PDU, and stays failed.
    fn fails_at_header(mut f: Framer, header: [u8; 8], error: &RtrError) {
        f.feed(&header);
        assert_eq!(f.next_pdu().as_ref(), Err(error));
        assert_eq!(f.erroneous_pdu(), header);
        assert_eq!(f.error(), Some(error));
        assert_eq!(f.buffered(), 0);
        // Final: more octets are dropped and the error repeats.
        f.feed(&stream(&pdus()));
        assert_eq!(f.buffered(), 0);
        assert_eq!(f.next_frame().as_ref(), Err(error));
        assert_eq!(f.next_pdu().as_ref(), Err(error));
        assert_eq!(f.erroneous_pdu(), header);
    }

    #[test]
    fn oversize_pdus_fail_before_buffering() {
        // An Error Report may be long, but not beyond MAX_PDU_LEN: the
        // framer refuses after 8 octets instead of buffering 4 GiB.
        for length in [MAX_PDU_LEN + 1, u32::MAX] {
            let mut header = [1, 10, 0, 0, 0, 0, 0, 0];
            header[4..].copy_from_slice(&length.to_be_bytes());
            let error = RtrError::TooLong {
                pdu_type: 10,
                length,
                max: MAX_PDU_LEN,
            };
            assert_eq!(error.code(), ErrorCode::CorruptData);
            fails_at_header(Framer::new(), header, &error);
        }
        // A fixed-size PDU with a longer Length fails at once too, rather
        // than swallowing the PDUs that follow it.
        fails_at_header(
            Framer::new(),
            [1, 3, 0, 7, 0, 0, 0xfd, 0xe8],
            &RtrError::TooLong {
                pdu_type: 3,
                length: 65_000,
                max: 8,
            },
        );
    }

    #[test]
    fn short_lengths_fail() {
        // Every Length is at least the header, so the framer always moves
        // on: a Length of 0 would otherwise frame the same octets forever.
        for length in [0u8, 7, 15] {
            fails_at_header(
                Framer::new(),
                [1, 10, 0, 0, 0, 0, 0, length],
                &RtrError::TooShort {
                    pdu_type: 10,
                    length: u32::from(length),
                    min: 16,
                },
            );
        }
    }

    #[test]
    fn unknown_types_and_versions_fail() {
        fails_at_header(
            Framer::new(),
            [1, 5, 0, 0, 0, 0, 0, 8],
            &RtrError::UnsupportedPduType {
                version: Version::V1,
                pdu_type: 5,
            },
        );
        fails_at_header(
            Framer::new(),
            [7, 3, 0, 0, 0, 0, 0, 8],
            &RtrError::UnsupportedVersion {
                version: 7,
                pdu_type: 3,
            },
        );
    }

    #[test]
    fn body_errors_keep_the_whole_pdu() {
        let good = pdus();
        // An IPv4 Prefix whose Max Length is below its Prefix Length.
        let bad = [
            1, 4, 0, 0, 0, 0, 0, 20, 1, 24, 16, 0, 192, 0, 2, 0, 0, 0, 0, 1,
        ];
        let mut s = stream(&good[..2]);
        s.extend(bad);
        s.extend(stream(&good[2..]));
        let mut f = Framer::new();
        f.feed(&s);
        assert_eq!(f.next_pdu(), Ok(Some(good[0].clone())));
        assert_eq!(f.next_pdu(), Ok(Some(good[1].clone())));
        let error = RtrError::BadPrefixLength {
            pdu_type: 4,
            prefix_len: 24,
            max_len: 16,
        };
        assert_eq!(f.next_pdu(), Err(error.clone()));
        assert_eq!(f.erroneous_pdu(), bad);
        // Nothing after it is handed out.
        assert_eq!(f.next_pdu(), Err(error.clone()));
        assert_eq!(f.next_frame(), Err(error));
        assert_eq!(f.buffered(), 0);
    }

    #[test]
    fn negotiated_version_is_enforced() {
        let mut f = Framer::new();
        assert_eq!(f.version(), None);
        // Before negotiation, both versions pass.
        let v0 = Pdu::CacheReset {
            version: Version::V0,
        };
        f.feed(&v0.encode());
        assert_eq!(f.next_pdu(), Ok(Some(v0.clone())));
        f.set_version(Version::V1);
        assert_eq!(f.version(), Some(Version::V1));
        // RFC 8210 §7, §12 code 8.
        let error = RtrError::UnexpectedVersion {
            expected: Version::V1,
            version: 0,
            pdu_type: 8,
        };
        assert_eq!(error.code(), ErrorCode::UnexpectedProtocolVersion);
        let header: [u8; 8] = v0.encode().try_into().unwrap();
        fails_at_header(f.clone(), header, &error);
        // An Error Report of the wrong version is not to be answered.
        let report = Pdu::ErrorReport(ErrorReport::new(
            Version::V0,
            ErrorCode::InternalError,
            &[],
            "",
        ));
        f.feed(&report.encode());
        assert!(!f.next_pdu().unwrap_err().may_report());
    }

    /// A Serial Notify of protocol version 2, which this code does not
    /// speak, `length` octets long.
    fn v2_notify(length: u8) -> Vec<u8> {
        let mut b = vec![2, 0, 0, 7, 0, 0, 0, length];
        b.resize(usize::from(length).max(8), 0xee);
        b
    }

    #[test]
    fn serial_notify_of_any_version_is_ignored_while_negotiating() {
        // RFC 8210 §7: ignored "regardless of the Protocol Version field".
        let response = Pdu::CacheResponse {
            version: Version::V1,
            session_id: 9,
        };
        let mut s = v2_notify(12);
        s.extend(v2_notify(16));
        s.extend(response.encode());
        for chunk in [1, 5, s.len()] {
            let mut f = Framer::new();
            assert_eq!(run(&mut f, s.chunks(chunk)), Ok(vec![response.clone()]));
            assert_eq!(f.buffered(), 0);
        }
        // Its Length must still be one a PDU can have.
        fails_at_header(
            Framer::new(),
            [2, 0, 0, 7, 0, 0, 0, 4],
            &RtrError::UnsupportedVersion {
                version: 2,
                pdu_type: 0,
            },
        );
        fails_at_header(
            Framer::new(),
            [2, 0, 0, 7, 0, 1, 0, 1],
            &RtrError::UnsupportedVersion {
                version: 2,
                pdu_type: 0,
            },
        );
        // Other types of an unknown version are refused.
        fails_at_header(
            Framer::new(),
            [2, 3, 0, 7, 0, 0, 0, 8],
            &RtrError::UnsupportedVersion {
                version: 2,
                pdu_type: 3,
            },
        );
        // Once negotiated, the version is simply wrong.
        let mut f = Framer::new();
        f.set_version(Version::V1);
        fails_at_header(
            f,
            v2_notify(12)[..8].try_into().unwrap(),
            &RtrError::UnexpectedVersion {
                expected: Version::V1,
                version: 2,
                pdu_type: 0,
            },
        );
    }
}
