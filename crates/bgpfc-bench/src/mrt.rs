//! MRT `TABLE_DUMP_V2` routing table dumps (RFC 6396 §4.3), as `RouteViews`
//! and RIPE RIS publish them, read for replay.
//!
//! Only uncompressed files: std has no bzip2 or gzip, so a dump is
//! decompressed first (`bunzip2 rib.20261001.0000.bz2`, `gunzip
//! bview.20261001.0000.gz`). Records other than `PEER_INDEX_TABLE`,
//! `RIB_IPV4_UNICAST` and `RIB_IPV6_UNICAST` are skipped.
//!
//! Implements: RFC 6396 §2 (common header), §4.3.1 (`PEER_INDEX_TABLE`),
//! §4.3.2 (AFI/SAFI-specific RIB subtypes), §4.3.4 (RIB entries: four-octet
//! `AS_PATH`, `MP_REACH_NLRI` reduced to its next hop).

use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use bgpfc_wire::attribute::{PathAttribute, code, parse_raw};
use bgpfc_wire::mp::NextHop;
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::reader::Reader;
use bgpfc_wire::types::{AddressFamily, Afi, Asn};
use bgpfc_wire::update::{DecodeContext, PeerKind, UpdateMessage};

use crate::table::{AttrSet, Route, Table, family_of};

/// MRT type `TABLE_DUMP_V2` (RFC 6396 §4.3).
pub const TABLE_DUMP_V2: u16 = 13;
/// Subtype `PEER_INDEX_TABLE`.
pub const PEER_INDEX_TABLE: u16 = 1;
/// Subtype `RIB_IPV4_UNICAST`.
pub const RIB_IPV4_UNICAST: u16 = 2;
/// Subtype `RIB_IPV6_UNICAST`.
pub const RIB_IPV6_UNICAST: u16 = 4;

/// Length of the MRT common header (RFC 6396 §2).
const HEADER_LEN: usize = 12;
/// Records larger than this are refused rather than allocated.
const MAX_RECORD: usize = 64 * 1024 * 1024;

/// A malformed or unusable dump.
#[derive(Debug)]
pub enum MrtError {
    /// Reading the file failed.
    Io(io::Error),
    /// A record is shorter than its fields say.
    Truncated(&'static str),
    /// A field has a value the RFC does not allow.
    Invalid(String),
    /// A RIB record came before the `PEER_INDEX_TABLE`.
    NoPeerIndex,
    /// The chosen peer index is not in the table.
    NoSuchPeer(u16),
}

impl fmt::Display for MrtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MrtError::Io(e) => write!(f, "{e}"),
            MrtError::Truncated(what) => write!(f, "truncated {what}"),
            MrtError::Invalid(m) => f.write_str(m),
            MrtError::NoPeerIndex => f.write_str("RIB record before the PEER_INDEX_TABLE"),
            MrtError::NoSuchPeer(i) => write!(f, "no peer with index {i}"),
        }
    }
}

impl std::error::Error for MrtError {}

impl From<io::Error> for MrtError {
    fn from(e: io::Error) -> Self {
        MrtError::Io(e)
    }
}

/// One entry of the `PEER_INDEX_TABLE`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    /// The peer's BGP Identifier.
    pub bgp_id: Ipv4Addr,
    /// The peer's address.
    pub addr: IpAddr,
    /// The peer's AS.
    pub asn: Asn,
}

/// The `PEER_INDEX_TABLE` (RFC 6396 §4.3.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerIndex {
    /// The collector's BGP Identifier.
    pub collector: Ipv4Addr,
    /// The view name, often empty.
    pub view: String,
    /// The peers, by index.
    pub peers: Vec<Peer>,
}

/// One route of a RIB record (RFC 6396 §4.3.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RibEntry<'a> {
    /// Index into the `PEER_INDEX_TABLE`.
    pub peer: u16,
    /// When the route was learned, Unix seconds.
    pub originated: u32,
    /// The path attributes as dumped.
    pub attributes: &'a [u8],
}

/// A RIB record: one prefix and every peer's route to it (RFC 6396
/// §4.3.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rib<'a> {
    /// Sequence number.
    pub sequence: u32,
    /// The prefix.
    pub prefix: Prefix,
    /// The routes.
    pub entries: Vec<RibEntry<'a>>,
}

/// One parsed record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record<'a> {
    /// `PEER_INDEX_TABLE`.
    PeerIndex(PeerIndex),
    /// `RIB_IPV4_UNICAST` or `RIB_IPV6_UNICAST`.
    Rib(Rib<'a>),
    /// Anything else, skipped.
    Other {
        /// MRT type.
        kind: u16,
        /// MRT subtype.
        subtype: u16,
    },
}

/// Parse the message of a record of `kind` and `subtype`.
///
/// # Errors
/// [`MrtError`] for a malformed message.
pub fn parse_record(kind: u16, subtype: u16, body: &[u8]) -> Result<Record<'_>, MrtError> {
    match (kind, subtype) {
        (TABLE_DUMP_V2, PEER_INDEX_TABLE) => parse_peer_index(body).map(Record::PeerIndex),
        (TABLE_DUMP_V2, RIB_IPV4_UNICAST) => parse_rib(body, Afi::Ipv4).map(Record::Rib),
        (TABLE_DUMP_V2, RIB_IPV6_UNICAST) => parse_rib(body, Afi::Ipv6).map(Record::Rib),
        _ => Ok(Record::Other { kind, subtype }),
    }
}

fn parse_peer_index(body: &[u8]) -> Result<PeerIndex, MrtError> {
    let t = |_| MrtError::Truncated("PEER_INDEX_TABLE");
    let mut r = Reader::new(body);
    let collector = Ipv4Addr::from(r.array::<4>().map_err(t)?);
    let view_len = usize::from(r.u16().map_err(t)?);
    let view = String::from_utf8_lossy(r.take(view_len).map_err(t)?).into_owned();
    let count = r.u16().map_err(t)?;
    let mut peers = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        // Bit 0: IPv6 address; bit 1: four-octet AS.
        let peer_type = r.u8().map_err(t)?;
        let bgp_id = Ipv4Addr::from(r.array::<4>().map_err(t)?);
        let addr = if peer_type & 0x01 == 0 {
            IpAddr::V4(Ipv4Addr::from(r.array::<4>().map_err(t)?))
        } else {
            IpAddr::V6(Ipv6Addr::from(r.array::<16>().map_err(t)?))
        };
        let asn = if peer_type & 0x02 == 0 {
            Asn::from(r.u16().map_err(t)?)
        } else {
            Asn(r.u32().map_err(t)?)
        };
        peers.push(Peer { bgp_id, addr, asn });
    }
    Ok(PeerIndex {
        collector,
        view,
        peers,
    })
}

fn parse_rib(body: &[u8], afi: Afi) -> Result<Rib<'_>, MrtError> {
    let t = |_| MrtError::Truncated("RIB record");
    let mut r = Reader::new(body);
    let sequence = r.u32().map_err(t)?;
    // The same <length, prefix> encoding as NLRI (RFC 6396 §4.3.2).
    let prefix = Prefix::decode(&mut r, afi)
        .map_err(|e| MrtError::Invalid(format!("RIB record prefix: {e}")))?;
    let count = r.u16().map_err(t)?;
    let mut entries = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        let peer = r.u16().map_err(t)?;
        let originated = r.u32().map_err(t)?;
        let len = usize::from(r.u16().map_err(t)?);
        let attributes = r.take(len).map_err(t)?;
        entries.push(RibEntry {
            peer,
            originated,
            attributes,
        });
    }
    Ok(Rib {
        sequence,
        prefix,
        entries,
    })
}

/// A record's type, subtype and message.
pub type RawRecord<'a> = (u16, u16, &'a [u8]);

/// Reads records one at a time from a stream.
#[derive(Debug)]
pub struct Records<R> {
    inner: R,
    body: Vec<u8>,
}

impl<R: Read> Records<R> {
    /// Records from `inner`.
    pub fn new(inner: R) -> Records<R> {
        Records {
            inner,
            body: Vec::new(),
        }
    }

    /// Read the next record's header and message; its type, subtype and
    /// message, or `None` at a clean end of file.
    ///
    /// # Errors
    /// I/O errors, a record cut short, or one over 64 MiB.
    pub fn next_record(&mut self) -> Result<Option<RawRecord<'_>>, MrtError> {
        let mut header = [0u8; HEADER_LEN];
        let mut got = 0;
        while got < HEADER_LEN {
            match self.inner.read(&mut header[got..])? {
                0 if got == 0 => return Ok(None),
                0 => return Err(MrtError::Truncated("record header")),
                n => got += n,
            }
        }
        let mut r = Reader::new(&header);
        // invariant: the header buffer is exactly HEADER_LEN octets.
        let _timestamp = r.u32().unwrap_or(0);
        let kind = r.u16().unwrap_or(0);
        let subtype = r.u16().unwrap_or(0);
        let len = r.u32().unwrap_or(0) as usize;
        if len > MAX_RECORD {
            return Err(MrtError::Invalid(format!("record of {len} octets")));
        }
        self.body.resize(len, 0);
        self.inner
            .read_exact(&mut self.body)
            .map_err(|_| MrtError::Truncated("record"))?;
        Ok(Some((kind, subtype, &self.body)))
    }
}

/// One peer's routes, with attribute sets shared between the routes that
/// carry the same attributes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerRoutes {
    /// The peer.
    pub peer: Peer,
    /// Distinct attribute sets as dumped.
    pub sets: Vec<AttrSet>,
    /// The routes.
    pub routes: Vec<Route>,
    /// Entries left out: attributes the daemon would treat as withdrawn
    /// (malformed, or `AS_SET` per RFC 9774), or no usable next hop.
    pub skipped: usize,
}

impl PeerRoutes {
    /// The families present.
    #[must_use]
    pub fn families(&self) -> Vec<AddressFamily> {
        Table {
            sets: Vec::new(),
            routes: self.routes.clone(),
        }
        .families()
    }

    /// The routes as a speaker in `local_as` sends them to `peer_as`: on an
    /// external session with `local_as` prepended (RFC 4271 §5.1.2) and no
    /// `LOCAL_PREF` (§5.1.5). Routes whose path holds `peer_as` are left
    /// out: the receiver would drop them as AS loops (§9.1.2).
    #[must_use]
    pub fn table(&self, local_as: Asn, peer_as: Asn) -> Table {
        let internal = local_as == peer_as;
        let mut keep = vec![false; self.sets.len()];
        let sets: Vec<AttrSet> = self
            .sets
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let mut s = s.clone();
                for a in &mut s.attributes {
                    if let PathAttribute::AsPath(p) = a {
                        keep[i] = !p.contains(peer_as);
                        if !internal {
                            *p = p.prepend(local_as);
                        }
                    }
                }
                if !internal {
                    s.attributes
                        .retain(|a| !matches!(a, PathAttribute::LocalPref(_)));
                }
                s
            })
            .collect();
        let routes = self
            .routes
            .iter()
            .copied()
            .filter(|r| keep[r.set as usize])
            .collect();
        Table { sets, routes }
    }
}

/// Turn one RIB entry's attributes into an attribute set, decoding them
/// with the daemon's decoder; `None` when it would not accept them.
fn attr_set(raw: &[u8], prefix: &Prefix) -> Option<AttrSet> {
    // RFC 6396 §4.3.4: MP_REACH_NLRI holds only the next hop. Take it out
    // and hand the rest to the UPDATE decoder.
    let mut rest = Vec::with_capacity(raw.len());
    let mut mp_next_hop = None;
    let mut r = Reader::new(raw);
    while !r.is_empty() {
        let a = parse_raw(&mut r).ok()?;
        if a.code == code::MP_REACH_NLRI {
            mp_next_hop = Some(next_hop_of(a.value)?);
        } else {
            rest.extend_from_slice(a.raw);
        }
    }
    let mut body = Vec::with_capacity(rest.len() + 4);
    body.extend_from_slice(&[0, 0]);
    body.extend_from_slice(&u16::try_from(rest.len()).ok()?.to_be_bytes());
    body.extend_from_slice(&rest);
    // External, four-octet, AS_SET refused: the daemon's defaults.
    let ctx = DecodeContext {
        four_octet_as: true,
        peer: PeerKind::External,
        allow_as_set: false,
    };
    let decoded = UpdateMessage::decode(&body, &ctx).ok()?;
    if decoded.treated_as_withdraw.is_some() {
        return None;
    }
    let mut attributes = decoded.message.attributes;
    let v4_next_hop = attributes.iter().find_map(|a| match a {
        PathAttribute::NextHop(n) => Some(*n),
        _ => None,
    });
    attributes.retain(|a| !matches!(a, PathAttribute::NextHop(_)));
    let next_hop = match (family_of(prefix), mp_next_hop, v4_next_hop) {
        (AddressFamily::IPV4_UNICAST, _, Some(n)) => NextHop::Ipv4(n),
        (_, Some(n), _) => n,
        _ => return None,
    };
    if !attributes
        .iter()
        .any(|a| matches!(a, PathAttribute::AsPath(_)))
    {
        return None;
    }
    Some(AttrSet {
        attributes,
        next_hop,
    })
}

/// The next hop of a dumped `MP_REACH_NLRI`: the RFC 6396 §4.3.4 form
/// (length, address), or the full RFC 4760 form some dumpers write.
fn next_hop_of(v: &[u8]) -> Option<NextHop> {
    let (len, rest) = v.split_first()?;
    let addr = if usize::from(*len) + 1 == v.len() {
        rest
    } else {
        // AFI (2), SAFI (1), length (1), address.
        let len = usize::from(*v.get(3)?);
        v.get(4..4 + len)?
    };
    match addr.len() {
        4 => Some(NextHop::Ipv4(Ipv4Addr::from(
            <[u8; 4]>::try_from(addr).ok()?,
        ))),
        16 | 32 => {
            let global = Ipv6Addr::from(<[u8; 16]>::try_from(&addr[..16]).ok()?);
            let link_local = addr
                .get(16..32)
                .and_then(|l| <[u8; 16]>::try_from(l).ok())
                .map(Ipv6Addr::from);
            Some(NextHop::Ipv6 { global, link_local })
        }
        _ => None,
    }
}

/// Read every route of peer `peer` from a dump. Attribute sets are shared
/// between routes with equal attributes, as a real speaker groups them.
///
/// # Errors
/// [`MrtError`] for an unreadable or malformed dump or an unknown peer.
pub fn load(r: impl Read, peer: u16) -> Result<PeerRoutes, MrtError> {
    let mut records = Records::new(r);
    let mut index: Option<PeerIndex> = None;
    let mut ids: HashMap<AttrSet, u32> = HashMap::new();
    let mut out = PeerRoutes {
        peer: Peer {
            bgp_id: Ipv4Addr::UNSPECIFIED,
            addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            asn: Asn(0),
        },
        sets: Vec::new(),
        routes: Vec::new(),
        skipped: 0,
    };
    while let Some((kind, subtype, body)) = records.next_record()? {
        match parse_record(kind, subtype, body)? {
            Record::PeerIndex(p) => {
                out.peer = p
                    .peers
                    .get(usize::from(peer))
                    .cloned()
                    .ok_or(MrtError::NoSuchPeer(peer))?;
                index = Some(p);
            }
            Record::Rib(rib) => {
                if index.is_none() {
                    return Err(MrtError::NoPeerIndex);
                }
                for e in rib.entries.iter().filter(|e| e.peer == peer) {
                    let Some(set) = attr_set(e.attributes, &rib.prefix) else {
                        out.skipped += 1;
                        continue;
                    };
                    let next = u32::try_from(out.sets.len()).unwrap_or(u32::MAX);
                    let id = *ids.entry(set).or_insert_with_key(|s| {
                        out.sets.push(s.clone());
                        next
                    });
                    out.routes.push(Route {
                        set: id,
                        prefix: rib.prefix,
                    });
                }
            }
            Record::Other { .. } => {}
        }
    }
    if index.is_none() {
        return Err(MrtError::NoPeerIndex);
    }
    Ok(out)
}

/// The peer table and how many routes each peer has, for choosing one.
///
/// # Errors
/// [`MrtError`] for an unreadable or malformed dump.
pub fn peer_counts(r: impl Read) -> Result<(PeerIndex, Vec<usize>), MrtError> {
    let mut records = Records::new(r);
    let mut index = None;
    let mut counts: Vec<usize> = Vec::new();
    while let Some((kind, subtype, body)) = records.next_record()? {
        match parse_record(kind, subtype, body)? {
            Record::PeerIndex(p) => {
                counts = vec![0; p.peers.len()];
                index = Some(p);
            }
            Record::Rib(rib) => {
                for e in &rib.entries {
                    if let Some(c) = counts.get_mut(usize::from(e.peer)) {
                        *c += 1;
                    }
                }
            }
            Record::Other { .. } => {}
        }
    }
    Ok((index.ok_or(MrtError::NoPeerIndex)?, counts))
}

/// [`load`] from a file; with no peer given, the one with the most routes
/// (one more pass over the file).
///
/// # Errors
/// [`MrtError`].
pub fn load_file(path: &Path, peer: Option<u16>) -> Result<PeerRoutes, MrtError> {
    let peer = if let Some(p) = peer {
        p
    } else {
        let (_, counts) = peer_counts(BufReader::new(File::open(path)?))?;
        let best = counts
            .iter()
            .enumerate()
            .max_by_key(|(_, n)| **n)
            .map_or(0, |(i, _)| i);
        u16::try_from(best).map_err(|_| MrtError::Invalid("too many peers".to_owned()))?
    };
    load(BufReader::new(File::open(path)?), peer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(kind: u16, subtype: u16, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&1_760_000_000u32.to_be_bytes());
        out.extend_from_slice(&kind.to_be_bytes());
        out.extend_from_slice(&subtype.to_be_bytes());
        out.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    /// Two peers: 0 is IPv4 with a two-octet AS, 1 is IPv6 with a
    /// four-octet AS.
    fn peer_index() -> Vec<u8> {
        let mut b = vec![198, 51, 100, 254];
        b.extend_from_slice(&4u16.to_be_bytes());
        b.extend_from_slice(b"rv-x");
        b.extend_from_slice(&2u16.to_be_bytes());
        b.push(0x00);
        b.extend_from_slice(&[192, 0, 2, 1, 192, 0, 2, 1]);
        b.extend_from_slice(&64_500u16.to_be_bytes());
        b.push(0x03);
        b.extend_from_slice(&[192, 0, 2, 2]);
        b.extend_from_slice(&"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());
        b.extend_from_slice(&4_200_000_000u32.to_be_bytes());
        record(TABLE_DUMP_V2, PEER_INDEX_TABLE, &b)
    }

    /// ORIGIN IGP and a four-octet `AS_PATH` sequence.
    fn origin_and_path(asns: &[u32]) -> Vec<u8> {
        let mut a = vec![0x40, code::ORIGIN, 1, 0];
        let len = 2 + 4 * asns.len();
        a.extend_from_slice(&[0x40, code::AS_PATH, u8::try_from(len).unwrap(), 2]);
        a.push(u8::try_from(asns.len()).unwrap());
        for x in asns {
            a.extend_from_slice(&x.to_be_bytes());
        }
        a
    }

    fn entry(peer: u16, attrs: &[u8]) -> Vec<u8> {
        let mut e = peer.to_be_bytes().to_vec();
        e.extend_from_slice(&1_759_000_000u32.to_be_bytes());
        e.extend_from_slice(&u16::try_from(attrs.len()).unwrap().to_be_bytes());
        e.extend_from_slice(attrs);
        e
    }

    fn rib(subtype: u16, seq: u32, prefix: &[u8], entries: &[Vec<u8>]) -> Vec<u8> {
        let mut b = seq.to_be_bytes().to_vec();
        b.extend_from_slice(prefix);
        b.extend_from_slice(&u16::try_from(entries.len()).unwrap().to_be_bytes());
        for e in entries {
            b.extend_from_slice(e);
        }
        record(TABLE_DUMP_V2, subtype, &b)
    }

    fn dump() -> Vec<u8> {
        let mut v4 = origin_and_path(&[64_500, 3356]);
        v4.extend_from_slice(&[0x40, code::NEXT_HOP, 4, 192, 0, 2, 1]);
        let mut v4b = origin_and_path(&[64_500, 3356]);
        v4b.extend_from_slice(&[0x40, code::NEXT_HOP, 4, 192, 0, 2, 1]);
        let mut v4_other = origin_and_path(&[4_200_000_000, 174]);
        v4_other.extend_from_slice(&[0x40, code::NEXT_HOP, 4, 192, 0, 2, 2]);
        // RFC 6396 §4.3.4: MP_REACH_NLRI is just the next hop.
        let mut v6 = origin_and_path(&[4_200_000_000, 6939]);
        v6.extend_from_slice(&[0x80, code::MP_REACH_NLRI, 17, 16]);
        v6.extend_from_slice(&"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());
        // An AS_SET: RFC 9774 treat-as-withdraw at the daemon.
        let mut set = vec![0x40, code::ORIGIN, 1, 0, 0x40, code::AS_PATH, 10, 1, 2];
        set.extend_from_slice(&64_500u32.to_be_bytes());
        set.extend_from_slice(&64_501u32.to_be_bytes());
        set.extend_from_slice(&[0x40, code::NEXT_HOP, 4, 192, 0, 2, 1]);

        let mut out = peer_index();
        // Something else first: BGP4MP, skipped.
        out.extend(record(16, 4, &[1, 2, 3]));
        out.extend(rib(
            RIB_IPV4_UNICAST,
            0,
            &[24, 203, 0, 113],
            &[entry(0, &v4), entry(1, &v4_other)],
        ));
        out.extend(rib(RIB_IPV4_UNICAST, 1, &[16, 198, 18], &[entry(0, &v4b)]));
        out.extend(rib(RIB_IPV4_UNICAST, 2, &[8, 44], &[entry(0, &set)]));
        out.extend(rib(
            RIB_IPV6_UNICAST,
            3,
            &[32, 0x20, 0x01, 0x0d, 0xb8],
            &[entry(1, &v6)],
        ));
        out
    }

    #[test]
    fn parses_records() {
        let data = dump();
        let mut records = Records::new(&data[..]);
        let (kind, subtype, body) = records.next_record().unwrap().unwrap();
        let Record::PeerIndex(p) = parse_record(kind, subtype, body).unwrap() else {
            panic!("peer index first");
        };
        assert_eq!(p.collector, Ipv4Addr::new(198, 51, 100, 254));
        assert_eq!(p.view, "rv-x");
        assert_eq!(p.peers[0].asn, Asn(64_500));
        assert_eq!(p.peers[0].addr, "192.0.2.1".parse::<IpAddr>().unwrap());
        assert_eq!(p.peers[1].asn, Asn(4_200_000_000));
        assert_eq!(p.peers[1].addr, "2001:db8::2".parse::<IpAddr>().unwrap());
        let (kind, subtype, body) = records.next_record().unwrap().unwrap();
        assert_eq!(
            parse_record(kind, subtype, body).unwrap(),
            Record::Other {
                kind: 16,
                subtype: 4
            }
        );
        let (kind, subtype, body) = records.next_record().unwrap().unwrap();
        let Record::Rib(r) = parse_record(kind, subtype, body).unwrap() else {
            panic!("rib");
        };
        assert_eq!(r.prefix, "203.0.113.0/24".parse().unwrap());
        assert_eq!(r.entries.len(), 2);
        assert_eq!(r.entries[1].peer, 1);
        let mut n = 3;
        while records.next_record().unwrap().is_some() {
            n += 1;
        }
        assert_eq!(n, 6);
    }

    #[test]
    fn loads_one_peer_with_shared_attribute_sets() {
        let p0 = load(&dump()[..], 0).unwrap();
        assert_eq!(p0.peer.asn, Asn(64_500));
        // Two IPv4 routes with equal attributes share a set; the AS_SET
        // route is skipped.
        assert_eq!(p0.routes.len(), 2);
        assert_eq!(p0.sets.len(), 1);
        assert_eq!(p0.skipped, 1);
        assert_eq!(
            p0.sets[0].next_hop,
            NextHop::Ipv4(Ipv4Addr::new(192, 0, 2, 1))
        );
        assert_eq!(p0.families(), vec![AddressFamily::IPV4_UNICAST]);

        let p1 = load(&dump()[..], 1).unwrap();
        assert_eq!(p1.routes.len(), 2);
        assert_eq!(
            p1.families(),
            vec![AddressFamily::IPV4_UNICAST, AddressFamily::IPV6_UNICAST]
        );
        let v6 = p1
            .routes
            .iter()
            .find(|r| family_of(&r.prefix) == AddressFamily::IPV6_UNICAST)
            .unwrap();
        assert_eq!(
            p1.sets[v6.set as usize].next_hop,
            NextHop::Ipv6 {
                global: "2001:db8::2".parse().unwrap(),
                link_local: None
            }
        );
        assert!(matches!(load(&dump()[..], 7), Err(MrtError::NoSuchPeer(7))));
    }

    #[test]
    fn replays_as_an_external_speaker() {
        let p0 = load(&dump()[..], 0).unwrap();
        let t = p0.table(Asn(65_001), Asn(65_000));
        let PathAttribute::AsPath(path) = &t.sets[0].attributes[1] else {
            panic!("AS_PATH");
        };
        assert_eq!(
            path.asns().collect::<Vec<_>>(),
            vec![Asn(65_001), Asn(64_500), Asn(3356)]
        );
        assert_eq!(t.routes.len(), 2);
        // A receiver whose AS is on the path would drop the route.
        assert_eq!(p0.table(Asn(65_001), Asn(3356)).routes, Vec::new());
        // The routes pack and decode with the daemon's codec.
        let messages = crate::pack::Packer::new(true, false).table(&t).unwrap();
        assert_eq!(messages.len(), 1);
    }

    #[test]
    fn counts_routes_per_peer() {
        let (index, counts) = peer_counts(&dump()[..]).unwrap();
        assert_eq!(index.peers.len(), 2);
        assert_eq!(counts, vec![3, 2]);
    }

    #[test]
    fn refuses_malformed_dumps() {
        let data = dump();
        // Cut inside a record.
        assert!(matches!(
            load(&data[..data.len() - 3], 0),
            Err(MrtError::Truncated(_))
        ));
        // Cut inside a header.
        assert!(matches!(
            load(&data[..5], 0),
            Err(MrtError::Truncated("record header"))
        ));
        // A RIB record before the peer table.
        let late = rib(RIB_IPV4_UNICAST, 0, &[8, 44], &[]);
        assert!(matches!(load(&late[..], 0), Err(MrtError::NoPeerIndex)));
        // A prefix longer than the family allows.
        let bad = [
            peer_index(),
            rib(RIB_IPV4_UNICAST, 0, &[33, 1, 2, 3, 4, 5], &[]),
        ]
        .concat();
        assert!(matches!(load(&bad[..], 0), Err(MrtError::Invalid(_))));
        // An entry whose attributes run past the record.
        let mut short = entry(0, &[0x40, 1, 1, 0]);
        short[7] = 200;
        let bad = [peer_index(), rib(RIB_IPV4_UNICAST, 0, &[8, 44], &[short])].concat();
        assert!(matches!(load(&bad[..], 0), Err(MrtError::Truncated(_))));
        // An empty file has no peer table.
        assert!(matches!(load(&[][..], 0), Err(MrtError::NoPeerIndex)));
    }

    #[test]
    fn next_hops_in_both_forms() {
        let g: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let l: Ipv6Addr = "fe80::1".parse().unwrap();
        let mut short = vec![32];
        short.extend_from_slice(&g.octets());
        short.extend_from_slice(&l.octets());
        assert_eq!(
            next_hop_of(&short),
            Some(NextHop::Ipv6 {
                global: g,
                link_local: Some(l)
            })
        );
        let mut full = vec![0, 2, 1, 16];
        full.extend_from_slice(&g.octets());
        full.extend_from_slice(&[0, 32, 0x20, 0x01, 0x0d, 0xb8]);
        assert_eq!(
            next_hop_of(&full),
            Some(NextHop::Ipv6 {
                global: g,
                link_local: None
            })
        );
        assert_eq!(next_hop_of(&[5, 1, 2]), None);
    }
}
