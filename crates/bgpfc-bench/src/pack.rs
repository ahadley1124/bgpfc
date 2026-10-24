//! UPDATE packing: as many prefixes per message as fit the negotiated
//! size (RFC 4271 §4.1: 4096 octets; RFC 8654 §4: 65535 with Extended
//! Message), encoded with `bgpfc-wire`, the daemon's own encoder.

use std::fmt;

use bgpfc_wire::attribute::PathAttribute;
use bgpfc_wire::error::EncodeError;
use bgpfc_wire::header::{MessageType, frame};
use bgpfc_wire::mp::{MpReach, MpUnreach, NextHop};
use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::AddressFamily;
use bgpfc_wire::update::{EncodeContext, UpdateMessage};

use crate::table::{AttrSet, Table, family_of};

/// Why messages could not be built.
#[derive(Debug)]
pub enum PackError {
    /// The encoder refused.
    Encode(EncodeError),
    /// An attribute set leaves no room for even one prefix.
    NoRoom {
        /// Octets the message has before any prefix.
        base: usize,
        /// The message size limit.
        max: usize,
    },
}

impl fmt::Display for PackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PackError::Encode(e) => write!(f, "cannot encode: {e}"),
            PackError::NoRoom { base, max } => {
                write!(
                    f,
                    "attributes take {base} of {max} octets: no room for NLRI"
                )
            }
        }
    }
}

impl std::error::Error for PackError {}

impl From<EncodeError> for PackError {
    fn from(e: EncodeError) -> Self {
        PackError::Encode(e)
    }
}

/// Builds framed UPDATEs for one session.
#[derive(Clone, Copy, Debug)]
pub struct Packer {
    ctx: EncodeContext,
    max_len: usize,
}

/// The most octets one NLRI entry takes: a length octet and 16 of address.
const MAX_PREFIX_OCTETS: usize = 17;

impl Packer {
    /// A packer for a session that negotiated four-octet ASNs or not, and
    /// Extended Message or not.
    #[must_use]
    pub fn new(four_octet_as: bool, extended: bool) -> Packer {
        Packer {
            ctx: EncodeContext { four_octet_as },
            max_len: if extended { 65_535 } else { 4_096 },
        }
    }

    /// The largest message this packer builds, header included.
    #[must_use]
    pub fn max_len(&self) -> usize {
        self.max_len
    }

    fn framed(&self, m: &UpdateMessage) -> Result<Vec<u8>, PackError> {
        Ok(frame(MessageType::Update, &m.encode(&self.ctx)?)?)
    }

    /// Append UPDATEs announcing `prefixes`, all of `family`, with `set`.
    ///
    /// # Errors
    /// [`PackError`] if the set cannot be encoded or leaves no room.
    pub fn announce(
        &self,
        family: AddressFamily,
        set: &AttrSet,
        prefixes: &[Prefix],
        out: &mut Vec<Vec<u8>>,
    ) -> Result<(), PackError> {
        if prefixes.is_empty() {
            return Ok(());
        }
        let (base_msg, in_mp) = announcement(family, set, Vec::new());
        let base = self.framed(&base_msg)?.len();
        // MP_REACH_NLRI's length field may grow to two octets as NLRI is
        // added (RFC 4271 §4.3 Extended Length).
        let reserve = usize::from(in_mp);
        let room = self.room(base + reserve)?;
        for chunk in chunks(prefixes, room) {
            let (m, _) = announcement(family, set, chunk.to_vec());
            out.push(self.checked(&m)?);
        }
        Ok(())
    }

    /// Append UPDATEs withdrawing `prefixes`, all of `family`: the
    /// Withdrawn Routes field for IPv4 unicast, `MP_UNREACH_NLRI` otherwise
    /// (RFC 4760 §4).
    ///
    /// # Errors
    /// [`PackError`] if the encoder refuses.
    pub fn withdraw(
        &self,
        family: AddressFamily,
        prefixes: &[Prefix],
        out: &mut Vec<Vec<u8>>,
    ) -> Result<(), PackError> {
        if prefixes.is_empty() {
            return Ok(());
        }
        let base = self.framed(&withdrawal(family, Vec::new()))?.len();
        let reserve = usize::from(family != AddressFamily::IPV4_UNICAST);
        let room = self.room(base + reserve)?;
        for chunk in chunks(prefixes, room) {
            out.push(self.checked(&withdrawal(family, chunk.to_vec()))?);
        }
        Ok(())
    }

    /// The End-of-RIB marker of `family` (RFC 4724 §2): an empty UPDATE for
    /// IPv4 unicast, an empty `MP_UNREACH_NLRI` otherwise.
    ///
    /// # Errors
    /// [`PackError`] if the encoder refuses.
    pub fn end_of_rib(&self, family: AddressFamily) -> Result<Vec<u8>, PackError> {
        self.framed(&withdrawal(family, Vec::new()))
    }

    /// Every route of `table`, grouped by attribute set and family, in as
    /// few UPDATEs as fit. Returns the messages; NLRI order inside a group
    /// follows the table.
    ///
    /// # Errors
    /// [`PackError`] from [`Packer::announce`].
    pub fn table(&self, table: &Table) -> Result<Vec<Vec<u8>>, PackError> {
        let mut order: Vec<usize> = (0..table.routes.len()).collect();
        order.sort_by_key(|&i| {
            let r = &table.routes[i];
            (r.set, family_of(&r.prefix))
        });
        let mut out = Vec::new();
        let mut group: Vec<Prefix> = Vec::new();
        let mut key = None;
        for i in order {
            let r = table.routes[i];
            let k = (r.set, family_of(&r.prefix));
            if key != Some(k) {
                if let Some((set, family)) = key {
                    self.announce(family, &table.sets[set as usize], &group, &mut out)?;
                }
                group.clear();
                key = Some(k);
            }
            group.push(r.prefix);
        }
        if let Some((set, family)) = key {
            self.announce(family, &table.sets[set as usize], &group, &mut out)?;
        }
        Ok(out)
    }

    fn room(&self, base: usize) -> Result<usize, PackError> {
        self.max_len
            .checked_sub(base)
            .filter(|r| *r >= MAX_PREFIX_OCTETS)
            .ok_or(PackError::NoRoom {
                base,
                max: self.max_len,
            })
    }

    /// Encode `m`, refusing anything over the limit: a bug in the sizing,
    /// which must not reach a peer.
    fn checked(&self, m: &UpdateMessage) -> Result<Vec<u8>, PackError> {
        let bytes = self.framed(m)?;
        if bytes.len() > self.max_len {
            return Err(PackError::Encode(EncodeError::TooLong {
                what: "UPDATE message",
                len: bytes.len(),
                max: self.max_len,
            }));
        }
        Ok(bytes)
    }
}

/// The UPDATE announcing `nlri` with `set`, and whether the NLRI travels in
/// `MP_REACH_NLRI`.
fn announcement(family: AddressFamily, set: &AttrSet, nlri: Vec<Prefix>) -> (UpdateMessage, bool) {
    let mut attributes = set.attributes.clone();
    match (family, set.next_hop) {
        (AddressFamily::IPV4_UNICAST, NextHop::Ipv4(a)) => {
            attributes.push(PathAttribute::NextHop(a));
            (
                UpdateMessage {
                    attributes,
                    nlri,
                    ..UpdateMessage::default()
                },
                false,
            )
        }
        // RFC 4760 §3, and RFC 8950 for IPv4 NLRI with an IPv6 next hop.
        (family, next_hop) => (
            UpdateMessage {
                attributes,
                mp_reach: Some(MpReach {
                    family,
                    next_hop,
                    nlri,
                }),
                ..UpdateMessage::default()
            },
            true,
        ),
    }
}

fn withdrawal(family: AddressFamily, prefixes: Vec<Prefix>) -> UpdateMessage {
    if family == AddressFamily::IPV4_UNICAST {
        UpdateMessage {
            withdrawn: prefixes,
            ..UpdateMessage::default()
        }
    } else {
        UpdateMessage {
            mp_unreach: Some(MpUnreach {
                family,
                withdrawn: prefixes,
            }),
            ..UpdateMessage::default()
        }
    }
}

/// Split `prefixes` into runs whose NLRI encoding fits `room` octets.
fn chunks(prefixes: &[Prefix], room: usize) -> Vec<&[Prefix]> {
    let mut out = Vec::new();
    let (mut start, mut used) = (0, 0);
    for (i, p) in prefixes.iter().enumerate() {
        let len = 1 + usize::from(p.prefix_len().div_ceil(8));
        if used + len > room && i > start {
            out.push(&prefixes[start..i]);
            start = i;
            used = 0;
        }
        used += len;
    }
    if start < prefixes.len() {
        out.push(&prefixes[start..]);
    }
    out
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use bgpfc_wire::header::{HEADER_LEN, Header};
    use bgpfc_wire::types::Asn;
    use bgpfc_wire::update::{DecodeContext, DecodedUpdate, PeerKind};

    use super::*;
    use crate::synth::{SynthOpts, generate};

    const CTX: DecodeContext = DecodeContext {
        four_octet_as: true,
        peer: PeerKind::External,
        allow_as_set: false,
    };

    /// Decode one framed message with the daemon's decoder.
    fn decode(bytes: &[u8], extended: bool) -> DecodedUpdate {
        let h = Header::decode(&bytes[..HEADER_LEN], extended).unwrap();
        assert_eq!(h.kind, MessageType::Update);
        assert_eq!(HEADER_LEN + h.body_len(), bytes.len());
        UpdateMessage::decode(&bytes[HEADER_LEN..], &CTX).unwrap()
    }

    fn table(prefixes: usize, sets: usize) -> Table {
        generate(&SynthOpts {
            prefixes,
            attr_sets: sets,
            ..SynthOpts::new(Asn(65_001), Asn(65_000))
        })
    }

    #[test]
    fn a_table_round_trips_within_the_limit() {
        let t = table(30_000, 40);
        for extended in [false, true] {
            let p = Packer::new(true, extended);
            let messages = p.table(&t).unwrap();
            let mut got = Vec::new();
            for m in &messages {
                assert!(m.len() <= p.max_len(), "{} > {}", m.len(), p.max_len());
                let d = decode(m, extended);
                assert!(d.treated_as_withdraw.is_none());
                got.extend(d.announcements().map(|(_, prefix)| prefix));
            }
            let mut want: Vec<Prefix> = t.routes.iter().map(|r| r.prefix).collect();
            want.sort();
            got.sort();
            assert_eq!(got, want, "extended={extended}");
            // 30 000 prefixes over 40 sets: groups of hundreds to thousands.
            // Every group fits one 65535-octet message; 4096 octets hold
            // about a thousand /24s, so the big groups need several.
            if extended {
                assert_eq!(messages.len(), t.used_sets());
            } else {
                assert!(messages.len() > t.used_sets());
                assert!(t.routes.len() / messages.len() > 400);
            }
        }
    }

    #[test]
    fn messages_are_full_before_a_new_one_starts() {
        let t = table(5000, 1);
        let p = Packer::new(true, false);
        let set = &t.sets[0];
        let prefixes: Vec<Prefix> = t.routes.iter().map(|r| r.prefix).collect();
        let mut out = Vec::new();
        p.announce(AddressFamily::IPV4_UNICAST, set, &prefixes, &mut out)
            .unwrap();
        let mut next = 0;
        for (i, m) in out.iter().enumerate() {
            let n = decode(m, false).message.nlri.len();
            next += n;
            if i + 1 < out.len() {
                // The next prefix would not have fitted.
                let extra = 1 + usize::from(prefixes[next].prefix_len().div_ceil(8));
                assert!(m.len() + extra > p.max_len(), "message {i} had room");
            }
        }
        assert_eq!(next, prefixes.len());
    }

    #[test]
    fn ipv6_and_withdrawals_and_end_of_rib() {
        let v6: Vec<Prefix> = (0..3000u16)
            .map(|i| {
                Prefix::new(Ipv6Addr::new(0x2001, 0xdb8, i, 0, 0, 0, 0, 0).into(), 48).unwrap()
            })
            .collect();
        let set = AttrSet {
            attributes: table(1, 1).sets[0].attributes.clone(),
            next_hop: NextHop::Ipv6 {
                global: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                link_local: None,
            },
        };
        let p = Packer::new(true, false);
        let mut out = Vec::new();
        p.announce(AddressFamily::IPV6_UNICAST, &set, &v6, &mut out)
            .unwrap();
        p.withdraw(AddressFamily::IPV6_UNICAST, &v6, &mut out)
            .unwrap();
        let v4: Vec<Prefix> = table(2000, 1).routes.iter().map(|r| r.prefix).collect();
        p.withdraw(AddressFamily::IPV4_UNICAST, &v4, &mut out)
            .unwrap();
        let (mut announced, mut withdrawn) = (0, 0);
        for m in &out {
            assert!(m.len() <= 4096);
            let d = decode(m, false);
            announced += d.announcements().count();
            withdrawn += d.withdrawals().count();
        }
        assert_eq!(announced, 3000);
        assert_eq!(withdrawn, 5000);

        let eor4 = decode(&p.end_of_rib(AddressFamily::IPV4_UNICAST).unwrap(), false);
        assert_eq!(eor4.message, UpdateMessage::default());
        let eor6 = decode(&p.end_of_rib(AddressFamily::IPV6_UNICAST).unwrap(), false);
        let un = eor6.message.mp_unreach.unwrap();
        assert_eq!(un.family, AddressFamily::IPV6_UNICAST);
        assert_eq!(un.withdrawn, Vec::new());
    }

    #[test]
    fn two_octet_sessions_encode_as4_path() {
        let t = table(100, 5);
        let p = Packer::new(false, false);
        let ctx = DecodeContext {
            four_octet_as: false,
            ..CTX
        };
        let mut n = 0;
        for m in p.table(&t).unwrap() {
            let d = UpdateMessage::decode(&m[HEADER_LEN..], &ctx).unwrap();
            n += d.announcements().count();
        }
        assert_eq!(n, 100);
    }

    #[test]
    fn oversized_attributes_are_refused() {
        let mut set = table(1, 1).sets[0].clone();
        set.attributes.push(PathAttribute::Unknown {
            flags: 0xc0,
            code: 99,
            value: vec![0; 4090],
        });
        let p = Packer::new(true, false);
        let prefix: Prefix = "192.0.2.0/24".parse().unwrap();
        let err = p
            .announce(
                AddressFamily::IPV4_UNICAST,
                &set,
                &[prefix],
                &mut Vec::new(),
            )
            .unwrap_err();
        assert!(matches!(err, PackError::NoRoom { .. }), "{err}");
    }
}
