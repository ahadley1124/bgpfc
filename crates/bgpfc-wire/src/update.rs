//! The UPDATE message, with RFC 7606 error handling.
//!
//! Decoding does not simply fail on a bad attribute. Following RFC 7606,
//! each problem is classified as one of:
//!
//! - **session reset**: the message cannot be trusted at all; the caller
//!   sends the NOTIFICATION in [`UpdateError`] and closes the session;
//! - **AFI/SAFI disable**: a multiprotocol attribute is unusable; the caller
//!   drops that family's routes from this peer (RFC 4760 §7) and uses the
//!   rest of the message ([`DecodedUpdate::disabled`]);
//! - **treat-as-withdraw**: every route the message announces is withdrawn
//!   instead ([`DecodedUpdate::treated_as_withdraw`]);
//! - **attribute discard**: the attribute is dropped and the rest of the
//!   message stands ([`DecodedUpdate::discarded`]).
//!
//! Implements: RFC 4271 §4.3 (format), §5 (attribute categories), §6.3
//! (error subcodes; a next hop is a valid IP host address); RFC 7606 §3,
//! §4, §5.1–§5.3, §7, §7.1–§7.8, §7.11, §7.12, §7.14; RFC 4760 §3 (the next
//! hop rules hold for `MP_REACH_NLRI`), §4, §7; RFC 6793 §4.2.2, §4.2.3,
//! §6; RFC 7607 §2;
//! RFC 9774 §3; RFC 8092 §6; RFC 8950 §3, §4 (IPv6 next hops for IPv4
//! NLRI, only when negotiated); RFC 7911 §3, §5 (a Path Identifier before
//! each NLRI tuple of the Withdrawn Routes field, the NLRI field,
//! `MP_REACH_NLRI` and `MP_UNREACH_NLRI`, only for the families and the
//! direction ADD-PATH was negotiated for); RFC 9234 §5 (a malformed Only to
//! Customer attribute is treat-as-withdraw); RFC 4724 §2 (the End-of-RIB
//! marker, built and recognised).

use std::fmt;
use std::net::Ipv4Addr;

use crate::as_path::AsPath;
use crate::attribute::{
    Aggregator, Origin, PathAttribute, RawAttribute, code, encode_attribute, expected_flags, flags,
    parse_raw,
};
use crate::community::{decode_communities, decode_extended_communities, decode_large_communities};
use crate::error::{DecodeError, EncodeError, UpdateSubcode};
use crate::mp::{MpReach, MpUnreach, NextHop, family_of, is_host_ipv4};
use crate::prefix::{
    Prefix, decode_prefixes, decode_prefixes_with_ids, encode_prefixes, encode_prefixes_with_ids,
};
use crate::reader::{Reader, WriteBytes as _};
use crate::types::{AddressFamily, Afi, Asn, PathId};

/// Whether the peer is in the local AS (RFC 4271 §5: it changes which
/// attributes are expected and which are ignored).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerKind {
    /// Internal BGP: same AS.
    Internal,
    /// External BGP: different AS.
    External,
}

/// The families of a session whose NLRI carries a Path Identifier ahead of
/// each prefix, in one direction (RFC 7911 §3, §5). Only IPv4 and IPv6
/// unicast, the families this implementation parses; the NLRI field and
/// `MP_REACH_NLRI` of IPv4 unicast alike follow the IPv4 entry.
///
/// NOTE(interop): RFC 7911 §3 extends "the NLRI encoding" of RFC 4271,
/// which RFC 4760 §5 reuses in both multiprotocol attributes, and §5 does
/// not list the fields. BIRD and FRR extend them all for a family with
/// ADD-PATH and none for any other (`tests/captures.rs` has BIRD's NLRI
/// and Withdrawn Routes fields and `MP_UNREACH_NLRI`), and so does this.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct AddPathFamilies {
    ipv4_unicast: bool,
    ipv6_unicast: bool,
}

impl AddPathFamilies {
    /// No family: the encoding of RFC 4271 §4.3 throughout.
    pub const NONE: AddPathFamilies = AddPathFamilies {
        ipv4_unicast: false,
        ipv6_unicast: false,
    };

    /// Exactly the families of `families` that this implementation
    /// parses.
    #[must_use]
    pub fn of(families: &[AddressFamily]) -> AddPathFamilies {
        AddPathFamilies {
            ipv4_unicast: families.contains(&AddressFamily::IPV4_UNICAST),
            ipv6_unicast: families.contains(&AddressFamily::IPV6_UNICAST),
        }
    }

    /// Whether NLRI of `family` carries Path Identifiers.
    #[must_use]
    pub const fn contains(self, family: AddressFamily) -> bool {
        match family {
            AddressFamily::IPV4_UNICAST => self.ipv4_unicast,
            AddressFamily::IPV6_UNICAST => self.ipv6_unicast,
            _ => false,
        }
    }

    /// Whether no family does.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        !self.ipv4_unicast && !self.ipv6_unicast
    }
}

/// What the decoder needs to know about the session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodeContext {
    /// Both sides advertised the Four-octet AS capability (RFC 6793 §3):
    /// `AS_PATH` and AGGREGATOR carry four-octet ASNs, and `AS4_PATH` /
    /// `AS4_AGGREGATOR` must not appear.
    pub four_octet_as: bool,
    /// Internal or external session.
    pub peer: PeerKind,
    /// Accept `AS_SET` segments. RFC 9774 §3 deprecates them and requires
    /// treat-as-withdraw unless an operator explicitly configures otherwise.
    pub allow_as_set: bool,
    /// We advertised Extended Next Hop Encoding for IPv4 unicast with an
    /// IPv6 next hop (RFC 8950 §4), which tells the peer we take one,
    /// whether or not it advertised the capability too: an IPv4 unicast
    /// `MP_REACH_NLRI` may carry a 16- or 32-octet IPv6 next hop (§3).
    /// Without it four octets are the only length expected, and any other
    /// makes the attribute malformed (RFC 7606 §7.11).
    pub extended_next_hop: bool,
    /// The families the peer sends us routes of with Path Identifiers: we
    /// advertised the ADD-PATH capability to receive them and the peer to
    /// send them (RFC 7911 §5). Their Withdrawn Routes, NLRI and
    /// `MP_REACH_NLRI` / `MP_UNREACH_NLRI` use the extended NLRI encoding
    /// (§3); the NLRI of any other family does not.
    pub add_path: AddPathFamilies,
}

/// What the encoder needs to know about the session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncodeContext {
    /// Both sides advertised the Four-octet AS capability. When false,
    /// `AS_PATH` and AGGREGATOR are two-octet with `AS_TRANS` and the
    /// `AS4_*` attributes are generated as RFC 6793 §4.2.2 requires.
    pub four_octet_as: bool,
    /// The peer advertised Extended Next Hop Encoding for IPv4 unicast
    /// (RFC 8950 §4), and we may send it IPv4 NLRI with an IPv6 next hop.
    /// When false, such NLRI is an [`EncodeError`], so the peer is never
    /// sent what it did not agree to take.
    pub extended_next_hop: bool,
    /// The families we send the peer routes of with Path Identifiers: we
    /// advertised the ADD-PATH capability to send them and the peer to
    /// receive them (RFC 7911 §5). The message must carry an identifier
    /// for every prefix of these families and none for any other, so that
    /// the peer is never sent an encoding it did not agree to take.
    pub add_path: AddPathFamilies,
}

/// An UPDATE message body.
///
/// IPv4 unicast routes travel in the RFC 4271 fields (`withdrawn`, `nlri`);
/// every other family in the multiprotocol attributes. `attributes` never
/// holds `MpReach` or `MpUnreach`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UpdateMessage {
    /// Withdrawn Routes: IPv4 unicast prefixes no longer reachable.
    pub withdrawn: Vec<Prefix>,
    /// Network Layer Reachability Information: IPv4 unicast prefixes that
    /// share `attributes`.
    pub nlri: Vec<Prefix>,
    /// `MP_REACH_NLRI`, if present.
    pub mp_reach: Option<MpReach>,
    /// `MP_UNREACH_NLRI`, if present.
    pub mp_unreach: Option<MpUnreach>,
    /// All other path attributes, at most one per type code.
    pub attributes: Vec<PathAttribute>,
    /// The Path Identifiers that go with the prefixes of the four lists
    /// above (RFC 7911 §3); `None` on a session, or for a message, with no
    /// ADD-PATH family, so that no UPDATE costs anything for the feature
    /// unless it is in use.
    pub path_ids: Option<Box<PathIds>>,
}

/// The Path Identifiers of an UPDATE's NLRI, beside the lists they belong
/// to (RFC 7911 §3): each list is either empty, for a field without
/// identifiers, or as long as its prefix list, `[i]` being the identifier
/// of prefix `i`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PathIds {
    /// Of [`UpdateMessage::withdrawn`].
    pub withdrawn: Vec<PathId>,
    /// Of [`UpdateMessage::nlri`].
    pub nlri: Vec<PathId>,
    /// Of [`MpReach::nlri`].
    pub mp_reach: Vec<PathId>,
    /// Of [`MpUnreach::withdrawn`].
    pub mp_unreach: Vec<PathId>,
}

impl PathIds {
    /// Whether no list holds an identifier.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.withdrawn.is_empty()
            && self.nlri.is_empty()
            && self.mp_reach.is_empty()
            && self.mp_unreach.is_empty()
    }
}

/// Identifiers `ids` holds for a prefix list, if it holds any.
fn ids_of(ids: Option<&PathIds>, list: impl FnOnce(&PathIds) -> &[PathId]) -> &[PathId] {
    ids.map_or(&[], list)
}

impl UpdateMessage {
    /// The Path Identifiers of [`UpdateMessage::withdrawn`]; empty when it
    /// has none (RFC 7911 §3).
    #[must_use]
    pub fn withdrawn_ids(&self) -> &[PathId] {
        ids_of(self.path_ids.as_deref(), |i| &i.withdrawn)
    }

    /// The Path Identifiers of [`UpdateMessage::nlri`]; empty when it has
    /// none.
    #[must_use]
    pub fn nlri_ids(&self) -> &[PathId] {
        ids_of(self.path_ids.as_deref(), |i| &i.nlri)
    }

    /// The Path Identifiers of the `MP_REACH_NLRI` prefixes; empty when
    /// they have none.
    #[must_use]
    pub fn mp_reach_ids(&self) -> &[PathId] {
        ids_of(self.path_ids.as_deref(), |i| &i.mp_reach)
    }

    /// The Path Identifiers of the `MP_UNREACH_NLRI` prefixes; empty when
    /// they have none.
    #[must_use]
    pub fn mp_unreach_ids(&self) -> &[PathId] {
        ids_of(self.path_ids.as_deref(), |i| &i.mp_unreach)
    }

    /// The attribute with type `code`, if present.
    #[must_use]
    pub fn attribute(&self, code: u8) -> Option<&PathAttribute> {
        self.attributes.iter().find(|a| a.code() == code)
    }

    /// ORIGIN, if present.
    #[must_use]
    pub fn origin(&self) -> Option<Origin> {
        match self.attribute(code::ORIGIN) {
            Some(PathAttribute::Origin(o)) => Some(*o),
            _ => None,
        }
    }

    /// `AS_PATH`, if present.
    #[must_use]
    pub fn as_path(&self) -> Option<&AsPath> {
        match self.attribute(code::AS_PATH) {
            Some(PathAttribute::AsPath(p)) => Some(p),
            _ => None,
        }
    }

    /// `NEXT_HOP`, if present.
    #[must_use]
    pub fn next_hop(&self) -> Option<Ipv4Addr> {
        match self.attribute(code::NEXT_HOP) {
            Some(PathAttribute::NextHop(a)) => Some(*a),
            _ => None,
        }
    }

    /// The End-of-RIB marker for `family` (RFC 4724 §2): for IPv4 unicast
    /// "an UPDATE message with the minimum length", with no withdrawn
    /// routes, attributes or NLRI; for any other family "an UPDATE message
    /// that contains only the `MP_UNREACH_NLRI` attribute with no withdrawn
    /// routes for that <AFI, SAFI>".
    #[must_use]
    pub fn end_of_rib(family: AddressFamily) -> UpdateMessage {
        if family == AddressFamily::IPV4_UNICAST {
            return UpdateMessage::default();
        }
        UpdateMessage {
            mp_unreach: Some(MpUnreach {
                family,
                withdrawn: Vec::new(),
            }),
            ..UpdateMessage::default()
        }
    }

    /// The family this UPDATE is the End-of-RIB marker of, if it is one
    /// (RFC 4724 §2): it withdraws and announces nothing. The empty UPDATE
    /// is IPv4 unicast's; one with only an empty `MP_UNREACH_NLRI` is that
    /// attribute's family's.
    ///
    /// NOTE(interop): an empty `MP_UNREACH_NLRI` for IPv4 unicast is taken
    /// as IPv4 unicast's marker too, as RFC 4724 §2 names none but the
    /// minimum-length UPDATE for it and a sender using the attribute for
    /// every family means the same.
    #[must_use]
    pub fn end_of_rib_family(&self) -> Option<AddressFamily> {
        // The cheap tests first: an UPDATE with NLRI, the usual one, is out
        // after the first.
        if !self.nlri.is_empty()
            || !self.withdrawn.is_empty()
            || self.mp_reach.is_some()
            || !self.attributes.is_empty()
        {
            return None;
        }
        match &self.mp_unreach {
            None => Some(AddressFamily::IPV4_UNICAST),
            Some(u) if u.withdrawn.is_empty() => Some(u.family),
            Some(_) => None,
        }
    }

    /// Whether the message announces anything (RFC 4271 §5: only then are
    /// the mandatory attributes required).
    #[must_use]
    pub fn has_reachable(&self) -> bool {
        !self.nlri.is_empty() || self.mp_reach.is_some()
    }

    /// Encode the body (RFC 4271 §4.3).
    ///
    /// Attributes are written in ascending type order (RFC 4271 §5 SHOULD)
    /// except that `MP_REACH_NLRI` / `MP_UNREACH_NLRI` come first (RFC 7606
    /// §5.1 SHALL). With a two-octet peer, `AS4_PATH` and `AS4_AGGREGATOR`
    /// are added when the path or aggregator holds a non-mappable ASN
    /// (RFC 6793 §4.2.2).
    ///
    /// # Errors
    /// [`EncodeError`] if a field exceeds its length field, an `AS_PATH`
    /// segment cannot be encoded, or IPv4 NLRI has an IPv6 next hop for a
    /// peer that did not advertise RFC 8950 Extended Next Hop Encoding.
    pub fn encode(&self, ctx: &EncodeContext) -> Result<Vec<u8>, EncodeError> {
        let v4 = AddressFamily::IPV4_UNICAST;
        // RFC 7911 §5: the extended encoding for the families negotiated
        // for it and the plain one for the rest, never a mixture.
        check_ids(ctx.add_path, v4, &self.withdrawn, self.withdrawn_ids())?;
        check_ids(ctx.add_path, v4, &self.nlri, self.nlri_ids())?;
        let mut withdrawn = Vec::new();
        encode_field(
            ctx.add_path.contains(v4),
            &self.withdrawn,
            self.withdrawn_ids(),
            &mut withdrawn,
        );
        let withdrawn_len = u16::try_from(withdrawn.len()).map_err(|_| EncodeError::TooLong {
            what: "withdrawn routes",
            len: withdrawn.len(),
            max: usize::from(u16::MAX),
        })?;

        let mut encoded: Vec<(u8, Vec<u8>)> = Vec::with_capacity(self.attributes.len() + 4);
        if let Some(m) = &self.mp_reach {
            // RFC 8950 §4: IPv4 NLRI goes with an IPv6 next hop only to a
            // peer that advertised Extended Next Hop Encoding for it.
            if m.family.afi == Afi::Ipv4
                && matches!(m.next_hop, NextHop::Ipv6 { .. })
                && !ctx.extended_next_hop
            {
                return Err(EncodeError::NextHopNotNegotiated(m.family));
            }
            check_ids(ctx.add_path, m.family, &m.nlri, self.mp_reach_ids())?;
            let mut value = Vec::new();
            m.encode_with(self.mp_reach_ids(), &mut value);
            let mut buf = Vec::new();
            encode_attribute(flags::OPTIONAL, code::MP_REACH_NLRI, &value, &mut buf)?;
            encoded.push((0, buf));
        }
        if let Some(m) = &self.mp_unreach {
            check_ids(ctx.add_path, m.family, &m.withdrawn, self.mp_unreach_ids())?;
            let mut value = Vec::new();
            m.encode_with(self.mp_unreach_ids(), &mut value);
            let mut buf = Vec::new();
            encode_attribute(flags::OPTIONAL, code::MP_UNREACH_NLRI, &value, &mut buf)?;
            encoded.push((0, buf));
        }
        for attr in &self.attributes {
            let mut buf = Vec::new();
            attr.encode(ctx.four_octet_as, &mut buf)?;
            encoded.push((attr.code(), buf));
            if !ctx.four_octet_as
                && let Some(extra) = as4_companion(attr)?
            {
                encoded.push(extra);
            }
        }
        encoded.sort_by_key(|(code, _)| *code);
        let attrs_len: usize = encoded.iter().map(|(_, b)| b.len()).sum();
        let attrs_len = u16::try_from(attrs_len).map_err(|_| EncodeError::TooLong {
            what: "path attributes",
            len: attrs_len,
            max: usize::from(u16::MAX),
        })?;

        let mut out = Vec::with_capacity(4 + withdrawn.len() + usize::from(attrs_len) + 32);
        out.put_u16(withdrawn_len);
        out.put_bytes(&withdrawn);
        out.put_u16(attrs_len);
        for (_, b) in &encoded {
            out.put_bytes(b);
        }
        encode_field(
            ctx.add_path.contains(v4),
            &self.nlri,
            self.nlri_ids(),
            &mut out,
        );
        Ok(out)
    }

    /// Decode a body (the octets after the header, at least four).
    ///
    /// # Errors
    /// [`UpdateError`] when RFC 7606 calls for a session reset. AFI/SAFI
    /// disable, treat-as-withdraw and attribute discard are not errors:
    /// the rest of the message is still decoded; see [`DecodedUpdate`].
    pub fn decode(body: &[u8], ctx: &DecodeContext) -> Result<DecodedUpdate, UpdateError> {
        #[cfg(feature = "profiling")]
        let _span = bgpfc_prof::Timer::start(&bgpfc_prof::metrics::MSG_PARSE_UPDATE);
        let (withdrawn_bytes, attr_bytes, nlri_bytes) = split_fields(body)?;
        // RFC 7606 §3 i) and §5.3: both prefix fields are checked for syntax,
        // and RFC 7606 §3 j): if the NLRI cannot be parsed, treat-as-withdraw
        // is impossible, so RFC 4271 §6.3 Invalid Network Field resets.
        // RFC 7911 §5: both fields of IPv4 unicast carry Path Identifiers
        // when it was negotiated for it.
        let with_ids = ctx.add_path.contains(AddressFamily::IPV4_UNICAST);
        let invalid = |_| UpdateError::reset(UpdateSubcode::InvalidNetworkField, Vec::new());
        let (withdrawn, withdrawn_ids) =
            decode_field(withdrawn_bytes, with_ids).map_err(invalid)?;
        let (nlri, nlri_ids) = decode_field(nlri_bytes, with_ids).map_err(invalid)?;
        let mut st = State::default();
        decode_attributes(attr_bytes, *ctx, !nlri.is_empty(), &mut st)?;
        apply_as4(&mut st, *ctx);
        // RFC 4271 §5: any order is accepted; ascending type order is the
        // canonical form, so equal messages compare equal.
        st.attributes.sort_by_key(PathAttribute::code);
        let ids = PathIds {
            withdrawn: withdrawn_ids,
            nlri: nlri_ids,
            mp_reach: std::mem::take(&mut st.mp_reach_ids),
            mp_unreach: std::mem::take(&mut st.mp_unreach_ids),
        };
        let message = UpdateMessage {
            withdrawn,
            nlri,
            mp_reach: st.mp_reach.take(),
            mp_unreach: st.mp_unreach.take(),
            attributes: std::mem::take(&mut st.attributes),
            path_ids: (!ids.is_empty()).then(|| Box::new(ids)),
        };
        check_mandatory(&message, &mut st);
        // RFC 7606 §5.2: an UPDATE that "does contain path attributes other
        // than MP_UNREACH_NLRI and doesn't encode any reachable NLRI" cannot
        // be trusted to have had its NLRI parsed, so any error there that is
        // not attribute discard resets the session. An MP_REACH_NLRI encodes
        // reachable NLRI even when it was too broken to decode.
        let reachable = message.has_reachable() || st.reach;
        if !reachable
            && st.other_attributes
            && let Some(notification) = st
                .disabled
                .first()
                .map(|d| d.error.clone())
                .or_else(|| st.withdraw.clone())
        {
            return Err(UpdateError { notification });
        }
        Ok(DecodedUpdate {
            message,
            treated_as_withdraw: st.withdraw,
            discarded: st.discarded,
            disabled: st.disabled,
        })
    }
}

/// RFC 7911 §5: whether the Path Identifiers `ids` of a list of `family`
/// prefixes are what the session negotiated: one per prefix for a family
/// with ADD-PATH, none for any other.
fn check_ids(
    add_path: AddPathFamilies,
    family: AddressFamily,
    prefixes: &[Prefix],
    ids: &[PathId],
) -> Result<(), EncodeError> {
    if add_path.contains(family) {
        if ids.len() == prefixes.len() {
            Ok(())
        } else {
            Err(EncodeError::PathIdsMissing(family))
        }
    } else if ids.is_empty() {
        Ok(())
    } else {
        Err(EncodeError::PathIdsNotNegotiated(family))
    }
}

/// Append a Withdrawn Routes or NLRI field, in the extended encoding when
/// `with_ids` (RFC 7911 §3).
fn encode_field(with_ids: bool, prefixes: &[Prefix], ids: &[PathId], out: &mut Vec<u8>) {
    if with_ids {
        encode_prefixes_with_ids(prefixes, ids, out);
    } else {
        encode_prefixes(prefixes, out);
    }
}

/// Decode a Withdrawn Routes or NLRI field of IPv4 unicast, in the
/// extended encoding when `with_ids` (RFC 7911 §3); the identifiers are
/// empty without it.
fn decode_field(
    bytes: &[u8],
    with_ids: bool,
) -> Result<(Vec<Prefix>, Vec<PathId>), crate::prefix::NlriError> {
    if with_ids {
        decode_prefixes_with_ids(bytes, Afi::Ipv4)
    } else {
        Ok((decode_prefixes(bytes, Afi::Ipv4)?, Vec::new()))
    }
}

/// The `AS4_PATH` or `AS4_AGGREGATOR` a two-octet session needs alongside
/// `attr`, if any (RFC 6793 §4.2.2).
fn as4_companion(attr: &PathAttribute) -> Result<Option<(u8, Vec<u8>)>, EncodeError> {
    let mut value = Vec::new();
    let code = match attr {
        PathAttribute::AsPath(p) if p.has_non_mappable() => {
            // RFC 6793 §4.2.2: confederation segments are excluded.
            p.without_confed().encode(true, &mut value)?;
            code::AS4_PATH
        }
        PathAttribute::Aggregator(a) if !a.asn.is_mappable() => {
            value.put_u32(a.asn.0);
            value.put_bytes(&a.address.octets());
            code::AS4_AGGREGATOR
        }
        _ => return Ok(None),
    };
    let mut buf = Vec::new();
    encode_attribute(flags::OPTIONAL | flags::TRANSITIVE, code, &value, &mut buf)?;
    Ok(Some((code, buf)))
}

/// The three variable fields of a body: withdrawn routes, path attributes,
/// NLRI (RFC 4271 §4.3).
type Fields<'a> = (&'a [u8], &'a [u8], &'a [u8]);

/// Split the body into its three variable fields (RFC 4271 §4.3).
fn split_fields(body: &[u8]) -> Result<Fields<'_>, UpdateError> {
    // RFC 7606 §3 b) (unchanged from RFC 4271 §6.3): lengths that overrun
    // the message are Malformed Attribute List.
    let overrun = || UpdateError::reset(UpdateSubcode::MalformedAttributeList, Vec::new());
    let mut r = Reader::new(body);
    let withdrawn_len = r.u16().map_err(|_| overrun())?;
    let withdrawn = r.take(usize::from(withdrawn_len)).map_err(|_| overrun())?;
    let attrs_len = r.u16().map_err(|_| overrun())?;
    let attrs = r.take(usize::from(attrs_len)).map_err(|_| overrun())?;
    Ok((withdrawn, attrs, r.rest()))
}

/// Attributes collected while parsing, plus the strongest non-fatal
/// outcome seen so far.
#[derive(Default)]
struct State {
    attributes: Vec<PathAttribute>,
    mp_reach: Option<MpReach>,
    mp_unreach: Option<MpUnreach>,
    /// The Path Identifiers of those two (RFC 7911 §3).
    mp_reach_ids: Vec<PathId>,
    mp_unreach_ids: Vec<PathId>,
    as4_path: Option<AsPath>,
    as4_aggregator: Option<Aggregator>,
    /// Bitset of attribute type codes already seen.
    seen: [u64; 4],
    /// First treat-as-withdraw error, if any (RFC 7606 §3 h): all of them
    /// have the same strength, so the first is reported).
    withdraw: Option<DecodeError>,
    discarded: Vec<DiscardedAttribute>,
    /// Families of incorrect MP attributes (RFC 4760 §7), each once.
    disabled: Vec<DisabledFamily>,
    /// An `MP_REACH_NLRI` was present, decoded or not (RFC 7606 §5.2).
    reach: bool,
    /// Something other than `MP_UNREACH_NLRI` was in the attribute field
    /// (RFC 7606 §5.2), unparseable octets included.
    other_attributes: bool,
}

impl State {
    /// Mark `code` seen; returns whether it had been seen before.
    fn mark_seen(&mut self, code: u8) -> bool {
        let word = &mut self.seen[usize::from(code / 64)];
        let bit = 1u64 << (code % 64);
        let seen = *word & bit != 0;
        *word |= bit;
        seen
    }

    fn withdraw(&mut self, e: DecodeError) {
        self.withdraw.get_or_insert(e);
    }

    /// Keep a decoded attribute: the MP ones apart, with their Path
    /// Identifiers `ids`.
    fn keep(&mut self, a: PathAttribute, ids: Vec<PathId>, raw: &RawAttribute<'_>, nlri: bool) {
        if let Some(e) = invalid_next_hop(&a, raw, nlri) {
            self.withdraw(e);
        }
        match a {
            PathAttribute::MpReach(m) => {
                self.mp_reach = Some(m);
                self.mp_reach_ids = ids;
            }
            PathAttribute::MpUnreach(m) => {
                self.mp_unreach = Some(m);
                self.mp_unreach_ids = ids;
            }
            a => self.attributes.push(a),
        }
    }

    fn discard(&mut self, code: u8, reason: DiscardReason) {
        self.discarded.push(DiscardedAttribute { code, reason });
    }

    fn disable(&mut self, d: DisabledFamily) {
        if !self.disabled.iter().any(|x| x.family == d.family) {
            self.disabled.push(d);
        }
    }
}

/// What one attribute turned out to be.
enum Outcome {
    Keep(PathAttribute),
    /// An MP attribute, with the Path Identifiers of its NLRI (RFC 7911
    /// §3), which are empty for a family without ADD-PATH.
    KeepMp(PathAttribute, Vec<PathId>),
    As4Path(AsPath),
    As4Aggregator(Aggregator),
    /// Unrecognised optional non-transitive: quietly ignored (RFC 4271 §5).
    Ignore,
    Discard(DiscardReason),
    Withdraw(DecodeError),
    /// An incorrect MP attribute: its family is disabled (RFC 4760 §7).
    Disable(DisabledFamily),
}

/// Decode the path attributes into `st`. `nlri_field`: the NLRI field
/// carries routes, which `NEXT_HOP` is for.
fn decode_attributes(
    bytes: &[u8],
    ctx: DecodeContext,
    nlri_field: bool,
    st: &mut State,
) -> Result<(), UpdateError> {
    #[cfg(feature = "profiling")]
    let _span = bgpfc_prof::Timer::start(&bgpfc_prof::metrics::ATTR_PARSE);
    let mut r = Reader::new(bytes);
    while !r.is_empty() {
        let Ok(raw) = parse_raw(&mut r) else {
            // RFC 7606 §4: an attribute header or length inconsistent with
            // the Total Path Attribute Length is treat-as-withdraw; the
            // remaining attributes cannot be located.
            st.withdraw(DecodeError::update(
                UpdateSubcode::MalformedAttributeList,
                Vec::new(),
            ));
            st.other_attributes = true;
            break;
        };
        st.reach |= raw.code == code::MP_REACH_NLRI;
        st.other_attributes |= raw.code != code::MP_UNREACH_NLRI;
        if st.mark_seen(raw.code) {
            // RFC 7606 §3 g): a repeated MP attribute resets; any other
            // repeat is discarded after the first occurrence.
            if matches!(raw.code, code::MP_REACH_NLRI | code::MP_UNREACH_NLRI) {
                return Err(UpdateError::reset(
                    UpdateSubcode::MalformedAttributeList,
                    raw.raw.to_vec(),
                ));
            }
            st.discard(raw.code, DiscardReason::Duplicate);
            continue;
        }
        match decode_one(&raw, ctx)? {
            Outcome::Keep(a) => st.keep(a, Vec::new(), &raw, nlri_field),
            Outcome::KeepMp(a, ids) => st.keep(a, ids, &raw, nlri_field),
            Outcome::As4Path(p) => st.as4_path = Some(p),
            Outcome::As4Aggregator(a) => st.as4_aggregator = Some(a),
            Outcome::Ignore => {}
            Outcome::Discard(reason) => st.discard(raw.code, reason),
            Outcome::Withdraw(e) => st.withdraw(e),
            // RFC 7606 §3 h) and j): AFI/SAFI disable for that family; the
            // rest of the message is still decoded, so that a second
            // incorrect MP attribute disables its family too and the other
            // families' routes are not lost with the message.
            Outcome::Disable(d) => st.disable(d),
        }
    }
    Ok(())
}

/// Classify and decode one attribute. `Err` is a session reset; everything
/// milder is an [`Outcome`].
fn decode_one(raw: &RawAttribute<'_>, ctx: DecodeContext) -> Result<Outcome, UpdateError> {
    let Some(expected) = expected_flags(raw.code) else {
        return unknown_attribute(raw);
    };
    if raw.category_bits() != expected {
        // RFC 7606 §3 c): Optional/Transitive bits in conflict are
        // treat-as-withdraw, unless the attribute's own rule is milder
        // (§3 f: discard for ATOMIC_AGGREGATE and AGGREGATOR; RFC 6793 §6:
        // discard for AS4_*), or it is an MP attribute (§5.3: incorrect).
        let e = DecodeError::update(UpdateSubcode::AttributeFlagsError, raw.raw.to_vec());
        return Ok(match raw.code {
            code::ATOMIC_AGGREGATE | code::AGGREGATOR | code::AS4_PATH | code::AS4_AGGREGATOR => {
                Outcome::Discard(DiscardReason::Malformed(e))
            }
            code::MP_REACH_NLRI | code::MP_UNREACH_NLRI => mp_failure(raw, None)?,
            _ => Outcome::Withdraw(e),
        });
    }
    let length_error = || {
        Outcome::Withdraw(DecodeError::update(
            UpdateSubcode::AttributeLengthError,
            raw.raw.to_vec(),
        ))
    };
    let v = raw.value;
    Ok(match raw.code {
        // RFC 7606 §7.1.
        code::ORIGIN => match v {
            [o] => match Origin::from_u8(*o) {
                Some(o) => Outcome::Keep(PathAttribute::Origin(o)),
                None => Outcome::Withdraw(DecodeError::update(
                    UpdateSubcode::InvalidOrigin,
                    raw.raw.to_vec(),
                )),
            },
            _ => length_error(),
        },
        code::AS_PATH => decode_as_path(raw, ctx.four_octet_as, ctx.allow_as_set),
        // RFC 7606 §7.3: the length. Whether it is a host address is
        // `invalid_next_hop`'s; the semantic checks of RFC 4271 §6.3 are
        // the RIB's (log and ignore the route, never reset).
        code::NEXT_HOP => match <[u8; 4]>::try_from(v) {
            Ok(octets) => Outcome::Keep(PathAttribute::NextHop(Ipv4Addr::from(octets))),
            Err(_) => length_error(),
        },
        // RFC 7606 §7.4.
        code::MULTI_EXIT_DISC => match u32_value(v) {
            Some(m) => Outcome::Keep(PathAttribute::MultiExitDisc(m)),
            None => length_error(),
        },
        // RFC 7606 §7.5; RFC 4271 §5.1.5.
        code::LOCAL_PREF if ctx.peer == PeerKind::External => {
            Outcome::Discard(DiscardReason::FromExternalPeer)
        }
        code::LOCAL_PREF => match u32_value(v) {
            Some(l) => Outcome::Keep(PathAttribute::LocalPref(l)),
            None => length_error(),
        },
        // RFC 7606 §7.6.
        code::ATOMIC_AGGREGATE if v.is_empty() => Outcome::Keep(PathAttribute::AtomicAggregate),
        code::ATOMIC_AGGREGATE => discard_malformed(raw),
        // RFC 7606 §7.7; RFC 7607 §2 (AS 0) with §3 f) discard.
        code::AGGREGATOR => match decode_aggregator(v, ctx.four_octet_as) {
            Some(a) if a.asn != Asn(0) => Outcome::Keep(PathAttribute::Aggregator(a)),
            _ => discard_malformed(raw),
        },
        // RFC 7606 §7.8.
        code::COMMUNITIES => match decode_communities(v) {
            Ok(cs) => Outcome::Keep(PathAttribute::Communities(cs)),
            Err(_) => length_error(),
        },
        code::MP_REACH_NLRI => match MpReach::decode_with(v, ctx.extended_next_hop, ctx.add_path) {
            Ok((m, ids)) => Outcome::KeepMp(PathAttribute::MpReach(m), ids),
            Err(e) => mp_failure(raw, e.family())?,
        },
        code::MP_UNREACH_NLRI => match MpUnreach::decode_with(v, ctx.add_path) {
            Ok((m, ids)) => Outcome::KeepMp(PathAttribute::MpUnreach(m), ids),
            Err(e) => mp_failure(raw, e.family())?,
        },
        // RFC 7606 §7.14.
        code::EXTENDED_COMMUNITIES => match decode_extended_communities(v) {
            Ok(cs) => Outcome::Keep(PathAttribute::ExtendedCommunities(cs)),
            Err(_) => length_error(),
        },
        // RFC 8092 §6.
        code::LARGE_COMMUNITIES => match decode_large_communities(v) {
            Ok(cs) => Outcome::Keep(PathAttribute::LargeCommunities(cs)),
            Err(_) => length_error(),
        },
        // RFC 9234 §5: "The OTC Attribute is considered malformed if the
        // length value is not 4. An UPDATE message with a malformed OTC
        // Attribute SHALL be handled using the approach of
        // 'treat-as-withdraw'", with RFC 7606 §7's Attribute Length Error.
        // The value is an AS number and kept whatever it is: the RFC names
        // no check on it, and "once the OTC Attribute has been set, it MUST
        // be preserved unchanged".
        // NOTE(interop): FRR 8.4 treats a value of 0 as malformed
        // (treat-as-withdraw); BIRD 2.14 and RFC 9234 §5 do not. Following
        // the RFC, it is kept; from a peer it is a leak anyway, as no AS 0
        // is a peer's.
        code::ONLY_TO_CUSTOMER => match u32_value(v) {
            Some(a) => Outcome::Keep(PathAttribute::OnlyToCustomer(Asn(a))),
            None => length_error(),
        },
        // RFC 6793 §6: AS4_* from a NEW speaker are discarded; otherwise a
        // malformed one is discarded too.
        code::AS4_PATH | code::AS4_AGGREGATOR if ctx.four_octet_as => {
            Outcome::Discard(DiscardReason::FromNewSpeaker)
        }
        code::AS4_PATH => decode_as4_path(raw, ctx.allow_as_set),
        code::AS4_AGGREGATOR => match decode_aggregator(v, true) {
            Some(a) if a.asn != Asn(0) => Outcome::As4Aggregator(a),
            _ => discard_malformed(raw),
        },
        // `expected_flags` knows no other codes.
        _ => Outcome::Ignore,
    })
}

/// RFC 4271 §5 and §6.3 for a type code this implementation does not know.
fn unknown_attribute(raw: &RawAttribute<'_>) -> Result<Outcome, UpdateError> {
    if raw.flags & flags::OPTIONAL == 0 {
        // RFC 4271 §6.3: an unrecognised well-known attribute resets;
        // RFC 7606 leaves this case unchanged.
        return Err(UpdateError::reset(
            UpdateSubcode::UnrecognizedWellKnownAttribute,
            raw.raw.to_vec(),
        ));
    }
    if raw.flags & flags::TRANSITIVE == 0 {
        // RFC 4271 §5: unrecognised non-transitive optional attributes are
        // quietly ignored.
        return Ok(Outcome::Ignore);
    }
    // RFC 4271 §5: unrecognised transitive optional attributes are kept and
    // passed on with the Partial bit set. RFC 4271 §4.3: the low-order four
    // flag bits are ignored on receipt, and Extended Length is a property
    // of the encoding, so only the category bits and Partial are kept.
    Ok(Outcome::Keep(PathAttribute::Unknown {
        flags: raw.flags & (flags::OPTIONAL | flags::TRANSITIVE | flags::PARTIAL),
        code: raw.code,
        value: raw.value.to_vec(),
    }))
}

fn decode_as_path(raw: &RawAttribute<'_>, four_octet: bool, allow_as_set: bool) -> Outcome {
    let malformed = || {
        Outcome::Withdraw(DecodeError::update(
            UpdateSubcode::MalformedAsPath,
            raw.raw.to_vec(),
        ))
    };
    match AsPath::decode(raw.value, four_octet) {
        // RFC 7606 §7.2.
        Err(_) => malformed(),
        // RFC 7607 §2: AS 0 is malformed, handled per RFC 7606 §3 e).
        Ok(p) if p.contains_as0() => malformed(),
        // RFC 9774 §3: AS_SET is treat-as-withdraw unless configured.
        Ok(p) if p.contains_set() && !allow_as_set => malformed(),
        Ok(p) => Outcome::Keep(PathAttribute::AsPath(p)),
    }
}

fn decode_as4_path(raw: &RawAttribute<'_>, allow_as_set: bool) -> Outcome {
    match AsPath::decode(raw.value, true) {
        // RFC 6793 §6: malformed AS4_PATH is discarded; RFC 7607 §2 routes
        // AS 0 in AS4_PATH to the same procedure.
        Err(_) => discard_malformed(raw),
        Ok(p) if p.contains_as0() => discard_malformed(raw),
        // RFC 9774 §3 names AS4_PATH explicitly: treat-as-withdraw.
        Ok(p) if p.contains_set() && !allow_as_set => Outcome::Withdraw(DecodeError::update(
            UpdateSubcode::MalformedAsPath,
            raw.raw.to_vec(),
        )),
        // RFC 6793 §6: confederation segments are dropped, processing goes on.
        Ok(p) => Outcome::As4Path(p.without_confed()),
    }
}

/// RFC 4271 §6.3: a `NEXT_HOP` that is not a valid IP host address is
/// syntactically incorrect, an Invalid `NEXT_HOP` Attribute error with the
/// attribute as data; RFC 7606 §3 e) makes that treat-as-withdraw. RFC 4760
/// §3 gives the next hop of `MP_REACH_NLRI` the same rules, and RFC 7606 §7
/// asks for the same approach for checks it does not list, so it is
/// handled alike (the attribute's length was right, so its NLRI can be
/// withdrawn, unlike RFC 7606 §7.11's case). A next hop with no routes to
/// go with is not judged: RFC 4760 §3 has `NEXT_HOP` ignored when the NLRI
/// field is empty.
fn invalid_next_hop(
    a: &PathAttribute,
    raw: &RawAttribute<'_>,
    nlri_field: bool,
) -> Option<DecodeError> {
    let valid = match a {
        PathAttribute::NextHop(n) => !nlri_field || is_host_ipv4(*n),
        PathAttribute::MpReach(m) => m.nlri.is_empty() || m.next_hop.is_valid(),
        _ => true,
    };
    (!valid).then(|| DecodeError::update(UpdateSubcode::InvalidNextHop, raw.raw.to_vec()))
}

fn discard_malformed(raw: &RawAttribute<'_>) -> Outcome {
    Outcome::Discard(DiscardReason::Malformed(DecodeError::update(
        UpdateSubcode::OptionalAttributeError,
        raw.raw.to_vec(),
    )))
}

fn u32_value(v: &[u8]) -> Option<u32> {
    <[u8; 4]>::try_from(v).ok().map(u32::from_be_bytes)
}

/// AGGREGATOR value: ASN (two or four octets) then an IPv4 address
/// (RFC 4271 §4.3 g; RFC 6793 §3; RFC 7606 §7.7 lengths).
fn decode_aggregator(v: &[u8], four_octet: bool) -> Option<Aggregator> {
    let mut r = Reader::new(v);
    let asn = if four_octet {
        Asn(r.u32().ok()?)
    } else {
        Asn::from(r.u16().ok()?)
    };
    let address = Ipv4Addr::from(r.array::<4>().ok()?);
    r.is_empty().then_some(Aggregator { asn, address })
}

/// An MP attribute that cannot be used: AFI/SAFI disable when the family is
/// known (RFC 4760 §7, RFC 7606 §3 j), else a session reset, in both cases
/// with the NOTIFICATION RFC 4760 §7 names (UPDATE Message Error / Optional
/// Attribute Error).
fn mp_failure(
    raw: &RawAttribute<'_>,
    family: Option<AddressFamily>,
) -> Result<Outcome, UpdateError> {
    let error = DecodeError::update(UpdateSubcode::OptionalAttributeError, raw.raw.to_vec());
    match family.or_else(|| family_of(raw.value)) {
        Some(family) => Ok(Outcome::Disable(DisabledFamily { family, error })),
        None => Err(UpdateError {
            notification: error,
        }),
    }
}

/// Fold `AS4_PATH` / `AS4_AGGREGATOR` into `AS_PATH` / AGGREGATOR
/// (RFC 6793 §4.2.3).
fn apply_as4(st: &mut State, ctx: DecodeContext) {
    if ctx.four_octet_as {
        return;
    }
    let mut as4_path = st.as4_path.take();
    if let Some(as4_agg) = st.as4_aggregator.take() {
        let agg = st.attributes.iter_mut().find_map(|a| match a {
            PathAttribute::Aggregator(agg) => Some(agg),
            _ => None,
        });
        match agg {
            // RFC 6793 §4.2.3: AGGREGATOR not AS_TRANS means an OLD speaker
            // aggregated after the AS4 attributes were attached; both
            // AS4_AGGREGATOR and AS4_PATH are ignored.
            Some(agg) if agg.asn != Asn::TRANS => as4_path = None,
            Some(agg) => *agg = as4_agg,
            None => {}
        }
    }
    if let Some(as4) = as4_path {
        for a in &mut st.attributes {
            if let PathAttribute::AsPath(p) = a {
                *p = AsPath::merge_as4(p, &as4);
            }
        }
    }
}

/// RFC 4271 §5 / §6.3 and RFC 7606 §3 d): a missing well-known mandatory
/// attribute is treat-as-withdraw. `NEXT_HOP` is mandatory only for the
/// RFC 4271 NLRI field (RFC 4760 §3), and `LOCAL_PREF` is left to the RIB,
/// which defaults it for internal peers.
// NOTE(interop): BIRD and FRR accept an internal UPDATE without LOCAL_PREF
// and use the default preference; resetting or withdrawing would be
// stricter than the installed base.
fn check_mandatory(m: &UpdateMessage, st: &mut State) {
    if !m.has_reachable() {
        return;
    }
    let mut required = vec![code::ORIGIN, code::AS_PATH];
    if !m.nlri.is_empty() {
        required.push(code::NEXT_HOP);
    }
    for c in required {
        if m.attribute(c).is_none() {
            st.withdraw(DecodeError::update(
                UpdateSubcode::MissingWellKnownAttribute,
                vec![c],
            ));
            return;
        }
    }
}

/// An UPDATE that cannot be processed even as a withdraw: the caller sends
/// the NOTIFICATION and closes the session (RFC 7606 §2 "session reset").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateError {
    /// The NOTIFICATION to send.
    pub notification: DecodeError,
}

impl UpdateError {
    fn reset(subcode: UpdateSubcode, data: Vec<u8>) -> UpdateError {
        UpdateError {
            notification: DecodeError::update(subcode, data),
        }
    }
}

impl fmt::Display for UpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "session reset: {}", self.notification)
    }
}

/// A family to disable for the rest of the session because the UPDATE's
/// `MP_REACH_NLRI` or `MP_UNREACH_NLRI` for it was incorrect (RFC 4760 §7,
/// RFC 7606 §2 "AFI/SAFI disable"): the receiver drops every route of the
/// family it has from the peer and ignores the family from then on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisabledFamily {
    /// The family the attribute named.
    pub family: AddressFamily,
    /// UPDATE Message Error / Optional Attribute Error with the attribute
    /// as data: what RFC 4760 §7 has sent should the receiver reset the
    /// session instead, which it MAY. For the log.
    pub error: DecodeError,
}

impl std::error::Error for UpdateError {}

/// Why an attribute was dropped from an otherwise accepted UPDATE.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiscardReason {
    /// Malformed, and RFC 7606 or RFC 6793 chose "attribute discard".
    Malformed(DecodeError),
    /// A second occurrence of an attribute (RFC 7606 §3 g).
    Duplicate,
    /// `LOCAL_PREF` from an external peer (RFC 7606 §7.5).
    FromExternalPeer,
    /// `AS4_PATH` or `AS4_AGGREGATOR` on a four-octet session (RFC 6793 §6).
    FromNewSpeaker,
}

/// An attribute dropped under "attribute discard"; worth a log line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscardedAttribute {
    /// Attribute Type Code.
    pub code: u8,
    /// Why.
    pub reason: DiscardReason,
}

/// A successfully decoded UPDATE and what RFC 7606 made of it.
///
/// The approaches combine as RFC 7606 §3 h) has the strongest win: the
/// receiver first disables the families in `disabled`, whose routes the
/// rest of the message no longer counts, then applies the message, as a
/// withdrawal of everything it announces when `treated_as_withdraw` is set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DecodedUpdate {
    /// The message as received, after attribute discards and `AS4_*`
    /// merging. An incorrect MP attribute is not in it.
    pub message: UpdateMessage,
    /// Set when the message must be treated as a withdrawal of everything it
    /// announces (RFC 7606 §2 "treat-as-withdraw"); the error is for the log.
    pub treated_as_withdraw: Option<DecodeError>,
    /// Attributes dropped from `message`.
    pub discarded: Vec<DiscardedAttribute>,
    /// Families an incorrect MP attribute disabled (RFC 4760 §7), each
    /// once.
    pub disabled: Vec<DisabledFamily>,
}

/// The prefixes with their Path Identifiers `ids`, which are as many or
/// none; none are zero.
fn with_ids<'a>(
    prefixes: &'a [Prefix],
    ids: &'a [PathId],
) -> impl Iterator<Item = (Prefix, PathId)> + 'a {
    prefixes
        .iter()
        .enumerate()
        .map(|(i, p)| (*p, ids.get(i).copied().unwrap_or_default()))
}

impl DecodedUpdate {
    /// Whether this UPDATE disabled `family` (RFC 4760 §7).
    #[must_use]
    pub fn disables(&self, family: AddressFamily) -> bool {
        self.disabled.iter().any(|d| d.family == family)
    }

    /// Every route the receiver must withdraw: the withdrawn fields, plus
    /// the announced routes when treated as withdraw; none of a disabled
    /// family, which goes as a whole.
    pub fn withdrawals(&self) -> impl Iterator<Item = (AddressFamily, Prefix)> + '_ {
        self.withdrawn_paths()
            .map(|(family, prefix, _)| (family, prefix))
    }

    /// [`DecodedUpdate::withdrawals`] with the Path Identifier of each
    /// route (RFC 7911 §3), which is zero for a family without ADD-PATH.
    /// A route treated as withdrawn is withdrawn by the identifier it was
    /// announced with, as RFC 7606 §2 has it "treated as though the
    /// corresponding NLRI had been withdrawn".
    pub fn withdrawn_paths(&self) -> impl Iterator<Item = (AddressFamily, Prefix, PathId)> + '_ {
        let m = &self.message;
        let v4 = AddressFamily::IPV4_UNICAST;
        let taw = self.treated_as_withdraw.is_some();
        with_ids(&m.withdrawn, m.withdrawn_ids())
            .map(move |(p, id)| (v4, p, id))
            .chain(m.mp_unreach.iter().flat_map(|u| {
                with_ids(&u.withdrawn, m.mp_unreach_ids()).map(move |(p, id)| (u.family, p, id))
            }))
            .chain(
                with_ids(&m.nlri, m.nlri_ids())
                    .filter(move |_| taw)
                    .map(move |(p, id)| (v4, p, id)),
            )
            .chain(m.mp_reach.iter().filter(move |_| taw).flat_map(|r| {
                with_ids(&r.nlri, m.mp_reach_ids()).map(move |(p, id)| (r.family, p, id))
            }))
            .filter(move |(f, ..)| !self.disables(*f))
    }

    /// Every route the receiver may install with `message.attributes`;
    /// empty when treated as withdraw, and none of a disabled family.
    pub fn announcements(&self) -> impl Iterator<Item = (AddressFamily, Prefix)> + '_ {
        let m = &self.message;
        let keep = self.treated_as_withdraw.is_none();
        m.nlri
            .iter()
            .filter(move |_| keep)
            .map(|p| (AddressFamily::IPV4_UNICAST, *p))
            .chain(
                m.mp_reach
                    .iter()
                    .filter(move |_| keep)
                    .flat_map(|r| r.nlri.iter().map(move |p| (r.family, *p))),
            )
            .filter(move |(f, _)| !self.disables(*f))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::community::{Community, LargeCommunity};
    use crate::error::ErrorCode;
    use crate::mp::NextHop;
    use crate::types::{Afi, Safi};

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    const EBGP2: DecodeContext = DecodeContext {
        four_octet_as: false,
        peer: PeerKind::External,
        allow_as_set: false,
        extended_next_hop: false,
        add_path: AddPathFamilies::NONE,
    };
    const EBGP4: DecodeContext = DecodeContext {
        four_octet_as: true,
        ..EBGP2
    };
    const IBGP4: DecodeContext = DecodeContext {
        peer: PeerKind::Internal,
        ..EBGP4
    };
    const ENC2: EncodeContext = EncodeContext {
        four_octet_as: false,
        extended_next_hop: false,
        add_path: AddPathFamilies::NONE,
    };
    const ENC4: EncodeContext = EncodeContext {
        four_octet_as: true,
        extended_next_hop: false,
        add_path: AddPathFamilies::NONE,
    };

    /// 10.0.0.0/8 via 192.0.2.1, path 65001 65002, origin IGP, MED 50, from
    /// a two-octet speaker. Laid out by hand from RFC 4271 §4.3.
    const ANNOUNCE: [u8; 33] = [
        0, 0, // withdrawn routes length
        0, 27, // total path attribute length
        0x40, 1, 1, 0, // ORIGIN igp
        0x40, 2, 6, 2, 2, 0xfd, 0xe9, 0xfd, 0xea, // AS_PATH seq 65001 65002
        0x40, 3, 4, 192, 0, 2, 1, // NEXT_HOP
        0x80, 4, 4, 0, 0, 0, 50, // MED
        8, 10, // NLRI 10.0.0.0/8
    ];

    fn announce() -> UpdateMessage {
        UpdateMessage {
            nlri: vec![p("10.0.0.0/8")],
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::sequence(&[Asn(65_001), Asn(65_002)])),
                PathAttribute::NextHop(Ipv4Addr::new(192, 0, 2, 1)),
                PathAttribute::MultiExitDisc(50),
            ],
            ..UpdateMessage::default()
        }
    }

    #[test]
    fn announce_round_trips() {
        let m = announce();
        assert_eq!(m.encode(&ENC2).unwrap(), ANNOUNCE);
        let d = UpdateMessage::decode(&ANNOUNCE, &EBGP2).unwrap();
        assert_eq!(d.message, m);
        assert_eq!(d.treated_as_withdraw, None);
        assert_eq!(d.discarded, vec![]);
        assert_eq!(
            d.announcements().collect::<Vec<_>>(),
            vec![(AddressFamily::IPV4_UNICAST, p("10.0.0.0/8"))]
        );
        assert_eq!(d.withdrawals().count(), 0);
        assert_eq!(m.origin(), Some(Origin::Igp));
        assert_eq!(m.as_path().unwrap().hop_count(), 2);
        assert_eq!(m.next_hop(), Some(Ipv4Addr::new(192, 0, 2, 1)));
        // Attributes out of order are accepted (RFC 4271 §5 MUST).
        let mut shuffled = ANNOUNCE.to_vec();
        shuffled[4..31].rotate_left(4);
        assert_eq!(UpdateMessage::decode(&shuffled, &EBGP2).unwrap().message, m);
    }

    #[test]
    fn end_of_rib_markers_follow_rfc_4724_section_2() {
        let v4 = AddressFamily::IPV4_UNICAST;
        let v6 = AddressFamily::IPV6_UNICAST;
        // IPv4 unicast: the UPDATE of minimum length, four octets of body
        // (the two length fields), 23 with the header.
        let eor4 = UpdateMessage::end_of_rib(v4);
        assert_eq!(eor4.encode(&ENC4).unwrap(), [0, 0, 0, 0]);
        let d = UpdateMessage::decode(&[0, 0, 0, 0], &EBGP4).unwrap();
        assert_eq!(d.message.end_of_rib_family(), Some(v4));
        // Any other family: only an MP_UNREACH_NLRI (optional,
        // non-transitive, type 15) holding the AFI and SAFI.
        let eor6 = UpdateMessage::end_of_rib(v6);
        let wire6 = [0, 0, 0, 6, 0x80, 15, 3, 0, 2, 1];
        assert_eq!(eor6.encode(&ENC4).unwrap(), wire6);
        let d = UpdateMessage::decode(&wire6, &EBGP4).unwrap();
        assert_eq!(d.message, eor6);
        assert_eq!(d.message.end_of_rib_family(), Some(v6));
        // A family the decoder does not speak is still a marker of its
        // own; it round-trips and names its family.
        let other = AddressFamily {
            afi: Afi::Unknown(25),
            safi: Safi::Unknown(65),
        };
        let m = UpdateMessage::end_of_rib(other);
        assert_eq!(m.end_of_rib_family(), Some(other));
        // NOTE(interop): an empty MP_UNREACH_NLRI for IPv4 unicast counts.
        let m = UpdateMessage {
            mp_unreach: Some(MpUnreach {
                family: v4,
                withdrawn: vec![],
            }),
            ..UpdateMessage::default()
        };
        assert_eq!(m.end_of_rib_family(), Some(v4));
        // Anything announced or withdrawn is no marker.
        assert_eq!(announce().end_of_rib_family(), None);
        let withdraw = |m: UpdateMessage| m.end_of_rib_family();
        assert_eq!(
            withdraw(UpdateMessage {
                withdrawn: vec![p("10.0.0.0/8")],
                ..UpdateMessage::default()
            }),
            None
        );
        assert_eq!(
            withdraw(UpdateMessage {
                mp_unreach: Some(MpUnreach {
                    family: v6,
                    withdrawn: vec![p("2001:db8::/32")],
                }),
                ..UpdateMessage::default()
            }),
            None
        );
        // Attributes beside the attribute make it something else.
        assert_eq!(
            withdraw(UpdateMessage {
                attributes: vec![PathAttribute::Origin(Origin::Igp)],
                ..eor6.clone()
            }),
            None
        );
        assert_eq!(
            withdraw(UpdateMessage {
                attributes: vec![PathAttribute::Origin(Origin::Igp)],
                ..UpdateMessage::default()
            }),
            None
        );
    }

    #[test]
    fn withdraw_only_and_empty_updates() {
        let m = UpdateMessage {
            withdrawn: vec![p("10.0.0.0/8"), p("192.0.2.0/24")],
            ..UpdateMessage::default()
        };
        let wire = m.encode(&ENC4).unwrap();
        assert_eq!(wire, [0, 6, 8, 10, 24, 192, 0, 2, 0, 0]);
        let d = UpdateMessage::decode(&wire, &EBGP4).unwrap();
        assert_eq!(d.message, m);
        assert_eq!(d.withdrawals().count(), 2);
        // RFC 4271 §4.3: the 4-octet minimum body is a valid, empty UPDATE.
        let d = UpdateMessage::decode(&[0, 0, 0, 0], &EBGP4).unwrap();
        assert_eq!(d.message, UpdateMessage::default());
    }

    #[test]
    fn length_overruns_reset_the_session() {
        // RFC 7606 §3 b).
        for body in [
            &[0, 1][..],
            &[0, 5, 1, 2][..],
            &[0, 0, 0, 9, 1][..],
            &[0][..],
        ] {
            let e = UpdateMessage::decode(body, &EBGP4).unwrap_err();
            assert_eq!(
                e.notification.subcode,
                UpdateSubcode::MalformedAttributeList as u8
            );
            assert_eq!(e.notification.code, ErrorCode::Update);
        }
    }

    #[test]
    fn bad_nlri_syntax_resets_the_session() {
        // RFC 7606 §5.3 + §3 j): the NLRI cannot be located, so no withdraw.
        let mut bad = ANNOUNCE.to_vec();
        bad[31] = 33;
        let e = UpdateMessage::decode(&bad, &EBGP2).unwrap_err();
        assert_eq!(
            e.notification.subcode,
            UpdateSubcode::InvalidNetworkField as u8
        );
        let e = UpdateMessage::decode(&[0, 2, 24, 10, 0, 0], &EBGP2).unwrap_err();
        assert_eq!(
            e.notification.subcode,
            UpdateSubcode::InvalidNetworkField as u8
        );
    }

    #[test]
    fn bad_origin_is_treat_as_withdraw() {
        // RFC 7606 §7.1.
        let mut bad = ANNOUNCE.to_vec();
        bad[7] = 3;
        let d = UpdateMessage::decode(&bad, &EBGP2).unwrap();
        let e = d.treated_as_withdraw.clone().unwrap();
        assert_eq!(e.subcode, UpdateSubcode::InvalidOrigin as u8);
        assert_eq!(e.data, vec![0x40, 1, 1, 3]);
        assert_eq!(d.announcements().count(), 0);
        assert_eq!(
            d.withdrawals().collect::<Vec<_>>(),
            vec![(AddressFamily::IPV4_UNICAST, p("10.0.0.0/8"))]
        );
        // The rest of the message is still decoded.
        assert_eq!(d.message.next_hop(), Some(Ipv4Addr::new(192, 0, 2, 1)));
    }

    #[test]
    fn attribute_length_and_flag_errors() {
        // RFC 7606 §7.3: NEXT_HOP length.
        let mut bad = ANNOUNCE.to_vec();
        bad[19] = 3;
        bad.remove(23);
        bad[3] -= 1;
        let d = UpdateMessage::decode(&bad, &EBGP2).unwrap();
        assert_eq!(
            d.treated_as_withdraw.unwrap().subcode,
            UpdateSubcode::AttributeLengthError as u8
        );
        // RFC 7606 §3 c): ORIGIN flagged optional.
        let mut bad = ANNOUNCE.to_vec();
        bad[4] = 0xc0;
        let d = UpdateMessage::decode(&bad, &EBGP2).unwrap();
        let e = d.treated_as_withdraw.unwrap();
        assert_eq!(e.subcode, UpdateSubcode::AttributeFlagsError as u8);
        assert_eq!(e.data, vec![0xc0, 1, 1, 0]);
        // RFC 7606 §3 f): ATOMIC_AGGREGATE with a value is discarded only.
        let mut m = announce();
        m.attributes.push(PathAttribute::AtomicAggregate);
        let mut wire = m.encode(&ENC2).unwrap();
        let at = wire.len() - 2 - 3; // before NLRI, the 3-octet attribute
        assert_eq!(&wire[at..at + 3], &[0x40, 6, 0]);
        wire[at + 2] = 1;
        wire.insert(at + 3, 9);
        wire[3] += 1;
        let d = UpdateMessage::decode(&wire, &EBGP2).unwrap();
        assert_eq!(d.treated_as_withdraw, None);
        assert_eq!(d.discarded.len(), 1);
        assert_eq!(d.discarded[0].code, code::ATOMIC_AGGREGATE);
        assert!(matches!(d.discarded[0].reason, DiscardReason::Malformed(_)));
        assert_eq!(d.message.attribute(code::ATOMIC_AGGREGATE), None);
    }

    #[test]
    fn next_hops_that_are_not_host_addresses_are_treat_as_withdraw() {
        // RFC 4271 §6.3: syntactically incorrect, Invalid NEXT_HOP Attribute
        // with the attribute as data; RFC 7606 §3 e): treat-as-withdraw.
        for bad in [
            [0, 0, 0, 0],
            [0, 1, 2, 3],
            [127, 0, 0, 1],
            [224, 0, 0, 5],
            [239, 1, 1, 1],
            [240, 0, 0, 1],
            [255, 255, 255, 255],
        ] {
            let mut wire = ANNOUNCE.to_vec();
            wire[20..24].copy_from_slice(&bad);
            let d = UpdateMessage::decode(&wire, &EBGP2).unwrap();
            let e = d.treated_as_withdraw.clone().unwrap();
            assert_eq!(e.subcode, UpdateSubcode::InvalidNextHop as u8, "{bad:?}");
            let mut attr = vec![0x40, 3, 4];
            attr.extend_from_slice(&bad);
            assert_eq!(e.data, attr);
            assert_eq!(d.announcements().count(), 0);
            assert_eq!(
                d.withdrawals().collect::<Vec<_>>(),
                vec![(AddressFamily::IPV4_UNICAST, p("10.0.0.0/8"))]
            );
        }
        // The data is the attribute as received, Extended Length included.
        let mut wire = ANNOUNCE.to_vec();
        wire.splice(17..20, [0x50, 3, 0, 4]);
        wire[3] += 1;
        wire[21..25].copy_from_slice(&[0, 0, 0, 0]);
        let e = UpdateMessage::decode(&wire, &EBGP2)
            .unwrap()
            .treated_as_withdraw
            .unwrap();
        assert_eq!(e.data, [0x50, 3, 0, 4, 0, 0, 0, 0]);
        // A host address is fine at the edges of the ranges around it.
        for good in [[1, 0, 0, 0], [126, 255, 255, 255], [223, 255, 255, 255]] {
            let mut wire = ANNOUNCE.to_vec();
            wire[20..24].copy_from_slice(&good);
            let d = UpdateMessage::decode(&wire, &EBGP2).unwrap();
            assert_eq!(d.treated_as_withdraw, None, "{good:?}");
        }
    }

    #[test]
    fn mp_reach_next_hops_follow_the_next_hop_rules() {
        // RFC 4760 §3: the rules of NEXT_HOP hold for MP_REACH_NLRI, which
        // RFC 2545 §3 makes a global address, optionally followed by a
        // link-local one.
        let reach = |family, next_hop| UpdateMessage {
            mp_reach: Some(MpReach {
                family,
                next_hop,
                nlri: vec![match family {
                    AddressFamily::IPV6_UNICAST => p("2001:db8:1::/48"),
                    _ => p("192.0.2.0/24"),
                }],
            }),
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::sequence(&[Asn(65_001)])),
            ],
            ..UpdateMessage::default()
        };
        let v6 = |global: &str, link_local: Option<&str>| NextHop::Ipv6 {
            global: global.parse().unwrap(),
            link_local: link_local.map(|a| a.parse().unwrap()),
        };
        let enc = EncodeContext {
            extended_next_hop: true,
            add_path: AddPathFamilies::NONE,
            ..ENC4
        };
        let ctx = DecodeContext {
            extended_next_hop: true,
            add_path: AddPathFamilies::NONE,
            ..EBGP4
        };
        let v4 = AddressFamily::IPV4_UNICAST;
        let v6f = AddressFamily::IPV6_UNICAST;
        for (family, next_hop, valid) in [
            (v6f, v6("2001:db8::1", None), true),
            (v6f, v6("2001:db8::1", Some("fe80::1")), true),
            (v6f, v6("::", None), false),
            (v6f, v6("::", Some("fe80::1")), false),
            (v6f, v6("::1", None), false),
            (v6f, v6("ff02::1", None), false),
            // RFC 2545 §3: link-local is legal second, not alone or first.
            (v6f, v6("fe80::1", None), false),
            (v6f, v6("fe80::1", Some("fe80::2")), false),
            (v4, NextHop::Ipv4(Ipv4Addr::new(192, 0, 2, 1)), true),
            (v4, NextHop::Ipv4(Ipv4Addr::UNSPECIFIED), false),
            (v4, NextHop::Ipv4(Ipv4Addr::BROADCAST), false),
            // RFC 8950 §3: IPv4 NLRI with an IPv6 next hop.
            (v4, v6("2001:db8::1", Some("fe80::1")), true),
            (v4, v6("ff02::1", None), false),
        ] {
            let m = reach(family, next_hop);
            let wire = m.encode(&enc).unwrap();
            let d = UpdateMessage::decode(&wire, &ctx).unwrap();
            if valid {
                assert_eq!(d.treated_as_withdraw, None, "{next_hop}");
                assert_eq!(d.message, m);
            } else {
                let e = d.treated_as_withdraw.clone().unwrap();
                assert_eq!(e.subcode, UpdateSubcode::InvalidNextHop as u8);
                assert_eq!(e.data[1], code::MP_REACH_NLRI);
                assert_eq!(d.announcements().count(), 0, "{next_hop}");
                assert_eq!(d.withdrawals().count(), 1);
            }
        }
        // An MP_REACH_NLRI with no routes has nothing to withdraw.
        let mut m = reach(v6f, v6("::", None));
        if let Some(r) = &mut m.mp_reach {
            r.nlri.clear();
        }
        let d = UpdateMessage::decode(&m.encode(&enc).unwrap(), &ctx).unwrap();
        assert_eq!(d.treated_as_withdraw, None);
    }

    #[test]
    fn next_hop_is_judged_only_for_the_nlri_field() {
        // RFC 4760 §3: with routes only in MP_REACH_NLRI, a NEXT_HOP is to
        // be ignored, so whatever it holds withdraws nothing.
        let mut m = UpdateMessage {
            mp_reach: Some(MpReach {
                family: AddressFamily::IPV6_UNICAST,
                next_hop: NextHop::Ipv6 {
                    global: "2001:db8::1".parse().unwrap(),
                    link_local: None,
                },
                nlri: vec![p("2001:db8:1::/48")],
            }),
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::sequence(&[Asn(65_001)])),
                PathAttribute::NextHop(Ipv4Addr::UNSPECIFIED),
            ],
            ..UpdateMessage::default()
        };
        let d = UpdateMessage::decode(&m.encode(&ENC4).unwrap(), &EBGP4).unwrap();
        assert_eq!(d.treated_as_withdraw, None);
        assert_eq!(d.announcements().count(), 1);
        // With routes in the NLRI field it serves them, and all of the
        // UPDATE's routes are withdrawn (RFC 7606 §2).
        m.nlri = vec![p("10.0.0.0/8")];
        let d = UpdateMessage::decode(&m.encode(&ENC4).unwrap(), &EBGP4).unwrap();
        assert_eq!(
            d.treated_as_withdraw.as_ref().map(|e| e.subcode),
            Some(UpdateSubcode::InvalidNextHop as u8)
        );
        assert_eq!(d.withdrawals().count(), 2);
    }

    #[test]
    fn truncated_attribute_header_is_treat_as_withdraw() {
        // RFC 7606 §4: a lone octet after the last attribute.
        let mut bad = ANNOUNCE.to_vec();
        bad.insert(31, 0x40);
        bad[3] += 1;
        let d = UpdateMessage::decode(&bad, &EBGP2).unwrap();
        assert_eq!(
            d.treated_as_withdraw.unwrap().subcode,
            UpdateSubcode::MalformedAttributeList as u8
        );
        assert_eq!(d.message.nlri, vec![p("10.0.0.0/8")]);
    }

    #[test]
    fn unknown_attributes_per_rfc4271_section_5() {
        let mut m = announce();
        // Optional transitive: kept, flags preserved.
        m.attributes.push(PathAttribute::Unknown {
            flags: 0xe0,
            code: 99,
            value: vec![1, 2],
        });
        let wire = m.encode(&ENC2).unwrap();
        let d = UpdateMessage::decode(&wire, &EBGP2).unwrap();
        assert_eq!(d.message, m);
        // Optional non-transitive: quietly ignored.
        let mut wire = announce().encode(&ENC2).unwrap();
        let at = wire.len() - 2;
        wire.splice(at..at, [0x80, 99, 1, 7]);
        wire[3] += 4;
        let d = UpdateMessage::decode(&wire, &EBGP2).unwrap();
        assert_eq!(d.message, announce());
        assert_eq!(d.discarded, vec![]);
        // Well-known unrecognised: session reset (RFC 4271 §6.3).
        wire[at] = 0x40;
        let e = UpdateMessage::decode(&wire, &EBGP2).unwrap_err();
        assert_eq!(
            e.notification.subcode,
            UpdateSubcode::UnrecognizedWellKnownAttribute as u8
        );
        assert_eq!(e.notification.data, vec![0x40, 99, 1, 7]);
    }

    #[test]
    fn unused_flag_bits_are_ignored_on_receipt() {
        // Found by the update fuzz target: RFC 4271 §4.3 says the low four
        // flag bits MUST be ignored, so an unknown attribute with them set
        // must decode to, and re-encode as, the same canonical flags.
        let wire = [0, 1, 0, 0, 4, 0xf9, 0, 0, 0];
        let d = UpdateMessage::decode(&wire, &EBGP4).unwrap();
        assert_eq!(
            d.message.attributes,
            vec![PathAttribute::Unknown {
                flags: 0xe0,
                code: 0,
                value: vec![],
            }]
        );
        // The input used the Extended Length form; the canonical encoding
        // uses one length octet, so only the decoded form must match.
        let again = d.message.encode(&ENC4).unwrap();
        assert_eq!(again, [0, 1, 0, 0, 3, 0xe0, 0, 0]);
        assert_eq!(
            UpdateMessage::decode(&again, &EBGP4).unwrap().message,
            d.message
        );
        // A known attribute with junk low bits is still recognised.
        let mut junk = ANNOUNCE.to_vec();
        junk[4] = 0x4f;
        assert_eq!(
            UpdateMessage::decode(&junk, &EBGP2).unwrap().message,
            announce()
        );
    }

    #[test]
    fn duplicates_discard_or_reset() {
        // RFC 7606 §3 g).
        let mut wire = announce().encode(&ENC2).unwrap();
        let at = wire.len() - 2;
        wire.splice(at..at, [0x40, 1, 1, 2]); // second ORIGIN
        wire[3] += 4;
        let d = UpdateMessage::decode(&wire, &EBGP2).unwrap();
        assert_eq!(d.message.origin(), Some(Origin::Igp));
        assert_eq!(d.discarded[0].reason, DiscardReason::Duplicate);
        let m = UpdateMessage {
            mp_unreach: Some(MpUnreach {
                family: AddressFamily::IPV6_UNICAST,
                withdrawn: vec![p("2001:db8::/32")],
            }),
            ..UpdateMessage::default()
        };
        let mut wire = m.encode(&ENC4).unwrap();
        let attr = wire[4..].to_vec();
        wire.extend_from_slice(&attr);
        wire[3] *= 2;
        let e = UpdateMessage::decode(&wire, &EBGP4).unwrap_err();
        assert_eq!(
            e.notification.subcode,
            UpdateSubcode::MalformedAttributeList as u8
        );
    }

    #[test]
    fn missing_mandatory_attributes() {
        // RFC 7606 §3 d).
        let m = UpdateMessage {
            nlri: vec![p("10.0.0.0/8")],
            attributes: vec![PathAttribute::Origin(Origin::Igp)],
            ..UpdateMessage::default()
        };
        let d = UpdateMessage::decode(&m.encode(&ENC4).unwrap(), &EBGP4).unwrap();
        let e = d.treated_as_withdraw.unwrap();
        assert_eq!(e.subcode, UpdateSubcode::MissingWellKnownAttribute as u8);
        assert_eq!(e.data, vec![code::AS_PATH]);
        // NEXT_HOP is not required when only MP_REACH carries routes (RFC 4760 §3).
        let m = UpdateMessage {
            mp_reach: Some(MpReach {
                family: AddressFamily::IPV6_UNICAST,
                next_hop: NextHop::Ipv6 {
                    global: "2001:db8::1".parse().unwrap(),
                    link_local: None,
                },
                nlri: vec![p("2001:db8::/32")],
            }),
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::sequence(&[Asn(65_001)])),
            ],
            ..UpdateMessage::default()
        };
        let wire = m.encode(&ENC4).unwrap();
        // RFC 7606 §5.1: MP_REACH_NLRI is the very first attribute.
        assert_eq!(wire[5], code::MP_REACH_NLRI);
        let d = UpdateMessage::decode(&wire, &EBGP4).unwrap();
        assert_eq!(d.treated_as_withdraw, None);
        assert_eq!(d.message, m);
        assert_eq!(
            d.announcements().collect::<Vec<_>>(),
            vec![(AddressFamily::IPV6_UNICAST, p("2001:db8::/32"))]
        );
        // No NLRI at all: nothing is mandatory.
        let m = UpdateMessage {
            attributes: vec![PathAttribute::Origin(Origin::Igp)],
            ..UpdateMessage::default()
        };
        assert!(UpdateMessage::decode(&m.encode(&ENC4).unwrap(), &EBGP4).is_ok());
    }

    #[test]
    fn no_reachable_nlri_escalates_withdraw_to_reset() {
        // RFC 7606 §5.2.
        let m = UpdateMessage {
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::sequence(&[Asn(65_001)])),
            ],
            ..UpdateMessage::default()
        };
        let mut wire = m.encode(&ENC4).unwrap();
        wire[7] = 9; // undefined ORIGIN
        let e = UpdateMessage::decode(&wire, &EBGP4).unwrap_err();
        assert_eq!(e.notification.subcode, UpdateSubcode::InvalidOrigin as u8);
    }

    #[test]
    fn local_pref_depends_on_the_peer_kind() {
        // RFC 7606 §7.5.
        let mut m = announce();
        m.attributes.push(PathAttribute::LocalPref(200));
        let wire = m.encode(&ENC4).unwrap();
        let d = UpdateMessage::decode(&wire, &EBGP4).unwrap();
        assert_eq!(d.message.attribute(code::LOCAL_PREF), None);
        assert_eq!(d.discarded[0].reason, DiscardReason::FromExternalPeer);
        let d = UpdateMessage::decode(&wire, &IBGP4).unwrap();
        assert_eq!(
            d.message.attribute(code::LOCAL_PREF),
            Some(&PathAttribute::LocalPref(200))
        );
        let mut short = wire.clone();
        let at = short.len() - 2 - 7;
        assert_eq!(short[at + 1], code::LOCAL_PREF);
        short[at + 2] = 3;
        short.remove(at + 6);
        short[3] -= 1;
        let d = UpdateMessage::decode(&short, &IBGP4).unwrap();
        assert_eq!(
            d.treated_as_withdraw.unwrap().subcode,
            UpdateSubcode::AttributeLengthError as u8
        );
    }

    #[test]
    fn as_path_rules() {
        // RFC 7607 §2: AS 0.
        let mut m = announce();
        m.attributes[1] = PathAttribute::AsPath(AsPath::sequence(&[Asn(0)]));
        let d = UpdateMessage::decode(&m.encode(&ENC4).unwrap(), &EBGP4).unwrap();
        assert_eq!(
            d.treated_as_withdraw.unwrap().subcode,
            UpdateSubcode::MalformedAsPath as u8
        );
        // RFC 9774 §3: AS_SET, unless allowed.
        let set = AsPath::from_segments(&[crate::as_path::AsPathSegment {
            kind: crate::as_path::SegmentType::Set,
            asns: vec![Asn(65_001)],
        }]);
        m.attributes[1] = PathAttribute::AsPath(set.clone());
        let wire = m.encode(&ENC4).unwrap();
        let d = UpdateMessage::decode(&wire, &EBGP4).unwrap();
        assert!(d.treated_as_withdraw.is_some());
        let lenient = DecodeContext {
            allow_as_set: true,
            ..EBGP4
        };
        let d = UpdateMessage::decode(&wire, &lenient).unwrap();
        assert_eq!(d.treated_as_withdraw, None);
        assert_eq!(d.message.as_path(), Some(&set));
        // RFC 7606 §7.2: malformed segment.
        let mut bad = ANNOUNCE.to_vec();
        bad[11] = 7;
        let d = UpdateMessage::decode(&bad, &EBGP2).unwrap();
        assert_eq!(
            d.treated_as_withdraw.unwrap().subcode,
            UpdateSubcode::MalformedAsPath as u8
        );
    }

    #[test]
    fn as4_path_is_generated_for_old_peers_and_merged_on_receipt() {
        // RFC 6793 §4.2.2 / §4.2.3.
        let mut m = announce();
        m.attributes[1] =
            PathAttribute::AsPath(AsPath::sequence(&[Asn(4_200_000_000), Asn(65_002)]));
        m.attributes.push(PathAttribute::Aggregator(Aggregator {
            asn: Asn(4_200_000_001),
            address: Ipv4Addr::new(192, 0, 2, 9),
        }));
        let two = m.encode(&ENC2).unwrap();
        // AS_PATH carries AS_TRANS; AS4_PATH (17) and AS4_AGGREGATOR (18)
        // follow in type order.
        assert!(two.windows(6).any(|w| w == [2, 2, 0x5b, 0xa0, 0xfd, 0xea]));
        let codes: Vec<u8> = {
            let mut r = Reader::new(&two[4..4 + usize::from(u16::from_be_bytes([two[2], two[3]]))]);
            let mut v = Vec::new();
            while !r.is_empty() {
                v.push(parse_raw(&mut r).unwrap().code);
            }
            v
        };
        assert_eq!(codes, vec![1, 2, 3, 4, 7, 17, 18]);
        // A NEW speaker reading it reconstructs the four-octet information.
        let d = UpdateMessage::decode(&two, &EBGP2).unwrap();
        assert_eq!(d.message, m);
        assert_eq!(d.discarded, vec![]);
        // A four-octet session needs none of that.
        let four = m.encode(&ENC4).unwrap();
        assert!(!four.windows(2).any(|w| w == [0xc0, 17]));
        assert_eq!(UpdateMessage::decode(&four, &EBGP4).unwrap().message, m);
        // RFC 6793 §6: AS4_PATH on a four-octet session is discarded.
        let d = UpdateMessage::decode(&two, &EBGP4).unwrap();
        assert!(
            d.discarded
                .iter()
                .any(|x| x.code == 17 && x.reason == DiscardReason::FromNewSpeaker)
        );
        assert!(d.discarded.iter().any(|x| x.code == 18));
    }

    #[test]
    fn as4_aggregator_from_an_old_aggregator_wins() {
        // RFC 6793 §4.2.3: AGGREGATOR not AS_TRANS → ignore both AS4 attributes.
        let mut m = announce();
        m.attributes.push(PathAttribute::Aggregator(Aggregator {
            asn: Asn(65_009),
            address: Ipv4Addr::new(192, 0, 2, 9),
        }));
        let mut wire = m.encode(&ENC2).unwrap();
        let at = wire.len() - 2;
        let extra = [
            0xc0, 17, 8, 2, 1, 0xfa, 0x56, 0xea, 0x00, // AS4_PATH 4200000000
            0xc0, 18, 8, 0xfa, 0x56, 0xea, 0x01, 192, 0, 2, 9, // AS4_AGGREGATOR
        ];
        wire.splice(at..at, extra);
        wire[3] += u8::try_from(extra.len()).unwrap();
        let d = UpdateMessage::decode(&wire, &EBGP2).unwrap();
        assert_eq!(d.message, m);
    }

    #[test]
    fn communities_round_trip_and_length_errors() {
        let mut m = announce();
        m.attributes.push(PathAttribute::Communities(vec![
            Community::new(65_001, 1),
            Community::NO_EXPORT,
        ]));
        m.attributes
            .push(PathAttribute::LargeCommunities(vec![LargeCommunity {
                global: 65_001,
                local1: 1,
                local2: 2,
            }]));
        let wire = m.encode(&ENC4).unwrap();
        assert_eq!(UpdateMessage::decode(&wire, &EBGP4).unwrap().message, m);
        // RFC 7606 §7.8: not a multiple of four.
        let mut bad = announce().encode(&ENC4).unwrap();
        let at = bad.len() - 2;
        bad.splice(at..at, [0xc0, 8, 3, 1, 2, 3]);
        bad[3] += 6;
        let d = UpdateMessage::decode(&bad, &EBGP4).unwrap();
        assert_eq!(
            d.treated_as_withdraw.unwrap().subcode,
            UpdateSubcode::AttributeLengthError as u8
        );
    }

    /// `announce()` as a four-octet session sends it, with `attr` added
    /// to its path attributes.
    fn announce_with(attr: &[u8]) -> Vec<u8> {
        let mut wire = announce().encode(&ENC4).unwrap();
        let at = wire.len() - 2;
        wire.splice(at..at, attr.iter().copied());
        wire[3] += u8::try_from(attr.len()).unwrap();
        wire
    }

    #[test]
    fn only_to_customer_round_trips() {
        // RFC 9234 §5: optional transitive, type code 35, four octets.
        let mut m = announce();
        m.attributes
            .push(PathAttribute::OnlyToCustomer(Asn(65_001)));
        m.attributes.sort_by_key(PathAttribute::code);
        let wire = m.encode(&ENC4).unwrap();
        let attr = [0xc0, 35, 4, 0, 0, 0xfd, 0xe9];
        assert!(wire.windows(attr.len()).any(|w| w == attr), "{wire:?}");
        let d = UpdateMessage::decode(&wire, &EBGP4).unwrap();
        assert_eq!(d.message, m);
        assert_eq!(d.treated_as_withdraw, None);
        assert_eq!(d.discarded, vec![]);
        // It is an AS number of four octets also towards a two-octet
        // speaker: RFC 9234 §5 has no two-octet form and no AS4_ twin.
        let wire = m.encode(&ENC2).unwrap();
        assert!(wire.windows(attr.len()).any(|w| w == attr), "{wire:?}");
        assert_eq!(UpdateMessage::decode(&wire, &EBGP2).unwrap().message, m);
        // Internal sessions carry it too ("once set, preserved").
        let wire = m.encode(&ENC4).unwrap();
        assert_eq!(UpdateMessage::decode(&wire, &IBGP4).unwrap().message, m);
        // The value is whatever the AS put there, AS 0 included.
        for asn in [0, 1, 4_200_000_000, u32::MAX] {
            let mut wire = vec![0xc0, 35, 4];
            wire.extend_from_slice(&asn.to_be_bytes());
            let d = UpdateMessage::decode(&announce_with(&wire), &EBGP4).unwrap();
            assert_eq!(
                d.message.attribute(code::ONLY_TO_CUSTOMER),
                Some(&PathAttribute::OnlyToCustomer(Asn(asn)))
            );
        }
        // A Partial bit set by a speaker that did not know it is dropped
        // with the rest of the flags we re-derive, and the value is kept.
        let d = UpdateMessage::decode(&announce_with(&[0xe0, 35, 4, 0, 0, 0xfd, 0xe9]), &EBGP4)
            .unwrap();
        assert_eq!(d.treated_as_withdraw, None);
        assert_eq!(
            d.message.attribute(code::ONLY_TO_CUSTOMER),
            Some(&PathAttribute::OnlyToCustomer(Asn(65_001)))
        );
    }

    #[test]
    fn bird_update_with_otc_is_read_and_written_back() {
        // Captured from BIRD 2.14, AS 65001, `local role provider`, sending
        // a static route to its customer: ORIGIN, AS_PATH 65001, NEXT_HOP,
        // and the Only to Customer attribute (RFC 9234 §5: 0xc0, type 35,
        // length 4) set to its own AS, as §5 egress 1 has it.
        let wire = [
            0, 0, // withdrawn routes length
            0, 27, // total path attribute length
            0x40, 1, 1, 0, // ORIGIN igp
            0x40, 2, 6, 2, 1, 0, 0, 0xfd, 0xe9, // AS_PATH seq 65001
            0x40, 3, 4, 10, 77, 0, 2, // NEXT_HOP
            0xc0, 35, 4, 0, 0, 0xfd, 0xe9, // OTC 65001
            24, 192, 0, 2, // NLRI 192.0.2.0/24
        ];
        let d = UpdateMessage::decode(&wire, &EBGP4).unwrap();
        assert_eq!(d.treated_as_withdraw, None);
        assert_eq!(d.discarded, vec![]);
        assert_eq!(
            d.message.attribute(code::ONLY_TO_CUSTOMER),
            Some(&PathAttribute::OnlyToCustomer(Asn(65_001)))
        );
        assert_eq!(d.message.nlri, vec![p("192.0.2.0/24")]);
        // The canonical form: the encoder writes the same octets.
        assert_eq!(d.message.encode(&ENC4).unwrap(), wire);
    }

    #[test]
    fn a_malformed_only_to_customer_is_treat_as_withdraw() {
        // RFC 9234 §5: "considered malformed if the length value is not 4";
        // the UPDATE "SHALL be handled using the approach of
        // 'treat-as-withdraw'" (RFC 7606 §2), without a session reset.
        for len in [0usize, 1, 3, 5, 8] {
            let mut attr = vec![0xc0, 35, u8::try_from(len).unwrap()];
            attr.extend(std::iter::repeat_n(7, len));
            let d = UpdateMessage::decode(&announce_with(&attr), &EBGP4).unwrap();
            let e = d.treated_as_withdraw.clone().unwrap();
            assert_eq!(e.code, ErrorCode::Update, "length {len}");
            assert_eq!(e.subcode, UpdateSubcode::AttributeLengthError as u8);
            // RFC 4271 §6.3: the Data field is the attribute.
            assert_eq!(e.data, attr);
            assert_eq!(d.announcements().count(), 0);
            assert_eq!(
                d.withdrawals().collect::<Vec<_>>(),
                vec![(AddressFamily::IPV4_UNICAST, p("10.0.0.0/8"))]
            );
        }
    }

    #[test]
    fn only_to_customer_flags_must_be_optional_transitive() {
        // RFC 7606 §3 c): the category bits in conflict with the registry
        // are treat-as-withdraw for an attribute with no milder rule.
        for flags in [0x40, 0x80, 0x00] {
            let attr = [flags, 35, 4, 0, 0, 0xfd, 0xe9];
            let d = UpdateMessage::decode(&announce_with(&attr), &EBGP4).unwrap();
            let e = d.treated_as_withdraw.clone().unwrap();
            assert_eq!(e.subcode, UpdateSubcode::AttributeFlagsError as u8);
            assert_eq!(e.data, attr);
            assert_eq!(d.message.attribute(code::ONLY_TO_CUSTOMER), None);
        }
    }

    #[test]
    fn a_repeated_only_to_customer_is_discarded() {
        // RFC 7606 §3 g): the first occurrence is kept.
        let mut attrs = vec![0xc0, 35, 4, 0, 0, 0xfd, 0xe9];
        attrs.extend_from_slice(&[0xc0, 35, 4, 0, 0, 0xfd, 0xea]);
        let d = UpdateMessage::decode(&announce_with(&attrs), &EBGP4).unwrap();
        assert_eq!(d.treated_as_withdraw, None);
        assert_eq!(
            d.message.attribute(code::ONLY_TO_CUSTOMER),
            Some(&PathAttribute::OnlyToCustomer(Asn(65_001)))
        );
        assert_eq!(
            d.discarded,
            vec![DiscardedAttribute {
                code: 35,
                reason: DiscardReason::Duplicate
            }]
        );
    }

    #[test]
    fn mp_attribute_errors_disable_the_family() {
        // RFC 4760 §7 + RFC 7606 §7.11.
        let mut wire = vec![0, 0, 0, 0];
        let attr = [0x80, 14, 9, 0, 2, 1, 4, 1, 2, 3, 4, 0];
        wire.extend_from_slice(&attr);
        wire[3] = 12;
        let d = UpdateMessage::decode(&wire, &EBGP4).unwrap();
        assert_eq!(
            d.disabled,
            vec![DisabledFamily {
                family: AddressFamily::IPV6_UNICAST,
                error: DecodeError::update(UpdateSubcode::OptionalAttributeError, attr.to_vec()),
            }]
        );
        assert_eq!(d.message, UpdateMessage::default());
        assert_eq!(d.treated_as_withdraw, None);
        // Unsupported family: disabled too.
        let mut wire = vec![0, 0, 0, 7, 0x80, 15, 4, 0, 1, 128, 0];
        assert_eq!(
            disabled(&wire),
            vec![AddressFamily {
                afi: Afi::Ipv4,
                safi: Safi::Unknown(128)
            }]
        );
        // Too short to name a family: session reset.
        wire.truncate(9);
        wire[3] = 5;
        wire[6] = 2;
        let e = UpdateMessage::decode(&wire, &EBGP4).unwrap_err();
        assert_eq!(
            e.notification.subcode,
            UpdateSubcode::OptionalAttributeError as u8
        );
        // Wrong flags on an MP attribute (RFC 7606 §5.3).
        let wire = [0, 0, 0, 7, 0xc0, 15, 4, 0, 2, 1, 0];
        assert_eq!(disabled(&wire), vec![AddressFamily::IPV6_UNICAST]);
    }

    /// The families an UPDATE disables, decoded on an eBGP four-octet
    /// session.
    fn disabled(wire: &[u8]) -> Vec<AddressFamily> {
        let d = UpdateMessage::decode(wire, &EBGP4).unwrap();
        d.disabled.iter().map(|x| x.family).collect()
    }

    /// `wire` with `attr` put first in its path attributes.
    fn with_first_attribute(wire: &[u8], attr: &[u8]) -> Vec<u8> {
        let w = usize::from(u16::from_be_bytes([wire[0], wire[1]]));
        let at = 2 + w;
        let len = u16::from_be_bytes([wire[at], wire[at + 1]]) + u16::try_from(attr.len()).unwrap();
        let mut out = wire.to_vec();
        out[at..at + 2].copy_from_slice(&len.to_be_bytes());
        out.splice(at + 2..at + 2, attr.iter().copied());
        out
    }

    #[test]
    fn the_rest_of_an_update_survives_an_incorrect_mp_attribute() {
        // RFC 4760 §7 disables the MP attribute's family only: the IPv4
        // routes in the RFC 4271 fields of the same UPDATE still count, so
        // that none is lost with the message (RFC 7606 §6: discarding an
        // UPDATE "could cause invalid routes to be kept").
        let bad_v6_reach = [0x80, 14, 9, 0, 2, 1, 4, 1, 2, 3, 4, 0];
        let mut m = announce();
        m.withdrawn = vec![p("10.1.0.0/16")];
        let wire = with_first_attribute(&m.encode(&ENC2).unwrap(), &bad_v6_reach);
        let d = UpdateMessage::decode(&wire, &EBGP2).unwrap();
        assert_eq!(d.disabled.len(), 1);
        assert!(d.disables(AddressFamily::IPV6_UNICAST));
        assert_eq!(d.treated_as_withdraw, None);
        assert_eq!(d.message, m);
        assert_eq!(
            d.announcements().collect::<Vec<_>>(),
            vec![(AddressFamily::IPV4_UNICAST, p("10.0.0.0/8"))]
        );
        assert_eq!(
            d.withdrawals().collect::<Vec<_>>(),
            vec![(AddressFamily::IPV4_UNICAST, p("10.1.0.0/16"))]
        );
        // A second incorrect MP attribute disables its family as well, and
        // that family's routes elsewhere in the message no longer count.
        let bad_v4_unreach = [0x80, 15, 4, 0, 1, 1, 33];
        let wire = with_first_attribute(&wire, &bad_v4_unreach);
        let d = UpdateMessage::decode(&wire, &EBGP2).unwrap();
        assert_eq!(
            d.disabled.iter().map(|x| x.family).collect::<Vec<_>>(),
            vec![AddressFamily::IPV4_UNICAST, AddressFamily::IPV6_UNICAST]
        );
        assert_eq!(d.announcements().count(), 0);
        assert_eq!(d.withdrawals().count(), 0);
        // Both attributes of one family disable it once.
        let bad_v6_unreach = [0x80, 15, 4, 0, 2, 1, 129];
        let wire = with_first_attribute(&m.encode(&ENC2).unwrap(), &bad_v6_reach);
        let wire = with_first_attribute(&wire, &bad_v6_unreach);
        let d = UpdateMessage::decode(&wire, &EBGP2).unwrap();
        assert_eq!(d.disabled.len(), 1);
        assert_eq!(d.announcements().count(), 1);
        // Other errors still apply to what is left (RFC 7606 §3 h).
        let mut broken = with_first_attribute(&ANNOUNCE, &bad_v6_reach);
        let origin = broken.len() - 2 - 27 + 3;
        assert_eq!(broken[origin - 2], code::ORIGIN);
        broken[origin] = 7;
        let d = UpdateMessage::decode(&broken, &EBGP2).unwrap();
        assert!(d.disables(AddressFamily::IPV6_UNICAST));
        assert_eq!(
            d.treated_as_withdraw.unwrap().subcode,
            UpdateSubcode::InvalidOrigin as u8
        );
        // A session reset outranks it: an MP attribute repeated after an
        // incorrect one (RFC 7606 §3 g).
        let twice = with_first_attribute(
            &with_first_attribute(&ANNOUNCE, &bad_v6_reach),
            &[0x80, 14, 5, 0, 2, 1, 0, 0],
        );
        let e = UpdateMessage::decode(&twice, &EBGP2).unwrap_err();
        assert_eq!(
            e.notification.subcode,
            UpdateSubcode::MalformedAttributeList as u8
        );
    }

    #[test]
    fn an_incorrect_mp_unreach_among_other_attributes_resets() {
        // RFC 7606 §5.2: no reachable NLRI but attributes other than
        // MP_UNREACH_NLRI, so an error that is not attribute discard resets
        // the session; AFI/SAFI disable is such an error.
        let bad_v6_unreach = [0x80, 15, 4, 0, 2, 1, 129];
        let m = UpdateMessage {
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::sequence(&[Asn(65_001)])),
            ],
            ..UpdateMessage::default()
        };
        let wire = with_first_attribute(&m.encode(&ENC4).unwrap(), &bad_v6_unreach);
        let e = UpdateMessage::decode(&wire, &EBGP4).unwrap_err();
        assert_eq!(
            e.notification,
            DecodeError::update(
                UpdateSubcode::OptionalAttributeError,
                bad_v6_unreach.to_vec()
            )
        );
        // Alone, it is AFI/SAFI disable.
        let mut alone = vec![0, 0, 0, 7];
        alone.extend_from_slice(&bad_v6_unreach);
        assert_eq!(disabled(&alone), vec![AddressFamily::IPV6_UNICAST]);
        // An incorrect MP_REACH_NLRI encodes reachable NLRI, so with the
        // same attributes it is AFI/SAFI disable too.
        let bad_v6_reach = [0x80, 14, 9, 0, 2, 1, 4, 1, 2, 3, 4, 0];
        let wire = with_first_attribute(&m.encode(&ENC4).unwrap(), &bad_v6_reach);
        assert_eq!(disabled(&wire), vec![AddressFamily::IPV6_UNICAST]);
        // Octets that cannot be parsed after an MP_UNREACH_NLRI are not
        // known to be MP_UNREACH_NLRI either.
        let mut tail = vec![0, 0, 0, 0];
        let unreach = [0x80, 15, 8, 0, 2, 1, 32, 0x20, 0x01, 0x0d, 0xb8];
        let tail_attrs = [&unreach[..], &[0x40]].concat();
        tail[3] = u8::try_from(tail_attrs.len()).unwrap();
        tail.extend_from_slice(&tail_attrs);
        let e = UpdateMessage::decode(&tail, &EBGP4).unwrap_err();
        assert_eq!(
            e.notification.subcode,
            UpdateSubcode::MalformedAttributeList as u8
        );
        // An End-of-RIB (RFC 4724) is fine.
        assert!(UpdateMessage::decode(&[0, 0, 0, 6, 0x80, 15, 3, 0, 2, 1], &EBGP4).is_ok());
    }

    #[test]
    fn mp_unreach_withdrawals_and_treat_as_withdraw_cover_mp_reach() {
        let m = UpdateMessage {
            mp_reach: Some(MpReach {
                family: AddressFamily::IPV6_UNICAST,
                next_hop: NextHop::Ipv6 {
                    global: "2001:db8::1".parse().unwrap(),
                    link_local: None,
                },
                nlri: vec![p("2001:db8:1::/48")],
            }),
            mp_unreach: Some(MpUnreach {
                family: AddressFamily::IPV6_UNICAST,
                withdrawn: vec![p("2001:db8:2::/48")],
            }),
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::sequence(&[Asn(65_001)])),
            ],
            ..UpdateMessage::default()
        };
        let mut wire = m.encode(&ENC4).unwrap();
        let d = UpdateMessage::decode(&wire, &EBGP4).unwrap();
        assert_eq!(d.message, m);
        assert_eq!(
            d.withdrawals().collect::<Vec<_>>(),
            vec![(AddressFamily::IPV6_UNICAST, p("2001:db8:2::/48"))]
        );
        assert_eq!(d.announcements().count(), 1);
        // Break ORIGIN (the 4 octets before the 9-octet AS_PATH): the
        // MP_REACH routes become withdrawals.
        let at = wire.len() - 9 - 1;
        assert_eq!(&wire[at - 3..at], &[0x40, 1, 1]);
        wire[at] = 7;
        let d = UpdateMessage::decode(&wire, &EBGP4).unwrap();
        assert!(d.treated_as_withdraw.is_some());
        assert_eq!(d.announcements().count(), 0);
        assert_eq!(
            d.withdrawals().collect::<Vec<_>>(),
            vec![
                (AddressFamily::IPV6_UNICAST, p("2001:db8:2::/48")),
                (AddressFamily::IPV6_UNICAST, p("2001:db8:1::/48")),
            ]
        );
    }

    #[test]
    fn ipv4_routes_with_an_ipv6_next_hop_need_rfc8950() {
        // RFC 8950 §6.1: IPv4 unicast NLRI in MP_REACH_NLRI with a 16-octet
        // IPv6 next hop, and no NEXT_HOP attribute (RFC 4760 §3).
        let global: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let m = UpdateMessage {
            mp_reach: Some(MpReach {
                family: AddressFamily::IPV4_UNICAST,
                next_hop: NextHop::Ipv6 {
                    global,
                    link_local: None,
                },
                nlri: vec![p("192.0.2.0/24")],
            }),
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::sequence(&[Asn(65_001)])),
            ],
            ..UpdateMessage::default()
        };
        // RFC 8950 §4: never sent without the capability.
        assert_eq!(
            m.encode(&ENC4),
            Err(EncodeError::NextHopNotNegotiated(
                AddressFamily::IPV4_UNICAST
            ))
        );
        let enc = EncodeContext {
            extended_next_hop: true,
            add_path: AddPathFamilies::NONE,
            ..ENC4
        };
        let wire = m.encode(&enc).unwrap();
        let mut attr = vec![0x80, code::MP_REACH_NLRI, 25, 0, 1, 1, 16];
        attr.extend_from_slice(&global.octets());
        attr.extend_from_slice(&[0, 24, 192, 0, 2]);
        assert_eq!(&wire[4..4 + attr.len()], &attr[..]);
        // Negotiated: an ordinary announcement.
        let ctx = DecodeContext {
            extended_next_hop: true,
            add_path: AddPathFamilies::NONE,
            ..EBGP4
        };
        let d = UpdateMessage::decode(&wire, &ctx).unwrap();
        assert_eq!(d.message, m);
        assert_eq!(d.treated_as_withdraw, None);
        assert_eq!(
            d.announcements().collect::<Vec<_>>(),
            vec![(AddressFamily::IPV4_UNICAST, p("192.0.2.0/24"))]
        );
        // Not advertised by us: the next hop length is not the expected
        // one, the attribute is malformed and IPv4 unicast is disabled (RFC
        // 7606 §7.11, RFC 4760 §7), with the attribute as NOTIFICATION data.
        let d = UpdateMessage::decode(&wire, &EBGP4).unwrap();
        assert_eq!(
            d.disabled,
            vec![DisabledFamily {
                family: AddressFamily::IPV4_UNICAST,
                error: DecodeError::update(UpdateSubcode::OptionalAttributeError, attr),
            }]
        );
        assert_eq!(d.announcements().count(), 0);
        // An IPv4 next hop in MP_REACH_NLRI needs nothing, and IPv6 NLRI
        // is not affected by the flag.
        let mut v4 = m.clone();
        if let Some(r) = &mut v4.mp_reach {
            r.next_hop = NextHop::Ipv4(Ipv4Addr::new(192, 0, 2, 1));
        }
        let wire = v4.encode(&ENC4).unwrap();
        assert_eq!(UpdateMessage::decode(&wire, &EBGP4).unwrap().message, v4);
        assert_eq!(
            EncodeError::NextHopNotNegotiated(AddressFamily::IPV4_UNICAST).to_string(),
            "IPv6 next hop for ipv4-unicast without the Extended Next Hop Encoding capability"
        );
    }

    const V4: AddressFamily = AddressFamily::IPV4_UNICAST;
    const V6: AddressFamily = AddressFamily::IPV6_UNICAST;

    fn add_path(families: &[AddressFamily]) -> (DecodeContext, EncodeContext) {
        let add_path = AddPathFamilies::of(families);
        (
            DecodeContext { add_path, ..EBGP4 },
            EncodeContext { add_path, ..ENC4 },
        )
    }

    /// The attributes of `ANNOUNCE`, four-octet.
    const ATTRS4: [u8; 30] = [
        0x40, 1, 1, 0, // ORIGIN igp
        0x40, 2, 10, 2, 2, 0, 0, 0xfd, 0xe9, 0, 0, 0xfd, 0xea, // AS_PATH seq
        0x40, 3, 4, 192, 0, 2, 1, // NEXT_HOP
        0x80, 4, 4, 0, 0, 0, // MED, completed below
    ];

    fn announce4(nlri: &[u8]) -> Vec<u8> {
        let mut wire = vec![0, 0, 0, 31];
        wire.extend_from_slice(&ATTRS4);
        wire.push(50);
        wire.extend_from_slice(nlri);
        wire
    }

    #[test]
    fn nlri_field_carries_a_path_identifier_for_each_prefix() {
        // RFC 7911 §3: Path Identifier (4 octets), Length, Prefix; two
        // paths for one prefix, which a plain UPDATE could not carry.
        let nlri = [0, 0, 0, 1, 8, 10, 0, 0, 0, 2, 8, 10];
        let wire = announce4(&nlri);
        let (dec, enc) = add_path(&[V4]);
        let d = UpdateMessage::decode(&wire, &dec).unwrap();
        assert_eq!(d.treated_as_withdraw, None);
        let m = &d.message;
        assert_eq!(m.nlri, vec![p("10.0.0.0/8"); 2]);
        assert_eq!(m.nlri_ids(), [PathId(1), PathId(2)]);
        assert!(m.withdrawn_ids().is_empty() && m.mp_reach_ids().is_empty());
        assert_eq!(m.encode(&enc).unwrap(), wire);
        assert_eq!(d.announcements().count(), 2);
        // The same octets on a session without it are no NLRI at all.
        assert!(UpdateMessage::decode(&wire, &EBGP4).is_err());
        // A message with no ids at all has no id lists: nothing is
        // allocated for a family without ADD-PATH.
        let plain = UpdateMessage::decode(&ANNOUNCE, &EBGP2).unwrap();
        assert_eq!(plain.message.path_ids, None);
    }

    #[test]
    fn withdrawn_routes_name_the_path_to_withdraw() {
        // RFC 7911 §5: a withdrawal is for a prefix and a Path Identifier.
        let wire = [
            0, 14, // withdrawn routes length
            0, 0, 0, 1, 8, 10, // path 1 of 10.0.0.0/8
            0, 0, 0, 7, 24, 192, 0, 2, // path 7 of 192.0.2.0/24
            0, 0, // no attributes
        ];
        let (dec, enc) = add_path(&[V4]);
        let d = UpdateMessage::decode(&wire, &dec).unwrap();
        assert_eq!(
            d.withdrawn_paths().collect::<Vec<_>>(),
            vec![
                (V4, p("10.0.0.0/8"), PathId(1)),
                (V4, p("192.0.2.0/24"), PathId(7))
            ]
        );
        assert_eq!(
            d.withdrawals().collect::<Vec<_>>(),
            vec![(V4, p("10.0.0.0/8")), (V4, p("192.0.2.0/24"))]
        );
        assert_eq!(d.message.encode(&enc).unwrap(), wire);
    }

    #[test]
    fn multiprotocol_attributes_carry_path_identifiers_per_family() {
        // RFC 7911 §3, §5: MP_REACH_NLRI and MP_UNREACH_NLRI of IPv6
        // unicast, while IPv4 unicast stays plain.
        let wire = vec![
            0, 2, 8, 10, // withdrawn routes: 10.0.0.0/8, plain
            0, 61, // total path attribute length
            0x80, 14, 30, 0, 2, 1, 16, // MP_REACH_NLRI, IPv6 unicast, next hop length
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // 2001:db8::1
            0, // reserved
            0, 0, 0, 9, 32, 0x20, 0x01, 0x0d, 0xb8, // path 9, 2001:db8::/32
            0x80, 15, 12, 0, 2, 1, // MP_UNREACH_NLRI, IPv6 unicast
            0, 0, 0, 3, 32, 0x20, 0x01, 0x0d, 0xb9, // path 3, 2001:db9::/32
            0x40, 1, 1, 0, // ORIGIN igp
            0x40, 2, 6, 2, 1, 0, 0, 0xfd, 0xe9, // AS_PATH 65001
        ];
        assert_eq!(wire.len(), 6 + 61);
        let (dec, enc) = add_path(&[V6]);
        let d = UpdateMessage::decode(&wire, &dec).unwrap();
        assert_eq!(d.treated_as_withdraw, None, "{:?}", d.discarded);
        assert_eq!(d.disabled, vec![]);
        let m = &d.message;
        assert_eq!(m.withdrawn, vec![p("10.0.0.0/8")]);
        assert!(m.withdrawn_ids().is_empty(), "IPv4 has no ADD-PATH here");
        assert_eq!(m.mp_reach.as_ref().unwrap().nlri, vec![p("2001:db8::/32")]);
        assert_eq!(m.mp_reach_ids(), [PathId(9)]);
        assert_eq!(
            m.mp_unreach.as_ref().unwrap().withdrawn,
            vec![p("2001:db9::/32")]
        );
        assert_eq!(m.mp_unreach_ids(), [PathId(3)]);
        assert_eq!(
            d.withdrawn_paths().collect::<Vec<_>>(),
            vec![
                (V4, p("10.0.0.0/8"), PathId(0)),
                (V6, p("2001:db9::/32"), PathId(3)),
            ]
        );
        assert_eq!(m.encode(&enc).unwrap(), wire);
    }

    #[test]
    fn ipv4_in_mp_reach_follows_the_ipv4_entry() {
        // RFC 8950 §3 carries IPv4 unicast NLRI in MP_REACH_NLRI: the
        // <IPv4, unicast> tuple of RFC 7911 §4 is what governs them.
        let m = UpdateMessage {
            mp_reach: Some(MpReach {
                family: V4,
                next_hop: NextHop::Ipv4(Ipv4Addr::new(192, 0, 2, 1)),
                nlri: vec![p("10.0.0.0/8")],
            }),
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath::sequence(&[Asn(65_001)])),
            ],
            path_ids: Some(Box::new(PathIds {
                mp_reach: vec![PathId(5)],
                ..PathIds::default()
            })),
            ..UpdateMessage::default()
        };
        let (dec, enc) = add_path(&[V4]);
        let wire = m.encode(&enc).unwrap();
        assert_eq!(UpdateMessage::decode(&wire, &dec).unwrap().message, m);
        // IPv6 alone does not cover it.
        let (_, enc6) = add_path(&[V6]);
        assert_eq!(m.encode(&enc6), Err(EncodeError::PathIdsNotNegotiated(V4)));
    }

    #[test]
    fn a_broken_path_identifier_is_a_broken_nlri() {
        // RFC 7606 §5.3 with RFC 7911 §3: a tuple cut short in the NLRI or
        // Withdrawn Routes field resets the session, one in an MP
        // attribute disables its family (RFC 4760 §7).
        let (dec4, _) = add_path(&[V4]);
        let (dec6, _) = add_path(&[V6]);
        for wire in [
            announce4(&[0, 0, 0, 1, 8]),
            announce4(&[0, 0, 0]),
            vec![0, 5, 0, 0, 0, 1, 8, 0, 0],
        ] {
            let e = UpdateMessage::decode(&wire, &dec4).unwrap_err();
            assert_eq!(
                e.notification.subcode,
                UpdateSubcode::InvalidNetworkField as u8,
                "{wire:?}"
            );
        }
        // MP_UNREACH_NLRI for IPv6 with a length of 129 after the id.
        let wire = [
            0, 0, 0, 12, 0x80, 15, 9, 0, 2, 1, 0, 0, 0, 1, 129, 0, //
        ];
        let d = UpdateMessage::decode(&wire, &dec6).unwrap();
        assert_eq!(
            d.disabled.iter().map(|x| x.family).collect::<Vec<_>>(),
            vec![V6]
        );
    }

    #[test]
    fn encoding_checks_the_identifiers_against_the_negotiation() {
        // RFC 7911 §5: an identifier per prefix for a family with ADD-PATH,
        // none for any other.
        let (_, enc) = add_path(&[V4]);
        let plain = UpdateMessage {
            withdrawn: vec![p("10.0.0.0/8")],
            ..UpdateMessage::default()
        };
        assert_eq!(plain.encode(&enc), Err(EncodeError::PathIdsMissing(V4)));
        let with = UpdateMessage {
            path_ids: Some(Box::new(PathIds {
                withdrawn: vec![PathId(1)],
                ..PathIds::default()
            })),
            ..plain.clone()
        };
        assert!(with.encode(&enc).is_ok());
        assert_eq!(
            with.encode(&ENC4),
            Err(EncodeError::PathIdsNotNegotiated(V4))
        );
        let two = UpdateMessage {
            withdrawn: vec![p("10.0.0.0/8"), p("11.0.0.0/8")],
            ..with
        };
        assert_eq!(two.encode(&enc), Err(EncodeError::PathIdsMissing(V4)));
        // Empty lists need no identifiers either way.
        assert!(UpdateMessage::default().encode(&enc).is_ok());
        assert_eq!(
            EncodeError::PathIdsMissing(V4).to_string(),
            "ipv4-unicast NLRI without a Path Identifier for every prefix, with ADD-PATH"
        );
        assert_eq!(
            EncodeError::PathIdsNotNegotiated(V6).to_string(),
            "Path Identifiers for ipv6-unicast without ADD-PATH"
        );
    }

    #[test]
    fn add_path_families_are_the_ones_this_implementation_parses() {
        let both = AddPathFamilies::of(&[V4, V6]);
        assert!(both.contains(V4) && both.contains(V6) && !both.is_empty());
        let odd = AddressFamily {
            afi: Afi::Ipv4,
            safi: crate::types::Safi::Multicast,
        };
        assert!(!AddPathFamilies::of(&[odd]).contains(odd));
        assert!(AddPathFamilies::of(&[odd]).is_empty());
        assert_eq!(AddPathFamilies::of(&[]), AddPathFamilies::NONE);
        assert!(!AddPathFamilies::of(&[V6]).contains(V4));
    }

    #[test]
    fn encode_limits() {
        let m = UpdateMessage {
            withdrawn: vec![p("10.0.0.0/8"); 40_000],
            ..UpdateMessage::default()
        };
        assert!(matches!(
            m.encode(&ENC4),
            Err(EncodeError::TooLong {
                what: "withdrawn routes",
                ..
            })
        ));
        let m = UpdateMessage {
            attributes: vec![PathAttribute::Unknown {
                flags: 0xc0,
                code: 99,
                value: vec![0; 65_535],
            }],
            ..UpdateMessage::default()
        };
        assert!(matches!(
            m.encode(&ENC4),
            Err(EncodeError::TooLong {
                what: "path attributes",
                ..
            })
        ));
    }
}
