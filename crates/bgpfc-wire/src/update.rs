//! The UPDATE message, with RFC 7606 error handling.
//!
//! Decoding does not simply fail on a bad attribute. Following RFC 7606,
//! each problem is classified as one of:
//!
//! - **session reset**: the message cannot be trusted at all; the caller
//!   sends the NOTIFICATION in [`UpdateError`] and closes the session;
//! - **AFI/SAFI disable**: a multiprotocol attribute is unusable; the caller
//!   drops that family's routes from this peer (RFC 4760 §7);
//! - **treat-as-withdraw**: every route the message announces is withdrawn
//!   instead ([`DecodedUpdate::treated_as_withdraw`]);
//! - **attribute discard**: the attribute is dropped and the rest of the
//!   message stands ([`DecodedUpdate::discarded`]).
//!
//! Implements: RFC 4271 §4.3 (format), §5 (attribute categories), §6.3
//! (error subcodes); RFC 7606 §3, §4, §5.1–§5.3, §7.1–§7.8, §7.11, §7.12,
//! §7.14; RFC 4760 §3, §4, §7; RFC 6793 §4.2.2, §4.2.3, §6; RFC 7607 §2;
//! RFC 9774 §3; RFC 8092 §6.

use std::fmt;
use std::net::Ipv4Addr;

use crate::as_path::AsPath;
use crate::attribute::{
    Aggregator, Origin, PathAttribute, RawAttribute, code, encode_attribute, expected_flags, flags,
    parse_raw,
};
use crate::community::{decode_communities, decode_extended_communities, decode_large_communities};
use crate::error::{DecodeError, EncodeError, UpdateSubcode};
use crate::mp::{MpReach, MpUnreach, family_of};
use crate::prefix::{Prefix, decode_prefixes, encode_prefixes};
use crate::reader::{Reader, WriteBytes as _};
use crate::types::{AddressFamily, Afi, Asn};

/// Whether the peer is in the local AS (RFC 4271 §5: it changes which
/// attributes are expected and which are ignored).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerKind {
    /// Internal BGP: same AS.
    Internal,
    /// External BGP: different AS.
    External,
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
}

/// What the encoder needs to know about the session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncodeContext {
    /// Both sides advertised the Four-octet AS capability. When false,
    /// `AS_PATH` and AGGREGATOR are two-octet with `AS_TRANS` and the
    /// `AS4_*` attributes are generated as RFC 6793 §4.2.2 requires.
    pub four_octet_as: bool,
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
}

impl UpdateMessage {
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
    /// [`EncodeError`] if a field exceeds its length field or an `AS_PATH`
    /// segment cannot be encoded.
    pub fn encode(&self, ctx: &EncodeContext) -> Result<Vec<u8>, EncodeError> {
        let mut withdrawn = Vec::new();
        encode_prefixes(&self.withdrawn, &mut withdrawn);
        let withdrawn_len = u16::try_from(withdrawn.len()).map_err(|_| EncodeError::TooLong {
            what: "withdrawn routes",
            len: withdrawn.len(),
            max: usize::from(u16::MAX),
        })?;

        let mut encoded: Vec<(u8, Vec<u8>)> = Vec::with_capacity(self.attributes.len() + 4);
        if let Some(m) = &self.mp_reach {
            let mut buf = Vec::new();
            PathAttribute::MpReach(m.clone()).encode(ctx.four_octet_as, &mut buf)?;
            encoded.push((0, buf));
        }
        if let Some(m) = &self.mp_unreach {
            let mut buf = Vec::new();
            PathAttribute::MpUnreach(m.clone()).encode(ctx.four_octet_as, &mut buf)?;
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
        encode_prefixes(&self.nlri, &mut out);
        Ok(out)
    }

    /// Decode a body (the octets after the header, at least four).
    ///
    /// # Errors
    /// [`UpdateError`] when RFC 7606 calls for a session reset or an
    /// AFI/SAFI disable. Treat-as-withdraw and attribute discard are not
    /// errors; see [`DecodedUpdate`].
    pub fn decode(body: &[u8], ctx: &DecodeContext) -> Result<DecodedUpdate, UpdateError> {
        let (withdrawn_bytes, attr_bytes, nlri_bytes) = split_fields(body)?;
        // RFC 7606 §3 i) and §5.3: both prefix fields are checked for syntax,
        // and RFC 7606 §3 j): if the NLRI cannot be parsed, treat-as-withdraw
        // is impossible, so RFC 4271 §6.3 Invalid Network Field resets.
        let withdrawn = decode_prefixes(withdrawn_bytes, Afi::Ipv4)
            .map_err(|_| UpdateError::reset(UpdateSubcode::InvalidNetworkField, Vec::new()))?;
        let nlri = decode_prefixes(nlri_bytes, Afi::Ipv4)
            .map_err(|_| UpdateError::reset(UpdateSubcode::InvalidNetworkField, Vec::new()))?;
        let mut st = State::default();
        decode_attributes(attr_bytes, *ctx, &mut st)?;
        apply_as4(&mut st, *ctx);
        // RFC 4271 §5: any order is accepted; ascending type order is the
        // canonical form, so equal messages compare equal.
        st.attributes.sort_by_key(PathAttribute::code);
        let message = UpdateMessage {
            withdrawn,
            nlri,
            mp_reach: st.mp_reach.take(),
            mp_unreach: st.mp_unreach.take(),
            attributes: std::mem::take(&mut st.attributes),
        };
        check_mandatory(&message, &mut st);
        // RFC 7606 §5.2: with no reachable NLRI and attributes other than
        // MP_UNREACH_NLRI, a non-discard error cannot be handled as a
        // withdraw, so the session is reset.
        if let Some(e) = &st.withdraw
            && !message.has_reachable()
            && !message.attributes.is_empty()
        {
            return Err(UpdateError {
                action: ErrorAction::SessionReset,
                notification: e.clone(),
            });
        }
        Ok(DecodedUpdate {
            message,
            treated_as_withdraw: st.withdraw,
            discarded: st.discarded,
        })
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
    as4_path: Option<AsPath>,
    as4_aggregator: Option<Aggregator>,
    /// Bitset of attribute type codes already seen.
    seen: [u64; 4],
    /// First treat-as-withdraw error, if any (RFC 7606 §3 h): all of them
    /// have the same strength, so the first is reported).
    withdraw: Option<DecodeError>,
    discarded: Vec<DiscardedAttribute>,
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

    fn discard(&mut self, code: u8, reason: DiscardReason) {
        self.discarded.push(DiscardedAttribute { code, reason });
    }
}

/// What one attribute turned out to be.
enum Outcome {
    Keep(PathAttribute),
    As4Path(AsPath),
    As4Aggregator(Aggregator),
    /// Unrecognised optional non-transitive: quietly ignored (RFC 4271 §5).
    Ignore,
    Discard(DiscardReason),
    Withdraw(DecodeError),
}

fn decode_attributes(bytes: &[u8], ctx: DecodeContext, st: &mut State) -> Result<(), UpdateError> {
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
            break;
        };
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
            Outcome::Keep(PathAttribute::MpReach(m)) => st.mp_reach = Some(m),
            Outcome::Keep(PathAttribute::MpUnreach(m)) => st.mp_unreach = Some(m),
            Outcome::Keep(a) => st.attributes.push(a),
            Outcome::As4Path(p) => st.as4_path = Some(p),
            Outcome::As4Aggregator(a) => st.as4_aggregator = Some(a),
            Outcome::Ignore => {}
            Outcome::Discard(reason) => st.discard(raw.code, reason),
            Outcome::Withdraw(e) => st.withdraw(e),
        }
    }
    Ok(())
}

/// Classify and decode one attribute. `Err` is a session reset or an
/// AFI/SAFI disable; everything milder is an [`Outcome`].
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
            code::MP_REACH_NLRI | code::MP_UNREACH_NLRI => return Err(mp_failure(raw, None)),
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
        // RFC 7606 §7.3: length only; semantic checks are the RIB's
        // (RFC 4271 §6.3 says to log and ignore the route, never reset).
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
        code::MP_REACH_NLRI => match MpReach::decode(v) {
            Ok(m) => Outcome::Keep(PathAttribute::MpReach(m)),
            Err(e) => return Err(mp_failure(raw, e.family())),
        },
        code::MP_UNREACH_NLRI => match MpUnreach::decode(v) {
            Ok(m) => Outcome::Keep(PathAttribute::MpUnreach(m)),
            Err(e) => return Err(mp_failure(raw, e.family())),
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
    // passed on with the Partial bit set.
    Ok(Outcome::Keep(PathAttribute::Unknown {
        flags: raw.flags & !flags::EXTENDED_LENGTH,
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
/// known, else a session reset, in both cases with the NOTIFICATION RFC 4760
/// §7 names (UPDATE Message Error / Optional Attribute Error).
fn mp_failure(raw: &RawAttribute<'_>, family: Option<AddressFamily>) -> UpdateError {
    let notification = DecodeError::update(UpdateSubcode::OptionalAttributeError, raw.raw.to_vec());
    let action = match family.or_else(|| family_of(raw.value)) {
        Some(f) => ErrorAction::AfiSafiDisable(f),
        None => ErrorAction::SessionReset,
    };
    UpdateError {
        action,
        notification,
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

/// What a session-level UPDATE error requires of the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorAction {
    /// Send the NOTIFICATION and close the session (RFC 7606 §2).
    SessionReset,
    /// Drop every route of this family learned from the peer and ignore the
    /// family for the rest of the session (RFC 4760 §7); the session MAY be
    /// reset instead with the same NOTIFICATION.
    AfiSafiDisable(AddressFamily),
}

/// An UPDATE that cannot be processed even as a withdraw.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateError {
    /// Required reaction.
    pub action: ErrorAction,
    /// The NOTIFICATION to send if the session is reset.
    pub notification: DecodeError,
}

impl UpdateError {
    fn reset(subcode: UpdateSubcode, data: Vec<u8>) -> UpdateError {
        UpdateError {
            action: ErrorAction::SessionReset,
            notification: DecodeError::update(subcode, data),
        }
    }
}

impl fmt::Display for UpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.action {
            ErrorAction::SessionReset => write!(f, "session reset: {}", self.notification),
            ErrorAction::AfiSafiDisable(fam) => {
                write!(f, "disable {fam}: {}", self.notification)
            }
        }
    }
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedUpdate {
    /// The message as received, after attribute discards and `AS4_*` merging.
    pub message: UpdateMessage,
    /// Set when the message must be treated as a withdrawal of everything it
    /// announces (RFC 7606 §2 "treat-as-withdraw"); the error is for the log.
    pub treated_as_withdraw: Option<DecodeError>,
    /// Attributes dropped from `message`.
    pub discarded: Vec<DiscardedAttribute>,
}

impl DecodedUpdate {
    /// Every route the receiver must withdraw: the withdrawn fields, plus
    /// the announced routes when treated as withdraw.
    pub fn withdrawals(&self) -> impl Iterator<Item = (AddressFamily, Prefix)> + '_ {
        let m = &self.message;
        let v4 = AddressFamily::IPV4_UNICAST;
        let taw = self.treated_as_withdraw.is_some();
        m.withdrawn
            .iter()
            .map(move |p| (v4, *p))
            .chain(
                m.mp_unreach
                    .iter()
                    .flat_map(|u| u.withdrawn.iter().map(move |p| (u.family, *p))),
            )
            .chain(m.nlri.iter().filter(move |_| taw).map(move |p| (v4, *p)))
            .chain(
                m.mp_reach
                    .iter()
                    .filter(move |_| taw)
                    .flat_map(|r| r.nlri.iter().map(move |p| (r.family, *p))),
            )
    }

    /// Every route the receiver may install with `message.attributes`;
    /// empty when treated as withdraw.
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
    };
    const ENC4: EncodeContext = EncodeContext {
        four_octet_as: true,
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
            assert_eq!(e.action, ErrorAction::SessionReset);
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
        assert_eq!(e.action, ErrorAction::SessionReset);
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
        assert_eq!(e.action, ErrorAction::SessionReset);
        assert_eq!(
            e.notification.subcode,
            UpdateSubcode::UnrecognizedWellKnownAttribute as u8
        );
        assert_eq!(e.notification.data, vec![0x40, 99, 1, 7]);
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
        assert_eq!(e.action, ErrorAction::SessionReset);
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
        assert_eq!(e.action, ErrorAction::SessionReset);
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
        let set = AsPath {
            segments: vec![crate::as_path::AsPathSegment {
                kind: crate::as_path::SegmentType::Set,
                asns: vec![Asn(65_001)],
            }],
        };
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

    #[test]
    fn mp_attribute_errors_disable_the_family() {
        // RFC 4760 §7 + RFC 7606 §7.11.
        let mut wire = vec![0, 0, 0, 0];
        let attr = [0x80, 14, 9, 0, 2, 1, 4, 1, 2, 3, 4, 0];
        wire.extend_from_slice(&attr);
        wire[3] = 12;
        let e = UpdateMessage::decode(&wire, &EBGP4).unwrap_err();
        assert_eq!(
            e.action,
            ErrorAction::AfiSafiDisable(AddressFamily::IPV6_UNICAST)
        );
        assert_eq!(
            e.notification.subcode,
            UpdateSubcode::OptionalAttributeError as u8
        );
        assert_eq!(e.notification.data, attr);
        // Unsupported family: disabled too.
        let mut wire = vec![0, 0, 0, 7, 0x80, 15, 4, 0, 1, 128, 0];
        let e = UpdateMessage::decode(&wire, &EBGP4).unwrap_err();
        assert_eq!(
            e.action,
            ErrorAction::AfiSafiDisable(AddressFamily {
                afi: Afi::Ipv4,
                safi: Safi::Unknown(128)
            })
        );
        // Too short to name a family: session reset.
        wire.truncate(9);
        wire[3] = 5;
        wire[6] = 2;
        let e = UpdateMessage::decode(&wire, &EBGP4).unwrap_err();
        assert_eq!(e.action, ErrorAction::SessionReset);
        // Wrong flags on an MP attribute (RFC 7606 §5.3).
        let wire = [0, 0, 0, 7, 0xc0, 15, 4, 0, 2, 1, 0];
        let e = UpdateMessage::decode(&wire, &EBGP4).unwrap_err();
        assert_eq!(
            e.action,
            ErrorAction::AfiSafiDisable(AddressFamily::IPV6_UNICAST)
        );
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
