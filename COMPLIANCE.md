# Compliance

One row per MUST / SHOULD / MAY in each in-scope RFC (AGENTS.md §6).

- **Level**: MUST, SHOULD or MAY as written in the RFC (MUST NOT and SHOULD
  NOT count as MUST and SHOULD).
- **Status**: `done`, `partial`, `todo`, `n/a`, or `deviates` (with a reason).
- **Code** / **Test**: file paths, `path:line` where useful. `wire/` is
  `crates/bgpfc-wire/src/`.

The README must not claim compliance with an RFC until every MUST row for it
is `done`.

## RFC 4271 — A Border Gateway Protocol 4 (BGP-4)

| RFC § | Requirement (short) | Level | Status | Code | Test |
|---|---|---|---|---|---|
| 4.1 | Marker is 16 octets of all ones | MUST | done | wire/header.rs `MARKER`, `Header::encode` | header.rs `encode_and_frame` |
| 4.1 | Length field 19..=4096 inclusive (65535 per RFC 8654) | MUST | done | wire/header.rs `Header::decode` | header.rs `length_bounds_carry_the_length_field_as_data` |
| 4.1 | No padding; Length is the smallest value for the message | MUST | done (OPEN) | wire/open.rs `OpenMessage::decode` trailing check | open.rs `parameter_errors` |
| 4.1 | Type is OPEN/UPDATE/NOTIFICATION/KEEPALIVE (+ROUTE-REFRESH) | MUST | done | wire/header.rs `MessageType` | header.rs `message_type_table` |
| 4.2 | Hold Timer = min(configured, received) | MUST | todo (FSM) | | |
| 4.2 | Hold Time is zero or at least three seconds | MUST | done | wire/types.rs `HoldTime::new` | types.rs `hold_time_rejects_one_and_two` |
| 4.2 | May reject connections on the basis of Hold Time | MAY | todo (FSM) | | |
| 4.2 | Minimum OPEN length is 29 octets | MUST | done | wire/header.rs `MessageType::min_len` | header.rs `length_bounds_carry_the_length_field_as_data` |
| 6.1 | Header errors use Error Code Message Header Error | MUST | done | wire/error.rs `DecodeError::header` | header.rs tests |
| 6.1 | Bad marker → Connection Not Synchronized | MUST | done | wire/header.rs `Header::decode` | header.rs `bad_marker_is_connection_not_synchronized` |
| 6.1 | Length <19, >4096, or below per-type minimum (OPEN 29, UPDATE 23, KEEPALIVE =19, NOTIFICATION 21) → Bad Message Length, Data = Length field | MUST | done | wire/header.rs `Header::decode`, `MessageType::min_len`/`max_len` | header.rs `length_bounds_carry_the_length_field_as_data` |
| 6.1 | Unknown Type → Bad Message Type, Data = Type field | MUST | done | wire/header.rs `Header::decode` | header.rs `unknown_type_carries_the_type_as_data` |
| 6.2 | OPEN errors use Error Code OPEN Message Error | MUST | done | wire/error.rs `DecodeError::open` | open.rs tests |
| 6.2 | Unsupported version → Unsupported Version Number, Data = 2-octet supported version | MUST | done | wire/open.rs `OpenMessage::decode` | open.rs `fixed_field_errors` |
| 6.2 | Unacceptable AS → Bad Peer AS | MUST | partial (AS 0 only; configured-AS check is the FSM's) | wire/open.rs `OpenMessage::decode` | open.rs `fixed_field_errors` |
| 6.2 | Hold Time 1 or 2 → Unacceptable Hold Time | MUST | done | wire/open.rs, wire/types.rs `HoldTime::new` | open.rs `fixed_field_errors` |
| 6.2 | May reject any Hold Time | MAY | todo (FSM) | | |
| 6.2 | Use the negotiated Hold Time | MUST | todo (FSM) | | |
| 6.2 | Syntactically bad BGP Identifier → Bad BGP Identifier | MUST | done (RFC 6286 §2.1: non-zero) | wire/open.rs, wire/types.rs `RouterId::new` | open.rs `fixed_field_errors`, types.rs `router_id_rejects_zero_only` |
| 6.2 | Unrecognised optional parameter → Unsupported Optional Parameters | MUST | done | wire/open.rs `decode_parameters` | open.rs `parameter_errors` |
| 6.2 | Recognised but malformed optional parameter → subcode 0 | MUST | done | wire/open.rs `malformed`, wire/capability.rs `malformed` | open.rs `parameter_errors`, capability.rs `malformed_known_capabilities_are_unspecific_open_errors` |

Rows for §4.3–§4.5, §5, §6.3–§6.8, §8 and §9 are added by the PRs that
implement them.

## RFC 5492 — Capabilities Advertisement

| RFC § | Requirement (short) | Level | Status | Code | Test |
|---|---|---|---|---|---|
| 4 | Capabilities parameter type 2, `<Code, Length, Value>` triples | MUST | done | wire/capability.rs `Capability::encode`/`decode` | capability.rs `known_capabilities_round_trip` |
| 4 | Do not send duplicate identical capabilities | SHOULD | done (encoder emits the given list once) | wire/open.rs `encode_capabilities` | open.rs `open_with_capabilities_round_trips` |
| 4 | Accept duplicate identical capabilities | MUST | done | wire/open.rs `decode_parameters` | open.rs `several_capabilities_parameters_are_merged` |
| 4 | Include the Capabilities parameter once | SHOULD | done | wire/open.rs `encode_with` | open.rs `several_capabilities_parameters_are_merged` |
| 4 | Accept several Capabilities parameters and merge them | MUST | done | wire/open.rs `decode_parameters` | open.rs `several_capabilities_parameters_are_merged` |
| 5 | Unsupported Capability subcode 7, Data lists the capabilities | MUST | partial (subcode defined; sending is the FSM's) | wire/error.rs `OpenSubcode::UnsupportedCapability` | error.rs `constructors_set_code_and_subcode` |
| 5 | Never send Unsupported Capability for a capability not understood; ignore it | MUST | done (decoder keeps it as `Unknown`) | wire/capability.rs `Capability::decode` | capability.rs `unknown_capabilities_are_kept_not_rejected` |

## RFC 6793 — Four-Octet AS Numbers

| RFC § | Requirement (short) | Level | Status | Code | Test |
|---|---|---|---|---|---|
| 3 | Capability 65, length 4, carries the speaker's ASN | MUST | done | wire/capability.rs | capability.rs `known_capabilities_round_trip` |
| 3 | My Autonomous System = `AS_TRANS` (23456) when the ASN is not mappable | MUST | done | wire/open.rs `OpenMessage::new`, wire/types.rs `Asn::to_two_octet` | open.rs `new_uses_as_trans_for_a_four_octet_asn` |
| 3 | AS4_PATH / AS4_AGGREGATOR attributes | MUST | todo (UPDATE PR) | | |
| 4 | Interaction between NEW and OLD speakers | MUST | todo (UPDATE PR) | | |

## RFC 4760 — Multiprotocol Extensions

| RFC § | Requirement (short) | Level | Status | Code | Test |
|---|---|---|---|---|---|
| 8 | Use capability advertisement to negotiate | SHOULD | done (codec; FSM uses it later) | wire/capability.rs | capability.rs |
| 8 | Capability 1, length 4: AFI, reserved, SAFI | MUST | done | wire/capability.rs | capability.rs `known_capabilities_round_trip` |
| 8 | Reserved octet zero on send, ignored on receipt | SHOULD | done | wire/capability.rs | capability.rs `multiprotocol_ignores_the_reserved_octet` |
| 8 | Both sides must advertise an `<AFI, SAFI>` to exchange it | MUST | todo (FSM) | | |
| 3–5 | MP_REACH_NLRI / MP_UNREACH_NLRI | MUST | todo (UPDATE PR) | | |

## RFC 2918 — Route Refresh

| RFC § | Requirement (short) | Level | Status | Code | Test |
|---|---|---|---|---|---|
| 2 | Capability 2, length 0 | MUST | done | wire/capability.rs | capability.rs `known_capabilities_round_trip` |
| 3 | ROUTE-REFRESH message type 5, `<AFI, Res, SAFI>` | MUST | partial (type code; message in next PR) | wire/header.rs `MessageType::RouteRefresh` | header.rs `message_type_table` |
| 4 | Send only if the peer advertised the capability; ignore unadvertised families | SHOULD | todo (RIB) | | |

## RFC 7606 — Revised Error Handling

| RFC § | Requirement (short) | Level | Status | Code | Test |
|---|---|---|---|---|---|

## RFC 8654 — Extended Messages

| RFC § | Requirement (short) | Level | Status | Code | Test |
|---|---|---|---|---|---|
| 3 | Capability 6, length 0 | MUST | done | wire/capability.rs | capability.rs `known_capabilities_round_trip` |
| 3 | Peers using it must support RFC 7606 error handling | MUST | todo (UPDATE PR) | | |
| 4 | Applies to all messages except OPEN and KEEPALIVE | MUST | done | wire/header.rs `MessageType::max_len` | header.rs `extended_messages_only_when_negotiated_and_never_for_open_or_keepalive` |
| 4 | Advertise the capability when able | SHOULD | todo (config/FSM) | | |
| 4 | Send extended messages only if the peer advertised the capability | MAY | todo (RIB update packing) | | |
| 4 | Having advertised it, accept up to 65535 octets | MUST | done | wire/header.rs `Header::decode` | header.rs `extended_messages_only_when_negotiated_and_never_for_open_or_keepalive` |
| 4 | Over 4096 without the capability → Bad Message Length | MUST | done | wire/header.rs `Header::decode` | header.rs `extended_messages_only_when_negotiated_and_never_for_open_or_keepalive` |
| 5 | Never accept extended messages without having advertised the capability | MUST | done | wire/header.rs `Header::decode` (`extended` flag) | header.rs |
| 5 | NOTIFICATION to a non-extended peer at most 4096 octets | MUST | todo (NOTIFICATION PR) | | |
| 4 | Shrink or withhold an over-size UPDATE for a non-extended neighbour | SHOULD | todo (RIB) | | |

## RFC 1997 / 4360 / 8092 — Communities

| RFC § | Requirement (short) | Level | Status | Code | Test |
|---|---|---|---|---|---|

## RFC 4486 / 6608 / 9003 — NOTIFICATION subcodes and shutdown communication

| RFC § | Requirement (short) | Level | Status | Code | Test |
|---|---|---|---|---|---|

## RFC 7607 / 9072 / 9687 / 9774 — AS 0, extended OPEN parameters, send hold timer, AS_SET deprecation

| RFC § | Requirement (short) | Level | Status | Code | Test |
|---|---|---|---|---|---|
| 7607 §2 | AS 0 as peer AS in OPEN → Bad Peer AS | MUST | done | wire/open.rs `OpenMessage::decode` | open.rs `fixed_field_errors` |
| 7607 §2 | Never initiate a connection claiming AS 0 | MUST | todo (config validation) | | |
| 7607 §2 | AS 0 in AS_PATH / AGGREGATOR | MUST | todo (UPDATE PR) | | |
| 9072 §2 | Use the RFC 4271 encoding when parameters fit 255 octets | SHOULD | done | wire/open.rs `encode_with` | open.rs `open_with_capabilities_round_trips` |
| 9072 §2 | May force the extended encoding by configuration | MAY | done (codec flag; config knob later) | wire/open.rs `encode_with(true)` | open.rs `extended_parameters_are_chosen_when_needed_and_accepted_always` |
| 9072 §2 | Accept the extended encoding even for ≤255 octets | MUST | done | wire/open.rs `decode_parameters` | open.rs `extended_parameters_are_chosen_when_needed_and_accepted_always` |
| 9072 §2 | Use the extended encoding when parameters exceed 255 octets | MUST | done | wire/open.rs `encode_with` | open.rs `extended_parameters_are_chosen_when_needed_and_accepted_always` |
| 9072 §2 | Non-Ext OP Len. 255 on send, never 0, ignored on receipt | SHOULD/MUST | done | wire/open.rs | open.rs `extended_parameters_are_chosen_when_needed_and_accepted_always` |
| 9072 §2 | Non-Ext OP Type 255 on send; 255 on receipt selects extended | MUST | done | wire/open.rs | open.rs `extended_parameters_are_chosen_when_needed_and_accepted_always` |
| 9072 §3 | Type 255 elsewhere is an unrecognised parameter | MUST | done | wire/open.rs `decode_parameters` | open.rs `parameter_errors` |
| 6286 §2.1 | BGP Identifier is any non-zero 4-octet value | MUST | done | wire/types.rs `RouterId::new` | types.rs `router_id_rejects_zero_only` |
