# Compliance

One row per MUST / SHOULD / MAY in each in-scope RFC (AGENTS.md §6).

- **Level**: MUST, SHOULD or MAY as written in the RFC (MUST NOT and SHOULD
  NOT count as MUST and SHOULD).
- **Status**: `done`, `partial`, `todo`, `n/a`, or `deviates` (with a reason).
- **Code** / **Test**: file paths, `path:line` where useful. `wire/` is
  `crates/bgpfc-wire/src/`, `fsm/` is `crates/bgpfc-fsm/src/`, "fsm
  tests" are `crates/bgpfc-fsm/src/machine/tests.rs`, `bgpfcd/` is
  `crates/bgpfcd/src/`, `config/` is `crates/bgpfc-config/src/`
  ("config golden" is `crates/bgpfc-config/tests/golden/`), `rib/` is
  `crates/bgpfc-rib/src/` ("rib tests" are `crates/bgpfc-rib/src/tests.rs`),
  `policy/` is `crates/bgpfc-policy/src/` ("policy tests" are
  `crates/bgpfc-policy/src/tests.rs`), `fib/` is `crates/bgpfc-fib/src/`,
  `sys/` is `crates/bgpfc-sys/src/`, and "interop" names a test in
  `interop/tests/bird.rs`.

The README must not claim compliance with an RFC until every MUST row for it
is `done`.

## RFC 4271 — A Border Gateway Protocol 4 (BGP-4)

| RFC § | Requirement (short) | Level | Status | Code | Test |
|---|---|---|---|---|---|
| 4.1 | Marker is 16 octets of all ones | MUST | done | wire/header.rs `MARKER`, `Header::encode` | header.rs `encode_and_frame` |
| 4.1 | Length field 19..=4096 inclusive (65535 per RFC 8654) | MUST | done | wire/header.rs `Header::decode` | header.rs `length_bounds_carry_the_length_field_as_data` |
| 4.1 | No padding; Length is the smallest value for the message | MUST | done (OPEN) | wire/open.rs `OpenMessage::decode` trailing check | open.rs `parameter_errors` |
| 4.1 | Type is OPEN/UPDATE/NOTIFICATION/KEEPALIVE (+ROUTE-REFRESH) | MUST | done | wire/header.rs `MessageType` | header.rs `message_type_table` |
| 4.2 | Hold Timer = min(configured, received) | MUST | done | fsm/machine.rs `accept_open` | fsm tests `open_negotiation` |
| 4.2 | Hold Time is zero or at least three seconds | MUST | done | wire/types.rs `HoldTime::new` | types.rs `hold_time_rejects_one_and_two` |
| 4.2 | May reject connections on the basis of Hold Time | MAY | n/a (not exercised; one and two seconds are rejected by the codec) | | |
| 4.2 | Minimum OPEN length is 29 octets | MUST | done | wire/header.rs `MessageType::min_len` | header.rs `length_bounds_carry_the_length_field_as_data` |
| 6.1 | Header errors use Error Code Message Header Error | MUST | done | wire/error.rs `DecodeError::header` | header.rs tests |
| 6.1 | Bad marker → Connection Not Synchronized | MUST | done | wire/header.rs `Header::decode` | header.rs `bad_marker_is_connection_not_synchronized` |
| 6.1 | Length <19, >4096, or below per-type minimum (OPEN 29, UPDATE 23, KEEPALIVE =19, NOTIFICATION 21) → Bad Message Length, Data = Length field | MUST | done | wire/header.rs `Header::decode`, `MessageType::min_len`/`max_len` | header.rs `length_bounds_carry_the_length_field_as_data` |
| 6.1 | Unknown Type → Bad Message Type, Data = Type field | MUST | done | wire/header.rs `Header::decode` | header.rs `unknown_type_carries_the_type_as_data` |
| 6.2 | OPEN errors use Error Code OPEN Message Error | MUST | done | wire/error.rs `DecodeError::open` | open.rs tests |
| 6.2 | Unsupported version → Unsupported Version Number, Data = 2-octet supported version | MUST | done | wire/open.rs `OpenMessage::decode` | open.rs `fixed_field_errors` |
| 6.2 | Unacceptable AS → Bad Peer AS | MUST | done (AS 0 in the codec, configured AS in the FSM) | wire/open.rs `OpenMessage::decode`, fsm/machine.rs `accept_open` | open.rs `fixed_field_errors`, fsm tests `bad_peer_as_and_unsupported_capability` |
| 6.2 | Hold Time 1 or 2 → Unacceptable Hold Time | MUST | done | wire/open.rs, wire/types.rs `HoldTime::new` | open.rs `fixed_field_errors` |
| 6.2 | May reject any Hold Time | MAY | n/a | | |
| 6.2 | Use the negotiated Hold Time | MUST | done | fsm/machine.rs `start_session_timers` | fsm tests `open_negotiation`, `established_timers_and_send_hold` |
| 6.2 | Syntactically bad BGP Identifier → Bad BGP Identifier | MUST | done (RFC 6286 §2.1: non-zero) | wire/open.rs, wire/types.rs `RouterId::new` | open.rs `fixed_field_errors`, types.rs `router_id_rejects_zero_only` |
| 6.2 | Unrecognised optional parameter → Unsupported Optional Parameters | MUST | done | wire/open.rs `decode_parameters` | open.rs `parameter_errors` |
| 6.2 | Recognised but malformed optional parameter → subcode 0 | MUST | done | wire/open.rs `malformed`, wire/capability.rs `malformed` | open.rs `parameter_errors`, capability.rs `malformed_known_capabilities_are_unspecific_open_errors` |
| 4.4 | KEEPALIVE is the 19-octet header only | MUST | done | wire/keepalive.rs `KEEPALIVE` | keepalive.rs `keepalive_is_the_bare_header` |
| 4.4 | KEEPALIVEs at most one per second; none when Hold Time is zero | MUST | done (KeepaliveTime ≥ Hold Time/3 ≥ 1 s; none at zero) | fsm/machine.rs `accept_open`, `start_session_timers` | fsm tests `hold_time_zero_disables_timers` |
| 4.4 | May adjust the KEEPALIVE rate to the Hold Time | MAY | done (one third of the negotiated value) | fsm/machine.rs `accept_open` | fsm tests `open_negotiation` |
| 4.5 | NOTIFICATION: code, subcode, data; connection closed after sending | MUST | done (codec; close is the FSM's) | wire/notification.rs | notification.rs `plain_notifications_round_trip` |
| 4.5 | Subcode 0 when the code defines none | MUST | done | wire/notification.rs `hold_timer_expired` | notification.rs `display_names` |
| 4.5 | Minimum NOTIFICATION length is 21 octets | MUST | done | wire/header.rs `MessageType::min_len` | header.rs `length_bounds_carry_the_length_field_as_data` |
| 6.4 | Errors in a received NOTIFICATION are logged, never answered | SHOULD | done (decoder never rejects; `is_recognised` for the log) | wire/notification.rs `decode`, `is_recognised` | notification.rs `unknown_codes_are_kept_and_flagged` |
| 6.5 | Hold Timer Expired NOTIFICATION, then close | MUST | done | wire/notification.rs `hold_timer_expired`, fsm/machine.rs (event 10) | fsm tests state tables |
| 6.6 | FSM errors use Error Code Finite State Machine Error | MUST | done | fsm/machine.rs `fsm_error` | fsm tests state tables, `fsm_error_data_names_the_unexpected_message` |
| 6.7 | Cease only in the absence of a fatal error | MUST | done (Cease only for stops and collisions) | fsm/machine.rs | fsm tests state tables |
| 6.7 | May impose a prefix limit and Cease when reached | MAY | todo (RIB) | | |

| 4.3 | UPDATE: withdrawn routes length/field, total path attribute length/field, NLRI | MUST | done | wire/update.rs `encode`, `split_fields` | update.rs `announce_round_trips`, `withdraw_only_and_empty_updates` |
| 4.3 | Prefix `<length, prefix>` with minimal octets; length 0 is the default route; trailing bits irrelevant | MUST | done | wire/prefix.rs | prefix.rs `encoding_uses_the_minimum_octets`, `trailing_bits_are_ignored_on_decode` |
| 4.3 | Attribute flags: Optional, Transitive, Partial, Extended Length; low bits zero on send, ignored on receipt | MUST | done | wire/attribute.rs `flags`, `encode_attribute`, `parse_raw` | attribute.rs `extended_length_is_used_above_255_octets`, `well_known_attributes_encode_with_their_flags` |
| 4.3 | Well-known attributes carry Transitive=1 and Partial=0 | MUST | done (send); receive checked per RFC 7606 §3 c | wire/attribute.rs `expected_flags` | update.rs `attribute_length_and_flag_errors` |
| 4.3 | ORIGIN values 0..=2 | MUST | done | wire/attribute.rs `Origin` | attribute.rs `origin_table`, update.rs `bad_origin_is_treat_as_withdraw` |
| 4.3 | `AS_PATH` segments `<type, count, ASes>`, types `AS_SET`/`AS_SEQUENCE` | MUST | done | wire/as_path.rs | as_path.rs `two_and_four_octet_round_trips` |
| 4.3 | `NEXT_HOP` four-octet IPv4 address | MUST | done | wire/attribute.rs, wire/update.rs | update.rs `announce_round_trips` |
| 4.3 | `MULTI_EXIT_DISC` optional non-transitive four octets | MUST | done | wire/attribute.rs | update.rs `announce_round_trips` |
| 4.3 | `LOCAL_PREF` well-known four octets | MUST | done | wire/attribute.rs | update.rs `local_pref_depends_on_the_peer_kind` |
| 4.3 | `ATOMIC_AGGREGATE` length 0 | MUST | done | wire/attribute.rs | attribute.rs, update.rs `attribute_length_and_flag_errors` |
| 4.3 | AGGREGATOR optional transitive, AS (2 octets) + IPv4 | MUST | done (4 octets per RFC 6793) | wire/attribute.rs, wire/update.rs `decode_aggregator` | attribute.rs `four_octet_as_in_as_path_and_aggregator` |
| 4.3 | Minimum UPDATE length 23 octets | MUST | done | wire/header.rs `MessageType::min_len` | header.rs |
| 4.3 | Same prefix in both withdrawn and NLRI: accept, treat as not withdrawn | MUST / SHOULD | done (withdrawals are applied before announcements) | rib/lib.rs `Rib::update` | rib tests `prefix_in_both_withdrawn_and_nlri_is_announced` |
| 5 | Recognise all well-known attributes | MUST | done | wire/attribute.rs `expected_flags` | attribute.rs `expected_flags_table` |
| 5 | Mandatory attributes present in every UPDATE with NLRI | MUST | done (receive; RFC 7606 §3 d treat-as-withdraw) | wire/update.rs `check_mandatory` | update.rs `missing_mandatory_attributes` |
| 5 | Pass well-known attributes on to peers | MUST | done | rib/attrs.rs `PathAttrs::to_update` | rib tests `attributes_round_trip_through_an_update` |
| 5 | Accept unrecognised transitive optional attributes; pass on with Partial set | SHOULD / MUST | done (kept with flags); Partial set by the RIB on export | wire/update.rs `unknown_attribute` | update.rs `unknown_attributes_per_rfc4271_section_5` |
| 5 | Never clear a Partial bit set upstream | MUST | done (flags are kept and Partial is only ever added) | rib/attrs.rs `to_attributes` | rib tests `attributes_round_trip_through_an_update` |
| 5 | Quietly ignore unrecognised non-transitive optional attributes | MUST | done | wire/update.rs `unknown_attribute` | update.rs `unknown_attributes_per_rfc4271_section_5` |
| 5 | Send attributes in ascending type order | SHOULD | done | wire/update.rs `encode` | update.rs `as4_path_is_generated_for_old_peers_and_merged_on_receipt` |
| 5 | Accept attributes in any order | MUST | done | wire/update.rs `decode` | update.rs `announce_round_trips` |
| 5 | An attribute appears at most once | MUST | done (receive per RFC 7606 §3 g) | wire/update.rs `decode_attributes` | update.rs `duplicates_discard_or_reset` |
| 5.1.2 | `AS_PATH` to an internal peer unchanged; to an external peer with the local AS prepended | MUST | done | rib/export.rs `export`, `prepend` | rib tests `export_to_external_peer_prepends_and_rewrites`, `export_to_internal_peer_keeps_attributes_and_sets_local_pref` |
| 5.1.2 | Prepend as `AS_SEQUENCE`; a segment holds at most 255 ASes | MUST | done | rib/export.rs `prepend` | rib tests `prepend_respects_segment_limit_and_sets` |
| 5.1.3 | `NEXT_HOP` to an internal peer unchanged | SHOULD | done | rib/export.rs `export` | rib tests `export_to_internal_peer_keeps_attributes_and_sets_local_pref` |
| 5.1.3 | `NEXT_HOP` to an external peer: the local address of the session (next-hop-self) | MUST (the "shall" cases) | done; third-party next hops on a shared subnet (MAY) are not used | rib/export.rs `export` | rib tests `export_to_external_peer_prepends_and_rewrites`, `ipv6_next_hop_self_and_v4_over_v6_session`, interop `routes_are_relayed_withdrawn_and_refreshed` |
| 5.1.3 | Never use the peer's own address or an address of the sending speaker's peer as `NEXT_HOP` (MUST NOT) | MUST | done (next-hop-self only) | rib/export.rs `export` | rib tests `export_to_external_peer_prepends_and_rewrites` |
| 5.1.4 | MED received from a neighboring AS not propagated to other neighboring ASes; passed on to internal peers | MUST / SHOULD | done | rib/export.rs `export` | rib tests `export_to_external_peer_prepends_and_rewrites`, `export_to_internal_peer_keeps_attributes_and_sets_local_pref` |
| 5.1.5 | `LOCAL_PREF` included to internal peers, never to external peers | MUST | done | rib/export.rs `export` | rib tests `export_to_internal_peer_keeps_attributes_and_sets_local_pref` |
| 5.1.5 | Ignore `LOCAL_PREF` from an external peer | MUST | done | wire/update.rs `decode_one` | update.rs `local_pref_depends_on_the_peer_kind` |
| 5.1.6 | `ATOMIC_AGGREGATE` is passed on; no de-aggregation | MUST | done (no aggregation is performed) | rib/attrs.rs `to_attributes` | rib tests `attributes_round_trip_through_an_update` |
| 5.1.7 | AGGREGATOR when aggregating | MAY | n/a (no aggregation); a received one is passed on | rib/attrs.rs | rib tests `attributes_round_trip_through_an_update` |
| 6.3 | Withdrawn + attribute lengths + 23 over the message length → Malformed Attribute List | MUST | done | wire/update.rs `split_fields` | update.rs `length_overruns_reset_the_session` |
| 6.3 | Attribute Flags Error, Data = the attribute | MUST | done (treat-as-withdraw per RFC 7606) | wire/update.rs `decode_one` | update.rs `attribute_length_and_flag_errors` |
| 6.3 | Attribute Length Error, Data = the attribute | MUST | done (treat-as-withdraw per RFC 7606) | wire/update.rs `decode_one` | update.rs `attribute_length_and_flag_errors` |
| 6.3 | Missing Well-known Attribute, Data = type code | MUST | done (treat-as-withdraw per RFC 7606) | wire/update.rs `check_mandatory` | update.rs `missing_mandatory_attributes` |
| 6.3 | Unrecognized Well-known Attribute, Data = the attribute; session reset | MUST | done | wire/update.rs `unknown_attribute` | update.rs `unknown_attributes_per_rfc4271_section_5` |
| 6.3 | Invalid ORIGIN Attribute, Data = the attribute | MUST | done (treat-as-withdraw per RFC 7606) | wire/update.rs `decode_one` | update.rs `bad_origin_is_treat_as_withdraw` |
| 6.3 | Invalid `NEXT_HOP`: semantic errors logged and route ignored, no NOTIFICATION | SHOULD | todo (next hop validation arrives with the FIB in milestone 7) | | |
| 6.3 | Malformed `AS_PATH` | MUST | done (treat-as-withdraw per RFC 7606) | wire/update.rs `decode_as_path` | update.rs `as_path_rules` |
| 6.3 | Leftmost AS equals the external peer's AS | MAY | done (treat-as-withdraw per RFC 7606 §7.2) | rib/lib.rs `Rib::update` | rib tests `leftmost_as_must_be_the_external_peer` |
| 6.3 | Optional Attribute Error, Data = the attribute | MUST | done | wire/update.rs `discard_malformed`, `mp_failure` | update.rs `mp_attribute_errors_disable_the_family` |
| 6.3 | Duplicate attribute → Malformed Attribute List | MUST | done (as revised by RFC 7606 §3 g) | wire/update.rs `decode_attributes` | update.rs `duplicates_discard_or_reset` |
| 6.3 | Invalid Network Field for syntactically bad NLRI | MUST | done | wire/update.rs `decode` | update.rs `bad_nlri_syntax_resets_the_session` |
| 6.3 | Semantically bad prefix: log and ignore | SHOULD | n/a (syntax is checked by the codec; what is semantically unwanted, martians and the like, is the import policy's `prefix-list` to reject) | policy/lib.rs `PolicySet::evaluate` | policy tests `terms_run_in_order_and_undecided_rejects` |
| 6.3 | Correct attributes with no NLRI is a valid UPDATE | MUST | done | wire/update.rs `decode` | update.rs `missing_mandatory_attributes` |

| 6.8 | One of two colliding connections is closed; the one from the higher BGP Identifier is kept | MUST | done | bgpfcd/peer.rs `resolve_collision`, fsm/machine.rs `collision_dump` | interop `session_survives_simultaneous_connect` |
| 6.8 | Examine OpenConfirm connections on every OPEN; may examine OpenSent | MUST / MAY | done (a second connection is tracked in both states until its OPEN) | bgpfcd/peer.rs `accept_stream`, `track_pending` | interop `session_survives_simultaneous_connect` |
| 6.8 | A collision with an Established connection closes the new one unless configured | MUST | done (`collision_detect_established`) | fsm/machine.rs (event 23 in Established) | fsm tests `collision_dump_in_established_needs_the_option` |
| 6.8 | Close the losing connection with a Cease | MUST | done (Connection Collision Resolution subcode) | fsm/machine.rs `collision_dump` | fsm tests state tables |
| 8 | Mandatory session attributes: State, ConnectRetryCounter, ConnectRetryTimer/Time, HoldTimer/Time, KeepaliveTimer/Time | MUST | done | fsm/machine.rs `Fsm`, fsm/lib.rs `Config` | fsm tests |
| 8.1.1 | Optional attributes: DampPeerOscillations/IdleHoldTime/IdleHoldTimer, PassiveTcpEstablishment, DelayOpen/DelayOpenTime/DelayOpenTimer, SendNOTIFICATIONwithoutOPEN, CollisionDetectEstablishedState | MAY | done; AllowAutomaticStart implicit (configured peers restart), AcceptConnectionsUnconfiguredPeers and TrackTcpState not supported | fsm/lib.rs `Config` | fsm tests `delay_open`, `damping_doubles_the_idle_hold_and_a_session_resets_it`, `send_notification_without_open`, `active_retries_connect_when_not_passive` |
| 8.1.2 | Events 1 and 2 mandatory; 3–8 optional | MUST | done (3, 5–7 as `AutomaticStart` with config; 4 as `ManualStartPassive`; 8 with its Cease) | fsm/lib.rs `Event` | fsm tests `event_numbers_and_timer_events` |
| 8.1.3 | Timer events 9–13 | MUST / MAY | done | fsm/lib.rs `TimerKind::event` | fsm tests |
| 8.1.4 | TCP events 14–18 | MUST / MAY | done | fsm/lib.rs `Event` | fsm tests state tables |
| 8.1.5 | Message events 19–28 | MUST / MAY | done (20 derived from the DelayOpenTimer) | fsm/lib.rs `Event` | fsm tests state tables, `delay_open` |
| 8.2.1 | One FSM per configured peer and per unidentified incoming connection; listen on and connect to port 179 | MUST | done (one peer thread and FSM per neighbour; a second connection is tracked without its own FSM until its OPEN; connections from unconfigured addresses are refused) | bgpfcd/peer.rs, bgpfcd/coordinator.rs | interop `session_with_bird_bgpfcd_connects`, `session_with_bird_bird_connects` |
| 8.2.1.2 | Dispose of the losing FSM after collision resolution | SHOULD | done (the losing connection is closed; the FSM restarts on the winner) | bgpfcd/peer.rs `resolve_collision` | interop `session_survives_simultaneous_connect` |
| 8.2.2 | Idle refuses all incoming connections | MUST | done | bgpfcd/peer.rs `accept_stream` | |
| 8.2.2 | Second connection in OpenSent/OpenConfirm tracked until its OPEN; invalid requests ignored | MUST | done | bgpfcd/peer.rs `track_pending`, `pending_message` | interop `session_survives_simultaneous_connect` |
| 8.2.2 | Idle: start events initialise, zero the counter, start ConnectRetryTimer, connect or listen; stop events ignored; other events ignored | MUST | done | fsm/machine.rs `in_idle`, `start` | fsm tests `idle_state_table` |
| 8.2.2 | Connect: every event per the text (ConnectRetryTimer restart, DelayOpen handling, OPEN on connect, failures to Idle with damping) | MUST | done | fsm/machine.rs `in_connect` | fsm tests `connect_state_table`, `delay_open`, `send_notification_without_open` |
| 8.2.2 | Active: every event per the text | MUST | done; a PassiveTcpEstablishment peer stays Active on ConnectRetryTimer expiry (NOTE(interop)) | fsm/machine.rs `in_active` | fsm tests `active_state_table`, `active_retries_connect_when_not_passive` |
| 8.2.2 | OpenSent: Cease on stops, Hold Timer Expired, TcpConnectionFails → Active, OPEN → KEEPALIVE + timers + OpenConfirm, errors → NOTIFICATION, collision → Cease, version error → Idle, others → FSM error | MUST | done | fsm/machine.rs `in_open_sent` | fsm tests `open_sent_state_table` |
| 8.2.2 | OpenSent: internal/external set from the AS field | MUST | done | fsm/machine.rs `accept_open` | fsm tests `internal_session_and_old_speaker` |
| 8.2.2 | OpenConfirm: every event per the text; KEEPALIVE → Established | MUST | done | fsm/machine.rs `in_open_confirm` | fsm tests `open_confirm_state_table` |
| 8.2.2 | Established: KEEPALIVE/UPDATE restart HoldTimer; KeepaliveTimer restarts on every sent KEEPALIVE/UPDATE unless Hold Time is zero; stops and errors delete routes and send the NOTIFICATION; others → FSM error | MUST | done; event 21 sends the header error per §6.1 rather than an FSM error (NOTE(interop)) | fsm/machine.rs `in_established`, `message_sent` | fsm tests `established_state_table`, `established_timers_and_send_hold` |
| 8.2.2 | "Large" HoldTimer value while waiting for the peer's OPEN; 4 minutes suggested | SHOULD | done | fsm/lib.rs `Config::open_hold_time` | fsm tests `connect_retry_timer_in_connect_and_open_sent` |
| 10 | Suggested defaults: ConnectRetryTime 120 s, HoldTime 90 s, KeepaliveTime one third | SHOULD | done | fsm/lib.rs `Config::new` | fsm tests `open_negotiation` |
| 10 | HoldTimer configurable per peer; other timers may be | MUST / MAY | done (`hold-time`, `keepalive-time`, `connect-retry-time` per neighbor) | config/lower.rs `NeighborBuilder`, bgpfcd/wiring.rs `peer_config` | config golden `full.conf`, bgpfcd/wiring.rs `neighbor_becomes_peer_config` |
| 10 | Jitter on KeepaliveTimer and ConnectRetryTimer, factor uniformly in [0.75, 1.0], redrawn each time | SHOULD | done | fsm/timers.rs `Jitter` | timers.rs `jitter_stays_within_rfc_bounds`, fsm tests `jitter_shortens_timers_within_bounds` |

| 3.2 | Adj-RIBs-In, Loc-RIB and Adj-RIBs-Out (conceptual) | MUST | done (one table per family holds every candidate and the chosen route; Adj-RIB-Out per peer) | rib/lib.rs `Rib` | rib tests `announce_withdraw_and_fib_changes` |
| 9 | Run the decision process when an UPDATE changes the Adj-RIB-In | MUST | done (for the destinations the UPDATE touched) | rib/lib.rs `Rib::update`, `reconsider` | rib tests `announce_withdraw_and_fib_changes`, order.rs `loc_rib_is_independent_of_arrival_order` |
| 9.1.1 | Phase 1: degree of preference is `LOCAL_PREF` for internal routes, local policy otherwise | MUST | done (import policy `set local-pref`, 100 otherwise) | rib/decision.rs `Candidate::degree_of_preference`, policy/lib.rs `apply` | rib tests `degree_of_preference_wins_first`, policy tests `engine_applies_each_neighbors_policies` |
| 9.1.2 | A route whose `NEXT_HOP` is unresolvable is excluded from Phase 2 | MUST | deviates (no IGP; every next hop counts as resolvable in the decision; the kernel rejects a route whose gateway it cannot reach and the failure is logged) | rib/decision.rs, bgpfcd/fib.rs `report` | |
| 9.1.2 | A route whose `AS_PATH` contains an AS loop is excluded from Phase 2 | SHOULD | done (not even stored) | rib/lib.rs `Rib::update` | rib tests `as_loop_routes_are_excluded` |
| 9.1.2 | Select the route with the highest degree of preference; one route per destination | MUST | done | rib/decision.rs `best` | rib tests `degree_of_preference_wins_first` |
| 9.1.2.2 a | Tie-break: shortest `AS_PATH`, `AS_SET` counts one, confederation segments zero | MUST | done | rib/decision.rs `path_length`, wire/as_path.rs `hop_count` | rib tests `shorter_as_path_wins`, `as_set_counts_as_one_hop` |
| 9.1.2.2 b | Lowest ORIGIN | MUST | done | rib/decision.rs `compare` | rib tests `lower_origin_wins` |
| 9.1.2.2 c | Lowest MED, compared only between routes from the same neighboring AS; a missing MED is the lowest value | MUST | done (comparison-order independent: the per-AS minimum is computed first) | rib/decision.rs `best`, `med_rank` | rib tests `med_compares_within_the_neighboring_as_only`, `med_uses_the_leftmost_as_for_internal_routes` |
| 9.1.2.2 d | External over internal | MUST | done | rib/decision.rs `kind_rank` | rib tests `external_beats_internal` |
| 9.1.2.2 e | Lowest interior cost to the `NEXT_HOP` | MUST | n/a (no IGP; every cost is equal) | rib/decision.rs `compare` | |
| 9.1.2.2 f | Lowest BGP Identifier | MUST | done | rib/decision.rs `compare` | rib tests `lower_router_id_then_lower_peer_address` |
| 9.1.2.2 g | Lowest peer address | MUST | done | rib/decision.rs `compare` | rib tests `lower_router_id_then_lower_peer_address` |
| 9.1.3 | Phase 3: Adj-RIBs-Out follow Loc-RIB changes, subject to export policy; a route previously advertised is withdrawn when no longer sent | MUST | done | rib/lib.rs `reconsider`, `exported`, policy/lib.rs `Engine` | rib tests `announce_withdraw_and_fib_changes`, interop `export_policy_filters_and_sets` |
| 9.1.4 | Overlapping routes are independent destinations; no special handling | MAY | done (longest-match is the FIB's) | rib/lib.rs | rib tests `announce_withdraw_and_fib_changes` |
| 9.2 | UPDATE generation: routes with identical attributes share an UPDATE; a route learned from an internal peer is not redistributed to internal peers | MUST | done | rib/export.rs `Batch`, `export` | rib tests `large_batches_are_packed_within_the_message_limit`, `export_to_internal_peer_keeps_attributes_and_sets_local_pref` |
| 9.2 | Initial Adj-RIB-Out after a session is established | MUST | done | rib/lib.rs `peer_up`, `refresh` | rib tests `new_peer_receives_the_loc_rib_and_route_refresh_resends_it`, interop `routes_are_relayed_withdrawn_and_refreshed` |
| 9.2.1.1 | `MinRouteAdvertisementIntervalTimer` between UPDATEs for the same destination | MUST | todo (updates are sent as the Loc-RIB changes) | | |
| 9.2.2 | Withdrawn and feasible routes may share an UPDATE; a withdrawn route may be omitted when the same UPDATE announces its replacement | MAY | done (withdrawals and announcements go in separate UPDATEs; a replacement announcement implicitly withdraws) | rib/export.rs `Batch::encode` | rib tests `announce_withdraw_and_fib_changes` |
| 9.3 | Loc-RIB routes are installed in the forwarding table | MUST | done (rtnetlink, our protocol number, one table; dry-run by default) | fib/lib.rs `Fib`, bgpfcd/fib.rs | fib/route.rs `requests_match_iproute2_captures`, interop `fib_install_and_clean_shutdown` |

## RFC 5492 — Capabilities Advertisement

| RFC § | Requirement (short) | Level | Status | Code | Test |
|---|---|---|---|---|---|
| 4 | Capabilities parameter type 2, `<Code, Length, Value>` triples | MUST | done | wire/capability.rs `Capability::encode`/`decode` | capability.rs `known_capabilities_round_trip` |
| 4 | Do not send duplicate identical capabilities | SHOULD | done (encoder emits the given list once) | wire/open.rs `encode_capabilities` | open.rs `open_with_capabilities_round_trips` |
| 4 | Accept duplicate identical capabilities | MUST | done | wire/open.rs `decode_parameters` | open.rs `several_capabilities_parameters_are_merged` |
| 4 | Include the Capabilities parameter once | SHOULD | done | wire/open.rs `encode_with` | open.rs `several_capabilities_parameters_are_merged` |
| 4 | Accept several Capabilities parameters and merge them | MUST | done | wire/open.rs `decode_parameters` | open.rs `several_capabilities_parameters_are_merged` |
| 5 | Unsupported Capability subcode 7, Data lists the capabilities | MUST | done (sent when no address family is shared) | fsm/machine.rs `accept_open` | fsm tests `bad_peer_as_and_unsupported_capability` |
| 5 | Never send Unsupported Capability for a capability not understood; ignore it | MUST | done (decoder keeps it as `Unknown`) | wire/capability.rs `Capability::decode` | capability.rs `unknown_capabilities_are_kept_not_rejected` |

## RFC 6793 — Four-Octet AS Numbers

| RFC § | Requirement (short) | Level | Status | Code | Test |
|---|---|---|---|---|---|
| 3 | Capability 65, length 4, carries the speaker's ASN | MUST | done | wire/capability.rs | capability.rs `known_capabilities_round_trip` |
| 3 | My Autonomous System = `AS_TRANS` (23456) when the ASN is not mappable | MUST | done | wire/open.rs `OpenMessage::new`, wire/types.rs `Asn::to_two_octet` | open.rs `new_uses_as_trans_for_a_four_octet_asn` |
| 3 | `AS4_PATH` / `AS4_AGGREGATOR` optional transitive, four-octet; no confederation segments in `AS4_PATH` | MUST | done | wire/update.rs `as4_companion`, `decode_as4_path` | update.rs `as4_path_is_generated_for_old_peers_and_merged_on_receipt` |
| 4.2.2 | To an OLD speaker: two-octet `AS_PATH` with `AS_TRANS`, plus `AS4_PATH` only when a non-mappable ASN is present | MUST | done | wire/update.rs `as4_companion`, wire/as_path.rs `encode` | update.rs `as4_path_is_generated_for_old_peers_and_merged_on_receipt`, as_path.rs `as_trans_replaces_non_mappable_asns_in_two_octet_paths` |
| 4.2.2 | AGGREGATOR with `AS_TRANS` plus `AS4_AGGREGATOR` for a non-mappable aggregator; neither otherwise | MUST | done | wire/update.rs `as4_companion` | update.rs `as4_path_is_generated_for_old_peers_and_merged_on_receipt` |
| 4.2.3 | Accept `AS4_PATH` with `AS_PATH` from an OLD speaker and reconstruct | MUST | done | wire/as_path.rs `merge_as4`, wire/update.rs `apply_as4` | as_path.rs `as4_merge_per_rfc6793` |
| 4.2.3 | AGGREGATOR not `AS_TRANS` → ignore `AS4_AGGREGATOR` and `AS4_PATH`; else take `AS4_AGGREGATOR` | MUST | done | wire/update.rs `apply_as4` | update.rs `as4_aggregator_from_an_old_aggregator_wins` |
| 4.2.3 | `AS_PATH` shorter than `AS4_PATH` → ignore `AS4_PATH`; else prepend the leading ASes | MUST | done | wire/as_path.rs `merge_as4` | as_path.rs `as4_merge_per_rfc6793` |
| 6 | Malformed `AS4_PATH` / `AS4_AGGREGATOR` → attribute discard | MUST | done | wire/update.rs `decode_as4_path` | update.rs |
| 6 | `AS4_*` between NEW speakers: discard and continue, log | MUST / SHOULD | done (reported as `FromNewSpeaker` for the log) | wire/update.rs `decode_one` | update.rs `as4_path_is_generated_for_old_peers_and_merged_on_receipt` |
| 6 | Confederation segments in a received `AS4_PATH` are discarded | MUST | done | wire/update.rs `decode_as4_path` | as_path.rs `counting_and_predicates` |

## RFC 4760 — Multiprotocol Extensions

| RFC § | Requirement (short) | Level | Status | Code | Test |
|---|---|---|---|---|---|
| 8 | Use capability advertisement to negotiate | SHOULD | done (codec; FSM uses it later) | wire/capability.rs | capability.rs |
| 8 | Capability 1, length 4: AFI, reserved, SAFI | MUST | done | wire/capability.rs | capability.rs `known_capabilities_round_trip` |
| 8 | Reserved octet zero on send, ignored on receipt | SHOULD | done | wire/capability.rs | capability.rs `multiprotocol_ignores_the_reserved_octet` |
| 8 | Both sides must advertise an `<AFI, SAFI>` to exchange it | MUST | done (no Multiprotocol capability means IPv4 unicast only) | fsm/machine.rs `negotiate_families` | fsm tests `open_negotiation`, `internal_session_and_old_speaker` |
| 3 | `MP_REACH_NLRI` type 14, optional non-transitive: AFI, SAFI, next hop length, next hop, reserved, NLRI | MUST | done | wire/mp.rs `MpReach` | mp.rs `ipv6_unicast_reach_round_trips` |
| 3 | Reserved octet zero on send, ignored on receipt | MUST / SHOULD | done | wire/mp.rs | mp.rs `ipv4_nlri_with_ipv4_or_ipv6_next_hop` |
| 3 | UPDATE with `MP_REACH_NLRI` carries ORIGIN and `AS_PATH` (and `LOCAL_PREF` on iBGP) | MUST | done for ORIGIN/`AS_PATH` (treat-as-withdraw); `LOCAL_PREF` left to the RIB | wire/update.rs `check_mandatory` | update.rs `missing_mandatory_attributes` |
| 3 | `NEXT_HOP` ignored when only `MP_REACH_NLRI` carries routes | SHOULD | done (the family's next hop comes from `MP_REACH_NLRI`) | rib/attrs.rs `PathAttrs::from_update` | rib tests `new_peer_receives_the_loc_rib_and_route_refresh_resends_it` |
| 4 | `MP_UNREACH_NLRI` type 15: AFI, SAFI, withdrawn routes; no other attributes required | MUST | done | wire/mp.rs `MpUnreach` | mp.rs `unreach_round_trip_and_errors` |
| 5 | NLRI `<length, prefix>` encoding | MUST | done | wire/prefix.rs | prefix.rs |
| 6 | SAFI 1 unicast, 2 multicast | MAY | done (unicast only is parsed) | wire/types.rs `Safi`, wire/mp.rs `supported` | mp.rs `reach_errors` |
| 7 | Incorrect MP attribute → drop that family's routes from the peer, ignore the family for the session | MUST / SHOULD | partial (reported to the RIB as `FamilyDisabled`; the RIB acts in milestone 5) | wire/update.rs `mp_failure`, bgpfcd/peer.rs `update` | update.rs `mp_attribute_errors_disable_the_family` |
| 7 | May reset with Optional Attribute Error | MAY | done (NOTIFICATION supplied) | wire/update.rs `mp_failure` | update.rs `mp_attribute_errors_disable_the_family` |

## RFC 2918 — Route Refresh

| RFC § | Requirement (short) | Level | Status | Code | Test |
|---|---|---|---|---|---|
| 2 | Capability 2, length 0 | MUST | done | wire/capability.rs | capability.rs `known_capabilities_round_trip` |
| 3 | ROUTE-REFRESH message type 5, `<AFI, Res, SAFI>` | MUST | done | wire/header.rs `MessageType::RouteRefresh`, wire/route_refresh.rs | route_refresh.rs `route_refresh_round_trips` |
| 3 | Reserved octet zero on send, ignored on receipt | SHOULD | done | wire/route_refresh.rs | route_refresh.rs `route_refresh_round_trips` |
| 4 | Send only if the peer advertised the capability; ignore unadvertised families | SHOULD | done (a soft reset or import-policy reload sends ROUTE-REFRESH only to peers that advertised it, for negotiated families; one received for an unadvertised family is ignored) | bgpfcd/peer.rs `request_routes`, `primary_message` | interop `control_plane_commands`, fsm tests `open_negotiation` |
| 4 | On a ROUTE-REFRESH, re-advertise the Adj-RIB-Out of the family | MUST | done | rib/lib.rs `refresh`, bgpfcd/rib.rs | rib tests `new_peer_receives_the_loc_rib_and_route_refresh_resends_it`, interop `routes_are_relayed_withdrawn_and_refreshed` |

## RFC 7606 — Revised Error Handling

| RFC § | Requirement (short) | Level | Status | Code | Test |
|---|---|---|---|---|---|
| 3 a | NOTIFICATION only for errors specified as session reset | MUST | done | wire/update.rs `UpdateError` vs `DecodedUpdate` | update.rs |
| 3 b | Length overrun → Malformed Attribute List, session reset | MUST | done | wire/update.rs `split_fields` | update.rs `length_overruns_reset_the_session` |
| 3 c | Optional/Transitive flag conflict → treat-as-withdraw unless the attribute says otherwise | MUST | done | wire/update.rs `decode_one` | update.rs `attribute_length_and_flag_errors` |
| 3 d | Missing well-known mandatory attribute → treat-as-withdraw | MUST | done | wire/update.rs `check_mandatory` | update.rs `missing_mandatory_attributes` |
| 3 e | ORIGIN, `AS_PATH`, `NEXT_HOP`, MED, `LOCAL_PREF` errors → treat-as-withdraw | MUST | done | wire/update.rs `decode_one` | update.rs `bad_origin_is_treat_as_withdraw`, `as_path_rules`, `local_pref_depends_on_the_peer_kind` |
| 3 f | `ATOMIC_AGGREGATE`, AGGREGATOR errors → attribute discard | MUST | done | wire/update.rs `decode_one` | update.rs `attribute_length_and_flag_errors` |
| 3 g | Repeated MP attribute → Malformed Attribute List; other repeats discarded | MUST / SHALL | done | wire/update.rs `decode_attributes` | update.rs `duplicates_discard_or_reset` |
| 3 h | Strongest approach wins when several errors exist | MUST | done (reset/disable return at once; withdraw outranks discard) | wire/update.rs `decode_attributes` | update.rs |
| 3 i | Withdrawn Routes checked for syntax like NLRI | MUST | done | wire/update.rs `decode` | update.rs `bad_nlri_syntax_resets_the_session` |
| 3 j | NLRI not parseable → session reset / AFI-SAFI disable | MUST | done | wire/update.rs `decode`, `mp_failure` | update.rs `bad_nlri_syntax_resets_the_session`, `mp_attribute_errors_disable_the_family` |
| 4 | Attribute overrun or underrun → treat-as-withdraw; NLRI located by Total Attribute Length | MUST | done | wire/attribute.rs `parse_raw`, wire/update.rs `decode_attributes` | update.rs `truncated_attribute_header_is_treat_as_withdraw` |
| 4 | Zero length is a syntax error except for `AS_PATH` and `ATOMIC_AGGREGATE` | SHALL | done for known attributes (per-attribute length rules) | wire/update.rs `decode_one` | update.rs |
| 5.1 | MP attributes encoded first; at most one of withdrawn/NLRI/`MP_REACH`/`MP_UNREACH` | SHALL / MUST | partial (MP first on encode; the RIB packs one kind per UPDATE) | wire/update.rs `encode` | update.rs `missing_mandatory_attributes` |
| 5.1 | Accept the fields in any position or combination | MUST | done | wire/update.rs `decode` | update.rs `mp_unreach_withdrawals_and_treat_as_withdraw_cover_mp_reach` |
| 5.2 | No reachable NLRI plus attributes other than `MP_UNREACH_NLRI` and a non-discard error → session reset | MUST | done | wire/update.rs `decode` | update.rs `no_reachable_nlri_escalates_withdraw_to_reset` |
| 5.3 | NLRI syntax: length over the family size, or overrun | SHALL | done | wire/prefix.rs `decode_prefixes` | prefix.rs `field_decoding_and_syntax_errors` |
| 5.3 | MP attribute incorrect: bad NLRI, inconsistent flags, `MP_UNREACH` < 3 or `MP_REACH` < 5 | SHALL | done | wire/mp.rs, wire/update.rs `decode_one` | mp.rs `reach_errors`, update.rs `mp_attribute_errors_disable_the_family` |
| 7.1 | ORIGIN: length 1 and defined value, else treat-as-withdraw | SHALL | done | wire/update.rs | update.rs `bad_origin_is_treat_as_withdraw` |
| 7.2 | `AS_PATH`: unknown segment type, overrun, underrun, zero length → treat-as-withdraw | SHALL | done | wire/as_path.rs `decode` | as_path.rs `malformations_per_rfc7606` |
| 7.2 | Leftmost-AS check failure → treat-as-withdraw (reset if configured) | SHOULD / MAY | done (treat-as-withdraw; no reset option) | rib/lib.rs `Rib::update` | rib tests `leftmost_as_must_be_the_external_peer` |
| 7.3 | `NEXT_HOP` length 4 else treat-as-withdraw | SHALL | done | wire/update.rs | update.rs `attribute_length_and_flag_errors` |
| 7.4 | MED length 4 else treat-as-withdraw | SHALL | done | wire/update.rs | update.rs |
| 7.5 | `LOCAL_PREF` from external: discard; internal with length ≠ 4: treat-as-withdraw | SHALL | done | wire/update.rs | update.rs `local_pref_depends_on_the_peer_kind` |
| 7.6 | `ATOMIC_AGGREGATE` length ≠ 0 → discard | SHALL | done | wire/update.rs | update.rs `attribute_length_and_flag_errors` |
| 7.7 | AGGREGATOR length 6 (two-octet) / 8 (four-octet) else discard | SHALL | done | wire/update.rs `decode_aggregator` | update.rs |
| 7.8 | COMMUNITIES length non-zero multiple of 4 else treat-as-withdraw | SHALL | done | wire/community.rs | update.rs `communities_round_trip_and_length_errors` |
| 7.11 | `MP_REACH_NLRI` next hop length inconsistent → session reset / AFI-SAFI disable | MUST | done | wire/mp.rs `NextHop::decode`, wire/update.rs `mp_failure` | update.rs `mp_attribute_errors_disable_the_family` |
| 7.14 | Extended Communities length non-zero multiple of 8 else treat-as-withdraw; unknown types never an error | SHALL / MUST | done | wire/community.rs | community.rs `extended_communities` |

## RFC 8654 — Extended Messages

| RFC § | Requirement (short) | Level | Status | Code | Test |
|---|---|---|---|---|---|
| 3 | Capability 6, length 0 | MUST | done | wire/capability.rs | capability.rs `known_capabilities_round_trip` |
| 3 | Peers using it must support RFC 7606 error handling | MUST | done | wire/update.rs | update.rs |
| 4 | Applies to all messages except OPEN and KEEPALIVE | MUST | done | wire/header.rs `MessageType::max_len` | header.rs `extended_messages_only_when_negotiated_and_never_for_open_or_keepalive` |
| 4 | Advertise the capability when able | SHOULD | done (`Config::capabilities`; both sides needed for `Session::extended_messages`) | fsm/machine.rs `accept_open` | fsm tests `open_negotiation` |
| 4 | Send extended messages only if the peer advertised the capability | MAY | done | rib/peer.rs `PeerInfo::max_message_len`, rib/export.rs `Batch::encode` | rib tests `large_batches_are_packed_within_the_message_limit` |
| 4 | Having advertised it, accept up to 65535 octets | MUST | done | wire/header.rs `Header::decode` | header.rs `extended_messages_only_when_negotiated_and_never_for_open_or_keepalive` |
| 4 | Over 4096 without the capability → Bad Message Length | MUST | done | wire/header.rs `Header::decode` | header.rs `extended_messages_only_when_negotiated_and_never_for_open_or_keepalive` |
| 5 | Never accept extended messages without having advertised the capability | MUST | done | wire/header.rs `Header::decode` (`extended` flag) | header.rs |
| 5 | NOTIFICATION to a non-extended peer at most 4096 octets | MUST | done | wire/notification.rs `encode` | notification.rs `notification_size_limit_depends_on_extended_messages` |
| 4 | Shrink or withhold an over-size UPDATE for a non-extended neighbour | SHOULD | done (prefixes are split across UPDATEs; an attribute set that fits in no message is reported, not sent) | rib/export.rs `Batch::encode`, `chunks` | rib tests `large_batches_are_packed_within_the_message_limit` |

## RFC 1997 / 4360 / 8092 — Communities

| RFC § | Requirement (short) | Level | Status | Code | Test |
|---|---|---|---|---|---|
| 1997 | COMMUNITIES type 8, optional transitive, set of four-octet values | MUST | done | wire/community.rs, wire/attribute.rs | community.rs `standard_communities` |
| 1997 | `NO_EXPORT`, `NO_ADVERTISE`, `NO_EXPORT_SUBCONFED` recognised | MUST | done (values; export rules are the RIB's) | wire/community.rs `Community` consts | community.rs `standard_communities` |
| 1997 | Routes with the well-known communities are not advertised as each specifies | MUST | done | rib/export.rs `export` | rib tests `well_known_communities_limit_export` |
| 4360 §2 | Extended Communities type 16, optional transitive, eight-octet values; equal only when all octets equal | MUST | done | wire/community.rs `ExtendedCommunity` | community.rs `extended_communities` |
| 4360 §2 | Transitive bit (T) of the type high octet | MUST | done | wire/community.rs `is_transitive` | community.rs `extended_communities` |
| 4360 §3.1–3.3 | Two-octet AS, IPv4 address and opaque templates | MUST | done (constructors and display) | wire/community.rs | community.rs `extended_communities` |
| 4360 §6 | Non-transitive extended communities not propagated across ASes | MUST | done | rib/export.rs `export` | rib tests `non_transitive_extended_communities_stay_in_the_as` |
| 8092 §3 | Large Communities type 32, optional transitive, twelve-octet values | MUST | done | wire/community.rs `LargeCommunity` | community.rs `large_communities` |
| 8092 §3 | Never transmit duplicates; silently remove duplicates on receipt | MUST | done | wire/community.rs `decode_large_communities` | community.rs `large_communities` |
| 8092 §5 | Canonical `global:local1:local2` representation | MUST | done | wire/community.rs `Display` | community.rs `large_communities` |
| 8092 §6 | Length non-zero multiple of 12 else treat-as-withdraw; duplicates and reserved ASNs are not errors | SHALL / MUST | done | wire/community.rs, wire/update.rs | community.rs `large_communities`, update.rs |

## RFC 4486 / 6608 / 9003 — NOTIFICATION subcodes and shutdown communication

| RFC § | Requirement (short) | Level | Status | Code | Test |
|---|---|---|---|---|---|
| 4486 §3 | Cease subcodes 1–8 | MUST | done | wire/error.rs `CeaseSubcode`, `subcode_name` | error.rs `subcode_names_cover_every_defined_subcode` |
| 4486 §4 | Prefix limit exceeded → Cease / Maximum Number of Prefixes Reached | MUST | done (message; limit is the RIB's) | wire/notification.rs `max_prefixes_reached` | notification.rs `max_prefixes_data_field` |
| 4486 §4 | Maximum Prefixes Data: AFI, SAFI, upper bound | MAY | done | wire/notification.rs `max_prefixes_reached`, `max_prefixes` | notification.rs `max_prefixes_data_field` |
| 4486 §4 | Administrative Shutdown / Peer De-configured / Administrative Reset / Connection Rejected / Other Configuration Change / Connection Collision Resolution subcodes in their situations | SHOULD | done (ManualStop → Administrative Shutdown, collisions → Connection Collision Resolution; AutomaticStop carries the caller's subcode) | fsm/machine.rs | fsm tests state tables |
| 4486 §4 | Out of Resources subcode | MAY | done (message) | wire/notification.rs `cease` | notification.rs |
| 4486 §4 | Damp oscillations after Shutdown / De-configured / Rejected / Out of Resources; bound automatic retries | SHOULD | partial (IdleHoldTime doubles up to a cap after every damped failure; no retry bound) | fsm/machine.rs `go_idle` | fsm tests `damping_doubles_the_idle_hold_and_a_session_resets_it` |
| 6608 §3 | FSM subcodes 0–3 | MUST | done | wire/error.rs `FsmSubcode` | error.rs `subcode_names_cover_every_defined_subcode` |
| 6608 §4 | Unexpected message in OpenSent / OpenConfirm / Established → the matching subcode, Data = message type | MUST | done | fsm/machine.rs `fsm_error` | fsm tests `fsm_error_data_names_the_unexpected_message` |
| 9003 §2 | Shutdown Communication only with subcode 2 or 4 | MUST | done | wire/notification.rs `shutdown` | notification.rs `shutdown_communication_round_trips` |
| 9003 §2 | One-octet length; zero means absent | MUST | done | wire/notification.rs `shutdown`, `shutdown_communication` | notification.rs `shutdown_communication_round_trips` |
| 9003 §2 | UTF-8, shortest form; invalid sequences never interpreted | MUST | done (`std::str::from_utf8` rejects non-shortest forms) | wire/notification.rs `shutdown_communication` | notification.rs `malformed_shutdown_communication_is_reported_not_interpreted` |
| 9003 §2 | Report the communication, e.g. via syslog | SHOULD | done (logged at warn with the NOTIFICATION) | bgpfcd/peer.rs `primary_message` | interop `bird_shutdown_sends_cease_and_bgpfcd_retries` |
| 9003 §3 | At most 255 octets; at most 128 to a peer not known to support RFC 9003 | MAY / SHOULD | done (the codec enforces 255; the control plane refuses more than 128, as nothing tells it which peers support the RFC) | wire/notification.rs `shutdown`, bgpfcd/control.rs `check_communication` | notification.rs `shutdown_communication_round_trips`, bgpfcd/control.rs `parses_commands` |
| 9003 §4 | Log an invalid UTF-8 communication | SHOULD | done | wire/notification.rs `ShutdownCommunicationError`, bgpfcd/peer.rs `primary_message` | notification.rs `malformed_shutdown_communication_is_reported_not_interpreted` |

## RFC 7607 / 9072 / 9687 / 9774 — AS 0, extended OPEN parameters, send hold timer, AS_SET deprecation

| RFC § | Requirement (short) | Level | Status | Code | Test |
|---|---|---|---|---|---|
| 7607 §2 | AS 0 as peer AS in OPEN → Bad Peer AS | MUST | done | wire/open.rs `OpenMessage::decode` | open.rs `fixed_field_errors` |
| 7607 §2 | Never initiate a connection claiming AS 0 | MUST | done (`local-as 0` and `remote-as 0` are configuration errors) | config/lower.rs `asn` | config golden `value-errors.conf` |
| 7607 §2 | Never originate or propagate a route with AS 0 | MUST | done (nothing is originated; a received AS 0 path is treated as withdrawn before it can reach the Loc-RIB) | wire/update.rs `decode_as_path`, rib/lib.rs | update.rs `as_path_rules` |
| 7607 §2 | AS 0 in `AS_PATH` → malformed per RFC 7606 (treat-as-withdraw); in AGGREGATOR → attribute discard | MUST | done | wire/update.rs `decode_as_path`, `decode_one` | update.rs `as_path_rules` |
| 7607 §2 | AS 0 in `AS4_PATH` / `AS4_AGGREGATOR` → malformed per RFC 6793 (discard) | MUST | done | wire/update.rs `decode_as4_path` | update.rs |
| 9774 §3 | Never advertise `AS_SET` / `AS_CONFED_SET` | MUST | done (no aggregation; prepending always uses `AS_SEQUENCE`; a set accepted under `allow-as-set` is relayed as received, the operator's choice) | rib/export.rs `prepend` | rib tests `prepend_respects_segment_limit_and_sets` |
| 9774 §3 | `AS_SET` / `AS_CONFED_SET` in `AS_PATH` or `AS4_PATH` → treat-as-withdraw unless configured | MUST | done (`DecodeContext::allow_as_set`; `allow-as-set yes` per neighbor) | wire/update.rs `decode_as_path`, `decode_as4_path`, config/lower.rs | update.rs `as_path_rules`, config golden `full.conf` |
| 2545 §3 | IPv6 next hop: global address, link-local appended only when on a shared subnet; length 16 or 32 | MUST | done (codec; next-hop-self sends the global address only) | wire/mp.rs `NextHop`, rib/export.rs `export` | mp.rs `ipv6_unicast_reach_round_trips`, rib tests `ipv6_next_hop_self_and_v4_over_v6_session` |
| 8950 §3 | IPv4 NLRI with a 16- or 32-octet IPv6 next hop; the length selects the protocol | MUST | done | wire/mp.rs `NextHop::decode` | mp.rs `ipv4_nlri_with_ipv4_or_ipv6_next_hop` |
| 8950 §4 | Extended Next Hop Encoding capability | MUST | todo (capability code 5; needed before sending IPv6 next hops for IPv4) | | |
| 9072 §2 | Use the RFC 4271 encoding when parameters fit 255 octets | SHOULD | done | wire/open.rs `encode_with` | open.rs `open_with_capabilities_round_trips` |
| 9072 §2 | May force the extended encoding by configuration | MAY | done (codec flag; config knob later) | wire/open.rs `encode_with(true)` | open.rs `extended_parameters_are_chosen_when_needed_and_accepted_always` |
| 9687 §4.1 | SendHoldTimer / SendHoldTime session attributes, per peer | MAY | done (`send-hold-time N | off` per neighbor) | fsm/lib.rs `SendHoldTime`, config/lower.rs | fsm tests `send_hold_time_configuration`, config golden `full.conf` |
| 9687 §4.3 | Start the SendHoldTimer on entering Established when SendHoldTime is non-zero | MUST | done | fsm/machine.rs (event 26 in OpenConfirm) | fsm tests `established_timers_and_send_hold` |
| 9687 §4.3 | On expiry: optional NOTIFICATION, log an error, release resources, drop, counter +1, damp, Idle | MUST | done | fsm/machine.rs (event 29) | fsm tests `established_state_table` |
| 9687 §4.3 | Restart the SendHoldTimer on every sent message; stop it when SendHoldTime or the negotiated Hold Time is zero; stop it on leaving Established | MUST | done | fsm/machine.rs `restart_send_hold`, `message_sent`, `release_resources` | fsm tests `established_timers_and_send_hold`, `hold_time_zero_disables_timers` |
| 9687 §4.4 | A non-zero SendHoldTime must exceed the Hold Time | MUST | done (a configuration error; the FSM also falls back to the default against the negotiated value) | config/validate.rs, fsm/machine.rs `restart_send_hold` | config golden `validation-errors.conf`, fsm tests `send_hold_time_configuration` |
| 9687 §5 | Close the connection and log on expiry; NOTIFICATION may be sent | MUST / MAY | done (sent) | fsm/machine.rs (event 29) | fsm tests `established_state_table` |
| 9687 §6 | Enabled by default; default the greater of 8 minutes and twice the Hold Time; subcode 0, no data | SHOULD | done | fsm/lib.rs `SendHoldTime::Default`, fsm/machine.rs `restart_send_hold` | fsm tests `established_timers_and_send_hold` |
| 9687 §9 | Error code 8 "Send Hold Timer Expired" | MUST | done | fsm/machine.rs `SEND_HOLD_TIMER_EXPIRED` | fsm tests `established_state_table` |
| 9072 §2 | Accept the extended encoding even for ≤255 octets | MUST | done | wire/open.rs `decode_parameters` | open.rs `extended_parameters_are_chosen_when_needed_and_accepted_always` |
| 9072 §2 | Use the extended encoding when parameters exceed 255 octets | MUST | done | wire/open.rs `encode_with` | open.rs `extended_parameters_are_chosen_when_needed_and_accepted_always` |
| 9072 §2 | Non-Ext OP Len. 255 on send, never 0, ignored on receipt | SHOULD/MUST | done | wire/open.rs | open.rs `extended_parameters_are_chosen_when_needed_and_accepted_always` |
| 9072 §2 | Non-Ext OP Type 255 on send; 255 on receipt selects extended | MUST | done | wire/open.rs | open.rs `extended_parameters_are_chosen_when_needed_and_accepted_always` |
| 9072 §3 | Type 255 elsewhere is an unrecognised parameter | MUST | done | wire/open.rs `decode_parameters` | open.rs `parameter_errors` |
| 6286 §2.1 | BGP Identifier is any non-zero 4-octet value | MUST | done | wire/types.rs `RouterId::new` | types.rs `router_id_rejects_zero_only` |
