# openbgpify

A from-scratch BGP-4 speaker written in Rust, using **only the Rust standard
library**.

This replaces the earlier `bgpfc` prototype, which is gone as of this commit.
That prototype reached a pre-alpha state — it listened on TCP/179, encoded and
decoded BGP headers, OPEN and KEEPALIVE, split raw UPDATEs without interpreting
them, and read a JSON config — and is being rewritten rather than extended. The
old code remains in this repository's history if you need it.

**Status: pre-implementation.** There is no code in this repository yet. The
README below describes where the project is going, and the issue tree tracks how
it gets there. Nothing here is usable, and nothing here should be pointed at a
production network.

## Why standard-library-only is tractable here

BGP-4 is an unusually good fit for a no-dependency implementation, because the
base protocol mandates no cryptography. The wire format is fixed-width binary
TLV: a 19-octet header, then messages built from big-endian integers, length
prefixes, and bit flags. `u16::from_be_bytes`, `u32::to_be_bytes`, slice
indexing and careful bounds checks cover essentially the whole parser. There is
no certificate chain to validate, no cipher suite to negotiate, no ASN.1 to
decode. Compare this to writing a TLS stack from scratch, where "no
dependencies" means "hand-rolled cryptography" and the answer is simply don't.

`std` covers the rest of what a speaker needs: `std::net::TcpListener` and
`TcpStream` for the transport, `std::thread` for per-peer concurrency,
`std::sync::mpsc` for message passing to the RIB owner, `std::collections` for
the RIB itself, and `std::process::Command` for supervising the RPKI validator.

Two places still reach past pure `std`, and both are deliberately deferred:

- **TCP-MD5 authentication (RFC 2385)** needs `TCP_MD5SIG` via `setsockopt`,
  which `std` does not expose. It would require an `unsafe extern "C"`
  declaration against the platform's libc (the declaration can be written by
  hand — the `libc` crate is convenience, not necessity) plus an MD5
  implementation. TCP-AO (RFC 5925) has the same shape. Neither is in v1 scope.
- **Generalized TTL Security (GTSM, RFC 5082)** can send with a TTL of 255 using
  `TcpStream::set_ttl`, but *enforcing* the received TTL needs `IP_MINTTL`,
  which is again a raw `setsockopt`.

If either becomes a requirement, the fix is a small, clearly-marked `unsafe`
module — not a dependency tree.

### Dependency policy

Zero runtime dependencies, enforced by an empty `[dependencies]` table. Adding
one requires explicit sign-off from the repository owner, recorded in the issue
that introduces it. Test-only `[dev-dependencies]` are permitted under the same
sign-off rule; none are in use today, and the fuzz-harness issue will propose
specific ones when it is picked up.

- Rust edition 2024, MSRV 1.85 (pinned via `rust-version`, checked in CI).
- Licensed MIT, same as the prototype.

## Architecture

Two decisions shape everything else.

### The `ValidationSource` boundary

The RIB and decision engine never talk to a validator directly. They hold a
trait object and ask it questions:

```text
  UPDATE ──▶ parser ──▶ Adj-RIB-In ──┐
                                      ├──▶ decision process ──▶ Loc-RIB
  ValidationSource ───────────────────┘        (validation state is an
   • lookup(prefix, origin_as) -> ROV state     input to best-path, not a
   • verify(as_path) -> ASPA state              separate pass afterwards)
   • subscribe(changes) -> re-evaluation
```

Every route carries a validation-state field from the moment it is created, and
the trait is wired in from the first commit rather than retrofitted. Three
implementations are anticipated:

- **Null** — everything resolves to `NotFound`, no external process, validation
  effectively disabled. This is what makes "turn RPKI off" a config value
  instead of a code path.
- **RTR client** — speaks RPKI-RTR (RFC 8210) to a validator over TCP. The
  default, pointed at the bundled sidecar, but repointable at any cache.
- **In-process** (someday, maybe) — if the project ever grows its own validation
  logic, it slots in behind the same trait with no changes above it.

The subscription half matters as much as the lookup half: when the cache pushes
new VRPs, routes already in the RIB must be re-evaluated. Validation state
changes without any BGP message arriving.

### Routinator as a supervised sidecar

RPKI-to-Router is the easy half of RPKI. The hard half — fetching repositories
over RRDP and rsync, validating X.509 certificate chains, CMS signed objects,
manifests and CRLs — is a larger project than this BGP speaker, and it drags in
exactly the TLS-and-crypto problem that std-only was chosen to avoid.

So it isn't reimplemented. [Routinator](https://github.com/NLnetLabs/routinator)
(NLnet Labs' relying-party software) is bundled and run as a child process via
`std::process::Command`, with a watcher thread that restarts it if it dies, and
its RTR socket auto-wired to localhost. The operator configures one thing, in
one file, and gets a validating speaker. Pointing at an existing organizational
validator instead — and skipping the sidecar entirely — stays a config option.

## v1.0.0 goals

- **Wire format** — header, OPEN, KEEPALIVE, NOTIFICATION encode/decode; 4-byte
  ASN negotiation with AS_TRANS fallback (RFC 6793); Multiprotocol Extensions
  (RFC 4760) and Route Refresh (RFC 2918) capabilities.
- **Finite state machine** — RFC 4271 §8, Idle through Established, with
  ConnectRetryTimer / HoldTimer / KeepaliveTimer, connection collision detection
  by BGP Identifier tie-break, and both active and passive establishment on
  TCP/179.
- **UPDATE handling** — withdrawn routes and NLRI parsing; ORIGIN, NEXT_HOP,
  MED, LOCAL_PREF, ATOMIC_AGGREGATE, AGGREGATOR; AS_PATH originating
  AS_SEQUENCE only (AS_SET origination is deprecated by RFC 9774; receipt is
  handled defensively); attribute flag validation with RFC 7606
  treat-as-withdraw semantics.
- **IPv4 and IPv6 from the start** — MP_REACH_NLRI / MP_UNREACH_NLRI in v1, not
  bolted on later. Retrofitting multiprotocol into a v4-shaped RIB is the kind
  of rework this rewrite exists to avoid.
- **RIB and decision engine** — Adj-RIB-In / Loc-RIB / Adj-RIB-Out behind a
  `Rib` trait, interned attribute sets, best-path selection with a documented
  tie-break order, and a validation-state field on every route.
- **Policy, reject-by-default** — carried forward from `bgpfc` unchanged.
  Nothing is imported or exported without an explicit policy match. ROV-Invalid
  routes are dropped by default.
- **Concurrency** — thread-per-peer I/O loops, a central RIB-owner thread,
  channel-based message passing, graceful teardown.
- **RPKI ROV, on by default** — `ValidationSource` trait, RTR client against RFC
  8210 (session setup, serial numbers, cache reset and response PDUs), RFC 6811
  Valid / NotFound / Invalid states applied in the decision process, and cache
  changes triggering re-evaluation independently of new UPDATEs.
- **Error handling** — NOTIFICATION error codes and subcodes, and a documented
  policy for when a fault is treat-as-withdraw versus session reset.
- **Advertisement** — per-peer re-advertisement under policy, withdraw
  generation, MRAI pacing.
- **Routinator sidecar, minimal** — spawn, restart-on-crash, localhost RTR
  wiring, one unified config surface.
- **Interop** — a v1 is not done until it peers successfully and exchanges
  routes correctly with **both FRRouting and BIRD** in the lab. Two independent
  implementations cross-checking the parser is the point; a speaker that only
  talks to itself validates nothing.

## v1.1.0 goals

- **ASPA (opt-in, draft-track)** — see below.
- **Fuller sidecar supervision** — backoff, health checks, log plumbing,
  operational visibility.
- **Fuzz hardening** — a malformed-UPDATE corpus and sustained fuzzing of the
  parser.
- **Configuration polish** — whatever the FRR/BIRD-style config parser needs
  after real use.

## Configuration

Config is an FRR/BIRD-style indented block language, parsed by hand. With
`serde_json` gone, JSON stopped being free, and if a parser has to be written
either way it may as well be one network operators can read without a manual.
The parser reports errors with line numbers and is treated as untrusted input
like any other.

## Non-goals

Not planned, and a patch implementing one will be declined unless the scope
decision is revisited first:

- MPLS VPNs (RFC 4364) and EVPN (RFC 7432)
- BGP-LS (RFC 9552) and Segment Routing Policy distribution
- FlowSpec (RFC 8955)
- BGPsec (RFC 8205)
- Route-server operation (RFC 7947)
- Confederations (RFC 5065)
- Add-Path (RFC 7911)
- Long-Lived Graceful Restart

This is a standards-oriented BGP-4 speaker with origin validation. It is not
aiming to be a service-provider edge platform.

**ASPA is not in this list.** ASPA is *draft-track and opt-in*, tracked
separately for v1.1. Both the ASPA profile and the AS_PATH verification
procedure are still IETF drafts rather than published RFCs, and real-world
deployment remains a fraction of a percent of ASes. It ships behind an
explicitly-off-by-default flag — mirroring how Routinator gates its own ASPA
support — and the spec is expected to move underneath the implementation. The
transport is an open question that resolves when the work is picked up: RTR
version 2 (8210bis) if it is stable by then, otherwise Routinator's JSON/HTTP
API as a fallback.

A handful of features are deliberately undecided rather than ruled out — route
reflection (RFC 4456) and plain graceful restart (RFC 4724) among them. They
will be settled when there is a reason to settle them.

## Lab and testing

All development and interop testing happens in a private VM lab, kept strictly
separate from any production network — in particular **AS17290**, which is not
to be used for, peered with, or configured from this project's testing.

The lab uses reserved resources only:

- **ASNs** from the private ranges: 64512–65534 (16-bit) and 4200000000–
  4294967294 (32-bit), for exercising 4-byte ASN handling and AS_TRANS.
- **IPv4** from RFC 1918 (10/8, 172.16/12, 192.168/16) and the documentation
  prefixes 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24.
- **IPv6** from ULA space (fd00::/8) and the 2001:db8::/32 documentation prefix.

Interop targets are **FRRouting** and **BIRD**, run as VM peers. Beyond live
peering, testing covers unit tests on every encoder and decoder, round-trip
tests over the wire format, and a malformed-UPDATE fuzz corpus. Anything that
parses bytes off a socket is treated as hostile input; a malformed UPDATE must
never panic the process, and per RFC 7606 it usually must not reset the session
either.

## Resources

RFCs and drafts relevant to this work are collected in [RESOURCES.md](RESOURCES.md).
