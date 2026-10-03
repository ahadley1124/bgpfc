# AGENTS.md

Rules for anyone writing code in this repository, whether human or AI. Read the
whole file before your first change. Where this file and your instincts
disagree, this file wins. If this file is silent or ambiguous, ask the
maintainer rather than guessing, and propose an edit to this file in the same
PR.

bgpfc is a std-only BGP-4 routing daemon for Linux. See [`README.md`](README.md)
for what it does and [`RESOURCES.md`](RESOURCES.md) for the RFCs.

---

## 1. The non-negotiables

1. **std only in shipped code.** No crate in `crates/` may have a
   `[dependencies]` or `[build-dependencies]` entry other than another
   `bgpfc-*` workspace crate. That rules out `libc`, `serde`, `bytes`,
   `thiserror`, `log`, `regex`, `nix`, `socket2`, and so on. If you think you
   need one, write the 50 lines yourself. `scripts/check-deps.sh` enforces this.
2. **Crates are fine for verification.** `proptest` and `criterion` may go in
   `[dev-dependencies]`. `libfuzzer-sys` and `arbitrary` live only in `fuzz/`.
   The interop harness lives only in `interop/`. None of these may ever leak
   into a normal dependency edge of a shipped crate.
3. **`unsafe` only in `bgpfc-sys`.** Every other crate starts with
   `#![forbid(unsafe_code)]`. In `bgpfc-sys`:
   - every `unsafe` block has a `// SAFETY:` comment explaining why it is
     sound;
   - `#![deny(unsafe_op_in_unsafe_fn)]` and
     `#![warn(clippy::undocumented_unsafe_blocks)]` are on;
   - `unsafe` never escapes. The crate exports only safe wrappers, such as
     `NetlinkSocket::send(&self, &[u8])`, and no raw pointers or file
     descriptors.
4. **OS access goes through hand-written `extern "C"` declarations** in
   `bgpfc-sys`. std already links glibc or musl, so declaring `socket`,
   `bind`, `sendto`, `recvfrom`, `setsockopt`, `getsockopt`, `close`,
   `setuid`, `setgid`, `setgroups`, and `getuid` adds no dependency. Rules:
   - Declare only what you use.
   - Take constants and struct layouts from the Linux uapi headers. Cite the
     header in a comment, for example `// <linux/rtnetlink.h>`.
   - Add a test that asserts `size_of`/`align_of` for every `#[repr(C)]`
     struct.
   - Wrap file descriptors in `std::os::fd::OwnedFd` immediately.
   - Do not use inline-asm syscalls, and do not shell out to `ip`.
5. **Linux only.** Gate `bgpfc-sys` and `bgpfc-fib` I/O on
   `#[cfg(target_os = "linux")]`. Do not add abstraction layers for other
   operating systems.
6. **Never crash on peer input.** Error handling is pragmatic. `unwrap()` is
   fine for genuine internal invariants, but a malformed message from a
   neighbor, a bad config file, or a bad control-socket request must become a
   typed error and the correct protocol reaction, never a panic. Slice
   indexing on wire data must be bounds-checked, either through a cursor type
   or `get()`. When you do `unwrap`, the reason must be obvious, or carry an
   `// invariant:` comment.

## 2. Workspace layout

```
Cargo.toml              [workspace], shared [workspace.lints], profile settings
rust-toolchain.toml     channel = "<current stable>", components = rustfmt, clippy, miri
crates/
  bgpfc-wire/           codec: header, OPEN, UPDATE, NOTIFICATION, KEEPALIVE,
                        ROUTE-REFRESH, path attributes, capabilities, NLRI.
                        Pure: &[u8] -> Result<T, DecodeError>, T -> Vec<u8>.
  bgpfc-fsm/            RFC 4271 §8 FSM. Pure: (State, Event, Instant) ->
                        (State, Vec<Action>). Never reads the clock, never
                        touches sockets.
  bgpfc-rib/            Adj-RIB-In per peer, Loc-RIB, Adj-RIB-Out per peer,
                        decision process (§9.1), update generation.
  bgpfc-policy/         prefix lists, AS-path regex (own engine), community
                        match, set actions, evaluation.
  bgpfc-config/         lexer -> parser -> AST -> validated Config. Errors
                        carry line:col and a caret snippet.
  bgpfc-fib/            rtnetlink message encode/decode (pure, Miri-tested) and
                        FIB reconciliation (desired vs. installed). Uses
                        bgpfc-sys for the socket only.
  bgpfc-sys/            unsafe FFI boundary: sockets, netlink, setsockopt,
                        privilege drop, capability inspection.
  bgpfc-log/            leveled logger to stderr.
  bgpfc-control/        Unix-socket line protocol, minimal HTTP/1.1 server,
                        JSON writer (and a minimal JSON reader if needed).
  bgpfcd/               daemon binary: wiring, threads, signals.
  bgpfcctl/             CLI binary.
fuzz/                   cargo-fuzz crate, NOT a workspace member. Nightly allowed.
interop/                dev-only crate: drives BIRD / FRR / GoBGP in network
                        namespaces or containers. Not a workspace default-member.
benches/ (per crate)    criterion benches as dev-dependencies.
scripts/                check.sh, check-deps.sh, miri.sh, ...
contrib/                bgpfcd.service, example configs.
docs/                   config.md (grammar), control.md (CLI + HTTP API), design notes.
COMPLIANCE.md           RFC requirement matrix (see §6).
```

The dependency direction is strictly downward:
`bgpfcd → {control, rib, policy, fsm, config, fib, log} → wire`, and `fib → sys`.
`wire`, `fsm`, `policy`, and `config` must not depend on `sys`. Keep
protocol logic pure so it can be tested without sockets or time.

The crate names and boundaries above are the plan. Changing them, for example
by merging two crates, is fine if it is justified in the PR description and
this file is updated in the same PR.

## 3. Architecture

**Threading model: one thread per peer, plus channels.** There is no async
runtime and no hand-rolled epoll.

- **Listener thread**: `TcpListener` on the configured addresses. When it
  accepts a connection, it identifies the peer by remote address and hands the
  `TcpStream` to the coordinator.
- **Peer thread** (one per configured neighbor): owns the `TcpStream` and that
  peer's `bgpfc-fsm` state.
  - Blocking reads use `set_read_timeout`, with the timeout set to the time
    until the next FSM timer deadline.
  - Each decoded message becomes an FSM event, and the actions the FSM returns
    are executed (send, close, connect, notify the RIB).
  - It sends `RibMsg::{PeerUp, Update, PeerDown, RouteRefresh}` to the RIB
    thread and receives `PeerCmd::{Send(Vec<u8>), Stop, Clear}`.
- **Connection collision (§6.8)**: resolved by the coordinator, which owns the
  peer table and can see both connections.
- **RIB thread**: the only owner of all RIB state. It runs import policy, the
  decision process, export policy, and update generation. It sends outbound
  UPDATEs to peer threads and route deltas to the FIB thread. **There is no
  `Mutex` around RIB data.**
- **FIB thread**: owns the netlink socket. It reconciles the desired routes
  from the RIB against the routes actually installed. In dry-run mode it logs
  the netlink operations it would perform and stops there.
- **Control thread(s)**: the Unix-socket server and the HTTP server. They
  query the RIB and coordinator through request/response channels, for
  example `(Query, mpsc::Sender<Reply>)`. They never read shared state
  directly.
- **Signals**: std has no signal API, so `bgpfc-sys` installs a minimal
  `SIGTERM`/`SIGHUP`/`SIGINT` handler that only writes to a self-pipe or sets
  an `AtomicBool`. Everything else happens on normal threads.
- **Backpressure**: use bounded `mpsc::sync_channel` between peer threads and
  the RIB thread. A slow peer must not be able to grow memory without bound.
  Outbound queues per peer are bounded too. When a peer falls too far behind,
  reset its session and log it. Never drop updates silently.

**Time.** Use `std::time::Instant` for timers and `SystemTime` for log
timestamps only. FSM and RIB code receive `now: Instant` as an argument so
tests can drive time deterministically.

**FIB.**
- Routes use rtnetlink with `rtm_protocol = 186` (RTPROT_BGP, configurable)
  in the main table.
- At startup, the FIB thread dumps the routes that carry our protocol number,
  diffs them against the (empty) desired set, and removes the stale ones.
  Never touch routes with another protocol number.
- `mode dry-run | install` comes from config, can be overridden with a CLI
  flag, and can be toggled at runtime through the control channel. **The
  default is dry-run.** Switching from dry-run to install performs a full
  reconcile.
- Single best path only. Do not use nexthop groups.

**Privileges.** Support both modes described in the README:

- **Capabilities (recommended).** At startup, parse `CapEff` from
  `/proc/self/status`. Do not use FFI for this. Fail with a clear message
  that names any capability that is missing and needed.
- **Root, then drop.** Open listeners and the netlink socket first. Then call
  `setgroups` → `setgid` → `setuid`, and verify that `setuid(0)` now fails.

Ship `contrib/bgpfcd.service` with the ambient-capabilities setup.

**Control plane.**
- `bgpfcctl` speaks a line-oriented request/response protocol over a Unix
  socket. Document it in `docs/control.md`.
- The HTTP server is hand-written HTTP/1.1 and JSON-only:
  - Bind to loopback only. Reject a non-loopback `listen` address at config
    validation.
  - Write endpoints return 403 unless `writes yes;` is set.
  - If a token file is configured, require `Authorization: Bearer`.
  - Cap request size, header count, and connection count, and set read
    timeouts.
  - There is no TLS.
- JSON output is produced by a small writer in `bgpfc-control` that handles
  escaping correctly. Test it against a reference parser in dev-dependencies
  if useful.

**Logging.**
- `bgpfc-log` writes one line per event to stderr, in this format:
  `2026-10-03T12:34:56.789Z INFO  peer=198.51.100.1 msg="session established" hold=90`.
- Levels are `error`, `warn`, `info`, `debug`, and `trace`.
- Timestamps are UTC, formatted by hand from `SystemTime`, because std has no
  date formatting.
- No global allocator tricks and no `log` crate facade.

**Config.**
- The config language is block-style, in the spirit of BIRD and OpenBGPD. The
  README shows an example.
- `docs/config.md` holds the grammar in EBNF and is authoritative. Update it
  in the same commit as any parser change.
- The parser reports every error with `file:line:col`, and recovers enough to
  report several errors in one pass.
- Validation is a separate pass after parsing. It checks:
  - undefined policy or prefix-list references;
  - duplicate neighbors;
  - that every neighbor has an import and an export policy;
  - that the HTTP listen address is loopback.
- Reload is triggered by SIGHUP or `bgpfcctl reload`. It diffs the old and new
  config, applies only what changed, and resets only the sessions whose
  session parameters changed. Policy-only changes trigger a soft
  re-evaluation, using route refresh where the peer supports it.

**Policy (v1).**
- Per-neighbor `import` and `export` policies are ordered lists of terms.
  Each term has match clauses and then actions. A term ends with `accept`,
  `reject`, or `next`. If no term decides, the route is rejected.
- Match clauses: `prefix`, `prefix-list` (with `ge`/`le`), `as-path` regex,
  `community`/`ext-community`/`large-community`, `origin`, and `neighbor`.
- Set actions: `local-pref`, `med`, add/remove/replace communities (all three
  kinds), `as-path prepend`, and `next-hop self`.
- The AS-path regex engine is our own. Operators match on ASN tokens, not
  characters: `^ $ . * + ? [ ] ( ) |` and `_`. Build it as a Thompson NFA or
  a backtracker with a step limit, so that pathological patterns cannot hang
  the RIB thread.

## 4. Protocol rules

- **Implement to the RFC text, not to another daemon's behavior.** Where an
  RFC is ambiguous, follow what BIRD and FRR do. Document it in a
  `// NOTE(interop):` comment and in COMPLIANCE.md.
- **Cite the section on every rule**: `// RFC 4271 §6.3: ...`,
  `// RFC 7606 §7.3`. This applies to every check, every NOTIFICATION
  code/subcode choice, every timer default, and every decision-process step.
  A reviewer must be able to trace each line of protocol logic to its source.
- **Error handling (RFC 7606).** Classify every attribute error as one of
  session reset, treat-as-withdraw, attribute discard, or AFI/SAFI disable.
  Do not reset a session where 7606 says treat-as-withdraw.
- **NOTIFICATIONs** use the exact code/subcode from RFC 4271 §6, 4486, 6608,
  and 7606, and carry the correct data field.
- **Cease / Shutdown** messages follow RFC 9003. `bgpfcctl` can send a shutdown
  communication string.
- **Send hold timer (RFC 9687).** Implement it. A peer that stops reading must
  not wedge us.
- **AS_SET (RFC 9774).** Never generate AS_SET. Treat received AS_SET per
  9774.
- **AS 0 (RFC 7607).** Implement as specified.
- **Extended messages (RFC 8654).** Negotiate the capability. The maximum
  message length is 4096 bytes unless both sides advertise it, in which case
  it is 65535. This applies to encode and decode alike.
- **4-octet ASN (RFC 6793).** Full support, including AS4_PATH/AS4_AGGREGATOR
  reconstruction for old speakers, and AS_TRANS.
- **Address families in v1**: IPv4 unicast and IPv6 unicast. That includes
  IPv6 link-local next hops (RFC 2545) and IPv4 NLRI over an IPv6 next hop
  (RFC 8950).

## 5. Testing and verification

**Every change ships with tests.** The level of testing depends on the layer:

| Layer | Required |
|---|---|
| `bgpfc-wire` | Unit tests with byte vectors copied from the RFCs and from real captures. `proptest` round-trips (`decode(encode(x)) == x`, and `encode(decode(b)) == b` for canonical inputs). A fuzz target per top-level decoder. Miri. |
| `bgpfc-fsm` | Table-driven tests covering every (state, event) pair in RFC 4271 §8.2.2, with injected time. |
| `bgpfc-rib` | Decision-process tests per tie-break step (§9.1.2.2). Proptest invariants: Loc-RIB is a function of the Adj-RIBs-In and policy, and is independent of arrival order. |
| `bgpfc-policy` | Regex engine tests, including pathological-pattern step-limit tests. A fuzz target. |
| `bgpfc-config` | Golden tests: input file → AST/debug output, and input file → error message snapshot. A fuzz target. |
| `bgpfc-fib` | Netlink encode/decode tests against byte captures from `ip -d monitor` or strace. Miri on the pure parts. A reconcile-logic proptest. |
| `bgpfc-sys` | Layout assertions. Real-socket tests where no privileges are needed. Mark tests that need privileges `#[ignore]`, and document how to run them. |
| `interop/` | Scenarios against BIRD, FRR, and GoBGP: session up, prefixes exchanged both ways, withdraw, route refresh, NOTIFICATION on bad input, 4-octet ASN with a 2-octet peer. Uses network namespaces and needs root, so it runs in CI and on demand. |
| benches | `criterion` benches for UPDATE decode, RIB insert/withdraw at full-table scale (~1M IPv4 + ~250k IPv6), and policy evaluation. Do not regress them without saying so in the PR. |

Miri cannot run FFI. Put real syscalls behind
`#[cfg(not(miri))]` and keep the encode/decode logic separate so Miri can cover
it.

### Gates: all must pass before every commit

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
scripts/check-deps.sh                                   # std-only enforcement
cargo +nightly miri test -p bgpfc-wire -p bgpfc-sys -p bgpfc-fib   # via scripts/miri.sh
```

`scripts/check.sh` runs all five. If a gate fails, fix the cause. Never
`#[allow]` a lint, `#[ignore]` a test, or loosen a gate to get green without
the maintainer's explicit agreement. If you must add an `#[allow]`, it needs a
comment explaining why.

`check-deps.sh` must fail if `cargo tree -e normal,build --workspace` (with
`fuzz/` and `interop/` excluded) lists any package that is not a `bgpfc-*`
workspace member.

**Milestone 0** creates `scripts/check.sh`, `scripts/check-deps.sh`,
`scripts/miri.sh`, `rust-toolchain.toml`, the workspace lint table, and a
GitHub Actions workflow running the same gates, plus a separate interop job.
Until then, run whatever gates exist.

### Workspace lints (set in root `Cargo.toml`)

```toml
[workspace.lints.rust]
unsafe_code = "forbid"          # bgpfc-sys overrides to "deny" + per-block allow
missing_docs = "warn"
unreachable_pub = "warn"

[workspace.lints.clippy]
all = { level = "warn", priority = -1 }
pedantic = { level = "warn", priority = -1 }
undocumented_unsafe_blocks = "deny"
dbg_macro = "deny"
todo = "warn"
```

## 6. Compliance tracking

`COMPLIANCE.md` lists every MUST, SHOULD, and MAY in each in-scope RFC, one
row per requirement:

| RFC § | Requirement (short) | Level | Status | Code | Test |
|---|---|---|---|---|---|

- **Status** is one of `done`, `partial`, `todo`, `n/a`, or `deviates`.
  `deviates` needs a reason.
- **Code** and **Test** are file paths.
- A PR that implements protocol behavior updates the matching rows.
- The README must not claim compliance with an RFC until every MUST row for
  it is `done`.

## 7. Style

- Rust 2024 edition, current stable toolchain, pinned in
  `rust-toolchain.toml`. No nightly features in shipped crates. `fuzz/` and
  Miri may use nightly.
- Wire types are typed. Use newtypes such as `Asn(u32)`, `RouterId(Ipv4Addr)`,
  and `HoldTime(u16)` with validated constructors, and enums for codes and
  subcodes with a `Unknown(u8)` variant where the RFC allows unknown values.
- **Errors**: one enum per crate, implementing `std::error::Error` and
  `Display` by hand. Decode errors carry enough information to build the
  NOTIFICATION, namely code, subcode, and data.
- **Parsing**: use a small `Reader<'a>` cursor (`u8()`, `u16_be()`,
  `take(n)`, ...) that returns `Result`. Do not use manual offset arithmetic
  on raw slices.
- **Allocation**: avoid per-route heap churn in hot paths. Attribute sets are
  interned or shared with `Arc` across routes with identical attributes.
- **Docs**: every `pub` item has a doc comment. Module docs list the RFCs the
  module implements.
- **Comments**: explain *why* and cite the RFC. Do not narrate the code.
- Keep functions small enough to test. Prefer pure functions plus a thin I/O
  shell.

## 8. Git workflow

- **One logical change per commit.** Use Conventional Commit prefixes with the
  crate as the scope, and an imperative, lowercase subject of 72 characters or
  fewer:
  - `feat(wire): add OPEN message decoder`
  - `fix(fsm): reset ConnectRetryCounter on ManualStop`
  - `test(rib): cover MED tie-break across neighbor AS`
  - `docs(config): document prefix-list ge/le`
  - `chore(ci): add miri job`
- Types: `feat`, `fix`, `test`, `docs`, `refactor`, `perf`, `chore`, `ci`.
- Every commit compiles and passes the gates. Do not commit with "fix tests
  later".
- Open one PR per milestone feature, not one giant PR. The PR description
  lists:
  - the RFC sections implemented;
  - the COMPLIANCE.md rows changed;
  - how the change was tested.
- Do not rewrite published history on shared branches.

## 9. Roadmap

Work roughly in this order. Each step should end with a green gate run and an
updated COMPLIANCE.md.

0. **Skeleton.**
   - Workspace, toolchain pin, lints, and the scripts in `scripts/`.
   - CI.
   - Empty crates with `#![forbid(unsafe_code)]`.
   - `bgpfc-log`.
1. **Codec (`bgpfc-wire`).**
   - Header, OPEN (with RFC 9072 extended optional parameters), and
     capabilities (5492, 6793, 4760, 2918, 8654).
   - KEEPALIVE, NOTIFICATION (4271 §6, 4486, 6608, 9003), and ROUTE-REFRESH.
   - UPDATE with all well-known attributes, AS_PATH/AS4_PATH,
     MP_REACH/MP_UNREACH, and communities (1997, 4360, 8092).
   - RFC 7606 error classification.
   - Proptest, fuzz targets, and Miri.
2. **FSM (`bgpfc-fsm`).**
   - Full RFC 4271 §8 state machine, including the RFC 9687 send hold timer.
3. **Sessions (`bgpfcd`).**
   - Listener, peer threads, and collision detection.
   - Establish a session with BIRD in `interop/`.
4. **Config (`bgpfc-config`).**
   - Lexer, parser, validation, and `docs/config.md`.
   - Reload diffing.
5. **RIB (`bgpfc-rib`).**
   - Adj-RIB-In, decision process, Loc-RIB, Adj-RIB-Out, and update
     generation and packing.
   - Route refresh, and 4-octet ASN interop with 2-octet peers.
6. **Policy (`bgpfc-policy`).**
   - Prefix lists, the AS-path regex engine, community match/set, and wiring
     into the RIB.
7. **FIB (`bgpfc-fib` + `bgpfc-sys`).**
   - rtnetlink route add/delete/dump, startup flush, and reconcile.
   - Dry-run and install modes, and the runtime toggle.
8. **Control (`bgpfc-control`, `bgpfcctl`).**
   - Unix-socket protocol, HTTP/JSON API, and `docs/control.md`.
9. **Hardening.**
   - Both privilege modes and `contrib/bgpfcd.service`.
   - Full-table benchmarks, and the interop matrix against FRR and GoBGP.
   - Fuzzing campaign.
   - README status update.

**Out of scope until the maintainer says otherwise:** RPKI/RTR, BGP roles
(9234), RFC 8212, graceful restart, ADD-PATH, route reflection, confederations,
ECMP, VPN families, TCP-MD5/AO, and non-Linux platforms. Do not add hooks or
abstractions "for later". Build v1 cleanly, and refactor when a feature
actually lands.

## 10. When unsure

- Read the RFC section before writing the code. RESOURCES.md links them, and
  `resources/` has offline copies of some.
- If a requirement conflicts with this file, stop and ask.
- If you notice something wrong in this file, fix it in its own
  `docs(agents): ...` commit.
