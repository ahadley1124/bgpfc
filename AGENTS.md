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
   - The counting global allocator of profiling builds lives here too
     (`bgpfc_sys::alloc`, behind the `profiling` feature): its
     `unsafe impl GlobalAlloc` forwards to `System`.
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
  bgpfc-fib/            rtnetlink message encode/decode (pure, Miri-tested),
                        FIB reconciliation (desired vs. installed), and the
                        read-only monitor of the kernel's routing table.
                        Uses bgpfc-sys for the sockets only.
  bgpfc-sys/            unsafe FFI boundary: sockets, netlink, setsockopt,
                        TCP connect options, privilege drop, capability
                        inspection, network namespaces.
  bgpfc-log/            leveled logger to stderr.
  bgpfc-control/        Unix-socket line protocol, minimal HTTP/1.1 server,
                        JSON writer (and a minimal JSON reader if needed).
  bgpfc-rpki/           VRP set, RFC 6811 route origin validation, and the
                        ValidationSource trait. Pure: no sockets, no clock.
  bgpfc-rtr/            RFC 8210 RTR: PDU codec (pure, Miri-tested), session
                        machine with injected time, and the client thread.
  bgpfc-sidecar/        Routinator supervision: a child process spawned and
                        restarted through std::process::Command.
  bgpfcd/               daemon binary: wiring, threads, signals.
  bgpfcctl/             CLI binary.
  bgpfc-prof/           profiling instruments: counters, log2 histograms, span
                        timers, /proc memory, the report line. Linked only
                        through the `profiling` features (docs/PROFILING.md).
  bgpfc-bench/          dev tooling, never linked by the daemon: bgp_loadgen,
                        bgp_bench, the MRT reader, std-only micro-benchmarks.
fuzz/                   cargo-fuzz crate, NOT a workspace member. Nightly allowed.
interop/                dev-only crate: drives BIRD / FRR / GoBGP in network
                        namespaces or containers, with RTR caches (StayRTR and
                        a stub of its own) and a fake Routinator. Not a
                        workspace default-member.
benches/ (per crate)    criterion benches as dev-dependencies.
bench/results.csv       bgp_bench history; machine-specific, git-ignored.
scripts/                check.sh, check-deps.sh, miri.sh, ...
contrib/                bgpfcd.service, example configs.
docs/                   config.md (grammar), control.md (CLI + HTTP API),
                        PROFILING.md, design notes.
COMPLIANCE.md           RFC requirement matrix (see §6).
```

The dependency direction is strictly downward:
`bgpfcd → {control, rib, policy, fsm, config, fib, log} → wire`, and `fib → sys`.
Route origin validation adds `rpki → wire`, `rtr → {rpki, wire, log}`,
`sidecar → {sys, log}`, `rib → rpki`, and `config → rpki`, so that the
configuration reads validation states and enforcement modes as `bgpfc-rpki`
spells them; `bgpfcd` may depend on all three.
`wire`, `fsm`, `policy`, `config`, `rpki`, and `rtr` must not depend on
`sys`. Keep protocol logic pure so it can be tested without sockets or time.
`bgpfc-prof` is a leaf below `wire`; `wire`, `rib` and `bgpfcd` reach it only
through their `profiling` feature, so a default build does not link it.
`bgpfc-bench` sits on top and only `bgpfcd`'s tests depend on it.

The crate names and boundaries above are the plan. Changing them, for example
by merging two crates, is fine if it is justified in the PR description and
this file is updated in the same PR.

## 3. Architecture

**Threading model: one thread per peer, plus channels.** There is no async
runtime and no hand-rolled epoll.

- **Listener thread**: `TcpListener` on the configured addresses. When it
  accepts a connection, it identifies the peer by remote address and hands the
  `TcpStream` to the coordinator. Before that it sets the neighbor's TTL on
  the accepted socket (1 for an external neighbor without `multihop`; the
  SYN-ACK has already left with the listener's), and it closes a connection
  to another local address than the neighbor's `local-address`.
- **Peer thread** (one per configured neighbor): owns the `TcpStream` and that
  peer's `bgpfc-fsm` state. It connects through `bgpfc_sys::TcpConnect`,
  with the neighbor's TTL and bound to its `local-address`, since std's
  `TcpStream` can do neither.
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
  `Mutex` around RIB data.** It also keeps the copy of the kernel's table
  that next hops resolve in (RFC 4271 §9.1.2), and an index from each next
  hop to the destinations with a route through it, so that a change of the
  table decides again only those destinations.
- **FIB thread**: owns the netlink socket. It reconciles the desired routes
  from the RIB against the routes actually installed. In dry-run mode it logs
  the netlink operations it would perform and stops there.
- **Kernel thread**: owns a second netlink socket, subscribed to the route,
  link and address groups before it dumps. `main` reads the kernel's main
  table through it before the RIB thread exists, so no route is judged
  without one; the thread then forwards the changes to the RIB thread
  (`RibMsg::Kernel`), keeping only the routes a next hop may resolve
  through: neither bgpfcd's own (its protocol number) nor a default route.
  It keeps them as the kernel holds them (`bgpfc_fib::mirror`), every
  route at a destination and metric in the kernel's order, placed by the
  notifications' `nlmsg_flags`, and hands the RIB, which keeps one a
  destination and metric, the one the kernel uses there when it changes.
  It hands on together, by their net effect, the notifications that come
  within 10 ms of the first of a batch. It reads the table whole again
  when notifications were lost (`ENOBUFS`), when an interface goes down or
  away or an address is removed, since IPv4 then drops routes without a
  notification each, and when a change cannot be placed for sure (a route
  of bgpfcd's among others' at one destination and metric). It never
  writes to the kernel, in dry-run and install mode alike.
- **Control thread(s)**: the Unix-socket server and the HTTP server. They
  query the RIB and coordinator through request/response channels, for
  example `(Query, mpsc::Sender<Reply>)`. They never read shared state
  directly.
- **Signals**: std has no signal API, so `bgpfc-sys` installs a minimal
  `SIGTERM`/`SIGHUP`/`SIGINT` handler that only writes to a self-pipe or sets
  an `AtomicBool`. Everything else happens on normal threads. The self-pipe
  is created close-on-exec (`pipe2(O_CLOEXEC)`), so no child inherits it.
  Only the sidecar reaps its own child: nothing else in bgpfcd may ignore
  `SIGCHLD`, call `waitpid(-1)` or run a reaper thread, or the sidecar loses
  its child (`bgpfc-sidecar`, `Sidecar`, "Threads").
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
- A route not installed yet goes in with `NLM_F_EXCL`, so that another
  program's route with its destination and metric (20, zebra's too) stays:
  the kernel answers `EEXIST` and the route waits, reported as a failure,
  until the RIB offers it again once that route leaves the kernel's table.
  A route of ours whose hop changes replaces itself (`NLM_F_REPLACE`), with
  no moment without a route.
- `mode dry-run | install` comes from config, can be overridden with a CLI
  flag, and can be toggled at runtime through the control channel. **The
  default is dry-run.** Switching from dry-run to install performs a full
  reconcile.
- Single best path only. Do not use nexthop groups.
- A route goes in through the hop its next hop resolves to: the gateway and
  interface (`oif`) of the kernel route that resolves it, or the next hop
  itself on a connected network, with its interface. A delete the kernel
  answers `ESRCH` is done: the kernel removed the route itself.

**Privileges.** Support both modes described in the README:

- **Capabilities (recommended).** At startup, parse `CapEff` from
  `/proc/self/status`. Do not use FFI for this. Fail with a clear message
  that names any capability that is missing and needed.
- **Root, then drop.** Open listeners and the netlink socket first. Then call
  `setgroups` → `setgid` → `setuid`, and verify that `setuid(0)` now fails.
- **Network namespace** (`netns`, `--netns`). Join it first, in both modes:
  on the main thread while it is the only thread, before any socket is
  opened and before the privilege drop, as `setns(2)` acts on the calling
  thread and needs `CAP_SYS_ADMIN`. Check for the capability first, verify
  the join from `/proc/thread-self/ns/net`, and drop `CAP_SYS_ADMIN` right
  after it, root or not. Any failure stops the start.

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

**Profiling** (`docs/PROFILING.md`).
- Every hook is a `#[cfg(feature = "profiling")]` statement that only
  observes: it never changes a result, a protocol decision or the default
  build. Counters and histograms are relaxed atomics in `bgpfc-prof`.
- Profiling builds read the clock in `wire` and `rib` for histograms only;
  the FSM is not instrumented and stays clock-free.
- Report lines go to stderr as `msg="profile"` log lines whatever the log
  level, and to `bgpfcctl stats`; never over HTTP or the network.

**Logging.**
- `bgpfc-log` writes one line per event to stderr, in this format:
  `2026-10-03T12:34:56.789Z INFO  msg="session established" peer=198.51.100.1 hold=90`.
  `msg` comes first and is always quoted; fields follow in call order and
  are quoted only when they contain whitespace, `"`, `\` or `=`.
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
  session parameters changed. Policy-only changes are applied on the RIB
  thread without a reset: a changed export policy to the Loc-RIB, and a
  changed import policy to the routes the Adj-RIBs-In kept, held ones
  included (RFC 4271 §3 (a), `Rib::reimport`). The RIB does not keep the
  routes an import policy rejected whatever their validation state, so
  that `maximum-prefix` bounds a filtered peer's memory. For a changed
  import policy it therefore sends a route refresh (RFC 2918), where the
  peer supports it, for each family in which import policy dropped a
  route since the session came up or the family was last asked for. A
  route refresh names only the family (RFC 2918 §3), so the peer sends
  all of it again: under an import policy that rejects any route at all,
  every change of it asks. An export change sends none.

**Policy (v1).**
- Per-neighbor `import` and `export` policies are ordered lists of terms.
  Each term has match clauses and then actions. A term ends with `accept`,
  `reject`, or `next`. If no term decides, the route is rejected.
- Match clauses: `prefix`, `prefix-list` (with `ge`/`le`), `as-path` regex,
  `community`/`ext-community`/`large-community`, `origin`, `neighbor`, and
  `rpki` (the RFC 6811 validation state).
- Set actions: `local-pref`, `med`, add/remove/replace communities (all three
  kinds), `as-path prepend`, `next-hop self`, and, in import policies only,
  `rpki` (the validation state the route is used with, RFC 6811 §3).
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
- **RTR transport (RFC 8210 §9).** RTR runs over plain TCP, the one
  transport §9 makes mandatory to implement. The protected transports §9
  lists (SSH, TLS, TCP-MD5, TCP-AO, IPsec) are out of scope. §9 requires a
  router and a cache on unprotected TCP to share a trusted, controlled
  network, so operators keep the cache on loopback or a trusted network.
  `docs/config.md` says so next to the `rpki` block. Every connection has
  TCP keep-alive on (§9: routers "SHOULD enable keep-alives when
  available"), with the `rpki` block's `tcp-keepalive` times. `bgpfc-rtr`
  must not depend on `bgpfc-sys` (§2), so `bgpfcd` sets it through the
  client's per-connection hook, `client::Config::check`, which runs on
  each new connection before its first PDU, and again on the connection
  in use (`Client::check_again`) when a reload changes the times.

## 5. Testing and verification

**Every change ships with tests.** The level of testing depends on the layer:

| Layer | Required |
|---|---|
| `bgpfc-wire` | Unit tests with byte vectors copied from the RFCs and from real captures. `proptest` round-trips (`decode(encode(x)) == x`, and `encode(decode(b)) == b` for canonical inputs). A fuzz target per top-level decoder. Miri. |
| `bgpfc-fsm` | Table-driven tests covering every (state, event) pair in RFC 4271 §8.2.2, with injected time. |
| `bgpfc-rib` | Decision-process tests per step of route selection, the validation step of `prefer-valid` included (§9.1.2.2), and a proptest of route selection against a model of §9.1.2.2's elimination. Tests that hold and release routes per `enforcement` mode and per state import policy sets. Proptest invariants: Loc-RIB is a function of the Adj-RIBs-In, policy and the `enforcement`, and is independent of arrival order; after a change of import policy applied from the Adj-RIBs-In, with the route refresh it asks for answered, it equals a RIB built under the new policy. Next-hop resolution against a kernel table: held and released routes, longest match and lowest metric, never through a default route or our own, the hop installed, the RPKI holds first; proptests that the lookup matches a linear scan, that the next-hop index is exactly the routes' next hops, and that the Loc-RIB is a function of the kernel table too. |
| `bgpfc-policy` | Regex engine tests, including pathological-pattern step-limit tests. A fuzz target. |
| `bgpfc-config` | Golden tests: input file → AST/debug output, and input file → error message snapshot. A fuzz target. |
| `bgpfc-fib` | Netlink encode/decode tests against byte captures from `ip -d monitor` or strace. Miri on the pure parts. A reconcile-logic proptest. |
| `bgpfc-sys` | Layout assertions. Real-socket tests where no privileges are needed. Mark tests that need privileges `#[ignore]`, and document how to run them. |
| `bgpfc-rpki` | Validation vectors from RFC 6811 §2 (the Route Origin ASN for each kind of final segment; Covered and Matched), the RFC 6483 §2 outcome table and §4 AS 0 ROAs, and the RFC 9319 §3 maxLength examples, covering NotFound, Valid, and Invalid by origin AS and by prefix length in both families. VRP bounds from RFC 8210 §5.1, §5.6 and §5.7. Proptests that check validation against the RFC 6811 §2.1 pseudo-code run over a plain list, VRP insert and remove against a set model, and that validating again only the routes `AffectedPrefixes` names, a merged backlog of changes included, gives the states validating every route gives. Miri, since the RTR decoder fills its VRP set. No fuzz target: the crate decodes no bytes. |
| `bgpfc-rtr` | Unit tests with PDU byte vectors laid out as in the figures of RFC 8210 §5 and RFC 6810 §5, and from a capture of a real version 0 session. `proptest` round-trips of the codec, and framer properties: the same PDUs, and the same error, however the stream is cut. Fuzz targets for the PDU decoder and framer and for the client session. Miri. Table-driven session tests with injected time: every PDU type and every transport and timer event in every state, then the RFC 8210 §8 sequences, the §7 version fallback, the §6 timers and stale data. A proptest of the session against a simulated cache that updates, restarts, goes away and runs out of data: every commit is a whole set the cache held, and the session ends in sync with it. Client tests against an in-process cache served from a std `TcpListener`. |
| `bgpfc-sidecar` | Supervisor state-machine tests with injected time (start, exit, restart backoff, shutdown). Process tests against stub executables that exit, hang, or ignore `SIGTERM`, never against a real Routinator. |
| `interop/` | Scenarios against BIRD, FRR, and GoBGP: session up, prefixes exchanged both ways, withdraw, route refresh, NOTIFICATION on bad input, 4-octet ASN with a 2-octet peer. A reload that changes import policy imports the kept routes again with no ROUTE-REFRESH, one that changes only export policy sends none, and the next import change, after import policy dropped a route, asks for that family alone, whole; the FIB reports what it did in `fib: changes` lines and, at debug, a line per route, never naming a route import policy rejected. Route origin validation with VRPs over RTR from StayRTR, an independent cache: each state of BIRD's routes, a VRP change that moves them without an UPDATE, a cache that goes away, restarts, fails over and comes back, or never answers, a reload, and `mode disabled`; TCP keep-alive on bgpfcd's connection to the cache, and a reload of `tcp-keepalive` that sets it on that connection with no new one; `startup hold` holding every route, through a reload to `accept` and back, until a late cache's first full set, then releasing all but the Invalid ones. What acts on the state: Invalid routes held by the default `drop-invalid` and kept from the kernel and a relay, ROAs created, changed and deleted moving installed routes with the per-route log lines and `show rpki transitions`, `prefer-valid` against a higher LOCAL_PREF, a reload of the `enforcement` that leaves the RTR client alone, `enforcement off`, and import policy that matches and sets the state; a stub cache of the crate's own stands in where StayRTR cannot. The Routinator sidecar, with `bgpfcd --user nobody` and a fake Routinator, a script that answers `--version`, records its arguments and `exec`s the stub cache: the arguments derived from the block, Routinator started after the privilege drop with no capabilities, RTR on loopback only, a server of another user on its port refused, a version mismatch, a missing binary and root without `--user` stopping the start, the stop order at `SIGTERM`, no restart when Routinator is signalled with bgpfcd, and no orphan after `SIGKILL` (Routinator's own child, which the fake leaves as `rsync` would, gone with its process group at a stop or restart, and left to the service manager after a `SIGKILL` of bgpfcd), a killed Routinator restarted with the data held, one that keeps failing backing off and raising the alarm, one a reload could not start raising its alarm until a reload starts it, a cold start that converges without hanging, the import-policy hold until the first set, a reload walk across settings and modes, and the warning of a weaker owner check, once, before Routinator starts. And the real Routinator 0.15 at `/usr/bin/routinator`, with no network: a repository the harness signs with `openssl` and serves with `rsync` on loopback (`LocalRpki`), a block that sets every option bgpfcd derives an argument from, all of them taken, the version check, Routinator as `nobody` on a loopback port only, the client in sync over RTR version 1 with keep-alive on, BIRD's routes validated, and a stop that leaves no process. Multihop in a lab routed through a third namespace: an external neighbor two hops away down at TTL 1 with the log and `show neighbor` saying why, up with `multihop` and `local-address`, the directly connected session up with TTL 1; a route installed through the gateway that resolves its next hop, held, removed and withdrawn when that route goes and back when it returns, with one `rib: next hops changed` line; an internal session over loopbacks with the system's TTL. bgpfcd started from the host with `--netns` or `netns`: sessions, installed routes, the HTTP API, RTR and the sidecar in the namespace, `CAP_SYS_ADMIN` gone after the join, and `--check` and a start without the capability refused. Uses network namespaces and needs root, so it runs in CI and on demand. |
| benches | `criterion` benches for UPDATE decode, RIB insert/withdraw at full-table scale (~1M IPv4 + ~250k IPv6), and policy evaluation; std-only micro-benchmarks in `bgpfc-bench`. Do not regress them without saying so in the PR. |
| `bgpfc-prof`, `bgpfc-bench`, profiling | Histogram bucket and percentile math; allocator arithmetic on a private instance, under Miri; UPDATE packing against the size limit and round-tripped through the daemon's decoder; MRT parsing from hand-built records; the ignored loadgen-to-daemon test (`cargo test -p bgpfcd --features profiling -- --ignored`). `bgp_bench` keeps the time and memory history (`docs/PROFILING.md`); quote it when a change claims to be faster or smaller. |

Miri cannot run FFI. Put real syscalls behind
`#[cfg(not(miri))]` and keep the encode/decode logic separate so Miri can cover
it. Besides the crates with `unsafe` or a byte decoder of their own,
`scripts/miri.sh` runs `bgpfc-rpki`, whose VRP set the RTR decoder fills.

### Gates: all must pass before every commit

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --workspace --all-targets --features profiling -- -D warnings
cargo test --workspace
cargo test --workspace --features profiling
scripts/check-deps.sh                                   # std-only enforcement
cargo +nightly miri test -p bgpfc-wire -p bgpfc-sys -p bgpfc-fib \
  -p bgpfc-rpki -p bgpfc-rtr --features bgpfc-sys/profiling   # via scripts/miri.sh
```

`scripts/check.sh` runs all seven. If a gate fails, fix the cause. Never
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

Steps 0–9 are complete: they built v1. Their text stays as a record of what
v1 covers. Steps 10 to 15 are complete as well, and their text stays as a
record of what they added; step 11 also did the part of step 13 that
re-evaluates only the prefixes a VRP delta affects (RFC 6811 §4), and step
12 the part that adds the `rpki` config, external caches or disabled. So
are the post-14 follow-ups listed after step 14, which came before step 15.
There is no step after 15: ask the maintainer what comes next.

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
10. **v1 gaps (branch `m10-v1-gaps`).**
    - MRAI pacing (issue #66).
    - RFC 8950 extended next hop.
    - The RFC 4271 §6.7 prefix limit and the RFC 4486 §4 retry bound.
    - RFC 4271 §6.3 NEXT_HOP semantic checks.
    - The RFC 4760 §7 and §5.1 rows in COMPLIANCE.md.
11. **Validation source (new crate `bgpfc-rpki`, issues #52, #56).**
    - A `RovState`, plus an `AspaState` placeholder, on every route.
    - The `ValidationSource` trait, with a null source.
    - A re-evaluation command on the RIB thread's channel.
12. **RTR client (new crate `bgpfc-rtr`, issues #57, #58).**
    - RFC 8210 version 1, falling back to version 0 (RFC 6810) as RFC 8210
      §7 allows.
    - Reconnect with backoff.
    - A stale-data policy for VRPs from a cache that has gone away
      (RFC 8210 §6, Expire Interval).
13. **ROV (issues #59–#61).**
    - RFC 6811 in the decision process, and a policy match on validation
      state (RFC 6811 §3).
    - Drop Invalid by default, with a non-enforcing prefer-valid mode.
    - Re-evaluate only the prefixes a VRP delta affects (RFC 6811 §4).
    - `rpki` config: external caches, or disabled.
14. **Routinator sidecar (new crate `bgpfc-sidecar`, issues #70–#72).**
    - A Routinator child supervised through `std::process::Command`.
      Routinator is an external executable; bgpfc neither bundles nor links
      it.
    - `PR_SET_PDEATHSIG` through `bgpfc-sys`. Setting it takes an `unsafe`
      `pre_exec` hook, so `bgpfc-sys` owns the hook behind a safe wrapper
      (§1.3). The signal fires when the spawning *thread* exits, so spawn
      from a thread that lives as long as the daemon.
    - Localhost RTR auto-wiring.
    - A unified config surface for external caches and the sidecar.

**Post-14 follow-ups** (branch `followups-r1`, one PR): the maintainer's
decisions after reviewing step 14, and the answers that followed.
- RTR TCP keep-alive on every connection (RFC 8210 §9), set from `bgpfcd`
  through the client's per-connection hook (§4, "RTR transport"), with
  `tcp-keepalive idle|interval|count` in the `rpki` block (60, 10, 6 by
  default; the kernel's bounds), applied at a reload to the connection in
  use.
- The FIB thread's log folded: a `fib: changes` line at info at most once a
  second, counts by operation, sample prefixes and dry-run or install;
  each route at debug, and at most three failure lines a change, and
  three between two `fib: changes` lines, at error.
- The sidecar's owner check is `partial` in COMPLIANCE.md (RFC 8210 §9,
  §13), as it tells users apart and nothing finer; bgpfcd warns, and starts
  all the same, when it runs as `nobody`, as the overflow user or in a user
  namespace.
- `rpki { startup accept | hold; }`: `hold` holds every route until the
  first full set (RFC 6811 §2, "unless explicitly configured").
- A changed import policy imports the routes the RIB kept again at once
  (RFC 4271 §3 (a)). The routes it rejected whatever their state are not
  kept, so a route refresh, which has the peer send the whole family
  again, still goes out for each family where import policy dropped one
  since the session came up or the family was last asked for (§3 (b));
  an export change sends none.
- Routinator 0.15.3 as the tested release, and an interop scenario that
  runs the real one, offline, which CI installs from NLnet Labs' packages.

15. **Multihop and network namespaces (branch `m15-multihop`).**
    - TTL 1 for eBGP unless `multihop`, the system TTL for iBGP, and
      `local-address`, through a socket builder in `bgpfc-sys`.
    - Next-hop resolution from the kernel's main table over rtnetlink
      (RFC 4271 §9.1.2, §9.1.2.1): a kernel thread follows it, the RIB
      resolves and indexes next hop → destinations, routes with an
      unresolvable next hop are held; install via the immediate gateway
      and interface; `show nexthops`.
    - `netns` / `--netns`: bgpfcd joins a network namespace itself.
    - Later, as the owner decided: GTSM (RFC 5082), the RFC 4271 §6.3 b
      subnet check, an interior cost from the kernel's metrics, and an FRR
      best-path corpus.

**Out of scope until the maintainer says otherwise:** ASPA (planned for
v1.1.0), BGPsec (RFC 8205), the protected RTR transports (RFC 8210 §9; see
§4), BGP roles (9234), RFC 8212, graceful restart, ADD-PATH, route
reflection, confederations, ECMP, VPN families, TCP-MD5/AO, and non-Linux
platforms. Do not add hooks or abstractions "for later"; the `AspaState`
placeholder in step 11 is the one exception the maintainer asked for. Build
cleanly, and refactor when a feature actually lands.

## 10. When unsure

- Read the RFC section before writing the code. RESOURCES.md links them, and
  `resources/` has offline copies of some.
- If a requirement conflicts with this file, stop and ask.
- If you notice something wrong in this file, fix it in its own
  `docs(agents): ...` commit.
