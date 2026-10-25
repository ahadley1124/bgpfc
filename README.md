# bgpfc

A BGP-4 routing daemon for Linux, written in Rust using **only the standard library**.

bgpfc speaks BGP to its neighbors, runs the RFC 4271 decision process, applies
per-neighbor import/export policy, and installs best paths into the Linux kernel
routing table over rtnetlink. It also ships with `bgpfcctl`, a command-line
client, and a small localhost HTTP/JSON API for inspecting the running daemon.

> **Status:** v1 feature-complete and exercised against BIRD, FRR and GoBGP in
> CI, but young: it has not run in production anywhere.
> [`COMPLIANCE.md`](COMPLIANCE.md) tracks every MUST, SHOULD and MAY. Every MUST
> row is `done` for RFC 4760, 8950, 5492, 6793, 2918, 7606, 8654, 1997, 4360,
> 8092, 4486, 6608, 9003, 7607, 9072, 9687, 9774 and 7911. RFC 4271 has five rows
> open. Two need the host's interfaces and routes, which bgpfc does not track,
> so the kernel's verdict is logged instead: next-hop resolvability (§9.1.2),
> and a next hop on a shared subnet for one-hop EBGP (§6.3 b). One is partial:
> a received next hop is checked against our own address on that session, not
> against every address of the host (§6.3 a). Two are deliberate deviations: a
> NOTIFICATION received in OpenSent closes the connection without an FSM error
> in reply, as BIRD and FRR do (§8.2.2), and the MinRouteAdvertisementInterval
> timer paces announcements but never holds back a withdrawal (§9.2.1.1). RFC
> 2545 has one partial row for the same lack of interfaces: bgpfc never sends a
> link-local next hop, which §3 asks for where it shares a subnet with the next
> hop and the peer. Nothing else is claimed.

### What works

- Sessions with 2- and 4-octet AS peers over IPv4 and IPv6, with route refresh,
  extended messages, send hold timer, collision detection, RFC 8950 IPv6 next
  hops for IPv4 routes (per neighbor, `extended-next-hop yes`) and RFC 7606
  error handling, with the RFC 4271 §6.3 next-hop checks; interop tests against
  BIRD 2, FRR 8 and GoBGP 3 run on every push.
- Per-neighbor, per-family prefix limits (`maximum-prefix`, RFC 4271 §6.7) that
  end the session with the RFC 4486 Cease, and damped automatic restarts with
  an upper bound (`restart-limit`, RFC 4486 §4) after which a failing neighbor
  waits for `bgpfcctl clear neighbor`.
- The RFC 4271 decision process over interned attribute sets, per-neighbor
  import/export policy with prefix lists, an AS-path regex engine and community
  matching, and update generation packed to the negotiated message size and
  paced per destination by the RFC 4271 MinRouteAdvertisementInterval timer.
- Routes installed through rtnetlink under a dedicated protocol number, with
  dry-run as the default and a runtime toggle; privilege drop and a capability
  check; clean shutdown on `SIGTERM`.
- `bgpfcctl` over a Unix socket and a loopback HTTP/JSON API, including reload
  with a configuration diff ([`docs/control.md`](docs/control.md)).
- ADD-PATH (RFC 7911), per neighbor and family, off unless configured:
  `add-path receive FAMILY yes` keeps every path a neighbor sends for a prefix
  under its Path Identifier and runs the decision process over all of them,
  and `add-path send FAMILY N` or `all` sends a neighbor the N best paths of
  each prefix, or every path export policy accepts, each under an identifier
  of bgpfcd's own that stays with it while it is sent. The kernel still gets
  the one best path. `bgpfcctl show routes PREFIX` and the HTTP API show the
  identifier a path came with. Sessions that do not use it pay nothing for it.
  Interop tests run it in both directions against BIRD and FRR.
- An RFC 6811 origin validation state on every route, from VRPs fetched over
  RTR (RFC 8210, falling back to RFC 6810) from the caches of an `rpki` block,
  with failover in order of preference; `bgpfcctl show rpki` reports the
  client, and interop tests run it against StayRTR. Nothing acts on the
  state yet.

Rough figures from the criterion benches on one core (`cargo bench`): UPDATE
decode about 0.3 µs for one prefix and 4.4 µs for 500; RIB insert about 1 µs
per route and withdraw on peer loss about 0.6 µs per route (100k routes);
policy evaluation through six terms about 0.8 µs per route.

## Why std-only?

The daemon and every library crate it is built from depend on nothing but `std`.
There is no `libc`, `serde`, `tokio`, `nix`, or `regex`. The few operating-system
calls that std does not expose (netlink sockets, `setsockopt` options,
privilege changes) are declared by hand in a single, audited `bgpfc-sys` crate.

This keeps the trusted code base small and auditable, and every byte on the wire
is produced by code in this repository.

Test, fuzzing, benchmark, and interop tooling (`proptest`, `cargo-fuzz`,
`criterion`, and real BIRD, FRR, GoBGP, and StayRTR daemons) are allowed, but
only as dev-dependencies or in separate crates that the daemon never links
against.

## Scope

### Milestone 1 (v1)

| Area | RFCs |
|---|---|
| Core protocol, FSM, decision process | 4271, 6608, 7607, 9072, 9687, 9774, 4486, 9003 |
| 4-octet AS numbers | 6793 |
| Multiprotocol / IPv6 | 4760, 2545, 8950 |
| Capabilities, route refresh | 5492, 2918 |
| Error handling, large messages | 7606, 8654 |
| Communities | 1997, 4360, 8092 |
| Policy | Prefix lists, AS-path regex, community matching; set local-pref, MED, and communities, and prepend AS path |
| Kernel FIB | rtnetlink, a dedicated route protocol number, main table, dry-run toggle |
| Control | `bgpfcctl` over a Unix socket, plus a read-only-by-default HTTP/JSON API on localhost |

Only a single best path goes to the kernel, with no ECMP, also on sessions
that exchange several paths (ADD-PATH, RFC 7911, added after v1). Linux only.

### Next: RPKI route origin validation

In progress ([`AGENTS.md`](AGENTS.md) §9, steps 11 to 14). Every route
carries its RFC 6811 origin validation state (step 11), which the RIB
validates again in place when the VRPs change, and which `bgpfcctl show
routes` and the HTTP API show. With an `rpki { mode external; ... }` block
the states are real (step 12): each route reads `valid`, `invalid` or
`not-found` against the VRPs bgpfcd fetches over RTR, RFC 8210 falling back
to version 0 (RFC 6810), from the block's external caches, with failover in
order of preference, a reconnect back-off, and the last VRPs kept while no
cache answers, until they expire. Without the block, or with `mode
disabled`, every route reads `disabled`. RTR runs over plain TCP only (RFC
8210 §9), so the cache belongs on loopback or a trusted network.

Enforcement comes next. Nothing acts on the state yet; step 13 will drop
Invalid routes by default, offer a non-enforcing prefer-valid mode, and let
policy match on the validation state (RFC 6811 §3). Then bgpfcd will be
able to start and supervise an optional Routinator as a child process.
Routinator is a separate program; bgpfc neither bundles nor links it.

### Later

ASPA (planned for v1.1.0), origin validation on export (RFC 8893), BGP roles
and OTC (RFC 9234), RFC 8212 default policy, graceful restart (RFC 4724),
route reflection (RFC 4456), multipath, and TCP-MD5/TCP-AO.

The full reference list is in [`RESOURCES.md`](RESOURCES.md).

## Layout

```
crates/
  bgpfc-wire     message and attribute codec (no I/O)
  bgpfc-fsm      RFC 4271 §8 session state machine (pure, time injected)
  bgpfc-rib      Adj-RIB-In / Loc-RIB / Adj-RIB-Out, decision process
  bgpfc-policy   prefix lists, AS-path regex engine, match/set actions
  bgpfc-config   config DSL lexer, parser, validation
  bgpfc-fib      rtnetlink message encoding + FIB sync logic
  bgpfc-sys      the ONLY crate with `unsafe`: hand-written extern "C" decls
  bgpfc-log      leveled stderr logger
  bgpfc-control  Unix-socket protocol, HTTP/1.1 server, JSON writer
  bgpfc-rpki     VRP set, RFC 6811 origin validation, validation sources (no I/O)
  bgpfc-rtr      RTR (RFC 8210/6810): PDU codec, session machine, client thread
  bgpfc-prof     profiling counters and histograms (only with --features profiling)
  bgpfc-bench    load generator, benchmark harness, micro-benchmarks (dev tooling)
  bgpfcd         daemon binary
  bgpfcctl       CLI binary
fuzz/            cargo-fuzz targets (excluded from the workspace)
interop/         tests against BIRD / FRR / GoBGP and the StayRTR cache (dev-only)
```

## Build

You need Rust stable (the version is pinned in `rust-toolchain.toml`, 2024 edition).

```sh
cargo build --release
```

The binaries are written to `target/release/bgpfcd` and `target/release/bgpfcctl`.

For time and memory measurements, `cargo build --profile profiling --features
profiling` adds counters, latency histograms and a counting allocator, plus a
load generator and a benchmark harness that records results in
`bench/results.csv`. [`docs/PROFILING.md`](docs/PROFILING.md) describes them;
the default build contains none of it.

## Configure

bgpfc uses its own block-style configuration language, similar to BIRD's and
OpenBGPD's. [`docs/config.md`](docs/config.md) is the authoritative grammar;
[`contrib/bgpfc.conf`](contrib/bgpfc.conf) is the example below as a file.
`bgpfcd -c FILE --check` validates a file without starting anything.

```
router-id 192.0.2.1;
local-as 65000;

log { level info; }

listen { address ::; port 179; }

fib {
    mode dry-run;        # dry-run | install
    table main;
    protocol 186;        # rtnetlink route protocol bgpfc owns
}

control {
    socket /run/bgpfc/bgpfc.sock;
    http {
        listen 127.0.0.1:8179;
        writes no;       # reload/clear via HTTP are disabled by default
        # token-file /etc/bgpfc/api-token;
    }
}

prefix-list BOGONS {
    10.0.0.0/8 le 32;
    192.168.0.0/16 le 32;
}

policy UPSTREAM-IN {
    term no-bogons { match prefix-list BOGONS; action reject; }
    term rest      { set local-pref 100; action accept; }
}

policy UPSTREAM-OUT {
    term own { match prefix 203.0.113.0/24; action accept; }
    term rest { action reject; }
}

neighbor 198.51.100.1 {
    remote-as 64511;
    description "transit";
    hold-time 90;
    families ipv4-unicast ipv6-unicast;
    import UPSTREAM-IN;
    export UPSTREAM-OUT;
}
```

Every neighbor must name both an `import` and an `export` policy. A config
without them is rejected.

### FIB dry-run

In `fib { mode dry-run; }`, bgpfc computes every kernel route change and logs it,
but never writes to the kernel. `mode install` applies the changes. The mode can
be overridden at startup with `bgpfcd --fib dry-run|install` and changed at
runtime with `bgpfcctl fib mode <dry-run|install>`. **Dry-run is the default.**

In install mode, bgpfc only touches routes tagged with its own protocol number.
At startup it flushes stale routes left by a previous run, and it never modifies
routes it did not create.

## Run

bgpfcd needs two privileges:

- `CAP_NET_BIND_SERVICE` to listen on TCP port 179.
- `CAP_NET_ADMIN` to change the kernel routing table. Dry-run mode does not
  need this.

It never needs full root. There are two supported ways to run it.

### Option A (recommended): unprivileged user with capabilities

**Under systemd** (`contrib/bgpfcd.service`):

```ini
[Service]
User=bgpfc
Group=bgpfc
ExecStart=/usr/local/bin/bgpfcd -c /etc/bgpfc/bgpfc.conf
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
NoNewPrivileges=yes
RuntimeDirectory=bgpfc
```

**Manual run.** Pick one of these:

```sh
# 1. File capabilities on the binary. Re-apply after every rebuild.
sudo setcap 'cap_net_bind_service,cap_net_admin=+ep' target/release/bgpfcd
./target/release/bgpfcd -c bgpfc.conf

# 2. Grant ambient capabilities for a single run only, without touching the binary.
sudo setpriv --reuid="$(id -u)" --regid="$(id -g)" --init-groups \
     --inh-caps=+net_bind_service,+net_admin \
     --ambient-caps=+net_bind_service,+net_admin \
     ./target/release/bgpfcd -c bgpfc.conf
```

For development without any privileges, use `listen { port 1179; }` together
with `fib { mode dry-run; }`.

At startup, bgpfcd reads its effective capabilities from `/proc/self/status`. It
reports any capability that is missing and exits, unless the configuration does
not need it. `contrib/bgpfcd.service` is a complete unit with the capabilities
and hardening settings.

### Option B: start as root, drop privileges

```sh
sudo ./target/release/bgpfcd -c bgpfc.conf --user bgpfc --group bgpfc
```

As root, bgpfcd binds port 179 and opens its rtnetlink socket. It then calls
`setgroups`, `setgid`, and `setuid` to switch to the given user, and confirms
that it cannot regain root.

The already-open sockets keep working, because Linux checks netlink permissions
against the credentials of whoever opened the socket. The trade-off is that a
reload cannot open new listen sockets or a new netlink socket. Changes like that
need a restart.

## Operate

```sh
bgpfcctl show neighbors
bgpfcctl show neighbor 198.51.100.1
bgpfcctl show routes [ipv4|ipv6] [prefix]
bgpfcctl show fib
bgpfcctl clear neighbor 198.51.100.1 [soft]
bgpfcctl reload
bgpfcctl fib mode install
```

The HTTP API listens on `127.0.0.1` only and serves the same data as JSON, for
example `GET /v1/neighbors` or `GET /v1/routes?family=ipv6`. Write endpoints
(`POST /v1/reload`, `POST /v1/neighbors/{addr}/clear`) return `403` unless
`writes yes;` is set. If a `token-file` is configured, every request must send
`Authorization: Bearer <token>`. There is no TLS. If you need remote access,
put the API behind a reverse proxy.

## Contributing

Read [`AGENTS.md`](AGENTS.md). It applies to humans and AI agents alike.

## License

MIT. See [`LICENSE`](LICENSE).
