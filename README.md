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
> 8092, 4486, 6608, 9003, 7607, 9072, 9687, 9774 and 6811. RFC 4271 has five
> rows open. Next hops resolve in the kernel's routing table (§9.1.2), but
> one check is not made yet: that a one-hop EBGP neighbor's next hop is on a
> subnet shared with us (§6.3 b). One is partial: a received next hop is
> checked against our own address on that session, not against every address
> of the host (§6.3 a). Two are deliberate deviations: a NOTIFICATION received
> in OpenSent closes the connection without an FSM error in reply, as BIRD and
> FRR do (§8.2.2), and the MinRouteAdvertisementInterval timer paces
> announcements but never holds back a withdrawal (§9.2.1.1). The fifth
> applies only under `enforcement prefer-valid`: the validation state ranks
> routes before LOCAL_PREF, and that rank is not passed on to internal
> neighbors (§9.1.1). RFC 2545 has one partial row: bgpfc cannot tell when
> it shares a subnet with the next hop and the peer, so it never sends the
> link-local next hop §3 asks for there. RFC
> 8481, which clarifies RFC 6811, has one deliberate deviation: turning
> validation on with `mode external` or `mode sidecar` also holds Invalid
> routes back unless `enforcement` says otherwise, the project's chosen default
> (§5). Nothing else is claimed.

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
- Next hops resolved in the kernel's main routing table, which bgpfcd follows
  over rtnetlink (RFC 4271 §9.1.2): a route whose next hop does not resolve is
  held, neither installed nor advertised, until it does, and routes are
  installed through the gateway and interface that resolve their next hop.
  `bgpfcctl show nexthops` lists them.
- Neighbors more than one hop away, such as over loopback addresses: external
  sessions are sent with TTL 1 unless `multihop` says otherwise, as with BIRD
  and FRR, and `local-address` runs a session from an address of the host.
  bgpfcd also joins a network namespace by itself (`netns`, `--netns`).
- `bgpfcctl` over a Unix socket and a loopback HTTP/JSON API, including reload
  with a configuration diff ([`docs/control.md`](docs/control.md)); a changed
  import policy applies at once to the routes already received. Routes an
  import policy rejected are not kept, so when it has rejected any route of
  a family, the neighbor is also asked to send that whole family again with
  a route refresh.
- RPKI route origin validation (RFC 6811): a validation state on every
  route, from VRPs fetched over RTR (RFC 8210, falling back to RFC 6810) from
  the caches of an `rpki` block, with failover in order of preference, or
  from a Routinator that bgpfcd runs, supervises and wires to itself on
  loopback (`rpki { mode sidecar; }`). The
  block's `enforcement` acts on it: `drop-invalid`, the default, keeps Invalid
  routes out of route selection, the kernel and the neighbors, holding them to
  use again without an UPDATE once they are no longer Invalid; `prefer-valid`
  ranks Valid over NotFound over Invalid before LOCAL_PREF; `off` leaves the
  state to policy, which can match it (`match rpki`) and, on import, set the
  state a route is used with (`set rpki`). A VRP change moves only the routes
  it concerns, through the same path as an UPDATE; each route that changed
  state is logged, and `bgpfcctl show rpki transitions` keeps the latest.
  Interop tests run it against StayRTR and BIRD, and the sidecar against a
  stand-in for Routinator and against Routinator 0.15 itself, offline, on
  an RPKI repository the test signs and serves on loopback.

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

Only single best path, with no ECMP. Linux only.

### RPKI route origin validation

[`AGENTS.md`](AGENTS.md) §9 steps 11 to 14 are done. Every route carries
its RFC 6811 origin validation state (step 11), which the RIB validates
again in place when the VRPs change, and which `bgpfcctl show routes` and
the HTTP API show. With an `rpki { mode external; ... }` block the states
are real (step 12): each route reads `valid`, `invalid` or
`not-found` against the VRPs bgpfcd fetches over RTR, RFC 8210 falling back
to version 0 (RFC 6810), from the block's external caches, with failover in
order of preference, a reconnect back-off, and the last VRPs kept while no
cache answers, until they expire. Without the block, or with `mode
disabled`, every route reads `disabled`. RTR runs over plain TCP only (RFC
8210 §9), so the cache belongs on loopback or a trusted network. Every RTR
connection has TCP keep-alive on, as §9 asks of routers: by default a first
probe after a minute without traffic and one every 10 seconds after it, so
that a cache that vanished without closing the connection is noticed within
two minutes rather than at the next query, an hour on. `tcp-keepalive`
changes the times, and a reload applies them to the connection in use.

bgpfcd acts on the states (step 13) as the block's `enforcement` says
([`docs/config.md`](docs/config.md), "RPKI"): `drop-invalid`, the default,
holds Invalid routes in the Adj-RIB-In, neither installed nor advertised;
`prefer-valid` holds nothing but ranks Valid over NotFound over Invalid
before LOCAL_PREF; `off` leaves the states to policy. Import policy can
match the state and set the one a route is used with (RFC 6811 §3), for
example to fold it into LOCAL_PREF or to use a customer prefix whose ROA is
known to be wrong. A ROA created, changed or deleted moves installed and
advertised routes with no UPDATE, paced like any other change; `show
routes PREFIX` marks held routes, `show neighbor` counts them, and each
change of state is logged and kept for `show rpki transitions`.

bgpfcd can also run the validator itself (step 14). The one line
`rpki { mode sidecar; }` starts Routinator, NLnet Labs' RPKI relying-party
software, as a child process, with its command line derived from the
block (TALs, the ARIN agreement, refresh, cache directory, binary, and
extra arguments or a Routinator config file as an escape hatch). bgpfcd
checks Routinator's version at start: it is tested with 0.15.3, accepts
any 0.15.x and refuses other releases with an error. Routinator serves
RTR on a loopback port bgpfcd picks, and the RTR client connects to it
with nothing else configured. bgpfcd restarts it with a back-off when it
fails, keeping the last VRPs in use meanwhile, raises an alarm in `show
rpki` and `show status` when it keeps failing, and stops it when bgpfcd
stops; a bgpfcd that is killed takes Routinator along, though not an
`rsync` Routinator runs, which systemd's `KillMode=mixed` ends instead
([`docs/config.md`](docs/config.md), "Routinator sidecar"). Routinator is
a separate program that bgpfc neither bundles nor links; see "Routinator
sidecar" under "Run". Its first validation run takes minutes from a cold
cache, and bgpfcd does not wait for it: routes are used unvalidated until
the first full set, then validated and acted on, and the wait is logged
and shown ([`docs/config.md`](docs/config.md), "Startup window").
`rpki { startup hold; }` holds every route until that set instead, in
either mode, and `show rpki` and the log say that the routes are held. An external validator
(`mode external`) and no validation (`mode disabled`, or no `rpki` block)
work as before, without Routinator on the host.

### Multihop, next hops and network namespaces

[`AGENTS.md`](AGENTS.md) §9 step 15 is done. External neighbors are sent
TTL 1, and `multihop` raises it for neighbors further away, as BIRD and FRR
do; `local-address` binds a session to an address of the host, typically a
loopback, and a connection the neighbor opens to another address is
refused. Next hops resolve in the kernel's main routing table, through
connected, static and IGP routes but never through a default route or
bgpfcd's own: a route whose next hop does not resolve is held, and comes
back with no UPDATE when it resolves, and routes are installed through the
immediate gateway and interface. `netns` or `--netns` names the network
namespace bgpfcd joins at startup ("Network namespace" under "Run").
Checking the TTL of what neighbors send (GTSM, RFC 5082), the RFC 4271
§6.3 b subnet check and an interior cost from the kernel's metrics come
later.

### Later

ASPA (planned for v1.1.0), origin validation on export (RFC 8893), BGP roles
and OTC (RFC 9234), RFC 8212 default policy, graceful restart (RFC 4724),
ADD-PATH (RFC 7911), route reflection (RFC 4456), multipath, and
TCP-MD5/TCP-AO.

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
  bgpfc-sidecar  Routinator as a supervised child process (restart back-off, stop)
  bgpfc-prof     profiling counters and histograms (only with --features profiling)
  bgpfc-bench    load generator, benchmark harness, micro-benchmarks (dev tooling)
  bgpfcd         daemon binary
  bgpfcctl       CLI binary
fuzz/            cargo-fuzz targets (excluded from the workspace)
interop/         tests against BIRD / FRR / GoBGP, StayRTR, a fake and the real Routinator (dev-only)
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

# Route origin validation from an RPKI cache over RTR. RTR is plain TCP:
# keep the cache on this host or a trusted network (RFC 8210 §9).
# `mode external` also acts on the result as `enforcement` says:
# drop-invalid, the default, holds Invalid routes back (docs/config.md,
# "RPKI").
# rpki {
#     mode external;
#     enforcement drop-invalid;   # drop-invalid | prefer-valid | off
#     startup accept;             # accept | hold: routes until the first data
#     tcp-keepalive idle 60;      # idle, interval, count: 60, 10, 6 by default
#     cache 127.0.0.1 port 3323;
# }
#
# Or let bgpfcd run Routinator 0.15.x itself, serving RTR on loopback
# only and restarting it when it fails (README, "Routinator sidecar").
# Routes are used unvalidated until its first validation run ends,
# minutes from a cold start, unless `startup hold;` holds them; ARIN's
# TAL needs `sidecar { accept-arin-rpa yes; }`.
# rpki { mode sidecar; }

prefix-list BOGONS {
    10.0.0.0/8 le 32;
    192.168.0.0/16 le 32;
}

policy UPSTREAM-IN {
    term no-bogons { match prefix-list BOGONS; action reject; }
    # With the rpki block: Valid routes before the others (RFC 6811 §5;
    # docs/config.md, "Route selection").
    # term valid   { match rpki valid; set local-pref 110; action accept; }
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

# A neighbor two hops away, peered between loopback addresses. bgpfcd
# sends external neighbors TTL 1 unless `multihop` raises it, and runs
# the session from `local-address`, on which it listens through `::`
# above. Each end needs a route to the other's loopback, such as
# `ip route add 192.0.2.30/32 via GATEWAY`, and the neighbor's next hops
# must resolve in the kernel's main table (docs/config.md, "Neighbors"
# and "Next hops").
# neighbor 192.0.2.30 {
#     remote-as 64512;
#     multihop 2;                 # TTL 2; `multihop;` alone sends 255
#     local-address 192.0.2.1;    # this host's loopback address
#     import UPSTREAM-IN;
#     export UPSTREAM-OUT;
# }
```

Every neighbor must name both an `import` and an `export` policy. A config
without them is rejected.

### Neighbors more than one hop away

bgpfcd sends to an external neighbor with TTL 1, as BIRD and FRR do: a
neighbor that is not directly connected, such as one peered between
loopback addresses as in the commented example above, needs `multihop`
(TTL 255, or `multihop N;`), and usually `local-address`. Internal
neighbors keep the system's TTL. A route is used only if its next hop
resolves in the kernel's main routing table, through a connected, static or
IGP route, never through a default route or a route of bgpfcd's own, and it
is installed through the gateway and interface of the route that resolves
it ([`docs/config.md`](docs/config.md), "Next hops"). `bgpfcctl show
nexthops` shows what each next hop resolves to.

**Upgrading from an earlier bgpfcd**, which sent with the system's TTL and
used every route whatever its next hop:

- An external neighbor more than one hop away now needs `multihop`. Without
  it the session no longer comes up: the log says `connect failed` with
  `hint="external neighbor: more than one hop away needs multihop"`, and
  `bgpfcctl show neighbor` shows `ttl 1` and the `last error`.
- A route whose next hop the kernel's main table reaches only through a
  default route, or not at all, is now held (`next hop unresolvable` in
  `bgpfcctl show routes`): add a route to the next hop.

### FIB dry-run

In `fib { mode dry-run; }`, bgpfc computes every kernel route change and logs it,
but never writes to the kernel. `mode install` applies the changes. The mode can
be overridden at startup with `bgpfcd --fib dry-run|install` and changed at
runtime with `bgpfcctl fib mode <dry-run|install>`. **Dry-run is the default.**
In either mode the log has a line at info at most once a second while the
routing table changes, counting the routes installed and removed since the line
before and naming the first few, and a line per route at debug
(`docs/control.md`, "Validation state").

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

### Network namespace

To run bgpfcd in a network namespace, such as the one `ip netns add blue`
creates, name it with `netns blue;` in the configuration file or with
`bgpfcd --netns blue`, which overrides the file: `/run/netns/blue`. An
absolute path, such as `/proc/PID/ns/net`, names a namespace as well.
bgpfcd joins it itself at startup, before it opens a socket or starts a
thread, so its sessions, the routes it installs, the HTTP API, its RTR
connections and Routinator are all in the namespace, as if it had been
started with `ip netns exec blue`. `bgpfcctl` reaches the control socket
from any namespace.

Joining takes `CAP_SYS_ADMIN` (`setns(2)`), which bgpfcd gives up right
after the join. Root has it (Option B); under Option A it is a third
capability:

```sh
sudo setpriv --reuid="$(id -u)" --regid="$(id -g)" --init-groups \
     --inh-caps=+net_bind_service,+net_admin,+sys_admin \
     --ambient-caps=+net_bind_service,+net_admin,+sys_admin \
     ./target/release/bgpfcd -c bgpfc.conf --netns blue
```

Without it bgpfcd stops with `cannot join network namespace` and
`setns(2) needs CAP_SYS_ADMIN`. A bgpfcd started inside the namespace
already needs no capability for it. Under systemd,
`NetworkNamespacePath=/run/netns/blue` has systemd put bgpfcd there
instead, with no capability at all; `contrib/bgpfcd.service` shows both
ways. `bgpfcd --check --netns blue` checks that the namespace is there,
as any user. Unlike `ip netns exec`, bgpfcd does not put
`/etc/netns/blue/` over `/etc`: the host names of RPKI caches are looked
up with the host's `/etc/resolv.conf`, from inside the namespace, so give
caches by address or use a resolver the namespace reaches
(`docs/config.md`, "Network namespace").

### Routinator sidecar

With `rpki { mode sidecar; }` bgpfcd runs Routinator, tested with 0.15.3;
any 0.15.x is accepted, and another release stops the start with `cannot
start rpki` naming both versions.

- **Install** Routinator 0.15.x and `rsync`. NLnet Labs' packages put the
  binary at `/usr/bin/routinator`, the default `binary`; bgpfcd never
  searches `PATH` for it. Disable the package's own `routinator.service`:
  bgpfcd runs its own Routinator, on a port of its own, and two would
  fetch everything twice. To use a Routinator that runs anyway, point
  `mode external` at it instead (`cache 127.0.0.1 port 3323;`).
- **Privileges.** Routinator fetches and parses data from the internet,
  so it runs as the user bgpfcd runs as, with no capabilities. bgpfcd
  starts it only after it has opened its privileged sockets and dropped
  root: a child of root would get every capability whatever bgpfcd holds.
  Under Option A the unit's `User=bgpfc` applies, and bgpfcd clears its own
  ambient capabilities for the child; the unit's `StateDirectory=bgpfc`
  makes `/var/lib/bgpfc`, where the default `repository-dir`
  (`/var/lib/bgpfc/rpki`) lives, writable. Under Option B `--user` is
  required: as root without it, bgpfcd refuses `mode sidecar` (`mode
  sidecar would run Routinator as root`), and the repository directory
  must be writable by that user. bgpfcd creates it, mode 0750, if it is
  missing.
- **The RTR port** is on loopback only (`rtr-listen` refuses anything
  else, RFC 8210 §9). By default (port 0) bgpfcd picks a free one when it
  starts the sidecar and keeps it across Routinator's restarts. A port set
  explicitly must be 1024 or above, since Routinator holds no capability
  to bind a lower one. Until Routinator listens, after its first
  validation run, another local process could bind the port; bgpfcd's RTR
  client uses only a server that runs as bgpfcd's own user, as
  Routinator does, so give bgpfcd a user of its own (`bgpfc`, not
  `nobody`), and in a user namespace one the namespace maps: there every
  unmapped user, root included, reads as `nobody` (`docs/config.md`, "Who
  serves the sidecar's port"). bgpfcd warns at the start of the sidecar,
  and `bgpfcd --check` too, when it runs as `nobody`, as the overflow
  user, or in a user namespace, and starts all the same.
- **systemd**: `contrib/bgpfcd.service` has `KillMode=mixed`, so that
  `systemctl stop` signals bgpfcd alone, which stops its RTR client and
  then Routinator itself; with the default mode systemd would signal
  Routinator at the same moment, before the client lets go of it, and
  bgpfcd would log a failure it did not cause (it starts no Routinator
  again once it is stopping). `TimeoutStopSec=40` covers Routinator's
  `stop-timeout` and a version check that may be running, during the FIB
  cleanup.
- **Logs.** Routinator's standard error, where it writes its messages, is
  logged at warn in bgpfcd's log, each line with `sidecar=routinator
  stream=stderr`; its standard output at info.
- **The first validation run** takes minutes from a cold cache, less
  from a warm one, and Routinator serves RTR only after it. Routes are
  used unvalidated meanwhile, or held with `startup hold;`. `show rpki`
  says `validation waiting` meanwhile, and `sidecar running` with
  Routinator's pid; a Routinator that keeps failing shows as `sidecar
  FAILED` there and as an alarm in `show status` (`docs/control.md`,
  "Alarms").
- **A Routinator config file** (`config-file`) is passed on unread. It
  must not set `rtr-tls-listen`, `systemd-listen`, `user` or `group`, nor
  add TALs the block does not show (`docs/config.md`, "The Routinator
  sidecar", has the details).
- `bgpfcd --check` checks the block as Routinator would take it but does
  not run Routinator; the version is checked at start, and at a reload
  that starts Routinator, before anything changes.

## Operate

```sh
bgpfcctl show neighbors
bgpfcctl show neighbor 198.51.100.1
bgpfcctl show routes [ipv4|ipv6] [prefix] [held]
bgpfcctl show fib
bgpfcctl show nexthops
bgpfcctl show rpki
bgpfcctl show rpki transitions
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
