# bgpfc

A BGP-4 routing daemon for Linux, written in Rust using **only the standard library**.

bgpfc speaks BGP to its neighbors, runs the RFC 4271 decision process, applies
per-neighbor import/export policy, and installs best paths into the Linux kernel
routing table over rtnetlink. It also ships with `bgpfcctl`, a command-line
client, and a small localhost HTTP/JSON API for inspecting the running daemon.

> **Status:** rewrite in progress on the `rewrite` branch. Nothing here is usable
> yet. It is not production-ready, and it is not claimed to comply with any RFC
> until [`COMPLIANCE.md`](COMPLIANCE.md) says so.

## Why std-only?

The daemon and every library crate it is built from depend on nothing but `std`.
There is no `libc`, `serde`, `tokio`, `nix`, or `regex`. The few operating-system
calls that std does not expose (netlink sockets, `setsockopt` options,
privilege changes) are declared by hand in a single, audited `bgpfc-sys` crate.

This keeps the trusted code base small and auditable, and every byte on the wire
is produced by code in this repository.

Test, fuzzing, benchmark, and interop tooling (`proptest`, `cargo-fuzz`,
`criterion`, and real BIRD, FRR, and GoBGP daemons) are allowed, but only as
dev-dependencies or in separate crates that the daemon never links against.

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

### Later

RPKI (RFC 8210, 6811, 8893), BGP roles and OTC (RFC 9234), RFC 8212 default
policy, graceful restart (RFC 4724), ADD-PATH (RFC 7911), route reflection
(RFC 4456), multipath, and TCP-MD5/TCP-AO.

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
  bgpfcd         daemon binary
  bgpfcctl       CLI binary
fuzz/            cargo-fuzz targets (excluded from the workspace)
interop/         tests against BIRD / FRR / GoBGP (dev-only)
```

## Build

You need Rust stable (the version is pinned in `rust-toolchain.toml`, 2024 edition).

```sh
cargo build --release
```

The binaries are written to `target/release/bgpfcd` and `target/release/bgpfcctl`.

## Configure

bgpfc uses its own block-style configuration language, similar to BIRD's and
OpenBGPD's. The example below is a sketch. Once it exists,
[`docs/config.md`](docs/config.md) is the authoritative grammar.

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
be overridden at startup with `bgpfcd --fib=dry-run|install` and changed at
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
not need it.

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
