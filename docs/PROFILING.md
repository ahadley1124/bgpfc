# Profiling

`bgpfcd` can measure itself: how long the work on each UPDATE and route
takes, how much memory a route costs, and how often attributes repeat. A
load generator and a benchmark harness drive it reproducibly, so a change's
effect on time and memory shows up as a number in `bench/results.csv`.

Everything here is behind the Cargo feature `profiling`. A default build
has none of it: the crates depend on `bgpfc-prof` only through that
feature, every hook is `#[cfg(feature = "profiling")]`, there is no
counting allocator and no clock read, and `nm target/release/bgpfcd` shows
no `bgpfc_prof` or `Counting` symbol. Nothing changes what the daemon does;
the instrumentation only observes.

All of it is std only. External profilers (`perf`, `heaptrack`, `valgrind`)
are described below as recipes; none is needed.

## Build

```sh
# Optimised like release, with full debug info for perf and heaptrack.
cargo build --profile profiling --features profiling
```

This builds `target/profiling/bgpfcd` and `bgpfcctl` with the
instrumentation, and the tools of `crates/bgpfc-bench`: `bgp_loadgen` and
`bgp_bench`. Run the command at the workspace root: `bgpfc-bench` has no
`profiling` feature of its own, so `-p bgpfc-bench --features profiling`
alone is refused. `cargo build --features profiling` gives a debug build of
the same.

The default build stays as it was:

```sh
cargo build --release
```

## Run

`contrib/bgpfc-bench.conf` needs no privileges: it listens on
127.0.0.1:11179, keeps the FIB in dry-run, and has two neighbors, a passive
127.0.0.1 for a load generator that connects and an active 127.0.0.2:11180
for one that listens.

```sh
./target/profiling/bgpfcd -c contrib/bgpfc-bench.conf
```

In a second terminal, one of the scenarios:

```sh
# load: a synthetic 1M-prefix table, End-of-RIB, then hold the session.
./target/profiling/bgp_loadgen --connect 127.0.0.1:11179

# churn: after the load, 1000 random changes a second for 10 seconds.
./target/profiling/bgp_loadgen --connect 127.0.0.1:11179 --scenario churn --rate 1000 --duration 10

# withdraw-all: after the load, withdraw every route.
./target/profiling/bgp_loadgen --connect 127.0.0.1:11179 --scenario withdraw-all

# flap: after the load, Cease, wait, reconnect and resend, three times.
./target/profiling/bgp_loadgen --connect 127.0.0.1:11179 --scenario flap --cycles 3 --gap 1

# the other way round: bgpfcd connects to the load generator.
./target/profiling/bgp_loadgen --listen 127.0.0.2:11180
```

To measure install mode without touching the host's routes, run both
programs in a network namespace of their own, with `lo` up and an address
in 192.0.2.0/24 so the load generator's next hops (192.0.2.1–4) resolve,
and `fib { mode install; }` in the configuration:

```sh
sed 's/mode dry-run/mode install/' contrib/bgpfc-bench.conf > install.conf
sudo unshare -n sh -c '
  ip link set lo up && ip addr add 192.0.2.10/24 dev lo
  ./target/profiling/bgpfcd -c install.conf &
  sleep 1; ./target/profiling/bgp_loadgen --connect 127.0.0.1:11179'
```

`bgp_loadgen --help` lists every option: table size (`--prefixes`,
`--attr-sets`, `--seed`), session (`--asn`, `--router-id`, `--hold-time`,
`--extended` for 65535-octet UPDATEs), and `--hold SECS` to end the session
after the scenario instead of when the daemon closes it. Each phase prints
what it sent and how fast:

```
loadgen phase=load updates=50009 prefixes=1000000 bytes=7408508 ms=1767 updates_per_s=28299 prefixes_per_s=565897 bytes_per_s=4192452
```

That is the time to hand the UPDATEs to TCP, not the time the daemon took
to process them: the daemon's `event=table_load` line says that.

While a session is up:

```sh
./target/profiling/bgpfcctl -s /tmp/bgpfc-bench.sock stats
```

prints the report line now. `stats` exists only in profiling builds and
only on the control socket: metrics are not served over HTTP.

### The synthetic table

`--prefixes N` IPv4 prefixes, unique, shaped like the public table (about
62 % /24, a third /23–/16, about 1 % shorter), over `--attr-sets M`
attribute sets (default 50 000), each with its own `AS_PATH` of 2 to 8 ASes
starting with the load generator's AS. A few paths carry thousands of
prefixes and most carry a few. ORIGIN, MED and communities vary between
sets; `LOCAL_PREF` is sent only on an internal session. The table depends
only on the options and `--seed`: the same seed gives the same table.
Prefixes sharing a set are packed into as few UPDATEs as fit 4096 octets,
or 65535 with `--extended`.

### A real table from MRT

RouteViews and RIPE RIS publish `TABLE_DUMP_V2` dumps compressed; std has
no decompressor, so decompress first:

```sh
curl -O https://archive.routeviews.org/route-views.sg/bgpdata/2026.10/RIBS/rib.20261001.0000.bz2
bunzip2 -k rib.20261001.0000.bz2            # RIPE RIS: gunzip -k bview.20261001.0000.gz
./target/profiling/bgp_loadgen --mrt rib.20261001.0000 --mrt-list
./target/profiling/bgp_loadgen --connect 127.0.0.1:11179 --mrt rib.20261001.0000 --mrt-peer 39
```

`--mrt-list` prints the collector's peers and how many routes each has;
without `--mrt-peer` the one with the most is replayed. The routes go out
as an external speaker sends them: the load generator's AS prepended, no
`LOCAL_PREF`, attribute sets shared between routes that carry the same
ones. Entries the daemon would treat as withdrawn (malformed, or `AS_SET`
per RFC 9774) and routes whose path holds the daemon's AS are left out;
`event=mrt ... skipped=` counts the first kind.

### Environment

| Variable | Effect |
|---|---|
| `BGP_PROFILE_INTERVAL_SECS=N` | also report every `N` seconds (off by default) |
| `BGP_PROFILE_SPANS=0` | no span timing: histograms stay empty, everything else is reported |
| `BGP_PROFILE_LOAD_IDLE_SECS=N` | end a table load that has no End-of-RIB after `N` seconds without an UPDATE (default 10; `0`: End-of-RIB only) |

## The benchmark harness

```sh
./target/profiling/bgp_bench --scenario load --runs 5
```

Each run writes a config like the one above into a scratch directory,
starts `bgpfcd`, starts `bgp_loadgen` against it, waits for the
scenario's report lines, then stops the daemon with SIGTERM. After the
runs it prints the median, minimum and maximum of:

| Metric | From |
|---|---|
| `load_us` | the first `table_load`: first UPDATE to End-of-RIB, µs |
| `updates_per_s` | the same line: UPDATEs the RIB handled per second |
| `bytes_per_prefix` | the same line |
| `peak_live_bytes` | `peak` when the scenario ended |
| `peak_rss_kb` | `hwm_kb` when the scenario ended |
| `residual_bytes` | `withdraw-all`, `flap`: live bytes after the withdrawals or the last session reset, minus live bytes before the first load |

and appends one row to `bench/results.csv`:

```
timestamp,git_rev,dirty,scenario,prefixes,seed,params,runs,load_us,updates_per_s,peak_live_bytes,bytes_per_prefix,peak_rss_kb,residual_bytes
2026-10-24T21:20:02.120Z,847fb00,0,load,1000000,1,attr_sets=50000;extended=false;spans=on,5,3205533,15600,341670804,341,360396,
```

The row is compared with the last earlier row of the same scenario, size,
seed and `params` (the other options that change the result). A time
metric (`load_us` up, `updates_per_s` down) or a memory metric
(`peak_live_bytes`, `bytes_per_prefix`, `peak_rss_kb` up) worse by more
than `--threshold` percent (default 10) is a regression, and `bgp_bench`
exits with status 1 (2 for an error). `residual_bytes` is shown and never
checked; its baseline can be near zero.

`bench/results.csv` is git-ignored: the figures belong to one machine.
Compare rows from the same host only; the same binary ran 21 % slower
after this container moved to another host. `--no-record` compares
without appending, `--results FILE` keeps another history, `--keep` keeps
each run's directory with the configuration and both programs' logs.
`bgp_bench --help` lists the rest, including `--mrt FILE` for a real
table, `--extended`, and `--spans off`.

### Micro-benchmarks

```sh
cargo bench -p bgpfc-bench --bench micro            # or a name filter: ... micro best_path
```

UPDATE decoding (one prefix, so mostly the attribute section; and a full
4096-octet message per prefix), RIB insert (alone, and with a second peer
up to export to), withdraw, peer down and sending the table to a second
peer per route over 100 000 routes, the
decision process over 1–16 candidates,
interning an attribute set already held, and `Instant::now` itself. Each
warms up for 300 ms and reports the median of 15 samples, setup excluded,
using only `std::time::Instant` and `std::hint::black_box`.

The criterion benches (`cargo bench -p bgpfc-wire`, `-p bgpfc-rib`,
`-p bgpfc-policy`) measure what they did before; the RIB's now passes a
`Vec` as the output sink.

### Tests

```sh
cargo test --workspace --features profiling
cargo test -p bgpfcd --features profiling -- --ignored     # loadgen to daemon, 10 000 prefixes;
                                                            # two peers, 100 000 each
```

## Reading the report line

The daemon writes each report to stderr as a log line with `msg="profile"`,
whatever the log level:

```
2026-10-24T21:20:00.533Z INFO  msg="profile" event=table_load uptime_ms=4075 peer=127.0.0.1 end=eor prefixes=1000000 ...
```

After `msg="profile"` it is space-separated `key=value` pairs; values
never contain spaces, so split on spaces, then each pair on its first `=`
(`bgpfc_prof::report::fields` does this). `bgpfcctl stats` prints the same
pairs without the log prefix.

### Events

| `event` | When |
|---|---|
| `table_load` | a peer's table load ended: its End-of-RIB arrived for every negotiated family, or `BGP_PROFILE_LOAD_IDLE_SECS` passed without an UPDATE |
| `duplication` | right after `table_load` and `eor`: the RIB walk below |
| `eor` | an End-of-RIB after the table load: a sync point the load generator sends after churn and withdrawals |
| `peer_down` | the RIB removed a peer's routes after its session went down |
| `interval` | every `BGP_PROFILE_INTERVAL_SECS` |
| `shutdown` | clean shutdown (SIGTERM, SIGINT) |
| `stats` | `bgpfcctl stats` |

The End-of-RIB marker (RFC 4724 §2) is an UPDATE with nothing in it, or
for IPv6 one with only an empty `MP_UNREACH_NLRI`. The daemon does not
implement graceful restart; profiling builds recognise the marker only to
end the measurement.

### Fields of `table_load`

| Field | Meaning |
|---|---|
| `peer` | the neighbor |
| `end` | `eor`, or `idle` when the idle timeout ended it (the load time then ends at the last UPDATE) |
| `prefixes` | routes in the peer's Adj-RIB-In at the end |
| `updates` | UPDATEs during the load, End-of-RIB included |
| `load_ms`, `load_us` | from the RIB thread starting the first UPDATE after Established to finishing the End-of-RIB |
| `updates_per_s`, `prefixes_per_s` | rates over that time |
| `live_before` | live heap bytes when the session came up |
| `bytes_per_prefix` | `(live - live_before) / prefixes`: what a route costs across every thread (Loc-RIB, Adj-RIB-In, FIB table, interned attributes); see the caveats |

### Fields every report carries

| Field | Meaning |
|---|---|
| `uptime_ms` | since the daemon started |
| `live`, `peak` | heap bytes in use now, and the most ever, by the counting allocator |
| `allocs`, `deallocs` | allocator calls; a `realloc` is one allocation |
| `rss_kb`, `hwm_kb` | `VmRSS` and `VmHWM` from `/proc/self/status`. Far above `live`/`peak` means memory the allocator holds without the program using it: fragmentation, or large short-lived buffers (see `peer_down` below) |
| `rib_prefixes` | Loc-RIB destinations, all families |
| `adj_rib_in`, `adj_rib_out` | routes in all Adj-RIBs-In and -Out |
| `updates_rx`, `updates_tx` | UPDATE messages received (before decoding) and sent |
| `prefixes_announced`, `prefixes_withdrawn` | routes in the UPDATEs received; treat-as-withdraw counts as withdrawn |
| `bytes_rx`, `bytes_tx` | BGP octets read and written, headers included |
| `best_path_runs` | decision process runs: one per destination whose routes changed, none for a new destination (its one route is the best) |
| `sessions_established`, `sessions_dropped` | sessions reaching and leaving Established |

Then, for each histogram, `<name>.count`, `.sum_ns`, `.max_ns`, `.p50_ns`,
`.p90_ns` and `.p99_ns`. The percentiles come from 64 power-of-two
buckets, interpolated inside the bucket and capped at the largest sample:
an estimate is within a factor of two, and close for smooth distributions.
The histograms count from daemon start, not per event.

| Histogram | One sample is |
|---|---|
| `fsm_open_to_established` | the first OPEN sent or received on a connection to Established |
| `msg_parse_update` | one `UpdateMessage::decode` (peer thread) |
| `attr_parse` | the path attribute section of one UPDATE |
| `rib_insert` | one announced route into the Adj-RIB-In, import policy and the decision process for its destination included |
| `rib_remove` | one withdrawn route out of the Adj-RIB-In |
| `best_path` | one decision process run for one destination (see `best_path_runs`) |
| `adj_rib_out_build` | packing one peer's batch of changes into UPDATEs |
| `rib_peer_down` | removing every route of a peer that went down |
| `rib_update` | the RIB thread on one UPDATE: Adj-RIB-In, decision process, Adj-RIB-Out, outputs handed to the FIB and peer threads |
| `update_total` | one UPDATE from the start of its decode on the peer thread to the RIB thread finishing it, the wait in the RIB queue included |

`update_total` minus `rib_update` is the time an UPDATE waited in the
queue: during a table load the RIB thread is the bottleneck, and the
p50 of `update_total` is tens of milliseconds while `rib_update` is tens
of microseconds.

### Fields of `duplication`

| Field | Meaning |
|---|---|
| `destinations`, `routes` | destinations, and routes (candidates) over all of them |
| `attr_sets` | distinct attribute sets the routes use, by allocation |
| `attr_values` | distinct attribute sets by value; equal to `attr_sets` while interning works |
| `interned` | sets the interner holds. A set goes with its last route; one still held elsewhere at that moment (a control-plane reply, say) goes at the next sweep |
| `as_paths` | distinct `AS_PATH`s among the sets |
| `as_path_bytes`, `as_path_bytes_if_interned` | `AS_PATH` heap octets as stored (one copy per set) and if each distinct path were stored once: their difference is what interning paths separately would save |
| `candidate_bytes` | heap octets of the per-destination route vectors: only destinations with routes from two or more peers have one (a single route is held inline) |
| `adj_rib_out`, `adj_rib_out_bytes` | Adj-RIB-Out entries and an estimate of their octets: a copy of the exported table per peer |
| `walk_ms` | how long the walk took (the RIB thread is busy meanwhile) |

### Structure sizes

```sh
./target/profiling/bgpfcd --print-sizes
```

prints `size_of` for the structures a route is made of (`Prefix` 18,
`Destination` 24 with its first route inline, `Route` 16 for each further
one, `PathAttrs` 152, an installed IPv4 route in the FIB 9 octets on
x86-64), and for the
messages and the per-peer state.

## External profilers

Recipes for tools you may have; none is required. They all want the
`profiling` profile for symbols. Leave out `--features profiling` if the
counting allocator should not be in the picture.

```sh
# CPU: sampled call graphs.
perf record -g --call-graph dwarf -F 999 -- ./target/profiling/bgpfcd -c contrib/bgpfc-bench.conf
perf report

# Flame graphs, if installed.
flamegraph -- ./target/profiling/bgpfcd -c contrib/bgpfc-bench.conf
samply record ./target/profiling/bgpfcd -c contrib/bgpfc-bench.conf

# Heap: every allocation with its call stack.
heaptrack ./target/profiling/bgpfcd -c contrib/bgpfc-bench.conf
heaptrack_gui heaptrack.bgpfcd.*.zst

# Heap over time; slow, so use a small table (bgp_loadgen --prefixes 20000).
valgrind --tool=massif ./target/profiling/bgpfcd -c contrib/bgpfc-bench.conf
ms_print massif.out.*

# Peak RSS of the whole run.
/usr/bin/time -v ./target/profiling/bgpfcd -c contrib/bgpfc-bench.conf
```

Start the daemon under the tool, run `bgp_loadgen` from another terminal,
and stop the daemon with Ctrl-C (SIGINT is a clean shutdown).

## What to look for

- **Per-prefix allocations.** A synthetic load makes about one allocation
  per prefix (`allocs` on the `table_load` line), two thirds of them
  still live at the end (`allocs` minus `deallocs`): B-tree nodes of the
  RIB and FIB tables, and the attribute sets with their paths and
  communities. A new destination holds its route inline; only a
  second peer's route to it allocates (`candidate_bytes`), sized exactly.
  An UPDATE's own work reuses buffers kept in the RIB. Much more than one
  allocation a prefix means something per route started allocating
  again.
- **Duplicated attributes.** `attr_sets` against `routes` says how well
  attribute sets are shared; `attr_values` equal to `attr_sets` says the
  interner leaves no duplicates. `as_path_bytes` against
  `as_path_bytes_if_interned` says whether interning `AS_PATH`s on their
  own would pay off.
- **Per-peer RIB copies.** Every peer that is sent routes has an
  Adj-RIB-Out map of the exported table (`adj_rib_out`,
  `adj_rib_out_bytes`). With one load generator nothing is exported; add a
  second session to see it grow.
- **Live bytes after `withdraw-all` or `flap`** (`residual_bytes`): an
  attribute set goes with its last route, so `interned` drops to zero
  with the routes and what stays is the maps' own capacity, under a
  megabyte. The same figure after every flap cycle means nothing leaks.
- **`hwm_kb` against `peak`.** They stay close. RIB outputs go to the FIB
  thread in bounded batches as they are produced, so a peer with a full
  table going down builds no table-sized list (it raised RSS by 150 MB
  before).
- **Which thread is the bottleneck.** During a load the RIB thread is:
  `rib_update` is most of `load_us`, and the queue wait
  (`update_total` minus `rib_update`) is long. Its time per route grows
  with the table, because each B-tree lookup misses the cache more. In
  install mode the FIB thread is: netlink requests go to the kernel 256
  to a message with one acknowledgement, and most of the time is the
  kernel's.

## Baseline

From this branch, in a 4-CPU cloud container (figures move with the host;
see above). Synthetic table: 1 000 000 prefixes, 50 000 attribute sets,
seed 1, IPv4, 4096-octet UPDATEs, spans on, medians of 5 runs. The second
column is the same measurement where the profiling tools were added
(24ae7d9), on the same host.

| | now | 24ae7d9 |
|---|---|---|
| table load | 1.64 s (1.58–1.74), 30 500 UPDATEs/s | 3.26 s, 15 300 UPDATEs/s |
| of which on the RIB thread (`rib_update`) | 1.27 s; inserts and the decision process 0.70 s | 2.9 s |
| decode on the peer thread (`msg_parse_update`) | 0.15 s, in parallel | 0.22 s |
| bytes per prefix | 121 | 341 |
| peak live / peak RSS | 121.7 MB / 130.3 MB | 341.7 MB / 360.4 MB |
| allocations during the load | 1.02 M | 7.7 M |
| spans off | 1.51 s | 3.02 s |
| `withdraw-all`: peak live, residual | 153.6 MB, 0.76 MB | 373.6 MB, 13.7 MB |
| `flap`, 3 cycles: `rib_peer_down`, live after a reset, `hwm_kb` | 0.42–0.49 s, 0.98 MB, 133 MB | 1.2–1.3 s, 14.2 MB, 595 MB |

A real table, RouteViews `route-views.sg` 2026-10-01 00:00, peer 39
(AS23673): 1 114 715 routes over 159 391 attribute sets and 137 311
`AS_PATH`s; load 2.44 s, 161 octets per prefix, 180 MB peak live, 195 MB
RSS (at 24ae7d9: 4.55 s, 386 octets, 431 MB, 457 MB).

A profiling build is slower than the default build. Measured from outside
on the same host, interleaved, from starting the load generator until the
daemon reports every route received (session setup included, so not
comparable with `load_us`): 1.87 s in the default build, 1.99 s in the
profiling build with spans off and 2.06 s with spans on. Compare
profiling builds with profiling builds. In another run the same way,
interleaved with 24ae7d9's default build: 1.95 s and 130 MB of RSS
against 3.38 s and 360 MB.

Install mode, 1M routes into the kernel of a network namespace of their
own (a veth pair, one end 192.0.2.10/24, so the load generator's next
hops resolve), default build, three runs each, timed until the FIB
thread goes idle with every route in the kernel: 5.2–5.6 s and 131 MB
RSS, against 9.4–9.6 s and 416 MB at 24ae7d9, which held the desired and
the installed routes as two tables. The FIB thread bounds it: 4.7 s of
CPU (8.7 s at 24ae7d9), two thirds of it in the kernel, for one netlink
request and acknowledgement per route. Listing the kernel table while it
fills (`ip route | wc -l`) slows the inserts; count it once, at the end.

## Caveats

- `bytes_per_prefix` counts everything allocated during the load in every
  thread, and the snapshot is taken at the End-of-RIB: UPDATEs the peer
  thread has already decoded for the next phase are counted too. After
  `withdraw-all` the queued withdrawals show up as 143 octets per prefix
  against 121 for `load`. Use `load` for the per-prefix figure.
- The FIB thread may still be a few thousand changes behind at the
  End-of-RIB (its queue holds 64 batches of up to 256), so the FIB table
  is slightly undercounted.
- `flap` cycles take about ten seconds each: after a reset the daemon holds
  the peer in Idle (RFC 4271 §8.1.1 damping, 10 s jittered) and the load
  generator retries until it is let in.
- In `--listen` mode start the load generator first, or the daemon waits
  for its next connect retry (5 s in `contrib/bgpfc-bench.conf`).
