# Control plane

`bgpfcd` answers operators two ways (AGENTS.md §3, "Control plane"): a
line protocol on a Unix socket, spoken by `bgpfcctl`, and an HTTP/1.1 JSON
API on a loopback address. Both run the same commands; the data comes from
the daemon's threads over request/response channels. Configuration:

```
control {
    socket /run/bgpfc/bgpfc.sock;
    http {
        listen 127.0.0.1:8179;    # loopback only; validation rejects anything else
        writes no;                # yes enables the write endpoints
        # token-file /etc/bgpfc/api-token;
    }
}
```

## bgpfcctl

```
bgpfcctl [-s SOCKET] COMMAND...
```

The socket defaults to `/run/bgpfc/bgpfc.sock` or `$BGPFC_SOCKET`. Exit
status is 0 on `+ok`, 1 on an error from the daemon or a connection
failure, 2 on a usage error.

| Command | Effect |
|---|---|
| `show status` | version, local AS, router ID, neighbor counts, FIB mode, the `rpki` mode with whether validation is off, waiting or active, and the alarms (see [Alarms](#alarms)) |
| `show neighbors` | one line per configured neighbor: AS, FSM state, time in state, routes received and advertised |
| `show neighbor ADDR` | the same in detail, with routes received, held and advertised per family next to the family's `maximum-prefix` (received is what the RFC 4271 §6.7 limit counts; held is how many of those are held for their validation state, see [Validation state](#validation-state)), the negotiated session (router ID, timers, capabilities, families, and the families whose routes may carry an IPv6 next hop under RFC 8950, from the neighbor and to it), and whether the `restart-limit` left the neighbor Idle (RFC 4486 §4) |
| `show routes [ipv4\|ipv6] [PREFIX] [held]` | the Loc-RIB of a family; with a prefix, every route the Adj-RIBs-In hold for it: the candidates, the chosen one marked `*`, then the routes held for their validation state, marked `!` and followed by `held by enforcement` or `held by policy`; with `held`, only the held routes, of the family or of the prefix. Each route has its origin validation state (`rov`), and after `>` the state import policy set (see [Validation state](#validation-state)) |
| `show fib` | FIB mode and every desired route with `installed` or `pending`, and every installed route not desired as `stale`, in prefix order |
| `show rpki` | the `rpki` mode and enforcement, whether validation is off, waiting for its first data or active, Routinator's state with `mode sidecar`, the cache list with the cache in use, and where the RTR client stands with it (see [RPKI](#rpki)) |
| `show rpki transitions` | the latest routes whose origin validation state changed, oldest first, each with its time (see [Changes of state](#changes-of-state)) |
| `show rpki validate PREFIX ASN` | the origin validation state of a route to PREFIX originated by ASN (`64496` or `AS64496`) against the VRPs in use, with every VRP that covers it, marked `matches` where it matches (RFC 6811 §2) |
| `clear neighbor ADDR [soft]` | hard: Cease / Administrative Reset (RFC 4486 §4), then reconnect; this is the manual start that brings back a neighbor the `restart-limit` left Idle; soft: ROUTE-REFRESH for every family (RFC 2918 §4) and a full resend of our Adj-RIB-Out. A soft reset is refused if the peer did not advertise the capability. |
| `clear neighbor ADDR MESSAGE` | a hard reset carrying a Shutdown Communication (RFC 9003); at most 128 octets (RFC 9003 §3) |
| `reload` | re-read the configuration file and apply the difference (`docs/config.md`, "Reload") |
| `fib mode dry-run\|install` | switch the FIB mode at runtime; switching to install performs a full reconcile |
| `stats` | profiling builds only (`docs/PROFILING.md`): the report line of counters, histograms and memory. Not served over HTTP. |

### Wire format

```
request  = word { " " word } "\n" ;            words may be "double quoted"
response = ( "+ok" | "-error: " message ) "\n" { line "\n" } ".\n" ;
```

A body line that starts with `.` is sent as `..`. One request per
connection; the daemon closes after the response. Requests over 4096
bytes are refused.

`show routes` of a whole family, held routes or not, and `show fib` can
list millions of routes. The daemon takes them from the RIB and the FIB
about 4096 at a time (all the held routes of a destination in one go) and
writes each part as it comes, so the listing is not one snapshot: a
route that changes meanwhile may show either way. If the daemon cannot
finish a listing, the response ends without its `.` line, which the client
reports as an error.

## HTTP API

Every response is JSON with `Connection: close`. `GET /v1/routes` without
a prefix and `GET /v1/fib` are written as they are produced, as above,
without `Content-Length`: the body ends when the connection closes (RFC
9112 §6.3), and a body cut short is not valid JSON. Errors are
`{"error": "..."}` with the status below. When a `token-file` is
configured, every request must carry `Authorization: Bearer TOKEN` (the
file's content, trimmed), else `401` with `WWW-Authenticate: Bearer`.
Write endpoints answer `403` unless `writes yes;` is set. Requests are
capped at 16 KiB, 64 header lines and a 4 KiB body (`413`); at most 16
connections are served at once (`503`); reads and writes time out after
5 seconds. There is no TLS: put a reverse proxy in front for remote use.

| Method and path | Equivalent command |
|---|---|
| `GET /v1/status` | `show status` |
| `GET /v1/neighbors` | `show neighbors` |
| `GET /v1/neighbors/{addr}` | `show neighbor ADDR` (`404` if unknown) |
| `GET /v1/routes?family=ipv4\|ipv6[&prefix=P][&held=1]` | `show routes` |
| `GET /v1/fib` | `show fib` |
| `GET /v1/rpki` | `show rpki` |
| `GET /v1/rpki/transitions` | `show rpki transitions` |
| `GET /v1/rpki/validate?prefix=P&origin=ASN` | `show rpki validate` (`400` without both) |
| `POST /v1/reload` | `reload` |
| `POST /v1/neighbors/{addr}/clear[?soft=1][&message=TEXT]` | `clear neighbor` |
| `POST /v1/fib/mode/install`, `POST /v1/fib/mode/dry-run` | `fib mode` |

Example objects:

```json
{"version":"0.1.0","local_as":65000,"router_id":"192.0.2.1","neighbors":2,"established":2,"fib_mode":"dry-run",
 "rpki":{"mode":"sidecar","validation":"active"},"alarms":["rpki-sidecar-failed"]}

[{"address":"198.51.100.1","remote_as":64511,"state":"Established","since_seconds":120,
  "admin_down":false,"restart_limit_reached":false,"updates_in":4,"updates_out":2,
  "received":2,"held":1,"advertised":1,
  "prefixes":[{"family":"ipv4-unicast","received":2,"held":1,"advertised":1,"limit":1000},
              {"family":"ipv6-unicast","received":0,"held":0,"advertised":0,"limit":null}],
  "session":{"router_id":"198.51.100.1","hold_time":90,"keepalive_time":30,
             "four_octet_as":true,"extended_messages":false,"route_refresh":true,
             "families":["ipv4-unicast","ipv6-unicast"],
             "extended_next_hop":{"receive":["ipv4-unicast"],"send":[]}}}]

[{"prefix":"192.0.2.0/24","next_hop":"198.51.100.1","origin":"igp","local_pref":100,"med":null,
  "peer":"198.51.100.1","best":true,"rov":"valid","rov_set":null,"held":null,"as_path":[64511],
  "communities":[],"large_communities":[]},
 {"prefix":"192.0.2.0/24","next_hop":"198.51.100.2","origin":"igp","local_pref":null,"med":null,
  "peer":"198.51.100.2","best":false,"rov":"invalid","rov_set":null,"held":"enforcement",
  "as_path":[64497],"communities":[],"large_communities":[]}]

{"mode":"install","routes":[{"prefix":"192.0.2.0/24","gateway":"198.51.100.1","installed":true}]}

{"mode":"external","enforcement":"drop-invalid","validation":"active","waiting_seconds":null,
 "sidecar":null,"caches":[{"host":"127.0.0.1","port":3323,
 "preference":0,"in_use":true,"current":true}],"running":true,"state":"idle","connected":true,"version":1,"session_id":4242,
 "serial":17,"synced_seconds_ago":12,"expires_in_seconds":7188,
 "vrps":{"ipv4":512340,"ipv6":121877,"from":{"host":"127.0.0.1","port":3323}},
 "failures":0,"last_error":null,"last_error_seconds_ago":null}

{"mode":"sidecar","enforcement":"drop-invalid","validation":"active","waiting_seconds":null,
 "sidecar":{"state":"failed","alarm":true,"pid":null,"running_seconds":null,"retry_in_seconds":280,
            "restarts":6,"consecutive_failures":7,"last_exit":"exited with status 1",
            "rtr":"127.0.0.1:41234","binary":"/usr/bin/routinator","version":"0.15.2"},
 "caches":[{"host":"127.0.0.1","port":41234,"preference":0,"in_use":true,"current":true}],
 "running":true,"state":"connecting","connected":false,"version":1,"session_id":4242,
 "serial":17,"synced_seconds_ago":1250,"expires_in_seconds":5950,
 "vrps":{"ipv4":512340,"ipv6":121877,"from":{"host":"127.0.0.1","port":41234}},
 "failures":3,"last_error":"rtr cache connection failed cache=127.0.0.1:41234 error=\"Connection refused (os error 111)\" serving_vrps=634217 expires_in=5954s retry_in=19s",
 "last_error_seconds_ago":4}

{"prefix":"192.0.2.0/24","origin":64496,"rov":"valid",
 "vrps":[{"prefix":"192.0.2.0/24","max_length":24,"asn":64496,"matches":true}]}

{"capacity":1024,"unrecorded":0,"transitions":[{"time":"2026-10-22T12:34:56.789Z",
 "seconds_ago":12,"family":"ipv4-unicast","prefix":"192.0.2.0/24","peer":"198.51.100.1",
 "origin":65001,"from":"valid","to":"invalid","route":"held","held_by":"enforcement"}]}
```

## Validation state

Every route carries its RFC 6811 origin validation state, which `show
routes` prints in the `rov` column and `GET /v1/routes` as the `rov`
member:

| `rov` | Meaning |
|---|---|
| `valid` | a VRP matches the route: it covers the prefix, allows its length, and names its origin AS (RFC 6811 §2) |
| `invalid` | at least one VRP covers the prefix, but none matches the route |
| `not-found` | no VRP covers the prefix |
| `disabled` | origin validation is not performed |

`disabled` is kept apart from `not-found`, which RFC 6811 §2 suggests for
a route that was not validated, so that a route nobody checked can be told
from one that no VRP covers (issue #52). Every route is `disabled` until
the `rpki` block (`docs/config.md`, "RPKI") gives bgpfcd the VRPs of an
RPKI cache, external (`mode external`) or Routinator run by bgpfcd (`mode
sidecar`), and that cache has sent its first full set (`show rpki` says
`validation waiting` meanwhile); from then on the states follow the
cache's data.

The state is judged on the route as the neighbor sent it, before import
policy, and follows the validation source when it changes (RFC 6811 §4).
What acts on it is the `rpki` block's `enforcement`, which `show rpki`
prints, and the import policy (`docs/config.md`, "RPKI"): under
`drop-invalid`, the default, an Invalid route is held; under
`prefer-valid` route selection ranks Valid routes first; under `off`
nothing acts on the state but policy.

When import policy sets the state a route is used with (`set rpki`, RFC
6811 §3), `show routes` prints it after the looked-up one, as in
`invalid>valid`, and the JSON has it as `rov_set` (`null` otherwise);
enforcement, route selection and export policy use the state set.

A route the Adj-RIB-In holds for its state stays there, counted as
received, but is no candidate for route selection, so it is neither
installed nor advertised (RFC 6811 §2: kept in the Adj-RIB-In, and out
of the decision process only as configured). It is used again, with no
UPDATE from its neighbor, once its state allows. `show routes PREFIX`
lists it after the candidates, marked `!`, followed by `held by
enforcement` (the `enforcement` rules out the state it is used with) or
`held by policy` (the import policy rejects it in its state and would
accept it in another); the JSON has `held` (`enforcement`, `policy` or
`null`). A held route keeps the attributes its neighbor sent, and is shown
with them: the import policy runs on them again when the route is used
again, so what the policy sets, such as a `set local-pref`, shows only
then. `show routes held` lists every held route of a family, and `show
neighbor` counts them per family.

```
prefix                                       next-hop                                 origin   lpref     med rov       path
*192.0.2.0/24                                198.51.100.2                             igp          -       - valid     64496 via 198.51.100.2
!192.0.2.0/24                                198.51.100.1                             igp          -       - invalid   65001 via 198.51.100.1 held by enforcement
```

`show rpki validate` answers the question for any route, held or not,
from the same VRPs the RIB validates with.

Routes also carry an ASPA verdict. Until ASPA verification exists, its
only value is `disabled`, so it is not shown.

### Changes of state

Issue #59: "An operator needs to see that a prefix went Valid → Invalid
at a specific time." Each change of the validation source (an RTR End of
Data that changes the VRPs, a move to another cache, VRPs that expire,
validation switched on or off) is logged at info as one line that counts
what it did:

```
2026-10-22T12:34:56.789Z INFO  msg="rib: validation states changed" routes=3 changed=2 changes=valid->invalid:1,invalid->valid:1 destinations=2 prefixes=192.0.2.0/24,203.0.113.0/24 best_changed=2 held=1 released=1 logged=2 unlogged=0
```

`routes` were validated again, `changed` of them changed state, as
`changes` details per pair of states; `destinations` is the number of
prefixes they are for, the first eight of which `prefixes` names, and
`best_changed` those whose best route changed. `held` routes the change
took out of use, and `released` it put back into use. Of the routes it
moved among `valid`, `invalid` and `not-found`, `logged` have a line of
their own at info, which follows, and `unlogged` do not:

```
2026-10-22T12:34:56.789Z INFO  msg="rib: route validation state changed" prefix=192.0.2.0/24 peer=198.51.100.1 origin=AS65001 from=valid to=invalid route=held by=enforcement
2026-10-22T12:34:56.789Z INFO  msg="rib: route validation state changed" prefix=203.0.113.0/24 peer=198.51.100.1 origin=AS65001 from=invalid to=valid route=best
```

`origin` is the route's origin AS (`none` when it has none, RFC 6811 §2);
`route` is what the route is after route selection: `best`, `candidate`,
or `held` with `by` the reason. Moves to and from `disabled`, which mean
validation being switched on or off, are counted on the first line and
never listed. A change of `enforcement` on reload is logged as one line
too:

```
2026-10-22T12:34:56.789Z INFO  msg="rib: rpki enforcement changed" from=off to=drop-invalid routes=1250000 held=5000 released=0 best_changed=4800
```

`show rpki transitions` and `GET /v1/rpki/transitions` give the latest
routes that moved among `valid`, `invalid` and `not-found`, oldest first,
each with the time of its log line, then how many are kept and how many
were never kept:

```
2026-10-22T12:34:56.789Z 192.0.2.0/24 peer 198.51.100.1 origin AS65001 valid->invalid held by enforcement
2026-10-22T12:34:56.789Z 203.0.113.0/24 peer 198.51.100.1 origin AS65001 invalid->valid best
2 kept (most recent 1024); 0 not recorded
```

In the JSON (see the example above), `seconds_ago` is how long ago the
change was, `origin` is `null` for none, and `held_by` is `null` unless
`route` is `held`. The memory is the RIB thread's and starts empty with
the daemon. Three bounds keep a change that moves a whole table, such as
VRPs that expire or validation switched on with a full table, from
holding the RIB thread or flooding the log with the RIB's lines, and none
is configurable:

| Bound | Value | Why |
|---|---|---|
| per-route lines at info per change | 100 | Ordinary RTR deltas move few routes, since most VRP churn re-issues ROAs that are already Valid, so a hundred logs a typical change whole. A change that moves many routes (expiry, a move to a cache with other data, a bulk ROA operation) then costs about 15 KB of log rather than a line per route of a table of a million. |
| routes listed per change | 1024 | The RIB names at most this many routes per change (`Revalidation::LISTED`): those after the first hundred go out at `debug`, and routes beyond the 1024 are only counted (`unlogged`, `not recorded`). It bounds the report (about 55 KB) and the debug output, which would otherwise be a line per route of the table. |
| changes kept for `show rpki transitions` | 1024 | The latest, about 90 KB: as many as one change lists, so that the last large one shows whole. |

Nothing is uncounted: the first line counts every move per pair of
states, and `show routes` gives every route's current state. A knob
would change no outcome, only how much is written.

The bounds are on the RIB's lines only. The FIB thread logs each route it
installs or removes at info (`fib: dry-run` or `fib: applied`), whatever
made the change, as it does for an UPDATE. So a change of state or of
`enforcement` adds up to one such line for each destination it counts in
`best_changed`: under `drop-invalid`, one for each destination whose only
route it holds or releases. The example above, `best_changed=4800`, comes
with about 4800 of them. At `log { level warn; }` the FIB thread writes
only its failures.

## RPKI

`show rpki` and `GET /v1/rpki` report the `rpki` block (`docs/config.md`,
"RPKI"), Routinator when bgpfcd runs it (`mode sidecar`), and the RTR
client. bgpfcd validates with the VRPs of one cache at a time (RFC 8210
§10), which `in_use` (`in use`) marks, and its client talks to one cache
at a time, which `current` marks: the one it is connected to, or the one
it tries next. Once that cache has sent its VRPs, both mark the same
cache. After a move to another cache they differ: the last VRPs stay in
use until the new cache has sent a full set, which replaces them, or until
they expire (§10, §6). With `mode sidecar` the client's one cache is
Routinator's RTR address on loopback, listed as `cache ADDRESS (sidecar)`
at preference 0.

```
mode sidecar
enforcement drop-invalid
validation active
sidecar running pid 4242 for 312s, routinator 0.15.2 (/usr/bin/routinator)
sidecar rtr 127.0.0.1:41234, restarts 1, failures 0, last exit: killed by signal 9 (SIGKILL)
cache 127.0.0.1:41234 (sidecar) preference 0, in use, current
state idle, connected, version 1
session-id 4242 serial 17
last sync 12s ago
vrps ipv4 512340 ipv6 121877 from 127.0.0.1:41234, expire in 7188s
failures 0
```

| Member | Line | Meaning |
|---|---|---|
| `mode` | `mode` | `disabled`, `external` or `sidecar` |
| `enforcement` | `enforcement` | what acts on the validation state: `drop-invalid`, `prefer-valid` or `off` (see [Validation state](#validation-state)); written or the default, and shown in every mode |
| `validation` | `validation` | `off`: no RTR client runs, so every route is `disabled`, as with `mode disabled` or after a reload that could not start the client or Routinator; `waiting` (`waiting Ns for the first full set: ...`): the client has had no full set yet, so every route is `disabled` and used as received, and `enforcement` acts once the set arrives (`docs/config.md`, "Startup window"); `active`: the RIB validates with a cache's VRPs, or with VRPs held from one until they expire |
| `waiting_seconds` | `waiting Ns` | while `validation` is `waiting`, for how long; `null` otherwise |
| `sidecar` | `sidecar` | Routinator, while bgpfcd runs it: see below. `null` without; with `mode sidecar` that means a reload could not start it, and the text says `sidecar not running` |
| `caches` | `cache` | the configured caches, and with a sidecar the client's cache at Routinator's address, marked `(sidecar)` in the text: `host`, `port`, `preference`, `in_use` (`in use`: its VRPs are in use) and `current` (`current`: the client talks to it) |
| `running` | `state stopped` | whether the client runs; it stops only when the RIB is gone |
| `state` | `state` | the session with the current cache: `disconnected`, `connecting` (a connection attempt is under way), `querying` (a query is out), `receiving` (an answer is coming in) or `idle` (in sync, waiting to poll) |
| `connected` | `connected` | whether a TCP connection to it is open |
| `version` | `version` | the RTR protocol version spoken: 1 (RFC 8210), or 0 (RFC 6810) after a fallback (RFC 8210 §7) or with `version 0` |
| `session_id`, `serial` | `session-id`, `serial` | the cache's Session ID and the Serial Number of the data, while the client can ask for changes since then (RFC 8210 §5.1) |
| `synced_seconds_ago` | `last sync` | since the cache's last End of Data |
| `vrps` | `vrps` | the VRPs in use, per family, and `from` (`from`) the cache they came from, `host` and `port`: the one `in_use` marks, or after a reload maybe a cache the list no longer has; `null` once VRPs held from a cache bgpfcd moved away from expired. `vrps` is `null` (`none yet`) before any cache sent data, when every route is `disabled` |
| `expires_in_seconds` | `expire in` | until those VRPs expire unless a cache refreshes them (RFC 8210 §6); then every route becomes `not-found` |
| `failures` | `failures` | failed attempts, connections lost before the cache was in sync, and No Data Available answers in a row; 0 again once a cache brings bgpfcd in sync |
| `last_error`, `last_error_seconds_ago` | `last error` | the last warning or error the client logged, with its fields as the log line has them, and how long ago; the text line escapes any control character (`\n`, `\u{001b}`), so that what a cache wrote stays on its line |

Without a client, in `mode disabled`, every member but `mode`,
`enforcement`, `validation` (`off`) and `caches` is `null`, `false` or 0,
and the text lists only those four. The members are the same in every
mode.

The `sidecar` object and its two lines, `sidecar STATE, routinator VERSION
(BINARY)` and `sidecar rtr ADDRESS, restarts N, failures N, last exit:
REASON`, come from the sidecar at each request:

| Member | Line | Meaning |
|---|---|---|
| `state` | `sidecar STATE` | `starting` (a start is under way), `running` (`running pid N for Ns`), `backing-off` (`backing-off after N failures, next attempt in Ns`: it failed, and is started again after a delay that doubles with each failure in a row up to the `restart-backoff` cap), `failed` (`FAILED after N failures in a row, next attempt in Ns`, the alarm below), `shutting-down` (bgpfcd is stopping it) or `stopped` |
| `alarm` | `FAILED` | whether `state` is `failed` |
| `pid` | `pid` | Routinator's process id, while one runs or is being stopped |
| `running_seconds` | `for Ns` | how long it has run, while `running` |
| `retry_in_seconds` | `next attempt in Ns` | until it is started again, while `backing-off` or `failed` |
| `restarts` | `restarts` | how often it was started again after it failed, since bgpfcd started it; a reload that changes the `sidecar` block starts it afresh |
| `consecutive_failures` | `failures` | its failures in a row: those since it last ran for `stable-after` seconds |
| `last_exit` | `last exit` | how it last ended: `exited with status N`, `killed by signal N (NAME)`, or `could not be started: REASON`, as when a replaced binary is of another release; `null`, and no text, before it first ended. The text escapes any control character |
| `rtr` | `sidecar rtr` | where it serves RTR: the `rtr-listen` address, with the port bgpfcd picked when that is 0 |
| `binary`, `version` | `routinator VERSION (BINARY)` | the binary the `sidecar` block names, and the version it reported when last checked: at start, and before a restart once the binary was replaced |

A Routinator that has failed `failure-threshold` times in a row is
`failed`: `FAILED` in upper case, and `alarm` true (issue #70: repeated
failures surface as an operational error, not only as log lines);
`show status` lists it among the [alarms](#alarms). bgpfcd also logs each of these failures at error (`RPKI sidecar keeps failing;
the validator is not running, retrying at the backoff cap`), and keeps
starting it at the `restart-backoff` cap. While such a retry runs, the
state is `running` and `failures` keeps its count; once Routinator has run
`stable-after` seconds, the count is 0 again and bgpfcd logs `RPKI sidecar
is stable again`. Routing goes on meanwhile: the VRPs Routinator last sent
stay in use until they expire (`expire in`; by default the Expire Interval
of 7200 seconds that Routinator announces), and then every route is
`not-found`, so that `drop-invalid` holds nothing (RFC 8210 §6). A failing
Routinator is not restarted by a reload that leaves its block alone.

## Alarms

`show status` and `GET /v1/status` end with what needs an operator now:
a line `alarm ...` for each alarm, and their names in `alarms`, an empty
array when there is none. They are the one reply a monitoring system
needs to poll; this is not a health check. There is one alarm:

| Name | Line | Raised while |
|---|---|---|
| `rpki-sidecar-failed` | `alarm rpki sidecar failed: N failures in a row` | Routinator has failed `failure-threshold` times in a row and waits for its next start: the `failed` state of `show rpki` (see [RPKI](#rpki)) |

Before the alarms, `show status` says `rpki MODE, validation STATE`, with
the mode of the `rpki` block and `off`, `waiting` or `active` as `show
rpki` has them; the JSON has `"rpki": {"mode": ..., "validation": ...}`.
Both come from the thread that also applies a reload. If it does not
answer within 10 seconds, as during a reload that waits for a slow
Routinator to stop, the line is `rpki unknown`, and `rpki` and `alarms`
are `null` in the JSON: not known, which an empty list would hide.

```
bgpfcd 0.1.0
local-as AS65000 router-id 192.0.2.1
neighbors 2 established 2
fib mode dry-run
rpki sidecar, validation active
alarm rpki sidecar failed: 7 failures in a row
```

## Reload

`SIGHUP`, `bgpfcctl reload` and `POST /v1/reload` all re-read the file
named with `-c`. A file that fails to parse, validate or compile leaves the
running configuration untouched and reports the errors. Otherwise, per
`docs/config.md`: new neighbors start; removed ones stop with Cease / Peer
De-configured; neighbors whose session parameters changed stop with Cease /
Other Configuration Change and start again; neighbors whose import or
export policy changed get a ROUTE-REFRESH and a re-export of the
difference; a changed `advertisement-interval` applies to the running
session without a reset, and so does a changed `maximum-prefix` (a session
already over its new limit ends with Cease / Maximum Number of Prefixes
Reached); a changed `fib { mode }` is applied; a changed
`log { level }` takes effect at once; a changed `rpki` block restarts the
RTR client, which keeps the VRPs it had until a cache of the new list has
sent a full set, or stops it with `mode disabled`, every route `disabled`
again, and restarts Routinator only when its `sidecar` block changes; a changed `enforcement` alone leaves the client alone and judges
every route again under the new mode at once (the summary says `rpki
enforcement MODE`, the log `rib: rpki enforcement changed`).
`router-id` and `local-as` changes are refused, and `listen`,
`control`, `fib { table }` and `fib { protocol }` changes are noted for the
next restart.
