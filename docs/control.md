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
| `show status` | version, local AS, router ID, neighbor counts, FIB mode |
| `show neighbors` | one line per configured neighbor: AS, FSM state, time in state, routes received and advertised |
| `show neighbor ADDR` | the same in detail, with routes received and advertised per family next to the family's `maximum-prefix` (received is what the RFC 4271 §6.7 limit counts), the negotiated session (router ID, timers, capabilities, families, and the families whose routes may carry an IPv6 next hop under RFC 8950, from the neighbor and to it), and whether the `restart-limit` left the neighbor Idle (RFC 4486 §4) |
| `show routes [ipv4\|ipv6] [PREFIX]` | the Loc-RIB of a family; with a prefix, every candidate route to it, the chosen one marked `*`; each route with its origin validation state (`rov`, see [Validation state](#validation-state)) |
| `show fib` | FIB mode and every desired route with `installed`, `pending` or `stale` |
| `show rpki` | the `rpki` mode, the cache list with the cache in use, and where the RTR client stands with it (see [RPKI](#rpki)) |
| `show rpki validate PREFIX ASN` | the origin validation state of a route to PREFIX originated by ASN (`64496` or `AS64496`) against the VRPs in use, with every VRP that covers it, marked `matches` where it matches (RFC 6811 §2) |
| `clear neighbor ADDR [soft]` | hard: Cease / Administrative Reset (RFC 4486 §4), then reconnect; this is the manual start that brings back a neighbor the `restart-limit` left Idle; soft: ROUTE-REFRESH for every family (RFC 2918 §4) and a full resend of our Adj-RIB-Out. A soft reset is refused if the peer did not advertise the capability. |
| `clear neighbor ADDR MESSAGE` | a hard reset carrying a Shutdown Communication (RFC 9003); at most 128 octets (RFC 9003 §3) |
| `reload` | re-read the configuration file and apply the difference (`docs/config.md`, "Reload") |
| `fib mode dry-run\|install` | switch the FIB mode at runtime; switching to install performs a full reconcile |

### Wire format

```
request  = word { " " word } "\n" ;            words may be "double quoted"
response = ( "+ok" | "-error: " message ) "\n" { line "\n" } ".\n" ;
```

A body line that starts with `.` is sent as `..`. One request per
connection; the daemon closes after the response. Requests over 4096
bytes are refused.

## HTTP API

Every response is JSON with `Connection: close`. Errors are
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
| `GET /v1/routes?family=ipv4\|ipv6[&prefix=P]` | `show routes` |
| `GET /v1/fib` | `show fib` |
| `GET /v1/rpki` | `show rpki` |
| `GET /v1/rpki/validate?prefix=P&origin=ASN` | `show rpki validate` (`400` without both) |
| `POST /v1/reload` | `reload` |
| `POST /v1/neighbors/{addr}/clear[?soft=1][&message=TEXT]` | `clear neighbor` |
| `POST /v1/fib/mode/install`, `POST /v1/fib/mode/dry-run` | `fib mode` |

Example objects:

```json
{"version":"0.1.0","local_as":65000,"router_id":"192.0.2.1","neighbors":2,"established":2,"fib_mode":"dry-run"}

[{"address":"198.51.100.1","remote_as":64511,"state":"Established","since_seconds":120,
  "admin_down":false,"restart_limit_reached":false,"updates_in":4,"updates_out":2,
  "received":2,"advertised":1,
  "prefixes":[{"family":"ipv4-unicast","received":2,"advertised":1,"limit":1000},
              {"family":"ipv6-unicast","received":0,"advertised":0,"limit":null}],
  "session":{"router_id":"198.51.100.1","hold_time":90,"keepalive_time":30,
             "four_octet_as":true,"extended_messages":false,"route_refresh":true,
             "families":["ipv4-unicast","ipv6-unicast"],
             "extended_next_hop":{"receive":["ipv4-unicast"],"send":[]}}}]

[{"prefix":"192.0.2.0/24","next_hop":"198.51.100.1","origin":"igp","local_pref":100,"med":null,
  "peer":"198.51.100.1","best":true,"rov":"disabled","as_path":[64511],"communities":[],
  "large_communities":[]}]

{"mode":"install","routes":[{"prefix":"192.0.2.0/24","gateway":"198.51.100.1","installed":true}]}

{"mode":"external","caches":[{"host":"127.0.0.1","port":3323,"preference":0,"in_use":true}],
 "running":true,"state":"idle","connected":true,"version":1,"session_id":4242,"serial":17,
 "synced_seconds_ago":12,"expires_in_seconds":7188,"vrps":{"ipv4":512340,"ipv6":121877},
 "failures":0,"last_error":null,"last_error_seconds_ago":null}

{"prefix":"192.0.2.0/24","origin":64496,"rov":"valid",
 "vrps":[{"prefix":"192.0.2.0/24","max_length":24,"asn":64496,"matches":true}]}
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
`rpki { mode external; ... }` (`docs/config.md`, "RPKI") gives bgpfcd the
VRPs of an RPKI cache; from then on the states follow the cache's data.

The state is judged on the route as the neighbor sent it, before import
policy, and follows the validation source when it changes. It is shown
for information only: it does not yet change whether a route is used or
which one is chosen.

`show rpki validate` answers the question for any route, held or not,
from the same VRPs the RIB validates with.

Routes also carry an ASPA verdict. Until ASPA verification exists, its
only value is `disabled`, so it is not shown.

## RPKI

`show rpki` and `GET /v1/rpki` report the `rpki` block (`docs/config.md`,
"RPKI") and its RTR client. bgpfcd uses one cache of the list at a time
(RFC 8210 §10); `in_use` marks it.

| Member | Line | Meaning |
|---|---|---|
| `mode` | `mode` | `disabled` or `external` |
| `caches` | `cache` | the configured caches: `host`, `port`, `preference`, `in_use` |
| `running` | `state stopped` | whether the client runs; it stops only when the RIB is gone |
| `state` | `state` | the session with the cache in use: `disconnected`, `connecting`, `querying` (a query is out), `receiving` (an answer is coming in) or `idle` (in sync, waiting to poll) |
| `connected` | `connected` | whether a TCP connection to it is open |
| `version` | `version` | the RTR protocol version spoken: 1 (RFC 8210), or 0 (RFC 6810) after a fallback (RFC 8210 §7) or with `version 0` |
| `session_id`, `serial` | `session-id`, `serial` | the cache's Session ID and the Serial Number of the data, while the client can ask for changes since then (RFC 8210 §5.1) |
| `synced_seconds_ago` | `last sync` | since the cache's last End of Data |
| `vrps` | `vrps` | the VRPs in use, per family; `null` (`none yet`) before any cache sent data, when every route is `disabled` |
| `expires_in_seconds` | `expire in` | until those VRPs expire unless a cache refreshes them (RFC 8210 §6); then every route becomes `not-found` |
| `failures` | `failures` | failed attempts, connections lost before the cache was in sync, and No Data Available answers in a row; 0 again once a cache brings bgpfcd in sync |
| `last_error`, `last_error_seconds_ago` | `last error` | the last warning or error the client logged, with its fields as the log line has them, and how long ago; the text line escapes any control character (`\n`, `\u{001b}`), so that what a cache wrote stays on its line |

Without a client, in `mode disabled`, every member but `mode` and
`caches` is `null`, `false` or 0, and the text lists only those two.

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
again. `router-id` and `local-as` changes are refused, and `listen`,
`control`, `fib { table }` and `fib { protocol }` changes are noted for the
next restart.
