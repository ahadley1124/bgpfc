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
| `show neighbor ADDR` | the same in detail, with the negotiated session (router ID, timers, capabilities, families) |
| `show routes [ipv4\|ipv6] [PREFIX]` | the Loc-RIB of a family; with a prefix, every candidate route to it, the chosen one marked `*` |
| `show fib` | FIB mode and every desired route with `installed`, `pending` or `stale` |
| `clear neighbor ADDR [soft]` | hard: Cease / Administrative Reset (RFC 4486 §4), then reconnect; soft: ROUTE-REFRESH for every family (RFC 2918 §4) and a full resend of our Adj-RIB-Out. A soft reset is refused if the peer did not advertise the capability. |
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
| `POST /v1/reload` | `reload` |
| `POST /v1/neighbors/{addr}/clear[?soft=1][&message=TEXT]` | `clear neighbor` |
| `POST /v1/fib/mode/install`, `POST /v1/fib/mode/dry-run` | `fib mode` |

Example objects:

```json
{"version":"0.1.0","local_as":65000,"router_id":"192.0.2.1","neighbors":2,"established":2,"fib_mode":"dry-run"}

[{"address":"198.51.100.1","remote_as":64511,"state":"Established","since_seconds":120,
  "admin_down":false,"updates_in":4,"updates_out":2,"received":2,"advertised":1,
  "session":{"router_id":"198.51.100.1","hold_time":90,"keepalive_time":30,
             "four_octet_as":true,"extended_messages":false,"route_refresh":true,
             "families":["ipv4-unicast","ipv6-unicast"]}}]

[{"prefix":"192.0.2.0/24","next_hop":"198.51.100.1","origin":"igp","local_pref":100,"med":null,
  "peer":"198.51.100.1","best":true,"as_path":[64511],"communities":[],"large_communities":[]}]

{"mode":"install","routes":[{"prefix":"192.0.2.0/24","gateway":"198.51.100.1","installed":true}]}
```

## Reload

`SIGHUP`, `bgpfcctl reload` and `POST /v1/reload` all re-read the file
named with `-c`. A file that fails to parse, validate or compile leaves the
running configuration untouched and reports the errors. Otherwise, per
`docs/config.md`: new neighbors start; removed ones stop with Cease / Peer
De-configured; neighbors whose session parameters changed stop with Cease /
Other Configuration Change and start again; neighbors whose import or
export policy changed get a ROUTE-REFRESH and a re-export of the
difference; a changed `fib { mode }` is applied; a changed `log { level }`
takes effect at once. `router-id` and `local-as` changes are refused, and
`listen`, `control`, `fib { table }` and `fib { protocol }` changes are
noted for the next restart.
