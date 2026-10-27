# Configuration language

This is the authoritative grammar for `bgpfcd` configuration files
(AGENTS.md §3, "Config"). `contrib/bgpfc.conf` is a complete example. Parsing
and validation live in `crates/bgpfc-config`; every change to that crate
updates this file in the same commit.

## Lexical structure

- A file is UTF-8 text. `#` starts a comment that runs to the end of the line.
- Words are runs of characters other than whitespace, `{`, `}`, `;`, `"`
  and `#`. Addresses, prefixes, communities, numbers and keywords are all
  words; the parser gives them meaning by position.
- Strings are double-quoted. Escapes: `\"`, `\\`, `\n`, `\t`. Strings may
  span lines. Only the as-path regex and the description need quoting;
  everywhere else a string and a word are interchangeable.
- Every statement ends with `;` or with a `{ ... }` block.

Errors are reported as `file:line:col: message` with the source line and a
caret, and the parser recovers at the next `;` or `}` so one run reports
several problems. Lexical and syntax errors are reported first; once the file
parses, value and cross-reference errors are reported together.

## Grammar

```ebnf
file        = { statement } ;
statement   = word { argument } ( ";" | block ) ;
block       = "{" { statement } "}" ;
argument    = word | string ;
```

The statements that have meaning are listed below. `yes-no` is one of
`yes`, `no`, `on`, `off`, `true`, `false`. Any other keyword, any
statement repeated where it may appear only once, and any wrong number of
arguments is an error.

```ebnf
config       = { global | prefix-list | policy | neighbor } ;

global       = "router-id" ipv4 ";"              (* required; not 0.0.0.0 *)
             | "local-as" asn ";"                (* required; never 0 *)
             | "log" "{" [ "level" level ";" ] "}"
             | "listen" "{" "address" ip ";" [ "port" u16 ";" ] "}"   (* repeatable *)
             | "fib" "{" { fib-item } "}"
             | "control" "{" { control-item } "}"
             | "rpki" "{" { rpki-item } "}"      (* none: validation disabled *)
             | "netns" netns ";" ;               (* once; default: the namespace
                                                    bgpfcd is started in *)

level        = "error" | "warn" | "info" | "debug" | "trace" ;    (* default info *)

fib-item     = "mode" ( "dry-run" | "install" ) ";"   (* default dry-run *)
             | "table" ( "main" | "local" | "default" | u32 ) ";"   (* default main *)
             | "protocol" u8 ";" ;                    (* default 186, RTPROT_BGP *)

control-item = "socket" path ";"
             | "http" "{" "listen" ip ":" u16 ";"     (* loopback only *)
                       [ "writes" yes-no ";" ]        (* default no *)
                       [ "token-file" path ";" ] "}" ;

rpki-item    = "mode" ( "disabled" | "external" | "sidecar" ) ";"   (* required *)
             | "enforcement" ( "drop-invalid" | "prefer-valid" | "off" ) ";"   (* default drop-invalid *)
             | "startup" ( "accept" | "hold" ) ";"     (* default accept *)
             | "cache" host { cache-option } ";"       (* repeatable; options once each; not with mode sidecar *)
             | "sidecar" "{" { sidecar-item } "}"      (* once; not with mode external *)
             | "version" ( "0" | "1" ) ";"             (* default 1 *)
             | "connect-timeout" u32 ";"              (* default 10 *)
             | "response-timeout" u32 ";"             (* default 60 *)
             | "reply-timeout" u32 ";"                (* default 1800 *)
             | "max-expire" u32 ";"                   (* 600-172800; default 172800 *)
             | "max-vrps" u32 ";"                     (* at least 1; default 4000000 *)
             | "backoff" u32 u32 ";"                  (* MIN MAX: 1-7200 each, MIN <= MAX;
                                                         default 1 600, with mode sidecar 1 30 *)
             | "tcp-keepalive" keepalive-option { keepalive-option } ";" ;
                                                      (* options once each; default
                                                         idle 60 interval 10 count 6 *)
cache-option = "port" u16                              (* default 323; not 0 *)
             | "preference" u32 ;                      (* default 0 *)
keepalive-option
             = "idle" u32                              (* 1-32767; default 60 *)
             | "interval" u32                          (* 1-32767; default 10 *)
             | "count" u32 ;                           (* 1-127; default 6 *)

sidecar-item = "binary" path ";"                       (* absolute; default /usr/bin/routinator *)
             | "repository-dir" path ";"               (* absolute; default /var/lib/bgpfc/rpki *)
             | "rtr-listen" ip [ "port" u16 ] ";"      (* loopback; port 0 or 1024-65535;
                                                         default 127.0.0.1 port 0: picked at start *)
             | "rir-tals" yes-no ";"                   (* default yes *)
             | "tals" tal { tal } ";"                  (* further bundled TALs; default none *)
             | "extra-tals-dir" path ";"               (* absolute; default none *)
             | "accept-arin-rpa" yes-no ";"            (* default no *)
             | "refresh" u32 ";"                       (* 1-7199; default 600 *)
             | "config-file" path ";"                  (* absolute; default none *)
             | "global-args" argument { argument } ";" (* escape hatch, before `server` *)
             | "server-args" argument { argument } ";" (* escape hatch, after `server` *)
             | "restart-backoff" u32 u32 ";"           (* INITIAL CAP: 1-3600 each, INITIAL <= CAP;
                                                         default 1 300 *)
             | "stable-after" u32 ";"                  (* 1-86400; default 300 *)
             | "stop-timeout" u32 ";"                  (* 1-3600; default 10 *)
             | "failure-threshold" u32 ";" ;           (* at least 1; default 5 *)
tal          = word ;   (* a TAL Routinator 0.15 bundles: afrinic apnic arin lacnic ripe
                           apnic-testbed arin-ote ripe-pilot nlnetlabs-testbed *)

prefix-list  = "prefix-list" name "{" { prefix-entry ";" } "}" ;
prefix-entry = prefix [ "ge" u8 ] [ "le" u8 ] ;

policy       = "policy" name "{" { term } "}" ;
term         = "term" name "{" { "match" match ";" } { "set" set ";" } "action" action ";" "}" ;
match        = "prefix" prefix-entry
             | "prefix-list" name
             | "as-path" string
             | "community" community
             | "ext-community" ext-community
             | "large-community" large-community
             | "origin" ( "igp" | "egp" | "incomplete" )
             | "neighbor" ip
             | "rpki" rov-state ;
rov-state    = "valid" | "invalid" | "not-found" | "disabled" ;
set          = "local-pref" u32
             | "med" u32
             | "community" op community { community }
             | "ext-community" op ext-community { ext-community }
             | "large-community" op large-community { large-community }
             | "as-path" "prepend" asn { asn }
             | "next-hop" "self"
             | "rpki" ( "valid" | "invalid" | "not-found" ) ;   (* import policies only *)
op           = "add" | "remove" | "replace" ;
action       = "accept" | "reject" | "next" ;

neighbor     = "neighbor" ip "{" { neighbor-item } "}" ;
neighbor-item
             = "remote-as" asn ";"                   (* required *)
             | "import" name ";"                     (* required *)
             | "export" name ";"                     (* required *)
             | "description" string ";"
             | "port" u16 ";"                        (* default 179 *)
             | "hold-time" u16 ";"                   (* 0 or >= 3; default 90 *)
             | "keepalive-time" u32 ";"              (* default hold-time / 3 *)
             | "connect-retry-time" u32 ";"          (* default 120 *)
             | "send-hold-time" ( u16 | "off" ) ";"  (* default max(480, 2 * hold-time) *)
             | "advertisement-interval" u16 ";"      (* default 30 external, 5 internal; 0 off *)
             | "families" family { family } ";"      (* default both *)
             | "extended-next-hop" yes-no ";"        (* default no *)
             | "restart-limit" ( u32 | "off" ) ";"  (* default 10 *)
             | "maximum-prefix" family u32 ";"     (* once per family; default none *)
             | "multihop" [ u8 ] ";"                 (* 1-255, bare 255; default 1 external, the system's internal *)
             | "local-address" ip ";"                (* the neighbor's family; default the kernel's choice *)
             | "passive" yes-no ";"                  (* default no *)
             | "allow-as-set" yes-no ";"             (* default no *)
             | "collision-detect-established" yes-no ";" ;   (* default no *)
family       = "ipv4-unicast" | "ipv6-unicast" ;
```

Value syntax:

| Token | Form |
|---|---|
| `asn` | decimal, 1–4294967295 (RFC 6793 "asplain"; AS 0 is rejected, RFC 7607) |
| `ipv4`, `ip` | dotted quad; `ip` also accepts an IPv6 address |
| `host` | an `ip` (IPv6 without brackets), or a host name: dot-separated labels of letters, digits and hyphens, none starting or ending with a hyphen, the last not all digits (RFC 1123 §2.1), optionally ending in `.` |
| `prefix` | `address/length`; host bits are zeroed |
| `community` | `asn:value` with 16-bit halves, or `no-export`, `no-advertise`, `no-export-subconfed` |
| `ext-community` | `as2:SUB:ASN:LOCAL`, `as4:SUB:ASN:LOCAL`, `ipv4:SUB:ADDR:LOCAL` (prefix the kind with `nt-` for non-transitive), or `0x` and 16 hex digits |
| `large-community` | `global:local1:local2`, each 32-bit |
| `name` | any word |
| `path` | any word or string |
| `netns` | a name in `/run/netns`: one path component, not empty, without `/`, not `.` or `..`, at most 255 octets (iproute2's rule); or an absolute path, starting with `/` |

## Semantics

**Prefix entries.** `10.0.0.0/8` alone matches exactly that prefix.
`le 24` matches every prefix inside `10.0.0.0/8` with a length up to 24.
`ge 16 le 24` restricts the length to 16–24. Both bounds must lie between
the entry's own length and the address size, and `ge` must not exceed `le`.

**Policies.** A policy is an ordered list of terms. For each route, terms run
in order; a term applies when all of its `match` clauses hold (a term without
clauses always applies). An applying term runs its `set` actions in order and
then its action: `accept` and `reject` decide the route, `next` continues
with the following term keeping the modifications. If no term decides, the
route is rejected (AGENTS.md §3, "Policy").

Match clauses: `prefix` and `prefix-list` compare the route's NLRI;
`as-path` is a regular expression over AS numbers (below); the three
community clauses hold when the route carries the value; `origin` compares
the ORIGIN attribute; `neighbor` compares the peer the route was received
from (import) or is being sent to (export); `rpki` compares the route's
origin validation state (RFC 6811 §3: "the ability to match and set the
validation state of routes"; see **RPKI** below).

`match rpki not-found` also holds for a route that is not validated
(`disabled`): RFC 6811 §2 says such a route SHOULD read as NotFound, so a
policy written for validation does the same with or without it. `match
rpki disabled` holds only when validation is off, so a term with it,
placed first, treats unvalidated routes apart. That matters for a policy
that rejects on `not-found` and accepts some other state, such as one
that takes Valid routes only: while validation is off it holds every
route, `held by policy` (see **RPKI** below), and uses none, until
validation gives them a state it accepts. A term `match rpki disabled;
action accept;` placed before it takes unvalidated routes as they are.
On import the clause sees
the state the lookup gave the route, or the one an earlier term of the
same run set (`action next`), as later terms see an earlier `set
local-pref`; on export it sees the state the route is used with.

`set rpki valid|invalid|not-found` sets the state the route is used with
from then on: `enforcement` acts on it, route selection ranks by it under
`prefer-valid`, and export policies match it. The route keeps the state
the lookup gave it too, which is what is shown and logged (RFC 6811 §2:
"The validation state of the Route MUST be set to reflect the result of
the lookup"). When the VRPs change the route's looked-up state, the import
policy runs again, and may set a state again or not. `set rpki disabled`
is an error, since `disabled` says that no lookup was made, and so is `set
rpki` in a policy that is some neighbor's `export` policy: the state goes
no further than this router (bgpfcd does not implement RFC 8097, the
extended community that would carry it), so there it would do nothing. A
typical use is a customer prefix whose ROA is known to be wrong:
`match prefix 198.51.100.0/24; match rpki invalid; set rpki valid;`. Another
is the receiving side of RFC 6811 §5, a state that an internal neighbor
which validates puts in a community: `match community 65000:666; set rpki
invalid;`.

Set actions change the route's attributes before the decision process
(import) or before sending (export). On export they run before the
session rewriting of RFC 4271 §5.1 (our AS is prepended after a policy's
`as-path prepend`; the next hop of a route to an external peer is our
address on the session, see `extended-next-hop` below for IPv4 routes on an
IPv6 session). `next-hop self` is therefore only meaningful in export
policies towards internal peers. A policy cannot advertise a route to the
peer it came from, nor an internal route to another internal peer.

**AS-path regular expressions.** The pattern is matched against the
route's `AS_PATH` as a sequence of AS numbers; every operator acts on
whole AS numbers, never on digits:

| Syntax | Meaning |
|---|---|
| `65001` | that AS |
| `.` | any one AS |
| `[64512-65534 1 2]` | any AS in the set; `[^...]` any AS not in it |
| `^`, `$` | the start and the end of the path |
| `X*`, `X+`, `X?` | zero or more, one or more, zero or one `X` |
| `(X Y)`, `X\|Y` | grouping and alternation |
| space, `_` | separate tokens; no meaning of their own |

A pattern without `^` matches anywhere in the path. `AS_SET` members are
matched as if they were a sequence. The engine is a state-set simulation
of a Thompson NFA, so matching time is bounded by pattern size times path
length whatever the pattern; a pattern compiling to more than 4096 NFA
instructions is rejected at load time. Pattern errors are reported with
the term's position and the offset in the pattern.

**Neighbors.** Each neighbor is identified by its address; defining one twice
is an error. `import` and `export` must name policies defined in the same
file. Timers are in seconds. `hold-time 0` disables keepalives and the hold
timer (RFC 4271 §4.4). `keepalive-time` must be below `hold-time`.
`send-hold-time` must exceed `hold-time` (RFC 9687 §4.4); `off` disables
the send hold timer. `advertisement-interval` is the
MinRouteAdvertisementIntervalTimer of RFC 4271 §9.2.1.1: the least time
between two advertisements of the same prefix to this neighbor. Changes
inside the interval are held, and when it ends only the latest route goes
out, so a flapping route is advertised at most once per interval. The
first advertisement of a prefix is never held, and withdrawals are always
sent at once (RFC 4271 applies the interval to withdrawals too; bgpfc does
not, because holding a withdrawal back prolongs a blackhole). So that
memory follows the routes rather than their churn, at most as many prefixes
may be held at once as the neighbor was ever sent routes, or 1024 if that
is more; past that, a change goes out at once. Without the
statement the interval is the RFC 4271 §10 default for the session: 30
seconds for an external neighbor, 5 for an internal one. `0` sends every
change at once. `allow-as-set yes` accepts `AS_SET` in received
UPDATEs against RFC 9774 §3. `collision-detect-established yes` lets a new
connection replace an Established session per RFC 4271 §6.8.

`multihop` sets the TTL (IPv4) or hop limit (IPv6) of every segment
bgpfcd sends the neighbor, the SYN of its own connections included:

| Neighbor | `multihop` | TTL sent |
|---|---|---|
| external (`remote-as` is not `local-as`) | none | 1 |
| external | `multihop;` | 255 |
| external | `multihop N;` | N, from 1 to 255 |
| internal | none | the system's (`net.ipv4.ip_default_ttl`, 64 by default; IPv6 `hop_limit`) |
| internal | `multihop;` or `multihop N;` | 255 or N |

As with FRR and BIRD, an external neighbor is taken to be directly
connected: TTL 1 reaches the next router and no further. One more than a
hop away, such as one peered over loopback addresses, needs `multihop N`
with N at least the number of hops to it, or a bare `multihop` for 255. An internal
neighbor needs no `multihop`, since it keeps the system's TTL, as BIRD's
and FRR's internal sessions do; `multihop N` there sets N all the same.
`multihop` sets only what bgpfcd sends and checks nothing of what it
receives: checking the TTL of arriving packets is the Generalized TTL
Security Mechanism (GTSM, RFC 5082), which bgpfcd does not implement.

A connection the neighbor opens gets the neighbor's TTL as soon as bgpfcd
accepts it, so from bgpfcd's first segment on it, its OPEN. The SYN-ACK
that answered the neighbor's SYN has left by then with the listener's TTL,
the system's: one listener serves every neighbor.

An external neighbor more than one hop away without `multihop` never
comes up, and it shows:

- bgpfcd's own connections fail at once, as the first router answers the
  SYN with an ICMP Time Exceeded: a warning `msg="connect failed"
  peer=P error="No route to host (os error 113)" ttl=1 hint="external
  neighbor: more than one hop away needs multihop"`, again at debug while
  the same error repeats. The hint comes with that error, with `Network
  is unreachable` and with a timeout. bgpfcd retries every
  `connect-retry-time`, as after any failed connection.
- A connection the neighbor opens is accepted, but bgpfcd's OPEN never
  reaches it: the session waits in OpenSent until its hold timer of four
  minutes (RFC 4271 §8.2.2) ends it, with a warning `msg="connection
  closed with a socket error"` that has the same error as
  `socket_error=`, and the same hint.
- `bgpfcctl show neighbor` says `ttl 1`, and the error as `last error`
  with how long ago it was.
- The neighbor sees connections that never bring an OPEN, which its own
  timers end (BIRD logs them as `Connection lost` or a hold timer
  expiry).

`local-address 192.0.2.1;` runs the session from that address. bgpfcd
binds its own connections to it before connecting, and closes a
connection the neighbor opens to any other of its addresses, with an info
line `msg="connection to another local address, closing"` that names
both. Either way it is the session's local address, which bgpfcd
advertises as the next hop to an external neighbor and for `set next-hop
self` (RFC 4271 §5.1.3). Its use is peering from a loopback address, so
that the session survives the loss of an interface. Refusing the other
addresses keeps it there, as BIRD's `local` address does: a session
accepted on an interface address would end with that interface, and
advertise that address as its next hop, with nothing to tell the
operator why. The neighbor must then reach the address, through a route
to it, and bgpfcd must listen on it (`listen`), or on the wildcard
address, its default, to accept the neighbor's connections. Its family
is the neighbor's, and it is not unspecified (`0.0.0.0`, `::`),
multicast, the neighbor's own address or an IPv6 link-local address,
which a socket can only be bound to with an interface that bgpfcd has
no way to be given. An address the host does not have fails every
connect with `Cannot assign requested address`. Without
`local-address` the kernel picks the source address by route, and a
connection the neighbor opens is accepted on any local address.

`extended-next-hop yes` advertises the Extended Next Hop Encoding
capability of RFC 8950 for IPv4 unicast, which must then be in `families`.
The capability tells the neighbor that we take IPv4 routes with an IPv6
next hop, so such routes from it are accepted whether or not it advertises
the capability too. When it does, IPv4 routes sent to it may carry an IPv6
next hop as well: on a session over IPv6 the IPv4 routes sent to an
external neighbor, or through `set next-hop self`, carry our IPv6 address
on the session (RFC 8950 §5), and a route whose IPv6 next hop is passed on
unchanged, as to an internal neighbor, keeps it (its global address: no
link-local address is ever sent, as bgpfc cannot tell whether it shares a
subnet with the next hop and the neighbor, RFC 2545 §3). A neighbor that
did not advertise the capability is never sent an IPv4 route with an IPv6
next hop (RFC 8950 §4). Without `extended-next-hop yes`, which is the
default, the extension is used neither way: an IPv4 route received with an
IPv6 next hop is malformed, and IPv4 unicast is disabled for the session
(RFC 7606 §7.11); IPv4 routes sent over an IPv6 session keep the next hop
they were received with. In the FIB, an IPv4 route via an IPv6 next hop is
installed with `RTA_VIA`.

`maximum-prefix ipv4-unicast 1000;` ends the session once the neighbor has
more than 1000 IPv4 unicast routes in the RIB (RFC 4271 §6.7): bgpfcd
sends Cease / Maximum Number of Prefixes Reached with the family and the
limit in its data (RFC 4486 §4), drops every route the neighbor sent
(none of the UPDATE that crossed the limit is passed on), and logs an
error. Counted are the routes the RIB keeps: those that passed the AS loop
check and the import policy, which is what `show neighbor` reports as
received, and the routes it holds for their validation state (see
**RPKI** below), so that a change of state never moves the count. Routes
the import policy rejects whatever their state are not kept and not
counted, as with FRR's `maximum-prefix` and BIRD's `import limit`. The
limit must be at least 1 and its family one of the neighbor's `families`.
The neighbor then restarts like after any other damped failure, so a peer
that keeps sending too many routes is retried `restart-limit` times and
then left Idle; `restart-limit 0` leaves it Idle at once.

`restart-limit` bounds the automatic restarts after failures, as RFC 4486
§4 asks. Some failures damp the restart (RFC 4271 §8.2.2): a NOTIFICATION
we send for an error, an expired timer or a local stop such as an output
queue overrun or a `maximum-prefix`; a NOTIFICATION received, or the
connection lost after the OPENs were exchanged, before the session is up;
and a Cease received while Established with Administrative Shutdown, Peer
De-configured, Connection Rejected or Out of Resources (RFC 4486 §4). Each
holds the neighbor Idle for 10 seconds, doubling with each such failure in
a row up to 120 seconds. After `restart-limit` restarts in a row, the next
such failure leaves the neighbor Idle, refusing connections, until
`bgpfcctl clear neighbor`, or a reload that resets it, starts it again; the
daemon logs an error when that happens. A manual start ends the run of
failures, and so does a session that stayed up for five minutes; a session
torn down soon after it comes up keeps counting. A refused or timed-out
connection does not damp: a neighbor that is simply down is retried without
bound. Nor do the operator's own stops and resets, or a connection that
loses a collision (RFC 4271 §6.8), after which the session goes on with the
other one; neither counts toward the limit or ends a run. `0` never
restarts after a damped failure; `off` always does.

**RPKI.** The `rpki` block says where the Validated ROA Payloads (VRPs)
come from that give every route its RFC 6811 origin validation state
(`docs/control.md`, "Validation state"), and what that state does.
Without the block, or with `mode disabled`, there are none and every route
is `disabled`. The block must state its `mode`; nothing else implies one.
`mode external` takes the VRPs over the RPKI-to-Router protocol (RTR) from
the caches listed with `cache`, of which there must be at least one. `mode
sidecar` takes them over RTR from Routinator, which bgpfcd runs and
supervises itself (see **The Routinator sidecar** below). `mode disabled`
keeps the cache list and the `sidecar` block but uses neither, so that
turning validation off is a one-word change (issue #60).

`mode external` and `mode sidecar` are the statements that turn origin
validation on, and each means: validate every route against the VRPs, and
act on the result as `enforcement` says, `drop-invalid` unless the block
says otherwise. `enforcement` is one of:

- `drop-invalid`, the default. A route whose state is Invalid is *held*:
  it stays in the Adj-RIB-In, counted as received, but it is no candidate
  for route selection, so it is neither installed nor advertised. As soon
  as its state is no longer Invalid it is used again, without an UPDATE or
  a route refresh. This is RFC 6811 §5's "rejecting all "invalid" routes",
  the default the project ships with (issue #61).
- `prefer-valid`. No route is held for its state. Route selection prefers
  Valid routes to `not-found` (and `disabled`) ones, and those to Invalid
  ones, before anything else, LOCAL_PREF included: RFC 6811 §5's
  "adjusting a route's degree of preference in the selection algorithm
  based on its validation state". An Invalid route is used only when the
  destination has no other.
- `off`. Nothing acts on the state: it is shown, but neither whether a
  route is used nor which route is chosen depends on it (RFC 8481 §5,
  "Set State, Don't Act").

RFC 6811 §2: "An implementation MUST NOT exclude a route from the
Adj-RIB-In or from consideration in the decision process as a side effect
of its validation state, unless explicitly configured to do so." bgpfcd
keeps every route in the Adj-RIB-In whatever its state, and takes one out
of route selection for its state only where the file says so: by `mode
external` or `mode sidecar`, whose meaning includes `enforcement
drop-invalid` as above, by an `enforcement` statement, by `startup hold`,
or by an import policy that matches or sets the state (`match rpki`, `set
rpki`). Without
an `rpki` block, or with `mode disabled`, no route is validated, and no
`enforcement` holds a `disabled` route; only an import policy that matches
or sets the state can, such as one that rejects on `match rpki not-found`
(see `match rpki` above).
`enforcement` is accepted with `mode disabled` too, and then applies only
to a state an import policy sets: `set rpki invalid` holds the route under
`drop-invalid`. RFC 8481 §5 is stricter: "Absent specific operator
configuration, policy MUST NOT be applied." bgpfcd's default departs from
it, as the project chose (issue #61); `enforcement off;` gives the RFC 8481
§5 behaviour.

`startup` says what becomes of the routes while validation waits for its
first data, in the startup window (see **Startup window** below), when
no route has a state yet and every one is `disabled`:

- `accept`, the default. They are used as received, and `enforcement`
  acts once the first full set of VRPs has given them a state.
- `hold`. They are held as `drop-invalid` holds an Invalid route: kept
  in the Adj-RIB-In, counted as received and held, and neither installed
  nor advertised, until the first full set gives them a state; then
  `enforcement` acts on it, and a route it admits is used without an
  UPDATE or a route refresh.

The names are bgpfc's own words for what becomes of a route: import
policy's `accept` lets it be used, and a *held* route is what `show
routes held` lists. `startup` applies with `mode external` and `mode
sidecar`; with `mode disabled` no data will come, and it holds nothing.

Each route goes through these steps in order:

1. The checks that make a route unusable whatever the policy, such as an
   AS_PATH holding our own AS (RFC 4271 §9.1.2). A route that fails them is
   not kept.
2. The lookup gives the route its state from its AS_PATH as received (RFC
   6811 §2).
3. The import policy accepts the route, possibly with other attributes,
   or rejects it. It may match the state, and set the state the route is
   used with from then on (`set rpki`).
4. `startup hold` holds a route used with state `disabled` while
   validation waits for its first data; otherwise `enforcement` acts on
   the state the route is used with, the one import policy set or else the
   one the lookup gave: `drop-invalid` holds an Invalid route. So `set rpki valid` in an import policy wins over
   `drop-invalid`, and `match rpki invalid; action reject;` rejects in
   every mode.
5. The Adj-RIB-In keeps the routes the import policy accepted and the ones
   held for their state: by `startup` or `enforcement`, or because the
   import policy rejects them only in their current state, which it would
   accept in another. A route the import policy rejects whatever its state
   is not kept: a reload that changes the policy asks the neighbor for it
   again (see **Reload**).
6. Route selection among the routes not held, ranking by state first under
   `prefer-valid`.
7. The export policy of each neighbor, which sees the state the route is
   used with, the rewriting of RFC 4271 §5.1, and the neighbor's
   `advertisement-interval`.

A reload that changes a neighbor's import policy puts every route of the
neighbor the Adj-RIB-In keeps, held or not, through steps 3 to 7 again,
with the state it has (see **Reload**).

When the VRPs change, the routes whose state they change go through steps
3 to 7 again (RFC 6811 §4: "When a mapping is added or deleted, the
implementation MUST re-validate any affected prefixes and run the BGP
decision process if needed"). Under `drop-invalid`, a used route that
becomes Invalid is withdrawn from the neighbors and the kernel, and a held
route that is no longer Invalid is used again, installed and advertised
when it is the best route, with no UPDATE from its neighbor.

A change of state reaches the neighbors through the same pacing as a
change an UPDATE brings (`advertisement-interval` above), and no other
limit applies. A destination is advertised again to a neighbor at most
once per interval, a withdrawal goes out at once and does not end the
interval, and a first advertisement is never held. So VRPs that keep
changing, such as two caches with different data taking turns, send a
neighbor at most one announcement and one withdrawal of a destination per
interval. A route that becomes Invalid under `drop-invalid` is withdrawn
at once: holding the withdrawal back would keep propagating what
enforcement exists to stop. A large change, such as expiry releasing every
held route, goes out at once, many prefixes to an UPDATE; its size is that
of the change, and RFC 6811 §4 asks for it.

VRPs that expire (`max-expire` below) leave no data, so every route
becomes `not-found` and every route `drop-invalid` held is used again:
validation fails open. RFC 8210 §6 forbids keeping them ("The router MUST
NOT retain the data past the time indicated by this parameter"), and the
expiry is logged as an error.

> **Keep the cache on the router or on a trusted network.** RTR runs over
> plain TCP to port 323: nothing authenticates the cache to bgpfcd or
> protects the VRPs on the way, so whoever can reach the session can change
> which routes are `invalid`. RFC 8210 §9: "If unprotected TCP is the
> transport, the cache and routers MUST be on the same trusted and
> controlled network." Run the cache on the router itself (`cache
> 127.0.0.1;`) or on a network only trusted hosts can reach, and filter
> port 323 there. The protected transports of RFC 8210 §9 (SSH, TLS,
> TCP-MD5, TCP-AO) are not supported.

`cache` names a cache by address or host name, with its TCP `port`, 323
(rpki-rtr, RFC 8210 §9) unless given, and its `preference`, lower values
first (RFC 8210 §10); caches of equal preference are tried in file order.
bgpfcd uses one cache at a time: the first in that order that answers.
After a failure it tries the next, wrapping round to the first; when a
cache it was in sync with goes away, it starts again from the first. In
sync with a cache while more preferred ones are listed, it tries those
again every Retry Interval the cache in use gives (600 seconds unless it
says otherwise), and moves to the first that accepts a connection, so
that a preferred cache that comes back after an outage takes its load
back (RFC 8210 §4). The VRPs from the last cache stay in use until another
cache has sent a full set, which replaces them, or until they expire (RFC
8210 §10, §6). A cache listed twice, by the same address or the same name
in any case, and the same port, is an error.

**When caches disagree.** bgpfcd validates with the VRPs of exactly one
cache at a time: the most preferred cache it is in sync with (RFC 8210 §4:
the router "MUST choose the most preferred, by configuration, cache or set
of caches"). It never merges data from several caches and never weighs one
cache's data against another's: RFC 8210 §10 says a preference "merely
denotes proximity, not trust, preferred belief, et cetera". So two caches
that disagree about a ROA never make bgpfcd mix their answers. While the
preferred cache answers, its data decides. When it goes away, its last
VRPs stay in use until a less preferred cache has sent a full set (§10:
"it SHOULD retain the data from the previous cache until it has a full set
of data from one or more other caches") or until they expire (§6). Then
the other cache's set replaces them as a whole, and only the routes the two
sets judge differently are validated again. Those moves are VRP changes
like any other: they go through `enforcement` and route selection as
described above. When a more preferred cache comes back, bgpfcd moves to it
the same way once it has sent its full set. To have the caches agree, point
them at the same RPKI repositories with the same relying-party settings; a
difference between them then shows up only as routes that change state at
each move from one cache to the other.

A cache that restarts usually starts a new session, with a new Session ID
(RFC 8210 §5.1). bgpfcd resumes with a Serial Query from its last data
(§8.1), which such a cache should answer with an Error Report or a Cache
Reset, after which bgpfcd loads the cache's data afresh. StayRTR 0.5.1 sends
its Error Report but closes the connection at the same time, so the report
is sometimes lost; bgpfcd then sees only the close and, like BIRD, keeps its
VRPs and asks again until the report gets through, the VRPs expire, or
another cache answers. List a second cache to have bgpfcd move on to it.

`version 1`, the default, offers RTR version 1 (RFC 8210) and falls back to
version 0 (RFC 6810) for a cache that answers in version 0 (RFC 8210 §7);
`version 0` starts with version 0, for a cache that mishandles version 1.
The timeouts are in seconds, each at least 1. `connect-timeout` bounds a
connection attempt, the name lookup included where the resolver allows;
a reload or a shutdown never waits for an attempt to end.
`response-timeout` bounds the wait for the cache to start answering a
query, and between two PDUs of an answer; it must be at least
`connect-timeout`. `reply-timeout` bounds a whole answer, from the query to
its End of Data, and must be at least `response-timeout`. A cache that
breaks one of them is dropped and the next one tried.

Between queries a connection in sync is idle, an hour by default (the
cache's Refresh Interval), so bgpfcd turns TCP keep-alive on for every
connection to a cache, in both modes (RFC 8210 §9: routers "SHOULD enable
keep-alives when available"). `tcp-keepalive` says how the kernel probes
it (`tcp(7)`): after `idle` seconds without a segment it sends a probe,
then one every `interval` seconds while none is answered, and drops the
connection after `count` unanswered probes. A cache that vanished without
closing the connection, by a crash or a network that drops its packets,
is then noticed within `idle` + `interval` × `count` seconds, and bgpfcd
moves to the next cache or reconnects, rather than at the next query an
hour on. Each option may be given once, in any order; one left out keeps
its default, and the defaults, `idle 60 interval 10 count 6`, notice a
dead cache within two minutes: the first probe comes after the same
minute as Routinator's on its end (`--rtr-tcp-keepalive`), and a minute of
unanswered probes rides out a short loss on the trusted network RTR needs.
`tcp-keepalive count 3;` gives up after half a minute of silence instead.
The bounds are the kernel's, which refuses anything else: `idle` and
`interval` from 1 to 32767 seconds, `count` from 1 to 127
(`MAX_TCP_KEEPIDLE`, `MAX_TCP_KEEPINTVL` and `MAX_TCP_KEEPCNT` in its
`include/net/tcp.h`). Keep-alive acts only on an idle connection: while a
query is unanswered, `response-timeout` finds a dead cache instead. Should
the kernel still refuse the options, the connection is used without
keep-alive, with a warning.

`max-expire` is the longest bgpfcd keeps using VRPs it cannot refresh.
The cache's Expire Interval applies when it is shorter (RFC 8210 §6: "The
router MUST NOT retain the data past the time indicated by this
parameter"), so the setting can only shorten it; it lies in 600–172800, the
range §6 gives the Expire Interval, and the default leaves the cache's
value. When the data expires, every route becomes `not-found`; with `mode
sidecar` that means Routinator has not answered for the Expire Interval
(7200 seconds, unless `server-args` or `max-expire` say otherwise), as
when it keeps failing (`docs/control.md`, "RPKI"). `max-vrps`,
at least 1, is the most VRPs an answer may leave bgpfcd holding; an answer
that would exceed it is refused with an Internal Error (RFC 8210 §12) and
the data before it stays in use. The default, four million, is several
times what the whole RPKI holds.

With `mode external`, bgpfcd looks every cache up as it starts and
refuses to start, naming the cache, if one has no address: a typo must not
leave every route unvalidated without a word (issue #60). `bgpfcd --check`
looks nothing up; it judges the file alone, wherever it runs. The client
looks a name up again at every connection attempt, so a cache whose address
changes is followed. It starts before the neighbors, and every route is
`disabled` until a cache has sent its VRPs; from then on the states follow
the cache's data. A route that arrives before then is therefore used, as
no `enforcement` holds a `disabled` route, and withdrawn once the VRPs
make it Invalid; under `startup hold` it is held until they give it a
state, and an import policy that rejects on `match rpki not-found` holds
it until they give it a state it accepts. A
cache on the router or near it answers well before a BGP session comes up,
so this window is normally empty (see **Startup window** below); BIRD
and FRR behave the same way. The
client logs with the rest of the daemon, at the `log` level: losing a cache
is a warning, its return an info line, and VRPs that expire before a cache
could refresh them an error.

`backoff MIN MAX` paces reconnects. After a connection attempt fails, a
connection ends before the cache has brought bgpfcd in sync, or a cache
answers No Data Available, bgpfcd waits MIN seconds, doubling with
each such failure in a row up to MAX, and then up to half as long again,
by a jitter seeded from the `router-id`, so that routers that lost a cache
together do not return together. Each bound lies in 1–7200, the range of
the Retry Interval it stands in for, and MAX must not be below MIN. RFC
8210 §6 says a router SHOULD NOT retry sooner than the cache's Retry
Interval, 600 seconds by default; bgpfcd's default, `backoff 1 600`, does,
so that a validator that restarts is picked up within seconds (issue #57),
and reaches 600 seconds by the eleventh failure in a row. `backoff 600
600` keeps to the RFC's default. With `mode sidecar` the default is
`backoff 1 30`: the cache is bgpfcd's own child on loopback, which starts
to listen only once its first validation run has ended, minutes after it
starts from a cold repository, and the client should not then wait
minutes more to try it. With `1 600`, a client that starts with a cold
Routinator would have backed off to about 511 seconds by the time
Routinator listens, and could find it up to about 15 minutes later; with
`1 30` it finds it within about 45 seconds. Each attempt costs a SYN and a
RST on loopback and one warning line, about 25 lines over a ten-minute
cold start. This departs further from the Retry Interval of RFC 8210 §6,
for a cache that is the router's own child; write `backoff` to choose
otherwise.

**The Routinator sidecar.** With `mode sidecar`, bgpfcd runs Routinator,
the RPKI relying-party software of NLnet Labs, as a child process: it
derives Routinator's command line from the `sidecar` block, restarts it
with a back-off when it fails, and stops it when bgpfcd stops (issues
#26, #70). Its RTR client then has exactly one cache, the loopback address
Routinator serves RTR on (issue #71), so `cache` is an error with this
mode; and a `sidecar` block is an error with `mode external`, where it
would never run. The other statements of the `rpki` block apply to that
one session as they apply to an external cache: `enforcement`, `version`,
the timeouts, `max-expire`, `max-vrps`, `backoff` and `tcp-keepalive`. Routinator is a
separate program that bgpfc neither bundles nor links; bgpfcd needs
Routinator 0.15.x, and is tested with 0.15.3.

The smallest file that validates every route:

```
router-id 192.0.2.1;
local-as 65000;
policy ANY { term all { action accept; } }
neighbor 198.51.100.1 { remote-as 64511; import ANY; export ANY; }
rpki { mode sidecar; }
```

The host needs Routinator 0.15.x at `/usr/bin/routinator`, with `rsync`
on `PATH`, `/var/lib/bgpfc` writable by the user bgpfcd runs as (the
unit's `StateDirectory=bgpfc`), and outbound access to the RPKI
repositories. It validates with the trust anchors (TALs) of the Regional
Internet Registries except ARIN's; `sidecar { accept-arin-rpa yes; }`
adds ARIN's. The import and export policies are what every neighbor
needs, not RPKI configuration.

Routinator runs as the user bgpfcd runs as, with no capabilities: it
fetches and parses data from the internet. bgpfcd starts it only after it
has opened its privileged sockets and dropped root (README, "Run", Option
B), and clears the ambient capabilities it holds itself (Option A) from
Routinator's. A child of root would get every capability whatever bgpfcd
holds, so with `mode sidecar` bgpfcd refuses to start as root without
`--user` (`mode sidecar would run Routinator as root`). For the same reason
`rtr-listen` takes a port of 1024 or more, or 0, and the repository
directory must be writable by that user: bgpfcd creates it, with the
parents it lacks, mode 0750, before it starts Routinator.

At start, after the privilege drop and before any neighbor starts,
bgpfcd creates the repository directory, runs `routinator --version`,
which must name a 0.15 release within ten seconds, binds the `rtr-listen`
address with port 0 and closes it again, which picks the RTR port if
`rtr-listen` leaves it at 0, and starts Routinator; then its RTR client
connects to Routinator's address. If one of these steps fails (a binary
that is missing, does not run or is another release, an `rtr-listen`
address this host cannot bind, such as `::1` without IPv6, or a
repository directory that cannot be created), bgpfcd logs `cannot start
rpki` with the reason and exits with status 1 (issue #60: fail loudly and
early).
Routinator's standard output is logged at info and its standard error,
where it writes its warnings, at warn, each line with
`sidecar=routinator`. When bgpfcd stops, right after the Ceases, it
stops its RTR client, then Routinator: `SIGTERM`, and `SIGKILL` after
`stop-timeout`, while it removes its routes from the kernel. From then on
it starts no Routinator again, even one that exits meanwhile (issue #70).
If bgpfcd dies without stopping it, the kernel kills Routinator too
(`PR_SET_PDEATHSIG`), but not what Routinator started, such as an `rsync`
under way: the death signal is not passed on to a child's children, and
Routinator's process group, which bgpfcd kills when it reaps Routinator,
is never killed by a bgpfcd that was killed itself. Such a process runs
on, in the repository directory the next Routinator uses, until it ends or
times out. Under systemd, `KillMode=mixed` (`contrib/bgpfcd.service`) kills
it with the rest of the service once bgpfcd is gone; under another
supervisor, have it kill bgpfcd's whole process tree or control group when
bgpfcd dies. A Routinator that bgpfcd stops, or that exits by itself,
takes its process group along.
Nothing else in bgpfcd reaps child processes, which is what lets the
sidecar keep track of its own.

**Who serves the sidecar's port.** Loopback keeps other hosts away from
the RTR port, not other processes on this one. Routinator binds the port
only once its first validation run ends, minutes after a cold start and
again after each restart, and until then any local process may bind it,
picked or fixed alike: the port is on Routinator's command line for
anyone to read. So bgpfcd's RTR client uses a connection to the sidecar
only if the socket at its other end belongs to bgpfcd's own user, as
Routinator's does, by the kernel's socket tables (`/proc/net/tcp`,
`/proc/net/tcp6`). A process of another user that holds the port is
refused before a byte is exchanged, each attempt logged as `rtr cache
connection failed` with `error="127.0.0.1:PORT is served by uid N, not by
uid M as bgpfcd is: another process holds the port"`, the last of them in
`show rpki`; its VRPs never reach the RIB, and the routes keep the states
they had (`disabled`, while validation waits). Routinator, finding the
port taken, fails to start, and its failures raise the alarm (issue #70).
The check tells users apart and nothing finer, so it is only as strong
as the user bgpfcd runs as. A process that runs as bgpfcd's own user is
not told apart: it could change Routinator's repository and
configuration anyway. Root, which can make a socket as any user, can
pass it too. Run bgpfcd as a user of its own, not as one other daemons
share, such as `nobody`, and keep untrusted code off that user. In a user
namespace the kernel's socket tables show every user the namespace does
not map as the overflow user (`/proc/sys/kernel/overflowuid`, 65534,
`nobody`), so a bgpfcd that runs as that user there, or in a namespace
with no user map at all, where it is that user itself, takes every
process of an unmapped user, root's included, for its own: give it a
mapped user of its own there too. Without `/proc` no connection to the
sidecar is used. For these reasons COMPLIANCE.md marks the RFC 8210 §9,
§13 requirement (cache and router on a trusted, controlled network)
`partial` with `mode sidecar`.

bgpfcd says so where it applies. With `mode sidecar`, each time it starts
Routinator, at startup and at a reload that starts it, it logs a warning,
`rpki sidecar: the owner check of Routinator's port is weaker here;
starting anyway`, with its `uid` and the `reasons`, when

- it runs as the overflow user (`/proc/sys/kernel/overflowuid`, 65534
  unless the kernel says otherwise),
- it runs as the user called `nobody` in `/etc/passwd`, or
- it runs in a user namespace, one whose `/proc/self/uid_map` is not the
  identity map, `0 0 4294967295`.

It starts Routinator all the same: the check still refuses every user it
can tell apart from bgpfcd's own. `bgpfcd --check` prints the same
warning on standard error, at the `mode sidecar` statement or the
`sidecar` block, for the user `--user` names, or else the user it runs
as, and still reports the file ok.

**Startup window.** Until the RTR client's first full set arrives there
are no VRPs, and every route is `disabled`: shown so, not as `not-found`.
With an external cache on the router or near it, the window is normally
too short to matter. With the sidecar it is long: Routinator opens its
RTR listener only once its first validation run has ended, minutes after
it starts from a cold repository directory, less from a warm one. bgpfcd
does not wait for it to bring the neighbors up: they come up at once.
What becomes of their routes meanwhile is the block's `startup`:

- `startup accept`, the default: the routes are used as received,
  unvalidated, since no `enforcement` acts on `disabled`. When the first
  set arrives, every route is validated (RFC 6811 §4) and `enforcement`
  acts on the result, so that under `drop-invalid` the Invalid routes are
  then held and withdrawn from the neighbors and the kernel. Holding every
  route until then without being told to is what RFC 6811 §2 forbids
  ("MUST NOT exclude a route from the Adj-RIB-In or from consideration in
  the decision process as a side effect of its validation state, unless
  explicitly configured to do so"), and on a transit router it would
  black-hole the whole table for the minutes of a cold start after every
  reboot; BIRD and FRR converge the same way.
- `startup hold`: that explicit configuration. Every route is held until
  the first set arrives, kept in the Adj-RIB-In and counted, but neither
  installed nor advertised; `show routes held` lists each as `held by
  startup`. When the set arrives every route is validated and judged
  again, with no UPDATE or route refresh: under `drop-invalid` the Valid
  and `not-found` routes are used and the Invalid ones stay held, now by
  `enforcement`; under the other modes all of them are used. Routes that
  arrive later are validated on arrival and never held for the startup,
  and a route whose import policy sets a state with `set rpki` is used
  with that state and not held either. It suits a router that must never
  install or pass on a route that was not validated, and that can do
  without its BGP routes for as long as the cache takes; with the sidecar
  from a cold repository, that is minutes after every start.

VRPs that expire give `not-found`, not `disabled`, so `hold` holds routes
before the first set only, not after the data expires (see `max-expire`:
validation then fails open). With validation off, `mode disabled` or
after a reload that could not start Routinator or the client, no set will
come, and `startup` holds nothing: every route is `disabled` and used.

The window is not silent (issue #71). When a client starts with no data
to hold, bgpfcd logs `rpki: no validation data yet; routes are used
unvalidated until the first full set`, or under `startup hold` `rpki: no
validation data yet; routes are held until the first full set (startup
hold)`, with the mode, the `enforcement` and the `startup`: at warn with
`mode sidecar`, with a hint about Routinator's first run, or with `startup
hold`, and at info with `mode external` and `startup accept`, whose
window is normally a moment. When the first set arrives it logs `rpki:
validation data arrived; routes are validated from now on` with
`waited=`, the seconds the routes waited; the RIB's `rib: validation
states changed` line follows, with the routes held and released.
Meanwhile `show rpki` says `validation waiting Ns for the first full set`
with what becomes of the routes (`docs/control.md`, "RPKI"), and `show
status` `validation waiting`. A reload from `mode disabled` opens the
window again, and under `startup hold` holds every route until the first
set. A reload that restarts the client does not, since the data in use
stays in use until the new set arrives.

An import policy can hold the routes of some neighbors only, in the same
way, with a first term:

```
policy UPSTREAM-IN {
    term unvalidated { match rpki disabled; action reject; }   # held until the first full set
    ...
}
```

During the window each such route is then held by policy (`show routes
held`), and none is used. When the first set arrives they are judged
again, as under `startup hold`. Unlike `startup hold`, such a term also
holds every route for good with `mode disabled`.

The `sidecar` block takes these statements, each at most once:

- `binary`: the Routinator executable, an absolute path,
  `/usr/bin/routinator` unless given. bgpfcd never searches `PATH` for it
  (issue #70).
- `repository-dir`: where Routinator keeps the RPKI data it fetches, an
  absolute path, `/var/lib/bgpfc/rpki` unless given.
- `rtr-listen ADDRESS [port N]`: where Routinator serves RTR to bgpfcd. The
  address is a loopback address, `127.0.0.1` or `::1`, so that nothing off
  the host can reach the unprotected RTR socket (issue #71; RFC 8210 §9);
  `::ffff:127.0.0.1` is refused, write `127.0.0.1`. Port 0, the default,
  has bgpfcd pick a free port each time it starts the sidecar; any other
  port lies in 1024–65535, since Routinator runs without capabilities and
  could not bind a lower one. The default is `127.0.0.1 port 0`. See
  **Who serves the sidecar's port** below.
- `rir-tals yes|no`: whether the production TALs of the five RIRs are
  used, ARIN's only with `accept-arin-rpa yes`; `yes` unless given.
- `tals NAME...`: further TALs Routinator 0.15 bundles, by name:
  `afrinic`, `apnic`, `arin`, `lacnic`, `ripe`, `apnic-testbed`,
  `arin-ote`, `ripe-pilot` and `nlnetlabs-testbed`. With `rir-tals no`,
  naming RIR TALs here picks some of them. `arin` needs `accept-arin-rpa
  yes`.
- `extra-tals-dir PATH`: a directory whose `.tal` files (RFC 8630)
  Routinator uses as well, an absolute path. bgpfcd does not read it: what
  it holds is up to the operator, ARIN's TAL included.
- `accept-arin-rpa yes|no`: whether the operator accepts ARIN's Relying
  Party Agreement, the terms under which ARIN publishes its TAL; `no`
  unless given. Without it ARIN's TAL is left out, and routes in ARIN's
  address space are `not-found`. Accepting an agreement is the operator's
  decision, so bgpfcd does not make it by default.
- `refresh N`: the seconds between Routinator's validation runs, which it
  also announces as its Refresh Interval (RFC 8210 §6); 1–7199, below the
  Expire Interval of 7200 seconds Routinator announces; 600 unless given.
  Routinator announces a Retry Interval of 600 seconds and that Expire
  Interval, so the default `max-expire` leaves 7200 seconds; Routinator's
  own `--retry` and `--expire` can be set with `server-args`.
- `config-file PATH`: a Routinator config file, an absolute path, for
  settings the block does not model; passed as `--config`. See below for
  what it must not set.
- `global-args ARG...` and `server-args ARG...`: the escape hatch (issue
  #72). The arguments are passed to Routinator as written, after bgpfcd's
  own: `global-args` before Routinator's `server` command, `server-args`
  after it. Quote an argument that holds whitespace, `;`, `{`, `}`, `"` or
  `#`. bgpfcd refuses an option it sets itself or that would defeat
  supervision or the loopback rule: `--config`, `--repository-dir`,
  `--no-rir-tals`, `--tal`, `--extra-tals-dir`, `--rtr`, `--rtr-tls`,
  `--systemd-listen`, `--refresh`, `--detach`, `--user`, `--group`,
  `--help` and `--version`, and the short forms `-c`, `-r`, `-d`, `-h` and
  `-V`.
- `restart-backoff INITIAL CAP`: after Routinator fails, bgpfcd waits
  INITIAL seconds before starting it again, doubling with each failure in
  a row up to CAP, and shortened by up to half by a jitter. Each lies in
  1–3600, and CAP must not be below INITIAL; `1 300` unless given.
- `stable-after N`: how many seconds Routinator must run for its next
  failure to count as a first failure again; 1–86400, 300 unless given.
- `stop-timeout N`: how many seconds Routinator gets to stop after
  `SIGTERM` before bgpfcd kills it; 1–3600, 10 unless given.
- `failure-threshold N`: after this many failures in a row the sidecar is
  reported as failed, an alarm (`sidecar FAILED` in `show rpki`, `alarm
  rpki sidecar failed` in `show status`; `docs/control.md`, "Alarms"),
  while bgpfcd keeps trying at the back-off's cap (issue #70); at least
  1, 5 unless given.

With `mode sidecar`, bgpfcd also checks the block as Routinator would take
it, and reports a problem at the block's position like any other error:
an unknown TAL name, `arin` without `accept-arin-rpa yes`, TAL settings
that leave no trust anchor, or a reserved option in `global-args` or
`server-args`. It does so with `--check` too, without running anything.
With `mode disabled` the block is only read.

A Routinator config file (`config-file`) is trusted operator input:
bgpfcd passes it on and does not read it. The command line bgpfcd builds
overrides the file's `repository-dir`, `rtr-listen` and `refresh`, its
`tals` only when the block selects at least one bundled TAL (`rir-tals
yes`, the default, or a `tals` statement), and its `extra-tals-dir` only
when the block sets `extra-tals-dir`; whatever else the file sets applies.
So the file must not set:

- `rtr-tls-listen`, which would serve RTR over TLS on any address,
  outside the loopback rule;
- `systemd-listen`, since bgpfcd passes Routinator no sockets, so every
  start would fail;
- `user` or `group`, since Routinator would switch to them itself, which
  clears the signal that ends it when bgpfcd dies;
- `tals` while the block selects no bundled TAL (`rir-tals no` and no
  `tals`), or `extra-tals-dir` while the block sets none: those would add
  trust anchors the block does not show, ARIN's whatever
  `accept-arin-rpa` says;
- `log` or `log-file` away from standard error, unless Routinator's
  messages are wanted out of bgpfcd's log.

Routinator 0.15 also wants such a file to set `repository-dir`, although
the command line overrides it.

**Route selection.** Of the routes to a destination that the import
policy accepted and that are not held, for their validation state (see
**RPKI**) or for a next hop that does not resolve (see **Next hops**
below), bgpfcd uses one, chosen by removing routes from consideration in
this order until one is left (RFC 4271 §9.1.2.2: "The criteria MUST be
applied in the order specified"; issue #47):

1. Under `enforcement prefer-valid` only, the validation state the route is
   used with: Valid, then `not-found` and `disabled`, then Invalid (RFC
   6811 §5).
2. The highest degree of preference: LOCAL_PREF, 100 for a route without
   one (RFC 4271 §9.1.1).
3. §9.1.2.2 a): the shortest AS_PATH, an AS_SET counting as one AS.
4. b): the lowest ORIGIN, IGP before EGP before INCOMPLETE.
5. c): among the routes from the same neighboring AS, the lowest
   MULTI_EXIT_DISC, a route without one counting as 0. Only the routes
   still under consideration count: a route an earlier step removed takes
   no other out, however low its MULTI_EXIT_DISC.
6. d): routes from external neighbors over routes from internal ones.
7. e): the lowest interior cost to the next hop. bgpfcd runs no IGP, and
   does not take the metric of the kernel route a next hop resolves
   through for one, so every route ties, as with BIRD and FRR when they
   know no IGP metric.
8. f): the lowest BGP Identifier of the neighbor.
9. g): the lowest neighbor address.

Steps 2 to 9 are RFC 4271's, unchanged. `prefer-valid` puts the state
first, as the most significant part of the degree of preference that RFC
4271 §9.1.1 lets local policy compute: below LOCAL_PREF, a forged origin
heard from a customer, whose routes usually have the highest LOCAL_PREF,
would still beat the Valid route from a transit provider, which is the
case the mode exists for. Cisco IOS XE and XR and Nokia SR OS place their
comparison of the state there too. The state travels to no other router,
though (bgpfcd does not implement RFC 8097, the extended community that
would carry it): RFC 4271 §9.1.1 wants an external route's degree of
preference sent to internal neighbors as its LOCAL_PREF, and RFC 6811 §5
notes that a preference no attribute carries may need the state propagated
for routing to stay correct. With internal neighbors, either run
`prefer-valid` on every router of the AS with the same caches, or fold the
state into LOCAL_PREF by policy, which does reach them.

The other common behaviours are policies:

- The state as a LOCAL_PREF, as Juniper, FRR and BIRD do it, which
  internal neighbors see and the operator weighs against their own tiers:
  `enforcement off;` and an import policy such as
  `term v { match rpki valid; set local-pref 110; action next; }
  term i { match rpki invalid; set local-pref 90; action next; }
  term rest { action accept; }`. To break ties within each commercial tier
  only, use offsets inside it, such as 200, 199 and 198 for customers and
  100, 99 and 98 for transit.
- Invalid routes held, and Valid ones preferred to `not-found` ones:
  `enforcement drop-invalid;` and `match rpki valid; set local-pref ...;`.
- Invalid routes rejected from some neighbors only: `enforcement off;` and
  `match rpki invalid; action reject;` in those neighbors' import policies.
  Such routes are held for their state too (see **RPKI** above), so they
  are used again once they are no longer Invalid.

**Next hops.** RFC 4271 §9.1.2 takes out of route selection a route
whose NEXT_HOP cannot be resolved ("the BGP route MUST be excluded from
the Phase 2 decision function"), and issue #47 makes routes with an
unreachable next hop ineligible. bgpfcd resolves every next hop in the
kernel's main routing table, the routes that connected networks, static
routes and an IGP daemon put there, which a thread of its own reads
whole at startup, before any route is judged, and then follows through
the kernel's notifications (`docs/control.md`, "Next hops"):

- The next hop resolved is the one the route is used with, after import
  policy, so that `set next-hop self` on import counts. Of an IPv6 next
  hop it is the global address; a link-local address the neighbor sends
  after it (RFC 2545 §3) is neither resolved nor installed, as with
  BIRD's `next hop prefer global`. An IPv4 route with an IPv6 next hop
  (RFC 8950) resolves in the IPv6 routes.
- It resolves through the longest matching route ("only the longest
  matching route SHOULD be considered", RFC 4271 §9.1.2.1), and among
  routes to the same prefix through the one of lowest metric, as the
  kernel does.
- Never through a route of bgpfcd's own, those that carry the `fib {
  protocol }` number, so never through another BGP route, and never
  through a default route (`0.0.0.0/0`, `::/0`): FRR's defaults, as
  without `resolve-via-default`. A next hop only such a route covers
  does not resolve. So no route resolves through itself or through
  another that resolves through it (the mutual recursion of RFC 4271
  §9.1.2.1), and installing a route never changes what a next hop
  resolves to. A blackhole, unreachable, prohibit or throw route resolves
  nothing, and hides a less specific route as in the kernel.
- Only the main table counts, whatever `fib { table }` says: policy
  routing rules and VRFs are not looked at. A route of another program
  with bgpfcd's protocol number is taken for bgpfcd's own.

A route whose next hop does not resolve stays in the Adj-RIB-In, counted
as received and held, but is no candidate, so it is neither installed nor
advertised: `show routes` marks it `next hop unresolvable`. A route held
for its validation state shows that reason whatever its next hop, since
the RPKI rules come first; once they admit it, its next hop is checked.
When its next hop resolves again, it is a candidate again at once, with
no UPDATE from the neighbor and no run of import policy.

With `fib { mode install; }` a route goes to the kernel through the hop
its next hop resolves to: the next hop itself, on the interface of the
connected route that covers it, or else the gateway and interface of the
kernel route that resolves it, the immediate next hop, as BIRD's
`gateway recursive` and FRR do. The interface is always given, so that a
next hop that comes back through another interface is installed again
through it. Dry-run mode resolves the same way and installs nothing.

A change of the kernel's table decides again only the destinations with a
route through a next hop whose resolution it changed, however large the
table, and is one line at info, `rib: next hops changed`, never a line a
route (`docs/control.md`, "Next hops"). A next hop that no longer resolves
takes its routes out of use: each destination then uses its next best
route, or its route is withdrawn from the kernel and from the neighbors at
once. When the next hop resolves again they are installed again at once,
and announced again as any change is under `advertisement-interval` (see
**Neighbors**): within the interval since the prefix was last announced it
waits for the interval's end, so that a next hop that flaps costs a
neighbor at most one announcement an interval. A next hop that only moves
to another gateway or interface has its routes installed again through it
and sends no neighbor anything, since nothing a neighbor sees changed.
IPv4 removes the routes through an interface that goes down, or that loses
its address, without a notification each, so bgpfcd then reads the table
whole again: a route through an interface counts only while the interface
is up (RFC 4271 §9.1.2.1 2)). Until a new reading is whole the RIB keeps
the one it has, so neither at startup nor after lost notifications does a
next hop look unresolvable, or resolvable, for want of a table.

**Network namespace.** `netns NAME;` makes bgpfcd join the network
namespace `/run/netns/NAME`, the file `ip netns add NAME` creates
(iproute2's convention); a value that starts with `/` is a path used as
it is, such as `/proc/PID/ns/net`, the namespace process PID is in, or
`/var/run/netns/NAME`. Any other value, such as `a/b`, `..` or an empty
string, is an error. `bgpfcd --netns` overrides the statement (see
**Command line**). Without either, bgpfcd runs in the namespace it is
started in.

bgpfcd joins the namespace itself, at startup, before it opens a socket
or starts a thread, so that everything it does happens there, as if it
had been started with `ip netns exec NAME`: the BGP listeners and
sessions, the routes it installs (`fib { table }` names a table of that
namespace), the HTTP API's listener, the connections to RTR caches, and
Routinator with `mode sidecar`. The control socket is a file, so
`bgpfcctl` reaches it from any namespace. The configuration file, the
`token-file` and every other file are read as before the join: the
namespace changes the network, not the file system.

Joining needs `CAP_SYS_ADMIN` (`setns(2)`): root has it, and a bgpfcd run
as an unprivileged user needs it besides the others (README, "Run").
bgpfcd checks for it before the join, and stops with `cannot join network
namespace` and `setns(2) needs CAP_SYS_ADMIN` without it. It gives the
capability up right after the join, as root and as a user alike, so that
nothing it runs later holds it; the log says `network namespace joined`,
with the namespace's identity (`dev:inode` of its file), then
`capability dropped`. Started inside the namespace already, such as with
`ip netns exec`, bgpfcd does not join and needs no capability. Whatever
stops the join stops the start: bgpfcd never runs in another namespace
than the one it was told.

`ip netns exec` does more than join the namespace: it gives the program
a mount namespace of its own, in which `/sys` shows the namespace's
interfaces, and the files of `/etc/netns/NAME/`, typically `resolv.conf`
and `hosts`, stand in for those of `/etc`. bgpfcd does neither. It reads
nothing under `/sys` and no setting under `/proc/sys/net`, and the
socket tables it reads, `/proc/net/tcp` and `/proc/net/tcp6` for the
sidecar's port, are the namespace's. What differs is name resolution:
the host names of `rpki` caches, and Routinator's repository hosts, are
looked up from inside the namespace with the host's `/etc/resolv.conf`
and `/etc/hosts`, and a resolver on the host's loopback, such as
systemd-resolved's `127.0.0.53`, cannot be reached from there. Give the
caches by address, or use a resolver the namespace reaches.

**Validation.** After parsing, these checks run and every failure is
reported with the position of the item at fault: every `prefix-list` and
`policy` reference resolves; no neighbor is defined twice; every neighbor
has `remote-as`, `import` and `export`; no neighbor's `export` policy has
`set rpki`; the HTTP listen address is a loopback address; `netns` is a
name or an absolute path (above); timer
constraints above; `extended-next-hop` only with `ipv4-unicast` in
`families`; `maximum-prefix` only for a family in `families`; `multihop`
from 1 to 255; a `local-address` of the neighbor's family that is not
unspecified, multicast, the neighbor's own address or IPv6 link-local; an `rpki`
block has a `mode`, at least one `cache` with `mode external`, no cache
twice, `connect-timeout` ≤ `response-timeout` ≤ `reply-timeout`,
`max-vrps` at least 1, a `backoff` MAX no lower than its MIN, no `cache`
with `mode sidecar` and no `sidecar` block with `mode external`; in a
`sidecar` block, absolute paths, a loopback `rtr-listen` on port 0 or
1024–65535, `refresh` in 1–7199, `restart-backoff` bounds in 1–3600 with
CAP no lower than INITIAL, `stable-after` in 1–86400, `stop-timeout` in
1–3600, `failure-threshold` at least 1, and at least one word after `tals`,
`global-args` and `server-args`. With `mode sidecar`, bgpfcd adds the
checks of Routinator's settings described under **The Routinator
sidecar**.

**Reload.** On `SIGHUP` or `bgpfcctl reload` the file is parsed again. If
it fails, the running configuration stays and the errors are logged.
Otherwise the daemon applies the difference: new neighbors start, removed
ones stop with Cease / Peer De-configured, neighbors whose session
parameters changed (anything but `description`, `import`, `export`,
`advertisement-interval` and `maximum-prefix`; `restart-limit`,
`multihop` and `local-address` included) reset with Cease / Other
Configuration Change and start again, and
neighbors whose policies, or the prefix lists those policies use, changed
are re-evaluated without a reset. A changed `import` policy applies at
once to the routes the neighbor sent, from those bgpfcd kept (RFC 4271
§3), held ones included (see **RPKI**): each goes through the new policy
again, and what it changes is installed and advertised, or withdrawn,
with no UPDATE and no route refresh. A route an import policy rejected
whatever its validation state was not kept, so for a neighbor that had
such routes the reload also asks for them again with a route refresh
(RFC 2918), where the neighbor supports it, for the families concerned.
The neighbor then sends the whole family again, as a route refresh names
nothing finer, so with an import policy that rejects any route at all,
every change of it costs one (`docs/control.md`, "Reload"). Without the
capability they come back when the neighbor sends them again, or after
`bgpfcctl clear neighbor`. A changed `export` policy sends each neighbor
the difference, with no route refresh. A changed
`advertisement-interval` applies to the running session at once, also
without a reset. So does a changed `maximum-prefix`:
a session that already holds more routes than its new limit ends as if it
had just exceeded it, and a raised limit does not start a neighbor the old
one stopped (`bgpfcctl clear neighbor` does). A changed `router-id` or
`local-as` resets every session.

A changed `netns`, added or removed, takes effect at the next restart,
as a changed `listen` or `control` block, `fib { table }` or `fib {
protocol }` does: the reload applies everything else and its summary
says `netns changed: takes effect at the next restart; bgpfcd stays in
PATH`, PATH being the namespace bgpfcd joined, or `the namespace it was
started in`. With `--netns` the statement is overridden, so a change of
it is none. The running
daemon stays in the namespace it joined, where its sockets are: moving
would need every one of them opened again, and the `CAP_SYS_ADMIN` it
gave up. Refusing the whole reload, as for `router-id`, would hold back
the other changes for no gain.

A changed `rpki` block restarts the RTR client with the new settings. The
VRPs the old client had stay in use until a cache of the new list has sent
a full set, which then validates again only the routes it judges
differently, or until they expire (RFC 8210 §10, §6). A change to `mode
disabled` stops the client and makes every route `disabled` again. A block
that differs only in spelling, such as a default written out or a cache
written another way that names the same cache (see `cache` above), leaves
the running client alone, and so does a change to `enforcement` alone,
which the client does not use. A changed `enforcement` instead judges every
route again at once under the new mode, with the new import policies: the
routes it rules out are held, those it admits again are used, and route
selection runs for every destination, so that what changes is installed
and advertised, or withdrawn, with no UPDATE or route refresh (RFC 6811
§5). The reload summary then says `rpki enforcement MODE`. A changed
`startup` leaves the client alone as well: it acts on the routes not
validated yet, so while they wait for the first full set it holds them, or
uses them, at once, and otherwise it changes nothing until validation
waits again (RFC 6811 §2); the summary says `rpki startup SETTING`. A
reload that turns validation on with `startup hold` holds every route
until the first set (see **Startup window**), and one that turns it off
lets the held routes go before every route becomes `disabled`, so that no
route in use is withdrawn on the way. A changed `tcp-keepalive` leaves the
client alone as well, and applies to the connection in use at once, not
only to the next: bgpfcd sets the new values on it, and the kernel
restarts its keep-alive timer with them, with no new connection and no
reload of the cache's data; every later connection gets them too. The
summary says `rpki tcp-keepalive idle N interval N count N`, with `(no rtr
client runs)` when there is no connection to set them on. A new cache
whose name does not resolve fails the reload as it fails the start.

With `mode sidecar`, a reload restarts only what changed, since every
start of Routinator costs a validation run before it listens again:

- A change to the client's settings (`version`, the timeouts,
  `max-expire`, `max-vrps`, `backoff`) restarts the RTR client at the
  same address and leaves Routinator running (`rpki: rtr client
  restarted`); `tcp-keepalive` restarts neither.
- A change to the `sidecar` block stops Routinator and starts it with
  the new settings, which with `rtr-listen` port 0 picks a new port
  (`rpki: sidecar restarted`). The VRPs in use stay in use until the new
  Routinator has sent a full set, or until they expire (RFC 8210 §10,
  §6), so the routes keep their states through its first validation run.
- From `mode external`, Routinator starts and the external cache's VRPs
  stay in use until its first full set (`rpki: sidecar started`); from
  `mode disabled` it starts with nothing to hold, so the startup window
  opens again (see **Startup window**).
- To `mode external`, Routinator stops after the client, and its VRPs stay
  in use until an external cache has sent a full set (`rpki: rtr client
  restarted; sidecar stopped`); to `mode disabled`, it stops and every
  route is `disabled` again (`rpki: validation disabled; sidecar
  stopped`).

Before anything changes, a reload that would start Routinator checks what
the start checks: bgpfcd must not be root (it is not, after `--user`),
the repository directory is created, `routinator --version` must name a
0.15 release (issue #72), and the `rtr-listen` address must bind with
port 0, so that the port the running Routinator holds is no obstacle. If
one fails, the reload fails, the running configuration is kept, and the
running Routinator goes on serving: a reload onto a binary that would not
start never stops the one that works. Should Routinator still fail to
start after that, as when the binary changes in between, the reload goes
ahead with validation off, every route `disabled`, and its summary and an
error line say so; `show status` raises the alarm
`rpki-sidecar-not-running` until it runs (`docs/control.md`, "Alarms").
The next reload starts it again, after the same checks, also when the
file has not changed: fix the cause, then reload. The same holds for an
RTR client that could not be started (`rpki-client-not-running`). A
Routinator that keeps failing is not restarted by a reload that leaves its
block alone: bgpfcd keeps retrying it at the back-off's cap.

## Command line

```
bgpfcd -c FILE [--check] [--log-level LEVEL] [--fib dry-run|install]
       [--netns NAME|PATH] [--user USER [--group GROUP]]
```

`--check` parses and validates the file (policies included), prints any
errors, and exits with status 0 or 1 without starting anything; it does not
look up the names of `rpki` caches or run Routinator. With a network
namespace, from `netns` or `--netns`, it also opens the namespace's file
and checks that it is one, which needs no privilege, and says `netns PATH`
after the counts; it does not join it.
`--log-level`, `--fib` and `--netns` override the corresponding settings in
the file for this run, and at every reload. `--netns` takes what `netns`
takes: a name in `/run/netns` or an absolute path (see **Network
namespace**). `--user` is for a daemon started as root: the listeners and
the netlink socket are opened first, then the process drops to that user
(README, "Option B"). Without it, an unprivileged daemon must hold
`CAP_NET_BIND_SERVICE` for a listen port below 1024 and `CAP_NET_ADMIN`
for `fib { mode install; }`; the daemon checks and names what is missing.
To join a network namespace it needs `CAP_SYS_ADMIN` as well, root or
not, which it gives up right after the join (see **Network namespace**).

`SIGTERM` and `SIGINT` shut the daemon down: every session gets a Cease
(Administrative Shutdown) and every route it installed is removed.
