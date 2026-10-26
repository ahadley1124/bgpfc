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
             | "rpki" "{" { rpki-item } "}" ;    (* none: validation disabled *)

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
             | "cache" host { cache-option } ";"       (* repeatable; options once each; not with mode sidecar *)
             | "sidecar" "{" { sidecar-item } "}"      (* once; not with mode external *)
             | "version" ( "0" | "1" ) ";"             (* default 1 *)
             | "connect-timeout" u32 ";"              (* default 10 *)
             | "response-timeout" u32 ";"             (* default 60 *)
             | "reply-timeout" u32 ";"                (* default 1800 *)
             | "max-expire" u32 ";"                   (* 600-172800; default 172800 *)
             | "max-vrps" u32 ";"                     (* at least 1; default 4000000 *)
             | "backoff" u32 u32 ";" ;                (* MIN MAX: 1-7200 each, MIN <= MAX;
                                                         default 1 600, with mode sidecar 1 30 *)
cache-option = "port" u16                              (* default 323; not 0 *)
             | "preference" u32 ;                      (* default 0 *)

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
drop-invalid` as above, by an `enforcement` statement, or by an import
policy that matches or sets the state (`match rpki`, `set rpki`). Without
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

Each route goes through these steps in order:

1. The checks that make a route unusable whatever the policy, such as an
   AS_PATH holding our own AS (RFC 4271 §9.1.2). A route that fails them is
   not kept.
2. The lookup gives the route its state from its AS_PATH as received (RFC
   6811 §2).
3. The import policy accepts the route, possibly with other attributes,
   or rejects it. It may match the state, and set the state the route is
   used with from then on (`set rpki`).
4. `enforcement` acts on the state the route is used with, the one import
   policy set or else the one the lookup gave: `drop-invalid` holds an
   Invalid route. So `set rpki valid` in an import policy wins over
   `drop-invalid`, and `match rpki invalid; action reject;` rejects in
   every mode.
5. The Adj-RIB-In keeps the routes the import policy accepted and the ones
   held for their state: by `enforcement`, or because the import policy
   rejects them only in their current state, which it would accept in
   another. A route the import policy rejects whatever its state is not
   kept.
6. Route selection among the routes not held, ranking by state first under
   `prefer-valid`.
7. The export policy of each neighbor, which sees the state the route is
   used with, the rewriting of RFC 4271 §5.1, and the neighbor's
   `advertisement-interval`.

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

`max-expire` is the longest bgpfcd keeps using VRPs it cannot refresh.
The cache's Expire Interval applies when it is shorter (RFC 8210 §6: "The
router MUST NOT retain the data past the time indicated by this
parameter"), so the setting can only shorten it; it lies in 600–172800, the
range §6 gives the Expire Interval, and the default leaves the cache's
value. When the data expires, every route becomes `not-found`. `max-vrps`,
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
make it Invalid; an import policy that rejects on `match rpki not-found`
holds it instead until they give it a state it accepts. A
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
the timeouts, `max-expire`, `max-vrps` and `backoff`. Routinator is a
separate program that bgpfc neither bundles nor links; bgpfcd needs
Routinator 0.15.x, and is tested with 0.15.2.

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
which must name a 0.15 release within ten seconds, picks the RTR port if
`rtr-listen` leaves it at 0, and starts Routinator; then its RTR client
connects to Routinator's address. If one of these steps fails (a binary
that is missing, does not run or is another release, or a repository
directory that cannot be created), bgpfcd logs `cannot start rpki` with
the reason and exits with status 1 (issue #60: fail loudly and early).
Routinator's standard output is logged at info and its standard error,
where it writes its warnings, at warn, each line with
`sidecar=routinator`. When bgpfcd stops, it stops its RTR client, then
Routinator: `SIGTERM`, and `SIGKILL` after `stop-timeout`. If bgpfcd dies
without stopping it, the kernel kills Routinator too (`PR_SET_PDEATHSIG`).
Nothing else in bgpfcd reaps child processes, which is what lets the
sidecar keep track of its own.

**Startup window.** Until the RTR client's first full set arrives there
are no VRPs, and every route is `disabled`: shown so, not as `not-found`,
and used as received, since no `enforcement` acts on `disabled`. With an
external cache on the router or near it, the window is normally too short
to matter. With the sidecar it is long: Routinator opens its RTR listener
only once its first validation run has ended, minutes after it starts
from a cold repository directory, less from a warm one. bgpfcd does not
wait for it: the neighbors come up at once and their routes are used,
unvalidated. When the first set arrives, every route is validated (RFC
6811 §4) and `enforcement` acts on the result, so that under
`drop-invalid` the Invalid routes are then held and withdrawn from the
neighbors and the kernel. Holding every route until then without being
told to is what RFC 6811 §2 forbids ("MUST NOT exclude a route from the
Adj-RIB-In or from consideration in the decision process as a side effect
of its validation state, unless explicitly configured to do so"), and on a
transit router it would black-hole the whole table for the minutes of a
cold start after every reboot; BIRD and FRR converge the same way. The
window is not silent (issue #71). When a client starts with no data to
hold, bgpfcd logs `rpki: no validation data yet; routes are used
unvalidated until the first full set` with the mode and the
`enforcement`: at warn with `mode sidecar`, with a hint about
Routinator's first run, and at info with `mode external`, whose window is
normally a moment. When the first set arrives it logs `rpki: validation
data arrived; routes are validated from now on` with `waited=`, the
seconds the routes waited; the RIB's `rib: validation states changed` line
follows, with the routes held and released. A reload from `mode
disabled` opens the window again. A reload that restarts the client
does not, since the data in use stays in use until the new set arrives.

To hold the routes until the first set instead, say so in each import
policy, first:

```
policy UPSTREAM-IN {
    term unvalidated { match rpki disabled; action reject; }   # held until the first full set
    ...
}
```

During the window every route is then held by policy (`show routes
held`), and none is used. When the first set arrives they are judged
again: under `drop-invalid`, the Valid and `not-found` routes are used and
the Invalid ones stay held. VRPs that expire give `not-found`, not
`disabled`, so this holds routes before the first set only, not after the
data expires; with `mode disabled` it holds every route for good.

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
  could not bind a lower one. The default is `127.0.0.1 port 0`.
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
  reported as failed, an alarm, while bgpfcd keeps trying at the
  back-off's cap (issue #70); at least 1, 5 unless given.

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
policy accepted and that are not held, bgpfcd uses one, chosen by removing
routes from consideration in this order until one is left (RFC 4271
§9.1.2.2: "The criteria MUST be applied in the order specified"; issue
#47):

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
7. e): the lowest interior cost to the next hop. bgpfcd runs no IGP, so
   every route ties, as with BIRD and FRR when they know no IGP metric.
8. f): the lowest BGP Identifier of the neighbor.
9. g): the lowest neighbor address.

RFC 4271 §9.1.2 also takes out of route selection a route whose NEXT_HOP
cannot be resolved ("the BGP route MUST be excluded from the Phase 2
decision function"), and issue #47 makes routes with an unreachable next
hop ineligible. bgpfcd does not apply this rule: it runs no IGP and reads
no routes from the kernel, so every next hop counts as resolvable, as
every interior cost counts as equal in step 7. A route whose next hop is
unreachable can therefore be chosen and advertised. With `fib { mode
install; }` the kernel refuses to install a route whose gateway it cannot
reach directly, and the failure is logged at error as `fib: failed`, but
the route stays chosen.

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

**Validation.** After parsing, these checks run and every failure is
reported with the position of the item at fault: every `prefix-list` and
`policy` reference resolves; no neighbor is defined twice; every neighbor
has `remote-as`, `import` and `export`; no neighbor's `export` policy has
`set rpki`; the HTTP listen address is a loopback address; timer
constraints above; `extended-next-hop` only with `ipv4-unicast` in
`families`; `maximum-prefix` only for a family in `families`; an `rpki`
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
`advertisement-interval` and `maximum-prefix`; `restart-limit` included)
reset with Cease / Other Configuration Change and start again, and
neighbors whose policies, or the prefix lists those policies use, changed
are re-evaluated without a reset, using route refresh where the peer
supports it. A route held for its validation state (see **RPKI**) meets
the new import policy the same way, when its neighbor sends it again, or
at once when the same reload also changes `enforcement`. A changed
`advertisement-interval` applies to the running session at once, also
without a reset. So does a changed `maximum-prefix`:
a session that already holds more routes than its new limit ends as if it
had just exceeded it, and a raised limit does not start a neighbor the old
one stopped (`bgpfcctl clear neighbor` does). A changed `router-id` or
`local-as` resets every session.

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
§5). The reload summary then says `rpki enforcement MODE`. A new cache
whose name does not resolve fails the reload as it fails the start.

With `mode sidecar`, a reload restarts only what changed, since every
start of Routinator costs a validation run before it listens again:

- A change to the client's settings (`version`, the timeouts,
  `max-expire`, `max-vrps`, `backoff`) restarts the RTR client at the
  same address and leaves Routinator running (`rpki: rtr client
  restarted`).
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
the repository directory is created, and `routinator --version` must name
a 0.15 release (issue #72). If one fails, the reload fails, the running
configuration is kept, and the running Routinator goes on serving: a
reload onto a binary that would not start never stops the one that works.
Should Routinator still fail to start after that, as when the binary
changes in between, the reload goes ahead with validation off, every
route `disabled`, and its summary and an error line say so; a later
reload that changes the block starts it again. A Routinator that keeps
failing is not restarted by a reload that leaves its block alone: bgpfcd
keeps retrying it at the back-off's cap.

## Command line

```
bgpfcd -c FILE [--check] [--log-level LEVEL] [--fib dry-run|install]
       [--user USER [--group GROUP]]
```

`--check` parses and validates the file (policies included), prints any
errors, and exits with status 0 or 1 without starting anything; it does not
look up the names of `rpki` caches or run Routinator.
`--log-level` and `--fib` override the corresponding settings in the file
for this run. `--user` is for a daemon started as root: the listeners and
the netlink socket are opened first, then the process drops to that user
(README, "Option B"). Without it, an unprivileged daemon must hold
`CAP_NET_BIND_SERVICE` for a listen port below 1024 and `CAP_NET_ADMIN`
for `fib { mode install; }`; the daemon checks and names what is missing.

`SIGTERM` and `SIGINT` shut the daemon down: every session gets a Cease
(Administrative Shutdown) and every route it installed is removed.
