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
             | "rpki" "{" { rpki-item } "}" ;    (* none: disabled *)

level        = "error" | "warn" | "info" | "debug" | "trace" ;    (* default info *)

fib-item     = "mode" ( "dry-run" | "install" ) ";"   (* default dry-run *)
             | "table" ( "main" | "local" | "default" | u32 ) ";"   (* default main *)
             | "protocol" u8 ";" ;                    (* default 186, RTPROT_BGP *)

control-item = "socket" path ";"
             | "http" "{" "listen" ip ":" u16 ";"     (* loopback only *)
                       [ "writes" yes-no ";" ]        (* default no *)
                       [ "token-file" path ";" ] "}" ;

rpki-item    = "mode" ( "disabled" | "external" ) ";"    (* required *)
             | "cache" host { cache-option } ";"       (* repeatable; options once each *)
             | "version" ( "0" | "1" ) ";"             (* default 1 *)
             | "connect-timeout" u32 ";"              (* default 10 *)
             | "response-timeout" u32 ";"             (* default 60 *)
             | "reply-timeout" u32 ";"                (* default 1800 *)
             | "max-expire" u32 ";"                   (* 600-172800; default 172800 *)
             | "max-vrps" u32 ";"                     (* at least 1; default 4000000 *)
             | "backoff" u32 u32 ";" ;                (* MIN MAX: 1-7200 each, MIN <= MAX; default 1 600 *)
cache-option = "port" u16                              (* default 323; not 0 *)
             | "preference" u32 ;                      (* default 0 *)

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
             | "neighbor" ip ;
set          = "local-pref" u32
             | "med" u32
             | "community" op community { community }
             | "ext-community" op ext-community { ext-community }
             | "large-community" op large-community { large-community }
             | "as-path" "prepend" asn { asn }
             | "next-hop" "self" ;
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
             | "add-path" "receive" family yes-no ";"                  (* once per family; default no *)
             | "add-path" "send" family ( u32 | "all" | "off" ) ";"    (* once per family; u32 is 1-4294967295; default off *)
             | "graceful-restart" yes-no ";"         (* default no *)
             | "restart-time" u16 ";"                (* 0-4095; default 120; needs graceful-restart yes *)
             | "stale-time" u16 ";"                  (* 1-65535; default 360; needs graceful-restart yes *)
             | "role" role ";"                       (* default none; external sessions only *)
             | "role-strict" yes-no ";"              (* default no; needs a role *)
             | "passive" yes-no ";"                  (* default no *)
             | "allow-as-set" yes-no ";"             (* default no *)
             | "collision-detect-established" yes-no ";" ;   (* default no *)
family       = "ipv4-unicast" | "ipv6-unicast" ;
role         = "provider" | "rs" | "rs-client" | "customer" | "peer" ;
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
from (import) or is being sent to (export).

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
error. Counted are the routes accepted: those that passed the AS loop
check and the import policy, which is what `show neighbor` reports as
received. Routes the import policy rejects are not kept and not counted,
as with FRR's `maximum-prefix` and BIRD's `import limit`. The limit must
be at least 1 and its family one of the neighbor's `families`. The
neighbor then restarts like after any other damped failure, so a peer
that keeps sending too many routes is retried `restart-limit` times and
then left Idle; `restart-limit 0` leaves it Idle at once.

`add-path receive FAMILY yes` and `add-path send FAMILY N` or `all`
advertise the ADD-PATH capability of RFC 7911 for the family and use it
once the neighbor advertises the other half: bgpfcd sends the capability
with Receive for a family it takes several paths for and with Send for
one it sends several for, both in one capability. A family is exchanged
with Path Identifiers in a direction only when the two sides agree
(RFC 7911 §5): we receive them when we advertised Receive and the
neighbor Send, and send them when we advertised Send and the neighbor
Receive; otherwise the family is exchanged as without ADD-PATH in that
direction. Neither is on unless configured, and a session without it
costs nothing for it. The family must be one of the neighbor's
`families`; `no` and `off` say nothing and may be left out. `N` is a
number from 1 to 4294967295; `0` is refused, since sending no more than
the one best path is what `off` is for: it advertises no Send for the
family, where `1` still sends Path Identifiers to a neighbor that takes
them.

With `add-path receive`, each path the neighbor sends for a prefix is
kept under the Path Identifier it came with, and every one of them takes
part in the decision process (RFC 4271 §9.1) next to the paths of other
neighbors; import policy runs on each, and `maximum-prefix` counts each.
The kernel still gets the one best path per prefix. A withdrawal names a
path, and one for a Path Identifier bgpfcd does not hold is ignored
(RFC 7911 §5). Several paths from one neighbor to one prefix tie-break
like paths from different neighbors, and then on the lowest Path
Identifier, so the choice does not depend on arrival order.

With `add-path send FAMILY N`, bgpfcd sends the neighbor the `N` best
paths for each prefix, in the order of the decision process, among those
its export policy accepts and that RFC 4271 §9.2 allows it to send to
that neighbor (a path is never sent back to the neighbor it came from).
`all` sends every such path. RFC 7911 §5 asks that the best path be
among them unless it came from that neighbor, which both do: the best
path that can be sent is always the first. A path keeps the Path
Identifier bgpfcd gave it while it is sent, through changes to its
attributes, and when it is withdrawn the withdrawal names that
identifier; a path that drops out of the `N` best and comes back may be
numbered anew. The identifiers are local to the neighbor and mean
nothing: a new path takes the smallest number from 1 that no other path
sent to the neighbor for that prefix has, counting those a withdrawal in
the same step frees, so that an identifier is not reused while its
withdrawal may still be on the way. The `advertisement-interval` paces
all the paths of a prefix as one destination: when it holds a prefix
back, the neighbor keeps what it was sent and gets the paths the prefix
has when the interval ends. A path that is gone is withdrawn at once, as
for any prefix; one that only dropped out of the `N` best is withdrawn
with the announcements that displace it, so the neighbor keeps it until
its replacement can go. `show routes` and the
HTTP API show a path's identifier where it has one (`docs/control.md`).
A reload that only changes `N`, or `N` to `all`, applies at once to the
running session, without a reset, sending or withdrawing the paths the
change adds or takes away.

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

**Graceful Restart.** `graceful-restart yes;` makes the neighbor take part
in Graceful Restart (RFC 4724) with the Graceful Notification of RFC 8538:
bgpfcd advertises the capability with the N bit, a Restart Time and a
tuple for each of the neighbor's `families`, and follows the Receiving
Speaker procedures for a neighbor that advertised it too. It is off by
default, and a neighbor without it is treated as RFC 4271 has it: no
capability, no End-of-RIB, and the routes of a session that ended are
deleted. `restart-time` is the Restart Time advertised, the time in
seconds the neighbor should allow our session to come back in after we
restart (RFC 4724 §3): 0 to 4095, the most its twelve bits hold, 120 by
default as BIRD and FRR have it. `stale-time` is how long the stale
routes of a neighbor that restarted are kept once its session is back,
waiting for its End-of-RIB (RFC 8538 §4.1): 1 to 65535 seconds, 360 by
default as FRR has it (`bgp graceful-restart stalepath-time`). Both need
`graceful-restart yes`; stating `graceful-restart no` is the default.

As a Receiving Speaker bgpfcd keeps the routes of the neighbor as stale
ones when its session ends by a TCP failure (RFC 4724 §4.2), by a Hold
Timer or Send Hold Timer expiry (RFC 8538 §4; bgpfcd does so also when the
neighbor sent no N bit, as the text reads), and, where both sides sent
the N bit, after any NOTIFICATION but a Hard Reset (RFC 8538 §4). A stale
route is in the RIB, the kernel and what other neighbors were told like any
other. It is replaced when the neighbor sends the route again, and deleted
when the neighbor's End-of-RIB for the family comes, when the neighbor's
Restart Time from before has run out with the session still down, when the
`stale-time` has run out with the session back but the End-of-RIB not
there, and at once when the session comes back without the capability or
without the Forwarding State bit for the family. The `stale-time` starts
with the first session that is back, and a session that ends again does not
start it afresh (RFC 8538 §9). Routes still stale when a session ends again
are deleted, unless both sides sent the N bit (RFC 8538 §4.1). A neighbor
that a reload removes loses its stale routes at once. `bgpfcctl show
neighbor` and `show routes` show what is stale ([`docs/control.md`](control.md),
"Graceful Restart"). With ADD-PATH each path is kept and replaced under its
own Path Identifier, which need not be the same after the neighbor restarts
(RFC 7911 §5).

The End-of-RIB marker (RFC 4724 §2) follows the initial update of each
family sent to a neighbor with `graceful-restart yes`; one received from
any neighbor is recognised.

As a Restarting Speaker bgpfcd acts in install mode only. At the start, the
routes of the `fib` protocol number it finds in the kernel, for the families
of the neighbors with `graceful-restart yes`, are the forwarding state that
a restart kept (RFC 4724 §4.1), and are left where they are instead of being
removed as stale. Until every such neighbor has sent its End-of-RIB for a
family, or the longest `restart-time` among them has passed since the start
(the Selection_Deferral_Timer, which `restart-time` also configures; FRR
and BIRD have a setting of their own for it), bgpfcd selects no route of that
family: it installs and advertises nothing for it, and the kernel's routes
forward meanwhile. A neighbor whose capability has the Restart State bit is
not waited for, nor is one that advertised no capability (RFC 4724 §4.1);
FRR without zebra sets the bit for as long as its own startup lasts. Then
the kernel is brought in line with the RIB for the family, which removes
only the routes not learned again and replaces those with another next hop,
and every neighbor is sent its table and the End-of-RIB marker. While route
selection is deferred, and until it is done for every family, the OPENs set
the Restart State bit. The Forwarding State bit of a family is set while the
kernel holds routes of it in install mode, so never in dry-run mode, where
nothing is installed; a neighbor that gets it clear from a restarted bgpfcd
removes the routes it kept at once (RFC 4724 §4.2). A `SIGTERM` is an
administrative shutdown, not a restart: bgpfcd sends the neighbors a Hard
Reset, where they sent the N bit, and takes its routes out of the kernel.

bgpfcd sends a Hard Reset (RFC 8538 §3), a Cease whose data is another
NOTIFICATION, to a neighbor that sent the N bit when it shuts down, when a
reload removes the neighbor, when the neighbor exceeds its `maximum-prefix`,
and when `bgpfcctl clear neighbor ADDR hard-reset` asks for one; RFC 8538 §5.1
suggests a Hard Reset for those reasons. Other Ceases, such as the Other
Configuration Change of a reload that resets a session, and a plain `clear
neighbor`, are graceful ones: both sides keep the other's routes as stale
ones.

**BGP Roles.** `role customer;` says that our Role on the session is
Customer: the neighbor is our transit provider (RFC 9234 §4). The names
are those of RFC 9234 §4.1, and the Role is ours, the one the OPEN
carries in the BGP Role capability, not the neighbor's. `provider` makes
the neighbor our customer, `rs` and `rs-client` a route server and its
client, `peer` a lateral peer. The neighbor must state the matching Role
(Provider with Customer, RS with RS-Client, Peer with Peer, RFC 9234
§4.2, Table 2); if it states another, or several that differ, the
session is refused with OPEN Message Error / Role Mismatch (subcode 11).
A neighbor that states none is accepted, with our Role, unless
`role-strict yes;` asks for the receipt of its capability (RFC 9234 §4.2,
"strict mode"), in which case the session is refused with Role Mismatch
too. Strict mode is off by default, as RFC 9234 §8 asks, and needs a
`role`.

With a `role` the neighbor takes part in the Only to Customer procedures
of RFC 9234 §5 (`docs/control.md`, "Only to Customer"): a route received
with the OTC attribute from a customer or an RS-Client, or from a peer
with an OTC other than the peer's AS, is a route leak and is dropped; a
route received from a provider, a peer or an RS without the attribute
gets it, set to the neighbor's AS; a route that carries the attribute is
not sent to a provider, a peer or an RS; and a route sent to a customer,
a peer or an RS-Client without it gets it, set to our AS. The procedures
cannot be changed by policy. A neighbor without a `role` is not subject to
them, and the attribute passes through it unchanged. With `add-path`, each
path is a route of its own (RFC 7911 §5): a leak takes the one path the
neighbor sent it under, by its Path Identifier, and leaves the others to
the prefix, and each path sent goes through the procedures on its own, so
a neighbor sent several may be sent some of a prefix's paths and not
others. The procedures apply to IPv4 unicast and IPv6 unicast, the only
families bgpfc speaks.
Roles are for external sessions: a `role` on a neighbor whose `remote-as`
is our own is an error (RFC 9234 §4).

**RPKI.** The `rpki` block says where the Validated ROA Payloads (VRPs)
come from that give every route its RFC 6811 origin validation state
(`docs/control.md`, "Validation state"). Without the block, or with `mode
disabled`, there are none and every route is `disabled`. The block must
state its `mode`; nothing else implies one. `mode external` takes the VRPs
over the RPKI-to-Router protocol (RTR) from the caches listed with `cache`,
of which there must be at least one; `mode disabled` keeps the cache list
but uses none of it. The state is not yet acted on: it does not decide
whether a route is accepted or which one is chosen.

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
the cache's data. The client logs with the rest of the daemon, at the `log`
level: losing a cache is a warning, its return an info line, and VRPs that
expire before a cache could refresh them an error.

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
600` keeps to the RFC's default.

**Validation.** After parsing, these checks run and every failure is
reported with the position of the item at fault: every `prefix-list` and
`policy` reference resolves; no neighbor is defined twice; every neighbor
has `remote-as`, `import` and `export`; the HTTP listen address is a
loopback address; timer constraints above; `extended-next-hop` only with
`ipv4-unicast` in `families`; `maximum-prefix` and `add-path` only for a
family in `families`; a `role` only on an external session, and
`role-strict yes` only with a `role`; `restart-time` and `stale-time` only
with `graceful-restart yes`; an `rpki` block has a `mode`, at least one
`cache` with `mode external`, no cache twice, `connect-timeout` ≤ `response-timeout` ≤
`reply-timeout`, `max-vrps` at least 1, and a `backoff` MAX no lower than
its MIN.

**Reload.** On `SIGHUP` or `bgpfcctl reload` the file is parsed again. If
it fails, the running configuration stays and the errors are logged.
Otherwise the daemon applies the difference: new neighbors start, removed
ones stop with Cease / Peer De-configured, neighbors whose session
parameters changed (anything but `description`, `import`, `export`,
`advertisement-interval` and `maximum-prefix`, and the number of paths
`add-path send` sends; `restart-limit`, `role`, `role-strict`,
`graceful-restart`, `restart-time` and `stale-time` included, and so are
the families `add-path` is on for, since the capability is in the OPEN)
reset with Cease / Other Configuration Change and start again, and
neighbors whose policies, or the prefix lists those policies use, changed
are re-evaluated without a reset, using route refresh where the peer
supports it. A changed `advertisement-interval` applies to the running
session at once, also without a reset. So does a changed `maximum-prefix`:
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
the running client alone, and a new cache whose name does not resolve fails
the reload as it fails the start.

## Command line

```
bgpfcd -c FILE [--check] [--log-level LEVEL] [--fib dry-run|install]
       [--user USER [--group GROUP]]
```

`--check` parses and validates the file (policies included), prints any
errors, and exits with status 0 or 1 without starting anything; it does not
look up the names of `rpki` caches.
`--log-level` and `--fib` override the corresponding settings in the file
for this run. `--user` is for a daemon started as root: the listeners and
the netlink socket are opened first, then the process drops to that user
(README, "Option B"). Without it, an unprivileged daemon must hold
`CAP_NET_BIND_SERVICE` for a listen port below 1024 and `CAP_NET_ADMIN`
for `fib { mode install; }`; the daemon checks and names what is missing.

`SIGTERM` and `SIGINT` shut the daemon down: every session gets a Cease
(Administrative Shutdown) and every route it installed is removed.
