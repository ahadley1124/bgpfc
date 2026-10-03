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
             | "control" "{" { control-item } "}" ;

level        = "error" | "warn" | "info" | "debug" | "trace" ;    (* default info *)

fib-item     = "mode" ( "dry-run" | "install" ) ";"   (* default dry-run *)
             | "table" ( "main" | "local" | "default" | u32 ) ";"   (* default main *)
             | "protocol" u8 ";" ;                    (* default 186, RTPROT_BGP *)

control-item = "socket" path ";"
             | "http" "{" "listen" ip ":" u16 ";"     (* loopback only *)
                       [ "writes" yes-no ";" ]        (* default no *)
                       [ "token-file" path ";" ] "}" ;

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
             | "families" family { family } ";"      (* default both *)
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
`as-path prepend`; the next hop of a route to an external peer is always
our address). `next-hop self` is therefore only meaningful in export
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
the send hold timer. `allow-as-set yes` accepts `AS_SET` in received
UPDATEs against RFC 9774 §3. `collision-detect-established yes` lets a new
connection replace an Established session per RFC 4271 §6.8.

**Validation.** After parsing, these checks run and every failure is
reported with the position of the item at fault: every `prefix-list` and
`policy` reference resolves; no neighbor is defined twice; every neighbor
has `remote-as`, `import` and `export`; the HTTP listen address is a
loopback address; timer constraints above.

**Reload.** On `SIGHUP` or `bgpfcctl reload` the file is parsed again. If it
fails, the running configuration stays and the errors are logged. Otherwise
the daemon applies the difference: new neighbors start, removed ones stop
with Cease / Peer De-configured, neighbors whose session parameters changed
(anything but `description`, `import` and `export`) reset with Cease / Other
Configuration Change, and neighbors whose policies, or the prefix lists those
policies use, changed are re-evaluated without a reset, using route refresh
where the peer supports it. A changed `router-id` or `local-as` resets every
session.

## Command line

```
bgpfcd -c FILE [--check] [--log-level LEVEL] [--fib dry-run|install]
```

`--check` parses and validates the file, prints any errors, and exits with
status 0 or 1 without starting anything. `--log-level` and `--fib` override
the corresponding settings in the file for this run.
