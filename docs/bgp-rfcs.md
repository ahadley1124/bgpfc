# BGP RFCs

The RFCs where BGP is the subject or a core mechanism, with their IETF
status and how far bgpfc implements each. [`RESOURCES.md`](../RESOURCES.md)
is the short list of what bgpfc builds on;
[`COMPLIANCE.md`](../COMPLIANCE.md) tracks every MUST, SHOULD and MAY of
the RFCs in scope and stays the authority on them. This page is the wider
map.

The list covers the 116 RFCs the IETF datatracker files under the
Inter-Domain Routing (IDR) working group, plus BGP RFCs from other
working groups. Titles, status, and the obsoleted-by and updated-by
relations were checked against the RFC Editor's metadata on 2026-10-25.
PS is Proposed Standard and DS is Draft Standard.

## Reading the bgpfc column

| Mark | Meaning |
|---|---|
| `done` | Implemented. For an RFC in COMPLIANCE.md, every MUST row is `done`; open SHOULD and MAY rows are named in the notes. |
| `partial` | Some of it is implemented; the notes say what is missing. |
| `later` | Named as later work in README.md, AGENTS.md §9 or RESOURCES.md. Out of scope until the maintainer says otherwise. |
| `no` | Not planned: outside what bgpfc is for (MPLS, VPN signalling, Flowspec, BGP-LS, Segment Routing, BMP, ...). |
| `n/a` | Nothing to implement: obsoleted, historic, informational, an IANA procedure or operator practice. |

## Where bgpfc stands

Of the 154 RFCs below, 22 are `done`, 8 `partial`,
16 `later`, 47 `no` and 61 `n/a`.

**Done:** 1997, 2918, 4360, 4486, 4760, 5396, 5492, 5668, 6608, 6793, 7606, 7607, 7911, 8092, 8212, 8538, 8654, 8950, 9003, 9072, 9687, 9774.

**Partial, with what is left:**

- RFC 4271: §6.3 a) is the one MUST row still `partial`: a received
  `NEXT_HOP` is compared with our address on the session only, as bgpfc
  tracks no interfaces. Four rows deviate (§6.3 b, §8.2.2, §9.1.2,
  §9.2.1.1); its row below says how.
- RFC 2545: bgpfc never sends a link-local next hop (§3, MUST), as it
  cannot tell when it shares a subnet with the next hop and the peer.
- RFC 4724: Graceful Restart, as a Receiving Speaker and as a Restarting
  Speaker with forwarding state kept in the kernel (AGENTS.md §9 step 16).
  The one MUST row not `done` is §4.1's Restart State bit: it is set after
  a restart that kept forwarding state, and a restart that kept none is not
  told from a first start. Open SHOULD rows: the Restart Time default is
  120 s, not at most the Hold Time (§4), and the End-of-RIB marker goes only
  to neighbors with `graceful-restart yes` (§2).
- RFC 6811: every route carries its validation state, from VRPs fetched
  over RTR (§2, §4). Missing: a policy match on the state (§3, MUST) and
  acting on it, AGENTS.md §9 step 13.
- RFC 6286: §2.2 (our own identifier from an internal peer is Bad BGP
  Identifier) and §2.3 (equal identifiers in a collision: the larger AS
  keeps its connection).
- RFC 7454 (BCP 194): GTSM (RFC 5082).
- RFC 9234: the Role capability and the Only to Customer procedures are
  done (§4, §5). The one MUST row left is §3.1: a Customer, RS-Client or
  Peer must send only routes learned from a customer, and bgpfc enforces
  that through the attribute, so a route learned over a session with no
  Role is the operator's policy to keep from a provider.
- RFC 8326: an option to tag our announcements with `GRACEFUL_SHUTDOWN`.

**Smaller items found in the review:**

- RFC 8642 §6 (MUST): document in [`docs/config.md`](config.md) that
  `set community replace` also drops well-known communities.
- [`docs/config.md`](config.md) cites RFC 6793 for "asplain"; the term
  is RFC 5396's.
- RFC 8212 is met by design (see its row) but is still listed as later
  work and has no rows in COMPLIANCE.md.

**Later** (needs the maintainer's go-ahead): 2385, 4364, 4456, 4659, 4684, 5065, 6514, 7313, 7432, 7705, 7947, 8097, 8481, 8893, 9494, 10005.

Not in the list but used by bgpfc: RFC 8210 and RFC 6810 (RTR, which
`bgpfc-rtr` speaks to fetch VRPs), RFC 6483 and RFC 9319 (tracked in
COMPLIANCE.md beside RFC 6811), RFC 6396 (MRT, read by `bgpfc-bench`),
and for the control plane RFC 8259 (JSON), RFC 9112 (HTTP/1.1) and
RFC 6750 (bearer tokens).

## Core protocol and history

RFC 4271 is the current BGP-4 specification; a revision (rfc4271bis) is a working group draft in IDR.

| RFC | Title | IETF status | bgpfc | Notes |
|---|---|---|---|---|
| [1105](https://datatracker.ietf.org/doc/html/rfc1105) | Border Gateway Protocol (BGP) | Experimental; obsoleted by 1163 | `n/a` |  |
| [1163](https://datatracker.ietf.org/doc/html/rfc1163) | Border Gateway Protocol (BGP) | Historic; obsoleted by 1267 | `n/a` |  |
| [1267](https://datatracker.ietf.org/doc/html/rfc1267) | Border Gateway Protocol 3 (BGP-3) | Historic | `n/a` |  |
| [1654](https://datatracker.ietf.org/doc/html/rfc1654) | A Border Gateway Protocol 4 (BGP-4) | PS; obsoleted by 1771 | `n/a` |  |
| [1771](https://datatracker.ietf.org/doc/html/rfc1771) | A Border Gateway Protocol 4 (BGP-4) | DS; obsoleted by 4271 | `n/a` |  |
| [4271](https://datatracker.ietf.org/doc/html/rfc4271) | A Border Gateway Protocol 4 (BGP-4) | DS; updated by 4724, 6286, 6608, 6793, 7606, 7607, 7705, 8212, 8654, 9072, 9687, 9774 | `partial` | Open in [COMPLIANCE.md](../COMPLIANCE.md): a received `NEXT_HOP` is checked against our own address on the session, not every address of the host (§6.3 a, MUST, partial). Deviates, as bgpfc tracks no interfaces: next-hop resolvability (§9.1.2) and the one-hop EBGP shared-subnet check (§6.3 b) are left to the kernel, whose verdict is logged. Deviates by choice: a NOTIFICATION in OpenSent goes to Idle as in BIRD and FRR (§8.2.2); the MinRouteAdvertisementInterval paces announcements but never holds back a withdrawal (§9.2.1.1, issue #66). |
| [1164](https://datatracker.ietf.org/doc/html/rfc1164) | Application of the Border Gateway Protocol in the Internet | Historic; obsoleted by 1268 | `n/a` |  |
| [1268](https://datatracker.ietf.org/doc/html/rfc1268) | Application of the Border Gateway Protocol in the Internet | Historic; obsoleted by 1655 | `n/a` |  |
| [1655](https://datatracker.ietf.org/doc/html/rfc1655) | Application of the Border Gateway Protocol in the Internet | PS; obsoleted by 1772 | `n/a` |  |
| [1772](https://datatracker.ietf.org/doc/html/rfc1772) | Application of the Border Gateway Protocol in the Internet | DS | `n/a` |  |
| [1265](https://datatracker.ietf.org/doc/html/rfc1265) | BGP Protocol Analysis | Informational | `n/a` |  |
| [1266](https://datatracker.ietf.org/doc/html/rfc1266) | Experience with the BGP Protocol | Informational | `n/a` |  |
| [1656](https://datatracker.ietf.org/doc/html/rfc1656) | BGP-4 Protocol Document Roadmap and Implementation Experience | Informational; obsoleted by 1773 | `n/a` |  |
| [1773](https://datatracker.ietf.org/doc/html/rfc1773) | Experience with the BGP-4 protocol | Informational | `n/a` |  |
| [1774](https://datatracker.ietf.org/doc/html/rfc1774) | BGP-4 Protocol Analysis | Informational | `n/a` |  |
| [4274](https://datatracker.ietf.org/doc/html/rfc4274) | BGP-4 Protocol Analysis | Informational | `n/a` |  |
| [4275](https://datatracker.ietf.org/doc/html/rfc4275) | BGP-4 MIB Implementation Survey | Informational | `n/a` |  |
| [4276](https://datatracker.ietf.org/doc/html/rfc4276) | BGP-4 Implementation Report | Informational | `n/a` |  |
| [4277](https://datatracker.ietf.org/doc/html/rfc4277) | Experience with the BGP-4 Protocol | Informational | `n/a` |  |
| [4272](https://datatracker.ietf.org/doc/html/rfc4272) | BGP Security Vulnerabilities Analysis | Informational | `n/a` | Background for TCP-MD5/AO, which is later work. |
| [1269](https://datatracker.ietf.org/doc/html/rfc1269) | Definitions of Managed Objects for the Border Gateway Protocol: Version 3 | PS; obsoleted by 4273 | `n/a` |  |
| [1657](https://datatracker.ietf.org/doc/html/rfc1657) | Definitions of Managed Objects for the Fourth Version of the Border Gateway Protocol (BGP-4) using SMIv2 | DS; obsoleted by 4273 | `n/a` |  |
| [4273](https://datatracker.ietf.org/doc/html/rfc4273) | Definitions of Managed Objects for BGP-4 | PS | `no` | No SNMP; state is read through `bgpfcctl` and the HTTP/JSON API. |
| [1364](https://datatracker.ietf.org/doc/html/rfc1364) | BGP OSPF Interaction | PS; obsoleted by 1403 | `n/a` |  |
| [1403](https://datatracker.ietf.org/doc/html/rfc1403) | BGP OSPF Interaction | Historic | `n/a` |  |
| [1745](https://datatracker.ietf.org/doc/html/rfc1745) | BGP4/IDRP for IP---OSPF Interaction | Historic | `n/a` |  |
| [1397](https://datatracker.ietf.org/doc/html/rfc1397) | Default Route Advertisement In BGP2 and BGP3 Version of The Border Gateway Protocol | Historic | `n/a` |  |

## Capabilities, sessions and message handling

| RFC | Title | IETF status | bgpfc | Notes |
|---|---|---|---|---|
| [5492](https://datatracker.ietf.org/doc/html/rfc5492) | Capabilities Advertisement with BGP-4 | DS; updated by 8810 | `done` |  |
| [3392](https://datatracker.ietf.org/doc/html/rfc3392) | Capabilities Advertisement with BGP-4 | DS; obsoleted by 5492 | `n/a` |  |
| [2842](https://datatracker.ietf.org/doc/html/rfc2842) | Capabilities Advertisement with BGP-4 | PS; obsoleted by 3392 | `n/a` |  |
| [8810](https://datatracker.ietf.org/doc/html/rfc8810) | Revision to Capability Codes Registration Procedures | PS | `n/a` | IANA procedure. |
| [2918](https://datatracker.ietf.org/doc/html/rfc2918) | Route Refresh Capability for BGP-4 | PS; updated by 7313 | `done` |  |
| [7313](https://datatracker.ietf.org/doc/html/rfc7313) | Enhanced Route Refresh Capability for BGP-4 | PS | `later` | RESOURCES.md, "Later: features". |
| [4486](https://datatracker.ietf.org/doc/html/rfc4486) | Subcodes for BGP Cease Notification Message | PS; updated by 8203, 9003 | `done` |  |
| [8203](https://datatracker.ietf.org/doc/html/rfc8203) | BGP Administrative Shutdown Communication | PS; obsoleted by 9003 | `n/a` |  |
| [9003](https://datatracker.ietf.org/doc/html/rfc9003) | Extended BGP Administrative Shutdown Communication | PS | `done` |  |
| [9384](https://datatracker.ietf.org/doc/html/rfc9384) | A BGP Cease NOTIFICATION Subcode for Bidirectional Forwarding Detection (BFD) | PS | `no` | No BFD. A received Cease subcode 10 is logged as unrecognised. |
| [6608](https://datatracker.ietf.org/doc/html/rfc6608) | Subcodes for BGP Finite State Machine Error | PS | `done` |  |
| [9687](https://datatracker.ietf.org/doc/html/rfc9687) | Border Gateway Protocol 4 (BGP-4) Send Hold Timer | PS | `done` |  |
| [9072](https://datatracker.ietf.org/doc/html/rfc9072) | Extended Optional Parameters Length for BGP OPEN Message | PS | `done` |  |
| [8654](https://datatracker.ietf.org/doc/html/rfc8654) | Extended Message Support for BGP | PS | `done` |  |
| [7606](https://datatracker.ietf.org/doc/html/rfc7606) | Revised Error Handling for BGP UPDATE Messages | PS | `done` |  |
| [6286](https://datatracker.ietf.org/doc/html/rfc6286) | Autonomous-System-Wide Unique BGP Identifier for BGP-4 | PS | `partial` | §2.1 (any non-zero identifier) is done. Missing: §2.2, an OPEN from an internal peer carrying our own identifier is Bad BGP Identifier; §2.3, on a collision between equal identifiers the speaker with the larger AS keeps the connection it initiated (`resolve_collision` closes the new connection either way). |
| [4893](https://datatracker.ietf.org/doc/html/rfc4893) | BGP Support for Four-octet AS Number Space | PS; obsoleted by 6793 | `n/a` |  |
| [6793](https://datatracker.ietf.org/doc/html/rfc6793) | BGP Support for Four-Octet Autonomous System (AS) Number Space | PS | `done` |  |
| [7607](https://datatracker.ietf.org/doc/html/rfc7607) | Codification of AS 0 Processing | PS | `done` |  |
| [7705](https://datatracker.ietf.org/doc/html/rfc7705) | Autonomous System Migration Mechanisms and Their Effects on the BGP AS_PATH Attribute | PS | `later` | RESOURCES.md, "Later: features". There is no per-neighbor `local-as`. |
| [6472](https://datatracker.ietf.org/doc/html/rfc6472) | Recommendation for Not Using AS_SET and AS_CONFED_SET in BGP | BCP 172; obsoleted by 9774 | `n/a` |  |
| [9774](https://datatracker.ietf.org/doc/html/rfc9774) | Deprecation of AS_SET and AS_CONFED_SET in BGP | PS | `done` | `allow-as-set yes` per neighbor accepts `AS_SET` against §3. |
| [6938](https://datatracker.ietf.org/doc/html/rfc6938) | Deprecation of BGP Path Attributes: DPA, ADVERTISER, and RCID_PATH / CLUSTER_ID | PS | `n/a` | IANA only. Received ones are unrecognised optional attributes (RFC 4271 §5). |
| [8093](https://datatracker.ietf.org/doc/html/rfc8093) | Deprecation of BGP Path Attribute Values 30, 31, 129, 241, 242, and 243 | PS | `n/a` | IANA only. Received ones are unrecognised optional attributes (RFC 4271 §5). |
| [9234](https://datatracker.ietf.org/doc/html/rfc9234) | Route Leak Prevention and Detection Using Roles in UPDATE and OPEN Messages | PS | `partial` | `role` and `role-strict` per neighbor: the Role capability, the Role Mismatch NOTIFICATION, and the OTC attribute set and checked on ingress and egress (§4, §5), tested against BIRD. Open in [COMPLIANCE.md](../COMPLIANCE.md): routes learned over a session with no Role are not marked and are the operator's policy to keep from a provider (§3.1, MUST NOT, partial). |

## Attributes, communities and AS numbers

RFC 4360 is being replaced by rfc4360-bis, which is in the RFC Editor queue.

| RFC | Title | IETF status | bgpfc | Notes |
|---|---|---|---|---|
| [1997](https://datatracker.ietf.org/doc/html/rfc1997) | BGP Communities Attribute | PS; updated by 7606, 8642 | `done` | RFC 8642 §6 asks that the `set` behavior be documented: `set community replace` also drops well-known communities, and [`docs/config.md`](config.md) does not say so yet. |
| [1998](https://datatracker.ietf.org/doc/html/rfc1998) | An Application of the BGP Community Attribute in Multi-home Routing | Informational | `n/a` | Expressible as import policy (`match community`, `set local-pref`). |
| [4360](https://datatracker.ietf.org/doc/html/rfc4360) | BGP Extended Communities Attribute | PS; updated by 7153, 7606 | `done` |  |
| [7153](https://datatracker.ietf.org/doc/html/rfc7153) | IANA Registries for BGP Extended Communities | PS; updated by 9184 | `n/a` | Registries. Policy has typed forms for the two-octet AS, IPv4 and four-octet AS types; any other value is written in hex. |
| [9184](https://datatracker.ietf.org/doc/html/rfc9184) | BGP Extended Community Registries Update | PS | `n/a` |  |
| [8092](https://datatracker.ietf.org/doc/html/rfc8092) | BGP Large Communities Attribute | PS | `done` |  |
| [10005](https://datatracker.ietf.org/doc/html/rfc10005) | BGP Link Bandwidth Extended Community | PS | `later` | Only useful with multipath, which AGENTS.md §9 rules out for v1. |
| [7311](https://datatracker.ietf.org/doc/html/rfc7311) | The Accumulated IGP Metric Attribute for BGP | PS | `no` |  |
| [1930](https://datatracker.ietf.org/doc/html/rfc1930) | Guidelines for creation, selection, and registration of an Autonomous System (AS) | BCP 6; updated by 6996, 7300 | `n/a` |  |
| [6996](https://datatracker.ietf.org/doc/html/rfc6996) | Autonomous System (AS) Reservation for Private Use | BCP 6 | `n/a` |  |
| [7300](https://datatracker.ietf.org/doc/html/rfc7300) | Reservation of Last Autonomous System (AS) Numbers | BCP 6 | `n/a` |  |
| [5396](https://datatracker.ietf.org/doc/html/rfc5396) | Textual Representation of Autonomous System (AS) Numbers | PS | `done` | asplain in the configuration and in all output. |
| [5398](https://datatracker.ietf.org/doc/html/rfc5398) | Autonomous System (AS) Number Reservation for Documentation Use | Informational | `n/a` |  |
| [2270](https://datatracker.ietf.org/doc/html/rfc2270) | Using a Dedicated AS for Sites Homed to a Single Provider | Informational | `n/a` |  |
| [2519](https://datatracker.ietf.org/doc/html/rfc2519) | A Framework for Inter-Domain Route Aggregation | Informational | `n/a` | No aggregation in v1. |

## Multiprotocol extensions and tunnels

| RFC | Title | IETF status | bgpfc | Notes |
|---|---|---|---|---|
| [2283](https://datatracker.ietf.org/doc/html/rfc2283) | Multiprotocol Extensions for BGP-4 | PS; obsoleted by 2858 | `n/a` |  |
| [2858](https://datatracker.ietf.org/doc/html/rfc2858) | Multiprotocol Extensions for BGP-4 | PS; obsoleted by 4760 | `n/a` |  |
| [4760](https://datatracker.ietf.org/doc/html/rfc4760) | Multiprotocol Extensions for BGP-4 | DS; updated by 7606 | `done` |  |
| [2545](https://datatracker.ietf.org/doc/html/rfc2545) | Use of BGP-4 Multiprotocol Extensions for IPv6 Inter-Domain Routing | PS | `partial` | bgpfc tracks no interfaces, so it never sends a link-local next hop where it shares a subnet with the next hop and the peer (§3, MUST, partial). |
| [4798](https://datatracker.ietf.org/doc/html/rfc4798) | Connecting IPv6 Islands over IPv4 MPLS Using IPv6 Provider Edge Routers (6PE) | PS | `no` | MPLS. |
| [9012](https://datatracker.ietf.org/doc/html/rfc9012) | The BGP Tunnel Encapsulation Attribute | PS; updated by 9830 | `no` |  |

## Scaling and convergence

| RFC | Title | IETF status | bgpfc | Notes |
|---|---|---|---|---|
| [1966](https://datatracker.ietf.org/doc/html/rfc1966) | BGP Route Reflection An alternative to full mesh IBGP | Experimental; obsoleted by 4456; updated by 2796 | `n/a` |  |
| [2796](https://datatracker.ietf.org/doc/html/rfc2796) | BGP Route Reflection - An Alternative to Full Mesh IBGP | PS; obsoleted by 4456 | `n/a` |  |
| [4456](https://datatracker.ietf.org/doc/html/rfc4456) | BGP Route Reflection: An Alternative to Full Mesh Internal BGP (IBGP) | DS; updated by 7606 | `later` | AGENTS.md §9. |
| [9107](https://datatracker.ietf.org/doc/html/rfc9107) | BGP Optimal Route Reflection (BGP ORR) | PS | `no` | Builds on route reflection. |
| [1965](https://datatracker.ietf.org/doc/html/rfc1965) | Autonomous System Confederations for BGP | Experimental; obsoleted by 3065 | `n/a` |  |
| [3065](https://datatracker.ietf.org/doc/html/rfc3065) | Autonomous System Confederations for BGP | PS; obsoleted by 5065 | `n/a` |  |
| [5065](https://datatracker.ietf.org/doc/html/rfc5065) | Autonomous System Confederations for BGP | DS; updated by 9774 | `later` | AGENTS.md §9. The codec already knows the confederation segment types and counts them as §5.3 says. |
| [5291](https://datatracker.ietf.org/doc/html/rfc5291) | Outbound Route Filtering Capability for BGP-4 | PS | `no` |  |
| [5292](https://datatracker.ietf.org/doc/html/rfc5292) | Address-Prefix-Based Outbound Route Filter for BGP-4 | PS | `no` |  |
| [7911](https://datatracker.ietf.org/doc/html/rfc7911) | Advertisement of Multiple Paths in BGP | PS | `done` | Send and receive, per neighbor and family, for IPv4 and IPv6 unicast (AGENTS.md §9 step 15); every path received takes part in the decision process and the FIB still gets the one best path. Path Identifiers need not be stable across a restart: stale paths are replaced by prefix and identifier and the rest go at the End-of-RIB (§5, with graceful restart). |
| [5004](https://datatracker.ietf.org/doc/html/rfc5004) | Avoid BGP Best Path Transitions from One External to Another | PS | `no` | Would make the Loc-RIB depend on arrival order, against the RIB invariant in AGENTS.md §5. |
| [7947](https://datatracker.ietf.org/doc/html/rfc7947) | Internet Exchange BGP Route Server | PS | `later` | RESOURCES.md, "Later: features". |
| [1863](https://datatracker.ietf.org/doc/html/rfc1863) | A BGP/IDRP Route Server alternative to a full mesh routing | Historic; obsoleted by 4223 | `n/a` |  |
| [4223](https://datatracker.ietf.org/doc/html/rfc4223) | Reclassification of RFC 1863 to Historic | Informational | `n/a` |  |
| [2439](https://datatracker.ietf.org/doc/html/rfc2439) | BGP Route Flap Damping | PS | `no` |  |
| [7196](https://datatracker.ietf.org/doc/html/rfc7196) | Making Route Flap Damping Usable | PS | `no` |  |
| [4724](https://datatracker.ietf.org/doc/html/rfc4724) | Graceful Restart Mechanism for BGP | PS; updated by 8538 | `partial` | Per neighbor with `graceful-restart yes` (AGENTS.md §9 step 16): the Receiving Speaker procedures (§4.2) and, in install mode with routes of our protocol number left in the kernel, the Restarting Speaker's (§4.1). Open in [COMPLIANCE.md](../COMPLIANCE.md): the Restart State bit after a restart that kept no forwarding state (§4.1, MUST, partial); the default Restart Time (§4) and the End-of-RIB marker for neighbors without the option (§2) deviate (SHOULD). |
| [8538](https://datatracker.ietf.org/doc/html/rfc8538) | Notification Message Support for BGP Graceful Restart | PS | `done` | The N bit, graceful NOTIFICATIONs, the Hard Reset (Cease subcode 9) sent by `bgpfcctl clear neighbor ADDR hard-reset` and as RFC 8538 §5.1 suggests, and the stale timer (`stale-time`). Open SHOULD: the Forwarding State bit is clear in dry-run mode, where nothing is installed (§4). |
| [9494](https://datatracker.ietf.org/doc/html/rfc9494) | Long-Lived Graceful Restart for BGP | PS | `later` | RESOURCES.md, "Later: features". |
| [3345](https://datatracker.ietf.org/doc/html/rfc3345) | Border Gateway Protocol (BGP) Persistent Route Oscillation Condition | Informational | `n/a` |  |
| [7964](https://datatracker.ietf.org/doc/html/rfc7964) | Solutions for BGP Persistent Route Oscillation | PS | `no` | The fixes rely on ADD-PATH or route reflection. |

## Flowspec

| RFC | Title | IETF status | bgpfc | Notes |
|---|---|---|---|---|
| [5575](https://datatracker.ietf.org/doc/html/rfc5575) | Dissemination of Flow Specification Rules | PS; obsoleted by 8955; updated by 7674 | `n/a` |  |
| [7674](https://datatracker.ietf.org/doc/html/rfc7674) | Clarification of the Flowspec Redirect Extended Community | PS; obsoleted by 8955 | `n/a` |  |
| [8955](https://datatracker.ietf.org/doc/html/rfc8955) | Dissemination of Flow Specification Rules | PS; updated by 8956, 9117, 9184 | `no` |  |
| [8956](https://datatracker.ietf.org/doc/html/rfc8956) | Dissemination of Flow Specification Rules for IPv6 | PS | `no` |  |
| [9117](https://datatracker.ietf.org/doc/html/rfc9117) | Revised Validation Procedure for BGP Flow Specifications | PS | `no` |  |

## BGP-LS

| RFC | Title | IETF status | bgpfc | Notes |
|---|---|---|---|---|
| [7752](https://datatracker.ietf.org/doc/html/rfc7752) | North-Bound Distribution of Link-State and Traffic Engineering (TE) Information Using BGP | PS; obsoleted by 9552; updated by 9029 | `n/a` |  |
| [9029](https://datatracker.ietf.org/doc/html/rfc9029) | Updates to the Allocation Policy for the Border Gateway Protocol - Link State (BGP-LS) Parameters Registries | PS; obsoleted by 9552 | `n/a` |  |
| [9552](https://datatracker.ietf.org/doc/html/rfc9552) | Distribution of Link-State and Traffic Engineering Information Using BGP | PS | `no` |  |
| [8571](https://datatracker.ietf.org/doc/html/rfc8571) | BGP - Link State (BGP-LS) Advertisement of IGP Traffic Engineering Performance Metric Extensions | PS | `no` |  |
| [8814](https://datatracker.ietf.org/doc/html/rfc8814) | Signaling Maximum SID Depth (MSD) Using the Border Gateway Protocol - Link State | PS | `no` |  |
| [9085](https://datatracker.ietf.org/doc/html/rfc9085) | Border Gateway Protocol - Link State (BGP-LS) Extensions for Segment Routing | PS; updated by 9356 | `no` |  |
| [9086](https://datatracker.ietf.org/doc/html/rfc9086) | Border Gateway Protocol - Link State (BGP-LS) Extensions for Segment Routing BGP Egress Peer Engineering | PS | `no` |  |
| [9104](https://datatracker.ietf.org/doc/html/rfc9104) | Distribution of Traffic Engineering Extended Administrative Groups Using the Border Gateway Protocol - Link State (BGP-LS) | PS | `no` |  |
| [9247](https://datatracker.ietf.org/doc/html/rfc9247) | BGP - Link State (BGP-LS) Extensions for Seamless Bidirectional Forwarding Detection (S-BFD) | PS | `no` |  |
| [9294](https://datatracker.ietf.org/doc/html/rfc9294) | Application-Specific Link Attributes Advertisement Using the Border Gateway Protocol - Link State (BGP-LS) | PS | `no` |  |
| [9351](https://datatracker.ietf.org/doc/html/rfc9351) | Border Gateway Protocol - Link State (BGP-LS) Extensions for Flexible Algorithm Advertisement | PS | `no` |  |
| [9514](https://datatracker.ietf.org/doc/html/rfc9514) | Border Gateway Protocol - Link State (BGP-LS) Extensions for Segment Routing over IPv6 (SRv6) | PS | `no` |  |
| [9857](https://datatracker.ietf.org/doc/html/rfc9857) | Advertisement of Segment Routing Policies Using BGP - Link State | PS | `no` |  |

## Segment Routing, color and transport planes

| RFC | Title | IETF status | bgpfc | Notes |
|---|---|---|---|---|
| [8669](https://datatracker.ietf.org/doc/html/rfc8669) | Segment Routing Prefix Segment Identifier Extensions for BGP | PS | `no` |  |
| [9830](https://datatracker.ietf.org/doc/html/rfc9830) | Advertising Segment Routing Policies in BGP | PS | `no` |  |
| [9831](https://datatracker.ietf.org/doc/html/rfc9831) | Segment Type Extensions for BGP Segment Routing (SR) Policy | Experimental | `no` |  |
| [9723](https://datatracker.ietf.org/doc/html/rfc9723) | BGP Colored Prefix Routing (CPR) for Services Based on Segment Routing over IPv6 (SRv6) | Informational | `no` |  |
| [9832](https://datatracker.ietf.org/doc/html/rfc9832) | BGP Classful Transport Planes | Experimental | `no` |  |
| [9871](https://datatracker.ietf.org/doc/html/rfc9871) | BGP Color-Aware Routing (CAR) | Experimental | `no` |  |

## Other working groups

These come from GROW, SIDR/SIDROPS, L3VPN/BESS, IDR-adjacent work and BCPs. This part is a curated set, not exhaustive.

| RFC | Title | IETF status | bgpfc | Notes |
|---|---|---|---|---|
| [2385](https://datatracker.ietf.org/doc/html/rfc2385) | Protection of BGP Sessions via the TCP MD5 Signature Option | PS; obsoleted by 5925; updated by 6691 | `later` | TCP-MD5/AO, AGENTS.md §9. |
| [3562](https://datatracker.ietf.org/doc/html/rfc3562) | Key Management Considerations for the TCP MD5 Signature Option | Informational | `n/a` |  |
| [7854](https://datatracker.ietf.org/doc/html/rfc7854) | BGP Monitoring Protocol (BMP) | PS; updated by 8671, 9069, 9515, 9736 | `no` |  |
| [8671](https://datatracker.ietf.org/doc/html/rfc8671) | Support for Adj-RIB-Out in the BGP Monitoring Protocol (BMP) | PS; updated by 9736 | `no` |  |
| [9069](https://datatracker.ietf.org/doc/html/rfc9069) | Support for Local RIB in the BGP Monitoring Protocol (BMP) | PS; updated by 9736 | `no` |  |
| [9515](https://datatracker.ietf.org/doc/html/rfc9515) | Revision to Registration Procedures for Multiple BMP Registries | PS | `no` |  |
| [9736](https://datatracker.ietf.org/doc/html/rfc9736) | The BGP Monitoring Protocol (BMP) Peer Up Message Namespace | PS | `no` |  |
| [9972](https://datatracker.ietf.org/doc/html/rfc9972) | Advanced BGP Monitoring Protocol (BMP) Statistics Types | PS | `no` |  |
| [6397](https://datatracker.ietf.org/doc/html/rfc6397) | Multi-Threaded Routing Toolkit (MRT) Border Gateway Protocol (BGP) Routing Information Export Format with Geo-Location Extensions | PS | `no` | `bgpfc-bench` reads RFC 6396 `TABLE_DUMP_V2` dumps for benchmarks; the daemon has no MRT export. |
| [6811](https://datatracker.ietf.org/doc/html/rfc6811) | BGP Prefix Origin Validation | PS; updated by 8481, 8893 | `partial` | Every route is validated on arrival and again when the VRPs change (§2, §4), against VRPs fetched over RTR (RFC 8210). Missing: route policy matching the validation state (§3, MUST) and dropping Invalid by default, AGENTS.md §9 step 13. |
| [8097](https://datatracker.ietf.org/doc/html/rfc8097) | BGP Prefix Origin Validation State Extended Community | PS | `later` | RPKI. Matchable today as a hex extended community. |
| [8481](https://datatracker.ietf.org/doc/html/rfc8481) | Clarifications to BGP Origin Validation Based on Resource Public Key Infrastructure (RPKI) | PS; updated by 9324 | `later` | RPKI, AGENTS.md §9. |
| [8893](https://datatracker.ietf.org/doc/html/rfc8893) | Resource Public Key Infrastructure (RPKI) Origin Validation for BGP Export | PS | `later` | RPKI, AGENTS.md §9. |
| [8205](https://datatracker.ietf.org/doc/html/rfc8205) | BGPsec Protocol Specification | PS; updated by 8206 | `no` |  |
| [8206](https://datatracker.ietf.org/doc/html/rfc8206) | BGPsec Considerations for Autonomous System (AS) Migration | PS | `no` |  |
| [8207](https://datatracker.ietf.org/doc/html/rfc8207) | BGPsec Operational Considerations | BCP 211 | `no` |  |
| [8208](https://datatracker.ietf.org/doc/html/rfc8208) | BGPsec Algorithms, Key Formats, and Signature Formats | PS; obsoleted by 8608 | `no` |  |
| [8209](https://datatracker.ietf.org/doc/html/rfc8209) | A Profile for BGPsec Router Certificates, Certificate Revocation Lists, and Certification Requests | PS | `no` |  |
| [7454](https://datatracker.ietf.org/doc/html/rfc7454) | BGP Operations and Security | BCP 194 | `partial` | Prefix and AS-path filtering are in the policy language, and `maximum-prefix` sets per-neighbor limits (RFC 4271 §6.7). Missing: GTSM (RFC 5082) and TCP-MD5/AO (later). |
| [4384](https://datatracker.ietf.org/doc/html/rfc4384) | BGP Communities for Data Collection | BCP 114 | `n/a` |  |
| [7999](https://datatracker.ietf.org/doc/html/rfc7999) | BLACKHOLE Community | Informational | `n/a` | Operator practice; `65535:666` can be matched and set in policy. |
| [8326](https://datatracker.ietf.org/doc/html/rfc8326) | Graceful BGP Session Shutdown | PS | `partial` | Receiving works through policy (`match community 65535:0; set local-pref 0;`). There is no knob to tag our own announcements before a shutdown (§4.3, SHOULD). |
| [8327](https://datatracker.ietf.org/doc/html/rfc8327) | Mitigating the Negative Impact of Maintenance through BGP Session Culling | BCP 214 | `n/a` | Operator practice. |
| [8212](https://datatracker.ietf.org/doc/html/rfc8212) | Default External BGP (EBGP) Route Propagation Behavior without Policies | PS | `done` | By design: every neighbor must name an import and an export policy, and a policy that decides nothing rejects. Not in COMPLIANCE.md, and README and AGENTS.md §9 still call it later work. |
| [5668](https://datatracker.ietf.org/doc/html/rfc5668) | 4-Octet AS Specific BGP Extended Community | PS | `done` | `as4:` extended communities in policy and output. |
| [5701](https://datatracker.ietf.org/doc/html/rfc5701) | IPv6 Address Specific BGP Extended Community Attribute | PS; updated by 7153, 7606 | `no` | Passed on as an unrecognised optional transitive attribute. |
| [3107](https://datatracker.ietf.org/doc/html/rfc3107) | Carrying Label Information in BGP-4 | PS; obsoleted by 8277; updated by 6790 | `n/a` |  |
| [8277](https://datatracker.ietf.org/doc/html/rfc8277) | Using BGP to Bind MPLS Labels to Address Prefixes | PS | `no` | MPLS. |
| [4364](https://datatracker.ietf.org/doc/html/rfc4364) | BGP/MPLS IP Virtual Private Networks (VPNs) | PS; updated by 4577, 4684, 5462 | `later` | VPN families, AGENTS.md §9. |
| [4659](https://datatracker.ietf.org/doc/html/rfc4659) | BGP-MPLS IP Virtual Private Network (VPN) Extension for IPv6 VPN | PS | `later` | VPN families, AGENTS.md §9. |
| [4684](https://datatracker.ietf.org/doc/html/rfc4684) | Constrained Route Distribution for Border Gateway Protocol/MultiProtocol Label Switching (BGP/MPLS) Internet Protocol (IP) Virtual Private Networks (VPNs) | PS | `later` | VPN families, AGENTS.md §9. |
| [6514](https://datatracker.ietf.org/doc/html/rfc6514) | BGP Encodings and Procedures for Multicast in MPLS/BGP IP VPNs | PS; updated by 13 RFCs | `later` | VPN families, AGENTS.md §9. |
| [7432](https://datatracker.ietf.org/doc/html/rfc7432) | BGP MPLS-Based Ethernet VPN | PS; updated by 8584, 9161, 9572, 9573, 9746 | `later` | VPN families, AGENTS.md §9. |
| [5549](https://datatracker.ietf.org/doc/html/rfc5549) | Advertising IPv4 Network Layer Reachability Information with an IPv6 Next Hop | PS; obsoleted by 8950 | `n/a` |  |
| [8950](https://datatracker.ietf.org/doc/html/rfc8950) | Advertising IPv4 Network Layer Reachability Information (NLRI) with an IPv6 Next Hop | PS | `done` | `extended-next-hop yes` advertises the capability for IPv4 unicast (§4). VPN-IPv4 with a VPN-IPv6 next hop (§3) is n/a: VPN families are out of scope. |
| [9252](https://datatracker.ietf.org/doc/html/rfc9252) | BGP Overlay Services Based on Segment Routing over IPv6 (SRv6) | PS; updated by 9819 | `no` |  |

## Still in the pipeline

Drafts expected to become RFCs, as of the IDR documents page on 2026-10-25.

| Draft | Title | Stage |
|---|---|---|
| [draft-ietf-idr-rfc4360-bis](https://datatracker.ietf.org/doc/draft-ietf-idr-rfc4360-bis/) | BGP Extended Communities Attribute | RFC Editor queue; replaces RFC 4360 |
| [draft-ietf-idr-nhc](https://datatracker.ietf.org/doc/draft-ietf-idr-nhc/) | BGP Next Hop Dependent Characteristics Attribute | RFC Editor queue |
| [draft-ietf-idr-flowspec-redirect-ip](https://datatracker.ietf.org/doc/draft-ietf-idr-flowspec-redirect-ip/) | BGP Flow-Spec Redirect-to-IP Action | RFC Editor queue |
| [draft-ietf-idr-bgpls-inter-as-topology-ext](https://datatracker.ietf.org/doc/draft-ietf-idr-bgpls-inter-as-topology-ext/) | BGP-LS Extensions for Inter-AS Topology Retrieval | RFC Editor queue |
| [draft-ietf-idr-bgp-ls-sr-epe-over-l2bundle](https://datatracker.ietf.org/doc/draft-ietf-idr-bgp-ls-sr-epe-over-l2bundle/) | Segment Routing BGP Egress Peer Engineering over Layer 2 Bundle Members | RFC Editor queue |
| [draft-ietf-idr-bgpls-sr-vtn-mt](https://datatracker.ietf.org/doc/draft-ietf-idr-bgpls-sr-vtn-mt/) | BGP-LS with Multi-Topology for SR-based Network Resource Partitions | RFC Editor queue (Informational) |
| [draft-ietf-idr-sr-policy-nrp](https://datatracker.ietf.org/doc/draft-ietf-idr-sr-policy-nrp/) | BGP SR Policy Extensions for Network Resource Partition | RFC Editor queue |
| [draft-ietf-idr-sr-policy-seglist-id](https://datatracker.ietf.org/doc/draft-ietf-idr-sr-policy-seglist-id/) | BGP SR Policy Extensions for Segment List Identifier | RFC Editor queue |
| [draft-ietf-idr-vpn-prefix-orf](https://datatracker.ietf.org/doc/draft-ietf-idr-vpn-prefix-orf/) | VPN Prefix Outbound Route Filter (VPN Prefix ORF) for BGP-4 | RFC Editor queue (Experimental) |
| [draft-ietf-idr-rt-derived-community](https://datatracker.ietf.org/doc/draft-ietf-idr-rt-derived-community/) | Extended Communities Derived from Route Targets | IETF last call, ends 28 Oct 2026 |
| [draft-ietf-idr-ts-flowspec-srv6-policy](https://datatracker.ietf.org/doc/draft-ietf-idr-ts-flowspec-srv6-policy/) | Traffic Steering using BGP FlowSpec with SR Policy | IETF last call, ends 28 Oct 2026 |
| [draft-ietf-idr-bgp4-rfc4271bis](https://datatracker.ietf.org/doc/draft-ietf-idr-bgp4-rfc4271bis/) | A Border Gateway Protocol 4 (BGP-4) | Working group draft, revision 03 |
| [draft-ietf-idr-bgp-model](https://datatracker.ietf.org/doc/draft-ietf-idr-bgp-model/) | YANG Model for Border Gateway Protocol (BGP-4) | Working group last call |

## Sources

- [IDR working group documents](https://datatracker.ietf.org/group/idr/documents/),
  IETF datatracker: the 116 IDR RFCs, their status and the pipeline.
- [Concluded BGP working group](https://datatracker.ietf.org/wg/bgp/documents/):
  RFC 1772.
- [ICIR BGP RFC index](https://www.icir.org/netdb/protocols/BGP.html) and
  IETF proceedings: RFCs 1105, 1403 and 1771.
- [BCP index](https://datatracker.ietf.org/doc/bcp): BCP numbers.
- The [RFC Editor](https://www.rfc-editor.org/) metadata for every RFC
  (`https://www.rfc-editor.org/rfc/rfcNNNN.json`): titles, status and
  the obsoleted-by and updated-by relations.
