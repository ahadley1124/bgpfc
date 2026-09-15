# Resources

Specifications relevant to this project. Pruned to match the scope in the
[README](README.md) — RFCs covering declared non-goals (MPLS VPNs, BGP-LS,
Segment Routing, BGPsec) have been removed, and several titles that were wrong
in the prototype's version of this file are corrected here.

Three of these are also saved offline under [`resources/`](resources/) for
working without a network.

## Core BGP-4

- [RFC 4271 - A Border Gateway Protocol 4 (BGP-4)](https://datatracker.ietf.org/doc/html/rfc4271) — the base spec; §4 wire format, §8 FSM, §9 decision process
- [RFC 4632 - Classless Inter-domain Routing (CIDR)](https://datatracker.ietf.org/doc/html/rfc4632)
- [RFC 5492 - Capabilities Advertisement with BGP-4](https://datatracker.ietf.org/doc/html/rfc5492)
- [RFC 4760 - Multiprotocol Extensions for BGP-4](https://datatracker.ietf.org/doc/html/rfc4760) — MP_REACH_NLRI / MP_UNREACH_NLRI, IPv6
- [RFC 2918 - Route Refresh Capability for BGP-4](https://datatracker.ietf.org/doc/html/rfc2918)
- [RFC 6793 - BGP Support for Four-Octet Autonomous System (AS) Number Space](https://datatracker.ietf.org/doc/html/rfc6793) — AS_TRANS, AS4_PATH
- [RFC 6286 - Autonomous-System-Wide Unique BGP Identifier for BGP-4](https://datatracker.ietf.org/doc/html/rfc6286) — collision detection tie-break
- [RFC 7606 - Revised Error Handling for BGP UPDATE Messages](https://datatracker.ietf.org/doc/html/rfc7606) — treat-as-withdraw vs. session reset
- [RFC 9774 - Deprecation of AS_SET and AS_CONFED_SET in BGP](https://datatracker.ietf.org/doc/html/rfc9774)
- [RFC 1997 - BGP Communities Attribute](https://datatracker.ietf.org/doc/html/rfc1997)
- [RFC 8092 - BGP Large Communities Attribute](https://datatracker.ietf.org/doc/html/rfc8092)
- [RFC 8212 - Default External BGP (EBGP) Route Propagation Behavior without Policies](https://datatracker.ietf.org/doc/html/rfc8212) — the standards basis for reject-by-default

## Session security and transport

Not in v1 scope; listed because both require reaching past `std` and that
constraint shapes the design.

- [RFC 2385 - Protection of BGP Sessions via the TCP MD5 Signature Option](https://datatracker.ietf.org/doc/html/rfc2385)
- [RFC 5925 - The TCP Authentication Option](https://datatracker.ietf.org/doc/html/rfc5925)
- [RFC 5082 - The Generalized TTL Security Mechanism (GTSM)](https://datatracker.ietf.org/doc/html/rfc5082)

## RPKI and origin validation

- [RFC 6480 - An Architecture for the Resource Public Key Infrastructure (RPKI)](https://datatracker.ietf.org/doc/html/rfc6480)
- [RFC 6481 - A Profile for Resource Certificate Repository Structure](https://datatracker.ietf.org/doc/html/rfc6481)
- [RFC 6483 - Validation of Route Origination Using the Resource Certificate PKI and ROAs](https://datatracker.ietf.org/doc/html/rfc6483)
- [RFC 6811 - BGP Prefix Origin Validation](https://datatracker.ietf.org/doc/html/rfc6811) — Valid / NotFound / Invalid
- [RFC 8097 - BGP Prefix Origin Validation State Extended Community](https://datatracker.ietf.org/doc/html/rfc8097)
- [RFC 8210 - The RPKI to Router Protocol, Version 1](https://datatracker.ietf.org/doc/html/rfc8210) — the RTR client target
- [RFC 8893 - Resource Public Key Infrastructure (RPKI) Origin Validation for BGP Export](https://datatracker.ietf.org/doc/html/rfc8893)
- [RFC 9319 - The Use of maxLength in the RPKI](https://datatracker.ietf.org/doc/html/rfc9319)
- [RFC 9582 - A Profile for Route Origin Authorizations (ROAs)](https://datatracker.ietf.org/doc/html/rfc9582)

### What the sidecar handles, not this project

Context for the Routinator-as-sidecar decision — this is the work that is
deliberately not reimplemented here.

- [RFC 8182 - The RPKI Repository Delta Protocol (RRDP)](https://datatracker.ietf.org/doc/html/rfc8182)
- [RFC 9286 - Manifests for the Resource Public Key Infrastructure (RPKI)](https://datatracker.ietf.org/doc/html/rfc9286)
- [RFC 6487 - A Profile for X.509 PKIX Resource Certificates](https://datatracker.ietf.org/doc/html/rfc6487)
- [RFC 6488 - Signed Object Template for the Resource Public Key Infrastructure (RPKI)](https://datatracker.ietf.org/doc/html/rfc6488)
- [RFC 6490 - Resource Public Key Infrastructure (RPKI) Trust Anchor Locator](https://datatracker.ietf.org/doc/html/rfc6490)

## ASPA — draft-track, opt-in, v1.1

These are Internet-Drafts, not published RFCs. They are expected to change, and
the datatracker links below track the current revision rather than a frozen one.
Check the state of each before implementing against it.

- [draft-ietf-sidrops-aspa-profile - A Profile for Autonomous System Provider Authorization](https://datatracker.ietf.org/doc/draft-ietf-sidrops-aspa-profile/)
- [draft-ietf-sidrops-aspa-verification - BGP AS_PATH Verification Based on ASPA Objects](https://datatracker.ietf.org/doc/draft-ietf-sidrops-aspa-verification/)
- [draft-ietf-sidrops-8210bis - The RPKI to Router Protocol, Version 2](https://datatracker.ietf.org/doc/draft-ietf-sidrops-8210bis/) — ASPA PDU transport, if stable in time

Related route-leak work, not currently in scope:

- [RFC 9234 - Route Leak Prevention and Detection Using Roles in UPDATE and OPEN Messages](https://datatracker.ietf.org/doc/html/rfc9234)

## Undecided

Neither goals nor non-goals; see the README.

- [RFC 4456 - BGP Route Reflection](https://datatracker.ietf.org/doc/html/rfc4456) — obsoletes RFC 2796
- [RFC 4724 - Graceful Restart Mechanism for BGP](https://datatracker.ietf.org/doc/html/rfc4724)
