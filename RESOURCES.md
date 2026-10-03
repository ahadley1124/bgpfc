# Resources

RFCs relevant to bgpfc, grouped by when we need them. The titles were checked
against the RFC Editor index. Offline copies of some RFCs are in
[`resources/`](resources/).

## v1: core protocol

- [RFC 4271 - A Border Gateway Protocol 4 (BGP-4)](https://datatracker.ietf.org/doc/html/rfc4271)
- [RFC 4486 - Subcodes for BGP Cease Notification Message](https://datatracker.ietf.org/doc/html/rfc4486)
- [RFC 6608 - Subcodes for BGP Finite State Machine Error](https://datatracker.ietf.org/doc/html/rfc6608)
- [RFC 7607 - Codification of AS 0 Processing](https://datatracker.ietf.org/doc/html/rfc7607)
- [RFC 9003 - Extended BGP Administrative Shutdown Communication](https://datatracker.ietf.org/doc/html/rfc9003)
- [RFC 9072 - Extended Optional Parameters Length for BGP OPEN Message](https://datatracker.ietf.org/doc/html/rfc9072)
- [RFC 9687 - Border Gateway Protocol 4 (BGP-4) Send Hold Timer](https://datatracker.ietf.org/doc/html/rfc9687)
- [RFC 9774 - Deprecation of AS_SET and AS_CONFED_SET in BGP](https://datatracker.ietf.org/doc/html/rfc9774)

## v1: capabilities, address families, robustness

- [RFC 5492 - Capabilities Advertisement with BGP-4](https://datatracker.ietf.org/doc/html/rfc5492)
- [RFC 6793 - BGP Support for Four-Octet Autonomous System (AS) Number Space](https://datatracker.ietf.org/doc/html/rfc6793)
- [RFC 4760 - Multiprotocol Extensions for BGP-4](https://datatracker.ietf.org/doc/html/rfc4760)
- [RFC 2545 - Use of BGP-4 Multiprotocol Extensions for IPv6 Inter-Domain Routing](https://datatracker.ietf.org/doc/html/rfc2545)
- [RFC 8950 - Advertising IPv4 Network Layer Reachability Information (NLRI) with an IPv6 Next Hop](https://datatracker.ietf.org/doc/html/rfc8950)
- [RFC 2918 - Route Refresh Capability for BGP-4](https://datatracker.ietf.org/doc/html/rfc2918)
- [RFC 7606 - Revised Error Handling for BGP UPDATE Messages](https://datatracker.ietf.org/doc/html/rfc7606)
- [RFC 8654 - Extended Message Support for BGP](https://datatracker.ietf.org/doc/html/rfc8654)

## v1: communities

- [RFC 1997 - BGP Communities Attribute](https://datatracker.ietf.org/doc/html/rfc1997)
- [RFC 4360 - BGP Extended Communities Attribute](https://datatracker.ietf.org/doc/html/rfc4360)
- [RFC 8092 - BGP Large Communities Attribute](https://datatracker.ietf.org/doc/html/rfc8092)

## Later: routing security

- [RFC 8212 - Default External BGP (EBGP) Route Propagation Behavior without Policies](https://datatracker.ietf.org/doc/html/rfc8212)
- [RFC 9234 - Route Leak Prevention and Detection Using Roles in UPDATE and OPEN Messages](https://datatracker.ietf.org/doc/html/rfc9234)
- [RFC 6811 - BGP Prefix Origin Validation](https://datatracker.ietf.org/doc/html/rfc6811)
- [RFC 8481 - Clarifications to BGP Origin Validation Based on RPKI](https://datatracker.ietf.org/doc/html/rfc8481)
- [RFC 8893 - Resource Public Key Infrastructure (RPKI) Origin Validation for BGP Export](https://datatracker.ietf.org/doc/html/rfc8893)
- [RFC 8210 - The Resource Public Key Infrastructure (RPKI) to Router Protocol, Version 1](https://datatracker.ietf.org/doc/html/rfc8210)

## Later: features

- [RFC 4724 - Graceful Restart Mechanism for BGP](https://datatracker.ietf.org/doc/html/rfc4724)
- [RFC 9494 - Long-Lived Graceful Restart for BGP](https://datatracker.ietf.org/doc/html/rfc9494)
- [RFC 7313 - Enhanced Route Refresh Capability for BGP-4](https://datatracker.ietf.org/doc/html/rfc7313)
- [RFC 7911 - Advertisement of Multiple Paths in BGP](https://datatracker.ietf.org/doc/html/rfc7911)
- [RFC 4456 - BGP Route Reflection: An Alternative to Full Mesh Internal BGP (IBGP)](https://datatracker.ietf.org/doc/html/rfc4456) (obsoletes RFC 2796)
- [RFC 5065 - Autonomous System Confederations for BGP](https://datatracker.ietf.org/doc/html/rfc5065)
- [RFC 7705 - Autonomous System Migration Mechanisms and Their Effects on the BGP AS_PATH Attribute](https://datatracker.ietf.org/doc/html/rfc7705)
- [RFC 6286 - Autonomous-System-Wide Unique BGP Identifier for BGP-4](https://datatracker.ietf.org/doc/html/rfc6286)
- [RFC 7947 - Internet Exchange BGP Route Server](https://datatracker.ietf.org/doc/html/rfc7947)
- [RFC 4364 - BGP/MPLS IP Virtual Private Networks (VPNs)](https://datatracker.ietf.org/doc/html/rfc4364)

## Later: RPKI infrastructure (background for an RTR client)

- [RFC 6480 - An Infrastructure to Support Secure Internet Routing](https://datatracker.ietf.org/doc/html/rfc6480)
- [RFC 6481 - A Profile for Resource Certificate Repository Structure](https://datatracker.ietf.org/doc/html/rfc6481)
- [RFC 6483 - Validation of Route Origination Using the Resource Certificate PKI and ROAs](https://datatracker.ietf.org/doc/html/rfc6483)
- [RFC 6484 - Certificate Policy (CP) for the Resource Public Key Infrastructure (RPKI)](https://datatracker.ietf.org/doc/html/rfc6484)
- [RFC 7935 - The Profile for Algorithms and Key Sizes for Use in the RPKI](https://datatracker.ietf.org/doc/html/rfc7935) (obsoletes RFC 6485)
- [RFC 6487 - A Profile for X.509 PKIX Resource Certificates](https://datatracker.ietf.org/doc/html/rfc6487)
- [RFC 6488 - Signed Object Template for the Resource Public Key Infrastructure (RPKI)](https://datatracker.ietf.org/doc/html/rfc6488)
- [RFC 6489 - Certification Authority (CA) Key Rollover in the RPKI](https://datatracker.ietf.org/doc/html/rfc6489)
- [RFC 7730 - Resource Public Key Infrastructure (RPKI) Trust Anchor Locator](https://datatracker.ietf.org/doc/html/rfc7730) (obsoletes RFC 6490)
- [RFC 6491 - Resource Public Key Infrastructure (RPKI) Objects Issued by IANA](https://datatracker.ietf.org/doc/html/rfc6491)
- [RFC 6492 - A Protocol for Provisioning Resource Certificates](https://datatracker.ietf.org/doc/html/rfc6492)
- [RFC 8182 - The RPKI Repository Delta Protocol (RRDP)](https://datatracker.ietf.org/doc/html/rfc8182)
- [RFC 8209 - A Profile for BGPsec Router Certificates, CRLs, and Certification Requests](https://datatracker.ietf.org/doc/html/rfc8209)
- [RFC 8360 - Resource Public Key Infrastructure (RPKI) Validation Reconsidered](https://datatracker.ietf.org/doc/html/rfc8360)
- [RFC 9286 - Manifests for the Resource Public Key Infrastructure (RPKI)](https://datatracker.ietf.org/doc/html/rfc9286)
- [RFC 9582 - A Profile for Route Origin Authorizations (ROAs)](https://datatracker.ietf.org/doc/html/rfc9582)

## Linux kernel interfaces (for `bgpfc-sys` / `bgpfc-fib`)

- [netlink(7)](https://man7.org/linux/man-pages/man7/netlink.7.html), [rtnetlink(7)](https://man7.org/linux/man-pages/man7/rtnetlink.7.html)
- [capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html), [proc_pid_status(5)](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html)
- `include/uapi/linux/rtnetlink.h`, `include/uapi/linux/netlink.h` in the kernel source tree
