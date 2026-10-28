//! `RTM_NEWROUTE` / `RTM_DELROUTE` / `RTM_GETROUTE` messages
//! (`<linux/rtnetlink.h>`, `rtnetlink(7)`), pure.
//!
//! Implements: route installation with our protocol number in one table
//! (README, "FIB dry-run"); RFC 8950 §3 next hops (an IPv6 gateway for an
//! IPv4 route goes in `RTA_VIA` as a `struct rtvia`, since `RTA_GATEWAY`
//! holds an address of the route's own family).

use std::net::IpAddr;

use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::Afi;

use crate::netlink::{self, Attr, NetlinkError};
use crate::reconcile::Hop;

/// `RTM_NEWROUTE`.
pub const RTM_NEWROUTE: u16 = 24;
/// `RTM_DELROUTE`.
pub const RTM_DELROUTE: u16 = 25;
/// `RTM_GETROUTE`.
pub const RTM_GETROUTE: u16 = 26;

/// `RTPROT_BGP`, the default protocol number our routes carry.
pub const RTPROT_BGP: u8 = 186;
/// `RT_TABLE_MAIN`.
pub const RT_TABLE_MAIN: u32 = 254;
/// `RT_TABLE_UNSPEC`: what `rtm_table` holds when `RTA_TABLE` carries a
/// table id above 255.
const RT_TABLE_UNSPEC: u8 = 0;
/// `RTN_UNICAST`.
pub(crate) const RTN_UNICAST: u8 = 1;
/// `RT_SCOPE_UNIVERSE`.
const RT_SCOPE_UNIVERSE: u8 = 0;
/// `RT_SCOPE_NOWHERE`: what `ip route del` sends.
const RT_SCOPE_NOWHERE: u8 = 255;
/// `RTM_F_CLONED`: routes the kernel made itself; never ours.
pub(crate) const RTM_F_CLONED: u32 = 0x200;
/// `RTNH_F_ONLINK`: the gateway is taken to be on the link of the
/// interface, though no route covers it, as `ip route add ... onlink`
/// says; the kernel refuses a gateway no route covers otherwise. In
/// `rtm_flags` for a route with one next hop, in `rtnh_flags` for each of
/// several.
pub const RTNH_F_ONLINK: u8 = 4;

// enum rtattr_type_t
pub(crate) const RTA_DST: u16 = 1;
pub(crate) const RTA_OIF: u16 = 4;
pub(crate) const RTA_GATEWAY: u16 = 5;
pub(crate) const RTA_PRIORITY: u16 = 6;
pub(crate) const RTA_TABLE: u16 = 15;
pub(crate) const RTA_VIA: u16 = 18;

// <bits/socket.h>
pub(crate) const AF_INET: u8 = 2;
pub(crate) const AF_INET6: u8 = 10;

/// `offsetof(struct rtvia, rtvia_addr)`: `<linux/rtnetlink.h>` declares
/// `struct rtvia { __kernel_sa_family_t rtvia_family; __u8 rtvia_addr[]; }`,
/// and `__kernel_sa_family_t` is an `unsigned short` in host byte order
/// (`<linux/socket.h>`).
const RTVIA_ADDR_OFFSET: usize = 2;

/// `sizeof(struct rtmsg)`.
pub(crate) const RTMSG_LEN: usize = 12;

/// The metric every route we install gets (`RTA_PRIORITY`), the one FRR's
/// zebra gives every route it installs. The kernel keeps routes to one
/// destination with different metrics apart and forwards through the
/// lowest; one with the same metric would be replaced by ours, so ours
/// goes in only where none has it ([`RouteMsg::encode_add_with`]).
pub const METRIC: u32 = 20;

/// A unicast route as this daemon installs or reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteMsg {
    /// The destination.
    pub dst: Prefix,
    /// The routing table.
    pub table: u32,
    /// `rtm_protocol`.
    pub protocol: u8,
    /// The gateway, if any (a connected route has none).
    pub gateway: Option<IpAddr>,
    /// `RTA_OIF`, if present.
    pub oif: Option<u32>,
    /// `RTA_PRIORITY`, if present.
    pub priority: Option<u32>,
    /// `rtm_type`.
    pub kind: u8,
    /// `rtm_flags`.
    pub flags: u32,
}

impl RouteMsg {
    /// A unicast route to `dst` through `hop` (its gateway, and its
    /// interface as `RTA_OIF` when it has one, `RTNH_F_ONLINK` when the
    /// gateway is on its link though no route covers it) with our metric.
    #[must_use]
    pub fn unicast(dst: Prefix, hop: Hop, table: u32, protocol: u8) -> RouteMsg {
        RouteMsg {
            dst,
            table,
            protocol,
            gateway: Some(hop.gateway),
            oif: hop.oif,
            priority: Some(METRIC),
            kind: RTN_UNICAST,
            flags: if hop.onlink {
                u32::from(RTNH_F_ONLINK)
            } else {
                0
            },
        }
    }

    /// Whether the route's gateway is on its interface's link though no
    /// route covers it (`RTNH_F_ONLINK` in `rtm_flags`).
    #[must_use]
    pub fn onlink(&self) -> bool {
        self.flags & u32::from(RTNH_F_ONLINK) != 0
    }

    fn family(&self) -> u8 {
        match self.dst.afi() {
            Afi::Ipv6 => AF_INET6,
            _ => AF_INET,
        }
    }

    fn table_byte(&self) -> u8 {
        u8::try_from(self.table).unwrap_or(RT_TABLE_UNSPEC)
    }

    /// The `struct rtmsg` and attributes of a request.
    fn payload(&self, scope: u8, kind: u8) -> Vec<u8> {
        let mut p = vec![
            self.family(),
            self.dst.prefix_len(),
            0, // rtm_src_len
            0, // rtm_tos
            self.table_byte(),
            self.protocol,
            scope,
            kind,
        ];
        // rtm_flags: what `unicast` set, RTNH_F_ONLINK or nothing.
        p.extend_from_slice(&self.flags.to_ne_bytes());
        netlink::push_attr(&mut p, RTA_DST, &addr_bytes(self.dst.addr()));
        if let Some(gw) = self.gateway {
            match (self.dst.afi(), gw) {
                // RFC 8950 §3: an IPv6 next hop for IPv4 NLRI. RTA_GATEWAY
                // only holds an address of the route's family, so the kernel
                // takes this one as RTA_VIA, as `ip route add ... via inet6`
                // sends it.
                (Afi::Ipv4, IpAddr::V6(_)) => netlink::push_attr(&mut p, RTA_VIA, &encode_via(gw)),
                _ => netlink::push_attr(&mut p, RTA_GATEWAY, &addr_bytes(gw)),
            }
        }
        if let Some(oif) = self.oif {
            netlink::push_attr(&mut p, RTA_OIF, &oif.to_ne_bytes());
        }
        if let Some(prio) = self.priority {
            netlink::push_attr(&mut p, RTA_PRIORITY, &prio.to_ne_bytes());
        }
        if self.table > 255 {
            netlink::push_attr(&mut p, RTA_TABLE, &self.table.to_ne_bytes());
        }
        p
    }

    /// `RTM_NEWROUTE` with `NLM_F_CREATE | NLM_F_REPLACE`: add, or replace
    /// the first route with this destination and metric, whoever's it is.
    /// For a route of ours whose hop changes, which must not leave the
    /// destination without a route in between.
    #[must_use]
    pub fn encode_set(&self, seq: u32) -> Vec<u8> {
        self.encode_set_with(seq, true)
    }

    /// `RTM_NEWROUTE` with `NLM_F_CREATE | NLM_F_EXCL`: add where no route
    /// has this destination and metric, and only there. The kernel answers
    /// `EEXIST` where one has: another program's route, which is not ours
    /// to replace (AGENTS.md §3, "Never touch routes with another protocol
    /// number"). With an acknowledgement only if `ack`.
    #[must_use]
    pub fn encode_add_with(&self, seq: u32, ack: bool) -> Vec<u8> {
        netlink::encode(
            RTM_NEWROUTE,
            netlink::NLM_F_REQUEST
                | if ack { netlink::NLM_F_ACK } else { 0 }
                | netlink::NLM_F_CREATE
                | netlink::NLM_F_EXCL,
            seq,
            &self.payload(RT_SCOPE_UNIVERSE, RTN_UNICAST),
        )
    }

    /// As [`RouteMsg::encode_set`], asking for an acknowledgement only if
    /// `ack`: the kernel reports a failure either way (`netlink(7)`,
    /// `NLM_F_ACK`), so in a batch only the last request needs one.
    #[must_use]
    pub fn encode_set_with(&self, seq: u32, ack: bool) -> Vec<u8> {
        netlink::encode(
            RTM_NEWROUTE,
            netlink::NLM_F_REQUEST
                | if ack { netlink::NLM_F_ACK } else { 0 }
                | netlink::NLM_F_CREATE
                | netlink::NLM_F_REPLACE,
            seq,
            &self.payload(RT_SCOPE_UNIVERSE, RTN_UNICAST),
        )
    }

    /// `RTM_DELROUTE`.
    #[must_use]
    pub fn encode_delete(&self, seq: u32) -> Vec<u8> {
        self.encode_delete_with(seq, true)
    }

    /// As [`RouteMsg::encode_delete`], with an acknowledgement only if
    /// `ack` (see [`RouteMsg::encode_set_with`]).
    #[must_use]
    pub fn encode_delete_with(&self, seq: u32, ack: bool) -> Vec<u8> {
        netlink::encode(
            RTM_DELROUTE,
            netlink::NLM_F_REQUEST | if ack { netlink::NLM_F_ACK } else { 0 },
            seq,
            &self.payload(RT_SCOPE_NOWHERE, 0),
        )
    }

    /// `RTM_GETROUTE` with `NLM_F_DUMP` for one family.
    #[must_use]
    pub fn encode_dump(afi: Afi, seq: u32) -> Vec<u8> {
        let mut p = vec![0u8; RTMSG_LEN];
        p[0] = match afi {
            Afi::Ipv6 => AF_INET6,
            _ => AF_INET,
        };
        netlink::encode(
            RTM_GETROUTE,
            netlink::NLM_F_REQUEST | netlink::NLM_F_DUMP,
            seq,
            &p,
        )
    }

    /// Decode an `RTM_NEWROUTE` payload from a dump. `None` for a route
    /// this daemon could never have installed (not unicast, cloned, or a
    /// family or address it cannot represent).
    ///
    /// # Errors
    /// [`NetlinkError`] on malformed bytes.
    pub fn decode(payload: &[u8]) -> Result<Option<RouteMsg>, NetlinkError> {
        if payload.len() < RTMSG_LEN {
            return Err(NetlinkError::ShortRoute);
        }
        let family = payload[0];
        let dst_len = payload[1];
        let table_byte = payload[4];
        let protocol = payload[5];
        let kind = payload[7];
        let flags = u32::from_ne_bytes([payload[8], payload[9], payload[10], payload[11]]);
        let attrs = netlink::parse_attrs(&payload[RTMSG_LEN..])?;
        let afi = match family {
            AF_INET => Afi::Ipv4,
            AF_INET6 => Afi::Ipv6,
            _ => return Ok(None),
        };
        let mut dst = None;
        let mut gateway = None;
        let mut oif = None;
        let mut priority = None;
        let mut table = u32::from(table_byte);
        for Attr { ty, value } in attrs {
            match ty {
                RTA_DST => dst = parse_addr(afi, value),
                RTA_GATEWAY => gateway = parse_addr(afi, value),
                RTA_VIA => gateway = decode_via(value),
                RTA_OIF => oif = parse_u32(value),
                RTA_PRIORITY => priority = parse_u32(value),
                RTA_TABLE => {
                    if let Some(t) = parse_u32(value) {
                        table = t;
                    }
                }
                _ => {}
            }
        }
        if kind != RTN_UNICAST || flags & RTM_F_CLONED != 0 {
            return Ok(None);
        }
        let dst = match dst {
            Some(a) => Prefix::new(a, dst_len),
            None => Prefix::default_route(afi),
        };
        let Some(dst) = dst else {
            return Ok(None);
        };
        Ok(Some(RouteMsg {
            dst,
            table,
            protocol,
            gateway,
            oif,
            priority,
            kind,
            flags,
        }))
    }
}

/// The value of an `RTA_VIA` attribute: a `struct rtvia` holding `gw`
/// (`<linux/rtnetlink.h>`).
fn encode_via(gw: IpAddr) -> Vec<u8> {
    let family = match gw {
        IpAddr::V4(_) => AF_INET,
        IpAddr::V6(_) => AF_INET6,
    };
    let mut via = u16::from(family).to_ne_bytes().to_vec();
    via.extend_from_slice(&addr_bytes(gw));
    via
}

/// The gateway in an `RTA_VIA` value (`struct rtvia`, `<linux/rtnetlink.h>`),
/// or `None` for a family other than IPv4 and IPv6 (the kernel also uses
/// it for MPLS) or an address of the wrong length.
pub(crate) fn decode_via(value: &[u8]) -> Option<IpAddr> {
    let family = <[u8; RTVIA_ADDR_OFFSET]>::try_from(value.get(..RTVIA_ADDR_OFFSET)?).ok()?;
    let family = u16::from_ne_bytes(family);
    let addr = value.get(RTVIA_ADDR_OFFSET..)?;
    if family == u16::from(AF_INET6) {
        parse_addr(Afi::Ipv6, addr)
    } else if family == u16::from(AF_INET) {
        parse_addr(Afi::Ipv4, addr)
    } else {
        None
    }
}

fn addr_bytes(a: IpAddr) -> Vec<u8> {
    match a {
        IpAddr::V4(v) => v.octets().to_vec(),
        IpAddr::V6(v) => v.octets().to_vec(),
    }
}

pub(crate) fn parse_addr(afi: Afi, value: &[u8]) -> Option<IpAddr> {
    match afi {
        Afi::Ipv4 => <[u8; 4]>::try_from(value).ok().map(IpAddr::from),
        Afi::Ipv6 => <[u8; 16]>::try_from(value).ok().map(IpAddr::from),
        Afi::Unknown(_) => None,
    }
}

pub(crate) fn parse_u32(value: &[u8]) -> Option<u32> {
    <[u8; 4]>::try_from(value).ok().map(u32::from_ne_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// A hop through `gateway`, with no interface.
    fn h(gateway: &str) -> Hop {
        Hop {
            gateway: ip(gateway),
            oif: None,
            onlink: false,
        }
    }

    /// Replace the sequence number and flags of a framed message so a
    /// capture from `ip route` (which uses `NLM_F_EXCL|NLM_F_CREATE` and
    /// its own sequence) compares equal.
    fn normalise(mut m: Vec<u8>) -> Vec<u8> {
        m[6..8].copy_from_slice(&0u16.to_ne_bytes());
        m[8..12].copy_from_slice(&0u32.to_ne_bytes());
        m
    }

    /// Captured with `strace -e trace=sendmsg ip route add 192.0.2.0/24
    /// via 127.0.0.1 proto 186 metric 20` (payload after the header).
    const ADD4_PAYLOAD: [u8; 36] = [
        0x02, 0x18, 0x00, 0x00, 0xfe, 0xba, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x01,
        0x00, 0xc0, 0x00, 0x02, 0x00, 0x08, 0x00, 0x05, 0x00, 0x7f, 0x00, 0x00, 0x01, 0x08, 0x00,
        0x06, 0x00, 0x14, 0x00, 0x00, 0x00,
    ];
    /// `ip route del 192.0.2.0/24 via 127.0.0.1 proto 186 metric 20`.
    const DEL4_PAYLOAD: [u8; 36] = [
        0x02, 0x18, 0x00, 0x00, 0xfe, 0xba, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x01,
        0x00, 0xc0, 0x00, 0x02, 0x00, 0x08, 0x00, 0x05, 0x00, 0x7f, 0x00, 0x00, 0x01, 0x08, 0x00,
        0x06, 0x00, 0x14, 0x00, 0x00, 0x00,
    ];
    /// `ip -6 route add 2001:db8:1::/48 via ::1 proto 186 metric 20`.
    const ADD6_PAYLOAD: [u8; 60] = [
        0x0a, 0x30, 0x00, 0x00, 0xfe, 0xba, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x01,
        0x00, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x14, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x06, 0x00, 0x14, 0x00, 0x00, 0x00,
    ];
    /// `ip route add 203.0.113.0/24 via 127.0.0.1 proto 186 table 300`:
    /// `rtm_table` 0 and `RTA_TABLE` 300 (and no metric).
    const TABLE300_PAYLOAD: [u8; 36] = [
        0x02, 0x18, 0x00, 0x00, 0x00, 0xba, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x01,
        0x00, 0xcb, 0x00, 0x71, 0x00, 0x08, 0x00, 0x05, 0x00, 0x7f, 0x00, 0x00, 0x01, 0x08, 0x00,
        0x0f, 0x00, 0x2c, 0x01, 0x00, 0x00,
    ];

    fn framed(ty: u16, payload: &[u8]) -> Vec<u8> {
        normalise(netlink::encode(ty, 0, 0, payload))
    }

    #[test]
    fn requests_match_iproute2_captures() {
        let r = RouteMsg::unicast(p("192.0.2.0/24"), h("127.0.0.1"), RT_TABLE_MAIN, RTPROT_BGP);
        assert_eq!(
            normalise(r.encode_set(5)),
            framed(RTM_NEWROUTE, &ADD4_PAYLOAD)
        );
        assert_eq!(
            normalise(r.encode_delete(5)),
            framed(RTM_DELROUTE, &DEL4_PAYLOAD)
        );
        let r6 = RouteMsg::unicast(p("2001:db8:1::/48"), h("::1"), RT_TABLE_MAIN, RTPROT_BGP);
        assert_eq!(
            normalise(r6.encode_set(1)),
            framed(RTM_NEWROUTE, &ADD6_PAYLOAD)
        );
        let mut t = RouteMsg::unicast(p("203.0.113.0/24"), h("127.0.0.1"), 300, RTPROT_BGP);
        t.priority = None;
        assert_eq!(
            normalise(t.encode_set(1)),
            framed(RTM_NEWROUTE, &TABLE300_PAYLOAD)
        );
        // `ip route add` asks for NLM_F_EXCL, as a route of ours sent the
        // first time does.
        let add = r.encode_add_with(5, true);
        assert_eq!(
            u16::from_ne_bytes([add[6], add[7]]),
            netlink::NLM_F_REQUEST
                | netlink::NLM_F_ACK
                | netlink::NLM_F_CREATE
                | netlink::NLM_F_EXCL
        );
        assert_eq!(normalise(add), framed(RTM_NEWROUTE, &ADD4_PAYLOAD));
        let quiet = r.encode_add_with(5, false);
        assert_eq!(
            u16::from_ne_bytes([quiet[6], quiet[7]]),
            netlink::NLM_F_REQUEST | netlink::NLM_F_CREATE | netlink::NLM_F_EXCL
        );
        // Flags we send for a route of ours whose hop changes.
        let m = r.encode_set(9);
        assert_eq!(
            u16::from_ne_bytes([m[6], m[7]]),
            netlink::NLM_F_REQUEST
                | netlink::NLM_F_ACK
                | netlink::NLM_F_CREATE
                | netlink::NLM_F_REPLACE
        );
        assert_eq!(u32::from_ne_bytes([m[8], m[9], m[10], m[11]]), 9);
        let d = RouteMsg::encode_dump(Afi::Ipv6, 3);
        assert_eq!(d.len(), 28);
        assert_eq!(u16::from_ne_bytes([d[4], d[5]]), RTM_GETROUTE);
        assert_eq!(
            u16::from_ne_bytes([d[6], d[7]]),
            netlink::NLM_F_REQUEST | netlink::NLM_F_DUMP
        );
        assert_eq!(d[16], AF_INET6);
    }

    /// `strace -e trace=sendmsg ip route add 198.51.100.0/24 via inet6
    /// 2001:db8::1 proto 186 metric 20` (iproute2 6.1): `RTA_DST`, then
    /// `RTA_VIA` holding `struct rtvia` (`rtvia_family` `AF_INET6` in host
    /// order on x86-64, the 16 address octets, two octets of padding), then
    /// `RTA_PRIORITY`.
    const ADD_VIA6_PAYLOAD: [u8; 52] = [
        0x02, 0x18, 0x00, 0x00, 0xfe, 0xba, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x01,
        0x00, 0xc6, 0x33, 0x64, 0x00, 0x16, 0x00, 0x12, 0x00, 0x0a, 0x00, 0x20, 0x01, 0x0d, 0xb8,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x08,
        0x00, 0x06, 0x00, 0x14, 0x00, 0x00, 0x00,
    ];
    /// `ip route del 198.51.100.0/24 via inet6 2001:db8::1 proto 186
    /// metric 20`.
    const DEL_VIA6_PAYLOAD: [u8; 52] = [
        0x02, 0x18, 0x00, 0x00, 0xfe, 0xba, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x01,
        0x00, 0xc6, 0x33, 0x64, 0x00, 0x16, 0x00, 0x12, 0x00, 0x0a, 0x00, 0x20, 0x01, 0x0d, 0xb8,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x08,
        0x00, 0x06, 0x00, 0x14, 0x00, 0x00, 0x00,
    ];
    /// An `RTM_NEWROUTE` dump entry for that route, laid out as the
    /// kernel's `fib_dump_info` and `fib_nexthop_info`
    /// (`net/ipv4/fib_semantics.c`) emit it: `RTA_TABLE`, `RTA_DST`,
    /// `RTA_PRIORITY`, then the next hop as `RTA_VIA` and `RTA_OIF` 2. Not
    /// a capture: the build host boots with IPv6 disabled, so its kernel
    /// refuses the route.
    const DUMP_VIA6_PAYLOAD: [u8; 68] = [
        0x02, 0x18, 0x00, 0x00, 0xfe, 0xba, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // rtmsg
        0x08, 0x00, 0x0f, 0x00, 0xfe, 0x00, 0x00, 0x00, // RTA_TABLE 254
        0x08, 0x00, 0x01, 0x00, 0xc6, 0x33, 0x64, 0x00, // RTA_DST
        0x08, 0x00, 0x06, 0x00, 0x14, 0x00, 0x00, 0x00, // RTA_PRIORITY 20
        0x16, 0x00, 0x12, 0x00, 0x0a, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, // RTA_VIA
        0x08, 0x00, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00, // RTA_OIF 2
    ];

    #[test]
    fn ipv4_route_with_ipv6_gateway_matches_iproute2() {
        // RFC 8950 §3 next hop in the FIB: RTA_VIA, never RTA_GATEWAY.
        let r = RouteMsg::unicast(
            p("198.51.100.0/24"),
            h("2001:db8::1"),
            RT_TABLE_MAIN,
            RTPROT_BGP,
        );
        assert_eq!(
            normalise(r.encode_set(1)),
            framed(RTM_NEWROUTE, &ADD_VIA6_PAYLOAD)
        );
        assert_eq!(
            normalise(r.encode_delete(1)),
            framed(RTM_DELROUTE, &DEL_VIA6_PAYLOAD)
        );
        // What we send decodes back to the same route.
        let m = r.encode_set(1);
        assert_eq!(
            RouteMsg::decode(&m[netlink::HEADER_LEN..]).unwrap(),
            Some(r.clone())
        );
        // A kernel dump entry decodes to the route plus its interface.
        let back = RouteMsg::decode(&DUMP_VIA6_PAYLOAD).unwrap().unwrap();
        assert_eq!(back, RouteMsg { oif: Some(2), ..r });
    }

    #[test]
    fn rta_via_values() {
        // struct rtvia: family in host order, then the address.
        let v6 = encode_via(ip("2001:db8::1"));
        assert_eq!(v6.len(), 18);
        assert_eq!(&v6[..2], &u16::from(AF_INET6).to_ne_bytes());
        assert_eq!(decode_via(&v6), Some(ip("2001:db8::1")));
        let v4 = encode_via(ip("192.0.2.1"));
        assert_eq!(v4.len(), 6);
        assert_eq!(decode_via(&v4), Some(ip("192.0.2.1")));
        // Too short for the family, an address of the wrong length, and
        // another family (AF_MPLS, 28, which the kernel also puts in
        // RTA_VIA): no gateway, and no panic.
        assert_eq!(decode_via(&[]), None);
        assert_eq!(decode_via(&[0x0a]), None);
        assert_eq!(decode_via(&v6[..17]), None);
        assert_eq!(decode_via(&v4[..5]), None);
        let mut mpls = 28u16.to_ne_bytes().to_vec();
        mpls.extend_from_slice(&[0, 0, 0x10, 0]);
        assert_eq!(decode_via(&mpls), None);
        // In a dump entry the route is still read, without a gateway.
        // RTA_VIA starts at octet 36: length, type, then rtvia_family.
        let mut bad = DUMP_VIA6_PAYLOAD;
        assert_eq!(&bad[36..40], &[0x16, 0x00, 0x12, 0x00]);
        bad[40..42].copy_from_slice(&28u16.to_ne_bytes());
        let r = RouteMsg::decode(&bad).unwrap().unwrap();
        assert_eq!(r.gateway, None);
        assert_eq!(r.dst, p("198.51.100.0/24"));
    }

    #[test]
    fn decode_round_trips_and_filters() {
        for (prefix, gw, table) in [
            ("192.0.2.0/24", "10.0.0.1", RT_TABLE_MAIN),
            ("2001:db8:1::/48", "2001:db8::1", RT_TABLE_MAIN),
            ("0.0.0.0/0", "10.0.0.1", 300),
            ("::/0", "2001:db8::1", RT_TABLE_MAIN),
        ] {
            let r = RouteMsg::unicast(p(prefix), h(gw), table, RTPROT_BGP);
            let m = r.encode_set(1);
            let back = RouteMsg::decode(&m[netlink::HEADER_LEN..])
                .unwrap()
                .unwrap();
            assert_eq!(back, r, "{prefix}");
        }
        // Not unicast, cloned, unknown family: None.
        let r = RouteMsg::unicast(p("192.0.2.0/24"), h("10.0.0.1"), RT_TABLE_MAIN, RTPROT_BGP);
        let mut m = r.encode_set(1);
        m[netlink::HEADER_LEN + 7] = 6; // RTN_BLACKHOLE
        assert_eq!(RouteMsg::decode(&m[netlink::HEADER_LEN..]).unwrap(), None);
        let mut m = r.encode_set(1);
        m[netlink::HEADER_LEN + 8..netlink::HEADER_LEN + 12]
            .copy_from_slice(&RTM_F_CLONED.to_ne_bytes());
        assert_eq!(RouteMsg::decode(&m[netlink::HEADER_LEN..]).unwrap(), None);
        let mut m = r.encode_set(1);
        m[netlink::HEADER_LEN] = 7; // AF_BRIDGE
        assert_eq!(RouteMsg::decode(&m[netlink::HEADER_LEN..]).unwrap(), None);
        assert_eq!(RouteMsg::decode(&[0; 5]), Err(NetlinkError::ShortRoute));
        // A dst of the wrong length is not a prefix.
        let mut m = r.encode_set(1);
        m[netlink::HEADER_LEN + 1] = 40;
        assert_eq!(RouteMsg::decode(&m[netlink::HEADER_LEN..]).unwrap(), None);
    }

    /// A hop with an interface: `RTA_OIF` after the gateway, as `ip route
    /// add ... via GATEWAY dev DEV` sends it, in a set and in a delete,
    /// and back.
    #[test]
    fn a_hop_with_an_interface_names_it() {
        let hop = Hop {
            gateway: ip("10.0.0.9"),
            oif: Some(3),
            onlink: false,
        };
        let r = RouteMsg::unicast(p("192.0.2.0/24"), hop, RT_TABLE_MAIN, RTPROT_BGP);
        assert_eq!(r.oif, Some(3));
        for m in [r.encode_set(1), r.encode_delete(1)] {
            let attrs = netlink::parse_attrs(&m[netlink::HEADER_LEN + RTMSG_LEN..]).unwrap();
            let types: Vec<u16> = attrs.iter().map(|a| a.ty).collect();
            assert_eq!(types, [RTA_DST, RTA_GATEWAY, RTA_OIF, RTA_PRIORITY]);
            assert_eq!(attrs[2].value, 3u32.to_ne_bytes());
        }
        let back = RouteMsg::decode(&r.encode_set(1)[netlink::HEADER_LEN..]).unwrap();
        assert_eq!(back, Some(r));
    }

    /// `strace -e trace=sendmsg ip route add 203.0.113.0/24 via
    /// 192.168.77.1 dev v0 proto 186 metric 20 onlink`, with `v0` at index
    /// 3 and no route covering the gateway: `rtm_flags` 4,
    /// `RTNH_F_ONLINK`, without which the kernel refuses such a gateway
    /// ("Nexthop has invalid gateway"). iproute2 puts `RTA_OIF` last.
    const ADD_ONLINK_PAYLOAD: [u8; 44] = [
        0x02, 0x18, 0x00, 0x00, 0xfe, 0xba, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, // rtmsg
        0x08, 0x00, 0x01, 0x00, 0xcb, 0x00, 0x71, 0x00, // RTA_DST
        0x08, 0x00, 0x05, 0x00, 0xc0, 0xa8, 0x4d, 0x01, // RTA_GATEWAY
        0x08, 0x00, 0x06, 0x00, 0x14, 0x00, 0x00, 0x00, // RTA_PRIORITY 20
        0x08, 0x00, 0x04, 0x00, 0x03, 0x00, 0x00, 0x00, // RTA_OIF 3
    ];

    /// The `struct rtmsg` of a payload and its attributes, in type order:
    /// the kernel reads them in any order.
    fn parts(payload: &[u8]) -> (Vec<u8>, Vec<(u16, Vec<u8>)>) {
        let mut attrs: Vec<(u16, Vec<u8>)> = netlink::parse_attrs(&payload[RTMSG_LEN..])
            .unwrap()
            .into_iter()
            .map(|a| (a.ty, a.value.to_vec()))
            .collect();
        attrs.sort();
        (payload[..RTMSG_LEN].to_vec(), attrs)
    }

    /// A hop whose gateway the kernel route that resolves it has `onlink`
    /// goes in with `RTNH_F_ONLINK` too, as iproute2 sends it, in a set
    /// and in a delete, and back.
    #[test]
    fn an_onlink_hop_says_so() {
        let hop = Hop {
            gateway: ip("192.168.77.1"),
            oif: Some(3),
            onlink: true,
        };
        let r = RouteMsg::unicast(p("203.0.113.0/24"), hop, RT_TABLE_MAIN, RTPROT_BGP);
        assert!(r.onlink());
        let set = r.encode_set(1);
        assert_eq!(
            parts(&set[netlink::HEADER_LEN..]),
            parts(&ADD_ONLINK_PAYLOAD)
        );
        let delete = r.encode_delete(1);
        assert_eq!(delete[netlink::HEADER_LEN + 8], RTNH_F_ONLINK);
        let back = RouteMsg::decode(&set[netlink::HEADER_LEN..])
            .unwrap()
            .unwrap();
        assert_eq!(back, r);
        assert!(back.onlink());
        assert!(
            RouteMsg::decode(&ADD_ONLINK_PAYLOAD)
                .unwrap()
                .unwrap()
                .onlink()
        );
        // Without it, nothing in rtm_flags.
        let plain = RouteMsg::unicast(
            p("203.0.113.0/24"),
            Hop {
                onlink: false,
                ..hop
            },
            RT_TABLE_MAIN,
            RTPROT_BGP,
        );
        assert!(!plain.onlink());
        assert_eq!(plain.encode_set(1)[netlink::HEADER_LEN + 8], 0);
    }
}
