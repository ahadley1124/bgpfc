//! `RTM_NEWROUTE` / `RTM_DELROUTE` / `RTM_GETROUTE` messages
//! (`<linux/rtnetlink.h>`, `rtnetlink(7)`), pure.
//!
//! Implements: route installation with our protocol number in one table
//! (README, "FIB dry-run"); RFC 8950 §3 next hops (an IPv6 gateway for an
//! IPv4 route goes in `RTA_VIA`).

use std::net::IpAddr;

use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::Afi;

use crate::netlink::{self, Attr, NetlinkError};

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
const RTN_UNICAST: u8 = 1;
/// `RT_SCOPE_UNIVERSE`.
const RT_SCOPE_UNIVERSE: u8 = 0;
/// `RT_SCOPE_NOWHERE`: what `ip route del` sends.
const RT_SCOPE_NOWHERE: u8 = 255;
/// `RTM_F_CLONED`: routes the kernel made itself; never ours.
const RTM_F_CLONED: u32 = 0x200;

// enum rtattr_type_t
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_PRIORITY: u16 = 6;
const RTA_TABLE: u16 = 15;
const RTA_VIA: u16 = 18;

// <bits/socket.h>
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

/// `sizeof(struct rtmsg)`.
const RTMSG_LEN: usize = 12;

/// The metric every route we install gets, as BIRD and FRR do for
/// external BGP routes (`RTA_PRIORITY`).
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
    /// A unicast route to `dst` via `gateway` with our metric.
    #[must_use]
    pub fn unicast(dst: Prefix, gateway: IpAddr, table: u32, protocol: u8) -> RouteMsg {
        RouteMsg {
            dst,
            table,
            protocol,
            gateway: Some(gateway),
            oif: None,
            priority: Some(METRIC),
            kind: RTN_UNICAST,
            flags: 0,
        }
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
        p.extend_from_slice(&0u32.to_ne_bytes()); // rtm_flags
        netlink::push_attr(&mut p, RTA_DST, &addr_bytes(self.dst.addr()));
        if let Some(gw) = self.gateway {
            match (self.dst.afi(), gw) {
                // RFC 8950 §3: an IPv6 next hop for IPv4 NLRI; the kernel
                // takes it as `struct rtvia { family, addr }`.
                (Afi::Ipv4, IpAddr::V6(v6)) => {
                    let mut via = u16::from(AF_INET6).to_ne_bytes().to_vec();
                    via.extend_from_slice(&v6.octets());
                    netlink::push_attr(&mut p, RTA_VIA, &via);
                }
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

    /// `RTM_NEWROUTE` with `NLM_F_CREATE | NLM_F_REPLACE`: add or replace.
    #[must_use]
    pub fn encode_set(&self, seq: u32) -> Vec<u8> {
        netlink::encode(
            RTM_NEWROUTE,
            netlink::NLM_F_REQUEST
                | netlink::NLM_F_ACK
                | netlink::NLM_F_CREATE
                | netlink::NLM_F_REPLACE,
            seq,
            &self.payload(RT_SCOPE_UNIVERSE, RTN_UNICAST),
        )
    }

    /// `RTM_DELROUTE`.
    #[must_use]
    pub fn encode_delete(&self, seq: u32) -> Vec<u8> {
        netlink::encode(
            RTM_DELROUTE,
            netlink::NLM_F_REQUEST | netlink::NLM_F_ACK,
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
                RTA_VIA => {
                    gateway = match value {
                        [f0, f1, rest @ ..] => {
                            let fam = u16::from_ne_bytes([*f0, *f1]);
                            if fam == u16::from(AF_INET6) {
                                parse_addr(Afi::Ipv6, rest)
                            } else {
                                parse_addr(Afi::Ipv4, rest)
                            }
                        }
                        _ => None,
                    };
                }
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

fn addr_bytes(a: IpAddr) -> Vec<u8> {
    match a {
        IpAddr::V4(v) => v.octets().to_vec(),
        IpAddr::V6(v) => v.octets().to_vec(),
    }
}

fn parse_addr(afi: Afi, value: &[u8]) -> Option<IpAddr> {
    match afi {
        Afi::Ipv4 => <[u8; 4]>::try_from(value).ok().map(IpAddr::from),
        Afi::Ipv6 => <[u8; 16]>::try_from(value).ok().map(IpAddr::from),
        Afi::Unknown(_) => None,
    }
}

fn parse_u32(value: &[u8]) -> Option<u32> {
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
        let r = RouteMsg::unicast(
            p("192.0.2.0/24"),
            ip("127.0.0.1"),
            RT_TABLE_MAIN,
            RTPROT_BGP,
        );
        assert_eq!(
            normalise(r.encode_set(5)),
            framed(RTM_NEWROUTE, &ADD4_PAYLOAD)
        );
        assert_eq!(
            normalise(r.encode_delete(5)),
            framed(RTM_DELROUTE, &DEL4_PAYLOAD)
        );
        let r6 = RouteMsg::unicast(p("2001:db8:1::/48"), ip("::1"), RT_TABLE_MAIN, RTPROT_BGP);
        assert_eq!(
            normalise(r6.encode_set(1)),
            framed(RTM_NEWROUTE, &ADD6_PAYLOAD)
        );
        let mut t = RouteMsg::unicast(p("203.0.113.0/24"), ip("127.0.0.1"), 300, RTPROT_BGP);
        t.priority = None;
        assert_eq!(
            normalise(t.encode_set(1)),
            framed(RTM_NEWROUTE, &TABLE300_PAYLOAD)
        );
        // Flags we actually send.
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

    #[test]
    fn ipv4_route_with_ipv6_gateway_uses_rta_via() {
        let r = RouteMsg::unicast(
            p("198.51.100.0/24"),
            ip("2001:db8::1"),
            RT_TABLE_MAIN,
            RTPROT_BGP,
        );
        let m = r.encode_set(1);
        let attrs = netlink::parse_attrs(&m[netlink::HEADER_LEN + RTMSG_LEN..]).unwrap();
        let via = attrs.iter().find(|a| a.ty == RTA_VIA).unwrap();
        assert_eq!(via.value.len(), 18);
        assert_eq!(
            u16::from_ne_bytes([via.value[0], via.value[1]]),
            u16::from(AF_INET6)
        );
        assert!(attrs.iter().all(|a| a.ty != RTA_GATEWAY));
        // And decodes back.
        let back = RouteMsg::decode(&m[netlink::HEADER_LEN..])
            .unwrap()
            .unwrap();
        assert_eq!(back.gateway, Some(ip("2001:db8::1")));
        assert_eq!(back.dst, p("198.51.100.0/24"));
    }

    #[test]
    fn decode_round_trips_and_filters() {
        for (prefix, gw, table) in [
            ("192.0.2.0/24", "10.0.0.1", RT_TABLE_MAIN),
            ("2001:db8:1::/48", "2001:db8::1", RT_TABLE_MAIN),
            ("0.0.0.0/0", "10.0.0.1", 300),
            ("::/0", "2001:db8::1", RT_TABLE_MAIN),
        ] {
            let r = RouteMsg::unicast(p(prefix), ip(gw), table, RTPROT_BGP);
            let m = r.encode_set(1);
            let back = RouteMsg::decode(&m[netlink::HEADER_LEN..])
                .unwrap()
                .unwrap();
            assert_eq!(back, r, "{prefix}");
        }
        // Not unicast, cloned, unknown family: None.
        let r = RouteMsg::unicast(p("192.0.2.0/24"), ip("10.0.0.1"), RT_TABLE_MAIN, RTPROT_BGP);
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
}
