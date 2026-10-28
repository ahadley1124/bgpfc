//! What the kernel says about its routes and interfaces: rtnetlink
//! notifications and dump entries (`rtnetlink(7)`; `<linux/rtnetlink.h>`,
//! `<linux/if_link.h>`, `<linux/if_addr.h>`, `<linux/if.h>`), decoded, and
//! the filter that keeps the routes a BGP next hop may resolve through.
//! Pure: bytes in, values out, every access bounds-checked, so Miri covers
//! it; `monitor` reads the socket.
//!
//! Implements, for the RIB's resolution of next hops (RFC 4271 §9.1.2,
//! §9.1.2.1): the kernel's routes in its main table, each with the
//! immediate next hop it forwards through (a gateway and an interface, or
//! the interface alone for a connected or device route), or none for a
//! route that drops what it matches (blackhole, unreachable, prohibit,
//! throw); never bgpfcd's own routes, so never a BGP route (FRR's default:
//! no recursion through BGP), and never a default route (FRR's default
//! without `resolve-via-default`). The interface and address events that
//! remove IPv4 routes without a notification of their own.

use std::fmt;
use std::net::IpAddr;

use bgpfc_wire::prefix::Prefix;
use bgpfc_wire::types::Afi;

use crate::netlink::{self, Attr, Message, NetlinkError};
use crate::route::{
    self, AF_INET, AF_INET6, RT_TABLE_MAIN, RTA_DST, RTA_GATEWAY, RTA_OIF, RTA_PRIORITY, RTA_TABLE,
    RTA_VIA, RTM_DELROUTE, RTM_F_CLONED, RTM_NEWROUTE, RTMSG_LEN, RTN_UNICAST, RTNH_F_ONLINK,
};

/// `RTM_NEWLINK`: an interface appeared or changed.
pub const RTM_NEWLINK: u16 = 16;
/// `RTM_DELLINK`: an interface went away.
pub const RTM_DELLINK: u16 = 17;
/// `RTM_GETLINK`: list the interfaces.
pub const RTM_GETLINK: u16 = 18;
/// `RTM_DELADDR`: an address was removed from an interface.
pub const RTM_DELADDR: u16 = 21;

/// `RTNLGRP_LINK` (`enum rtnetlink_groups`, `<linux/rtnetlink.h>`).
pub const RTNLGRP_LINK: u32 = 1;
/// `RTNLGRP_IPV4_IFADDR`.
pub const RTNLGRP_IPV4_IFADDR: u32 = 5;
/// `RTNLGRP_IPV4_ROUTE`.
pub const RTNLGRP_IPV4_ROUTE: u32 = 7;
/// `RTNLGRP_IPV6_ROUTE`.
pub const RTNLGRP_IPV6_ROUTE: u32 = 11;

/// The groups a reader of the kernel's routes joins: the routes of both
/// families, and the interface and IPv4 address changes that remove IPv4
/// routes without a notification of their own (an interface going down,
/// its last address going). IPv6 notifies each route it removes when an
/// address goes (`fib6_del`), so its address group is not joined.
/// Joining the IPv6 route group works with IPv6 disabled.
pub const GROUPS: [u32; 4] = [
    RTNLGRP_LINK,
    RTNLGRP_IPV4_IFADDR,
    RTNLGRP_IPV4_ROUTE,
    RTNLGRP_IPV6_ROUTE,
];

// `rtm_type`, `<linux/rtnetlink.h>`: the types of route that forward
// nothing. A more specific one shadows a covering route in the kernel's
// lookup, so it must here too.
const RTN_BLACKHOLE: u8 = 6;
const RTN_UNREACHABLE: u8 = 7;
const RTN_PROHIBIT: u8 = 8;
const RTN_THROW: u8 = 9;

/// `RTA_MULTIPATH`: a run of `struct rtnexthop`.
const RTA_MULTIPATH: u16 = 9;
/// `sizeof(struct rtnexthop)`: `rtnh_len` u16, `rtnh_flags` u8,
/// `rtnh_hops` u8, `rtnh_ifindex` int; its attributes follow.
const RTNEXTHOP_LEN: usize = 8;
/// `RTNH_F_DEAD`: the next hop cannot be used. The kernel also sets it in
/// `rtm_flags` for a route with one next hop.
const RTNH_F_DEAD: u8 = 1;

/// `sizeof(struct ifinfomsg)`: `ifi_family` u8, pad u8, `ifi_type` u16,
/// `ifi_index` int, `ifi_flags` u32, `ifi_change` u32
/// (`<linux/rtnetlink.h>`).
const IFINFOMSG_LEN: usize = 16;
/// `IFLA_IFNAME` (`<linux/if_link.h>`): the name, NUL-terminated.
const IFLA_IFNAME: u16 = 3;
/// `IFF_UP` (`<linux/if.h>`): administratively up.
const IFF_UP: u32 = 0x1;
/// `sizeof(struct ifaddrmsg)`: `ifa_family`, `ifa_prefixlen`,
/// `ifa_flags`, `ifa_scope` (u8 each), `ifa_index` u32
/// (`<linux/if_addr.h>`).
const IFADDRMSG_LEN: usize = 8;

/// Where a kernel route sends what it matches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Via {
    /// Forwarded: through `gateway`, or straight to the destination on
    /// the link for a connected or device route (no gateway), out of the
    /// interface `oif`. For a route with several next hops, the first the
    /// kernel can use: bgpfc installs a single best path (AGENTS.md §3).
    Unicast {
        /// The gateway, of either family (`RTA_VIA` holds one of the
        /// other family).
        gateway: Option<IpAddr>,
        /// The interface index.
        oif: u32,
        /// `RTNH_F_ONLINK`: the gateway is on the link of `oif` though no
        /// route covers it, so a route through it must say so too.
        onlink: bool,
    },
    /// Dropped (blackhole, unreachable, prohibit, throw), or a route
    /// whose next hops are all dead or held in a nexthop object the
    /// message does not expand: nothing resolves through it.
    Unreachable,
}

/// A route as the kernel reports it, in a dump or a notification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    /// The destination.
    pub dst: Prefix,
    /// The table (`RTA_TABLE`, else `rtm_table`).
    pub table: u32,
    /// `rtm_protocol`: who installed it.
    pub protocol: u8,
    /// `rtm_type`.
    pub kind: u8,
    /// `rtm_tos`.
    pub tos: u8,
    /// `rtm_flags`.
    pub flags: u32,
    /// `RTA_PRIORITY`, the metric; 0 when absent. Routes to one
    /// destination with different metrics coexist, and the kernel uses
    /// the lowest.
    pub metric: u32,
    /// Where it sends what it matches.
    pub via: Via,
    /// Its next hops as the kernel lists them, dead ones included: one,
    /// or several from `RTA_MULTIPATH`; none for a route that drops what
    /// it matches. A removal names the next hops it removes, so that the
    /// copy can tell which of several routes at a destination and metric
    /// went ([`crate::mirror`]).
    pub next_hops: Vec<NextHop>,
}

/// One next hop of a route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NextHop {
    /// The gateway (`RTA_GATEWAY`, or `RTA_VIA` for one of the other
    /// family), if any.
    pub gateway: Option<IpAddr>,
    /// The interface index.
    pub oif: u32,
    /// `rtnh_flags`, or the low octet of `rtm_flags` for a route with one
    /// next hop: `RTNH_F_DEAD`, `RTNH_F_ONLINK`, `RTNH_F_LINKDOWN`, ...
    pub flags: u8,
}

/// An interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Link {
    /// `ifi_index`.
    pub index: u32,
    /// `IFLA_IFNAME`; empty if the message has none.
    pub name: String,
    /// Whether it is administratively up (`IFF_UP`).
    pub up: bool,
}

/// What one notification says, for a reader of the routes a next hop may
/// resolve through.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A route that [`relevant`] keeps was added, or put in place of the
    /// first with its destination and metric. `flags` are the
    /// notification's `nlmsg_flags`, which say where it went among the
    /// routes there ([`crate::mirror`]).
    Route {
        /// The route.
        route: Route,
        /// `NLM_F_REPLACE`, `NLM_F_EXCL`, `NLM_F_CREATE`, `NLM_F_APPEND`.
        flags: u16,
    },
    /// Such a route was removed: the route, with the next hops removed.
    RouteGone(Route),
    /// One of bgpfcd's own routes in the main table (those with its
    /// protocol number) was added, put in place of the first route with
    /// its destination and metric (`flags`, as for `Route`), or removed
    /// (`gone`). Nothing resolves through it, but it may have replaced, or
    /// sit among, routes that something does.
    Own {
        /// Its destination.
        dst: Prefix,
        /// Its metric.
        metric: u32,
        /// The notification's `nlmsg_flags`.
        flags: u16,
        /// Whether it was removed.
        gone: bool,
    },
    /// An interface appeared or changed.
    Link(Link),
    /// An interface went away; IPv4 removes the routes through it without
    /// a notification of their own.
    LinkGone(u32),
    /// An IPv4 address was removed from the interface with this index;
    /// with its last one, routes through a gateway on it go without a
    /// notification of their own.
    AddressGone(u32),
}

impl fmt::Display for Via {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Via::Unicast {
                gateway: Some(g),
                oif,
                onlink,
            } => write!(
                f,
                "via {g} oif {oif}{}",
                if *onlink { " onlink" } else { "" }
            ),
            Via::Unicast {
                gateway: None, oif, ..
            } => write!(f, "oif {oif}"),
            Via::Unreachable => f.write_str("unreachable"),
        }
    }
}

impl Event {
    /// The destination and metric of a route's notification.
    #[must_use]
    pub fn key(&self) -> Option<(Prefix, u32)> {
        match self {
            Event::Route { route, .. } | Event::RouteGone(route) => Some((route.dst, route.metric)),
            Event::Own { dst, metric, .. } => Some((*dst, *metric)),
            Event::Link(_) | Event::LinkGone(_) | Event::AddressGone(_) => None,
        }
    }
}

/// Whether a next hop may resolve through `route`, the filter of the
/// kernel's table bgpfc keeps a copy of, for routes installed by someone
/// else than the bgpfcd whose routes carry `protocol`:
///
/// - in the main table (`RT_TABLE_MAIN`): policy routing and VRFs are
///   not looked at;
/// - not ours (`rtm_protocol` other than `protocol`): never through a
///   route bgpfcd installed, so never recursively through a BGP route
///   (FRR's default), which also makes a route that would become
///   unresolvable once installed impossible (RFC 4271 §9.1.2.1);
/// - not a default route: never through `0.0.0.0/0` or `::/0` (FRR's
///   default, without `resolve-via-default`);
/// - `rtm_tos` 0, not a route the kernel cloned (`RTM_F_CLONED`);
/// - a unicast route, or one that forwards nothing (blackhole,
///   unreachable, prohibit, throw), which shadows a covering route as it
///   does in the kernel; local, broadcast, multicast and the other types
///   are not.
#[must_use]
pub fn relevant(route: &Route, protocol: u8) -> bool {
    // NOTE(interop): RFC 4271 §9.1.2.1 1) lets a next hop resolve through
    // any route of the Routing Table that does not itself resolve through
    // the BGP route. As FRR does by default (no `resolve-via-default`),
    // bgpfc resolves neither through a BGP route, its own, nor through a
    // default route, through which every next hop would resolve.
    route.protocol != protocol && candidate(route)
}

/// [`relevant`] but for who installed the route: a route of the main
/// table, not a default route, `rtm_tos` 0, not cloned, unicast or one
/// that drops. Of bgpfcd's own routes, these are the ones that compete
/// with the routes next hops resolve through for a destination and metric.
#[must_use]
pub fn candidate(route: &Route) -> bool {
    route.table == RT_TABLE_MAIN
        && route.dst.prefix_len() > 0
        && route.tos == 0
        && route.flags & RTM_F_CLONED == 0
        && matches!(
            route.kind,
            RTN_UNICAST | RTN_BLACKHOLE | RTN_UNREACHABLE | RTN_PROHIBIT | RTN_THROW
        )
}

/// Decode the payload of an `RTM_NEWROUTE` or `RTM_DELROUTE`. `None` for
/// a family other than IPv4 and IPv6, or a destination that is no prefix.
///
/// The next hop: `RTA_GATEWAY`, or `RTA_VIA` for a gateway of the other
/// family, and `RTA_OIF`; for `RTA_MULTIPATH`, the first `struct
/// rtnexthop` without `RTNH_F_DEAD`. A route whose next hops are all dead,
/// or that names a nexthop object (`RTA_NH_ID`) without the next hop
/// expanded (`net.ipv4.nexthop_compat_mode` 0), has none: it is
/// [`Via::Unreachable`]. `RTNH_F_LINKDOWN` next hops count, as the kernel
/// uses them unless `ignore_routes_with_linkdown` is set. `RTNH_F_ONLINK`
/// (in `rtm_flags` for one next hop, `rtnh_flags` for several) is kept: a
/// route through such a gateway needs it.
///
/// # Errors
/// [`NetlinkError`] on malformed bytes.
pub fn decode_route(payload: &[u8]) -> Result<Option<Route>, NetlinkError> {
    let Some((head, rest)) = payload.split_first_chunk::<RTMSG_LEN>() else {
        return Err(NetlinkError::ShortRoute);
    };
    let [
        family,
        dst_len,
        _src_len,
        tos,
        table,
        protocol,
        _scope,
        kind,
        f0,
        f1,
        f2,
        f3,
    ] = *head;
    let flags = u32::from_ne_bytes([f0, f1, f2, f3]);
    let attrs = netlink::parse_attrs(rest)?;
    let afi = match family {
        AF_INET => Afi::Ipv4,
        AF_INET6 => Afi::Ipv6,
        _ => return Ok(None),
    };
    let mut dst = None;
    let mut table = u32::from(table);
    let mut metric = 0;
    let mut gateway = None;
    let mut oif = None;
    let mut multipath = None;
    for Attr { ty, value } in attrs {
        match ty {
            RTA_DST => dst = route::parse_addr(afi, value),
            RTA_TABLE => table = route::parse_u32(value).unwrap_or(table),
            RTA_PRIORITY => metric = route::parse_u32(value).unwrap_or(0),
            RTA_GATEWAY => gateway = route::parse_addr(afi, value),
            RTA_VIA => gateway = route::decode_via(value),
            RTA_OIF => oif = route::parse_u32(value),
            RTA_MULTIPATH => multipath = Some(value),
            _ => {}
        }
    }
    let dst = match dst {
        Some(a) => Prefix::new(a, dst_len),
        None => Prefix::default_route(afi).filter(|_| dst_len == 0),
    };
    let Some(dst) = dst else {
        return Ok(None);
    };
    let next_hops = match multipath {
        Some(nexthops) => multipath_hops(afi, nexthops)?,
        // The next hop's own flags are the low octet of `rtm_flags`.
        None => oif
            .map(|oif| NextHop {
                gateway,
                oif,
                flags: u8::try_from(flags & 0xff).unwrap_or(0),
            })
            .into_iter()
            .collect(),
    };
    Ok(Some(Route {
        dst,
        table,
        protocol,
        kind,
        tos,
        flags,
        metric,
        via: via_of(kind, &next_hops),
        next_hops,
    }))
}

/// Where a route of type `kind` with `next_hops` sends what it matches:
/// nowhere for a type that drops; else through the first next hop
/// without `RTNH_F_DEAD`, with its `RTNH_F_ONLINK`; nowhere when every
/// one is dead, or there is none, as for a route that names a nexthop
/// object the message does not expand.
#[must_use]
pub fn via_of(kind: u8, next_hops: &[NextHop]) -> Via {
    if kind != RTN_UNICAST {
        return Via::Unreachable;
    }
    next_hops
        .iter()
        .find(|h| h.flags & RTNH_F_DEAD == 0)
        .map_or(Via::Unreachable, |h| Via::Unicast {
            gateway: h.gateway,
            oif: h.oif,
            onlink: h.flags & RTNH_F_ONLINK != 0,
        })
}

/// Every next hop of an `RTA_MULTIPATH` value, a run of `struct
/// rtnexthop` each followed by its attributes, in order; one with an
/// interface index that is no interface's is passed over.
fn multipath_hops(afi: Afi, mut nexthops: &[u8]) -> Result<Vec<NextHop>, NetlinkError> {
    let mut hops = Vec::new();
    let mut at = 0;
    while !nexthops.is_empty() {
        let Some((head, _)) = nexthops.split_first_chunk::<RTNEXTHOP_LEN>() else {
            return Err(NetlinkError::BadAttribute { at });
        };
        let [l0, l1, flags, _hops, i0, i1, i2, i3] = *head;
        let len = usize::from(u16::from_ne_bytes([l0, l1]));
        let Some(attrs) = nexthops.get(RTNEXTHOP_LEN..len) else {
            return Err(NetlinkError::BadAttribute { at });
        };
        if let Ok(oif) = u32::try_from(i32::from_ne_bytes([i0, i1, i2, i3])) {
            let mut gateway = None;
            for Attr { ty, value } in netlink::parse_attrs(attrs)? {
                match ty {
                    RTA_GATEWAY => gateway = route::parse_addr(afi, value),
                    RTA_VIA => gateway = route::decode_via(value),
                    _ => {}
                }
            }
            hops.push(NextHop {
                gateway,
                oif,
                flags,
            });
        }
        let next = netlink::align(len);
        nexthops = nexthops.get(next..).unwrap_or_default();
        at += next;
    }
    Ok(hops)
}

/// Decode the payload of an `RTM_NEWLINK` or `RTM_DELLINK`. `None` for an
/// index that is no interface's (not positive).
///
/// # Errors
/// [`NetlinkError`] on malformed bytes.
pub fn decode_link(payload: &[u8]) -> Result<Option<Link>, NetlinkError> {
    let Some((head, rest)) = payload.split_first_chunk::<IFINFOMSG_LEN>() else {
        return Err(NetlinkError::ShortLink);
    };
    let [_, _, _, _, i0, i1, i2, i3, f0, f1, f2, f3, ..] = *head;
    let flags = u32::from_ne_bytes([f0, f1, f2, f3]);
    let mut name = String::new();
    for Attr { ty, value } in netlink::parse_attrs(rest)? {
        if ty == IFLA_IFNAME {
            let end = value.iter().position(|&b| b == 0).unwrap_or(value.len());
            name = String::from_utf8_lossy(&value[..end]).into_owned();
        }
    }
    let index = i32::from_ne_bytes([i0, i1, i2, i3]);
    Ok(u32::try_from(index)
        .ok()
        .filter(|&i| i > 0)
        .map(|index| Link {
            index,
            name,
            up: flags & IFF_UP != 0,
        }))
}

/// The family and interface index of an `RTM_NEWADDR` or `RTM_DELADDR`
/// payload.
///
/// # Errors
/// [`NetlinkError::ShortAddress`] if shorter than `struct ifaddrmsg`.
pub fn decode_address(payload: &[u8]) -> Result<(u8, u32), NetlinkError> {
    match payload.first_chunk::<IFADDRMSG_LEN>() {
        Some(&[family, _, _, _, i0, i1, i2, i3]) => {
            Ok((family, u32::from_ne_bytes([i0, i1, i2, i3])))
        }
        None => Err(NetlinkError::ShortAddress),
    }
}

/// What a notification says, if anything a reader of the routes bgpfcd
/// may resolve through needs: routes [`relevant`] keeps for `protocol`,
/// with the notification's flags; bgpfcd's own routes that compete with
/// them ([`candidate`]), by destination and metric; interfaces; and
/// removed addresses. `None` for anything else.
///
/// # Errors
/// [`NetlinkError`] on a malformed message.
pub fn event(message: &Message<'_>, protocol: u8) -> Result<Option<Event>, NetlinkError> {
    let route = |gone: bool| -> Result<Option<Event>, NetlinkError> {
        let Some(r) = decode_route(message.payload)?.filter(candidate) else {
            return Ok(None);
        };
        let flags = message.header.flags;
        Ok(Some(match (r.protocol == protocol, gone) {
            (true, gone) => Event::Own {
                dst: r.dst,
                metric: r.metric,
                flags,
                gone,
            },
            (false, false) => Event::Route { route: r, flags },
            (false, true) => Event::RouteGone(r),
        }))
    };
    Ok(match message.header.ty {
        RTM_NEWROUTE => route(false)?,
        RTM_DELROUTE => route(true)?,
        RTM_NEWLINK => decode_link(message.payload)?.map(Event::Link),
        RTM_DELLINK => decode_link(message.payload)?.map(|l| Event::LinkGone(l.index)),
        // Only IPv4 removes routes through an address without a
        // notification each.
        RTM_DELADDR => match decode_address(message.payload)? {
            (AF_INET, index) => Some(Event::AddressGone(index)),
            _ => None,
        },
        _ => None,
    })
}

/// `RTM_GETLINK` with `NLM_F_DUMP` and a zeroed `struct ifinfomsg`: list
/// every interface.
#[must_use]
pub fn encode_link_dump(seq: u32) -> Vec<u8> {
    netlink::encode(
        RTM_GETLINK,
        netlink::NLM_F_REQUEST | netlink::NLM_F_DUMP,
        seq,
        &[0; IFINFOMSG_LEN],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `RTA_NH_ID`: the route uses a nexthop object (`ip nexthop`); the
    /// decoder needs nothing of it but the next hop it may expand to.
    const RTA_NH_ID: u16 = 30;

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The one message of a captured datagram.
    fn message(bytes: &[u8]) -> Message<'_> {
        let mut m = netlink::parse(bytes).unwrap();
        assert_eq!(m.len(), 1);
        m.pop().unwrap()
    }

    /// The event of a captured message, for bgpfcd with protocol 186.
    fn event_of(s: &str) -> Option<Event> {
        event(&message(&hex(s)), route::RTPROT_BGP).unwrap()
    }

    // Captured with `capture.py` (rtnetlink notifications in a network
    // namespace of its own, interface `ar` at index 2, 10.1.0.1/24 on it)
    // while `ip` made each change named.

    /// `ip route add 192.0.2.128/25 via 10.1.0.2 proto static metric 5`.
    const STATIC: &str = "4400000018000006e0a4e06a4109000002190000fe0400010000000008000f00fe00000008000100c00002800800060005000000080005000a0100020800040002000000";
    /// `ip route add 198.51.100.0/24 via 10.1.0.2 proto 186 metric 20`.
    const OURS: &str = "4400000018000006e1a4e06a4309000002180000feba00010000000008000f00fe00000008000100c63364000800060014000000080005000a0100020800040002000000";
    /// `ip route add 198.18.0.0/24 proto static nexthop via 10.1.0.2
    /// nexthop via 10.1.0.4`.
    const MULTIPATH: &str = "5000000018000006e1a4e06a4509000002180000fe0400010000000008000f00fe00000008000100c6120000240009001000000002000000080005000a0100021000000002000000080005000a010004";
    /// `ip route add blackhole 203.0.113.0/24 proto static`.
    const BLACKHOLE: &str =
        "2c00000018000006e1a4e06a4709000002180000fe0400060000000008000f00fe00000008000100cb007100";
    /// `ip route add 192.0.2.64/26 dev ar proto static`.
    const DEV: &str = "3400000018000006e2a4e06a49090000021a0000fe04fd010000000008000f00fe00000008000100c00002400800040002000000";
    /// `ip route del 192.0.2.128/25 via 10.1.0.2 proto static metric 5`.
    const DELETE: &str = "4400000019000000e2a4e06a4e09000002190000fe0400010000000008000f00fe00000008000100c00002800800060005000000080005000a0100020800040002000000";
    /// After `ip link set ar up`: the connected route back (proto kernel,
    /// scope link, `RTA_PREFSRC`).
    const CONNECTED: &str = "3c00000018000006000000000000000002180000fe02fd010000000008000f00fe000000080001000a010000080007000a0100010800040002000000";
    /// After `ip link set ar up`: the broadcast route of the local table.
    const LOCAL_BROADCAST: &str = "3c00000018000006000000000000000002200000ff02fd030000000008000f00ff000000080001000a0100ff080007000a0100010800040002000000";
    /// `ip addr del 10.1.0.1/24 dev ar`.
    const DELADDR: &str = "4c00000015000000e3a4e06a540900000218800002000000080001000a010001080002000a0100010700030061720000080008008000000014000600fffffffffffffffffe380300fe380300";
    /// `ip link set ar down`: `RTM_NEWLINK`, 828 octets, `ifi_flags` 0x1002.
    const LINK_DOWN: &str = concat!(
        "3c03000010000000000000000000000000000100020000000210000001000000070003006172000008000d00",
        "e803000005001000020000000500110000000000050043000000000008000400dc0500000800320044000000",
        "08003300ffff000008001b000000000008001e000000000008003d000000000008001f000400000008002800",
        "ffff0000080029000000010008003a000000010008003f0000000100080040000000010008003b00f8ff0700",
        "08003c00ffff0000080042000000000008002000040000000500210000000000080023000300000008002f00",
        "0100000008003000020000000600440000000000060045000000000005002700000000000a00010076da9cbe",
        "093700000a000200ffffffffffff0000cc00170016000000000000002200000000000000e805000000000000",
        "b008000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "640007001600000022000000e8050000b0080000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000c002b0005000200000000001000120009000100766574680000000008002500",
        "0000000008000500020000000c0006006e6f71756575650090001a008c000200880001000000000000000000",
        "0000000001000000010000000100000001000000000000000100000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000010270000e8030000000000000000000000000000000000000100000024000e0000000000",
        "0000000000000000000000000000000000000000000000000000000004003e8004004180",
    );
    /// `ip link set ar up`: `ifi_flags` 0x11003.
    const LINK_UP: &str = concat!(
        "3c03000010000000000000000000000000000100020000000310010001000000070003006172000008000d00",
        "e803000005001000020000000500110000000000050043000000000008000400dc0500000800320044000000",
        "08003300ffff000008001b000000000008001e000000000008003d000000000008001f000400000008002800",
        "ffff0000080029000000010008003a000000010008003f0000000100080040000000010008003b00f8ff0700",
        "08003c00ffff0000080042000000000008002000040000000500210001000000080023000400000008002f00",
        "0200000008003000020000000600440000000000060045000000000005002700000000000a00010076da9cbe",
        "093700000a000200ffffffffffff0000cc00170016000000000000002200000000000000e805000000000000",
        "b008000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "640007001600000022000000e8050000b0080000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000c002b0005000200000000001000120009000100766574680000000008002500",
        "0000000008000500020000000c0006006e6f71756575650090001a008c000200880001000000000000000000",
        "0000000001000000010000000100000001000000000000000100000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000010270000e8030000000000000000000000000000000000000100000024000e0000000000",
        "0000000000000000000000000000000000000000000000000000000004003e8004004180",
    );

    #[test]
    fn routes_through_a_gateway_a_device_and_several_next_hops() {
        let Some(Event::Route { route: r, .. }) = event_of(STATIC) else {
            panic!("{:?}", event_of(STATIC));
        };
        assert_eq!(
            r,
            Route {
                dst: p("192.0.2.128/25"),
                table: RT_TABLE_MAIN,
                protocol: 4, // RTPROT_STATIC
                kind: RTN_UNICAST,
                tos: 0,
                flags: 0,
                metric: 5,
                via: Via::Unicast {
                    gateway: Some(ip("10.1.0.2")),
                    oif: 2,
                    onlink: false,
                },
                next_hops: vec![NextHop {
                    gateway: Some(ip("10.1.0.2")),
                    oif: 2,
                    flags: 0,
                }],
            }
        );
        // `ip route add`: NLM_F_CREATE | NLM_F_EXCL, as no route had the
        // destination and metric.
        assert_eq!(
            message(&hex(STATIC)).header.flags,
            netlink::NLM_F_CREATE | netlink::NLM_F_EXCL
        );
        assert!(matches!(
            event_of(STATIC),
            Some(Event::Route { flags, .. })
                if flags == netlink::NLM_F_CREATE | netlink::NLM_F_EXCL
        ));
        // RTA_MULTIPATH: the first next hop; no metric given.
        let Some(Event::Route { route: r, .. }) = event_of(MULTIPATH) else {
            panic!("multipath");
        };
        assert_eq!(r.dst, p("198.18.0.0/24"));
        assert_eq!(r.metric, 0);
        assert_eq!(
            r.via,
            Via::Unicast {
                gateway: Some(ip("10.1.0.2")),
                oif: 2,
                onlink: false,
            }
        );
        // Every next hop, for a removal of one of them to name.
        let gateways: Vec<Option<IpAddr>> = r.next_hops.iter().map(|h| h.gateway).collect();
        assert_eq!(gateways, [Some(ip("10.1.0.2")), Some(ip("10.1.0.4"))]);
        // A device route and the connected route: no gateway.
        for (s, dst) in [(DEV, "192.0.2.64/26"), (CONNECTED, "10.1.0.0/24")] {
            let Some(Event::Route { route: r, .. }) = event_of(s) else {
                panic!("{dst}");
            };
            assert_eq!(r.dst, p(dst));
            assert_eq!(
                r.via,
                Via::Unicast {
                    gateway: None,
                    oif: 2,
                    onlink: false,
                }
            );
        }
        // A blackhole forwards nothing, and is kept: it shadows.
        let Some(Event::Route { route: r, .. }) = event_of(BLACKHOLE) else {
            panic!("blackhole");
        };
        assert_eq!(
            (r.dst, r.kind, r.via),
            (p("203.0.113.0/24"), 6, Via::Unreachable)
        );
    }

    #[test]
    fn our_routes_and_other_tables_are_not_kept() {
        // Ours only by destination and metric: nothing resolves through
        // it, but it may stand where another's route stood.
        assert_eq!(
            event_of(OURS),
            Some(Event::Own {
                dst: p("198.51.100.0/24"),
                metric: 20,
                flags: netlink::NLM_F_CREATE | netlink::NLM_F_EXCL,
                gone: false,
            })
        );
        assert_eq!(
            event_of(OURS).unwrap().key(),
            Some((p("198.51.100.0/24"), 20))
        );
        // Under another protocol number, the same route counts.
        let m = hex(OURS);
        let Some(Event::Route { route: r, .. }) = event(&message(&m), 4).unwrap() else {
            panic!("another daemon's route");
        };
        assert_eq!(r.protocol, 186);
        assert_eq!(event_of(LOCAL_BROADCAST), None);
        let r = decode_route(message(&hex(LOCAL_BROADCAST)).payload)
            .unwrap()
            .unwrap();
        assert_eq!((r.table, r.kind), (255, 3)); // RT_TABLE_LOCAL, RTN_BROADCAST
    }

    #[test]
    fn deletions_name_the_route_and_its_next_hops() {
        let Some(Event::RouteGone(r)) = event_of(DELETE) else {
            panic!("{:?}", event_of(DELETE));
        };
        assert_eq!((r.dst, r.metric), (p("192.0.2.128/25"), 5));
        assert_eq!(
            r.next_hops,
            [NextHop {
                gateway: Some(ip("10.1.0.2")),
                oif: 2,
                flags: 0,
            }]
        );
        // A deletion of ours: by destination and metric.
        let mut ours = hex(OURS);
        ours[4..6].copy_from_slice(&RTM_DELROUTE.to_ne_bytes());
        assert_eq!(
            event(&message(&ours), 186).unwrap(),
            Some(Event::Own {
                dst: p("198.51.100.0/24"),
                metric: 20,
                flags: netlink::NLM_F_CREATE | netlink::NLM_F_EXCL,
                gone: true,
            })
        );
        // Of another table, nothing.
        let mut local = hex(LOCAL_BROADCAST);
        local[4..6].copy_from_slice(&RTM_DELROUTE.to_ne_bytes());
        assert_eq!(event(&message(&local), 186).unwrap(), None);
    }

    #[test]
    fn interfaces_and_addresses() {
        let down = hex(LINK_DOWN);
        assert_eq!(down.len(), 828);
        let up_bytes = hex(LINK_UP);
        assert_eq!(up_bytes.len(), 828);
        let link = |up| Link {
            index: 2,
            name: "ar".to_owned(),
            up,
        };
        assert_eq!(
            event(&message(&down), 186).unwrap(),
            Some(Event::Link(link(false)))
        );
        assert_eq!(
            event(&message(&up_bytes), 186).unwrap(),
            Some(Event::Link(link(true)))
        );
        let mut gone = down.clone();
        gone[4..6].copy_from_slice(&RTM_DELLINK.to_ne_bytes());
        assert_eq!(
            event(&message(&gone), 186).unwrap(),
            Some(Event::LinkGone(2))
        );
        assert_eq!(event_of(DELADDR), Some(Event::AddressGone(2)));
        // An IPv6 address gone: IPv6 notifies the routes it removes.
        let mut v6 = hex(DELADDR);
        v6[netlink::HEADER_LEN] = AF_INET6;
        assert_eq!(event(&message(&v6), 186).unwrap(), None);
        // An RTM_NEWADDR says nothing a reader needs: the routes it adds
        // have notifications of their own.
        let mut new = hex(DELADDR);
        new[4..6].copy_from_slice(&20u16.to_ne_bytes());
        assert_eq!(event(&message(&new), 186).unwrap(), None);
    }

    /// A route message built field by field, as the kernel lays it out:
    /// `struct rtmsg`, then the attributes.
    fn rtmsg(
        family: u8,
        dst_len: u8,
        tos: u8,
        kind: u8,
        flags: u32,
        attrs: &[(u16, &[u8])],
    ) -> Vec<u8> {
        let mut payload = vec![family, dst_len, 0, tos, 254, 4, 0, kind];
        payload.extend_from_slice(&flags.to_ne_bytes());
        for (ty, value) in attrs {
            netlink::push_attr(&mut payload, *ty, value);
        }
        netlink::encode(RTM_NEWROUTE, 0, 0, &payload)
    }

    fn via_of(m: &[u8]) -> Via {
        decode_route(&m[netlink::HEADER_LEN..])
            .unwrap()
            .unwrap()
            .via
    }

    /// `struct rtnexthop` with its attributes.
    fn rtnexthop(flags: u8, ifindex: i32, attrs: &[(u16, &[u8])]) -> Vec<u8> {
        let mut a = Vec::new();
        for (ty, value) in attrs {
            netlink::push_attr(&mut a, *ty, value);
        }
        let mut nh = u16::try_from(RTNEXTHOP_LEN + a.len())
            .unwrap()
            .to_ne_bytes()
            .to_vec();
        nh.extend_from_slice(&[flags, 0]);
        nh.extend_from_slice(&ifindex.to_ne_bytes());
        nh.extend_from_slice(&a);
        nh
    }

    #[test]
    fn hand_built_single_next_hops() {
        let oif3 = 3u32.to_ne_bytes();
        // An IPv6 IGP route through a link-local gateway: usable with its
        // interface.
        let ll: IpAddr = ip("fe80::1");
        let IpAddr::V6(ll6) = ll else { unreachable!() };
        let dst6 = ip("2001:db8:5::");
        let IpAddr::V6(dst6) = dst6 else {
            unreachable!()
        };
        let m = rtmsg(
            AF_INET6,
            48,
            0,
            RTN_UNICAST,
            0,
            &[
                (RTA_DST, &dst6.octets()),
                (RTA_GATEWAY, &ll6.octets()),
                (RTA_OIF, &oif3),
            ],
        );
        let r = decode_route(&m[netlink::HEADER_LEN..]).unwrap().unwrap();
        assert_eq!(r.dst, p("2001:db8:5::/48"));
        assert_eq!(
            r.via,
            Via::Unicast {
                gateway: Some(ll),
                oif: 3,
                onlink: false,
            }
        );
        assert!(relevant(&r, 186));
        // An IPv4 route through an IPv6 gateway (RFC 8950 §3): RTA_VIA.
        let mut via = u16::from(AF_INET6).to_ne_bytes().to_vec();
        via.extend_from_slice(&ll6.octets());
        let dst4 = [198, 51, 100, 0];
        let m = rtmsg(
            AF_INET,
            24,
            0,
            RTN_UNICAST,
            0,
            &[(RTA_DST, &dst4), (RTA_VIA, &via), (RTA_OIF, &oif3)],
        );
        assert_eq!(
            via_of(&m),
            Via::Unicast {
                gateway: Some(ll),
                oif: 3,
                onlink: false,
            }
        );
        // A nexthop object not expanded: nothing to forward through.
        let m = rtmsg(
            AF_INET,
            24,
            0,
            RTN_UNICAST,
            0,
            &[(RTA_DST, &dst4), (RTA_NH_ID, &7u32.to_ne_bytes())],
        );
        assert_eq!(via_of(&m), Via::Unreachable);
        // Expanded (`nexthop_compat_mode` 1, the default): usable.
        let m = rtmsg(
            AF_INET,
            24,
            0,
            RTN_UNICAST,
            0,
            &[
                (RTA_DST, &dst4),
                (RTA_NH_ID, &7u32.to_ne_bytes()),
                (RTA_OIF, &oif3),
            ],
        );
        assert_eq!(
            via_of(&m),
            Via::Unicast {
                gateway: None,
                oif: 3,
                onlink: false,
            }
        );
        // A single next hop marked dead.
        let m = rtmsg(
            AF_INET,
            24,
            0,
            RTN_UNICAST,
            u32::from(RTNH_F_DEAD),
            &[(RTA_DST, &dst4), (RTA_OIF, &oif3)],
        );
        assert_eq!(via_of(&m), Via::Unreachable);
    }

    /// `ip route add 10.255.0.30/32 via 192.168.77.1 dev v0 onlink`:
    /// `RTNH_F_ONLINK` in `rtm_flags`, which a route through the gateway
    /// needs too.
    #[test]
    fn onlink_gateways_are_kept() {
        let oif3 = 3u32.to_ne_bytes();
        let gw = [192, 168, 77, 1];
        let m = rtmsg(
            AF_INET,
            32,
            0,
            RTN_UNICAST,
            u32::from(RTNH_F_ONLINK),
            &[
                (RTA_DST, &[10, 255, 0, 30]),
                (RTA_GATEWAY, &gw),
                (RTA_OIF, &oif3),
            ],
        );
        let onlink = via_of(&m);
        assert_eq!(
            onlink,
            Via::Unicast {
                gateway: Some(ip("192.168.77.1")),
                oif: 3,
                onlink: true,
            }
        );
        assert_eq!(onlink.to_string(), "via 192.168.77.1 oif 3 onlink");
    }

    #[test]
    fn hand_built_multipath() {
        let dst4 = [198, 51, 100, 0];
        // Several next hops: the first live one; all dead, none.
        let gw = |last: u8| [10, 1, 0, last];
        let (g2, g4) = (gw(2), gw(4));
        let dead = rtnexthop(RTNH_F_DEAD, 2, &[(RTA_GATEWAY, &g2)]);
        let live = rtnexthop(0x10, 5, &[(RTA_GATEWAY, &g4)]); // RTNH_F_LINKDOWN
        let both = [dead.clone(), live].concat();
        let m = rtmsg(
            AF_INET,
            24,
            0,
            RTN_UNICAST,
            0,
            &[(RTA_DST, &dst4), (RTA_MULTIPATH, &both)],
        );
        assert_eq!(
            via_of(&m),
            Via::Unicast {
                gateway: Some(ip("10.1.0.4")),
                oif: 5,
                onlink: false,
            }
        );
        let all_dead = [dead.clone(), dead].concat();
        let m = rtmsg(
            AF_INET,
            24,
            0,
            RTN_UNICAST,
            0,
            &[(RTA_DST, &dst4), (RTA_MULTIPATH, &all_dead)],
        );
        assert_eq!(via_of(&m), Via::Unreachable);
        // RTNH_F_ONLINK in the next hop's own flags.
        let onlink = rtnexthop(RTNH_F_ONLINK, 7, &[(RTA_GATEWAY, &g4)]);
        let m = rtmsg(
            AF_INET,
            24,
            0,
            RTN_UNICAST,
            0,
            &[(RTA_DST, &dst4), (RTA_MULTIPATH, &onlink)],
        );
        assert_eq!(
            via_of(&m),
            Via::Unicast {
                gateway: Some(ip("10.1.0.4")),
                oif: 7,
                onlink: true,
            }
        );
        // A next hop without a gateway: a device next hop.
        let dev = rtnexthop(0, 6, &[]);
        let m = rtmsg(
            AF_INET,
            24,
            0,
            RTN_UNICAST,
            0,
            &[(RTA_DST, &dst4), (RTA_MULTIPATH, &dev)],
        );
        assert_eq!(
            via_of(&m),
            Via::Unicast {
                gateway: None,
                oif: 6,
                onlink: false,
            }
        );
        // A struct rtnexthop longer than the attribute: an error.
        let mut bad = rtnexthop(0, 6, &[]);
        bad[0] = 40;
        let m = rtmsg(
            AF_INET,
            24,
            0,
            RTN_UNICAST,
            0,
            &[(RTA_DST, &dst4), (RTA_MULTIPATH, &bad)],
        );
        assert_eq!(
            decode_route(&m[netlink::HEADER_LEN..]),
            Err(NetlinkError::BadAttribute { at: 0 })
        );
    }

    #[test]
    fn default_routes_tos_and_clones_are_not_kept() {
        let oif = 2u32.to_ne_bytes();
        let gw = [10, 1, 0, 2];
        // `ip route add default via 10.1.0.2`: no RTA_DST.
        let m = rtmsg(
            AF_INET,
            0,
            0,
            RTN_UNICAST,
            0,
            &[(RTA_GATEWAY, &gw), (RTA_OIF, &oif)],
        );
        let r = decode_route(&m[netlink::HEADER_LEN..]).unwrap().unwrap();
        assert_eq!(r.dst, p("0.0.0.0/0"));
        assert!(!relevant(&r, 186));
        // A missing RTA_DST with a length is no prefix.
        let m = rtmsg(AF_INET, 8, 0, RTN_UNICAST, 0, &[(RTA_OIF, &oif)]);
        assert_eq!(decode_route(&m[netlink::HEADER_LEN..]).unwrap(), None);
        let dst = [10, 0, 0, 0];
        let m = rtmsg(
            AF_INET,
            8,
            0x10,
            RTN_UNICAST,
            0,
            &[(RTA_DST, &dst), (RTA_OIF, &oif)],
        );
        let r = decode_route(&m[netlink::HEADER_LEN..]).unwrap().unwrap();
        assert_eq!(r.tos, 0x10);
        assert!(!relevant(&r, 186));
        let m = rtmsg(
            AF_INET,
            8,
            0,
            RTN_UNICAST,
            RTM_F_CLONED,
            &[(RTA_DST, &dst), (RTA_OIF, &oif)],
        );
        assert!(!relevant(
            &decode_route(&m[netlink::HEADER_LEN..]).unwrap().unwrap(),
            186
        ));
        let m = rtmsg(
            AF_INET,
            8,
            0,
            RTN_UNICAST,
            0,
            &[(RTA_DST, &dst), (RTA_OIF, &oif)],
        );
        assert!(relevant(
            &decode_route(&m[netlink::HEADER_LEN..]).unwrap().unwrap(),
            186
        ));
        // Another family: not a route of ours to read.
        let m = rtmsg(7, 8, 0, RTN_UNICAST, 0, &[]);
        assert_eq!(decode_route(&m[netlink::HEADER_LEN..]).unwrap(), None);
        // Unreachable, prohibit and throw are kept as blackholes are;
        // local (2) is not.
        for (kind, kept) in [(7, true), (8, true), (9, true), (2, false), (5, false)] {
            let m = rtmsg(AF_INET, 8, 0, kind, 0, &[(RTA_DST, &dst)]);
            let r = decode_route(&m[netlink::HEADER_LEN..]).unwrap().unwrap();
            assert_eq!(r.via, Via::Unreachable);
            assert_eq!(relevant(&r, 186), kept, "type {kind}");
        }
    }

    #[test]
    fn link_dump_request() {
        let m = encode_link_dump(9);
        assert_eq!(m.len(), netlink::HEADER_LEN + IFINFOMSG_LEN);
        let msg = message(&m);
        assert_eq!(msg.header.ty, RTM_GETLINK);
        assert_eq!(
            msg.header.flags,
            netlink::NLM_F_REQUEST | netlink::NLM_F_DUMP
        );
        assert_eq!(msg.header.seq, 9);
        assert_eq!(msg.payload, &[0; IFINFOMSG_LEN]);
        assert_eq!(GROUPS, [1, 5, 7, 11]);
    }

    /// Every vector above, cut at every length: the message is an error,
    /// and its payload an error, `None` or a route with fewer attributes;
    /// never a panic.
    #[test]
    fn truncation_never_panics() {
        let vectors = [
            STATIC,
            OURS,
            MULTIPATH,
            BLACKHOLE,
            DEV,
            DELETE,
            CONNECTED,
            LOCAL_BROADCAST,
            DELADDR,
            LINK_DOWN,
            LINK_UP,
        ];
        for v in vectors {
            let bytes = hex(v);
            for len in 1..bytes.len() {
                assert!(netlink::parse(&bytes[..len]).is_err(), "{v} at {len}");
            }
            let payload = &bytes[netlink::HEADER_LEN..];
            for len in 0..payload.len() {
                let cut = &payload[..len];
                let _ = decode_route(cut);
                let _ = decode_link(cut);
                let _ = decode_address(cut);
                // The header says the full length: shorten it with the
                // payload, so `event` sees each cut.
                let mut m = bytes[..netlink::HEADER_LEN + len].to_vec();
                let n = u32::try_from(m.len()).unwrap();
                m[..4].copy_from_slice(&n.to_ne_bytes());
                if let Ok(messages) = netlink::parse(&m) {
                    for msg in messages {
                        let _ = event(&msg, 186);
                    }
                }
            }
            assert_eq!(decode_route(&payload[..3]), Err(NetlinkError::ShortRoute));
        }
        assert_eq!(decode_link(&[0; 15]), Err(NetlinkError::ShortLink));
        assert_eq!(decode_address(&[0; 7]), Err(NetlinkError::ShortAddress));
    }
}
