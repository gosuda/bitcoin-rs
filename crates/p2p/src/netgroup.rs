//! Core31.1 IP netgroups. Classification never rewrites a dial endpoint.
use std::net::{IpAddr, Ipv4Addr};

pub(crate) fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

// Match CNetAddr::IsRoutable for grouping. Transport admission has its own
// explicit local/multicast/port restrictions; it must not change hash vectors.
fn routable(ip: IpAddr) -> bool {
    match canonical_ip(ip) {
        IpAddr::V4(ip) => {
            let b = ip.octets();
            !(ip.is_broadcast()
                || b[0] == 0
                || b[0] == 127
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_documentation()
                || b[0] == 198 && matches!(b[1], 18 | 19)
                || b[0] == 100 && (64..=127).contains(&b[1]))
        }
        IpAddr::V6(ip) => {
            let b = ip.octets();
            !(ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_unique_local()
                || b[..4] == [0x20, 1, 0x0d, 0xb8]
                || b[..8] == [0xfe, 0x80, 0, 0, 0, 0, 0, 0]
                || b[..3] == [0x20, 1, 0] && matches!(b[3] & 0xf0, 0x10 | 0x20))
        }
    }
}

pub(crate) fn linked_ipv4(ip: IpAddr) -> Option<Ipv4Addr> {
    let ip = canonical_ip(ip);
    if !routable(ip) {
        return None;
    }
    let IpAddr::V6(ip) = ip else {
        return match ip {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(_) => None,
        };
    };
    let b = ip.octets();
    let bytes = if b[..2] == [0x20, 2] {
        [b[2], b[3], b[4], b[5]]
    } else if b[..12] == [0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0]
        || b[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0]
    {
        [b[12], b[13], b[14], b[15]]
    } else if b[..4] == [0x20, 1, 0, 0] {
        [!b[12], !b[13], !b[14], !b[15]]
    } else {
        return None;
    };
    Some(Ipv4Addr::from(bytes))
}

pub(crate) fn group(ip: IpAddr) -> Vec<u8> {
    let ip = canonical_ip(ip);
    if !routable(ip) {
        return vec![0];
    }
    if let Some(ip) = linked_ipv4(ip) {
        let b = ip.octets();
        return vec![1, b[0], b[1]];
    }
    let IpAddr::V6(ip) = ip else {
        return vec![0];
    };
    let b = ip.octets();
    let mut group = vec![2, b[0], b[1], b[2], b[3]];
    if b[..4] == [0x20, 1, 4, 0x70] {
        group.push(b[4] | 15);
    }
    group
}
