//! Subnet primitive coverage: parsing, normalization, expiry, and matching.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, SystemTime};

use bitcoin_rs_p2p::subnet::is_banned;
use bitcoin_rs_p2p::{BannedSubnet, IpSubnet, SubnetParseError};

#[test]
fn ipv4_cidr_contains_only_same_network_family() {
    let subnet = parse_subnet("192.0.2.0/24");

    assert_eq!(subnet.to_string(), "192.0.2.0/24");
    assert!(subnet.contains(v4(192, 0, 2, 7)));
    assert!(!subnet.contains(v4(192, 0, 3, 1)));
    assert!(!subnet.contains(v6([0x2001, 0x0db8, 0, 0, 0, 0, 0, 1])));
}

#[test]
fn bare_ipv4_parses_as_host_subnet() {
    let subnet = parse_subnet("127.0.0.1");

    assert_eq!(subnet.to_string(), "127.0.0.1/32");
    assert!(subnet.contains(v4(127, 0, 0, 1)));
    assert!(!subnet.contains(v4(127, 0, 0, 2)));
}

#[test]
fn bare_ipv6_parses_as_host_subnet() {
    let subnet = parse_subnet("::1");

    assert_eq!(subnet.to_string(), "::1/128");
    assert!(subnet.contains(v6([0, 0, 0, 0, 0, 0, 0, 1])));
    assert!(!subnet.contains(v6([0, 0, 0, 0, 0, 0, 0, 2])));
}

#[test]
fn ipv6_cidr_normalizes_host_bits() {
    let subnet = parse_subnet("2001:db8::beef/32");

    assert_eq!(subnet.to_string(), "2001:db8::/32");
    assert_eq!(subnet.base(), v6([0x2001, 0x0db8, 0, 0, 0, 0, 0, 0]));
    assert_eq!(subnet.prefix(), 32);
}

#[test]
fn rejects_invalid_subnets() {
    assert_eq!(
        "192.0.2.1/33".parse::<IpSubnet>(),
        Err(SubnetParseError::PrefixTooLarge {
            width: 32,
            prefix: 33,
        })
    );
    assert_eq!(
        "2001:db8::1/129".parse::<IpSubnet>(),
        Err(SubnetParseError::PrefixTooLarge {
            width: 128,
            prefix: 129,
        })
    );
    assert_eq!(
        "192.0.2.1:8333".parse::<IpSubnet>(),
        Err(SubnetParseError::TrailingJunk)
    );
    assert_eq!(
        "[2001:db8::1]:8333".parse::<IpSubnet>(),
        Err(SubnetParseError::TrailingJunk)
    );
    assert_eq!(
        "not-an-ip".parse::<IpSubnet>(),
        Err(SubnetParseError::BadIp)
    );
}

#[test]
fn zero_prefix_matches_entire_same_family_only() {
    let v4_subnet = parse_subnet("192.0.2.1/0");
    let v6_subnet = parse_subnet("2001:db8::1/0");

    assert_eq!(v4_subnet.to_string(), "0.0.0.0/0");
    assert!(v4_subnet.contains(v4(203, 0, 113, 1)));
    assert!(!v4_subnet.contains(v6([0x2001, 0x0db8, 0, 0, 0, 0, 0, 1])));

    assert_eq!(v6_subnet.to_string(), "::/0");
    assert!(v6_subnet.contains(v6([0x2001, 0x0db8, 0, 0, 0, 0, 0, 1])));
    assert!(!v6_subnet.contains(v4(203, 0, 113, 1)));
}

#[test]
fn is_banned_honors_permanent_future_and_past_entries() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
    let created = SystemTime::UNIX_EPOCH;
    let ip = v4(192, 0, 2, 7);
    let permanent = ban("192.0.2.0/24", None, created);
    let future = ban(
        "198.51.100.0/24",
        Some(now + Duration::from_secs(1)),
        created,
    );
    let expired = ban(
        "203.0.113.0/24",
        Some(now - Duration::from_secs(1)),
        created,
    );

    assert!(is_banned(&[permanent], ip, now));
    assert!(is_banned(&[future], v4(198, 51, 100, 7), now));
    assert!(!is_banned(&[expired], v4(203, 0, 113, 7), now));
    assert!(!is_banned(&[], ip, now));
}

fn ban(subnet: &str, banned_until: Option<SystemTime>, ban_created: SystemTime) -> BannedSubnet {
    BannedSubnet {
        subnet: parse_subnet(subnet),
        banned_until,
        ban_created,
        reason: String::from("test"),
    }
}

fn parse_subnet(input: &str) -> IpSubnet {
    match input.parse::<IpSubnet>() {
        Ok(subnet) => subnet,
        Err(error) => panic!("failed to parse subnet {input}: {error}"),
    }
}

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn v6(segments: [u16; 8]) -> IpAddr {
    IpAddr::V6(Ipv6Addr::from(segments))
}
