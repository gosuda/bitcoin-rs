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

fn prefix_group(ip: IpAddr) -> Vec<u8> {
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

use bitcoin::hex::DisplayHex as _;
use sha2::{Digest, Sha256};
use std::io::{self, Read};

use std::path::Path;

const MAX_ASMAP_BYTES: u64 = 4 * 1024 * 1024;
const ASN_BITS: &[u8] = &[15, 16, 17, 18, 19, 20, 21, 22, 23, 24];
const MATCH_BITS: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];
const JUMP_BITS: &[u8] = &[
    5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
    30,
];

#[derive(Default)]
pub(crate) struct NetGroups {
    bytes: Vec<u8>,
    identity: Option<[u8; 32]>,
}

impl NetGroups {
    pub(crate) fn load(path: Option<&Path>) -> Self {
        let Some(path) = path else {
            return Self::default();
        };
        match Self::read(path) {
            Ok(map) => {
                tracing::info!(path = %path.display(), sha256 = %map.identity.unwrap_or_default().to_lower_hex_string(), "ASMap netgroup classifier active");
                map
            }
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "ASMap unavailable; using IP prefix netgroups");
                Self::default()
            }
        }
    }

    fn read(path: &Path) -> io::Result<Self> {
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take(MAX_ASMAP_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_ASMAP_BYTES || !valid(&bytes) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid or oversized ASMap bytecode",
            ));
        }
        let identity = Some(Sha256::digest(&bytes).into());
        Ok(Self { bytes, identity })
    }

    pub(crate) const fn identity(&self) -> Option<[u8; 32]> {
        self.identity
    }

    pub(crate) fn group(&self, ip: IpAddr) -> Vec<u8> {
        // Core applies ASMap only to IPv4/IPv6 network classes; local and
        // unroutable IPs keep the prefix owner's unclassified group.
        let asn = if self.bytes.is_empty() || !routable(ip) {
            0
        } else {
            interpret(&self.bytes, ip).unwrap_or(0)
        };
        if asn == 0 {
            prefix_group(ip)
        } else {
            let mut group = vec![2]; // Core NET_IPV6 groups both IP families by ASN.
            group.extend_from_slice(&asn.to_le_bytes());
            group
        }
    }
}

struct Bits<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl Bits<'_> {
    fn bit(&mut self) -> Option<u32> {
        let bit = u32::from((*self.bytes.get(self.pos / 8)? >> (self.pos % 8)) & 1);
        self.pos += 1;
        Some(bit)
    }
    fn number(&mut self, min: u32, sizes: &[u8]) -> Option<u32> {
        let mut value = min;
        for (index, &size) in sizes.iter().enumerate() {
            if index + 1 < sizes.len() && self.bit()? != 0 {
                value = value.checked_add(1_u32.checked_shl(u32::from(size))?)?;
            } else {
                for shift in (0..size).rev() {
                    value = value.checked_add(self.bit()? << shift)?;
                }
                return Some(value);
            }
        }
        None
    }
    fn opcode(&mut self) -> Option<u32> {
        self.number(0, &[0, 0, 1])
    }
}

fn valid(bytes: &[u8]) -> bool {
    validate(bytes).is_some()
}

// Walk every branch in serialization order; forward-only jumps and at most
// 128 input bits bound work and stack depth independently of hostile bytecode.
fn validate(bytes: &[u8]) -> Option<()> {
    let mut bits = Bits { bytes, pos: 0 };
    let end = bytes.len().checked_mul(8)?;
    let mut remaining = 128_u32;
    let mut jumps: Vec<(usize, u32)> = Vec::new();
    let mut previous = 1;
    let mut incomplete_match = false;
    while bits.pos < end {
        if jumps.last().is_some_and(|(target, _)| bits.pos >= *target) {
            return None;
        }
        let opcode = bits.opcode()?;
        match opcode {
            0 => {
                if previous == 3 {
                    return None;
                }
                bits.number(1, ASN_BITS)?;
                if let Some((target, input_left)) = jumps.pop() {
                    if bits.pos != target {
                        return None;
                    }
                    remaining = input_left;
                    previous = 1;
                } else {
                    if end - bits.pos > 7 {
                        return None;
                    }
                    while bits.pos < end {
                        if bits.bit()? != 0 {
                            return None;
                        }
                    }
                    return Some(());
                }
            }
            1 => {
                let distance = usize::try_from(bits.number(17, JUMP_BITS)?).ok()?;
                let target = bits.pos.checked_add(distance)?;
                if target > end || jumps.last().is_some_and(|(outer, _)| target >= *outer) {
                    return None;
                }
                remaining = remaining.checked_sub(1)?;
                jumps.push((target, remaining));
                previous = 1;
            }
            2 => {
                let pattern = bits.number(2, MATCH_BITS)?;
                let length = pattern.ilog2();
                if previous != 2 {
                    incomplete_match = false;
                }
                if length < 8 && incomplete_match {
                    return None;
                }
                incomplete_match = length < 8;
                remaining = remaining.checked_sub(length)?;
                previous = 2;
            }
            3 => {
                if previous == 3 {
                    return None;
                }
                bits.number(1, ASN_BITS)?;
                previous = 3;
            }
            _ => return None,
        }
    }
    None
}

fn interpret(bytes: &[u8], ip: IpAddr) -> Option<u32> {
    let octets = match linked_ipv4(ip).map_or(ip, IpAddr::V4) {
        IpAddr::V4(ip) => ip.to_ipv6_mapped().octets(),
        IpAddr::V6(ip) => ip.octets(),
    };
    let mut input = 0_usize;
    let mut bits = Bits { bytes, pos: 0 };
    let mut fallback = 0;
    while bits.pos < bytes.len() * 8 {
        match bits.opcode()? {
            0 => return bits.number(1, ASN_BITS),
            1 => {
                let distance = usize::try_from(bits.number(17, JUMP_BITS)?).ok()?;
                let bit = (*octets.get(input / 8)? >> (7 - input % 8)) & 1;
                input += 1;
                if bit != 0 {
                    bits.pos = bits.pos.checked_add(distance)?;
                }
            }
            2 => {
                let pattern = bits.number(2, MATCH_BITS)?;
                let length = pattern.ilog2();
                for shift in (0..length).rev() {
                    let bit = u32::from((*octets.get(input / 8)? >> (7 - input % 8)) & 1);
                    input += 1;
                    if bit != (pattern >> shift) & 1 {
                        return Some(fallback);
                    }
                }
            }
            3 => fallback = bits.number(1, ASN_BITS)?,
            _ => return None,
        }
    }
    None
}

#[cfg(test)]
pub(crate) const CORE_ASMAP: &[u8] = include_bytes!("../tests/data/asmap-core-v31.1.raw");

#[cfg(test)]
pub(crate) const LINKED_ASMAP: &[u8] =
    include_bytes!("../tests/data/asmap-linked-ipv4-core-v31.1.raw");

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests {
    use super::*;

    // The bytes and expected addresses/ASNs are copied unchanged from Bitcoin
    // Core v31.1 src/test/netbase_tests.cpp::asmap_test_vectors (MIT).
    #[test]
    fn independent_core_vectors_cover_the_bytecode_interpreter() {
        assert!(valid(CORE_ASMAP));
        for (address, expected) in [
            ("0:1559:183:3728:224c:65a5:62e6:e991", 961_340),
            ("d0:d493:faa0:8609:e927:8b75:293c:f5a4", 961_340),
            ("2a0:26f:8b2c:2ee7:c7d1:3b24:4705:3f7f", 693_761),
            ("a77:7cd4:4be5:a449:89f2:3212:78c6:ee38", 0),
            ("1336:1ad6:2f26:4fe3:d809:7321:6e0d:4615", 672_176),
            ("1d56:abd0:a52f:a8d5:d5a7:a610:581d:d792", 499_880),
            ("378e:7290:54e5:bd36:4760:971c:e9b9:570d", 0),
            ("406c:820b:272a:c045:b74e:fc0a:9ef2:cecc", 248_495),
            ("46c2:ae07:9d08:2d56:d473:2bc7:57e3:20ac", 248_495),
            ("50d2:3db6:52fa:2e7:12ec:5bc4:1bd1:49f9", 124_471),
            ("53e1:1812:ffa:dccf:f9f2:64be:75fa:795", 539_993),
            ("544d:eeba:3990:35d1:ad66:f9a3:576d:8617", 374_443),
            ("6a53:40dc:8f1d:3ffa:efeb:3aa3:df88:b94b", 435_070),
            ("87aa:d1c9:9edb:91e7:aab1:9eb9:baa0:de18", 244_121),
            ("9f00:48fa:88e3:4b67:a6f3:e6d2:5cc1:5be2", 862_116),
            ("c49f:9cc6:86ad:ba08:4580:315e:dbd1:8a62", 969_411),
            ("dff5:8021:61d:b17d:406d:7888:fdac:4a20", 969_411),
            ("e888:6791:2960:d723:bcfd:47e1:2d8c:599f", 824_019),
            ("ffff:d499:8c4b:4941:bc81:d5b9:b51e:85a8", 824_019),
        ] {
            assert_eq!(
                interpret(CORE_ASMAP, address.parse().expect("IP")),
                Some(expected),
                "{address}"
            );
        }
    }

    #[test]
    fn different_prefixes_in_one_asn_share_a_group_and_invalid_files_fall_back() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("asmap.dat");
        std::fs::write(&path, CORE_ASMAP).expect("write fixture");
        let groups = NetGroups::load(Some(&path));
        let a: IpAddr = "406c:820b:272a:c045:b74e:fc0a:9ef2:cecc"
            .parse()
            .expect("a");
        let b: IpAddr = "46c2:ae07:9d08:2d56:d473:2bc7:57e3:20ac"
            .parse()
            .expect("b");
        assert_ne!(prefix_group(a), prefix_group(b));
        assert_eq!(groups.group(a), vec![2, 0xaf, 0xca, 3, 0]);
        assert_eq!(groups.group(a), groups.group(b));
        assert!(groups.identity().is_some());
        for bytes in [
            vec![],
            vec![0],
            vec![255; 128],
            CORE_ASMAP[..CORE_ASMAP.len() - 1].to_vec(),
        ] {
            std::fs::write(&path, bytes).expect("invalid file");
            let fallback = NetGroups::load(Some(&path));
            assert_eq!(fallback.identity(), None);
            assert_eq!(fallback.group(a), prefix_group(a));
        }
        assert_eq!(
            NetGroups::load(Some(&directory.path().join("missing"))).group(a),
            prefix_group(a)
        );
    }

    #[test]
    fn core_linked_ipv4_forms_share_the_mapped_asn_and_prefix_group() {
        // Core netbase_tests.cpp::netbase_getgroup independently supplies these
        // four equivalent encodings of IPv4 1.2.3.4.
        for encoded in [
            "::FFFF:0:102:304",
            "64:FF9B::102:304",
            "2002:102:304:9999:9999:9999:9999:9999",
            "2001:0:9999:9999:9999:9999:FEFD:FCFB",
        ] {
            let ip = encoded.parse().expect("Core vector");
            assert_eq!(NetGroups::default().group(ip), vec![1, 1, 2]);
        }
        // A Core-generated map maps native IPv6 to 64500, while linked IPv4
        // 8.8.8.8 maps to 64501; passing raw transition bytes cannot pass.
        assert!(valid(LINKED_ASMAP));
        for encoded in [
            "8.8.8.8",
            "::ffff:8.8.8.8",
            "2002:0808:0808::1",
            "64:ff9b::808:808",
            "::ffff:0:808:808",
            "2001:0:0:0:0:0:f7f7:f7f7",
        ] {
            let ip = encoded.parse().expect("linked vector");
            assert_eq!(interpret(LINKED_ASMAP, ip), Some(64501), "{encoded}");
            assert_eq!(prefix_group(ip), vec![1, 8, 8]);
        }
        for native in ["64:ff9b:1::808:808", "2001:4860:4860::8888"] {
            let ip = native.parse().expect("native IPv6");
            assert_eq!(linked_ipv4(ip), None);
            assert_eq!(interpret(LINKED_ASMAP, ip), Some(64500));
        }
        assert_eq!(
            interpret(LINKED_ASMAP, "8.8.1.1".parse().expect("IPv4")),
            Some(15169)
        );
        assert_eq!(
            interpret(LINKED_ASMAP, "9.9.9.9".parse().expect("IPv4")),
            Some(19281)
        );
    }

    proptest::proptest! {
        #[test]
        fn validated_programs_terminate_for_arbitrary_addresses(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..128), ip in proptest::prelude::any::<[u8; 16]>()) {
            if valid(&bytes) { proptest::prop_assert!(interpret(&bytes, std::net::Ipv6Addr::from(ip).into()).is_some()); }
        }
    }
}
