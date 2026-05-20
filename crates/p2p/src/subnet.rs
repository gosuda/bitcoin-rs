use core::{fmt, str::FromStr};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;

use thiserror::Error;

/// Canonical IP subnet with host bits normalized out of the base address.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct IpSubnet {
    base: IpAddr,
    prefix: u8,
}

/// Manual ban entry for an IP subnet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BannedSubnet {
    /// Subnet matched by this ban entry.
    pub subnet: IpSubnet,
    /// Expiry time, or `None` for a permanent ban.
    pub banned_until: Option<SystemTime>,
    /// Time at which the ban was created.
    pub ban_created: SystemTime,
    /// Human-readable ban reason supplied by the caller.
    pub reason: String,
}

/// Error returned when parsing an IP subnet.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SubnetParseError {
    /// The subnet string was empty.
    #[error("empty subnet")]
    Empty,
    /// A prefix separator was present without a preceding IP address.
    #[error("missing subnet IP")]
    MissingIp,
    /// The IP address portion was invalid.
    #[error("invalid subnet IP")]
    BadIp,
    /// The prefix portion was invalid.
    #[error("invalid subnet prefix")]
    BadPrefix,
    /// The prefix exceeded the width of the IP address family.
    #[error("subnet prefix {prefix} exceeds address width {width}")]
    PrefixTooLarge {
        /// Address-family width in bits.
        width: u8,
        /// Parsed prefix length.
        prefix: u8,
    },
    /// Extra input followed an otherwise subnet-like value.
    #[error("unexpected subnet suffix")]
    TrailingJunk,
}

impl IpSubnet {
    /// Constructs a subnet after validating the prefix and zeroing host bits.
    pub fn new(base: IpAddr, prefix: u8) -> Result<Self, SubnetParseError> {
        match base {
            IpAddr::V4(ip) => {
                validate_prefix(prefix, 32)?;
                Ok(Self {
                    base: IpAddr::V4(mask_v4(ip, prefix)),
                    prefix,
                })
            }
            IpAddr::V6(ip) => {
                validate_prefix(prefix, 128)?;
                Ok(Self {
                    base: IpAddr::V6(mask_v6(ip, prefix)),
                    prefix,
                })
            }
        }
    }

    /// Constructs a single-address subnet for the IP address family.
    pub fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(ip) => Self {
                base: IpAddr::V4(ip),
                prefix: 32,
            },
            IpAddr::V6(ip) => Self {
                base: IpAddr::V6(ip),
                prefix: 128,
            },
        }
    }

    /// Returns the normalized base address.
    pub fn base(&self) -> IpAddr {
        self.base
    }

    /// Returns the CIDR prefix length.
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// Returns whether `ip` is in this subnet.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.base, ip) {
            (IpAddr::V4(base), IpAddr::V4(ip)) => mask_v4(ip, self.prefix) == base,
            (IpAddr::V6(base), IpAddr::V6(ip)) => mask_v6(ip, self.prefix) == base,
            (IpAddr::V4(_), IpAddr::V6(_)) | (IpAddr::V6(_), IpAddr::V4(_)) => false,
        }
    }
}

impl FromStr for IpSubnet {
    type Err = SubnetParseError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        if raw.is_empty() {
            return Err(SubnetParseError::Empty);
        }

        let (ip_part, prefix_part) = match raw.split_once('/') {
            Some((ip_part, prefix_part)) => {
                if ip_part.is_empty() {
                    return Err(SubnetParseError::MissingIp);
                }
                if prefix_part.contains('/') {
                    return Err(SubnetParseError::TrailingJunk);
                }
                (ip_part, Some(prefix_part))
            }
            None => (raw, None),
        };

        let ip = parse_ip(ip_part)?;
        let prefix = match prefix_part {
            Some(prefix_part) => parse_prefix(prefix_part)?,
            None => match ip {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            },
        };

        Self::new(ip, prefix)
    }
}

impl fmt::Display for IpSubnet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.base, self.prefix)
    }
}

/// Returns whether `ip` is covered by an active ban entry.
pub fn is_banned(banned: &[BannedSubnet], ip: IpAddr, now: SystemTime) -> bool {
    banned.iter().any(|entry| {
        entry.subnet.contains(ip) && entry.banned_until.is_none_or(|until| until > now)
    })
}

fn validate_prefix(prefix: u8, width: u8) -> Result<(), SubnetParseError> {
    if prefix > width {
        Err(SubnetParseError::PrefixTooLarge { width, prefix })
    } else {
        Ok(())
    }
}

fn parse_ip(input: &str) -> Result<IpAddr, SubnetParseError> {
    input.parse::<IpAddr>().map_err(|_| {
        if has_subnet_suffix(input) {
            SubnetParseError::TrailingJunk
        } else {
            SubnetParseError::BadIp
        }
    })
}

fn parse_prefix(input: &str) -> Result<u8, SubnetParseError> {
    if input.is_empty() {
        return Err(SubnetParseError::BadPrefix);
    }
    input.parse::<u8>().map_err(|_| SubnetParseError::BadPrefix)
}

fn has_subnet_suffix(input: &str) -> bool {
    if input.starts_with('[') || input.contains(']') {
        return true;
    }

    input
        .rsplit_once(':')
        .is_some_and(|(host, _)| host.parse::<Ipv4Addr>().is_ok())
}

fn mask_v4(ip: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let value = u32::from(ip);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (u32::BITS - u32::from(prefix))
    };
    Ipv4Addr::from(value & mask)
}

fn mask_v6(ip: Ipv6Addr, prefix: u8) -> Ipv6Addr {
    let value = u128::from(ip);
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (u128::BITS - u32::from(prefix))
    };
    Ipv6Addr::from(value & mask)
}
