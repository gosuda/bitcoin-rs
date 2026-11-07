use core::{fmt, str::FromStr};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;

use thiserror::Error;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct IpSubnet {
    base: IpAddr,
    prefix: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BannedSubnet {
    pub subnet: IpSubnet,
    pub banned_until: Option<SystemTime>,
    pub ban_created: SystemTime,
    pub reason: String,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SubnetParseError {
    #[error("empty subnet")]
    Empty,
    #[error("missing subnet IP")]
    MissingIp,
    #[error("invalid subnet IP")]
    BadIp,
    #[error("invalid subnet prefix")]
    BadPrefix,
    #[error("subnet prefix {prefix} exceeds address width {width}")]
    PrefixTooLarge { width: u8, prefix: u8 },
    #[error("unexpected subnet suffix")]
    TrailingJunk,
}

impl IpSubnet {
    pub fn new(base: IpAddr, prefix: u8) -> Result<Self, SubnetParseError> {
        let base = base.to_canonical();
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

    pub fn from_ip(ip: IpAddr) -> Self {
        let ip = ip.to_canonical();
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

    pub fn base(&self) -> IpAddr {
        self.base
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
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
        let ip = parse_ip(ip_part)?.to_canonical();
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
