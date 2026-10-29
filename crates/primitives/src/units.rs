//! Native protocol scalar newtypes: amounts, sequences, locktime, compact targets.

use core::fmt;

/// An amount in satoshis.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Amount(u64);

impl Amount {
    pub const ZERO: Self = Self(0);
    pub const SAT: Self = Self(1);
    pub const COIN: Self = Self(100_000_000);
    /// Consensus maximum money (21 million bitcoin).
    pub const MAX_MONEY: Self = Self(21_000_000 * Self::COIN.0);

    #[must_use]
    pub const fn from_sat(sat: u64) -> Self {
        Self(sat)
    }

    #[must_use]
    pub const fn to_sat(self) -> u64 {
        self.0
    }

    #[must_use]
    pub const fn saturating_add(self, rhs: Self) -> Self {
        Self(self.0.saturating_add(rhs.0))
    }

    /// Little-endian consensus encoding of the satoshi count.
    #[must_use]
    pub const fn to_le_bytes(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }
}

impl PartialEq<u64> for Amount {
    fn eq(&self, other: &u64) -> bool {
        self.0 == *other
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Sequence(u32);

impl Sequence {
    pub const ZERO: Self = Self(0);
    /// `0xffffffff` — final, disables relative locktime and RBF signaling.
    pub const MAX: Self = Self(u32::MAX);
    /// BIP125 opt-in RBF without locktime (`0xfffffffd`).
    pub const ENABLE_RBF_NO_LOCKTIME: Self = Self(0xffff_fffd);

    #[must_use]
    pub const fn from_consensus(n: u32) -> Self {
        Self(n)
    }

    #[must_use]
    pub const fn to_consensus(self) -> u32 {
        self.0
    }

    /// Little-endian consensus encoding.
    #[must_use]
    pub const fn to_le_bytes(self) -> [u8; 4] {
        self.0.to_le_bytes()
    }
}

impl PartialEq<u32> for Sequence {
    fn eq(&self, other: &u32) -> bool {
        self.0 == *other
    }
}

impl PartialOrd<u32> for Sequence {
    fn partial_cmp(&self, other: &u32) -> Option<core::cmp::Ordering> {
        self.0.partial_cmp(other)
    }
}

impl core::ops::BitAnd<u32> for Sequence {
    type Output = u32;

    fn bitand(self, rhs: u32) -> u32 {
        self.0 & rhs
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct LockTime(u32);

impl LockTime {
    /// Locktime zero — always final from the locktime field alone.
    pub const ZERO: Self = Self(0);

    #[must_use]
    pub const fn from_consensus(n: u32) -> Self {
        Self(n)
    }

    #[must_use]
    pub const fn to_consensus(self) -> u32 {
        self.0
    }

    /// Little-endian consensus encoding.
    #[must_use]
    pub const fn to_le_bytes(self) -> [u8; 4] {
        self.0.to_le_bytes()
    }
}

impl fmt::Display for LockTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CompactTarget(u32);

impl CompactTarget {
    #[must_use]
    pub const fn from_consensus(n: u32) -> Self {
        Self(n)
    }

    #[must_use]
    pub const fn to_consensus(self) -> u32 {
        self.0
    }

    /// Little-endian consensus encoding.
    #[must_use]
    pub const fn to_le_bytes(self) -> [u8; 4] {
        self.0.to_le_bytes()
    }
}

impl fmt::LowerHex for CompactTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl From<u32> for CompactTarget {
    fn from(n: u32) -> Self {
        Self::from_consensus(n)
    }
}

#[cfg(test)]
mod tests {
    use super::{Amount, LockTime, Sequence};

    #[test]
    fn bitcoin_unit_constants_match_protocol_values() {
        assert_eq!(Amount::COIN.to_sat(), 100_000_000);
        assert_eq!(
            Amount::MAX_MONEY.to_sat(),
            21_000_000 * Amount::COIN.to_sat()
        );
        assert_eq!(Sequence::MAX.to_consensus(), u32::MAX);
        assert_eq!(Sequence::ENABLE_RBF_NO_LOCKTIME.to_consensus(), 0xffff_fffd);
        assert_eq!(LockTime::ZERO.to_consensus(), 0);
    }
}
