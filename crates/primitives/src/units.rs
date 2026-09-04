//! Native protocol scalar newtypes: amounts, sequences, locktime, compact targets.
//!
//! These are bitcoin-rs types, not `rust-bitcoin` aliases. Arithmetic and wire
//! conversion live here so `Tx`, `TxIn`, `TxOut`, and `Header` do not restate
//! satoshi, sequence, or nBits layout.

use core::fmt;

/// An amount in satoshis.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Amount(u64);

impl Amount {
    /// Zero satoshis.
    pub const ZERO: Self = Self(0);
    /// One satoshi.
    pub const SAT: Self = Self(1);
    /// One bitcoin in satoshis.
    pub const COIN: Self = Self(100_000_000);
    /// Consensus maximum money (21 million bitcoin).
    pub const MAX_MONEY: Self = Self(21_000_000 * 100_000_000);

    /// Constructs an amount from satoshis.
    #[must_use]
    pub const fn from_sat(sat: u64) -> Self {
        Self(sat)
    }

    /// Returns the amount in satoshis.
    #[must_use]
    pub const fn to_sat(self) -> u64 {
        self.0
    }

    /// Checked addition.
    #[must_use]
    pub const fn checked_add(self, rhs: Self) -> Option<Self> {
        match self.0.checked_add(rhs.0) {
            Some(sum) => Some(Self(sum)),
            None => None,
        }
    }

    /// Checked subtraction.
    #[must_use]
    pub const fn checked_sub(self, rhs: Self) -> Option<Self> {
        match self.0.checked_sub(rhs.0) {
            Some(diff) => Some(Self(diff)),
            None => None,
        }
    }

    /// Saturating addition.
    #[must_use]
    pub const fn saturating_add(self, rhs: Self) -> Self {
        Self(self.0.saturating_add(rhs.0))
    }

    /// Saturating subtraction.
    #[must_use]
    pub const fn saturating_sub(self, rhs: Self) -> Self {
        Self(self.0.saturating_sub(rhs.0))
    }

    /// Little-endian consensus encoding of the satoshi count.
    #[must_use]
    pub const fn to_le_bytes(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u64> for Amount {
    fn from(sat: u64) -> Self {
        Self::from_sat(sat)
    }
}

impl PartialEq<u64> for Amount {
    fn eq(&self, other: &u64) -> bool {
        self.0 == *other
    }
}

impl PartialEq<Amount> for u64 {
    fn eq(&self, other: &Amount) -> bool {
        *self == other.0
    }
}

impl PartialOrd<u64> for Amount {
    fn partial_cmp(&self, other: &u64) -> Option<core::cmp::Ordering> {
        self.0.partial_cmp(other)
    }
}

impl PartialOrd<Amount> for u64 {
    fn partial_cmp(&self, other: &Amount) -> Option<core::cmp::Ordering> {
        self.partial_cmp(&other.0)
    }
}

/// A transaction input sequence number.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sequence(u32);

impl Sequence {
    /// Sequence zero.
    pub const ZERO: Self = Self(0);
    /// `0xffffffff` — final, disables relative locktime and RBF signaling.
    pub const MAX: Self = Self(u32::MAX);
    /// BIP125 opt-in RBF without locktime (`0xfffffffd`).
    pub const ENABLE_RBF_NO_LOCKTIME: Self = Self(0xffff_fffd);

    /// Constructs a sequence from its consensus `u32`.
    #[must_use]
    pub const fn from_consensus(n: u32) -> Self {
        Self(n)
    }

    /// Returns the consensus `u32`.
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

impl fmt::Display for Sequence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u32> for Sequence {
    fn from(n: u32) -> Self {
        Self::from_consensus(n)
    }
}

impl PartialEq<u32> for Sequence {
    fn eq(&self, other: &u32) -> bool {
        self.0 == *other
    }
}

impl PartialEq<Sequence> for u32 {
    fn eq(&self, other: &Sequence) -> bool {
        *self == other.0
    }
}

impl PartialOrd<u32> for Sequence {
    fn partial_cmp(&self, other: &u32) -> Option<core::cmp::Ordering> {
        self.0.partial_cmp(other)
    }
}

impl PartialOrd<Sequence> for u32 {
    fn partial_cmp(&self, other: &Sequence) -> Option<core::cmp::Ordering> {
        self.partial_cmp(&other.0)
    }
}

impl fmt::LowerHex for Sequence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl fmt::UpperHex for Sequence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::UpperHex::fmt(&self.0, f)
    }
}

impl core::ops::BitAnd<u32> for Sequence {
    type Output = u32;

    fn bitand(self, rhs: u32) -> u32 {
        self.0 & rhs
    }
}

/// A transaction lock time (`nLockTime`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LockTime(u32);

impl LockTime {
    /// Locktime zero — always final from the locktime field alone.
    pub const ZERO: Self = Self(0);

    /// Constructs a lock time from its consensus `u32`.
    #[must_use]
    pub const fn from_consensus(n: u32) -> Self {
        Self(n)
    }

    /// Returns the consensus `u32`.
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

impl From<u32> for LockTime {
    fn from(n: u32) -> Self {
        Self::from_consensus(n)
    }
}

impl PartialEq<u32> for LockTime {
    fn eq(&self, other: &u32) -> bool {
        self.0 == *other
    }
}

impl PartialEq<LockTime> for u32 {
    fn eq(&self, other: &LockTime) -> bool {
        *self == other.0
    }
}

impl PartialOrd<u32> for LockTime {
    fn partial_cmp(&self, other: &u32) -> Option<core::cmp::Ordering> {
        self.0.partial_cmp(other)
    }
}

impl PartialOrd<LockTime> for u32 {
    fn partial_cmp(&self, other: &LockTime) -> Option<core::cmp::Ordering> {
        self.partial_cmp(&other.0)
    }
}

impl fmt::LowerHex for LockTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl fmt::UpperHex for LockTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::UpperHex::fmt(&self.0, f)
    }
}

/// Compact proof-of-work target (`nBits`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct CompactTarget(u32);

impl CompactTarget {
    /// Constructs a compact target from its consensus `u32`.
    #[must_use]
    pub const fn from_consensus(n: u32) -> Self {
        Self(n)
    }

    /// Returns the consensus `u32`.
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

impl fmt::UpperHex for CompactTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::UpperHex::fmt(&self.0, f)
    }
}

impl fmt::Display for CompactTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#010x}", self.0)
    }
}

impl From<u32> for CompactTarget {
    fn from(n: u32) -> Self {
        Self::from_consensus(n)
    }
}

impl PartialEq<u32> for CompactTarget {
    fn eq(&self, other: &u32) -> bool {
        self.0 == *other
    }
}

impl PartialEq<CompactTarget> for u32 {
    fn eq(&self, other: &CompactTarget) -> bool {
        *self == other.0
    }
}

#[cfg(test)]
mod tests {
    use super::{Amount, CompactTarget, LockTime, Sequence};

    #[test]
    fn amount_sat_roundtrip_and_overflow() {
        assert_eq!(Amount::from_sat(50_000).to_sat(), 50_000);
        assert_eq!(Amount::COIN.to_sat(), 100_000_000);
        assert_eq!(Amount::from_sat(u64::MAX).checked_add(Amount::SAT), None);
        assert_eq!(
            Amount::from_sat(2)
                .saturating_add(Amount::from_sat(3))
                .to_sat(),
            5
        );
    }

    #[test]
    fn sequence_and_locktime_consensus_roundtrip() {
        assert_eq!(Sequence::MAX.to_consensus(), u32::MAX);
        assert_eq!(Sequence::ENABLE_RBF_NO_LOCKTIME.to_consensus(), 0xffff_fffd);
        assert_eq!(Sequence::MAX & 0xffff_ffff, u32::MAX);
        assert_eq!(LockTime::ZERO.to_consensus(), 0);
        assert_eq!(
            LockTime::from_consensus(500_000_000).to_consensus(),
            500_000_000
        );
    }

    #[test]
    fn compact_target_consensus_roundtrip() {
        let bits = CompactTarget::from_consensus(0x1d00_ffff);
        assert_eq!(bits.to_consensus(), 0x1d00_ffff);
        assert_eq!(bits, 0x1d00_ffff_u32);
    }

    #[test]
    fn integer_comparisons_and_from() {
        assert_eq!(Amount::from_sat(7), 7_u64);
        assert!(Amount::from_sat(3) < 4_u64);
        assert_eq!(
            Sequence::from(0xffff_fffd),
            Sequence::ENABLE_RBF_NO_LOCKTIME
        );
        assert!(Sequence::ENABLE_RBF_NO_LOCKTIME < 0xffff_fffe);
        assert_eq!(LockTime::from(0_u32), LockTime::ZERO);
        assert_eq!(CompactTarget::from(0x207f_ffff), 0x207f_ffff_u32);
    }
}
