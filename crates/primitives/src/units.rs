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
    pub const MAX_MONEY: Self = Self(21_000_000 * Self::COIN.0);

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

    /// Saturating addition.
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

/// Raw `nSequence` that makes an input final: [`Sequence::MAX`].
pub const SEQUENCE_FINAL: u32 = Sequence::MAX.0;
/// BIP68: set in `nSequence` to disable the input's relative lock-time.
pub const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;
/// BIP68: set in `nSequence` when the relative lock-time counts time, not blocks.
pub const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;
/// BIP68: the `nSequence` bits holding the relative lock-time value.
pub const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000_ffff;
/// BIP68: seconds per unit of a time-based relative lock-time.
pub const SEQUENCE_LOCKTIME_GRANULARITY_SECONDS: u32 = 512;

/// `nLockTime` values below this are block heights; at or above it, UNIX times.
pub const LOCKTIME_THRESHOLD: u32 = 500_000_000;

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

    /// Decodes into the 256-bit little-endian magnitude and the sign bit.
    ///
    /// Mirrors Core's `arith_uint256::SetCompact` exactly: the mantissa's
    /// bytes are shifted by the exponent, with bytes pushed past the 256-bit
    /// width silently dropped.
    ///
    /// The magnitude ignores the sign bit — like Core's own `GetHex`, it
    /// renders the unsigned value — so callers doing proof-of-work
    /// comparisons must separately treat a negative encoding or an all-zero
    /// magnitude as unmeetable.
    #[must_use]
    pub fn decode_magnitude(self) -> ([u8; 32], bool) {
        let bits = self.0;
        let exponent = usize::from(u8::try_from(bits >> 24).unwrap_or(0));
        let mut mantissa = bits & 0x007f_ffff;
        let mut magnitude = [0_u8; 32];
        if exponent <= 3 {
            mantissa >>= 8 * (3 - exponent);
            magnitude[..8].copy_from_slice(&u64::from(mantissa).to_le_bytes());
        } else {
            let shift = exponent - 3;
            for (offset, byte) in mantissa.to_le_bytes().iter().enumerate() {
                if let Some(slot) = magnitude.get_mut(shift + offset) {
                    *slot = *byte;
                }
            }
        }
        let negative = mantissa != 0 && bits & 0x0080_0000 != 0;
        (magnitude, negative)
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
