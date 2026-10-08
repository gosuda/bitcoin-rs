//! The cumulative chain transaction count as a known-or-unknown fact.

/// Cumulative transaction count through a chain tip.
///
/// Bitcoin Core's `CBlockIndex::m_chain_tx_count`, including its convention
/// that a persisted zero means *unset* rather than *empty*
/// (`HaveNumChainTxs()`). In memory the absence is explicit, and this type is
/// the one implementation of the arithmetic that preserves it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ChainTxCount(Option<u64>);

impl ChainTxCount {
    /// A count nobody has established: no arithmetic here yields a total.
    pub const UNKNOWN: Self = Self(None);

    /// Names a count computed from a counted parent, or from genesis.
    ///
    /// The wire encoding cannot carry zero as a known total, so a count
    /// established as zero round-trips through [`Self::from_wire`] as unknown.
    #[must_use]
    pub const fn established(count: u64) -> Self {
        Self(Some(count))
    }

    /// Decodes a persisted or wire count, where zero means unset.
    #[must_use]
    pub const fn from_wire(raw: u64) -> Self {
        match raw {
            0 => Self::UNKNOWN,
            count => Self(Some(count)),
        }
    }

    /// Encodes for a persisted field, where unknown is zero.
    #[must_use]
    pub const fn to_wire(self) -> u64 {
        match self.0 {
            Some(count) => count,
            None => 0,
        }
    }

    /// The known total, or `None` when the chain has never counted.
    #[must_use]
    pub const fn get(self) -> Option<u64> {
        self.0
    }

    /// Carries the count forward across the block at `height`, which adds
    /// `delta` transactions.
    ///
    /// Genesis can establish a count from unknown; otherwise overflow or an
    /// unknown parent stays unknown rather than becoming a wrapped total.
    #[must_use]
    pub fn advance(self, height: u32, delta: u64) -> Self {
        match self.0 {
            Some(known) => known
                .checked_add(delta)
                .map_or(Self::UNKNOWN, Self::established),
            // Genesis is the one block with nothing below it, so its own
            // transactions are the whole chain total at that height.
            None if height == 0 => Self::established(delta),
            None => Self::UNKNOWN,
        }
    }

    /// Takes `delta` transactions back out of the count, as the disconnect of
    /// the block that added them does.
    ///
    /// Underflow stays unknown rather than becoming a clamped total.
    #[must_use]
    pub fn rewind(self, delta: u64) -> Self {
        match self.0 {
            Some(known) => known
                .checked_sub(delta)
                .map_or(Self::UNKNOWN, Self::established),
            None => Self::UNKNOWN,
        }
    }
}
