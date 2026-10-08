use bitcoin_rs_primitives::chain_constants::CORE_REORG_SAFETY_MARGIN;

const BYTES_PER_MIB: u64 = 1024 * 1024;

/// Block and undo pruning policy.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PrunePolicy {
    /// Target serialized block-data footprint in mebibytes.
    pub target_size_mb: u64,
    /// Caller-requested number of blocks retained below the active tip.
    pub keep_below_tip: u32,
}

impl PrunePolicy {
    /// Returns true when this policy disables pruning.
    #[must_use]
    pub const fn is_full_node(self) -> bool {
        self.target_size_mb == u64::MAX
    }

    /// Returns the byte target used by pruning passes.
    #[must_use]
    pub const fn target_size_bytes(self) -> u64 {
        self.target_size_mb.saturating_mul(BYTES_PER_MIB)
    }

    /// Returns the effective retention depth below tip.
    #[must_use]
    pub fn retention_depth(self) -> u32 {
        // SPEC: Core's reorg-safety margin is 288 blocks.
        self.keep_below_tip.max(CORE_REORG_SAFETY_MARGIN)
    }
}
