/// Minimum number of blocks kept below the active tip for Core-compatible reorg safety.
pub const CORE_REORG_SAFETY_MARGIN: u32 = 288;

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
    /// Returns a policy that disables pruning.
    #[must_use]
    pub const fn full_node() -> Self {
        Self {
            target_size_mb: u64::MAX,
            keep_below_tip: u32::MAX,
        }
    }

    /// Returns Bitcoin Core's minimal pruning shape: 550 MiB and 288-block reorg margin.
    #[must_use]
    pub const fn minimal() -> Self {
        Self {
            target_size_mb: 550,
            keep_below_tip: CORE_REORG_SAFETY_MARGIN,
        }
    }

    /// Returns a Utreexo-only policy that discards block bodies immediately.
    #[must_use]
    pub const fn utreexo_only() -> Self {
        Self {
            target_size_mb: 0,
            keep_below_tip: 0,
        }
    }

    /// Returns true when this policy disables pruning.
    #[must_use]
    pub const fn is_full_node(self) -> bool {
        self.target_size_mb == u64::MAX
    }

    /// Returns true when this policy requests immediate Utreexo-only block deletion.
    #[must_use]
    pub const fn is_utreexo_only(self) -> bool {
        self.target_size_mb == 0 && self.keep_below_tip == 0
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

impl Default for PrunePolicy {
    fn default() -> Self {
        Self::full_node()
    }
}
