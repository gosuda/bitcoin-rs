use serde::Deserialize;

/// User-supplied chainstate journal overrides.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ChainstateJournalOverrides {
    /// Whether the journal is active.
    pub enabled: Option<bool>,
    /// Durability batch size, in blocks.
    pub blocks: Option<u32>,
    /// Durability batch period, in seconds.
    pub seconds: Option<u64>,
    /// Active-segment rotation threshold, in MiB.
    pub rotate_mib: Option<u64>,
    /// Total-journal retention bound, in MiB.
    pub max_journal_mib: Option<u64>,
    /// Backpressure threshold, in blocks.
    pub max_lag_blocks: Option<u32>,
    /// Backpressure threshold, in seconds.
    pub max_lag_seconds: Option<u64>,
}

impl ChainstateJournalOverrides {
    pub(super) fn overlay(&mut self, other: &Self) {
        if other.enabled.is_some() {
            self.enabled = other.enabled;
        }
        if other.blocks.is_some() {
            self.blocks = other.blocks;
        }
        if other.seconds.is_some() {
            self.seconds = other.seconds;
        }
        if other.rotate_mib.is_some() {
            self.rotate_mib = other.rotate_mib;
        }
        if other.max_journal_mib.is_some() {
            self.max_journal_mib = other.max_journal_mib;
        }
        if other.max_lag_blocks.is_some() {
            self.max_lag_blocks = other.max_lag_blocks;
        }
        if other.max_lag_seconds.is_some() {
            self.max_lag_seconds = other.max_lag_seconds;
        }
    }

    pub(super) fn apply_to(self, config: &mut ChainstateJournalConfig) {
        if let Some(enabled) = self.enabled {
            config.enabled = enabled;
        }
        if let Some(blocks) = self.blocks {
            config.blocks = blocks;
        }
        if let Some(seconds) = self.seconds {
            config.seconds = seconds;
        }
        if let Some(rotate_mib) = self.rotate_mib {
            config.rotate_mib = rotate_mib;
        }
        if let Some(max_journal_mib) = self.max_journal_mib {
            config.max_journal_mib = max_journal_mib;
        }
        if let Some(max_lag_blocks) = self.max_lag_blocks {
            config.max_lag_blocks = max_lag_blocks;
        }
        if let Some(max_lag_seconds) = self.max_lag_seconds {
            config.max_lag_seconds = max_lag_seconds;
        }
    }
}

/// Chainstate journal settings (`[chainstate_journal]`, issue #230).
///
/// The journal bounds crash-recovery work between checkpoint publications:
/// instead of re-validating the whole chain, boot replays only the records
/// the durable head covers. `enabled = false` restores the checkpoint-only
/// recovery behavior exactly as it was before the journal existed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChainstateJournalConfig {
    /// Whether the journal is active. `false` = checkpoint-only recovery.
    pub enabled: bool,
    /// Durability batch size, in blocks (head advances at least this often).
    pub blocks: u32,
    /// Durability batch period, in seconds (time-based boundary trigger).
    pub seconds: u64,
    /// Active-segment rotation threshold, in MiB.
    pub rotate_mib: u64,
    /// Retention bound on total journal size, in MiB.
    pub max_journal_mib: u64,
    /// Backpressure threshold: max blocks applied beyond the durable head.
    pub max_lag_blocks: u32,
    /// Backpressure threshold: max seconds the head may lag the applied tip.
    pub max_lag_seconds: u64,
}

impl Default for ChainstateJournalConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            blocks: 500,
            seconds: 5,
            rotate_mib: 256,
            max_journal_mib: 2048,
            max_lag_blocks: 500,
            max_lag_seconds: 30,
        }
    }
}
