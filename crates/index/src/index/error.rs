//! Typed failures shared by index reads, preparation, and durable writes.

use super::capability::IndexWatermark;
use bitcoin_rs_storage::StorageError;
use thiserror::Error;

/// Errors returned while indexing confirmed blocks.
#[derive(Debug, Error)]
pub enum IndexError {
    /// Backend storage failed while applying index rows.
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    /// `bitcoin_slices` rejected the serialized block.
    #[error("invalid serialized block: {0:?}")]
    BlockParse(bitcoin_slices::Error),
    /// This indexer cannot undo a block, so a reorg cannot be made consistent.
    #[error("this indexer does not support block disconnect")]
    UnsupportedRollback,
    /// A block header did not have the consensus 80-byte length.
    #[error("invalid block header length {len}")]
    InvalidHeaderLength {
        /// Actual header length observed by the visitor.
        len: usize,
    },
    /// A transaction's byte range in the block does not fit the `u32` that
    /// [`crate::types::TxPosition`] stores.
    ///
    /// Unreachable for any consensus-valid block — a block is capped far below
    /// 4 GiB — but the arithmetic is checked rather than wrapped, and the
    /// failure is an addressing limit, not a malformed header.
    #[error("transaction byte range does not fit u32 at block offset {offset}")]
    UnaddressablePosition {
        /// Block byte offset reached when the range stopped fitting.
        offset: u64,
    },
    /// Durable watermark bytes do not have the expected length.
    #[error("invalid TxIndex watermark encoding")]
    InvalidWatermark,
    /// A persisted `TxIndex` prefix row had an invalid key length.
    #[error("invalid TxIndex prefix row length {len}")]
    InvalidPrefixRowLength {
        /// Actual key length observed in storage.
        len: usize,
    },
    /// A `ScriptLive` row had a non-empty value even though the row format is
    /// key-only.
    #[error("invalid ScriptLive row value length {len}")]
    InvalidLiveRowValue {
        /// Actual value length observed in storage.
        len: usize,
    },
    /// The `TxIndex` format version is not supported.
    #[error("unsupported TxIndex format version {version}")]
    UnsupportedTxIndexFormatVersion {
        /// Format version value found in the store.
        version: u32,
    },
    /// A serialized block header does not hash to the expected identity.
    #[error(
        "block body identity mismatch at height {height}: expected {expected:?}, found {actual:?}"
    )]
    BlockIdentityMismatch {
        /// Expected active-chain height.
        height: u32,
        /// Expected active-chain block hash.
        expected: [u8; 32],
        /// Hash of the serialized body's exact 80-byte header.
        actual: [u8; 32],
    },
    /// The watermark block identity row is missing during rollback.
    #[error("TxIndex watermark block identity row is missing at height {height} ({hash:?})")]
    MissingWatermarkIdentity {
        /// Watermark height.
        height: u32,
        /// Watermark hash.
        hash: [u8; 32],
    },
    /// Prepared mutation accounting exceeded the platform size type.
    #[error("prepared TxIndex mutation size overflow")]
    MutationSizeOverflow,
    /// A prepared forward transition does not extend the durable watermark.
    #[error("prepared TxIndex transition is not contiguous with {watermark:?}")]
    NonContiguousPrepared {
        /// Durable watermark observed before the write.
        watermark: Option<IndexWatermark>,
    },
    /// A prepared transition did not begin at the durable watermark it expected.
    #[error("TxIndex watermark mismatch: expected {expected:?}, found {actual:?}")]
    WatermarkMismatch {
        /// Watermark the caller prepared from.
        expected: Option<IndexWatermark>,
        /// Watermark found in the store.
        actual: Option<IndexWatermark>,
    },
    /// A capability set containing `ScriptLive` was prepared through a path
    /// that carries no spent-coin script source. Live deletes need the spent
    /// coin's exact script (#225), and a prevout-only block parse cannot
    /// produce it.
    #[error("ScriptLive preparation requires a spent-coin script source")]
    MissingSpentScripts,
    /// The spent-coin source could not resolve an external input's script.
    /// Failing closed here is deliberate: a missing anchor means the Live view
    /// would silently keep a spent output alive.
    #[error("no spent-coin script for outpoint {txid:02x?}:{vout} in block at height {height}")]
    MissingSpentCoin {
        /// Spent transaction id (little-endian bytes).
        txid: [u8; 32],
        /// Spent output index.
        vout: u32,
        /// Height of the spending block.
        height: u32,
    },
    /// `seed_script_live` was asked to seed over an existing live watermark.
    /// Seeding assumes a fresh (or reset) capability; overwriting a live view
    /// in place is how partial states become queryable.
    #[error("ScriptLive is already seeded; reset the capability first")]
    LiveAlreadySeeded,
    /// `TxIndex` tables exist but the format-version key is missing.
    #[error("TxIndex tables are present without a versioned watermark")]
    LegacyCursorlessIndex,
    /// A crash-recovery marker for a capability rebuild was malformed.
    #[error("invalid TxIndex capability reset marker")]
    InvalidResetMarker,
    /// A durable capability reset rejected state derived before the reset.
    #[error("capability reset in progress; discard prepared state and re-derive")]
    ResetInProgress,
    /// The durable reset version exhausted `u64` and can no longer advance.
    #[error("capability reset version exhausted")]
    ResetVersionOverflow,
    /// Storage returned an empty but incomplete reset scan, which no
    /// conforming backend produces when row capacity is positive.
    #[error("capability reset scan returned an empty incomplete result")]
    ResetScanIncomplete,
    /// Durable ordinary-state revision bytes were not exactly one little-endian `u64`.
    #[error("invalid TxIndex ordinary-state revision encoding")]
    InvalidStateRevision,
    /// The ordinary-state revision exhausted `u64` and can no longer advance.
    #[error("TxIndex ordinary-state revision exhausted")]
    StateRevisionOverflow,
    /// Another ordinary writer committed after this state was captured.
    #[error("TxIndex state changed; discard derived state and re-derive")]
    StaleIndexState,
}
