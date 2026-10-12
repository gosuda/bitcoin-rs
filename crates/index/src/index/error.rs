//! Typed failures shared by index reads, preparation, and durable writes.

use super::capability::IndexWatermark;
use bitcoin_rs_storage::StorageError;
use thiserror::Error;

/// Errors returned while indexing confirmed blocks.
#[derive(Debug, Error)]
pub enum IndexError {
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("invalid serialized block: {0:?}")]
    BlockParse(bitcoin_rs_primitives::DecodeError),
    #[error("a watermark anchor cannot cover ScriptLive or an empty capability set")]
    AnchorUnsupportedSelection,
    #[error("invalid block header length {len}")]
    InvalidHeaderLength { len: usize },
    #[error("transaction byte range does not fit u32 at block offset {offset}")]
    UnaddressablePosition { offset: u64 },
    #[error("invalid TxIndex watermark encoding")]
    InvalidWatermark,
    #[error("invalid TxIndex prefix row length {len}")]
    InvalidPrefixRowLength { len: usize },
    #[error("invalid ScriptLive row value length {len}")]
    InvalidLiveRowValue { len: usize },
    #[error("unsupported TxIndex format version {version}")]
    UnsupportedTxIndexFormatVersion { version: u32 },
    #[error(
        "block body identity mismatch at height {height}: expected {expected:?}, found {actual:?}"
    )]
    BlockIdentityMismatch {
        height: u32,
        expected: [u8; 32],
        actual: [u8; 32],
    },
    #[error("TxIndex watermark block identity row is missing at height {height} ({hash:?})")]
    MissingWatermarkIdentity { height: u32, hash: [u8; 32] },
    #[error("prepared TxIndex mutation size overflow")]
    MutationSizeOverflow,
    #[error("prepared TxIndex transition is not contiguous with {watermark:?}")]
    NonContiguousPrepared { watermark: Option<IndexWatermark> },
    #[error("TxIndex watermark mismatch: expected {expected:?}, found {actual:?}")]
    WatermarkMismatch {
        expected: Option<IndexWatermark>,
        actual: Option<IndexWatermark>,
    },
    #[error("ScriptLive preparation requires a spent-coin script source")]
    MissingSpentScripts,
    #[error("no spent-coin script for outpoint {txid:02x?}:{vout} in block at height {height}")]
    MissingSpentCoin {
        /// Spent transaction id (little-endian bytes).
        txid: [u8; 32],
        vout: u32,
        height: u32,
    },
    #[error("ScriptLive is already seeded; reset the capability first")]
    LiveAlreadySeeded,
    #[error("TxIndex tables are present without a versioned watermark")]
    LegacyCursorlessIndex,
    #[error("invalid TxIndex capability reset marker")]
    InvalidResetMarker,
    #[error("capability reset in progress; discard prepared state and re-derive")]
    ResetInProgress,
    #[error("capability reset version exhausted")]
    ResetVersionOverflow,
    #[error("capability reset scan returned an empty incomplete result")]
    ResetScanIncomplete,
    #[error("invalid TxIndex ordinary-state revision encoding")]
    InvalidStateRevision,
    #[error("TxIndex ordinary-state revision exhausted")]
    StateRevisionOverflow,
    #[error("TxIndex state changed; discard derived state and re-derive")]
    StaleIndexState,
}
