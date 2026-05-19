#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

/// Confirmed block indexing over the workspace key-value store.
pub mod index;
/// Unconfirmed transaction row writing over the workspace key-value store.
pub mod mempool;
/// Electrum scripthash status hashing.
pub mod status;
/// Stable electrs-shaped row types.
pub mod types;

pub use index::{IndexError, IndexRowCounts, Indexer};
pub use mempool::{MempoolRowCounts, MempoolRowWriter};
pub use status::{HistoryEntry, HistoryHeight, StatusHash, compute_status_hash};
pub use types::{
    HASH_PREFIX_LEN, HASH_PREFIX_ROW_SIZE, HEADER_ROW_SIZE, HashPrefix, HashPrefixRow, HeaderRow,
    ScriptHash, ScriptHashRow, SpendingPrefixRow, TxidRow,
};
