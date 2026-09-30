//! Shared test support: writers for raw index rows, plus a block header
//! fixture.
//!
//! The rows land in `bitcoin_rs_storage::InMemoryKvStore`, the backend-free
//! `KvStore` owned by bitcoin-rs-storage. Deliberately not behind a storage
//! feature. Correctness tests that gate a refactor must run on a plain
//! `cargo test --workspace`; a test hidden behind `required-features` is a
//! test that silently does not run.
#![allow(dead_code)]

use bitcoin_rs_index::types::{TxPosition, TxPositionValue};
use bitcoin_rs_index::{ScriptHash, ScriptHashRow, SpendingPrefixRow};
use bitcoin_rs_primitives::{BlockHash, CompactTarget, Hash256, Header, OutPoint};
use bitcoin_rs_storage::{ColumnFamily, InMemoryKvStore, KvStore, StorageError};

/// Writes one funding-row key at `height` with an empty value.
///
/// Empty values take the scan-fallback resolver path. Tests that pin
/// little-endian key order, not watermark contiguity, use this instead of
/// [`bitcoin_rs_index::IndexWriter::commit_block`].
pub(crate) fn put_funding_row(
    store: &InMemoryKvStore,
    scripthash: ScriptHash,
    height: u32,
) -> Result<(), StorageError> {
    store.put(
        ColumnFamily::Funding,
        &ScriptHashRow::row(scripthash, height).to_db_row(),
        &[],
    )
}

/// Writes one funding-row key at `height` carrying `positions`.
///
/// Real positions take the resolver's positioned-read path; tests that pin
/// `TxPosition`-backed resolution use this instead of the empty-value
/// [`put_funding_row`].
pub(crate) fn put_funding_row_positions(
    store: &InMemoryKvStore,
    scripthash: ScriptHash,
    height: u32,
    positions: &[TxPosition],
) -> Result<(), StorageError> {
    // An empty slice encodes an empty value — indistinguishable from
    // `put_funding_row`'s scan-path marker, so the positioned read would
    // silently not be exercised.
    assert!(
        !positions.is_empty(),
        "a funding row exists only because at least one transaction produced it"
    );
    store.put(
        ColumnFamily::Funding,
        &ScriptHashRow::row(scripthash, height).to_db_row(),
        &TxPositionValue::encode(positions),
    )
}

/// Writes one spending-row key at `height` with an empty value.
pub(crate) fn put_spending_row(
    store: &InMemoryKvStore,
    outpoint: &OutPoint,
    height: u32,
) -> Result<(), StorageError> {
    store.put(
        ColumnFamily::Spending,
        &SpendingPrefixRow::row(outpoint, height).to_db_row(),
        &[],
    )
}

/// A version-1 header with every other field zeroed, for fixture blocks that
/// need no chain linkage or proof of work.
pub(crate) fn header() -> Header {
    Header {
        version: 1,
        prev_blockhash: BlockHash::default(),
        merkle_root: Hash256::default(),
        time: 0,
        bits: CompactTarget::from_consensus(0),
        nonce: 0,
    }
}
