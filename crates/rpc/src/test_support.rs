//! Shared fixtures for the crate's `#[cfg(test)]` unit-test modules.

use bitcoin_rs_index::DerivedIndexInfo;
use bitcoin_rs_primitives::{Hash256, OutPoint, Txid};

/// An outpoint whose txid is the byte `tag` repeated, at `vout` 0.
pub(crate) fn outpoint(tag: u8) -> OutPoint {
    OutPoint::new(Txid(Hash256::from_le_bytes(&[tag; 32])), 0)
}

/// A `DerivedIndexInfo` stub for fake index queries.
pub(crate) fn derived_index_info(synced: bool, best_block_height: u32) -> DerivedIndexInfo {
    DerivedIndexInfo {
        synced,
        best_block_height,
    }
}
