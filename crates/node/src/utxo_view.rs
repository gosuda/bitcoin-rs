//! `UtxoView` adapter over the in-memory `UtxoSet`.
//!
//! Converts `bitcoin::OutPoint` lookups (the consensus crate's contract)
//! into `bitcoin_rs_primitives::OutPoint` lookups (the UTXO crate's
//! internal layout). Used by `NodeState::apply_block` to run per-tx
//! script verification against the committed UTXO set.

use std::sync::Arc;

use bitcoin::hashes::Hash as _;
use bitcoin_rs_consensus::rust_path::UtxoView;
use bitcoin_rs_primitives::{Hash256, OutPoint as InternalOutPoint};
use bitcoin_rs_utxo::UtxoSet;

/// Thin lookup adapter around a shared `UtxoSet` handle.
pub struct UtxoSetView {
    set: Arc<UtxoSet>,
}

impl UtxoSetView {
    /// Constructs a view that borrows `set` for the lifetime of the view.
    #[must_use]
    pub const fn new(set: Arc<UtxoSet>) -> Self {
        Self { set }
    }
}

impl UtxoView for UtxoSetView {
    fn lookup(&self, outpoint: &bitcoin::OutPoint) -> Option<bitcoin::TxOut> {
        let internal = InternalOutPoint::new(
            Hash256::from_le_bytes(outpoint.txid.as_byte_array()),
            outpoint.vout,
        );
        self.set.get(&internal)
    }
}
