//! Parse-once block state shared by the native apply path.
//!
//! One decoded block drives every validation stage: block rules, BIP30/BIP34,
//! the UTXO overlay walk, and per-input script checks. [`BlockView`] carries
//! that block's transaction slice together with the identities and resolved
//! prevouts computed once during apply preparation, so later stages consume the
//! same hashes and the same decoded transactions instead of recomputing them.

use bitcoin_rs_primitives::{Tx, TxOut, Txid, Wtxid};

/// A decoded block's transactions, identities, and resolved prevouts.
///
/// The node computes the transaction IDs once (the kernel parse provides them
/// in kernel builds; the native build hashes each transaction once) and hands
/// them here by value. Witness IDs are computed lazily at most once, because
/// only witness-carrying blocks under active segwit ever need them (the BIP141
/// witness-commitment check).
pub struct BlockView<'b> {
    txs: &'b [Tx],
    txids: Vec<Txid>,
    wtxids: Option<Vec<Wtxid>>,
    resolved: Vec<Vec<Option<TxOut>>>,
}

impl<'b> BlockView<'b> {
    /// Binds one decoded block's transactions to identities computed once.
    ///
    /// `txids` must hold one transaction ID per transaction in block order; the
    /// same vector every other stage consumes, so no stage re-hashes.
    #[must_use]
    pub fn new(txs: &'b [Tx], txids: Vec<Txid>) -> Self {
        debug_assert_eq!(
            txs.len(),
            txids.len(),
            "block view needs one txid per transaction"
        );
        Self {
            txs,
            txids,
            wtxids: None,
            resolved: Vec::new(),
        }
    }

    /// Returns the decoded transactions in block order.
    #[must_use]
    pub const fn transactions(&self) -> &'b [Tx] {
        self.txs
    }

    /// Returns transaction IDs computed once during apply preparation.
    #[must_use]
    pub fn txids(&self) -> &[Txid] {
        &self.txids
    }

    /// Returns witness transaction IDs, computing them at most once.
    ///
    /// Only callers that already know the block carries witness data reach
    /// here, so witness-free blocks never pay for the serialization and
    /// hashing.
    pub fn witness_ids(&mut self) -> &[Wtxid] {
        if self.wtxids.is_none() {
            self.wtxids = Some(self.txs.iter().map(Tx::wtxid).collect());
        }
        self.wtxids
            .as_deref()
            .unwrap_or_else(|| unreachable!("witness IDs were just computed"))
    }

    /// Returns witness IDs if they were already computed, without hashing.
    #[must_use]
    pub fn computed_witness_ids(&self) -> Option<&[Wtxid]> {
        self.wtxids.as_deref()
    }

    /// Installs the prevout matrix resolved in block order.
    ///
    /// One row per transaction in input order (empty for the coinbase); the
    /// script stage consumes it once via [`Self::parts_mut`].
    pub fn set_resolved(&mut self, resolved: Vec<Vec<Option<TxOut>>>) {
        self.resolved = resolved;
    }

    /// Releases the owned transaction IDs for the commit scratch state.
    ///
    /// The identities were handed in once by the caller and leave through the
    /// same single owner; nothing else clones or recomputes them.
    #[must_use]
    pub fn into_txids(self) -> Vec<Txid> {
        self.txids
    }

    /// Splits the view into its transaction slice and its resolved matrix.
    pub(crate) fn parts_mut(&mut self) -> (&'b [Tx], &mut Vec<Vec<Option<TxOut>>>) {
        (self.txs, &mut self.resolved)
    }
}
