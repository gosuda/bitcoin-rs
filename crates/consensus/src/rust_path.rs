use bitcoin::{BlockHash, Network, OutPoint, TxOut};
use bitcoin_rs_primitives::{Block, Tx};
use bitcoin_rs_script::VerifyFlags;

use crate::{ConsensusError, verify_block_rules, verify_transaction};

/// Minimal UTXO lookup contract used by the portable validator.
pub trait UtxoView {
    /// Looks up a previous output by outpoint.
    fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut>;
}

impl<T> UtxoView for &T
where
    T: UtxoView + ?Sized,
{
    fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
        (*self).lookup(outpoint)
    }
}

impl UtxoView for std::collections::BTreeMap<OutPoint, TxOut> {
    fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
        self.get(outpoint).cloned()
    }
}

/// Previous-tip state needed for contextual block connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TipState {
    /// Previous block height, or `None` before genesis.
    pub height: Option<u32>,
    /// Previous block hash, when known.
    pub block_hash: Option<BlockHash>,
    /// Median-time-past of the previous tip.
    pub median_time_past: u32,
}

impl TipState {
    /// Returns the height of the next block being connected.
    #[must_use]
    pub const fn next_height(&self) -> u32 {
        match self.height {
            Some(height) => height.saturating_add(1),
            None => 0,
        }
    }
}

/// State produced after connecting a block through the portable path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockState {
    /// Connected block height.
    pub height: u32,
    /// Connected block hash.
    pub block_hash: BlockHash,
    /// Total transaction count in the block.
    pub tx_count: usize,
}

/// Portable Rust consensus validator.
#[derive(Clone, Debug)]
pub struct RustValidator {
    network: Network,
}

impl RustValidator {
    /// Creates a validator for a Bitcoin network.
    #[must_use]
    pub const fn new(network: Network) -> Self {
        Self { network }
    }

    /// Returns the network this validator was configured for.
    #[must_use]
    pub const fn network(&self) -> Network {
        self.network
    }

    /// Verifies one transaction against a supplied UTXO view.
    pub fn verify_tx(
        &self,
        tx: &Tx,
        prevouts: &impl UtxoView,
        height: u32,
        flags: VerifyFlags,
    ) -> Result<(), ConsensusError> {
        let _ = self.network;
        verify_transaction(tx, prevouts, height, flags)
    }

    /// Connects block-level rules. Per-input UTXO updates land with Task 5.
    pub fn connect_block(
        &self,
        block: &Block,
        prev_tip: &TipState,
    ) -> Result<BlockState, ConsensusError> {
        let _ = self.network;
        verify_block_rules(block, prev_tip)?;
        Ok(BlockState {
            height: prev_tip.next_height(),
            block_hash: block.0.block_hash(),
            tx_count: block.0.txdata.len(),
        })
    }
}
