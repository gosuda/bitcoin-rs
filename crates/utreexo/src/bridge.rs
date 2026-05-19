use bitcoin::hashes::Hash as _;
use bitcoin_rs_primitives::{Block, Hash256};
use rustreexo::mem_forest::MemForest;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::accumulator::{NativeHash, from_native_hash, to_native_hash};
use crate::proof::Proof;

/// Errors returned by the bridge-node `MemForest` wrapper.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BridgeError {
    /// rustreexo `MemForest` rejected an operation.
    #[error("memforest error: {0}")]
    MemForest(String),
    /// A transaction output index does not fit Bitcoin's `u32` output number.
    #[error("transaction output index does not fit u32: {0}")]
    OutputIndexOverflow(usize),
}

/// Bridge-node accumulator backed by rustreexo's full in-memory forest.
#[derive(Clone, Debug, Default)]
pub struct Bridge {
    forest: MemForest<NativeHash>,
}

impl Bridge {
    /// Creates an empty bridge-node accumulator.
    #[must_use]
    pub fn new() -> Self {
        Self {
            forest: MemForest::new(),
        }
    }

    /// Generates an inclusion proof for the provided target leaf hashes.
    pub fn generate_proof(&self, target_hashes: &[Hash256]) -> Result<Proof, BridgeError> {
        let targets = target_hashes
            .iter()
            .copied()
            .map(to_native_hash)
            .collect::<Vec<_>>();
        let proof = self
            .forest
            .prove(&targets)
            .map_err(BridgeError::MemForest)?;
        Ok(Proof::from_native(proof, target_hashes.to_vec()))
    }

    /// Ingests a Bitcoin block using deterministic outpoint leaf hashes.
    pub fn ingest_block(&mut self, block: &Block) -> Result<(), BridgeError> {
        let mut deletes = Vec::new();
        let mut adds = Vec::new();

        for tx in &block.0.txdata {
            for input in &tx.input {
                if !input.previous_output.is_null() {
                    deletes.push(outpoint_leaf_hash(
                        input.previous_output.txid,
                        input.previous_output.vout,
                    ));
                }
            }

            let txid = tx.compute_txid();
            for (vout, _) in tx.output.iter().enumerate() {
                let vout =
                    u32::try_from(vout).map_err(|_| BridgeError::OutputIndexOverflow(vout))?;
                adds.push(outpoint_leaf_hash(txid, vout));
            }
        }

        self.modify_hashes(&adds, &deletes)
    }

    /// Adds already-computed leaf hashes to the bridge forest.
    pub fn ingest_hashes(&mut self, hashes: &[Hash256]) -> Result<(), BridgeError> {
        self.modify_hashes(hashes, &[])
    }

    /// Deletes already-computed leaf hashes from the bridge forest.
    pub fn delete_hashes(&mut self, hashes: &[Hash256]) -> Result<(), BridgeError> {
        self.modify_hashes(&[], hashes)
    }

    /// Returns the current bridge accumulator roots.
    #[must_use]
    pub fn roots(&self) -> Vec<Hash256> {
        self.forest
            .get_roots()
            .iter()
            .map(|root| from_native_hash(root.get_data()))
            .collect()
    }

    fn modify_hashes(&mut self, adds: &[Hash256], deletes: &[Hash256]) -> Result<(), BridgeError> {
        let adds = adds.iter().copied().map(to_native_hash).collect::<Vec<_>>();
        let deletes = deletes
            .iter()
            .copied()
            .map(to_native_hash)
            .collect::<Vec<_>>();
        self.forest
            .modify(&adds, &deletes)
            .map_err(BridgeError::MemForest)
    }
}

/// Computes the bridge leaf hash for an outpoint.
#[must_use]
pub fn outpoint_leaf_hash(txid: bitcoin::Txid, vout: u32) -> Hash256 {
    let mut engine = Sha256::new();
    engine.update(b"bitcoin-rs-utreexo/outpoint");
    engine.update(txid.as_byte_array());
    engine.update(vout.to_le_bytes());
    let first = engine.finalize();
    let second = Sha256::digest(first);
    let bytes = second.into();
    Hash256::from_le_bytes(&bytes)
}
