//! Block import pipeline (skeleton).
//!
//! The real pipeline lands as follow-up turns wire P2P → download →
//! decode → consensus validation → UTXO commit → chain tip advance
//! → index / filter / coinstats updates → RPC long-poll wake. This
//! file declares the contract those commits fill in.

use anyhow::{Context as _, Result};
use bitcoin::Block;
use bitcoin::consensus::Decodable as _;
use bitcoin::hashes::Hash as _;
use bitcoin_rs_primitives::Hash256;

use crate::state::NodeState;

/// Outcome of importing one block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportOutcome {
    /// Block hash in canonical little-endian form.
    pub hash: Hash256,
    /// Number of transactions in the block.
    pub tx_count: usize,
    /// Whether the block was applied to the active chain.
    ///
    /// In the v1 skeleton this is always `false` — the validation
    /// pipeline is not yet wired. Future commits flip it to `true`
    /// once UTXO commit + chain tip advance succeed.
    pub applied: bool,
}

/// Decodes `block_bytes` and returns the synthetic outcome.
///
/// V1 contract: decode-only. Returns an error if the bytes are
/// malformed. Returns `ImportOutcome { applied: false, ... }` on
/// successful decode.
pub fn import_block(_state: &NodeState, block_bytes: &[u8]) -> Result<ImportOutcome> {
    let mut cursor = std::io::Cursor::new(block_bytes);
    let block = Block::consensus_decode(&mut cursor)
        .with_context(|| format!("decode block ({} bytes)", block_bytes.len()))?;
    let block_hash = block.block_hash();
    let hash = Hash256::from_le_bytes(block_hash.as_byte_array());
    Ok(ImportOutcome {
        hash,
        tx_count: block.txdata.len(),
        applied: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn import_decodes_a_well_formed_block() -> Result<()> {
        // Smallest valid Bitcoin block: regtest genesis.
        let block_hex = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff7f20020000000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";
        let bytes = hex_decode(block_hex)?;
        let dir = tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config)?;
        let outcome = import_block(&state, &bytes)?;
        assert_eq!(outcome.tx_count, 1, "genesis has one transaction");
        assert!(!outcome.applied, "v1 skeleton must not apply blocks");
        Ok(())
    }

    fn hex_decode(hex: &str) -> Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(hex.len() / 2);
        let chars: Vec<char> = hex.chars().collect();
        for pair in chars.chunks(2) {
            let high = pair[0]
                .to_digit(16)
                .with_context(|| format!("non-hex char {}", pair[0]))?;
            let low = pair[1]
                .to_digit(16)
                .with_context(|| format!("non-hex char {}", pair[1]))?;
            bytes.push(
                u8::try_from((high << 4) | low).with_context(|| "hex value out of u8 range")?,
            );
        }
        Ok(bytes)
    }
}
