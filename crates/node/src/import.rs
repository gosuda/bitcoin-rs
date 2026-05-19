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
    /// Successful decode now publishes the block as a synthetic active-chain
    /// tip through [`NodeState::apply_block`].
    pub applied: bool,
}

/// Decodes `block_bytes`, applies the decoded block, and returns the outcome.
///
/// V1 contract: synthetically apply after decode. Returns an error if the bytes
/// are malformed or the block cannot connect to the current synthetic tip.
pub fn import_block(state: &NodeState, block_bytes: &[u8]) -> Result<ImportOutcome> {
    let mut cursor = std::io::Cursor::new(block_bytes);
    let block = Block::consensus_decode(&mut cursor)
        .with_context(|| format!("decode block ({} bytes)", block_bytes.len()))?;
    let block_hash = block.block_hash();
    let hash = Hash256::from_le_bytes(block_hash.as_byte_array());
    let tx_count = block.txdata.len();
    let _tip = state.apply_block(&block).context("apply_block")?;
    Ok(ImportOutcome {
        hash,
        tx_count,
        applied: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::Encodable as _;
    use tempfile::tempdir;

    const REGTEST_GENESIS_HEX: &str = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff7f20020000000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";

    #[test]
    fn import_decodes_a_well_formed_block() -> Result<()> {
        let bytes = hex_decode(REGTEST_GENESIS_HEX)?;
        let mut cursor = std::io::Cursor::new(bytes.as_slice());
        let block = Block::consensus_decode(&mut cursor)?;
        let genesis_hash = Hash256::from_le_bytes(block.block_hash().as_byte_array());

        let dir = tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config)?;
        let outcome = import_block(&state, &bytes)?;

        assert_eq!(outcome.tx_count, 1, "genesis has one transaction");
        assert!(outcome.applied, "decoded block must be applied");
        let tip = state
            .chain_tip()
            .load_full()
            .ok_or_else(|| anyhow::anyhow!("missing chain tip after import"))?;
        assert_eq!(tip.height, 0);
        assert_eq!(tip.hash, genesis_hash);
        assert_eq!(
            state.utxo().len(),
            1,
            "genesis has one live coinbase output"
        );
        assert_eq!(
            state.transactions().read().len(),
            1,
            "genesis coinbase must be indexed"
        );
        assert!(
            state.mempool().read().is_empty(),
            "genesis import must leave mempool empty"
        );
        Ok(())
    }

    #[test]
    fn import_two_blocks_in_sequence_advances_height_to_one() -> Result<()> {
        let genesis_bytes = hex_decode(REGTEST_GENESIS_HEX)?;
        let mut cursor = std::io::Cursor::new(genesis_bytes.as_slice());
        let mut follow_up = Block::consensus_decode(&mut cursor)?;
        follow_up.header.prev_blockhash = follow_up.block_hash();
        follow_up.header.merkle_root = follow_up
            .compute_merkle_root()
            .ok_or_else(|| anyhow::anyhow!("follow-up block should have merkle root"))?;
        follow_up.header.nonce = follow_up.header.nonce.wrapping_add(1);

        let mut follow_up_bytes = Vec::new();
        follow_up.consensus_encode(&mut follow_up_bytes)?;

        let dir = tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config)?;

        let _genesis = import_block(&state, &genesis_bytes)?;
        let _follow_up = import_block(&state, &follow_up_bytes)?;

        let tip = state
            .chain_tip()
            .load_full()
            .ok_or_else(|| anyhow::anyhow!("missing chain tip after second import"))?;
        assert_eq!(tip.height, 1);
        Ok(())
    }

    #[test]
    fn import_rejects_block_with_no_coinbase() -> Result<()> {
        let genesis_bytes = hex_decode(REGTEST_GENESIS_HEX)?;
        let mut cursor = std::io::Cursor::new(genesis_bytes.as_slice());
        let mut block = Block::consensus_decode(&mut cursor)?;
        block.txdata[0].input[0].previous_output = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([1_u8; 32]),
            vout: 0,
        };
        let merkle_root = block
            .compute_merkle_root()
            .ok_or_else(|| anyhow::anyhow!("mutated block should have merkle root"))?;
        block.header.merkle_root = merkle_root;

        let mut block_bytes = Vec::new();
        block.consensus_encode(&mut block_bytes)?;

        let dir = tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config)?;

        let Err(error) = import_block(&state, &block_bytes) else {
            anyhow::bail!("block without coinbase should be rejected");
        };

        assert!(
            error.chain().any(
                |cause| cause.downcast_ref::<bitcoin_rs_consensus::ConsensusError>()
                    == Some(&bitcoin_rs_consensus::ConsensusError::MissingCoinbase)
            ),
            "error chain should contain MissingCoinbase: {error:?}"
        );
        assert!(
            state.chain_tip().load().is_none(),
            "rejected block must not advance chain tip"
        );
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
