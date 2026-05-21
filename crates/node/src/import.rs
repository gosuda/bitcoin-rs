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
        assert!(
            state.applied_tip().load_full().is_some(),
            "applied_tip published after import_block"
        );
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
    fn import_rejects_block_whose_hash_exceeds_declared_target() -> Result<()> {
        let genesis_bytes = hex_decode(REGTEST_GENESIS_HEX)?;
        let mut cursor = std::io::Cursor::new(genesis_bytes.as_slice());
        let mut block = Block::consensus_decode(&mut cursor)?;
        block.header.prev_blockhash = block.block_hash();
        block.header.bits = bitcoin::CompactTarget::from_consensus(0x0010_0001);

        let mut block_bytes = Vec::new();
        block.consensus_encode(&mut block_bytes)?;

        let dir = tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config)?;
        let _genesis = import_block(&state, &genesis_bytes)?;

        let Err(error) = import_block(&state, &block_bytes) else {
            anyhow::bail!("block whose hash exceeds declared target should be rejected");
        };

        assert!(
            error.chain().any(|cause| {
                matches!(
                    cause.downcast_ref::<crate::state::ApplyError>(),
                    Some(crate::state::ApplyError::ProofOfWork { .. })
                )
            }),
            "error chain should contain ProofOfWork rejection: {error:?}"
        );

        assert_eq!(
            state
                .chain_tip()
                .load_full()
                .ok_or_else(|| anyhow::anyhow!("genesis tip should remain published"))?
                .height,
            0,
            "rejected block must not advance chain tip"
        );
        Ok(())
    }

    #[test]
    fn import_rejects_block_with_target_above_network_limit() -> Result<()> {
        let genesis_block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Bitcoin);
        let genesis_bytes = encode_block(&genesis_block)?;
        let mut block = genesis_block.clone();
        block.header.prev_blockhash = genesis_block.block_hash();
        block.header.bits = bitcoin::CompactTarget::from_consensus(0x207f_ffff);
        block.txdata[0].input[0].script_sig = bitcoin::ScriptBuf::from_bytes(vec![1, 1]);
        block.header.merkle_root = block
            .compute_merkle_root()
            .ok_or_else(|| anyhow::anyhow!("mutated block should have merkle root"))?;
        mine_block_to_declared_target(&mut block)?;
        let block_bytes = encode_block(&block)?;

        let dir = tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Mainnet);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config)?;
        let _genesis = import_block(&state, &genesis_bytes)?;

        let Err(error) = import_block(&state, &block_bytes) else {
            anyhow::bail!("child block target exceeds mainnet PoW limit");
        };

        assert!(
            error.chain().any(|cause| {
                matches!(
                    cause.downcast_ref::<crate::state::ApplyError>(),
                    Some(crate::state::ApplyError::TargetAboveLimit)
                )
            }),
            "error chain should contain TargetAboveLimit rejection: {error:?}"
        );
        assert_eq!(
            state
                .chain_tip()
                .load_full()
                .ok_or_else(|| anyhow::anyhow!("genesis tip should remain published"))?
                .height,
            0,
            "rejected block must not advance chain tip"
        );
        Ok(())
    }

    #[test]
    fn import_two_blocks_in_sequence_advances_height_to_one() -> Result<()> {
        let genesis_bytes = hex_decode(REGTEST_GENESIS_HEX)?;
        let mut cursor = std::io::Cursor::new(genesis_bytes.as_slice());
        let mut follow_up = Block::consensus_decode(&mut cursor)?;
        follow_up.header.prev_blockhash = follow_up.block_hash();
        follow_up.txdata[0].input[0].script_sig = bitcoin::ScriptBuf::from_bytes(vec![1, 1]);
        follow_up.header.merkle_root = follow_up
            .compute_merkle_root()
            .ok_or_else(|| anyhow::anyhow!("follow-up block should have merkle root"))?;
        mine_block_to_declared_target(&mut follow_up)?;

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
    fn two_block_import_grows_block_tree_to_two_headers() -> Result<()> {
        let genesis_bytes = hex_decode(REGTEST_GENESIS_HEX)?;
        let mut cursor = std::io::Cursor::new(genesis_bytes.as_slice());
        let mut follow_up = Block::consensus_decode(&mut cursor)?;
        follow_up.header.prev_blockhash = follow_up.block_hash();
        follow_up.txdata[0].input[0].script_sig = bitcoin::ScriptBuf::from_bytes(vec![1, 1]);
        follow_up.header.merkle_root = follow_up
            .compute_merkle_root()
            .ok_or_else(|| anyhow::anyhow!("follow-up block should have merkle root"))?;
        mine_block_to_declared_target(&mut follow_up)?;

        let mut follow_up_bytes = Vec::new();
        follow_up.consensus_encode(&mut follow_up_bytes)?;

        let dir = tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config)?;

        let _genesis = import_block(&state, &genesis_bytes)?;
        let _follow_up = import_block(&state, &follow_up_bytes)?;

        assert_eq!(state.block_tree().read().len(), 2);
        Ok(())
    }

    #[test]
    fn import_rejects_block_with_unspendable_input_tx() -> Result<()> {
        let genesis_bytes = hex_decode(REGTEST_GENESIS_HEX)?;
        let mut cursor = std::io::Cursor::new(genesis_bytes.as_slice());
        let mut block = Block::consensus_decode(&mut cursor)?;
        block.header.prev_blockhash = block.block_hash();
        block.txdata[0].input[0].script_sig = bitcoin::ScriptBuf::from_bytes(vec![1, 1]);
        block.txdata.push(bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: bitcoin::Txid::from_byte_array([0_u8; 32]),
                    vout: 0,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(1),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        });
        block.header.merkle_root = block
            .compute_merkle_root()
            .ok_or_else(|| anyhow::anyhow!("mutated block should have merkle root"))?;
        mine_block_to_declared_target(&mut block)?;

        let mut block_bytes = Vec::new();
        block.consensus_encode(&mut block_bytes)?;

        let dir = tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config)?;

        let _genesis = import_block(&state, &genesis_bytes)?;
        let Err(error) = import_block(&state, &block_bytes) else {
            anyhow::bail!("block with missing prevout should be rejected");
        };

        assert!(
            error.chain().any(|cause| matches!(
                cause.downcast_ref::<bitcoin_rs_consensus::ConsensusError>(),
                Some(bitcoin_rs_consensus::ConsensusError::MissingPrevout { input_index: 0 })
            )),
            "error chain should contain MissingPrevout: {error:?}"
        );
        assert_eq!(
            state
                .chain_tip()
                .load_full()
                .ok_or_else(|| anyhow::anyhow!("genesis tip should remain published"))?
                .height,
            0
        );
        Ok(())
    }

    #[test]
    fn import_rejects_premature_coinbase_spend() -> Result<()> {
        let genesis_bytes = hex_decode(REGTEST_GENESIS_HEX)?;
        let mut cursor = std::io::Cursor::new(genesis_bytes.as_slice());
        let genesis_block = Block::consensus_decode(&mut cursor)?;
        let genesis_coinbase_txid = genesis_block.txdata[0].compute_txid();

        let dir = tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config)?;
        let _genesis = import_block(&state, &genesis_bytes)?;

        let mut block = genesis_block;
        block.header.prev_blockhash = block.block_hash();
        block.txdata[0].input[0].script_sig = bitcoin::ScriptBuf::from_bytes(vec![1, 1]);
        block.txdata.push(bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: genesis_coinbase_txid,
                    vout: 0,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(1),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        });

        let Err(error) = state.check_coinbase_maturity(&block, 1) else {
            anyhow::bail!("premature coinbase spend should be rejected");
        };

        assert!(
            matches!(
                error,
                crate::state::ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::Bip {
                    bip: "COINBASE_MATURITY",
                    ..
                })
            ),
            "error should be COINBASE_MATURITY rejection: {error:?}"
        );
        assert_eq!(
            state
                .chain_tip()
                .load_full()
                .ok_or_else(|| anyhow::anyhow!("genesis tip should remain published"))?
                .height,
            0
        );

        Ok(())
    }

    #[test]
    fn import_rejects_block_with_no_coinbase() -> Result<()> {
        let genesis_bytes = hex_decode(REGTEST_GENESIS_HEX)?;
        let mut cursor = std::io::Cursor::new(genesis_bytes.as_slice());
        let mut block = Block::consensus_decode(&mut cursor)?;
        block.header.prev_blockhash = block.block_hash();
        block.txdata[0].input[0].previous_output = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([1_u8; 32]),
            vout: 0,
        };
        let merkle_root = block
            .compute_merkle_root()
            .ok_or_else(|| anyhow::anyhow!("mutated block should have merkle root"))?;
        block.header.merkle_root = merkle_root;
        mine_block_to_declared_target(&mut block)?;

        let mut block_bytes = Vec::new();
        block.consensus_encode(&mut block_bytes)?;

        let dir = tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config)?;
        let _genesis = import_block(&state, &genesis_bytes)?;

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
        assert_eq!(
            state
                .chain_tip()
                .load_full()
                .ok_or_else(|| anyhow::anyhow!("genesis tip should remain published"))?
                .height,
            0,
            "rejected block must not advance chain tip"
        );
        Ok(())
    }

    #[test]
    fn import_rejects_post_bip34_block_with_no_height_in_coinbase() -> Result<()> {
        let genesis_bytes = hex_decode(REGTEST_GENESIS_HEX)?;
        let mut cursor = std::io::Cursor::new(genesis_bytes.as_slice());
        let mut block = Block::consensus_decode(&mut cursor)?;

        let dir = tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config)?;
        let synthetic_tip = seed_synthetic_header_tip(&state, 499)?;

        block.header.prev_blockhash =
            bitcoin::BlockHash::from_byte_array(synthetic_tip.hash.to_le_bytes());
        block.txdata[0].input[0].script_sig = bitcoin::ScriptBuf::new();
        block.header.merkle_root = block
            .compute_merkle_root()
            .ok_or_else(|| anyhow::anyhow!("mutated block should have merkle root"))?;
        mine_block_to_declared_target(&mut block)?;

        let mut block_bytes = Vec::new();
        block.consensus_encode(&mut block_bytes)?;

        let Err(error) = import_block(&state, &block_bytes) else {
            anyhow::bail!("post-BIP34 block without height should be rejected");
        };

        assert!(
            error.chain().any(|cause| matches!(
                cause.downcast_ref::<bitcoin_rs_consensus::ConsensusError>(),
                Some(bitcoin_rs_consensus::ConsensusError::Bip { bip: "BIP34", .. })
            )),
            "error chain should contain BIP34 rejection: {error:?}"
        );
        assert_eq!(
            state
                .chain_tip()
                .load_full()
                .ok_or_else(|| anyhow::anyhow!("synthetic tip should remain published"))?
                .height,
            synthetic_tip.height
        );
        Ok(())
    }

    fn encode_block(block: &Block) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        block.consensus_encode(&mut bytes)?;
        Ok(bytes)
    }

    fn seed_synthetic_header_tip(
        state: &NodeState,
        height: u32,
    ) -> Result<bitcoin_rs_chain::TipSnapshot> {
        let block_tree = state.block_tree();
        let mut tree = block_tree.write();
        let bits = bitcoin::CompactTarget::from_consensus(0x207f_ffff);
        let mut parent = None;
        let mut prev_blockhash = bitcoin::BlockHash::all_zeros();
        let mut tip = None;

        for current_height in 0..=height {
            let mut merkle = [0_u8; 32];
            merkle[..4].copy_from_slice(&current_height.to_le_bytes());
            let mut header = bitcoin::block::Header {
                version: bitcoin::block::Version::ONE,
                prev_blockhash,
                merkle_root: bitcoin::TxMerkleNode::from_byte_array(merkle),
                time: current_height,
                bits,
                nonce: 0,
            };
            mine_header_to_declared_target(&mut header)?;
            let node_id =
                tree.insert_node(parent, header, bitcoin_rs_chain::NodeStatus::HeaderValid)?;
            let node = tree.node(node_id)?;
            let snapshot = bitcoin_rs_chain::TipSnapshot {
                tip_id: node_id,
                height: node.height,
                chainwork: node.chainwork,
                hash: node.hash,
            };
            prev_blockhash = header.block_hash();
            parent = Some(node_id);
            tip = Some(snapshot);
        }

        let tip =
            tip.ok_or_else(|| anyhow::anyhow!("synthetic header chain should not be empty"))?;
        drop(tree);
        state
            .chain_tip()
            .store(Some(std::sync::Arc::new(tip.clone())));
        state
            .applied_tip()
            .store(Some(std::sync::Arc::new(tip.clone())));
        Ok(tip)
    }

    fn mine_header_to_declared_target(header: &mut bitcoin::block::Header) -> Result<()> {
        while header.validate_pow(header.target()).is_err() {
            header.nonce = header
                .nonce
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("exhausted nonce while mining test header"))?;
        }
        Ok(())
    }

    fn mine_block_to_declared_target(block: &mut Block) -> Result<()> {
        while block.header.validate_pow(block.header.target()).is_err() {
            block.header.nonce = block
                .header
                .nonce
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("exhausted nonce while mining test block"))?;
        }
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
