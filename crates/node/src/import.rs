//! Block import pipeline (skeleton).
//!
//! The real pipeline lands as follow-up turns wire P2P → download →
//! decode → consensus validation → UTXO commit → chain tip advance
//! → index / filter / coinstats updates → RPC long-poll wake. This
//! file declares the contract those commits fill in.

use anyhow::{Context as _, Result};
use bitcoin_rs_primitives::{Block, Hash256};

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
    let block = Block::consensus_decode(block_bytes)
        .with_context(|| format!("decode block ({} bytes)", block_bytes.len()))?;
    let hash = block.block_hash().0;
    let tx_count = block.txs.len();
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
    use bitcoin_rs_primitives::encode::double_sha256;
    use bitcoin_rs_primitives::{
        Block, BlockHash, Hash256, Header, OutPoint, Tx, TxIn, TxOut, Txid, consensus_bytes,
    };
    use std::time::{Duration, Instant};
    use tempfile::tempdir;

    const REGTEST_GENESIS_HEX: &str = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff7f20020000000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";

    #[test]
    fn import_decodes_a_well_formed_block() -> Result<()> {
        let bytes = hex_decode(REGTEST_GENESIS_HEX)?;
        let block = Block::consensus_decode(&bytes)?;
        let genesis_hash = block.block_hash().0;

        let dir = tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        config.txindex = true;
        let mut state = NodeState::open(config, None)?;
        state.start_index_workers()?;
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
            0,
            "genesis coinbase is unspendable and absent from live UTXO state"
        );
        assert!(
            state.transactions().read().is_empty(),
            "confirmed transaction cache must stay empty"
        );
        let coinbase = block
            .txs
            .first()
            .ok_or_else(|| anyhow::anyhow!("genesis block has no transactions"))?;
        let txid = coinbase.txid();
        let tx_index = state
            .tx_index_query()
            .ok_or_else(|| anyhow::anyhow!("txindex missing after enabled open"))?;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match tx_index.index_info() {
                Ok(info) if info.synced => break,
                Ok(_)
                | Err(
                    bitcoin_rs_rpc::context::TxQueryError::Retry
                    | bitcoin_rs_rpc::context::TxQueryError::Unavailable(_),
                ) => {}
                Err(error) => return Err(error.into()),
            }
            if Instant::now() >= deadline {
                anyhow::bail!("txindex did not catch up after import");
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        let resolved = tx_index.transaction(&txid)?;
        assert_eq!(
            resolved.as_ref().map(Tx::txid),
            Some(txid),
            "genesis coinbase must resolve through txindex"
        );
        assert!(
            state.mempool().read().is_empty(),
            "genesis import must leave mempool empty"
        );
        Ok(())
    }

    fn compute_merkle_root(block: &Block) -> Option<Hash256> {
        let mut leaves: Vec<[u8; 32]> = block.txs.iter().map(|tx| *tx.txid().as_bytes()).collect();
        if leaves.is_empty() {
            return None;
        }
        while leaves.len() > 1 {
            let original_len = leaves.len();
            let mut next = Vec::with_capacity(original_len.div_ceil(2));
            for pos in 0..original_len.div_ceil(2) {
                let left = leaves[2 * pos];
                let right = leaves[(2 * pos + 1).min(original_len - 1)];
                let mut pair = [0_u8; 64];
                pair[..32].copy_from_slice(&left);
                pair[32..].copy_from_slice(&right);
                next.push(double_sha256(&pair).to_le_bytes());
            }
            leaves = next;
        }
        Some(Hash256::from_le_bytes(&leaves[0]))
    }

    fn pow_met(bits: u32, hash: Hash256) -> bool {
        // Interpret the hash as a little-endian 256-bit integer and compare it
        // against the decoded compact target. Regtest bits 0x207f_ffff is the
        // easiest target (about half of all hashes pass); lower targets reject
        // more. Both arrays are reversed into big-endian order so `[u8; 32]`
        // ordering is numeric ordering.
        let target = uint_be(&compact_to_target(bits));
        if target == [0_u8; 32] {
            return false;
        }
        uint_be(&hash.to_le_bytes()) <= target
    }

    fn compact_to_target(bits: u32) -> [u8; 32] {
        let exponent = usize::from(u8::try_from(bits >> 24).unwrap_or(0));
        let mantissa = u64::from(bits & 0x007f_ffff);
        let mut target = [0_u8; 32];
        if exponent <= 3 {
            let val = mantissa >> (8 * (3 - exponent));
            target[..8].copy_from_slice(&val.to_le_bytes());
        } else {
            let shift = 8 * (exponent - 3);
            if shift < 256 {
                let byte_shift = shift / 8;
                for (offset, &byte) in mantissa.to_le_bytes().iter().enumerate() {
                    let position = byte_shift + offset;
                    if position < 32 {
                        target[position] = byte;
                    }
                }
            }
        }
        if mantissa != 0 && bits & 0x0080_0000 != 0 {
            return [0_u8; 32];
        }
        if mantissa != 0
            && (exponent > 34
                || (mantissa > 0xff && exponent > 33)
                || (mantissa > 0xffff && exponent > 32))
        {
            return [0_u8; 32];
        }
        target
    }

    /// Reverses a 32-byte little-endian integer so array ordering is numeric.
    fn uint_be(bytes: &[u8; 32]) -> [u8; 32] {
        let mut arr = [0_u8; 32];
        arr.copy_from_slice(bytes);
        arr.reverse();
        arr
    }

    fn mine_header_to_declared_target(header: &mut Header) -> Result<()> {
        while !pow_met(header.bits, header.compute_hash().0) {
            header.nonce = header
                .nonce
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("exhausted nonce while mining test header"))?;
        }
        Ok(())
    }

    fn mine_block_to_declared_target(block: &mut Block) -> Result<()> {
        while !pow_met(block.header.bits, block.block_hash().0) {
            block.header.nonce = block
                .header
                .nonce
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("exhausted nonce while mining test block"))?;
        }
        Ok(())
    }

    #[test]
    fn import_rejects_block_whose_hash_exceeds_declared_target() -> Result<()> {
        let genesis_bytes = hex_decode(REGTEST_GENESIS_HEX)?;
        let mut block = Block::consensus_decode(&genesis_bytes)?;
        block.header.prev_blockhash = block.block_hash();
        block.header.time = block.header.time.saturating_add(1);
        block.header.bits = 0x0010_0001;

        let block_bytes = consensus_bytes(&block);

        let dir = tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config, None)?;
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
        let genesis_block = crate::Network::Mainnet.genesis_block();
        let genesis_bytes = encode_block(&genesis_block);
        let mut block = genesis_block.clone();
        block.header.prev_blockhash = genesis_block.block_hash();
        block.header.time = block.header.time.saturating_add(1);
        block.header.bits = 0x207f_ffff;
        block.txs[0].inputs[0].script_sig = vec![1, 1];
        block.header.merkle_root = compute_merkle_root(&block)
            .ok_or_else(|| anyhow::anyhow!("mutated block should have merkle root"))?;
        mine_block_to_declared_target(&mut block)?;
        let block_bytes = encode_block(&block);

        let dir = tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Mainnet);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config, None)?;
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
    fn import_rejects_non_retarget_child_with_changed_nbits() -> Result<()> {
        let genesis_bytes = hex_decode(REGTEST_GENESIS_HEX)?;
        let mut block = Block::consensus_decode(&genesis_bytes)?;
        block.header.prev_blockhash = block.block_hash();
        block.header.time = block.header.time.saturating_add(1);
        block.header.bits = 0x207e_ffff;
        block.txs[0].inputs[0].script_sig = vec![1, 1];
        block.header.merkle_root = compute_merkle_root(&block)
            .ok_or_else(|| anyhow::anyhow!("mutated block should have merkle root"))?;
        mine_block_to_declared_target(&mut block)?;
        let block_bytes = encode_block(&block);

        let dir = tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config, None)?;
        let _genesis = import_block(&state, &genesis_bytes)?;

        let Err(error) = import_block(&state, &block_bytes) else {
            anyhow::bail!("non-retarget child with changed nBits should be rejected");
        };

        assert!(
            error.chain().any(|cause| {
                matches!(
                    cause.downcast_ref::<crate::state::ApplyError>(),
                    Some(crate::state::ApplyError::NbitsNonRetargetMismatch {
                        actual: 0x207e_ffff,
                        expected: 0x207f_ffff,
                        height: 1,
                    })
                )
            }),
            "error chain should contain nBits mismatch rejection: {error:?}"
        );
        assert_eq!(
            state
                .chain_tip()
                .load_full()
                .ok_or_else(|| anyhow::anyhow!("genesis tip should remain published"))?
                .height,
            0,
            "rejected nBits mismatch must not advance chain tip"
        );
        Ok(())
    }

    #[test]
    fn import_two_blocks_in_sequence_advances_height_to_one() -> Result<()> {
        let genesis_bytes = hex_decode(REGTEST_GENESIS_HEX)?;
        let mut follow_up = Block::consensus_decode(&genesis_bytes)?;
        follow_up.header.prev_blockhash = follow_up.block_hash();
        follow_up.header.time = follow_up.header.time.saturating_add(1);
        follow_up.txs[0].inputs[0].script_sig = vec![1, 1];
        follow_up.header.merkle_root = compute_merkle_root(&follow_up)
            .ok_or_else(|| anyhow::anyhow!("follow-up block should have merkle root"))?;
        mine_block_to_declared_target(&mut follow_up)?;

        let follow_up_bytes = consensus_bytes(&follow_up);

        let dir = tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config, None)?;

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
        let mut follow_up = Block::consensus_decode(&genesis_bytes)?;
        follow_up.header.prev_blockhash = follow_up.block_hash();
        follow_up.header.time = follow_up.header.time.saturating_add(1);
        follow_up.txs[0].inputs[0].script_sig = vec![1, 1];
        follow_up.header.merkle_root = compute_merkle_root(&follow_up)
            .ok_or_else(|| anyhow::anyhow!("follow-up block should have merkle root"))?;
        mine_block_to_declared_target(&mut follow_up)?;

        let follow_up_bytes = consensus_bytes(&follow_up);

        let dir = tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config, None)?;

        let _genesis = import_block(&state, &genesis_bytes)?;
        let _follow_up = import_block(&state, &follow_up_bytes)?;

        assert_eq!(state.block_tree().read().len(), 2);
        Ok(())
    }

    #[test]
    fn import_rejects_block_with_unspendable_input_tx() -> Result<()> {
        let genesis_bytes = hex_decode(REGTEST_GENESIS_HEX)?;
        let mut block = Block::consensus_decode(&genesis_bytes)?;
        block.header.prev_blockhash = block.block_hash();
        block.header.time = block.header.time.saturating_add(1);
        block.txs[0].inputs[0].script_sig = vec![1, 1];
        block.txs.push(Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[0_u8; 32])), 0),
                script_sig: Vec::new(),
                sequence: u32::MAX,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 1,
                script_pubkey: Vec::new(),
            }],
            lock_time: 0,
        });
        block.header.merkle_root = compute_merkle_root(&block)
            .ok_or_else(|| anyhow::anyhow!("mutated block should have merkle root"))?;
        mine_block_to_declared_target(&mut block)?;

        let block_bytes = consensus_bytes(&block);

        let dir = tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config, None)?;

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
        let genesis_block = Block::consensus_decode(&genesis_bytes)?;

        let dir = tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config, None)?;
        let _genesis = import_block(&state, &genesis_bytes)?;

        let mut coinbase_block = genesis_block.clone();
        coinbase_block.header.prev_blockhash = genesis_block.block_hash();
        coinbase_block.header.time = coinbase_block.header.time.saturating_add(1);
        coinbase_block.txs[0].inputs[0].script_sig = vec![1, 1];
        coinbase_block.header.merkle_root = compute_merkle_root(&coinbase_block)
            .ok_or_else(|| anyhow::anyhow!("height-1 block should have merkle root"))?;
        mine_block_to_declared_target(&mut coinbase_block)?;
        let coinbase_bytes = encode_block(&coinbase_block);
        let _coinbase = import_block(&state, &coinbase_bytes)?;
        let immature_coinbase_txid = coinbase_block.txs[0].txid();

        let mut block = coinbase_block;
        block.header.prev_blockhash = block.block_hash();
        block.header.time = block.header.time.saturating_add(1);
        block.txs[0].inputs[0].script_sig = vec![1, 2];
        block.txs.push(Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(immature_coinbase_txid, 0),
                script_sig: Vec::new(),
                sequence: u32::MAX,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 1,
                script_pubkey: Vec::new(),
            }],
            lock_time: 0,
        });

        let Err(error) = state.check_coinbase_maturity(&block, 2) else {
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
            1
        );

        Ok(())
    }

    #[test]
    fn import_rejects_block_with_no_coinbase() -> Result<()> {
        let genesis_bytes = hex_decode(REGTEST_GENESIS_HEX)?;
        let mut block = Block::consensus_decode(&genesis_bytes)?;
        block.header.prev_blockhash = block.block_hash();
        block.header.time = block.header.time.saturating_add(1);
        block.txs[0].inputs[0].previous_output =
            OutPoint::new(Txid(Hash256::from_le_bytes(&[1_u8; 32])), 0);
        let merkle_root = compute_merkle_root(&block)
            .ok_or_else(|| anyhow::anyhow!("mutated block should have merkle root"))?;
        block.header.merkle_root = merkle_root;
        mine_block_to_declared_target(&mut block)?;

        let block_bytes = consensus_bytes(&block);

        let dir = tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config, None)?;
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
        let mut block = Block::consensus_decode(&genesis_bytes)?;

        let dir = tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config, None)?;
        let synthetic_tip = seed_synthetic_header_tip(&state, 499)?;

        block.header.prev_blockhash = BlockHash(synthetic_tip.hash);
        block.txs[0].inputs[0].script_sig = Vec::new();
        block.header.merkle_root = compute_merkle_root(&block)
            .ok_or_else(|| anyhow::anyhow!("mutated block should have merkle root"))?;
        mine_block_to_declared_target(&mut block)?;

        let block_bytes = consensus_bytes(&block);

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

    fn encode_block(block: &Block) -> Vec<u8> {
        consensus_bytes(block)
    }

    fn seed_synthetic_header_tip(
        state: &NodeState,
        height: u32,
    ) -> Result<bitcoin_rs_chain::TipSnapshot> {
        let block_tree = state.block_tree();
        let mut tree = block_tree.write();
        let bits = 0x207f_ffff;
        let mut parent = None;
        let mut prev_blockhash = BlockHash(Hash256::from_le_bytes(&[0_u8; 32]));
        let mut tip = None;

        for current_height in 0..=height {
            let mut merkle = [0_u8; 32];
            merkle[..4].copy_from_slice(&current_height.to_le_bytes());
            let mut header = Header {
                version: 1,
                prev_blockhash,
                merkle_root: Hash256::from_le_bytes(&merkle),
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
            prev_blockhash = header.compute_hash();
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
