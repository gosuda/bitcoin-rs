//! End-to-end crash-recovery coverage for the chainstate journal.

use std::sync::atomic::Ordering;

use anyhow::Result;
use bitcoin_rs_node::{Network, NodeConfig, state::NodeState};
use bitcoin_rs_primitives::{Block, BlockHash, Hash256, Header, OutPoint, Tx, TxIn, TxOut, Txid};
use sha2::{Digest, Sha256};

#[test]
fn restart_replays_durable_journal_suffix_above_checkpoint() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p_listen.clear();
    config.chainstate_journal.blocks = 1;

    let genesis = Network::Regtest.genesis_block();
    let initial = NodeState::open(config.clone(), None)?;
    initial.apply_block(&genesis)?;
    initial.publish_checkpoint()?;
    drop(initial);

    // Reopening once rebases the fresh writer onto the published checkpoint.
    let base = NodeState::open(config.clone(), None)?;
    let child = mined_regtest_child(genesis.block_hash())?;
    let expected_tip = base.apply_block(&child)?;
    let expected_utxo = base
        .utxo()
        .with_stable_view(|view| view.hash_serialized_3())?;
    let expected_stats = base.coin_stats().snapshot();
    let expected_tx_count = base.chain_tx_count_handle().load(Ordering::Relaxed);
    drop(base);

    // No checkpoint was published for `child`: only the journal can recover it.
    let resumed = NodeState::open(config, None)?;
    let resumed_tip = resumed
        .applied_tip()
        .load_full()
        .ok_or_else(|| std::io::Error::other("journal replay did not publish a tip"))?;
    assert_eq!(resumed_tip.as_ref(), &expected_tip);
    assert_eq!(
        resumed
            .utxo()
            .with_stable_view(|view| view.hash_serialized_3())?,
        expected_utxo
    );
    assert_eq!(
        resumed.coin_stats().snapshot().to_bytes(),
        expected_stats.to_bytes()
    );
    assert_eq!(
        resumed.chain_tx_count_handle().load(Ordering::Relaxed),
        expected_tx_count
    );
    Ok(())
}

fn mined_regtest_child(prev_blockhash: BlockHash) -> Result<Block> {
    let coinbase = Tx {
        version: 2,
        lock_time: 0,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid::default(), u32::MAX),
            script_sig: vec![1, 1],
            sequence: u32::MAX,
            witness: Vec::new(),
        }],
        outputs: vec![TxOut {
            value: 1,
            script_pubkey: Vec::new(),
        }],
    };
    let mut block = Block {
        header: Header {
            version: 1,
            prev_blockhash,
            merkle_root: Hash256::default(),
            time: Network::Regtest.genesis_block().header.time + 1,
            bits: 0x207f_ffff,
            nonce: 0,
        },
        txs: vec![coinbase],
    };
    block.header.merkle_root = merkle_root(&block.txs)
        .ok_or_else(|| std::io::Error::other("test block has no merkle root"))?;
    while !pow_met(block.header.bits, block.block_hash().0) {
        block.header.nonce = block
            .header
            .nonce
            .checked_add(1)
            .ok_or_else(|| std::io::Error::other("test nonce exhausted"))?;
    }
    Ok(block)
}

fn merkle_root(txs: &[Tx]) -> Option<Hash256> {
    let mut leaves: Vec<[u8; 32]> = txs.iter().map(|tx| *tx.txid().as_bytes()).collect();
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
            next.push(double_sha256(&pair));
        }
        leaves = next;
    }
    Some(Hash256::from_le_bytes(&leaves[0]))
}

fn double_sha256(bytes: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(bytes);
    Sha256::digest(first).into()
}

fn pow_met(bits: u32, hash: Hash256) -> bool {
    let exponent = u8::try_from(bits >> 24).unwrap_or(0);
    let mantissa = bits & 0x007f_ffff;
    if exponent <= 3 || exponent > 32 || mantissa > 0x00ff_ffff {
        return false;
    }
    let bytes = hash.as_byte_array();
    let low = usize::from(exponent - 3);
    let window =
        u32::from(bytes[low]) | u32::from(bytes[low + 1]) << 8 | u32::from(bytes[low + 2]) << 16;
    window <= mantissa && bytes[usize::from(exponent)..].iter().all(|&byte| byte == 0)
}
