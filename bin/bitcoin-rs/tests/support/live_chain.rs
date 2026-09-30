//! Segwit regtest chains and node probes for the live head-sync wire tests:
//! coinbase-only blocks a `LivePeer` serves, applied-tip RPC reads, and the
//! stderr health check.
//!
//! Included by `#[path]` from each test that uses it; every item is used by
//! every includer, so no `dead_code` allowance is needed.

use bitcoin::absolute::LockTime;
use bitcoin::block::Header as BlockHeader;
use bitcoin::hashes::{Hash as _, sha256d};
use bitcoin::{
    Amount, Block, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use bitcoin_rs_e2e::{Error, ProcessNode};
use serde_json::{Value, json};

/// Builds a BIP141 segwit coinbase-only block on `parent`: the coinbase
/// carries the 32-byte reserved nonce in its input witness and an `OP_RETURN`
/// commitment output (`aa21a9ed`), so the body binds to the header only when
/// witness data is intact — a stripped body fails the body/header binding
/// check. `tag` separates competing branches so coinbases (and therefore
/// txids/headers) differ across forks at equal heights.
fn segwit_coinbase_block(parent: &Block, height: u32, tag: u8) -> Block {
    let reserved = [tag; 32];
    // Coinbase-only tree: witness leaf 0 is zeroed out, so the wtxid merkle
    // root is exactly [0;32]; commitment = sha256d(root || reserved).
    let mut buffer = [0_u8; 64];
    buffer[32..].copy_from_slice(&reserved);
    let commitment = sha256d::Hash::hash(&buffer).to_byte_array();
    let mut commit_script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    commit_script.extend_from_slice(&commitment);
    let coinbase = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![
                0x01,
                u8::try_from(height).unwrap_or(0xff),
                0x01,
                tag,
            ]),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[&reserved[..]]),
        }],
        output: vec![
            TxOut {
                // 50 BTC regtest subsidy; spend path never exercised.
                value: Amount::from_sat(5_000_000_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::from_bytes(commit_script),
            },
        ],
    };
    let mut block = Block {
        header: BlockHeader {
            version: parent.header.version,
            prev_blockhash: parent.block_hash(),
            merkle_root: parent.header.merkle_root, // placeholder, replaced below
            time: parent.header.time.saturating_add(1),
            bits: parent.header.bits,
            nonce: 0,
        },
        txdata: vec![coinbase],
    };
    block.header.merkle_root = block.compute_merkle_root().expect("coinbase merkle root");
    while !pow_met(block.header.bits, block.header.block_hash()) {
        block.header.nonce = block
            .header
            .nonce
            .checked_add(1)
            .expect("nonce space exhausted");
    }
    block
}

fn pow_met(bits: CompactTarget, hash: bitcoin::BlockHash) -> bool {
    bitcoin::Target::from_compact(bits).is_met_by(hash)
}

/// RPC helpers.
fn rpc(node: &mut ProcessNode, method: &str) -> Result<Value, Error> {
    node.rpc(method, &json!([]))
}

pub(crate) fn block_count(node: &mut ProcessNode) -> Result<u64, Error> {
    Ok(rpc(node, "getblockcount")?.as_u64().unwrap_or(u64::MAX))
}

pub(crate) fn best_hash(node: &mut ProcessNode) -> Result<String, Error> {
    Ok(rpc(node, "getbestblockhash")?
        .as_str()
        .unwrap_or("")
        .to_owned())
}

pub(crate) fn connection_count(node: &mut ProcessNode) -> Result<u64, Error> {
    Ok(rpc(node, "getconnectioncount")?
        .as_u64()
        .unwrap_or(u64::MAX))
}

/// Reads the node's stderr evidence so far.
fn node_stderr(node: &ProcessNode) -> String {
    std::fs::read_to_string(node.evidence.join("stderr.log")).unwrap_or_default()
}

fn count_occurrences(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

pub(crate) fn regtest_genesis() -> Block {
    bitcoin::constants::genesis_block(bitcoin::Network::Regtest)
}

/// Builds a chain of `count` segwit coinbase blocks extending `parent`.
pub(crate) fn build_chain(parent: &Block, count: u32, tag: u8, start_height: u32) -> Vec<Block> {
    let mut chain = Vec::with_capacity(usize::try_from(count).unwrap_or(64));
    let mut prev = parent.clone();
    for i in 0..count {
        let tag = tag.wrapping_add(u8::try_from(i).unwrap_or(0));
        let block = segwit_coinbase_block(&prev, start_height + i, tag);
        prev = block.clone();
        chain.push(block);
    }
    chain
}

/// Asserts the node's stderr shows no panic and no `PrevHashMismatch` —
/// `context` names where a mismatch would indicate commit churn.
pub(crate) fn assert_clean_stderr(node: &ProcessNode, context: &str) {
    let stderr = node_stderr(node);
    assert_eq!(
        count_occurrences(&stderr, "panic"),
        0,
        "node stderr contains a panic"
    );
    assert_eq!(
        count_occurrences(&stderr, "PrevHashMismatch"),
        0,
        "node stderr shows PrevHashMismatch: {context}"
    );
}
