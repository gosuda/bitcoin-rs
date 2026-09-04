//! Canonical Bitcoin Core block and header JSON projections.
//!
//! Callers supply applied-chain facts. This module never queries node state and
//! does not choose JSON-RPC versus REST transport policy.

use bitcoin_rs_primitives::{Block, Header, Network, consensus_bytes};
use sonic_rs::{Value, json};

use crate::tx_render::transaction_json;

/// Applied-chain facts required to project a header or block.
#[derive(Clone, Debug, PartialEq)]
pub struct BlockChainContext {
    /// Height of this block on the applied chain when active; still reported
    /// for known headers that are not active.
    pub height: u32,
    /// Bitcoin Core confirmations: applied-tip depth, or `-1` when inactive.
    pub confirmations: i64,
    /// Median time past for this block.
    pub mediantime: u32,
    /// Difficulty derived from `nBits` using Core's calculation.
    pub difficulty: f64,
    /// Lowercase hex chainwork through this block.
    pub chainwork_hex: String,
    /// Transaction count reported by Core for header and block responses.
    pub n_tx: u32,
    /// Hash of the next applied-chain block, when one exists.
    pub next_block_hash: Option<bitcoin_rs_primitives::BlockHash>,
}

/// Transaction array shape for `getblock` verbosity levels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockTxVerbosity {
    /// Verbosity 1: array of txid strings.
    Ids,
    /// Verbosity 2+: array of full transaction objects.
    Full,
}

/// Render a block header using Bitcoin Core's verbose header shape.
#[must_use]
pub fn header_json(header: &Header, chain: &BlockChainContext) -> Value {
    header_common_json(header, chain)
}

/// Render a block using Bitcoin Core's verbose block shape.
#[must_use]
pub fn block_json(
    block: &Block,
    chain: &BlockChainContext,
    tx_verbosity: BlockTxVerbosity,
    network: Network,
) -> Value {
    let header = &block.header;
    let mut value = header_common_json(header, chain);
    let size = block.total_size();
    let weight = block.weight();
    let stripped_size = block.stripped_size();

    let _ = value.insert("strippedsize", json!(stripped_size));
    let _ = value.insert("size", json!(size));
    let _ = value.insert("weight", json!(weight));
    let tx_array = match tx_verbosity {
        BlockTxVerbosity::Ids => block
            .txs
            .iter()
            .map(|tx| json!(tx.txid().to_string()))
            .collect::<Vec<_>>(),
        BlockTxVerbosity::Full => block
            .txs
            .iter()
            .map(|tx| transaction_json(tx, network, None))
            .collect::<Vec<_>>(),
    };
    let _ = value.insert("tx", json!(tx_array));
    value
}

/// Hex-encode a header using consensus serialization.
#[must_use]
pub fn header_hex(header: &Header) -> String {
    hex_encode(&consensus_bytes(header))
}

/// Hex-encode a block using consensus serialization.
#[must_use]
pub fn block_hex(block: &Block) -> String {
    hex_encode(&consensus_bytes(block))
}

/// Compute Bitcoin Core confirmations from applied-chain membership facts.
///
/// `on_active_chain` must already encode applied-chain membership for
/// `block_height`. Height alone is insufficient after a reorg.
#[must_use]
pub fn confirmations(applied_height: u32, block_height: u32, on_active_chain: bool) -> i64 {
    if !on_active_chain || block_height > applied_height {
        return -1;
    }
    i64::from(applied_height)
        .saturating_sub(i64::from(block_height))
        .saturating_add(1)
}

fn header_common_json(header: &Header, chain: &BlockChainContext) -> Value {
    let version = header.version;
    let bits = header.bits;
    let mut value = json!({
        "hash": header.compute_hash().to_string(),
        "confirmations": chain.confirmations,
        "height": chain.height,
        "version": i64::from(version),
        "versionHex": format!("{version:08x}"),
        "merkleroot": header.merkle_root.to_string_be(),
        "time": header.time,
        "mediantime": chain.mediantime,
        "nonce": header.nonce,
        "bits": format!("{bits:08x}"),
        "difficulty": chain.difficulty,
        "chainwork": chain.chainwork_hex,
        "nTx": chain.n_tx,
        "previousblockhash": header.prev_blockhash.to_string()
    });
    if let Some(next) = chain.next_block_hash {
        let _ = value.insert("nextblockhash", json!(next.to_string()));
    }
    value
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}
