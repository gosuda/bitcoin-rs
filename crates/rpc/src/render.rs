use bitcoin::hex::DisplayHex as _;
use bitcoin_rs_primitives::{Block, Header, Network, consensus_bytes};
use sonic_rs::{Value, json};

use crate::tx_render::transaction_json;

#[derive(Debug)]
pub(crate) struct BlockChainContext {
    pub height: u32,
    pub confirmations: i64,
    pub mediantime: u32,
    pub difficulty: f64,
    pub chainwork_hex: String,
    pub n_tx: u32,
    pub next_block_hash: Option<bitcoin_rs_primitives::BlockHash>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BlockTxVerbosity {
    Ids,
    Full,
}

#[must_use]
pub(crate) fn block_json(
    block: &Block,
    chain: &BlockChainContext,
    tx_verbosity: BlockTxVerbosity,
    network: Network,
) -> Value {
    let header = &block.header;
    let mut value = header_json(header, chain);
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

#[must_use]
pub(crate) fn header_hex(header: &Header) -> String {
    consensus_bytes(header).to_lower_hex_string()
}

#[must_use]
pub(crate) fn confirmations(applied_height: u32, block_height: u32, on_active_chain: bool) -> i64 {
    if !on_active_chain || block_height > applied_height {
        return -1;
    }
    i64::from(applied_height)
        .saturating_sub(i64::from(block_height))
        .saturating_add(1)
}

#[must_use]
pub(crate) fn header_json(header: &Header, chain: &BlockChainContext) -> Value {
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
