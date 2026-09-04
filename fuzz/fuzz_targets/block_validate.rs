#![no_main]

use bitcoin::consensus::encode::{deserialize, serialize};
use libfuzzer_sys::fuzz_target;

use bitcoin_rs_consensus::rust_path::UtxoView;
use bitcoin_rs_consensus::{verify_block_rules, verify_transaction_non_script};
use bitcoin_rs_primitives::{Block, OutPoint, TxOut};

/// UTXO view with no coins. Non-coinbase inputs fail `MissingPrevout`;
/// `verify_block_rules` does not consult it.
struct EmptyView;

impl UtxoView for EmptyView {
    fn lookup(&self, _outpoint: &OutPoint) -> Option<TxOut> {
        None
    }
}

/// rust-bitcoin parses; bitcoin-rs runs `verify_block_rules`.
fn validate_block(data: &[u8]) {
    let Ok(parsed) = deserialize::<bitcoin::Block>(data) else {
        return;
    };
    let encoded = serialize(&parsed);
    let Ok(block) = Block::consensus_decode(&encoded) else {
        return;
    };
    let _ = verify_block_rules(&block);
    for tx in &block.txs {
        let _ = verify_transaction_non_script(tx, &EmptyView, 1, 0);
    }
}

fuzz_target!(|data: &[u8]| {
    validate_block(data);
});
