#![no_main]

use bitcoin::consensus::encode::{deserialize, serialize};
use libfuzzer_sys::fuzz_target;

use bitcoin_rs_consensus::rust_path::UtxoView;
use bitcoin_rs_consensus::{verify_block_rules, verify_transaction_non_script};
use bitcoin_rs_primitives::{Block, OutPoint, TxOut};

/// Deterministic synthetic coins let non-script checks reach value and sigop validation.
struct SyntheticView;

impl UtxoView for SyntheticView {
    fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
        (!outpoint.is_null()).then_some(TxOut {
            value: 50_000_000,
            script_pubkey: vec![0x51],
        })
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
    let view = SyntheticView;
    for tx in &block.txs {
        let _ = verify_transaction_non_script(tx, &view, 1, 0);
    }
}

fuzz_target!(|data: &[u8]| {
    validate_block(data);
});
