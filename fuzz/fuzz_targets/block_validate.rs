#![no_main]

use bitcoin::consensus::encode::{deserialize, serialize};
use libfuzzer_sys::fuzz_target;

use bitcoin_rs_consensus::rust_path::UtxoView;
use bitcoin_rs_consensus::{verify_block_rules, verify_transaction_non_script};
use bitcoin_rs_primitives::{Block, OutPoint, TxOut};

/// Dummy coins for every requested outpoint so non-coinbase transactions
/// run past `MissingPrevout` into value and sigop checks. Coinbase
/// detection does not consult the view.
struct AnyCoinView {
    coin: TxOut,
}

impl UtxoView for AnyCoinView {
    fn lookup(&self, _outpoint: &OutPoint) -> Option<TxOut> {
        Some(self.coin.clone())
    }
}

/// rust-bitcoin parses; bitcoin-rs runs `verify_block_rules` and per-tx
/// non-script checks.
fn validate_block(data: &[u8]) {
    let Ok(parsed) = deserialize::<bitcoin::Block>(data) else {
        return;
    };
    let encoded = serialize(&parsed);
    let Ok(block) = Block::consensus_decode(&encoded) else {
        return;
    };
    let _ = verify_block_rules(&block);
    let view = AnyCoinView {
        coin: TxOut {
            value: 50_000_000,
            script_pubkey: vec![0x51],
        },
    };
    for tx in &block.txs {
        let _ = verify_transaction_non_script(tx, &view, 1, 0);
    }
}

fuzz_target!(|data: &[u8]| {
    validate_block(data);
});
