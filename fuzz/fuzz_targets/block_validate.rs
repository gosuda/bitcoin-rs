#![no_main]

use bitcoin::consensus::encode::{deserialize, serialize};
use libfuzzer_sys::fuzz_target;

use bitcoin_rs_consensus::rust_path::UtxoView;
use bitcoin_rs_consensus::{verify_block_rules, verify_transaction_non_script};
use bitcoin_rs_primitives::{Amount, Block, OutPoint, Script, TxOut};
use bitcoin_rs_script::VerifyFlags;

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
            value: Amount::from_sat(50_000_000),
            script_pubkey: Script::from(vec![0x51]),
        },
    };
    // No softfork is active at height 1; the mandatory-only flag set keeps
    // sigop accounting active without any fork-dependent rules.
    for tx in &block.txs {
        let _ = verify_transaction_non_script(tx, &view, 1, 0, VerifyFlags::MANDATORY);
    }
}

fuzz_target!(|data: &[u8]| {
    validate_block(data);
});
