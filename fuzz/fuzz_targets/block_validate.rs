#![no_main]

use bitcoin::consensus::encode::{deserialize, serialize};
use libfuzzer_sys::fuzz_target;

use bitcoin_rs_consensus::UtxoView;
use bitcoin_rs_consensus::{verify_block_rules, verify_transaction_non_script};
use bitcoin_rs_consensus::primitives::{Amount, Block, OutPoint, Script, TxOut};
use bitcoin_rs_consensus::script::VerifyFlags;

struct AnyCoinView {
    coin: TxOut,
}

impl UtxoView for AnyCoinView {
    fn lookup(&self, _outpoint: &OutPoint) -> Option<TxOut> {
        Some(self.coin.clone())
    }
}

fn validate_block(data: &[u8]) {
    let Ok(parsed) = deserialize::<bitcoin::Block>(data) else {
        return;
    };
    let encoded = serialize(&parsed);
    let Ok(block) = bitcoin_rs_consensus::primitives::deserialize::<Block>(&encoded) else {
        return;
    };
    let consensus = bitcoin_rs_consensus::primitives::consensus_bytes(&block);
    assert_eq!(
        consensus,
        encoded,
        "native decode must re-encode to the rust-bitcoin serialization"
    );
    let re_decoded = bitcoin_rs_consensus::primitives::deserialize::<Block>(&consensus)
        .expect("native re-decode must succeed on consensus_bytes");
    assert_eq!(re_decoded, block, "round-trip block equality");
    let re_consensus = bitcoin_rs_consensus::primitives::consensus_bytes(&re_decoded);
    assert_eq!(re_consensus, consensus, "canonical block bytes idempotent");

    assert!(
        encoded.len() + block.retained_heap_bytes()
            <= bitcoin_rs_consensus::primitives::layout::decode_reservation(encoded.len()),
        "decoded block exceeds its decode reservation"
    );

    let r1 = verify_block_rules(&block);
    let r2 = verify_block_rules(&block);
    assert_eq!(
        format!("{r1:?}"),
        format!("{r2:?}"),
        "verify_block_rules determinism"
    );

    let view = AnyCoinView {
        coin: TxOut {
            value: Amount::from_sat(50_000_000),
            script_pubkey: Script::from(vec![0x51]),
        },
    };
    for tx in &block.txs {
        let t1 = verify_transaction_non_script(tx, &view, 1, 0, VerifyFlags::MANDATORY);
        let t2 = verify_transaction_non_script(tx, &view, 1, 0, VerifyFlags::MANDATORY);
        assert_eq!(
            format!("{t1:?}"),
            format!("{t2:?}"),
            "verify_transaction_non_script determinism"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    validate_block(data);
});
