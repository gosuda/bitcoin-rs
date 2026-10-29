use alloc::sync::Arc;

use bitcoin::hex::DisplayHex as _;
use bitcoin_rs_chain::{BlockHeader, NodeId, NodeStatus, TipSnapshot};
use bitcoin_rs_primitives::{
    Amount, BlockHash, CompactTarget, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn,
    TxOut, Txid, Witness, consensus_bytes,
};
use bitcoin_rs_utxo::contract::{BlockChanges, UtxoAdd};
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, json};

use super::{getrawtransaction, sendrawtransaction, testmempoolaccept};
use crate::context::Context;
use crate::error::RpcError;

fn fixture_outpoint(tag: u8) -> OutPoint {
    OutPoint::new(Txid(Hash256::from_le_bytes(&[tag; 32])), 0)
}

fn seed_utxo(ctx: &Context, tag: u8, value: u64) {
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(
        fixture_outpoint(tag),
        TxOut {
            value: Amount::from_sat(value),
            script_pubkey: Script::from_bytes(vec![0x51]),
        },
        false,
        7,
    ));
    bitcoin_rs_utxo::contract::commit_block_changes(
        &ctx.chain.utxo.fixture_set(),
        &changes,
        &Hash256::default(),
    )
    .unwrap_or_else(|err| panic!("commit_block failed: {err}"));
}

fn spending_tx(tag: u8, output_value: u64) -> Tx {
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: fixture_outpoint(tag),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(output_value),
            script_pubkey: {
                let mut out = Vec::with_capacity(25);
                out.push(0x76);
                out.push(0xa9);
                out.push(0x14);
                out.extend_from_slice(&[9_u8; 20]);
                out.push(0x88);
                out.push(0xac);
                Script::from_bytes(out)
            },
        }],
    }
}

fn hex_of(tx: &Tx) -> String {
    consensus_bytes(tx).to_lower_hex_string()
}

#[test]
fn sendrawtransaction_admits_the_transaction_to_the_mempool() {
    let ctx = Arc::new(Context::new());
    seed_utxo(&ctx, 1, 100_000);
    let tx = spending_tx(1, 90_000);

    let Ok(value) = sendrawtransaction(&ctx, &json!([hex_of(&tx)])) else {
        panic!("a standard transaction spending a confirmed output must be accepted");
    };

    assert_eq!(value.as_str(), Some(tx.txid().to_string().as_str()));
    assert_eq!(ctx.mempool.gateway.read().len(), 1, "the pool must hold it");
    assert!(ctx.mempool.gateway.read().contains_txid(&tx.txid()));
}

#[test]
fn sendrawtransaction_refuses_an_absurd_fee_by_default() {
    let ctx = Arc::new(Context::new());
    seed_utxo(&ctx, 8, 100_000_000);
    let tx = spending_tx(8, 1_000_000);

    let error = sendrawtransaction(&ctx, &json!([hex_of(&tx)]))
        .err()
        .unwrap_or_else(|| panic!("an absurd fee must not be sent by default"));

    assert_eq!(
        error.code(),
        RpcError::INVALID_PARAMS,
        "max-fee-exceeded is a parameter error: {error:?}"
    );
    assert_eq!(
        ctx.mempool.gateway.read().len(),
        0,
        "and nothing was admitted"
    );
}

#[test]
fn the_fee_ceiling_is_a_rate_and_zero_disables_it() {
    let disabled = {
        let ctx = Arc::new(Context::new());
        seed_utxo(&ctx, 9, 100_000_000);
        let tx = spending_tx(9, 1_000_000);
        let sent = sendrawtransaction(&ctx, &json!([hex_of(&tx), 0]));
        assert_eq!(
            ctx.mempool.gateway.read().len(),
            1,
            "zero sends it: {sent:?}"
        );
        sent
    };
    assert!(disabled.is_ok(), "{disabled:?}");

    let ctx = Arc::new(Context::new());
    seed_utxo(&ctx, 12, 100_000_000);
    let tx = spending_tx(12, 1_000_000);
    let error = sendrawtransaction(&ctx, &json!([hex_of(&tx), 0.99]))
        .err()
        .unwrap_or_else(|| panic!("0.99 BTC/kvB is a ceiling, not a fee allowance"));
    assert_eq!(error.code(), RpcError::INVALID_PARAMS, "{error:?}");
    assert_eq!(ctx.mempool.gateway.read().len(), 0);
}

#[test]
fn sendrawtransaction_admits_a_fee_below_the_ceiling() {
    let ctx = Arc::new(Context::new());
    seed_utxo(&ctx, 10, 100_000);
    let tx = spending_tx(10, 90_000);

    let sent = sendrawtransaction(&ctx, &json!([hex_of(&tx)]));

    assert!(sent.is_ok(), "an ordinary fee is not capped: {sent:?}");
    assert_eq!(ctx.mempool.gateway.read().len(), 1);
}

#[test]
fn sendrawtransaction_rejects_a_fee_rate_of_a_whole_coin() {
    let ctx = Arc::new(Context::new());
    seed_utxo(&ctx, 11, 100_000);
    let tx = spending_tx(11, 90_000);

    let error = sendrawtransaction(&ctx, &json!([hex_of(&tx), 1.0]))
        .err()
        .unwrap_or_else(|| panic!("1 BTC/kvB is not an accepted ceiling"));

    assert_eq!(error.code(), RpcError::INVALID_PARAMS, "{error:?}");
    assert_eq!(
        ctx.mempool.gateway.read().len(),
        0,
        "nothing admitted: {error:?}"
    );
}

#[test]
fn sendrawtransaction_rejects_a_transaction_whose_inputs_do_not_exist() {
    let ctx = Arc::new(Context::new());
    let tx = spending_tx(4, 90_000);

    let outcome = sendrawtransaction(&ctx, &json!([hex_of(&tx)]));

    let Err(error) = outcome else {
        panic!("a transaction with no resolvable inputs must not be accepted");
    };
    assert!(
        matches!(error, RpcError::TxVerifyError(_)),
        "expected a verify error, got {error:?}"
    );
    assert_eq!(error.code(), RpcError::CORE_VERIFY_ERROR);
    assert!(ctx.mempool.gateway.read().is_empty());
}

#[test]
fn sendrawtransaction_rejects_a_transaction_with_duplicate_inputs() {
    let ctx = Arc::new(Context::new());
    seed_utxo(&ctx, 1, 100_000);
    let prev = fixture_outpoint(1);
    let tx = Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![
            TxIn {
                previous_output: prev,
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            },
            TxIn {
                previous_output: prev,
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            },
        ],
        outputs: vec![TxOut {
            value: Amount::from_sat(90_000),
            script_pubkey: Script::from_bytes(vec![0x51]),
        }],
    };

    let outcome = sendrawtransaction(&ctx, &json!([hex_of(&tx)]));

    let Err(error) = outcome else {
        panic!("a transaction with duplicate inputs must not be accepted");
    };
    assert!(
        matches!(error, RpcError::TxRejected(_)),
        "expected a rejection, got {error:?}"
    );
    assert!(ctx.mempool.gateway.read().is_empty());
}

#[test]
fn sendrawtransaction_is_idempotent_for_a_transaction_already_in_the_pool() {
    let ctx = Arc::new(Context::new());
    seed_utxo(&ctx, 1, 100_000);
    let tx = spending_tx(1, 90_000);
    let params = json!([hex_of(&tx)]);
    let Ok(first) = sendrawtransaction(&ctx, &params) else {
        panic!("the first submission must succeed");
    };

    let Ok(second) = sendrawtransaction(&ctx, &params) else {
        panic!("resubmitting a transaction already in the mempool must not fail");
    };

    assert_eq!(first.as_str(), second.as_str());
    assert_eq!(
        ctx.mempool.gateway.read().len(),
        1,
        "it must not be inserted twice"
    );
}

#[test]
fn sendrawtransaction_does_not_treat_an_evicted_tx_as_already_known() {
    let ctx = Arc::new(Context::new());
    seed_utxo(&ctx, 1, 100_000);

    let mut original = spending_tx(1, 90_000);
    original.inputs[0].sequence = Sequence::from_consensus(0xFFFF_FFFD);
    let original_hex = hex_of(&original);
    let original_txid = original.txid();
    let params = json!([original_hex]);

    let Ok(_) = sendrawtransaction(&ctx, &params) else {
        panic!("the RBF-signaling original must be accepted");
    };
    assert!(
        ctx.mempool.gateway.read().contains_txid(&original_txid),
        "the original must enter the pool"
    );

    let replacement = spending_tx(1, 80_000);
    let Ok(_) = sendrawtransaction(&ctx, &json!([hex_of(&replacement)])) else {
        panic!("the higher-fee replacement must be accepted");
    };
    assert!(
        !ctx.mempool.gateway.read().contains_txid(&original_txid),
        "the original must be swept by the replacement"
    );
    assert!(
        ctx.mempool
            .gateway
            .read()
            .contains_txid(&replacement.txid()),
        "the replacement must occupy the pool"
    );

    let resent = sendrawtransaction(&ctx, &params);
    assert!(
        resent.is_err(),
        "resubmitting the evicted original must re-evaluate, not succeed as already-known: {resent:?}"
    );
    assert!(
        !ctx.mempool.gateway.read().contains_txid(&original_txid),
        "the evicted original must still be absent after the failed retry"
    );

    let lookup = getrawtransaction(&ctx, &json!([original_txid.to_string()]));
    assert!(
        matches!(lookup, Err(RpcError::NotFound(_))),
        "getrawtransaction must not serve an evicted body from the lookup cache: {lookup:?}"
    );
}

#[test]
fn testmempoolaccept_rejects_a_transaction_that_only_decodes() {
    let ctx = Arc::new(Context::new());
    let tx = spending_tx(4, 90_000);

    let Ok(value) = testmempoolaccept(&ctx, &json!([[hex_of(&tx)]])) else {
        panic!("testmempoolaccept must answer");
    };

    let Some(rows) = value.as_array() else {
        panic!("testmempoolaccept must return an array");
    };
    let Some(row) = rows.first() else {
        panic!("one transaction in, one row out");
    };
    assert_eq!(row.get("allowed").as_bool(), Some(false));
    assert!(
        row.get("reject-reason")
            .as_str()
            .is_some_and(|r| !r.is_empty()),
        "a rejection must carry a reason"
    );
}

#[test]
fn testmempoolaccept_allows_a_transaction_without_admitting_it() {
    let ctx = Arc::new(Context::new());
    seed_utxo(&ctx, 1, 100_000);
    let tx = spending_tx(1, 90_000);

    let Ok(value) = testmempoolaccept(&ctx, &json!([[hex_of(&tx)]])) else {
        panic!("testmempoolaccept must answer");
    };

    let Some(row) = value.as_array().and_then(|rows| rows.first()) else {
        panic!("one transaction in, one row out");
    };
    assert_eq!(row.get("allowed").as_bool(), Some(true));
    assert_eq!(
        row.get("vsize").as_u64(),
        Some(tx.vsize()),
        "vsize must be the transaction's, not a placeholder"
    );
    assert!(
        ctx.mempool.gateway.read().is_empty(),
        "testing acceptance must not accept"
    );
}

#[test]
fn testmempoolaccept_reports_the_witness_txid() {
    let ctx = Arc::new(Context::new());
    let mut tx = spending_tx(4, 90_000);
    tx.inputs[0].witness.push(vec![1_u8; 8]);
    assert_ne!(
        tx.txid().to_string(),
        tx.wtxid().to_string(),
        "the fixture must carry a witness or this proves nothing"
    );

    let Ok(value) = testmempoolaccept(&ctx, &json!([[hex_of(&tx)]])) else {
        panic!("testmempoolaccept must answer");
    };

    let Some(row) = value.as_array().and_then(|rows| rows.first()) else {
        panic!("one transaction in, one row out");
    };
    assert_eq!(
        row.get("txid").as_str(),
        Some(tx.txid().to_string().as_str())
    );
    assert_eq!(
        row.get("wtxid").as_str(),
        Some(tx.wtxid().to_string().as_str())
    );
}

#[test]
fn standardness_is_enforced_on_mainnet() {
    let mainnet = Arc::new(Context::new());
    assert_eq!(
        mainnet.chain.chain_network,
        bitcoin_rs_primitives::Network::Mainnet,
        "the fixture assumes the default context is mainnet"
    );
    seed_utxo(&mainnet, 1, 100_000);
    let mut tx = spending_tx(1, 90_000);
    tx.version = 4;
    assert!(
        sendrawtransaction(&mainnet, &json!([hex_of(&tx)])).is_err(),
        "mainnet must enforce standardness"
    );
}
fn build_divergent_tips(ctx: &Context) -> (u32, u32) {
    const BASE: u32 = 500_000_000;
    const STEP: u32 = 600;

    let mut ids = Vec::new();
    {
        let mut tree = ctx.chain.block_tree.write();
        let mut prev_id: Option<NodeId> = None;
        for height in 0..=11_u32 {
            let prev_hash = match prev_id {
                Some(id) => tree.node(id).expect("parent node exists").hash,
                None => Hash256::default(),
            };
            let header = BlockHeader {
                version: 1,
                prev_blockhash: BlockHash::from(prev_hash),
                merkle_root: Hash256::default(),
                time: BASE + STEP * height,
                bits: CompactTarget::from_consensus(
                    bitcoin_rs_chain::regtest_fixture::REGTEST_BITS,
                ),
                nonce: 0,
            };
            let id = tree
                .insert_node(prev_id, header, NodeStatus::HeaderValid)
                .unwrap_or_else(|err| panic!("insert header {height}: {err}"));
            ids.push(id);
            prev_id = Some(id);
        }
    }

    let (applied_hash, best_hash) = {
        let tree = ctx.chain.block_tree.read();
        let applied_id = ids[10];
        let best_id = ids[11];
        let applied_node = tree.node(applied_id).expect("applied node exists");
        let best_node = tree.node(best_id).expect("best node exists");
        ctx.chain.applied_tip.store(Some(Arc::new(TipSnapshot {
            tip_id: applied_id,
            height: applied_node.height,
            chainwork: applied_node.chainwork,
            hash: applied_node.hash,
            chain_tx_count: applied_node.chain_tx_count,
        })));
        ctx.chain.chain_tip.store(Some(Arc::new(TipSnapshot {
            tip_id: best_id,
            height: best_node.height,
            chainwork: best_node.chainwork,
            hash: best_node.hash,
            chain_tx_count: best_node.chain_tx_count,
        })));
        (applied_node.hash, best_node.hash)
    };

    (
        ctx.chain
            .median_time_past_for_hash(applied_hash)
            .expect("applied MTP exists"),
        ctx.chain
            .median_time_past_for_hash(best_hash)
            .expect("best MTP exists"),
    )
}

#[test]
fn sendrawtransaction_rejects_tx_final_only_under_header_tip_mtp() {
    const BASE: u32 = 500_000_000;
    let ctx = Arc::new(Context::new());
    let (applied_mtp, best_mtp) = build_divergent_tips(&ctx);

    assert!(
        applied_mtp < best_mtp,
        "fixture: header-tip MTP must exceed applied-tip MTP"
    );

    let lock_time = BASE + 3_300;
    assert!(
        applied_mtp < lock_time && lock_time < best_mtp,
        "fixture: lock time must sit between the two MTPs"
    );

    seed_utxo(&ctx, 1, 100_000);
    let mut tx = spending_tx(1, 90_000);
    tx.lock_time = LockTime::from_consensus(lock_time);
    tx.inputs[0].sequence = Sequence::from_consensus(0xFFFF_FFFE);

    let result = sendrawtransaction(&ctx, &json!([hex_of(&tx)]));
    assert!(
        result.is_err(),
        "a tx final only under the header-tip MTP must be rejected; got {result:?}"
    );
    assert_eq!(
        ctx.mempool.gateway.read().len(),
        0,
        "rejected tx must not enter the pool"
    );
}
