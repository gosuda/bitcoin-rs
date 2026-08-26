#![allow(clippy::expect_used, clippy::unwrap_used)]
//! Focused Core transaction RPC contracts for R2.

use std::sync::Arc;

use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::Hash as _;
use bitcoin::hex::DisplayHex as _;
use bitcoin::{
    Amount, OutPoint as BitcoinOutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    WPubkeyHash, Witness, absolute, transaction,
};
use bitcoin_rs_chain::{ChainWork, NodeStatus, TipSnapshot};
use bitcoin_rs_mempool::MempoolEntry;
use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut as PrimitiveTxOut};
use bitcoin_rs_rpc::context::{
    BlockBodySource, BlockRecord, BlockUndoSource, Context, TxIndexQuery, TxQueryError,
};
use bitcoin_rs_rpc::{Handler, RpcError};
use bitcoin_rs_utxo::{BlockChanges, UndoBatch, UtxoAdd};
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, json};

fn empty_tx() -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: Vec::new(),
        output: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

fn spend_tx(prev_txid: Txid, vout: u32, value: u64) -> Transaction {
    spend_tx_with(
        prev_txid,
        vout,
        value,
        Sequence::MAX,
        ScriptBuf::from_bytes(vec![0x51]),
    )
}

fn standard_output_script() -> ScriptBuf {
    ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([0x42; 20]))
}

fn spend_tx_with(
    prev_txid: Txid,
    vout: u32,
    value: u64,
    sequence: Sequence,
    script_pubkey: ScriptBuf,
) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: BitcoinOutPoint {
                txid: prev_txid,
                vout,
            },
            script_sig: ScriptBuf::new(),
            sequence,
            witness: Witness::default(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey,
        }],
    }
}

fn commit_utxo(ctx: &Context, txid: Txid, vout: u32, value: u64, height: u32) {
    commit_utxo_script(
        ctx,
        txid,
        vout,
        value,
        height,
        ScriptBuf::from_bytes(vec![0x51]),
    );
}

fn commit_utxo_script(
    ctx: &Context,
    txid: Txid,
    vout: u32,
    value: u64,
    height: u32,
    script_pubkey: ScriptBuf,
) {
    let outpoint = OutPoint::new(Hash256::from_le_bytes(txid.as_byte_array()), vout);
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(
        outpoint,
        PrimitiveTxOut {
            value: Amount::from_sat(value),
            script_pubkey,
        },
        false,
        height,
    ));
    ctx.utxo
        .commit_block(&changes, &Hash256::from_le_bytes(&[9_u8; 32]))
        .unwrap_or_else(|err| panic!("commit utxo: {err}"));
}

#[test]
fn getrawtransaction_prefers_mempool_over_cache() {
    let ctx = Arc::new(Context::new());
    let handler = Handler::new(Arc::clone(&ctx));
    let tx = empty_tx();
    let txid = tx.compute_txid();
    ctx.add_transaction(tx.clone());
    let vsize = u32::try_from(tx.vsize()).expect("vsize");
    ctx.mempool
        .write()
        .insert_entry(MempoolEntry::new(Arc::new(tx.clone()), vsize, 1_000, 1, 1))
        .expect("insert mempool");

    let hex = handler
        .dispatch("getrawtransaction", &json!([txid.to_string()]))
        .expect("getrawtransaction");
    assert_eq!(
        hex.as_str(),
        Some(serialize(&tx).to_lower_hex_string().as_str())
    );
}

#[test]
fn getrawtransaction_rejects_malformed_txid_and_hex() {
    let handler = Handler::new(Arc::new(Context::new()));
    let bad_txid = handler.dispatch("getrawtransaction", &json!(["zz"]));
    assert!(matches!(
        bad_txid,
        Err(RpcError::InvalidParams("txid must be 64 hex characters"))
    ));

    let missing = handler.dispatch("getrawtransaction", &json!(["aa".repeat(32)]));
    assert!(matches!(
        missing,
        Err(RpcError::NotFound("transaction not found"))
    ));

    let bad_decode = handler.dispatch("decoderawtransaction", &json!(["deadbeef"]));
    assert!(matches!(
        bad_decode,
        Err(RpcError::InvalidParams("transaction decode failed"))
    ));
}

#[test]
fn gettxout_spent_unspent_and_mempool_views() {
    let ctx = Arc::new(Context::new());
    let handler = Handler::new(Arc::clone(&ctx));
    let funding = empty_tx();
    let funding_txid = funding.compute_txid();
    commit_utxo(&ctx, funding_txid, 0, 50_000, 9);

    let unspent = handler
        .dispatch("gettxout", &json!([funding_txid.to_string(), 0_u64, true]))
        .expect("unspent gettxout");
    assert_eq!(
        unspent
            .get("confirmations")
            .and_then(sonic_rs::JsonValueTrait::as_u64),
        Some(1)
    );
    assert_eq!(
        unspent
            .get("coinbase")
            .and_then(sonic_rs::JsonValueTrait::as_bool),
        Some(false)
    );

    let spender = spend_tx(funding_txid, 0, 40_000);
    let spender_txid = spender.compute_txid();
    let vsize = u32::try_from(spender.vsize()).expect("vsize");
    ctx.mempool
        .write()
        .insert_entry(MempoolEntry::new(Arc::new(spender), vsize, 10_000, 1, 10))
        .expect("insert spender");

    let spent_with_mempool = handler
        .dispatch("gettxout", &json!([funding_txid.to_string(), 0_u64, true]))
        .expect("spent-with-mempool");
    assert!(spent_with_mempool.is_null());

    let spent_without_mempool = handler
        .dispatch("gettxout", &json!([funding_txid.to_string(), 0_u64, false]))
        .expect("spent-without-mempool");
    assert!(
        spent_without_mempool.get("confirmations").is_some(),
        "chain UTXO remains visible when include_mempool=false"
    );

    let mempool_created = handler
        .dispatch("gettxout", &json!([spender_txid.to_string(), 0_u64, true]))
        .expect("mempool-created");
    assert_eq!(
        mempool_created
            .get("confirmations")
            .and_then(sonic_rs::JsonValueTrait::as_u64),
        Some(0)
    );
}

#[test]
fn testmempoolaccept_reports_package_reject_categories() {
    let ctx = Arc::new(Context::new());
    let handler = Handler::new(Arc::clone(&ctx));
    let orphan = spend_tx(Txid::from_byte_array([7_u8; 32]), 0, 1_000);
    let raw = serialize(&orphan).to_lower_hex_string();

    let result = handler
        .dispatch("testmempoolaccept", &json!([[raw.as_str()]]))
        .expect("testmempoolaccept");
    let row = result
        .as_array()
        .and_then(|rows| rows.first())
        .expect("one row");
    assert_eq!(
        row.get("allowed")
            .and_then(sonic_rs::JsonValueTrait::as_bool),
        Some(false)
    );
    assert_eq!(
        row.get("reject-reason").and_then(|v| v.as_str()),
        Some("missing-inputs")
    );

    let already = empty_tx();
    let already_txid = already.compute_txid();
    let vsize = u32::try_from(already.vsize()).expect("vsize");
    ctx.mempool
        .write()
        .insert_entry(MempoolEntry::new(Arc::new(already), vsize, 1_000, 1, 1))
        .expect("insert");
    // Give it a prevout so missing-inputs does not mask already-in-mempool.
    commit_utxo(&ctx, Txid::from_byte_array([3_u8; 32]), 0, 60_000, 1);
    let funded = spend_tx(Txid::from_byte_array([3_u8; 32]), 0, 50_000);
    // Insert the exact funded tx, then re-test it.
    let funded_txid = funded.compute_txid();
    let funded_vsize = u32::try_from(funded.vsize()).expect("vsize");
    ctx.mempool
        .write()
        .insert_entry(MempoolEntry::new(
            Arc::new(funded.clone()),
            funded_vsize,
            10_000,
            1,
            1,
        ))
        .expect("insert funded");
    let raw_funded = serialize(&funded).to_lower_hex_string();
    let dup = handler
        .dispatch("testmempoolaccept", &json!([[raw_funded.as_str()]]))
        .expect("duplicate accept");
    let dup_row = dup.as_array().and_then(|rows| rows.first()).expect("row");
    assert_eq!(
        dup_row.get("reject-reason").and_then(|v| v.as_str()),
        Some("txn-already-in-mempool")
    );
    assert_eq!(
        dup_row.get("txid").and_then(|v| v.as_str()),
        Some(funded_txid.to_string().as_str())
    );

    let oversized = handler.dispatch("testmempoolaccept", &json!([vec![raw.as_str(); 26]]));
    assert!(
        matches!(
            oversized,
            Err(RpcError::InvalidParameter(ref message))
                if message == "Array must contain between 1 and 25 transactions."
        ),
        "expected package-length InvalidParameter, got {oversized:?}"
    );

    let empty = handler.dispatch("testmempoolaccept", &json!([[]]));
    assert!(
        matches!(
            empty,
            Err(RpcError::InvalidParameter(ref message))
                if message == "Array must contain between 1 and 25 transactions."
        ),
        "expected empty-package InvalidParameter, got {empty:?}"
    );

    let _ = already_txid;
}

#[test]
fn sendrawtransaction_maps_core_reject_categories() {
    let ctx = Arc::new(Context::new());
    let handler = Handler::new(Arc::clone(&ctx));
    let orphan = spend_tx(Txid::from_byte_array([8_u8; 32]), 1, 500);
    let raw = serialize(&orphan).to_lower_hex_string();
    let rejected = handler.dispatch("sendrawtransaction", &json!([raw.as_str()]));
    assert!(
        matches!(rejected, Err(RpcError::Misc(ref message)) if message == "missing-inputs"),
        "expected missing-inputs Misc, got {rejected:?}"
    );
}

#[test]
fn sendrawtransaction_rejects_invalid_script_before_mempool_mutation() {
    let ctx = Arc::new(Context::new());
    let handler = Handler::new(Arc::clone(&ctx));
    let prev_txid = Txid::from_byte_array([0x11; 32]);
    // OP_0 leaves false on the stack, so consensus script verification fails.
    commit_utxo_script(
        &ctx,
        prev_txid,
        0,
        50_000,
        1,
        ScriptBuf::from_bytes(vec![0x00]),
    );
    let bad = spend_tx_with(
        prev_txid,
        0,
        40_000,
        Sequence::MAX,
        standard_output_script(),
    );
    let raw = serialize(&bad).to_lower_hex_string();
    let rejected = handler.dispatch("sendrawtransaction", &json!([raw.as_str()]));
    assert!(
        matches!(
            rejected,
            Err(RpcError::Misc(ref message)) if message.contains("script verification failed")
        ),
        "expected script verification Misc, got {rejected:?}"
    );
    assert!(
        !ctx.mempool.read().contains_txid(&bad.compute_txid()),
        "invalid script must not enter the mempool"
    );
}

#[test]
fn sendrawtransaction_opt_in_rbf_leaves_only_the_replacement() {
    let ctx = Arc::new(Context::new());
    let handler = Handler::new(Arc::clone(&ctx));
    let prev_txid = Txid::from_byte_array([0x22; 32]);
    // Anyone-can-spend prevout so canonical verification passes with an empty scriptSig.
    commit_utxo_script(
        &ctx,
        prev_txid,
        0,
        50_000,
        1,
        ScriptBuf::from_bytes(vec![0x51]),
    );

    let original = spend_tx_with(
        prev_txid,
        0,
        40_000,
        Sequence::ENABLE_RBF_NO_LOCKTIME,
        standard_output_script(),
    );
    let original_txid = original.compute_txid();
    let original_raw = serialize(&original).to_lower_hex_string();
    let accepted = handler
        .dispatch("sendrawtransaction", &json!([original_raw.as_str()]))
        .expect("original admission");
    assert_eq!(accepted.as_str(), Some(original_txid.to_string().as_str()));
    assert!(ctx.mempool.read().contains_txid(&original_txid));

    let replacement = spend_tx_with(
        prev_txid,
        0,
        30_000,
        Sequence::ENABLE_RBF_NO_LOCKTIME,
        ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([0x43; 20])),
    );
    let replacement_txid = replacement.compute_txid();
    let replacement_raw = serialize(&replacement).to_lower_hex_string();
    let replaced = handler
        .dispatch("sendrawtransaction", &json!([replacement_raw.as_str()]))
        .expect("replacement admission");
    assert_eq!(
        replaced.as_str(),
        Some(replacement_txid.to_string().as_str())
    );

    let pool = ctx.mempool.read();
    assert!(
        pool.contains_txid(&replacement_txid),
        "replacement must remain in the mempool"
    );
    assert!(
        !pool.contains_txid(&original_txid),
        "successful opt-in RBF must evict the original"
    );
    assert_eq!(pool.len(), 1, "mempool must contain only the replacement");
}

#[test]
fn sendrawtransaction_rejected_replacement_leaves_mempool_unchanged() {
    let ctx = Arc::new(Context::new());
    let handler = Handler::new(Arc::clone(&ctx));
    let prev_txid = Txid::from_byte_array([0x23; 32]);
    commit_utxo_script(
        &ctx,
        prev_txid,
        0,
        50_000,
        1,
        ScriptBuf::from_bytes(vec![0x51]),
    );

    let original = spend_tx_with(
        prev_txid,
        0,
        40_000,
        Sequence::ENABLE_RBF_NO_LOCKTIME,
        standard_output_script(),
    );
    let original_txid = original.compute_txid();
    let original_raw = serialize(&original).to_lower_hex_string();
    handler
        .dispatch("sendrawtransaction", &json!([original_raw.as_str()]))
        .expect("original admission");

    let before_stats = ctx.mempool.read().stats();
    let before_sequence = ctx.mempool.read().sequence_number();
    let before_entry = {
        let pool = ctx.mempool.read();
        let entry = pool
            .entry_by_txid(&original_txid)
            .expect("original present");
        (entry.fee, entry.vsize, entry.fee_delta)
    };

    // Higher absolute fee than the original is required by BIP125, but keep the
    // replacement below the pool min-relay floor raised after admission.
    ctx.mempool.write().limits.min_relay_fee_sat_per_kvb = 10_000_000;
    let replacement = spend_tx_with(
        prev_txid,
        0,
        30_000,
        Sequence::ENABLE_RBF_NO_LOCKTIME,
        ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([0x44; 20])),
    );
    let replacement_txid = replacement.compute_txid();
    let replacement_raw = serialize(&replacement).to_lower_hex_string();
    let rejected = handler.dispatch("sendrawtransaction", &json!([replacement_raw.as_str()]));
    assert!(
        matches!(rejected, Err(RpcError::Misc(_))),
        "expected Misc rejection for under-floor replacement, got {rejected:?}"
    );

    let pool = ctx.mempool.read();
    assert!(
        pool.contains_txid(&original_txid),
        "rejected replacement must leave the original"
    );
    assert!(
        !pool.contains_txid(&replacement_txid),
        "rejected replacement must not be admitted"
    );
    let entry = pool
        .entry_by_txid(&original_txid)
        .expect("original present");
    assert_eq!((entry.fee, entry.vsize, entry.fee_delta), before_entry);
    assert_eq!(pool.stats(), before_stats);
    assert_eq!(pool.sequence_number(), before_sequence);
}

#[test]
fn decoderawtransaction_preserves_caller_bytes() {
    let ctx = Arc::new(Context::new());
    let handler = Handler::new(Arc::clone(&ctx));
    let tx = empty_tx();
    let hex = serialize(&tx).to_lower_hex_string();

    let verbose = handler
        .dispatch("decoderawtransaction", &json!([hex.as_str()]))
        .expect("decoderawtransaction");
    assert_eq!(
        verbose.get("hex").and_then(|v| v.as_str()),
        Some(hex.as_str())
    );
    assert!(verbose.get("vin").and_then(|v| v.as_array()).is_some());
    assert!(verbose.get("vout").and_then(|v| v.as_array()).is_some());
}

#[test]
fn gettxoutproof_and_verifytxoutproof_round_trip() {
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let coinbase = genesis.txdata.first().expect("coinbase").clone();
    let txid = coinbase.compute_txid();
    let mut ctx = Context::new();
    let body = serialize(&genesis);
    let record = BlockRecord::from_block(0, &genesis);
    let hash = record.hash;
    ctx.block_body_source = Some(Arc::new(StaticBody {
        height: 0,
        hash,
        body,
    }));
    ctx.add_block(record);
    let ctx = Arc::new(ctx);
    let handler = Handler::new(Arc::clone(&ctx));

    let proof = handler
        .dispatch("gettxoutproof", &json!([[txid.to_string()]]))
        .expect("gettxoutproof");
    let proof_hex = proof.as_str().expect("proof hex").to_owned();
    let verified = handler
        .dispatch("verifytxoutproof", &json!([proof_hex.as_str()]))
        .expect("verifytxoutproof");
    let matched = verified.as_array().expect("txid array");
    assert_eq!(matched.len(), 1);
    assert_eq!(matched[0].as_str(), Some(txid.to_string().as_str()));
}

#[test]
fn sendrawtransaction_cache_only_is_evaluated_not_skipped() {
    let ctx = Arc::new(Context::new());
    let handler = Handler::new(Arc::clone(&ctx));
    let prev_txid = Txid::from_byte_array([0x71; 32]);
    commit_utxo_script(
        &ctx,
        prev_txid,
        0,
        50_000,
        1,
        ScriptBuf::from_bytes(vec![0x51]),
    );
    let tx = spend_tx_with(
        prev_txid,
        0,
        40_000,
        Sequence::MAX,
        standard_output_script(),
    );
    let txid = tx.compute_txid();
    ctx.add_transaction(tx.clone());
    assert!(
        !ctx.mempool.read().contains_txid(&txid),
        "fixture cache entry must not already be in the mempool"
    );
    let raw = serialize(&tx).to_lower_hex_string();
    let accepted = handler
        .dispatch("sendrawtransaction", &json!([raw.as_str()]))
        .expect("cache-only submit must be evaluated");
    assert_eq!(accepted.as_str(), Some(txid.to_string().as_str()));
    assert!(
        ctx.mempool.read().contains_txid(&txid),
        "a cache-only submit that passes admission must enter the mempool"
    );
}

#[test]
fn sendrawtransaction_true_duplicate_is_mempool_idempotent() {
    let ctx = Arc::new(Context::new());
    let handler = Handler::new(Arc::clone(&ctx));
    let prev_txid = Txid::from_byte_array([0x72; 32]);
    commit_utxo_script(
        &ctx,
        prev_txid,
        0,
        50_000,
        1,
        ScriptBuf::from_bytes(vec![0x51]),
    );
    let tx = spend_tx_with(
        prev_txid,
        0,
        40_000,
        Sequence::MAX,
        standard_output_script(),
    );
    let txid = tx.compute_txid();
    let raw = serialize(&tx).to_lower_hex_string();
    handler
        .dispatch("sendrawtransaction", &json!([raw.as_str()]))
        .expect("first admission");
    let before = ctx.mempool.read().len();
    let second = handler
        .dispatch("sendrawtransaction", &json!([raw.as_str()]))
        .expect("duplicate admission");
    assert_eq!(second.as_str(), Some(txid.to_string().as_str()));
    assert_eq!(ctx.mempool.read().len(), before);
}

#[test]
#[allow(clippy::too_many_lines)]
fn testmempoolaccept_package_uses_parent_scripts_and_unconfirmed_bip68() {
    let ctx = Arc::new(Context::new());
    let handler = Handler::new(Arc::clone(&ctx));
    let prev_txid = Txid::from_byte_array([0x73; 32]);
    commit_utxo_script(
        &ctx,
        prev_txid,
        0,
        50_000,
        1,
        ScriptBuf::from_bytes(vec![0x51]),
    );

    let parent = spend_tx_with(
        prev_txid,
        0,
        40_000,
        Sequence::MAX,
        standard_output_script(),
    );
    let overlay_child = spend_tx_with(
        parent.compute_txid(),
        0,
        30_000,
        Sequence::MAX,
        standard_output_script(),
    );
    let overlay = handler
        .dispatch(
            "testmempoolaccept",
            &json!([[
                serialize(&parent).to_lower_hex_string().as_str(),
                serialize(&overlay_child).to_lower_hex_string().as_str()
            ]]),
        )
        .expect("overlay package");
    let overlay_rows = overlay.as_array().expect("rows");
    assert_eq!(
        overlay_rows[0]
            .get("allowed")
            .and_then(sonic_rs::JsonValueTrait::as_bool),
        Some(true)
    );
    assert_eq!(
        overlay_rows[1]
            .get("allowed")
            .and_then(sonic_rs::JsonValueTrait::as_bool),
        Some(false)
    );
    assert_eq!(
        overlay_rows[1]
            .get("reject-reason")
            .and_then(|v| v.as_str()),
        Some("script-verify-flag-failed"),
        "package children must verify against the parent's real script: {overlay:?}"
    );

    let locked_child = spend_tx_with(
        parent.compute_txid(),
        0,
        30_000,
        Sequence::from_consensus(1),
        standard_output_script(),
    );
    let locked = handler
        .dispatch(
            "testmempoolaccept",
            &json!([[
                serialize(&parent).to_lower_hex_string().as_str(),
                serialize(&locked_child).to_lower_hex_string().as_str()
            ]]),
        )
        .expect("bip68 sequence 1 package");
    let locked_rows = locked.as_array().expect("rows");
    assert_eq!(
        locked_rows[0]
            .get("allowed")
            .and_then(sonic_rs::JsonValueTrait::as_bool),
        Some(true)
    );
    assert_eq!(
        locked_rows[1]
            .get("allowed")
            .and_then(sonic_rs::JsonValueTrait::as_bool),
        Some(false)
    );
    assert_eq!(
        locked_rows[1].get("reject-reason").and_then(|v| v.as_str()),
        Some("non-BIP68-final"),
        "package parents must be unconfirmed for relative locks: {locked:?}"
    );

    let unlocked_child = spend_tx_with(
        parent.compute_txid(),
        0,
        30_000,
        Sequence::from_consensus(0),
        standard_output_script(),
    );
    let unlocked = handler
        .dispatch(
            "testmempoolaccept",
            &json!([[
                serialize(&parent).to_lower_hex_string().as_str(),
                serialize(&unlocked_child).to_lower_hex_string().as_str()
            ]]),
        )
        .expect("bip68 sequence 0 package");
    let unlocked_rows = unlocked.as_array().expect("rows");
    assert_eq!(
        unlocked_rows[1]
            .get("reject-reason")
            .and_then(|v| v.as_str()),
        Some("script-verify-flag-failed"),
        "relative lock 0 against a package parent must reach script checks: {unlocked:?}"
    );
}

#[test]
fn testmempoolaccept_malformed_row_is_deserialization_error() {
    let handler = Handler::new(Arc::new(Context::new()));
    let rejected = handler.dispatch("testmempoolaccept", &json!([["deadbeef"]]));
    assert!(
        matches!(
            rejected,
            Err(RpcError::Deserialization(ref message)) if message == "TX decode failed"
        ),
        "expected -22 TX decode failed, got {rejected:?}"
    );
}

#[test]
fn testmempoolaccept_unvalidated_rows_omit_policy_fields() {
    let ctx = Arc::new(Context::new());
    let handler = Handler::new(Arc::clone(&ctx));
    let first = spend_tx(Txid::from_byte_array([0x74; 32]), 0, 1_000);
    let second = spend_tx(Txid::from_byte_array([0x75; 32]), 0, 1_000);
    let result = handler
        .dispatch(
            "testmempoolaccept",
            &json!([[
                serialize(&first).to_lower_hex_string().as_str(),
                serialize(&second).to_lower_hex_string().as_str()
            ]]),
        )
        .expect("package");
    let rows = result.as_array().expect("rows");
    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows[0]
            .get("allowed")
            .and_then(sonic_rs::JsonValueTrait::as_bool),
        Some(false)
    );
    assert_eq!(
        rows[0].get("reject-reason").and_then(|v| v.as_str()),
        Some("missing-inputs")
    );
    assert!(rows[0].get("vsize").is_some());
    assert_eq!(
        rows[1].get("txid").and_then(|v| v.as_str()),
        Some(second.compute_txid().to_string().as_str())
    );
    assert!(rows[1].get("wtxid").is_some());
    assert!(
        rows[1].get("allowed").is_none(),
        "unvalidated rows must omit allowed"
    );
    assert!(rows[1].get("vsize").is_none());
    assert!(rows[1].get("weight").is_none());
    assert!(rows[1].get("fees").is_none());
    assert!(rows[1].get("reject-reason").is_none());
}

struct StaticBody {
    height: u32,
    hash: Hash256,
    body: Vec<u8>,
}

impl bitcoin_rs_rpc::context::BlockBodySource for StaticBody {
    fn block_body(&self, height: u32, hash: Hash256) -> Option<Vec<u8>> {
        (self.height == height && self.hash == hash).then(|| self.body.clone())
    }
}

struct MapBody {
    bodies: Vec<(u32, Hash256, Vec<u8>)>,
}

impl BlockBodySource for MapBody {
    fn block_body(&self, height: u32, hash: Hash256) -> Option<Vec<u8>> {
        self.bodies
            .iter()
            .find(|(record_height, record_hash, _)| {
                *record_height == height && *record_hash == hash
            })
            .map(|(_, _, body)| body.clone())
    }
}

struct StaticUndo {
    height: u32,
    hash: Hash256,
    undo: Result<Option<UndoBatch>, TxQueryError>,
}

impl BlockUndoSource for StaticUndo {
    fn block_undo(&self, height: u32, hash: Hash256) -> Result<Option<UndoBatch>, TxQueryError> {
        if self.height == height && self.hash == hash {
            self.undo.clone()
        } else {
            Ok(None)
        }
    }
}

fn coinbase_tx() -> Transaction {
    bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest)
        .txdata
        .into_iter()
        .next()
        .expect("genesis coinbase")
}

fn block_with_txs(
    prev: bitcoin::BlockHash,
    time: u32,
    nonce: u32,
    txs: Vec<Transaction>,
) -> bitcoin::Block {
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let mut block = bitcoin::Block {
        header: genesis.header,
        txdata: txs,
    };
    block.header.prev_blockhash = prev;
    block.header.time = time;
    block.header.nonce = nonce;
    block.header.merkle_root = block.compute_merkle_root().expect("merkle root");
    block
}

fn publish_tip(ctx: &Context, tip_id: bitcoin_rs_chain::NodeId, height: u32, hash: Hash256) {
    let tip = TipSnapshot {
        tip_id,
        height,
        chainwork: ChainWork::ZERO,
        hash,
    };
    ctx.set_chain_tip(tip.clone());
    ctx.set_applied_tip(tip);
}

fn install_bodies(ctx: &mut Context, blocks: &[(u32, bitcoin::Block)]) {
    let bodies = blocks
        .iter()
        .map(|(height, block)| {
            let record = BlockRecord::from_block(*height, block);
            (record.height, record.hash, serialize(block))
        })
        .collect();
    ctx.block_body_source = Some(Arc::new(MapBody { bodies }));
}

fn insert_header(
    ctx: &Context,
    parent: Option<bitcoin_rs_chain::NodeId>,
    header: bitcoin::block::Header,
    status: NodeStatus,
) -> bitcoin_rs_chain::NodeId {
    ctx.block_tree
        .write()
        .insert_node(parent, header, status)
        .expect("insert header")
}

#[test]
fn getrawtransaction_explicit_stale_hash_v1_and_v2_report_inactive() {
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let stale = block_with_txs(genesis.block_hash(), 1_700_000_001, 1, vec![coinbase_tx()]);
    let active = block_with_txs(genesis.block_hash(), 1_700_000_002, 2, vec![coinbase_tx()]);
    let stale_tx = stale.txdata[0].clone();
    let mut ctx = Context::new();
    install_bodies(
        &mut ctx,
        &[
            (0, genesis.clone()),
            (1, stale.clone()),
            (1, active.clone()),
        ],
    );
    let genesis_id = insert_header(&ctx, None, genesis.header, NodeStatus::Active);
    let _stale_id = insert_header(&ctx, Some(genesis_id), stale.header, NodeStatus::Stale);
    let active_id = insert_header(&ctx, Some(genesis_id), active.header, NodeStatus::Active);
    ctx.add_block(BlockRecord::from_block(0, &genesis));
    ctx.add_block(BlockRecord::from_block(1, &stale));
    ctx.add_block(BlockRecord::from_block(1, &active));
    let stale_hash = Hash256::from_le_bytes(stale.block_hash().as_byte_array());
    publish_tip(
        &ctx,
        active_id,
        1,
        Hash256::from_le_bytes(active.block_hash().as_byte_array()),
    );
    let ctx = Arc::new(ctx);
    let handler = Handler::new(Arc::clone(&ctx));
    for verbosity in [1_u64, 2_u64] {
        let result = handler
            .dispatch(
                "getrawtransaction",
                &json!([
                    stale_tx.compute_txid().to_string(),
                    verbosity,
                    stale_hash.to_string_be()
                ]),
            )
            .unwrap_or_else(|err| panic!("stale v{verbosity}: {err}"));
        assert_eq!(
            result
                .get("in_active_chain")
                .and_then(sonic_rs::JsonValueTrait::as_bool),
            Some(false),
            "verbosity {verbosity}"
        );
        assert_eq!(
            result
                .get("confirmations")
                .and_then(sonic_rs::JsonValueTrait::as_i64),
            Some(0),
            "verbosity {verbosity}"
        );
        assert_eq!(
            result.get("blockhash").and_then(|v| v.as_str()),
            Some(stale.block_hash().to_string().as_str()),
            "verbosity {verbosity}"
        );
        assert_eq!(
            result
                .get("time")
                .and_then(sonic_rs::JsonValueTrait::as_u64),
            Some(u64::from(stale.header.time)),
            "verbosity {verbosity}"
        );
        assert_eq!(
            result
                .get("blocktime")
                .and_then(sonic_rs::JsonValueTrait::as_u64),
            Some(u64::from(stale.header.time)),
            "verbosity {verbosity}"
        );
    }
}

#[test]
fn getrawtransaction_explicit_active_hash_reports_true_and_depth() {
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let child = block_with_txs(genesis.block_hash(), 1_700_000_010, 7, vec![coinbase_tx()]);
    let tx = child.txdata[0].clone();
    let mut ctx = Context::new();
    install_bodies(&mut ctx, &[(0, genesis.clone()), (1, child.clone())]);
    let genesis_id = insert_header(&ctx, None, genesis.header, NodeStatus::Active);
    let child_id = insert_header(&ctx, Some(genesis_id), child.header, NodeStatus::Active);
    ctx.add_block(BlockRecord::from_block(0, &genesis));
    ctx.add_block(BlockRecord::from_block(1, &child));
    publish_tip(
        &ctx,
        child_id,
        1,
        Hash256::from_le_bytes(child.block_hash().as_byte_array()),
    );
    let hash = Hash256::from_le_bytes(child.block_hash().as_byte_array());
    let handler = Handler::new(Arc::new(ctx));
    let result = handler
        .dispatch(
            "getrawtransaction",
            &json!([tx.compute_txid().to_string(), 1_u64, hash.to_string_be()]),
        )
        .expect("active explicit");
    assert_eq!(
        result
            .get("in_active_chain")
            .and_then(sonic_rs::JsonValueTrait::as_bool),
        Some(true)
    );
    assert_eq!(
        result
            .get("confirmations")
            .and_then(sonic_rs::JsonValueTrait::as_i64),
        Some(1)
    );
}

#[test]
fn getrawtransaction_txindex_lookup_omits_in_active_chain() {
    struct Indexed {
        tx: Transaction,
        height: u32,
    }
    impl TxIndexQuery for Indexed {
        fn transaction(&self, txid: &Txid) -> Result<Option<Transaction>, TxQueryError> {
            Ok((self.tx.compute_txid() == *txid).then(|| self.tx.clone()))
        }
        fn outpoint_value(
            &self,
            _outpoint: &bitcoin::OutPoint,
        ) -> Result<Option<u64>, TxQueryError> {
            Ok(None)
        }
        fn transaction_height(&self, txid: &Txid) -> Result<Option<u32>, TxQueryError> {
            Ok((self.tx.compute_txid() == *txid).then_some(self.height))
        }
        fn index_info(&self) -> Result<bitcoin_rs_rpc::context::TxIndexInfo, TxQueryError> {
            Ok(bitcoin_rs_rpc::context::TxIndexInfo {
                synced: true,
                best_block_height: 1,
            })
        }
    }
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let tx = empty_tx();
    let block = block_with_txs(
        genesis.block_hash(),
        1_700_000_020,
        9,
        vec![coinbase_tx(), tx.clone()],
    );
    let mut ctx = Context::new();
    install_bodies(&mut ctx, &[(0, genesis.clone()), (1, block.clone())]);
    let genesis_id = insert_header(&ctx, None, genesis.header, NodeStatus::Active);
    let child_id = insert_header(&ctx, Some(genesis_id), block.header, NodeStatus::Active);
    ctx.add_block(BlockRecord::from_block(0, &genesis));
    ctx.add_block(BlockRecord::from_block(1, &block));
    publish_tip(
        &ctx,
        child_id,
        1,
        Hash256::from_le_bytes(block.block_hash().as_byte_array()),
    );
    ctx.tx_index = Some(Arc::new(Indexed {
        tx: tx.clone(),
        height: 1,
    }));
    let handler = Handler::new(Arc::new(ctx));
    let result = handler
        .dispatch(
            "getrawtransaction",
            &json!([tx.compute_txid().to_string(), 1_u64]),
        )
        .expect("txindex verbose");
    assert!(
        result.get("in_active_chain").is_none(),
        "txindex lookup must omit in_active_chain"
    );
    assert_eq!(
        result.get("blockhash").and_then(|v| v.as_str()),
        Some(block.block_hash().to_string().as_str())
    );
}

#[test]
fn getrawtransaction_verbosity_two_same_block_child_has_prevout_and_fee() {
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let parent = empty_tx();
    let child = spend_tx(parent.compute_txid(), 0, 40_000);
    let block = block_with_txs(
        genesis.block_hash(),
        1_700_000_030,
        11,
        vec![coinbase_tx(), parent, child.clone()],
    );
    let mut ctx = Context::new();
    install_bodies(&mut ctx, &[(0, genesis.clone()), (1, block.clone())]);
    let genesis_id = insert_header(&ctx, None, genesis.header, NodeStatus::Active);
    let child_id = insert_header(&ctx, Some(genesis_id), block.header, NodeStatus::Active);
    ctx.add_block(BlockRecord::from_block(0, &genesis));
    ctx.add_block(BlockRecord::from_block(1, &block));
    publish_tip(
        &ctx,
        child_id,
        1,
        Hash256::from_le_bytes(block.block_hash().as_byte_array()),
    );
    let hash = Hash256::from_le_bytes(block.block_hash().as_byte_array());
    let handler = Handler::new(Arc::new(ctx));
    let result = handler
        .dispatch(
            "getrawtransaction",
            &json!([child.compute_txid().to_string(), 2_u64, hash.to_string_be()]),
        )
        .expect("same-block v2");
    let vin = result.get("vin").and_then(|v| v.as_array()).expect("vin");
    let prevout = vin[0].get("prevout").expect("prevout");
    assert_eq!(
        prevout
            .get("generated")
            .and_then(sonic_rs::JsonValueTrait::as_bool),
        Some(false)
    );
    assert_eq!(
        prevout
            .get("height")
            .and_then(sonic_rs::JsonValueTrait::as_u64),
        Some(1)
    );
    assert!(
        result.get("fee").is_some(),
        "fee required when every input resolves"
    );
}

#[test]
fn getrawtransaction_verbosity_two_spent_older_output_from_undo() {
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let parent = empty_tx();
    let child = spend_tx(parent.compute_txid(), 0, 40_000);
    let created = block_with_txs(
        genesis.block_hash(),
        1_700_000_040,
        13,
        vec![coinbase_tx(), parent.clone()],
    );
    let spent = block_with_txs(
        created.block_hash(),
        1_700_000_041,
        14,
        vec![coinbase_tx(), child.clone()],
    );
    let spent_hash = Hash256::from_le_bytes(spent.block_hash().as_byte_array());
    let mut undo = UndoBatch::default();
    undo.restore(UtxoAdd::new(
        OutPoint::new(
            Hash256::from_le_bytes(parent.compute_txid().as_byte_array()),
            0,
        ),
        PrimitiveTxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        },
        false,
        1,
    ));
    let mut ctx = Context::new().with_block_undo_source(Arc::new(StaticUndo {
        height: 2,
        hash: spent_hash,
        undo: Ok(Some(undo)),
    }));
    install_bodies(
        &mut ctx,
        &[
            (0, genesis.clone()),
            (1, created.clone()),
            (2, spent.clone()),
        ],
    );
    let genesis_id = insert_header(&ctx, None, genesis.header, NodeStatus::Active);
    let created_id = insert_header(&ctx, Some(genesis_id), created.header, NodeStatus::Active);
    let spent_id = insert_header(&ctx, Some(created_id), spent.header, NodeStatus::Active);
    ctx.add_block(BlockRecord::from_block(0, &genesis));
    ctx.add_block(BlockRecord::from_block(1, &created));
    ctx.add_block(BlockRecord::from_block(2, &spent));
    publish_tip(&ctx, spent_id, 2, spent_hash);
    let handler = Handler::new(Arc::new(ctx));
    let result = handler
        .dispatch(
            "getrawtransaction",
            &json!([
                child.compute_txid().to_string(),
                2_u64,
                spent_hash.to_string_be()
            ]),
        )
        .expect("undo v2");
    let vin = result.get("vin").and_then(|v| v.as_array()).expect("vin");
    let prevout = vin[0].get("prevout").expect("undo prevout");
    assert_eq!(
        prevout
            .get("height")
            .and_then(sonic_rs::JsonValueTrait::as_u64),
        Some(1)
    );
    assert_eq!(
        prevout
            .get("generated")
            .and_then(sonic_rs::JsonValueTrait::as_bool),
        Some(false)
    );
    assert!(result.get("fee").is_some());
}

#[test]
fn getrawtransaction_verbosity_two_omits_unresolved_prevout_without_undo() {
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let parent = empty_tx();
    let child = spend_tx(parent.compute_txid(), 0, 40_000);
    let spent = block_with_txs(
        genesis.block_hash(),
        1_700_000_050,
        15,
        vec![coinbase_tx(), child.clone()],
    );
    let hash = Hash256::from_le_bytes(spent.block_hash().as_byte_array());
    let mut ctx = Context::new();
    install_bodies(&mut ctx, &[(0, genesis.clone()), (1, spent.clone())]);
    let genesis_id = insert_header(&ctx, None, genesis.header, NodeStatus::Active);
    let spent_id = insert_header(&ctx, Some(genesis_id), spent.header, NodeStatus::Active);
    ctx.add_block(BlockRecord::from_block(0, &genesis));
    ctx.add_block(BlockRecord::from_block(1, &spent));
    publish_tip(&ctx, spent_id, 1, hash);
    let handler = Handler::new(Arc::new(ctx));
    let result = handler
        .dispatch(
            "getrawtransaction",
            &json!([child.compute_txid().to_string(), 2_u64, hash.to_string_be()]),
        )
        .expect("missing undo v2");
    let vin = result.get("vin").and_then(|v| v.as_array()).expect("vin");
    assert!(vin[0].get("prevout").is_none());
    assert!(result.get("fee").is_none());
}

#[test]
fn getrawtransaction_verbosity_two_corrupt_undo_is_typed_error() {
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let parent = empty_tx();
    let child = spend_tx(parent.compute_txid(), 0, 40_000);
    let spent = block_with_txs(
        genesis.block_hash(),
        1_700_000_060,
        16,
        vec![coinbase_tx(), child.clone()],
    );
    let hash = Hash256::from_le_bytes(spent.block_hash().as_byte_array());
    let mut ctx = Context::new().with_block_undo_source(Arc::new(StaticUndo {
        height: 1,
        hash,
        undo: Err(TxQueryError::Decode("corrupt undo".into())),
    }));
    install_bodies(&mut ctx, &[(0, genesis.clone()), (1, spent.clone())]);
    let genesis_id = insert_header(&ctx, None, genesis.header, NodeStatus::Active);
    let spent_id = insert_header(&ctx, Some(genesis_id), spent.header, NodeStatus::Active);
    ctx.add_block(BlockRecord::from_block(0, &genesis));
    ctx.add_block(BlockRecord::from_block(1, &spent));
    publish_tip(&ctx, spent_id, 1, hash);
    let handler = Handler::new(Arc::new(ctx));
    let err = handler
        .dispatch(
            "getrawtransaction",
            &json!([child.compute_txid().to_string(), 2_u64, hash.to_string_be()]),
        )
        .expect_err("corrupt undo");
    match err {
        RpcError::Internal(message) => {
            assert!(
                message.contains("undo decode error"),
                "typed decode error, got {message}"
            );
        }
        other => panic!("expected Internal decode error, got {other:?}"),
    }
}
