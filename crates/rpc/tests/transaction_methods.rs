//! Focused Core transaction RPC contracts for R2.

use std::sync::Arc;

use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::Hash as _;
use bitcoin::hex::DisplayHex as _;
use bitcoin::{
    Amount, OutPoint as BitcoinOutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    WPubkeyHash, Witness, absolute, transaction,
};
use bitcoin_rs_mempool::MempoolEntry;
use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut as PrimitiveTxOut};
use bitcoin_rs_rpc::context::{BlockRecord, Context};
use bitcoin_rs_rpc::{Handler, RpcError};
use bitcoin_rs_utxo::{BlockChanges, UtxoAdd};
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
        unspent.get("confirmations").and_then(|v| v.as_u64()),
        Some(1)
    );
    assert_eq!(
        unspent.get("coinbase").and_then(|v| v.as_bool()),
        Some(false)
    );

    let spender = spend_tx(funding_txid, 0, 40_000);
    let spender_txid = spender.compute_txid();
    let vsize = u32::try_from(spender.vsize()).expect("vsize");
    ctx.mempool
        .write()
        .insert_entry(MempoolEntry::new(
            Arc::new(spender.clone()),
            vsize,
            10_000,
            1,
            10,
        ))
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
            .and_then(|v| v.as_u64()),
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
    assert_eq!(row.get("allowed").and_then(|v| v.as_bool()), Some(false));
    assert_eq!(
        row.get("reject-reason").and_then(|v| v.as_str()),
        Some("missing-inputs")
    );

    let already = empty_tx();
    let already_txid = already.compute_txid();
    let vsize = u32::try_from(already.vsize()).expect("vsize");
    ctx.mempool
        .write()
        .insert_entry(MempoolEntry::new(
            Arc::new(already.clone()),
            vsize,
            1_000,
            1,
            1,
        ))
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
        matches!(oversized, Err(RpcError::Misc(ref message)) if message == "package-too-large"),
        "expected package-too-large Misc error, got {oversized:?}"
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
