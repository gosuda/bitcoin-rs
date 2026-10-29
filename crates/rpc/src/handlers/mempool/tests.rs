use alloc::sync::Arc;
use alloc::vec::Vec;

use bitcoin_rs_mempool::MempoolEntry;
use bitcoin_rs_primitives::{
    Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
};
use sonic_rs::{JsonContainerTrait, JsonValueTrait, json};

use super::*;

#[test]
fn getmempoolinfo_emits_one_sat_per_vbyte_default_for_relay_fees() {
    let ctx = Arc::new(Context::new());
    let handler = crate::Handler::new(Arc::clone(&ctx));
    let result = handler
        .dispatch("getmempoolinfo", &json!([]))
        .unwrap_or_else(|err| panic!("getmempoolinfo failed: {err}"));
    let Some(min_relay) = result.get("minrelaytxfee").and_then(JsonValueTrait::as_f64) else {
        panic!("minrelaytxfee missing: {result:?}");
    };

    assert!(
        (min_relay - 0.00001).abs() < 1e-9,
        "expected ~0.00001, got {min_relay}"
    );
}

#[test]
fn getmempoolinfo_cluster_limits_follow_the_pool_rather_than_a_constant() {
    let ctx = Arc::new(Context::new());
    {
        let mut pool = ctx.mempool.gateway.pool().write();
        *pool = bitcoin_rs_mempool::Mempool::new(bitcoin_rs_mempool::MempoolLimits {
            cluster_count: 7,
            cluster_size_vbytes: 4_242,
            ..bitcoin_rs_mempool::MempoolLimits::default()
        });
    }

    let handler = crate::Handler::new(Arc::clone(&ctx));
    let result = handler
        .dispatch("getmempoolinfo", &json!([]))
        .unwrap_or_else(|err| panic!("getmempoolinfo failed: {err}"));

    assert_eq!(
        result
            .get("limitclustercount")
            .and_then(JsonValueTrait::as_i64),
        Some(7),
        "limitclustercount must follow the pool: {result:?}"
    );
    assert_eq!(
        result
            .get("limitclustersize")
            .and_then(JsonValueTrait::as_i64),
        Some(4_242),
        "limitclustersize must follow the pool: {result:?}"
    );
}

#[test]
fn getmempoolinfo_defaults_to_cores_cluster_limits() {
    let ctx = Arc::new(Context::new());
    let handler = crate::Handler::new(Arc::clone(&ctx));
    let result = handler
        .dispatch("getmempoolinfo", &json!([]))
        .unwrap_or_else(|err| panic!("getmempoolinfo failed: {err}"));

    assert_eq!(
        result
            .get("limitclustercount")
            .and_then(JsonValueTrait::as_i64),
        Some(64),
        "{result:?}"
    );
    assert_eq!(
        result
            .get("limitclustersize")
            .and_then(JsonValueTrait::as_i64),
        Some(101_000),
        "{result:?}"
    );
}

#[test]
fn getmempoolinfo_minrelaytxfee_reflects_custom_mempool_floor() {
    let ctx = Arc::new(Context::new());
    {
        let mut pool = ctx.mempool.gateway.pool().write();
        *pool = bitcoin_rs_mempool::Mempool::new(bitcoin_rs_mempool::MempoolLimits {
            min_relay_fee_sat_per_kvb: 5_000,
            ..bitcoin_rs_mempool::MempoolLimits::default()
        });
    }

    let handler = crate::Handler::new(Arc::clone(&ctx));
    let result = handler
        .dispatch("getmempoolinfo", &json!([]))
        .unwrap_or_else(|err| panic!("getmempoolinfo failed: {err}"));
    let Some(min_relay) = result.get("minrelaytxfee").and_then(JsonValueTrait::as_f64) else {
        panic!("minrelaytxfee missing: {result:?}");
    };
    let Some(mempool_min_fee) = result.get("mempoolminfee").and_then(JsonValueTrait::as_f64) else {
        panic!("mempoolminfee missing: {result:?}");
    };

    assert!(
        (min_relay - 0.00005).abs() < 1e-9,
        "expected ~0.00005, got {min_relay}"
    );
    assert!(
        (mempool_min_fee - 0.00005).abs() < 1e-9,
        "expected ~0.00005, got {mempool_min_fee}"
    );
}

#[test]
fn getmempoolinfo_maxmempool_reflects_custom_limit() {
    let ctx = Context::new();
    *ctx.mempool.gateway.pool().write() =
        bitcoin_rs_mempool::Mempool::new(bitcoin_rs_mempool::MempoolLimits {
            max_total_bytes: 50_000_000,
            ..bitcoin_rs_mempool::MempoolLimits::default()
        });
    let ctx = Arc::new(ctx);
    let handler = crate::Handler::new(Arc::clone(&ctx));
    let result = handler
        .dispatch("getmempoolinfo", &json!([]))
        .unwrap_or_else(|err| panic!("getmempoolinfo failed: {err}"));
    let Some(maxmempool) = result.get("maxmempool").and_then(JsonValueTrait::as_u64) else {
        panic!("maxmempool missing: {result:?}");
    };
    assert_eq!(maxmempool, 50_000_000);
}

#[test]
fn getmempoolinfo_omits_mempool_sequence_like_core() {
    let ctx = Arc::new(Context::new());
    let handler = crate::Handler::new(Arc::clone(&ctx));
    let result = handler
        .dispatch("getmempoolinfo", &json!([]))
        .unwrap_or_else(|err| panic!("getmempoolinfo failed: {err}"));
    assert!(
        result.get("mempool_sequence").is_none(),
        "mempool_sequence must stay absent from getmempoolinfo: {result:?}"
    );
}

#[test]
fn getmempoolinfo_policy_fields_project_the_enforced_record() {
    let ctx = Arc::new(Context::new());
    let handler = crate::Handler::new(Arc::clone(&ctx));
    let result = handler
        .dispatch("getmempoolinfo", &json!([]))
        .unwrap_or_else(|err| panic!("getmempoolinfo failed: {err}"));
    assert_eq!(
        result
            .get("permitbaremultisig")
            .and_then(JsonValueTrait::as_bool),
        Some(true)
    );
    assert_eq!(
        result
            .get("maxdatacarriersize")
            .and_then(JsonValueTrait::as_u64),
        Some(83)
    );
    assert_eq!(
        result
            .get("limitclustercount")
            .and_then(JsonValueTrait::as_i64),
        Some(64)
    );
    assert_eq!(
        result
            .get("limitclustersize")
            .and_then(JsonValueTrait::as_i64),
        Some(101_000)
    );
    assert_eq!(
        result.get("optimal").and_then(JsonValueTrait::as_bool),
        Some(true)
    );
    let Some(incremental) = result
        .get("incrementalrelayfee")
        .and_then(JsonValueTrait::as_f64)
    else {
        panic!("incrementalrelayfee missing: {result:?}");
    };
    assert!((incremental - 0.00001).abs() < 1e-12);
    assert_eq!(
        result.get("fullrbf").and_then(JsonValueTrait::as_bool),
        Some(true)
    );
}

#[test]
fn getmempoolinfo_policy_follows_the_configured_pool_limits() {
    let ctx = Arc::new(Context::new());
    ctx.mempool.gateway.pool().write().limits.cluster_count = 7;
    ctx.mempool
        .gateway
        .pool()
        .write()
        .limits
        .cluster_size_vbytes = 42_000;
    let handler = crate::Handler::new(Arc::clone(&ctx));
    let result = handler
        .dispatch("getmempoolinfo", &json!([]))
        .unwrap_or_else(|err| panic!("getmempoolinfo failed: {err}"));
    assert_eq!(
        result
            .get("limitclustercount")
            .and_then(JsonValueTrait::as_i64),
        Some(7)
    );
    assert_eq!(
        result
            .get("limitclustersize")
            .and_then(JsonValueTrait::as_i64),
        Some(42_000)
    );
    assert_eq!(
        result.get("fullrbf").and_then(JsonValueTrait::as_bool),
        Some(true)
    );
}

#[test]
fn getrawmempool_with_sequence_flag_wraps_response() {
    let ctx = Arc::new(Context::new());
    let handler = crate::Handler::new(Arc::clone(&ctx));
    let result = handler
        .dispatch("getrawmempool", &json!([false, true]))
        .unwrap_or_else(|err| panic!("getrawmempool failed: {err}"));
    let Some(seq) = result
        .get("mempool_sequence")
        .and_then(JsonValueTrait::as_u64)
    else {
        panic!("mempool_sequence missing: {result:?}");
    };
    assert_eq!(seq, 0);
    let Some(txids) = result.get("txids").and_then(JsonContainerTrait::as_array) else {
        panic!("txids missing: {result:?}");
    };
    assert!(txids.is_empty());
}

#[test]
fn getrawmempool_without_sequence_flag_returns_bare_array() {
    let ctx = Arc::new(Context::new());
    let handler = crate::Handler::new(Arc::clone(&ctx));
    let result = handler
        .dispatch("getrawmempool", &json!([]))
        .unwrap_or_else(|err| panic!("getrawmempool failed: {err}"));
    assert!(result.is_array(), "expected bare array: {result:?}");
}

#[test]
fn getrawmempool_verbose_with_sequence_is_rejected() {
    let ctx = Arc::new(Context::new());
    let handler = crate::Handler::new(Arc::clone(&ctx));
    let error = handler
        .dispatch("getrawmempool", &json!([true, true]))
        .expect_err("verbose+sequence must be rejected");
    assert!(matches!(
        error,
        RpcError::InvalidParams(msg) if msg.contains("Verbose results cannot contain mempool sequence values")
    ));
}

#[test]
fn getmempooldescendants_walks_real_descendant_graph() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());
    let parent = tx(1, Vec::new());
    let parent_txid = parent.txid();
    let child = tx(2, vec![OutPoint::new(parent_txid, 0)]);
    let child_txid = child.txid().to_string();
    {
        let mut pool = ctx.mempool.gateway.pool().write();
        pool.insert_entry(MempoolEntry::new(Arc::new(parent), 100, 1_000, 0, 0, 0))?;
        pool.insert_entry(MempoolEntry::new(Arc::new(child), 100, 1_000, 0, 0, 0))?;
    }

    let result = getmempooldescendants(&ctx, &json!([parent_txid.to_string()]))?;
    let Some(array) = result.as_array() else {
        return Err("expected descendants array".into());
    };

    assert_eq!(array.len(), 1);
    assert_eq!(
        array.first().and_then(|value| value.as_str()),
        Some(child_txid.as_str())
    );
    let verbose = getmempooldescendants(&ctx, &json!([parent_txid.to_string(), true]))?;
    let child_entry = getmempoolentry(&ctx, &json!([child_txid]))?;
    assert_eq!(verbose.get(&child_txid), Some(&child_entry));
    let all = getrawmempool(&ctx, &json!([true]))?;
    assert_eq!(all.get(&child_txid), Some(&child_entry));
    assert_eq!(
        child_entry.get("depends"),
        Some(&json!([parent_txid.to_string()]))
    );
    assert_eq!(child_entry.get("ancestorcount"), Some(&json!(2)));
    Ok(())
}

#[test]
fn getmempoolancestors_walks_real_ancestor_graph() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());
    let parent = tx(3, Vec::new());
    let parent_txid = parent.txid();
    let parent_txid_string = parent_txid.to_string();
    let child = tx(4, vec![OutPoint::new(parent_txid, 0)]);
    let child_txid = child.txid();
    {
        let mut pool = ctx.mempool.gateway.pool().write();
        pool.insert_entry(MempoolEntry::new(Arc::new(parent), 100, 1_000, 0, 0, 0))?;
        pool.insert_entry(MempoolEntry::new(Arc::new(child), 100, 1_000, 0, 0, 0))?;
    }

    let result = getmempoolancestors(&ctx, &json!([child_txid.to_string()]))?;
    let Some(array) = result.as_array() else {
        return Err("expected ancestors array".into());
    };

    assert_eq!(array.len(), 1);
    assert_eq!(
        array.first().and_then(|value| value.as_str()),
        Some(parent_txid_string.as_str())
    );
    let verbose = getmempoolancestors(&ctx, &json!([child_txid.to_string(), true]))?;
    let parent_entry = getmempoolentry(&ctx, &json!([parent_txid_string]))?;
    assert_eq!(verbose.get(&parent_txid_string), Some(&parent_entry));
    assert_eq!(
        parent_entry.get("spentby"),
        Some(&json!([child_txid.to_string()]))
    );
    assert_eq!(parent_entry.get("descendantcount"), Some(&json!(2)));
    Ok(())
}

#[test]
fn getmempoolentry_emits_depends_when_input_spends_mempool_tx() {
    let ctx = Arc::new(Context::new());
    let handler = crate::Handler::new(Arc::clone(&ctx));
    let parent = Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: Vec::new(),
        outputs: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: vec![0x51].into(),
        }],
    };
    let parent_txid = parent.txid();
    let child = Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: parent_txid,
                vout: 0,
            },
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: Vec::new(),
    };
    let child_txid = child.txid();
    {
        let mut pool = ctx.mempool.gateway.pool().write();
        let parent_entry =
            bitcoin_rs_mempool::MempoolEntry::new(Arc::new(parent), 100, 1_000, 1, 7, 0);
        let Ok(_) = pool.insert_entry(parent_entry) else {
            panic!("parent insert failed");
        };
        let child_entry =
            bitcoin_rs_mempool::MempoolEntry::new(Arc::new(child), 100, 1_000, 1, 7, 0);
        let Ok(_) = pool.insert_entry(child_entry) else {
            panic!("child insert failed");
        };
    }
    let result = handler
        .dispatch("getmempoolentry", &json!([child_txid.to_string()]))
        .unwrap_or_else(|err| panic!("getmempoolentry: {err}"));
    let Some(depends) = result.get("depends").and_then(JsonContainerTrait::as_array) else {
        panic!("depends missing: {result:?}");
    };
    assert_eq!(depends.len(), 1, "expected one depends entry");
}

#[test]
fn getmempoolentry_bip125_replaceable_reflects_input_sequence() {
    let ctx = Arc::new(Context::new());
    let rbf_tx = Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid(Hash256::from_le_bytes(&[0xaa; 32])),
                vout: 0,
            },
            script_sig: Script::new(),
            sequence: Sequence::from_consensus(0x0000_0001),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: vec![0x51].into(),
        }],
    };
    let rbf_txid = rbf_tx.txid();
    {
        let mut pool = ctx.mempool.gateway.pool().write();
        let Ok(_) = pool.insert_entry(MempoolEntry::new(Arc::new(rbf_tx), 100, 10_000, 1, 7, 0))
        else {
            panic!("mempool insert failed");
        };
    }
    let handler = crate::Handler::new(Arc::clone(&ctx));
    let result = handler
        .dispatch("getmempoolentry", &json!([rbf_txid.to_string()]))
        .unwrap_or_else(|err| panic!("getmempoolentry failed: {err}"));
    assert_eq!(
        result
            .get("bip125-replaceable")
            .and_then(JsonValueTrait::as_bool),
        Some(true)
    );
}

fn tx(label: u8, previous_outputs: Vec<OutPoint>) -> Tx {
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: previous_outputs
            .into_iter()
            .map(|previous_output| TxIn {
                previous_output,
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect(),
        outputs: vec![TxOut {
            value: Amount::from_sat(5_000 + u64::from(label)),
            script_pubkey: vec![label].into(),
        }],
    }
}
