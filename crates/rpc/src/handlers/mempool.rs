use alloc::sync::Arc;
use core::str::FromStr as _;

use bitcoin::{Amount, Txid};
use bitcoin_rs_mempool::MempoolEntry;
use sonic_rs::{Deserialize as _, Value, json};

use crate::context::Context;
use crate::error::RpcError;
use crate::handlers::{optional_bool, required_str};
use crate::tx_render::btc_amount_json;

// Bitcoin Core default for incremental relay-fee policy until per-node
// configuration is wired. Units: sat/kvB (the canonical workspace internal).
// 1000 sat/kvB = 1 sat/vB = 0.00001 BTC/kvB.
const DEFAULT_INCREMENTAL_RELAY_FEE_SAT_PER_KVB: u64 = 1_000;

pub(crate) fn getmempoolinfo(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    crate::handlers::ensure_no_params(params)?;
    let pool = ctx.mempool.read();
    let stats = pool.stats();
    let incremental_relay_fee =
        btc_amount_json(Amount::from_sat(DEFAULT_INCREMENTAL_RELAY_FEE_SAT_PER_KVB));
    let mempool_min_fee = bitcoin_rs_mempool::eviction::mempool_min_fee_sat_per_kvb(
        &pool,
        DEFAULT_INCREMENTAL_RELAY_FEE_SAT_PER_KVB,
    );
    let mut object = sonic_rs::Object::new();
    let _ = object.insert("loaded", json!(true));
    let _ = object.insert("size", json!(stats.txs));
    let _ = object.insert("bytes", json!(stats.bytes));
    let _ = object.insert("usage", json!(stats.bytes));
    let _ = object.insert(
        "total_fee",
        btc_amount_json(Amount::from_sat(stats.total_fee)),
    );
    let _ = object.insert("maxmempool", json!(pool.limits.max_total_bytes));
    let _ = object.insert(
        "mempoolminfee",
        btc_amount_json(Amount::from_sat(mempool_min_fee)),
    );
    let _ = object.insert(
        "minrelaytxfee",
        btc_amount_json(Amount::from_sat(pool.min_relay_fee_sat_per_kvb())),
    );
    let _ = object.insert("incrementalrelayfee", incremental_relay_fee);
    let _ = object.insert("mempool_sequence", json!(pool.sequence_number()));
    let _ = object.insert("unbroadcastcount", json!(0));
    let _ = object.insert("fullrbf", json!(true));
    Ok(Value::from(object))
}

pub(crate) fn getmempoolentry(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let txid = parse_txid(required_str(params, 0, "txid is required")?)?;
    let pool = ctx.mempool.read();
    let entry = pool
        .entry_by_txid(&txid)
        .ok_or(RpcError::NotFound("transaction not in mempool"))?;
    Ok(mempool_entry_json(entry, &pool))
}

pub(crate) fn getrawmempool(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let verbose = optional_bool(params, 0, false)?;
    let include_sequence = optional_bool(params, 1, false)?;
    if verbose && include_sequence {
        // Core's MempoolToJSON rejects this combination with
        // RPC_INVALID_PARAMETER; the REST twin enforces the same rule.
        return Err(RpcError::InvalidParameter(
            "Verbose results cannot contain mempool sequence values.".to_owned(),
        ));
    }
    let pool = ctx.mempool.read();
    if verbose {
        let mut object = sonic_rs::Object::new();
        for txid in pool.iter_txids() {
            if let Some(entry) = pool.entry_by_txid(&txid) {
                let _ = object.insert(&txid.to_string(), mempool_entry_json(entry, &pool));
            }
        }
        return Ok(Value::from(object));
    }

    let txids: Vec<String> = pool
        .iter_txids()
        .into_iter()
        .map(|txid| txid.to_string())
        .collect();
    if include_sequence {
        return Ok(json!({
            "txids": txids,
            "mempool_sequence": pool.sequence_number(),
        }));
    }
    Ok(json!(txids))
}

pub(crate) fn getmempoolancestors(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let txid = parse_txid(required_str(params, 0, "txid is required")?)?;
    let verbose = optional_bool(params, 1, false)?;
    let pool = ctx.mempool.read();
    let Some(id) = pool.entry_id_by_txid(&txid) else {
        return Err(RpcError::NotFound("transaction not in mempool"));
    };
    let related_ids = pool.ancestor_ids_for_entry(id);
    Ok(render_relatives(&pool, &related_ids, verbose))
}

pub(crate) fn getmempooldescendants(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let txid = parse_txid(required_str(params, 0, "txid is required")?)?;
    let verbose = optional_bool(params, 1, false)?;
    let pool = ctx.mempool.read();
    let Some(id) = pool.entry_id_by_txid(&txid) else {
        return Err(RpcError::NotFound("transaction not in mempool"));
    };
    let related_ids = pool.descendant_ids_for_entry(id);
    Ok(render_relatives(&pool, &related_ids, verbose))
}

fn render_relatives(
    pool: &bitcoin_rs_mempool::Mempool,
    ids: &[bitcoin_rs_mempool::EntryId],
    verbose: bool,
) -> Value {
    if verbose {
        let mut object = sonic_rs::Object::new();
        for id in ids {
            if let Some(entry) = pool.entry(*id) {
                let _ = object.insert(&entry.txid.to_string(), mempool_entry_json(entry, pool));
            }
        }
        Value::from(object)
    } else {
        json!(
            ids.iter()
                .filter_map(|id| pool.entry(*id))
                .map(|entry| entry.txid.to_string())
                .collect::<Vec<_>>()
        )
    }
}

fn parse_txid(value: &str) -> Result<Txid, RpcError> {
    Txid::from_str(value).map_err(|_| RpcError::InvalidParams("txid must be 64 hex characters"))
}

fn mempool_entry_json(entry: &MempoolEntry, pool: &bitcoin_rs_mempool::Mempool) -> Value {
    let mut depends = entry
        .tx
        .input
        .iter()
        .map(|input| input.previous_output.txid)
        .filter(|txid| pool.contains_txid(txid))
        .map(|txid| txid.to_string())
        .collect::<Vec<_>>();
    depends.sort();
    depends.dedup();

    let entry_id = pool.entry_id_by_txid(&entry.txid);
    let mut spentby = entry_id
        .map(|id| pool.spender_txids(id))
        .unwrap_or_default()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    spentby.sort();
    spentby.dedup();
    let (descendantcount, ancestorcount) = entry_id.map_or((1, 1), |id| {
        (
            pool.descendant_count_inclusive(id),
            pool.ancestor_count_inclusive(id),
        )
    });

    let mut fees = sonic_rs::Object::new();
    let _ = fees.insert("base", btc_amount_json(Amount::from_sat(entry.fee)));
    let _ = fees.insert("modified", signed_btc_amount_json(entry.modified_fee()));
    let _ = fees.insert(
        "ancestor",
        signed_btc_amount_json(i128::from(entry.ancestor_fee) + entry.ancestor_fee_delta),
    );
    let _ = fees.insert(
        "descendant",
        signed_btc_amount_json(i128::from(entry.descendant_fee) + entry.descendant_fee_delta),
    );

    let mut object = sonic_rs::Object::new();
    let _ = object.insert("vsize", json!(entry.vsize));
    let _ = object.insert("weight", json!(entry.weight));
    let _ = object.insert("time", json!(entry.time));
    let _ = object.insert("height", json!(entry.height));
    let _ = object.insert("descendantcount", json!(descendantcount));
    let _ = object.insert("descendantsize", json!(entry.descendant_size));
    let _ = object.insert("ancestorcount", json!(ancestorcount));
    let _ = object.insert("ancestorsize", json!(entry.ancestor_size));
    let _ = object.insert("wtxid", json!(entry.wtxid.to_string()));
    let _ = object.insert("fees", Value::from(fees));
    let _ = object.insert("depends", json!(depends));
    let _ = object.insert("spentby", json!(spentby));
    let _ = object.insert("bip125-replaceable", json!(entry.is_replaceable()));
    let _ = object.insert("unbroadcast", json!(false));
    Value::from(object)
}

fn signed_btc_amount_json(satoshis: i128) -> Value {
    let sign = if satoshis.is_negative() { "-" } else { "" };
    let magnitude = satoshis.unsigned_abs();
    let whole = magnitude / 100_000_000;
    let fractional = magnitude % 100_000_000;
    let text = format!("{sign}{whole}.{fractional:08}");
    let mut deserializer = sonic_rs::Deserializer::from_str(&text).use_rawnumber();
    match Value::deserialize(&mut deserializer) {
        Ok(value) => value,
        Err(error) => panic!("formatted signed BTC amount was invalid JSON: {error}"),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod amount_format_probe {
    use bitcoin::Amount;
    use sonic_rs::JsonValueTrait;

    #[test]
    fn btc_amount_json_preserves_eight_decimals_as_raw_number() {
        let value = crate::tx_render::btc_amount_json(Amount::from_sat(3_000));
        let Some(raw) = value.as_raw_number() else {
            panic!("expected raw number, got {value:?}");
        };
        assert_eq!(raw.as_str(), "0.00003000");
        assert_eq!(sonic_rs::to_string(&value).unwrap(), "0.00003000");

        let mut object = sonic_rs::Object::new();
        let _ = object.insert("mempoolminfee", value);
        let wrapped = sonic_rs::Value::from(object);
        let field = wrapped.get("mempoolminfee").expect("field");
        let Some(raw) = field.as_raw_number() else {
            panic!("object insert lost raw number: {field:?}");
        };
        assert_eq!(raw.as_str(), "0.00003000");
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod mempoolminfee_pressure_tests {
    use std::sync::Arc;

    use super::*;
    use sonic_rs::JsonValueTrait;

    #[test]
    fn mempoolminfee_equals_minrelay_when_pool_below_pressure() {
        let ctx = Arc::new(Context::new());
        // Empty pool, default limits: mempoolminfee == minrelaytxfee.
        let value =
            getmempoolinfo(&ctx, &json!([])).unwrap_or_else(|err| panic!("getmempoolinfo: {err}"));
        let Some(mempool_min) = value.get("mempoolminfee").and_then(JsonValueTrait::as_f64) else {
            panic!("mempoolminfee missing");
        };
        let Some(min_relay) = value.get("minrelaytxfee").and_then(JsonValueTrait::as_f64) else {
            panic!("minrelaytxfee missing");
        };
        // Both should equal the default 0.00001 BTC/kvB (1000 sat/kvB).
        assert!((mempool_min - min_relay).abs() < 1e-9);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use bitcoin::hashes::Hash as _;

    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
    use bitcoin_rs_mempool::MempoolEntry;
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

        // 1000 sat/kvB / 100_000_000 = 0.00001
        assert!(
            (min_relay - 0.00001).abs() < 1e-9,
            "expected ~0.00001, got {min_relay}"
        );
    }

    #[test]
    fn getmempoolinfo_minrelaytxfee_reflects_custom_mempool_floor() {
        let ctx = Arc::new(Context::new());
        {
            let mut pool = ctx.mempool.write();
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
        let Some(mempool_min_fee) = result.get("mempoolminfee").and_then(JsonValueTrait::as_f64)
        else {
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
        *ctx.mempool.write() =
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
    fn getmempoolinfo_emits_mempool_sequence_field() {
        let ctx = Arc::new(Context::new());
        let handler = crate::Handler::new(Arc::clone(&ctx));
        let result = handler
            .dispatch("getmempoolinfo", &json!([]))
            .unwrap_or_else(|err| panic!("getmempoolinfo failed: {err}"));
        assert!(
            result.get("mempool_sequence").is_some(),
            "mempool_sequence missing: {result:?}"
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
        // Core's MempoolToJSON rejects verbose=true with mempool_sequence=true
        // with RPC_INVALID_PARAMETER. The REST twin enforces the same rule.
        let ctx = Arc::new(Context::new());
        let handler = crate::Handler::new(Arc::clone(&ctx));
        let error = handler
            .dispatch("getrawmempool", &json!([true, true]))
            .expect_err("verbose+sequence must be rejected");
        assert!(matches!(
            error,
            crate::RpcError::InvalidParameter(msg) if msg.contains("Verbose results cannot contain mempool sequence values")
        ));
    }

    #[test]
    fn getmempooldescendants_walks_real_descendant_graph() -> Result<(), Box<dyn std::error::Error>>
    {
        let ctx = Arc::new(Context::new());
        let parent = tx(1, Vec::new());
        let parent_txid = parent.compute_txid();
        let child = tx(2, vec![OutPoint::new(parent_txid, 0)]);
        let child_txid = child.compute_txid().to_string();
        {
            let mut pool = ctx.mempool.write();
            pool.insert_entry(MempoolEntry::new(Arc::new(parent), 100, 1_000, 0, 0))?;
            pool.insert_entry(MempoolEntry::new(Arc::new(child), 100, 1_000, 0, 0))?;
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
        Ok(())
    }

    #[test]
    fn getmempoolancestors_walks_real_ancestor_graph() -> Result<(), Box<dyn std::error::Error>> {
        let ctx = Arc::new(Context::new());
        let parent = tx(3, Vec::new());
        let parent_txid = parent.compute_txid();
        let parent_txid_string = parent_txid.to_string();
        let child = tx(4, vec![OutPoint::new(parent_txid, 0)]);
        let child_txid = child.compute_txid();
        {
            let mut pool = ctx.mempool.write();
            pool.insert_entry(MempoolEntry::new(Arc::new(parent), 100, 1_000, 0, 0))?;
            pool.insert_entry(MempoolEntry::new(Arc::new(child), 100, 1_000, 0, 0))?;
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
        Ok(())
    }

    #[test]
    fn getmempoolentry_emits_depends_when_input_spends_mempool_tx() {
        let ctx = Arc::new(Context::new());
        let handler = crate::Handler::new(Arc::clone(&ctx));
        let parent = bitcoin::Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: Vec::new(),
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(1_000),
                script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let parent_txid = parent.compute_txid();
        let child = bitcoin::Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: parent_txid,
                    vout: 0,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: Vec::new(),
        };
        let child_txid = child.compute_txid();
        {
            let mut pool = ctx.mempool.write();
            let parent_entry =
                bitcoin_rs_mempool::MempoolEntry::new(Arc::new(parent), 100, 1_000, 1, 7);
            let Ok(_) = pool.insert_entry(parent_entry) else {
                panic!("parent insert failed");
            };
            let child_entry =
                bitcoin_rs_mempool::MempoolEntry::new(Arc::new(child), 100, 1_000, 1, 7);
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
        let rbf_tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: bitcoin::Txid::from_byte_array([0xaa; 32]),
                    vout: 0,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence(0x0000_0001),
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(1_000),
                script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let rbf_txid = rbf_tx.compute_txid();
        {
            let mut pool = ctx.mempool.write();
            let Ok(_) = pool.insert_entry(MempoolEntry::new(Arc::new(rbf_tx), 100, 10_000, 1, 7))
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

    fn tx(label: u8, previous_outputs: Vec<OutPoint>) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: previous_outputs
                .into_iter()
                .map(|previous_output| TxIn {
                    previous_output,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            output: vec![TxOut {
                value: Amount::from_sat(5_000 + u64::from(label)),
                script_pubkey: ScriptBuf::from_bytes(vec![label]),
            }],
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod spentby_tests {
    use alloc::sync::Arc;
    use alloc::vec::Vec;

    use bitcoin::hashes::Hash as _;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
    use bitcoin_rs_mempool::{Mempool, MempoolEntry};

    use super::*;

    fn entry_to_serde(entry: &MempoolEntry, pool: &Mempool) -> serde_json::Value {
        let rendered = sonic_rs::to_string(&mempool_entry_json(entry, pool))
            .unwrap_or_else(|err| panic!("re-encoding mempool entry failed: {err}"));
        serde_json::from_str(&rendered)
            .unwrap_or_else(|err| panic!("re-parsing mempool entry failed: {err}"))
    }

    /// The answer `entry_to_serde` used to compute: for every entry in the pool,
    /// walk its inputs and keep it if any of them spends `txid`.
    ///
    /// Spelled out here instead of being shared with the implementation. An
    /// oracle that calls the code under test cannot disagree with it.
    fn spentby_by_scanning_every_entry(pool: &Mempool, txid: Txid) -> Vec<String> {
        let mut spentby = Vec::new();
        for (_id, candidate) in &pool.entries {
            for input in &candidate.tx.input {
                if input.previous_output.txid == txid {
                    spentby.push(candidate.tx.compute_txid().to_string());
                    break;
                }
            }
        }
        spentby.sort();
        spentby.dedup();
        spentby
    }

    fn tx_with(inputs: &[OutPoint], outputs: u32, tag: u64) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: inputs
                .iter()
                .map(|previous_output| TxIn {
                    previous_output: *previous_output,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence(0xFFFF_FFFD),
                    witness: Witness::new(),
                })
                .collect(),
            output: (0..outputs)
                .map(|vout| TxOut {
                    value: Amount::from_sat(
                        10_000_u64
                            .saturating_add(u64::from(vout))
                            .saturating_add(tag.saturating_mul(1_000)),
                    ),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                })
                .collect(),
        }
    }

    /// A pool whose spend graph is not a chain:
    ///
    /// ```text
    ///   root ──vout 0──> child_a ──vout 0──> child_c
    ///        ──vout 1──> child_b
    ///        ──vout 2──> child_b
    ///   loner (spends nothing in the pool)
    /// ```
    ///
    /// So `root` has two spenders, `child_a` one, and everything else none.
    /// `child_b` spends two of the root's outputs, so a walk of the spend index
    /// reaches it twice — the case a missing dedup shows up in, and the case a
    /// fixture where every child spends one output cannot reach.
    fn graph_ctx() -> (Arc<Context>, Txid) {
        let confirmed = OutPoint::new(Txid::from_byte_array([7_u8; 32]), 0);
        let root = tx_with(&[confirmed], 3, 1);
        let root_txid = root.compute_txid();
        let child_a = tx_with(&[OutPoint::new(root_txid, 0)], 1, 2);
        let child_a_txid = child_a.compute_txid();
        let child_b = tx_with(
            &[OutPoint::new(root_txid, 1), OutPoint::new(root_txid, 2)],
            1,
            3,
        );
        let child_c = tx_with(&[OutPoint::new(child_a_txid, 0)], 1, 4);
        let loner = tx_with(&[OutPoint::new(Txid::from_byte_array([9_u8; 32]), 0)], 1, 5);

        // `spentby` is rendered in txid order, but the spend index answers in
        // `EntryId` — that is, insertion — order. Insert the root's two spenders
        // highest-txid-first so the two orders are opposite: a rendering that
        // forgets to sort then produces a visibly different list, instead of
        // passing because the fixture happened to be inserted in order already.
        let root_spenders = if child_a.compute_txid() > child_b.compute_txid() {
            [child_a, child_b]
        } else {
            [child_b, child_a]
        };
        let [first_spender, second_spender] = root_spenders;

        let ctx = Arc::new(Context::new());
        {
            let mut pool = ctx.mempool.write();
            for tx in [root, first_spender, second_spender, child_c, loner] {
                let entry = MempoolEntry::new(Arc::new(tx), 100, 10_000, 1, 7);
                let Ok(_id) = pool.insert_entry(entry) else {
                    panic!("mempool insert failed while building the fixture");
                };
            }
        }
        (ctx, root_txid)
    }

    fn rendered_spentby(value: &serde_json::Value) -> Vec<String> {
        let Some(array) = value.get("spentby").and_then(serde_json::Value::as_array) else {
            panic!("spentby missing from {value}");
        };
        array
            .iter()
            .map(|item| {
                item.as_str()
                    .unwrap_or_else(|| panic!("spentby entry is not a string: {item}"))
                    .to_owned()
            })
            .collect()
    }

    #[test]
    fn spentby_matches_the_scan_it_replaced_for_every_entry() {
        let (ctx, root_txid) = graph_ctx();
        let pool = ctx.mempool.read();

        let mut spenders_seen = 0_usize;
        for (_id, entry) in &pool.entries {
            let expected = spentby_by_scanning_every_entry(&pool, entry.txid);
            spenders_seen = spenders_seen.saturating_add(expected.len());
            assert_eq!(
                rendered_spentby(&entry_to_serde(entry, &pool)),
                expected,
                "spentby diverged from the scan for {}",
                entry.txid
            );
        }

        // Without this the equality above would pass on a pool where nothing
        // spends anything, which is exactly the fixture this bug survived.
        assert_eq!(
            spenders_seen, 3,
            "the fixture must exercise spenders: root has 2, child_a has 1"
        );
        assert_eq!(
            spentby_by_scanning_every_entry(&pool, root_txid).len(),
            2,
            "root must be spent by two transactions"
        );
    }

    #[test]
    fn getrawmempool_verbose_spentby_matches_the_scan_for_every_key() {
        let (ctx, _root_txid) = graph_ctx();
        let handler = crate::Handler::new(Arc::clone(&ctx));
        let result = handler
            .dispatch("getrawmempool", &json!([true]))
            .unwrap_or_else(|err| panic!("getrawmempool failed: {err}"));
        let rendered = sonic_rs::to_string(&result)
            .unwrap_or_else(|err| panic!("re-encoding the response failed: {err}"));
        let rendered: serde_json::Value = serde_json::from_str(&rendered)
            .unwrap_or_else(|err| panic!("re-parsing the response failed: {err}"));
        let Some(object) = rendered.as_object() else {
            panic!("verbose getrawmempool must answer an object: {rendered}");
        };

        let pool = ctx.mempool.read();
        assert_eq!(object.len(), pool.len(), "one key per mempool entry");
        for (txid, entry) in object {
            let txid = Txid::from_str(txid)
                .unwrap_or_else(|err| panic!("key {txid} is not a txid: {err}"));
            assert_eq!(
                rendered_spentby(entry),
                spentby_by_scanning_every_entry(&pool, txid),
                "spentby diverged for key {txid}"
            );
        }
    }

    #[test]
    fn getmempoolentry_reports_every_spender_of_the_root() {
        let (ctx, root_txid) = graph_ctx();
        let expected = {
            let pool = ctx.mempool.read();
            spentby_by_scanning_every_entry(&pool, root_txid)
        };
        let handler = crate::Handler::new(Arc::clone(&ctx));
        let result = handler
            .dispatch("getmempoolentry", &json!([root_txid.to_string()]))
            .unwrap_or_else(|err| panic!("getmempoolentry failed: {err}"));
        let rendered = sonic_rs::to_string(&result)
            .unwrap_or_else(|err| panic!("re-encoding the response failed: {err}"));
        let rendered: serde_json::Value = serde_json::from_str(&rendered)
            .unwrap_or_else(|err| panic!("re-parsing the response failed: {err}"));
        assert_eq!(rendered_spentby(&rendered), expected);
    }
}
