use alloc::sync::Arc;
use core::str::FromStr as _;

use bitcoin::Txid;
use bitcoin_rs_mempool::MempoolEntry;
use serde_json::json as serde_json_value;
use sonic_rs::{Value, json};

use crate::context::Context;
use crate::error::RpcError;
use crate::handlers::{optional_bool, required_str, serde_to_sonic};

// Bitcoin Core default for incremental relay-fee policy until per-node
// configuration is wired. Units: sat/kvB (the canonical workspace internal).
// 1000 sat/kvB = 1 sat/vB = 0.00001 BTC/kvB.
const DEFAULT_INCREMENTAL_RELAY_FEE_SAT_PER_KVB: u64 = 1_000;

pub(crate) fn getmempoolinfo(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    crate::handlers::ensure_no_params(params)?;
    let pool = ctx.mempool.read();
    let stats = pool.stats();
    let mempool_sequence = pool.sequence_number();
    let live_min_relay_sat_per_kvb = pool.min_relay_fee_sat_per_kvb();
    let min_relay_fee = sat_per_kvb_to_btc(live_min_relay_sat_per_kvb);
    let incremental_relay_fee = sat_per_kvb_to_btc(DEFAULT_INCREMENTAL_RELAY_FEE_SAT_PER_KVB);
    Ok(json!({
        "loaded": true,
        "size": stats.txs,
        "bytes": stats.bytes,
        "usage": stats.bytes,
        "total_fee": sats_to_btc(stats.total_fee),
        "maxmempool": 300_000_000_u64,
        "mempoolminfee": min_relay_fee,
        "minrelaytxfee": min_relay_fee,
        "incrementalrelayfee": incremental_relay_fee,
        // Deviation: Bitcoin Core exposes this via getrawmempool's
        // mempool_sequence argument; this v1 surface emits it here instead.
        "mempool_sequence": mempool_sequence,
        "unbroadcastcount": 0,
        "fullrbf": true
    }))
}

pub(crate) fn getmempoolentry(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let txid = parse_txid(required_str(params, 0, "txid is required")?)?;
    let pool = ctx.mempool.read();
    let id = pool
        .by_txid
        .get(&txid)
        .ok_or(RpcError::NotFound("transaction not in mempool"))?;
    let entry = pool
        .entry(*id)
        .ok_or(RpcError::NotFound("transaction not in mempool"))?;
    entry_to_value(entry, &pool)
}

pub(crate) fn getrawmempool(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let verbose = optional_bool(params, 0, false)?;
    let include_sequence = optional_bool(params, 1, false)?;
    let pool = ctx.mempool.read();
    let sequence = pool.sequence_number();
    if verbose {
        let mut object = serde_json::Map::new();
        for (_id, entry) in &pool.entries {
            object.insert(
                entry.tx.compute_txid().to_string(),
                entry_to_serde(entry, &pool),
            );
        }
        if include_sequence {
            object.insert(
                "mempool_sequence".to_owned(),
                serde_json::Value::Number(serde_json::Number::from(sequence)),
            );
        }
        return serde_to_sonic(&serde_json::Value::Object(object));
    }

    let txids: Vec<String> = pool
        .entries
        .iter()
        .map(|(_id, entry)| entry.tx.compute_txid().to_string())
        .collect();
    if include_sequence {
        return Ok(json!({
            "txids": txids,
            "mempool_sequence": sequence,
        }));
    }
    Ok(json!(txids))
}

pub(crate) fn getmempoolancestors(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let txid = parse_txid(required_str(params, 0, "txid is required")?)?;
    let verbose = optional_bool(params, 1, false)?;
    let pool = ctx.mempool.read();
    let Some(&id) = pool.by_txid.get(&txid) else {
        return Err(RpcError::NotFound("transaction not in mempool"));
    };
    let related_ids = pool.ancestor_ids_for_entry(id);
    render_relatives(&pool, &related_ids, verbose)
}

pub(crate) fn getmempooldescendants(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let txid = parse_txid(required_str(params, 0, "txid is required")?)?;
    let verbose = optional_bool(params, 1, false)?;
    let pool = ctx.mempool.read();
    let Some(&id) = pool.by_txid.get(&txid) else {
        return Err(RpcError::NotFound("transaction not in mempool"));
    };
    let related_ids = pool.descendant_ids_for_entry(id);
    render_relatives(&pool, &related_ids, verbose)
}

fn render_relatives(
    pool: &bitcoin_rs_mempool::Mempool,
    ids: &[bitcoin_rs_mempool::EntryId],
    verbose: bool,
) -> Result<Value, RpcError> {
    if verbose {
        let mut object = serde_json::Map::new();
        for id in ids {
            if let Some(entry) = pool.entry(*id) {
                let txid = entry.tx.compute_txid().to_string();
                object.insert(txid, entry_to_serde(entry, pool));
            }
        }
        serde_to_sonic(&serde_json::Value::Object(object))
    } else {
        let mut txids = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(entry) = pool.entry(*id) {
                txids.push(entry.tx.compute_txid().to_string());
            }
        }
        Ok(json!(txids))
    }
}

fn parse_txid(value: &str) -> Result<Txid, RpcError> {
    Txid::from_str(value).map_err(|_| RpcError::InvalidParams("txid must be 64 hex characters"))
}

fn entry_to_value(
    entry: &MempoolEntry,
    pool: &bitcoin_rs_mempool::Mempool,
) -> Result<Value, RpcError> {
    serde_to_sonic(&entry_to_serde(entry, pool))
}

fn entry_to_serde(entry: &MempoolEntry, pool: &bitcoin_rs_mempool::Mempool) -> serde_json::Value {
    let txid = entry.tx.compute_txid();
    let mut depends = Vec::new();
    for input in &entry.tx.input {
        let prev_txid = input.previous_output.txid;
        if pool.by_txid.contains_key(&prev_txid) {
            depends.push(prev_txid.to_string());
        }
    }
    depends.sort();
    depends.dedup();

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

    serde_json_value!({
        "vsize": entry.vsize,
        "weight": u64::from(entry.vsize).saturating_mul(4),
        "time": entry.time,
        "height": entry.height,
        "descendantcount": 1,
        "descendantsize": entry.descendant_size,
        "ancestorcount": 1,
        "ancestorsize": entry.ancestor_size,
        "wtxid": entry.tx.compute_wtxid().to_string(),
        "fees": {
            "base": sats_to_btc(entry.fee),
            "modified": sats_to_btc(entry.fee),
            "ancestor": sats_to_btc(entry.ancestor_fee),
            "descendant": sats_to_btc(entry.descendant_fee)
        },
        "depends": depends,
        "spentby": spentby,
        "bip125-replaceable": false,
        "unbroadcast": false
    })
}

fn sats_to_btc(sats: u64) -> f64 {
    bitcoin::Amount::from_sat(sats).to_btc()
}

// TODO(refactor): share fee-unit helpers via handlers::common.
fn sat_per_kvb_to_btc(sat: u64) -> f64 {
    if let Ok(small) = u32::try_from(sat) {
        f64::from(small) / 100_000_000.0_f64
    } else {
        f64::from(u32::MAX) / 100_000_000.0_f64
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use alloc::vec::Vec;

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
    fn getrawmempool_verbose_sequence_flag_flattens_response() {
        let ctx = Arc::new(Context::new());
        let handler = crate::Handler::new(Arc::clone(&ctx));
        let result = handler
            .dispatch("getrawmempool", &json!([true, true]))
            .unwrap_or_else(|err| panic!("getrawmempool failed: {err}"));
        let Some(seq) = result
            .get("mempool_sequence")
            .and_then(JsonValueTrait::as_u64)
        else {
            panic!("mempool_sequence missing: {result:?}");
        };
        assert_eq!(seq, 0);
        assert!(
            result.get("txids").is_none(),
            "verbose response must not use txids wrapper: {result:?}"
        );
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
