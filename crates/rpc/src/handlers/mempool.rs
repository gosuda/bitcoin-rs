use alloc::borrow::Cow;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use bitcoin::hex::DisplayHex as _;
use bitcoin_rs_mempool::MempoolEntry;
use bitcoin_rs_primitives::{OutPoint, consensus_bytes};
use sonic_rs::{JsonContainerTrait, JsonValueTrait, Value};

use crate::context::Context;
use crate::convert::{i64_saturated, sat_to_btc, signed_sat_to_btc, typed_to_sonic};
use crate::error::RpcError;
use crate::handlers::{optional_bool, parse_txid, required_str};
use corepc_types::v31;

pub(crate) fn getmempoolinfo(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    crate::handlers::ensure_no_params(params)?;
    let pool = ctx.mempool.gateway.read();
    let policy = pool.policy_snapshot();
    let stats = pool.stats();
    let maxmempool = pool.limits.max_total_bytes;
    let live_min_relay_sat_per_kvb = pool.min_relay_fee_sat_per_kvb();
    let mempool_min_fee_sat_per_kvb =
        pool.min_fee_sat_per_kvb(bitcoin_rs_primitives::unix_time_secs());
    let info = v31::GetMempoolInfo {
        loaded: true,
        size: i64_saturated(stats.txs),
        bytes: i64_saturated(stats.bytes),
        usage: i64_saturated(pool.dynamic_memory_usage()),
        total_fee: sat_to_btc(stats.total_fee),
        max_mempool: i64_saturated(maxmempool),
        mempool_min_fee: sat_to_btc(mempool_min_fee_sat_per_kvb),
        min_relay_tx_fee: sat_to_btc(live_min_relay_sat_per_kvb),
        incremental_relay_fee: sat_to_btc(policy.incremental_relay_fee_sat_per_kvb),
        unbroadcast_count: i64_saturated(
            u64::try_from(
                pool.iter_entries()
                    .filter(|entry| entry.unbroadcast)
                    .count(),
            )
            .unwrap_or(u64::MAX),
        ),
        full_rbf: policy.full_rbf,
        permit_bare_multisig: policy.permit_bare_multisig,
        max_data_carrier_size: policy.max_data_carrier_size(),
        limit_cluster_count: i64::from(policy.cluster_count),
        limit_cluster_size: i64_saturated(policy.cluster_size_vbytes),
        optimal: policy.optimal,
    };
    drop(pool);
    typed_to_sonic(&info)
}

pub(crate) fn getmempoolentry(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let txid = parse_txid(required_str(params, 0, "txid is required")?, "txid")?;
    let response = {
        let pool = ctx.mempool.gateway.read();
        let entry = pool
            .entry_by_txid(&txid)
            .ok_or(RpcError::NotFound("transaction not in mempool"))?;
        v31::GetMempoolEntry(mempool_entry_typed(entry, &pool))
    };
    typed_to_sonic(&response)
}

/// Resolve all requested outpoints against one mempool generation. Copy only
/// transaction references while locked; hex encoding and JSON serialization
/// happen after the guard is released.
pub(crate) fn gettxspendingprevout(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let bound = spending_prevout_arguments(params)?;
    let array = super::params_array(bound.as_ref())?;
    super::ensure_at_most_params(bound.as_ref(), 2)?;
    if params.is_object()
        && params.get("outputs").is_none()
        && params
            .get("args")
            .and_then(JsonContainerTrait::as_array)
            .is_none_or(sonic_rs::Array::is_empty)
    {
        return Err(RpcError::InvalidParams("outputs is required"));
    }
    let outputs = array
        .first()
        .ok_or(RpcError::InvalidParams("outputs is required"))?;
    let options = array.get(1).cloned().unwrap_or_default();
    if !outputs.is_array() && !options.is_null() && !options.is_object() {
        return Err(RpcError::InvalidType(format!(
            "Wrong type passed:\n{{\n    \"Position 1 (outputs)\": \"JSON value of type {} is not of expected type array\",\n    \"Position 2 (options)\": \"JSON value of type {} is not of expected type object\"\n}}",
            super::json_type_name(outputs),
            super::json_type_name(&options),
        )));
    }
    let outputs = outputs
        .as_array()
        .ok_or_else(|| super::wrong_type(1, "outputs", outputs, "array"))?;
    if !options.is_null() && !options.is_object() {
        return Err(super::wrong_type(2, "options", &options, "object"));
    }
    if outputs.is_empty() {
        return Err(RpcError::InvalidParameter(
            "Invalid parameter, outputs are missing".to_owned(),
        ));
    }
    check_prevout_fields(
        &options,
        &[("mempool_only", "bool"), ("return_spending_tx", "bool")],
        true,
    )?;
    let option = |key, default| {
        options.get(key).map_or(Ok(default), |value| {
            value
                .as_bool()
                .ok_or_else(|| super::wrong_type_plain(value, "bool"))
        })
    };
    let mempool_only = option("mempool_only", true)?;
    let return_spending_tx = option("return_spending_tx", false)?;
    let prevouts = outputs
        .iter()
        .map(|output| {
            if !output.is_object() {
                return Err(super::wrong_type_plain(output, "object"));
            }
            check_prevout_fields(output, &[("txid", "string"), ("vout", "number")], false)?;
            let txid_text = output["txid"]
                .as_str()
                .ok_or_else(|| RpcError::InvalidType("Missing txid".to_owned()))?;
            let txid = parse_txid(txid_text, "txid")?;
            let index = output["vout"]
                .as_i64()
                .and_then(|n| i32::try_from(n).ok())
                .ok_or_else(|| RpcError::Misc("JSON integer out of range".to_owned()))?;
            let vout = u32::try_from(index).map_err(|_| {
                RpcError::InvalidParameter("Invalid parameter, vout cannot be negative".to_owned())
            })?;
            Ok((OutPoint::new(txid, vout), txid_text))
        })
        .collect::<Result<Vec<_>, RpcError>>()?;
    let spenders = {
        let pool = ctx.mempool.gateway.read();
        prevouts
            .iter()
            .map(|(outpoint, _)| {
                pool.outpoint_spender(*outpoint)
                    .map(|spender| {
                        spender.map(|spender| (spender.entry.txid, Arc::clone(&spender.entry.tx)))
                    })
                    .map_err(|error| RpcError::Internal(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?
    };
    let rows = prevouts.into_iter().zip(spenders).map(|((outpoint, txid), spender)| {
        let vout = outpoint.vout;
        if !mempool_only && spender.is_none() {
            return Err(RpcError::Misc(format!(
                "No spending tx for the outpoint {}:{} in mempool, and txospenderindex is unavailable.",
                outpoint.txid, vout,
            )));
        }
        Ok(v31::GetTxSpendingPrevoutItem {
            txid: txid.to_owned(),
            vout: outpoint.vout,
            spending_txid: spender.as_ref().map(|(txid, _)| txid.to_string()),
            spending_tx: spender.as_ref().filter(|_| return_spending_tx)
                .map(|(_, tx)| consensus_bytes(tx.as_ref()).to_lower_hex_string()),
            block_hash: None,
        })
    }).collect::<Result<Vec<_>, _>>()?;
    typed_to_sonic(&v31::GetTxSpendingPrevout(rows))
}

/// Core's strict object check validates declared fields before unknown keys.
fn check_prevout_fields(
    value: &Value,
    fields: &[(&str, &str)],
    allow_null: bool,
) -> Result<(), RpcError> {
    for &(key, expected) in fields {
        let field = value.get(key);
        if field.is_none_or(JsonValueTrait::is_null) {
            if allow_null {
                continue;
            }
            return Err(RpcError::InvalidType(format!("Missing {key}")));
        }
        if let Some(field) = field {
            let actual = super::json_type_name(field);
            if actual != expected {
                return Err(RpcError::InvalidType(format!(
                    "JSON value of type {actual} for field {key} is not of expected type {expected}",
                )));
            }
        }
    }
    if let Some(object) = value.as_object() {
        for (key, _) in object {
            if !fields.iter().any(|(name, _)| *name == key) {
                return Err(RpcError::InvalidType(format!("Unexpected key {key}")));
            }
        }
    }
    Ok(())
}

/// Fold this method's named-only option keys before ordinary argument binding.
fn spending_prevout_arguments(params: &Value) -> Result<Cow<'_, Value>, RpcError> {
    let option_names = ["mempool_only", "return_spending_tx"];
    if !params.is_object() || !option_names.iter().any(|name| params.get(*name).is_some()) {
        return super::bind_named_params(params, &["outputs", "options"]);
    }
    let object = params
        .as_object()
        .ok_or(RpcError::InvalidParams("params must be an object"))?;
    super::ensure_unique_named_params(object)?;
    if params.get("options").is_some() {
        for key in option_names {
            if params.get(key).is_some() {
                return Err(RpcError::InvalidParameter(format!(
                    "Parameter options conflicts with parameter {key}"
                )));
            }
        }
    }
    let mut normalized = sonic_rs::Object::new();
    let mut options = sonic_rs::Object::new();
    for (key, value) in object {
        if option_names.contains(&key) {
            options.insert(key, value.clone());
        } else {
            normalized.insert(key, value.clone());
        }
    }
    normalized.insert("options", Value::from(options));
    let normalized = Value::from(normalized);
    super::bind_named_params(&normalized, &["outputs", "options"])
        .map(|bound| Cow::Owned(bound.into_owned()))
}

pub(crate) fn getrawmempool(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let verbose = optional_bool(params, 0, false)?;
    let include_sequence = optional_bool(params, 1, false)?;
    if verbose && include_sequence {
        return Err(RpcError::InvalidParams(
            "Verbose results cannot contain mempool sequence values.",
        ));
    }
    let pool = ctx.mempool.gateway.read();
    if verbose {
        let response = v31::GetRawMempoolVerbose(mempool_entries_typed(pool.iter_entries(), &pool));
        drop(pool);
        return typed_to_sonic(&response);
    }

    let txids = pool.iter_txids();
    let sequence = pool.sequence_number();
    drop(pool);
    let txids = txids
        .into_iter()
        .map(|txid| txid.to_string())
        .collect::<Vec<_>>();
    if include_sequence {
        return typed_to_sonic(&v31::GetRawMempoolSequence {
            txids,
            mempool_sequence: sequence,
        });
    }
    typed_to_sonic(&v31::GetRawMempool(txids))
}

pub(crate) fn getmempoolancestors(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let txid = parse_txid(required_str(params, 0, "txid is required")?, "txid")?;
    let verbose = optional_bool(params, 1, false)?;
    let txids = {
        let pool = ctx.mempool.gateway.read();
        let Some(id) = pool.entry_id_by_txid(&txid) else {
            return Err(RpcError::NotFound("transaction not in mempool"));
        };
        let related_ids = pool.ancestor_ids_for_entry(id);
        if verbose {
            let response = v31::GetMempoolAncestorsVerbose(mempool_entries_typed(
                related_ids.iter().filter_map(|id| pool.entry(*id)),
                &pool,
            ));
            drop(pool);
            return typed_to_sonic(&response);
        }
        related_ids
            .iter()
            .filter_map(|id| pool.entry(*id))
            .map(|entry| entry.txid)
            .collect::<Vec<_>>()
    };
    let names = txids.into_iter().map(|txid| txid.to_string()).collect();
    typed_to_sonic(&v31::GetMempoolAncestors(names))
}

pub(crate) fn getmempooldescendants(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let txid = parse_txid(required_str(params, 0, "txid is required")?, "txid")?;
    let verbose = optional_bool(params, 1, false)?;
    let txids = {
        let pool = ctx.mempool.gateway.read();
        let Some(id) = pool.entry_id_by_txid(&txid) else {
            return Err(RpcError::NotFound("transaction not in mempool"));
        };
        let related_ids = pool.descendant_ids_for_entry(id);
        if verbose {
            let response = v31::GetMempoolDescendantsVerbose(mempool_entries_typed(
                related_ids.iter().filter_map(|id| pool.entry(*id)),
                &pool,
            ));
            drop(pool);
            return typed_to_sonic(&response);
        }
        related_ids
            .iter()
            .filter_map(|id| pool.entry(*id))
            .map(|entry| entry.txid)
            .collect::<Vec<_>>()
    };
    let names = txids.into_iter().map(|txid| txid.to_string()).collect();
    typed_to_sonic(&v31::GetMempoolDescendants(names))
}

fn mempool_entry_typed(
    entry: &MempoolEntry,
    pool: &bitcoin_rs_mempool::Mempool,
) -> v31::MempoolEntry {
    let mut depends = entry
        .tx
        .inputs
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
    let (descendant_count, ancestor_count) = entry_id.map_or((1, 1), |id| {
        (
            pool.descendant_count_inclusive(id),
            pool.ancestor_count_inclusive(id),
        )
    });

    let fees = v31::MempoolEntryFees {
        base: sat_to_btc(entry.fee),
        modified: signed_sat_to_btc(entry.modified_fee()),
        ancestor: signed_sat_to_btc(i128::from(entry.ancestor_fee) + entry.ancestor_fee_delta),
        descendant: signed_sat_to_btc(
            i128::from(entry.descendant_fee) + entry.descendant_fee_delta,
        ),
        chunk: sat_to_btc(entry.fee),
    };
    v31::MempoolEntry {
        vsize: i64_saturated(u64::from(entry.vsize)),
        weight: i64_saturated(entry.weight),
        time: i64_saturated(entry.time),
        height: i64::from(entry.height),
        descendant_count: i64::from(descendant_count),
        descendant_size: i64_saturated(entry.descendant_size),
        ancestor_count: i64::from(ancestor_count),
        ancestor_size: i64_saturated(entry.ancestor_size),
        chunk_weight: i64_saturated(entry.weight),
        wtxid: entry.wtxid.to_string(),
        fees,
        depends,
        spent_by: spentby,
        bip125_replaceable: entry.is_replaceable(),
        unbroadcast: entry.unbroadcast,
    }
}

fn mempool_entries_typed<'a>(
    entries: impl Iterator<Item = &'a MempoolEntry>,
    pool: &bitcoin_rs_mempool::Mempool,
) -> BTreeMap<String, v31::MempoolEntry> {
    entries
        .map(|entry| (entry.txid.to_string(), mempool_entry_typed(entry, pool)))
        .collect()
}

#[cfg(test)]
mod mempoolminfee_pressure_tests {
    use std::sync::Arc;

    use super::*;
    use sonic_rs::JsonValueTrait;
    use sonic_rs::json;

    #[test]
    fn mempoolminfee_equals_minrelay_when_pool_below_pressure() {
        let ctx = Arc::new(Context::new());
        let value =
            getmempoolinfo(&ctx, &json!([])).unwrap_or_else(|err| panic!("getmempoolinfo: {err}"));
        let Some(mempool_min) = value.get("mempoolminfee").and_then(JsonValueTrait::as_f64) else {
            panic!("mempoolminfee missing");
        };
        let Some(min_relay) = value.get("minrelaytxfee").and_then(JsonValueTrait::as_f64) else {
            panic!("minrelaytxfee missing");
        };
        assert!((mempool_min - min_relay).abs() < 1e-9);
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests;

#[cfg(test)]
mod usage_wiring_tests {
    use alloc::sync::Arc;

    use bitcoin_rs_mempool::MempoolEntry;
    use bitcoin_rs_primitives::{
        Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
    };
    use sonic_rs::{JsonValueTrait, json};

    use super::*;

    #[test]
    fn getmempoolinfo_usage_is_the_pools_memory_not_its_vsize_sum() {
        let ctx = Arc::new(Context::new());
        {
            let mut pool = ctx.mempool.gateway.pool().write();
            for tag in 0_u8..4 {
                let tx = Tx {
                    version: 2,
                    lock_time: LockTime::ZERO,
                    inputs: vec![TxIn {
                        previous_output: OutPoint::new(
                            Txid::from(Hash256::from_le_bytes(&[tag; 32])),
                            0,
                        ),
                        script_sig: Script::new(),
                        sequence: Sequence::MAX,
                        witness: Witness::new(),
                    }],
                    outputs: vec![TxOut {
                        value: Amount::from_sat(10_000),
                        script_pubkey: vec![0x51; 128].into(),
                    }],
                };
                let entry = MempoolEntry::new(Arc::new(tx), 100, 10_000, 1, 7, 0);
                let Ok(_id) = pool.insert_entry(entry) else {
                    panic!("fixture insert failed");
                };
            }
        }

        let value =
            getmempoolinfo(&ctx, &json!([])).unwrap_or_else(|err| panic!("getmempoolinfo: {err}"));
        let Some(bytes) = value.get("bytes").and_then(JsonValueTrait::as_u64) else {
            panic!("bytes missing: {value:?}");
        };
        let Some(usage) = value.get("usage").and_then(JsonValueTrait::as_u64) else {
            panic!("usage missing: {value:?}");
        };

        assert!(bytes > 0, "the fixture must hold transactions");
        assert_ne!(
            usage, bytes,
            "`usage` was literally `bytes`; that is the defect"
        );
        assert!(usage > bytes, "{usage} vs {bytes}");
    }
}

#[cfg(test)]
mod spentby_tests {
    use alloc::sync::Arc;
    use alloc::vec::Vec;

    use bitcoin_rs_mempool::MempoolEntry;
    use bitcoin_rs_primitives::{
        Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
    };
    use sonic_rs::json;

    use super::*;

    fn tx_with(inputs: &[OutPoint], outputs: u32, tag: u64) -> Tx {
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: inputs
                .iter()
                .map(|previous_output| TxIn {
                    previous_output: *previous_output,
                    script_sig: Script::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                })
                .collect(),
            outputs: (0..outputs)
                .map(|vout| TxOut {
                    value: Amount::from_sat(
                        10_000_u64
                            .saturating_add(u64::from(vout))
                            .saturating_add(tag.saturating_mul(1_000)),
                    ),
                    script_pubkey: vec![0x51].into(),
                })
                .collect(),
        }
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "fixture and RPC failures identify the broken boundary"
    )]
    fn gettxspendingprevout_projects_queries_and_removal_from_the_existing_index() {
        let (ctx, root, _) = graph_ctx();
        let handler = crate::Handler::new(Arc::clone(&ctx));
        let outputs = json!([
            {"txid": root.to_string().to_uppercase(), "vout": 2},
            {"txid": root.to_string(), "vout": 0},
            {"txid": root.to_string(), "vout": 3},
            {"txid": root.to_string().to_uppercase(), "vout": 2},
        ]);
        let answer = handler
            .dispatch("gettxspendingprevout", &json!([outputs]))
            .expect("spending query");
        assert_eq!(
            answer[0], answer[3],
            "duplicate input remains a duplicate row"
        );
        assert_eq!(
            answer[0]["txid"], outputs[0]["txid"],
            "preserve caller spelling"
        );
        assert_eq!(
            answer[2], outputs[2],
            "absent spender omits optional fields"
        );
        let pooled_spender = ctx
            .mempool
            .gateway
            .read()
            .outpoint_spender(OutPoint::new(root, 2))
            .expect("consistent index")
            .expect("child b")
            .entry
            .txid;
        assert_eq!(answer[0]["spendingtxid"], json!(pooled_spender.to_string()));
        ctx.mempool
            .gateway
            .pool()
            .write()
            .remove_for_reorg(&[pooled_spender]);
        let after = handler
            .dispatch("gettxspendingprevout", &json!([outputs]))
            .expect("after removal");
        assert_eq!(after[0], outputs[0]);
        assert_eq!(after[1], answer[1], "other spender remains resident");
        assert_eq!(after[3], outputs[3]);
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "a valid count here would violate the RPC contract"
    )]
    fn gettxspendingprevout_rejects_argument_count_with_local_shape_errors() {
        let handler = crate::Handler::new(Arc::new(Context::new()));
        for params in [
            json!([]),
            json!([[], {}, false]),
            json!({}),
            json!({"args": [[], {}, false]}),
        ] {
            assert_eq!(
                handler
                    .dispatch("gettxspendingprevout", &params)
                    .expect_err("invalid argument count")
                    .code(),
                RpcError::INVALID_PARAMS
            );
        }
    }

    fn graph_ctx() -> (Arc<Context>, Txid, Vec<String>) {
        let confirmed = OutPoint::new(Txid(Hash256::from_le_bytes(&[7_u8; 32])), 0);
        let root = tx_with(&[confirmed], 3, 1);
        let root_txid = root.txid();
        let child_a = tx_with(&[OutPoint::new(root_txid, 0)], 1, 2);
        let child_a_txid = child_a.txid();
        let child_b = tx_with(
            &[OutPoint::new(root_txid, 1), OutPoint::new(root_txid, 2)],
            1,
            3,
        );
        let child_b_txid = child_b.txid();
        let child_c = tx_with(&[OutPoint::new(child_a_txid, 0)], 1, 4);
        let loner = tx_with(
            &[OutPoint::new(Txid(Hash256::from_le_bytes(&[9_u8; 32])), 0)],
            1,
            5,
        );

        let root_spenders = if child_a.txid() > child_b.txid() {
            [child_a, child_b]
        } else {
            [child_b, child_a]
        };
        let [first_spender, second_spender] = root_spenders;

        let ctx = Arc::new(Context::new());
        {
            let mut pool = ctx.mempool.gateway.pool().write();
            for tx in [root, first_spender, second_spender, child_c, loner] {
                let entry = MempoolEntry::new(Arc::new(tx), 100, 10_000, 1, 7, 0);
                let Ok(_id) = pool.insert_entry(entry) else {
                    panic!("mempool insert failed while building the fixture");
                };
            }
        }
        let mut expected = [child_a_txid, child_b_txid]
            .map(|txid| txid.to_string())
            .to_vec();
        expected.sort();
        (ctx, root_txid, expected)
    }

    fn rendered_spentby(value: &sonic_rs::Value) -> Vec<String> {
        let Some(array) = value.get("spentby").and_then(|spentby| spentby.as_array()) else {
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
    fn getmempoolentry_reports_every_spender_of_the_root() {
        let (ctx, root_txid, expected) = graph_ctx();
        let handler = crate::Handler::new(Arc::clone(&ctx));
        let result = handler
            .dispatch("getmempoolentry", &json!([root_txid.to_string()]))
            .unwrap_or_else(|err| panic!("getmempoolentry failed: {err}"));
        let rendered = sonic_rs::to_string(&result)
            .unwrap_or_else(|err| panic!("re-encoding the response failed: {err}"));
        let rendered: sonic_rs::Value = sonic_rs::from_str(&rendered)
            .unwrap_or_else(|err| panic!("re-parsing the response failed: {err}"));
        assert_eq!(rendered_spentby(&rendered), expected);
    }
}
