use alloc::sync::Arc;
use core::str::FromStr as _;
use hashbrown::HashSet;

use bitcoin::consensus::encode::serialize as bitcoin_serialize;
use bitcoin::hashes::Hash as _;
use bitcoin::hex::{DisplayHex as _, FromHex as _};
use bitcoin::merkle_tree::MerkleBlock;
use bitcoin_rs_mempool::standardness::AcceptanceRejectReason;
use bitcoin_rs_mempool::{LocalOrigin, SubmitError};
use bitcoin_rs_primitives::{
    Amount, Block as NativeBlock, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut,
    Txid, Witness, consensus_bytes, deserialize as native_deserialize, unix_time_secs,
};
use bitcoin_rs_script::{opcode, push_data};
use miniscript::psbt::PsbtExt as _;
use sonic_rs::{JsonContainerTrait as _, JsonValueMutTrait as _, JsonValueTrait, Value, json};

use crate::context::{AppliedView, Context};
use crate::convert::{self, sat_to_btc, typed_to_sonic, typed_to_sonic_omitting_nulls};
use crate::error::RpcError;
use crate::handlers::{optional_bool, params_array, parse_txid, required_str, required_u64};
use bitcoin_rs_index::block_log::BlockRecord;
use corepc_types::v31;

pub(crate) mod submit_package;

/// A non-hex string is a correctly typed but unacceptable value, so it
/// answers Bitcoin Core's `RPC_INVALID_PARAMETER` (-8) class.
fn hex_decode(hex: &str) -> Result<Vec<u8>, RpcError> {
    Vec::<u8>::from_hex(hex).map_err(|error| match error {
        bitcoin::hex::HexToBytesError::OddLengthString(_) => {
            RpcError::InvalidParameter("hex string must have even length".to_owned())
        }
        bitcoin::hex::HexToBytesError::InvalidChar(_) => {
            RpcError::InvalidParameter("invalid hex character".to_owned())
        }
    })
}

/// Builds Bitcoin Core 31.1's `-8` message for a malformed block-hash
/// parameter.
fn block_hash_param_error(value: &str, label: &str) -> RpcError {
    if value.len() != 64 {
        return RpcError::InvalidParameter(format!(
            "{label} must be of length 64 (not {}, for '{value}')",
            value.len()
        ));
    }
    RpcError::InvalidParameter(format!(
        "{label} must be hexadecimal string (not '{value}')"
    ))
}

pub(crate) fn getrawtransaction(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let txid = parse_txid(required_str(params, 0, "txid is required")?, "parameter 1")?;
    let verbose = raw_transaction_verbosity(params)?;
    let view = ctx.chain.applied_view();
    let blockhash = params_array(params)?
        .get(2)
        .filter(|value| !value.is_null())
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| RpcError::InvalidType("blockhash must be a string".to_owned()))
                .and_then(|hash| {
                    Hash256::from_str(hash).map_err(|_| block_hash_param_error(hash, "parameter 3"))
                })
        })
        .transpose()?;

    if let Some(hash) = blockhash {
        let record = if verbose == 2 && ctx.chain.block_undo_source.is_some() {
            ctx.chain.header_record(hash)
        } else {
            ctx.chain.block_by_hash(hash)
        }
        .ok_or(RpcError::NotFound("block not found"))?;
        if verbose == 2 {
            return raw_transaction_with_spends(ctx, txid, &record, &view, true);
        }
        let block = load_block(ctx, &record)?;
        let tx = block
            .txs
            .iter()
            .find(|tx| tx.txid() == txid)
            .ok_or(RpcError::NotFound("transaction not in specified block"))?;
        return render_raw_transaction(ctx, tx, verbose, Some(&record), true, &view, None);
    }

    let pooled_tx = {
        let pool = ctx.mempool.gateway.read();
        pool.entry_by_txid(&txid).map(|entry| Arc::clone(&entry.tx))
    };
    if let Some(tx) = pooled_tx {
        return render_raw_transaction(ctx, tx.as_ref(), verbose, None, false, &view, None);
    }
    if let Some(derived_index) = ctx.indexes.derived_index.as_ref() {
        let tx = derived_index.transaction(&txid).map_err(RpcError::from)?;
        if let Some(tx) = tx {
            let record = derived_index
                .transaction_height(&txid)
                .map_err(RpcError::from)?
                .and_then(|height| {
                    if verbose == 2 && ctx.chain.block_undo_source.is_some() {
                        ctx.chain
                            .block_hash_at_height_in_view(&view, height)
                            .and_then(|hash| ctx.chain.header_record(hash))
                    } else {
                        ctx.chain.block_by_height_in_view(&view, height)
                    }
                });
            if verbose == 2 && !tx.is_coinbase() {
                let record = record.as_ref().ok_or_else(|| {
                    RpcError::Misc("transaction block changed during the query; retry".to_owned())
                })?;
                return raw_transaction_with_spends(ctx, txid, record, &view, false);
            }
            return render_raw_transaction(ctx, &tx, verbose, record.as_ref(), false, &view, None);
        }
    }

    Err(RpcError::NotFound("transaction not found"))
}

fn raw_transaction_verbosity(params: &Value) -> Result<u64, RpcError> {
    let Some(value) = params_array(params)?.get(1) else {
        return Ok(0);
    };
    if value.is_null() {
        return Ok(0);
    }
    if let Some(verbose) = value.as_bool() {
        return Ok(u64::from(verbose));
    }
    match value.as_u64() {
        Some(verbosity @ 0..=2) => Ok(verbosity),
        Some(_) => Err(RpcError::InvalidParams("verbosity must be 0, 1, or 2")),
        None => Err(RpcError::InvalidType(
            "verbosity must be a boolean or integer".to_owned(),
        )),
    }
}

fn load_block(ctx: &Context, record: &BlockRecord) -> Result<NativeBlock, RpcError> {
    let bytes = ctx
        .chain
        .block_body_bytes(record)
        .ok_or(RpcError::NotFound("block data pruned"))?;
    native_deserialize(&bytes)
        .map_err(|_| RpcError::Internal("stored block bytes failed decode".to_owned()))
}

fn render_raw_transaction(
    ctx: &Context,
    tx: &Tx,
    verbose: u64,
    record: Option<&BlockRecord>,
    explicit_block: bool,
    view: &AppliedView,
    coins: Option<&[bitcoin_rs_utxo::UtxoCoin]>,
) -> Result<Value, RpcError> {
    if verbose == 0 {
        return typed_to_sonic(&v31::GetRawTransaction(
            consensus_bytes(tx).to_lower_hex_string(),
        ));
    }
    let chain = record.map(|record| {
        let confirmations =
            super::chain::confirmations(ctx, view, record.hash.into(), record.height);
        crate::tx_render::TransactionChainContext {
            block_hash: record.hash,
            confirmations: confirmations.max(0),
            block_time: u64::from(record.time),
            in_active_chain: explicit_block.then_some(confirmations > 0),
        }
    });
    crate::tx_render::transaction_json_with_spends(
        tx,
        ctx.chain.chain_network,
        chain,
        coins,
        verbose == 2,
    )
}

fn raw_transaction_with_spends(
    ctx: &Context,
    txid: Txid,
    record: &BlockRecord,
    view: &AppliedView,
    explicit_block: bool,
) -> Result<Value, RpcError> {
    let _render = ctx
        .try_acquire_block_render()
        .ok_or_else(|| RpcError::Misc("too many concurrent full-block reads; retry".to_owned()))?;
    let (block, spent) = super::chain::block_with_spends(ctx, record, view, 2)?;
    let (index, tx) = block
        .txs
        .iter()
        .enumerate()
        .find(|(_, tx)| tx.txid() == txid)
        .ok_or_else(|| {
            if explicit_block {
                RpcError::NotFound("transaction not in specified block")
            } else {
                RpcError::Misc("transaction block changed during the query; retry".to_owned())
            }
        })?;
    render_raw_transaction(
        ctx,
        tx,
        2,
        Some(record),
        explicit_block,
        view,
        spent.as_ref().map(|rows| rows[index].as_slice()),
    )
}

pub(crate) fn gettxout(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let txid = parse_txid(required_str(params, 0, "txid is required")?, "txid")?;
    let vout = required_u64(params, 1, "vout is required")?;
    let vout_u32 = u32::try_from(vout).map_err(|_| RpcError::InvalidParams("vout exceeds u32"))?;
    let include_mempool = optional_bool(params, 2, true)?;

    let outpoint = OutPoint::new(txid, vout_u32);

    if include_mempool {
        let pooled_tx = {
            let pool = ctx.mempool.gateway.read();
            if pool.is_outpoint_spent(&outpoint) {
                return Ok(Value::new_null());
            }
            pool.entry_by_txid(&txid)
                .map(|entry| (Arc::clone(&entry.tx), ctx.chain.applied_hash()))
        };
        if let Some((tx, best_block)) = pooled_tx
            && let Ok(vout) = usize::try_from(vout_u32)
            && let Some(output) = tx.outputs.get(vout)
        {
            return txout_typed(ctx, output, 0, false, best_block);
        }
    }

    let Some((live, view)) = ctx.chain.with_stable_chainstate(|| {
        ctx.chain
            .utxo
            .get_entry(&outpoint)
            .map(|live| (live, ctx.chain.applied_view()))
    }) else {
        return Ok(Value::new_null());
    };
    let confirmations = view.height().saturating_sub(live.height).saturating_add(1);
    txout_typed(
        ctx,
        &live.txout,
        confirmations,
        live.coinbase,
        view.hash(ctx.chain.chain_network),
    )
}

fn txout_typed(
    ctx: &Context,
    output: &TxOut,
    confirmations: u32,
    coinbase: bool,
    best_block: Hash256,
) -> Result<Value, RpcError> {
    typed_to_sonic_omitting_nulls(&v31::GetTxOut {
        best_block: best_block.to_string(),
        confirmations,
        value: sat_to_btc(output.value.to_sat()),
        script_pubkey: convert::script_pub_key_typed(
            &output.script_pubkey,
            ctx.chain.chain_network,
        ),
        coinbase,
    })
}

pub(crate) fn gettxoutproof(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let array = params_array(params)?;
    let txids_value = array
        .first()
        .and_then(|value| value.as_array())
        .ok_or(RpcError::InvalidParams("txids must be an array"))?;
    if txids_value.is_empty() {
        return Err(RpcError::InvalidParams("txids are required"));
    }

    let mut wanted = hashbrown::HashSet::new();
    for value in txids_value {
        let Some(txid) = value.as_str() else {
            return Err(RpcError::InvalidType(
                "each txid must be a string".to_owned(),
            ));
        };
        wanted.insert(parse_txid(txid, "txid")?);
    }

    if let Some(hash_str) = array.get(1).and_then(JsonValueTrait::as_str) {
        let hash = Hash256::from_str(hash_str)
            .map_err(|_| block_hash_param_error(hash_str, "blockhash"))?;
        let Some(record) = ctx.chain.block_by_hash(hash) else {
            return Err(RpcError::NotFound("block not found"));
        };
        return proof_from_single_record(ctx, &record, &wanted);
    }

    if let Some(proof) = proof_via_index(ctx, &wanted) {
        return Ok(proof);
    }
    proof_from_block_log(ctx, &wanted)
}

fn proof_via_index(ctx: &Arc<Context>, wanted: &hashbrown::HashSet<Txid>) -> Option<Value> {
    let derived_index = ctx.indexes.derived_index.as_ref()?;
    for probe in wanted {
        let height = match derived_index.transaction_height(probe) {
            Ok(Some(height)) => height,
            Ok(None) => continue,
            Err(error) => {
                tracing::warn!(
                    txid = %probe,
                    %error,
                    "txindex lookup failed; answering from the block scan instead"
                );
                return None;
            }
        };
        let Some(record) = ctx.chain.block_by_height(height) else {
            continue;
        };
        if let Some(proof) = proof_from_record(ctx, &record, wanted) {
            return Some(proof);
        }
    }
    None
}

fn proof_from_single_record(
    ctx: &Arc<Context>,
    record: &bitcoin_rs_index::block_log::BlockRecord,
    wanted: &hashbrown::HashSet<Txid>,
) -> Result<Value, RpcError> {
    let Some(bytes) = ctx.chain.block_body_bytes(record) else {
        return Err(RpcError::NotFound("block data pruned"));
    };
    proof_from_body(&bytes, wanted)
        .ok_or(RpcError::NotFound("no block contains all requested txids"))
}

fn proof_from_block_log(
    ctx: &Arc<Context>,
    wanted: &hashbrown::HashSet<Txid>,
) -> Result<Value, RpcError> {
    let len = ctx.chain.blocks.read().len();
    let mut saw_pruned_block = false;
    let mut records_scanned: u64 = 0;
    let mut body_bytes_scanned: u64 = 0;
    for index in 0..len {
        let Some(record) = ctx.chain.blocks.read().get(index).cloned() else {
            break;
        };
        records_scanned += 1;
        let Some(bytes) = ctx.chain.block_body_bytes(&record) else {
            saw_pruned_block = true;
            continue;
        };
        body_bytes_scanned =
            body_bytes_scanned.saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        if let Some(proof) = proof_from_body(&bytes, wanted) {
            tracing::debug!(
                records_scanned,
                body_bytes_scanned,
                found = true,
                "gettxoutproof fallback scan"
            );
            return Ok(proof);
        }
    }
    tracing::debug!(
        records_scanned,
        body_bytes_scanned,
        found = false,
        saw_pruned_block,
        "gettxoutproof fallback scan"
    );

    if saw_pruned_block {
        Err(RpcError::NotFound("block data pruned"))
    } else {
        Err(RpcError::NotFound("no block contains all requested txids"))
    }
}

fn proof_from_record(
    ctx: &Arc<Context>,
    record: &bitcoin_rs_index::block_log::BlockRecord,
    wanted: &hashbrown::HashSet<Txid>,
) -> Option<Value> {
    let bytes = ctx.chain.block_body_bytes(record)?;
    proof_from_body(&bytes, wanted)
}

fn proof_from_body(bytes: &[u8], wanted: &hashbrown::HashSet<Txid>) -> Option<Value> {
    let block = native_deserialize::<NativeBlock>(bytes).ok()?;
    let block_txids = block
        .txs
        .iter()
        .map(Tx::txid)
        .collect::<hashbrown::HashSet<Txid>>();
    if !wanted.iter().all(|txid| block_txids.contains(txid)) {
        return None;
    }

    let bitcoin_block = bitcoin::consensus::encode::deserialize::<bitcoin::Block>(bytes).ok()?;
    let bitcoin_wanted: hashbrown::HashSet<bitcoin::Txid> = wanted
        .iter()
        .map(|txid| bitcoin::Txid::from_byte_array(*txid.as_bytes()))
        .collect();
    let merkle_block = MerkleBlock::from_block_with_predicate(&bitcoin_block, |txid| {
        bitcoin_wanted.contains(txid)
    });
    Some(json!(
        bitcoin_serialize(&merkle_block).to_lower_hex_string()
    ))
}

pub(crate) fn verifytxoutproof(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let proof_hex = required_str(params, 0, "proof is required")?;

    let bytes = hex_decode(proof_hex)?;
    let Ok(merkle_block) = bitcoin::consensus::encode::deserialize::<MerkleBlock>(&bytes) else {
        return typed_to_sonic(&v31::VerifyTxOutProof(Vec::new()));
    };

    let mut matched_txids = Vec::new();
    let mut indexes = Vec::new();
    if merkle_block
        .extract_matches(&mut matched_txids, &mut indexes)
        .is_err()
    {
        return typed_to_sonic(&v31::VerifyTxOutProof(Vec::new()));
    }

    let result = matched_txids
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    typed_to_sonic(&v31::VerifyTxOutProof(result))
}

/// Fee rate above which `sendrawtransaction` refuses by default, in sat/kvB.
/// Bitcoin Core's `DEFAULT_MAX_RAW_TX_FEE_RATE`, `COIN / 10` — 0.1 BTC per kvB.
use crate::context::DEFAULT_MAX_RAW_TX_FEE_RATE_SAT_PER_KVB;

pub(crate) fn sendrawtransaction(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let bound = super::bind_named_params(params, &["hexstring", "maxfeerate", "maxburnamount"])?;
    let params = bound.as_ref();
    super::ensure_at_most_params(params, 3)?;
    let raw = required_str(params, 0, "raw transaction is required")?;
    let max_feerate = send_max_feerate(params, 1)?;
    let max_burn = params_array(params)?
        .get(2)
        .filter(|value| !value.is_null())
        .map(parse_btc_amount)
        .transpose()?
        .unwrap_or(0);
    if max_burn > Amount::MAX_MONEY.to_sat() {
        return Err(RpcError::InvalidParameter(
            "maxburnamount is out of range".to_owned(),
        ));
    }
    let tx = decode_tx(
        raw,
        "TX decode failed. Make sure the tx has at least one input.".to_owned(),
    )?;
    for output in &tx.outputs {
        let script = output.script_pubkey.as_bytes();
        if (script.len() > bitcoin_rs_script::MAX_SCRIPT_SIZE
            || bitcoin_rs_script::is_op_return(script)
            || !bitcoin_rs_script::has_valid_ops(script))
            && output.value.to_sat() > max_burn
        {
            return Err(RpcError::TxVerifyError(
                "Unspendable output exceeds maximum configured by user (maxburnamount)".to_owned(),
            ));
        }
    }
    let txid = tx.txid();

    let _mutation = ctx
        .mempool
        .gateway
        .submit_local_transaction(
            Arc::new(tx),
            LocalOrigin::Rpc,
            max_feerate,
            unix_time_secs(),
            &ctx.chain.admission_chain(),
        )
        .map_err(submit_error_to_rpc_error)?;
    typed_to_sonic(&v31::SendRawTransaction(txid.to_string()))
}

#[derive(serde::Serialize)]
#[serde(untagged)]
enum AcceptanceRow {
    Complete(v31::MempoolAcceptance),
    Unfinished {
        txid: String,
        wtxid: String,
        #[serde(rename = "package-error", skip_serializing_if = "Option::is_none")]
        package_error: Option<String>,
    },
}

pub(crate) fn testmempoolaccept(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let array = params_array(params)?;
    let raw_txs = array
        .first()
        .and_then(|value| value.as_array())
        .ok_or(RpcError::InvalidParams("raw transaction array is required"))?;
    if raw_txs.is_empty() || raw_txs.len() > bitcoin_rs_mempool::standardness::MAX_PACKAGE_COUNT {
        return Err(RpcError::InvalidParams(
            "Array must contain between 1 and 25 transactions.",
        ));
    }
    let max_feerate = optional_max_feerate(params, 1)?;

    let mut txs = Vec::with_capacity(raw_txs.len());
    for raw in raw_txs {
        let Some(raw) = raw.as_str() else {
            return Err(RpcError::InvalidType(
                "raw transaction must be a string".to_owned(),
            ));
        };
        txs.push(decode_tx(
            raw,
            format!("TX decode failed: {raw} Make sure the tx has at least one input."),
        )?);
    }

    let facts = ctx
        .mempool
        .gateway
        .preview_transactions(&txs, max_feerate, &ctx.chain.admission_chain())
        .map_err(submit_error_to_rpc_error)?;

    let mut rows = Vec::with_capacity(facts.results.len());
    for fact in &facts.results {
        let Some(allowed) = fact.allowed else {
            rows.push(AcceptanceRow::Unfinished {
                txid: fact.txid.to_string(),
                wtxid: fact.wtxid.to_string(),
                package_error: facts.package_error.map(reject_reason_to_frozen_string),
            });
            continue;
        };
        let fees = if allowed {
            fact.base_fee.map(|fee| v31::MempoolAcceptanceFees {
                base: sat_to_btc(fee),
                effective_fee_rate: fact.effective_fee_rate.map(sat_to_btc),
                effective_includes: vec![fact.wtxid.to_string()],
            })
        } else {
            None
        };
        rows.push(AcceptanceRow::Complete(v31::MempoolAcceptance {
            txid: fact.txid.to_string(),
            wtxid: fact.wtxid.to_string(),
            allowed,
            vsize: allowed.then(|| i64::from(fact.vsize)),
            fees,
            reject_reason: fact.reject_reason.map(reject_reason_to_frozen_string),
            reject_details: None,
        }));
    }
    typed_to_sonic_omitting_nulls(&rows)
}

pub(crate) fn decoderawtransaction(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let bound = super::bind_named_params(params, &["hexstring"])?;
    let params = bound.as_ref();
    let raw = required_str(params, 0, "raw transaction is required")?;
    let tx = decode_tx(raw, "TX decode failed".to_owned())?;
    let mut value = crate::tx_render::transaction_json(&tx, ctx.chain.chain_network, None);
    if let Some(object) = value.as_object_mut() {
        object.remove(&"hex");
    }
    Ok(value)
}

/// with one warning each. Disabled (`-32603`) unless the node started
/// with `--compressed-transactions`.
pub(crate) fn compressrawtransaction(
    ctx: &Arc<Context>,
    params: &Value,
    cancellation: &bitcoin_rs_chain::LatchReader,
) -> Result<Value, RpcError> {
    if !ctx.compressed_transactions {
        return Err(RpcError::MethodDisabled(
            "compressrawtransaction is disabled; enable --compressed-transactions",
        ));
    }
    let bound = super::bind_named_params(params, &["hexstring", "compress_outpoints"])?;
    let params = bound.as_ref();
    let raw = required_str(params, 0, "raw transaction is required")?;
    if raw.len() > crate::compressed_tx::MAX_COMPRESSED_TX_BYTES * 2 {
        return Err(RpcError::InvalidParameter(
            "hex string exceeds the compressed transaction size limit".to_owned(),
        ));
    }
    let compress_outpoints = optional_bool(params, 1, true)?;
    let tx = decode_tx(raw, "TX decode failed".to_owned())?;
    ctx.chain.with_stable_chainstate(|| {
        let mut resolver = crate::context::RpcPrevoutResolver::new(ctx, cancellation.clone())?;
        let (compressed, warnings) = crate::compressed_tx::compress_transaction(
            &tx,
            &mut resolver,
            crate::compressed_tx::CompressOptions { compress_outpoints },
        )
        .map_err(RpcError::from)?;
        if cancellation.is_triggered() || !resolver.view_matches_current() {
            return Err(RpcError::Misc(
                "compressed transaction request cancelled or the applied tip moved; retry"
                    .to_owned(),
            ));
        }
        Ok(json!({
            "result": compressed.to_lower_hex_string(),
            "warnings": warnings,
        }))
    })
}

/// Disabled (`-32603`) unless the node started with
/// `--compressed-transactions`.
pub(crate) fn decompressrawtransaction(
    ctx: &Arc<Context>,
    params: &Value,
    cancellation: &bitcoin_rs_chain::LatchReader,
) -> Result<Value, RpcError> {
    if !ctx.compressed_transactions {
        return Err(RpcError::MethodDisabled(
            "decompressrawtransaction is disabled; enable --compressed-transactions",
        ));
    }
    let bound = super::bind_named_params(params, &["hexstring"])?;
    let params = bound.as_ref();
    let raw = required_str(params, 0, "compressed transaction is required")?;
    if raw.len() > crate::compressed_tx::MAX_COMPRESSED_TX_BYTES * 2 {
        return Err(RpcError::InvalidParameter(
            "hex string exceeds the compressed transaction size limit".to_owned(),
        ));
    }
    let bytes =
        hex_decode(raw).map_err(|_| RpcError::Deserialization("TX decode failed".to_owned()))?;
    let (plan, resolver) = ctx.chain.with_stable_chainstate(|| {
        let mut resolver = crate::context::RpcPrevoutResolver::new(ctx, cancellation.clone())?;
        let plan = crate::compressed_tx::decompress_prepare(&bytes, &mut resolver)
            .map_err(RpcError::from)?;
        Ok::<_, RpcError>((plan, resolver))
    })?;
    let tx = crate::compressed_tx::decompress_finalize(plan, &resolver).map_err(RpcError::from)?;
    ctx.chain.with_stable_chainstate(|| {
        if cancellation.is_triggered() || !resolver.view_matches_current() {
            return Err(RpcError::Misc(
                "compressed transaction request cancelled or the applied tip moved; retry"
                    .to_owned(),
            ));
        }
        Ok(json!(consensus_bytes(&tx).to_lower_hex_string()))
    })
}

const CREATE_TRANSACTION_ARGUMENTS: &[&str] = &["inputs", "outputs", "locktime", "replaceable"];

pub(crate) fn createrawtransaction(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let bound = super::bind_named_params(params, CREATE_TRANSACTION_ARGUMENTS)?;
    let params = bound.as_ref();
    super::ensure_at_most_params(params, CREATE_TRANSACTION_ARGUMENTS.len())?;
    let array = params_array(params)?;
    let inputs = array
        .first()
        .and_then(|value| value.as_array())
        .ok_or(RpcError::InvalidParams("inputs must be an array"))?;
    let outputs = array
        .get(1)
        .and_then(|value| value.as_object())
        .ok_or(RpcError::InvalidParams("outputs must be an object"))?;
    let locktime = match array.get(2) {
        None => 0_u32,
        Some(value) if value.is_null() => 0_u32,
        Some(value) => {
            let locktime = value
                .as_u64()
                .ok_or_else(|| RpcError::InvalidType("locktime must be an integer".to_owned()))?;
            u32::try_from(locktime).map_err(|_| RpcError::InvalidParams("locktime exceeds u32"))?
        }
    };
    let replaceable = optional_bool(params, 3, false)?;

    let default_sequence: u32 = if replaceable {
        0xFFFF_FFFD
    } else {
        0xFFFF_FFFF
    };

    let mut tx_inputs = Vec::with_capacity(inputs.len());
    let mut seen = HashSet::new();
    for input in inputs {
        let object = input
            .as_object()
            .ok_or_else(|| RpcError::InvalidType("input must be an object".to_owned()))?;
        let txid = parse_txid(
            object
                .get(&"txid")
                .and_then(JsonValueTrait::as_str)
                .ok_or(RpcError::InvalidParams("input txid is required"))?,
            "txid",
        )?;
        let vout = object
            .get(&"vout")
            .and_then(JsonValueTrait::as_u64)
            .ok_or(RpcError::InvalidParams("input vout is required"))?;
        let vout = u32::try_from(vout).map_err(|_| RpcError::InvalidParams("vout exceeds u32"))?;
        if !seen.insert((txid, vout)) {
            return Err(RpcError::InvalidParams("duplicate input specified"));
        }
        let sequence = match object.get(&"sequence") {
            None => default_sequence,
            Some(value) => {
                let sequence = value.as_u64().ok_or_else(|| {
                    RpcError::InvalidType("sequence must be an integer".to_owned())
                })?;
                u32::try_from(sequence)
                    .map_err(|_| RpcError::InvalidParams("sequence exceeds u32"))?
            }
        };
        tx_inputs.push(TxIn {
            previous_output: OutPoint::new(txid, vout),
            script_sig: Script::new(),
            sequence: Sequence::from_consensus(sequence),
            witness: Witness::new(),
        });
    }

    let network = convert::bitcoin_network(ctx.chain.chain_network);
    let mut tx_outputs = Vec::with_capacity(outputs.len());
    for (key, value) in outputs {
        if key == "data" {
            let data_hex = value.as_str().ok_or_else(|| {
                RpcError::InvalidType("data output must be a hex string".to_owned())
            })?;
            let data = hex_decode(data_hex)?;
            let mut script = vec![opcode::OP_RETURN];
            script.extend_from_slice(&push_data(&data));
            tx_outputs.push(TxOut {
                value: Amount::ZERO,
                script_pubkey: Script::from_bytes(script),
            });
            continue;
        }

        let address = bitcoin::Address::from_str(key)
            .map_err(|_| RpcError::InvalidParams("invalid Bitcoin address"))?
            .require_network(network)
            .map_err(|_| RpcError::InvalidParams("invalid Bitcoin address"))?;
        tx_outputs.push(TxOut {
            value: Amount::from_sat(parse_btc_amount(value)?),
            script_pubkey: Script::from_bytes(address.script_pubkey().as_bytes().to_vec()),
        });
    }

    let tx = Tx {
        version: 2,
        lock_time: LockTime::from_consensus(locktime),
        inputs: tx_inputs,
        outputs: tx_outputs,
    };
    typed_to_sonic(&v31::CreateRawTransaction(
        consensus_bytes(&tx).to_lower_hex_string(),
    ))
}

/// Deserialize a raw transaction hex string, reporting failures as Core's
/// `RPC_DESERIALIZATION_ERROR` (-22) with the method-specific message.
fn decode_tx(raw: &str, message: String) -> Result<Tx, RpcError> {
    let bytes = hex_decode(raw).map_err(|_| RpcError::Deserialization(message.clone()))?;
    native_deserialize(&bytes).map_err(|_| RpcError::Deserialization(message))
}

/// Converts a BTC-denominated JSON value (number or string) to satoshis using exact
/// decimal parsing, expanding e/E notation without floating point arithmetic and
/// rejecting signs other than optional positive, non-digits, more than 8 fractional
/// decimals, fractional satoshis, and overflow.
#[expect(
    clippy::too_many_lines,
    reason = "one amount parser keeps sign, exponent, mantissa, and scale checks in a single auditable sequence"
)]
fn sats_from_btc(value: &Value, message: &'static str) -> Result<u64, RpcError> {
    let text = if let Some(text) = value.as_str() {
        text.to_owned()
    } else if let Some(raw) = value.as_raw_number() {
        raw.as_str().to_owned()
    } else if value.is_number() {
        value.to_string()
    } else {
        return Err(RpcError::InvalidType(
            "amount must be a number or string".to_owned(),
        ));
    };

    let text = text.as_str();
    if text.is_empty() {
        return Err(RpcError::InvalidParams(message));
    }

    let text = if let Some(stripped) = text.strip_prefix('+') {
        stripped
    } else if text.starts_with('-') {
        return Err(RpcError::InvalidParams(message));
    } else {
        text
    };

    if text.is_empty() {
        return Err(RpcError::InvalidParams(message));
    }

    let (mantissa, exp) = if let Some(pos) = text.find(['e', 'E']) {
        let (m, e) = text.split_at(pos);
        let e_str = &e[1..];
        if m.is_empty() || e_str.is_empty() {
            return Err(RpcError::InvalidParams(message));
        }
        let (e_sign, e_digits) = if let Some(stripped) = e_str.strip_prefix('+') {
            (1_i32, stripped)
        } else if let Some(stripped) = e_str.strip_prefix('-') {
            (-1_i32, stripped)
        } else {
            (1_i32, e_str)
        };
        if e_digits.is_empty() || !e_digits.chars().all(|c| c.is_ascii_digit()) {
            return Err(RpcError::InvalidParams(message));
        }
        let exp_mag: i32 = e_digits
            .parse()
            .map_err(|_| RpcError::InvalidParams(message))?;
        (
            m,
            e_sign
                .checked_mul(exp_mag)
                .ok_or(RpcError::InvalidParams(message))?,
        )
    } else {
        (text, 0_i32)
    };

    let (int_part, frac_part) = if let Some(pos) = mantissa.find('.') {
        let (i, f) = mantissa.split_at(pos);
        let f = &f[1..];
        if i.is_empty() || f.is_empty() || f.contains('.') {
            return Err(RpcError::InvalidParams(message));
        }
        (i, f)
    } else {
        (mantissa, "")
    };

    if int_part.is_empty()
        || !int_part.chars().all(|c| c.is_ascii_digit())
        || !frac_part.chars().all(|c| c.is_ascii_digit())
    {
        return Err(RpcError::InvalidParams(message));
    }

    let mut digits = Vec::with_capacity(int_part.len() + frac_part.len());
    digits.extend_from_slice(int_part.as_bytes());
    digits.extend_from_slice(frac_part.as_bytes());

    if digits.iter().all(|&d| d == b'0') {
        return Ok(0);
    }

    while digits.last() == Some(&b'0') {
        digits.pop();
    }

    let initial_point =
        i32::try_from(int_part.len()).map_err(|_| RpcError::InvalidParams(message))?;
    let point = initial_point
        .checked_add(exp)
        .ok_or(RpcError::InvalidParams(message))?;

    let digits_len = i32::try_from(digits.len()).map_err(|_| RpcError::InvalidParams(message))?;
    let frac_digits = digits_len
        .checked_sub(point)
        .ok_or(RpcError::InvalidParams(message))?;
    if frac_digits > 8 {
        return Err(RpcError::InvalidParams(message));
    }

    let sat_point = point
        .checked_add(8)
        .ok_or(RpcError::InvalidParams(message))?;
    if sat_point < digits_len {
        return Err(RpcError::InvalidParams(message));
    }

    let trailing_zeros = sat_point
        .checked_sub(digits_len)
        .ok_or(RpcError::InvalidParams(message))?;
    if trailing_zeros > 20 {
        return Err(RpcError::InvalidParams(message));
    }

    let mut sats: u64 = 0;
    for &d in &digits {
        sats = sats
            .checked_mul(10)
            .and_then(|v| v.checked_add(u64::from(d - b'0')))
            .ok_or(RpcError::InvalidParams(message))?;
    }
    for _ in 0..trailing_zeros {
        sats = sats
            .checked_mul(10)
            .ok_or(RpcError::InvalidParams(message))?;
    }

    Ok(sats)
}

/// `sendrawtransaction`'s fee argument: Core's `maxfeerate` amount, or the
/// one pre-0.19 `allowhighfees` value that btcd's RPC client still emits.
fn send_max_feerate(params: &Value, index: usize) -> Result<Option<u64>, RpcError> {
    let legacy_default = params_array(params)?
        .get(index)
        .and_then(JsonValueTrait::as_bool)
        == Some(false);
    if legacy_default {
        Ok(Some(DEFAULT_MAX_RAW_TX_FEE_RATE_SAT_PER_KVB))
    } else {
        optional_max_feerate(params, index)
    }
}

fn optional_max_feerate(params: &Value, index: usize) -> Result<Option<u64>, RpcError> {
    let Some(value) = params_array(params)?.get(index) else {
        return Ok(Some(DEFAULT_MAX_RAW_TX_FEE_RATE_SAT_PER_KVB));
    };
    if value.is_null() {
        return Ok(Some(DEFAULT_MAX_RAW_TX_FEE_RATE_SAT_PER_KVB));
    }
    if !value.is_number() && !value.is_str() {
        return Err(RpcError::InvalidType(
            "maxfeerate must be a number".to_owned(),
        ));
    }
    if let Some(text) = value.as_str() {
        if text.starts_with('-') {
            return Err(RpcError::InvalidParams("maxfeerate must be non-negative"));
        }
    } else if let Some(raw) = value.as_raw_number() {
        if raw.as_str().starts_with('-') {
            return Err(RpcError::InvalidParams("maxfeerate must be non-negative"));
        }
    } else if let Some(f) = value.as_f64() {
        if f < 0.0 {
            return Err(RpcError::InvalidParams("maxfeerate must be non-negative"));
        }
    }
    let sats = sats_from_btc(value, "maxfeerate is out of range")?;
    if sats == 0 {
        return Ok(None);
    }
    if sats >= 100_000_000 {
        return Err(RpcError::InvalidParams(
            "Fee rates larger than or equal to 1BTC/kvB are not accepted",
        ));
    }
    Ok(Some(sats))
}

fn parse_btc_amount(value: &Value) -> Result<u64, RpcError> {
    sats_from_btc(value, "Invalid amount")
}

/// `MaxFeeExceeded` is a parameter error (`-32602`), pinned by the policy-contract
/// integration test.
///
/// All other admission rejections are transaction rejections (`-26`), matching Bitcoin
/// Core's `RPC_VERIFY_REJECTED` code. Both typed cluster-limit failures map to Core's
/// public `too-large-cluster` reason.
pub(crate) fn reject_reason_to_rpc_error(reason: AcceptanceRejectReason) -> RpcError {
    match reason {
        AcceptanceRejectReason::MaxFeeExceeded => RpcError::InvalidParams("max-fee-exceeded"),
        AcceptanceRejectReason::MissingInputs => {
            RpcError::TxVerifyError("bad-txns-inputs-missingorspent".to_owned())
        }
        other => RpcError::TxRejected(reject_reason_to_frozen_string(other)),
    }
}

fn submit_error_to_rpc_error(error: SubmitError) -> RpcError {
    match error {
        SubmitError::Policy(reason) => reject_reason_to_rpc_error(reason),
        SubmitError::Consensus => RpcError::TxRejected(error.to_string()),
        SubmitError::RetryExhausted => RpcError::Internal(error.to_string()),
    }
}

/// Cluster count and weight failures share Core's `too-large-cluster` reason;
/// other variants use the mempool owner's public policy reason.
fn reject_reason_to_frozen_string(reason: AcceptanceRejectReason) -> String {
    match reason {
        AcceptanceRejectReason::PackageLimit(
            bitcoin_rs_mempool::PolicyError::ClusterCountLimit
            | bitcoin_rs_mempool::PolicyError::ClusterSizeLimit,
        ) => "too-large-cluster".to_owned(),
        other => other.to_string(),
    }
}

pub(crate) fn finalizepsbt(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let raw = required_str(params, 0, "psbt is required")?;
    let extract = optional_bool(params, 1, true)?;
    let decoded =
        crate::base64::decode(raw).map_err(|()| RpcError::InvalidParams("invalid base64 PSBT"))?;
    let Ok(mut psbt) = bitcoin::psbt::Psbt::deserialize(&decoded) else {
        return Err(RpcError::InvalidParams("invalid base64 PSBT"));
    };
    let secp = bitcoin::secp256k1::Secp256k1::verification_only();
    let _incomplete = psbt.finalize_mut(&secp);
    let finalized_tx = if psbt.inputs.is_empty() {
        None
    } else {
        psbt.extract(&secp).ok()
    };
    let complete = finalized_tx.is_some();
    if extract && let Some(tx) = finalized_tx {
        let hex = bitcoin_serialize(&tx).to_lower_hex_string();
        typed_to_sonic(&v31::FinalizePsbt {
            psbt: None,
            hex: Some(hex),
            complete: true,
        })
    } else {
        let serialized = crate::base64::encode(&psbt.serialize());
        typed_to_sonic(&v31::FinalizePsbt {
            psbt: Some(serialized),
            hex: None,
            complete,
        })
    }
}

pub(crate) fn combinepsbt(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let array = params_array(params)?
        .first()
        .and_then(|value| value.as_array())
        .ok_or(RpcError::InvalidParams("psbts must be an array"))?;
    if array.is_empty() {
        return Err(RpcError::InvalidParams("psbts array must not be empty"));
    }

    let mut iter = array.iter();
    let Some(first_val) = iter.next() else {
        return Err(RpcError::InvalidParams("psbts array must not be empty"));
    };
    let Some(first_str) = first_val.as_str() else {
        return Err(RpcError::InvalidType(
            "each psbt must be a string".to_owned(),
        ));
    };
    let mut psbt = bitcoin::psbt::Psbt::deserialize(
        &crate::base64::decode(first_str)
            .map_err(|()| RpcError::InvalidParams("invalid base64 PSBT"))?,
    )
    .map_err(|_| RpcError::InvalidParams("invalid base64 PSBT"))?;

    for value in iter {
        let Some(s) = value.as_str() else {
            return Err(RpcError::InvalidType(
                "each psbt must be a string".to_owned(),
            ));
        };
        let other = bitcoin::psbt::Psbt::deserialize(
            &crate::base64::decode(s)
                .map_err(|()| RpcError::InvalidParams("invalid base64 PSBT"))?,
        )
        .map_err(|_| RpcError::InvalidParams("invalid base64 PSBT"))?;
        psbt.combine(other)
            .map_err(|err| RpcError::Internal(format!("combine failed: {err}")))?;
    }

    typed_to_sonic(&v31::CombinePsbt(crate::base64::encode(&psbt.serialize())))
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests;

#[cfg(test)]
mod gettxout_via_utxo_tests {
    use super::*;

    #[test]
    fn gettxout_returns_null_for_unknown_outpoint() {
        let ctx = Arc::new(Context::new());
        let txid_hex = "a".repeat(64);
        let params = json!([txid_hex.as_str(), 0_u64]);
        let value = gettxout(&ctx, &params).unwrap_or_else(|err| panic!("gettxout failed: {err}"));
        assert!(
            value.is_null(),
            "expected null for unknown outpoint, got {value:?}"
        );
    }

    #[test]
    fn gettxout_returns_null_for_transaction_output_absent_from_utxo() {
        let ctx = Arc::new(Context::new());
        let tx = Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: Vec::new(),
            outputs: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: Script::from_bytes(vec![0x51]),
            }],
        };
        let txid = tx.txid();
        let params = json!([txid.to_string(), 0_u64]);
        let value = gettxout(&ctx, &params).unwrap_or_else(|err| panic!("gettxout failed: {err}"));
        assert!(
            value.is_null(),
            "expected null for output absent from UTXO set, got {value:?}"
        );
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod acceptance_tests;

#[cfg(test)]
fn empty_psbt() -> String {
    let tx = bitcoin::Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: Vec::new(),
        output: Vec::new(),
    };
    let psbt = bitcoin::psbt::Psbt::from_unsigned_tx(tx)
        .unwrap_or_else(|err| panic!("from_unsigned_tx: {err}"));
    crate::base64::encode(&psbt.serialize())
}

#[cfg(test)]
mod combinepsbt_tests {
    use alloc::sync::Arc;

    use super::*;

    #[test]
    fn combinepsbt_single_input_returns_same_psbt() {
        let ctx = Arc::new(Context::new());
        let psbt_str = empty_psbt();
        let result = combinepsbt(&ctx, &json!([[psbt_str.as_str()]]))
            .unwrap_or_else(|err| panic!("combinepsbt: {err}"));
        let Some(out) = result.as_str() else {
            panic!("expected string: {result:?}");
        };
        assert_eq!(out, psbt_str);
    }

    #[test]
    fn combinepsbt_empty_array_errors() {
        let ctx = Arc::new(Context::new());
        let result = combinepsbt(&ctx, &json!([[]]));
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod finalizepsbt_tests {
    use alloc::sync::Arc;

    use bitcoin::sighash::SighashCache;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

    use super::*;

    #[test]
    fn finalizepsbt_returns_incomplete_for_unfinalized_inputs() {
        let ctx = Arc::new(Context::new());
        let raw = empty_psbt();
        let result = finalizepsbt(&ctx, &json!([raw.as_str()]))
            .unwrap_or_else(|err| panic!("finalizepsbt failed: {err}"));
        let Some(complete) = result.get("complete").and_then(Value::as_bool) else {
            panic!("complete missing: {result:?}");
        };
        assert!(!complete);
        assert!(result.get("hex").is_none_or(Value::is_null));
        assert!(result.get("psbt").and_then(Value::as_str).is_some());
    }

    fn signed_p2wpkh_psbts() -> (String, String) {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let secret = bitcoin::secp256k1::SecretKey::from_slice(&[7_u8; 32])
            .unwrap_or_else(|err| panic!("secret key: {err}"));
        let public_key = bitcoin::PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(
            &secp, &secret,
        ));
        let witness_hash = public_key
            .wpubkey_hash()
            .unwrap_or_else(|err| panic!("compressed public key: {err}"));
        let prevout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::new_p2wpkh(&witness_hash),
        };
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(bitcoin::Txid::all_zeros(), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(40_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let mut metadata =
            bitcoin::psbt::Psbt::from_unsigned_tx(tx).unwrap_or_else(|err| panic!("psbt: {err}"));
        metadata.inputs[0].witness_utxo = Some(prevout);
        let mut signatures = metadata.clone();
        let mut cache = SighashCache::new(&metadata.unsigned_tx);
        let (message, sighash_type) = metadata
            .sighash_ecdsa(0, &mut cache)
            .unwrap_or_else(|err| panic!("sighash: {err}"));
        signatures.inputs[0].witness_utxo = None;
        signatures.inputs[0].partial_sigs.insert(
            public_key,
            bitcoin::ecdsa::Signature {
                signature: secp.sign_ecdsa(&message, &secret),
                sighash_type,
            },
        );
        (
            crate::base64::encode(&metadata.serialize()),
            crate::base64::encode(&signatures.serialize()),
        )
    }

    #[test]
    fn finalizepsbt_honors_extract_false_for_complete_psbt() {
        let ctx = Arc::new(Context::new());
        let (metadata, signatures) = signed_p2wpkh_psbts();
        let combined = combinepsbt(&ctx, &json!([[metadata, signatures]]))
            .unwrap_or_else(|err| panic!("combinepsbt failed: {err}"));
        let combined = combined
            .as_str()
            .unwrap_or_else(|| panic!("combined PSBT missing: {combined:?}"));
        let result = finalizepsbt(&ctx, &json!([combined, false]))
            .unwrap_or_else(|err| panic!("finalizepsbt failed: {err}"));
        assert_eq!(result.get("complete").and_then(Value::as_bool), Some(true));
        assert!(result.get("hex").is_none_or(Value::is_null));
        assert!(result.get("psbt").and_then(Value::as_str).is_some());
    }

    #[test]
    fn combinepsbt_then_finalizepsbt_extracts_signed_transaction() {
        let ctx = Arc::new(Context::new());
        let (metadata, signatures) = signed_p2wpkh_psbts();
        let combined = combinepsbt(&ctx, &json!([[metadata, signatures]]))
            .unwrap_or_else(|err| panic!("combinepsbt failed: {err}"));
        let combined = combined
            .as_str()
            .unwrap_or_else(|| panic!("combined PSBT missing: {combined:?}"));
        let result = finalizepsbt(&ctx, &json!([combined]))
            .unwrap_or_else(|err| panic!("finalizepsbt failed: {err}"));
        assert_eq!(result.get("complete").and_then(Value::as_bool), Some(true));
        assert!(result.get("psbt").is_none_or(Value::is_null));
        assert!(result.get("hex").and_then(Value::as_str).is_some());
    }

    #[test]
    fn exact_amount_parsing_honors_precision_invariants() {
        use super::sats_from_btc;

        assert_eq!(
            sats_from_btc(&json!(1e-8), "Invalid amount")
                .unwrap_or_else(|err| panic!("sats_from_btc 1e-8 must parse: {err}")),
            1
        );
        assert_eq!(
            sats_from_btc(&json!("1e-8"), "Invalid amount")
                .unwrap_or_else(|err| panic!("sats_from_btc 1e-8 must parse: {err}")),
            1
        );
        assert_eq!(
            sats_from_btc(&json!("1E-8"), "Invalid amount")
                .unwrap_or_else(|err| panic!("sats_from_btc 1E-8 must parse: {err}")),
            1
        );
        assert!(sats_from_btc(&json!(1e-9), "Invalid amount").is_err());
        assert!(sats_from_btc(&json!("1e-9"), "Invalid amount").is_err());
        assert!(sats_from_btc(&json!("1E-9"), "Invalid amount").is_err());

        assert_eq!(
            sats_from_btc(&json!("0.00000001"), "Invalid amount")
                .unwrap_or_else(|err| panic!("sats_from_btc boundary must parse: {err}")),
            1
        );
        assert!(sats_from_btc(&json!("0.000000001"), "Invalid amount").is_err());
        assert!(sats_from_btc(&json!("1.000000001"), "Invalid amount").is_err());
        assert_eq!(
            sats_from_btc(&json!("1.000000000"), "Invalid amount")
                .unwrap_or_else(|err| panic!("sats_from_btc trailing zeros must parse: {err}")),
            100_000_000
        );
        assert_eq!(
            sats_from_btc(&json!("100e-10"), "Invalid amount")
                .unwrap_or_else(|err| panic!("sats_from_btc 100e-10 must parse: {err}")),
            1
        );
        assert_eq!(
            sats_from_btc(&json!("0e-100"), "Invalid amount")
                .unwrap_or_else(|err| panic!("sats_from_btc 0e-100 must parse: {err}")),
            0
        );
        assert_eq!(
            sats_from_btc(&json!("0.000000000"), "Invalid amount")
                .unwrap_or_else(|err| panic!("sats_from_btc zeros must parse: {err}")),
            0
        );
        assert!(sats_from_btc(&json!("1."), "Invalid amount").is_err());
        assert!(sats_from_btc(&json!(".1"), "Invalid amount").is_err());
        assert!(sats_from_btc(&json!("."), "Invalid amount").is_err());
        assert!(sats_from_btc(&json!("1.2.3"), "Invalid amount").is_err());
    }

    #[test]
    fn exact_amount_parsing_handles_zero_sign_and_malformed_inputs() {
        use super::sats_from_btc;

        assert_eq!(
            sats_from_btc(&json!(0), "Invalid amount")
                .unwrap_or_else(|err| panic!("sats_from_btc zero must parse: {err}")),
            0
        );
        assert_eq!(
            sats_from_btc(&json!("0"), "Invalid amount")
                .unwrap_or_else(|err| panic!("sats_from_btc zero must parse: {err}")),
            0
        );
        assert_eq!(
            sats_from_btc(&json!("0.0"), "Invalid amount")
                .unwrap_or_else(|err| panic!("sats_from_btc zero must parse: {err}")),
            0
        );
        assert_eq!(
            sats_from_btc(&json!("0e2147483647"), "Invalid amount")
                .unwrap_or_else(|err| panic!("sats_from_btc zero exp must parse: {err}")),
            0
        );

        assert_eq!(
            sats_from_btc(&json!("+1.5"), "Invalid amount")
                .unwrap_or_else(|err| panic!("sats_from_btc +1.5 must parse: {err}")),
            150_000_000
        );
        assert!(sats_from_btc(&json!("-1"), "Invalid amount").is_err());
        assert!(sats_from_btc(&json!("-0"), "Invalid amount").is_err());
        assert!(sats_from_btc(&json!("-0.0"), "Invalid amount").is_err());

        assert!(sats_from_btc(&json!("abc"), "Invalid amount").is_err());
        assert!(sats_from_btc(&json!("1.2.3"), "Invalid amount").is_err());
        assert!(sats_from_btc(&json!(""), "Invalid amount").is_err());
        assert!(sats_from_btc(&json!("."), "Invalid amount").is_err());
        assert!(sats_from_btc(&json!(" 1"), "Invalid amount").is_err());
        assert!(sats_from_btc(&json!("1 "), "Invalid amount").is_err());
    }

    #[test]
    fn exact_amount_parsing_enforces_overflow_exponent_and_feerate_ceilings() {
        use super::{optional_max_feerate, parse_btc_amount, sats_from_btc};

        assert_eq!(
            sats_from_btc(&json!("184467440737.09551615"), "Invalid amount")
                .unwrap_or_else(|err| panic!("sats_from_btc max must parse: {err}")),
            u64::MAX
        );
        assert!(sats_from_btc(&json!("184467440737.09551616"), "Invalid amount").is_err());
        assert!(sats_from_btc(&json!("18446744073709551616"), "Invalid amount").is_err());
        assert!(sats_from_btc(&json!("1e25"), "Invalid amount").is_err());
        assert!(matches!(
            sats_from_btc(&json!("1.1e-2147483647"), "Invalid amount"),
            Err(RpcError::InvalidParams("Invalid amount"))
        ));

        assert_eq!(
            parse_btc_amount(&json!("1e-8"))
                .unwrap_or_else(|err| panic!("parse_btc_amount 1e-8 must parse: {err}")),
            1
        );
        assert!(parse_btc_amount(&json!("1e-9")).is_err());

        assert_eq!(
            optional_max_feerate(&json!([0]), 0)
                .unwrap_or_else(|err| panic!("optional_max_feerate zero must parse: {err}")),
            None
        );
        assert_eq!(
            optional_max_feerate(&json!(["0"]), 0)
                .unwrap_or_else(|err| panic!("optional_max_feerate zero must parse: {err}")),
            None
        );
        assert_eq!(
            optional_max_feerate(&json!(["1e-8"]), 0)
                .unwrap_or_else(|err| panic!("optional_max_feerate 1e-8 must parse: {err}")),
            Some(1)
        );
        assert!(optional_max_feerate(&json!([1.0]), 0).is_err());
        assert!(optional_max_feerate(&json!(["1.0"]), 0).is_err());
        assert!(optional_max_feerate(&json!([-0.1]), 0).is_err());
        assert!(optional_max_feerate(&json!([-1]), 0).is_err());
        assert!(optional_max_feerate(&json!(["-1"]), 0).is_err());
    }
}
