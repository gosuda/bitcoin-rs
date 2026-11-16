use alloc::sync::Arc;
use core::str::FromStr as _;
use hashbrown::HashSet;

use bitcoin::consensus::encode::serialize as bitcoin_serialize;
use bitcoin::hashes::Hash as _;
use bitcoin::hex::DisplayHex as _;
use bitcoin::merkle_tree::MerkleBlock;
use bitcoin_rs_consensus::primitives::{
    Amount, Block as NativeBlock, Hash256, Header as NativeHeader, LockTime, OutPoint, Script,
    Sequence, Tx, TxIn, TxOut, Txid, Witness, consensus_bytes, deserialize as native_deserialize,
    unix_time_secs,
};
use bitcoin_rs_consensus::script::{opcode, push_data};
use bitcoin_rs_mempool::standardness::AcceptanceRejectReason;
use bitcoin_rs_mempool::{LocalOrigin, SubmitError};
use miniscript::psbt::PsbtExt as _;
use sonic_rs::{JsonContainerTrait as _, JsonValueMutTrait as _, JsonValueTrait, Value, json};

use crate::context::{AppliedView, Context};
use crate::convert::{self, sat_to_btc, typed_to_sonic, typed_to_sonic_omitting_nulls};
use crate::error::RpcError;
use crate::handlers::{
    optional_bool, params_array, parse_txid, required_str, required_u64, wrong_type,
    wrong_type_plain,
};
use bitcoin_rs_index::block_log::BlockRecord;
use corepc_types::v31;

pub(crate) mod submit_package;

fn hex_decode(hex: &str) -> Result<Vec<u8>, RpcError> {
    bitcoin_rs_consensus::primitives::hex::hex_decode(hex).map_err(|error| match error {
        bitcoin_rs_consensus::primitives::hex::HexError::OddLength => {
            RpcError::InvalidParameter("hex string must have even length".to_owned())
        }
        bitcoin_rs_consensus::primitives::hex::HexError::InvalidDigit { .. }
        | bitcoin_rs_consensus::primitives::hex::HexError::WrongLength { .. } => {
            RpcError::InvalidParameter("invalid hex character".to_owned())
        }
    })
}

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
                .transaction_block(&txid)
                .map_err(RpcError::from)?
                .and_then(|(_, identity)| {
                    let height = identity.height;
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
    if let Some(verbosity) = value.as_i64() {
        let Ok(verbosity) = i32::try_from(verbosity) else {
            return Err(RpcError::Misc("JSON integer out of range".to_owned()));
        };
        return Ok(match verbosity {
            ..=0 => 0,
            1 => 1,
            _ => 2,
        });
    }
    if value.is_number() {
        return Err(RpcError::Misc("JSON integer out of range".to_owned()));
    }
    Err(RpcError::InvalidType(
        "verbosity must be a boolean or integer".to_owned(),
    ))
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
    coins: Option<&[bitcoin_rs_storage::utxo::UtxoCoin]>,
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
            .map(|live| live.map(|live| (live, ctx.chain.applied_view())))
    })?
    else {
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

pub(crate) fn gettxoutproof(
    ctx: &Arc<Context>,
    params: &Value,
    cancellation: &bitcoin_rs_consensus::latch::LatchReader,
) -> Result<Value, RpcError> {
    let array = params_array(params)?;
    let Some(txids_value) = array.first() else {
        return Err(RpcError::InvalidParams("txids must be an array"));
    };
    let Some(txids_value) = txids_value.as_array() else {
        return Err(wrong_type(1, "txids", txids_value, "array"));
    };
    if txids_value.is_empty() {
        return Err(RpcError::InvalidParameter(
            "Parameter 'txids' cannot be empty".to_owned(),
        ));
    }

    let mut wanted = hashbrown::HashSet::new();
    for value in txids_value.iter() {
        let Some(txid_str) = value.as_str() else {
            return Err(wrong_type_plain(value, "string"));
        };
        let txid = parse_txid(txid_str, "txid")?;
        if !wanted.insert(txid) {
            return Err(RpcError::InvalidParameter(format!(
                "Invalid parameter, duplicated txid: {txid_str}"
            )));
        }
    }

    if let Some(blockhash) = array.get(1).filter(|value| !value.is_null()) {
        let Some(hash_str) = blockhash.as_str() else {
            return Err(wrong_type(2, "blockhash", blockhash, "string"));
        };
        let hash = Hash256::from_str(hash_str)
            .map_err(|_| block_hash_param_error(hash_str, "blockhash"))?;
        let Some(record) = ctx.chain.block_by_hash(hash) else {
            return Err(RpcError::InvalidAddressOrKey("Block not found".to_owned()));
        };
        return proof_from_single_record(ctx, &record, &wanted, cancellation);
    }

    let mut ordered: Vec<Txid> = wanted.iter().copied().collect();
    ordered.sort_unstable();
    if let Some(record) = ctx
        .chain
        .with_stable_chainstate(|| block_from_utxo(ctx, &ordered, cancellation))?
    {
        return proof_from_single_record(ctx, &record, &wanted, cancellation);
    }
    if txindex_usable(ctx)
        && let Some(record) = block_via_index(ctx, ordered.first(), cancellation)?
    {
        return proof_from_single_record(ctx, &record, &wanted, cancellation);
    }
    Err(RpcError::InvalidAddressOrKey(
        "Transaction not yet in block".to_owned(),
    ))
}

const MAX_OUTPUTS_PER_BLOCK: u32 = 111_111;

fn block_from_utxo(
    ctx: &Arc<Context>,
    ordered: &[Txid],
    cancellation: &bitcoin_rs_consensus::latch::LatchReader,
) -> Result<Option<BlockRecord>, RpcError> {
    for txid in ordered {
        if cancellation.is_triggered() {
            return Err(proof_interrupted());
        }
        if let Some(height) = ctx
            .chain
            .utxo
            .confirmation_height(&txid.0, MAX_OUTPUTS_PER_BLOCK)?
        {
            return Ok(ctx.chain.block_by_height(height));
        }
    }
    Ok(None)
}

fn block_via_index(
    ctx: &Arc<Context>,
    txid: Option<&Txid>,
    cancellation: &bitcoin_rs_consensus::latch::LatchReader,
) -> Result<Option<BlockRecord>, RpcError> {
    let Some(txid) = txid else {
        return Ok(None);
    };
    if cancellation.is_triggered() {
        return Err(proof_interrupted());
    }
    let Some(derived_index) = ctx.indexes.derived_index.as_ref() else {
        return Ok(None);
    };
    match derived_index.transaction_block(txid) {
        Ok(Some((_, identity))) => ctx
            .chain
            .block_by_height(identity.height)
            .map(Some)
            .ok_or_else(|| RpcError::CoreInternal("Transaction index corrupt".to_owned())),
        Ok(None) => Ok(None),
        Err(error) => {
            tracing::warn!(
                txid = %txid,
                %error,
                "txindex lookup failed; gettxoutproof cannot answer"
            );
            Err(error.into())
        }
    }
}

fn txindex_usable(ctx: &Context) -> bool {
    if ctx.indexes.derived_index.is_none() {
        return false;
    }
    ctx.indexes
        .derived_index_status
        .as_deref()
        .is_none_or(|source| {
            let capability = source.capability();
            capability.enabled && capability.state == bitcoin_rs_index::CapabilityState::Ready
        })
}

fn proof_interrupted() -> RpcError {
    RpcError::Misc("gettxoutproof interrupted".to_owned())
}

fn proof_from_single_record(
    ctx: &Arc<Context>,
    record: &bitcoin_rs_index::block_log::BlockRecord,
    wanted: &hashbrown::HashSet<Txid>,
    cancellation: &bitcoin_rs_consensus::latch::LatchReader,
) -> Result<Value, RpcError> {
    if cancellation.is_triggered() {
        return Err(proof_interrupted());
    }
    let Some(bytes) = ctx.chain.block_body_bytes(record) else {
        return Err(RpcError::Misc(block_unavailable_error(ctx)));
    };
    proof_from_body(&bytes, wanted)
}

fn block_unavailable_error(ctx: &Context) -> String {
    if ctx.chain.prune_status().pruned {
        "Block not available (pruned data)".to_owned()
    } else {
        "Block not available (not fully downloaded)".to_owned()
    }
}

fn proof_from_body(bytes: &[u8], wanted: &hashbrown::HashSet<Txid>) -> Result<Value, RpcError> {
    let block = native_deserialize::<NativeBlock>(bytes)
        .map_err(|_| RpcError::CoreInternal("Can't read block from disk".to_owned()))?;
    let block_txids = block
        .txs
        .iter()
        .map(Tx::txid)
        .collect::<hashbrown::HashSet<Txid>>();
    if !wanted.iter().all(|txid| block_txids.contains(txid)) {
        return Err(RpcError::InvalidAddressOrKey(
            "Not all transactions found in specified or retrieved block".to_owned(),
        ));
    }

    let bitcoin_block = bitcoin::consensus::encode::deserialize::<bitcoin::Block>(bytes)
        .map_err(|_| RpcError::CoreInternal("Can't read block from disk".to_owned()))?;
    let bitcoin_wanted: hashbrown::HashSet<bitcoin::Txid> = wanted
        .iter()
        .map(|txid| bitcoin::Txid::from_byte_array(*txid.as_bytes()))
        .collect();
    let merkle_block = MerkleBlock::from_block_with_predicate(&bitcoin_block, |txid| {
        bitcoin_wanted.contains(txid)
    });
    Ok(json!(
        bitcoin_serialize(&merkle_block).to_lower_hex_string()
    ))
}

pub(crate) fn verifytxoutproof(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
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

    let header_bytes = bitcoin_serialize(&merkle_block.header);
    let Ok(native_header) = native_deserialize::<NativeHeader>(&header_bytes) else {
        return typed_to_sonic(&v31::VerifyTxOutProof(Vec::new()));
    };
    let header_hash = Hash256::from(native_header.compute_hash());
    let Some(record) = ctx.chain.block_by_hash(header_hash) else {
        return Err(RpcError::InvalidAddressOrKey(
            "Block not found in chain".to_owned(),
        ));
    };
    if ctx.chain.block_hash_at_height(record.height) != Some(header_hash) {
        return Err(RpcError::InvalidAddressOrKey(
            "Block not found in chain".to_owned(),
        ));
    }
    let proof_tx_count = usize::try_from(merkle_block.txn.num_transactions()).unwrap_or(0);
    if record.tx_count == 0 || record.tx_count != proof_tx_count {
        return typed_to_sonic(&v31::VerifyTxOutProof(Vec::new()));
    }

    let result = matched_txids
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    typed_to_sonic(&v31::VerifyTxOutProof(result))
}

use crate::context::DEFAULT_MAX_RAW_TX_FEE_RATE_SAT_PER_KVB;

pub(crate) fn sendrawtransaction(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
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
        if (script.len() > bitcoin_rs_consensus::script::MAX_SCRIPT_SIZE
            || bitcoin_rs_consensus::script::is_op_return(script)
            || !bitcoin_rs_consensus::script::has_valid_ops(script))
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
    super::ensure_at_most_params(params, 2)?;
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
            reject_details: fact
                .reject_reason
                .as_ref()
                .and_then(|reason| oversize_reject_string(reason))
                .map(str::to_owned),
        }));
    }
    typed_to_sonic_omitting_nulls(&rows)
}

pub(crate) fn decoderawtransaction(
    ctx: &Arc<Context>,
    params: &Value,
    cancellation: &bitcoin_rs_consensus::latch::LatchReader,
) -> Result<Value, RpcError> {
    let raw = required_str(params, 0, "raw transaction is required")?;
    if cancellation.is_triggered() {
        return Err(RpcError::Misc(
            "transaction decode request cancelled; retry".to_owned(),
        ));
    }
    let tx = decode_tx(raw, "TX decode failed".to_owned())?;
    let mut value = crate::tx_render::transaction_json(&tx, ctx.chain.chain_network, None);
    if let Some(object) = value.as_object_mut() {
        object.remove(&"hex");
    }
    Ok(value)
}

pub(crate) fn compressrawtransaction(
    ctx: &Arc<Context>,
    params: &Value,
    cancellation: &bitcoin_rs_consensus::latch::LatchReader,
) -> Result<Value, RpcError> {
    if !ctx.compressed_transactions {
        return Err(RpcError::MethodDisabled(
            "compressrawtransaction is disabled; enable --compressed-transactions",
        ));
    }
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

pub(crate) fn decompressrawtransaction(
    ctx: &Arc<Context>,
    params: &Value,
    cancellation: &bitcoin_rs_consensus::latch::LatchReader,
) -> Result<Value, RpcError> {
    if !ctx.compressed_transactions {
        return Err(RpcError::MethodDisabled(
            "decompressrawtransaction is disabled; enable --compressed-transactions",
        ));
    }
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

const CREATE_TRANSACTION_MAX_ARGUMENTS: usize = 4;

pub(crate) fn createrawtransaction(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    super::ensure_at_most_params(params, CREATE_TRANSACTION_MAX_ARGUMENTS)?;
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

    let tx_inputs = parse_create_tx_inputs(inputs, default_sequence)?;
    let network = convert::bitcoin_network(ctx.chain.chain_network);
    let tx_outputs = parse_create_tx_outputs(outputs, network)?;
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

fn parse_create_tx_inputs(inputs: &[Value], default_sequence: u32) -> Result<Vec<TxIn>, RpcError> {
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
    Ok(tx_inputs)
}

fn parse_create_tx_outputs(
    outputs: &sonic_rs::Object,
    network: bitcoin::Network,
) -> Result<Vec<TxOut>, RpcError> {
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
    Ok(tx_outputs)
}

fn decode_tx(raw: &str, message: String) -> Result<Tx, RpcError> {
    let bytes = hex_decode(raw).map_err(|_| RpcError::Deserialization(message.clone()))?;
    native_deserialize(&bytes).map_err(|_| RpcError::Deserialization(message))
}

const MAX_BROADCAST_HEX_CHARS: u64 = 2 * bitcoin_rs_mempool::standardness::MAX_STANDARD_TX_WEIGHT;
const BROADCAST_HEX_LIMIT_ERROR: &str = "transaction hex exceeds the broadcast size limit";

pub(crate) fn check_broadcast_hex_len(raw: &str) -> Result<(), &'static str> {
    if u64::try_from(raw.len()).unwrap_or(u64::MAX) > MAX_BROADCAST_HEX_CHARS {
        return Err(BROADCAST_HEX_LIMIT_ERROR);
    }
    Ok(())
}

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

const CORE_TX_SIZE_REJECT: &str = "tx-size";
const CORE_TX_OVERSIZE_REJECT: &str = "bad-txns-oversize";

fn oversize_reject_string(reason: &AcceptanceRejectReason) -> Option<&'static str> {
    match reason {
        AcceptanceRejectReason::NonStandard(
            bitcoin_rs_mempool::standardness::StandardnessError::Weight,
        ) => Some(CORE_TX_SIZE_REJECT),
        AcceptanceRejectReason::NonStandard(
            bitcoin_rs_mempool::standardness::StandardnessError::Oversize,
        ) => Some(CORE_TX_OVERSIZE_REJECT),
        _ => None,
    }
}

pub(crate) fn reject_reason_to_rpc_error(reason: AcceptanceRejectReason) -> RpcError {
    match reason {
        AcceptanceRejectReason::MaxFeeExceeded => RpcError::InvalidParams("max-fee-exceeded"),
        AcceptanceRejectReason::MissingInputs => {
            RpcError::TxVerifyError("bad-txns-inputs-missingorspent".to_owned())
        }
        ref oversize if let Some(reject) = oversize_reject_string(oversize) => {
            RpcError::TxRejected(reject.to_owned())
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

fn reject_reason_to_frozen_string(reason: AcceptanceRejectReason) -> String {
    match reason {
        AcceptanceRejectReason::PackageLimit(
            bitcoin_rs_mempool::PolicyError::ClusterCountLimit
            | bitcoin_rs_mempool::PolicyError::ClusterSizeLimit,
        ) => "too-large-cluster".to_owned(),
        ref oversize if let Some(reject) = oversize_reject_string(oversize) => reject.to_owned(),
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
mod tests {
    use alloc::sync::Arc;

    use bitcoin_rs_chain::chain::{NodeId, NodeStatus, TipSnapshot};
    use bitcoin_rs_consensus::latch::LatchReader;
    use bitcoin_rs_consensus::primitives::{
        Block, BlockHash, Hash256, Header, OutPoint, Tx, TxIn, TxOut, Txid, consensus_bytes,
    };
    use bitcoin_rs_mempool::{
        AdmissionOrigin, MempoolEntry, arm_admission_park, reset_admission_park,
    };
    use bitcoin_rs_storage::utxo::contract::{BlockChanges, UtxoAdd};
    use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, Value, json};
    use std::sync::mpsc;
    use std::thread;

    use super::{getrawtransaction, gettxout};
    use crate::Handler;
    use crate::context::{Context, DerivedIndexQuery, TransactionBlock, TxQueryError};
    use crate::error::RpcError;
    use bitcoin::hex::DisplayHex as _;
    use bitcoin_rs_index::block_log::BlockRecord;

    fn fixture_genesis() -> Block {
        use bitcoin_rs_consensus::primitives::{
            Amount, CompactTarget, LockTime, Script, Sequence, Witness,
        };
        let coinbase = Tx {
            version: 1,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(vec![0x51; 4]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(50),
                script_pubkey: Script::from_bytes(vec![0x51]),
            }],
        };
        let mut block = Block {
            header: Header {
                version: 1,
                prev_blockhash: BlockHash::default(),
                merkle_root: Hash256::default(),
                time: 0,
                bits: CompactTarget::from_consensus(0),
                nonce: 0,
            },
            txs: vec![coinbase],
        };
        block.header.merkle_root =
            bitcoin_rs_chain::chain::regtest_fixture::merkle_root(&block.txs).unwrap_or_default();
        block
    }

    #[test]
    fn getrawtransaction_falls_back_to_mempool_for_unconfirmed()
    -> Result<(), crate::test_error::TestError> {
        let ctx = Arc::new(Context::new());
        let genesis = fixture_genesis();
        let coinbase = genesis
            .txs
            .first()
            .ok_or_else(|| RpcError::Internal("genesis has no transactions".to_owned()))?
            .clone();
        let txid = coinbase.txid();
        {
            let mut pool = ctx.mempool.gateway.pool().write();
            let vsize = u32::try_from(coinbase.vsize())?;
            let entry =
                MempoolEntry::new(Arc::new(coinbase.clone()), vsize, u64::from(vsize), 0, 0, 0);
            pool.insert_entry(entry)?;
        }

        let result = getrawtransaction(&ctx, &json!([txid.to_string()]))?;

        let expected = consensus_bytes(&coinbase).to_lower_hex_string();
        assert_eq!(result.as_str(), Some(expected.as_str()));
        let output = gettxout(&ctx, &json!([txid.to_string(), 0]))?;
        assert_eq!(output["confirmations"], json!(0));
        assert_eq!(output["coinbase"], json!(false));
        assert_eq!(
            output["bestblock"],
            json!(ctx.chain.applied_hash().to_string())
        );
        assert_eq!(output["value"], json!(0.000_000_5));
        assert!(gettxout(&ctx, &json!([txid.to_string(), 0, false]))?.is_null());
        assert!(gettxout(&ctx, &json!([txid.to_string(), 1]))?.is_null());
        Ok(())
    }
    struct SpentRows {
        block: Block,
    }

    impl bitcoin_rs_storage::utxo::contract::BlockUndoSource for SpentRows {
        fn block_spends(
            &self,
            _hash: Hash256,
            _expected: Hash256,
        ) -> Result<
            bitcoin_rs_storage::utxo::contract::BlockSpends,
            bitcoin_rs_storage::utxo::contract::BlockSpendsError,
        > {
            use bitcoin_rs_consensus::primitives::{Amount, Script};
            let Some(spend) = self.block.txs.get(1) else {
                return Err(bitcoin_rs_storage::utxo::contract::BlockSpendsError::UnknownBlock);
            };
            let spent = spend
                .inputs
                .iter()
                .map(|input| bitcoin_rs_storage::utxo::UtxoCoin {
                    outpoint: input.previous_output,
                    txout: TxOut {
                        value: Amount::from_sat(5_000_000_000),
                        script_pubkey: Script::new(),
                    },
                    coinbase: false,
                    height: 0,
                })
                .collect();
            Ok(bitcoin_rs_storage::utxo::contract::BlockSpends {
                block: self.block.clone(),
                spent: Ok(vec![vec![], spent]),
            })
        }
    }

    #[test]
    fn getrawtransaction_clamps_out_of_range_verbosity_like_core()
    -> Result<(), crate::test_error::TestError> {
        let block = block_with_two_txs(9);
        let spend = block
            .txs
            .get(1)
            .cloned()
            .ok_or_else(|| RpcError::Internal("fixture lost its spend".to_owned()))?;
        let mut ctx = Context::new();
        ctx.chain
            .block_tree
            .write()
            .insert_node(None, block.header, NodeStatus::Active)
            .expect("header");
        ctx.chain.block_undo_source = Some(Arc::new(SpentRows {
            block: block.clone(),
        }));
        attach_body_for_block(&mut ctx, &block, 0);
        let ctx = Arc::new(ctx);
        let hash = block.block_hash().to_string();
        let txid = spend.txid().to_string();
        let expected_hex = consensus_bytes(&spend).to_lower_hex_string();
        for verbosity in [json!(-1), json!(0), json!(false)] {
            let value = getrawtransaction(&ctx, &json!([txid.as_str(), verbosity, hash.as_str()]))?;
            assert_eq!(
                value.as_str(),
                Some(expected_hex.as_str()),
                "verbosity {verbosity} renders hex"
            );
        }
        let level_one = getrawtransaction(&ctx, &json!([txid.as_str(), true, hash.as_str()]))?;
        assert!(level_one["vin"][0].get("prevout").is_none());
        for verbosity in [json!(2), json!(3), json!(4), json!(99)] {
            let value = getrawtransaction(&ctx, &json!([txid.as_str(), verbosity, hash.as_str()]))?;
            assert!(
                value["vin"][0].get("prevout").is_some(),
                "verbosity {verbosity} renders level two: {value:?}"
            );
        }
        Ok(())
    }
    #[test]
    fn sendrawtransaction_rejects_odd_length_and_invalid_and_oversize_hex() {
        let ctx = Arc::new(Context::new());
        let odd =
            super::sendrawtransaction(&ctx, &json!(["abc"])).expect_err("odd length hex must fail");
        assert_eq!(odd.code(), RpcError::CORE_DESERIALIZATION_ERROR);

        let invalid =
            super::sendrawtransaction(&ctx, &json!(["zz"])).expect_err("invalid hex must fail");
        assert_eq!(invalid.code(), RpcError::CORE_DESERIALIZATION_ERROR);

        let limit = usize::try_from(super::MAX_BROADCAST_HEX_CHARS / 2).unwrap_or(0);
        let oversize = "00".repeat(limit + 1);
        let too_large = super::sendrawtransaction(&ctx, &json!([oversize]))
            .expect_err("oversize hex must fail");
        assert_eq!(too_large.code(), RpcError::CORE_DESERIALIZATION_ERROR);
    }

    #[test]
    fn decoderawtransaction_rejects_odd_length_and_invalid_and_oversize_hex() {
        let ctx = Arc::new(Context::new());
        let latch = bitcoin_rs_consensus::latch::LatchWriter::new().reader();
        let odd = super::decoderawtransaction(&ctx, &json!(["abc"]), &latch)
            .expect_err("odd length hex must fail");
        assert_eq!(odd.code(), RpcError::CORE_DESERIALIZATION_ERROR);

        let invalid = super::decoderawtransaction(&ctx, &json!(["zz"]), &latch)
            .expect_err("invalid hex must fail");
        assert_eq!(invalid.code(), RpcError::CORE_DESERIALIZATION_ERROR);

        let oversize = "00".repeat(1_000_001);
        let too_large = super::decoderawtransaction(&ctx, &json!([oversize]), &latch)
            .expect_err("oversize hex must fail");
        assert_eq!(too_large.code(), RpcError::CORE_DESERIALIZATION_ERROR);
    }
    // API-10
    #[test]
    fn sendrawtransaction_answers_core_oversize_for_hex_beyond_the_broadcast_bound() {
        let ctx = Context::new();
        fund_coin(
            &ctx,
            OutPoint::new(Txid(Hash256::from_le_bytes(&[0x5a; 32])), 0),
            29_424_000,
        );
        let ctx = Arc::new(ctx);
        let raw = consensus_bytes(&many_output_tx(29_424)).to_lower_hex_string();
        let error = ctx
            .chain
            .with_stable_chainstate(|| super::sendrawtransaction(&ctx, &json!([raw.clone()])))
            .expect_err(
                "a transaction over the consensus bound must answer Core bad-txns-oversize",
            );

        assert_eq!(
            error.code(),
            RpcError::CORE_VERIFY_REJECTED,
            "Core answers -26 for an oversize transaction: {error}"
        );
        assert_eq!(
            error.to_string(),
            "bad-txns-oversize",
            "Core CheckTransaction answers bad-txns-oversize before the standard weight check"
        );
    }

    // API-10
    #[test]
    fn sendrawtransaction_maps_the_gateway_weight_reject_to_core_tx_size() {
        let ctx = Context::new();
        fund_coin(
            &ctx,
            OutPoint::new(Txid(Hash256::from_le_bytes(&[0x5a; 32])), 0),
            2_954_000,
        );
        let ctx = Arc::new(ctx);
        let raw = consensus_bytes(&many_output_tx(2_954)).to_lower_hex_string();
        let error = ctx
            .chain
            .with_stable_chainstate(|| super::sendrawtransaction(&ctx, &json!([raw.clone()])))
            .expect_err("a transaction above the standard weight must answer Core tx-size");

        assert_eq!(
            error.code(),
            RpcError::CORE_VERIFY_REJECTED,
            "Core answers -26 for an oversize transaction: {error}"
        );
        assert_eq!(error.to_string(), "tx-size");
    }

    // API-10
    #[test]
    fn testmempoolaccept_reports_core_tx_size_on_the_oversize_row() {
        let ctx = Context::new();
        fund_coin(
            &ctx,
            OutPoint::new(Txid(Hash256::from_le_bytes(&[0x5a; 32])), 0),
            2_954_000,
        );
        let ctx = Arc::new(ctx);
        let raw = consensus_bytes(&many_output_tx(2_954)).to_lower_hex_string();
        let rows = ctx
            .chain
            .with_stable_chainstate(|| super::testmempoolaccept(&ctx, &json!([[raw.clone()]])))
            .unwrap_or_else(|err| panic!("one oversize row must not fail the request: {err}"));
        let rows = rows.as_array().unwrap_or_else(|| panic!("rows: {rows:?}"));
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row["allowed"].as_bool(), Some(false), "row: {row}");
        assert_eq!(row["reject-reason"].as_str(), Some("tx-size"), "row: {row}");
        assert_eq!(
            row["reject-details"].as_str(),
            Some("tx-size"),
            "row: {row}"
        );
    }

    // API-10
    #[test]
    fn testmempoolaccept_survives_one_oversize_row_with_package_too_large() {
        let ctx = Context::new();
        let outpoint = retry_fund_utxo(&ctx, 1, 10_000);
        let small = retry_tx(outpoint, 9_000);
        let oversize_raw = consensus_bytes(&many_output_tx(29_424)).to_lower_hex_string();
        let small_raw = consensus_bytes(&small).to_lower_hex_string();
        let ctx = Arc::new(ctx);
        let rows = ctx
            .chain
            .with_stable_chainstate(|| {
                super::testmempoolaccept(&ctx, &json!([[oversize_raw, small_raw]]))
            })
            .unwrap_or_else(|err| panic!("one oversize row must not fail the request: {err}"));
        let rows = rows.as_array().unwrap_or_else(|| panic!("rows: {rows:?}"));
        assert_eq!(rows.len(), 2);
        for row in rows {
            assert_eq!(
                row["package-error"].as_str(),
                Some("package-too-large"),
                "row: {row}"
            );
            assert!(
                row["allowed"].is_null(),
                "unfinished rows carry no allowed key: {row}"
            );
        }
    }

    // API-02
    #[test]
    fn decoderawtransaction_decodes_oversize_hex_like_core() {
        let ctx = Arc::new(Context::new());
        let latch = bitcoin_rs_consensus::latch::LatchWriter::new().reader();
        let raw = consensus_bytes(&many_output_tx(117_700)).to_lower_hex_string();
        let value = super::decoderawtransaction(&ctx, &json!([raw]), &latch)
            .unwrap_or_else(|err| panic!("Core decodes any hex that fits the request: {err}"));
        assert_eq!(
            value["vout"].as_array().map(|items| items.len()),
            Some(117_700),
            "the decoded transaction renders every output"
        );
    }

    #[test]
    fn testmempoolaccept_binds_named_parameters_and_rejects_excess() {
        let ctx = Arc::new(Context::new());
        let excess = super::testmempoolaccept(&ctx, &json!([[], 0, "extra"]))
            .expect_err("excess parameters must fail");
        assert!(matches!(excess, RpcError::InvalidParams(_)));

        let handler = crate::Handler::new(Arc::clone(&ctx));
        let named = handler.dispatch("testmempoolaccept", &json!({"rawtxs": []}));
        let positional = handler.dispatch("testmempoolaccept", &json!([[]]));
        assert_eq!(
            named.expect_err("named empty rawtxs").to_string(),
            positional.expect_err("positional empty rawtxs").to_string()
        );
    }

    #[test]
    fn getrawtransaction_checks_mempool_before_failing_txindex()
    -> Result<(), crate::test_error::TestError> {
        struct FailingQuery;

        impl DerivedIndexQuery for FailingQuery {
            fn transaction(&self, _txid: &Txid) -> Result<Option<Tx>, TxQueryError> {
                Err(TxQueryError::Storage("disk full".into()))
            }

            fn outpoint_value(&self, _outpoint: &OutPoint) -> Result<Option<u64>, TxQueryError> {
                Ok(None)
            }

            fn index_info(&self) -> Result<crate::context::DerivedIndexInfo, TxQueryError> {
                Ok(crate::context::DerivedIndexInfo {
                    synced: false,
                    best_block_height: 0,
                    applied_height: 0,
                    historical_height: 0,
                    verified_height: 0,
                    coverage_height: 0,
                })
            }
        }

        let mut ctx = Context::new();
        ctx.indexes.derived_index = Some(Arc::new(FailingQuery));
        let ctx = Arc::new(ctx);
        let genesis = fixture_genesis();
        let mut coinbase = genesis
            .txs
            .first()
            .ok_or_else(|| RpcError::Internal("genesis has no transactions".to_owned()))?
            .clone();
        coinbase.version = u32::MAX;
        let txid = coinbase.txid();
        {
            let mut pool = ctx.mempool.gateway.pool().write();
            let vsize = u32::try_from(coinbase.vsize())?;
            let entry =
                MempoolEntry::new(Arc::new(coinbase.clone()), vsize, u64::from(vsize), 0, 0, 0);
            pool.insert_entry(entry)?;
        }

        let result = getrawtransaction(&ctx, &json!([txid.to_string()]))?;

        let expected = consensus_bytes(&coinbase).to_lower_hex_string();
        assert_eq!(result.as_str(), Some(expected.as_str()));
        for verbosity in [json!(true), json!(1), json!(2)] {
            let verbose = getrawtransaction(&ctx, &json!([txid.to_string(), verbosity]))?;
            assert_eq!(verbose["version"].as_u64(), Some(4_294_967_295));
            assert_eq!(verbose["hex"].as_str(), Some(expected.as_str()));
            for field in [
                "blockhash",
                "confirmations",
                "time",
                "blocktime",
                "in_active_chain",
                "fee",
            ] {
                assert!(verbose.get(field).is_none(), "mempool omits {field}");
            }
        }
        Ok(())
    }

    #[test]
    fn getrawtransaction_explicit_coinbase_preserves_undo_failures_and_render_budget() {
        use bitcoin_rs_storage::utxo::contract::{BlockSpends, BlockSpendsError, BlockUndoSource};

        struct FailingSource(fn() -> BlockSpendsError);
        impl BlockUndoSource for FailingSource {
            fn block_spends(
                &self,
                _: Hash256,
                _: Hash256,
            ) -> Result<BlockSpends, BlockSpendsError> {
                Err((self.0)())
            }
        }
        let mut block = fixture_genesis();
        let mut spend = block.txs[0].clone();
        spend.inputs[0].previous_output = OutPoint::new(block.txs[0].txid(), 0);
        block.txs.push(spend);
        block.header.merkle_root =
            bitcoin_rs_chain::chain::regtest_fixture::merkle_root(&block.txs).expect("merkle root");
        let context = |failure| {
            let mut ctx = Context::new();
            ctx.chain
                .block_tree
                .write()
                .insert_node(None, block.header, NodeStatus::Active)
                .expect("header");
            ctx.chain.block_undo_source = Some(Arc::new(FailingSource(failure)));
            Arc::new(ctx)
        };
        let args = json!([
            block.txs[0].txid().to_string(),
            2,
            block.block_hash().to_string()
        ]);
        let retry: fn() -> BlockSpendsError = || BlockSpendsError::Retry;
        for (failure, code) in [
            (retry, -1),
            (|| BlockSpendsError::Closed, -1),
            (|| BlockSpendsError::ResourceLimit, -1),
            (|| BlockSpendsError::Corrupt("fixture"), -32603),
            (
                || {
                    BlockSpendsError::Undo(
                        bitcoin_rs_storage::utxo::contract::UndoReadError::Missing {
                            block: Hash256::default(),
                            height: 1,
                        },
                    )
                },
                -32603,
            ),
        ] {
            let mut ctx = context(failure);
            assert_eq!(
                getrawtransaction(&ctx, &args)
                    .expect_err("read failure")
                    .code(),
                code
            );
            attach_body_for_block(Arc::get_mut(&mut ctx).expect("unique context"), &block, 0);
            for verbosity in [json!(1), json!(true)] {
                let value = getrawtransaction(
                    &ctx,
                    &json!([
                        block.txs[0].txid().to_string(),
                        verbosity,
                        block.block_hash().to_string()
                    ]),
                )
                .expect("coinbase body is readable without undo");
                assert!(value.get("fee").is_none());
                assert!(value["vin"][0].get("prevout").is_none());
            }
            assert_eq!(
                getrawtransaction(&ctx, &args)
                    .expect_err("v2 still requires undo")
                    .code(),
                code
            );
        }
        let ctx = context(|| BlockSpendsError::Corrupt("fixture"));
        let first = ctx.try_acquire_block_render().expect("first permit");
        let second = ctx.try_acquire_block_render().expect("second permit");
        let error = getrawtransaction(&ctx, &args).expect_err("budget refusal");
        assert!(
            error
                .to_string()
                .contains("too many concurrent full-block reads")
        );
        drop((first, second));
        assert_eq!(
            getrawtransaction(&ctx, &args)
                .expect_err("undo failure")
                .code(),
            -32603
        );
    }

    #[test]
    fn getrawtransaction_detailed_read_omits_unavailable_undo_and_rejects_partial_rows() {
        use bitcoin_rs_consensus::primitives::Amount;
        use bitcoin_rs_storage::utxo::contract::{
            BlockSpends, BlockSpendsError, BlockUndoSource, HistoryUnavailable,
        };

        struct Source {
            block: Block,
            mode: u8,
            expected: Hash256,
        }
        impl BlockUndoSource for Source {
            fn block_spends(
                &self,
                hash: Hash256,
                expected: Hash256,
            ) -> Result<BlockSpends, BlockSpendsError> {
                assert_eq!(hash, Hash256::from(self.block.block_hash()));
                assert_eq!(expected, self.expected);
                let spent = match self.mode {
                    0 => Err(HistoryUnavailable::Missing),
                    1 => Err(HistoryUnavailable::Pruned { below: 1 }),
                    2 => Ok(vec![vec![]]),
                    _ => Ok(vec![vec![], vec![]]),
                };
                Ok(BlockSpends {
                    block: self.block.clone(),
                    spent,
                })
            }
        }
        let mut block = fixture_genesis();
        let mut spend = block.txs[0].clone();
        spend.inputs[0].previous_output = OutPoint::new(block.txs[0].txid(), 0);
        spend.outputs[0].value = Amount::from_sat(49);
        block.txs.push(spend.clone());
        block.header.merkle_root =
            bitcoin_rs_chain::chain::regtest_fixture::merkle_root(&block.txs).expect("merkle root");
        for mode in 0..4 {
            let mut ctx = Context::new();
            ctx.chain
                .block_tree
                .write()
                .insert_node(None, block.header, NodeStatus::Active)
                .expect("header");
            ctx.chain.block_undo_source = Some(Arc::new(Source {
                block: block.clone(),
                mode,
                expected: ctx.chain.applied_hash(),
            }));
            let result = getrawtransaction(
                &Arc::new(ctx),
                &json!([spend.txid().to_string(), 2, block.block_hash().to_string()]),
            );
            if mode < 2 {
                let value = result.expect("uncertified undo is omitted");
                assert!(value.get("fee").is_none());
                assert!(value["vin"][0].get("prevout").is_none());
                assert_eq!(value["in_active_chain"].as_bool(), Some(false));
            } else {
                assert_eq!(result.expect_err("partial undo").code(), -32603);
            }
        }
    }

    #[test]
    fn getrawtransaction_uses_applied_ancestry_for_explicit_block_metadata() {
        let genesis = distinct_block(1);
        let mut sibling = distinct_block(2);
        sibling.header.prev_blockhash = genesis.block_hash();
        let mut active = distinct_block(3);
        active.header.prev_blockhash = genesis.block_hash();
        let mut higher = distinct_block(4);
        higher.header.prev_blockhash = sibling.block_hash();
        let mut ctx = Context::new();
        let blocks = [(&genesis, 0), (&sibling, 1), (&active, 1), (&higher, 2)];
        ctx.chain.block_body_source = Some(Arc::new(BlockBodies {
            bodies: blocks
                .iter()
                .map(|(block, height)| (*height, block.block_hash(), consensus_bytes(*block)))
                .collect(),
        }));
        for (block, height) in blocks {
            ctx.chain.add_block(BlockRecord::from_block(height, block));
        }
        let active_tip = {
            let mut tree = ctx.chain.block_tree.write();
            let genesis_id = tree
                .insert_node(None, genesis.header, NodeStatus::Active)
                .expect("genesis");
            let sibling_id = tree
                .insert_node(Some(genesis_id), sibling.header, NodeStatus::Active)
                .expect("sibling");
            let active_id = tree
                .insert_node(Some(genesis_id), active.header, NodeStatus::Active)
                .expect("active sibling");
            tree.insert_node(Some(sibling_id), higher.header, NodeStatus::HeaderValid)
                .expect("higher header fork");
            let node = tree.node(active_id).expect("active node");
            bitcoin_rs_chain::chain::TipSnapshot {
                tip_id: active_id,
                chain_tx_count: node.chain_tx_count,
                hash: node.hash,
                height: node.height,
                chainwork: node.chainwork,
            }
        };
        ctx.chain.applied_tip.store(Some(Arc::new(active_tip)));
        let ctx = Arc::new(ctx);
        for (block, depth) in [(&genesis, 2), (&active, 1), (&sibling, 0), (&higher, 0)] {
            let tx = &block.txs[0];
            let args = json!([tx.txid().to_string(), true, block.block_hash().to_string()]);
            let value = getrawtransaction(&ctx, &args).expect("verbose lookup");
            assert_eq!(
                value.get("in_active_chain").and_then(Value::as_bool),
                Some(depth > 0)
            );
            assert_eq!(
                value.get("confirmations").and_then(Value::as_u64),
                Some(depth)
            );
            assert_eq!(
                value.get("blockhash").and_then(Value::as_str),
                Some(block.block_hash().to_string().as_str())
            );
            for field in ["time", "blocktime"] {
                assert_eq!(
                    value.get(field).and_then(Value::as_u64),
                    (depth > 0).then_some(u64::from(block.header.time))
                );
                if depth == 0 {
                    assert!(
                        value.get(field).is_none(),
                        "inactive {field} must be absent"
                    );
                }
            }
            let raw = getrawtransaction(
                &ctx,
                &json!([tx.txid().to_string(), false, block.block_hash().to_string()]),
            )
            .expect("raw lookup");
            assert_eq!(
                raw.as_str(),
                Some(consensus_bytes(tx).to_lower_hex_string().as_str())
            );
        }
        let missing = getrawtransaction(
            &ctx,
            &json!([
                sibling.txs[0].txid().to_string(),
                true,
                active.block_hash().to_string()
            ]),
        );
        assert!(matches!(
            missing,
            Err(RpcError::NotFound("transaction not in specified block"))
        ));
    }

    #[test]
    fn getrawtransaction_resolves_confirmed_transaction_from_txindex_without_cache() {
        struct StaticQuery {
            tx: Tx,
            block: TransactionBlock,
        }

        impl DerivedIndexQuery for StaticQuery {
            fn transaction(&self, txid: &Txid) -> Result<Option<Tx>, TxQueryError> {
                Ok((self.tx.txid() == *txid).then(|| self.tx.clone()))
            }

            fn outpoint_value(&self, _outpoint: &OutPoint) -> Result<Option<u64>, TxQueryError> {
                Ok(None)
            }

            fn transaction_block(
                &self,
                txid: &Txid,
            ) -> Result<Option<(Tx, TransactionBlock)>, TxQueryError> {
                Ok((self.tx.txid() == *txid).then(|| (self.tx.clone(), self.block)))
            }

            fn index_info(&self) -> Result<crate::context::DerivedIndexInfo, TxQueryError> {
                Ok(crate::context::DerivedIndexInfo {
                    synced: true,
                    best_block_height: 1,
                    applied_height: 1,
                    historical_height: 1,
                    verified_height: 1,
                    coverage_height: 1,
                })
            }
        }

        let mut genesis = fixture_genesis();
        genesis.txs[0].version = 1_u32 << 31;
        genesis.header.merkle_root = genesis.txs[0].txid().0;
        let Some(coinbase) = genesis.txs.first().cloned() else {
            panic!("genesis has no transactions");
        };
        let txid = coinbase.txid();
        let mut ctx = Context::new();
        ctx.indexes.derived_index = Some(Arc::new(StaticQuery {
            tx: coinbase.clone(),
            block: TransactionBlock {
                height: 0,
                hash: genesis.block_hash().into(),
            },
        }));
        ctx.chain.add_block(BlockRecord::from_block(0, &genesis));
        let tip = {
            let mut tree = ctx.chain.block_tree.write();
            tree.insert_node(None, genesis.header, NodeStatus::Active)
                .expect("genesis");
            tree.tip().expect("genesis tip")
        };
        ctx.chain.applied_tip.store(Some(Arc::new((*tip).clone())));
        let ctx = Arc::new(ctx);

        let result = getrawtransaction(&ctx, &json!([txid.to_string()]))
            .unwrap_or_else(|err| panic!("txindex lookup failed: {err}"));

        let expected = consensus_bytes(&coinbase).to_lower_hex_string();
        assert_eq!(result.as_str(), Some(expected.as_str()));
        let verbose = getrawtransaction(&ctx, &json!([txid.to_string(), true]))
            .expect("verbose txindex lookup");
        assert!(verbose.get("in_active_chain").is_none());
        assert_eq!(verbose["version"].as_u64(), Some(2_147_483_648));
        for field in ["time", "blocktime"] {
            assert_eq!(
                verbose[field].as_u64(),
                Some(u64::from(genesis.header.time))
            );
        }
        assert_eq!(
            verbose.get("confirmations").and_then(Value::as_u64),
            Some(1)
        );
    }

    #[test]
    fn getrawtransaction_with_blockhash_reports_pruned_block_body() {
        let ctx = Arc::new(Context::new());
        let genesis = fixture_genesis();
        let Some(coinbase) = genesis.txs.first() else {
            panic!("genesis has no transactions");
        };
        let txid = coinbase.txid();
        let record = BlockRecord::from_block(0, &genesis);
        let block_hash = record.hash;
        ctx.chain
            .block_tree
            .write()
            .insert_node(None, genesis.header, NodeStatus::Active)
            .expect("insert genesis header");
        ctx.chain.add_block(record);

        let result = getrawtransaction(
            &ctx,
            &json!([txid.to_string(), false, block_hash.to_string()]),
        );

        assert!(matches!(
            result,
            Err(RpcError::NotFound("block data pruned"))
        ));
    }

    #[test]
    fn getrawtransaction_with_blockhash_reports_pruned_body_for_a_header_only_block() {
        let ctx = Arc::new(Context::new());
        let genesis = fixture_genesis();
        let Some(coinbase) = genesis.txs.first() else {
            panic!("genesis has no transactions");
        };
        let block_hash = genesis.block_hash();
        ctx.chain
            .block_tree
            .write()
            .insert_node(None, genesis.header, NodeStatus::HeaderValid)
            .expect("insert header-only block");

        let result = getrawtransaction(
            &ctx,
            &json!([coinbase.txid().to_string(), false, block_hash.to_string()]),
        );

        assert!(matches!(
            result,
            Err(RpcError::NotFound("block data pruned"))
        ));
    }

    #[test]
    fn getrawtransaction_with_unknown_blockhash_errors() {
        let ctx = Arc::new(Context::new());
        let handler = Handler::new(Arc::clone(&ctx));
        let bogus_hash =
            bitcoin_rs_consensus::primitives::Hash256::from_le_bytes(&[7_u8; 32]).to_string_be();
        let result = handler.dispatch(
            "getrawtransaction",
            &json!([
                "0000000000000000000000000000000000000000000000000000000000000000",
                false,
                bogus_hash
            ]),
        );
        assert!(result.is_err());
    }

    #[test]
    fn gettxoutproof_finds_genesis_coinbase_through_the_index() {
        let genesis = fixture_genesis();
        let Some(coinbase) = genesis.txs.first() else {
            panic!("genesis has no transactions");
        };
        let txid = coinbase.txid();
        let mut ctx = Context::new();
        ctx.indexes.derived_index = Some(Arc::new(HeightQuery(resolving(&genesis, 0))));
        install_chain_blocks(&mut ctx, std::slice::from_ref(&genesis));
        let ctx = Arc::new(ctx);
        let handler = Handler::new(Arc::clone(&ctx));
        let result = handler
            .dispatch("gettxoutproof", &json!([[txid.to_string()]]))
            .unwrap_or_else(|err| panic!("gettxoutproof failed: {err}"));
        let Some(proof_hex) = result.as_str() else {
            panic!("expected string, got {result:?}");
        };

        let extracted = handler
            .dispatch("verifytxoutproof", &json!([proof_hex]))
            .unwrap_or_else(|err| panic!("verifytxoutproof failed: {err}"));
        let Some(arr) = extracted.as_array() else {
            panic!("expected array, got {extracted:?}");
        };
        assert_eq!(arr.len(), 1);
    }

    // API-02
    #[test]
    fn gettxoutproof_with_blockhash_answers_core_message_for_a_bodyless_block() {
        let ctx = Arc::new(Context::new());
        let genesis = fixture_genesis();
        let Some(coinbase) = genesis.txs.first() else {
            panic!("genesis has no transactions");
        };
        let txid = coinbase.txid();
        let record = BlockRecord::from_block(0, &genesis);
        ctx.chain
            .block_tree
            .write()
            .insert_node(None, genesis.header, NodeStatus::Active)
            .expect("insert genesis header");
        let block_hash = record.hash;
        ctx.chain.add_block(record);
        let handler = Handler::new(Arc::clone(&ctx));

        let result = handler.dispatch(
            "gettxoutproof",
            &json!([[txid.to_string()], block_hash.to_string()]),
        );

        assert!(
            matches!(
                result,
                Err(RpcError::Misc(reason))
                    if reason == "Block not available (not fully downloaded)"
            ),
            "Core v31.1 answers RPC_MISC_ERROR not fully downloaded for a bodyless block"
        );
    }

    // API-02
    #[test]
    fn gettxoutproof_with_blockhash_answers_core_message_for_a_header_only_block() {
        let ctx = Arc::new(Context::new());
        let genesis = fixture_genesis();
        let Some(coinbase) = genesis.txs.first() else {
            panic!("genesis has no transactions");
        };
        let block_hash = genesis.block_hash();
        ctx.chain
            .block_tree
            .write()
            .insert_node(None, genesis.header, NodeStatus::HeaderValid)
            .expect("insert header-only block");
        let handler = Handler::new(Arc::clone(&ctx));

        let result = handler.dispatch(
            "gettxoutproof",
            &json!([[coinbase.txid().to_string()], block_hash.to_string()]),
        );

        assert!(
            matches!(
                result,
                Err(RpcError::Misc(reason))
                    if reason == "Block not available (not fully downloaded)"
            ),
            "Core v31.1 answers RPC_MISC_ERROR not fully downloaded for a header-only block"
        );
    }

    // API-02
    #[test]
    fn gettxoutproof_without_blockhash_answers_from_the_utxo_set() {
        let mut genesis = fixture_genesis();
        let tx = many_output_tx(8);
        let txid = tx.txid();
        let live_vout = 7;
        let live_output = tx.outputs[live_vout].clone();
        genesis.txs.push(tx);
        genesis.header.merkle_root =
            bitcoin_rs_chain::chain::regtest_fixture::merkle_root(&genesis.txs)
                .expect("fixture merkle root");
        let mut ctx = Context::new();
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(
            OutPoint::new(
                txid,
                u32::try_from(live_vout).expect("fixture output index"),
            ),
            live_output,
            false,
            0,
        ));
        ctx.populate_fixture_coins(&changes)
            .unwrap_or_else(|err| panic!("commit_block failed: {err}"));
        assert!(
            ctx.chain
                .utxo
                .get_entry(&OutPoint::new(txid, 0))
                .expect("read absent output")
                .is_none()
        );
        install_chain_blocks(&mut ctx, std::slice::from_ref(&genesis));
        let ctx = Arc::new(ctx);
        let handler = Handler::new(Arc::clone(&ctx));

        let value = handler
            .dispatch("gettxoutproof", &json!([[txid.to_string()]]))
            .unwrap_or_else(|err| panic!("gettxoutproof failed: {err}"));
        let Some(proof_hex) = value.as_str() else {
            panic!("expected proof hex, got {value:?}");
        };
        let extracted = handler
            .dispatch("verifytxoutproof", &json!([proof_hex]))
            .unwrap_or_else(|err| panic!("verifytxoutproof failed: {err}"));
        let Some(arr) = extracted.as_array() else {
            panic!("expected array, got {extracted:?}");
        };
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0].as_str(), Some(txid.to_string()).as_deref());
    }

    #[test]
    fn gettxoutproof_reports_unreadable_coin_instead_of_transaction_absence()
    -> Result<(), crate::test_error::TestError> {
        let txid = many_output_tx(8).txid();
        let mut ctx = Context::new();
        ctx.chain.utxo =
            crate::test_coins::utxo_reader_with_undecodable_coin(&Hash256::from(txid))?;
        let result = proof_for(&Arc::new(ctx), &[txid]);
        assert!(matches!(result, Err(RpcError::Internal(_))));
        Ok(())
    }

    // API-02
    #[test]
    fn gettxoutproof_without_blockhash_answers_core_message_when_the_transaction_is_unknown() {
        let genesis = fixture_genesis();
        let Some(coinbase) = genesis.txs.first() else {
            panic!("genesis has no transactions");
        };
        let txid = coinbase.txid();
        let mut ctx = Context::new();
        let source = Arc::new(CountingBodySource::default());
        let body_source: Arc<dyn bitcoin_rs_storage::block_body::BlockBodySource> =
            Arc::<CountingBodySource>::clone(&source);
        ctx.chain.block_body_source = Some(body_source);
        ctx.chain.add_block(BlockRecord::from_block(0, &genesis));
        ctx.chain.add_block(BlockRecord::from_block(1, &genesis));
        let ctx = Arc::new(ctx);
        let handler = Handler::new(Arc::clone(&ctx));

        let error = handler
            .dispatch("gettxoutproof", &json!([[txid.to_string()]]))
            .expect_err("a transaction with no coin and no index must answer Core's miss");

        assert_eq!(
            error.code(),
            RpcError::CORE_NOT_FOUND,
            "Core answers -5 for a transaction it cannot place: {error}"
        );
        assert_eq!(
            error.to_string(),
            "Transaction not yet in block",
            "Core's miss text for a transaction outside the UTXO set and index"
        );
        assert_eq!(
            source.calls.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "the miss must not read any block body"
        );
    }

    fn many_output_tx(output_count: usize) -> Tx {
        use bitcoin_rs_consensus::primitives::{Amount, LockTime, Script, Sequence, Witness};
        let mut script = vec![0x76, 0xa9, 0x14];
        script.extend_from_slice(&[0x11_u8; 20]);
        script.push(0x88);
        script.push(0xac);
        let script = Script::from_bytes(script);
        let outputs = (0..output_count)
            .map(|_index| TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: script.clone(),
            })
            .collect::<Vec<_>>();
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[0x5a; 32])), 0),
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs,
        }
    }

    fn fund_coin(ctx: &Context, outpoint: OutPoint, value_sat: u64) {
        use bitcoin_rs_consensus::primitives::{Amount, Script};
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(
            outpoint,
            TxOut {
                value: Amount::from_sat(value_sat),
                script_pubkey: Script::from_bytes(vec![0x51]),
            },
            false,
            0,
        ));
        ctx.populate_fixture_coins(&changes)
            .unwrap_or_else(|err| panic!("commit_block failed: {err}"));
    }

    fn distinct_block(marker: u8) -> Block {
        use bitcoin_rs_consensus::primitives::Script;
        let mut block = fixture_genesis();
        if let Some(input) = block.txs.first_mut().and_then(|tx| tx.inputs.first_mut()) {
            input.script_sig = Script::from_bytes(vec![marker; 4]);
        }
        block.header.merkle_root =
            bitcoin_rs_chain::chain::regtest_fixture::merkle_root(&block.txs).unwrap_or_default();
        block
    }

    fn block_with_two_txs(marker: u8) -> Block {
        use bitcoin_rs_consensus::primitives::{Amount, LockTime, Script, Sequence, Witness};
        let mut block = distinct_block(marker);
        let extra = Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[marker; 32])), 0),
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000 + u64::from(marker)),
                script_pubkey: Script::from_bytes(vec![0x51]),
            }],
        };
        block.txs.push(extra);
        block.header.merkle_root =
            bitcoin_rs_chain::chain::regtest_fixture::merkle_root(&block.txs).unwrap_or_default();
        block
    }

    struct HeightQuery<F>(F);

    impl<F> DerivedIndexQuery for HeightQuery<F>
    where
        F: Fn(&Txid) -> Result<Option<(Tx, TransactionBlock)>, TxQueryError> + Send + Sync,
    {
        fn transaction(&self, _txid: &Txid) -> Result<Option<Tx>, TxQueryError> {
            Ok(None)
        }

        fn outpoint_value(&self, _outpoint: &OutPoint) -> Result<Option<u64>, TxQueryError> {
            Ok(None)
        }

        fn index_info(&self) -> Result<crate::context::DerivedIndexInfo, TxQueryError> {
            Ok(crate::context::DerivedIndexInfo {
                synced: true,
                best_block_height: 0,
                applied_height: 0,
                historical_height: 0,
                verified_height: 0,
                coverage_height: 0,
            })
        }

        fn transaction_block(
            &self,
            txid: &Txid,
        ) -> Result<Option<(Tx, TransactionBlock)>, TxQueryError> {
            (self.0)(txid)
        }
    }

    fn resolving(
        block: &Block,
        height: u32,
    ) -> impl Fn(&Txid) -> Result<Option<(Tx, TransactionBlock)>, TxQueryError> + use<> {
        let transactions = block.txs.clone();
        let identity = TransactionBlock {
            height,
            hash: block.block_hash().into(),
        };
        move |txid| {
            Ok(transactions
                .iter()
                .find(|tx| tx.txid() == *txid)
                .map(|tx| (tx.clone(), identity)))
        }
    }

    struct PanicUnlessBodySource {
        height: u32,
        hash: BlockHash,
        body: Vec<u8>,
    }

    impl bitcoin_rs_storage::block_body::BlockBodySource for PanicUnlessBodySource {
        fn block_body(
            &self,
            height: u32,
            hash: BlockHash,
        ) -> Result<Option<Vec<u8>>, bitcoin_rs_storage::block_body::BlockBodyReadError> {
            if height == self.height && hash == self.hash {
                Ok(Some(self.body.clone()))
            } else {
                panic!("should not load unrelated body {height}:{hash}");
            }
        }
    }

    use crate::context::BlockBodies;

    #[derive(Default)]
    struct CountingBodySource {
        calls: core::sync::atomic::AtomicUsize,
    }

    impl bitcoin_rs_storage::block_body::BlockBodySource for CountingBodySource {
        fn block_body(
            &self,
            _height: u32,
            _hash: BlockHash,
        ) -> Result<Option<Vec<u8>>, bitcoin_rs_storage::block_body::BlockBodyReadError> {
            self.calls
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            Ok(None)
        }
    }

    fn install_blocks(ctx: &mut Context, blocks: &[Block]) {
        let mut records = Vec::with_capacity(blocks.len());
        let mut bodies = Vec::with_capacity(blocks.len());
        for (height, block) in blocks.iter().enumerate() {
            let record = BlockRecord::from_block(
                u32::try_from(height).unwrap_or_else(|err| panic!("height: {err}")),
                block,
            );
            bodies.push((record.height, record.hash, consensus_bytes(block)));
            records.push(record);
        }
        ctx.chain.block_body_source = Some(Arc::new(BlockBodies { bodies }));
        for record in records {
            ctx.chain.add_block(record);
        }
    }

    fn install_chain_blocks(ctx: &mut Context, blocks: &[Block]) {
        install_blocks(ctx, blocks);
        let tip = {
            let mut tree = ctx.chain.block_tree.write();
            let mut parent: Option<NodeId> = None;
            for block in blocks {
                parent = Some(
                    tree.insert_node(parent, block.header, NodeStatus::Active)
                        .unwrap_or_else(|err| panic!("insert chain header: {err}")),
                );
            }
            let tip_id = parent.expect("chain blocks produce a tip");
            let node = tree.node(tip_id).expect("tip node");
            Arc::new(TipSnapshot {
                tip_id,
                height: node.height,
                chainwork: node.chainwork,
                hash: node.hash,
                chain_tx_count: node.chain_tx_count,
            })
        };
        ctx.chain.applied_tip.store(Some(tip));
    }

    fn attach_body_for_block(ctx: &mut Context, block: &Block, height: u32) {
        let record = BlockRecord::from_block(height, block);
        ctx.chain.block_body_source = Some(Arc::new(BlockBodies {
            bodies: vec![(record.height, record.hash, consensus_bytes(block))],
        }));
    }

    fn proof_for(ctx: &Arc<Context>, txids: &[Txid]) -> Result<sonic_rs::Value, RpcError> {
        let names = txids.iter().map(ToString::to_string).collect::<Vec<_>>();
        super::gettxoutproof(ctx, &json!([names]), &LatchReader::fixture_never())
    }

    #[test]

    fn gettxoutproof_index_path_does_not_read_unrelated_block_bodies() {
        let block = distinct_block(3);
        let Some(wanted) = block.txs.first().map(Tx::txid) else {
            panic!("block has no transactions");
        };
        let indexed = BlockRecord::from_block(2, &block);
        let mut ctx = Context::new();
        ctx.indexes.derived_index = Some(Arc::new(HeightQuery(resolving(&block, 2))));
        ctx.chain.block_body_source = Some(Arc::new(PanicUnlessBodySource {
            height: indexed.height,
            hash: indexed.hash,
            body: consensus_bytes(&block),
        }));
        ctx.chain.add_block(BlockRecord::synthetic(
            0,
            BlockHash::from(Hash256::from_le_bytes(&[7_u8; 32])),
        ));
        ctx.chain.add_block(BlockRecord::synthetic(
            1,
            BlockHash::from(Hash256::from_le_bytes(&[8_u8; 32])),
        ));
        ctx.chain.add_block(indexed);
        let ctx = Arc::new(ctx);

        let result = proof_for(&ctx, &[wanted]);

        assert!(
            result.as_ref().is_ok_and(|value| value.as_str().is_some()),
            "index path should answer from the indexed block alone: {result:?}"
        );
    }

    // API-02
    #[test]
    fn gettxoutproof_keeps_its_error_when_no_block_holds_every_txid() {
        let blocks = [distinct_block(1), distinct_block(2)];
        let wanted = blocks
            .iter()
            .filter_map(|block| block.txs.first().map(Tx::txid))
            .collect::<Vec<_>>();

        let mut index_ctx = Context::new();
        let indexed_blocks = blocks.clone();
        index_ctx.indexes.derived_index = Some(Arc::new(HeightQuery(move |txid: &Txid| {
            Ok(indexed_blocks
                .iter()
                .zip(0_u32..)
                .find_map(|(block, height)| {
                    block.txs.iter().find(|tx| tx.txid() == *txid).map(|tx| {
                        (
                            tx.clone(),
                            TransactionBlock {
                                height,
                                hash: block.block_hash().into(),
                            },
                        )
                    })
                }))
        })));
        install_blocks(&mut index_ctx, &blocks);
        let index_ctx = Arc::new(index_ctx);

        let result = proof_for(&index_ctx, &wanted);

        assert!(
            matches!(
                &result,
                Err(RpcError::InvalidAddressOrKey(reason))
                    if reason == "Not all transactions found in specified or retrieved block"
            ),
            "a resolved block missing txids must answer Core's not-all error: {result:?}"
        );
    }

    #[test]
    fn gettxoutproof_index_path_answers_for_several_txids_in_one_block() {
        let genesis = fixture_genesis();
        let mut block = block_with_two_txs(11);
        block.header.prev_blockhash = genesis.block_hash();
        let wanted = block.txs.iter().map(Tx::txid).collect::<Vec<_>>();

        let mut ctx = Context::new();
        ctx.indexes.derived_index = Some(Arc::new(HeightQuery(resolving(&block, 1))));
        install_chain_blocks(&mut ctx, &[genesis, block]);
        let ctx = Arc::new(ctx);

        let proof = proof_for(&ctx, &wanted).expect("proof generation must succeed");
        let proof_hex = proof.as_str().expect("proof hex string");
        let verified = super::verifytxoutproof(&ctx, &json!([proof_hex]))
            .unwrap_or_else(|err| panic!("verifytxoutproof failed: {err}"));
        let mut verified_txids: Vec<_> = verified
            .as_array()
            .expect("array of txids")
            .iter()
            .map(|v| v.as_str().expect("txid string").to_owned())
            .collect();
        let mut expected_txids: Vec<_> = wanted.iter().map(ToString::to_string).collect();
        verified_txids.sort();
        expected_txids.sort();
        assert_eq!(verified_txids, expected_txids);
    }

    // API-02
    #[test]
    fn gettxoutproof_asks_the_index_about_the_first_txid_only() {
        let block = block_with_two_txs(12);
        let mut wanted: Vec<Txid> = block.txs.iter().map(Tx::txid).collect();
        wanted.sort_unstable();
        let Some(first) = wanted.first().copied() else {
            panic!("block has no transactions");
        };

        let resolve = resolving(&block, 1);
        let mut ctx = Context::new();
        ctx.indexes.derived_index = Some(Arc::new(HeightQuery(move |txid: &Txid| {
            if *txid == first {
                resolve(txid)
            } else {
                panic!("the index must not be asked about later txids: {txid}")
            }
        })));
        let indexed = BlockRecord::from_block(1, &block);
        ctx.chain.block_body_source = Some(Arc::new(PanicUnlessBodySource {
            height: indexed.height,
            hash: indexed.hash,
            body: consensus_bytes(&block),
        }));
        ctx.chain.add_block(BlockRecord::synthetic(
            0,
            BlockHash::from(Hash256::from_le_bytes(&[6_u8; 32])),
        ));
        ctx.chain.add_block(indexed);
        let ctx = Arc::new(ctx);

        let result = proof_for(&ctx, &wanted);

        assert!(
            result.as_ref().is_ok_and(|value| value.as_str().is_some()),
            "one index answer for the first txid must resolve the whole proof: {result:?}"
        );
    }

    #[test]
    fn gettxoutproof_maps_a_transient_index_error_instead_of_reporting_absence() {
        let block = distinct_block(5);
        let Some(wanted) = block.txs.first().map(Tx::txid) else {
            panic!("block has no transactions");
        };
        let mut ctx = Context::new();
        ctx.indexes.derived_index = Some(Arc::new(HeightQuery(
            |_: &Txid| -> Result<Option<(Tx, TransactionBlock)>, TxQueryError> {
                Err(TxQueryError::Retry(
                    bitcoin_rs_index::RetryReason::TipMoved {
                        expected_revision: 0,
                        current_revision: 1,
                    },
                ))
            },
        )));
        install_blocks(&mut ctx, std::slice::from_ref(&block));
        let ctx = Arc::new(ctx);

        let error = proof_for(&ctx, &[wanted])
            .expect_err("a transient index failure is not an absence answer");

        assert_eq!(
            error.code(),
            -32603,
            "a transient index failure must not read as 'no block contains the txid': {error}"
        );
        assert_eq!(
            error.to_string(),
            "internal error: transaction index is still catching up; retry later"
        );
    }

    // API-02
    #[test]
    fn gettxoutproof_index_path_reports_the_missing_body() {
        let block = distinct_block(6);
        let Some(wanted) = block.txs.first().map(Tx::txid) else {
            panic!("block has no transactions");
        };
        let mut ctx = Context::new();
        ctx.indexes.derived_index = Some(Arc::new(HeightQuery(resolving(&block, 1))));
        ctx.chain.add_block(BlockRecord::synthetic(
            0,
            BlockHash::from(Hash256::from_le_bytes(&[9_u8; 32])),
        ));
        ctx.chain.add_block(BlockRecord::from_block(1, &block));
        let ctx = Arc::new(ctx);

        let error = proof_for(&ctx, &[wanted]).expect_err("a missing indexed body is not absence");

        assert!(
            matches!(
                error,
                RpcError::Misc(reason)
                    if reason == "Block not available (not fully downloaded)"
            ),
            "the indexed height holds no body, so the answer is Core's not-downloaded error"
        );
    }

    // API-02
    #[test]
    fn gettxoutproof_answers_core_pruned_message_when_the_node_has_pruned() {
        let block = distinct_block(6);
        let Some(wanted) = block.txs.first().map(Tx::txid) else {
            panic!("block has no transactions");
        };
        let mut ctx = Context::new();
        ctx.indexes.derived_index = Some(Arc::new(HeightQuery(resolving(&block, 1))));
        ctx.chain.add_block(BlockRecord::synthetic(
            0,
            BlockHash::from(Hash256::from_le_bytes(&[9_u8; 32])),
        ));
        ctx.chain.add_block(BlockRecord::from_block(1, &block));
        ctx.chain.prune_service = Some(Arc::new(PrunedStub));
        let ctx = Arc::new(ctx);

        let error = proof_for(&ctx, &[wanted]).expect_err("a missing body on a pruned node");

        assert!(
            matches!(
                error,
                RpcError::Misc(reason) if reason == "Block not available (pruned data)"
            ),
            "Core v31.1 answers RPC_MISC_ERROR pruned data once the node has pruned"
        );
    }

    struct PrunedStub;

    impl crate::context::PruneService for PrunedStub {
        fn prune_to_height(
            &self,
            _requested_height: u32,
        ) -> Result<crate::context::PruneResult, crate::context::PruneServiceError> {
            Err(crate::context::PruneServiceError::Failed(
                "pruning is stubbed".to_owned(),
            ))
        }

        fn status(&self) -> crate::context::PruneStatus {
            crate::context::PruneStatus {
                pruned: true,
                pruneheight: Some(0),
            }
        }
    }

    // API-02
    #[test]
    fn gettxoutproof_answers_core_message_for_an_empty_txid_list() {
        let ctx = Arc::new(Context::new());
        let handler = Handler::new(Arc::clone(&ctx));

        let result = handler.dispatch("gettxoutproof", &json!([[]]));

        assert!(
            matches!(
                result,
                Err(RpcError::InvalidParameter(reason))
                    if reason == "Parameter 'txids' cannot be empty"
            ),
            "Core v31.1 answers RPC_INVALID_PARAMETER for an empty txid list"
        );
    }

    // API-02
    #[test]
    fn gettxoutproof_answers_core_message_for_a_duplicated_txid() {
        let block = distinct_block(7);
        let Some(txid) = block.txs.first().map(Tx::txid) else {
            panic!("block has no transactions");
        };
        let raw = txid.to_string();
        let handler = Handler::new(Arc::new(Context::new()));

        let result = handler.dispatch("gettxoutproof", &json!([[raw.clone(), raw.clone()]]));

        assert!(
            matches!(
                result,
                Err(RpcError::InvalidParameter(reason))
                    if reason == format!("Invalid parameter, duplicated txid: {raw}")
            ),
            "Core v31.1 rejects a duplicated txid naming the raw input"
        );
    }

    // API-02
    #[test]
    fn gettxoutproof_answers_a_type_error_for_a_non_string_blockhash() {
        let block = distinct_block(8);
        let Some(txid) = block.txs.first().map(Tx::txid) else {
            panic!("block has no transactions");
        };
        let handler = Handler::new(Arc::new(Context::new()));

        let result = handler.dispatch("gettxoutproof", &json!([[txid.to_string()], 123]));

        let message = match result {
            Err(RpcError::InvalidType(message)) => message,
            other => {
                panic!("Core v31.1 answers a -3 type error for a numeric blockhash: {other:?}")
            }
        };
        assert_eq!(
            message,
            "Wrong type passed:\n{\n    \"Position 2 (blockhash)\": \"JSON value of type number is not of expected type string\"\n}",
            "Core v31.1 answers the RPCHelpMan wrong type shape for a numeric blockhash"
        );
    }

    // API-02
    #[test]
    fn gettxoutproof_answers_core_wrong_type_for_a_non_array_txid_list() {
        let handler = Handler::new(Arc::new(Context::new()));

        let result = handler.dispatch("gettxoutproof", &json!([42]));

        let message = match result {
            Err(RpcError::InvalidType(message)) => message,
            other => {
                panic!(
                    "Core v31.1 answers the RPCHelpMan wrong type shape for a non array txids: {other:?}"
                )
            }
        };
        assert_eq!(
            message,
            "Wrong type passed:\n{\n    \"Position 1 (txids)\": \"JSON value of type number is not of expected type array\"\n}",
            "Core v31.1 names Position 1 for a non array txids argument"
        );
    }

    // API-02
    #[test]
    fn gettxoutproof_answers_core_type_error_for_a_non_string_txid_element() {
        let handler = Handler::new(Arc::new(Context::new()));

        let result = handler.dispatch("gettxoutproof", &json!([[42]]));

        let message = match result {
            Err(RpcError::InvalidType(message)) => message,
            other => {
                panic!(
                    "Core v31.1 answers the univalue type error shape for a numeric txid: {other:?}"
                )
            }
        };
        assert_eq!(
            message, "JSON value of type number is not of expected type string",
            "Core v31.1 keeps the plain type error for an inner array element"
        );
    }

    // API-02
    #[test]
    fn gettxoutproof_answers_index_corrupt_when_the_index_names_an_absent_block() {
        let block = distinct_block(13);
        let Some(txid) = block.txs.first().map(Tx::txid) else {
            panic!("block has no transactions");
        };
        let mut ctx = Context::new();
        ctx.indexes.derived_index = Some(Arc::new(HeightQuery(resolving(&block, 3))));
        ctx.chain.add_block(BlockRecord::from_block(0, &block));
        let ctx = Arc::new(ctx);

        let result = proof_for(&ctx, &[txid]);

        let reason = match result {
            Err(RpcError::CoreInternal(reason)) => reason,
            other => panic!(
                "Core v31.1 answers -32603 when the index names a block the chain lacks: {other:?}"
            ),
        };
        assert_eq!(
            reason, "Transaction index corrupt",
            "Core v31.1 keeps the index corrupt text instead of the not yet in block answer"
        );
    }

    // API-02
    #[test]
    fn gettxoutproof_answers_block_not_found_for_an_unknown_blockhash() {
        let block = distinct_block(9);
        let Some(txid) = block.txs.first().map(Tx::txid) else {
            panic!("block has no transactions");
        };
        let unknown = Hash256::from_le_bytes(&[0xEE; 32]);
        let handler = Handler::new(Arc::new(Context::new()));

        let result = handler.dispatch(
            "gettxoutproof",
            &json!([[txid.to_string()], unknown.to_string()]),
        );

        assert!(
            matches!(
                result,
                Err(RpcError::InvalidAddressOrKey(reason)) if reason == "Block not found"
            ),
            "Core v31.1 answers Block not found for an unknown blockhash"
        );
    }

    struct CorruptBodySource {
        height: u32,
        hash: BlockHash,
    }

    impl bitcoin_rs_storage::block_body::BlockBodySource for CorruptBodySource {
        fn block_body(
            &self,
            height: u32,
            hash: BlockHash,
        ) -> Result<Option<Vec<u8>>, bitcoin_rs_storage::block_body::BlockBodyReadError> {
            if height == self.height && hash == self.hash {
                Ok(Some(vec![0xFF_u8; 80]))
            } else {
                Ok(None)
            }
        }
    }

    // API-02
    #[test]
    fn gettxoutproof_answers_core_read_error_for_an_undecodable_body() {
        let block = distinct_block(10);
        let Some(wanted) = block.txs.first().map(Tx::txid) else {
            panic!("block has no transactions");
        };
        let mut ctx = Context::new();
        ctx.indexes.derived_index = Some(Arc::new(HeightQuery(resolving(&block, 1))));
        ctx.chain.add_block(BlockRecord::synthetic(
            0,
            BlockHash::from(Hash256::from_le_bytes(&[9_u8; 32])),
        ));
        let record = BlockRecord::from_block(1, &block);
        ctx.chain.block_body_source = Some(Arc::new(CorruptBodySource {
            height: record.height,
            hash: record.hash,
        }));
        ctx.chain.add_block(record);
        let ctx = Arc::new(ctx);

        let error = proof_for(&ctx, &[wanted]).expect_err("an undecodable body is not absence");

        assert!(
            matches!(
                error,
                RpcError::CoreInternal(reason) if reason == "Can't read block from disk"
            ),
            "Core v31.1 answers Can't read block from disk instead of hiding storage damage"
        );
    }

    // API-02
    #[test]
    fn gettxoutproof_utxo_path_answers_interrupted_when_cancelled() {
        let block = distinct_block(11);
        let Some(txid) = block.txs.first().map(Tx::txid) else {
            panic!("block has no transactions");
        };
        let mut ctx = Context::new();
        attach_body_for_block(&mut ctx, &block, 1);
        ctx.chain.add_block(BlockRecord::synthetic(
            0,
            BlockHash::from(Hash256::from_le_bytes(&[3_u8; 32])),
        ));
        ctx.chain.add_block(BlockRecord::from_block(1, &block));
        let ctx = Arc::new(ctx);
        let latch = bitcoin_rs_consensus::latch::LatchWriter::new();
        latch.trigger();

        let cancelled = super::gettxoutproof(&ctx, &json!([[txid.to_string()]]), &latch.reader());
        assert!(
            matches!(
                cancelled,
                Err(RpcError::Misc(reason)) if reason == "gettxoutproof interrupted"
            ),
            "a cancelled request must stop the utxo probe"
        );
    }

    // API-02
    #[test]
    fn gettxoutproof_utxo_path_interrupts_for_a_mixed_txid_list() {
        let block = distinct_block(12);
        let Some(txid) = block.txs.first().map(Tx::txid) else {
            panic!("block has no transactions");
        };
        let unknown = Hash256::from_le_bytes(&[0x77; 32]);
        let unknown_txid = Txid(unknown);
        let mut ctx = Context::new();
        attach_body_for_block(&mut ctx, &block, 1);
        ctx.chain.add_block(BlockRecord::from_block(1, &block));
        let ctx = Arc::new(ctx);
        let latch = bitcoin_rs_consensus::latch::LatchWriter::new();
        latch.trigger();

        let cancelled = super::gettxoutproof(
            &ctx,
            &json!([[unknown_txid.to_string(), txid.to_string()]]),
            &latch.reader(),
        );
        assert!(
            matches!(
                cancelled,
                Err(RpcError::Misc(reason)) if reason == "gettxoutproof interrupted"
            ),
            "the per-txid check must fire before any lookup"
        );
    }

    #[test]
    fn gettxoutproof_with_blockhash_never_consults_the_index() {
        let block = distinct_block(4);
        let Some(wanted) = block.txs.first().map(Tx::txid) else {
            panic!("block has no transactions");
        };
        let record = BlockRecord::from_block(0, &block);
        let block_hash = record.hash;
        let mut ctx = Context::new();
        ctx.indexes.derived_index = Some(Arc::new(HeightQuery(
            |_: &Txid| -> Result<Option<(Tx, TransactionBlock)>, TxQueryError> {
                panic!("the explicit-blockhash path must not consult the index");
            },
        )));
        attach_body_for_block(&mut ctx, &block, 0);
        ctx.chain
            .block_tree
            .write()
            .insert_node(None, block.header, NodeStatus::Active)
            .expect("insert block header");
        ctx.chain.add_block(record);
        let ctx = Arc::new(ctx);

        let result = super::gettxoutproof(
            &ctx,
            &json!([[wanted.to_string()], block_hash.to_string()]),
            &LatchReader::fixture_never(),
        );

        assert!(
            result.as_ref().is_ok_and(|value| value.as_str().is_some()),
            "the explicit-blockhash path should answer without the index: {result:?}"
        );
    }

    fn retry_spendable_script() -> Vec<u8> {
        let mut script = vec![0x00, 0x20];
        script.extend_from_slice(&[
            0x4a, 0xe8, 0x15, 0x72, 0xf0, 0x6e, 0x1b, 0x88, 0xfd, 0x5c, 0xed, 0x7a, 0x1a, 0x00,
            0x09, 0x45, 0x43, 0x2e, 0x83, 0xe1, 0x55, 0x1e, 0x6f, 0x72, 0x1e, 0xe9, 0xc0, 0x0b,
            0x8c, 0xc3, 0x32, 0x60,
        ]);
        script
    }

    fn retry_fund_utxo(ctx: &Context, label: u8, value: u64) -> OutPoint {
        use bitcoin_rs_consensus::primitives::{Amount, Script};
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(
            OutPoint::new(Txid(Hash256::from_le_bytes(&[label; 32])), 0),
            TxOut {
                value: Amount::from_sat(value),
                script_pubkey: Script::from_bytes(retry_spendable_script()),
            },
            false,
            1,
        ));
        ctx.populate_fixture_coins(&changes)
            .unwrap_or_else(|err| panic!("commit_block failed: {err}"));
        OutPoint::new(Txid(Hash256::from_le_bytes(&[label; 32])), 0)
    }

    fn retry_tx(prevout: OutPoint, output_value: u64) -> Tx {
        use bitcoin_rs_consensus::primitives::{Amount, LockTime, Script, Sequence, Witness};
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: prevout,
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_stack(vec![vec![0x51]]),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(output_value),
                script_pubkey: Script::from_bytes(retry_spendable_script()),
            }],
        }
    }

    fn retry_raw_hex(tx: &Tx) -> String {
        consensus_bytes(tx).to_lower_hex_string()
    }

    #[test]
    fn sendrawtransaction_rebuilds_admission_context_after_transient_rejection() {
        let ctx = Arc::new(Context::new());
        reset_admission_park();

        let parent_prevout = retry_fund_utxo(&ctx, 0x70, 100_000);
        let parent = retry_tx(parent_prevout, 90_000);
        let parent_txid = parent.txid();
        let child_prevout = OutPoint::new(parent_txid, 0);
        let child = retry_tx(child_prevout, 80_000);
        let child_txid = child.txid();
        let child_hex = retry_raw_hex(&child);

        let (parked_tx, parked_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let target = Arc::as_ptr(&ctx.mempool.gateway).expose_provenance();
        arm_admission_park(target, parked_tx, release_rx);

        let ctx_clone = Arc::clone(&ctx);
        let handler = Handler::new(Arc::clone(&ctx));
        let admission =
            thread::spawn(move || handler.dispatch("sendrawtransaction", &json!([child_hex])));

        parked_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("first admission parked at the gateway seam");

        let guard = ctx_clone
            .mempool
            .gateway
            .begin_chain_change()
            .expect("begin chain change on even generation");
        guard
            .finish()
            .expect("finish chain change to next even generation");

        let parent_vsize = u32::try_from(parent.vsize()).unwrap_or(u32::MAX);
        ctx_clone
            .mempool
            .gateway
            .insert_entry(
                AdmissionOrigin::Rpc,
                MempoolEntry::new(
                    Arc::new(parent),
                    parent_vsize,
                    10_000,
                    bitcoin_rs_consensus::primitives::unix_time_secs(),
                    1,
                    0,
                ),
            )
            .expect("parent admitted to the mempool");

        release_tx.send(()).expect("release the parked admission");

        let result = admission.join().expect("admission thread did not panic");

        reset_admission_park();

        let txid_str = result
            .as_ref()
            .map_err(|err| format!("sendrawtransaction failed: {err}"))
            .and_then(|value| {
                value
                    .as_str()
                    .map(ToString::to_string)
                    .ok_or_else(|| format!("expected txid string, got {value:?}"))
            });
        assert_eq!(
            txid_str.expect("child admitted on retry"),
            child_txid.to_string(),
            "the retried admission must observe the fresh mempool state"
        );

        assert!(
            ctx.mempool.gateway.read().contains_txid(&child_txid),
            "the child must be pooled after successful retry"
        );
        assert!(
            ctx.mempool.gateway.read().contains_txid(&parent_txid),
            "the parent must remain pooled"
        );
    }

    // API-02
    #[test]
    fn verifytxoutproof_refuses_a_header_outside_the_active_chain()
    -> Result<(), crate::test_error::TestError> {
        let genesis = fixture_genesis();
        let Some(txid) = genesis.txs.first().map(Tx::txid) else {
            panic!("genesis has no transactions");
        };
        let mut ctx = Context::new();
        ctx.indexes.derived_index = Some(Arc::new(HeightQuery(resolving(&genesis, 0))));
        install_chain_blocks(&mut ctx, std::slice::from_ref(&genesis));
        let ctx = Arc::new(ctx);

        let proof = proof_for(&ctx, &[txid])?;
        let proof_hex = proof.as_str().expect("proof hex string");
        let bytes =
            bitcoin_rs_consensus::primitives::hex::hex_decode(proof_hex).expect("proof hex");
        let mut merkle_block =
            bitcoin::consensus::encode::deserialize::<bitcoin::merkle_tree::MerkleBlock>(&bytes)
                .expect("proof decodes");
        merkle_block.header.nonce = merkle_block.header.nonce.wrapping_add(1);
        let tampered = bitcoin::consensus::encode::serialize(&merkle_block).to_lower_hex_string();

        let refusal = match super::verifytxoutproof(&ctx, &json!([tampered])) {
            Err(RpcError::InvalidAddressOrKey(reason)) => reason,
            other => {
                panic!(
                    "Core v31.1 answers -5 for a header the active chain does not name: {other:?}"
                )
            }
        };
        assert_eq!(
            refusal, "Block not found in chain",
            "Core v31.1 names the missing chain entry"
        );
        Ok(())
    }

    // API-02
    #[test]
    fn verifytxoutproof_answers_an_empty_list_when_the_transaction_count_differs()
    -> Result<(), crate::test_error::TestError> {
        let genesis = fixture_genesis();
        let Some(txid) = genesis.txs.first().map(Tx::txid) else {
            panic!("genesis has no transactions");
        };
        let proof_hex = {
            let mut ctx = Context::new();
            ctx.indexes.derived_index = Some(Arc::new(HeightQuery(resolving(&genesis, 0))));
            install_chain_blocks(&mut ctx, std::slice::from_ref(&genesis));
            let proof = proof_for(&Arc::new(ctx), &[txid])?;
            proof.as_str().expect("proof hex string").to_owned()
        };

        let matching = {
            let mut ctx = Context::new();
            install_chain_blocks(&mut ctx, std::slice::from_ref(&genesis));
            Arc::new(ctx)
        };
        let listed = super::verifytxoutproof(&matching, &json!([proof_hex]))?;
        assert_eq!(
            listed.as_array().map(|items| items.len()),
            Some(1),
            "the same proof lists its transaction when the recorded count matches"
        );

        let mismatching = {
            let mut ctx = Context::new();
            let mut stale = BlockRecord::from_block(0, &genesis);
            stale.tx_count = 2;
            let hash = stale.hash;
            ctx.chain.block_body_source = Some(Arc::new(BlockBodies {
                bodies: vec![(0, hash, consensus_bytes(&genesis))],
            }));
            ctx.chain.add_block(stale);
            {
                let mut tree = ctx.chain.block_tree.write();
                tree.insert_node(None, genesis.header, NodeStatus::Active)
                    .expect("genesis header");
            }
            let tip = ctx.chain.block_tree.read().tip().expect("chain tip");
            ctx.chain.applied_tip.store(Some(Arc::new((*tip).clone())));
            Arc::new(ctx)
        };
        let mismatched = super::verifytxoutproof(&mismatching, &json!([proof_hex]))?;
        assert_eq!(
            mismatched.as_array().map(|items| items.len()),
            Some(0),
            "Core v31.1 lists nothing when the recorded transaction count differs"
        );

        let ctx = Context::new();
        {
            let mut tree = ctx.chain.block_tree.write();
            tree.insert_node(None, genesis.header, NodeStatus::Active)
                .expect("genesis header");
        }
        let header_only = Arc::new(ctx);
        let uncounted = super::verifytxoutproof(&header_only, &json!([proof_hex]));
        let uncounted_message = match uncounted {
            Err(RpcError::InvalidAddressOrKey(reason)) => reason,
            other => panic!(
                "Core v31.1 answers -5 while the chain entry records no transaction count: {other:?}"
            ),
        };
        assert_eq!(
            uncounted_message, "Block not found in chain",
            "Core v31.1 names the missing chain entry"
        );
        Ok(())
    }
}

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

    // API-02
    #[test]
    fn gettxout_reports_an_unreadable_coin_instead_of_null()
    -> Result<(), crate::test_error::TestError> {
        let txid = Hash256::from_le_bytes(&[0xD4; 32]);
        let mut ctx = Context::new();
        ctx.chain.utxo = crate::test_coins::utxo_reader_with_undecodable_coin(&txid)?;
        let ctx = Arc::new(ctx);
        let params = json!([Txid::from(txid).to_string(), 0_u64]);
        let result = gettxout(&ctx, &params);
        assert!(
            matches!(&result, Err(RpcError::Internal(_))),
            "expected an internal error for an unreadable coin, got {result:?}"
        );
        Ok(())
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod acceptance_tests {
    use alloc::sync::Arc;

    use bitcoin::hex::DisplayHex as _;
    use bitcoin_rs_chain::chain::{NodeId, NodeStatus, TipSnapshot};
    use bitcoin_rs_consensus::header_rules::BlockHeader;
    use bitcoin_rs_consensus::primitives::{
        Amount, BlockHash, CompactTarget, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn,
        TxOut, Txid, Witness, consensus_bytes,
    };
    use bitcoin_rs_storage::utxo::contract::{BlockChanges, UtxoAdd};
    use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, json};

    use super::{getrawtransaction, sendrawtransaction, testmempoolaccept};
    use crate::context::Context;
    use crate::error::RpcError;

    fn fixture_outpoint(tag: u8) -> OutPoint {
        OutPoint::new(Txid(Hash256::from_le_bytes(&[tag; 32])), 0)
    }

    fn p2sh_true_script() -> Script {
        let redeem = bitcoin::ScriptBuf::from_bytes(vec![0x51]);
        Script::from_bytes(redeem.to_p2sh().into_bytes())
    }

    fn p2sh_true_spend_script_sig() -> Script {
        Script::from_bytes(vec![0x01, 0x51])
    }

    fn seed_utxo(ctx: &Context, tag: u8, value: u64) {
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(
            fixture_outpoint(tag),
            TxOut {
                value: Amount::from_sat(value),
                script_pubkey: p2sh_true_script(),
            },
            false,
            7,
        ));
        ctx.populate_fixture_coins(&changes)
            .unwrap_or_else(|err| panic!("commit_block failed: {err}"));
    }

    fn spending_tx(tag: u8, output_value: u64) -> Tx {
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: fixture_outpoint(tag),
                script_sig: p2sh_true_spend_script_sig(),
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
        tx.inputs[0].witness.push(&[1_u8; 8]);
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
            bitcoin_rs_consensus::primitives::Network::Mainnet,
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
                        bitcoin_rs_chain::chain::regtest_fixture::REGTEST_BITS,
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
}

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
