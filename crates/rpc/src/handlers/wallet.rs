use alloc::sync::Arc;
use core::ops::RangeInclusive;
use core::str::FromStr as _;

use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::Hash as _;
use bitcoin::hex::{DisplayHex as _, FromHex as _};
use bitcoin::{Amount, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use bitcoin_rs_primitives::Hash256;
use hashbrown::HashMap;
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, Value, json};

use crate::context::Context;
use crate::error::RpcError;
use crate::handlers::{invalid_psbt, optional_bool, params_array, required_str};

const _: fn() -> Value = invalid_psbt;
const DEFAULT_RANGE_END: u32 = 1_000;
const MAX_DESCRIPTOR_RANGE_SPAN: u64 = 1_000_000;

pub(crate) fn getdescriptorinfo(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let descriptor = required_str(params, 0, "descriptor is required")?;
    let info = bitcoin_rs_wallet::Descriptor::info(descriptor).map_err(map_wallet_error)?;
    Ok(json!({
        "descriptor": info.descriptor,
        "checksum": info.checksum,
        "isrange": info.is_range,
        "issolvable": info.is_solvable,
        "hasprivatekeys": info.has_private_keys
    }))
}

pub(crate) fn deriveaddresses(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let descriptor = required_str(params, 0, "descriptor is required")?;
    let network = bitcoin_network(ctx.chain_network);
    let parsed = bitcoin_rs_wallet::Descriptor::parse(descriptor).map_err(map_wallet_error)?;
    let range = match params_array(params)?.get(1) {
        Some(value) if !value.is_null() => parse_range_value(value)?,
        Some(_) | None if parsed.is_ranged() => {
            return Err(RpcError::InvalidParameter(
                "Range must be specified for a ranged descriptor".to_owned(),
            ));
        }
        Some(_) | None => 0..=0,
    };
    let addresses = parsed
        .derive_addresses(network, range)
        .map_err(map_wallet_error)?;
    Ok(json!(
        addresses
            .into_iter()
            .map(|address| address.to_string())
            .collect::<Vec<_>>()
    ))
}

pub(crate) fn importdescriptors(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let wallet = require_wallet(ctx)?;
    let requests = params_array(params)?
        .first()
        .and_then(Value::as_array)
        .ok_or(RpcError::InvalidParams("requests must be an array"))?;
    if requests.is_empty() {
        return Err(RpcError::InvalidParams("requests must not be empty"));
    }

    let mut published = wallet.write();
    let mut prepared = published.clone();
    let mut results = Vec::with_capacity(requests.len());
    let mut changed = false;
    for request in requests {
        let result = import_one_descriptor(&mut prepared, request);
        if result.get("success").and_then(Value::as_bool) == Some(true) {
            changed = true;
        }
        results.push(result);
    }
    if changed {
        if let Err(error) = ctx.populate_wallet_utxos(&mut prepared) {
            return Ok(fail_successful_import_rows(results, &error));
        }
        if let Err(error) = ctx.persist_wallet(&prepared) {
            return Ok(fail_successful_import_rows(results, &error));
        }
        *published = prepared;
    }
    Ok(Value::from(results))
}

fn fail_successful_import_rows(results: Vec<Value>, error: &compact_str::CompactString) -> Value {
    Value::from(
        results
            .into_iter()
            .map(|row| {
                if row.get("success").and_then(Value::as_bool) == Some(true) {
                    descriptor_import_error(RpcError::CORE_MISC_ERROR, error.to_string())
                } else {
                    row
                }
            })
            .collect::<Vec<_>>(),
    )
}

pub(crate) fn scantxoutset(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let action = required_str(params, 0, "action is required")?;
    match action {
        "start" => scantxoutset_scan(ctx, scanobjects_param(params)?),
        "abort" => Ok(json!(false)),
        "status" => Ok(Value::new_null()),
        _ => Err(RpcError::InvalidParams(
            "action must be one of: start, abort, status",
        )),
    }
}

fn scanobjects_param(params: &Value) -> Result<&sonic_rs::Array, RpcError> {
    let array = params_array(params)?;
    let Some(scanobjects) = array.get(1) else {
        return Err(RpcError::InvalidParams(
            "scanobjects are required for scantxoutset start",
        ));
    };
    let scanobjects = scanobjects
        .as_array()
        .ok_or(RpcError::InvalidType("scanobjects must be an array"))?;
    if scanobjects.is_empty() {
        return Err(RpcError::InvalidParams("scanobjects must not be empty"));
    }
    Ok(scanobjects)
}

#[derive(Clone, Debug)]
struct ScanScript {
    script_pubkey: ScriptBuf,
    desc: String,
}

fn scantxoutset_scan(ctx: &Arc<Context>, scanobjects: &sonic_rs::Array) -> Result<Value, RpcError> {
    let scan_scripts = parse_scan_scripts(ctx.chain_network, scanobjects)?;
    let scripts = scan_scripts
        .iter()
        .map(|scan| scan.script_pubkey.clone())
        .collect::<Vec<_>>();
    let scan = ctx
        .utxo
        .scan_script_pubkeys(&scripts)
        .map_err(|error| RpcError::Internal(error.to_string()))?;
    let (unspents, total_amount) = scan_unspents(&scan, &scan_scripts, ctx.applied_height());
    Ok(json!({
        "success": true,
        "txouts": scan.txouts,
        "height": ctx.applied_height(),
        "bestblock": ctx.applied_hash().to_string_be(),
        "unspents": unspents,
        "total_amount": Amount::from_sat(total_amount).to_btc()
    }))
}

fn parse_scan_scripts(
    chain_network: bitcoin_rs_primitives::Network,
    scanobjects: &sonic_rs::Array,
) -> Result<Vec<ScanScript>, RpcError> {
    let network = bitcoin_network(chain_network);
    let mut scripts = Vec::new();
    for scanobject in scanobjects {
        scripts.extend(scanobject_scripts(scanobject, network)?);
    }
    Ok(scripts)
}

fn scanobject_scripts(
    scanobject: &Value,
    network: bitcoin::Network,
) -> Result<Vec<ScanScript>, RpcError> {
    let (descriptor, range) = if let Some(descriptor) = scanobject.as_str() {
        (descriptor, None)
    } else {
        let descriptor = scanobject
            .get("desc")
            .and_then(Value::as_str)
            .ok_or(RpcError::InvalidParams("scan object missing desc"))?;
        let range = match scanobject.get("range") {
            Some(value) => Some(parse_range_value(value)?),
            None => None,
        };
        (descriptor, range)
    };

    let info = bitcoin_rs_wallet::Descriptor::info(descriptor).map_err(map_wallet_error)?;
    let parsed = bitcoin_rs_wallet::Descriptor::parse(descriptor).map_err(map_wallet_error)?;
    let range = range.unwrap_or_else(|| {
        if parsed.is_ranged() {
            0..=DEFAULT_RANGE_END
        } else {
            0..=0
        }
    });
    parsed
        .derive_addresses(network, range)
        .map_err(map_wallet_error)?
        .into_iter()
        .map(|address| {
            Ok(ScanScript {
                script_pubkey: address.script_pubkey(),
                desc: info.descriptor.clone(),
            })
        })
        .collect()
}

fn scan_unspents(
    scan: &bitcoin_rs_utxo::UtxoScan,
    scan_scripts: &[ScanScript],
    applied_height: u32,
) -> (Vec<Value>, u64) {
    let descs = scan_scripts
        .iter()
        .map(|scan| (scan.script_pubkey.as_bytes(), scan.desc.as_str()))
        .collect::<HashMap<_, _>>();
    let mut total_amount = 0_u64;
    let unspents = scan
        .unspents
        .iter()
        .map(|utxo| {
            total_amount = total_amount.saturating_add(utxo.txout.value.to_sat());
            let desc = descs
                .get(utxo.txout.script_pubkey.as_bytes())
                .copied()
                .unwrap_or("");
            let outpoint = utxo.outpoint;
            let txid = outpoint.txid;
            let vout = outpoint.vout;
            json!({
                "txid": txid.to_string_be(),
                "vout": vout,
                "scriptPubKey": utxo.txout.script_pubkey.as_bytes().to_lower_hex_string(),
                "desc": desc,
                "amount": utxo.txout.value.to_btc(),
                "coinbase": utxo.coinbase,
                "height": utxo.height,
                "confirmations": confirmations(applied_height, utxo.height)
            })
        })
        .collect();
    (unspents, total_amount)
}

fn confirmations(applied_height: u32, output_height: u32) -> u64 {
    if output_height > applied_height {
        0
    } else {
        u64::from(applied_height - output_height) + 1
    }
}

pub(crate) fn walletcreatefundedpsbt(
    ctx: &Arc<Context>,
    params: &Value,
) -> Result<Value, RpcError> {
    let array = params_array(params)?;
    if array.len() < 2 {
        return Err(RpcError::InvalidParams("inputs and outputs are required"));
    }
    let inputs = array
        .first()
        .and_then(Value::as_array)
        .ok_or(RpcError::InvalidType("inputs must be an array"))?;
    let outputs = array
        .get(1)
        .ok_or(RpcError::InvalidParams("outputs are required"))?;
    let locktime = match array.get(2) {
        Some(value) if !value.is_null() => value
            .as_u64()
            .ok_or(RpcError::InvalidType("locktime must be an integer"))?,
        _ => 0,
    };
    let lock_time = bitcoin::absolute::LockTime::from_consensus(
        u32::try_from(locktime).map_err(|_| RpcError::InvalidParams("locktime out of range"))?,
    );

    let mut tx_inputs = Vec::with_capacity(inputs.len());
    let mut witness_utxos = Vec::with_capacity(inputs.len());
    for input in inputs {
        let txid = input
            .get("txid")
            .and_then(Value::as_str)
            .ok_or(RpcError::InvalidParams("input txid is required"))?;
        let vout = input
            .get("vout")
            .and_then(Value::as_u64)
            .ok_or(RpcError::InvalidParams("input vout is required"))?;
        let txid = bitcoin::Txid::from_str(txid)
            .map_err(|_| RpcError::InvalidParams("input txid must be hex"))?;
        let vout = u32::try_from(vout).map_err(|_| RpcError::InvalidParams("vout out of range"))?;
        let sequence = input.get("sequence").and_then(Value::as_u64).map_or(
            Ok(Sequence::ENABLE_RBF_NO_LOCKTIME),
            |value| {
                u32::try_from(value)
                    .map(Sequence)
                    .map_err(|_| RpcError::InvalidParams("sequence out of range"))
            },
        )?;
        let outpoint = bitcoin::OutPoint { txid, vout };
        witness_utxos.push(ctx.utxo.get(&primitive_outpoint(outpoint)));
        tx_inputs.push(TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence,
            witness: Witness::new(),
        });
    }

    let tx_outputs = parse_funded_outputs(outputs, bitcoin_network(ctx.chain_network))?;
    let unsigned_tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time,
        input: tx_inputs,
        output: tx_outputs,
    };
    let mut psbt = bitcoin::psbt::Psbt::from_unsigned_tx(unsigned_tx)
        .map_err(|error| RpcError::Internal(format!("psbt build: {error}")))?;
    for (input, witness_utxo) in psbt.inputs.iter_mut().zip(witness_utxos) {
        input.witness_utxo = witness_utxo;
    }
    let fee = funded_fee(&psbt).unwrap_or(0);
    Ok(json!({
        "psbt": encode_base64(&psbt.serialize()),
        "fee": Amount::from_sat(fee).to_btc(),
        "changepos": -1
    }))
}

pub(crate) fn walletprocesspsbt(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let raw = required_str(params, 0, "psbt is required")?;
    let mut psbt = decode_psbt(raw)?;
    let _bip32derivs = optional_bool(params, 1, true)?;
    let keys = optional_process_keys(params)?;
    let finalize = match params_array(params)?.get(3) {
        Some(value) if !value.is_null() => value
            .as_bool()
            .ok_or(RpcError::InvalidType("finalize must be boolean"))?,
        _ => true,
    };

    if let Some(wallet) = ctx.wallet.as_ref() {
        let guard = wallet.read();
        update_psbt_from_wallet(&mut psbt, &guard, bitcoin_network(ctx.chain_network));
    }
    update_psbt_utxos(ctx, &mut psbt);

    if !keys.is_empty() {
        psbt = bitcoin_rs_wallet::sign_psbt_with_caller_keys(&psbt, &keys)
            .map_err(|error| RpcError::Internal(format!("sign failed: {error}")))?;
    }
    if finalize {
        let _ = bitcoin_rs_wallet::finalize_psbt(&mut psbt);
    }

    Ok(json!({
        "psbt": encode_base64(&psbt.serialize()),
        "complete": psbt_is_complete(&psbt),
    }))
}

pub(crate) fn finalizepsbt(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let raw = required_str(params, 0, "psbt is required")?;
    let extract = optional_bool(params, 1, true)?;
    let psbt = decode_psbt(raw)?;

    if psbt_is_complete(&psbt) {
        if extract {
            let tx = psbt.extract_tx_unchecked_fee_rate();
            return Ok(json!({
                "hex": bitcoin::consensus::encode::serialize(&tx).to_lower_hex_string(),
                "complete": true,
            }));
        }
        return Ok(json!({
            "psbt": encode_base64(&psbt.serialize()),
            "complete": true,
        }));
    }

    match bitcoin_rs_wallet::finalize_signed(psbt.clone()) {
        Ok(tx) if extract => Ok(json!({
            "hex": bitcoin::consensus::encode::serialize(&tx).to_lower_hex_string(),
            "complete": true,
        })),
        Ok(_) => Ok(json!({
            "psbt": encode_base64(&psbt.serialize()),
            "complete": true,
        })),
        Err(_) => Ok(json!({
            "psbt": encode_base64(&psbt.serialize()),
            "complete": false,
        })),
    }
}

pub(crate) fn combinepsbt(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let array = params_array(params)?
        .first()
        .and_then(Value::as_array)
        .ok_or(RpcError::InvalidParams("psbts must be an array"))?;
    if array.is_empty() {
        return Err(RpcError::InvalidParams("psbts array must not be empty"));
    }
    let mut iter = array.iter();
    let first = iter
        .next()
        .and_then(Value::as_str)
        .ok_or(RpcError::InvalidType("each psbt must be a string"))?;
    let mut psbt = decode_psbt(first)?;
    for value in iter {
        let raw = value
            .as_str()
            .ok_or(RpcError::InvalidType("each psbt must be a string"))?;
        psbt.combine(decode_psbt(raw)?)
            .map_err(|err| RpcError::Internal(format!("combine failed: {err}")))?;
    }
    Ok(json!(encode_base64(&psbt.serialize())))
}

pub(crate) fn bumpfee(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let txid_str = required_str(params, 0, "txid is required")?;
    let txid = bitcoin::Txid::from_str(txid_str)
        .map_err(|_| RpcError::InvalidParams("txid must be 64 hex characters"))?;

    let (original_tx, original_fee, original_fee_rate_sat_per_kvb) = {
        let pool = ctx.mempool.read();
        if let Some(entry) = pool.entry_by_txid(&txid) {
            ((*entry.tx).clone(), entry.fee, entry.fee_rate)
        } else {
            drop(pool);
            let confirmed = ctx.transactions.read();
            if confirmed.get(&txid).is_none() {
                return Err(RpcError::NotFound("transaction not found"));
            }
            return Err(RpcError::InvalidParams(
                "cannot bump fee on confirmed transaction",
            ));
        }
    };

    let new_rate_sat_per_kvb = original_fee_rate_sat_per_kvb.saturating_mul(125) / 100;
    let psbt = bitcoin::psbt::Psbt::from_unsigned_tx(original_tx)
        .map_err(|err| RpcError::Internal(format!("psbt build: {err}")))?;
    let bumped =
        match bitcoin_rs_wallet::bump_psbt_with_rate_sat_per_kvb(&psbt, new_rate_sat_per_kvb) {
            Ok(bumped) => bumped,
            Err(bitcoin_rs_wallet::WalletError::Bip125(message)) => {
                return Ok(json!({
                    "psbt": "",
                    "origfee": Amount::from_sat(original_fee).to_btc(),
                    "fee": 0.0,
                    "errors": [message]
                }));
            }
            Err(err) => return Err(RpcError::Internal(format!("bumpfee: {err}"))),
        };
    let weight_wu = bumped.unsigned_tx.weight().to_wu();
    let target_fee_sats = new_rate_sat_per_kvb.saturating_mul(weight_wu) / 4_000;
    Ok(json!({
        "psbt": encode_base64(&bumped.serialize()),
        "origfee": Amount::from_sat(original_fee).to_btc(),
        "fee": Amount::from_sat(target_fee_sats).to_btc(),
        "errors": Vec::<String>::new()
    }))
}

pub(crate) fn signrawtransactionwithkey(
    ctx: &Arc<Context>,
    params: &Value,
) -> Result<Value, RpcError> {
    let raw = required_str(params, 0, "hexstring is required")?;
    let bytes =
        Vec::<u8>::from_hex(raw).map_err(|_| RpcError::InvalidParams("TX decode failed"))?;
    let mut tx: Transaction =
        deserialize(&bytes).map_err(|_| RpcError::InvalidParams("TX decode failed"))?;
    for input in &mut tx.input {
        input.script_sig = ScriptBuf::new();
        input.witness = Witness::new();
    }

    let keys = parse_wif_keys_param(params_array(params)?.get(1))?;
    let mut psbt = bitcoin::psbt::Psbt::from_unsigned_tx(tx)
        .map_err(|error| RpcError::Internal(format!("psbt build: {error}")))?;

    if let Some(prevtxs) = params_array(params)?.get(2).and_then(Value::as_array) {
        apply_prevtxs_to_psbt(&mut psbt, prevtxs)?;
    } else {
        update_psbt_utxos(ctx, &mut psbt);
    }

    let mut errors: Vec<Value> = Vec::new();
    match bitcoin_rs_wallet::sign_psbt_with_explicit_prevouts(&psbt, &keys) {
        Ok(signed) => psbt = signed,
        Err(error) => {
            errors.push(json!({
                "error": format!("sign failed: {error}"),
            }));
        }
    }

    match bitcoin_rs_wallet::finalize_signed(psbt.clone()) {
        Ok(final_tx) => Ok(json!({
            "hex": serialize(&final_tx).to_lower_hex_string(),
            "complete": true,
            "errors": errors,
        })),
        Err(_) => Ok(json!({
            "hex": serialize(&psbt.unsigned_tx).to_lower_hex_string(),
            "complete": false,
            "errors": errors,
        })),
    }
}

fn parse_wif_keys_param(value: Option<&Value>) -> Result<Vec<bitcoin::PrivateKey>, RpcError> {
    let Some(value) = value else {
        return Err(RpcError::InvalidParams("privkeys must be an array"));
    };
    if value.is_null() {
        return Err(RpcError::InvalidParams("privkeys must be an array"));
    }
    let Some(keys) = value.as_array() else {
        return Err(RpcError::InvalidType("privkeys must be an array"));
    };
    if keys.is_empty() {
        return Err(RpcError::InvalidParams("privkeys must not be empty"));
    }
    keys.iter()
        .map(|entry| {
            let wif = entry
                .as_str()
                .ok_or(RpcError::InvalidType("each key must be a WIF string"))?;
            bitcoin::PrivateKey::from_wif(wif)
                .map_err(|_| RpcError::InvalidParams("Invalid private key encoding"))
        })
        .collect()
}

fn apply_prevtxs_to_psbt(
    psbt: &mut bitcoin::psbt::Psbt,
    prevtxs: &[Value],
) -> Result<(), RpcError> {
    for entry in prevtxs {
        let object = entry
            .as_object()
            .ok_or(RpcError::InvalidType("prevtxs entry must be an object"))?;
        let txid = bitcoin::Txid::from_str(
            object
                .get(&"txid")
                .and_then(Value::as_str)
                .ok_or(RpcError::InvalidParams("prevtxs txid is required"))?,
        )
        .map_err(|_| RpcError::InvalidParams("txid must be 64 hex characters"))?;
        let vout = object
            .get(&"vout")
            .and_then(Value::as_u64)
            .ok_or(RpcError::InvalidParams("prevtxs vout is required"))?;
        let vout = u32::try_from(vout).map_err(|_| RpcError::InvalidParams("vout exceeds u32"))?;
        let script_hex = object
            .get(&"scriptPubKey")
            .and_then(Value::as_str)
            .ok_or(RpcError::InvalidParams("prevtxs scriptPubKey is required"))?;
        let script_bytes = Vec::<u8>::from_hex(script_hex)
            .map_err(|_| RpcError::InvalidParams("scriptPubKey must be hex"))?;
        let amount = match object.get(&"amount") {
            Some(value) if !value.is_null() => {
                let btc = value
                    .as_f64()
                    .ok_or(RpcError::InvalidType("amount must be a number"))?;
                Amount::from_btc(btc).map_err(|_| RpcError::InvalidParams("amount is invalid"))?
            }
            _ => {
                return Err(RpcError::InvalidParameter(
                    "amount is required for each prevtx".to_owned(),
                ));
            }
        };
        for (index, txin) in psbt.unsigned_tx.input.iter().enumerate() {
            if txin.previous_output.txid == txid && txin.previous_output.vout == vout {
                psbt.inputs[index].witness_utxo = Some(TxOut {
                    value: amount,
                    script_pubkey: ScriptBuf::from(script_bytes.clone()),
                });
            }
        }
    }
    Ok(())
}

fn descriptor_import_error(code: i64, message: impl Into<String>) -> Value {
    json!({
        "success": false,
        "error": {
            "code": code,
            "message": message.into(),
        }
    })
}

fn import_one_descriptor(watcher: &mut bitcoin_rs_wallet::Watcher, request: &Value) -> Value {
    let Some(descriptor) = request.get("desc").and_then(Value::as_str) else {
        return descriptor_import_error(
            RpcError::CORE_INVALID_PARAMETER,
            "Missing required parameter \"desc\"",
        );
    };
    let timestamp = match request.get("timestamp") {
        None => {
            return descriptor_import_error(
                RpcError::CORE_INVALID_PARAMETER,
                "Missing required parameter \"timestamp\"",
            );
        }
        Some(value) if value.as_str() == Some("now") => bitcoin_rs_wallet::DescriptorTimestamp::Now,
        Some(value) => match value.as_u64() {
            Some(time) => bitcoin_rs_wallet::DescriptorTimestamp::Time(time),
            None => {
                return descriptor_import_error(
                    RpcError::CORE_INVALID_TYPE,
                    "Expected number or \"now\" timestamp",
                );
            }
        },
    };
    let active = request
        .get("active")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let internal = request
        .get("internal")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let label = request
        .get("label")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if internal && label.is_some() {
        return descriptor_import_error(
            RpcError::CORE_INVALID_PARAMETER,
            "Internal addresses should not have a label",
        );
    }
    let parsed = match bitcoin_rs_wallet::Descriptor::parse_all(descriptor) {
        Ok(parsed) => parsed,
        Err(error) => {
            return descriptor_import_error(RpcError::CORE_NOT_FOUND, error.to_string());
        }
    };
    let ranged = parsed.iter().any(bitcoin_rs_wallet::Descriptor::is_ranged);
    let range = match request.get("range") {
        Some(value) => match parse_range_value(value) {
            Ok(range) => range,
            Err(error) => {
                return descriptor_import_error(error.code(), error.to_string());
            }
        },
        None if ranged => 0..=DEFAULT_RANGE_END,
        None => 0..=0,
    };
    match watcher.import(&bitcoin_rs_wallet::DescriptorImport {
        descriptor: descriptor.to_owned(),
        timestamp,
        range,
        active,
        internal,
        label,
    }) {
        Ok(_) => json!({ "success": true }),
        Err(error) => descriptor_import_error(RpcError::CORE_NOT_FOUND, error.to_string()),
    }
}

fn require_wallet(
    ctx: &Context,
) -> Result<Arc<parking_lot::RwLock<bitcoin_rs_wallet::Watcher>>, RpcError> {
    ctx.wallet
        .clone()
        .ok_or_else(|| RpcError::Misc("No wallet is loaded.".to_owned()))
}

fn parse_range_value(value: &Value) -> Result<RangeInclusive<u32>, RpcError> {
    let (start, end) = if let Some(end) = value.as_u64() {
        (0, end)
    } else {
        let Some(bounds) = value.as_array() else {
            return Err(RpcError::InvalidType(
                "range must be an integer or two-integer array",
            ));
        };
        if bounds.len() != 2 {
            return Err(RpcError::InvalidParams(
                "range array must contain two entries",
            ));
        }
        let start = bounds
            .first()
            .and_then(Value::as_u64)
            .ok_or(RpcError::InvalidType("range start must be an integer"))?;
        let end = bounds
            .get(1)
            .and_then(Value::as_u64)
            .ok_or(RpcError::InvalidType("range end must be an integer"))?;
        if start > end {
            return Err(RpcError::InvalidParams("range start must not exceed end"));
        }
        (start, end)
    };
    if end > u64::from(i32::MAX.cast_unsigned())
        || end >= start.saturating_add(MAX_DESCRIPTOR_RANGE_SPAN)
    {
        return Err(RpcError::InvalidParams("range out of bounds"));
    }
    let start = u32::try_from(start).map_err(|_| RpcError::InvalidParams("range out of bounds"))?;
    let end = u32::try_from(end).map_err(|_| RpcError::InvalidParams("range out of bounds"))?;
    Ok(start..=end)
}

fn parse_funded_outputs(
    outputs: &Value,
    network: bitcoin::Network,
) -> Result<Vec<TxOut>, RpcError> {
    if let Some(array) = outputs.as_array() {
        let mut tx_outputs = Vec::with_capacity(array.len());
        for output in array {
            let Some(object) = output.as_object() else {
                return Err(RpcError::InvalidType("output must be an object"));
            };
            let Some((address, amount)) = object.iter().next() else {
                return Err(RpcError::InvalidParams("output is empty"));
            };
            tx_outputs.push(output_from_address_amount(address, amount, network)?);
        }
        return Ok(tx_outputs);
    }
    let Some(object) = outputs.as_object() else {
        return Err(RpcError::InvalidType(
            "outputs must be an object or array of objects",
        ));
    };
    object
        .iter()
        .map(|(address, amount)| output_from_address_amount(address, amount, network))
        .collect()
}

fn output_from_address_amount(
    address: &str,
    amount: &Value,
    network: bitcoin::Network,
) -> Result<TxOut, RpcError> {
    let amount = amount
        .as_f64()
        .ok_or(RpcError::InvalidType("output amount must be a number"))?;
    let amount = Amount::from_btc(amount)
        .map_err(|_| RpcError::InvalidParams("output amount is invalid"))?;
    let address = bitcoin::Address::from_str(address)
        .map_err(|_| RpcError::InvalidParams("Address is not valid"))?
        .require_network(network)
        .map_err(|_| RpcError::InvalidParams("Address is not valid"))?;
    Ok(TxOut {
        value: amount,
        script_pubkey: address.script_pubkey(),
    })
}

fn optional_process_keys(params: &Value) -> Result<Vec<bitcoin::PrivateKey>, RpcError> {
    let Some(options) = params_array(params)?.get(2) else {
        return Ok(Vec::new());
    };
    if options.is_null() {
        return Ok(Vec::new());
    }
    let Some(keys) = options.get("keys") else {
        return Ok(Vec::new());
    };
    let Some(keys) = keys.as_array() else {
        return Err(RpcError::InvalidType("keys must be an array"));
    };
    keys.iter()
        .map(|value| {
            let wif = value
                .as_str()
                .ok_or(RpcError::InvalidType("each key must be a WIF string"))?;
            bitcoin::PrivateKey::from_wif(wif)
                .map_err(|_| RpcError::InvalidParams("invalid private key"))
        })
        .collect()
}

fn update_psbt_from_wallet(
    psbt: &mut bitcoin::psbt::Psbt,
    watcher: &bitcoin_rs_wallet::Watcher,
    network: bitcoin::Network,
) {
    for (index, input) in psbt.inputs.iter_mut().enumerate() {
        if input.witness_utxo.is_some() || input.non_witness_utxo.is_some() {
            continue;
        }
        let Some(txin) = psbt.unsigned_tx.input.get(index) else {
            continue;
        };
        for (descriptor_index, descriptor) in watcher.descriptors.iter().enumerate() {
            let range = watcher
                .imports
                .get(descriptor_index)
                .map(|import| import.range.clone())
                .unwrap_or(0..=0);
            for child in range {
                let Ok(address) = descriptor.derive_address(network, child) else {
                    continue;
                };
                if watcher.utxos_for(&address).contains(&txin.previous_output)
                    && let Some(value) = watcher.utxo_value(&txin.previous_output)
                    && let Ok(script_pubkey) = descriptor.script_pubkey_at(child)
                {
                    input.witness_utxo = Some(TxOut {
                        value,
                        script_pubkey,
                    });
                }
            }
        }
    }
}

fn update_psbt_utxos(ctx: &Context, psbt: &mut bitcoin::psbt::Psbt) {
    for (index, input) in psbt.inputs.iter_mut().enumerate() {
        let Some(txin) = psbt.unsigned_tx.input.get(index) else {
            continue;
        };
        if let Some(txout) = ctx.utxo.get(&primitive_outpoint(txin.previous_output)) {
            input.witness_utxo = Some(txout);
        }
    }
}

fn funded_fee(psbt: &bitcoin::psbt::Psbt) -> Option<u64> {
    let mut input_total = 0_u64;
    for (index, input) in psbt.inputs.iter().enumerate() {
        let txout = if let Some(txout) = input.witness_utxo.as_ref() {
            txout
        } else {
            let tx = input.non_witness_utxo.as_ref()?;
            let txin = psbt.unsigned_tx.input.get(index)?;
            tx.output
                .get(usize::try_from(txin.previous_output.vout).ok()?)?
        };
        input_total = input_total.saturating_add(txout.value.to_sat());
    }
    let output_total = psbt
        .unsigned_tx
        .output
        .iter()
        .map(|output| output.value.to_sat())
        .fold(0_u64, u64::saturating_add);
    input_total.checked_sub(output_total)
}

fn decode_psbt(raw: &str) -> Result<bitcoin::psbt::Psbt, RpcError> {
    let decoded = decode_base64(raw)?;
    bitcoin::psbt::Psbt::deserialize(&decoded)
        .map_err(|_| RpcError::InvalidParams("invalid base64 PSBT"))
}

fn psbt_is_complete(psbt: &bitcoin::psbt::Psbt) -> bool {
    !psbt.inputs.is_empty()
        && psbt
            .inputs
            .iter()
            .all(|input| input.final_script_sig.is_some() || input.final_script_witness.is_some())
}

fn map_wallet_error(error: bitcoin_rs_wallet::WalletError) -> RpcError {
    match error {
        bitcoin_rs_wallet::WalletError::PrivateDescriptor => {
            RpcError::InvalidParams("descriptor contains private keys")
        }
        bitcoin_rs_wallet::WalletError::DescriptorRange(message) => {
            RpcError::InvalidParams(message)
        }
        bitcoin_rs_wallet::WalletError::Descriptor(message) => {
            if message.contains("checksum") {
                RpcError::InvalidParams("descriptor checksum mismatch")
            } else {
                RpcError::InvalidParameter(message)
            }
        }
        other => RpcError::Internal(other.to_string()),
    }
}

fn primitive_outpoint(outpoint: bitcoin::OutPoint) -> bitcoin_rs_primitives::OutPoint {
    bitcoin_rs_primitives::OutPoint::new(
        Hash256::from_le_bytes(outpoint.txid.as_byte_array()),
        outpoint.vout,
    )
}

const fn bitcoin_network(chain_network: bitcoin_rs_primitives::Network) -> bitcoin::Network {
    crate::bitcoin_network(chain_network)
}

const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn decode_base64(input: &str) -> Result<Vec<u8>, RpcError> {
    crate::base64::decode(input).ok_or(RpcError::InvalidParams("invalid base64 PSBT"))
}

fn encode_base64(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(char::from(BASE64_ALPHABET[usize::from(b0 >> 2)]));
        out.push(char::from(
            BASE64_ALPHABET[usize::from(((b0 & 0b0000_0011) << 4) | (b1 >> 4))],
        ));
        if chunk.len() > 1 {
            out.push(char::from(
                BASE64_ALPHABET[usize::from(((b1 & 0b0000_1111) << 2) | (b2 >> 6))],
            ));
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(char::from(BASE64_ALPHABET[usize::from(b2 & 0b0011_1111)]));
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use alloc::sync::Arc;

    use bitcoin::hashes::Hash as _;
    use bitcoin::{Amount, Network, OutPoint, ScriptBuf, TxOut};
    use bitcoin_rs_wallet::{DescriptorTimestamp, Watcher};
    use parking_lot::RwLock;
    use sonic_rs::JsonValueTrait as _;

    use super::*;

    fn ctx_with_wallet() -> Arc<Context> {
        Arc::new(Context::new().with_wallet(Arc::new(RwLock::new(Watcher::new(Vec::new())))))
    }

    fn empty_psbt() -> String {
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: Vec::new(),
            output: Vec::new(),
        };
        let psbt = bitcoin::psbt::Psbt::from_unsigned_tx(tx)
            .unwrap_or_else(|err| panic!("from_unsigned_tx: {err}"));
        encode_base64(&psbt.serialize())
    }

    #[test]
    fn getdescriptorinfo_uses_shared_addr_contract() {
        let ctx = Arc::new(Context::new());
        let result = getdescriptorinfo(&ctx, &json!(["addr(1111111111111111111114oLvT2)"]))
            .unwrap_or_else(|err| panic!("getdescriptorinfo failed: {err}"));
        let checksum = result
            .get("checksum")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("checksum missing: {result:?}"));
        assert_eq!(checksum.len(), 8);
        assert_eq!(
            result.get("hasprivatekeys").and_then(Value::as_bool),
            Some(false)
        );
        assert_eq!(
            result.get("issolvable").and_then(Value::as_bool),
            Some(false)
        );
    }

    #[test]
    fn getdescriptorinfo_rejects_bad_checksum() {
        let ctx = Arc::new(Context::new());
        let err = getdescriptorinfo(&ctx, &json!(["addr(1111111111111111111114oLvT2)#00000000"]))
            .expect_err("bad checksum must fail");
        assert!(matches!(
            err,
            RpcError::InvalidParameter(_) | RpcError::InvalidParams(_)
        ));
    }

    #[test]
    fn parse_range_accepts_maximum_span() {
        let range =
            parse_range_value(&json!([0, MAX_DESCRIPTOR_RANGE_SPAN - 1])).expect("valid range");
        assert_eq!(range, 0..=999_999);
    }

    #[test]
    fn parse_range_rejects_one_million_span() {
        let error = parse_range_value(&json!([0, MAX_DESCRIPTOR_RANGE_SPAN]))
            .expect_err("one-million span must fail");
        assert!(matches!(
            error,
            RpcError::InvalidParams("range out of bounds")
        ));
    }

    #[test]
    fn parse_range_rejects_end_above_core_limit() {
        let error = parse_range_value(&json!([
            u64::from(i32::MAX.cast_unsigned()),
            u64::from(i32::MAX.cast_unsigned()) + 1
        ]))
        .expect_err("end above i32::MAX must fail");
        assert!(matches!(
            error,
            RpcError::InvalidParams("range out of bounds")
        ));
    }

    #[test]
    fn parse_range_accepts_scalar_form() {
        let range = parse_range_value(&json!(42)).expect("valid scalar range");
        assert_eq!(range, 0..=42);
    }

    #[test]
    fn deriveaddresses_rejects_range_on_unranged_descriptor() {
        let ctx = Arc::new(Context::new());
        let err = deriveaddresses(&ctx, &json!(["addr(1111111111111111111114oLvT2)", [0, 1]]))
            .expect_err("range must be rejected");
        assert!(matches!(
            err,
            RpcError::InvalidParams(_) | RpcError::InvalidParameter(_)
        ));
    }

    #[test]
    fn deriveaddresses_rejects_multipath_descriptor() {
        let ctx = Arc::new(Context::new());
        let key = bitcoin::PrivateKey {
            compressed: true,
            network: bitcoin::NetworkKind::Main,
            inner: bitcoin::secp256k1::SecretKey::from_slice(&[4_u8; 32])
                .unwrap_or_else(|err| panic!("secret: {err}")),
        };
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let xpriv = bitcoin::bip32::Xpriv::new_master(Network::Bitcoin, &key.inner.secret_bytes())
            .unwrap_or_else(|err| panic!("xpriv: {err}"));
        let xpub = bitcoin::bip32::Xpub::from_priv(&secp, &xpriv);
        let err = deriveaddresses(&ctx, &json!([format!("wpkh({xpub}/<0;1>/*)")]))
            .expect_err("multipath must fail");
        assert!(matches!(
            err,
            RpcError::InvalidParameter(_) | RpcError::InvalidParams(_)
        ));
    }

    #[test]
    fn importdescriptors_persists_watch_only_metadata() {
        let ctx = ctx_with_wallet();
        let signer_key = bitcoin::PrivateKey {
            compressed: true,
            network: bitcoin::NetworkKind::Main,
            inner: bitcoin::secp256k1::SecretKey::from_slice(&[1_u8; 32])
                .unwrap_or_else(|err| panic!("secret: {err}")),
        };
        let public = bitcoin::PublicKey::from_private_key(
            &bitcoin::secp256k1::Secp256k1::new(),
            &signer_key,
        );
        let desc = format!("wpkh({public})");
        let result = importdescriptors(
            &ctx,
            &json!([[{
                "desc": desc,
                "timestamp": "now",
                "active": true,
                "internal": false,
                "label": "savings"
            }]]),
        )
        .unwrap_or_else(|err| panic!("importdescriptors: {err}"));
        let first = result
            .as_array()
            .and_then(|array| array.first())
            .unwrap_or_else(|| panic!("missing result: {result:?}"));
        assert_eq!(first.get("success").and_then(Value::as_bool), Some(true));
        let wallet = ctx
            .wallet
            .as_ref()
            .unwrap_or_else(|| panic!("wallet missing"));
        let guard = wallet.read();
        assert_eq!(guard.descriptors.len(), 1);
        assert_eq!(guard.imports.len(), 1);
        assert_eq!(guard.imports[0].label.as_deref(), Some("savings"));
        assert!(guard.imports[0].active);
        assert!(!guard.imports[0].internal);
        assert_eq!(guard.imports[0].timestamp, DescriptorTimestamp::Now);
        assert!(!guard.imports[0].descriptor.contains(&signer_key.to_wif()));
    }

    #[test]
    fn importdescriptors_rejects_private_material_without_retention() {
        let ctx = ctx_with_wallet();
        let signer_key = bitcoin::PrivateKey {
            compressed: true,
            network: bitcoin::NetworkKind::Main,
            inner: bitcoin::secp256k1::SecretKey::from_slice(&[2_u8; 32])
                .unwrap_or_else(|err| panic!("secret: {err}")),
        };
        let wif = signer_key.to_wif();
        let result = importdescriptors(
            &ctx,
            &json!([[{
                "desc": format!("wpkh({wif})"),
                "timestamp": 0
            }]]),
        )
        .unwrap_or_else(|err| panic!("importdescriptors: {err}"));
        let first = result
            .as_array()
            .and_then(|array| array.first())
            .unwrap_or_else(|| panic!("missing result: {result:?}"));
        assert_eq!(first.get("success").and_then(Value::as_bool), Some(false));
        let wallet = ctx
            .wallet
            .as_ref()
            .unwrap_or_else(|| panic!("wallet missing"));
        let guard = wallet.read();
        assert!(guard.descriptors.is_empty());
        assert!(guard.imports.is_empty());
        assert!(!format!("{guard:?}").contains(&wif));
    }

    #[test]
    fn walletprocesspsbt_signs_with_transient_keys_only() {
        let ctx = ctx_with_wallet();
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let key = bitcoin::PrivateKey {
            compressed: true,
            network: bitcoin::NetworkKind::Main,
            inner: bitcoin::secp256k1::SecretKey::from_slice(&[3_u8; 32])
                .unwrap_or_else(|err| panic!("secret: {err}")),
        };
        let public = bitcoin::PublicKey::from_private_key(&secp, &key);
        let descriptor = bitcoin_rs_wallet::Descriptor::parse(&format!("wpkh({public})"))
            .unwrap_or_else(|err| panic!("parse: {err}"));
        let script = descriptor
            .script_pubkey()
            .unwrap_or_else(|err| panic!("script: {err}"));
        let prev_txout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: script,
        };
        let outpoint = OutPoint {
            txid: bitcoin::Txid::from_byte_array([9_u8; 32]),
            vout: 0,
        };
        let mut builder = bitcoin_rs_wallet::PsbtBuilder::new(core::slice::from_ref(&descriptor));
        builder
            .add_input(bitcoin_rs_wallet::PrevUtxo::new(outpoint, prev_txout), 0, 0)
            .unwrap_or_else(|err| panic!("input: {err}"));
        let dest = bitcoin::Address::from_script(
            &ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([7_u8; 20])),
            Network::Bitcoin,
        )
        .unwrap_or_else(|err| panic!("dest: {err}"));
        builder
            .add_output(dest, Amount::from_sat(40_000))
            .unwrap_or_else(|err| panic!("output: {err}"));
        let mut unsigned = builder
            .finalize()
            .unwrap_or_else(|err| panic!("finalize: {err}"));
        // RPC base64 round-trips unsigned PSBT v0; the builder may stamp v2.
        unsigned.version = 0;
        let raw = encode_base64(&unsigned.serialize());

        let processed = walletprocesspsbt(
            &ctx,
            &json!([raw.as_str(), true, { "keys": [key.to_wif()] }]),
        )
        .unwrap_or_else(|err| panic!("walletprocesspsbt: {err}"));
        let signed_raw = processed
            .get("psbt")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("psbt missing"));
        let signed = decode_psbt(signed_raw).unwrap_or_else(|err| panic!("decode: {err}"));
        assert!(!signed.inputs[0].partial_sigs.is_empty());

        let finalized = finalizepsbt(&ctx, &json!([signed_raw]))
            .unwrap_or_else(|err| panic!("finalizepsbt: {err}"));
        assert_eq!(
            finalized.get("complete").and_then(Value::as_bool),
            Some(true)
        );
        assert!(
            finalized
                .get("hex")
                .and_then(Value::as_str)
                .is_some_and(|hex| !hex.is_empty())
        );

        let wallet = ctx
            .wallet
            .as_ref()
            .unwrap_or_else(|| panic!("wallet missing"));
        let guard = wallet.read();
        assert!(!format!("{guard:?}").contains(&key.to_wif()));
    }

    #[test]
    fn combinepsbt_returns_single_input_unchanged() {
        let ctx = Arc::new(Context::new());
        let left = empty_psbt();
        let combined = combinepsbt(&ctx, &json!([[left.as_str()]]))
            .unwrap_or_else(|err| panic!("combine: {err}"));
        assert_eq!(combined.as_str(), Some(left.as_str()));
    }
    #[test]
    fn importdescriptors_errors_without_wallet() {
        let ctx = Arc::new(Context::new());
        let err = importdescriptors(&ctx, &json!([[{"desc": "wpkh(02aa)", "timestamp": 0}]]))
            .expect_err("missing wallet");
        assert!(matches!(err, RpcError::Misc(_)));
    }

    struct RecordingStore {
        path: std::path::PathBuf,
        fail: bool,
    }

    impl crate::context::WalletPersistence for RecordingStore {
        fn persist(
            &self,
            watcher: &bitcoin_rs_wallet::Watcher,
        ) -> core::result::Result<(), compact_str::CompactString> {
            if self.fail {
                return Err(compact_str::CompactString::from("forced persist failure"));
            }
            let bytes = watcher
                .encode_state()
                .map_err(|error| compact_str::CompactString::from(error.to_string()))?;
            std::fs::write(&self.path, bytes)
                .map_err(|error| compact_str::CompactString::from(error.to_string()))
        }
    }

    fn wpkh_desc(byte: u8) -> String {
        let signer_key = bitcoin::PrivateKey {
            compressed: true,
            network: bitcoin::NetworkKind::Main,
            inner: bitcoin::secp256k1::SecretKey::from_slice(&[byte; 32])
                .unwrap_or_else(|err| panic!("secret: {err}")),
        };
        let public = bitcoin::PublicKey::from_private_key(
            &bitcoin::secp256k1::Secp256k1::new(),
            &signer_key,
        );
        format!("wpkh({public})")
    }

    #[test]
    fn importdescriptors_scan_error_leaves_watcher_unchanged() {
        crate::context::fail_next_wallet_scan();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("watch_only.json");
        let ctx = Arc::new(
            Context::new()
                .with_wallet(Arc::new(RwLock::new(Watcher::new(Vec::new()))))
                .with_wallet_persistence(Arc::new(RecordingStore {
                    path: path.clone(),
                    fail: false,
                })),
        );
        let result = importdescriptors(
            &ctx,
            &json!([[{ "desc": wpkh_desc(11), "timestamp": "now" }]]),
        )
        .unwrap_or_else(|err| panic!("importdescriptors: {err}"));
        let first = result
            .as_array()
            .and_then(|array| array.first())
            .unwrap_or_else(|| panic!("missing result: {result:?}"));
        assert_eq!(first.get("success").and_then(Value::as_bool), Some(false));
        let wallet = ctx
            .wallet
            .as_ref()
            .unwrap_or_else(|| panic!("wallet missing"));
        assert!(wallet.read().imports.is_empty());
        assert!(!path.exists(), "scan error must not persist");
    }

    #[test]
    fn importdescriptors_persist_error_leaves_watcher_unchanged() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("watch_only.json");
        let ctx = Arc::new(
            Context::new()
                .with_wallet(Arc::new(RwLock::new(Watcher::new(Vec::new()))))
                .with_wallet_persistence(Arc::new(RecordingStore { path, fail: true })),
        );
        let result = importdescriptors(
            &ctx,
            &json!([[{ "desc": wpkh_desc(12), "timestamp": "now" }]]),
        )
        .unwrap_or_else(|err| panic!("importdescriptors: {err}"));
        let first = result
            .as_array()
            .and_then(|array| array.first())
            .unwrap_or_else(|| panic!("missing result: {result:?}"));
        assert_eq!(first.get("success").and_then(Value::as_bool), Some(false));
        let wallet = ctx
            .wallet
            .as_ref()
            .unwrap_or_else(|| panic!("wallet missing"));
        assert!(wallet.read().imports.is_empty());
    }

    #[test]
    fn importdescriptors_concurrent_imports_both_survive_and_reload() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("watch_only.json");
        let ctx = Arc::new(
            Context::new()
                .with_wallet(Arc::new(RwLock::new(Watcher::new(Vec::new()))))
                .with_wallet_persistence(Arc::new(RecordingStore {
                    path: path.clone(),
                    fail: false,
                })),
        );
        let left = wpkh_desc(13);
        let right = wpkh_desc(14);
        std::thread::scope(|scope| {
            let ctx_left = Arc::clone(&ctx);
            let left_desc = left.clone();
            scope.spawn(move || {
                importdescriptors(
                    &ctx_left,
                    &json!([[{ "desc": left_desc, "timestamp": "now" }]]),
                )
                .unwrap_or_else(|err| panic!("left import: {err}"));
            });
            let ctx_right = Arc::clone(&ctx);
            let right_desc = right.clone();
            scope.spawn(move || {
                importdescriptors(
                    &ctx_right,
                    &json!([[{ "desc": right_desc, "timestamp": "now" }]]),
                )
                .unwrap_or_else(|err| panic!("right import: {err}"));
            });
        });
        let wallet = ctx
            .wallet
            .as_ref()
            .unwrap_or_else(|| panic!("wallet missing"));
        let live = wallet.read().imports.len();
        assert_eq!(live, 2, "serialized updates must retain both imports");
        let bytes = std::fs::read(&path).expect("persisted");
        let reloaded = Watcher::decode_state(&bytes).expect("decode");
        assert_eq!(reloaded.imports.len(), 2);
    }
}
