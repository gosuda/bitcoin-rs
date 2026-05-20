use alloc::sync::Arc;
use core::str::FromStr as _;

use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hex::{DisplayHex as _, FromHex as _};
use bitcoin::{Amount, Transaction, Txid};
use bitcoin_rs_primitives::Hash256;
use serde_json::json as serde_json_value;
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait, Value, json};

use crate::context::Context;
use crate::error::RpcError;
use crate::handlers::{optional_bool, params_array, required_str, required_u64, serde_to_sonic};

pub(crate) fn getrawtransaction(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let txid = parse_txid(required_str(params, 0, "txid is required")?)?;
    let verbose = optional_bool(params, 1, false)?;
    {
        let transactions = ctx.transactions.read();
        if let Some(tx) = transactions.get(&txid) {
            if !verbose {
                return Ok(json!(serialize(tx).to_lower_hex_string()));
            }
            return tx_to_value(tx);
        }
    }
    {
        let pool = ctx.mempool.read();
        if let Some(id) = pool.by_txid.get(&txid) {
            if let Some(entry) = pool.entry(*id) {
                let tx = entry.tx.as_ref();
                if !verbose {
                    return Ok(json!(serialize(tx).to_lower_hex_string()));
                }
                return tx_to_value(tx);
            }
        }
    }
    Err(RpcError::NotFound("transaction not found"))
}

pub(crate) fn gettxout(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let txid = parse_txid(required_str(params, 0, "txid is required")?)?;
    let vout = required_u64(params, 1, "vout is required")?;
    let vout = usize::try_from(vout).map_err(|_| RpcError::InvalidParams("vout exceeds usize"))?;
    let transactions = ctx.transactions.read();
    let Some(tx) = transactions.get(&txid) else {
        return Ok(Value::new_null());
    };
    let Some(output) = tx.output.get(vout) else {
        return Ok(Value::new_null());
    };
    Ok(json!({
        "bestblock": ctx.best_hash().to_string_be(),
        "confirmations": 0,
        "value": btc_value(output.value.to_sat()),
        "scriptPubKey": {
            "asm": "",
            "desc": "raw()",
            "hex": output.script_pubkey.as_bytes().to_lower_hex_string(),
            "type": "nonstandard"
        },
        "coinbase": false
    }))
}

pub(crate) fn gettxoutproof(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let array = params_array(params)?;
    if array.is_empty() {
        return Err(RpcError::InvalidParams("txids are required"));
    }
    Ok(json!(""))
}

pub(crate) fn verifytxoutproof(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    required_str(params, 0, "proof is required")?;
    Ok(json!([]))
}

pub(crate) fn sendrawtransaction(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let raw = required_str(params, 0, "raw transaction is required")?;
    let tx = decode_tx(raw)?;
    let txid = ctx.add_transaction(tx);
    Ok(json!(txid.to_string()))
}

pub(crate) fn testmempoolaccept(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let raw_txs = params_array(params)?
        .first()
        .and_then(|value| value.as_array())
        .ok_or(RpcError::InvalidParams("raw transaction array is required"))?;
    let mut rows = Vec::with_capacity(raw_txs.len());
    for raw in raw_txs {
        let Some(raw) = raw.as_str() else {
            return Err(RpcError::InvalidType("raw transaction must be a string"));
        };
        let decoded = decode_tx(raw);
        let txid = decoded.as_ref().map_or_else(
            |_| Hash256::default().to_string_be(),
            |tx| tx.compute_txid().to_string(),
        );
        rows.push(json!({
            "txid": txid,
            "wtxid": txid,
            "allowed": decoded.is_ok(),
            "vsize": decoded.as_ref().map_or(0, Transaction::vsize),
            "fees": {"base": 0.0}
        }));
    }
    Ok(json!(rows))
}

pub(crate) fn decoderawtransaction(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let raw = required_str(params, 0, "raw transaction is required")?;
    let tx = decode_tx(raw)?;
    tx_to_value(&tx)
}

fn decode_tx(raw: &str) -> Result<Transaction, RpcError> {
    let bytes = Vec::<u8>::from_hex(raw)?;
    deserialize(&bytes).map_err(|_| RpcError::InvalidParams("transaction decode failed"))
}

fn parse_txid(value: &str) -> Result<Txid, RpcError> {
    Txid::from_str(value).map_err(|_| RpcError::InvalidParams("txid must be 64 hex characters"))
}

fn tx_to_value(tx: &Transaction) -> Result<Value, RpcError> {
    let txid = tx.compute_txid().to_string();
    let size = usize_to_u64(serialize(tx).len())?;
    let vsize = usize_to_u64(tx.vsize())?;
    let weight = tx.weight().to_wu();
    let vin = tx
        .input
        .iter()
        .map(|input| {
            serde_json_value!({
                "txid": input.previous_output.txid.to_string(),
                "vout": input.previous_output.vout,
                "scriptSig": {"asm": "", "hex": input.script_sig.as_bytes().to_lower_hex_string()},
                "sequence": input.sequence.to_consensus_u32(),
                "txinwitness": []
            })
        })
        .collect::<Vec<_>>();
    let vout = tx
        .output
        .iter()
        .enumerate()
        .map(|(index, output)| {
            serde_json_value!({
                "value": btc_value(output.value.to_sat()),
                "n": index,
                "scriptPubKey": {
                    "asm": "",
                    "desc": "raw()",
                    "hex": output.script_pubkey.as_bytes().to_lower_hex_string(),
                    "type": "nonstandard"
                }
            })
        })
        .collect::<Vec<_>>();
    let value = serde_json_value!({
        "txid": txid,
        "hash": tx.compute_wtxid().to_string(),
        "version": tx.version.0,
        "size": size,
        "vsize": vsize,
        "weight": weight,
        "locktime": tx.lock_time.to_consensus_u32(),
        "vin": vin,
        "vout": vout,
        "hex": serialize(tx).to_lower_hex_string()
    });
    serde_to_sonic(&value)
}

fn usize_to_u64(value: usize) -> Result<u64, RpcError> {
    u64::try_from(value).map_err(|_| RpcError::Internal("usize does not fit u64".to_owned()))
}

fn btc_value(sats: u64) -> f64 {
    Amount::from_sat(sats).to_btc()
}
#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use bitcoin::blockdata::constants::genesis_block;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::hex::DisplayHex as _;
    use bitcoin_rs_mempool::MempoolEntry;
    use sonic_rs::{JsonValueTrait as _, json};

    use super::getrawtransaction;
    use crate::context::Context;
    use crate::error::RpcError;

    #[test]
    fn getrawtransaction_falls_back_to_mempool_for_unconfirmed()
    -> Result<(), Box<dyn std::error::Error>> {
        let ctx = Arc::new(Context::new());
        let genesis = genesis_block(bitcoin::Network::Regtest);
        let coinbase = genesis
            .txdata
            .first()
            .ok_or_else(|| RpcError::Internal("genesis has no transactions".to_owned()))?
            .clone();
        let txid = coinbase.compute_txid();
        {
            let mut pool = ctx.mempool.write();
            let entry = MempoolEntry::new(
                Arc::new(coinbase.clone()),
                u32::try_from(coinbase.vsize())?,
                0,
                0,
                0,
            );
            pool.insert_entry(entry)?;
        }

        let result = getrawtransaction(&ctx, &json!([txid.to_string()]))?;

        let expected = serialize(&coinbase).to_lower_hex_string();
        assert_eq!(result.as_str(), Some(expected.as_str()));
        Ok(())
    }
}
