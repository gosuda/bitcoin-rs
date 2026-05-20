//! Shared transaction-to-JSON rendering for handlers.

use bitcoin::Transaction;
use bitcoin::consensus::encode::serialize;
use bitcoin::hex::DisplayHex as _;
use serde_json::json as serde_json_value;
use sonic_rs::Value;

use crate::error::RpcError;
use crate::handlers::serde_to_sonic;

pub(crate) fn tx_to_value(tx: &Transaction) -> Result<Value, RpcError> {
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

pub(crate) fn usize_to_u64(value: usize) -> Result<u64, RpcError> {
    u64::try_from(value).map_err(|_| RpcError::Internal("usize does not fit u64".to_owned()))
}

pub(crate) fn btc_value(sats: u64) -> f64 {
    bitcoin::Amount::from_sat(sats).to_btc()
}
