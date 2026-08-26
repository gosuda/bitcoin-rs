//! Canonical Bitcoin Core transaction JSON projections.
//!
//! Callers supply optional confirmed-chain context. This module never queries
//! node state and does not choose JSON-RPC versus REST transport policy.

use bitcoin::consensus::encode::serialize;
use bitcoin::hex::DisplayHex as _;
use bitcoin::{Amount, BlockHash, Network, Script, Transaction, TxIn, TxOut};
use sonic_rs::{Value, json};

/// Optional confirmed-chain fields projected beside a transaction object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionChainContext {
    /// Confirming block hash.
    pub block_hash: BlockHash,
    /// Confirmations on the applied chain, or `0` when the named block is inactive.
    pub confirmations: i64,
    /// Confirming block time.
    pub block_time: u64,
    /// Whether the confirming block is on the applied chain.
    ///
    /// Rendered only when `Some`. Explicit `blockhash` lookups set this;
    /// txindex lookups leave it absent.
    pub in_active_chain: Option<bool>,
}

/// Per-input prevout projected by Core verbosity 2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxPrevout {
    /// Whether the prevout was created by a coinbase.
    pub generated: bool,
    /// Confirming height of the prevout.
    pub height: u32,
    /// Prevout value.
    pub value: Amount,
    /// Prevout scriptPubKey.
    pub script_pubkey: bitcoin::ScriptBuf,
}

/// Exact eight-decimal BTC spelling used by Core JSON amount fields.
///
/// Parsed with sonic's raw-number mode so the decimal spelling survives
/// serialization instead of being reduced through binary floating point.
#[must_use]
pub fn btc_amount_json(amount: Amount) -> Value {
    let satoshis = amount.to_sat();
    let whole = satoshis / 100_000_000;
    let fractional = satoshis % 100_000_000;
    let text = format!("{whole}.{fractional:08}");
    let mut deserializer = sonic_rs::Deserializer::from_str(&text).use_rawnumber();
    match sonic_rs::Deserialize::deserialize(&mut deserializer) {
        Ok(value) => value,
        Err(error) => panic!("formatted unsigned BTC amount was invalid JSON: {error}"),
    }
}

/// Render one transaction in Bitcoin Core's verbose object shape.
#[must_use]
pub fn transaction_json(
    tx: &Transaction,
    network: Network,
    chain: Option<TransactionChainContext>,
) -> Value {
    transaction_json_with_prevouts(tx, network, chain, None)
}

/// Render one transaction, optionally including verbosity-2 `fee` and `prevout`.
#[must_use]
pub fn transaction_json_with_prevouts(
    tx: &Transaction,
    network: Network,
    chain: Option<TransactionChainContext>,
    prevouts: Option<&[Option<TxPrevout>]>,
) -> Value {
    let txid = tx.compute_txid().to_string();
    let hash = tx.compute_wtxid().to_string();
    let size = tx.total_size();
    let weight = tx.weight().to_wu();
    let vsize = tx.vsize();
    let coinbase = tx.is_coinbase();
    let vin: Vec<Value> = tx
        .input
        .iter()
        .enumerate()
        .map(|(index, input)| {
            let prevout =
                prevouts.and_then(|prevouts| prevouts.get(index).and_then(Option::as_ref));
            input_json(input, index == 0 && coinbase, prevout, network)
        })
        .collect();
    let vout: Vec<Value> = tx
        .output
        .iter()
        .enumerate()
        .map(|(n, output)| output_json(output, n, network))
        .collect();

    let mut value = json!({
        "txid": txid,
        "hash": hash,
        "version": i64::from(tx.version.0),
        "size": size,
        "vsize": vsize,
        "weight": weight,
        "locktime": tx.lock_time.to_consensus_u32(),
        "vin": vin,
        "vout": vout,
        "hex": serialize(tx).to_lower_hex_string()
    });
    if let Some(chain) = chain {
        let _ = value.insert("blockhash", json!(chain.block_hash.to_string()));
        let _ = value.insert("confirmations", json!(chain.confirmations));
        let _ = value.insert("time", json!(chain.block_time));
        let _ = value.insert("blocktime", json!(chain.block_time));
        if let Some(in_active_chain) = chain.in_active_chain {
            let _ = value.insert("in_active_chain", json!(in_active_chain));
        }
    }
    if !coinbase
        && let Some(prevouts) = prevouts
        && prevouts.len() == tx.input.len()
        && prevouts.iter().all(Option::is_some)
    {
        let input_value = prevouts.iter().fold(0_u64, |sum, prevout| {
            sum.saturating_add(prevout.as_ref().map_or(0, |prevout| prevout.value.to_sat()))
        });
        let output_value = tx.output.iter().fold(0_u64, |sum, output| {
            sum.saturating_add(output.value.to_sat())
        });
        let _ = value.insert(
            "fee",
            btc_amount_json(Amount::from_sat(input_value.saturating_sub(output_value))),
        );
    }
    value
}

/// Render a `scriptPubKey` object in Bitcoin Core's verbose shape.
#[must_use]
pub fn script_pub_key_json(script: &bitcoin::ScriptBuf, network: Network) -> Value {
    let script_type = classify_script(script);
    let mut value = json!({
        "asm": script_asm(script),
        "desc": script_desc(script, network),
        "hex": script.as_bytes().to_lower_hex_string(),
        "type": script_type
    });
    if let Ok(address) = bitcoin::Address::from_script(script, network) {
        let _ = value.insert("address", json!(address.to_string()));
    }
    value
}

fn input_json(
    input: &TxIn,
    coinbase: bool,
    prevout: Option<&TxPrevout>,
    network: Network,
) -> Value {
    if coinbase {
        let mut value = json!({
            "coinbase": input.script_sig.as_bytes().to_lower_hex_string(),
            "sequence": input.sequence.to_consensus_u32()
        });
        if !input.witness.is_empty() {
            let witness: Vec<String> = input
                .witness
                .iter()
                .map(bitcoin::hex::DisplayHex::to_lower_hex_string)
                .collect();
            let _ = value.insert("txinwitness", json!(witness));
        }
        return value;
    }

    let mut value = json!({
        "txid": input.previous_output.txid.to_string(),
        "vout": input.previous_output.vout,
        "scriptSig": {
            "asm": script_asm(&input.script_sig),
            "hex": input.script_sig.as_bytes().to_lower_hex_string()
        },
        "sequence": input.sequence.to_consensus_u32()
    });
    if !input.witness.is_empty() {
        let witness: Vec<String> = input
            .witness
            .iter()
            .map(bitcoin::hex::DisplayHex::to_lower_hex_string)
            .collect();
        let _ = value.insert("txinwitness", json!(witness));
    }
    if let Some(prevout) = prevout {
        let _ = value.insert(
            "prevout",
            json!({
                "generated": prevout.generated,
                "height": prevout.height,
                "value": btc_amount_json(prevout.value),
                "scriptPubKey": script_pub_key_json(&prevout.script_pubkey, network)
            }),
        );
    }
    value
}

fn output_json(output: &TxOut, n: usize, network: Network) -> Value {
    json!({
        "value": btc_amount_json(output.value),
        "n": n,
        "scriptPubKey": script_pub_key_json(&output.script_pubkey, network)
    })
}

fn script_asm(script: &Script) -> String {
    script.to_asm_string()
}

fn script_desc(script: &bitcoin::ScriptBuf, network: Network) -> String {
    if let Ok(address) = bitcoin::Address::from_script(script, network) {
        return format!("addr({address})");
    }
    format!("raw({})", script.as_bytes().to_lower_hex_string())
}

fn classify_script(script: &Script) -> &'static str {
    if script.is_p2tr() {
        "witness_v1_taproot"
    } else if script.is_p2wpkh() {
        "witness_v0_keyhash"
    } else if script.is_p2wsh() {
        "witness_v0_scripthash"
    } else if script.is_p2pkh() {
        "pubkeyhash"
    } else if script.is_p2sh() {
        "scripthash"
    } else if script.is_p2pk() {
        "pubkey"
    } else if script.is_op_return() {
        "nulldata"
    } else if script.is_multisig() {
        "multisig"
    } else {
        "nonstandard"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash as _;
    use bitcoin::{Amount, ScriptBuf, Transaction, TxOut, absolute, transaction};
    use sonic_rs::JsonValueTrait as _;

    fn sample_tx() -> Transaction {
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: Vec::new(),
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    #[test]
    fn in_active_chain_is_omitted_when_none() {
        let chain = TransactionChainContext {
            block_hash: bitcoin::BlockHash::from_byte_array([1; 32]),
            confirmations: 3,
            block_time: 9,
            in_active_chain: None,
        };
        let value = transaction_json(&sample_tx(), Network::Regtest, Some(chain));
        assert!(value.get("in_active_chain").is_none());
        assert_eq!(
            value
                .get("confirmations")
                .and_then(sonic_rs::JsonValueTrait::as_i64),
            Some(3)
        );
    }

    #[test]
    fn in_active_chain_is_emitted_when_some() {
        let chain = TransactionChainContext {
            block_hash: bitcoin::BlockHash::from_byte_array([2; 32]),
            confirmations: 0,
            block_time: 11,
            in_active_chain: Some(false),
        };
        let value = transaction_json(&sample_tx(), Network::Regtest, Some(chain));
        assert_eq!(
            value
                .get("in_active_chain")
                .and_then(sonic_rs::JsonValueTrait::as_bool),
            Some(false)
        );
    }
}
