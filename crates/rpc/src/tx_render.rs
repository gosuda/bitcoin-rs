//! Canonical Bitcoin Core transaction JSON projections.
//!
//! Callers supply optional confirmed-chain context. This module never queries
//! node state and does not choose JSON-RPC versus REST transport policy.

// WHY rust-bitcoin: address strings, `asm`, and `desc` in RPC response bodies
// are wire-format strings that must match Bitcoin Core byte-for-byte. They ride
// the sanctioned rust-bitcoin compat seam (`Address<T>`/`Script` disassembly);
// all transaction/amount/hash plumbing here is native.
use bitcoin::Address;
use bitcoin_rs_primitives::{BlockHash, Network, OutPoint, Tx, TxIn, TxOut, Txid, consensus_bytes};

#[cfg(test)]
use bitcoin_rs_primitives::{Amount, LockTime, Script, Sequence, Witness};
use sonic_rs::{Value, json};

use crate::script_util::{
    is_multisig, is_op_return, is_p2pk, is_p2pkh, is_p2sh, is_p2tr, is_p2wpkh, is_p2wsh,
};

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
    /// Prevout value in satoshis.
    pub value: u64,
    /// Prevout scriptPubKey.
    pub script_pubkey: Vec<u8>,
}

/// Exact eight-decimal BTC spelling used by Core JSON amount fields.
///
/// Parsed with sonic's raw-number mode so the decimal spelling survives
/// serialization instead of being reduced through binary floating point.
#[must_use]
pub fn btc_amount_json(satoshis: u64) -> Value {
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
    tx: &Tx,
    network: Network,
    chain: Option<TransactionChainContext>,
) -> Value {
    transaction_json_with_prevouts(tx, network, chain, None)
}

/// Render one transaction, optionally including verbosity-2 `fee` and `prevout`.
#[must_use]
pub fn transaction_json_with_prevouts(
    tx: &Tx,
    network: Network,
    chain: Option<TransactionChainContext>,
    prevouts: Option<&[Option<TxPrevout>]>,
) -> Value {
    let txid = tx.txid().to_string();
    let hash = tx.wtxid().to_string();
    let size = tx.total_size();
    let weight = tx.weight();
    let vsize = tx.vsize();
    let coinbase = is_coinbase(tx);
    let vin: Vec<Value> = tx
        .inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            let prevout =
                prevouts.and_then(|prevouts| prevouts.get(index).and_then(Option::as_ref));
            input_json(input, index == 0 && coinbase, prevout, network)
        })
        .collect();
    let vout: Vec<Value> = tx
        .outputs
        .iter()
        .enumerate()
        .map(|(n, output)| output_json(output, n, network))
        .collect();

    let mut value = json!({
        "txid": txid,
        "hash": hash,
        "version": i64::from(tx.version),
        "size": size,
        "vsize": vsize,
        "weight": weight,
        "locktime": tx.lock_time.to_consensus(),
        "vin": vin,
        "vout": vout,
        "hex": hex_encode(&consensus_bytes(tx))
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
        && prevouts.len() == tx.inputs.len()
        && prevouts.iter().all(Option::is_some)
    {
        let input_value = prevouts.iter().fold(0_u64, |sum, prevout| {
            sum.saturating_add(prevout.as_ref().map_or(0, |prevout| prevout.value))
        });
        let output_value = tx.outputs.iter().fold(0_u64, |sum, output| {
            sum.saturating_add(output.value.to_sat())
        });
        let _ = value.insert(
            "fee",
            btc_amount_json(input_value.saturating_sub(output_value)),
        );
    }
    value
}

/// Render a `scriptPubKey` object in Bitcoin Core's verbose shape.
#[must_use]
pub fn script_pub_key_json(script: &[u8], network: Network) -> Value {
    let script_type = classify_script(script);
    let mut value = json!({
        "asm": script_asm(script),
        "desc": script_desc(script, network),
        "hex": hex_encode(script),
        "type": script_type
    });
    if let Some(address) = script_address(script, network) {
        let _ = value.insert("address", json!(address));
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
            "coinbase": hex_encode(&input.script_sig),
            "sequence": input.sequence.to_consensus()
        });
        if !input.witness.is_empty() {
            let witness: Vec<String> = input.witness.iter().map(|item| hex_encode(item)).collect();
            let _ = value.insert("txinwitness", json!(witness));
        }
        return value;
    }
    let previous_output = input.previous_output;
    // Field copies come before any `&self` method: `OutPoint` is `#[repr(packed)]`
    // (consensus wire layout), so field references would be unaligned.
    let (prev_txid, prev_vout) = (previous_output.txid, previous_output.vout);
    let mut value = json!({
        "txid": prev_txid.to_string(),
        "vout": prev_vout,
        "scriptSig": {
            "asm": script_asm(&input.script_sig),
            "hex": hex_encode(&input.script_sig)
        },
        "sequence": input.sequence.to_consensus()
    });
    if !input.witness.is_empty() {
        let witness: Vec<String> = input.witness.iter().map(|item| hex_encode(item)).collect();
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
        "value": btc_amount_json(output.value.to_sat()),
        "n": n,
        "scriptPubKey": script_pub_key_json(&output.script_pubkey, network)
    })
}

/// A one-input, null-prevout transaction (Core's `IsCoinBase`).
#[must_use]
pub fn is_coinbase(tx: &Tx) -> bool {
    // Core's `COutPoint::IsNull`: zero txid and `u32::MAX` vout. `OutPoint`'s
    // derived `Default` has vout `0`, which is not the null outpoint.
    tx.inputs.len() == 1 && tx.inputs[0].previous_output == OutPoint::new(Txid::default(), u32::MAX)
}

fn script_asm(script: &[u8]) -> String {
    bitcoin::Script::from_bytes(script).to_asm_string()
}

/// Maps a native network to the rust-bitcoin network for the address seam.
#[must_use]
const fn bitcoin_network(network: Network) -> bitcoin::Network {
    match network {
        Network::Mainnet => bitcoin::Network::Bitcoin,
        Network::Testnet3 => bitcoin::Network::Testnet,
        Network::Testnet4 => bitcoin::Network::Testnet4,
        Network::Signet => bitcoin::Network::Signet,
        Network::Regtest => bitcoin::Network::Regtest,
    }
}

/// Renders the Core address string for a script, or `None` when the script has
/// no address form (via the sanctioned rust-bitcoin seam).
#[must_use]
fn script_address(script: &[u8], network: Network) -> Option<String> {
    Address::from_script(
        bitcoin::Script::from_bytes(script),
        bitcoin_network(network),
    )
    .ok()
    .map(|address| address.to_string())
}

fn script_desc(script: &[u8], network: Network) -> String {
    if let Some(address) = script_address(script, network) {
        return format!("addr({address})");
    }
    format!("raw({})", hex_encode(script))
}

fn classify_script(script: &[u8]) -> &'static str {
    if is_p2tr(script) {
        "witness_v1_taproot"
    } else if is_p2wpkh(script) {
        "witness_v0_keyhash"
    } else if is_p2wsh(script) {
        "witness_v0_scripthash"
    } else if is_p2pkh(script) {
        "pubkeyhash"
    } else if is_p2sh(script) {
        "scripthash"
    } else if is_p2pk(script) {
        "pubkey"
    } else if is_op_return(script) {
        "nulldata"
    } else if is_multisig(script) {
        "multisig"
    } else {
        "nonstandard"
    }
}

/// Encodes `bytes` as lowercase hexadecimal.
#[must_use]
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use bitcoin_rs_primitives::{Hash256, OutPoint};
    use core::str::FromStr as _;

    use sonic_rs::JsonValueTrait;

    /// Core's null outpoint: zero txid, `u32::MAX` vout.
    fn null_outpoint() -> OutPoint {
        OutPoint::new(Txid::default(), u32::MAX)
    }

    fn sample_tx() -> Tx {
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: Vec::new(),
            outputs: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: Script::new(),
            }],
        }
    }

    #[test]
    fn in_active_chain_is_omitted_when_none() {
        let chain = TransactionChainContext {
            block_hash: BlockHash::from_str(
                "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
            )
            .expect("valid hash hex"),
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
            block_hash: BlockHash::from(Hash256::from_le_bytes(&[2; 32])),
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

    #[test]
    fn one_input_null_prevout_is_coinbase() {
        let mut tx = sample_tx();
        tx.inputs.push(TxIn {
            previous_output: null_outpoint(),
            script_sig: vec![1, 2, 3].into(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        });
        assert!(is_coinbase(&tx));
        tx.inputs.push(TxIn {
            previous_output: null_outpoint(),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        });
        assert!(!is_coinbase(&tx));
    }

    #[test]
    fn coinbase_input_renders_hex_coinbase_field() {
        let mut tx = sample_tx();
        tx.inputs.push(TxIn {
            previous_output: null_outpoint(),
            script_sig: vec![0x51].into(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        });
        let value = transaction_json(&tx, Network::Regtest, None);
        let vin = value.get("vin").expect("vin present");
        let first = &vin[0];
        assert_eq!(
            first.get("coinbase").and_then(JsonValueTrait::as_str),
            Some("51")
        );
        assert!(first.get("txid").is_none());
    }

    #[test]
    fn non_coinbase_input_renders_outpoint_and_script_sig() {
        let tx = Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid::default(), 7),
                script_sig: vec![0x51].into(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: Script::new(),
            }],
        };
        let value = transaction_json(&tx, Network::Regtest, None);
        let first = &value.get("vin").expect("vin present")[0];
        assert_eq!(
            first.get("txid").and_then(JsonValueTrait::as_str),
            Some("0000000000000000000000000000000000000000000000000000000000000000")
        );
        assert_eq!(first.get("vout").and_then(JsonValueTrait::as_u64), Some(7));
        let script_sig = first.get("scriptSig").expect("scriptSig present");
        assert_eq!(
            script_sig.get("hex").and_then(JsonValueTrait::as_str),
            Some("51")
        );
        assert_eq!(
            first.get("sequence").and_then(JsonValueTrait::as_u64),
            Some(u64::from(Sequence::ENABLE_RBF_NO_LOCKTIME.to_consensus()))
        );
        assert!(first.get("coinbase").is_none());
    }

    #[test]
    fn p2wpkh_output_classifies_and_addresses_on_regtest() {
        let tx = Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: Vec::new(),
            outputs: vec![TxOut {
                value: Amount::from_sat(5_000),
                script_pubkey: vec![
                    0x00, 0x14, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c,
                    0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
                ]
                .into(),
            }],
        };
        let value = transaction_json(&tx, Network::Regtest, None);
        let spk = &value.get("vout").expect("vout")[0]
            .get("scriptPubKey")
            .expect("spk");
        assert_eq!(
            spk.get("type").and_then(JsonValueTrait::as_str),
            Some("witness_v0_keyhash")
        );
        assert_eq!(
            spk.get("address").and_then(JsonValueTrait::as_str),
            Some("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080")
        );
    }
}
