//! Canonical Bitcoin Core transaction JSON projections.
//!
//! Callers supply optional confirmed-chain context. This module never queries
//! node state and does not choose JSON-RPC versus REST transport policy.

// Address encoding uses the sanctioned rust-bitcoin seam. Core disassembly
// uses the native instruction parser, and descriptor inference reuses the
// existing shape owner and Miniscript parser without keys or wallet state.
use bitcoin_rs_primitives::{BlockHash, Network, Tx, TxIn, TxOut, consensus_bytes};

#[cfg(test)]
use bitcoin_rs_primitives::{Amount, LockTime, OutPoint, Script, Sequence, Txid, Witness};
use sonic_rs::{Value, json};

use bitcoin::hashes::Hash as _;
use bitcoin::hex::DisplayHex;
use bitcoin_rs_script::{Instruction, instructions};

use crate::compat::convert::{self};

/// Optional confirmed-chain fields projected beside a transaction object.
#[derive(Debug)]
pub(crate) struct TransactionChainContext {
    /// Confirming block hash.
    pub block_hash: BlockHash,
    /// Confirmations on the applied chain, or `0` when the named block is inactive.
    pub confirmations: i64,
    /// Confirming block time, emitted only with positive confirmations.
    pub block_time: u64,
    /// Whether the confirming block is on the applied chain.
    ///
    /// Rendered only when `Some`. Explicit `blockhash` lookups set this;
    /// txindex lookups leave it absent.
    pub in_active_chain: Option<bool>,
}

/// Exact eight-decimal BTC spelling used by Core JSON amount fields.
///
/// Parsed with sonic's raw-number mode so the decimal spelling survives
/// serialization instead of being reduced through binary floating point.
#[must_use]
pub(crate) fn btc_amount_json(satoshis: u64) -> Value {
    btc_amount_parts(false, satoshis)
}

/// Core signed amount projection, including negative fees and raw wire amounts.
#[must_use]
pub(crate) fn signed_btc_amount_json(satoshis: i64) -> Value {
    btc_amount_parts(satoshis < 0, satoshis.unsigned_abs())
}

fn btc_amount_parts(negative: bool, magnitude: u64) -> Value {
    let whole = magnitude / 100_000_000;
    let fractional = magnitude % 100_000_000;
    let sign = if negative { "-" } else { "" };
    let text = format!("{sign}{whole}.{fractional:08}");
    let mut deserializer = sonic_rs::Deserializer::from_str(&text).use_rawnumber();
    match sonic_rs::Deserialize::deserialize(&mut deserializer) {
        Ok(value) => value,
        Err(error) => panic!("formatted BTC amount was invalid JSON: {error}"),
    }
}

/// Core transaction versions expose all 32 wire bits as an unsigned number.
/// Native transaction and signed block-header representations stay unchanged.
#[must_use]
pub(crate) const fn wire_transaction_version(version: i32) -> u32 {
    u32::from_le_bytes(version.to_le_bytes())
}

/// Render one transaction in Bitcoin Core's verbose object shape.
///
/// PRE: `tx` is the transaction to project, `network` is the selected Bitcoin
///   network, and `chain` carries confirmed-chain fields when the caller has
///   them.
/// POST: returns the ordinary Core verbose object: identifiers, sizes, weight,
///   lock time, inputs, outputs, hex, and the chain fields when `chain` is
///   set.
/// INVARIANT: the projection reads no node state and emits no `fee` or
///   per-input `prevout` field.
#[must_use]
pub(crate) fn transaction_json(
    tx: &Tx,
    network: Network,
    chain: Option<TransactionChainContext>,
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
        .map(|input| input_json(input, coinbase))
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
        "version": wire_transaction_version(tx.version),
        "size": size,
        "vsize": vsize,
        "weight": weight,
        "locktime": tx.lock_time.to_consensus(),
        "vin": vin,
        "vout": vout,
        "hex": consensus_bytes(tx).to_lower_hex_string()
    });
    if let Some(chain) = chain {
        let _ = value.insert("blockhash", json!(chain.block_hash.to_string()));
        let _ = value.insert("confirmations", json!(chain.confirmations));
        if chain.confirmations > 0 {
            let _ = value.insert("time", json!(chain.block_time));
            let _ = value.insert("blocktime", json!(chain.block_time));
        }
        if let Some(in_active_chain) = chain.in_active_chain {
            let _ = value.insert("in_active_chain", json!(in_active_chain));
        }
    }
    value
}

/// Render a `scriptPubKey` object in Bitcoin Core's verbose shape.
#[must_use]
pub(crate) fn script_pub_key_json(script: &[u8], network: Network) -> Value {
    script_json(script, network, true, true)
}

/// Core `ScriptToUniv` projection. Address-bearing views also infer a descriptor;
/// PSBT redeem/witness-script metadata deliberately requests neither field.
#[must_use]
pub(crate) fn script_json(
    script: &[u8],
    network: Network,
    include_hex: bool,
    include_address: bool,
) -> Value {
    script_json_with_redeem(script, network, include_hex, include_address, None)
}

fn script_json_with_redeem(
    script: &[u8],
    network: Network,
    include_hex: bool,
    include_address: bool,
    redeem: Option<&[u8]>,
) -> Value {
    let shape = convert::classify(script);
    let mut value = json!({
        "asm": script_asm(script, false),
        "type": convert::core_type_name(shape)
    });
    if include_hex {
        let _ = value.insert("hex", json!(script.to_lower_hex_string()));
    }
    if include_address {
        let _ = value.insert(
            "desc",
            json!(redeem.map_or_else(
                || script_descriptor(script, network),
                |_| script_desc(script, network, redeem)
            )),
        );
        if shape != convert::ScriptShape::Pubkey
            && let Some(address) = convert::script_address(script, network)
        {
            let _ = value.insert("address", json!(address));
        }
    }
    value
}

fn input_json(input: &TxIn, coinbase: bool) -> Value {
    if coinbase {
        let mut value = json!({
            "coinbase": input.script_sig.to_lower_hex_string(),
            "sequence": input.sequence.to_consensus()
        });
        if !input.witness.is_empty() {
            let witness: Vec<String> = input
                .witness
                .iter()
                .map(DisplayHex::to_lower_hex_string)
                .collect();
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
            "asm": script_asm(&input.script_sig, true),
            "hex": input.script_sig.to_lower_hex_string()
        },
        "sequence": input.sequence.to_consensus()
    });
    if !input.witness.is_empty() {
        let witness: Vec<String> = input
            .witness
            .iter()
            .map(DisplayHex::to_lower_hex_string)
            .collect();
        let _ = value.insert("txinwitness", json!(witness));
    }
    value
}

fn output_json(output: &TxOut, n: usize, network: Network) -> Value {
    json!({
        "value": signed_btc_amount_json(i64::from_le_bytes(output.value.to_sat().to_le_bytes())),
        "n": n,
        "scriptPubKey": script_pub_key_json(&output.script_pubkey, network)
    })
}

/// A one-input, null-prevout transaction (Core's `IsCoinBase`).
#[must_use]
pub(crate) fn is_coinbase(tx: &Tx) -> bool {
    tx.inputs.len() == 1 && tx.inputs[0].previous_output.is_null()
}

/// Core's disassembly uses decimal short pushes and omits push-opcode labels.
/// Signature annotations are used only for input scripts, never output scripts.
#[must_use]
pub(crate) fn script_asm(script: &[u8], attempt_sighash_decode: bool) -> String {
    let mut words = String::new();
    for instruction in instructions(script) {
        let word = match instruction {
            Err(_) => {
                if !words.is_empty() {
                    words.push(' ');
                }
                words.push_str("[error]");
                break;
            }
            Ok(Instruction::PushBytes(data)) if data.len() <= 4 => {
                let mut value = data
                    .iter()
                    .enumerate()
                    .fold(0_i64, |n, (i, byte)| n | (i64::from(*byte) << (8 * i)));
                if data.last().is_some_and(|byte| byte & 0x80 != 0) {
                    value = -(value & !(0x80_i64 << (8 * (data.len() - 1))));
                }
                value.to_string()
            }
            Ok(Instruction::PushBytes(data)) => {
                if attempt_sighash_decode
                    && !unspendable(script)
                    && bitcoin_rs_script::check_signature_encoding(
                        data,
                        bitcoin_rs_script::VerifyFlags::STRICTENC,
                    )
                    .is_ok()
                {
                    let (signature, hash_type) = data.split_at(data.len() - 1);
                    let name = match hash_type[0] & 0x7f {
                        1 => "ALL",
                        2 => "NONE",
                        3 => "SINGLE",
                        _ => "",
                    };
                    let anyone = if hash_type[0] & 0x80 != 0 {
                        "|ANYONECANPAY"
                    } else {
                        ""
                    };
                    format!("{}[{name}{anyone}]", signature.to_lower_hex_string())
                } else {
                    data.to_lower_hex_string()
                }
            }
            Ok(Instruction::Op(op)) => match op {
                0x4f => "-1".to_owned(),
                0x51..=0x60 => (op - 0x50).to_string(),
                0xb1 => "OP_CHECKLOCKTIMEVERIFY".to_owned(),
                0xb2 => "OP_CHECKSEQUENCEVERIFY".to_owned(),
                0xbb..=0xfe => "OP_UNKNOWN".to_owned(),
                _ => bitcoin::opcodes::Opcode::from(op).to_string(),
            },
        };
        if !words.is_empty() {
            words.push(' ');
        }
        words.push_str(&word);
    }
    words
}

fn unspendable(script: &[u8]) -> bool {
    script.first() == Some(&bitcoin_rs_script::opcode::OP_RETURN)
        || script.len() > bitcoin_rs_script::MAX_SCRIPT_SIZE
}

/// Infer a checksummed descriptor with no key or script provider.
#[must_use]
pub(crate) fn script_descriptor(script: &[u8], network: Network) -> String {
    script_desc(script, network, None)
}

// Infer only information present in the script. There is no public/private key
// provider here; decodescript supplies only the script behind its P2WSH wrapper.
fn script_desc(script: &[u8], network: Network, redeem: Option<&[u8]>) -> String {
    let body = if let Some(redeem) = redeem {
        infer_inner_descriptor(redeem, true).map(|inner| format!("wsh({inner})"))
    } else {
        infer_inner_descriptor(script, false)
    }
    .or_else(|| convert::script_address(script, network).map(|address| format!("addr({address})")))
    .unwrap_or_else(|| format!("raw({})", script.to_lower_hex_string()));
    // All inferred text uses the descriptor alphabet (hex, op names, addresses).
    let checksum = crate::handlers::util::descriptor_checksum(&body)
        .unwrap_or_else(|| unreachable!("inferred descriptor contains only descriptor characters"));
    format!("{body}#{checksum}")
}

fn infer_inner_descriptor(script: &[u8], witness: bool) -> Option<String> {
    use convert::ScriptShape;
    let shape = convert::classify(script);
    let valid_key = |key: &[u8]| {
        matches!(key.first(), Some(2 | 3)) && key.len() == 33
            || !witness && key.first() == Some(&4) && key.len() == 65
    };
    match shape {
        ScriptShape::Pubkey => {
            let key = &script[1..script.len() - 1];
            if valid_key(key) {
                return Some(format!("pk({})", key.to_lower_hex_string()));
            }
        }
        ScriptShape::Multisig => {
            let mut iter = instructions(script);
            let required = match iter.next()?.ok()? {
                Instruction::Op(op) => u64::from(op.checked_sub(0x50)?),
                Instruction::PushBytes(data) => u64::from(*data.first()?),
            };
            let keys: Vec<_> = iter
                .filter_map(|instruction| match instruction {
                    Ok(Instruction::PushBytes(key)) if key.len() >= 33 => Some(key),
                    _ => None,
                })
                .collect();
            if keys.iter().all(|key| valid_key(key)) {
                let keys: Vec<_> = keys.iter().map(|key| key.to_lower_hex_string()).collect();
                return Some(format!("multi({required},{})", keys.join(",")));
            }
        }
        ScriptShape::WitnessV1Taproot
            if !witness && bitcoin::secp256k1::XOnlyPublicKey::from_slice(&script[2..]).is_ok() =>
        {
            return Some(format!("rawtr({})", script[2..].to_lower_hex_string()));
        }
        _ => {}
    }
    if witness {
        // Core considers impossible-to-satisfy scripts such as `0` sane when
        // their other type properties hold. rust-miniscript's default policy
        // additionally requires a satisfaction. Reuse its parsed AST and
        // sanity properties, applying Core's optional satisfaction bounds.
        let descriptor =
            miniscript::Miniscript::<bitcoin::PublicKey, miniscript::Segwitv0>::decode_with_ext(
                bitcoin::Script::from_bytes(script),
                &miniscript::ExtParams::sane().exceed_resource_limitations(),
            )
            .ok()?;
        if descriptor.ext.sat_data.is_some_and(|satisfaction| {
            descriptor.ext.static_ops + satisfaction.max_exec_op_count
                > miniscript::miniscript::limits::MAX_OPS_PER_SCRIPT
                || satisfaction.max_witness_stack_count
                    > miniscript::miniscript::limits::MAX_STANDARD_P2WSH_STACK_ITEMS
        }) {
            return None;
        }
        return Some(descriptor.to_string());
    }
    None
}

/// Decode and wrap one script using Core's wallet-free `ScriptToUniv` policy.
pub(crate) fn decoded_script_json(script: &[u8], network: Network) -> Value {
    use convert::ScriptShape;
    let mut result = script_json(script, network, false, true);
    let shape = convert::classify(script);
    let eligible = matches!(
        shape,
        ScriptShape::Empty
            | ScriptShape::Nonstandard
            | ScriptShape::Multisig
            | ScriptShape::Pubkey
            | ScriptShape::PubkeyHash
            | ScriptShape::WitnessV0KeyHash
            | ScriptShape::WitnessV0ScriptHash
    );
    if !eligible || !bitcoin_rs_script::has_valid_ops(script) || unspendable(script)
        || instructions(script).any(|instruction| matches!(instruction, Ok(Instruction::Op(op)) if op == 0xba || bitcoin_rs_script::is_op_success(op)))
    { return result; }
    let p2sh = bitcoin::ScriptBuf::new_p2sh(&bitcoin::ScriptHash::hash(script));
    if let Some(address) = convert::script_address(p2sh.as_bytes(), network) {
        let _ = result.insert("p2sh", json!(address));
    }
    if matches!(
        shape,
        ScriptShape::WitnessV0KeyHash | ScriptShape::WitnessV0ScriptHash
    ) || matches!(shape, ScriptShape::Pubkey | ScriptShape::Multisig)
        && instructions(script).any(
            |instruction| matches!(instruction, Ok(Instruction::PushBytes(key)) if key.len() == 65),
        )
    {
        return result;
    }
    let (segwit, redeem) = match shape {
        ScriptShape::Pubkey => (
            bitcoin::ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::hash(
                &script[1..script.len() - 1],
            )),
            None,
        ),
        ScriptShape::PubkeyHash => {
            let hash = bitcoin::WPubkeyHash::from_slice(&script[3..23])
                .unwrap_or_else(|_| unreachable!("classified P2PKH has a 20-byte hash"));
            (bitcoin::ScriptBuf::new_p2wpkh(&hash), None)
        }
        _ => (
            bitcoin::ScriptBuf::new_p2wsh(&bitcoin::WScriptHash::hash(script)),
            Some(script),
        ),
    };
    let mut wrapped = script_json_with_redeem(segwit.as_bytes(), network, true, true, redeem);
    let nested = bitcoin::ScriptBuf::new_p2sh(&bitcoin::ScriptHash::hash(segwit.as_bytes()));
    if let Some(address) = convert::script_address(nested.as_bytes(), network) {
        let _ = wrapped.insert("p2sh-segwit", json!(address));
    }
    let _ = result.insert("segwit", wrapped);
    result
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests {
    use super::*;
    use bitcoin_rs_primitives::Hash256;
    use core::str::FromStr as _;

    use sonic_rs::JsonValueTrait;

    /// Core's null outpoint: zero txid, `u32::MAX` vout.
    fn null_outpoint() -> OutPoint {
        OutPoint::null()
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
        for field in ["time", "blocktime"] {
            assert_eq!(value.get(field).and_then(Value::as_u64), Some(9));
        }
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
        for field in ["time", "blocktime"] {
            assert!(
                value.get(field).is_none(),
                "inactive {field} must be absent"
            );
        }
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

#[cfg(test)]
mod script_projection_tests {
    use super::*;
    use sonic_rs::JsonValueTrait;

    #[test]
    fn core_and_esplora_disassembly_remain_distinct() {
        let script = [0, 0x51, 1, 1];
        assert_eq!(script_asm(&script, false), "0 1 1");
        assert_eq!(
            convert::script_asm(&script),
            "OP_0 OP_PUSHNUM_1 OP_PUSHBYTES_1 01"
        );
        assert_eq!(script_asm(&[0x51, 0x4c], false), "1 [error]");
    }

    #[test]
    fn input_signature_annotation_is_not_an_output_script_annotation() {
        let script = [9, 0x30, 6, 2, 1, 1, 2, 1, 1, 0x81];
        assert_eq!(
            script_asm(&script, true),
            "3006020101020101[ALL|ANYONECANPAY]"
        );
        assert_eq!(script_asm(&script, false), "300602010102010181");
        let mut data = vec![0x6a];
        data.extend_from_slice(&script);
        assert_eq!(script_asm(&data, true), "OP_RETURN 300602010102010181");
    }

    #[test]
    fn core_script_field_selection_has_no_legacy_or_null_keys() {
        let script = [0x51];
        let plain = script_json(&script, Network::Regtest, true, false);
        assert!(plain.get("desc").is_none());
        assert!(plain.get("address").is_none());
        assert_eq!(
            plain.get("hex").and_then(JsonValueTrait::as_str),
            Some("51")
        );
        let decoded = decoded_script_json(&script, Network::Regtest);
        assert!(decoded.get("hex").is_none());
        assert!(decoded.get("reqSigs").is_none());
        assert!(decoded.get("addresses").is_none());
        assert!(
            decoded
                .get("desc")
                .and_then(JsonValueTrait::as_str)
                .is_some_and(|desc| desc.contains('#'))
        );
    }
}

#[cfg(test)]
mod wire_value_tests {
    use super::*;
    use sonic_rs::JsonValueTrait as _;

    #[test]
    fn wire_integer_projection_does_not_change_native_representations() {
        let tx = Tx {
            version: -1,
            lock_time: LockTime::ZERO,
            inputs: Vec::new(),
            outputs: vec![TxOut {
                value: Amount::from_sat(u64::MAX),
                script_pubkey: Script::new(),
            }],
        };
        let value = transaction_json(&tx, Network::Regtest, None);
        assert_eq!(
            value
                .get("version")
                .and_then(sonic_rs::JsonValueTrait::as_u64),
            Some(u64::from(u32::MAX))
        );
        assert_eq!(value["vout"][0]["value"].to_string(), "-0.00000001");
        assert_eq!(tx.version, -1);
        assert_eq!(tx.outputs[0].value.to_sat(), u64::MAX);
        assert_eq!(
            signed_btc_amount_json(i64::MIN).to_string(),
            "-92233720368.54775808"
        );
        assert_eq!(signed_btc_amount_json(-1).to_string(), "-0.00000001");
    }
}
