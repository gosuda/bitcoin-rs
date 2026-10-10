//! Wallet-free PSBT JSON over the one strict codec and Core script renderer.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use bitcoin::bip32::KeySource;
use bitcoin::hashes::Hash as _;
use bitcoin::hex::DisplayHex;
use bitcoin::psbt::{Input, Output, Psbt, raw};
use bitcoin_rs_primitives::{Amount, Network};
use sonic_rs::{JsonContainerTrait as _, JsonValueMutTrait as _, JsonValueTrait as _, Value, json};

use crate::context::Context;
use crate::error::RpcError;
use crate::tx_render::{script_asm, script_json, signed_btc_amount_json};

pub(crate) fn decodepsbt(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let bound = super::bind_named_params(params, &["psbt"])?;
    let array = super::params_array(bound.as_ref())?;
    if array.len() != 1 {
        return Err(RpcError::Misc("decodepsbt \"psbt\"".to_owned()));
    }
    let encoded = array[0]
        .as_str()
        .ok_or_else(|| super::wrong_type(1, "psbt", &array[0], "string"))?;
    let psbt = crate::psbt::decode(encoded).map_err(crate::psbt::DecodeError::into_rpc)?;
    project(&psbt, ctx.chain.chain_network)
}

fn project(psbt: &Psbt, network: Network) -> Result<Value, RpcError> {
    let mut xpubs: Vec<_> = psbt.xpub.iter().collect();
    xpubs.sort_by(|(a, ao), (b, bo)| {
        ao.0.cmp(&bo.0)
            .then_with(|| ao.1.len().cmp(&bo.1.len()))
            .then_with(|| {
                ao.1.into_iter()
                    .map(|child| u32::from(*child))
                    .cmp(bo.1.into_iter().map(|child| u32::from(*child)))
            })
            .then_with(|| a.public_key.serialize().cmp(&b.public_key.serialize()))
            .then_with(|| a.chain_code.cmp(&b.chain_code))
    });
    let global_xpubs: Vec<_> = xpubs.into_iter().map(|(xpub, origin)| {
        json!({"xpub":xpub.to_string(),"master_fingerprint":origin.0.to_string(),"path":origin_path(origin)})
    }).collect();
    let inputs: Vec<_> = psbt
        .inputs
        .iter()
        .map(|input| input_json(input, network))
        .collect::<Result<_, _>>()?;
    let outputs: Vec<_> = psbt
        .outputs
        .iter()
        .map(|output| output_json(output, network))
        .collect::<Result<_, _>>()?;
    let mut value = json!({
        "tx": transaction_json(&psbt.unsigned_tx,network),
        "global_xpubs":global_xpubs,
        "psbt_version":psbt.version,
        "proprietary":proprietary_json(&psbt.proprietary)?,
        "unknown":unknown_json(&psbt.unknown,None),
        "inputs":inputs,"outputs":outputs
    });
    let total_in = (0..psbt.inputs.len()).try_fold(0_i64, |total, index| {
        let utxo = crate::psbt::input_utxo(psbt, index)?;
        money_add(total, wire_amount(utxo.value))
    });
    let total_out = psbt
        .unsigned_tx
        .output
        .iter()
        .try_fold(0_i64, |total, output| {
            money_add(total, wire_amount(output.value))
        });
    if let (Some(total_in), Some(total_out)) = (total_in, total_out) {
        let _ = value.insert("fee", signed_btc_amount_json(total_in - total_out));
    }
    Ok(value)
}

fn wire_amount(amount: bitcoin::Amount) -> i64 {
    i64::from_le_bytes(amount.to_sat().to_le_bytes())
}
fn money_add(total: i64, amount: i64) -> Option<i64> {
    if amount < 0 || amount.unsigned_abs() > Amount::MAX_MONEY.to_sat() {
        return None;
    }
    let sum = total.checked_add(amount)?;
    (sum.unsigned_abs() <= Amount::MAX_MONEY.to_sat()).then_some(sum)
}

fn transaction_json(tx: &bitcoin::Transaction, network: Network) -> Value {
    let native = crate::compat::convert::native_transaction(tx);
    let mut value = crate::tx_render::transaction_json(&native, network, None);
    if let Some(object) = value.as_object_mut() {
        object.remove(&"hex");
    }
    value
}

fn origin_path(origin: &KeySource) -> String {
    let mut path = "m".to_owned();
    for child in &origin.1 {
        use std::fmt::Write as _;
        let _ = write!(path, "/{child:#}");
    }
    path
}
fn bip32_json(paths: &BTreeMap<bitcoin::secp256k1::PublicKey, KeySource>) -> Value {
    let values: Vec<_> = paths.iter().map(|(key,origin)| json!({"pubkey":key.serialize().to_lower_hex_string(),"master_fingerprint":origin.0.to_string(),"path":origin_path(origin)})).collect();
    json!(values)
}
fn tap_origins_json(
    paths: &BTreeMap<bitcoin::secp256k1::XOnlyPublicKey, (Vec<bitcoin::TapLeafHash>, KeySource)>,
) -> Value {
    let values: Vec<_> = paths.iter().map(|(key,(hashes,origin))| {
        let hashes: Vec<_> = hashes.iter().map(|hash| hash.as_byte_array().to_lower_hex_string()).collect();
        json!({"pubkey":key.serialize().to_lower_hex_string(),"master_fingerprint":origin.0.to_string(),"path":origin_path(origin),"leaf_hashes":hashes})
    }).collect();
    json!(values)
}
fn raw_key_hex(key: &raw::Key) -> String {
    let mut bytes = vec![key.type_value];
    bytes.extend_from_slice(&key.key);
    bytes.to_lower_hex_string()
}
fn unknown_json(fields: &BTreeMap<raw::Key, Vec<u8>>, input: Option<bool>) -> Value {
    let mut value = json!({});
    for (key, bytes) in fields {
        if input.is_some_and(|input| crate::psbt::is_musig2(key, input)) {
            continue;
        }
        let _ = value.insert(&raw_key_hex(key), json!(bytes.to_lower_hex_string()));
    }
    value
}
fn proprietary_json(fields: &BTreeMap<raw::ProprietaryKey, Vec<u8>>) -> Result<Value, RpcError> {
    let mut fields: Vec<_> = fields
        .iter()
        .map(|(key, value)| (key.to_key(), key, value))
        .collect();
    fields.sort_by(|(a, _, _), (b, _, _)| a.cmp(b));
    let rows: Vec<_> = fields.into_iter().map(|(raw,key,value)| {
        let subtype=crate::psbt::proprietary_subtype(key).map_err(crate::psbt::DecodeError::into_rpc)?;
        Ok(json!({"identifier":key.prefix.to_lower_hex_string(),"subtype":subtype,"key":raw_key_hex(&raw),"value":value.to_lower_hex_string()}))
    }).collect::<Result<_,RpcError>>()?;
    Ok(json!(rows))
}
fn hex_entries(entries: impl Iterator<Item = (String, String)>) -> Value {
    let mut value = json!({});
    for (key, bytes) in entries {
        let _ = value.insert(&key, json!(bytes));
    }
    value
}

fn input_json(input: &Input, network: Network) -> Result<Value, RpcError> {
    let mut value = json!({});
    if let Some(output) = &input.witness_utxo {
        let _=value.insert("witness_utxo",json!({"amount":signed_btc_amount_json(wire_amount(output.value)),"scriptPubKey":script_json(output.script_pubkey.as_bytes(),network,true,true)}));
    }
    if let Some(tx) = &input.non_witness_utxo {
        let _ = value.insert("non_witness_utxo", transaction_json(tx, network));
    }
    if !input.partial_sigs.is_empty() {
        let _ = value.insert(
            "partial_signatures",
            hex_entries(input.partial_sigs.iter().map(|(key, sig)| {
                (
                    key.to_bytes().to_lower_hex_string(),
                    sig.to_vec().to_lower_hex_string(),
                )
            })),
        );
    }
    if let Some(sighash) = input.sighash_type {
        let name = match sighash.to_u32() & 0xff {
            1 => "ALL",
            2 => "NONE",
            3 => "SINGLE",
            0x81 => "ALL|ANYONECANPAY",
            0x82 => "NONE|ANYONECANPAY",
            0x83 => "SINGLE|ANYONECANPAY",
            _ => "",
        };
        let _ = value.insert("sighash", json!(name));
    }
    for (name, script) in [
        ("redeem_script", &input.redeem_script),
        ("witness_script", &input.witness_script),
    ] {
        if let Some(script) = script.as_ref().filter(|script| !script.is_empty()) {
            let _ = value.insert(name, script_json(script.as_bytes(), network, true, false));
        }
    }
    if !input.bip32_derivation.is_empty() {
        let _ = value.insert("bip32_derivs", bip32_json(&input.bip32_derivation));
    }
    if let Some(script) = input
        .final_script_sig
        .as_ref()
        .filter(|script| !script.is_empty())
    {
        let _=value.insert("final_scriptSig",json!({"asm":script_asm(script.as_bytes(),true),"hex":script.as_bytes().to_lower_hex_string()}));
    }
    if let Some(witness) = input
        .final_script_witness
        .as_ref()
        .filter(|witness| !witness.is_empty())
    {
        let stack: Vec<_> = witness
            .iter()
            .map(DisplayHex::to_lower_hex_string)
            .collect();
        let _ = value.insert("final_scriptwitness", json!(stack));
    }
    macro_rules! preimages {
        ($field:ident) => {
            if !input.$field.is_empty() {
                let _ = value.insert(
                    stringify!($field),
                    hex_entries(input.$field.iter().map(|(hash, preimage)| {
                        (
                            hash.as_byte_array().to_lower_hex_string(),
                            preimage.to_lower_hex_string(),
                        )
                    })),
                );
            }
        };
    }
    preimages!(ripemd160_preimages);
    preimages!(sha256_preimages);
    preimages!(hash160_preimages);
    preimages!(hash256_preimages);
    input_taproot(input, &mut value);
    musig2_json(&input.unknown, true, &mut value);
    if !input.proprietary.is_empty() {
        let _ = value.insert("proprietary", proprietary_json(&input.proprietary)?);
    }
    let unknown = unknown_json(&input.unknown, Some(true));
    if unknown.as_object().is_some_and(|object| !object.is_empty()) {
        let _ = value.insert("unknown", unknown);
    }
    Ok(value)
}

fn input_taproot(input: &Input, value: &mut Value) {
    if let Some(sig) = input.tap_key_sig {
        let _ = value.insert(
            "taproot_key_path_sig",
            json!(sig.to_vec().to_lower_hex_string()),
        );
    }
    if !input.tap_script_sigs.is_empty() {
        let sigs:Vec<_>=input.tap_script_sigs.iter().map(|((key,hash),sig)| json!({"pubkey":key.serialize().to_lower_hex_string(),"leaf_hash":hash.as_byte_array().to_lower_hex_string(),"sig":sig.to_vec().to_lower_hex_string()})).collect();
        let _ = value.insert("taproot_script_path_sigs", json!(sigs));
    }
    if !input.tap_scripts.is_empty() {
        let mut scripts: BTreeMap<(Vec<u8>, u8), BTreeSet<Vec<u8>>> = BTreeMap::new();
        for (control, (script, version)) in &input.tap_scripts {
            scripts
                .entry((script.as_bytes().to_vec(), version.to_consensus()))
                .or_default()
                .insert(control.serialize());
        }
        let scripts:Vec<_>=scripts.into_iter().map(|((script,version),controls)| {let controls:Vec<_>=controls.iter().map(DisplayHex::to_lower_hex_string).collect();json!({"script":script.to_lower_hex_string(),"leaf_ver":version,"control_blocks":controls})}).collect();
        let _ = value.insert("taproot_scripts", json!(scripts));
    }
    if !input.tap_key_origins.is_empty() {
        let _ = value.insert(
            "taproot_bip32_derivs",
            tap_origins_json(&input.tap_key_origins),
        );
    }
    if let Some(key) = input.tap_internal_key {
        let _ = value.insert(
            "taproot_internal_key",
            json!(key.serialize().to_lower_hex_string()),
        );
    }
    if let Some(hash) = input
        .tap_merkle_root
        .filter(|hash| hash.as_byte_array() != &[0; 32])
    {
        let _ = value.insert(
            "taproot_merkle_root",
            json!(hash.as_byte_array().to_lower_hex_string()),
        );
    }
}

fn output_json(output: &Output, network: Network) -> Result<Value, RpcError> {
    let mut value = json!({});
    for (name, script) in [
        ("redeem_script", &output.redeem_script),
        ("witness_script", &output.witness_script),
    ] {
        if let Some(script) = script.as_ref().filter(|script| !script.is_empty()) {
            let _ = value.insert(name, script_json(script.as_bytes(), network, true, false));
        }
    }
    if !output.bip32_derivation.is_empty() {
        let _ = value.insert("bip32_derivs", bip32_json(&output.bip32_derivation));
    }
    if let Some(key) = output.tap_internal_key {
        let _ = value.insert(
            "taproot_internal_key",
            json!(key.serialize().to_lower_hex_string()),
        );
    }
    if let Some(tree) = &output.tap_tree {
        let leaves:Vec<_>=tree.script_leaves().map(|leaf| json!({"depth":leaf.merkle_branch().len(),"leaf_ver":leaf.version().to_consensus(),"script":leaf.script().as_bytes().to_lower_hex_string()})).collect();
        let _ = value.insert("taproot_tree", json!(leaves));
    }
    if !output.tap_key_origins.is_empty() {
        let _ = value.insert(
            "taproot_bip32_derivs",
            tap_origins_json(&output.tap_key_origins),
        );
    }
    musig2_json(&output.unknown, false, &mut value);
    if !output.proprietary.is_empty() {
        let _ = value.insert("proprietary", proprietary_json(&output.proprietary)?);
    }
    let unknown = unknown_json(&output.unknown, Some(false));
    if unknown.as_object().is_some_and(|object| !object.is_empty()) {
        let _ = value.insert("unknown", unknown);
    }
    Ok(value)
}

fn musig2_json(fields: &BTreeMap<raw::Key, Vec<u8>>, input: bool, value: &mut Value) {
    let mut participants = Vec::new();
    let mut nonces = Vec::new();
    let mut signatures = Vec::new();
    for (key, data) in fields
        .iter()
        .filter(|(key, _)| crate::psbt::is_musig2(key, input))
    {
        if !input || key.type_value == 0x1a {
            let keys: Vec<_> = data
                .as_chunks::<33>()
                .0
                .iter()
                .map(DisplayHex::to_lower_hex_string)
                .collect();
            participants.push(json!({"aggregate_pubkey":key.key.to_lower_hex_string(),"participant_pubkeys":keys}));
        } else {
            let mut item = json!({"participant_pubkey":key.key[..33].to_lower_hex_string(),"aggregate_pubkey":key.key[33..66].to_lower_hex_string()});
            let leaf = key.key.get(66..).unwrap_or_default();
            if leaf.iter().any(|byte| *byte != 0) {
                let _ = item.insert("leaf_hash", json!(leaf.to_lower_hex_string()));
            }
            let field = if key.type_value == 0x1b {
                "pubnonce"
            } else {
                "partial_sig"
            };
            let _ = item.insert(field, json!(data.to_lower_hex_string()));
            let order = (
                key.key[33..66].to_vec(),
                if leaf.is_empty() {
                    vec![0; 32]
                } else {
                    leaf.to_vec()
                },
                key.key[..33].to_vec(),
            );
            if key.type_value == 0x1b {
                nonces.push((order, item));
            } else {
                signatures.push((order, item));
            }
        }
    }
    if !participants.is_empty() {
        let _ = value.insert("musig2_participant_pubkeys", json!(participants));
    }
    for (name, mut rows) in [
        ("musig2_pubnonces", nonces),
        ("musig2_partial_sigs", signatures),
    ] {
        if !rows.is_empty() {
            rows.sort_by(|a, b| a.0.cmp(&b.0));
            let rows: Vec<_> = rows.into_iter().map(|(_, row)| row).collect();
            let _ = value.insert(name, json!(rows));
        }
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn in_process_decode_admission_enforces_the_shared_byte_limit() {
        let ctx = Arc::new(Context::new());
        let encoded = "A".repeat(crate::psbt::MAX_PSBT_BYTES + 1);
        let error = decodepsbt(&ctx, &json!([encoded])).expect_err("direct call remains bounded");
        assert!(
            matches!(error, RpcError::InvalidParameter(message) if message == "PSBT exceeds the RPC request byte limit")
        );
    }
}
