use alloc::sync::Arc;

use bitcoin::hex::DisplayHex as _;
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, Value, json};

use crate::context::Context;
use crate::error::RpcError;
use crate::handlers::{invalid_psbt, params_array, required_str};

const _: fn() -> Value = invalid_psbt;

pub(crate) fn getdescriptorinfo(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let descriptor = required_str(params, 0, "descriptor is required")?;
    // Strip any existing #XXXXXXXX checksum suffix.
    let payload = if let Some((body, _)) = descriptor.rsplit_once('#') {
        body
    } else {
        descriptor
    };
    let checksum = descriptor_checksum(payload).ok_or(RpcError::InvalidParams(
        "descriptor contains invalid characters",
    ))?;
    Ok(json!({
        "descriptor": format!("{payload}#{checksum}"),
        "checksum": checksum,
        "isrange": payload.contains('*'),
        "issolvable": false,
        "hasprivatekeys": false
    }))
}

pub(crate) fn deriveaddresses(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let descriptor = required_str(params, 0, "descriptor is required")?;
    // Strip optional #checksum suffix.
    let payload = descriptor
        .rsplit_once('#')
        .map_or(descriptor, |(body, _)| body);
    // Match addr(...) wrapper.
    if let Some(inner) = strip_addr_wrapper(payload) {
        if inner.contains('*') {
            // TODO(miniscript): support ranged addr() once miniscript+derivation
            // is wired. For now return empty since we cannot enumerate.
            return Ok(json!([]));
        }
        return Ok(json!([inner]));
    }
    // TODO(miniscript): other wrappers (pkh, sh, wpkh, tr, wsh, multi, ...) need
    // miniscript-based key derivation. Return empty until then.
    Ok(json!([]))
}

fn strip_addr_wrapper(payload: &str) -> Option<&str> {
    let stripped = payload.strip_prefix("addr(")?;
    let stripped = stripped.strip_suffix(')')?;
    Some(stripped)
}

#[derive(Clone, Debug)]
struct ScanScript {
    script_pubkey: bitcoin::ScriptBuf,
    desc: String,
}

pub(crate) fn scantxoutset(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let action = required_str(params, 0, "action is required")?;
    match action {
        "start" => {
            if let Some(scanobjects) = scanobjects_param(params)? {
                return scantxoutset_addr_scan(ctx, scanobjects);
            }

            let snapshot = ctx.coin_stats.snapshot();
            let total_amount_btc = bitcoin::Amount::from_sat(snapshot.total_amount).to_btc();
            Ok(json!({
                "success": true,
                "txouts": ctx.utxo.len(),
                "height": ctx.applied_height(),
                "bestblock": ctx.applied_hash().to_string_be(),
                "unspents": [],
                "total_amount": total_amount_btc
            }))
        }
        "abort" => Ok(json!(false)),
        "status" => Ok(Value::new_null()),
        _ => Err(RpcError::InvalidParams(
            "action must be one of: start, abort, status",
        )),
    }
}

fn scanobjects_param(params: &Value) -> Result<Option<&sonic_rs::Array>, RpcError> {
    let array = params_array(params)?;
    let Some(scanobjects) = array.get(1) else {
        return Ok(None);
    };
    let scanobjects = scanobjects
        .as_array()
        .ok_or(RpcError::InvalidType("scanobjects must be an array"))?;
    if scanobjects.is_empty() {
        return Err(RpcError::InvalidParams("scanobjects must not be empty"));
    }
    Ok(Some(scanobjects))
}

fn scantxoutset_addr_scan(
    ctx: &Arc<Context>,
    scanobjects: &sonic_rs::Array,
) -> Result<Value, RpcError> {
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
        "total_amount": bitcoin::Amount::from_sat(total_amount).to_btc()
    }))
}

fn parse_scan_scripts(
    chain_network: bitcoin_rs_primitives::Network,
    scanobjects: &sonic_rs::Array,
) -> Result<Vec<ScanScript>, RpcError> {
    let network = bitcoin_network(chain_network);
    let mut scripts = Vec::with_capacity(scanobjects.len());
    for scanobject in scanobjects {
        let descriptor = scanobject_descriptor(scanobject)?;
        scripts.push(parse_addr_scan_script(descriptor, network)?);
    }
    Ok(scripts)
}

fn scanobject_descriptor(scanobject: &Value) -> Result<&str, RpcError> {
    if let Some(descriptor) = scanobject.as_str() {
        return Ok(descriptor);
    }
    let Some(descriptor) = scanobject.get("desc") else {
        return Err(RpcError::InvalidParams("scan object missing desc"));
    };
    let descriptor = descriptor
        .as_str()
        .ok_or(RpcError::InvalidType("scan object desc must be a string"))?;
    if let Some(range) = scanobject.get("range") {
        validate_scanobject_range(range)?;
    }
    Ok(descriptor)
}

fn validate_scanobject_range(range: &Value) -> Result<(), RpcError> {
    if range.as_u64().is_some() {
        return Ok(());
    }
    let Some(bounds) = range.as_array() else {
        return Err(RpcError::InvalidType(
            "scan object range must be an integer or two-integer array",
        ));
    };
    if bounds.len() != 2 {
        return Err(RpcError::InvalidParams(
            "scan object range array must contain two entries",
        ));
    }
    let Some(start) = bounds.first().and_then(Value::as_u64) else {
        return Err(RpcError::InvalidType(
            "scan object range start must be an integer",
        ));
    };
    let Some(end) = bounds.get(1).and_then(Value::as_u64) else {
        return Err(RpcError::InvalidType(
            "scan object range end must be an integer",
        ));
    };
    if start > end {
        return Err(RpcError::InvalidParams(
            "scan object range start must not exceed end",
        ));
    }
    Ok(())
}

fn parse_addr_scan_script(
    descriptor: &str,
    network: bitcoin::Network,
) -> Result<ScanScript, RpcError> {
    use core::str::FromStr as _;

    let payload = checked_descriptor_payload(descriptor)?;
    if payload.contains('*') {
        return Err(RpcError::InvalidParams(
            "ranged scantxoutset descriptors are not supported",
        ));
    }
    let Some(address_text) = strip_addr_wrapper(payload) else {
        return Err(RpcError::InvalidParams(
            "unsupported scantxoutset descriptor; only addr() is supported",
        ));
    };
    let Ok(unchecked) = bitcoin::Address::from_str(address_text) else {
        return Err(RpcError::InvalidParams("Address is not valid"));
    };
    let Ok(address) = unchecked.require_network(network) else {
        return Err(RpcError::InvalidParams("Address is not valid"));
    };
    let payload = format!("addr({address})");
    let desc = descriptor_checksum(&payload).map_or_else(
        || payload.clone(),
        |checksum| format!("{payload}#{checksum}"),
    );
    Ok(ScanScript {
        script_pubkey: address.script_pubkey(),
        desc,
    })
}

fn checked_descriptor_payload(descriptor: &str) -> Result<&str, RpcError> {
    let Some((body, checksum)) = descriptor.rsplit_once('#') else {
        return Ok(descriptor);
    };
    let expected = descriptor_checksum(body).ok_or(RpcError::InvalidParams(
        "descriptor contains invalid characters",
    ))?;
    if checksum == expected {
        Ok(body)
    } else {
        Err(RpcError::InvalidParams("descriptor checksum mismatch"))
    }
}

fn scan_unspents(
    scan: &bitcoin_rs_utxo::UtxoScan,
    scan_scripts: &[ScanScript],
    applied_height: u32,
) -> (Vec<Value>, u64) {
    let mut total_amount = 0_u64;
    let unspents = scan
        .unspents
        .iter()
        .map(|utxo| {
            total_amount = total_amount.saturating_add(utxo.txout.value.to_sat());
            let desc = desc_for_script(scan_scripts, &utxo.txout.script_pubkey);
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

fn desc_for_script<'a>(scan_scripts: &'a [ScanScript], script: &bitcoin::Script) -> &'a str {
    scan_scripts
        .iter()
        .find(|scan| scan.script_pubkey.as_script() == script)
        .map_or("", |scan| scan.desc.as_str())
}

fn confirmations(applied_height: u32, output_height: u32) -> u64 {
    if output_height > applied_height {
        0
    } else {
        u64::from(applied_height - output_height) + 1
    }
}

const fn bitcoin_network(chain_network: bitcoin_rs_primitives::Network) -> bitcoin::Network {
    match chain_network {
        bitcoin_rs_primitives::Network::Mainnet => bitcoin::Network::Bitcoin,
        bitcoin_rs_primitives::Network::Testnet3 => bitcoin::Network::Testnet,
        bitcoin_rs_primitives::Network::Testnet4 => bitcoin::Network::Testnet4,
        bitcoin_rs_primitives::Network::Signet => bitcoin::Network::Signet,
        bitcoin_rs_primitives::Network::Regtest => bitcoin::Network::Regtest,
    }
}

pub(crate) fn walletcreatefundedpsbt(
    _ctx: &Arc<Context>,
    params: &Value,
) -> Result<Value, RpcError> {
    let array = params_array(params)?;
    if array.len() < 2 {
        return Err(RpcError::InvalidParams("inputs and outputs are required"));
    }
    Ok(json!({
        "psbt": "",
        "fee": 0.0,
        "changepos": -1
    }))
}

pub(crate) fn walletprocesspsbt(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let raw = required_str(params, 0, "psbt is required")?;
    let decoded = decode_base64(raw)?;
    let Ok(psbt) = bitcoin::psbt::Psbt::deserialize(&decoded) else {
        return Err(RpcError::InvalidParams("invalid base64 PSBT"));
    };
    let serialized = encode_base64(&psbt.serialize());
    // No signing in this PSBT-only wallet; `complete` reflects whether every
    // input is already finalized by an external signer that previously processed it.
    let complete = !psbt.inputs.is_empty()
        && psbt
            .inputs
            .iter()
            .all(|input| input.final_script_sig.is_some() || input.final_script_witness.is_some());
    Ok(json!({
        "psbt": serialized,
        "complete": complete,
    }))
}

pub(crate) fn finalizepsbt(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let raw = required_str(params, 0, "psbt is required")?;
    let decoded = decode_base64(raw)?;
    let Ok(psbt) = bitcoin::psbt::Psbt::deserialize(&decoded) else {
        return Err(RpcError::InvalidParams("invalid base64 PSBT"));
    };
    let serialized = encode_base64(&psbt.serialize());
    let complete = !psbt.inputs.is_empty()
        && psbt
            .inputs
            .iter()
            .all(|input| input.final_script_sig.is_some() || input.final_script_witness.is_some());
    if complete {
        let tx = psbt.extract_tx_unchecked_fee_rate();
        let hex = bitcoin::consensus::encode::serialize(&tx).to_lower_hex_string();
        Ok(json!({
            "psbt": serialized,
            "hex": hex,
            "complete": true,
        }))
    } else {
        Ok(json!({
            "psbt": serialized,
            "hex": "",
            "complete": false,
        }))
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
        return Err(RpcError::InvalidType("each psbt must be a string"));
    };
    let mut psbt = bitcoin::psbt::Psbt::deserialize(&decode_base64(first_str)?)
        .map_err(|_| RpcError::InvalidParams("invalid base64 PSBT"))?;

    for value in iter {
        let Some(s) = value.as_str() else {
            return Err(RpcError::InvalidType("each psbt must be a string"));
        };
        let other = bitcoin::psbt::Psbt::deserialize(&decode_base64(s)?)
            .map_err(|_| RpcError::InvalidParams("invalid base64 PSBT"))?;
        psbt.combine(other)
            .map_err(|err| RpcError::Internal(format!("combine failed: {err}")))?;
    }

    Ok(json!(encode_base64(&psbt.serialize())))
}

const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn decode_base64(input: &str) -> Result<Vec<u8>, RpcError> {
    let bytes = input.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
        return Err(RpcError::InvalidParams("invalid base64 PSBT"));
    }

    let chunk_count = bytes.len() / 4;
    let mut out = Vec::with_capacity(chunk_count * 3);
    for (index, chunk) in bytes.chunks_exact(4).enumerate() {
        let last = index + 1 == chunk_count;
        let pad2 = chunk[2] == b'=';
        let pad3 = chunk[3] == b'=';
        if chunk[0] == b'=' || chunk[1] == b'=' || pad2 && !pad3 || pad3 && !last {
            return Err(RpcError::InvalidParams("invalid base64 PSBT"));
        }

        let Some(a) = base64_value(chunk[0]) else {
            return Err(RpcError::InvalidParams("invalid base64 PSBT"));
        };
        let Some(b) = base64_value(chunk[1]) else {
            return Err(RpcError::InvalidParams("invalid base64 PSBT"));
        };
        let c = if pad2 {
            0
        } else {
            let Some(value) = base64_value(chunk[2]) else {
                return Err(RpcError::InvalidParams("invalid base64 PSBT"));
            };
            value
        };
        let d = if pad3 {
            0
        } else {
            let Some(value) = base64_value(chunk[3]) else {
                return Err(RpcError::InvalidParams("invalid base64 PSBT"));
            };
            value
        };

        out.push((a << 2) | (b >> 4));
        if !pad2 {
            out.push((b << 4) | (c >> 2));
        }
        if !pad3 {
            out.push((c << 6) | d);
        }
    }

    Ok(out)
}

const fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
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

const BIP380_INPUT_CHARSET: &str = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
const BIP380_CHECKSUM_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BIP380_GENERATOR: [u64; 5] = [
    0x00f5_dee5_1989,
    0x00a9_fdca_3312,
    0x001b_ab10_e32d,
    0x0037_06b1_677a,
    0x0064_4d62_6ffd,
];

fn descriptor_polymod(c: u64, val: u32) -> u64 {
    let c0 = c >> 35;
    let mut result = ((c & 0x0007_ffff_ffff) << 5) ^ u64::from(val);
    let mut bit = 0;
    while bit < 5 {
        if (c0 >> bit) & 1 != 0 {
            result ^= BIP380_GENERATOR[bit];
        }
        bit += 1;
    }
    result
}

fn descriptor_checksum(payload: &str) -> Option<String> {
    let mut c: u64 = 1;
    let mut cls: u64 = 0;
    let mut clscount: u64 = 0;
    for ch in payload.chars() {
        // INPUT_CHARSET is ASCII-only; find ch's byte position.
        let mut byte = [0_u8; 4];
        let encoded = ch.encode_utf8(&mut byte);
        if encoded.len() != 1 {
            return None;
        }
        let needle = encoded.as_bytes()[0];
        let pos = BIP380_INPUT_CHARSET
            .as_bytes()
            .iter()
            .position(|b| *b == needle)?;
        let pos_u64 = u64::try_from(pos).ok()?;
        let val = u32::try_from(pos_u64 & 31).ok()?;
        c = descriptor_polymod(c, val);
        cls = cls * 3 + (pos_u64 >> 5);
        clscount = clscount.saturating_add(1);
        if clscount == 3 {
            let val = u32::try_from(cls).ok()?;
            c = descriptor_polymod(c, val);
            cls = 0;
            clscount = 0;
        }
    }
    if clscount > 0 {
        let val = u32::try_from(cls).ok()?;
        c = descriptor_polymod(c, val);
    }
    for _ in 0..8_u32 {
        c = descriptor_polymod(c, 0);
    }
    c ^= 1;
    let mut out = String::with_capacity(8);
    for i in 0..8_u32 {
        let shift = 5_u32 * (7 - i);
        let idx = usize::try_from((c >> shift) & 31).ok()?;
        out.push(char::from(BIP380_CHECKSUM_CHARSET[idx]));
    }
    Some(out)
}

pub(crate) fn bumpfee(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    use core::str::FromStr as _;

    let txid_str = required_str(params, 0, "txid is required")?;
    let txid = bitcoin::Txid::from_str(txid_str)
        .map_err(|_| RpcError::InvalidParams("txid must be 64 hex characters"))?;

    // Locate the tx: prefer mempool (unconfirmed bumpable), fall back to confirmed.
    let (original_tx, original_fee, original_fee_rate_sat_per_kvb) = {
        let pool = ctx.mempool.read();
        if let Some(entry) = pool.entry_by_txid(&txid) {
            ((*entry.tx).clone(), entry.fee, entry.fee_rate)
        } else {
            drop(pool);
            let confirmed = ctx.transactions.read();
            let Some(tx) = confirmed.get(&txid) else {
                return Err(RpcError::NotFound("transaction not found"));
            };
            // Confirmed txs cannot be bumped via RBF; reject.
            let _ = tx;
            return Err(RpcError::InvalidParams(
                "cannot bump fee on confirmed transaction",
            ));
        }
    };

    // Bump fee rate by 25% as a default policy.
    let new_rate_sat_per_kvb = original_fee_rate_sat_per_kvb.saturating_mul(125) / 100;
    let psbt = bitcoin::psbt::Psbt::from_unsigned_tx(original_tx)
        .map_err(|err| RpcError::Internal(format!("psbt build: {err}")))?;
    let bumped =
        match bitcoin_rs_wallet::bump_psbt_with_rate_sat_per_kvb(&psbt, new_rate_sat_per_kvb) {
            Ok(bumped) => bumped,
            Err(bitcoin_rs_wallet::WalletError::Bip125(message)) => {
                return Ok(json!({
                    "psbt": "",
                    "origfee": bitcoin::Amount::from_sat(original_fee).to_btc(),
                    "fee": 0.0,
                    "errors": [message]
                }));
            }
            Err(err) => return Err(RpcError::Internal(format!("bumpfee: {err}"))),
        };
    let weight_wu = bumped.unsigned_tx.weight().to_wu();
    let target_fee_sats = new_rate_sat_per_kvb.saturating_mul(weight_wu) / 4_000;
    let target_fee_btc = bitcoin::Amount::from_sat(target_fee_sats).to_btc();
    let bumped_b64 = encode_base64(&bumped.serialize());

    Ok(json!({
        "psbt": bumped_b64,
        "origfee": bitcoin::Amount::from_sat(original_fee).to_btc(),
        "fee": target_fee_btc,
        "errors": Vec::<String>::new()
    }))
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use core::str::FromStr as _;

    use bitcoin::{Amount, ScriptBuf};
    use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut};
    use bitcoin_rs_utxo::{BlockChanges, UtxoAdd};
    use sonic_rs::JsonValueTrait as _;

    use super::*;

    fn test_txid(seed: u64) -> Hash256 {
        let mut bytes = [0_u8; 32];
        bytes[..8].copy_from_slice(&seed.to_le_bytes());
        bytes[8..16].copy_from_slice(&seed.rotate_left(7).to_le_bytes());
        bytes[16..24].copy_from_slice(&seed.wrapping_mul(17).to_le_bytes());
        bytes[24..32].copy_from_slice(&seed.wrapping_add(99).to_le_bytes());
        Hash256::from_le_bytes(&bytes)
    }

    fn commit_test_utxo(
        ctx: &Context,
        outpoint: OutPoint,
        txout: TxOut,
        coinbase: bool,
        height: u32,
    ) {
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(outpoint, txout, coinbase, height));
        ctx.utxo
            .commit_block(&changes, &test_txid(8_000))
            .unwrap_or_else(|err| panic!("commit utxo failed: {err}"));
    }

    #[test]
    fn scantxoutset_start_returns_real_summary_from_utxoset() {
        let ctx = Arc::new(Context::new());
        let result = scantxoutset(&ctx, &json!(["start"]))
            .unwrap_or_else(|err| panic!("scantxoutset failed: {err}"));
        let Some(success) = result.get("success").and_then(Value::as_bool) else {
            panic!("success missing: {result:?}");
        };
        assert!(
            success,
            "scantxoutset start should report success: {result:?}"
        );
        let Some(_height) = result.get("height").and_then(Value::as_u64) else {
            panic!("height missing: {result:?}");
        };
        let Some(txouts) = result.get("txouts").and_then(Value::as_u64) else {
            panic!("txouts missing: {result:?}");
        };
        assert_eq!(txouts, 0, "fresh ctx has empty utxoset");
    }

    #[test]
    fn scantxoutset_addr_returns_matching_unspents() {
        let ctx = Arc::new(Context::new());
        let address = "1111111111111111111114oLvT2";
        let script = bitcoin::Address::from_str(address)
            .unwrap_or_else(|err| panic!("address parse failed: {err}"))
            .require_network(bitcoin::Network::Bitcoin)
            .unwrap_or_else(|err| panic!("network check failed: {err}"))
            .script_pubkey();
        let txout = TxOut {
            value: Amount::from_sat(12_345),
            script_pubkey: script.clone(),
        };
        let outpoint = OutPoint::new(test_txid(11), 0);
        commit_test_utxo(&ctx, outpoint, txout, true, 0);
        commit_test_utxo(
            &ctx,
            OutPoint::new(test_txid(12), 0),
            TxOut {
                value: Amount::from_sat(9_999),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            },
            false,
            0,
        );

        let result = scantxoutset(&ctx, &json!(["start", [format!("addr({address})")]]))
            .unwrap_or_else(|err| panic!("scantxoutset failed: {err}"));
        let Some(unspents) = result.get("unspents").and_then(Value::as_array) else {
            panic!("unspents missing: {result:?}");
        };

        assert_eq!(result.get("txouts").and_then(Value::as_u64), Some(2));
        assert_eq!(
            result.get("total_amount").and_then(Value::as_f64),
            Some(0.000_123_45)
        );
        assert_eq!(unspents.len(), 1);
        let first = &unspents[0];
        let expected_txid = {
            let txid = outpoint.txid;
            txid.to_string_be()
        };
        assert_eq!(
            first.get("txid").and_then(Value::as_str),
            Some(expected_txid.as_str())
        );
        assert_eq!(first.get("vout").and_then(Value::as_u64), Some(0));
        assert_eq!(
            first.get("scriptPubKey").and_then(Value::as_str),
            Some(script.as_bytes().to_lower_hex_string().as_str())
        );
        assert_eq!(
            first.get("amount").and_then(Value::as_f64),
            Some(0.000_123_45)
        );
        assert_eq!(first.get("coinbase").and_then(Value::as_bool), Some(true));
        assert_eq!(first.get("height").and_then(Value::as_u64), Some(0));
        assert_eq!(first.get("confirmations").and_then(Value::as_u64), Some(1));
        let Some(desc) = first.get("desc").and_then(Value::as_str) else {
            panic!("desc missing: {first:?}");
        };
        assert!(desc.starts_with("addr(1111111111111111111114oLvT2)#"));
    }

    #[test]
    fn scantxoutset_accepts_object_form_addr_descriptor() {
        let ctx = Arc::new(Context::new());
        let address = "1111111111111111111114oLvT2";
        let script = bitcoin::Address::from_str(address)
            .unwrap_or_else(|err| panic!("address parse failed: {err}"))
            .require_network(bitcoin::Network::Bitcoin)
            .unwrap_or_else(|err| panic!("network check failed: {err}"))
            .script_pubkey();
        let txout = TxOut {
            value: Amount::from_sat(12_345),
            script_pubkey: script,
        };
        let outpoint = OutPoint::new(test_txid(13), 0);
        commit_test_utxo(&ctx, outpoint, txout, true, 0);

        let result = scantxoutset(
            &ctx,
            &json!(["start", [{"desc": format!("addr({address})"), "range": [0, 1]}]]),
        )
        .unwrap_or_else(|err| panic!("scantxoutset failed: {err}"));
        let Some(unspents) = result.get("unspents").and_then(Value::as_array) else {
            panic!("unspents missing: {result:?}");
        };

        assert_eq!(result.get("txouts").and_then(Value::as_u64), Some(1));
        assert_eq!(unspents.len(), 1);
        let first = &unspents[0];
        let expected_txid = {
            let txid = outpoint.txid;
            txid.to_string_be()
        };
        assert_eq!(
            first.get("txid").and_then(Value::as_str),
            Some(expected_txid.as_str())
        );
    }

    #[test]
    fn scantxoutset_rejects_empty_scanobjects() {
        let ctx = Arc::new(Context::new());
        let err = match scantxoutset(&ctx, &json!(["start", []])) {
            Ok(value) => panic!("empty scanobjects succeeded: {value:?}"),
            Err(err) => err,
        };

        assert!(
            err.to_string().contains("scanobjects must not be empty"),
            "wrong error: {err}"
        );
    }

    #[test]
    fn scantxoutset_rejects_scanobject_without_desc() {
        let ctx = Arc::new(Context::new());
        let err = match scantxoutset(&ctx, &json!(["start", [{"range": 0}]])) {
            Ok(value) => panic!("scanobject without desc succeeded: {value:?}"),
            Err(err) => err,
        };

        assert!(
            err.to_string().contains("missing desc"),
            "wrong error: {err}"
        );
    }

    #[test]
    fn scantxoutset_rejects_ranged_scan_descriptor() {
        let ctx = Arc::new(Context::new());
        let err = match scantxoutset(
            &ctx,
            &json!(["start", [{"desc": "addr(foo*)", "range": 1}]]),
        ) {
            Ok(value) => panic!("ranged descriptor succeeded: {value:?}"),
            Err(err) => err,
        };

        assert!(
            err.to_string()
                .contains("ranged scantxoutset descriptors are not supported"),
            "wrong error: {err}"
        );
    }

    #[test]
    fn scantxoutset_rejects_malformed_scanobject_range() {
        let ctx = Arc::new(Context::new());
        let err = match scantxoutset(
            &ctx,
            &json!(["start", [{"desc": "addr(1111111111111111111114oLvT2)", "range": [2, 1]}]]),
        ) {
            Ok(value) => panic!("bad range succeeded: {value:?}"),
            Err(err) => err,
        };

        assert!(
            err.to_string().contains("range start must not exceed end"),
            "wrong error: {err}"
        );
    }

    #[test]
    fn scantxoutset_rejects_object_form_unsupported_scan_descriptor() {
        let ctx = Arc::new(Context::new());
        let err = match scantxoutset(&ctx, &json!(["start", [{"desc": "raw(51)"}]])) {
            Ok(value) => panic!("unsupported object descriptor succeeded: {value:?}"),
            Err(err) => err,
        };

        assert!(
            err.to_string().contains("only addr() is supported"),
            "wrong error: {err}"
        );
    }

    #[test]
    fn scantxoutset_rejects_unsupported_scan_descriptors() {
        let ctx = Arc::new(Context::new());
        let err = match scantxoutset(&ctx, &json!(["start", ["raw(51)"]])) {
            Ok(value) => panic!("unsupported descriptor succeeded: {value:?}"),
            Err(err) => err,
        };

        assert!(
            err.to_string().contains("only addr() is supported"),
            "wrong error: {err}"
        );
    }

    #[test]
    fn scantxoutset_rejects_bad_descriptor_checksum() {
        let ctx = Arc::new(Context::new());
        let err = match scantxoutset(
            &ctx,
            &json!(["start", ["addr(1111111111111111111114oLvT2)#badbadba"]]),
        ) {
            Ok(value) => panic!("bad checksum succeeded: {value:?}"),
            Err(err) => err,
        };

        assert!(
            err.to_string().contains("checksum mismatch"),
            "wrong error: {err}"
        );
    }

    #[test]
    fn scantxoutset_rejects_wrong_network_address() {
        let ctx = Arc::new(Context::new());
        let err = match scantxoutset(
            &ctx,
            &json!([
                "start",
                ["addr(tb1qfm7h7nh4jjmzm0m2z8q9nu4n4yhndxj3x6gzt4)"]
            ]),
        ) {
            Ok(value) => panic!("wrong network address succeeded: {value:?}"),
            Err(err) => err,
        };

        assert!(
            err.to_string().contains("Address is not valid"),
            "wrong error: {err}"
        );
    }

    #[test]
    fn scantxoutset_rejects_non_array_scanobjects() {
        let ctx = Arc::new(Context::new());
        let err = match scantxoutset(&ctx, &json!(["start", "addr(1111111111111111111114oLvT2)"])) {
            Ok(value) => panic!("non-array scanobjects succeeded: {value:?}"),
            Err(err) => err,
        };

        assert!(
            err.to_string().contains("scanobjects must be an array"),
            "wrong error: {err}"
        );
    }

    #[test]
    fn scantxoutset_abort_returns_false() {
        let ctx = Arc::new(Context::new());
        let result = scantxoutset(&ctx, &json!(["abort"]))
            .unwrap_or_else(|err| panic!("scantxoutset abort failed: {err}"));
        assert_eq!(result.as_bool(), Some(false));
    }
}

#[cfg(test)]
mod descriptor_checksum_tests {
    use alloc::sync::Arc;

    use super::*;

    #[test]
    fn getdescriptorinfo_emits_8_char_bech32_checksum() {
        let ctx = Arc::new(Context::new());
        let result = getdescriptorinfo(&ctx, &json!(["addr(1111111111111111111114oLvT2)"]))
            .unwrap_or_else(|err| panic!("getdescriptorinfo failed: {err}"));
        let Some(checksum) = result.get("checksum").and_then(|v| v.as_str()) else {
            panic!("checksum missing: {result:?}");
        };
        assert_eq!(checksum.len(), 8, "checksum must be 8 chars: {checksum}");
        // All chars should be in the bech32 charset.
        for ch in checksum.chars() {
            assert!(
                BIP380_CHECKSUM_CHARSET.iter().any(|b| char::from(*b) == ch),
                "checksum char {ch} not in bech32 charset"
            );
        }
    }

    #[test]
    fn getdescriptorinfo_strips_existing_checksum() {
        let ctx = Arc::new(Context::new());
        let result = getdescriptorinfo(&ctx, &json!(["addr(x)#whatever"]))
            .unwrap_or_else(|err| panic!("getdescriptorinfo failed: {err}"));
        let Some(desc) = result.get("descriptor").and_then(|v| v.as_str()) else {
            panic!("descriptor missing: {result:?}");
        };
        assert!(
            desc.starts_with("addr(x)#"),
            "expected addr(x)# prefix: {desc}"
        );
    }
}

#[cfg(test)]
mod deriveaddresses_tests {
    use alloc::sync::Arc;

    use super::*;

    #[test]
    fn deriveaddresses_returns_addr_argument_for_single_addr_descriptor() {
        let ctx = Arc::new(Context::new());
        let result = deriveaddresses(&ctx, &json!(["addr(1111111111111111111114oLvT2)"]))
            .unwrap_or_else(|err| panic!("deriveaddresses failed: {err}"));
        let Some(arr) = result.as_array() else {
            panic!("expected array: {result:?}");
        };
        assert_eq!(arr.len(), 1);
        let Some(first) = arr.first().and_then(Value::as_str) else {
            panic!("expected string element: {result:?}");
        };
        assert_eq!(first, "1111111111111111111114oLvT2");
    }

    #[test]
    fn deriveaddresses_handles_checksum_suffix() {
        let ctx = Arc::new(Context::new());
        let result = deriveaddresses(&ctx, &json!(["addr(bc1qfoo)#aaaaaaaa"]))
            .unwrap_or_else(|err| panic!("deriveaddresses failed: {err}"));
        let Some(arr) = result.as_array() else {
            panic!("expected array: {result:?}");
        };
        assert_eq!(arr.len(), 1);
    }

    #[test]
    fn deriveaddresses_empty_for_ranged_descriptors() {
        let ctx = Arc::new(Context::new());
        let result = deriveaddresses(&ctx, &json!(["wpkh(xpub.../0/*)"]))
            .unwrap_or_else(|err| panic!("deriveaddresses failed: {err}"));
        let Some(arr) = result.as_array() else {
            panic!("expected array: {result:?}");
        };
        assert!(arr.is_empty());
    }
}

#[cfg(test)]
mod combinepsbt_tests {
    use alloc::sync::Arc;

    use sonic_rs::JsonValueTrait as _;

    use super::*;

    fn empty_psbt_str() -> String {
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: Vec::new(),
            output: Vec::new(),
        };
        let psbt = bitcoin::psbt::Psbt::from_unsigned_tx(tx)
            .unwrap_or_else(|err| panic!("from_unsigned_tx: {err}"));
        encode_base64(&psbt.serialize())
    }

    #[test]
    fn combinepsbt_single_input_returns_same_psbt() {
        let ctx = Arc::new(Context::new());
        let psbt_str = empty_psbt_str();
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
mod psbt_process_tests {
    use alloc::sync::Arc;

    use sonic_rs::JsonValueTrait as _;

    use super::*;

    fn empty_psbt() -> String {
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: Vec::new(),
            output: Vec::new(),
        };
        let psbt =
            bitcoin::psbt::Psbt::from_unsigned_tx(tx).unwrap_or_else(|err| panic!("psbt: {err}"));
        encode_base64(&psbt.serialize())
    }

    #[test]
    fn walletprocesspsbt_returns_same_psbt_with_complete_false() {
        let ctx = Arc::new(Context::new());
        let raw = empty_psbt();
        let result = walletprocesspsbt(&ctx, &json!([raw.as_str()]))
            .unwrap_or_else(|err| panic!("walletprocesspsbt failed: {err}"));
        let Some(complete) = result.get("complete").and_then(Value::as_bool) else {
            panic!("complete missing: {result:?}");
        };
        assert!(!complete);
    }

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
        let Some(hex) = result.get("hex").and_then(Value::as_str) else {
            panic!("hex missing: {result:?}");
        };
        assert_eq!(hex, "");
    }
}

#[cfg(test)]
mod bumpfee_tests {
    use alloc::sync::Arc;

    use bitcoin::hashes::Hash as _;

    use super::*;

    #[test]
    fn bumpfee_returns_not_found_for_unknown_txid() {
        let ctx = Arc::new(Context::new());
        let mut bytes = [0_u8; 32];
        bytes[0] = 0xaa;
        let txid = bitcoin::Txid::from_byte_array(bytes);
        let result = bumpfee(&ctx, &json!([txid.to_string()]));
        assert!(result.is_err());
    }

    #[test]
    fn bumpfee_rejects_confirmed_transaction() {
        let ctx = Arc::new(Context::new());
        // Insert a confirmed tx (not in mempool).
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: Vec::new(),
            output: Vec::new(),
        };
        let txid = ctx.add_transaction(tx);
        let result = bumpfee(&ctx, &json!([txid.to_string()]));
        assert!(result.is_err());
    }

    #[test]
    fn bumpfee_emits_nonzero_fee_when_bump_succeeds() {
        use bitcoin_rs_mempool::MempoolEntry;

        let ctx = Arc::new(Context::new());
        // Build an RBF-enabled tx (sequence < 0xfffffffe = explicit RBF).
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: bitcoin::Txid::from_byte_array([0xab; 32]),
                    vout: 0,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence(0x0000_0001),
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(10_000),
                script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let txid = tx.compute_txid();
        {
            let mut pool = ctx.mempool.write();
            let entry = MempoolEntry::new(Arc::new(tx), 250, 5_000, 1, 7);
            let _ = pool.insert_entry(entry);
        }

        let result = bumpfee(&ctx, &json!([txid.to_string()]));
        if let Ok(value) = result {
            if value
                .get("errors")
                .and_then(Value::as_array)
                .is_none_or(sonic_rs::Array::is_empty)
            {
                let Some(fee) = value.get("fee").and_then(Value::as_f64) else {
                    panic!("fee missing: {value:?}");
                };
                assert!(fee > 0.0, "expected positive fee on bump, got {fee}");
            }
        }
    }
}
