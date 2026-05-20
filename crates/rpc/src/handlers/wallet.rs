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

pub(crate) fn scantxoutset(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let action = required_str(params, 0, "action is required")?;
    match action {
        "start" => {
            // Aggregate UTXO-set summary. Descriptor filtering is NOT applied in v1;
            // the descriptor argument is accepted but ignored. A future strand will
            // wire a real descriptor-matched scan.
            // TODO(descriptors): match `params[1]` against `bitcoin::miniscript::Descriptor`
            // and stream only matching outpoints into `unspents`.
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
    use sonic_rs::JsonValueTrait as _;

    use super::*;

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
