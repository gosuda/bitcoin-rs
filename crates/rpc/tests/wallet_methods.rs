#![allow(clippy::expect_used, clippy::unwrap_used)]
//! Focused coverage for watch-only wallet RPC methods.
extern crate alloc;

use alloc::sync::Arc;

use bitcoin_rs_rpc::context::Context;
use bitcoin_rs_rpc::{Handler, RpcError};
use bitcoin_rs_wallet::Watcher;
use parking_lot::RwLock;
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, json};

fn handler_with_wallet() -> Handler {
    let ctx = Context::new().with_wallet(Arc::new(RwLock::new(Watcher::new(Vec::new()))));
    Handler::new(Arc::new(ctx))
}

#[test]
fn registered_descriptor_methods_accept_addr_descriptors() -> Result<(), Box<dyn std::error::Error>>
{
    let handler = Handler::new(Arc::new(Context::new()));
    let info = handler.dispatch(
        "getdescriptorinfo",
        &json!(["addr(1111111111111111111114oLvT2)"]),
    )?;
    assert_eq!(
        info.get("hasprivatekeys")
            .and_then(sonic_rs::JsonValueTrait::as_bool),
        Some(false)
    );
    assert_eq!(
        info.get("checksum").and_then(|v| v.as_str()).map(str::len),
        Some(8)
    );

    let derived = handler.dispatch(
        "deriveaddresses",
        &json!(["addr(1111111111111111111114oLvT2)"]),
    )?;
    assert_eq!(derived.as_array().map(sonic_rs::Array::len), Some(1));
    Ok(())
}

#[test]
fn registered_descriptor_checksum_failure_is_invalid_params() {
    let handler = Handler::new(Arc::new(Context::new()));
    let err = handler
        .dispatch(
            "getdescriptorinfo",
            &json!(["addr(1111111111111111111114oLvT2)#00000000"]),
        )
        .expect_err("bad checksum");
    assert!(matches!(
        err,
        RpcError::InvalidParams(_) | RpcError::InvalidParameter(_)
    ));
}

#[test]
fn custody_methods_are_not_registered_as_custom_handlers() {
    // I1 removes the temporary method_disabled arms so these resolve as
    // generic method-not-found. Accept either shape until that lands.
    let handler = handler_with_wallet();
    for method in [
        "dumpprivkey",
        "importprivkey",
        "dumpwallet",
        "importwallet",
        "walletpassphrase",
        "encryptwallet",
        "signrawtransactionwithwallet",
    ] {
        let err = handler.dispatch(method, &json!([])).expect_err(method);
        assert!(
            matches!(
                err,
                RpcError::MethodNotFound(_) | RpcError::MethodDisabled(_)
            ),
            "{method} returned {err:?}"
        );
        if let RpcError::MethodDisabled(message) = err {
            assert!(
                !message.contains("not implemented"),
                "no bespoke custody implementation leak"
            );
        }
    }
}

#[test]
fn walletcreatefundedpsbt_and_process_round_trip_empty_psbt()
-> Result<(), Box<dyn std::error::Error>> {
    let handler = Handler::new(Arc::new(Context::new()));
    let created = handler.dispatch("walletcreatefundedpsbt", &json!([[], []]))?;
    assert!(created.get("psbt").and_then(|v| v.as_str()).is_some());
    assert_eq!(
        created
            .get("changepos")
            .and_then(sonic_rs::JsonValueTrait::as_i64),
        Some(-1)
    );

    let psbt = created
        .get("psbt")
        .and_then(|v| v.as_str())
        .ok_or("missing psbt")?;
    let processed = handler.dispatch("walletprocesspsbt", &json!([psbt]))?;
    assert_eq!(
        processed
            .get("complete")
            .and_then(sonic_rs::JsonValueTrait::as_bool),
        Some(false)
    );
    Ok(())
}

#[test]
fn deriveaddresses_requires_range_for_ranged_xpub() {
    let handler = Handler::new(Arc::new(Context::new()));
    let key = bitcoin::PrivateKey {
        compressed: true,
        network: bitcoin::NetworkKind::Main,
        inner: bitcoin::secp256k1::SecretKey::from_slice(&[5_u8; 32]).expect("secret"),
    };
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let xpriv =
        bitcoin::bip32::Xpriv::new_master(bitcoin::Network::Bitcoin, &key.inner.secret_bytes())
            .expect("xpriv");
    let xpub = bitcoin::bip32::Xpub::from_priv(&secp, &xpriv);
    let err = handler
        .dispatch("deriveaddresses", &json!([format!("wpkh({xpub}/0/*)")]))
        .expect_err("ranged descriptor requires range");
    assert!(matches!(
        err,
        RpcError::InvalidParameter(_) | RpcError::InvalidParams(_)
    ));
}

#[test]
fn importdescriptors_returns_nested_error_objects() {
    let handler = handler_with_wallet();
    let result = handler
        .dispatch("importdescriptors", &json!([[{ "timestamp": "now" }]]))
        .expect("method succeeds with per-entry errors");
    let first = result
        .as_array()
        .and_then(|array| array.first())
        .expect("result entry");
    assert_eq!(
        first
            .get("success")
            .and_then(sonic_rs::JsonValueTrait::as_bool),
        Some(false)
    );
    let error = first.get("error").expect("nested error");
    assert!(
        error
            .get("code")
            .and_then(sonic_rs::JsonValueTrait::as_i64)
            .is_some()
    );
    assert!(error.get("message").and_then(|v| v.as_str()).is_some());
    assert!(first.get("code").is_none());
}

fn encode_base64(bytes: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(char::from(TABLE[usize::from(b0 >> 2)]));
        out.push(char::from(
            TABLE[usize::from(((b0 & 0x03) << 4) | (b1 >> 4))],
        ));
        out.push(if chunk.len() > 1 {
            char::from(TABLE[usize::from(((b1 & 0x0f) << 2) | (b2 >> 6))])
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            char::from(TABLE[usize::from(b2 & 0x3f)])
        } else {
            '='
        });
    }
    out
}

fn p2pkh_spend_fixture() -> Result<
    (
        bitcoin::PrivateKey,
        bitcoin::Transaction,
        bitcoin::psbt::Psbt,
        bitcoin::TxOut,
    ),
    Box<dyn std::error::Error>,
> {
    use bitcoin::{
        Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    };

    let key = bitcoin::PrivateKey {
        compressed: true,
        network: bitcoin::NetworkKind::Main,
        inner: bitcoin::secp256k1::SecretKey::from_slice(&[9_u8; 32])?,
    };
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let public = bitcoin::PublicKey::from_private_key(&secp, &key);
    let descriptor = bitcoin_rs_wallet::Descriptor::parse(&format!("pkh({public})"))?;
    let prev_txout = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: descriptor.script_pubkey()?,
    };
    let funding = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![prev_txout.clone()],
    };
    let outpoint = OutPoint {
        txid: funding.compute_txid(),
        vout: 0,
    };
    let mut builder = bitcoin_rs_wallet::PsbtBuilder::new(core::slice::from_ref(&descriptor));
    builder.add_input(
        bitcoin_rs_wallet::PrevUtxo::new(outpoint, prev_txout.clone()),
        0,
        0,
    )?;
    builder.add_output(
        descriptor.derive_address(Network::Regtest, 1)?,
        Amount::from_sat(40_000),
    )?;
    let unsigned = builder.finalize()?;
    let spend_tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: unsigned.unsigned_tx.output.clone(),
    };
    Ok((key, spend_tx, unsigned, prev_txout))
}

#[test]
fn walletprocesspsbt_rejects_unsafe_legacy_prevout() -> Result<(), Box<dyn std::error::Error>> {
    let handler = Handler::new(Arc::new(Context::new()));
    let (key, _spend_tx, mut unsigned, _prev) = p2pkh_spend_fixture()?;
    unsigned.version = 0;
    assert!(unsigned.inputs[0].witness_utxo.is_some());
    assert!(unsigned.inputs[0].non_witness_utxo.is_none());
    let psbt = encode_base64(&unsigned.serialize());
    let err = handler
        .dispatch(
            "walletprocesspsbt",
            &json!([psbt.as_str(), true, { "keys": [key.to_wif()] }]),
        )
        .expect_err("legacy witness-only PSBT must be rejected");
    assert!(
        matches!(err, RpcError::Internal(ref message) if message.contains("non-witness UTXO")),
        "unexpected error: {err:?}"
    );
    Ok(())
}

#[test]
fn signrawtransactionwithkey_signs_explicit_legacy_prevtxs()
-> Result<(), Box<dyn std::error::Error>> {
    use bitcoin::consensus::encode::serialize;
    use bitcoin::hex::DisplayHex as _;

    let handler = Handler::new(Arc::new(Context::new()));
    let (key, spend_tx, _unsigned, prev_txout) = p2pkh_spend_fixture()?;
    let hex = serialize(&spend_tx).to_lower_hex_string();
    let signed = handler.dispatch(
        "signrawtransactionwithkey",
        &json!([
            hex.as_str(),
            [key.to_wif()],
            [{
                "txid": spend_tx.input[0].previous_output.txid.to_string(),
                "vout": 0,
                "scriptPubKey": prev_txout.script_pubkey.as_bytes().to_lower_hex_string(),
                "amount": prev_txout.value.to_btc()
            }]
        ]),
    )?;
    assert_eq!(
        signed
            .get("complete")
            .and_then(sonic_rs::JsonValueTrait::as_bool),
        Some(true)
    );
    assert!(
        signed
            .get("hex")
            .and_then(|v| v.as_str())
            .is_some_and(|hex| !hex.is_empty())
    );
    Ok(())
}

struct FileStore {
    path: std::path::PathBuf,
}

impl bitcoin_rs_rpc::context::WalletPersistence for FileStore {
    fn persist(&self, watcher: &Watcher) -> Result<(), compact_str::CompactString> {
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
        inner: bitcoin::secp256k1::SecretKey::from_slice(&[byte; 32]).expect("secret"),
    };
    let public =
        bitcoin::PublicKey::from_private_key(&bitcoin::secp256k1::Secp256k1::new(), &signer_key);
    format!("wpkh({public})")
}

#[test]
fn importdescriptors_returns_only_after_scan_and_persist() -> Result<(), Box<dyn std::error::Error>>
{
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("watch_only.json");
    let ctx = Context::new()
        .with_wallet(Arc::new(RwLock::new(Watcher::new(Vec::new()))))
        .with_wallet_persistence(Arc::new(FileStore { path: path.clone() }));
    let handler = Handler::new(Arc::new(ctx));
    let desc = wpkh_desc(21);
    let result = handler.dispatch(
        "importdescriptors",
        &json!([[{ "desc": desc, "timestamp": "now" }]]),
    )?;
    let first = result
        .as_array()
        .and_then(|array| array.first())
        .expect("result entry");
    assert_eq!(
        first
            .get("success")
            .and_then(sonic_rs::JsonValueTrait::as_bool),
        Some(true)
    );
    let bytes = std::fs::read(&path)?;
    let stored = String::from_utf8(bytes)?;
    assert!(
        stored.contains("wpkh("),
        "response must wait until state is on disk"
    );
    Ok(())
}

#[test]
fn importdescriptors_two_concurrent_imports_both_survive_reload()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("watch_only.json");
    let ctx = Context::new()
        .with_wallet(Arc::new(RwLock::new(Watcher::new(Vec::new()))))
        .with_wallet_persistence(Arc::new(FileStore { path: path.clone() }));
    let handler = Handler::new(Arc::new(ctx));
    let left = wpkh_desc(22);
    let right = wpkh_desc(23);
    std::thread::scope(|scope| {
        let handler = &handler;
        let left = &left;
        let right = &right;
        scope.spawn(move || {
            handler
                .dispatch(
                    "importdescriptors",
                    &json!([[{ "desc": left.clone(), "timestamp": "now" }]]),
                )
                .expect("left import");
        });
        scope.spawn(move || {
            handler
                .dispatch(
                    "importdescriptors",
                    &json!([[{ "desc": right.clone(), "timestamp": "now" }]]),
                )
                .expect("right import");
        });
    });
    let live = handler
        .context()
        .wallet
        .as_ref()
        .expect("wallet")
        .read()
        .imports
        .len();
    assert_eq!(live, 2);
    let reloaded = Watcher::decode_state(&std::fs::read(&path)?)?;
    assert_eq!(reloaded.imports.len(), 2);
    Ok(())
}
