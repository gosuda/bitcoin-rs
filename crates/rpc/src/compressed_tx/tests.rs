//! Codec tests: published BIP337 vectors (fixture context derived from
//! real mainnet block bodies), signed round-trips per spend type, and
//! malformed/context failure modes.
//!
//! The fixture at `crates/rpc/tests/bip337_vectors.json` was derived
//! once from the published vectors plus mempool.space mainnet block
//! bodies at heights 833265..833280 by a throwaway generator; no context
//! field was written by hand. The ignored `mainnet_bodies_truth` test
//! re-derives every field from the bodies themselves.

#![expect(
    clippy::unwrap_used,
    reason = "test assertions fail with the checked value in the message"
)]

use std::collections::HashMap;
use std::str::FromStr as _;

use bitcoin::hex::FromHex as _;
use bitcoin::secp256k1::{Keypair, Message, PublicKey, Secp256k1, SecretKey};
use bitcoin_rs_primitives::{
    Amount, Hash256, LockTime, OutPoint, Script, Sequence, Sighash, SighashCache, Tx, TxIn, TxOut,
    Txid, Witness, consensus_bytes, deserialize, layout::ParsedBlock,
};
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, Value};

use super::{
    CodecError, CompressOptions, LookupError, ResolvedPrevout, compress_transaction,
    decompress_transaction, encode_bits, write_varint,
};
use crate::compressed_tx::PrevoutResolver;

const FIXTURE: &str = include_str!("../../tests/bip337_vectors.json");

#[derive(Default)]
struct MapResolver {
    prevouts: HashMap<OutPoint, ResolvedPrevout>,
    flats: HashMap<(u32, Txid, u32), u32>,
    at: HashMap<(u32, u32), (OutPoint, ResolvedPrevout)>,
    cancelled: bool,
}

impl MapResolver {
    fn register(&mut self, height: u32, txid: Txid, vout: u32, first_flat: u32, txout: TxOut) {
        let outpoint = OutPoint::new(txid, vout);
        let resolved = ResolvedPrevout {
            txout,
            confirmed_height: Some(height),
        };
        self.prevouts.insert(outpoint, resolved.clone());
        self.flats.insert((height, txid, vout), first_flat + vout);
        self.at
            .insert((height, first_flat + vout), (outpoint, resolved));
    }

    /// Registers every output of `tx` as confirmed at `height`, with
    /// `first_flat` outputs preceding it in the block.
    fn register_tx(&mut self, height: u32, tx: &Tx, first_flat: u32) {
        for (vout, output) in tx.outputs.iter().enumerate() {
            let vout = u32::try_from(vout).unwrap();
            self.register(height, tx.txid(), vout, first_flat, output.clone());
        }
    }
}

impl PrevoutResolver for MapResolver {
    fn prevout(&mut self, outpoint: &OutPoint) -> Result<Option<ResolvedPrevout>, LookupError> {
        Ok(self.prevouts.get(outpoint).cloned())
    }

    fn flat_output_index(
        &mut self,
        height: u32,
        txid: &Txid,
        vout: u32,
    ) -> Result<Option<u32>, LookupError> {
        Ok(self.flats.get(&(height, *txid, vout)).copied())
    }

    fn outpoint_at(
        &mut self,
        height: u32,
        flat_index: u32,
    ) -> Result<Option<(OutPoint, ResolvedPrevout)>, LookupError> {
        Ok(self.at.get(&(height, flat_index)).cloned())
    }

    fn cancelled(&self) -> bool {
        self.cancelled
    }
}

fn hex_bytes(text: &str) -> Vec<u8> {
    Vec::<u8>::from_hex(text).unwrap()
}

fn fixture_vectors() -> Vec<Value> {
    let parsed: Value = sonic_rs::from_str(FIXTURE).unwrap();
    parsed
        .get("vectors")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .cloned()
        .collect()
}

fn fixture_resolver(vector: &Value) -> MapResolver {
    let mut resolver = MapResolver::default();
    for input in vector.get("inputs").and_then(Value::as_array).unwrap() {
        let txid =
            Txid::from_str(input.get("prevout_txid").and_then(Value::as_str).unwrap()).unwrap();
        let vout = u32::try_from(input.get("vout").and_then(Value::as_u64).unwrap()).unwrap();
        let height = u32::try_from(input.get("height").and_then(Value::as_u64).unwrap()).unwrap();
        let flat = u32::try_from(
            input
                .get("flat_output_index")
                .and_then(Value::as_u64)
                .unwrap(),
        )
        .unwrap();
        let txout = TxOut {
            value: Amount::from_sat(input.get("value_sats").and_then(Value::as_u64).unwrap()),
            script_pubkey: Script::from_bytes(hex_bytes(
                input
                    .get("prevout_script_hex")
                    .and_then(Value::as_str)
                    .unwrap(),
            )),
        };
        resolver.register(height, txid, vout, flat - vout, txout);
    }
    resolver
}

#[test]
fn varint_uses_core_carry_form() {
    let mut encoded = Vec::new();
    write_varint(5000, &mut encoded).unwrap();
    assert_eq!(encoded, [0xa6, 0x08]);
    let mut reader = super::Reader::new(&encoded);
    assert_eq!(super::Reader::read_varint(&mut reader).unwrap(), 5000);
    for value in [
        0_u64,
        1,
        127,
        128,
        16_511,
        4_294_967_293,
        1_u64 << 40,
        2_100_000_000_000_000,
        u64::MAX,
    ] {
        let mut encoded = Vec::new();
        write_varint(value, &mut encoded).unwrap();
        let mut reader = super::Reader::new(&encoded);
        assert_eq!(reader.read_varint().unwrap(), value);
    }
    // Ten bytes carry every `u64`: the largest amount keeps a spelling.
    let mut encoded = Vec::new();
    write_varint(u64::MAX, &mut encoded).unwrap();
    assert_eq!(encoded.len(), 10);
    let mut reader = super::Reader::new(&encoded);
    assert_eq!(reader.read_varint().unwrap(), u64::MAX);
    // Six bytes carry past `u32`: still a valid `u64` spelling.
    let mut encoded = Vec::new();
    write_varint(1_u64 << 40, &mut encoded).unwrap();
    assert_eq!(encoded.len(), 6);
    let mut reader = super::Reader::new(&encoded);
    assert_eq!(reader.read_varint().unwrap(), 1_u64 << 40);
    // `u32` fields keep their five-byte ceiling: a six-byte spelling is
    // out of range even when the value would fit.
    let mut reader = super::Reader::new(&encoded);
    assert_eq!(
        super::read_u32_varint(&mut reader),
        Err(CodecError::Overflow)
    );
    // Eleven continuation bytes never terminate within the ten-byte cap.
    let unterminated = [0x80; 11];
    let mut reader = super::Reader::new(&unterminated);
    assert_eq!(reader.read_varint(), Err(CodecError::Overflow));
}

#[test]
fn encode_bits_matches_published_example() {
    assert_eq!(encode_bits(&[37], &[5]), [0x96, 0x80]);
}

#[test]
fn handlers_gate_on_the_runtime_opt_in() {
    use std::sync::Arc;

    use sonic_rs::json;

    use crate::context::{Context, ContextHandles};
    use crate::handlers::Handler;

    let tx = funding_tx(TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: p2wpkh_script([1_u8; 20]),
    });
    let raw_hex = bitcoin::hex::DisplayHex::to_lower_hex_string(&consensus_bytes(&tx));

    let disabled = Handler::new(Arc::new(Context::new()));
    for method in ["compressrawtransaction", "decompressrawtransaction"] {
        let error = disabled.dispatch(method, &json!([raw_hex])).unwrap_err();
        assert!(
            matches!(error, crate::RpcError::MethodDisabled(_)),
            "{method}: {error:?}"
        );
        assert_eq!(error.code(), -32603, "{method} must never answer -32601");
    }

    let enabled = Handler::new(Arc::new(Context::from_handles(ContextHandles {
        compressed_transactions: true,
        ..ContextHandles::default()
    })));
    let compressed = enabled
        .dispatch("compressrawtransaction", &json!([raw_hex]))
        .unwrap();
    let compressed_hex = compressed
        .get("result")
        .and_then(Value::as_str)
        .unwrap()
        .to_owned();
    assert_eq!(
        compressed
            .get("warnings")
            .and_then(Value::as_array)
            .unwrap()
            .len(),
        1
    );
    let restored = enabled
        .dispatch("decompressrawtransaction", &json!([compressed_hex]))
        .unwrap();
    assert_eq!(restored.as_str().unwrap(), raw_hex);
    // Oversize hex is refused (-8) before any decoding happens.
    let oversize = "00".repeat(super::MAX_COMPRESSED_TX_BYTES + 1);
    let error = enabled
        .dispatch("compressrawtransaction", &json!([oversize]))
        .unwrap_err();
    assert_eq!(error.code(), -8);
}

#[test]
fn codec_error_wire_matrix() {
    use super::Limit;
    use crate::RpcError;

    for (error, code) in [
        (CodecError::Truncated, -22),
        (CodecError::NonCanonical, -22),
        (CodecError::EmptyTransaction, -22),
        (CodecError::UnsupportedScript, -22),
        (CodecError::Sighash, -22),
        (CodecError::SignatureUnrecoverable, -22),
        (CodecError::Overflow, -8),
        (CodecError::LimitExceeded(Limit::State), -1),
        (CodecError::Cancelled, -1),
        (
            CodecError::PrevoutMissing(OutPoint::new(Txid(Hash256::from_le_bytes(&[1_u8; 32])), 0)),
            -5,
        ),
        (CodecError::BodyMissing(7), -1),
        (CodecError::CorruptBody(7), -1),
        (CodecError::BodyReadFailed(7), -1),
    ] {
        assert_eq!(RpcError::from(error).code(), code);
    }
}

#[test]
fn registry_rows_are_extensions_at_package_version() {
    for name in ["compressrawtransaction", "decompressrawtransaction"] {
        let entry = crate::manifest::MANIFEST
            .iter()
            .find(|entry| entry.name == name)
            .unwrap();
        assert_eq!(entry.status, crate::manifest::Status::Extension);
        assert_eq!(entry.feature, "");
        assert_eq!(entry.core_version, "");
        assert_eq!(entry.since, bitcoin_rs_primitives::PKG_VERSION);
    }
}

#[test]
fn published_vectors_restore_byte_for_byte() {
    for vector in fixture_vectors() {
        let name = vector.get("name").and_then(Value::as_str).unwrap();
        let raw_hex = vector.get("raw_hex").and_then(Value::as_str).unwrap();
        let compressed_hex = vector
            .get("compressed_hex")
            .and_then(Value::as_str)
            .unwrap();
        let raw: Tx = deserialize(&hex_bytes(raw_hex)).unwrap();
        assert_eq!(
            raw.txid().to_string(),
            vector.get("txid").and_then(Value::as_str).unwrap(),
            "{name}"
        );
        assert_eq!(
            raw.wtxid().to_string(),
            vector.get("wtxid").and_then(Value::as_str).unwrap(),
            "{name}"
        );
        let mut resolver = fixture_resolver(&vector);
        let (compressed, warnings) = compress_transaction(
            &raw,
            &mut resolver,
            CompressOptions {
                compress_outpoints: true,
            },
        )
        .unwrap();
        assert!(warnings.is_empty(), "{name}: {warnings:?}");
        assert_eq!(
            compressed,
            hex_bytes(compressed_hex),
            "{name}: compressed bytes differ"
        );
        let mut resolver = fixture_resolver(&vector);
        let restored = decompress_transaction(&compressed, &mut resolver).unwrap();
        assert_eq!(restored, raw, "{name}: round trip differs");
        assert_eq!(consensus_bytes(&restored), hex_bytes(raw_hex), "{name}");
    }
}

/// Derives (prev transaction, spending transaction) signed test pairs.
struct Signer {
    secp: Secp256k1<bitcoin::secp256k1::All>,
    secret: SecretKey,
    public: PublicKey,
}

impl Signer {
    fn new(seed: u8) -> Self {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[seed; 32]).unwrap();
        let public = PublicKey::from_secret_key(&secp, &secret);
        Self {
            secp,
            secret,
            public,
        }
    }

    fn compressed_pubkey(&self) -> Vec<u8> {
        self.public.serialize().to_vec()
    }

    fn uncompressed_pubkey(&self) -> Vec<u8> {
        self.public.serialize_uncompressed().to_vec()
    }

    fn pubkey_hash(&self) -> [u8; 20] {
        super::hash160_20(&self.compressed_pubkey())
    }

    /// Signs `digest` as ECDSA; `high_s` flips `s` to `n - s`.
    fn ecdsa_item(&self, digest: Hash256, high_s: bool) -> Vec<u8> {
        let message = Message::from_digest(*digest.as_byte_array());
        let signature = self.secp.sign_ecdsa(&message, &self.secret);
        let mut compact = signature.serialize_compact();
        if high_s {
            // s := n - s over the secp256k1 group order.
            const ORDER: [u8; 32] = [
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
                0xd0, 0x36, 0x41, 0x41,
            ];
            let mut borrow = 0_i32;
            for index in (32..64).rev() {
                let diff = i32::from(ORDER[index - 32]) - i32::from(compact[index]) - borrow;
                if diff < 0 {
                    compact[index] = u8::try_from(diff + 256).unwrap();
                    borrow = 1;
                } else {
                    compact[index] = u8::try_from(diff).unwrap();
                    borrow = 0;
                }
            }
        }
        let parsed = bitcoin::secp256k1::ecdsa::Signature::from_compact(&compact).unwrap();
        let mut item = parsed.serialize_der().to_vec();
        item.push(1);
        item
    }
}

fn funding_tx(output: TxOut) -> Tx {
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: Script::from_bytes(vec![0x01, 0x2a]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![output],
        lock_time: LockTime::ZERO,
    }
}

fn spend_of(prevout: &Tx, script_sig: Script, witness: Witness) -> Tx {
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(prevout.txid(), 0),
            script_sig,
            sequence: Sequence::from_consensus(0xffff_fffd),
            witness,
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(40_000),
            script_pubkey: Script::from_bytes(
                vec![0x00, 0x14].into_iter().chain([7_u8; 20]).collect(),
            ),
        }],
        lock_time: LockTime::ZERO,
    }
}

fn p2pkh_script(hash: [u8; 20]) -> Script {
    let mut script = vec![0x76, 0xa9, 0x14];
    script.extend_from_slice(&hash);
    script.extend_from_slice(&[0x88, 0xac]);
    Script::from_bytes(script)
}

fn p2wpkh_script(hash: [u8; 20]) -> Script {
    let mut script = vec![0x00, 0x14];
    script.extend_from_slice(&hash);
    Script::from_bytes(script)
}

fn roundtrip(tx: &Tx, resolver: &mut MapResolver, compress_outpoints: bool) -> Vec<u8> {
    let (compressed, _) =
        compress_transaction(tx, resolver, CompressOptions { compress_outpoints }).unwrap();
    let restored = decompress_transaction(&compressed, resolver).unwrap();
    assert_eq!(&restored, tx);
    compressed
}

#[test]
fn roundtrip_legacy_p2pkh() {
    let signer = Signer::new(7);
    let prevout = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: p2pkh_script(signer.pubkey_hash()),
    };
    let prev_tx = funding_tx(prevout.clone());
    let mut tx = spend_of(&prev_tx, Script::new(), Witness::new());
    let digest = SighashCache::new(&tx)
        .legacy_signature_hash(0, prevout.script_pubkey.as_bytes(), 1)
        .unwrap();
    let sig_item = signer.ecdsa_item(digest, false);
    let mut script_sig = super::push_data(&sig_item);
    script_sig.extend_from_slice(&super::push_data(&signer.compressed_pubkey()));
    tx.inputs[0].script_sig = Script::from_bytes(script_sig);
    let mut resolver = MapResolver::default();
    resolver.register_tx(100, &prev_tx, 3);
    roundtrip(&tx, &mut resolver, true);
}

#[test]
fn roundtrip_legacy_p2pkh_uncompressed_key() {
    // The 65-byte `0x04` form round-trips through recovery exactly.
    let signer = Signer::new(7);
    let uncompressed = signer.uncompressed_pubkey();
    let prevout = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: p2pkh_script(super::hash160_20(&uncompressed)),
    };
    let prev_tx = funding_tx(prevout.clone());
    let mut tx = spend_of(&prev_tx, Script::new(), Witness::new());
    let digest = SighashCache::new(&tx)
        .legacy_signature_hash(0, prevout.script_pubkey.as_bytes(), 1)
        .unwrap();
    let sig_item = signer.ecdsa_item(digest, false);
    let mut script_sig = super::push_data(&sig_item);
    script_sig.extend_from_slice(&super::push_data(&uncompressed));
    tx.inputs[0].script_sig = Script::from_bytes(script_sig);
    let mut resolver = MapResolver::default();
    resolver.register_tx(100, &prev_tx, 3);
    roundtrip(&tx, &mut resolver, true);
}

#[test]
fn hybrid_p2pkh_key_falls_back_to_uncompressed_envelope() {
    // A hybrid (non-round-tripping) pubkey must not compress: recovery
    // could never reproduce it, so the input keeps its exact bytes.
    let signer = Signer::new(7);
    let mut hybrid = signer.uncompressed_pubkey();
    hybrid[0] = 0x06;
    let prevout = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: p2pkh_script(super::hash160_20(&hybrid)),
    };
    let prev_tx = funding_tx(prevout.clone());
    let mut tx = spend_of(&prev_tx, Script::new(), Witness::new());
    let digest = SighashCache::new(&tx)
        .legacy_signature_hash(0, prevout.script_pubkey.as_bytes(), 1)
        .unwrap();
    let sig_item = signer.ecdsa_item(digest, false);
    let mut script_sig = super::push_data(&sig_item);
    script_sig.extend_from_slice(&super::push_data(&hybrid));
    tx.inputs[0].script_sig = Script::from_bytes(script_sig);
    let mut resolver = MapResolver::default();
    resolver.register_tx(100, &prev_tx, 3);
    roundtrip(&tx, &mut resolver, true);
}

#[test]
fn foreign_p2pkh_key_falls_back_instead_of_changing_signer() {
    // A valid key that does not hash to the prevout commitment must not
    // compress: rebuilding from recovery would silently swap the signer.
    let signer = Signer::new(7);
    let stranger = Signer::new(19);
    let prevout = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: p2pkh_script(signer.pubkey_hash()),
    };
    let prev_tx = funding_tx(prevout.clone());
    let mut tx = spend_of(&prev_tx, Script::new(), Witness::new());
    let digest = SighashCache::new(&tx)
        .legacy_signature_hash(0, prevout.script_pubkey.as_bytes(), 1)
        .unwrap();
    let sig_item = signer.ecdsa_item(digest, false);
    let mut script_sig = super::push_data(&sig_item);
    script_sig.extend_from_slice(&super::push_data(&stranger.compressed_pubkey()));
    tx.inputs[0].script_sig = Script::from_bytes(script_sig);
    let mut resolver = MapResolver::default();
    resolver.register_tx(100, &prev_tx, 3);
    roundtrip(&tx, &mut resolver, true);
}

#[test]
fn lossy_input_shapes_fall_back_to_uncompressed_envelope() {
    // Each shape carries bytes the compressed rebuild cannot reproduce, so
    // the round trip must still restore the exact transaction.
    let signer = Signer::new(7);
    let stranger = Signer::new(19);

    // P2PKH spend that also carries a witness item.
    let prevout = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: p2pkh_script(signer.pubkey_hash()),
    };
    let prev_tx = funding_tx(prevout.clone());
    let mut tx = spend_of(&prev_tx, Script::new(), Witness::new());
    let digest = SighashCache::new(&tx)
        .legacy_signature_hash(0, prevout.script_pubkey.as_bytes(), 1)
        .unwrap();
    let sig_item = signer.ecdsa_item(digest, false);
    let mut script_sig = super::push_data(&sig_item);
    script_sig.extend_from_slice(&super::push_data(&signer.compressed_pubkey()));
    tx.inputs[0].script_sig = Script::from_bytes(script_sig);
    tx.inputs[0].witness = Witness::from_stack(vec![vec![0x2a]]);
    let mut resolver = MapResolver::default();
    resolver.register_tx(100, &prev_tx, 3);
    roundtrip(&tx, &mut resolver, true);

    // P2WPKH spend whose witness key does not hash to the prevout.
    let prevout = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: p2wpkh_script(signer.pubkey_hash()),
    };
    let prev_tx = funding_tx(prevout.clone());
    let mut tx = spend_of(&prev_tx, Script::new(), Witness::new());
    let digest = SighashCache::new(&tx)
        .segwit_v0_signature_hash_raw(
            0,
            p2pkh_script(signer.pubkey_hash()).as_bytes(),
            prevout.value,
            1,
        )
        .unwrap();
    let sig_item = signer.ecdsa_item(digest, false);
    tx.inputs[0].witness = Witness::from_stack(vec![sig_item, stranger.compressed_pubkey()]);
    let mut resolver = MapResolver::default();
    resolver.register_tx(100, &prev_tx, 0);
    roundtrip(&tx, &mut resolver, true);

    // P2TR key-path spend that also carries scriptSig bytes.
    let mut script = vec![0x51, 0x20];
    script.extend_from_slice(&[3_u8; 32]);
    let prev_tx = funding_tx(TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: Script::from_bytes(script),
    });
    let tx = spend_of(
        &prev_tx,
        Script::from_bytes(vec![0x01, 0x2a]),
        Witness::from_stack(vec![vec![4_u8; 64]]),
    );
    let mut resolver = MapResolver::default();
    resolver.register_tx(100, &prev_tx, 0);
    roundtrip(&tx, &mut resolver, true);
}

#[test]
fn nonminimal_p2pkh_pushes_fall_back_to_uncompressed_envelope() {
    // Non-minimal PUSHDATA spellings carry the same payloads but rebuild
    // to different bytes via `push_data` on decompress, so they must not
    // take the compressed path. They fall back to the uncompressed
    // envelope and survive the round trip byte-for-byte.
    fn pushdata1(data: &[u8]) -> Vec<u8> {
        let mut out = vec![0x4c, u8::try_from(data.len()).unwrap()];
        out.extend_from_slice(data);
        out
    }

    fn pushdata2(data: &[u8]) -> Vec<u8> {
        let len = u16::try_from(data.len()).unwrap().to_le_bytes();
        let mut out = vec![0x4d, len[0], len[1]];
        out.extend_from_slice(data);
        out
    }

    let signer = Signer::new(7);
    let prevout = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: p2pkh_script(signer.pubkey_hash()),
    };
    let prev_tx = funding_tx(prevout.clone());
    let mut canonical = spend_of(&prev_tx, Script::new(), Witness::new());
    let digest = SighashCache::new(&canonical)
        .legacy_signature_hash(0, prevout.script_pubkey.as_bytes(), 1)
        .unwrap();
    let sig_item = signer.ecdsa_item(digest, false);
    let pubkey = signer.compressed_pubkey();
    // Positive control: the canonical spelling still compresses.
    let mut script_sig = super::push_data(&sig_item);
    script_sig.extend_from_slice(&super::push_data(&pubkey));
    canonical.inputs[0].script_sig = Script::from_bytes(script_sig);
    let kind = super::prevout_kind(prevout.script_pubkey.as_bytes());
    assert!(
        super::compressed_signature(&canonical.inputs[0], &kind).is_some(),
        "canonical P2PKH pushes must take the compressed path"
    );
    let mut resolver = MapResolver::default();
    resolver.register_tx(100, &prev_tx, 3);
    roundtrip(&canonical, &mut resolver, true);

    // The legacy sighash does not commit to the scriptSig framing, so this
    // payload-identical `sig_item` stays valid across push spellings.
    for script_sig in [
        {
            let mut raw = pushdata1(&sig_item);
            raw.extend_from_slice(&pushdata1(&pubkey));
            raw
        },
        {
            let mut raw = pushdata2(&sig_item);
            raw.extend_from_slice(&pushdata2(&pubkey));
            raw
        },
        {
            let mut raw = pushdata1(&sig_item);
            raw.extend_from_slice(&super::push_data(&pubkey));
            raw
        },
    ] {
        let tx = spend_of(&prev_tx, Script::from_bytes(script_sig), Witness::new());
        let kind = super::prevout_kind(prevout.script_pubkey.as_bytes());
        assert!(
            super::compressed_signature(&tx.inputs[0], &kind).is_none(),
            "non-minimal P2PKH pushes must fall back to the uncompressed envelope"
        );
        let mut resolver = MapResolver::default();
        resolver.register_tx(100, &prev_tx, 3);
        roundtrip(&tx, &mut resolver, true);
    }
}

#[test]
fn decompress_prepare_finalize_matches_single_pass() {
    // The handler recovers outside the stable chainstate lock; the split
    // entry points must agree with the single-pass wrapper exactly.
    let signer = Signer::new(23);
    let prevout = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: p2pkh_script(signer.pubkey_hash()),
    };
    let prev_tx = funding_tx(prevout.clone());
    let mut tx = spend_of(&prev_tx, Script::new(), Witness::new());
    let digest = SighashCache::new(&tx)
        .legacy_signature_hash(0, prevout.script_pubkey.as_bytes(), 1)
        .unwrap();
    let sig_item = signer.ecdsa_item(digest, false);
    let mut script_sig = super::push_data(&sig_item);
    script_sig.extend_from_slice(&super::push_data(&signer.compressed_pubkey()));
    tx.inputs[0].script_sig = Script::from_bytes(script_sig);
    let mut resolver = MapResolver::default();
    resolver.register_tx(100, &prev_tx, 3);
    let (compressed, _) = compress_transaction(
        &tx,
        &mut resolver,
        CompressOptions {
            compress_outpoints: true,
        },
    )
    .unwrap();
    let plan = super::decompress_prepare(&compressed, &mut resolver).unwrap();
    let restored = super::decompress_finalize(plan, &resolver).unwrap();
    assert_eq!(&restored, &tx);
    assert_eq!(
        &super::decompress_transaction(&compressed, &mut resolver).unwrap(),
        &tx
    );
}

#[test]
fn roundtrip_p2wpkh_including_high_s() {
    for high_s in [false, true] {
        let signer = Signer::new(9);
        let prevout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: p2wpkh_script(signer.pubkey_hash()),
        };
        let prev_tx = funding_tx(prevout.clone());
        let mut tx = spend_of(&prev_tx, Script::new(), Witness::new());
        let digest = SighashCache::new(&tx)
            .segwit_v0_signature_hash_raw(
                0,
                p2pkh_script(signer.pubkey_hash()).as_bytes(),
                prevout.value,
                1,
            )
            .unwrap();
        let sig_item = signer.ecdsa_item(digest, high_s);
        tx.inputs[0].witness = Witness::from_stack(vec![sig_item, signer.compressed_pubkey()]);
        let mut resolver = MapResolver::default();
        resolver.register_tx(100, &prev_tx, 0);
        roundtrip(&tx, &mut resolver, true);
    }
}

#[test]
fn roundtrip_nested_segwit() {
    let signer = Signer::new(11);
    let mut redeem = vec![0x00, 0x14];
    redeem.extend_from_slice(&signer.pubkey_hash());
    let prevout = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: {
            let mut script = vec![0xa9, 0x14];
            script.extend_from_slice(&super::hash160_20(&redeem));
            script.push(0x87);
            Script::from_bytes(script)
        },
    };
    let prev_tx = funding_tx(prevout.clone());
    let mut tx = spend_of(
        &prev_tx,
        Script::from_bytes(super::push_data(&redeem)),
        Witness::new(),
    );
    let digest = SighashCache::new(&tx)
        .segwit_v0_signature_hash_raw(
            0,
            p2pkh_script(signer.pubkey_hash()).as_bytes(),
            prevout.value,
            1,
        )
        .unwrap();
    let sig_item = signer.ecdsa_item(digest, false);
    tx.inputs[0].witness = Witness::from_stack(vec![sig_item, signer.compressed_pubkey()]);
    let mut resolver = MapResolver::default();
    resolver.register_tx(100, &prev_tx, 5);
    roundtrip(&tx, &mut resolver, true);
}

#[test]
fn roundtrip_taproot_key_path() {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[13_u8; 32]).unwrap();
    let keypair = Keypair::from_secret_key(&secp, &secret);
    let (xonly, _parity) = keypair.x_only_public_key();
    let mut script = vec![0x51, 0x20];
    script.extend_from_slice(&xonly.serialize());
    let prevout = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: Script::from_bytes(script),
    };
    let prev_tx = funding_tx(prevout.clone());
    let mut tx = spend_of(&prev_tx, Script::new(), Witness::new());
    let digest = SighashCache::new(&tx)
        .taproot_signature_hash(0, &[prevout], None, None, Sighash::Default)
        .unwrap();
    let message = Message::from_digest(*digest.as_byte_array());
    let signature = secp.sign_schnorr(&message, &keypair);
    tx.inputs[0].witness = Witness::from_stack(vec![signature[..].to_vec()]);
    let mut resolver = MapResolver::default();
    resolver.register_tx(100, &prev_tx, 0);
    roundtrip(&tx, &mut resolver, true);
}

#[test]
fn roundtrip_taproot_script_path_uses_uncompressed_envelope() {
    let mut script = vec![0x51, 0x20];
    script.extend_from_slice(&[3_u8; 32]);
    let prevout = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: Script::from_bytes(script),
    };
    let prev_tx = funding_tx(prevout);
    let tx = spend_of(
        &prev_tx,
        Script::new(),
        Witness::from_stack(vec![vec![4_u8; 64], vec![0x51, 0x60], vec![5_u8; 33]]),
    );
    let mut resolver = MapResolver::default();
    resolver.register_tx(100, &prev_tx, 0);
    roundtrip(&tx, &mut resolver, true);
}

#[test]
fn taproot_nonempty_scriptsig_falls_back_to_uncompressed_envelope() {
    // Decompression rebuilds an empty scriptSig for P2TR, so a key-path
    // witness paired with a non-empty scriptSig must not take the
    // compressed path: it has no round trip. It falls back to the
    // uncompressed envelope and survives the round trip byte-for-byte.
    let mut script = vec![0x51, 0x20];
    script.extend_from_slice(&[9_u8; 32]);
    let prevout = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: Script::from_bytes(script),
    };
    let prev_tx = funding_tx(prevout.clone());
    let kind = super::prevout_kind(prevout.script_pubkey.as_bytes());
    // Positive control: the exact key-path shape still compresses.
    let canonical = spend_of(
        &prev_tx,
        Script::new(),
        Witness::from_stack(vec![vec![7_u8; 64]]),
    );
    assert!(
        super::compressed_signature(&canonical.inputs[0], &kind).is_some(),
        "empty-scriptSig key-path witness must take the compressed path"
    );
    let mut resolver = MapResolver::default();
    resolver.register_tx(100, &prev_tx, 0);
    roundtrip(&canonical, &mut resolver, true);

    // The same witness with a non-empty scriptSig falls back instead.
    let tx = spend_of(
        &prev_tx,
        Script::from_bytes(vec![0x51]),
        Witness::from_stack(vec![vec![7_u8; 64]]),
    );
    assert!(
        super::compressed_signature(&tx.inputs[0], &kind).is_none(),
        "P2TR input with a non-empty scriptSig must fall back to the uncompressed envelope"
    );
    let mut resolver = MapResolver::default();
    resolver.register_tx(100, &prev_tx, 0);
    roundtrip(&tx, &mut resolver, true);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one table of output shapes exercised in a single round trip"
)]
fn roundtrip_p2sh_multisig_and_output_shapes() {
    // P2SH multisig prevout: signature compression must not trigger.
    let signer = Signer::new(15);
    let prevout = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: {
            let mut script = vec![0xa9, 0x14];
            script.extend_from_slice(&[8_u8; 20]);
            script.push(0x87);
            Script::from_bytes(script)
        },
    };
    let prev_tx = funding_tx(prevout);
    let mut script_sig = vec![0x00];
    script_sig.extend_from_slice(&super::push_data(
        &signer.ecdsa_item(Hash256::default(), false),
    ));
    script_sig.extend_from_slice(&super::push_data(&[0x52, 0x21]));
    let tx = spend_of(&prev_tx, Script::from_bytes(script_sig), Witness::new());
    let mut resolver = MapResolver::default();
    resolver.register_tx(100, &prev_tx, 0);
    roundtrip(&tx, &mut resolver, true);

    // Every output shape, nonzero locktime, all sequence spellings.
    let mut multi = Tx {
        version: 3,
        inputs: vec![
            TxIn {
                previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[1_u8; 32])), 0),
                sequence: Sequence::from_consensus(0),
                ..TxIn::default()
            },
            TxIn {
                previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[2_u8; 32])), 1),
                sequence: Sequence::from_consensus(0xffff_fffe),
                ..TxIn::default()
            },
            TxIn {
                previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[3_u8; 32])), 2),
                sequence: Sequence::from_consensus(0xffff_ffff),
                ..TxIn::default()
            },
            TxIn {
                previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[4_u8; 32])), 3),
                sequence: Sequence::from_consensus(0x1234_5678),
                script_sig: Script::from_bytes(vec![0x51]),
                witness: Witness::from_stack(vec![vec![9_u8; 3]]),
            },
        ],
        outputs: vec![
            TxOut {
                value: Amount::from_sat(1),
                script_pubkey: Script::from_bytes(vec![0x6a, 0x02, 0xaa, 0xbb]),
            },
            TxOut {
                value: Amount::from_sat(2),
                script_pubkey: Script::from_bytes({
                    let mut s = vec![0x41];
                    s.extend_from_slice(&[5_u8; 65]);
                    s.push(0xac);
                    s
                }),
            },
            TxOut {
                value: Amount::from_sat(3),
                script_pubkey: Script::from_bytes({
                    let mut s = vec![0x21];
                    s.extend_from_slice(&[5_u8; 33]);
                    s.push(0xac);
                    s
                }),
            },
            TxOut {
                value: Amount::from_sat(4),
                script_pubkey: p2pkh_script([6_u8; 20]),
            },
            TxOut {
                value: Amount::from_sat(5),
                script_pubkey: Script::from_bytes({
                    let mut s = vec![0xa9, 0x14];
                    s.extend_from_slice(&[6_u8; 20]);
                    s.push(0x87);
                    s
                }),
            },
            TxOut {
                value: Amount::from_sat(6),
                script_pubkey: p2wpkh_script([6_u8; 20]),
            },
            TxOut {
                value: Amount::from_sat(7),
                script_pubkey: Script::from_bytes({
                    let mut s = vec![0x00, 0x20];
                    s.extend_from_slice(&[6_u8; 32]);
                    s
                }),
            },
            TxOut {
                value: Amount::from_sat(8),
                script_pubkey: Script::from_bytes({
                    let mut s = vec![0x51, 0x20];
                    s.extend_from_slice(&[6_u8; 32]);
                    s
                }),
            },
        ],
        lock_time: LockTime::from_consensus(800_000),
    };
    let mut resolver = MapResolver::default();
    let compressed = roundtrip(&multi, &mut resolver, false);
    assert!(compressed.len() < consensus_bytes(&multi).len());
    multi.lock_time = LockTime::from_consensus(1_700_000_000);
    roundtrip(&multi, &mut resolver, false);
}

#[test]
fn minimum_height_sentinel_and_locktime_only_candidate_roundtrip() {
    // No locktime and no compressible coin: the u32::MAX "no candidate"
    // sentinel encodes as zero, so the minimum-height presence bit (bit
    // 7 of the metadata byte) stays clear and offsets never appear.
    let tx = funding_tx(TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: p2wpkh_script([2_u8; 20]),
    });
    let mut resolver = MapResolver::default();
    let (compressed, _) = compress_transaction(
        &tx,
        &mut resolver,
        CompressOptions {
            compress_outpoints: true,
        },
    )
    .unwrap();
    assert_eq!(compressed[0] & 0x80, 0, "sentinel must encode as zero");
    let restored = decompress_transaction(&compressed, &mut resolver).unwrap();
    assert_eq!(restored, tx);

    // Locktime alone supplies the candidate: minimum height is
    // locktime - 1 and the stored locktime is the checked difference 1.
    let mut locked = tx.clone();
    locked.lock_time = LockTime::from_consensus(500_000);
    let (compressed, _) = compress_transaction(
        &locked,
        &mut resolver,
        CompressOptions {
            compress_outpoints: true,
        },
    )
    .unwrap();
    assert_eq!(compressed[0] & 0x80, 0x80, "locktime candidate must encode");
    assert_eq!(
        compressed[0] & 0x40,
        0x40,
        "locktime presence bit must be set"
    );
    let restored = decompress_transaction(&compressed, &mut resolver).unwrap();
    assert_eq!(restored, locked);
}

#[test]
fn missing_context_degrades_compress_but_refuses_decompress() {
    let signer = Signer::new(17);
    let prevout = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: p2wpkh_script(signer.pubkey_hash()),
    };
    let prev_tx = funding_tx(prevout.clone());
    let mut tx = spend_of(&prev_tx, Script::new(), Witness::new());
    let digest = SighashCache::new(&tx)
        .segwit_v0_signature_hash_raw(
            0,
            p2pkh_script(signer.pubkey_hash()).as_bytes(),
            prevout.value,
            1,
        )
        .unwrap();
    tx.inputs[0].witness = Witness::from_stack(vec![
        signer.ecdsa_item(digest, false),
        signer.compressed_pubkey(),
    ]);

    // Compress with no context: raw outpoint plus exactly one warning.
    let mut empty = MapResolver::default();
    let (compressed, warnings) = compress_transaction(
        &tx,
        &mut empty,
        CompressOptions {
            compress_outpoints: true,
        },
    )
    .unwrap();
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].starts_with("UTXO(0): "), "{warnings:?}");
    // The signature stayed uncompressed (prevout kind unknown), so the
    // same empty resolver can still decompress.
    let restored = decompress_transaction(&compressed, &mut empty).unwrap();
    assert_eq!(restored, tx);

    // Compress with context (compressed signature + outpoint), then
    // decompress without it: refusal, never a fabricated prevout.
    let mut full = MapResolver::default();
    full.register_tx(100, &prev_tx, 0);
    let (compressed, warnings) = compress_transaction(
        &tx,
        &mut full,
        CompressOptions {
            compress_outpoints: true,
        },
    )
    .unwrap();
    assert_eq!(warnings, Vec::<String>::new());
    let mut empty = MapResolver::default();
    let error = decompress_transaction(&compressed, &mut empty).unwrap_err();
    assert!(
        matches!(error, CodecError::BodyMissing(_)),
        "compressed outpoint without its block: {error:?}"
    );
}

/// Production resolver integration: a Context whose block log and body
/// source serve one crafted block must compress the spend's outpoint
/// (no warning) and restore it through the handlers. Exercises
/// `RpcPrevoutResolver` against `block_by_height_in_view` and the body
/// source directly, not a codec fake.
#[test]
fn production_resolver_resolves_through_block_bodies() {
    use std::sync::Arc;

    use bitcoin_rs_chain::BlockBodySource;
    use sonic_rs::json;

    use crate::context::Context;
    use crate::handlers::tx::{compressrawtransaction, decompressrawtransaction};

    struct StubBody(Vec<u8>);
    impl BlockBodySource for StubBody {
        fn block_body(
            &self,
            height: u32,
            _hash: bitcoin_rs_primitives::BlockHash,
        ) -> Result<Option<Vec<u8>>, bitcoin_rs_chain::BlockBodyReadError> {
            Ok((height == 100).then(|| self.0.clone()))
        }
    }

    /// Height-only txindex: the resolver must walk from this height to
    /// the body source for the prevout itself.
    struct StubTxIndex(Txid);
    impl bitcoin_rs_index::DerivedIndexQuery for StubTxIndex {
        fn transaction(&self, _txid: &Txid) -> Result<Option<Tx>, bitcoin_rs_index::TxQueryError> {
            Ok(None)
        }
        fn outpoint_value(
            &self,
            _outpoint: &OutPoint,
        ) -> Result<Option<u64>, bitcoin_rs_index::TxQueryError> {
            Ok(None)
        }
        fn transaction_height(
            &self,
            txid: &Txid,
        ) -> Result<Option<u32>, bitcoin_rs_index::TxQueryError> {
            Ok((self.0 == *txid).then_some(100))
        }
        fn index_info(
            &self,
        ) -> Result<bitcoin_rs_index::DerivedIndexInfo, bitcoin_rs_index::TxQueryError> {
            Ok(bitcoin_rs_index::DerivedIndexInfo {
                synced: true,
                best_block_height: 100,
            })
        }
    }

    let signer = Signer::new(19);
    let prevout = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: p2wpkh_script(signer.pubkey_hash()),
    };
    let prev_tx = funding_tx(prevout.clone());
    let mut tx = spend_of(&prev_tx, Script::new(), Witness::new());
    let digest = SighashCache::new(&tx)
        .segwit_v0_signature_hash_raw(
            0,
            p2pkh_script(signer.pubkey_hash()).as_bytes(),
            prevout.value,
            1,
        )
        .unwrap();
    tx.inputs[0].witness = Witness::from_stack(vec![
        signer.ecdsa_item(digest, false),
        signer.compressed_pubkey(),
    ]);

    let mut block = bitcoin_rs_primitives::Network::Regtest.genesis_block();
    block.txs = vec![prev_tx.clone()];
    let body = consensus_bytes(&block);

    let mut ctx = Context::new();
    ctx.compressed_transactions = true;
    ctx.chain.block_body_source = Some(Arc::new(StubBody(body)));
    ctx.indexes.derived_index = Some(Arc::new(StubTxIndex(prev_tx.txid())));
    ctx.chain
        .add_block(bitcoin_rs_index::block_log::BlockRecord {
            hash: bitcoin_rs_primitives::BlockHash::from(
                bitcoin_rs_primitives::Hash256::from_le_bytes(&[9_u8; 32]),
            ),
            height: 100,
            body_size: 0,
            header: None,
            tx_count: 1,
            time: 0,
        });
    let ctx = Arc::new(ctx);
    let raw_hex = bitcoin::hex::DisplayHex::to_lower_hex_string(&consensus_bytes(&tx));
    let latch = bitcoin_rs_chain::LatchReader::fixture_never();
    let compressed = compressrawtransaction(&ctx, &json!([raw_hex]), &latch).unwrap();
    assert!(
        compressed
            .get("warnings")
            .and_then(Value::as_array)
            .is_some_and(sonic_rs::Array::is_empty),
        "body-backed resolver must leave no warning: {compressed}"
    );
    let compressed_hex = compressed
        .get("result")
        .and_then(Value::as_str)
        .unwrap()
        .to_owned();
    let restored = decompressrawtransaction(&ctx, &json!([compressed_hex]), &latch).unwrap();
    assert_eq!(restored.as_str().unwrap(), raw_hex);
}

#[test]
fn malformed_streams_are_rejected() {
    let vector = &fixture_vectors()[0];
    let compressed = hex_bytes(
        vector
            .get("compressed_hex")
            .and_then(Value::as_str)
            .unwrap(),
    );
    let mut resolver = fixture_resolver(vector);

    // Truncated.
    let error =
        decompress_transaction(&compressed[..compressed.len() - 3], &mut resolver).unwrap_err();
    assert_eq!(error, CodecError::Truncated);
    // Trailing bytes.
    let mut trailed = compressed.clone();
    trailed.push(0);
    let error = decompress_transaction(&trailed, &mut resolver).unwrap_err();
    assert_eq!(error, CodecError::NonCanonical);
    // Set padding bit in the metadata packing (byte 5 low bits are pad).
    let mut padded = compressed.clone();
    padded[5] |= 0x01;
    let error = decompress_transaction(&padded, &mut resolver).unwrap_err();
    assert_eq!(error, CodecError::NonCanonical);
    // Corrupt one ECDSA signature byte in the P2WPKH vector: recovery no
    // longer matches the prevout commitment.
    let wpkh = &fixture_vectors()[1];
    let wpkh_compressed = hex_bytes(wpkh.get("compressed_hex").and_then(Value::as_str).unwrap());
    let mut wpkh_resolver = fixture_resolver(wpkh);
    let mut forged = wpkh_compressed;
    forged[20] ^= 0xff;
    let error = decompress_transaction(&forged, &mut wpkh_resolver).unwrap_err();
    assert_eq!(error, CodecError::SignatureUnrecoverable);
    // Empty input.
    let error = decompress_transaction(&[], &mut resolver).unwrap_err();
    assert_eq!(error, CodecError::Truncated);
    // Cancellation.
    resolver.cancelled = true;
    let error = decompress_transaction(&compressed, &mut resolver).unwrap_err();
    assert_eq!(error, CodecError::Cancelled);
}

/// Resolver backed directly by downloaded mainnet bodies, used only by
/// the ignored truth test. Indexes are rebuilt from the bodies on every
/// run, so a stale fixture cannot pass against itself.
#[cfg(test)]
struct BodyResolver {
    heights: HashMap<Txid, (u32, u32, u32, u32)>, // txid -> (height, tx index, first flat, output count)
    txouts: HashMap<OutPoint, (TxOut, u32)>,
    at: HashMap<(u32, u32), OutPoint>,
}

#[cfg(test)]
impl BodyResolver {
    fn from_bodies(dir: &std::path::Path) -> Self {
        let mut resolver = Self {
            heights: HashMap::new(),
            txouts: HashMap::new(),
            at: HashMap::new(),
        };
        let mut entries: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "bin"))
            .collect();
        entries.sort();
        for path in entries {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let (height, hash) = name.split_once('-').unwrap();
            let height: u32 = height.parse().unwrap();
            let bytes = std::fs::read(&path).unwrap();
            // The filename hash must be the body's double-SHA256 header hash.
            let digest = {
                use sha2::{Digest as _, Sha256};
                let first = Sha256::digest(&bytes[..80]);
                Sha256::digest(first)
            };
            let mut displayed = digest.to_vec();
            displayed.reverse();
            assert_eq!(
                bitcoin::hex::DisplayHex::to_lower_hex_string(&displayed),
                hash.trim_end_matches(".bin"),
                "body file hash mismatch: {name}"
            );
            let block = ParsedBlock::parse_exact(&bytes).unwrap();
            let mut flat = 0_u32;
            for (tx_index, parsed) in block.transactions().iter().enumerate() {
                let tx = parsed.materialize();
                resolver.heights.insert(
                    tx.txid(),
                    (
                        height,
                        u32::try_from(tx_index).unwrap(),
                        flat,
                        u32::try_from(tx.outputs.len()).unwrap(),
                    ),
                );
                for (vout, output) in tx.outputs.iter().enumerate() {
                    let vout = u32::try_from(vout).unwrap();
                    let outpoint = OutPoint::new(tx.txid(), vout);
                    resolver.txouts.insert(outpoint, (output.clone(), height));
                    resolver.at.insert((height, flat + vout), outpoint);
                }
                flat += u32::try_from(tx.outputs.len()).unwrap();
            }
        }
        resolver
    }
}

#[cfg(test)]
impl PrevoutResolver for BodyResolver {
    fn prevout(&mut self, outpoint: &OutPoint) -> Result<Option<ResolvedPrevout>, LookupError> {
        Ok(self
            .txouts
            .get(outpoint)
            .map(|(txout, height)| ResolvedPrevout {
                txout: txout.clone(),
                confirmed_height: Some(*height),
            }))
    }

    fn flat_output_index(
        &mut self,
        height: u32,
        txid: &Txid,
        vout: u32,
    ) -> Result<Option<u32>, LookupError> {
        Ok(match self.heights.get(txid) {
            Some((h, _index, first, count)) if *h == height && vout < *count => Some(first + vout),
            _ => None,
        })
    }

    fn outpoint_at(
        &mut self,
        height: u32,
        flat_index: u32,
    ) -> Result<Option<(OutPoint, ResolvedPrevout)>, LookupError> {
        Ok(self.at.get(&(height, flat_index)).map(|outpoint| {
            let (txout, _) = self.txouts.get(outpoint).unwrap();
            (
                *outpoint,
                ResolvedPrevout {
                    txout: txout.clone(),
                    confirmed_height: Some(height),
                },
            )
        }))
    }

    fn cancelled(&self) -> bool {
        false
    }
}

/// Truth loop over the downloaded mainnet bodies: re-derives every
/// fixture field, then compresses and decompresses every published
/// vector against body-derived context, reporting ratio and cost per
/// representative type. Absent bodies are BLOCKED, not a pass.
#[test]
#[ignore = "requires BITCOIN_RS_BIP337_MAINNET_BODIES with mainnet block bodies"]
#[allow(
    clippy::too_many_lines,
    reason = "one derivation walk over every fixture field and vector"
)]
fn mainnet_bodies_truth() {
    let Ok(dir) = std::env::var("BITCOIN_RS_BIP337_MAINNET_BODIES") else {
        panic!(
            "BLOCKED: BITCOIN_RS_BIP337_MAINNET_BODIES is unset; download mainnet bodies \
             833265..833280 to run the BIP337 fixture truth loop"
        );
    };
    let resolver = BodyResolver::from_bodies(std::path::Path::new(&dir));
    for vector in fixture_vectors() {
        let name = vector
            .get("name")
            .and_then(Value::as_str)
            .unwrap()
            .to_owned();
        let raw: Tx = deserialize(&hex_bytes(
            vector.get("raw_hex").and_then(Value::as_str).unwrap(),
        ))
        .unwrap();
        assert_eq!(
            raw.txid().to_string(),
            vector.get("txid").and_then(Value::as_str).unwrap()
        );
        assert_eq!(
            raw.wtxid().to_string(),
            vector.get("wtxid").and_then(Value::as_str).unwrap()
        );
        for input in vector.get("inputs").and_then(Value::as_array).unwrap() {
            let prevout_txid =
                Txid::from_str(input.get("prevout_txid").and_then(Value::as_str).unwrap()).unwrap();
            let (height, tx_index, first_flat, _count) =
                resolver.heights.get(&prevout_txid).unwrap();
            assert_eq!(
                *tx_index,
                u32::try_from(
                    input
                        .get("tx_index_in_block")
                        .and_then(Value::as_u64)
                        .unwrap()
                )
                .unwrap(),
                "{name} tx index in block"
            );
            let vout = u32::try_from(input.get("vout").and_then(Value::as_u64).unwrap()).unwrap();
            let (txout, txout_height) = resolver
                .txouts
                .get(&OutPoint::new(prevout_txid, vout))
                .unwrap();
            assert_eq!(
                *height,
                u32::try_from(input.get("height").and_then(Value::as_u64).unwrap()).unwrap(),
                "{name} height"
            );
            assert_eq!(*txout_height, *height, "{name} txout height");
            assert_eq!(
                *first_flat,
                u32::try_from(
                    input
                        .get("cumulative_outputs_before")
                        .and_then(Value::as_u64)
                        .unwrap()
                )
                .unwrap(),
                "{name} cumulative outputs before"
            );
            assert_eq!(
                first_flat + vout,
                u32::try_from(
                    input
                        .get("flat_output_index")
                        .and_then(Value::as_u64)
                        .unwrap()
                )
                .unwrap(),
                "{name} flat index"
            );
            assert_eq!(
                txout.script_pubkey.as_bytes(),
                hex_bytes(
                    input
                        .get("prevout_script_hex")
                        .and_then(Value::as_str)
                        .unwrap()
                )
                .as_slice(),
                "{name} prevout script"
            );
            assert_eq!(
                txout.value.to_sat(),
                input.get("value_sats").and_then(Value::as_u64).unwrap(),
                "{name} value"
            );
        }
        let mut compress_resolver = BodyResolver::from_bodies(std::path::Path::new(&dir));
        let start = std::time::Instant::now();
        let mut compressed = Vec::new();
        for _ in 0..200 {
            let (bytes, warnings) = compress_transaction(
                &raw,
                &mut compress_resolver,
                CompressOptions {
                    compress_outpoints: true,
                },
            )
            .unwrap();
            assert!(warnings.is_empty(), "{name}: {warnings:?}");
            compressed = bytes;
        }
        let encode_elapsed = start.elapsed();
        assert_eq!(
            compressed,
            hex_bytes(
                vector
                    .get("compressed_hex")
                    .and_then(Value::as_str)
                    .unwrap()
            ),
            "{name} compressed bytes"
        );
        let start = std::time::Instant::now();
        let mut restored = raw.clone();
        for _ in 0..200 {
            restored = decompress_transaction(&compressed, &mut compress_resolver).unwrap();
        }
        let decode_elapsed = start.elapsed();
        assert_eq!(restored, raw, "{name} restored");
        eprintln!(
            "bip337 {name}: raw={} compressed={} ratio_permille={} encode_us_per={:.1} decode_us_per={:.1}",
            consensus_bytes(&raw).len(),
            compressed.len(),
            compressed.len() * 1000 / consensus_bytes(&raw).len(),
            encode_elapsed.as_secs_f64() * 1e6 / 200.0,
            decode_elapsed.as_secs_f64() * 1e6 / 200.0,
        );
    }
}

#[test]
fn shared_sighash_cache_recovers_every_input() {
    // One cache over the immutable skeleton must serve every compressed
    // input: the legacy input and the segwit input below share the same
    // transaction midstates, so rebuilding the cache per input repeats
    // identical hashing work.
    let signer_a = Signer::new(31);
    let signer_b = Signer::new(32);
    let prevout_a = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: p2pkh_script(signer_a.pubkey_hash()),
    };
    let prevout_b = TxOut {
        value: Amount::from_sat(60_000),
        script_pubkey: p2wpkh_script(signer_b.pubkey_hash()),
    };
    let prev_tx_a = funding_tx(prevout_a.clone());
    let prev_tx_b = funding_tx(prevout_b.clone());

    // Skeleton first: sighashes commit to outpoints, sequences, outputs,
    // and locktime, never to the authorizations being reconstructed.
    let mut tx = Tx {
        version: 2,
        inputs: vec![
            TxIn {
                previous_output: OutPoint::new(prev_tx_a.txid(), 0),
                script_sig: Script::new(),
                sequence: Sequence::from_consensus(0xffff_fffd),
                witness: Witness::new(),
            },
            TxIn {
                previous_output: OutPoint::new(prev_tx_b.txid(), 0),
                script_sig: Script::new(),
                sequence: Sequence::from_consensus(0xffff_fffd),
                witness: Witness::new(),
            },
        ],
        outputs: vec![TxOut {
            value: Amount::from_sat(40_000),
            script_pubkey: Script::from_bytes(
                vec![0x00, 0x14].into_iter().chain([7_u8; 20]).collect(),
            ),
        }],
        lock_time: LockTime::ZERO,
    };
    let digest_a = SighashCache::new(&tx)
        .legacy_signature_hash(0, prevout_a.script_pubkey.as_bytes(), 1)
        .unwrap();
    let digest_b = SighashCache::new(&tx)
        .segwit_v0_signature_hash_raw(
            1,
            p2pkh_script(signer_b.pubkey_hash()).as_bytes(),
            prevout_b.value,
            1,
        )
        .unwrap();
    let sig_item_a = signer_a.ecdsa_item(digest_a, false);
    let mut script_sig = super::push_data(&sig_item_a);
    script_sig.extend_from_slice(&super::push_data(&signer_a.compressed_pubkey()));
    tx.inputs[0].script_sig = Script::from_bytes(script_sig);
    let sig_item_b = signer_b.ecdsa_item(digest_b, false);
    tx.inputs[1].witness = Witness::from_stack(vec![sig_item_b, signer_b.compressed_pubkey()]);

    // The shared cache pins the new call shape at compile time: one
    // `SighashCache` borrowed alongside both recovery requests. The
    // transaction carries DER signatures plus a sighash byte; recovery
    // needs the 64-byte compact form, so strip the trailing byte and
    // parse the DER prefix.
    fn compact_of(der_plus_hashtype: &[u8]) -> [u8; 64] {
        let parsed = bitcoin::secp256k1::ecdsa::Signature::from_der(
            &der_plus_hashtype[..der_plus_hashtype.len() - 1],
        )
        .unwrap();
        parsed.serialize_compact()
    }
    let cache = SighashCache::new(&tx);
    let compact_a = compact_of(&sig_item_a);
    let compact_b = compact_of(&tx.inputs[1].witness[0]);
    let kind_a = super::prevout_kind(prevout_a.script_pubkey.as_bytes());
    let kind_b = super::prevout_kind(prevout_b.script_pubkey.as_bytes());
    let resolved_a = ResolvedPrevout {
        txout: prevout_a.clone(),
        confirmed_height: Some(100),
    };
    let resolved_b = ResolvedPrevout {
        txout: prevout_b.clone(),
        confirmed_height: Some(101),
    };
    let recovered_a = super::recover_pubkey(
        &cache,
        &super::Recovery {
            index: 0,
            sig: &compact_a,
            hash_type: 1,
            kind: &kind_a,
            prevout: &resolved_a,
            stored_pkh: None,
        },
    )
    .unwrap();
    assert_eq!(recovered_a, signer_a.compressed_pubkey());
    let recovered_b = super::recover_pubkey(
        &cache,
        &super::Recovery {
            index: 1,
            sig: &compact_b,
            hash_type: 1,
            kind: &kind_b,
            prevout: &resolved_b,
            stored_pkh: None,
        },
    )
    .unwrap();
    assert_eq!(recovered_b, signer_b.compressed_pubkey());

    // End to end: both inputs compress and the split prepare/finalize
    // path (which now builds that single cache) restores the pair.
    let mut resolver = MapResolver::default();
    resolver.register_tx(100, &prev_tx_a, 0);
    resolver.register_tx(101, &prev_tx_b, 0);
    let (compressed, warnings) = compress_transaction(
        &tx,
        &mut resolver,
        CompressOptions {
            compress_outpoints: true,
        },
    )
    .unwrap();
    assert!(warnings.is_empty(), "{warnings:?}");
    let plan = super::decompress_prepare(&compressed, &mut resolver).unwrap();
    assert_eq!(plan.inputs.len(), 2);
    let restored = super::decompress_finalize(plan, &resolver).unwrap();
    assert_eq!(&restored, &tx);
    assert_eq!(
        &super::decompress_transaction(&compressed, &mut resolver).unwrap(),
        &tx
    );
}

#[test]
fn production_resolver_clones_only_the_requested_output() {
    use std::sync::Arc;

    use bitcoin_rs_chain::BlockBodySource;

    use crate::context::Context;

    struct StubBody(Vec<u8>);
    impl BlockBodySource for StubBody {
        fn block_body(
            &self,
            height: u32,
            _hash: bitcoin_rs_primitives::BlockHash,
        ) -> Result<Option<Vec<u8>>, bitcoin_rs_chain::BlockBodyReadError> {
            Ok((height == 100).then(|| self.0.clone()))
        }
    }

    struct StubTxIndex(Txid);
    impl bitcoin_rs_index::DerivedIndexQuery for StubTxIndex {
        fn transaction(&self, _txid: &Txid) -> Result<Option<Tx>, bitcoin_rs_index::TxQueryError> {
            Ok(None)
        }
        fn outpoint_value(
            &self,
            _outpoint: &OutPoint,
        ) -> Result<Option<u64>, bitcoin_rs_index::TxQueryError> {
            Ok(None)
        }
        fn transaction_height(
            &self,
            txid: &Txid,
        ) -> Result<Option<u32>, bitcoin_rs_index::TxQueryError> {
            Ok((self.0 == *txid).then_some(100))
        }
        fn index_info(
            &self,
        ) -> Result<bitcoin_rs_index::DerivedIndexInfo, bitcoin_rs_index::TxQueryError> {
            Ok(bitcoin_rs_index::DerivedIndexInfo {
                synced: true,
                best_block_height: 100,
            })
        }
    }

    // One funding transaction with three distinct outputs: resolving or
    // locating the middle one must return exactly that output, proving
    // the resolver cloned the requested `TxOut` rather than the whole
    // funding transaction.
    let funding = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: Script::from_bytes(vec![0x01, 0x2a]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![
            TxOut {
                value: Amount::from_sat(11_000),
                script_pubkey: p2pkh_script([1_u8; 20]),
            },
            TxOut {
                value: Amount::from_sat(22_000),
                script_pubkey: p2wpkh_script([2_u8; 20]),
            },
            TxOut {
                value: Amount::from_sat(33_000),
                script_pubkey: p2pkh_script([3_u8; 20]),
            },
        ],
        lock_time: LockTime::ZERO,
    };
    let txid = funding.txid();

    let mut block = bitcoin_rs_primitives::Network::Regtest.genesis_block();
    block.txs = vec![funding.clone()];
    let body = consensus_bytes(&block);

    let mut ctx = Context::new();
    ctx.chain.block_body_source = Some(Arc::new(StubBody(body)));
    ctx.indexes.derived_index = Some(Arc::new(StubTxIndex(txid)));
    ctx.chain
        .add_block(bitcoin_rs_index::block_log::BlockRecord {
            hash: bitcoin_rs_primitives::BlockHash::from(
                bitcoin_rs_primitives::Hash256::from_le_bytes(&[9_u8; 32]),
            ),
            height: 100,
            body_size: 0,
            header: None,
            tx_count: 1,
            time: 0,
        });
    let ctx = Arc::new(ctx);
    let latch = bitcoin_rs_chain::LatchReader::fixture_never();
    let mut resolver = crate::context::RpcPrevoutResolver::new(&ctx, latch).unwrap();

    // `prevout` resolves each vout to its own output.
    for (vout, expected) in funding.outputs.iter().enumerate() {
        let vout = u32::try_from(vout).unwrap();
        let resolved = resolver
            .prevout(&OutPoint::new(txid, vout))
            .unwrap()
            .expect("funding output must resolve");
        assert_eq!(&resolved.txout, expected, "vout {vout} must match");
        assert_eq!(resolved.confirmed_height, Some(100));
    }
    // The middle output differs from its neighbours: a whole-transaction
    // mix-up would surface here, not just a missing-output failure.
    let middle = resolver.prevout(&OutPoint::new(txid, 1)).unwrap().unwrap();
    assert_eq!(middle.txout, funding.outputs[1]);
    assert_ne!(middle.txout, funding.outputs[0]);
    assert_ne!(middle.txout, funding.outputs[2]);

    // `outpoint_at` is the flat-index inverse and returns the same TxOuts.
    assert_eq!(resolver.flat_output_index(100, &txid, 1).unwrap(), Some(1));
    for flat in [0_u32, 1, 2] {
        let (outpoint, resolved) = resolver
            .outpoint_at(100, flat)
            .unwrap()
            .expect("flat index must locate an output");
        let vout = flat;
        assert_eq!(outpoint, OutPoint::new(txid, vout));
        assert_eq!(
            resolved.txout,
            funding.outputs[usize::try_from(vout).unwrap()]
        );
        assert_eq!(resolved.confirmed_height, Some(100));
    }

    // Proved-absent stays `None` on both paths, never an error.
    assert!(resolver.prevout(&OutPoint::new(txid, 9)).unwrap().is_none());
    assert!(resolver.outpoint_at(100, 9).unwrap().is_none());
}

/// Counts body reads per height so tests prove each body loads once.
struct CountingBodies {
    bodies: HashMap<u32, Vec<u8>>,
    loads: std::sync::Mutex<HashMap<u32, usize>>,
}

impl bitcoin_rs_chain::BlockBodySource for CountingBodies {
    fn block_body(
        &self,
        height: u32,
        _hash: bitcoin_rs_primitives::BlockHash,
    ) -> Result<Option<Vec<u8>>, bitcoin_rs_chain::BlockBodyReadError> {
        if let Some(body) = self.bodies.get(&height) {
            *self.loads.lock().unwrap().entry(height).or_default() += 1;
            Ok(Some(body.clone()))
        } else {
            Ok(None)
        }
    }
}

/// Builds one single-output funding block per `heights` entry, wires the
/// records plus a counting body source into a fresh [`Context`], and funds
/// the UTXO set so the compress pass resolves prevouts without body reads.
/// Returns the context, the source, and the funding txids in height order.
fn cycling_fixture(
    heights: &[u32],
) -> (
    crate::context::Context,
    std::sync::Arc<CountingBodies>,
    Vec<Txid>,
) {
    use std::sync::Arc;

    let mut ctx = crate::context::Context::new();
    let mut bodies = HashMap::new();
    let mut txids = Vec::new();
    let mut changes = bitcoin_rs_utxo::contract::BlockChanges::default();
    for (slot, &height) in heights.iter().enumerate() {
        let funding = funding_tx(TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: Script::from_bytes(vec![0x6a, u8::try_from(slot).unwrap()]),
        });
        let txid = funding.txid();
        let mut block = bitcoin_rs_primitives::Network::Regtest.genesis_block();
        block.txs = vec![funding.clone()];
        bodies.insert(height, consensus_bytes(&block));
        changes.add(bitcoin_rs_utxo::contract::UtxoAdd::new(
            OutPoint::new(txid, 0),
            funding.outputs[0].clone(),
            false,
            height,
        ));
        ctx.chain
            .add_block(bitcoin_rs_index::block_log::BlockRecord {
                hash: bitcoin_rs_primitives::BlockHash::from(
                    bitcoin_rs_primitives::Hash256::from_le_bytes(
                        &[u8::try_from(height).unwrap(); 32],
                    ),
                ),
                height,
                body_size: 0,
                header: None,
                tx_count: 1,
                time: 0,
            });
        txids.push(txid);
    }
    bitcoin_rs_utxo::contract::commit_block_changes(
        &ctx.chain.utxo.fixture_set(),
        &changes,
        &bitcoin_rs_primitives::Hash256::default(),
    )
    .unwrap();
    let source = Arc::new(CountingBodies {
        bodies,
        loads: std::sync::Mutex::new(HashMap::new()),
    });
    let object: Arc<dyn bitcoin_rs_chain::BlockBodySource> = source.clone();
    ctx.chain.block_body_source = Some(object);
    (ctx, source, txids)
}

/// Builds a spender with `inputs` inputs round-robining `txids` (vout 0),
/// empty authorizations, and one change output.
fn cycling_spend(txids: &[Txid], inputs: usize) -> Tx {
    Tx {
        version: 2,
        inputs: txids
            .iter()
            .cycle()
            .take(inputs)
            .map(|txid| TxIn {
                previous_output: OutPoint::new(*txid, 0),
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect(),
        outputs: vec![TxOut {
            value: Amount::from_sat(40_000),
            script_pubkey: p2wpkh_script([7_u8; 20]),
        }],
        lock_time: LockTime::ZERO,
    }
}

fn assert_loads(source: &CountingBodies, heights: &[u32], per_height: usize) {
    let loads = source.loads.lock().unwrap();
    assert_eq!(loads.len(), heights.len(), "{loads:?}");
    let mut total = 0_usize;
    for height in heights {
        let count = loads.get(height).copied().unwrap_or(0);
        assert_eq!(count, per_height, "height {height}");
        total += count;
    }
    assert_eq!(total, heights.len() * per_height);
}

/// Five heights cycling through the four-body cache: grouped resolution
/// loads each body once instead of paying a full body read, parse,
/// materialization, and txid pass per input inside the stable-chainstate
/// exclusion. Ten inputs round-robin five heights; the counting source
/// proves five total loads (one per height), and both codec passes
/// round-trip the spending transaction.
#[test]
fn five_heights_cycling_loads_each_body_once() {
    use std::sync::Arc;

    let heights: Vec<u32> = (100..105).collect();
    let (ctx, source, txids) = cycling_fixture(&heights);
    let ctx = Arc::new(ctx);
    let spend = cycling_spend(&txids, 10);

    // Compress: prevouts hit the UTXO set, so all five body loads happen in
    // the grouped flat-index pass — one per height despite round-robin inputs.
    let latch = bitcoin_rs_chain::LatchReader::fixture_never();
    let mut resolver = crate::context::RpcPrevoutResolver::new(&ctx, latch).unwrap();
    let (compressed, warnings) = compress_transaction(
        &spend,
        &mut resolver,
        CompressOptions {
            compress_outpoints: true,
        },
    )
    .unwrap();
    assert!(warnings.is_empty(), "{warnings:?}");
    assert_loads(&source, &heights, 1);

    // Decompress resolves the same five heights grouped: one load each,
    // restoring the exact spending transaction.
    let latch = bitcoin_rs_chain::LatchReader::fixture_never();
    let mut resolver = crate::context::RpcPrevoutResolver::new(&ctx, latch).unwrap();
    let plan = super::decompress_prepare(&compressed, &mut resolver).unwrap();
    let restored = super::decompress_finalize(plan, &resolver).unwrap();
    assert_eq!(&restored, &spend);
    assert_loads(&source, &heights, 2);
}

/// Past the grouped handful, the cumulative body-load budget fails closed:
/// ten distinct heights need ten loads against a budget of eight, so the
/// call refuses with `LimitExceeded` after bounded work instead of
/// materializing every body under the exclusion.
#[test]
fn cumulative_body_budget_fails_closed_past_grouped_heights() {
    use std::sync::Arc;

    let heights: Vec<u32> = (100..110).collect();
    let (ctx, source, txids) = cycling_fixture(&heights);
    let ctx = Arc::new(ctx);
    let spend = cycling_spend(&txids, 10);

    let latch = bitcoin_rs_chain::LatchReader::fixture_never();
    let mut resolver = crate::context::RpcPrevoutResolver::new(&ctx, latch).unwrap();
    let error = compress_transaction(
        &spend,
        &mut resolver,
        CompressOptions {
            compress_outpoints: true,
        },
    )
    .unwrap_err();
    assert_eq!(error, CodecError::LimitExceeded(super::Limit::Loads));
    // Bounded work: eight loads happened; the ninth failed before body I/O.
    let loads = source.loads.lock().unwrap();
    let total: usize = loads.values().sum();
    assert_eq!(total, super::MAX_CUMULATIVE_BODY_LOADS);
}
