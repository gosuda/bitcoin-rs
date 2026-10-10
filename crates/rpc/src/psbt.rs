//! The RPC PSBT codec boundary: library parsing plus bounded Core postconditions.
//!
//! No transaction/key codec lives here. Consumers own their method parameters
//! and error projection; supplied public metadata remains in rust-bitcoin's PSBT.
use bitcoin::psbt::{Psbt, raw};
use std::collections::BTreeMap;

use crate::error::RpcError;

pub(crate) const MAX_PSBT_BYTES: usize = crate::server::MAX_BODY_BYTES;
pub(crate) const MAX_PSBT_ITEMS: usize = 10_000;
pub(crate) const MAX_PSBT_MAP_PAIRS: usize = 100_000;

#[derive(Debug)]
pub(crate) enum DecodeError {
    Base64,
    Format(bitcoin::psbt::Error),
    Trailing,
    UtxoHash,
    UtxoIndex,
    Field(String),
    Limit(&'static str),
}

impl DecodeError {
    /// New PSBT methods use Core's deserialization class; older combine/finalize
    /// retain their separately exercised invalid-params error boundary.
    pub(crate) fn into_rpc(self) -> RpcError {
        let detail = match self {
            Self::Base64 => "invalid base64".to_owned(),
            Self::Trailing => "extra data after PSBT".to_owned(),
            Self::UtxoHash => {
                "Non-witness UTXO does not match outpoint hash: iostream error".to_owned()
            }
            Self::UtxoIndex => {
                "Input specifies output index that does not exist: iostream error".to_owned()
            }
            Self::Field(message) => format!("{message}: iostream error"),
            Self::Limit(message) => return RpcError::InvalidParameter(message.to_owned()),
            Self::Format(error) => format_error(&error),
        };
        RpcError::Deserialization(format!("TX decode failed {detail}"))
    }
}

fn format_error(error: &bitcoin::psbt::Error) -> String {
    use bitcoin::psbt::Error;
    match error {
        Error::InvalidMagic | Error::InvalidSeparator => {
            "Invalid PSBT magic bytes: iostream error".to_owned()
        }
        Error::UnsignedTxHasScriptSigs | Error::UnsignedTxHasScriptWitnesses => {
            "Unsigned tx does not have empty scriptSigs and scriptWitnesses.: iostream error"
                .to_owned()
        }
        Error::MustHaveUnsignedTx => {
            "No unsigned transaction was provided: iostream error".to_owned()
        }
        // The library performs additional typed-field validation. Do not expose
        // supplied signatures/preimages in its potentially large Display text.
        Error::InvalidPreimageHashPair { .. } => "hash preimage does not match its key".to_owned(),
        Error::InvalidEcdsaSignature(_) => "invalid ECDSA signature encoding".to_owned(),
        Error::InvalidTaprootSignature(_) => "invalid Taproot signature encoding".to_owned(),
        Error::InvalidPublicKey(_)
        | Error::InvalidSecp256k1PublicKey(_)
        | Error::InvalidXOnlyPublicKey => "invalid public key encoding".to_owned(),
        Error::ConsensusEncoding(_) | Error::Io(_) => {
            "end of data or invalid serialization: iostream error".to_owned()
        }
        Error::Version(_) => "Unsupported PSBT version: iostream error".to_owned(),
        Error::DuplicateKey(_) => "Duplicate Key: iostream error".to_owned(),
        _ => "invalid PSBT field: iostream error".to_owned(),
    }
}

pub(crate) fn decode(encoded: &str) -> Result<Psbt, DecodeError> {
    if encoded.len() > MAX_PSBT_BYTES {
        return Err(DecodeError::Limit(
            "PSBT exceeds the RPC request byte limit",
        ));
    }
    let bytes = if encoded.is_empty() {
        Vec::new()
    } else {
        crate::base64::decode(encoded).map_err(|()| DecodeError::Base64)?
    };
    let mut remaining = bytes.as_slice();
    let mut psbt = Psbt::deserialize_from_reader(&mut remaining).map_err(DecodeError::Format)?;
    if !remaining.is_empty() {
        return Err(DecodeError::Trailing);
    }
    normalize_missing_witness_utxos(&mut psbt);
    measure(&psbt)?;
    reject_explicit_default_signatures(&bytes, psbt.inputs.len())?;
    validate(&psbt)?;
    Ok(psbt)
}

// The typed signature reader drops an explicit DEFAULT byte. Inspect only this
// lossy field on the original, already library-validated framing, without
// retaining a second representation or interpreting transactions/keys here.
fn reject_explicit_default_signatures(bytes: &[u8], inputs: usize) -> Result<(), DecodeError> {
    use bitcoin::consensus::Decodable as _;
    fn field<'a>(bytes: &mut &'a [u8]) -> Result<&'a [u8], DecodeError> {
        let length = bitcoin::VarInt::consensus_decode(bytes)
            .map_err(|error| DecodeError::Format(error.into()))?
            .0;
        let length = usize::try_from(length).map_err(|_| DecodeError::Trailing)?;
        let (value, rest) = bytes
            .split_at_checked(length)
            .ok_or(DecodeError::Trailing)?;
        *bytes = rest;
        Ok(value)
    }
    let mut remaining = bytes.get(5..).ok_or(DecodeError::Trailing)?;
    for map in 0..=inputs {
        loop {
            let key = field(&mut remaining)?;
            if key.is_empty() {
                break;
            }
            let value = field(&mut remaining)?;
            if map != 0
                && matches!(key.first(), Some(0x13 | 0x14))
                && value.len() == 65
                && value[64] == 0
            {
                return Err(DecodeError::Field(
                    "explicit DEFAULT Taproot signature suffix is not supported".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

/// Admit the unsigned transaction's map counts before a creator allocates them.
pub(crate) fn check_item_count(inputs: usize, outputs: usize) -> Result<usize, DecodeError> {
    inputs
        .checked_add(outputs)
        .filter(|count| *count <= MAX_PSBT_ITEMS)
        .ok_or(DecodeError::Limit("PSBT exceeds the input/output limit"))
}

pub(crate) fn encode(psbt: &Psbt) -> Result<String, RpcError> {
    measure(psbt).map_err(DecodeError::into_rpc)?;
    let mut normalized = std::borrow::Cow::Borrowed(psbt);
    if needs_core_serialization(psbt) {
        normalize_for_core_serialization(normalized.to_mut());
    }
    let psbt = normalized.as_ref();
    validate(psbt).map_err(DecodeError::into_rpc)?;
    let mut output = LimitedWriter(Vec::new());
    psbt.serialize_to_writer(&mut output)
        .map_err(|_| DecodeError::Limit("PSBT exceeds the RPC request byte limit").into_rpc())?;
    let bytes = output.0;
    if bytes
        .len()
        .div_ceil(3)
        .checked_mul(4)
        .is_none_or(|size| size > MAX_PSBT_BYTES)
    {
        return Err(DecodeError::Limit("PSBT exceeds the RPC request byte limit").into_rpc());
    }
    // The library has additional per-map/value read limits (notably its
    // 4,000,000-byte global map). Never return output our sole reader rejects.
    let mut remaining = bytes.as_slice();
    Psbt::deserialize_from_reader(&mut remaining).map_err(|_| {
        RpcError::InvalidParameter(
            "PSBT output is not readable within library codec limits".to_owned(),
        )
    })?;
    if !remaining.is_empty() {
        return Err(RpcError::Internal(
            "library PSBT serialization left unread bytes".to_owned(),
        ));
    }
    reject_explicit_default_signatures(&bytes, psbt.inputs.len()).map_err(|_| {
        RpcError::InvalidParameter(
            "PSBT output contains an explicit DEFAULT Taproot signature suffix".to_owned(),
        )
    })?;
    Ok(crate::base64::encode(&bytes))
}

fn has_missing_witness_utxo(psbt: &Psbt) -> bool {
    psbt.inputs.iter().any(|input| {
        input
            .witness_utxo
            .as_ref()
            .is_some_and(|output| output.value.to_sat() == u64::MAX)
    })
}

fn normalize_missing_witness_utxos(psbt: &mut Psbt) {
    for input in &mut psbt.inputs {
        // Core CTxOut::IsNull tests the signed -1 sentinel, even with a script.
        // Negative non-witness transaction outputs are preserved as supplied.
        if input
            .witness_utxo
            .as_ref()
            .is_some_and(|output| output.value.to_sat() == u64::MAX)
        {
            input.witness_utxo = None;
        }
    }
}

fn needs_core_serialization(psbt: &Psbt) -> bool {
    has_missing_witness_utxo(psbt)
        || psbt.inputs.iter().any(|input| {
            input.final_script_sig.is_some()
                || input.final_script_witness.is_some()
                || input
                    .redeem_script
                    .as_ref()
                    .is_some_and(|script| script.is_empty())
                || input
                    .witness_script
                    .as_ref()
                    .is_some_and(|script| script.is_empty())
                || input
                    .non_witness_utxo
                    .as_ref()
                    .is_some_and(|tx| tx.input.iter().any(|input| !input.witness.is_empty()))
        })
        || psbt.outputs.iter().any(|output| {
            output
                .redeem_script
                .as_ref()
                .is_some_and(|script| script.is_empty())
                || output
                    .witness_script
                    .as_ref()
                    .is_some_and(|script| script.is_empty())
        })
}

fn normalize_for_core_serialization(psbt: &mut Psbt) {
    normalize_missing_witness_utxos(psbt);
    for output in &mut psbt.outputs {
        if output
            .redeem_script
            .as_ref()
            .is_some_and(|script| script.is_empty())
        {
            output.redeem_script = None;
        }
        if output
            .witness_script
            .as_ref()
            .is_some_and(|script| script.is_empty())
        {
            output.witness_script = None;
        }
    }
    for input in &mut psbt.inputs {
        if let Some(tx) = &mut input.non_witness_utxo {
            for previous_input in &mut tx.input {
                previous_input.witness.clear();
            }
        }
        if input
            .final_script_sig
            .as_ref()
            .is_some_and(|script| script.is_empty())
        {
            input.final_script_sig = None;
        }
        if input
            .final_script_witness
            .as_ref()
            .is_some_and(bitcoin::Witness::is_empty)
        {
            input.final_script_witness = None;
        }
        if input.final_script_sig.is_some() || input.final_script_witness.is_some() {
            // Core psbt.h PSBTInput::Serialize gates these known nonfinal fields.
            // Keep the caller's parsed metadata; only this encoding copy changes.
            let mut unknown = std::mem::take(&mut input.unknown);
            unknown.retain(|key, _| !is_musig2(key, true));
            *input = bitcoin::psbt::Input {
                non_witness_utxo: input.non_witness_utxo.take(),
                witness_utxo: input.witness_utxo.take(),
                final_script_sig: input.final_script_sig.take(),
                final_script_witness: input.final_script_witness.take(),
                proprietary: std::mem::take(&mut input.proprietary),
                unknown,
                ..Default::default()
            };
        } else {
            if input
                .redeem_script
                .as_ref()
                .is_some_and(|script| script.is_empty())
            {
                input.redeem_script = None;
            }
            if input
                .witness_script
                .as_ref()
                .is_some_and(|script| script.is_empty())
            {
                input.witness_script = None;
            }
        }
    }
}

/// One checked aggregate admission owner for PSBT transforms. Encoded bytes
/// are admitted before each library decode; decoded counts before each merge.
#[derive(Default)]
pub(crate) struct PsbtBudget {
    encoded_bytes: usize,
    inputs_outputs: usize,
    map_pairs: usize,
}
impl PsbtBudget {
    pub(crate) fn add_encoded(&mut self, encoded: &str) -> Result<(), DecodeError> {
        self.encoded_bytes = self
            .encoded_bytes
            .checked_add(encoded.len())
            .filter(|count| *count <= MAX_PSBT_BYTES)
            .ok_or(DecodeError::Limit(
                "aggregate PSBT bytes exceed the RPC request limit",
            ))?;
        Ok(())
    }
    pub(crate) fn add_decoded(&mut self, psbt: &Psbt) -> Result<(), DecodeError> {
        let size = measure(psbt)?;
        self.inputs_outputs = self
            .inputs_outputs
            .checked_add(size.inputs_outputs)
            .filter(|count| *count <= MAX_PSBT_ITEMS)
            .ok_or(DecodeError::Limit(
                "aggregate PSBT inputs/outputs exceed the limit",
            ))?;
        self.map_pairs = self
            .map_pairs
            .checked_add(size.map_pairs)
            .filter(|count| *count <= MAX_PSBT_MAP_PAIRS)
            .ok_or(DecodeError::Limit(
                "aggregate PSBT map entries exceed the limit",
            ))?;
        Ok(())
    }
}

struct LimitedWriter(Vec<u8>);
impl bitcoin::io::Write for LimitedWriter {
    fn write(&mut self, bytes: &[u8]) -> bitcoin::io::Result<usize> {
        if self
            .0
            .len()
            .checked_add(bytes.len())
            .is_none_or(|size| size > MAX_PSBT_BYTES / 4 * 3)
        {
            return Err(bitcoin::io::ErrorKind::Other.into());
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> bitcoin::io::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PsbtSize {
    pub inputs_outputs: usize,
    pub map_pairs: usize,
}

/// Count the serialized map entries once for decoder and transform admission.
///
/// Values remain subject to the encoded byte ceiling; these counts do not
/// pretend to bound every allocation within the library parser.
pub(crate) fn measure(psbt: &Psbt) -> Result<PsbtSize, DecodeError> {
    let inputs_outputs = check_item_count(psbt.inputs.len(), psbt.outputs.len())?;
    if psbt.inputs.len() != psbt.unsigned_tx.input.len()
        || psbt.outputs.len() != psbt.unsigned_tx.output.len()
    {
        return Err(DecodeError::Field(
            "PSBT maps do not match the unsigned transaction".to_owned(),
        ));
    }
    let mut map_pairs = 1_usize;
    let mut add = |count: usize| -> Result<(), DecodeError> {
        map_pairs = map_pairs
            .checked_add(count)
            .filter(|count| *count <= MAX_PSBT_MAP_PAIRS)
            .ok_or(DecodeError::Limit("PSBT exceeds the map-entry limit"))?;
        Ok(())
    };
    for count in [
        usize::from(psbt.version != 0),
        psbt.xpub.len(),
        psbt.proprietary.len(),
        psbt.unknown.len(),
    ] {
        add(count)?;
    }
    for input in &psbt.inputs {
        for present in [
            input.non_witness_utxo.is_some(),
            input.witness_utxo.is_some(),
            input.sighash_type.is_some(),
            input.redeem_script.is_some(),
            input.witness_script.is_some(),
            input.final_script_sig.is_some(),
            input.final_script_witness.is_some(),
            input.tap_key_sig.is_some(),
            input.tap_internal_key.is_some(),
            input.tap_merkle_root.is_some(),
        ] {
            add(usize::from(present))?;
        }
        for count in [
            input.partial_sigs.len(),
            input.bip32_derivation.len(),
            input.ripemd160_preimages.len(),
            input.sha256_preimages.len(),
            input.hash160_preimages.len(),
            input.hash256_preimages.len(),
            input.tap_script_sigs.len(),
            input.tap_scripts.len(),
            input.tap_key_origins.len(),
            input.proprietary.len(),
            input.unknown.len(),
        ] {
            add(count)?;
        }
    }
    for output in &psbt.outputs {
        for present in [
            output.redeem_script.is_some(),
            output.witness_script.is_some(),
            output.tap_internal_key.is_some(),
            output.tap_tree.is_some(),
        ] {
            add(usize::from(present))?;
        }
        for count in [
            output.bip32_derivation.len(),
            output.tap_key_origins.len(),
            output.proprietary.len(),
            output.unknown.len(),
        ] {
            add(count)?;
        }
    }
    let size = PsbtSize {
        inputs_outputs,
        map_pairs,
    };
    if size.inputs_outputs > MAX_PSBT_ITEMS || size.map_pairs > MAX_PSBT_MAP_PAIRS {
        return Err(DecodeError::Limit("PSBT exceeds the structural limits"));
    }
    Ok(size)
}

/// Select supplied UTXO information with Core's non-witness precedence.
///
/// Call after shared admission. A present non-witness transaction never falls
/// back to witness data when its referenced output is absent; validation owns
/// that typed failure. The witness null sentinel is normalized during decode.
pub(crate) fn input_utxo(psbt: &Psbt, index: usize) -> Option<&bitcoin::TxOut> {
    let input = psbt.inputs.get(index)?;
    if let Some(tx) = &input.non_witness_utxo {
        let vout = usize::try_from(psbt.unsigned_tx.input.get(index)?.previous_output.vout).ok()?;
        tx.output.get(vout)
    } else {
        input.witness_utxo.as_ref()
    }
}

fn validate(psbt: &Psbt) -> Result<(), DecodeError> {
    validate_unknown_types(&psbt.unknown)?;
    for key in psbt.proprietary.keys() {
        proprietary_subtype(key)?;
    }
    for (index, (input, txin)) in psbt.inputs.iter().zip(&psbt.unsigned_tx.input).enumerate() {
        if let Some(utxo) = &input.non_witness_utxo {
            if utxo.compute_txid() != txin.previous_output.txid {
                return Err(DecodeError::UtxoHash);
            }
            if input_utxo(psbt, index).is_none() {
                return Err(DecodeError::UtxoIndex);
            }
        }
        validate_unknown_types(&input.unknown)?;
        for key in input.proprietary.keys() {
            proprietary_subtype(key)?;
        }
        validate_musig2(&input.unknown, true)?;
    }
    for output in &psbt.outputs {
        validate_unknown_types(&output.unknown)?;
        for key in output.proprietary.keys() {
            proprietary_subtype(key)?;
        }
        validate_musig2(&output.unknown, false)?;
    }
    Ok(())
}

pub(crate) fn is_musig2(key: &raw::Key, input: bool) -> bool {
    if input {
        matches!(key.type_value, 0x1a..=0x1c)
    } else {
        key.type_value == 0x08
    }
}

fn valid_compressed_key(key: &[u8]) -> bool {
    key.len() == 33 && bitcoin::secp256k1::PublicKey::from_slice(key).is_ok()
}

/// BIP373 fields survive in the library's unknown map; validate only their
/// already-decoded keys/values, without parsing another PSBT representation.
fn validate_musig2(fields: &BTreeMap<raw::Key, Vec<u8>>, input: bool) -> Result<(), DecodeError> {
    let context = if input { "Input" } else { "Output" };
    for (key, value) in fields.iter().filter(|(key, _)| is_musig2(key, input)) {
        if key.type_value == 0x1a || !input {
            if key.key.len() != 33 {
                return Err(DecodeError::Field(format!(
                    "{context} musig2 participants pubkeys aggregate key is not 34 bytes"
                )));
            }
            if !valid_compressed_key(&key.key) {
                return Err(DecodeError::Field(format!(
                    "{context} musig2 aggregate pubkey is invalid"
                )));
            }
            for participant in value.as_chunks::<33>().0 {
                if !valid_compressed_key(participant) {
                    return Err(DecodeError::Field(format!(
                        "{context} musig2 participant pubkey is invalid"
                    )));
                }
            }
            if !value.len().is_multiple_of(33) {
                return Err(DecodeError::Field(format!(
                    "{context} musig2 participants pubkeys value size is not a multiple of 33"
                )));
            }
        } else {
            let field = if key.type_value == 0x1b {
                "pubnonce"
            } else {
                "partial sig"
            };
            if !matches!(key.key.len(), 66 | 98) {
                return Err(DecodeError::Field(format!(
                    "Input musig2 {field} key is not expected size of 67 or 99 bytes"
                )));
            }
            if !valid_compressed_key(&key.key[33..66]) {
                return Err(DecodeError::Field(
                    "musig2 aggregate pubkey is invalid".to_owned(),
                ));
            }
            if !valid_compressed_key(&key.key[..33]) {
                return Err(DecodeError::Field(
                    "musig2 participant pubkey is invalid".to_owned(),
                ));
            }
            if key.type_value == 0x1b && value.len() != 66 {
                return Err(DecodeError::Field(
                    "Input musig2 pubnonce value is not 66 bytes".to_owned(),
                ));
            }
            if key.type_value == 0x1c && value.len() != 32 {
                return Err(DecodeError::Field(
                    "Size of value was not the stated size".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

/// Interpret a proprietary subtype through the existing `CompactSize` codec.
///
/// The library's u8 field retains the additional encoded bytes in its key tail. Interpret that one
/// already-decoded field through the library codec, preserving the full key.
pub(crate) fn proprietary_subtype(key: &raw::ProprietaryKey) -> Result<u64, DecodeError> {
    let mut bytes = vec![key.subtype];
    bytes.extend_from_slice(&key.key);
    core_compact_size(&mut bytes.as_slice())
}

fn validate_unknown_types(fields: &BTreeMap<raw::Key, Vec<u8>>) -> Result<(), DecodeError> {
    for key in fields.keys() {
        // Only the CompactSize type prefix is inspected. The library remains
        // the owner of the complete key/value map and its serialization.
        let mut prefix = [0_u8; 9];
        prefix[0] = key.type_value;
        let count = key.key.len().min(8);
        prefix[1..=count].copy_from_slice(&key.key[..count]);
        core_compact_size(&mut &prefix[..=count])?;
    }
    Ok(())
}

fn core_compact_size(bytes: &mut &[u8]) -> Result<u64, DecodeError> {
    use bitcoin::consensus::Decodable as _;
    let value = bitcoin::VarInt::consensus_decode(bytes)
        .map_err(|error| {
            let message = if matches!(error, bitcoin::consensus::encode::Error::NonMinimalVarInt) {
                "non-canonical ReadCompactSize()"
            } else {
                "SpanReader::read(): end of data"
            };
            DecodeError::Field(message.to_owned())
        })?
        .0;
    // Core serialize.h ReadCompactSize's default range check also applies
    // to PSBT key types and proprietary subtypes, not just vector lengths.
    if value > 0x0200_0000 {
        return Err(DecodeError::Field(
            "ReadCompactSize(): size too large".to_owned(),
        ));
    }
    Ok(value)
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn fixtures() -> serde_json::Value {
        serde_json::from_str(include_str!("../tests/data/psbt-codec-core-v31.1.json"))
            .expect("Core fixture JSON")
    }
    fn fixture(name: &str) -> String {
        fixtures()["cases"]
            .as_array()
            .expect("cases")
            .iter()
            .find(|case| case["name"] == name)
            .expect("fixture")["psbt"]
            .as_str()
            .expect("encoded")
            .to_owned()
    }

    #[test]
    fn core_fixture_acceptance_and_rejection_has_no_silent_extra_data() {
        let mut differences = Vec::new();
        for case in fixtures()["cases"].as_array().expect("cases") {
            let result = decode(case["psbt"].as_str().expect("encoded"));
            let expected = case["candidate_valid"]
                .as_bool()
                .unwrap_or_else(|| case["core_valid"].as_bool().expect("expectation"));
            if result.is_ok() != expected {
                differences.push(format!("{}: {result:?}", case["name"]));
            }
        }
        assert!(differences.is_empty(), "{}", differences.join("\n"));
    }

    #[test]
    fn witnessed_null_is_normalized_without_discarding_negative_nonwitness_outputs() {
        assert!(
            decode(&fixture("null-witness-utxo"))
                .expect("accepted null")
                .inputs[0]
                .witness_utxo
                .is_none()
        );
        let conflicting = decode(&fixture("conflicting-utxos"))
            .expect("conflicting supplied views remain accepted");
        assert_eq!(
            input_utxo(&conflicting, 0)
                .expect("nonwitness wins")
                .value
                .to_sat(),
            100_000
        );
        let negative =
            decode(&fixture("negative-nonwitness-utxo")).expect("negative prevtx accepted");
        assert_eq!(
            negative.inputs[0]
                .non_witness_utxo
                .as_ref()
                .expect("preserved prevtx")
                .output[0]
                .value
                .to_sat(),
            u64::MAX
        );
        let mut programmatic = decode(&fixture("a")).expect("blank");
        programmatic.inputs[0].witness_utxo = Some(bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(u64::MAX),
            script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x51]),
        });
        let encoded = encode(&programmatic).expect("Core normalization");
        assert!(
            programmatic.inputs[0].witness_utxo.is_some(),
            "encoding does not mutate caller state"
        );
        assert!(
            decode(&encoded).expect("canonical output").inputs[0]
                .witness_utxo
                .is_none()
        );
        assert!(
            decode(&encode(&negative).expect("encode"))
                .expect("decode")
                .inputs[0]
                .non_witness_utxo
                .is_some()
        );
    }

    #[test]
    fn typed_utxo_failures_preserve_the_legacy_rpc_boundary() {
        assert!(matches!(
            decode(&fixture("wrong-nonwitness-hash")),
            Err(DecodeError::UtxoHash)
        ));
        assert!(matches!(
            decode(&fixture("wrong-nonwitness-index")),
            Err(DecodeError::UtxoIndex)
        ));
        assert!(matches!(
            decode(&fixture("trailing-data")),
            Err(DecodeError::Trailing)
        ));
        let handler = crate::handlers::Handler::new(Arc::new(crate::context::Context::new()));
        for name in [
            "wrong-nonwitness-hash",
            "wrong-nonwitness-index",
            "trailing-data",
            "invalid-base64",
        ] {
            let encoded = fixture(name);
            for (method, params) in [
                ("combinepsbt", sonic_rs::json!([[encoded]])),
                ("finalizepsbt", sonic_rs::json!([encoded])),
            ] {
                let error = handler
                    .dispatch(method, &params)
                    .expect_err("strict rejection");
                assert_eq!(error.code(), RpcError::INVALID_PARAMS, "{method} {name}");
            }
        }
    }

    #[test]
    fn raw_default_rejection_does_not_reject_canonical_or_opaque_bytes() {
        for side in ["taproot", "tapscript"] {
            let error = decode(&fixture(&format!("probe-{side}-65-explicit-default")))
                .expect_err("must not change a supplied signature encoding");
            assert!(
                matches!(error, DecodeError::Field(message) if message.contains("explicit DEFAULT"))
            );
            let canonical = decode(&fixture(&format!("probe-{side}-64-control")))
                .expect("canonical DEFAULT accepted");
            decode(&encode(&canonical).expect("canonical output"))
                .expect("programmatic DEFAULT remains readable");
        }
        let mut opaque = decode(&fixture("a")).expect("base");
        let mut signature_like = vec![0x11; 65];
        signature_like[64] = 0;
        opaque.inputs[0].unknown.insert(
            raw::Key {
                type_value: 0x42,
                key: vec![0x13],
            },
            signature_like.clone(),
        );
        opaque.outputs[0].unknown.insert(
            raw::Key {
                type_value: 0x13,
                key: Vec::new(),
            },
            signature_like,
        );
        decode(&encode(&opaque).expect("opaque data"))
            .expect("only input signature fields checked");
        opaque.inputs[0].unknown.insert(
            raw::Key {
                type_value: 0x13,
                key: Vec::new(),
            },
            {
                let mut bytes = vec![0x11; 65];
                bytes[64] = 0;
                bytes
            },
        );
        assert!(
            encode(&opaque).is_err(),
            "reserved unknown keys cannot bypass output admission"
        );
    }

    #[test]
    fn encoder_cannot_emit_a_global_map_the_library_cannot_read() {
        let mut psbt = decode(&fixture("a")).expect("base");
        psbt.unknown.insert(
            raw::Key {
                type_value: 0x42,
                key: vec![1],
            },
            vec![1; bitcoin::consensus::encode::MAX_VEC_SIZE],
        );
        let error = encode(&psbt).expect_err("global map exceeds the library read ceiling");
        assert!(
            matches!(error,RpcError::InvalidParameter(message) if message=="PSBT output is not readable within library codec limits")
        );
    }

    #[test]
    fn structural_and_aggregate_budgets_apply_before_transform_assembly() {
        assert_eq!(
            check_item_count(MAX_PSBT_ITEMS, 0).expect("inclusive"),
            MAX_PSBT_ITEMS
        );
        assert!(check_item_count(MAX_PSBT_ITEMS, 1).is_err());
        assert!(check_item_count(usize::MAX, 1).is_err());
        let mut budget = PsbtBudget::default();
        let source = "A".repeat(MAX_PSBT_BYTES / 2);
        budget.add_encoded(&source).expect("half");
        budget.add_encoded(&source).expect("inclusive");
        assert!(budget.add_encoded("A").is_err());
        let handler = crate::handlers::Handler::new(Arc::new(crate::context::Context::new()));
        let mut sources = Vec::new();
        for index in 0..6_u8 {
            let mut psbt = decode(&fixture("a")).expect("base");
            psbt.unknown.insert(
                raw::Key {
                    type_value: 0x42,
                    key: vec![index],
                },
                vec![index; 2 * 1024 * 1024],
            );
            sources.push(encode(&psbt).expect("individual source within bounds"));
        }
        let error = handler
            .dispatch("combinepsbt", &sonic_rs::json!([sources]))
            .expect_err("direct call aggregate bound");
        assert_eq!(error.code(), RpcError::INVALID_PARAMS);
        assert!(
            error
                .to_string()
                .contains("combined PSBT exceeds RPC limits")
        );
    }
}
