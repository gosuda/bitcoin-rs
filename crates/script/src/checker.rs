use bitcoin_rs_primitives::{Amount, Hash256, Sighash, SighashCache, Tx, TxOut};
use secp256k1::{Message, PublicKey, XOnlyPublicKey, ecdsa::Signature as EcdsaSig};

use crate::eval::{OP_CODESEPARATOR, remove_all};
use crate::interpreter::{ScriptErrCode, ScriptError, VerifyFlags};
use crate::signature_cache::SignatureCache;

#[derive(Copy, Clone, Debug, PartialEq)]
pub(crate) enum SigVersion {
    Base,
    WitnessV0,
    Tapscript,
}

const LOCKTIME_THRESHOLD: u32 = 500_000_000;

const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;

const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000_ffff;

const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;

const SEQUENCE_FINAL: u32 = 0xffff_ffff;

const SIGHASH_ANYONECANPAY: u8 = 0x80;

pub(crate) struct TxSignatureChecker<'a> {
    tx: &'a Tx,
    input_index: usize,
    amount: Amount,
    prevouts: &'a [TxOut],
    cache: &'a SighashCache<'a>,
    sig_cache: Option<&'a SignatureCache>,
    annex: Option<Vec<u8>>,
}

impl<'a> TxSignatureChecker<'a> {
    #[must_use]
    pub(crate) fn new(
        tx: &'a Tx,
        input_index: usize,
        amount: Amount,
        prevouts: &'a [TxOut],
        cache: &'a SighashCache<'a>,
        sig_cache: Option<&'a SignatureCache>,
    ) -> Self {
        Self {
            tx,
            input_index,
            amount,
            prevouts,
            cache,
            sig_cache,
            annex: None,
        }
    }

    pub(crate) fn set_annex(&mut self, annex: Option<Vec<u8>>) {
        self.annex = annex;
    }

    pub(crate) fn check_ecdsa_signature(
        &self,
        sig: &[u8],
        pubkey: &[u8],
        script_code: &[u8],
        sigversion: SigVersion,
        flags: VerifyFlags,
    ) -> Result<bool, ScriptError> {
        check_signature_encoding(sig, flags)?;
        check_pubkey_encoding(pubkey, flags, sigversion)?;

        if sig.is_empty() {
            return Ok(false);
        }

        let Ok(secp_pubkey) = PublicKey::from_slice(pubkey) else {
            return Ok(false);
        };

        let Some((hashtype_byte, der_sig)) = sig.split_last() else {
            return Ok(false);
        };

        let Ok(mut ecdsa_sig) = EcdsaSig::from_der_lax(der_sig) else {
            return Ok(false);
        };
        ecdsa_sig.normalize_s();

        let sighash = match sigversion {
            SigVersion::Base => {
                let raw_hashtype = u32::from(*hashtype_byte);
                let cleaned = remove_all(script_code, &[OP_CODESEPARATOR]).0;
                self.cache
                    .legacy_signature_hash(self.input_index, &cleaned, raw_hashtype)
                    .map_err(|e| ScriptError::Verification(e.to_string()))?
            }
            SigVersion::WitnessV0 => self
                .cache
                .segwit_v0_signature_hash_raw(
                    self.input_index,
                    script_code,
                    self.amount,
                    u32::from(*hashtype_byte),
                )
                .map_err(|e| ScriptError::Verification(e.to_string()))?,
            SigVersion::Tapscript => {
                return Err(ScriptError::Verification(
                    "ECDSA signature check requested for tapscript".to_owned(),
                ));
            }
        };

        let message = Message::from_digest(*sighash.as_byte_array());
        if let Some(sig_cache) = self.sig_cache {
            let key = SignatureCache::ecdsa_key(sighash.as_byte_array(), sig, pubkey);
            if sig_cache.contains(&key) {
                return Ok(true);
            }
            let verified = secp256k1::SECP256K1
                .verify_ecdsa(&message, &ecdsa_sig, &secp_pubkey)
                .is_ok();
            if verified {
                sig_cache.insert(key);
            }
            return Ok(verified);
        }
        let verified = secp256k1::SECP256K1
            .verify_ecdsa(&message, &ecdsa_sig, &secp_pubkey)
            .is_ok();

        Ok(verified)
    }

    pub(crate) fn check_schnorr_signature(
        &self,
        sig: &[u8],
        pubkey: &[u8],
        leaf_hash: Option<&Hash256>,
        codesep_pos: u32,
    ) -> Result<bool, ScriptError> {
        if sig.is_empty() {
            return Ok(false);
        }

        if sig.len() != 64 && sig.len() != 65 {
            return Err(ScriptError::Invalid {
                code: ScriptErrCode::SchnorrSigSize,
            });
        }

        let (schnorr_sig_bytes, hashtype_byte) = if sig.len() == 65 {
            (&sig[..64], sig[64])
        } else {
            (sig, 0x00)
        };

        if sig.len() == 65 && hashtype_byte == 0x00 {
            return Err(ScriptError::Invalid {
                code: ScriptErrCode::SchnorrSigHashtype,
            });
        }

        let sighash_type =
            Sighash::from_consensus_u8(hashtype_byte).map_err(|_| ScriptError::Invalid {
                code: ScriptErrCode::SchnorrSigHashtype,
            })?;

        if pubkey.len() != 32 {
            return Err(ScriptError::Verification(
                "Schnorr public key must be 32 bytes".to_owned(),
            ));
        }

        let xonly_pubkey = XOnlyPublicKey::from_slice(pubkey)
            .map_err(|e| ScriptError::Verification(format!("invalid Schnorr public key: {e}")))?;

        let schnorr_sig =
            secp256k1::schnorr::Signature::from_slice(schnorr_sig_bytes).map_err(|_| {
                ScriptError::Invalid {
                    code: ScriptErrCode::SchnorrSig,
                }
            })?;

        let leaf_codesep = leaf_hash.map(|lh| (*lh, codesep_pos));
        let sighash = self
            .cache
            .taproot_signature_hash(
                self.input_index,
                self.prevouts,
                self.annex.as_deref(),
                leaf_codesep,
                sighash_type,
            )
            .map_err(|e| ScriptError::Verification(e.to_string()))?;

        let message = Message::from_digest(*sighash.as_byte_array());
        if let Some(sig_cache) = self.sig_cache {
            let key = SignatureCache::schnorr_key(sighash.as_byte_array(), sig, pubkey);
            if sig_cache.contains(&key) {
                return Ok(true);
            }
            return match secp256k1::SECP256K1.verify_schnorr(&schnorr_sig, &message, &xonly_pubkey)
            {
                Ok(()) => {
                    sig_cache.insert(key);
                    Ok(true)
                }
                Err(_) => Err(ScriptError::Invalid {
                    code: ScriptErrCode::SchnorrSig,
                }),
            };
        }
        secp256k1::SECP256K1
            .verify_schnorr(&schnorr_sig, &message, &xonly_pubkey)
            .map(|()| true)
            .map_err(|_| ScriptError::Invalid {
                code: ScriptErrCode::SchnorrSig,
            })
    }

    #[must_use]
    pub(crate) fn check_locktime(&self, locktime: i64) -> bool {
        let tx_locktime = i64::from(self.tx.lock_time.to_consensus());

        let same_type = (tx_locktime < i64::from(LOCKTIME_THRESHOLD))
            == (locktime < i64::from(LOCKTIME_THRESHOLD));
        if !same_type {
            return false;
        }

        if locktime > tx_locktime {
            return false;
        }

        let input = match self.tx.inputs.get(self.input_index) {
            Some(inp) => inp,
            None => return false,
        };
        if input.sequence.to_consensus() == SEQUENCE_FINAL {
            return false;
        }

        true
    }

    #[must_use]
    pub(crate) fn check_sequence(&self, sequence: i64) -> bool {
        let input = match self.tx.inputs.get(self.input_index) {
            Some(inp) => inp,
            None => return false,
        };
        let tx_sequence = i64::from(input.sequence.to_consensus());

        if self.tx.version < 2 {
            return false;
        }

        if (input.sequence.to_consensus() & SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0 {
            return false;
        }

        let mask = i64::from(SEQUENCE_LOCKTIME_TYPE_FLAG | SEQUENCE_LOCKTIME_MASK);
        let tx_masked = tx_sequence & mask;
        let seq_masked = sequence & mask;

        let same_type = (tx_masked < i64::from(SEQUENCE_LOCKTIME_TYPE_FLAG))
            == (seq_masked < i64::from(SEQUENCE_LOCKTIME_TYPE_FLAG));
        if !same_type {
            return false;
        }

        if seq_masked > tx_masked {
            return false;
        }

        true
    }
}

pub fn check_signature_encoding(sig: &[u8], flags: VerifyFlags) -> Result<(), ScriptError> {
    if sig.is_empty() {
        return Ok(());
    }

    let needs_der = flags.contains(VerifyFlags::DERSIG)
        || flags.contains(VerifyFlags::LOW_S)
        || flags.contains(VerifyFlags::STRICTENC);

    if needs_der && !is_valid_der_encoding(sig) {
        return Err(ScriptError::Invalid {
            code: ScriptErrCode::SigDer,
        });
    }

    if flags.contains(VerifyFlags::LOW_S) && !is_low_der_signature(sig) {
        return Err(ScriptError::Invalid {
            code: ScriptErrCode::SigHighS,
        });
    }

    if flags.contains(VerifyFlags::STRICTENC) && !is_defined_hashtype(sig) {
        return Err(ScriptError::Invalid {
            code: ScriptErrCode::SigHashtype,
        });
    }

    Ok(())
}

fn check_pubkey_encoding(
    pubkey: &[u8],
    flags: VerifyFlags,
    sigversion: SigVersion,
) -> Result<(), ScriptError> {
    if flags.contains(VerifyFlags::STRICTENC) && !is_compressed_or_uncompressed_pubkey(pubkey) {
        return Err(ScriptError::Invalid {
            code: ScriptErrCode::PubkeyType,
        });
    }

    if flags.contains(VerifyFlags::WITNESS_PUBKEYTYPE)
        && sigversion == SigVersion::WitnessV0
        && !is_compressed_pubkey(pubkey)
    {
        return Err(ScriptError::Invalid {
            code: ScriptErrCode::WitnessPubkeyType,
        });
    }

    Ok(())
}

fn is_valid_der_encoding(sig: &[u8]) -> bool {
    if sig.len() < 9 || sig.len() > 73 {
        return false;
    }

    if sig[0] != 0x30 {
        return false;
    }

    if usize::from(sig[1]) != sig.len() - 3 {
        return false;
    }

    let len_r = usize::from(sig[3]);
    if 5 + len_r >= sig.len() {
        return false;
    }

    let len_s = usize::from(sig[5 + len_r]);
    if len_r + len_s + 7 != sig.len() {
        return false;
    }

    if sig[2] != 0x02 {
        return false;
    }
    if len_r == 0 {
        return false;
    }
    if sig[4] & 0x80 != 0 {
        return false;
    }
    if len_r > 1 && sig[4] == 0x00 && sig[5] & 0x80 == 0 {
        return false;
    }

    if sig[len_r + 4] != 0x02 {
        return false;
    }
    if len_s == 0 {
        return false;
    }
    if sig[len_r + 6] & 0x80 != 0 {
        return false;
    }
    if len_s > 1 && sig[len_r + 6] == 0x00 && sig[len_r + 7] & 0x80 == 0 {
        return false;
    }

    true
}

fn is_low_der_signature(sig: &[u8]) -> bool {
    const HALF_ORDER: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b,
        0x20, 0xa0,
    ];

    if !is_valid_der_encoding(sig) {
        return false;
    }

    let Some((_, der)) = sig.split_last() else {
        return false;
    };

    let len_r = usize::from(der[3]);
    let s_start = 6 + len_r;
    let s_bytes = &der[s_start..];

    let s_stripped = s_bytes
        .iter()
        .copied()
        .skip_while(|&b| b == 0x00)
        .collect::<Vec<_>>();

    if s_stripped.is_empty() {
        return true;
    }

    if s_stripped.len() > 32 {
        return false;
    }
    if s_stripped.len() < 32 {
        return true;
    }

    s_stripped.as_slice() <= HALF_ORDER.as_slice()
}

fn is_defined_hashtype(sig: &[u8]) -> bool {
    let &hashtype = sig.last().unwrap_or(&0xff);
    let masked = hashtype & (!SIGHASH_ANYONECANPAY);
    (0x01..=0x03).contains(&masked)
}

fn is_compressed_or_uncompressed_pubkey(pubkey: &[u8]) -> bool {
    is_compressed_pubkey(pubkey) || (pubkey.len() == 65 && pubkey[0] == 0x04)
}

fn is_compressed_pubkey(pubkey: &[u8]) -> bool {
    pubkey.len() == 33 && (pubkey[0] == 0x02 || pubkey[0] == 0x03)
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test assertions")]
    use bitcoin::hex::FromHex;
    use bitcoin_rs_primitives::{
        Amount, Hash256, LockTime, OutPoint, Script, Sequence, SighashCache, Tx, TxIn, TxOut, Txid,
        Witness, deserialize,
    };
    use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _};

    use super::{
        LOCKTIME_THRESHOLD, SEQUENCE_FINAL, SEQUENCE_LOCKTIME_DISABLE_FLAG,
        SEQUENCE_LOCKTIME_TYPE_FLAG, SigVersion, TxSignatureChecker,
    };
    use crate::eval::{OP_CODESEPARATOR, remove_all};
    use crate::interpreter::{ScriptErrCode, ScriptError, VerifyFlags};

    fn make_tx(version: u32, lock_time: u32, sequence: u32) -> Tx {
        Tx {
            version,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid::default(), 0),
                script_sig: Script::new(),
                sequence: Sequence::from_consensus(sequence),
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: Script::new(),
            }],
            lock_time: LockTime::from_consensus(lock_time),
        }
    }

    fn make_prevouts() -> Vec<TxOut> {
        vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: Script::new(),
        }]
    }

    fn low_s_der(hashtype: u8) -> Vec<u8> {
        let mut sig = vec![0x30, 0x44, 0x02, 0x20];
        sig.extend_from_slice(&[0x01; 32]);
        sig.extend_from_slice(&[0x02, 0x20]);
        sig.extend_from_slice(&[0x01; 32]);
        sig.push(hashtype);
        sig
    }

    fn high_s_der() -> Vec<u8> {
        let mut sig = vec![0x30, 0x45, 0x02, 0x20];
        sig.extend_from_slice(&[0x01; 32]);
        sig.extend_from_slice(&[0x02, 0x21, 0x00, 0x80]);
        sig.extend_from_slice(&[0x00; 31]);
        sig.push(0x01);
        sig
    }

    fn invalid(code: ScriptErrCode) -> Result<bool, ScriptError> {
        Err(ScriptError::Invalid { code })
    }

    type EcdsaCase = (
        &'static str,
        Vec<u8>,
        Vec<u8>,
        SigVersion,
        VerifyFlags,
        Result<bool, ScriptError>,
    );

    fn ecdsa_encoding_cases() -> [EcdsaCase; 10] {
        const COMPRESSED: [u8; 33] = [0x02; 33];
        const UNCOMPRESSED: [u8; 65] = [0x04; 65];
        const BAD_PREFIX: [u8; 33] = [0x05; 33];
        let dersig = VerifyFlags::DERSIG;
        [
            (
                "DERSIG rejects a non-DER signature",
                vec![0x00, 0x01, 0x02, 0x03, 0x01],
                COMPRESSED.to_vec(),
                SigVersion::Base,
                dersig,
                invalid(ScriptErrCode::SigDer),
            ),
            (
                "LOW_S rejects a high-S signature",
                high_s_der(),
                COMPRESSED.to_vec(),
                SigVersion::Base,
                dersig.union(VerifyFlags::LOW_S),
                invalid(ScriptErrCode::SigHighS),
            ),
            (
                "STRICTENC rejects an undefined hashtype",
                low_s_der(0x05),
                COMPRESSED.to_vec(),
                SigVersion::Base,
                dersig.union(VerifyFlags::STRICTENC),
                invalid(ScriptErrCode::SigHashtype),
            ),
            (
                "STRICTENC rejects an unknown pubkey prefix",
                low_s_der(0x01),
                BAD_PREFIX.to_vec(),
                SigVersion::Base,
                dersig.union(VerifyFlags::STRICTENC),
                invalid(ScriptErrCode::PubkeyType),
            ),
            (
                "WITNESS_PUBKEYTYPE rejects an uncompressed key in segwit",
                low_s_der(0x01),
                UNCOMPRESSED.to_vec(),
                SigVersion::WitnessV0,
                dersig.union(VerifyFlags::WITNESS_PUBKEYTYPE),
                invalid(ScriptErrCode::WitnessPubkeyType),
            ),
            (
                "an uncompressed key is fine in segwit without the flag",
                low_s_der(0x01),
                UNCOMPRESSED.to_vec(),
                SigVersion::WitnessV0,
                dersig,
                Ok(false),
            ),
            (
                "an empty signature is a clean false under DERSIG",
                Vec::new(),
                COMPRESSED.to_vec(),
                SigVersion::Base,
                dersig,
                Ok(false),
            ),
            (
                "an empty signature is a clean false under NULLFAIL",
                Vec::new(),
                COMPRESSED.to_vec(),
                SigVersion::Base,
                dersig.union(VerifyFlags::NULLFAIL),
                Ok(false),
            ),
            (
                "a failing signature is false without NULLFAIL",
                low_s_der(0x01),
                COMPRESSED.to_vec(),
                SigVersion::Base,
                dersig.union(VerifyFlags::LOW_S),
                Ok(false),
            ),
            (
                "the checker does not enforce NULLFAIL for a failing signature",
                low_s_der(0x01),
                COMPRESSED.to_vec(),
                SigVersion::Base,
                dersig
                    .union(VerifyFlags::LOW_S)
                    .union(VerifyFlags::NULLFAIL),
                Ok(false),
            ),
        ]
    }

    #[test]
    fn ecdsa_encoding_rules_match_core_per_flag() {
        for (name, sig, pubkey, sigversion, flags, expected) in ecdsa_encoding_cases() {
            for script_code in [[].as_slice(), &[0x51]] {
                let tx = make_tx(2, 0, SEQUENCE_FINAL);
                let prevouts = make_prevouts();
                let cache = SighashCache::new(&tx);
                let checker = TxSignatureChecker::new(
                    &tx,
                    0,
                    Amount::from_sat(50_000),
                    &prevouts,
                    &cache,
                    None,
                );
                let got =
                    checker.check_ecdsa_signature(&sig, &pubkey, script_code, sigversion, flags);
                assert_eq!(got, expected, "{name}");
            }
        }
    }

    #[test]
    fn check_locktime_follows_bip65() {
        let timestamp = i64::from(LOCKTIME_THRESHOLD) + 100;
        let cases = [
            (
                "a lower block-height locktime is satisfied",
                100_u32,
                0_u32,
                50_i64,
                true,
            ),
            (
                "an equal block-height locktime is satisfied",
                100,
                0,
                100,
                true,
            ),
            (
                "a locktime above the transaction's fails",
                100,
                0,
                101,
                false,
            ),
            (
                "a timestamp request against a height locktime fails",
                100,
                0,
                timestamp,
                false,
            ),
            (
                "a height request against a timestamp locktime fails",
                u32::try_from(timestamp).unwrap_or(0),
                0,
                50,
                false,
            ),
            ("a finalized input fails", 100, SEQUENCE_FINAL, 50, false),
        ];

        for (name, tx_locktime, sequence, required, expected) in cases {
            let tx = make_tx(2, tx_locktime, sequence);
            let prevouts = make_prevouts();
            let cache = SighashCache::new(&tx);
            let checker =
                TxSignatureChecker::new(&tx, 0, Amount::from_sat(50_000), &prevouts, &cache, None);
            assert_eq!(checker.check_locktime(required), expected, "{name}");
        }
    }

    #[test]
    fn check_sequence_follows_bip112() {
        let cases = [
            (
                "a lower relative locktime is satisfied",
                2_u32,
                100_u32,
                50_i64,
                true,
            ),
            ("an equal relative locktime is satisfied", 2, 100, 100, true),
            (
                "a relative locktime above the input's fails",
                2,
                100,
                101,
                false,
            ),
            ("version 1 disables relative locktime", 1, 100, 50, false),
            (
                "the input's disable bit fails the check",
                2,
                0x64 | SEQUENCE_LOCKTIME_DISABLE_FLAG,
                50,
                false,
            ),
            (
                "a time-based request against a height-based input fails",
                2,
                100,
                i64::from(SEQUENCE_LOCKTIME_TYPE_FLAG) + 50,
                false,
            ),
        ];

        for (name, version, sequence, required, expected) in cases {
            let tx = make_tx(version, 0, sequence);
            let prevouts = make_prevouts();
            let cache = SighashCache::new(&tx);
            let checker =
                TxSignatureChecker::new(&tx, 0, Amount::from_sat(50_000), &prevouts, &cache, None);
            assert_eq!(checker.check_sequence(required), expected, "{name}");
        }
    }

    #[test]
    fn sighash_json_corpus_legacy_path() {
        let corpus = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../consensus/tests/vectors/sighash.json");
        let json_str = std::fs::read_to_string(&corpus).unwrap_or_else(|error| {
            panic!("sighash.json unreadable at {}: {error}", corpus.display())
        });
        let json_str = json_str.as_str();
        let data: sonic_rs::Value =
            sonic_rs::from_str(json_str).unwrap_or_else(|e| panic!("sighash.json parse: {e}"));

        let rows = data.as_array().expect("sighash.json is an array");
        let mut tested = 0_u32;

        for row in rows {
            let Some(arr) = row.as_array().filter(|a| a.len() == 5) else {
                continue;
            };

            let tx_hex = arr
                .first()
                .and_then(sonic_rs::Value::as_str)
                .expect("tx hex");
            let script_hex = arr
                .get(1)
                .and_then(sonic_rs::Value::as_str)
                .expect("script hex");
            let input_index = usize::try_from(
                arr.get(2)
                    .and_then(sonic_rs::Value::as_u64)
                    .expect("input index"),
            )
            .expect("input index fits in usize");
            let hashtype_raw = arr
                .get(3)
                .and_then(sonic_rs::Value::as_i64)
                .expect("hashtype");
            let expected_hex = arr
                .get(4)
                .and_then(sonic_rs::Value::as_str)
                .expect("expected hash");

            let tx_bytes = hex_decode(tx_hex);
            let tx = deserialize::<Tx>(&tx_bytes)
                .unwrap_or_else(|e| panic!("tx decode at row {tested}: {e}"));

            let script_code = remove_all(&hex_decode(script_hex), &[OP_CODESEPARATOR]).0;

            #[expect(
                clippy::as_conversions,
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "Core casts int nHashType to uint32_t (bit-preserving)"
            )]
            let hashtype_u32 = hashtype_raw as i32 as u32;

            let cache = SighashCache::new(&tx);
            let sighash = cache
                .legacy_signature_hash(input_index, &script_code, hashtype_u32)
                .unwrap_or_else(|e| panic!("legacy sighash at row {tested}: {e}"));

            let expected = Hash256::from_str_be(expected_hex)
                .unwrap_or_else(|e| panic!("expected hash parse at row {tested}: {e}"));

            assert_eq!(
                sighash.to_le_bytes(),
                expected.to_le_bytes(),
                "sighash mismatch at row {tested} (hashtype={hashtype_raw:#x}, index={input_index})"
            );

            tested += 1;
        }

        assert!(tested > 0, "no sighash.json rows were tested");
    }

    #[test]
    fn script_err_code_display_matches_core_names() {
        use super::super::interpreter::ScriptErrCode as E;
        assert_eq!(E::EvalFalse.to_string(), "EVAL_FALSE");
        assert_eq!(E::SigDer.to_string(), "SIG_DER");
        assert_eq!(
            E::WitnessProgramMismatch.to_string(),
            "WITNESS_PROGRAM_MISMATCH"
        );
        assert_eq!(E::SigHighS.to_string(), "SIG_HIGH_S");
        assert_eq!(E::SigNullFail.to_string(), "SIG_NULLFAIL");
        assert_eq!(E::SchnorrSig.to_string(), "SCHNORR_SIG");
        assert_eq!(E::ScriptNum.to_string(), "SCRIPTNUM");
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        Vec::from_hex(s).unwrap_or_else(|error| panic!("bad hex: {error}"))
    }
}
