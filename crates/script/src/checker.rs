//! Transaction signature checker: ECDSA, Schnorr, locktime, and sequence verification.
//!
//! Implements the signature-checking layer the script evaluator calls. Every digest
//! is routed through the existing [`SighashCache`] engine; ECDSA through `secp256k1`,
//! Schnorr through `secp256k1`'s Schnorr API. Encoding enforcement (strict DER, low-S,
//! hashtype validity, pubkey encoding, `NULLFAIL`) is driven by [`VerifyFlags`].
//!
//! Behavioral authority: `.references/bitcoin/src/script/interpreter.cpp`
//! (`CheckSignatureEncoding`, `CheckPubKeyEncoding`, `IsLowDERSignature`,
//! `CheckLockTime`, `CheckSequence`).

use bitcoin_rs_primitives::{Hash256, Sighash, SighashCache, SighashError, Tx, TxOut};
use secp256k1::{Message, PublicKey, XOnlyPublicKey, ecdsa::Signature as EcdsaSig};

use crate::interpreter::{ScriptErrCode, ScriptError, VerifyFlags};

/// Signature version context: which sighash algorithm and encoding rules apply.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum SigVersion {
    /// Pre-segwit legacy signatures (double-SHA256 legacy sighash).
    Base,
    /// Segwit v0 signatures (BIP143).
    WitnessV0,
    /// Taproot key-path signatures (BIP341).
    Taproot,
    /// Taproot script-path signatures (BIP342).
    Tapscript,
}

/// BIP65 locktime threshold: values below this are block heights, values at or
/// above are Unix timestamps (median-time-past).
const LOCKTIME_THRESHOLD: u32 = 500_000_000;

/// BIP112 sequence-type flag: bit 22 of the sequence field.
const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;

/// BIP112 sequence lock-time mask: the low 16 bits carry the relative lock value.
const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000_ffff;

/// BIP112 disable flag: bit 31 of the sequence field disables relative locktime.
const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;

/// The sequence value that marks an input as finalized (disables locktime checks).
const SEQUENCE_FINAL: u32 = 0xffff_ffff;

/// `SIGHASH_ANYONECANPAY` bit mask for legacy hashtype validation.
const SIGHASH_ANYONECANPAY: u8 = 0x80;

/// Transaction signature checker that holds a transaction, input index, amount,
/// prevouts, and a lazily-initialized sighash cache.
pub struct TxSignatureChecker<'a> {
    tx: &'a Tx,
    input_index: usize,
    amount: u64,
    prevouts: &'a [TxOut],
    cache: SighashCache<'a>,
    /// Raw taproot annex bytes, when present (BIP341). Used by
    /// `check_schnorr_signature` to commit the annex to the sighash.
    annex: Option<Vec<u8>>,
}

/// Removes `OP_CODESEPARATOR` (0xab) opcodes from a script, matching Core's
/// `CTransactionSignatureSerializer::SerializeScriptCode`. Bytes inside data
/// pushes are preserved. The legacy sighash must exclude CS opcode bytes.
fn remove_codeseparators(script: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(script.len());
    let mut pos = 0;
    while pos < script.len() {
        let op = script[pos];
        if op == 0xab {
            // OP_CODESEPARATOR: skip this single byte.
            pos += 1;
        } else if (0x01..=0x4b).contains(&op) {
            // Direct push: copy the opcode and the data bytes.
            let end = pos + 1 + usize::from(op);
            out.extend_from_slice(&script[pos..end.min(script.len())]);
            pos = end;
        } else if op == 0x4c {
            // OP_PUSHDATA1: next byte is length.
            let len_pos = pos + 1;
            let len = script.get(len_pos).copied().unwrap_or(0);
            let end = len_pos + 1 + usize::from(len);
            out.extend_from_slice(&script[pos..end.min(script.len())]);
            pos = end;
        } else if op == 0x4d {
            // OP_PUSHDATA2: next 2 bytes are length (LE).
            let len_pos = pos + 1;
            let len = u16::from_le_bytes([
                script.get(len_pos).copied().unwrap_or(0),
                script.get(len_pos + 1).copied().unwrap_or(0),
            ]);
            let end = len_pos + 2 + usize::from(len);
            out.extend_from_slice(&script[pos..end.min(script.len())]);
            pos = end;
        } else if op == 0x4e {
            // OP_PUSHDATA4: next 4 bytes are length (LE).
            let len_pos = pos + 1;
            let len = u32::from_le_bytes([
                script.get(len_pos).copied().unwrap_or(0),
                script.get(len_pos + 1).copied().unwrap_or(0),
                script.get(len_pos + 2).copied().unwrap_or(0),
                script.get(len_pos + 3).copied().unwrap_or(0),
            ]);
            let end = len_pos + 4 + usize::try_from(len).unwrap_or(usize::MAX);
            out.extend_from_slice(&script[pos..end.min(script.len())]);
            pos = end;
        } else {
            // Other opcode (including OP_0 = 0x00): copy single byte.
            out.push(op);
            pos += 1;
        }
    }
    out
}

impl<'a> TxSignatureChecker<'a> {
    /// Builds a checker for one input of `tx`, with `prevouts` covering every
    /// input so taproot sighashes can commit to all spent outputs.
    #[must_use]
    pub fn new(tx: &'a Tx, input_index: usize, amount: u64, prevouts: &'a [TxOut]) -> Self {
        Self::with_cache(tx, input_index, amount, prevouts, SighashCache::new(tx))
    }

    /// Builds a checker that reuses a caller-filled [`SighashCache`].
    ///
    /// The cache must have been constructed over the same `tx`. Apply-path
    /// verification precomputes midstates once per transaction and clones that
    /// cache into each input checker.
    #[must_use]
    pub fn with_cache(
        tx: &'a Tx,
        input_index: usize,
        amount: u64,
        prevouts: &'a [TxOut],
        cache: SighashCache<'a>,
    ) -> Self {
        Self {
            tx,
            input_index,
            amount,
            prevouts,
            cache,
            annex: None,
        }
    }

    /// Sets the taproot annex for BIP341 sighash commitment.
    ///
    /// The driver calls this after stripping an annex from the witness stack
    /// so that subsequent Schnorr signature checks commit to the annex.
    pub fn set_annex(&mut self, annex: Option<Vec<u8>>) {
        self.annex = annex;
    }

    /// Verifies an ECDSA signature against the appropriate sighash.
    ///
    /// Enforces strict DER (`DERSIG`), low-S (`LOW_S`), hashtype validity and
    /// pubkey encoding (`STRICTENC`), compressed-only pubkeys in segwit
    /// (`WITNESS_PUBKEYTYPE`). `NULLFAIL` is enforced by the callers
    /// (`eval_checksig` / `check_multisig` cleanup), not here.
    ///
    /// Returns `Ok(true)` when the signature is valid, `Ok(false)` when it is
    /// empty (clean failure), and `Err` when encoding or verification fails
    /// under the active flags.
    pub fn check_ecdsa_signature(
        &mut self,
        sig: &[u8],
        pubkey: &[u8],
        script_code: &[u8],
        sigversion: SigVersion,
        flags: VerifyFlags,
    ) -> Result<bool, ScriptError> {
        // NULLFAIL: empty signature is a clean false, not an error.
        if sig.is_empty() {
            return Ok(false);
        }

        // Encoding checks driven by flags.
        check_signature_encoding(sig, flags)?;
        check_pubkey_encoding(pubkey, flags, sigversion)?;

        // Parse the pubkey; an invalid pubkey is a clean false (not an error)
        // matching Core's `CPubKey::IsValid()` returning false.
        let Ok(secp_pubkey) = PublicKey::from_slice(pubkey) else {
            return Ok(false);
        };

        // Split the hashtype byte from the DER signature (sig is non-empty here).
        let Some((hashtype_byte, der_sig)) = sig.split_last() else {
            return Ok(false);
        };

        // Parse the DER portion using lax DER parsing (Core's
        // `ecdsa_signature_parse_der_lax`), then normalize to low-S before
        // verification (Core's `secp256k1_ecdsa_signature_normalize`). Strict
        // DER enforcement is handled separately by `check_signature_encoding`
        // under the DERSIG flag; the verification path itself always uses lax
        // parsing so pre-BIP66 signatures still verify. Invalid DER is a
        // clean false.
        let Ok(mut ecdsa_sig) = EcdsaSig::from_der_lax(der_sig) else {
            return Ok(false);
        };
        ecdsa_sig.normalize_s();

        // Compute the sighash for the appropriate version.
        // Core's CTransactionSignatureSerializer::SerializeScriptCode removes
        // OP_CODESEPARATOR (0xab) opcode bytes from the scriptCode before
        // hashing. Segwit v0 uses BIP143 which does not have this step.
        let sighash = match sigversion {
            SigVersion::Base => {
                let raw_hashtype = u32::from(*hashtype_byte);
                let cleaned = remove_codeseparators(script_code);
                self.cache
                    .legacy_signature_hash(self.input_index, &cleaned, raw_hashtype)
                    .map_err(|e| sighash_to_script_error(&e))?
            }
            SigVersion::WitnessV0 => {
                let sighash_type = ecdsa_hashtype_from_byte(*hashtype_byte)?;
                self.cache
                    .segwit_v0_signature_hash(
                        self.input_index,
                        script_code,
                        self.amount,
                        sighash_type,
                    )
                    .map_err(|e| sighash_to_script_error(&e))?
            }
            SigVersion::Taproot | SigVersion::Tapscript => {
                // ECDSA is not used in taproot/tapscript; this is a caller error.
                return Err(ScriptError::Verification(
                    "ECDSA signature check requested for taproot/tapscript".to_owned(),
                ));
            }
        };

        let message = Message::from_digest(*sighash.as_byte_array());
        // One process-wide context: constructing `verification_only()` per
        // signature rebuilds secp256k1's verification tables on every CHECKSIG.
        let verified = secp256k1::SECP256K1
            .verify_ecdsa(&message, &ecdsa_sig, &secp_pubkey)
            .is_ok();

        // NULLFAIL is enforced by the callers (eval_checksig for CHECKSIG,
        // check_multisig cleanup for CHECKMULTISIG), matching Core where
        // CheckECDSASignature returns false without inspecting NULLFAIL.
        // A sig that fails against one pubkey may succeed against another in
        // multisig; an internal NULLFAIL check would fire prematurely.

        Ok(verified)
    }

    /// Verifies a Schnorr signature against the BIP341/BIP342 sighash.
    ///
    /// `leaf_hash` is `Some` for tapscript (script-path) spends and `None` for
    /// key-path spends. `codesep_pos` is the position of the last
    /// `OP_CODESEPARATOR` (or `CODESEPARATOR_POSITION` when none executed).
    ///
    /// Returns `Ok(true)` when valid, `Ok(false)` when the signature is empty
    /// (tapscript empty-sig convention), and `Err` for size/hashtype/verification
    /// failures.
    pub fn check_schnorr_signature(
        &mut self,
        sig: &[u8],
        pubkey: &[u8],
        sigversion: SigVersion,
        leaf_hash: Option<&Hash256>,
        codesep_pos: u32,
    ) -> Result<bool, ScriptError> {
        // Schnorr is only valid for taproot/tapscript.
        if sigversion != SigVersion::Taproot && sigversion != SigVersion::Tapscript {
            return Err(ScriptError::Verification(
                "Schnorr signature check requires taproot or tapscript version".to_owned(),
            ));
        }

        // Empty signature: in tapscript this is a clean false (invalid but not
        // an error); in key-path it's an error (wrong size).
        if sig.is_empty() {
            if sigversion == SigVersion::Tapscript {
                return Ok(false);
            }
            return Err(ScriptError::Invalid {
                code: ScriptErrCode::SchnorrSigSize,
            });
        }

        // Schnorr signatures are 64 or 65 bytes.
        if sig.len() != 64 && sig.len() != 65 {
            return Err(ScriptError::Invalid {
                code: ScriptErrCode::SchnorrSigSize,
            });
        }

        // Parse the hashtype from the optional 65th byte (length is 64 or 65 here).
        let (schnorr_sig_bytes, hashtype_byte) = if sig.len() == 65 {
            (&sig[..64], sig[64])
        } else {
            (sig, 0x00) // SIGHASH_DEFAULT (64-byte sig)
        };

        // A 65-byte signature with SIGHASH_DEFAULT (0x00) is invalid.
        if sig.len() == 65 && hashtype_byte == 0x00 {
            return Err(ScriptError::Invalid {
                code: ScriptErrCode::SchnorrSigHashtype,
            });
        }

        let sighash_type =
            Sighash::from_consensus_u8(hashtype_byte).map_err(|_| ScriptError::Invalid {
                code: ScriptErrCode::SchnorrSigHashtype,
            })?;

        // Parse the x-only public key (32 bytes).
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

        // Compute the BIP341/BIP342 sighash.
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
            .map_err(|e| sighash_to_script_error(&e))?;

        let message = Message::from_digest(*sighash.as_byte_array());
        secp256k1::SECP256K1
            .verify_schnorr(&schnorr_sig, &message, &xonly_pubkey)
            .map(|()| true)
            .map_err(|_| ScriptError::Invalid {
                code: ScriptErrCode::SchnorrSig,
            })
    }

    /// BIP65 `OP_CHECKLOCKTIMEVERIFY`: compares `locktime` against the
    /// transaction's nLockTime.
    ///
    /// Returns `true` when the locktime is satisfied: the types match
    /// (both block-height or both timestamp), `locktime <= tx.lock_time`,
    /// and the input's sequence is not `SEQUENCE_FINAL`.
    #[must_use]
    pub fn check_locktime(&self, locktime: i64) -> bool {
        let tx_locktime = i64::from(self.tx.lock_time);

        // Both must be the same type: below threshold = block height,
        // at or above = timestamp.
        let same_type = (tx_locktime < i64::from(LOCKTIME_THRESHOLD))
            == (locktime < i64::from(LOCKTIME_THRESHOLD));
        if !same_type {
            return false;
        }

        // The locktime must not be in the future.
        if locktime > tx_locktime {
            return false;
        }

        // The input must not be finalized (sequence == SEQUENCE_FINAL disables
        // locktime checks for that input).
        let input = match self.tx.inputs.get(self.input_index) {
            Some(inp) => inp,
            None => return false,
        };
        if input.sequence == SEQUENCE_FINAL {
            return false;
        }

        true
    }

    /// BIP112 `OP_CHECKSEQUENCEVERIFY`: compares `sequence` against the
    /// input's own nSequence.
    ///
    /// Returns `true` when the relative locktime is satisfied: the transaction
    /// version is >= 2, the input's sequence disable bit is not set, the types
    /// match (both block-height or both time-based), and the masked `sequence`
    /// is <= the masked input sequence.
    #[must_use]
    pub fn check_sequence(&self, sequence: i64) -> bool {
        let input = match self.tx.inputs.get(self.input_index) {
            Some(inp) => inp,
            None => return false,
        };
        let tx_sequence = i64::from(input.sequence);

        // Transaction version must be >= 2 for BIP68 rules. Core stores
        // version as uint32_t, so 0xffffffff is a large positive number, not
        // -1; compare as unsigned (bit-preserving) to match.
        #[expect(
            clippy::as_conversions,
            clippy::cast_sign_loss,
            reason = "Core stores tx version as uint32_t; bit-preserving cast to u32"
        )]
        let version_u32 = self.tx.version as u32;
        if version_u32 < 2 {
            return false;
        }

        // If the input's own sequence has the disable bit set, CSV cannot
        // be used to get around it.
        if (input.sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0 {
            return false;
        }

        // Mask off non-consensus bits before comparing.
        let mask = i64::from(SEQUENCE_LOCKTIME_TYPE_FLAG | SEQUENCE_LOCKTIME_MASK);
        let tx_masked = tx_sequence & mask;
        let seq_masked = sequence & mask;

        // Both must be the same type: below TYPE_FLAG = block height,
        // at or above = time-based.
        let same_type = (tx_masked < i64::from(SEQUENCE_LOCKTIME_TYPE_FLAG))
            == (seq_masked < i64::from(SEQUENCE_LOCKTIME_TYPE_FLAG));
        if !same_type {
            return false;
        }

        // The required sequence must not exceed the input's.
        if seq_masked > tx_masked {
            return false;
        }

        true
    }
}

// ---------------------------------------------------------------------------
// Encoding checks (mirrors Core's CheckSignatureEncoding / CheckPubKeyEncoding)
// ---------------------------------------------------------------------------

/// Checks signature encoding per Core's `CheckSignatureEncoding`.
///
/// Empty signatures are allowed (clean false). Under `DERSIG`, `LOW_S`, or
/// `STRICTENC`, the signature must be valid DER. Under `LOW_S`, the S value
/// must be low. Under `STRICTENC`, the hashtype must be defined.
fn check_signature_encoding(sig: &[u8], flags: VerifyFlags) -> Result<(), ScriptError> {
    // Empty signature is always allowed (not strictly DER, but valid for
    // CHECK(MULTI)SIG dummy / null-fail purposes).
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

/// Checks public key encoding per Core's `CheckPubKeyEncoding`.
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

    // Only compressed keys are accepted in segwit v0.
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

/// Core's `IsValidSignatureEncoding`: validates the DER structure of a
/// signature including the trailing hashtype byte.
fn is_valid_der_encoding(sig: &[u8]) -> bool {
    // Minimum and maximum size constraints (DER body + hashtype byte).
    // Core checks sig.size() < 9 and sig.size() > 73.
    if sig.len() < 9 || sig.len() > 73 {
        return false;
    }

    // A signature is of type 0x30 (compound).
    if sig[0] != 0x30 {
        return false;
    }

    // Make sure the length covers the entire signature (excluding the
    // compound type byte, length byte, and trailing hashtype byte).
    if usize::from(sig[1]) != sig.len() - 3 {
        return false;
    }

    // Extract the length of the R element.
    let len_r = usize::from(sig[3]);

    // Make sure the length of the S element is still inside the signature.
    if 5 + len_r >= sig.len() {
        return false;
    }

    // Extract the length of the S element.
    let len_s = usize::from(sig[5 + len_r]);

    // Verify that the length of the signature matches the sum of the
    // length of the elements.
    if len_r + len_s + 7 != sig.len() {
        return false;
    }

    // Check whether the R element is an integer.
    if sig[2] != 0x02 {
        return false;
    }

    // Zero-length integers are not allowed for R.
    if len_r == 0 {
        return false;
    }

    // Negative numbers are not allowed for R.
    if sig[4] & 0x80 != 0 {
        return false;
    }

    // Null bytes at the start of R are not allowed, unless R would
    // otherwise be interpreted as a negative number.
    if len_r > 1 && sig[4] == 0x00 && sig[5] & 0x80 == 0 {
        return false;
    }

    // Check whether the S element is an integer.
    if sig[len_r + 4] != 0x02 {
        return false;
    }

    // Zero-length integers are not allowed for S.
    if len_s == 0 {
        return false;
    }

    // Negative numbers are not allowed for S.
    if sig[len_r + 6] & 0x80 != 0 {
        return false;
    }

    // Null bytes at the start of S are not allowed, unless S would
    // otherwise be interpreted as a negative number.
    if len_s > 1 && sig[len_r + 6] == 0x00 && sig[len_r + 7] & 0x80 == 0 {
        return false;
    }

    true
}

/// Core's `IsLowDERSignature`: checks that the S value is at most half the
fn is_low_der_signature(sig: &[u8]) -> bool {
    // secp256k1's group order / 2 in big-endian:
    // n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    // n/2 = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
    const HALF_ORDER: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b,
        0x20, 0xa0,
    ];

    if !is_valid_der_encoding(sig) {
        return false;
    }

    // Strip the hashtype byte (sig is non-empty — checked by is_valid_der_encoding).
    let Some((_, der)) = sig.split_last() else {
        return false;
    };

    // Extract S from the DER: sig[0]=0x30, sig[1]=len, sig[2]=0x02, sig[3]=lenR,
    // sig[4..4+lenR]=R, sig[4+lenR]=0x02, sig[5+lenR]=lenS,
    // sig[6+lenR..6+lenR+lenS]=S
    let len_r = usize::from(der[3]);
    let s_start = 6 + len_r;
    let s_bytes = &der[s_start..];

    // The S value may have a leading zero byte for sign padding.
    // Strip leading zeros to get the raw big-endian integer.
    let s_stripped = s_bytes
        .iter()
        .copied()
        .skip_while(|&b| b == 0x00)
        .collect::<Vec<_>>();

    // If S is all zeros, it's low.
    if s_stripped.is_empty() {
        return true;
    }

    // Compare against half order (big-endian).
    if s_stripped.len() > 32 {
        return false;
    }
    if s_stripped.len() < 32 {
        return true;
    }

    s_stripped.as_slice() <= HALF_ORDER.as_slice()
}

/// Core's `IsDefinedHashtypeSignature`: checks that the hashtype byte
/// (ignoring `ANYONECANPAY`) is in the range `SIGHASH_ALL..=SIGHASH_SINGLE`.
fn is_defined_hashtype(sig: &[u8]) -> bool {
    let &hashtype = sig.last().unwrap_or(&0xff);
    let masked = hashtype & (!SIGHASH_ANYONECANPAY);
    // SIGHASH_ALL = 0x01, SIGHASH_SINGLE = 0x03
    (0x01..=0x03).contains(&masked)
}

/// Core's `IsCompressedOrUncompressedPubKey`.
fn is_compressed_or_uncompressed_pubkey(pubkey: &[u8]) -> bool {
    // COMPRESSED_SIZE = 33
    if pubkey.len() < 33 {
        return false;
    }
    match pubkey[0] {
        0x04 => pubkey.len() == 65,        // SIZE = 65
        0x02 | 0x03 => pubkey.len() == 33, // COMPRESSED_SIZE = 33
        _ => false,
    }
}

/// Core's `IsCompressedPubKey`.
fn is_compressed_pubkey(pubkey: &[u8]) -> bool {
    pubkey.len() == 33 && (pubkey[0] == 0x02 || pubkey[0] == 0x03)
}

/// Converts a legacy hashtype byte to a [`Sighash`] for segwit v0.
fn ecdsa_hashtype_from_byte(byte: u8) -> Result<Sighash, ScriptError> {
    match byte {
        0x01 => Ok(Sighash::All),
        0x02 => Ok(Sighash::None),
        0x03 => Ok(Sighash::Single),
        0x81 => Ok(Sighash::AllAnyoneCanPay),
        0x82 => Ok(Sighash::NoneAnyoneCanPay),
        0x83 => Ok(Sighash::SingleAnyoneCanPay),
        _ => Err(ScriptError::Invalid {
            code: ScriptErrCode::SigHashtype,
        }),
    }
}

/// Converts a [`SighashError`] to a [`ScriptError`].
fn sighash_to_script_error(error: &SighashError) -> ScriptError {
    ScriptError::Verification(error.to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test assertions")]
    use bitcoin_rs_primitives::{Hash256, OutPoint, SighashCache, Tx, TxIn, TxOut, Txid};

    use super::{
        LOCKTIME_THRESHOLD, SEQUENCE_FINAL, SEQUENCE_LOCKTIME_DISABLE_FLAG,
        SEQUENCE_LOCKTIME_TYPE_FLAG, SigVersion, TxSignatureChecker, remove_codeseparators,
    };
    use crate::interpreter::{ScriptErrCode, ScriptError, VerifyFlags};

    // --- Helper: build a minimal 1-input, 1-output transaction ---

    fn make_tx(version: i32, lock_time: u32, sequence: u32) -> Tx {
        Tx {
            version,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid::default(), 0),
                script_sig: Vec::new(),
                sequence,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 49_000,
                script_pubkey: Vec::new(),
            }],
            lock_time,
        }
    }

    fn make_prevouts() -> Vec<TxOut> {
        vec![TxOut {
            value: 50_000,
            script_pubkey: Vec::new(),
        }]
    }

    // =======================================================================
    // DER encoding tests (DERSIG flag)
    // =======================================================================

    #[test]
    fn der_flag_rejects_non_der_signature() {
        let tx = make_tx(2, 0, SEQUENCE_FINAL);
        let prevouts = make_prevouts();
        let mut checker = TxSignatureChecker::new(&tx, 0, 50_000, &prevouts);

        // A non-DER signature: just random bytes with a hashtype appended.
        let bad_sig = [0x00, 0x01, 0x02, 0x03, 0x01_u8];
        let pubkey = [0x02_u8; 33]; // compressed pubkey placeholder

        let result = checker.check_ecdsa_signature(
            &bad_sig,
            &pubkey,
            &[],
            SigVersion::Base,
            VerifyFlags::DERSIG,
        );

        // Deletion transcript: when the DERSIG check is removed (the
        // `needs_der && !is_valid_der_encoding` branch deleted), this
        // signature is not rejected at the encoding stage. Instead it
        // proceeds to `EcdsaSig::from_der` which returns `Err`, yielding
        // `Ok(false)` — a clean false instead of the expected `Err`.
        // The test would fail because it expects `Err` but gets `Ok(false)`.
        assert!(
            matches!(
                result,
                Err(ScriptError::Invalid {
                    code: ScriptErrCode::SigDer
                })
            ),
            "DERSIG flag must reject non-DER signatures, got {result:?}"
        );
    }

    #[test]
    fn der_flag_accepts_empty_signature() {
        let tx = make_tx(2, 0, SEQUENCE_FINAL);
        let prevouts = make_prevouts();
        let mut checker = TxSignatureChecker::new(&tx, 0, 50_000, &prevouts);

        let result = checker.check_ecdsa_signature(
            &[],
            &[0x02_u8; 33],
            &[],
            SigVersion::Base,
            VerifyFlags::DERSIG,
        );

        assert_eq!(result, Ok(false));
    }

    // =======================================================================
    // Low-S tests (LOW_S flag)
    // =======================================================================

    #[test]
    fn low_s_flag_rejects_high_s_signature() {
        let tx = make_tx(2, 0, SEQUENCE_FINAL);
        let prevouts = make_prevouts();
        let mut checker = TxSignatureChecker::new(&tx, 0, 50_000, &prevouts);

        // Construct a DER-encoded signature with a high S value that is
        // still valid DER (positive integer). S = 0x80...00 (32 bytes) is
        // above the half-order 0x7FFF...A0. To keep DER valid (positive),
        // prepend a 0x00 byte to S, making the DER length 33.
        // DER: 0x30 <len> 0x02 0x20 <R: 32 bytes> 0x02 0x21 0x00 <S: 32 bytes> <hashtype>
        let sig: Vec<u8> = [0x30, 0x45, 0x02, 0x20]
            .into_iter()
            .chain([0x01; 32])
            .chain([0x02, 0x21, 0x00, 0x80])
            .chain([0x00; 31])
            .chain([0x01])
            .collect();

        let result = checker.check_ecdsa_signature(
            &sig,
            &[0x02_u8; 33],
            &[],
            SigVersion::Base,
            VerifyFlags::DERSIG.union(VerifyFlags::LOW_S),
        );

        // Deletion transcript: when the LOW_S check is removed (the
        // `flags.contains(VerifyFlags::LOW_S) && !is_low_der_signature`
        // branch deleted), this signature passes encoding checks (it is
        // valid DER) and proceeds to `EcdsaSig::from_der` + verification.
        // `from_der` accepts it (secp256k1 does not enforce low-S by
        // default), so it returns `Ok(false)` (verification fails against
        // the random pubkey) instead of `Err(SigHighS)`. The test would
        // fail because it expects `Err` but gets `Ok(false)`.
        assert!(
            matches!(
                result,
                Err(ScriptError::Invalid {
                    code: ScriptErrCode::SigHighS
                })
            ),
            "LOW_S flag must reject high-S signatures, got {result:?}"
        );
    }

    // =======================================================================
    // STRICTENC hashtype test
    // =======================================================================

    #[test]
    fn strictenc_rejects_undefined_hashtype() {
        let tx = make_tx(2, 0, SEQUENCE_FINAL);
        let prevouts = make_prevouts();
        let mut checker = TxSignatureChecker::new(&tx, 0, 50_000, &prevouts);

        // Build a valid DER signature with an undefined hashtype (0x05).
        let sig: Vec<u8> = [0x30, 0x44, 0x02, 0x20]
            .into_iter()
            .chain([0x01; 32])
            .chain([0x02, 0x20])
            .chain([0x01; 32])
            .chain([0x05])
            .collect();

        let result = checker.check_ecdsa_signature(
            &sig,
            &[0x02_u8; 33],
            &[],
            SigVersion::Base,
            VerifyFlags::STRICTENC.union(VerifyFlags::DERSIG),
        );

        assert!(
            matches!(
                result,
                Err(ScriptError::Invalid {
                    code: ScriptErrCode::SigHashtype
                })
            ),
            "STRICTENC must reject undefined hashtype, got {result:?}"
        );
    }

    // =======================================================================
    // STRICTENC pubkey encoding test
    // =======================================================================

    #[test]
    fn strictenc_rejects_invalid_pubkey() {
        let tx = make_tx(2, 0, SEQUENCE_FINAL);
        let prevouts = make_prevouts();
        let mut checker = TxSignatureChecker::new(&tx, 0, 50_000, &prevouts);

        // A valid DER sig with low S.
        let sig: Vec<u8> = [0x30, 0x44, 0x02, 0x20]
            .into_iter()
            .chain([0x01; 32])
            .chain([0x02, 0x20])
            .chain([0x01; 32])
            .chain([0x01])
            .collect();

        // Invalid pubkey: wrong prefix byte.
        let bad_pubkey = [0x05_u8; 33];

        let result = checker.check_ecdsa_signature(
            &sig,
            &bad_pubkey,
            &[],
            SigVersion::Base,
            VerifyFlags::STRICTENC.union(VerifyFlags::DERSIG),
        );

        assert!(
            matches!(
                result,
                Err(ScriptError::Invalid {
                    code: ScriptErrCode::PubkeyType
                })
            ),
            "STRICTENC must reject invalid pubkey encoding, got {result:?}"
        );
    }

    // =======================================================================
    // WITNESS_PUBKEYTYPE test
    // =======================================================================

    #[test]
    fn witness_pubkeytype_rejects_uncompressed_in_segwit() {
        let tx = make_tx(2, 0, SEQUENCE_FINAL);
        let prevouts = make_prevouts();
        let mut checker = TxSignatureChecker::new(&tx, 0, 50_000, &prevouts);

        // Uncompressed pubkey (0x04 prefix, 65 bytes).
        let uncompressed = [0x04_u8; 65];

        let sig: Vec<u8> = [0x30, 0x44, 0x02, 0x20]
            .into_iter()
            .chain([0x01; 32])
            .chain([0x02, 0x20])
            .chain([0x01; 32])
            .chain([0x01])
            .collect();

        let result = checker.check_ecdsa_signature(
            &sig,
            &uncompressed,
            &[],
            SigVersion::WitnessV0,
            VerifyFlags::WITNESS_PUBKEYTYPE.union(VerifyFlags::DERSIG),
        );

        assert!(
            matches!(
                result,
                Err(ScriptError::Invalid {
                    code: ScriptErrCode::WitnessPubkeyType
                })
            ),
            "WITNESS_PUBKEYTYPE must reject uncompressed keys in segwit, got {result:?}"
        );
    }

    // =======================================================================
    // NULLFAIL test
    // =======================================================================

    #[test]
    fn nullfail_rejects_nonempty_failing_signature() {
        let tx = make_tx(2, 0, SEQUENCE_FINAL);
        let prevouts = make_prevouts();
        let mut checker = TxSignatureChecker::new(&tx, 0, 50_000, &prevouts);

        // Valid DER, low S, valid hashtype — but the signature won't verify
        // against this random pubkey, so without NULLFAIL it would be Ok(false).
        let sig: Vec<u8> = [0x30, 0x44, 0x02, 0x20]
            .into_iter()
            .chain([0x01; 32])
            .chain([0x02, 0x20])
            .chain([0x01; 32])
            .chain([0x01])
            .collect();

        // Use a valid compressed pubkey (0x02 prefix + 32 bytes).
        // This is a valid encoding but the signature won't match.
        let pubkey = [0x02_u8; 33];

        // Without NULLFAIL: should be Ok(false) (verification fails but no error).
        let result_no_nullfail = checker.check_ecdsa_signature(
            &sig,
            &pubkey,
            &[0x51], // script_code
            SigVersion::Base,
            VerifyFlags::DERSIG.union(VerifyFlags::LOW_S),
        );
        assert_eq!(result_no_nullfail, Ok(false));

        // With NULLFAIL: check_ecdsa_signature returns Ok(false) — NULLFAIL
        // enforcement is the caller's job (eval_checksig / check_multisig
        // cleanup), not the checker's.
        let mut checker2 = TxSignatureChecker::new(&tx, 0, 50_000, &prevouts);
        let result_nullfail = checker2.check_ecdsa_signature(
            &sig,
            &pubkey,
            &[0x51],
            SigVersion::Base,
            VerifyFlags::DERSIG
                .union(VerifyFlags::LOW_S)
                .union(VerifyFlags::NULLFAIL),
        );
        assert_eq!(
            result_nullfail,
            Ok(false),
            "check_ecdsa_signature must not enforce NULLFAIL; caller does"
        );
    }

    #[test]
    fn nullfail_allows_empty_signature() {
        let tx = make_tx(2, 0, SEQUENCE_FINAL);
        let prevouts = make_prevouts();
        let mut checker = TxSignatureChecker::new(&tx, 0, 50_000, &prevouts);

        let result = checker.check_ecdsa_signature(
            &[],
            &[0x02_u8; 33],
            &[],
            SigVersion::Base,
            VerifyFlags::NULLFAIL.union(VerifyFlags::DERSIG),
        );

        assert_eq!(result, Ok(false));
    }

    // =======================================================================
    // check_locktime tests (BIP65)
    // =======================================================================

    #[test]
    fn check_locktime_satisfied_when_types_match_and_locktime_le_tx() {
        let tx = make_tx(2, 100, 0);
        let prevouts = make_prevouts();
        let checker = TxSignatureChecker::new(&tx, 0, 50_000, &prevouts);

        // locktime 50 <= tx locktime 100, both block height, input not finalized.
        assert!(checker.check_locktime(50));
        assert!(checker.check_locktime(100)); // equal is satisfied
    }

    #[test]
    fn check_locktime_fails_when_locktime_exceeds_tx() {
        let tx = make_tx(2, 100, 0);
        let prevouts = make_prevouts();
        let checker = TxSignatureChecker::new(&tx, 0, 50_000, &prevouts);

        assert!(!checker.check_locktime(101));
    }

    #[test]
    fn check_locktime_fails_on_type_mismatch() {
        let tx = make_tx(2, 100, 0); // tx locktime = block height
        let prevouts = make_prevouts();
        let checker = TxSignatureChecker::new(&tx, 0, 50_000, &prevouts);

        // Timestamp locktime vs block-height tx locktime.
        let timestamp = i64::from(LOCKTIME_THRESHOLD) + 100;
        assert!(!checker.check_locktime(timestamp));
    }

    #[test]
    fn check_locktime_fails_when_input_finalized() {
        let tx = make_tx(2, 100, SEQUENCE_FINAL);
        let prevouts = make_prevouts();
        let checker = TxSignatureChecker::new(&tx, 0, 50_000, &prevouts);

        // Even though locktime 50 <= 100 and types match, the input is finalized.
        assert!(!checker.check_locktime(50));
    }

    // =======================================================================
    // check_sequence tests (BIP112)
    // =======================================================================

    #[test]
    fn check_sequence_satisfied_when_masked_sequence_le_input() {
        // tx version 2, sequence with type=height, value=100, disable bit clear.
        let sequence = 100_u32; // block-height type, value 100
        let tx = make_tx(2, 0, sequence);
        let prevouts = make_prevouts();
        let checker = TxSignatureChecker::new(&tx, 0, 50_000, &prevouts);

        // Required sequence 50 <= input sequence 100, same type.
        assert!(checker.check_sequence(50));
        assert!(checker.check_sequence(100)); // equal is satisfied
    }

    #[test]
    fn check_sequence_fails_when_sequence_exceeds_input() {
        let sequence = 100_u32;
        let tx = make_tx(2, 0, sequence);
        let prevouts = make_prevouts();
        let checker = TxSignatureChecker::new(&tx, 0, 50_000, &prevouts);

        assert!(!checker.check_sequence(101));
    }

    #[test]
    fn check_sequence_fails_when_tx_version_too_low() {
        let tx = make_tx(1, 0, 100);
        let prevouts = make_prevouts();
        let checker = TxSignatureChecker::new(&tx, 0, 50_000, &prevouts);

        assert!(!checker.check_sequence(50));
    }

    #[test]
    fn check_sequence_fails_when_input_disabled() {
        let sequence = 0x64_u32 | SEQUENCE_LOCKTIME_DISABLE_FLAG;
        let tx = make_tx(2, 0, sequence);
        let prevouts = make_prevouts();
        let checker = TxSignatureChecker::new(&tx, 0, 50_000, &prevouts);

        assert!(!checker.check_sequence(50));
    }

    #[test]
    fn check_sequence_fails_on_type_mismatch() {
        // Input sequence: block-height type (value < TYPE_FLAG).
        let tx = make_tx(2, 0, 100);
        let prevouts = make_prevouts();
        let checker = TxSignatureChecker::new(&tx, 0, 50_000, &prevouts);

        // Required: time-based type (value >= TYPE_FLAG).
        let time_based = i64::from(SEQUENCE_LOCKTIME_TYPE_FLAG) + 50;
        assert!(!checker.check_sequence(time_based));
    }

    // =======================================================================
    // Sighash.json corpus test (legacy path)
    // =======================================================================

    #[test]
    fn sighash_json_corpus_legacy_path() {
        // The tracked corpus, not the untracked `.references` checkout of Core:
        // this test must grade against the same rows on every machine.
        let corpus = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../consensus/tests/vectors/sighash.json");
        let json_str = std::fs::read_to_string(&corpus).unwrap_or_else(|error| {
            panic!("sighash.json unreadable at {}: {error}", corpus.display())
        });
        let json_str = json_str.as_str();
        let data: serde_json::Value =
            serde_json::from_str(json_str).unwrap_or_else(|e| panic!("sighash.json parse: {e}"));

        let rows = data.as_array().expect("sighash.json is an array");
        let mut tested = 0_u32;

        for row in rows {
            let Some(arr) = row.as_array().filter(|a| a.len() == 5) else {
                continue;
            };

            let tx_hex = arr
                .first()
                .and_then(serde_json::Value::as_str)
                .expect("tx hex");
            let script_hex = arr
                .get(1)
                .and_then(serde_json::Value::as_str)
                .expect("script hex");
            let input_index = usize::try_from(
                arr.get(2)
                    .and_then(serde_json::Value::as_u64)
                    .expect("input index"),
            )
            .expect("input index fits in usize");
            let hashtype_raw = arr
                .get(3)
                .and_then(serde_json::Value::as_i64)
                .expect("hashtype");
            let expected_hex = arr
                .get(4)
                .and_then(serde_json::Value::as_str)
                .expect("expected hash");

            let tx_bytes = hex_decode(tx_hex);
            let tx = Tx::consensus_decode(&tx_bytes)
                .unwrap_or_else(|e| panic!("tx decode at row {tested}: {e}"));

            // Core's SignatureHash removes OP_CODESEPARATOR (0xab) from
            // script_code before hashing; our legacy_signature_hash expects
            // the pre-processed script. Match Core's SerializeScriptCode.
            let script_code = remove_codeseparators(&hex_decode(script_hex));

            // The hashtype in sighash.json is a signed 32-bit integer;
            // Core casts `int nHashType` to `uint32_t` (bit-preserving).
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

    // =======================================================================
    // ScriptErrCode Display tests
    // =======================================================================

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

    // --- utility ---

    fn hex_decode(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks_exact(2)
            .map(|chunk| {
                let hex = std::str::from_utf8(chunk).expect("hex chars are ASCII");
                u8::from_str_radix(hex, 16).unwrap_or_else(|e| panic!("hex decode: {e}"))
            })
            .collect()
    }
}
