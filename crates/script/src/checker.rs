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
        Self::new_with_cache(
            tx,
            input_index,
            amount,
            prevouts,
            SighashCache::new(tx),
        )
    }

    /// Builds a checker using a caller-owned sighash cache for `tx`.
    ///
    /// This allows serial verification of multiple inputs from the same
    /// transaction to reuse the cached BIP143/BIP341 aggregate hashes.
    #[must_use]
    pub fn new_with_cache(
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

    /// Returns the underlying sighash cache so a caller can reuse it for the
    /// next input of the same transaction.
    #[must_use]
    pub fn into_cache(self) -> SighashCache<'a> {
        self.cache
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
        Ok(secp256k1::SECP256K1
            .verify_ecdsa(message, &ecdsa_sig, &secp_pubkey)
            .is_ok())
    }

    /// Verifies a BIP340 Schnorr signature against BIP341/BIP342 sighash.
    ///
    /// Returns `Ok(true)` when valid, `Ok(false)` when the signature is empty,
    /// and `Err` for encoding/sighash failures under active consensus rules.
    pub fn check_schnorr_signature(
        &mut self,
        sig: &[u8],
        pubkey: &[u8],
        leaf_hash: Option<Hash256>,
        codeseparator_pos: u32,
        sigversion: SigVersion,
    ) -> Result<bool, ScriptError> {
        if sig.is_empty() {
            return Ok(false);
        }
        if pubkey.len() != 32 {
            return Err(invalid(ScriptErrCode::Pubkeytype));
        }
        if sig.len() != 64 && sig.len() != 65 {
            return Err(invalid(ScriptErrCode::SchnorrSigSize));
        }

        let xonly = XOnlyPublicKey::from_slice(pubkey)
            .map_err(|e| ScriptError::Verification(format!("invalid x-only public key: {e}")))?;
        let signature = secp256k1::schnorr::Signature::from_slice(&sig[..64])
            .map_err(|e| ScriptError::Verification(format!("invalid schnorr signature: {e}")))?;

        let sighash_type = if sig.len() == 65 {
            let byte = sig[64];
            if byte == 0 {
                return Err(invalid(ScriptErrCode::SchnorrSigHashtype));
            }
            Sighash::from_consensus_byte(byte)
                .ok_or_else(|| invalid(ScriptErrCode::SchnorrSigHashtype))?
        } else {
            Sighash::Default
        };

        let annex = self.annex.as_deref();
        let digest = match sigversion {
            SigVersion::Taproot => self
                .cache
                .taproot_signature_hash(self.input_index, self.prevouts, sighash_type, annex, None)
                .map_err(|e| sighash_to_script_error(&e))?,
            SigVersion::Tapscript => self
                .cache
                .taproot_signature_hash(
                    self.input_index,
                    self.prevouts,
                    sighash_type,
                    annex,
                    leaf_hash.map(|h| (h, codeseparator_pos)),
                )
                .map_err(|e| sighash_to_script_error(&e))?,
            _ => {
                return Err(ScriptError::Verification(
                    "Schnorr signature check requested outside taproot".to_owned(),
                ));
            }
        };

        let message = Message::from_digest(*digest.as_byte_array());
        Ok(secp256k1::SECP256K1
            .verify_schnorr(&signature, &message, &xonly)
            .is_ok())
    }

    /// Checks BIP65 `CHECKLOCKTIMEVERIFY` semantics against the current input.
    pub fn check_lock_time(&self, lock_time: i64) -> bool {
        if lock_time < 0 {
            return false;
        }
        let Ok(lock_time) = u32::try_from(lock_time) else {
            return false;
        };
        if self.input_index >= self.tx.inputs.len() {
            return false;
        }
        let tx_lock = self.tx.lock_time;
        let same_kind = (tx_lock < LOCKTIME_THRESHOLD) == (lock_time < LOCKTIME_THRESHOLD);
        if !same_kind || lock_time > tx_lock {
            return false;
        }
        self.tx.inputs[self.input_index].sequence != SEQUENCE_FINAL
    }

    /// Checks BIP112 `CHECKSEQUENCEVERIFY` semantics against the current input.
    pub fn check_sequence(&self, sequence: i64) -> bool {
        if sequence < 0 {
            return false;
        }
        let Ok(sequence) = u32::try_from(sequence) else {
            return false;
        };
        if sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
            return true;
        }
        // BIP68 relative locktime only applies to transaction version >= 2.
        if self.tx.version < 2 || self.input_index >= self.tx.inputs.len() {
            return false;
        }
        let tx_seq = self.tx.inputs[self.input_index].sequence;
        if tx_seq & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
            return false;
        }
        // Mask to the type flag (bit 22) and the low 16-bit value, then require
        // the same lock-time units and a transaction sequence at least as large.
        let mask = SEQUENCE_LOCKTIME_TYPE_FLAG | SEQUENCE_LOCKTIME_MASK;
        let tx_masked = tx_seq & mask;
        let arg_masked = sequence & mask;
        if (tx_masked & SEQUENCE_LOCKTIME_TYPE_FLAG) != (arg_masked & SEQUENCE_LOCKTIME_TYPE_FLAG) {
            return false;
        }
        arg_masked <= tx_masked
    }
}

/// Converts a `SighashError` into the corresponding script error code.
fn sighash_to_script_error(err: &SighashError) -> ScriptError {
    match err {
        SighashError::InputIndexOutOfRange { .. } => invalid(ScriptErrCode::UnknownError),
        SighashError::PrevoutsLengthMismatch { .. } => invalid(ScriptErrCode::TaprootWrongControlSize),
        SighashError::SingleOutputOutOfRange { .. } => invalid(ScriptErrCode::UnknownError),
    }
}

/// Validates DER signature encoding per BIP66, operating on a full Bitcoin
/// ECDSA signature including its trailing sighash-type byte. Mirrors Core's
/// `IsValidSignatureEncoding`.
fn is_valid_signature_encoding(sig: &[u8]) -> bool {
    // Format: 0x30 <len> 0x02 <R-len> <R> 0x02 <S-len> <S> <hashtype>
    if sig.len() < 9 || sig.len() > 73 {
        return false;
    }
    if sig[0] != 0x30 || usize::from(sig[1]) != sig.len() - 3 {
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
    // R must be an integer, non-empty, non-negative, and minimally encoded.
    if sig[2] != 0x02 || len_r == 0 || sig[4] & 0x80 != 0 {
        return false;
    }
    if len_r > 1 && sig[4] == 0 && sig[5] & 0x80 == 0 {
        return false;
    }
    // S same constraints.
    let s_pos = 6 + len_r;
    if sig[4 + len_r] != 0x02 || len_s == 0 || sig[s_pos] & 0x80 != 0 {
        return false;
    }
    if len_s > 1 && sig[s_pos] == 0 && sig[s_pos + 1] & 0x80 == 0 {
        return false;
    }
    true
}

/// Checks that the sighash type byte is a defined legacy/BIP143 value: base
/// type 1 (ALL), 2 (NONE), or 3 (SINGLE), optionally with ANYONECANPAY.
fn is_defined_hashtype_signature(sig: &[u8]) -> bool {
    let Some(&last) = sig.last() else {
        return false;
    };
    let base = last & !SIGHASH_ANYONECANPAY;
    (1..=3).contains(&base)
}

/// Enforces signature encoding rules controlled by verification flags.
fn check_signature_encoding(sig: &[u8], flags: VerifyFlags) -> Result<(), ScriptError> {
    if sig.is_empty() {
        return Ok(());
    }
    if flags.intersects(VerifyFlags::DERSIG | VerifyFlags::LOW_S | VerifyFlags::STRICTENC)
        && !is_valid_signature_encoding(sig)
    {
        return Err(invalid(ScriptErrCode::SigDer));
    }
    if flags.contains(VerifyFlags::LOW_S) {
        // Parse DER excluding the sighash byte then reject if S > curve order/2.
        let der = &sig[..sig.len() - 1];
        if let Ok(sig_obj) = EcdsaSig::from_der(der) {
            let mut normalized = sig_obj;
            normalized.normalize_s();
            if normalized != sig_obj {
                return Err(invalid(ScriptErrCode::SigHighS));
            }
        }
    }
    if flags.contains(VerifyFlags::STRICTENC) && !is_defined_hashtype_signature(sig) {
        return Err(invalid(ScriptErrCode::SigHashtype));
    }
    Ok(())
}

/// Enforces public-key encoding per policy flags and signature version.
fn check_pubkey_encoding(
    pubkey: &[u8],
    flags: VerifyFlags,
    sigversion: SigVersion,
) -> Result<(), ScriptError> {
    if flags.contains(VerifyFlags::STRICTENC) && !is_valid_pubkey_encoding(pubkey) {
        return Err(invalid(ScriptErrCode::Pubkeytype));
    }
    if flags.contains(VerifyFlags::WITNESS_PUBKEYTYPE)
        && sigversion == SigVersion::WitnessV0
        && !is_compressed_pubkey(pubkey)
    {
        return Err(invalid(ScriptErrCode::WitnessPubkeytype));
    }
    Ok(())
}

/// Bitcoin pubkey encoding: compressed (33B, prefix 02/03) or uncompressed
/// (65B, prefix 04).
fn is_valid_pubkey_encoding(pubkey: &[u8]) -> bool {
    matches!(pubkey.len(), 33) && matches!(pubkey[0], 0x02 | 0x03)
        || matches!(pubkey.len(), 65) && pubkey[0] == 0x04
}

fn is_compressed_pubkey(pubkey: &[u8]) -> bool {
    pubkey.len() == 33 && matches!(pubkey[0], 0x02 | 0x03)
}

/// Converts an ECDSA sighash type byte to [`Sighash`]. All valid Bitcoin
/// legacy/BIP143 combinations map to the same consensus byte encoding used by
/// `Sighash`.
fn ecdsa_hashtype_from_byte(byte: u8) -> Result<Sighash, ScriptError> {
    Sighash::from_consensus_byte(byte)
        .ok_or_else(|| ScriptError::Verification(format!("invalid ECDSA sighash type 0x{byte:02x}")))
}
