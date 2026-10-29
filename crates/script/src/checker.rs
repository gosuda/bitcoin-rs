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
mod tests;
