use bitcoin::ecdsa;
use bitcoin::psbt::Psbt;
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::secp256k1::{Message, Secp256k1, VerifyOnly};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::{PublicKey, ScriptBuf, Transaction, TxOut, Witness, XOnlyPublicKey};
use thiserror::Error;

/// PSBT finalization errors.
#[derive(Debug, Error)]
pub enum FinalizeError {
    /// PSBT global/input lengths are inconsistent.
    #[error("PSBT input count does not match unsigned transaction input count")]
    InputCount,
    /// An input has no UTXO metadata.
    #[error("input {index} has no spend UTXO")]
    MissingUtxo {
        /// Input index.
        index: usize,
    },
    /// An input has no signatures.
    #[error("input {index} has no signatures")]
    MissingSignature {
        /// Input index.
        index: usize,
    },
    /// A signature did not verify against its public key and PSBT sighash.
    #[error("input {index} signature verification failed")]
    BadSignature {
        /// Input index.
        index: usize,
    },
    /// Required scripts are missing from the PSBT.
    #[error("input {index} is missing a redeem or witness script")]
    MissingScript {
        /// Input index.
        index: usize,
    },
    /// The input script type is unsupported by this finalizer.
    #[error("input {index} has unsupported script type")]
    UnsupportedScript {
        /// Input index.
        index: usize,
    },
    /// Sighash construction failed.
    #[error("input {index} sighash failed: {reason}")]
    Sighash {
        /// Input index.
        index: usize,
        /// Failure reason.
        reason: String,
    },
    /// Script push construction failed.
    #[error("input {index} script push failed: {reason}")]
    ScriptPush {
        /// Input index.
        index: usize,
        /// Failure reason.
        reason: String,
    },
}

/// Finalizes a signed PSBT into a transaction.
pub fn finalize_signed(psbt: Psbt) -> Result<Transaction, FinalizeError> {
    if psbt.inputs.len() != psbt.unsigned_tx.input.len() {
        return Err(FinalizeError::InputCount);
    }
    verify_signatures(&psbt)?;

    let mut psbt = psbt;
    for index in 0..psbt.inputs.len() {
        if psbt.inputs[index].final_script_sig.is_some()
            || psbt.inputs[index].final_script_witness.is_some()
        {
            continue;
        }
        finalize_input(&mut psbt, index)?;
    }

    Ok(psbt.extract_tx_unchecked_fee_rate())
}

fn verify_signatures(psbt: &Psbt) -> Result<(), FinalizeError> {
    let secp = Secp256k1::verification_only();
    let tx = psbt.unsigned_tx.clone();
    let mut cache = SighashCache::new(&tx);
    for index in 0..psbt.inputs.len() {
        let input = &psbt.inputs[index];
        if let Some(signature) = input.tap_key_sig {
            verify_taproot_signature(psbt, &mut cache, &secp, index, signature)?;
            continue;
        }
        if input.partial_sigs.is_empty() {
            return Err(FinalizeError::MissingSignature { index });
        }
        let (message, _hash_ty) =
            psbt.sighash_ecdsa(index, &mut cache)
                .map_err(|error| FinalizeError::Sighash {
                    index,
                    reason: error.to_string(),
                })?;
        for (public_key, signature) in &input.partial_sigs {
            secp.verify_ecdsa(&message, &signature.signature, &public_key.inner)
                .map_err(|_error| FinalizeError::BadSignature { index })?;
        }
    }
    Ok(())
}

fn verify_taproot_signature(
    psbt: &Psbt,
    cache: &mut SighashCache<&Transaction>,
    secp: &Secp256k1<VerifyOnly>,
    index: usize,
    signature: bitcoin::taproot::Signature,
) -> Result<(), FinalizeError> {
    let utxo = spend_utxo(psbt, index)?;
    let script_bytes = utxo.script_pubkey.as_bytes();
    let key_bytes = script_bytes
        .get(2..34)
        .ok_or(FinalizeError::UnsupportedScript { index })?;
    let xonly = XOnlyPublicKey::from_slice(key_bytes)
        .map_err(|_error| FinalizeError::BadSignature { index })?;
    let prevouts = all_prevouts(psbt)?;
    let sighash = cache
        .taproot_key_spend_signature_hash(index, &Prevouts::All(&prevouts), signature.sighash_type)
        .map_err(|error| FinalizeError::Sighash {
            index,
            reason: error.to_string(),
        })?;
    let message = Message::from(sighash);
    secp.verify_schnorr(&signature.signature, &message, &xonly)
        .map_err(|_error| FinalizeError::BadSignature { index })
}

fn all_prevouts(psbt: &Psbt) -> Result<Vec<&TxOut>, FinalizeError> {
    (0..psbt.inputs.len())
        .map(|index| spend_utxo(psbt, index))
        .collect()
}

fn spend_utxo(psbt: &Psbt, index: usize) -> Result<&TxOut, FinalizeError> {
    psbt.spend_utxo(index)
        .map_err(|_error| FinalizeError::MissingUtxo { index })
}

fn finalize_input(psbt: &mut Psbt, index: usize) -> Result<(), FinalizeError> {
    let script = spend_utxo(psbt, index)?.script_pubkey.clone();
    if script.is_p2pkh() {
        finalize_p2pkh(psbt, index)
    } else if script.is_p2wpkh() {
        finalize_p2wpkh(psbt, index)
    } else if script.is_p2sh() {
        finalize_p2sh_wpkh(psbt, index)
    } else if script.is_p2wsh() {
        finalize_p2wsh(psbt, index)
    } else if script.is_p2tr() {
        finalize_p2tr(psbt, index)
    } else {
        Err(FinalizeError::UnsupportedScript { index })
    }
}

fn finalize_p2pkh(psbt: &mut Psbt, index: usize) -> Result<(), FinalizeError> {
    let (public_key, signature) = first_partial_sig(psbt, index)?;
    psbt.inputs[index].final_script_sig = Some(
        Builder::new()
            .push_slice(signature.serialize())
            .push_key(&public_key)
            .into_script(),
    );
    Ok(())
}

fn finalize_p2wpkh(psbt: &mut Psbt, index: usize) -> Result<(), FinalizeError> {
    let (public_key, signature) = first_partial_sig(psbt, index)?;
    psbt.inputs[index].final_script_witness = Some(signature_pubkey_witness(signature, public_key));
    Ok(())
}

fn finalize_p2sh_wpkh(psbt: &mut Psbt, index: usize) -> Result<(), FinalizeError> {
    let (public_key, signature) = first_partial_sig(psbt, index)?;
    let redeem_script = psbt.inputs[index]
        .redeem_script
        .clone()
        .ok_or(FinalizeError::MissingScript { index })?;
    psbt.inputs[index].final_script_sig = Some(push_script(redeem_script, index)?);
    psbt.inputs[index].final_script_witness = Some(signature_pubkey_witness(signature, public_key));
    Ok(())
}

fn finalize_p2wsh(psbt: &mut Psbt, index: usize) -> Result<(), FinalizeError> {
    let witness_script = psbt.inputs[index]
        .witness_script
        .clone()
        .ok_or(FinalizeError::MissingScript { index })?;
    let mut witness = Witness::new();
    witness.push(Vec::<u8>::new());
    for signature in psbt.inputs[index].partial_sigs.values() {
        witness.push(signature.to_vec());
    }
    witness.push(witness_script.into_bytes());
    psbt.inputs[index].final_script_witness = Some(witness);
    Ok(())
}

fn finalize_p2tr(psbt: &mut Psbt, index: usize) -> Result<(), FinalizeError> {
    let signature = psbt.inputs[index]
        .tap_key_sig
        .ok_or(FinalizeError::MissingSignature { index })?;
    let mut witness = Witness::new();
    witness.push(signature.to_vec());
    psbt.inputs[index].final_script_witness = Some(witness);
    Ok(())
}

fn first_partial_sig(
    psbt: &Psbt,
    index: usize,
) -> Result<(PublicKey, ecdsa::Signature), FinalizeError> {
    psbt.inputs[index]
        .partial_sigs
        .iter()
        .next()
        .map(|(public_key, signature)| (*public_key, *signature))
        .ok_or(FinalizeError::MissingSignature { index })
}

fn signature_pubkey_witness(signature: ecdsa::Signature, public_key: PublicKey) -> Witness {
    let mut witness = Witness::new();
    witness.push(signature.to_vec());
    witness.push(public_key.to_bytes());
    witness
}

fn push_script(script: ScriptBuf, index: usize) -> Result<ScriptBuf, FinalizeError> {
    let bytes =
        PushBytesBuf::try_from(script.into_bytes()).map_err(|error| FinalizeError::ScriptPush {
            index,
            reason: error.to_string(),
        })?;
    Ok(Builder::new().push_slice(bytes).into_script())
}
