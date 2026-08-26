use bitcoin::key::{Keypair, TapTweak};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{All, Message, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::Signature as TaprootSignature;
use bitcoin::{
    PrivateKey, PublicKey, ScriptBuf, TapSighashType, Transaction, TxOut, XOnlyPublicKey,
};
use thiserror::Error;

/// External signer errors surfaced to wallet callers.
#[derive(Debug, Error)]
pub enum SignerError {
    /// The signer refused or could not satisfy the PSBT.
    #[error("external signer rejected PSBT: {0}")]
    Rejected(String),
    /// A legacy input supplied only witness UTXO metadata, which does not
    /// prove that the caller provided the transaction output being spent.
    #[error("PSBT input {index} requires a matching non-witness UTXO")]
    UnsafeLegacyPrevout {
        /// Input whose previous output was not proven.
        index: usize,
    },
    /// A legacy input's non-witness transaction does not prove its outpoint.
    #[error("PSBT input {index} non-witness UTXO does not match its previous outpoint")]
    MismatchedNonWitnessUtxo {
        /// Input whose previous transaction or output did not match.
        index: usize,
    },
    /// The signer returned a PSBT that does not match the requested transaction.
    #[error("external signer returned an unrelated PSBT")]
    MismatchedPsbt,
}

/// External signer contract.
///
/// The wallet crate never implements this trait for private-key types. Signers
/// consume an unsigned PSBT and return a signed PSBT for wallet finalization.
pub trait ExternalSigner: Send + Sync {
    /// Signs or annotates `psbt`, returning a PSBT with signatures attached.
    fn sign_psbt(&self, psbt: &Psbt) -> Result<Psbt, SignerError>;
}

/// Signs `psbt` with caller-provided keys after proving legacy prevouts.
///
/// The keys exist only for this call: they are never stored in wallet state
/// and are dropped when the call returns. Only inputs whose scripts reference
/// a supplied key are signed; every other input passes through unchanged.
/// Legacy inputs require a matching non-witness transaction because their
/// signatures do not commit to the spent output metadata.
pub fn sign_psbt_with_caller_keys(
    psbt: &Psbt,
    caller_keys: &[PrivateKey],
) -> Result<Psbt, SignerError> {
    sign_psbt_with_policy(psbt, caller_keys, LegacyPrevoutPolicy::RequireProof)
}

/// Signs `psbt` using prevouts explicitly asserted by the caller.
///
/// This is restricted to interfaces such as `signrawtransactionwithkey` whose
/// contract makes the caller responsible for the supplied previous outputs.
pub fn sign_psbt_with_explicit_prevouts(
    psbt: &Psbt,
    caller_keys: &[PrivateKey],
) -> Result<Psbt, SignerError> {
    sign_psbt_with_policy(
        psbt,
        caller_keys,
        LegacyPrevoutPolicy::ExplicitCallerAssertion,
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LegacyPrevoutPolicy {
    RequireProof,
    ExplicitCallerAssertion,
}

fn sign_psbt_with_policy(
    psbt: &Psbt,
    caller_keys: &[PrivateKey],
    legacy_prevout_policy: LegacyPrevoutPolicy,
) -> Result<Psbt, SignerError> {
    let secp = Secp256k1::new();
    let mut signed = psbt.clone();
    let tx = psbt.unsigned_tx.clone();
    let mut cache = SighashCache::new(&tx);
    for index in 0..psbt.inputs.len() {
        if legacy_prevout_policy == LegacyPrevoutPolicy::RequireProof {
            require_proven_legacy_prevout(psbt, index)?;
        }
        let utxo = psbt
            .spend_utxo(index)
            .map_err(|error| SignerError::Rejected(error.to_string()))?;
        if utxo.script_pubkey.is_p2tr() {
            sign_taproot_input(psbt, &mut signed, &secp, &mut cache, index, caller_keys)?;
        } else {
            sign_ecdsa_input(psbt, &mut signed, &secp, &mut cache, index, caller_keys)?;
        }
    }
    Ok(signed)
}

fn require_proven_legacy_prevout(psbt: &Psbt, index: usize) -> Result<(), SignerError> {
    let input = psbt
        .inputs
        .get(index)
        .ok_or_else(|| SignerError::Rejected("psbt input missing".to_owned()))?;
    let txin =
        psbt.unsigned_tx.input.get(index).ok_or_else(|| {
            SignerError::Rejected("unsigned transaction input missing".to_owned())
        })?;
    let spend_utxo = if let Some(utxo) = input.witness_utxo.as_ref() {
        utxo
    } else if let Some(transaction) = input.non_witness_utxo.as_ref() {
        let vout = usize::try_from(txin.previous_output.vout)
            .map_err(|_| SignerError::MismatchedNonWitnessUtxo { index })?;
        transaction
            .output
            .get(vout)
            .ok_or(SignerError::MismatchedNonWitnessUtxo { index })?
    } else {
        return Ok(());
    };

    if !is_legacy_prevout(psbt, index, spend_utxo) {
        return Ok(());
    }

    let transaction = input
        .non_witness_utxo
        .as_ref()
        .ok_or(SignerError::UnsafeLegacyPrevout { index })?;
    if transaction.compute_txid() != txin.previous_output.txid {
        return Err(SignerError::MismatchedNonWitnessUtxo { index });
    }
    let proven_utxo = transaction
        .output
        .get(
            usize::try_from(txin.previous_output.vout)
                .map_err(|_| SignerError::MismatchedNonWitnessUtxo { index })?,
        )
        .ok_or(SignerError::MismatchedNonWitnessUtxo { index })?;
    if proven_utxo != spend_utxo {
        return Err(SignerError::MismatchedNonWitnessUtxo { index });
    }
    Ok(())
}

fn is_legacy_prevout(psbt: &Psbt, index: usize, utxo: &TxOut) -> bool {
    if utxo.script_pubkey.is_witness_program() {
        return false;
    }
    if !utxo.script_pubkey.is_p2sh() {
        return true;
    }
    !psbt.inputs[index]
        .redeem_script
        .as_ref()
        .is_some_and(|script| script.is_witness_program())
}

fn sign_ecdsa_input(
    psbt: &Psbt,
    signed: &mut Psbt,
    secp: &Secp256k1<All>,
    cache: &mut SighashCache<&Transaction>,
    index: usize,
    caller_keys: &[PrivateKey],
) -> Result<(), SignerError> {
    let (message, sighash_type) = psbt
        .sighash_ecdsa(index, cache)
        .map_err(|error| SignerError::Rejected(error.to_string()))?;
    let script = signing_script(psbt, index)?;
    for key in caller_keys {
        let public = PublicKey::from_private_key(secp, key);
        if !script_mentions_key(&public, script) {
            continue;
        }
        let signature = secp.sign_ecdsa(&message, &key.inner);
        signed.inputs[index].partial_sigs.insert(
            public,
            bitcoin::ecdsa::Signature {
                signature,
                sighash_type,
            },
        );
    }
    Ok(())
}

fn sign_taproot_input(
    psbt: &Psbt,
    signed: &mut Psbt,
    secp: &Secp256k1<All>,
    cache: &mut SighashCache<&Transaction>,
    index: usize,
    caller_keys: &[PrivateKey],
) -> Result<(), SignerError> {
    let output_script = psbt
        .spend_utxo(index)
        .map_err(|error| SignerError::Rejected(error.to_string()))?
        .script_pubkey
        .clone();
    for key in caller_keys {
        let keypair = Keypair::from_secret_key(secp, &key.inner);
        let (untweaked, _parity) = XOnlyPublicKey::from_keypair(&keypair);
        let (output_key, _output_parity) = untweaked.tap_tweak(secp, None);
        if ScriptBuf::new_p2tr_tweaked(output_key) != output_script {
            continue;
        }
        let prevouts = all_prevouts(psbt)?;
        let sighash = cache
            .taproot_key_spend_signature_hash(
                index,
                &Prevouts::All(&prevouts),
                TapSighashType::Default,
            )
            .map_err(|error| SignerError::Rejected(error.to_string()))?;
        let message = Message::from(sighash);
        let tweaked = keypair.tap_tweak(secp, None).to_keypair();
        let signature = secp.sign_schnorr_no_aux_rand(&message, &tweaked);
        signed.inputs[index].tap_key_sig = Some(TaprootSignature {
            signature,
            sighash_type: TapSighashType::Default,
        });
    }
    Ok(())
}

/// Returns the script that carries the input's public keys: the witness
/// script, the redeem script, or the spent script pubkey.
fn signing_script(psbt: &Psbt, index: usize) -> Result<&bitcoin::Script, SignerError> {
    let input = psbt
        .inputs
        .get(index)
        .ok_or_else(|| SignerError::Rejected("psbt input missing".to_owned()))?;
    if let Some(script) = &input.witness_script {
        return Ok(script);
    }
    if let Some(script) = &input.redeem_script {
        return Ok(script);
    }
    Ok(&psbt
        .spend_utxo(index)
        .map_err(|error| SignerError::Rejected(error.to_string()))?
        .script_pubkey)
}

/// Returns whether `script` pays to or embeds `public`.
///
/// Miniscript witness scripts carry raw public keys, while P2PKH, P2WPKH,
/// and P2SH-wrapped P2WPKH scripts carry its hash160 instead.
fn script_mentions_key(public: &PublicKey, script: &bitcoin::Script) -> bool {
    let serialized = public.to_bytes();
    if script
        .as_bytes()
        .windows(serialized.len())
        .any(|window| window == serialized.as_slice())
    {
        return true;
    }
    if ScriptBuf::new_p2pkh(&public.pubkey_hash()).as_script() == script {
        return true;
    }
    public
        .wpubkey_hash()
        .is_ok_and(|hash| ScriptBuf::new_p2wpkh(&hash).as_script() == script)
}

fn all_prevouts(psbt: &Psbt) -> Result<Vec<&TxOut>, SignerError> {
    (0..psbt.inputs.len())
        .map(|index| {
            psbt.spend_utxo(index)
                .map_err(|error| SignerError::Rejected(error.to_string()))
        })
        .collect()
}
