//! PSBT build, external signing, caller-key signing, finalization, and
//! consensus roundtrips.
#![allow(clippy::expect_used)]
use std::collections::BTreeMap;

use bitcoin::hashes::Hash as _;
use bitcoin::{
    Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use bitcoin_rs_consensus::verify_transaction;
use bitcoin_rs_script::VerifyFlags;
use bitcoin_rs_wallet::{
    Descriptor, ExternalSigner, FinalizeError, PrevUtxo, PsbtBuilder, SignerError, finalize_signed,
    sign_psbt_with_caller_keys, sign_psbt_with_explicit_prevouts,
};

#[path = "fixtures/test_signer.rs"]
mod test_signer;

#[test]
fn descriptor_psbt_signer_finalizer_roundtrips_through_consensus()
-> Result<(), Box<dyn std::error::Error>> {
    let signer = test_signer::TestSigner::new()?;
    let public_key = signer.public_key();
    let cases = [
        format!("pkh({public_key})"),
        format!("wpkh({public_key})"),
        format!("sh(wpkh({public_key}))"),
        format!("tr({public_key})"),
        format!("wsh(multi(1,{public_key}))"),
    ];

    for (case_index, descriptor_text) in cases.iter().enumerate() {
        let descriptor = Descriptor::parse(descriptor_text)?;
        let script_pubkey = descriptor
            .derive_address(Network::Regtest, 0)?
            .script_pubkey();
        let byte = u8::try_from(case_index + 1)?;
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([byte; 32]),
            vout: 0,
        };
        let prev_txout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey,
        };

        let mut builder = PsbtBuilder::new(core::slice::from_ref(&descriptor));
        builder.add_input(PrevUtxo::new(outpoint, prev_txout.clone()), 0, 0)?;
        let destination = descriptor.derive_address(Network::Regtest, 1)?;
        builder.add_output(destination, Amount::from_sat(40_000))?;
        let unsigned = builder.finalize()?;
        assert!(unsigned.inputs[0].partial_sigs.is_empty());
        assert!(unsigned.inputs[0].tap_key_sig.is_none());

        let signed = signer.sign_psbt(&unsigned)?;
        let finalized = finalize_signed(signed)?;
        let mut prevouts = BTreeMap::new();
        prevouts.insert(outpoint, prev_txout);
        verify_transaction(&finalized, &prevouts, 0, 0, VerifyFlags::MANDATORY)?;
    }

    Ok(())
}

#[test]
fn ranged_descriptor_inputs_attach_scripts_at_their_derivation_index()
-> Result<(), Box<dyn std::error::Error>> {
    let signer = test_signer::TestSigner::new()?;
    let xpub = signer.bip32_xpub();
    let descriptor = Descriptor::parse(&format!("wsh(multi(1,{xpub}/0/*))"))?;
    let derivation_index = 5;
    let script_pubkey = descriptor.script_pubkey_at(derivation_index)?;
    let outpoint = OutPoint {
        txid: Txid::from_byte_array([9_u8; 32]),
        vout: 0,
    };
    let prev_txout = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: script_pubkey.clone(),
    };

    let mut builder = PsbtBuilder::new(core::slice::from_ref(&descriptor));
    builder.add_input(PrevUtxo::new(outpoint, prev_txout), 0, derivation_index)?;
    builder.add_txout(TxOut {
        value: Amount::from_sat(40_000),
        script_pubkey: descriptor.script_pubkey_at(0)?,
    });
    let unsigned = builder.finalize()?;

    assert_eq!(
        unsigned.inputs[0]
            .witness_utxo
            .as_ref()
            .map(|utxo| utxo.script_pubkey.clone()),
        Some(script_pubkey)
    );
    assert_eq!(
        unsigned.inputs[0].witness_script,
        Some(descriptor.explicit_script_at(derivation_index)?)
    );
    // Wrong-index scripts differ: the attachment is index-sensitive.
    assert_ne!(
        unsigned.inputs[0].witness_script,
        Some(descriptor.explicit_script_at(0)?)
    );

    Ok(())
}

#[test]
fn caller_keys_sign_every_script_family_through_consensus() -> Result<(), Box<dyn std::error::Error>>
{
    let signer = test_signer::TestSigner::new()?;
    let public_key = signer.public_key();
    let cases = [
        format!("pkh({public_key})"),
        format!("wpkh({public_key})"),
        format!("sh(wpkh({public_key}))"),
        format!("tr({public_key})"),
        format!("wsh(multi(1,{public_key}))"),
    ];

    for (case_index, descriptor_text) in cases.iter().enumerate() {
        let descriptor = Descriptor::parse(descriptor_text)?;
        let script_pubkey = descriptor
            .derive_address(Network::Regtest, 0)?
            .script_pubkey();
        let byte = u8::try_from(case_index + 21)?;
        let prev_txout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey,
        };
        let (outpoint, funding_tx) = if descriptor_text.starts_with("pkh(") {
            let funding = funding_transaction(prev_txout.clone());
            (
                OutPoint {
                    txid: funding.compute_txid(),
                    vout: 0,
                },
                Some(funding),
            )
        } else {
            (
                OutPoint {
                    txid: Txid::from_byte_array([byte; 32]),
                    vout: 0,
                },
                None,
            )
        };

        let mut builder = PsbtBuilder::new(core::slice::from_ref(&descriptor));
        builder.add_input(PrevUtxo::new(outpoint, prev_txout.clone()), 0, 0)?;
        let destination = descriptor.derive_address(Network::Regtest, 1)?;
        builder.add_output(destination, Amount::from_sat(40_000))?;
        let mut unsigned = builder.finalize()?;
        if let Some(funding) = funding_tx {
            unsigned.inputs[0].non_witness_utxo = Some(funding);
        }

        let signed = sign_psbt_with_caller_keys(&unsigned, &[signer.caller_key()])?;
        let finalized = finalize_signed(signed)?;
        let mut prevouts = BTreeMap::new();
        prevouts.insert(outpoint, prev_txout);
        verify_transaction(&finalized, &prevouts, 0, 0, VerifyFlags::MANDATORY)?;
    }

    Ok(())
}

#[test]
fn unmatched_caller_keys_leave_the_psbt_unsigned() -> Result<(), Box<dyn std::error::Error>> {
    let signer = test_signer::TestSigner::new()?;
    let public_key = signer.public_key();
    let unrelated_key = bitcoin::PrivateKey {
        compressed: true,
        network: bitcoin::NetworkKind::Main,
        inner: bitcoin::secp256k1::SecretKey::from_slice(&[7_u8; 32])?,
    };
    let cases = [format!("wpkh({public_key})"), format!("tr({public_key})")];

    for descriptor_text in cases {
        let descriptor = Descriptor::parse(&descriptor_text)?;
        let script_pubkey = descriptor
            .derive_address(Network::Regtest, 0)?
            .script_pubkey();
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([0xee_u8; 32]),
            vout: 0,
        };
        let prev_txout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey,
        };

        let mut builder = PsbtBuilder::new(core::slice::from_ref(&descriptor));
        builder.add_input(PrevUtxo::new(outpoint, prev_txout), 0, 0)?;
        let destination = descriptor.derive_address(Network::Regtest, 1)?;
        builder.add_output(destination, Amount::from_sat(40_000))?;
        let unsigned = builder.finalize()?;

        let signed = sign_psbt_with_caller_keys(&unsigned, &[unrelated_key])?;
        assert!(signed.inputs[0].partial_sigs.is_empty());
        assert!(signed.inputs[0].tap_key_sig.is_none());
        assert!(matches!(
            finalize_signed(signed),
            Err(FinalizeError::MissingSignature { index: 0 })
        ));
    }

    Ok(())
}

#[test]
fn p2wsh_finalize_orders_signatures_and_enforces_threshold()
-> Result<(), Box<dyn std::error::Error>> {
    let signer_a = test_signer::TestSigner::new()?;
    let key_b = bitcoin::PrivateKey {
        compressed: true,
        network: bitcoin::NetworkKind::Main,
        inner: bitcoin::secp256k1::SecretKey::from_slice(&[2_u8; 32])?,
    };
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let public_a = signer_a.public_key();
    let public_b = bitcoin::PublicKey::from_private_key(&secp, &key_b);
    let descriptor = Descriptor::parse(&format!("wsh(multi(2,{public_b},{public_a}))"))?;
    let script_pubkey = descriptor.script_pubkey()?;
    let outpoint = OutPoint {
        txid: Txid::from_byte_array([0x11_u8; 32]),
        vout: 0,
    };
    let prev_txout = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey,
    };
    let mut builder = PsbtBuilder::new(core::slice::from_ref(&descriptor));
    builder.add_input(PrevUtxo::new(outpoint, prev_txout), 0, 0)?;
    builder.add_output(
        descriptor.derive_address(Network::Regtest, 0)?,
        Amount::from_sat(40_000),
    )?;
    let unsigned = builder.finalize()?;

    let one_sig = sign_psbt_with_caller_keys(&unsigned, &[signer_a.caller_key()])?;
    assert!(matches!(
        finalize_signed(one_sig.clone()),
        Err(FinalizeError::InsufficientSignatures { index: 0 })
    ));

    let both = sign_psbt_with_caller_keys(&one_sig, &[key_b])?;
    let finalized = finalize_signed(both)?;
    let witness = &finalized.input[0].witness;
    assert_eq!(witness.len(), 4, "dummy, two signatures, witness script");
    assert!(witness.nth(0).is_some_and(<[u8]>::is_empty));
    let script = witness.nth(3).expect("witness script");
    let sig_a = witness.nth(1).expect("first signature");
    let sig_b = witness.nth(2).expect("second signature");
    assert_ne!(sig_a, sig_b);
    assert!(
        script
            .windows(public_b.to_bytes().len())
            .any(|w| w == public_b.to_bytes())
    );
    let pos_b = script
        .windows(public_b.to_bytes().len())
        .position(|w| w == public_b.to_bytes())
        .expect("key b in script");
    let pos_a = script
        .windows(public_a.to_bytes().len())
        .position(|w| w == public_a.to_bytes())
        .expect("key a in script");
    assert!(pos_b < pos_a, "script lists key B before key A");
    Ok(())
}

#[test]
fn unsupported_p2sh_redeem_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let signer = test_signer::TestSigner::new()?;
    let public_key = signer.public_key();
    let descriptor = Descriptor::parse(&format!("sh(wpkh({public_key}))"))?;
    let script_pubkey = descriptor.script_pubkey()?;
    let outpoint = OutPoint {
        txid: Txid::from_byte_array([0x22_u8; 32]),
        vout: 0,
    };
    let prev_txout = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey,
    };
    let mut builder = PsbtBuilder::new(core::slice::from_ref(&descriptor));
    builder.add_input(PrevUtxo::new(outpoint, prev_txout), 0, 0)?;
    builder.add_output(
        descriptor.derive_address(Network::Regtest, 0)?,
        Amount::from_sat(40_000),
    )?;
    let mut signed = sign_psbt_with_caller_keys(&builder.finalize()?, &[signer.caller_key()])?;
    let pubkey_bytes = public_key.to_bytes();
    let push = bitcoin::script::PushBytesBuf::try_from(pubkey_bytes)?;
    signed.inputs[0].redeem_script = Some(
        bitcoin::script::Builder::new()
            .push_int(1)
            .push_slice(push)
            .push_int(1)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKMULTISIG)
            .into_script(),
    );
    let err = finalize_signed(signed).expect_err("unsupported p2sh must fail");
    assert!(
        matches!(err, FinalizeError::UnsupportedScript { index: 0 }),
        "unexpected finalize error: {err:?}"
    );
    Ok(())
}

fn funding_transaction(spent: TxOut) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![spent],
    }
}

fn proven_p2pkh_psbt(
    public_key: bitcoin::PublicKey,
    spent: TxOut,
) -> Result<(bitcoin::psbt::Psbt, OutPoint, Transaction), Box<dyn std::error::Error>> {
    let descriptor = Descriptor::parse(&format!("pkh({public_key})"))?;
    let funding = funding_transaction(spent.clone());
    let outpoint = OutPoint {
        txid: funding.compute_txid(),
        vout: 0,
    };
    let mut builder = PsbtBuilder::new(core::slice::from_ref(&descriptor));
    builder.add_input(PrevUtxo::new(outpoint, spent), 0, 0)?;
    builder.add_output(
        descriptor.derive_address(Network::Regtest, 1)?,
        Amount::from_sat(40_000),
    )?;
    let mut unsigned = builder.finalize()?;
    unsigned.inputs[0].non_witness_utxo = Some(funding.clone());
    Ok((unsigned, outpoint, funding))
}

#[test]
fn safe_signing_rejects_legacy_witness_utxo_only() -> Result<(), Box<dyn std::error::Error>> {
    let signer = test_signer::TestSigner::new()?;
    let public_key = signer.public_key();
    let descriptor = Descriptor::parse(&format!("pkh({public_key})"))?;
    let prev_txout = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: descriptor.script_pubkey()?,
    };
    let outpoint = OutPoint {
        txid: Txid::from_byte_array([0xab_u8; 32]),
        vout: 0,
    };
    let mut builder = PsbtBuilder::new(core::slice::from_ref(&descriptor));
    builder.add_input(PrevUtxo::new(outpoint, prev_txout), 0, 0)?;
    builder.add_output(
        descriptor.derive_address(Network::Regtest, 1)?,
        Amount::from_sat(40_000),
    )?;
    let unsigned = builder.finalize()?;
    assert!(unsigned.inputs[0].witness_utxo.is_some());
    assert!(unsigned.inputs[0].non_witness_utxo.is_none());
    assert!(
        matches!(
            sign_psbt_with_caller_keys(&unsigned, &[signer.caller_key()]),
            Err(SignerError::UnsafeLegacyPrevout { index: 0 })
        ),
        "legacy witness-only metadata must be rejected"
    );
    Ok(())
}

#[test]
fn safe_signing_accepts_matching_non_witness_utxo() -> Result<(), Box<dyn std::error::Error>> {
    let signer = test_signer::TestSigner::new()?;
    let public_key = signer.public_key();
    let descriptor = Descriptor::parse(&format!("pkh({public_key})"))?;
    let prev_txout = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: descriptor.script_pubkey()?,
    };
    let (unsigned, _outpoint, _) = proven_p2pkh_psbt(public_key, prev_txout)?;
    let signed = sign_psbt_with_caller_keys(&unsigned, &[signer.caller_key()])?;
    assert!(!signed.inputs[0].partial_sigs.is_empty());
    let finalized = finalize_signed(signed)?;
    assert!(!finalized.input[0].script_sig.is_empty());
    Ok(())
}

#[test]
fn safe_signing_rejects_mismatched_non_witness_utxo() -> Result<(), Box<dyn std::error::Error>> {
    let signer = test_signer::TestSigner::new()?;
    let public_key = signer.public_key();
    let descriptor = Descriptor::parse(&format!("pkh({public_key})"))?;
    let prev_txout = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: descriptor.script_pubkey()?,
    };
    let outpoint = OutPoint {
        txid: Txid::from_byte_array([0xcd_u8; 32]),
        vout: 0,
    };
    let mut builder = PsbtBuilder::new(core::slice::from_ref(&descriptor));
    builder.add_input(PrevUtxo::new(outpoint, prev_txout.clone()), 0, 0)?;
    builder.add_output(
        descriptor.derive_address(Network::Regtest, 1)?,
        Amount::from_sat(40_000),
    )?;
    let mut unsigned = builder.finalize()?;
    unsigned.inputs[0].non_witness_utxo = Some(Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![prev_txout],
    });
    assert!(
        matches!(
            sign_psbt_with_caller_keys(&unsigned, &[signer.caller_key()]),
            Err(SignerError::MismatchedNonWitnessUtxo { index: 0 })
        ),
        "txid mismatch must be rejected"
    );
    Ok(())
}

#[test]
fn explicit_prevout_signing_accepts_legacy_witness_utxo() -> Result<(), Box<dyn std::error::Error>>
{
    let signer = test_signer::TestSigner::new()?;
    let public_key = signer.public_key();
    let descriptor = Descriptor::parse(&format!("pkh({public_key})"))?;
    let prev_txout = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: descriptor.script_pubkey()?,
    };
    let outpoint = OutPoint {
        txid: Txid::from_byte_array([0xef_u8; 32]),
        vout: 0,
    };
    let mut builder = PsbtBuilder::new(core::slice::from_ref(&descriptor));
    builder.add_input(PrevUtxo::new(outpoint, prev_txout), 0, 0)?;
    builder.add_output(
        descriptor.derive_address(Network::Regtest, 1)?,
        Amount::from_sat(40_000),
    )?;
    let unsigned = builder.finalize()?;
    let signed = sign_psbt_with_explicit_prevouts(&unsigned, &[signer.caller_key()])?;
    assert!(!signed.inputs[0].partial_sigs.is_empty());
    let finalized = finalize_signed(signed)?;
    assert!(!finalized.input[0].script_sig.is_empty());
    Ok(())
}
