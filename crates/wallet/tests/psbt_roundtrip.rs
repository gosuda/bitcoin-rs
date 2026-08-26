//! PSBT build, external signing, caller-key signing, finalization, and
//! consensus roundtrips.
use std::collections::BTreeMap;

use bitcoin::hashes::Hash as _;
use bitcoin::{Amount, Network, OutPoint, TxOut, Txid};
use bitcoin_rs_consensus::verify_transaction;
use bitcoin_rs_script::VerifyFlags;
use bitcoin_rs_wallet::{
    Descriptor, ExternalSigner, FinalizeError, PrevUtxo, PsbtBuilder, finalize_signed,
    sign_psbt_with_caller_keys,
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
