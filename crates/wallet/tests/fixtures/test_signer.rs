//! Test-only external signer fixture.
use bitcoin::PublicKey;
use bitcoin::key::{Keypair, TapTweak};
use bitcoin::psbt::Psbt;
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin_rs_wallet::{ExternalSigner, SignerError};

pub(crate) struct TestSigner {
    secp: bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>,
    key: bitcoin::secp256k1::SecretKey,
    public_key: PublicKey,
}

impl TestSigner {
    pub(crate) fn new() -> Result<Self, bitcoin::secp256k1::Error> {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let key = bitcoin::secp256k1::SecretKey::from_slice(&[1_u8; 32])?;
        let secp_public = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &key);
        Ok(Self {
            secp,
            key,
            public_key: PublicKey::new(secp_public),
        })
    }

    pub(crate) const fn public_key(&self) -> PublicKey {
        self.public_key
    }

    /// Returns the signer's key in the caller-supplied form used by
    /// transient signing calls.
    // Usage varies per test binary sharing this fixture; item-level allow
    // is the only form that holds across all of them.
    #[allow(dead_code)]
    pub(crate) fn caller_key(&self) -> bitcoin::PrivateKey {
        bitcoin::PrivateKey {
            compressed: true,
            network: bitcoin::NetworkKind::Main,
            inner: self.key,
        }
    }

    /// Returns a watch-only BIP32 account xpub for the signer's key.
    #[allow(dead_code)]
    #[allow(clippy::expect_used)]
    pub(crate) fn bip32_xpub(&self) -> bitcoin::bip32::Xpub {
        bitcoin::bip32::Xpub {
            network: bitcoin::NetworkKind::Main,
            depth: 0,
            parent_fingerprint: bitcoin::bip32::Fingerprint::default(),
            child_number: bitcoin::bip32::ChildNumber::from_normal_idx(0)
                .expect("zero is a normal child"),
            chain_code: bitcoin::bip32::ChainCode::from([0_u8; 32]),
            public_key: self.public_key.inner,
        }
    }
}

impl ExternalSigner for TestSigner {
    fn sign_psbt(&self, psbt: &Psbt) -> Result<Psbt, SignerError> {
        let mut signed = psbt.clone();
        let tx = psbt.unsigned_tx.clone();
        let mut cache = SighashCache::new(&tx);
        for index in 0..psbt.inputs.len() {
            let utxo = psbt
                .spend_utxo(index)
                .map_err(|error| SignerError::Rejected(error.to_string()))?;
            if utxo.script_pubkey.is_p2tr() {
                let prevouts = all_prevouts(psbt)?;
                let sighash = cache
                    .taproot_key_spend_signature_hash(
                        index,
                        &Prevouts::All(&prevouts),
                        bitcoin::TapSighashType::Default,
                    )
                    .map_err(|error| SignerError::Rejected(error.to_string()))?;
                let message = bitcoin::secp256k1::Message::from(sighash);
                let keypair = Keypair::from_secret_key(&self.secp, &self.key);
                let tweaked = keypair.tap_tweak(&self.secp, None).to_keypair();
                let signature = self.secp.sign_schnorr_no_aux_rand(&message, &tweaked);
                signed.inputs[index].tap_key_sig = Some(bitcoin::taproot::Signature {
                    signature,
                    sighash_type: bitcoin::TapSighashType::Default,
                });
            } else {
                let (message, hash_ty) = psbt
                    .sighash_ecdsa(index, &mut cache)
                    .map_err(|error| SignerError::Rejected(error.to_string()))?;
                let signature = self.secp.sign_ecdsa(&message, &self.key);
                signed.inputs[index].partial_sigs.insert(
                    self.public_key,
                    bitcoin::ecdsa::Signature {
                        signature,
                        sighash_type: hash_ty,
                    },
                );
            }
        }
        Ok(signed)
    }
}

fn all_prevouts(psbt: &Psbt) -> Result<Vec<&bitcoin::TxOut>, SignerError> {
    (0..psbt.inputs.len())
        .map(|index| {
            psbt.spend_utxo(index)
                .map_err(|error| SignerError::Rejected(error.to_string()))
        })
        .collect()
}
