use bitcoin::hashes::Hash as _;
use bitcoin::sighash::{Annex, EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::{Amount, Script, TapLeafHash, TxOut};

use crate::{Hash256, Tx};

/// Standard Bitcoin signature hash modes used by legacy, segwit, and taproot signing.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Sighash {
    /// `SIGHASH_ALL`.
    All,
    /// `SIGHASH_NONE`.
    None,
    /// `SIGHASH_SINGLE`.
    Single,
    /// `SIGHASH_ALL | SIGHASH_ANYONECANPAY`.
    AllAnyoneCanPay,
    /// `SIGHASH_NONE | SIGHASH_ANYONECANPAY`.
    NoneAnyoneCanPay,
    /// `SIGHASH_SINGLE | SIGHASH_ANYONECANPAY`.
    SingleAnyoneCanPay,
    /// `SIGHASH_DEFAULT`, valid for taproot only.
    Default,
}

impl Sighash {
    /// Computes the pre-segwit legacy signature hash.
    #[must_use]
    pub fn compute_legacy(
        tx: &Tx,
        input_idx: usize,
        script_code: &[u8],
        sighash_type: Self,
    ) -> Hash256 {
        let ty = sighash_type.to_ecdsa();
        let cache = SighashCache::new(&tx.0);
        let script = Script::from_bytes(script_code);
        let hash = match cache.legacy_signature_hash(input_idx, script, ty.to_u32()) {
            Ok(hash) => hash,
            Err(error) => panic!("legacy sighash failed: {error}"),
        };
        Hash256::from_le_bytes(hash.as_byte_array())
    }

    /// Computes the BIP143 segwit-v0 signature hash.
    #[must_use]
    pub fn compute_bip143(
        tx: &Tx,
        input_idx: usize,
        script_code: &[u8],
        value: u64,
        sighash_type: Self,
    ) -> Hash256 {
        let ty = sighash_type.to_ecdsa();
        let mut cache = SighashCache::new(&tx.0);
        let script = Script::from_bytes(script_code);
        let hash = match cache.p2wsh_signature_hash(input_idx, script, Amount::from_sat(value), ty)
        {
            Ok(hash) => hash,
            Err(error) => panic!("bip143 sighash failed: {error}"),
        };
        Hash256::from_le_bytes(hash.as_byte_array())
    }

    /// Computes the BIP341 taproot signature hash for key-path or script-path spends.
    #[must_use]
    pub fn compute_bip341(
        tx: &Tx,
        input_idx: usize,
        prevouts: &[TxOut],
        sighash_type: Self,
        leaf_hash: Option<Hash256>,
        annex: Option<&[u8]>,
    ) -> Hash256 {
        let ty = sighash_type.to_taproot();
        let mut cache = SighashCache::new(&tx.0);
        let prevouts = Prevouts::All(prevouts);
        let annex = annex.map(valid_annex);
        let hash = match leaf_hash {
            Some(leaf_hash) => {
                let leaf_hash = TapLeafHash::from_byte_array(leaf_hash.to_le_bytes());
                cache.taproot_signature_hash(
                    input_idx,
                    &prevouts,
                    annex,
                    Some((leaf_hash, 0xffff_ffff)),
                    ty,
                )
            }
            None => cache.taproot_signature_hash(input_idx, &prevouts, annex, None, ty),
        };
        match hash {
            Ok(hash) => Hash256::from_le_bytes(hash.as_byte_array()),
            Err(error) => panic!("bip341 sighash failed: {error}"),
        }
    }

    /// Computes the BIP342 tapscript signature hash.
    #[must_use]
    pub fn compute_bip342(
        tx: &Tx,
        input_idx: usize,
        prevouts: &[TxOut],
        sighash_type: Self,
        leaf_hash: Hash256,
        annex: Option<&[u8]>,
    ) -> Hash256 {
        Self::compute_bip341(
            tx,
            input_idx,
            prevouts,
            sighash_type,
            Some(leaf_hash),
            annex,
        )
    }

    /// Returns the consensus byte for the sighash mode.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        match self {
            Self::Default => 0x00,
            Self::All => 0x01,
            Self::None => 0x02,
            Self::Single => 0x03,
            Self::AllAnyoneCanPay => 0x81,
            Self::NoneAnyoneCanPay => 0x82,
            Self::SingleAnyoneCanPay => 0x83,
        }
    }

    fn to_ecdsa(self) -> EcdsaSighashType {
        match self {
            Self::All => EcdsaSighashType::All,
            Self::None => EcdsaSighashType::None,
            Self::Single => EcdsaSighashType::Single,
            Self::AllAnyoneCanPay => EcdsaSighashType::AllPlusAnyoneCanPay,
            Self::NoneAnyoneCanPay => EcdsaSighashType::NonePlusAnyoneCanPay,
            Self::SingleAnyoneCanPay => EcdsaSighashType::SinglePlusAnyoneCanPay,
            Self::Default => panic!("SIGHASH_DEFAULT is valid only for taproot"),
        }
    }

    const fn to_taproot(self) -> TapSighashType {
        match self {
            Self::Default => TapSighashType::Default,
            Self::All => TapSighashType::All,
            Self::None => TapSighashType::None,
            Self::Single => TapSighashType::Single,
            Self::AllAnyoneCanPay => TapSighashType::AllPlusAnyoneCanPay,
            Self::NoneAnyoneCanPay => TapSighashType::NonePlusAnyoneCanPay,
            Self::SingleAnyoneCanPay => TapSighashType::SinglePlusAnyoneCanPay,
        }
    }
}

fn valid_annex(bytes: &[u8]) -> Annex<'_> {
    match Annex::new(bytes) {
        Ok(annex) => annex,
        Err(error) => panic!("invalid taproot annex: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash as _;
    use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
    use bitcoin::{
        Amount, OutPoint as BitcoinOutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
        Witness, absolute,
    };

    use super::Sighash;
    use crate::{Hash256, Tx};

    #[test]
    fn legacy_sighash_matches_bitcoin_cache_for_all_ecdsa_modes() {
        let tx = Tx(synthetic_tx(2));
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let modes = [
            (Sighash::All, EcdsaSighashType::All),
            (Sighash::None, EcdsaSighashType::None),
            (Sighash::Single, EcdsaSighashType::Single),
            (
                Sighash::AllAnyoneCanPay,
                EcdsaSighashType::AllPlusAnyoneCanPay,
            ),
            (
                Sighash::NoneAnyoneCanPay,
                EcdsaSighashType::NonePlusAnyoneCanPay,
            ),
            (
                Sighash::SingleAnyoneCanPay,
                EcdsaSighashType::SinglePlusAnyoneCanPay,
            ),
        ];

        for (ours, bitcoin_ty) in modes {
            let cache = SighashCache::new(&tx.0);
            let expected = match cache.legacy_signature_hash(0, &script, bitcoin_ty.to_u32()) {
                Ok(hash) => Hash256::from_le_bytes(hash.as_byte_array()),
                Err(error) => panic!("fixture legacy sighash failed: {error}"),
            };
            assert_eq!(
                Sighash::compute_legacy(&tx, 0, script.as_bytes(), ours),
                expected
            );
        }
    }

    #[test]
    fn bip143_sighash_matches_bitcoin_cache() {
        let tx = Tx(synthetic_tx(2));
        let script = ScriptBuf::from_bytes(vec![0x51, 0x51]);
        let value = 50_000;
        let mut cache = SighashCache::new(&tx.0);
        let expected = match cache.p2wsh_signature_hash(
            0,
            &script,
            Amount::from_sat(value),
            EcdsaSighashType::Single,
        ) {
            Ok(hash) => Hash256::from_le_bytes(hash.as_byte_array()),
            Err(error) => panic!("fixture bip143 sighash failed: {error}"),
        };

        assert_eq!(
            Sighash::compute_bip143(&tx, 0, script.as_bytes(), value, Sighash::Single),
            expected
        );
    }

    #[test]
    fn bip341_key_path_and_bip342_script_path_match_bitcoin_cache() {
        let tx = Tx(synthetic_tx(2));
        let prevouts = vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::new(),
        }];
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let leaf_hash = script.tapscript_leaf_hash();

        let mut key_cache = SighashCache::new(&tx.0);
        let expected_key = match key_cache.taproot_signature_hash(
            0,
            &Prevouts::All(&prevouts),
            None,
            None,
            TapSighashType::AllPlusAnyoneCanPay,
        ) {
            Ok(hash) => Hash256::from_le_bytes(hash.as_byte_array()),
            Err(error) => panic!("fixture taproot key sighash failed: {error}"),
        };
        assert_eq!(
            Sighash::compute_bip341(&tx, 0, &prevouts, Sighash::AllAnyoneCanPay, None, None),
            expected_key
        );

        let mut script_cache = SighashCache::new(&tx.0);
        let expected_script = match script_cache.taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&prevouts),
            leaf_hash,
            TapSighashType::Default,
        ) {
            Ok(hash) => Hash256::from_le_bytes(hash.as_byte_array()),
            Err(error) => panic!("fixture tapscript sighash failed: {error}"),
        };
        let leaf_hash = Hash256::from_le_bytes(leaf_hash.as_byte_array());
        assert_eq!(
            Sighash::compute_bip342(&tx, 0, &prevouts, Sighash::Default, leaf_hash, None),
            expected_script
        );
    }

    fn synthetic_tx(output_count: usize) -> Transaction {
        let previous_output = BitcoinOutPoint::null();
        let input = TxIn {
            previous_output,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        };
        let mut outputs = Vec::new();
        for value in 0_u64
            ..u64::try_from(output_count)
                .unwrap_or_else(|_| unreachable!("small fixture output count"))
        {
            outputs.push(TxOut {
                value: Amount::from_sat(1_000 + value),
                script_pubkey: ScriptBuf::new(),
            });
        }
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![input],
            output: outputs,
        }
    }
}
