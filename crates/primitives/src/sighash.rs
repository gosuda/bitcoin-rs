use bitcoin::hashes::Hash as _;
use bitcoin::sighash::{
    Annex, AnnexError, EcdsaSighashType, Prevouts, PrevoutsIndexError, SighashCache,
    TapSighashType, TaprootError,
};
use bitcoin::{Amount, Script, TapLeafHash, TxOut};

use crate::{Hash256, Tx};
use thiserror::Error;

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

/// Errors returned while computing signature hashes.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SighashError {
    /// The requested transaction input does not exist.
    #[error("input index {index} out of range for {total} inputs")]
    InputOutOfRange {
        /// Requested input index.
        index: usize,
        /// Number of transaction inputs.
        total: usize,
    },
    /// `SIGHASH_DEFAULT` is valid for taproot only.
    #[error("SIGHASH_DEFAULT is valid only for taproot")]
    DefaultOnlyTaproot,
    /// Taproot annex bytes failed BIP341 validation.
    #[error("invalid taproot annex: {0}")]
    InvalidAnnex(#[source] AnnexError),
    /// Taproot `SIGHASH_SINGLE` requires an output at the same index as the input.
    #[error(
        "sighash single requires output at input index {input_index}; outputs length {outputs_length}"
    )]
    SingleMissingOutput {
        /// Input index being signed.
        input_index: usize,
        /// Number of transaction outputs.
        outputs_length: usize,
    },
    /// Taproot prevout count must match the transaction input count.
    #[error("taproot prevouts length {provided} does not match input count {expected}")]
    PrevoutsLength {
        /// Supplied prevout count.
        provided: usize,
        /// Transaction input count.
        expected: usize,
    },
    /// Taproot prevout lookup failed.
    #[error("taproot prevout index invalid: {0}")]
    PrevoutsIndex(#[source] PrevoutsIndexError),
    /// A future bitcoin crate taproot error variant was returned.
    #[error("taproot sighash failed: {0}")]
    Taproot(#[source] TaprootError),
}

impl Sighash {
    /// Computes the pre-segwit legacy signature hash.
    pub fn compute_legacy(
        tx: &Tx,
        input_idx: usize,
        script_code: &[u8],
        sighash_type: Self,
    ) -> Result<Hash256, SighashError> {
        let ty = sighash_type.to_ecdsa()?;
        let cache = SighashCache::new(&tx.0);
        let script = Script::from_bytes(script_code);
        let hash = cache
            .legacy_signature_hash(input_idx, script, ty.to_u32())
            .map_err(|error| input_out_of_range(error.0.index, error.0.length))?;
        Ok(Hash256::from_le_bytes(hash.as_byte_array()))
    }

    /// Computes the BIP143 segwit-v0 signature hash.
    pub fn compute_bip143(
        tx: &Tx,
        input_idx: usize,
        script_code: &[u8],
        value: u64,
        sighash_type: Self,
    ) -> Result<Hash256, SighashError> {
        let ty = sighash_type.to_ecdsa()?;
        let mut cache = SighashCache::new(&tx.0);
        let script = Script::from_bytes(script_code);
        let hash = cache
            .p2wsh_signature_hash(input_idx, script, Amount::from_sat(value), ty)
            .map_err(|error| input_out_of_range(error.0.index, error.0.length))?;
        Ok(Hash256::from_le_bytes(hash.as_byte_array()))
    }

    /// Computes the BIP341 taproot signature hash for key-path or script-path spends.
    pub fn compute_bip341(
        tx: &Tx,
        input_idx: usize,
        prevouts: &[TxOut],
        sighash_type: Self,
        leaf_hash: Option<Hash256>,
        annex: Option<&[u8]>,
    ) -> Result<Hash256, SighashError> {
        let ty = sighash_type.to_taproot();
        let mut cache = SighashCache::new(&tx.0);
        let prevout_count = prevouts.len();
        let prevouts = Prevouts::All(prevouts);
        let annex = annex.map(valid_annex).transpose()?;
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
        }
        .map_err(|error| taproot_error(error, tx.0.input.len(), prevout_count))?;
        Ok(Hash256::from_le_bytes(hash.as_byte_array()))
    }

    /// Computes the BIP342 tapscript signature hash.
    pub fn compute_bip342(
        tx: &Tx,
        input_idx: usize,
        prevouts: &[TxOut],
        sighash_type: Self,
        leaf_hash: Hash256,
        annex: Option<&[u8]>,
    ) -> Result<Hash256, SighashError> {
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

    const fn to_ecdsa(self) -> Result<EcdsaSighashType, SighashError> {
        match self {
            Self::All => Ok(EcdsaSighashType::All),
            Self::None => Ok(EcdsaSighashType::None),
            Self::Single => Ok(EcdsaSighashType::Single),
            Self::AllAnyoneCanPay => Ok(EcdsaSighashType::AllPlusAnyoneCanPay),
            Self::NoneAnyoneCanPay => Ok(EcdsaSighashType::NonePlusAnyoneCanPay),
            Self::SingleAnyoneCanPay => Ok(EcdsaSighashType::SinglePlusAnyoneCanPay),
            Self::Default => Err(SighashError::DefaultOnlyTaproot),
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

fn valid_annex(bytes: &[u8]) -> Result<Annex<'_>, SighashError> {
    Annex::new(bytes).map_err(SighashError::InvalidAnnex)
}

const fn input_out_of_range(index: usize, total: usize) -> SighashError {
    SighashError::InputOutOfRange { index, total }
}

const fn taproot_error(
    error: TaprootError,
    input_count: usize,
    prevout_count: usize,
) -> SighashError {
    match error {
        TaprootError::InputsIndex(error) => input_out_of_range(error.0.index, error.0.length),
        TaprootError::SingleMissingOutput(error) => SighashError::SingleMissingOutput {
            input_index: error.input_index,
            outputs_length: error.outputs_length,
        },
        TaprootError::PrevoutsSize(_) => SighashError::PrevoutsLength {
            provided: prevout_count,
            expected: input_count,
        },
        TaprootError::PrevoutsIndex(error) => SighashError::PrevoutsIndex(error),
        _ => SighashError::Taproot(error),
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

    use super::{Sighash, SighashError};
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
                Ok(expected)
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
            Ok(expected)
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
            Ok(expected_key)
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
            Ok(expected_script)
        );
    }

    #[test]
    fn legacy_sighash_reports_out_of_range_input() {
        let tx = Tx(synthetic_tx(1));
        let script = ScriptBuf::new();

        assert!(matches!(
            Sighash::compute_legacy(&tx, 999, script.as_bytes(), Sighash::All),
            Err(SighashError::InputOutOfRange {
                index: 999,
                total: 1
            })
        ));
    }

    #[test]
    fn bip143_rejects_default_sighash_without_panicking() {
        let tx = Tx(synthetic_tx(1));
        let script = ScriptBuf::new();

        assert_eq!(
            Sighash::compute_bip143(&tx, 0, script.as_bytes(), 50_000, Sighash::Default),
            Err(SighashError::DefaultOnlyTaproot)
        );
    }

    #[test]
    fn taproot_sighash_reports_invalid_annex() {
        let tx = Tx(synthetic_tx(1));
        let prevouts = vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::new(),
        }];

        assert!(matches!(
            Sighash::compute_bip341(&tx, 0, &prevouts, Sighash::All, None, Some(&[0x51])),
            Err(SighashError::InvalidAnnex(_))
        ));
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
