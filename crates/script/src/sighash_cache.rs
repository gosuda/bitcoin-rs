use bitcoin::sighash::{
    EcdsaSighashType, LegacySighash, P2wpkhError, Prevouts, SegwitV0Sighash, TapSighash,
    TapSighashType, TaprootError,
};
use bitcoin::{Amount, Script, TapLeafHash, TxOut};
use bitcoin_rs_primitives::Tx;

/// Public signature-hash cache wrapper for bitcoin-rs script callers.
#[derive(Debug)]
pub struct SigHashCache<'a> {
    inner: bitcoin::sighash::SighashCache<&'a bitcoin::Transaction>,
}

impl<'a> SigHashCache<'a> {
    /// Creates a cache for a transaction.
    #[must_use]
    pub fn new(tx: &'a Tx) -> Self {
        Self {
            inner: bitcoin::sighash::SighashCache::new(&tx.0),
        }
    }

    /// Computes a legacy signature hash.
    pub fn legacy_signature_hash(
        &self,
        input_index: usize,
        script_pubkey: &Script,
        sighash_type: u32,
    ) -> Result<LegacySighash, bitcoin::transaction::InputsIndexError> {
        self.inner
            .legacy_signature_hash(input_index, script_pubkey, sighash_type)
    }

    /// Computes a BIP143 P2WPKH signature hash.
    pub fn p2wpkh_signature_hash(
        &mut self,
        input_index: usize,
        script_pubkey: &Script,
        value: Amount,
        sighash_type: EcdsaSighashType,
    ) -> Result<SegwitV0Sighash, P2wpkhError> {
        self.inner
            .p2wpkh_signature_hash(input_index, script_pubkey, value, sighash_type)
    }

    /// Computes a BIP143 P2WSH signature hash.
    pub fn p2wsh_signature_hash(
        &mut self,
        input_index: usize,
        witness_script: &Script,
        value: Amount,
        sighash_type: EcdsaSighashType,
    ) -> Result<SegwitV0Sighash, bitcoin::transaction::InputsIndexError> {
        self.inner
            .p2wsh_signature_hash(input_index, witness_script, value, sighash_type)
    }

    /// Computes a BIP341 taproot key-path signature hash.
    pub fn taproot_key_spend_signature_hash<T: std::borrow::Borrow<TxOut>>(
        &mut self,
        input_index: usize,
        prevouts: &Prevouts<T>,
        sighash_type: TapSighashType,
    ) -> Result<TapSighash, TaprootError> {
        self.inner
            .taproot_key_spend_signature_hash(input_index, prevouts, sighash_type)
    }

    /// Computes a BIP342 tapscript signature hash.
    pub fn taproot_script_spend_signature_hash<S, T>(
        &mut self,
        input_index: usize,
        prevouts: &Prevouts<T>,
        leaf_hash: S,
        sighash_type: TapSighashType,
    ) -> Result<TapSighash, TaprootError>
    where
        S: Into<TapLeafHash>,
        T: std::borrow::Borrow<TxOut>,
    {
        self.inner.taproot_script_spend_signature_hash(
            input_index,
            prevouts,
            leaf_hash,
            sighash_type,
        )
    }
}
