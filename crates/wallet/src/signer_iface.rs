use thiserror::Error;

/// External signer errors surfaced to wallet callers.
#[derive(Debug, Error)]
pub enum SignerError {
    /// The signer refused or could not satisfy the PSBT.
    #[error("external signer rejected PSBT: {0}")]
    Rejected(String),
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
    fn sign_psbt(&self, psbt: &bitcoin::psbt::Psbt) -> Result<bitcoin::psbt::Psbt, SignerError>;
}
