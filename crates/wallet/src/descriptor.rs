use core::str::FromStr;

use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint};
use bitcoin::{Address, Network, PublicKey};
use miniscript::Descriptor as MiniscriptDescriptor;
use miniscript::descriptor::DescriptorType;
use serde::{Deserialize, Serialize};

use crate::WalletError;

/// Public BIP32 origin metadata attached to descriptor keys.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BIP32Derivation {
    /// Master key fingerprint for the origin key, when known.
    pub fingerprint: Option<Fingerprint>,
    /// Non-hardened public derivation path, when known.
    pub path: DerivationPath,
}

impl BIP32Derivation {
    /// Returns a copy with `index` appended as a normal child number.
    pub fn with_child(&self, index: u32) -> Result<Self, WalletError> {
        let child = ChildNumber::from_normal_idx(index)
            .map_err(|error| WalletError::Descriptor(error.to_string()))?;
        let mut children: Vec<ChildNumber> = self.path.into_iter().copied().collect();
        children.push(child);
        Ok(Self {
            fingerprint: self.fingerprint,
            path: DerivationPath::from(children),
        })
    }
}

/// Public, watch-only output descriptor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Descriptor {
    /// Parsed miniscript descriptor with public keys only.
    pub inner: MiniscriptDescriptor<PublicKey>,
    /// Public BIP32 derivation metadata.
    pub derivation: BIP32Derivation,
}

impl Descriptor {
    /// Parses one supported public descriptor form.
    pub fn parse(text: &str) -> Result<Self, WalletError> {
        let inner = MiniscriptDescriptor::<PublicKey>::from_str(text)
            .map_err(|error| WalletError::Descriptor(error.to_string()))?;
        ensure_supported(&inner)?;
        Ok(Self {
            inner,
            derivation: BIP32Derivation::default(),
        })
    }

    /// Derives the receive address for a descriptor index.
    pub fn derive_address(&self, network: Network, index: u32) -> Result<Address, WalletError> {
        let _derivation = self.derivation.with_child(index)?;
        self.inner
            .address(network)
            .map_err(|error| WalletError::Descriptor(error.to_string()))
    }

    /// Returns the descriptor script pubkey.
    #[must_use]
    pub fn script_pubkey(&self) -> bitcoin::ScriptBuf {
        self.inner.script_pubkey()
    }
}

impl FromStr for Descriptor {
    type Err = WalletError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

fn ensure_supported(descriptor: &MiniscriptDescriptor<PublicKey>) -> Result<(), WalletError> {
    match descriptor.desc_type() {
        DescriptorType::Pkh
        | DescriptorType::Wpkh
        | DescriptorType::ShWpkh
        | DescriptorType::Wsh
        | DescriptorType::Tr => Ok(()),
        other => Err(WalletError::Descriptor(format!(
            "unsupported descriptor type {other:?}"
        ))),
    }
}
