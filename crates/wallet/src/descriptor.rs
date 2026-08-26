use core::fmt;
use core::ops::RangeInclusive;
use core::str::FromStr;

use bitcoin::address::NetworkUnchecked;
use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint};
use bitcoin::hex::DisplayHex as _;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, Network, ScriptBuf};
use miniscript::descriptor::{DescriptorPublicKey, DescriptorType, Wildcard, checksum};
use miniscript::{Descriptor as MiniscriptDescriptor, ForEachKey as _};
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

/// Semantic descriptor analysis returned to protocol adapters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DescriptorInfo {
    /// Canonical public descriptor, including its BIP-380 checksum.
    pub descriptor: String,
    /// Alias for [`Self::descriptor`] matching older call sites.
    pub canonical: String,
    /// Canonical expansion of each multipath branch.
    pub multipath_expansion: Vec<String>,
    /// The canonical descriptor checksum.
    pub checksum: String,
    /// Whether the descriptor contains a wildcard derivation step.
    pub is_range: bool,
    /// Whether the descriptor passes miniscript safety checks / is solvable.
    pub is_solvable: bool,
    /// Whether the analyzed input contained private key material.
    pub has_private_keys: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum DescriptorBody {
    Miniscript(Box<MiniscriptDescriptor<DescriptorPublicKey>>),
    /// Bitcoin Core `addr()` descriptor.
    Addr(Address<NetworkUnchecked>),
    /// Bitcoin Core `raw()` descriptor.
    Raw(ScriptBuf),
}

/// Public, watch-only output descriptor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Descriptor {
    body: DescriptorBody,
    /// Public BIP32 derivation metadata retained for callers that attach it separately.
    pub derivation: BIP32Derivation,
}

impl Descriptor {
    /// Parses one public descriptor. Multipath descriptors must be imported with
    /// [`Descriptor::parse_all`].
    pub fn parse(text: &str) -> Result<Self, WalletError> {
        let mut descriptors = Self::parse_all(text)?;
        if descriptors.len() != 1 {
            return Err(WalletError::Descriptor(
                "multipath descriptor expands to more than one descriptor".to_owned(),
            ));
        }
        Ok(descriptors.remove(0))
    }

    /// Parses and expands a public descriptor without retaining any secret key material.
    pub fn parse_all(text: &str) -> Result<Vec<Self>, WalletError> {
        if let Some(unspendable) = parse_unspendable(text)? {
            return Ok(vec![Self {
                body: unspendable,
                derivation: BIP32Derivation::default(),
            }]);
        }

        let secp = Secp256k1::signing_only();
        let (inner, key_map) =
            MiniscriptDescriptor::<DescriptorPublicKey>::parse_descriptor(&secp, text)
                .map_err(|error| WalletError::Descriptor(error.to_string()))?;
        if !key_map.is_empty() {
            return Err(WalletError::PrivateDescriptor);
        }
        if inner.for_any_key(requires_private_derivation) {
            return Err(WalletError::Descriptor(
                "hardened derivation requires private key material".to_owned(),
            ));
        }
        ensure_supported(&inner)?;
        inner
            .into_single_descriptors()
            .map_err(|error| WalletError::Descriptor(error.to_string()))?
            .into_iter()
            .map(|inner| {
                ensure_supported(&inner)?;
                Ok(Self {
                    body: DescriptorBody::Miniscript(Box::new(inner)),
                    derivation: BIP32Derivation::default(),
                })
            })
            .collect()
    }

    /// Analyzes a descriptor without importing it. Secret keys are converted to
    /// public keys only for the returned analysis and are never retained.
    pub fn info(text: &str) -> Result<DescriptorInfo, WalletError> {
        analyse(text)
    }

    /// Returns whether this descriptor requires a derivation range.
    #[must_use]
    pub fn is_ranged(&self) -> bool {
        match &self.body {
            DescriptorBody::Miniscript(inner) => inner.has_wildcard(),
            DescriptorBody::Addr(_) | DescriptorBody::Raw(_) => false,
        }
    }

    /// Derives the receive address for a descriptor index.
    pub fn derive_address(&self, network: Network, index: u32) -> Result<Address, WalletError> {
        let _derivation = self.derivation.with_child(index)?;
        match &self.body {
            DescriptorBody::Addr(address) => {
                if index != 0 {
                    return Err(WalletError::DescriptorRange(
                        "Range should not be specified for an un-ranged descriptor",
                    ));
                }
                if !address.is_valid_for_network(network) {
                    return Err(WalletError::Descriptor(
                        "address is not valid for the requested network".to_owned(),
                    ));
                }
                address
                    .clone()
                    .require_network(network)
                    .map_err(|error| WalletError::Descriptor(error.to_string()))
            }
            DescriptorBody::Raw(script) => {
                if index != 0 {
                    return Err(WalletError::DescriptorRange(
                        "Range should not be specified for an un-ranged descriptor",
                    ));
                }
                Address::from_script(script, network).map_err(|_error| {
                    WalletError::Descriptor(
                        "Descriptor does not have a corresponding address".to_owned(),
                    )
                })
            }
            DescriptorBody::Miniscript(_) => self
                .derived(index)?
                .address(network)
                .map_err(|error| WalletError::Descriptor(error.to_string())),
        }
    }

    /// Derives every address in an inclusive range.
    pub fn derive_addresses(
        &self,
        network: Network,
        range: RangeInclusive<u32>,
    ) -> Result<Vec<Address>, WalletError> {
        validate_range(self.is_ranged(), &range)?;
        range
            .map(|index| self.derive_address(network, index))
            .collect()
    }

    /// Returns the descriptor script pubkey at derivation index zero.
    pub fn script_pubkey(&self) -> Result<ScriptBuf, WalletError> {
        self.script_pubkey_at(0)
    }

    /// Returns the descriptor script pubkey at a derivation index.
    pub fn script_pubkey_at(&self, index: u32) -> Result<ScriptBuf, WalletError> {
        match &self.body {
            DescriptorBody::Addr(address) => {
                if index != 0 {
                    return Err(WalletError::DescriptorRange(
                        "Range should not be specified for an un-ranged descriptor",
                    ));
                }
                Ok(address.clone().assume_checked().script_pubkey())
            }
            DescriptorBody::Raw(script) => {
                if index != 0 {
                    return Err(WalletError::DescriptorRange(
                        "Range should not be specified for an un-ranged descriptor",
                    ));
                }
                Ok(script.clone())
            }
            DescriptorBody::Miniscript(_) => Ok(self.derived(index)?.script_pubkey()),
        }
    }

    /// Returns the redeem or witness script for a derivation index.
    pub fn explicit_script_at(&self, index: u32) -> Result<ScriptBuf, WalletError> {
        match &self.body {
            DescriptorBody::Addr(_) | DescriptorBody::Raw(_) => Err(WalletError::Descriptor(
                "unspendable descriptors have no explicit script".to_owned(),
            )),
            DescriptorBody::Miniscript(_) => self
                .derived(index)?
                .explicit_script()
                .map_err(|error| WalletError::Descriptor(error.to_string())),
        }
    }

    /// Canonical public descriptor string, including BIP-380 checksum.
    #[must_use]
    pub fn to_descriptor_string(&self) -> String {
        match &self.body {
            DescriptorBody::Miniscript(inner) => inner.to_string(),
            DescriptorBody::Addr(address) => {
                let payload = format!("addr({})", address.clone().assume_checked());
                checksummed(&payload).unwrap_or(payload)
            }
            DescriptorBody::Raw(script) => {
                let payload = format!("raw({})", script.as_bytes().to_lower_hex_string());
                checksummed(&payload).unwrap_or(payload)
            }
        }
    }

    fn derived(&self, index: u32) -> Result<MiniscriptDescriptor<bitcoin::PublicKey>, WalletError> {
        let DescriptorBody::Miniscript(inner) = &self.body else {
            return Err(WalletError::Descriptor(
                "unspendable descriptors have no miniscript derivation".to_owned(),
            ));
        };
        if inner.for_any_key(requires_private_derivation) {
            return Err(WalletError::Descriptor(
                "hardened derivation requires private key material".to_owned(),
            ));
        }
        let secp = Secp256k1::verification_only();
        inner
            .derived_descriptor(&secp, index)
            .map_err(|error| WalletError::Descriptor(error.to_string()))
    }
}

impl fmt::Display for Descriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_descriptor_string())
    }
}

impl FromStr for Descriptor {
    type Err = WalletError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

/// Analyses a descriptor without keeping anything private it carried.
pub fn analyse(text: &str) -> Result<DescriptorInfo, WalletError> {
    if let Some(unspendable) = parse_unspendable(text)? {
        let descriptor = match &unspendable {
            DescriptorBody::Addr(address) => {
                checksummed(&format!("addr({})", address.clone().assume_checked()))?
            }
            DescriptorBody::Raw(script) => {
                checksummed(&format!("raw({})", script.as_bytes().to_lower_hex_string()))?
            }
            DescriptorBody::Miniscript(_) => unreachable!(),
        };
        let checksum = descriptor
            .rsplit_once('#')
            .map(|(_, checksum)| checksum.to_owned())
            .ok_or_else(|| WalletError::Descriptor("descriptor checksum missing".to_owned()))?;
        return Ok(DescriptorInfo {
            descriptor: descriptor.clone(),
            canonical: descriptor,
            multipath_expansion: Vec::new(),
            checksum,
            is_range: false,
            is_solvable: false,
            has_private_keys: false,
        });
    }

    let secp = Secp256k1::signing_only();
    let (inner, key_map) =
        MiniscriptDescriptor::<DescriptorPublicKey>::parse_descriptor(&secp, text)
            .map_err(|error| WalletError::Descriptor(error.to_string()))?;
    ensure_supported(&inner)?;
    let is_range = inner.has_wildcard();
    let is_solvable = inner.sanity_check().is_ok();
    let descriptor = inner.to_string();
    let checksum = descriptor
        .rsplit_once('#')
        .map(|(_, checksum)| checksum.to_owned())
        .ok_or_else(|| WalletError::Descriptor("descriptor checksum missing".to_owned()))?;
    let multipath_expansion = inner
        .into_single_descriptors()
        .map_err(|error| WalletError::Descriptor(error.to_string()))?
        .into_iter()
        .map(|expanded| expanded.to_string())
        .collect();
    Ok(DescriptorInfo {
        descriptor: descriptor.clone(),
        canonical: descriptor,
        multipath_expansion,
        checksum,
        is_range,
        is_solvable,
        has_private_keys: !key_map.is_empty(),
    })
}

/// Derives addresses for a descriptor text.
///
/// The outer vector is one entry per multipath expansion.
pub fn derive_addresses(
    text: &str,
    network: Network,
    range: Option<(u32, u32)>,
) -> Result<Vec<Vec<String>>, WalletError> {
    if let Some(unspendable) = parse_unspendable(text)? {
        if range.is_some() {
            return Err(WalletError::DescriptorRange(
                "Range should not be specified for an un-ranged descriptor",
            ));
        }
        let desc = Descriptor {
            body: unspendable,
            derivation: BIP32Derivation::default(),
        };
        return Ok(vec![vec![desc.derive_address(network, 0)?.to_string()]]);
    }

    let parsed = Descriptor::parse_all(text)?;
    let ranged = parsed.iter().any(Descriptor::is_ranged);
    let inclusive = match (ranged, range) {
        (true, None) => {
            return Err(WalletError::DescriptorRange(
                "Range must be specified for a ranged descriptor",
            ));
        }
        (false, Some(_)) => {
            return Err(WalletError::DescriptorRange(
                "Range should not be specified for an un-ranged descriptor",
            ));
        }
        (false, None) => 0..=0,
        (_, Some((start, end))) => start..=end,
    };
    parsed
        .into_iter()
        .map(|descriptor| {
            descriptor
                .derive_addresses(network, inclusive.clone())
                .map(|addresses| {
                    addresses
                        .into_iter()
                        .map(|address| address.to_string())
                        .collect()
                })
        })
        .collect()
}

/// Validates a derivation range against a descriptor's wildcard state.
pub(crate) fn validate_range(
    is_ranged: bool,
    range: &RangeInclusive<u32>,
) -> Result<(), WalletError> {
    if range.is_empty() {
        return Err(WalletError::Descriptor(
            "descriptor range start exceeds end".to_owned(),
        ));
    }
    if !is_ranged && (*range.start() != 0 || *range.end() != 0) {
        return Err(WalletError::DescriptorRange(
            "Range should not be specified for an un-ranged descriptor",
        ));
    }
    Ok(())
}

fn ensure_supported(
    descriptor: &MiniscriptDescriptor<DescriptorPublicKey>,
) -> Result<(), WalletError> {
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

fn requires_private_derivation(key: &DescriptorPublicKey) -> bool {
    if key.has_hardened_step() {
        return true;
    }
    match key {
        DescriptorPublicKey::XPub(x) => x.wildcard == Wildcard::Hardened,
        DescriptorPublicKey::MultiXPub(x) => x.wildcard == Wildcard::Hardened,
        DescriptorPublicKey::Single(_) => false,
    }
}

fn parse_unspendable(text: &str) -> Result<Option<DescriptorBody>, WalletError> {
    let payload = match checksum::verify_checksum(text) {
        Ok(payload) => payload,
        Err(
            checksum::Error::InvalidChecksum { .. } | checksum::Error::InvalidChecksumLength { .. },
        ) => {
            let body = strip_checksum(text);
            if body.starts_with("addr(") || body.starts_with("raw(") {
                return Err(WalletError::Descriptor(
                    "descriptor checksum mismatch".to_owned(),
                ));
            }
            // Not an unspendable form; let the miniscript parser report.
            return Ok(None);
        }
        Err(checksum::Error::InvalidCharacter { .. }) => {
            return Err(WalletError::Descriptor(
                "descriptor contains invalid characters".to_owned(),
            ));
        }
    };
    let Some(body) = payload.strip_suffix(')') else {
        return Ok(None);
    };
    if let Some(address) = body.strip_prefix("addr(") {
        if address.contains('*') || address.contains('<') {
            return Err(WalletError::Descriptor(
                "addr() descriptors are not ranged".to_owned(),
            ));
        }
        let address = Address::from_str(address)
            .map_err(|error| WalletError::Descriptor(error.to_string()))?;
        return Ok(Some(DescriptorBody::Addr(address)));
    }
    if let Some(hex) = body.strip_prefix("raw(") {
        let script =
            ScriptBuf::from_hex(hex).map_err(|error| WalletError::Descriptor(error.to_string()))?;
        return Ok(Some(DescriptorBody::Raw(script)));
    }
    Ok(None)
}

fn strip_checksum(text: &str) -> &str {
    text.rsplit_once('#').map_or(text, |(body, _)| body)
}

fn checksummed(payload: &str) -> Result<String, WalletError> {
    let mut engine = checksum::Engine::new();
    engine
        .input(payload)
        .map_err(|error| WalletError::Descriptor(error.to_string()))?;
    Ok(format!("{payload}#{}", engine.checksum()))
}
