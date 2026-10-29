//! Versioned bundle manifest: schema, canonical encoding, and field validation.

use super::{IndexBundleError, artifact::HEADER_LEN};
use bitcoin_rs_chain::ChainWork;
use bitcoin_rs_primitives::Network;
use serde::{Deserialize, Serialize};

pub(super) const BUNDLE_FORMAT: &str = "bitcoin-rs-index-bundle";
pub(super) const BUNDLE_VERSION: u32 = 1;
pub(super) const MANIFEST_FILE: &str = "manifest.json";
pub(super) const TXLOOKUP_FILE: &str = "txlookup-v1.dat";
pub(super) const SCRIPTHISTORY_FILE: &str = "scripthistory-v1.dat";
pub(super) const MAX_MANIFEST_BYTES: u64 = 1 << 20;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum BundleFamily {
    TxLookup,
    ScriptHistory,
}

impl BundleFamily {
    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::TxLookup => "tx_lookup",
            Self::ScriptHistory => "script_history",
        }
    }

    pub(super) const fn file_name(self) -> &'static str {
        match self {
            Self::TxLookup => TXLOOKUP_FILE,
            Self::ScriptHistory => SCRIPTHISTORY_FILE,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum IndexMode {
    Utxo,
    Full,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ManifestBase {
    pub(super) height: u32,
    pub(super) hash: String,
    pub(super) chainwork: String,
    pub(super) chain_tx_count: u64,
    pub(super) validated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ManifestCoverage {
    pub(super) capability: BundleFamily,
    pub(super) floor: u32,
    pub(super) height: u32,
    pub(super) hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ManifestIndex {
    pub(super) mode: IndexMode,
    pub(super) format_version: u32,
    pub(super) capabilities: Vec<ManifestCoverage>,
}

/// One artifact file: identity, exact length, and record count.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ManifestArtifact {
    pub(super) family: BundleFamily,
    pub(super) name: String,
    pub(super) sha256: String,
    pub(super) bytes: u64,
    pub(super) records: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct IndexBundleManifestV1 {
    pub(super) format: String,
    pub(super) version: u32,
    pub(super) network: String,
    pub(super) genesis_hash: String,
    pub(super) base: ManifestBase,
    pub(super) index: ManifestIndex,
    pub(super) artifacts: Vec<ManifestArtifact>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct BundleIdentity {
    pub(super) network: Network,
    /// Genesis block hash, little-endian bytes.
    pub(super) genesis: [u8; 32],
    pub(super) format_version: u32,
    pub(super) base_height: u32,
    /// Base block hash, little-endian bytes.
    pub(super) base_hash: [u8; 32],
    pub(super) chainwork: ChainWork,
    pub(super) chain_tx_count: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct TxLookupArtifact {
    pub(super) sha256: [u8; 32],
    pub(super) bytes: u64,
    pub(super) records: u64,
    pub(super) floor: u32,
}

#[derive(Clone, Debug)]
pub(super) struct ValidatedManifest {
    pub(super) identity: BundleIdentity,
    pub(super) tx_lookup: TxLookupArtifact,
}

impl IndexBundleManifestV1 {
    pub(super) fn parse(bytes: &[u8]) -> Result<Self, IndexBundleError> {
        sonic_rs::from_slice(bytes).map_err(|error| IndexBundleError::Manifest(error.to_string()))
    }

    pub(super) fn to_json(&self) -> Result<Vec<u8>, IndexBundleError> {
        sonic_rs::to_vec_pretty(self).map_err(|error| IndexBundleError::Manifest(error.to_string()))
    }

    pub(super) fn for_tx_lookup(
        identity: &BundleIdentity,
        mode: IndexMode,
        floor: u32,
        artifact: &TxLookupArtifact,
    ) -> Self {
        let base_hash = encode_hash_be(&identity.base_hash);
        Self {
            format: BUNDLE_FORMAT.to_owned(),
            version: BUNDLE_VERSION,
            network: identity.network.identity_name().to_owned(),
            genesis_hash: encode_hash_be(&identity.genesis),
            base: ManifestBase {
                height: identity.base_height,
                hash: base_hash.clone(),
                chainwork: encode_hex(&identity.chainwork.to_be_bytes::<32>()),
                chain_tx_count: identity.chain_tx_count,
                validated: true,
            },
            index: ManifestIndex {
                mode,
                format_version: identity.format_version,
                capabilities: vec![ManifestCoverage {
                    capability: BundleFamily::TxLookup,
                    floor,
                    height: identity.base_height,
                    hash: base_hash,
                }],
            },
            artifacts: vec![ManifestArtifact {
                family: BundleFamily::TxLookup,
                name: BundleFamily::TxLookup.file_name().to_owned(),
                sha256: encode_hex(&artifact.sha256),
                bytes: artifact.bytes,
                records: artifact.records,
            }],
        }
    }

    pub(super) fn validate(&self) -> Result<ValidatedManifest, IndexBundleError> {
        let refuse = |reason: String| IndexBundleError::Manifest(reason);
        if self.format != BUNDLE_FORMAT {
            return Err(refuse(format!(
                "format {:?} is not {BUNDLE_FORMAT:?}",
                self.format
            )));
        }
        if self.version != BUNDLE_VERSION {
            return Err(refuse(format!(
                "version {} is not {BUNDLE_VERSION}",
                self.version
            )));
        }
        if self
            .index
            .capabilities
            .iter()
            .any(|coverage| coverage.capability == BundleFamily::ScriptHistory)
            || self
                .artifacts
                .iter()
                .any(|artifact| artifact.family == BundleFamily::ScriptHistory)
        {
            return Err(IndexBundleError::UnsupportedCapability(
                BundleFamily::ScriptHistory.label(),
            ));
        }
        let network = [
            Network::Mainnet,
            Network::Testnet3,
            Network::Testnet4,
            Network::Signet,
            Network::Regtest,
        ]
        .into_iter()
        .find(|candidate| candidate.identity_name() == self.network)
        .ok_or_else(|| refuse(format!("unknown network {:?}", self.network)))?;
        let genesis = parse_hash_be(&self.genesis_hash, "genesis_hash")?;
        let base_hash = parse_hash_be(&self.base.hash, "base.hash")?;
        let chainwork =
            ChainWork::from_be_bytes(parse_hex32(&self.base.chainwork, "base.chainwork")?);
        if !self.base.validated {
            return Err(refuse("base is not marked validated".to_owned()));
        }
        let [coverage] = self.index.capabilities.as_slice() else {
            return Err(refuse(
                "exactly one tx_lookup capability is required".to_owned(),
            ));
        };
        if coverage.height != self.base.height
            || parse_hash_be(&coverage.hash, "capabilities.hash")? != base_hash
        {
            return Err(refuse(
                "tx_lookup coverage does not end at the base".to_owned(),
            ));
        }
        if coverage.floor > self.base.height.saturating_add(1) {
            return Err(refuse("tx_lookup floor is above the base".to_owned()));
        }
        let [artifact] = self.artifacts.as_slice() else {
            return Err(refuse(
                "exactly one tx_lookup artifact is required".to_owned(),
            ));
        };
        if artifact.name != BundleFamily::TxLookup.file_name() {
            return Err(refuse(format!(
                "artifact name {:?} is not {:?}",
                artifact.name,
                BundleFamily::TxLookup.file_name()
            )));
        }
        let sha256 = parse_hex32(&artifact.sha256, "artifacts.sha256")?;
        let header_len = u64::try_from(HEADER_LEN).unwrap_or(u64::MAX);
        if artifact.bytes < header_len {
            return Err(refuse("artifact is shorter than its header".to_owned()));
        }
        Ok(ValidatedManifest {
            identity: BundleIdentity {
                network,
                genesis,
                format_version: self.index.format_version,
                base_height: self.base.height,
                base_hash,
                chainwork,
                chain_tx_count: self.base.chain_tx_count,
            },
            tx_lookup: TxLookupArtifact {
                sha256,
                bytes: artifact.bytes,
                records: artifact.records,
                floor: coverage.floor,
            },
        })
    }
}

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

pub(super) fn encode_hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
    }
    text
}

/// Encodes little-endian hash bytes in the conventional big-endian spelling.
pub(super) fn encode_hash_be(le: &[u8; 32]) -> String {
    let mut be = *le;
    be.reverse();
    encode_hex(&be)
}

fn parse_hex32(text: &str, field: &str) -> Result<[u8; 32], IndexBundleError> {
    let invalid = || IndexBundleError::Manifest(format!("{field} is not 64 lowercase hex digits"));
    let digits = text.as_bytes();
    if digits.len() != 64 {
        return Err(invalid());
    }
    let nibble = |digit: u8| match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    };
    let mut out = [0_u8; 32];
    let (pairs, _) = digits.as_chunks::<2>();
    for (slot, &[high, low]) in out.iter_mut().zip(pairs) {
        let (Some(high), Some(low)) = (nibble(high), nibble(low)) else {
            return Err(invalid());
        };
        *slot = (high << 4) | low;
    }
    Ok(out)
}

/// Parses a big-endian hash spelling into little-endian bytes.
fn parse_hash_be(text: &str, field: &str) -> Result<[u8; 32], IndexBundleError> {
    let mut bytes = parse_hex32(text, field)?;
    bytes.reverse();
    Ok(bytes)
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests {
    use super::*;

    fn identity() -> BundleIdentity {
        let mut genesis = [0_u8; 32];
        genesis[0] = 0x0f;
        let mut base_hash = [0_u8; 32];
        base_hash[31] = 0xab;
        BundleIdentity {
            network: Network::Regtest,
            genesis,
            format_version: 5,
            base_height: 42,
            base_hash,
            chainwork: ChainWork::from(0x1234_u64),
            chain_tx_count: 99,
        }
    }

    fn artifact() -> TxLookupArtifact {
        TxLookupArtifact {
            sha256: [0xcd; 32],
            bytes: 73 + 43,
            records: 1,
            floor: 0,
        }
    }

    fn json() -> String {
        let manifest =
            IndexBundleManifestV1::for_tx_lookup(&identity(), IndexMode::Utxo, 0, &artifact());
        String::from_utf8(manifest.to_json().expect("encodes")).expect("json is utf-8")
    }

    #[test]
    fn manifest_round_trips_through_json_and_validates() {
        let text = json();
        assert!(text.contains("bitcoin-rs-index-bundle"));
        assert!(text.contains("ab00000000000000000000000000000000000000000000000000000000000000"));
        let parsed = IndexBundleManifestV1::parse(text.as_bytes()).expect("parses");
        let validated = parsed.validate().expect("validates");
        assert_eq!(validated.identity, identity());
        assert_eq!(validated.tx_lookup, artifact());
    }

    #[test]
    fn unknown_fields_are_denied_at_every_level() {
        let top = json().replacen('{', "{\"extra\": 1,", 1);
        assert!(matches!(
            IndexBundleManifestV1::parse(top.as_bytes()),
            Err(IndexBundleError::Manifest(_))
        ));
        let nested = json().replacen("\"validated\"", "\"surprise\": true, \"validated\"", 1);
        assert!(matches!(
            IndexBundleManifestV1::parse(nested.as_bytes()),
            Err(IndexBundleError::Manifest(_))
        ));
    }

    #[test]
    fn script_live_is_never_a_capability_and_script_history_is_refused() {
        let live = json().replace("\"tx_lookup\"", "\"script_live\"");
        assert!(matches!(
            IndexBundleManifestV1::parse(live.as_bytes()),
            Err(IndexBundleError::Manifest(_))
        ));
        let history = json().replace("\"tx_lookup\"", "\"script_history\"");
        let parsed = IndexBundleManifestV1::parse(history.as_bytes()).expect("schema allows it");
        assert!(matches!(
            parsed.validate(),
            Err(IndexBundleError::UnsupportedCapability("script_history"))
        ));
    }

    #[test]
    fn malformed_values_are_refused() {
        let refuse = |edit: &dyn Fn(&mut IndexBundleManifestV1)| {
            let mut manifest = IndexBundleManifestV1::parse(json().as_bytes()).expect("parses");
            edit(&mut manifest);
            matches!(manifest.validate(), Err(IndexBundleError::Manifest(_)))
        };
        assert!(refuse(&|m| m.format = "other".to_owned()));
        assert!(refuse(&|m| m.version = 2));
        assert!(refuse(&|m| m.network = "moonnet".to_owned()));
        assert!(refuse(&|m| m.genesis_hash = "ab".to_owned()));
        assert!(refuse(&|m| m.base.hash = m.base.hash.to_uppercase()));
        assert!(refuse(&|m| m.base.validated = false));
        assert!(refuse(&|m| m.index.capabilities[0].height += 1));
        assert!(refuse(&|m| m.index.capabilities[0].floor = 44));
        assert!(refuse(&|m| m.artifacts[0].name = "../escape.dat".to_owned()));
        assert!(refuse(&|m| m.artifacts[0].bytes = 10));
        assert!(refuse(&|m| m.artifacts.clear()));
    }
}
