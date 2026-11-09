use bitcoin_rs_consensus::primitives::{
    AssumeUtxoData, Hash256, IndexArtifactCapability, IndexArtifactCommitment, Network,
};
use sha2::Digest;

#[derive(Clone, Debug, PartialEq, Eq, sonic_rs::Deserialize, sonic_rs::Serialize)]
pub struct SnapshotManifest {
    pub manifest_version: u32,
    pub network: String,
    pub genesis: [u8; 32],
    pub base_hash: [u8; 32],
    pub base_height: u32,
    pub schema: u32,
    pub utxo_commitment: [u8; 32],
    pub index_commitments: [Option<ManifestIndexCommitment>; 4],
    pub coverage: [Option<u32>; 4],
    pub sizes: [u64; 5],
    pub hashes: [[u8; 32]; 5],
    pub historical_verified_height: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, sonic_rs::Deserialize, sonic_rs::Serialize)]
pub struct ManifestIndexCommitment {
    pub sha256: [u8; 32],
    pub size_bytes: u64,
}

pub const ARTIFACT_SLOTS: usize = 5;
pub const UTXO_SLOT: usize = 0;

pub const fn capability_slot(capability: IndexArtifactCapability) -> usize {
    match capability {
        IndexArtifactCapability::TxLookup => 1,
        IndexArtifactCapability::ScriptHistory => 2,
        IndexArtifactCapability::ScriptLive => 3,
        IndexArtifactCapability::CompactFilters => 4,
    }
}

pub const fn capability_at_slot(slot: usize) -> Option<IndexArtifactCapability> {
    match slot {
        1 => Some(IndexArtifactCapability::TxLookup),
        2 => Some(IndexArtifactCapability::ScriptHistory),
        3 => Some(IndexArtifactCapability::ScriptLive),
        4 => Some(IndexArtifactCapability::CompactFilters),
        _ => None,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("manifest format invalid: {0}")]
    Format(&'static str),
    #[error("manifest names network {found}, the node runs {expected}")]
    NetworkMismatch {
        expected: &'static str,
        found: String,
    },
    #[error("manifest genesis {found} does not match the node genesis {expected}")]
    GenesisMismatch { expected: Hash256, found: Hash256 },
    #[error("manifest base {found} at height {height} is not a compiled anchor")]
    UnknownAnchor { found: Hash256, height: u32 },
    #[error("manifest base identity does not match the anchor at height {height}")]
    AnchorMismatch { height: u32 },
    #[error("manifest schema {found} does not match the node index format {expected}")]
    SchemaMismatch { expected: u32, found: u32 },
    #[error("manifest UTXO commitment {found} does not match the anchor commitment {expected}")]
    UtxoCommitmentMismatch { expected: Hash256, found: Hash256 },
    #[error(
        "decoded snapshot base {found} at height {found_height} does not match the manifest base {expected} at height {expected_height}"
    )]
    SnapshotBaseMismatch {
        expected_height: u32,
        expected: Hash256,
        found_height: u32,
        found: Hash256,
    },
    #[error(
        "decoded snapshot UTXO commitment {found} does not match the manifest commitment {expected}"
    )]
    SnapshotCommitmentMismatch { expected: Hash256, found: Hash256 },
    #[error("manifest artifact table is malformed: {0}")]
    Artifacts(&'static str),
    #[error("index coverage floor {floor} exceeds the base height {base_height}")]
    CoverageFloorAboveBase { floor: u32, base_height: u32 },
    #[error("manifest artifact file {} not found", .path.display())]
    ArtifactNotFound { path: std::path::PathBuf },
    #[error("artifact size mismatch for slot {slot}: declared {declared}, actual {actual}")]
    ArtifactSizeMismatch {
        slot: usize,
        declared: u64,
        actual: u64,
    },
    #[error("artifact hash mismatch for slot {slot}: declared {declared:?}, actual {actual:?}")]
    ArtifactHashMismatch {
        slot: usize,
        declared: [u8; 32],
        actual: [u8; 32],
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapabilityTrust {
    Trusted(IndexArtifactCommitment),
    Untrusted,
}

#[derive(Clone, Debug)]
pub struct ManifestTrust {
    pub base_height: u32,
    pub base_hash: [u8; 32],
    pub capability_trust: [CapabilityTrust; 4],
}

impl SnapshotManifest {
    pub fn parse(bytes: &[u8]) -> Result<Self, ManifestError> {
        let manifest: Self = sonic_rs::from_slice(bytes)
            .map_err(|_| ManifestError::Format("manifest is not valid JSON"))?;
        manifest.check_shape()?;
        Ok(manifest)
    }

    fn check_shape(&self) -> Result<(), ManifestError> {
        if self.manifest_version != 1 {
            return Err(ManifestError::Format("unsupported manifest_version"));
        }
        if self.schema == 0 {
            return Err(ManifestError::Format("schema must be nonzero"));
        }
        if self.historical_verified_height > self.base_height {
            return Err(ManifestError::Format(
                "historical verification provenance exceeds the base height",
            ));
        }
        for floor in self.coverage.iter().flatten() {
            if *floor > self.base_height {
                return Err(ManifestError::CoverageFloorAboveBase {
                    floor: *floor,
                    base_height: self.base_height,
                });
            }
        }
        if self.sizes.len() != ARTIFACT_SLOTS || self.hashes.len() != ARTIFACT_SLOTS {
            return Err(ManifestError::Artifacts(
                "size and hash tables need 5 slots",
            ));
        }
        if self.sizes[UTXO_SLOT] == 0 {
            return Err(ManifestError::Artifacts("the UTXO artifact has no size"));
        }
        for slot in 1..ARTIFACT_SLOTS {
            let committed = self.index_commitments[slot - 1].is_some();
            let sized = self.sizes[slot] != 0;
            match (committed, sized) {
                (true, true) | (false, false) => {}
                (true, false) => {
                    return Err(ManifestError::Artifacts(
                        "a committed capability names no artifact size",
                    ));
                }
                (false, true) => {
                    return Err(ManifestError::Artifacts(
                        "an artifact size is declared without a commitment",
                    ));
                }
            }
            if let Some(commitment) = &self.index_commitments[slot - 1]
                && (self.sizes[slot] != commitment.size_bytes
                    || self.hashes[slot] != commitment.sha256)
            {
                return Err(ManifestError::Artifacts(
                    "an artifact does not match its index commitment",
                ));
            }
        }
        Ok(())
    }

    pub fn verify_against_anchor(
        &self,
        network: Network,
        genesis: [u8; 32],
        anchor: &AssumeUtxoData,
    ) -> Result<ManifestTrust, ManifestError> {
        if self.network != network.identity_name() {
            return Err(ManifestError::NetworkMismatch {
                expected: network.identity_name(),
                found: self.network.clone(),
            });
        }
        if self.genesis != genesis {
            return Err(ManifestError::GenesisMismatch {
                expected: Hash256::from_le_bytes(&genesis),
                found: Hash256::from_le_bytes(&self.genesis),
            });
        }
        if self.base_height != anchor.height || self.base_hash != anchor.block_hash.to_le_bytes() {
            return Err(ManifestError::AnchorMismatch {
                height: anchor.height,
            });
        }
        if self.utxo_commitment != anchor.hash_serialized.to_le_bytes() {
            return Err(ManifestError::UtxoCommitmentMismatch {
                expected: anchor.hash_serialized,
                found: Hash256::from_le_bytes(&self.utxo_commitment),
            });
        }
        let mut capability_trust = [CapabilityTrust::Untrusted; 4];
        for (slot_index, trust_slot) in capability_trust.iter_mut().enumerate() {
            let Some(commitment) = &self.index_commitments[slot_index] else {
                continue;
            };
            let capability = match IndexArtifactCapability::from_index(slot_index) {
                Some(capability) => capability,
                None => continue,
            };
            let compiled = {
                #[cfg(any(test, feature = "test-seam"))]
                {
                    get_test_index_commitment(network, self.base_height, capability)
                        .or_else(|| anchor.index_commitment(capability).copied())
                }
                #[cfg(not(any(test, feature = "test-seam")))]
                {
                    anchor.index_commitment(capability).copied()
                }
            };
            let verified = compiled.is_some_and(|compiled| {
                compiled.sha256 == commitment.sha256 && compiled.size_bytes == commitment.size_bytes
            });
            if verified {
                *trust_slot = CapabilityTrust::Trusted(IndexArtifactCommitment {
                    capability,
                    sha256: commitment.sha256,
                    size_bytes: commitment.size_bytes,
                });
            }
        }
        Ok(ManifestTrust {
            base_height: self.base_height,
            base_hash: self.base_hash,
            capability_trust,
        })
    }

    pub fn artifact_size(&self, capability: IndexArtifactCapability) -> u64 {
        self.sizes[capability_slot(capability)]
    }

    pub fn artifact_sha256(&self, capability: IndexArtifactCapability) -> [u8; 32] {
        self.hashes[capability_slot(capability)]
    }

    pub fn utxo_size(&self) -> u64 {
        self.sizes[UTXO_SLOT]
    }

    pub fn utxo_sha256(&self) -> [u8; 32] {
        self.hashes[UTXO_SLOT]
    }
    pub fn artifact_path(
        &self,
        dir: &std::path::Path,
        slot: usize,
    ) -> Result<std::path::PathBuf, ManifestError> {
        let names: &[&str] = match slot {
            UTXO_SLOT => &["utxo.dat", "core.dat", "snapshot.dat"],
            1 => &[
                "txlookup.artifact",
                "tx_lookup.artifact",
                "txlookup.dat",
                "tx_lookup.dat",
            ],
            2 => &[
                "scripthistory.artifact",
                "script_history.artifact",
                "scripthistory.dat",
                "script_history.dat",
            ],
            3 => &[
                "scriptlive.artifact",
                "script_live.artifact",
                "scriptlive.dat",
                "script_live.dat",
            ],
            4 => &[
                "compactfilters.artifact",
                "compact_filters.artifact",
                "compactfilters.dat",
                "compact_filters.dat",
            ],
            _ => return Err(ManifestError::Artifacts("invalid artifact slot")),
        };
        for name in names {
            let p = dir.join(name);
            if p.is_file() {
                return Ok(p);
            }
        }
        Err(ManifestError::ArtifactNotFound {
            path: dir.join(names[0]),
        })
    }

    pub fn verify_index_artifact(
        &self,
        dir: &std::path::Path,
        slot: usize,
    ) -> Result<(), ManifestError> {
        if slot == UTXO_SLOT || slot >= ARTIFACT_SLOTS {
            return Err(ManifestError::Artifacts("invalid artifact slot"));
        }
        if self.sizes[slot] == 0 {
            return Ok(());
        }
        let path = self.artifact_path(dir, slot)?;
        let meta = std::fs::metadata(&path)
            .map_err(|_| ManifestError::ArtifactNotFound { path: path.clone() })?;
        if meta.len() != self.sizes[slot] {
            return Err(ManifestError::ArtifactSizeMismatch {
                slot,
                declared: self.sizes[slot],
                actual: meta.len(),
            });
        }
        let (digest, bytes) = stream_sha256(&path)
            .map_err(|_| ManifestError::ArtifactNotFound { path: path.clone() })?;
        if bytes != self.sizes[slot] {
            return Err(ManifestError::ArtifactSizeMismatch {
                slot,
                declared: self.sizes[slot],
                actual: bytes,
            });
        }
        if digest != self.hashes[slot] {
            return Err(ManifestError::ArtifactHashMismatch {
                slot,
                declared: self.hashes[slot],
                actual: digest,
            });
        }
        Ok(())
    }
}

const STREAM_BUFFER_BYTES: usize = 64 * 1024;

fn stream_sha256(path: &std::path::Path) -> std::io::Result<([u8; 32], u64)> {
    use std::io::Read as _;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = sha2::Sha256::new();
    let mut buffer = vec![0_u8; STREAM_BUFFER_BYTES];
    let mut total = 0_u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        total += u64::try_from(read).unwrap_or(u64::MAX);
    }
    Ok((hasher.finalize().into(), total))
}

#[cfg(any(test, feature = "test-seam"))]
type TestCommitmentKey = (&'static str, u32, IndexArtifactCapability);
#[cfg(any(test, feature = "test-seam"))]
type TestCommitmentMap = std::collections::HashMap<TestCommitmentKey, IndexArtifactCommitment>;

#[cfg(any(test, feature = "test-seam"))]
static TEST_INDEX_COMMITMENTS: parking_lot::RwLock<Option<TestCommitmentMap>> =
    parking_lot::RwLock::new(None);
#[cfg(any(test, feature = "test-seam"))]
pub fn register_test_index_commitment(
    network: Network,
    height: u32,
    commitment: IndexArtifactCommitment,
) {
    let mut guard = TEST_INDEX_COMMITMENTS.write();
    let map = guard.get_or_insert_with(std::collections::HashMap::new);
    map.insert(
        (network.identity_name(), height, commitment.capability),
        commitment,
    );
}

#[cfg(any(test, feature = "test-seam"))]
pub fn clear_test_index_commitments() {
    *TEST_INDEX_COMMITMENTS.write() = None;
}

#[cfg(any(test, feature = "test-seam"))]
fn get_test_index_commitment(
    network: Network,
    height: u32,
    capability: IndexArtifactCapability,
) -> Option<IndexArtifactCommitment> {
    TEST_INDEX_COMMITMENTS.read().as_ref().and_then(|map| {
        map.get(&(network.identity_name(), height, capability))
            .copied()
    })
}
#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    const GENESIS: [u8; 32] = [0; 32];
    const BASE_HASH: [u8; 32] = [1; 32];
    const UTXO_COMMITMENT: [u8; 32] = [2; 32];

    fn anchor_with(compiled: [Option<IndexArtifactCommitment>; 4]) -> AssumeUtxoData {
        AssumeUtxoData {
            height: 840_000,
            block_hash: Hash256::from_le_bytes(&BASE_HASH),
            hash_serialized: Hash256::from_le_bytes(&UTXO_COMMITMENT),
            chain_tx_count: 991_032_194,
            index_commitments: compiled,
        }
    }

    fn plain_anchor() -> AssumeUtxoData {
        anchor_with([None; 4])
    }

    fn compiled(capability: IndexArtifactCapability, sha: [u8; 32]) -> IndexArtifactCommitment {
        IndexArtifactCommitment {
            capability,
            sha256: sha,
            size_bytes: 11,
        }
    }

    fn committed(sha: [u8; 32]) -> ManifestIndexCommitment {
        ManifestIndexCommitment {
            sha256: sha,
            size_bytes: 11,
        }
    }

    fn manifest_with(commitments: [Option<ManifestIndexCommitment>; 4]) -> SnapshotManifest {
        let mut sizes = [0_u64; ARTIFACT_SLOTS];
        let mut hashes = [[0_u8; 32]; ARTIFACT_SLOTS];
        sizes[UTXO_SLOT] = 7;
        hashes[UTXO_SLOT] = [9; 32];
        for (index, commitment) in commitments.iter().enumerate() {
            let slot = capability_at_slot(index + 1).expect("capability slot");
            let slot = capability_slot(slot);
            if let Some(commitment) = commitment {
                sizes[slot] = commitment.size_bytes;
                hashes[slot] = commitment.sha256;
            }
        }
        SnapshotManifest {
            manifest_version: 1,
            network: "mainnet".to_owned(),
            genesis: GENESIS,
            base_hash: BASE_HASH,
            base_height: 840_000,
            schema: 1,
            utxo_commitment: UTXO_COMMITMENT,
            index_commitments: commitments,
            coverage: [None; 4],
            sizes,
            hashes,
            historical_verified_height: 0,
        }
    }

    fn verify(
        manifest: &SnapshotManifest,
        anchor: &AssumeUtxoData,
    ) -> Result<ManifestTrust, ManifestError> {
        manifest.verify_against_anchor(Network::Mainnet, GENESIS, anchor)
    }

    #[test]
    fn manifest_index_commitments_are_untrusted_without_compiled_entries() {
        let manifest = manifest_with([Some(committed([5; 32])), None, None, None]);
        let trust = verify(&manifest, &plain_anchor()).expect("manifest is well formed");
        assert_eq!(
            trust.capability_trust[0],
            CapabilityTrust::Untrusted,
            "a manifest-only commitment never activates"
        );
    }

    #[test]
    fn manifest_commitment_matching_the_compiled_table_is_trusted() {
        let compiled = compiled(IndexArtifactCapability::TxLookup, [5; 32]);
        let manifest = manifest_with([Some(committed([5; 32])), None, None, None]);
        let trust = verify(&manifest, &anchor_with([Some(compiled), None, None, None]))
            .expect("manifest is well formed");
        assert_eq!(
            trust.capability_trust[0],
            CapabilityTrust::Trusted(compiled)
        );
    }

    #[test]
    fn a_wrong_manifest_commitment_stays_untrusted_against_a_compiled_entry() {
        let compiled = compiled(IndexArtifactCapability::TxLookup, [6; 32]);
        let manifest = manifest_with([Some(committed([5; 32])), None, None, None]);
        let trust = verify(&manifest, &anchor_with([Some(compiled), None, None, None]))
            .expect("manifest is well formed");
        assert_eq!(trust.capability_trust[0], CapabilityTrust::Untrusted);
    }

    #[test]
    fn an_untrusted_capability_does_not_affect_the_others() {
        let live_compiled = compiled(IndexArtifactCapability::ScriptLive, [7; 32]);
        let anchor = anchor_with([None, None, Some(live_compiled), None]);
        let manifest = manifest_with([
            Some(committed([5; 32])),
            None,
            Some(committed([7; 32])),
            None,
        ]);
        let trust = verify(&manifest, &anchor).expect("manifest is well formed");
        assert_eq!(trust.capability_trust[0], CapabilityTrust::Untrusted);
        assert_eq!(
            trust.capability_trust[2],
            CapabilityTrust::Trusted(live_compiled)
        );
    }

    #[test]
    fn a_manifest_on_an_unknown_anchor_is_refused() {
        let manifest = manifest_with([None; 4]);
        let unknown = AssumeUtxoData {
            height: 1,
            block_hash: Hash256::from_le_bytes(&[3; 32]),
            hash_serialized: Hash256::from_le_bytes(&[4; 32]),
            chain_tx_count: 1,
            index_commitments: [None; 4],
        };
        let error = verify(&manifest, &unknown).expect_err("anchor mismatch must refuse");
        assert!(matches!(error, ManifestError::AnchorMismatch { height: 1 }));
    }

    #[test]
    fn parse_round_trips_and_rejects_bad_json() {
        let manifest = manifest_with([None; 4]);
        let bytes = sonic_rs::to_vec(&manifest).expect("serialize");
        let parsed = SnapshotManifest::parse(&bytes).expect("parse");
        assert_eq!(parsed, manifest);
        assert!(matches!(
            SnapshotManifest::parse(b"{"),
            Err(ManifestError::Format(_))
        ));
        let mut empty_utxo = manifest_with([None; 4]);
        empty_utxo.sizes[UTXO_SLOT] = 0;
        let bytes = sonic_rs::to_vec(&empty_utxo).expect("serialize");
        assert!(matches!(
            SnapshotManifest::parse(&bytes),
            Err(ManifestError::Artifacts(_))
        ));
    }

    // SNP-02, SNP-03, SNP-04
    #[test]
    fn manifest_file_hash_must_equal_the_index_commitment() {
        let mut manifest = manifest_with([Some(committed([5; 32])), None, None, None]);
        manifest.hashes[1] = [0xaa; 32];
        let bytes = sonic_rs::to_vec(&manifest).expect("serialize");
        assert!(
            matches!(
                SnapshotManifest::parse(&bytes),
                Err(ManifestError::Artifacts(_) | ManifestError::Format(_))
            ),
            "a manifest whose artifact hash is not the index commitment must be refused"
        );
    }

    // SNP-02
    #[test]
    fn a_manifest_claiming_provenance_past_its_base_is_refused() {
        let mut manifest = manifest_with([None; 4]);
        manifest.historical_verified_height = manifest.base_height.saturating_add(1);
        let bytes = sonic_rs::to_vec(&manifest).expect("serialize");
        assert!(matches!(
            SnapshotManifest::parse(&bytes),
            Err(ManifestError::Format(_))
        ));
    }
    // SNP-02
    #[test]
    fn a_coverage_floor_above_the_base_height_is_refused() {
        let mut manifest = manifest_with([None; 4]);
        manifest.coverage[0] = Some(manifest.base_height + 1);
        let bytes = sonic_rs::to_vec(&manifest).expect("serialize");
        let error = SnapshotManifest::parse(&bytes).expect_err("floor above base is refused");
        assert!(
            matches!(
                error,
                ManifestError::CoverageFloorAboveBase { floor, base_height }
                if floor == manifest.base_height + 1 && base_height == manifest.base_height
            ),
            "the refusal carries the floor and the base height"
        );
    }

    // SNP-02
    #[test]
    fn a_coverage_floor_at_the_base_height_is_accepted() {
        let mut manifest = manifest_with([None; 4]);
        manifest.coverage[0] = Some(manifest.base_height);
        let bytes = sonic_rs::to_vec(&manifest).expect("serialize");
        SnapshotManifest::parse(&bytes).expect("floor at base height is the range end");
    }

    // SNP-02
    #[test]
    fn a_manifest_missing_a_declared_field_is_refused() {
        let manifest = manifest_with([None; 4]);
        let bytes = sonic_rs::to_vec(&manifest).expect("serialize");
        let renamed = String::from_utf8(bytes).expect("json is utf-8").replacen(
            "\"coverage\":",
            "\"renamed\":",
            1,
        );
        assert!(matches!(
            SnapshotManifest::parse(renamed.as_bytes()),
            Err(ManifestError::Format(_))
        ));
    }
}
