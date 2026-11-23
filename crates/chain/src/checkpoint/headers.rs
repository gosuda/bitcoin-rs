//! Canonical header-checkpoint representation and validation.
//!
//! Version 2 (written) layout, all integers little-endian:
//!
//! - 56-byte prefix: magic, version, network magic, genesis hash, and the
//!   active header count.
//! - The active ancestry of the selected best tip, genesis first, as
//!   80-byte headers. The manifest commitments cover only this section.
//! - `u64` side-header count, then a bounded prefix of valid side headers
//!   whose chainwork does not exceed the selected best tip. Logical insertion
//!   order keeps each parent before its children.
//!
//! Version 1 (read only) is the same prefix and active section with no side
//! section; it restores the active ancestry alone. The artifact SHA-256 in
//! the manifest authenticates every byte of either version.
//! Legacy side sections are validated in full before a bounded tree is returned.
//! Their temporary context index is discarded on every exit.

use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::io::{Read, Seek, SeekFrom, Write};

use crate::chain::header_sync::context::{
    HEADER_CONTEXT_SNAPSHOT_LEN, HeaderContextError, HeaderValidationContext,
};
use crate::chain::{BlockTree, NodeId, accept_headers};
use bitcoin_rs_consensus::header_rules::ChainWork;
use bitcoin_rs_consensus::primitives::{ConsensusEncode, Hash256, Header, Network, deserialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const HEADER_MAGIC: [u8; 8] = *b"BRSHEAD\0";
pub(super) const HEADER_VERSION: u32 = 2;
pub(super) const ACTIVE_ONLY_HEADER_VERSION: u32 = 1;
pub(super) const HEADER_PREFIX_LEN: usize = 56;
const HEADER_LEN: usize = Header::LEN;
const SIDE_COUNT_LEN: u64 = 8;
const BEST_CHAIN_DOMAIN: &[u8] = b"bitcoin-rs/headers-v1/best\0";
const APPLIED_PREFIX_DOMAIN: &[u8] = b"bitcoin-rs/headers-v1/applied\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HeaderCheckpointConfig {
    pub(crate) network: Network,
    pub(crate) genesis: Hash256,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HeaderCheckpointPoint {
    pub(crate) height: u32,
    pub(crate) hash: Hash256,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HeaderCheckpointTip {
    pub(crate) height: u32,
    pub(crate) hash: Hash256,
    pub(crate) chainwork: ChainWork,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HeaderCheckpointMetadata {
    pub(crate) version: u32,
    pub(crate) header_count: u64,
    pub(crate) best: HeaderCheckpointTip,
    pub(crate) applied: HeaderCheckpointTip,
    pub(crate) best_chain_commitment: [u8; 32],
    pub(crate) applied_prefix_commitment: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HeaderCheckpointWrite {
    pub(crate) metadata: HeaderCheckpointMetadata,
    pub(crate) bytes_written: u64,
}

pub(crate) struct RestoredHeaders {
    pub(crate) tree: BlockTree,
    pub(crate) applied_tip_id: NodeId,
}

#[derive(Debug, Error)]
pub enum HeaderCheckpointError {
    #[error("configured genesis {configured} does not match {network:?} genesis {expected}")]
    ConfiguredGenesisMismatch {
        configured: Hash256,
        expected: Hash256,
        network: Network,
    },
    #[error("header checkpoint contains zero headers")]
    ZeroHeaderCount,
    #[error("header checkpoint count {count} does not fit usize")]
    CountDoesNotFitUsize { count: u64 },
    #[error("header checkpoint count {count} exceeds the u32 block-height domain")]
    CountExceedsHeightDomain { count: u64 },
    #[error("header checkpoint byte length overflow for {count} headers")]
    SizeOverflow { count: u64 },
    #[error("header checkpoint has {actual} bytes, expected {expected}")]
    InvalidFileLength { actual: u64, expected: u64 },
    #[error("header checkpoint magic is invalid")]
    BadMagic,
    #[error("header checkpoint version {actual} is unsupported")]
    UnsupportedVersion { actual: u32 },
    #[error("header checkpoint version {artifact} does not match manifest version {manifest}")]
    VersionMismatch { manifest: u32, artifact: u32 },
    #[error("header checkpoint side header {index} does not add a new tree node")]
    MalformedSideBranch { index: u64 },
    #[error("header checkpoint side branches displaced the checkpoint best tip")]
    SideBranchDisplacedBestTip,
    #[error("header checkpoint side count {count} exceeds the tree node-id domain")]
    SideCountExceedsNodeDomain { count: u64 },
    #[error("header checkpoint network magic does not match configured network")]
    NetworkMismatch,
    #[error("header checkpoint genesis does not match configured genesis")]
    GenesisMismatch,
    #[error("header checkpoint count {actual} does not match manifest count {expected}")]
    CountMismatch { actual: u64, expected: u64 },
    #[error("header checkpoint best tip is not the tree's published best tip")]
    BestTipNotActive,
    #[error("header checkpoint active ancestry is malformed at height {height}")]
    MalformedAncestry { height: u32 },
    #[error("header checkpoint root is not the configured genesis")]
    RootIsNotGenesis,
    #[error("header checkpoint applied tip is not a prefix of the active best chain")]
    AppliedTipNotBestPrefix,
    #[error("header checkpoint metadata does not match reconstructed chain")]
    MetadataMismatch,
    #[error("header checkpoint commitment does not match reconstructed chain")]
    CommitmentMismatch,
    #[error("header checkpoint consensus codec failed: {0}")]
    Codec(String),
    #[error("header checkpoint I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("temporary header validation index failed: {0}")]
    TemporaryIndex(#[source] std::io::Error),
    #[error("header checkpoint consensus validation failed: {0}")]
    Chain(#[from] crate::chain::ChainError),
    #[error(transparent)]
    Context(#[from] HeaderContextError),
}

pub(crate) fn write_headers<W: Write + ?Sized>(
    writer: &mut W,
    tree: &BlockTree,
    config: HeaderCheckpointConfig,
    best_tip_id: NodeId,
    applied: HeaderCheckpointPoint,
) -> Result<HeaderCheckpointWrite, HeaderCheckpointError> {
    validate_config(config)?;
    if tree.tip_id() != Some(best_tip_id) {
        return Err(HeaderCheckpointError::BestTipNotActive);
    }
    write_headers_with_side_limit(
        writer,
        tree,
        config,
        best_tip_id,
        applied,
        crate::header_admission::HEADER_SIDE_CACHE_LIMIT,
    )
}

pub(super) fn write_selected_headers<W: Write + ?Sized>(
    writer: &mut W,
    tree: &BlockTree,
    config: HeaderCheckpointConfig,
    best_tip_id: NodeId,
    applied: HeaderCheckpointPoint,
) -> Result<HeaderCheckpointWrite, HeaderCheckpointError> {
    validate_config(config)?;
    write_headers_with_side_limit(
        writer,
        tree,
        config,
        best_tip_id,
        applied,
        crate::header_admission::HEADER_SIDE_CACHE_LIMIT,
    )
}

pub(super) fn write_headers_with_side_limit<W: Write + ?Sized>(
    writer: &mut W,
    tree: &BlockTree,
    config: HeaderCheckpointConfig,
    best_tip_id: NodeId,
    applied: HeaderCheckpointPoint,
    side_limit: usize,
) -> Result<HeaderCheckpointWrite, HeaderCheckpointError> {
    let mut ancestry = tree.ancestor_chain(best_tip_id)?;
    ancestry.reverse();
    let count = u64::try_from(ancestry.len())
        .map_err(|_| HeaderCheckpointError::SizeOverflow { count: u64::MAX })?;

    let root = tree.node(
        *ancestry
            .first()
            .ok_or(HeaderCheckpointError::ZeroHeaderCount)?,
    )?;
    if root.height != 0 || root.hash != config.genesis {
        return Err(HeaderCheckpointError::RootIsNotGenesis);
    }

    let best = tip_from_node(tree, best_tip_id)?;
    if u64::from(best.height).checked_add(1) != Some(count) {
        return Err(HeaderCheckpointError::MalformedAncestry {
            height: best.height,
        });
    }
    let applied_id = tree
        .lookup(applied.hash)
        .ok_or(HeaderCheckpointError::AppliedTipNotBestPrefix)?;
    let applied_node = tree.node(applied_id)?;
    if applied_node.height != applied.height
        || tree.node_at_height_from(best_tip_id, applied.height) != Some(applied_id)
    {
        return Err(HeaderCheckpointError::AppliedTipNotBestPrefix);
    }
    let applied = tip_from_node(tree, applied_id)?;
    let mut side = tree.replayable_side_nodes(best_tip_id)?;
    side.truncate(side_limit);
    let side_count = u64::try_from(side.len())
        .map_err(|_| HeaderCheckpointError::SizeOverflow { count: u64::MAX })?;
    let bytes_written = side_section_end(count, side_count)?;

    writer.write_all(&prefix(config, count))?;
    let mut best_hasher = Sha256::new();
    best_hasher.update(BEST_CHAIN_DOMAIN);
    let mut applied_hasher = Sha256::new();
    applied_hasher.update(APPLIED_PREFIX_DOMAIN);

    for (index, node_id) in ancestry.into_iter().enumerate() {
        let height = u32::try_from(index)
            .map_err(|_| HeaderCheckpointError::CountExceedsHeightDomain { count })?;
        let node = tree.node(node_id)?;
        if node.height != height {
            return Err(HeaderCheckpointError::MalformedAncestry { height });
        }
        let encoded = encode_header(&node.header)?;
        writer.write_all(&encoded)?;
        best_hasher.update(encoded);
        if node.height <= applied.height {
            applied_hasher.update(encoded);
        }
    }
    writer.write_all(&side_count.to_le_bytes())?;
    for node_id in side {
        writer.write_all(&encode_header(&tree.node(node_id)?.header)?)?;
    }

    Ok(HeaderCheckpointWrite {
        metadata: HeaderCheckpointMetadata {
            version: HEADER_VERSION,
            header_count: count,
            best,
            applied,
            best_chain_commitment: best_hasher.finalize().into(),
            applied_prefix_commitment: applied_hasher.finalize().into(),
        },
        bytes_written,
    })
}

pub(crate) fn read_headers<R: Read + Seek>(
    reader: &mut R,
    config: HeaderCheckpointConfig,
    expected: HeaderCheckpointMetadata,
) -> Result<RestoredHeaders, HeaderCheckpointError> {
    read_headers_with_side_limit(
        reader,
        config,
        expected,
        crate::header_admission::HEADER_SIDE_CACHE_LIMIT,
    )
}

pub(super) fn read_headers_with_side_limit<R: Read + Seek>(
    reader: &mut R,
    config: HeaderCheckpointConfig,
    expected: HeaderCheckpointMetadata,
    side_limit: usize,
) -> Result<RestoredHeaders, HeaderCheckpointError> {
    validate_config(config)?;
    if !is_readable_version(expected.version) {
        return Err(HeaderCheckpointError::UnsupportedVersion {
            actual: expected.version,
        });
    }
    let sizes = resolve_artifact_sizes(reader, &expected)?;
    let count = verify_artifact_prefix(reader, config, &expected)?;
    let mut active = replay_active_headers(reader, config, &expected, count)?;
    let applied_tip_id = verify_active_against_manifest(
        &active.tree,
        active.best_tip_id,
        &expected,
        active.best_chain_commitment,
        active.applied_prefix_commitment,
    )?;
    restore_side_branches(
        reader,
        &mut active.tree,
        config,
        &sizes,
        active.best_tip_id,
        side_limit,
    )?;
    Ok(RestoredHeaders {
        tree: active.tree,
        applied_tip_id,
    })
}

struct ResolvedArtifactSizes {
    active_end: u64,
    side_count: u64,
    artifact_bytes: u64,
}

fn resolve_artifact_sizes<R: Read + Seek>(
    reader: &mut R,
    expected: &HeaderCheckpointMetadata,
) -> Result<ResolvedArtifactSizes, HeaderCheckpointError> {
    let active_end = checkpoint_size(expected.header_count)?;
    reader.seek(SeekFrom::Start(0))?;
    let actual_size = reader.seek(SeekFrom::End(0))?;
    let side_count = if expected.version == ACTIVE_ONLY_HEADER_VERSION {
        0
    } else {
        let side_count_end =
            active_end
                .checked_add(SIDE_COUNT_LEN)
                .ok_or(HeaderCheckpointError::SizeOverflow {
                    count: expected.header_count,
                })?;
        if actual_size < side_count_end {
            return Err(HeaderCheckpointError::InvalidFileLength {
                actual: actual_size,
                expected: side_count_end,
            });
        }
        reader.seek(SeekFrom::Start(active_end))?;
        let mut encoded = [0_u8; 8];
        reader.read_exact(&mut encoded)?;
        u64::from_le_bytes(encoded)
    };
    let expected_size = if expected.version == ACTIVE_ONLY_HEADER_VERSION {
        active_end
    } else {
        side_section_end(expected.header_count, side_count)?
    };
    if actual_size != expected_size {
        return Err(HeaderCheckpointError::InvalidFileLength {
            actual: actual_size,
            expected: expected_size,
        });
    }
    Ok(ResolvedArtifactSizes {
        active_end,
        side_count,
        artifact_bytes: actual_size,
    })
}

fn verify_artifact_prefix<R: Read + Seek>(
    reader: &mut R,
    config: HeaderCheckpointConfig,
    expected: &HeaderCheckpointMetadata,
) -> Result<u64, HeaderCheckpointError> {
    reader.seek(SeekFrom::Start(0))?;
    let mut encoded_prefix = [0_u8; HEADER_PREFIX_LEN];
    reader.read_exact(&mut encoded_prefix)?;
    let (version, count) = parse_prefix(encoded_prefix, config)?;
    if version != expected.version {
        return Err(HeaderCheckpointError::VersionMismatch {
            manifest: expected.version,
            artifact: version,
        });
    }
    if count != expected.header_count {
        return Err(HeaderCheckpointError::CountMismatch {
            actual: count,
            expected: expected.header_count,
        });
    }
    Ok(count)
}

struct ActiveReplay {
    tree: BlockTree,
    best_tip_id: NodeId,
    best_chain_commitment: [u8; 32],
    applied_prefix_commitment: [u8; 32],
}

fn replay_active_headers<R: Read + Seek>(
    reader: &mut R,
    config: HeaderCheckpointConfig,
    expected: &HeaderCheckpointMetadata,
    count: u64,
) -> Result<ActiveReplay, HeaderCheckpointError> {
    reader.seek(SeekFrom::Start(u64::try_from(HEADER_PREFIX_LEN).map_err(
        |_| HeaderCheckpointError::SizeOverflow {
            count: expected.header_count,
        },
    )?))?;
    let mut tree = BlockTree::new();
    let mut best_hasher = Sha256::new();
    best_hasher.update(BEST_CHAIN_DOMAIN);
    let mut applied_hasher = Sha256::new();
    applied_hasher.update(APPLIED_PREFIX_DOMAIN);
    let mut last_id = None;
    for index in 0..usize::try_from(count)
        .map_err(|_| HeaderCheckpointError::CountDoesNotFitUsize { count })?
    {
        let height = u32::try_from(index)
            .map_err(|_| HeaderCheckpointError::CountExceedsHeightDomain { count })?;
        let mut encoded = [0_u8; HEADER_LEN];
        reader.read_exact(&mut encoded)?;
        let header: Header = deserialize(&encoded)
            .map_err(|error| HeaderCheckpointError::Codec(error.to_string()))?;
        let accepted = accept_headers(
            &mut tree,
            core::slice::from_ref(&header),
            config.network,
            0,
            crate::chain::HeaderValidationMode::HistoricalReplay,
        )?;
        let id = accepted.ids[0];
        let node = tree.node(id)?;
        if node.height != height || tree.len() != index + 1 {
            return Err(HeaderCheckpointError::MalformedAncestry { height });
        }
        best_hasher.update(encoded);
        if height <= expected.applied.height {
            applied_hasher.update(encoded);
        }
        last_id = Some(id);
    }
    let best_tip_id = last_id.ok_or(HeaderCheckpointError::ZeroHeaderCount)?;
    Ok(ActiveReplay {
        tree,
        best_tip_id,
        best_chain_commitment: best_hasher.finalize().into(),
        applied_prefix_commitment: applied_hasher.finalize().into(),
    })
}

fn verify_active_against_manifest(
    tree: &BlockTree,
    best_tip_id: NodeId,
    expected: &HeaderCheckpointMetadata,
    best_chain_commitment: [u8; 32],
    applied_prefix_commitment: [u8; 32],
) -> Result<NodeId, HeaderCheckpointError> {
    let best = tip_from_node(tree, best_tip_id)?;
    if tree.tip_id() != Some(best_tip_id) || best != expected.best {
        return Err(HeaderCheckpointError::MetadataMismatch);
    }
    let applied_tip_id = tree
        .lookup(expected.applied.hash)
        .ok_or(HeaderCheckpointError::AppliedTipNotBestPrefix)?;
    let applied_tip = tip_from_node(tree, applied_tip_id)?;
    if applied_tip != expected.applied
        || tree.node_at_height_from(best_tip_id, expected.applied.height) != Some(applied_tip_id)
    {
        return Err(HeaderCheckpointError::AppliedTipNotBestPrefix);
    }
    if best_chain_commitment != expected.best_chain_commitment
        || applied_prefix_commitment != expected.applied_prefix_commitment
    {
        return Err(HeaderCheckpointError::CommitmentMismatch);
    }
    Ok(applied_tip_id)
}

fn restore_side_branches<R: Read + Seek>(
    reader: &mut R,
    tree: &mut BlockTree,
    config: HeaderCheckpointConfig,
    sizes: &ResolvedArtifactSizes,
    best_tip_id: NodeId,
    side_limit: usize,
) -> Result<(), HeaderCheckpointError> {
    if sizes.side_count == 0 {
        return Ok(());
    }
    reader.seek(SeekFrom::Start(sizes.active_end + SIDE_COUNT_LEN))?;
    if usize::try_from(sizes.side_count).is_ok_and(|count| count <= side_limit) {
        replay_side_headers(reader, tree, config, sizes.side_count)?;
    } else {
        replay_indexed_side_headers(reader, tree, config, sizes, best_tip_id, side_limit)?;
    }
    if tree.tip_id() != Some(best_tip_id) {
        return Err(HeaderCheckpointError::SideBranchDisplacedBestTip);
    }
    Ok(())
}

pub(super) const fn is_readable_version(version: u32) -> bool {
    version == HEADER_VERSION || version == ACTIVE_ONLY_HEADER_VERSION
}

fn replay_side_headers<R: Read>(
    reader: &mut R,
    tree: &mut BlockTree,
    config: HeaderCheckpointConfig,
    side_count: u64,
) -> Result<(), HeaderCheckpointError> {
    for index in 0..side_count {
        let mut encoded = [0_u8; HEADER_LEN];
        reader.read_exact(&mut encoded)?;
        let header: Header = deserialize(&encoded)
            .map_err(|error| HeaderCheckpointError::Codec(error.to_string()))?;
        let before = tree.len();
        accept_headers(
            tree,
            core::slice::from_ref(&header),
            config.network,
            0,
            crate::chain::HeaderValidationMode::HistoricalReplay,
        )?;
        if tree.len() != before + 1 {
            return Err(HeaderCheckpointError::MalformedSideBranch { index });
        }
    }
    Ok(())
}

fn replay_indexed_side_headers<R: Read>(
    reader: &mut R,
    tree: &mut BlockTree,
    config: HeaderCheckpointConfig,
    sizes: &ResolvedArtifactSizes,
    best_tip_id: NodeId,
    side_limit: usize,
) -> Result<(), HeaderCheckpointError> {
    let best_work = tree.node(best_tip_id)?.chainwork;
    let mut contexts =
        TemporaryContextIndex::new(sizes.side_count, sizes.artifact_bytes, config.network)?;
    for index in 0..sizes.side_count {
        let mut encoded = [0_u8; HEADER_LEN];
        reader.read_exact(&mut encoded)?;
        let header: Header = deserialize(&encoded)
            .map_err(|error| HeaderCheckpointError::Codec(error.to_string()))?;
        let hash = Hash256::from(header.compute_hash());
        if tree.lookup(hash).is_some() {
            return Err(HeaderCheckpointError::MalformedSideBranch { index });
        }
        let ContextEntry::Vacant(offset) = contexts.entry(hash)? else {
            return Err(HeaderCheckpointError::MalformedSideBranch { index });
        };
        let parent_hash = Hash256::from(header.prev_blockhash);
        let mut context = if let Some(parent) = tree.lookup(parent_hash) {
            HeaderValidationContext::from_tree(tree, parent, config.network)?
        } else {
            match contexts.entry(parent_hash)? {
                ContextEntry::Occupied(context) => context,
                ContextEntry::Vacant(_) => {
                    return Err(crate::chain::ChainError::MissingParent {
                        prev_hash: parent_hash,
                    }
                    .into());
                }
            }
        };
        context.accept_header(
            &header,
            0,
            crate::chain::HeaderValidationMode::HistoricalReplay,
        )?;
        if context.chainwork() > best_work {
            return Err(HeaderCheckpointError::SideBranchDisplacedBestTip);
        }
        contexts.insert(offset, index, &context)?;
        if usize::try_from(index).is_ok_and(|index| index < side_limit) {
            tree.insert_header_with_hash(header, hash, crate::chain::NodeStatus::HeaderValid)?;
        }
    }
    Ok(())
}

const CONTEXT_INDEX_KEY_START: usize = 8;
const CONTEXT_INDEX_STATE_START: usize = CONTEXT_INDEX_KEY_START + 32;
const CONTEXT_INDEX_DIGEST_START: usize = CONTEXT_INDEX_STATE_START + HEADER_CONTEXT_SNAPSHOT_LEN;
const CONTEXT_INDEX_RECORD_LEN: usize = CONTEXT_INDEX_DIGEST_START + 32;
const CONTEXT_INDEX_EXPANSION: usize = (2 * CONTEXT_INDEX_RECORD_LEN).div_ceil(HEADER_LEN);

enum ContextEntry {
    Vacant(u64),
    Occupied(HeaderValidationContext),
}

/// Only an entirely zero record is empty. Checksums identify partial damage;
/// complete erasure to the empty representation cannot be distinguished here.
struct TemporaryContextIndex {
    file: std::fs::File,
    hasher: RandomState,
    slots: u64,
    side_count: u64,
    network: Network,
}

impl TemporaryContextIndex {
    fn new(
        side_count: u64,
        artifact_bytes: u64,
        network: Network,
    ) -> Result<Self, HeaderCheckpointError> {
        let slots = side_count
            .checked_mul(2)
            .filter(|&slots| slots != 0)
            .ok_or_else(|| temporary_index_failure("temporary header index capacity overflow"))?;
        let record_len = u64::try_from(CONTEXT_INDEX_RECORD_LEN)
            .map_err(|error| HeaderCheckpointError::TemporaryIndex(std::io::Error::other(error)))?;
        let bytes = slots.checked_mul(record_len).ok_or_else(|| {
            temporary_index_failure("temporary header index byte length overflow")
        })?;
        let expansion = u64::try_from(CONTEXT_INDEX_EXPANSION)
            .map_err(|error| HeaderCheckpointError::TemporaryIndex(std::io::Error::other(error)))?;
        let bound = artifact_bytes.checked_mul(expansion).ok_or_else(|| {
            temporary_index_failure("temporary header index artifact bound overflow")
        })?;
        if bytes > bound {
            return Err(temporary_index_failure(
                "temporary header index exceeds artifact bound",
            ));
        }
        let file = tempfile::tempfile().map_err(HeaderCheckpointError::TemporaryIndex)?;
        file.set_len(bytes)
            .map_err(HeaderCheckpointError::TemporaryIndex)?;
        Ok(Self {
            file,
            hasher: RandomState::new(),
            slots,
            side_count,
            network,
        })
    }

    fn entry(&mut self, hash: Hash256) -> Result<ContextEntry, HeaderCheckpointError> {
        let record_len = u64::try_from(CONTEXT_INDEX_RECORD_LEN)
            .map_err(|error| HeaderCheckpointError::TemporaryIndex(std::io::Error::other(error)))?;
        let mut slot = self.hasher.hash_one(hash) % self.slots;
        for _ in 0..self.slots {
            let offset = slot
                .checked_mul(record_len)
                .ok_or_else(|| temporary_index_failure("temporary header index offset overflow"))?;
            self.file
                .seek(SeekFrom::Start(offset))
                .map_err(HeaderCheckpointError::TemporaryIndex)?;
            let mut record = [0_u8; CONTEXT_INDEX_RECORD_LEN];
            self.file
                .read_exact(&mut record)
                .map_err(HeaderCheckpointError::TemporaryIndex)?;
            if record.iter().all(|&byte| byte == 0) {
                return Ok(ContextEntry::Vacant(offset));
            }
            let mut ordinal_bytes = [0_u8; 8];
            ordinal_bytes.copy_from_slice(&record[..CONTEXT_INDEX_KEY_START]);
            let ordinal = u64::from_le_bytes(ordinal_bytes);
            let digest: [u8; 32] = Sha256::digest(&record[..CONTEXT_INDEX_DIGEST_START]).into();
            if ordinal == 0
                || ordinal > self.side_count
                || record[CONTEXT_INDEX_DIGEST_START..] != digest
            {
                return Err(temporary_index_failure(
                    "temporary header index record is invalid",
                ));
            }
            if record[CONTEXT_INDEX_KEY_START..CONTEXT_INDEX_STATE_START] == hash.to_le_bytes() {
                let mut state = [0_u8; HEADER_CONTEXT_SNAPSHOT_LEN];
                state.copy_from_slice(
                    &record[CONTEXT_INDEX_STATE_START..CONTEXT_INDEX_DIGEST_START],
                );
                let context = HeaderValidationContext::decode_snapshot(self.network, &state)
                    .map_err(|error| {
                        HeaderCheckpointError::TemporaryIndex(std::io::Error::other(error))
                    })?;
                if context.hash() != hash {
                    return Err(temporary_index_failure(
                        "temporary header index context has a different hash",
                    ));
                }
                return Ok(ContextEntry::Occupied(context));
            }
            slot = if slot + 1 == self.slots { 0 } else { slot + 1 };
        }
        Err(temporary_index_failure(
            "temporary header index probe bound exhausted",
        ))
    }

    fn insert(
        &mut self,
        offset: u64,
        index: u64,
        context: &HeaderValidationContext,
    ) -> Result<(), HeaderCheckpointError> {
        let mut record = [0_u8; CONTEXT_INDEX_RECORD_LEN];
        let ordinal = index
            .checked_add(1)
            .filter(|&value| value <= self.side_count)
            .ok_or_else(|| temporary_index_failure("temporary header index ordinal overflow"))?;
        record[..CONTEXT_INDEX_KEY_START].copy_from_slice(&ordinal.to_le_bytes());
        record[CONTEXT_INDEX_KEY_START..CONTEXT_INDEX_STATE_START]
            .copy_from_slice(&context.hash().to_le_bytes());
        record[CONTEXT_INDEX_STATE_START..CONTEXT_INDEX_DIGEST_START]
            .copy_from_slice(&context.encode_snapshot());
        let digest: [u8; 32] = Sha256::digest(&record[..CONTEXT_INDEX_DIGEST_START]).into();
        record[CONTEXT_INDEX_DIGEST_START..].copy_from_slice(&digest);
        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(HeaderCheckpointError::TemporaryIndex)?;
        self.file
            .write_all(&record)
            .map_err(HeaderCheckpointError::TemporaryIndex)
    }
}

fn temporary_index_failure(message: &'static str) -> HeaderCheckpointError {
    HeaderCheckpointError::TemporaryIndex(std::io::Error::other(message))
}

fn side_section_end(count: u64, side_count: u64) -> Result<u64, HeaderCheckpointError> {
    let active_end = checkpoint_size(count)?;
    if count
        .checked_add(side_count)
        .is_none_or(|total| total > u64::from(u32::MAX) + 1)
    {
        return Err(HeaderCheckpointError::SideCountExceedsNodeDomain { count: side_count });
    }
    let header_len = u64::try_from(HEADER_LEN)
        .map_err(|_| HeaderCheckpointError::SizeOverflow { count: side_count })?;
    side_count
        .checked_mul(header_len)
        .and_then(|side_len| {
            active_end
                .checked_add(SIDE_COUNT_LEN)?
                .checked_add(side_len)
        })
        .ok_or(HeaderCheckpointError::SizeOverflow { count: side_count })
}

fn validate_config(config: HeaderCheckpointConfig) -> Result<(), HeaderCheckpointError> {
    let expected = config.network.genesis_block_hash();
    if config.genesis != expected {
        return Err(HeaderCheckpointError::ConfiguredGenesisMismatch {
            configured: config.genesis,
            expected,
            network: config.network,
        });
    }
    Ok(())
}

fn checkpoint_size(count: u64) -> Result<u64, HeaderCheckpointError> {
    if count == 0 {
        return Err(HeaderCheckpointError::ZeroHeaderCount);
    }
    if usize::try_from(count).is_err() {
        return Err(HeaderCheckpointError::CountDoesNotFitUsize { count });
    }
    if count > u64::from(u32::MAX) + 1 {
        return Err(HeaderCheckpointError::CountExceedsHeightDomain { count });
    }
    let prefix_len = u64::try_from(HEADER_PREFIX_LEN)
        .map_err(|_| HeaderCheckpointError::SizeOverflow { count })?;
    let header_len =
        u64::try_from(HEADER_LEN).map_err(|_| HeaderCheckpointError::SizeOverflow { count })?;
    prefix_len
        .checked_add(
            count
                .checked_mul(header_len)
                .ok_or(HeaderCheckpointError::SizeOverflow { count })?,
        )
        .ok_or(HeaderCheckpointError::SizeOverflow { count })
}

pub(super) fn prefix(config: HeaderCheckpointConfig, count: u64) -> [u8; HEADER_PREFIX_LEN] {
    let mut out = [0_u8; HEADER_PREFIX_LEN];
    out[..8].copy_from_slice(&HEADER_MAGIC);
    out[8..12].copy_from_slice(&HEADER_VERSION.to_le_bytes());
    out[12..16].copy_from_slice(&config.network.magic());
    out[16..48].copy_from_slice(&config.genesis.to_le_bytes());
    out[48..].copy_from_slice(&count.to_le_bytes());
    out
}

fn parse_prefix(
    encoded: [u8; HEADER_PREFIX_LEN],
    config: HeaderCheckpointConfig,
) -> Result<(u32, u64), HeaderCheckpointError> {
    if encoded[..8] != HEADER_MAGIC {
        return Err(HeaderCheckpointError::BadMagic);
    }
    let version = u32::from_le_bytes([encoded[8], encoded[9], encoded[10], encoded[11]]);
    if !is_readable_version(version) {
        return Err(HeaderCheckpointError::UnsupportedVersion { actual: version });
    }
    if encoded[12..16] != config.network.magic() {
        return Err(HeaderCheckpointError::NetworkMismatch);
    }
    if encoded[16..48] != config.genesis.to_le_bytes() {
        return Err(HeaderCheckpointError::GenesisMismatch);
    }
    let count = u64::from_le_bytes([
        encoded[48],
        encoded[49],
        encoded[50],
        encoded[51],
        encoded[52],
        encoded[53],
        encoded[54],
        encoded[55],
    ]);
    checkpoint_size(count)?;
    Ok((version, count))
}

fn tip_from_node(
    tree: &BlockTree,
    id: NodeId,
) -> Result<HeaderCheckpointTip, HeaderCheckpointError> {
    let node = tree.node(id)?;
    Ok(HeaderCheckpointTip {
        height: node.height,
        hash: node.hash,
        chainwork: node.chainwork,
    })
}

struct ByteSliceSink<'a>(&'a mut [u8]);

impl bitcoin_rs_consensus::primitives::Sink for ByteSliceSink<'_> {
    fn write_all(&mut self, bytes: &[u8]) {
        let len = bytes.len().min(self.0.len());
        let empty: &mut [u8] = &mut [];
        let rest = core::mem::replace(&mut self.0, empty);
        let (head, tail) = rest.split_at_mut(len);
        head.copy_from_slice(&bytes[..len]);
        self.0 = tail;
    }
}

impl ByteSliceSink<'_> {
    fn remaining(&self) -> &[u8] {
        self.0
    }
}

pub(super) fn encode_header(header: &Header) -> Result<[u8; HEADER_LEN], HeaderCheckpointError> {
    let mut encoded = [0_u8; HEADER_LEN];
    let mut sink = ByteSliceSink(&mut encoded[..]);
    header.consensus_encode(&mut sink);
    if !sink.remaining().is_empty() {
        return Err(HeaderCheckpointError::Codec(
            "Bitcoin header did not encode to 80 bytes".to_owned(),
        ));
    }
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use bitcoin_rs_consensus::primitives::BlockHash;

    use crate::chain::regtest_fixture::{mine_header_to_declared_target, mined_regtest_header};
    use crate::chain::{ChainError, HeaderValidationMode};
    use crate::test_fixtures::{TestError, TestResult};

    use super::*;

    const SIDE_LIMIT: usize = 8;

    struct BranchedHeaders {
        tree: BlockTree,
        best: NodeId,
        applied: HeaderCheckpointPoint,
        side: Vec<Header>,
    }

    fn config() -> HeaderCheckpointConfig {
        HeaderCheckpointConfig {
            network: Network::Regtest,
            genesis: Network::Regtest.genesis_block_hash(),
        }
    }

    fn append_header(
        tree: &mut BlockTree,
        parent: NodeId,
        height: u32,
        time_offset: u32,
    ) -> TestResult<(NodeId, Header)> {
        let mut header = mined_regtest_header(BlockHash(tree.node(parent)?.hash), height)?;
        header.time += time_offset;
        mine_header_to_declared_target(&mut header)?;
        let id = accept_headers(
            tree,
            &[header],
            Network::Regtest,
            0,
            HeaderValidationMode::HistoricalReplay,
        )?
        .ids[0];
        Ok((id, header))
    }

    fn branched_headers() -> TestResult<BranchedHeaders> {
        let mut tree = BlockTree::new();
        let mut best = accept_headers(
            &mut tree,
            &[Network::Regtest.genesis_block().header],
            Network::Regtest,
            0,
            HeaderValidationMode::HistoricalReplay,
        )?
        .ids[0];
        let mut applied = None;
        for height in 1..=40 {
            best = append_header(&mut tree, best, height, 0)?.0;
            if height == 20 {
                applied = Some(HeaderCheckpointPoint {
                    height,
                    hash: tree.node(best)?.hash,
                });
            }
        }
        let fork = tree
            .node_at_height_from(best, 10)
            .ok_or(TestError::Missing("fork point"))?;
        let mut side = Vec::new();
        for salt in 1..=4 {
            let mut parent = fork;
            for height in 11..=26 {
                let (id, header) = append_header(&mut tree, parent, height, 100 * salt)?;
                parent = id;
                side.push(header);
            }
        }
        Ok(BranchedHeaders {
            tree,
            best,
            applied: applied.ok_or(TestError::Missing("applied height"))?,
            side,
        })
    }

    fn artifact(
        fixture: &BranchedHeaders,
        side_limit: usize,
    ) -> TestResult<(Vec<u8>, HeaderCheckpointMetadata)> {
        let mut bytes = Vec::new();
        let written = write_headers_with_side_limit(
            &mut bytes,
            &fixture.tree,
            config(),
            fixture.best,
            fixture.applied,
            side_limit,
        )?;
        assert_eq!(written.bytes_written, u64::try_from(bytes.len())?);
        Ok((bytes, written.metadata))
    }

    fn side_start(metadata: HeaderCheckpointMetadata) -> TestResult<usize> {
        Ok(usize::try_from(checkpoint_size(metadata.header_count)?)? + 8)
    }

    // RCV-09, SYNC-01, SYNC-03
    #[test]
    fn side_publication_retains_a_bounded_topological_prefix() -> TestResult {
        let fixture = branched_headers()?;
        for side_limit in [0, SIDE_LIMIT - 1, SIDE_LIMIT] {
            let (bytes, metadata) = artifact(&fixture, side_limit)?;
            let start = side_start(metadata)?;
            assert_eq!(
                u64::from_le_bytes(bytes[start - 8..start].try_into()?),
                u64::try_from(side_limit)?
            );
            assert_eq!(bytes.len(), start + side_limit * HEADER_LEN);
            let restored = read_headers_with_side_limit(
                &mut Cursor::new(bytes),
                config(),
                metadata,
                side_limit,
            )?;
            assert_eq!(restored.tree.len(), 41 + side_limit);
            assert_eq!(
                restored.tree.tip().map(|tip| tip.hash),
                Some(metadata.best.hash)
            );
            assert_eq!(
                restored.tree.node(restored.applied_tip_id)?.hash,
                fixture.applied.hash
            );
            for (index, header) in fixture.side.iter().enumerate() {
                let hash = Hash256::from(header.compute_hash());
                assert_eq!(restored.tree.lookup(hash).is_some(), index < side_limit);
            }
        }
        Ok(())
    }

    // RCV-09, SYNC-01, SYNC-03, SYNC-05
    #[test]
    fn legacy_side_replay_validates_nonresident_parents_before_returning_a_bounded_tree()
    -> TestResult {
        let fixture = branched_headers()?;
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("headers.dat");
        for side_count in [
            SIDE_LIMIT - 1,
            SIDE_LIMIT,
            SIDE_LIMIT + 1,
            fixture.side.len(),
        ] {
            let (bytes, metadata) = artifact(&fixture, side_count)?;
            std::fs::write(&path, &bytes)?;
            for side_limit in [0, SIDE_LIMIT] {
                let retained = side_count.min(side_limit);
                let mut reader = std::fs::File::open(&path)?;
                let restored =
                    read_headers_with_side_limit(&mut reader, config(), metadata, side_limit)?;
                assert_eq!(reader.stream_position()?, u64::try_from(bytes.len())?);
                assert_eq!(restored.tree.len(), 41 + retained);
                assert_eq!(
                    restored.tree.tip().map(|tip| tip.hash),
                    Some(metadata.best.hash)
                );
                assert_eq!(
                    restored.tree.node(restored.applied_tip_id)?.hash,
                    fixture.applied.hash
                );
                for (index, header) in fixture.side.iter().enumerate() {
                    assert_eq!(
                        restored.tree.lookup(header.compute_hash().into()).is_some(),
                        index < retained
                    );
                }
                if side_count > SIDE_LIMIT + 1 {
                    assert!(
                        restored
                            .tree
                            .lookup(fixture.side[9].prev_blockhash.into())
                            .is_none()
                    );
                }
                assert_eq!(std::fs::read(&path)?, bytes);
            }
        }
        Ok(())
    }

    // RCV-09, SYNC-04, SYNC-05
    #[test]
    fn legacy_records_beyond_the_resident_limit_keep_context_duplicate_and_orphan_checks()
    -> TestResult {
        let fixture = branched_headers()?;
        let (bytes, metadata) = artifact(&fixture, usize::MAX)?;
        let start = side_start(metadata)?;
        let index = SIDE_LIMIT + 2;
        let at = start + index * HEADER_LEN;
        let mut invalid_context = bytes.clone();
        let last = fixture.side.len() - 1;
        let last_at = start + last * HEADER_LEN;
        let mut header = fixture.side[last];
        header.time = 0;
        mine_header_to_declared_target(&mut header)?;
        invalid_context[last_at..last_at + HEADER_LEN].copy_from_slice(&encode_header(&header)?);
        assert!(matches!(
            read_headers_with_side_limit(
                &mut Cursor::new(invalid_context),
                config(),
                metadata,
                SIDE_LIMIT
            ),
            Err(HeaderCheckpointError::Context(HeaderContextError::Chain(
                ChainError::TimestampTooEarly { .. }
            )))
        ));

        let mut invalid_pow = bytes.clone();
        let mut header = fixture.side[index];
        while crate::chain::compact_is_met_by(header.bits, header.compute_hash().into()) {
            header.nonce = header
                .nonce
                .checked_add(1)
                .ok_or(TestError::Missing("unsolved nonce"))?;
        }
        invalid_pow[at..at + HEADER_LEN].copy_from_slice(&encode_header(&header)?);
        assert!(matches!(
            read_headers_with_side_limit(
                &mut Cursor::new(invalid_pow),
                config(),
                metadata,
                SIDE_LIMIT
            ),
            Err(HeaderCheckpointError::Context(HeaderContextError::Chain(
                ChainError::InvalidPow { .. }
            )))
        ));

        let mut duplicate = bytes.clone();
        duplicate[at..at + HEADER_LEN].copy_from_slice(&encode_header(&fixture.side[index - 1])?);
        assert!(matches!(
            read_headers_with_side_limit(
                &mut Cursor::new(duplicate),
                config(),
                metadata,
                SIDE_LIMIT
            ),
            Err(HeaderCheckpointError::MalformedSideBranch { index: 10 })
        ));

        let mut orphan = bytes.clone();
        let mut header = fixture.side[index];
        header.prev_blockhash = BlockHash::from(Hash256::from_le_bytes(&[0x42; 32]));
        mine_header_to_declared_target(&mut header)?;
        orphan[at..at + HEADER_LEN].copy_from_slice(&encode_header(&header)?);
        assert!(matches!(
            read_headers_with_side_limit(&mut Cursor::new(orphan), config(), metadata, SIDE_LIMIT),
            Err(HeaderCheckpointError::Chain(
                ChainError::MissingParent { .. }
            ))
        ));

        let mut displaced = bytes;
        let mut header =
            mined_regtest_header(BlockHash(metadata.best.hash), metadata.best.height + 1)?;
        mine_header_to_declared_target(&mut header)?;
        let side_count = u64::try_from(fixture.side.len())? + 1;
        displaced[start - 8..start].copy_from_slice(&side_count.to_le_bytes());
        displaced.extend_from_slice(&encode_header(&header)?);
        assert!(matches!(
            read_headers_with_side_limit(
                &mut Cursor::new(displaced),
                config(),
                metadata,
                SIDE_LIMIT
            ),
            Err(HeaderCheckpointError::SideBranchDisplacedBestTip)
        ));
        Ok(())
    }

    // RCV-09, SYNC-01, SYNC-02
    #[test]
    fn retained_side_prefix_can_extend_to_a_valid_heavier_branch_after_restart() -> TestResult {
        let fixture = branched_headers()?;
        let (bytes, metadata) = artifact(&fixture, usize::MAX)?;
        let mut restored =
            read_headers_with_side_limit(&mut Cursor::new(bytes), config(), metadata, SIDE_LIMIT)?;
        let mut parent = restored
            .tree
            .lookup(fixture.side[SIDE_LIMIT - 1].compute_hash().into())
            .ok_or(TestError::Missing("retained side prefix"))?;
        for height in 19..=41 {
            parent = append_header(&mut restored.tree, parent, height, 100)?.0;
        }
        let tip = restored
            .tree
            .tip()
            .ok_or(TestError::Missing("heavier tip"))?;
        assert_eq!(restored.tree.tip_id(), Some(parent));
        assert_eq!(tip.height, 41);
        assert_ne!(tip.hash, metadata.best.hash);
        assert_eq!(
            restored.tree.node(restored.applied_tip_id)?.hash,
            fixture.applied.hash
        );
        Ok(())
    }

    // RCV-09, SYNC-03, SYNC-05
    #[test]
    fn repeated_winning_forks_do_not_expand_selected_checkpoint_side_publication() -> TestResult {
        let mut fixture = branched_headers()?;
        let genesis = fixture
            .tree
            .lookup(Network::Regtest.genesis_block_hash())
            .ok_or(TestError::Missing("genesis"))?;
        let applied_id = fixture
            .tree
            .lookup(fixture.applied.hash)
            .ok_or(TestError::Missing("applied tip"))?;
        let applied_node = fixture.tree.node(applied_id)?;
        let applied = crate::chain::TipSnapshot {
            tip_id: applied_id,
            height: applied_node.height,
            hash: applied_node.hash,
            chainwork: applied_node.chainwork,
            chain_tx_count: applied_node.chain_tx_count,
        };
        for salt in 1..=4 {
            let mut parent = genesis;
            for height in 1..=44 + salt {
                parent = append_header(&mut fixture.tree, parent, height, 10_000 * salt)?.0;
            }
            assert_eq!(fixture.tree.tip_id(), Some(parent));
            fixture.best = super::super::checkpoint_best_tip_id(&fixture.tree, &applied)?;
            assert_eq!(fixture.best, applied_id);
            let (bytes, metadata) = artifact(&fixture, SIDE_LIMIT)?;
            let start = side_start(metadata)?;
            assert_eq!(bytes.len(), start + SIDE_LIMIT * HEADER_LEN);
            assert_eq!(metadata.best.hash, fixture.applied.hash);
            let restored = read_headers_with_side_limit(
                &mut Cursor::new(bytes),
                config(),
                metadata,
                SIDE_LIMIT,
            )?;
            assert_eq!(restored.tree.len(), 21 + SIDE_LIMIT);
            assert_eq!(
                restored.tree.tip().map(|tip| tip.hash),
                Some(fixture.applied.hash)
            );
            assert_eq!(
                restored.tree.node(restored.applied_tip_id)?.hash,
                fixture.applied.hash
            );
        }
        Ok(())
    }

    // RCV-09, SYNC-03, SYNC-04
    #[test]
    fn temporary_context_index_bounds_space_handles_collisions_and_detects_damage() -> TestResult {
        let fixture = branched_headers()?;
        let mut index = TemporaryContextIndex::new(2, 160, Network::Regtest)?;
        let mut candidates: Vec<(u64, HeaderValidationContext)> = Vec::new();
        let mut collision = None;
        for header in fixture.side.iter().take(5) {
            let id = fixture
                .tree
                .lookup(header.compute_hash().into())
                .ok_or(TestError::Missing("side header"))?;
            let context = HeaderValidationContext::from_tree(&fixture.tree, id, Network::Regtest)?;
            let bucket = index.hasher.hash_one(context.hash()) % index.slots;
            if let Some((_, previous)) = candidates.iter().find(|(slot, _)| *slot == bucket) {
                collision = Some((previous.clone(), context));
                break;
            }
            candidates.push((bucket, context));
        }
        let (first, second) =
            collision.ok_or(TestError::Missing("five keys occupy four buckets"))?;
        let ContextEntry::Vacant(first_offset) = index.entry(first.hash())? else {
            return Err(TestError::UnexpectedSuccess("new index contains a context"));
        };
        index.insert(first_offset, 0, &first)?;
        let ContextEntry::Vacant(second_offset) = index.entry(second.hash())? else {
            return Err(TestError::UnexpectedSuccess("colliding key already exists"));
        };
        assert_ne!(first_offset, second_offset);
        index.insert(second_offset, 1, &second)?;
        for context in [&first, &second] {
            let ContextEntry::Occupied(loaded) = index.entry(context.hash())? else {
                return Err(TestError::Missing("stored context"));
            };
            assert_eq!(loaded, *context);
        }
        assert_eq!(index.file.metadata()?.len(), 984);
        assert!(index.file.metadata()?.len() <= 7 * 160);

        let mut full = TemporaryContextIndex::new(1, 80, Network::Regtest)?;
        full.insert(0, 0, &first)?;
        full.insert(u64::try_from(CONTEXT_INDEX_RECORD_LEN)?, 0, &first)?;
        assert!(matches!(
            full.entry(second.hash()),
            Err(HeaderCheckpointError::TemporaryIndex(_))
        ));

        index.file.seek(SeekFrom::Start(
            first_offset + u64::try_from(CONTEXT_INDEX_KEY_START)?,
        ))?;
        index.file.write_all(&[first.hash().to_le_bytes()[0] ^ 1])?;
        assert!(matches!(
            index.entry(first.hash()),
            Err(HeaderCheckpointError::TemporaryIndex(_))
        ));
        for (count, bytes) in [(1, 1), (0, 80), (u64::MAX, u64::MAX)] {
            assert!(matches!(
                TemporaryContextIndex::new(count, bytes, Network::Regtest),
                Err(HeaderCheckpointError::TemporaryIndex(_))
            ));
        }
        Ok(())
    }

    // RCV-09, SYNC-04
    #[test]
    fn temporary_context_index_rejects_zero_ordinal_with_nonzero_payload() -> TestResult {
        let fixture = branched_headers()?;
        let context =
            HeaderValidationContext::from_tree(&fixture.tree, fixture.best, Network::Regtest)?;
        let mut index = TemporaryContextIndex::new(1, 80, Network::Regtest)?;
        let ContextEntry::Vacant(offset) = index.entry(context.hash())? else {
            return Err(TestError::UnexpectedSuccess("new index contains a context"));
        };
        index.insert(offset, 0, &context)?;
        index.file.seek(SeekFrom::Start(offset))?;
        index.file.write_all(&[0_u8; 8])?;
        assert!(matches!(
            index.entry(context.hash()),
            Err(HeaderCheckpointError::TemporaryIndex(_))
        ));
        Ok(())
    }
}
