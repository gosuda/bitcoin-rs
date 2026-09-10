//! Canonical header-checkpoint representation and validation.
//!
//! Owns the headers-v1 prefix, ancestry serialization, independent best/applied
//! commitments, and consensus-validated reconstruction. The parent owns the
//! immutable generation and CURRENT publication; this codec does not publish,
//! remove, or sync files. Existing wire bytes and typed failures are unchanged.

use std::io::{Read, Seek, SeekFrom, Write};

use bitcoin_rs_chain::{BlockTree, ChainWork, NodeId, accept_headers};
use bitcoin_rs_primitives::{ConsensusEncode, Hash256, Header, Network, deserialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const HEADER_MAGIC: [u8; 8] = *b"BRSHEAD\0";
pub(super) const HEADER_VERSION: u32 = 1;
pub(super) const HEADER_PREFIX_LEN: usize = 56;
const HEADER_LEN: usize = 80;
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
pub(crate) enum HeaderCheckpointError {
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
    #[error("header checkpoint consensus validation failed: {0}")]
    Chain(#[from] bitcoin_rs_chain::ChainError),
}

pub(crate) fn write_headers<W: Write>(
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
    write_headers_inner(writer, tree, config, best_tip_id, applied)
}

pub(super) fn write_selected_headers<W: Write>(
    writer: &mut W,
    tree: &BlockTree,
    config: HeaderCheckpointConfig,
    best_tip_id: NodeId,
    applied: HeaderCheckpointPoint,
) -> Result<HeaderCheckpointWrite, HeaderCheckpointError> {
    validate_config(config)?;
    write_headers_inner(writer, tree, config, best_tip_id, applied)
}

fn write_headers_inner<W: Write>(
    writer: &mut W,
    tree: &BlockTree,
    config: HeaderCheckpointConfig,
    best_tip_id: NodeId,
    applied: HeaderCheckpointPoint,
) -> Result<HeaderCheckpointWrite, HeaderCheckpointError> {
    let mut ancestry = tree.ancestor_chain(best_tip_id)?;
    ancestry.reverse();
    let count = u64::try_from(ancestry.len())
        .map_err(|_| HeaderCheckpointError::SizeOverflow { count: u64::MAX })?;
    let bytes_written = checkpoint_size(count)?;

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

    Ok(HeaderCheckpointWrite {
        metadata: HeaderCheckpointMetadata {
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
    validate_config(config)?;
    let expected_size = checkpoint_size(expected.header_count)?;
    reader.seek(SeekFrom::Start(0))?;
    let actual_size = reader.seek(SeekFrom::End(0))?;
    if actual_size != expected_size {
        return Err(HeaderCheckpointError::InvalidFileLength {
            actual: actual_size,
            expected: expected_size,
        });
    }
    reader.seek(SeekFrom::Start(0))?;

    let mut encoded_prefix = [0_u8; HEADER_PREFIX_LEN];
    reader.read_exact(&mut encoded_prefix)?;
    let count = parse_prefix(encoded_prefix, config)?;
    if count != expected.header_count {
        return Err(HeaderCheckpointError::CountMismatch {
            actual: count,
            expected: expected.header_count,
        });
    }

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
        let ids = accept_headers(
            &mut tree,
            core::slice::from_ref(&header),
            config.network,
            bitcoin_rs_chain::current_unix_seconds(),
        )?;
        let id = ids[0];
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
    let best = tip_from_node(&tree, best_tip_id)?;
    if tree.tip_id() != Some(best_tip_id) || best != expected.best {
        return Err(HeaderCheckpointError::MetadataMismatch);
    }
    let applied_tip_id = tree
        .lookup(expected.applied.hash)
        .ok_or(HeaderCheckpointError::AppliedTipNotBestPrefix)?;
    let applied_tip = tip_from_node(&tree, applied_tip_id)?;
    if applied_tip != expected.applied
        || tree.node_at_height_from(best_tip_id, expected.applied.height) != Some(applied_tip_id)
    {
        return Err(HeaderCheckpointError::AppliedTipNotBestPrefix);
    }
    let best_chain_commitment: [u8; 32] = best_hasher.finalize().into();
    let applied_prefix_commitment: [u8; 32] = applied_hasher.finalize().into();
    if best_chain_commitment != expected.best_chain_commitment
        || applied_prefix_commitment != expected.applied_prefix_commitment
    {
        return Err(HeaderCheckpointError::CommitmentMismatch);
    }

    Ok(RestoredHeaders {
        tree,
        applied_tip_id,
    })
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
) -> Result<u64, HeaderCheckpointError> {
    if encoded[..8] != HEADER_MAGIC {
        return Err(HeaderCheckpointError::BadMagic);
    }
    let version = u32::from_le_bytes([encoded[8], encoded[9], encoded[10], encoded[11]]);
    if version != HEADER_VERSION {
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
    Ok(count)
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

pub(super) fn encode_header(header: &Header) -> Result<[u8; HEADER_LEN], HeaderCheckpointError> {
    let mut encoded = [0_u8; HEADER_LEN];
    let mut cursor = &mut encoded[..];
    header
        .consensus_encode(&mut cursor)
        .map_err(|error| HeaderCheckpointError::Codec(error.to_string()))?;
    if !cursor.is_empty() {
        return Err(HeaderCheckpointError::Codec(
            "Bitcoin header did not encode to 80 bytes".to_owned(),
        ));
    }
    Ok(encoded)
}
