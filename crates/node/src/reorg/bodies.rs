//! Hash-bound branch-body loading and bounded preflight materialization.

use super::LoadedBranchBody;
use super::LoadedBranchPrefix;
use super::ReorgError;
use crate::apply::Chainstate;
use alloc::vec::Vec;
use bitcoin_rs_chain::NodeId;
use bitcoin_rs_primitives::Block;
use bitcoin_rs_primitives::Hash256;

/// Loads every block named by a branch, in the order given.
pub(super) fn load_branch_bodies<F>(
    handles: &Chainstate,
    ids: &[NodeId],
    staged_body: &mut F,
) -> core::result::Result<Vec<LoadedBranchBody>, ReorgError>
where
    F: FnMut(Hash256) -> Option<(Block, bytes::Bytes)>,
{
    branch_nodes(handles, ids)?
        .into_iter()
        .map(|(hash, height)| load_branch_body(handles, hash, height, staged_body))
        .collect()
}

/// Loads the contiguous available prefix and names the first missing body.
pub(super) fn load_available_branch_prefix<F>(
    handles: &Chainstate,
    ids: &[NodeId],
    staged_body: &mut F,
) -> core::result::Result<LoadedBranchPrefix, ReorgError>
where
    F: FnMut(Hash256) -> Option<(Block, bytes::Bytes)>,
{
    let nodes = branch_nodes(handles, ids)?;
    let mut loaded = Vec::with_capacity(nodes.len());
    for (hash, height) in nodes {
        match load_branch_body(handles, hash, height, staged_body) {
            Ok(body) => loaded.push(body),
            Err(ReorgError::MissingBody { .. }) => {
                return Ok((loaded, Some((hash, height))));
            }
            Err(error) => return Err(error),
        }
    }
    Ok((loaded, None))
}

pub(super) fn branch_nodes(
    handles: &Chainstate,
    ids: &[NodeId],
) -> core::result::Result<Vec<(Hash256, u32)>, ReorgError> {
    let tree = handles.block_tree.read();
    ids.iter()
        .map(|id| {
            let node = tree.node(*id).map_err(ReorgError::Plan)?;
            Ok((node.hash, node.height))
        })
        .collect()
}

pub(super) fn load_branch_body<F>(
    handles: &Chainstate,
    hash: Hash256,
    height: u32,
    staged_body: &mut F,
) -> core::result::Result<LoadedBranchBody, ReorgError>
where
    F: FnMut(Hash256) -> Option<(Block, bytes::Bytes)>,
{
    if let Some((block, serialized)) = staged_body(hash) {
        return validate_branch_body(hash, height, block, serialized);
    }
    if let Some(store) = handles.block_body_store.as_ref()
        && let Some(body) =
            store
                .load_block_body(height, hash)
                .map_err(|source| ReorgError::BodyStore {
                    hash,
                    height,
                    source,
                })?
    {
        return decode_branch_body(hash, height, bytes::Bytes::from(body));
    }
    Err(ReorgError::MissingBody { hash, height })
}

pub(super) fn decode_branch_body(
    hash: Hash256,
    height: u32,
    serialized: bytes::Bytes,
) -> core::result::Result<LoadedBranchBody, ReorgError> {
    let block =
        Block::consensus_decode(serialized.as_ref()).map_err(|source| ReorgError::BodyDecode {
            hash,
            height,
            source,
        })?;
    validate_branch_body(hash, height, block, serialized)
}

pub(super) fn validate_branch_body(
    expected: Hash256,
    height: u32,
    block: Block,
    serialized: bytes::Bytes,
) -> core::result::Result<LoadedBranchBody, ReorgError> {
    let actual = block.block_hash().0;
    if actual != expected {
        return Err(ReorgError::BodyHashMismatch {
            expected,
            actual,
            height,
        });
    }
    if !crate::apply::prepare::bytes_are_block(serialized.as_ref(), &block) {
        return Err(ReorgError::BodyBytesMismatch {
            hash: expected,
            height,
        });
    }
    Ok(LoadedBranchBody {
        hash: expected,
        block,
        serialized,
        height,
    })
}
