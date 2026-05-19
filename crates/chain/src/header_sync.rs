use bitcoin_rs_primitives::Network;

use crate::{
    ChainError,
    node::{BlockHeader, ChainWork, NodeId, NodeStatus},
    tree::{BlockTree, hash_from_header},
};

/// Accepts a contiguous batch of headers after proof-of-work validation.
pub fn accept_headers(
    tree: &mut BlockTree,
    headers: &[BlockHeader],
    network: Network,
) -> Result<Vec<NodeId>, ChainError> {
    let mut accepted = Vec::with_capacity(headers.len());
    for header in headers {
        validate_pow(header, network)?;
        let id = tree.insert_header(*header, NodeStatus::HeaderValid)?;
        accepted.push(id);
    }
    Ok(accepted)
}

fn validate_pow(header: &BlockHeader, network: Network) -> Result<(), ChainError> {
    let hash = hash_from_header(header);
    let target = ChainWork::from_be_bytes(header.target().to_be_bytes());
    if target == ChainWork::ZERO {
        return Err(ChainError::ZeroTarget { hash });
    }

    let max_target = network.max_target();
    if target > max_target {
        return Err(ChainError::TargetExceedsLimit {
            hash,
            target,
            max_target,
        });
    }

    if !header.target().is_met_by(header.block_hash()) {
        return Err(ChainError::InvalidPow { hash, target });
    }

    Ok(())
}
