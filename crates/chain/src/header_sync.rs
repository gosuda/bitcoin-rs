use bitcoin::pow::CompactTarget;
use bitcoin_rs_primitives::Network;

use crate::{
    ChainError,
    node::{BlockHeader, ChainWork, NodeId, NodeStatus},
    tree::{BlockTree, hash_from_header, prev_hash_from_header},
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
        validate_candidate_nbits(tree, header, network)?;
        let id = tree.insert_header(*header, NodeStatus::HeaderValid)?;
        accepted.push(id);
    }
    Ok(accepted)
}

/// Validates a candidate header's compact target against the contextual network difficulty rules.
pub fn validate_header_nbits(
    tree: &BlockTree,
    parent_id: NodeId,
    header: &BlockHeader,
    network: Network,
) -> Result<(), ChainError> {
    let parent = tree.node(parent_id)?;
    let height = parent
        .height
        .checked_add(1)
        .ok_or(ChainError::HeightOverflow { parent: parent_id })?;
    let retarget_interval = network.retarget_interval();
    let is_retarget = retarget_interval != 0 && height.is_multiple_of(retarget_interval);
    let expected = if is_retarget {
        expected_retarget_bits(network, tree, parent_id, height, retarget_interval)?
    } else {
        expected_non_retarget_bits(network, tree, parent_id, header, retarget_interval)?
    };
    compare_expected_bits(header, height, expected)
}

fn validate_candidate_nbits(
    tree: &BlockTree,
    header: &BlockHeader,
    network: Network,
) -> Result<(), ChainError> {
    if tree.is_empty() {
        return Ok(());
    }

    let prev_hash = prev_hash_from_header(header);
    let parent_id = tree
        .lookup(prev_hash)
        .ok_or(ChainError::MissingParent { prev_hash })?;
    validate_header_nbits(tree, parent_id, header, network)
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

fn expected_non_retarget_bits(
    network: Network,
    tree: &BlockTree,
    parent_id: NodeId,
    header: &BlockHeader,
    retarget_interval: u32,
) -> Result<CompactTarget, ChainError> {
    let parent = tree.node(parent_id)?;
    if !network.allow_min_difficulty_blocks() {
        return Ok(parent.header.bits);
    }

    let min_difficulty_time = parent
        .header
        .time
        .saturating_add(network.target_spacing_seconds().saturating_mul(2));
    if header.time > min_difficulty_time {
        return Ok(pow_limit_bits(network));
    }

    let pow_limit = pow_limit_bits(network);
    let mut cursor_id = parent_id;
    loop {
        let cursor = tree.node(cursor_id)?;
        let at_period_boundary =
            retarget_interval != 0 && cursor.height.is_multiple_of(retarget_interval);
        if at_period_boundary || cursor.header.bits != pow_limit {
            return Ok(cursor.header.bits);
        }
        let Some(previous_id) = cursor.parent else {
            return Ok(cursor.header.bits);
        };
        cursor_id = previous_id;
    }
}

fn expected_retarget_bits(
    network: Network,
    tree: &BlockTree,
    parent_id: NodeId,
    height: u32,
    retarget_interval: u32,
) -> Result<CompactTarget, ChainError> {
    let prev_node = tree.node(parent_id)?;
    if network.pow_no_retargeting() {
        return Ok(prev_node.header.bits);
    }

    let Some(anchor_height) = height.checked_sub(retarget_interval) else {
        return Ok(prev_node.header.bits);
    };
    let Some(anchor_id) = tree.node_at_height_from(parent_id, anchor_height) else {
        return Ok(prev_node.header.bits);
    };
    let anchor_node = tree.node(anchor_id)?;
    let expected_timespan = network.target_timespan_seconds();
    if expected_timespan == 0 {
        return Ok(prev_node.header.bits);
    }

    let actual_timespan = prev_node
        .header
        .time
        .saturating_sub(anchor_node.header.time);
    let min_timespan = expected_timespan / 4;
    let max_timespan = expected_timespan.saturating_mul(4);
    let actual_clamped = actual_timespan.clamp(min_timespan, max_timespan);

    let base_header = if network.enforce_bip94() {
        &anchor_node.header
    } else {
        &prev_node.header
    };
    let prev_target = ChainWork::from_be_bytes(base_header.target().to_be_bytes());
    let actual_u256 = ChainWork::from(actual_clamped);
    let expected_u256 = ChainWork::from(expected_timespan);
    let max_target = network.max_target();
    let quotient = prev_target / expected_u256;
    let remainder = prev_target % expected_u256;
    let Some(scaled_quotient) = quotient.checked_mul(actual_u256) else {
        return Ok(target_to_bits(max_target));
    };
    let scaled_remainder = remainder.saturating_mul(actual_u256) / expected_u256;
    let new_target = scaled_quotient
        .saturating_add(scaled_remainder)
        .min(max_target);
    Ok(target_to_bits(new_target))
}

fn compare_expected_bits(
    header: &BlockHeader,
    height: u32,
    expected: CompactTarget,
) -> Result<(), ChainError> {
    let actual = header.bits.to_consensus();
    let expected = expected.to_consensus();
    if actual != expected {
        return Err(ChainError::NbitsMismatch {
            actual,
            expected,
            height,
        });
    }
    Ok(())
}

fn pow_limit_bits(network: Network) -> CompactTarget {
    target_to_bits(network.max_target())
}

fn target_to_bits(target: ChainWork) -> CompactTarget {
    bitcoin::Target::from_be_bytes(target.to_be_bytes::<32>()).to_compact_lossy()
}
