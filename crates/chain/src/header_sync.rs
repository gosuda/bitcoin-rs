use bitcoin::{BlockHash, hashes::Hash as _, pow::CompactTarget};
use bitcoin_rs_primitives::Network;

use crate::{
    ChainError,
    node::{BlockHeader, ChainWork, NodeId, NodeStatus},
    tree::{BlockTree, hash_from_header, prev_hash_from_header},
};

/// Maximum number of seconds a header timestamp may lie ahead of the
/// current system time, per the Bitcoin consensus future-drift bound.
const MAX_FUTURE_TIME_SECONDS: u32 = 7200;

/// Number of blocks the median-time-past rule spans, per consensus.
const MEDIAN_TIME_SPAN: usize = 11;

/// Accepts a contiguous batch of headers after proof-of-work validation.
///
/// An already-present header is treated as an idempotent input: before any
/// validation or insertion the header hash is derived and looked up in the
/// tree, and when found the existing [`NodeId`] is appended to the returned
/// vector and the header is skipped. This preserves a 1:1 positional
/// correspondence between input headers and returned ids (including duplicate
/// Genesis on a non-empty tree) without relaxing validation or error
/// propagation for unknown headers, which continue through proof-of-work and
/// contextual nBits validation before insertion.
/// `now_secs` is the reference time for the future-drift bound, supplied by
/// the caller rather than read here.
///
/// `TimestampTooFarAhead` documents a network-adjusted limit, and a host clock
/// running an hour slow would reject a header ninety minutes ahead of network
/// time even though it is well inside the two-hour window — across every peer,
/// stalling the sync. This node tracks no peer time offset yet, so every caller
/// passes [`current_unix_seconds`] today; the parameter is what lets one
/// callsite change when it does, and what makes the bound testable without
/// moving the system clock.
pub fn accept_headers(
    tree: &mut BlockTree,
    headers: &[BlockHeader],
    network: Network,
    now_secs: u32,
) -> Result<Vec<NodeId>, ChainError> {
    let mut accepted = Vec::with_capacity(headers.len());
    for header in headers {
        let hash = hash_from_header(header);
        if let Some(existing_id) = tree.lookup(hash) {
            accepted.push(existing_id);
            continue;
        }
        validate_pow(header, hash, network)?;
        validate_empty_tree_root(tree, header, hash, network)?;
        validate_candidate_nbits(tree, header, network)?;
        validate_header_timestamp(tree, header, hash, now_secs)?;
        let id = tree.insert_header_with_hash(*header, hash, NodeStatus::HeaderValid)?;
        accepted.push(id);
    }
    Ok(accepted)
}

/// Reads the wall clock as whole seconds since the UNIX epoch.
///
/// A clock before the epoch yields 0, which only makes the future-drift bound
/// stricter and can never wrongly accept a header.
pub fn current_unix_seconds() -> u32 {
    unix_seconds_at(std::time::SystemTime::now())
}

fn unix_seconds_at(now: std::time::SystemTime) -> u32 {
    now.duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u32::try_from(elapsed.as_secs()).unwrap_or(u32::MAX)
        })
}

/// Enforces the two consensus timestamp rules against `now_secs`.
///
/// The median is taken over the candidate's parent and up to ten of its
/// ancestors. Batch parents are already in the tree because `accept_headers`
/// inserts each header before moving to the next, so a header whose parent
/// arrived in the same batch is validated against it.
///
/// `now_secs` is passed in rather than read here so the drift bound is a pure
/// function of its inputs and testable at its boundaries.
/// Checks a header's timestamp against median-time-past and the future bound.
///
/// Public because header sync is not the only path that admits a header: the
/// apply path inserts one directly when a block arrives whose header was never
/// seen, and without this it could make a block with an invalid timestamp the
/// applied consensus tip.
pub fn validate_header_timestamp(
    tree: &BlockTree,
    header: &BlockHeader,
    hash: bitcoin_rs_primitives::Hash256,
    now_secs: u32,
) -> Result<(), ChainError> {
    let Some(parent_id) = tree.lookup(prev_hash_from_header(header)) else {
        // No parent in the tree: the root path is validated by
        // `validate_empty_tree_root`, and a genuinely unknown parent is
        // rejected by insertion. Neither case has ancestors to take a median
        // over, so there is no timestamp rule to apply.
        return Ok(());
    };
    let median = tree
        .median_time_past_at(parent_id, MEDIAN_TIME_SPAN)
        .ok_or(ChainError::UnknownNode { id: parent_id })?;
    if header.time <= median {
        return Err(ChainError::TimestampTooEarly {
            hash,
            timestamp: header.time,
            median,
        });
    }
    let max_allowed = now_secs.saturating_add(MAX_FUTURE_TIME_SECONDS);
    if header.time > max_allowed {
        return Err(ChainError::TimestampTooFarAhead {
            hash,
            timestamp: header.time,
            max_allowed,
        });
    }
    Ok(())
}

fn validate_empty_tree_root(
    tree: &BlockTree,
    header: &BlockHeader,
    hash: bitcoin_rs_primitives::Hash256,
    network: Network,
) -> Result<(), ChainError> {
    if !tree.is_empty() || hash == network.genesis_block_hash() {
        return Ok(());
    }

    Err(ChainError::MissingParent {
        prev_hash: prev_hash_from_header(header),
    })
}

/// Returns the compact target the block after `parent_id` must carry.
///
/// Bitcoin Core's `GetNextWorkRequired`. Split out of [`validate_header_nbits`]
/// so block-template assembly can ask the same question a validator asks:
/// `getblocktemplate` has to tell a miner which `nBits` to mine against, and
/// deriving that anywhere else would be a second implementation of the
/// difficulty rules to drift from this one.
///
/// `candidate_time` is the timestamp the candidate block would carry. It only
/// matters on networks with the minimum-difficulty rule, where a block far
/// enough after its parent may reset to the proof-of-work limit.
///
/// # Errors
///
/// Returns [`ChainError`] if `parent_id` is unknown or its height is at the
/// maximum.
pub fn expected_next_bits(
    network: Network,
    tree: &BlockTree,
    parent_id: NodeId,
    candidate_time: u32,
) -> Result<CompactTarget, ChainError> {
    let parent = tree.node(parent_id)?;
    let height = parent
        .height
        .checked_add(1)
        .ok_or(ChainError::HeightOverflow { parent: parent_id })?;
    let retarget_interval = network.retarget_interval();
    let is_retarget = retarget_interval != 0 && height.is_multiple_of(retarget_interval);
    if is_retarget {
        expected_retarget_bits(network, tree, parent_id, height, retarget_interval)
    } else {
        expected_non_retarget_bits(network, tree, parent_id, candidate_time, retarget_interval)
    }
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
    let expected = expected_next_bits(network, tree, parent_id, header.time)?;
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

fn validate_pow(
    header: &BlockHeader,
    hash: bitcoin_rs_primitives::Hash256,
    network: Network,
) -> Result<(), ChainError> {
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

    if !header
        .target()
        .is_met_by(BlockHash::from_byte_array(hash.to_le_bytes()))
    {
        return Err(ChainError::InvalidPow { hash, target });
    }

    Ok(())
}

fn expected_non_retarget_bits(
    network: Network,
    tree: &BlockTree,
    parent_id: NodeId,
    candidate_time: u32,
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
    if candidate_time > min_difficulty_time {
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

#[cfg(test)]
mod timestamp_tests {
    use super::{MAX_FUTURE_TIME_SECONDS, validate_header_timestamp};
    use crate::{
        ChainError,
        node::{BlockHeader, NodeStatus},
        tree::{BlockTree, hash_from_header},
    };
    use bitcoin::{BlockHash, TxMerkleNode, block::Version, hashes::Hash as _, pow::CompactTarget};

    const REGTEST_BITS: u32 = 0x207f_ffff;

    fn mine(prev_blockhash: BlockHash, height: u32, time: u32) -> BlockHeader {
        let mut merkle = [0_u8; 32];
        merkle[..4].copy_from_slice(&height.to_le_bytes());
        let mut header = BlockHeader {
            version: Version::ONE,
            prev_blockhash,
            merkle_root: TxMerkleNode::from_byte_array(merkle),
            time,
            bits: CompactTarget::from_consensus(REGTEST_BITS),
            nonce: 0,
        };
        while !header.target().is_met_by(header.block_hash()) {
            header.nonce = header.nonce.wrapping_add(1);
        }
        header
    }

    /// The future bound must follow the supplied time, not the host clock.
    ///
    /// A host running slow used to reject headers that were well inside the
    /// two-hour window relative to network time, and it would do that against
    /// every peer at once.
    #[test]
    fn the_future_bound_follows_the_supplied_time_not_the_host_clock() {
        let (tree, tip) = chain_with_median_five();
        // Far past any plausible host clock, so a raw-clock bound rejects it.
        let network_now = 2_000_000_000_u32;
        let header = mine(tip.block_hash(), 11, network_now + MAX_FUTURE_TIME_SECONDS);
        let hash = hash_from_header(&header);

        assert!(
            super::current_unix_seconds() + MAX_FUTURE_TIME_SECONDS < header.time,
            "the host clock must reject this header, or the test proves nothing"
        );
        assert!(
            validate_header_timestamp(&tree, &header, hash, network_now).is_ok(),
            "a header exactly at the bound relative to the supplied time is valid"
        );

        // One second past it is not.
        let beyond = mine(
            tip.block_hash(),
            12,
            network_now + MAX_FUTURE_TIME_SECONDS + 1,
        );
        let beyond_hash = hash_from_header(&beyond);
        assert!(
            matches!(
                validate_header_timestamp(&tree, &beyond, beyond_hash, network_now),
                Err(ChainError::TimestampTooFarAhead { .. })
            ),
            "one second past the bound must still be rejected"
        );
    }

    /// Builds a chain of 11 headers with times 0..=10, so the median-time-past
    /// of the tip is exactly 5. Insertion bypasses `accept_headers` so the
    /// fixture itself is not subject to the rule under test.
    fn chain_with_median_five() -> (BlockTree, BlockHeader) {
        let mut tree = BlockTree::new();
        let mut prev = BlockHash::all_zeros();
        let mut tip = mine(prev, 0, 0);
        for height in 0_u32..11 {
            let header = mine(prev, height, height);
            prev = header.block_hash();
            let hash = hash_from_header(&header);
            let inserted = tree.insert_header_with_hash(header, hash, NodeStatus::HeaderValid);
            assert!(
                inserted.is_ok(),
                "fixture header failed to insert: {inserted:?}"
            );
            tip = header;
        }
        (tree, tip)
    }

    fn check(tree: &BlockTree, header: &BlockHeader, now: u32) -> Result<(), ChainError> {
        validate_header_timestamp(tree, header, hash_from_header(header), now)
    }

    #[test]
    fn timestamp_equal_to_median_is_rejected() {
        let (tree, tip) = chain_with_median_five();
        let candidate = mine(tip.block_hash(), 11, 5);
        assert!(matches!(
            check(&tree, &candidate, 1_000_000),
            Err(ChainError::TimestampTooEarly { median: 5, .. })
        ));
    }

    #[test]
    fn timestamp_one_past_median_is_accepted() {
        let (tree, tip) = chain_with_median_five();
        let candidate = mine(tip.block_hash(), 11, 6);
        assert!(check(&tree, &candidate, 1_000_000).is_ok());
    }

    #[test]
    fn timestamp_exactly_at_the_drift_bound_is_accepted() {
        let (tree, tip) = chain_with_median_five();
        let now = 1_000_000_u32;
        let candidate = mine(tip.block_hash(), 11, now + MAX_FUTURE_TIME_SECONDS);
        assert!(check(&tree, &candidate, now).is_ok());
    }

    #[test]
    fn timestamp_one_past_the_drift_bound_is_rejected() {
        let (tree, tip) = chain_with_median_five();
        let now = 1_000_000_u32;
        let candidate = mine(tip.block_hash(), 11, now + MAX_FUTURE_TIME_SECONDS + 1);
        assert!(matches!(
            check(&tree, &candidate, now),
            Err(ChainError::TimestampTooFarAhead { .. })
        ));
    }

    #[test]
    fn header_without_a_parent_in_the_tree_is_not_timestamp_checked() {
        let tree = BlockTree::new();
        let orphan = mine(BlockHash::all_zeros(), 0, 0);
        assert!(check(&tree, &orphan, 1_000_000).is_ok());
    }

    #[test]
    fn wall_clock_conversion_saturates_after_u32_seconds() {
        let after_u32 =
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(u64::from(u32::MAX) + 1);
        assert_eq!(super::unix_seconds_at(after_u32), u32::MAX);
    }

    #[test]
    fn wall_clock_conversion_maps_pre_epoch_to_zero() {
        let before_epoch = std::time::UNIX_EPOCH - std::time::Duration::from_secs(1);
        assert_eq!(super::unix_seconds_at(before_epoch), 0);
    }
}
