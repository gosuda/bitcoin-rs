use bitcoin_rs_consensus::{MAX_TIMEWARP, MEDIAN_TIME_PAST_WINDOW};
use bitcoin_rs_primitives::{CompactTarget, Hash256, Network};

pub use pow::{compact_is_met_by, compact_within_pow_limit};
use pow::{compact_to_target, target_to_compact};

use crate::{
    ChainError,
    node::{BlockHeader, ChainWork, NodeId, NodeStatus},
    tree::{BlockTree, hash_from_header, prev_hash_from_header},
};

/// Maximum number of seconds a header timestamp may lie ahead of the
/// current system time, per the Bitcoin consensus future-drift bound.
const MAX_FUTURE_TIME_SECONDS: u32 = 7200;

/// Accepts a contiguous batch of headers after proof-of-work validation.
///
/// An already-present header is treated as an idempotent input: before any
/// validation or insertion the header hash is derived and looked up in the
/// tree, and when found the existing [`NodeId`] is appended to the returned
/// vector and the header is skipped. This preserves a 1:1 positional
/// correspondence between input headers and returned ids (including duplicate
/// Genesis on a non-empty tree) without relaxing validation or error
/// propagation for unknown headers, which continue through proof-of-work,
/// parent resolution, the invalid-parent refusal, and the shared contextual
/// header validation ([`validate_contextual_header`]) before insertion.
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
        let prev_hash = prev_hash_from_header(header);
        let parent_id = match tree.lookup(prev_hash) {
            Some(parent_id) => parent_id,
            None if tree.is_empty() => {
                // The validated genesis root: the tree is empty, so the
                // header has no parent and no contextual rule applies.
                let id = tree.insert_header_with_hash(*header, hash, NodeStatus::HeaderValid)?;
                accepted.push(id);
                continue;
            }
            None => return Err(ChainError::MissingParent { prev_hash }),
        };
        if tree.node(parent_id)?.status == NodeStatus::Invalid {
            // Core refuses a child of a failed block with `bad-prevblk`
            // before any contextual rule runs
            // (`src/validation.cpp:4228-4231`), so the header never grows
            // the invalid subtree.
            return Err(ChainError::InvalidParent { parent: parent_id });
        }
        validate_contextual_header(tree, parent_id, header, network, now_secs)?;
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

/// Validates the contextual rules for a header extending `parent_id`.
///
/// PRE: `parent_id` identifies the header named by `header.prev_blockhash`;
/// `now_secs` is UNIX time supplied by the caller, which keeps the
/// future-drift bound a pure function of the inputs and testable at its
/// boundaries.
///
/// POST: returns `Ok(())` only when Core's contextual nBits,
/// median-time-past, BIP94 timewarp, future-time, and version-floor rules
/// pass, checked in Core's order (`src/validation.cpp:4092-4126`). The median
/// is taken over the candidate's parent and up to ten of its ancestors; batch
/// parents are already in the tree because `accept_headers` inserts each
/// header before moving to the next, so a header whose parent arrived in the
/// same batch is validated against it.
///
/// INVARIANT: header admission and direct block connection use this
/// operation; no caller implements a second version, timewarp, or nBits
/// predicate.
pub fn validate_contextual_header(
    tree: &BlockTree,
    parent_id: NodeId,
    header: &BlockHeader,
    network: Network,
    now_secs: u32,
) -> Result<(), ChainError> {
    let parent = tree.node(parent_id)?;
    let height = parent
        .height
        .checked_add(1)
        .ok_or(ChainError::HeightOverflow { parent: parent_id })?;

    // Contextual difficulty: the compact target the parent requires.
    validate_header_nbits(tree, parent_id, header, network)?;

    // Median-time-past floor: the candidate must beat the median of its
    // eleven most recent ancestors.
    let median = tree
        .median_time_past_at(parent_id, MEDIAN_TIME_PAST_WINDOW)
        .ok_or(ChainError::UnknownNode { id: parent_id })?;
    if header.time <= median {
        return Err(ChainError::TimestampTooEarly {
            hash: hash_from_header(header),
            timestamp: header.time,
            median,
        });
    }

    // BIP94 timewarp floor at a difficulty-adjustment boundary: the
    // candidate may not fall more than `MAX_TIMEWARP` below its parent
    // (`src/validation.cpp:4100-4110`).
    if let Some(minimum) = bip94_timewarp_floor(network, height, parent.header.time) {
        if header.time < minimum {
            return Err(ChainError::TimewarpAttack {
                height,
                timestamp: header.time,
                minimum,
            });
        }
    }

    // Future-drift ceiling.
    let max_allowed = now_secs.saturating_add(MAX_FUTURE_TIME_SECONDS);
    if header.time > max_allowed {
        return Err(ChainError::TimestampTooFarAhead {
            hash: hash_from_header(header),
            timestamp: header.time,
            max_allowed,
        });
    }

    // Version floors for the buried deployments, in Core's order
    // (`src/validation.cpp:4112-4126`).
    for (required, active) in [
        (2, network.is_bip34_active(height)),
        (3, network.is_bip66_active(height)),
        (4, network.is_bip65_active(height)),
    ] {
        if active && header.version < required {
            return Err(ChainError::BadVersion {
                version: header.version,
                required,
                height,
            });
        }
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

/// Computes the compact target a block extending `parent_id` must carry.
///
/// This is the one next-work source: [`validate_header_nbits`] enforces
/// exactly this value, and candidate or template building reads it instead of
/// recomputing the difficulty arithmetic a second time. `candidate_time` is
/// the timestamp the candidate would carry; testnet-style minimum-difficulty
/// recovery keys off it.
///
/// # Errors
///
/// Returns [`ChainError::UnknownNode`] when `parent_id` is not in the tree and
/// [`ChainError::HeightOverflow`] when the parent is at the last height.
pub fn next_work_required(
    tree: &BlockTree,
    parent_id: NodeId,
    candidate_time: u32,
    network: Network,
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
///
/// Delegates to [`next_work_required`], so a header built from that source and
/// a header accepted here are held to the same computation.
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
    let expected = next_work_required(tree, parent_id, header.time, network)?;
    compare_expected_bits(header, height, expected)
}

/// Validates a header's proof-of-work target and hash.
///
/// # Errors
///
/// Returns [`ChainError::ZeroTarget`], [`ChainError::TargetExceedsLimit`], or
/// [`ChainError::InvalidPow`] when the header's target/hash is invalid.
pub fn validate_pow(
    header: &BlockHeader,
    hash: Hash256,
    network: Network,
) -> Result<(), ChainError> {
    let target = compact_to_target(header.bits);
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

    if !compact_is_met_by(header.bits, hash) {
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

    let base_target = if network.enforce_bip94() {
        anchor_node.header.bits
    } else {
        prev_node.header.bits
    };
    let prev_target = compact_to_target(base_target);
    let actual_u256 = ChainWork::from(actual_clamped);
    let expected_u256 = ChainWork::from(expected_timespan);
    let max_target = network.max_target();
    let quotient = prev_target / expected_u256;
    let remainder = prev_target % expected_u256;
    let Some(scaled_quotient) = quotient.checked_mul(actual_u256) else {
        return Ok(pow_limit_bits(network));
    };
    let scaled_remainder = remainder.saturating_mul(actual_u256) / expected_u256;
    let new_target = scaled_quotient
        .saturating_add(scaled_remainder)
        .min(max_target);
    Ok(target_to_compact(new_target))
}

fn compare_expected_bits(
    header: &BlockHeader,
    height: u32,
    expected: CompactTarget,
) -> Result<(), ChainError> {
    let actual = header.bits;
    if actual != expected {
        return Err(ChainError::NbitsMismatch {
            actual: actual.to_consensus(),
            expected: expected.to_consensus(),
            height,
        });
    }
    Ok(())
}

fn pow_limit_bits(network: Network) -> CompactTarget {
    target_to_compact(network.max_target())
}

/// The proof of work one header claims: `~target / (target + 1) + 1`.
///
/// This is Bitcoin Core's `GetBlockProof` (`bitcoin-core/src/pow.cpp`), and
/// it is the same quantity the block tree accumulates into a node's
/// chainwork, so a header chain's claimed work and its admitted work are
/// computed by one function.
#[must_use]
pub fn block_work(header: &BlockHeader) -> ChainWork {
    pow::work_from_header(header)
}

/// Whether a difficulty transition to `new_bits` at `height` is permitted.
///
/// PRE: `height` is the height of the header carrying `new_bits`, and
///   `old_bits` is the bits field of its parent.
/// POST: return true when the network allows this transition without
///   consulting any stored chain: test networks permit any transition, a
///   retarget height permits a target within the fourfold adjustment bound
///   after the compact round-trip Core applies, and every other height
///   requires the parent's bits unchanged.
/// INVARIANT: this is Core's tree-free `PermittedDifficultyTransition`
///   (`bitcoin-core/src/pow.cpp:89-136`), the check the header presync
///   state runs while it holds no tree; the contextual check in
///   [`validate_header_nbits`] remains the full-consensus rule.
#[must_use]
pub fn permitted_difficulty_transition(
    network: Network,
    height: u32,
    old_bits: CompactTarget,
    new_bits: CompactTarget,
) -> bool {
    if network.allow_min_difficulty_blocks() {
        return true;
    }
    let interval = network.retarget_interval();
    if interval == 0 || !height.is_multiple_of(interval) {
        return old_bits == new_bits;
    }
    // A retarget may move the target by at most the clamped timespan ratio:
    // four times up, four times down, never past the proof-of-work limit,
    // and the bound is compared after the compact round-trip, exactly as
    // Core rounds it.
    let pow_limit = network.max_target();
    let old_target = pow::compact_to_target(old_bits);
    let observed = pow::compact_to_target(new_bits);
    let quarter = ChainWork::from(4_u32);
    let largest = old_target
        .checked_mul(quarter)
        .unwrap_or(pow_limit)
        .min(pow_limit);
    if pow::compact_to_target(pow::target_to_compact(largest)) < observed {
        return false;
    }
    let smallest = (old_target / quarter).min(pow_limit);
    pow::compact_to_target(pow::target_to_compact(smallest)) <= observed
}

/// Whether `height` lands on a difficulty-adjustment boundary of `network`.
///
/// That boundary is the point where Core's `GetMinimumTime` applies the
/// `parent.time - MAX_TIMEWARP` timewarp floor
/// (`src/node/miner.cpp:42-49`); the floor is advisory on every network
/// and a consensus rule only where [`Network::enforce_bip94`] holds
/// (`src/validation.cpp:4100-4110`).
#[must_use]
pub fn at_retarget_boundary(network: Network, height: u32) -> bool {
    let retarget_interval = network.retarget_interval();
    retarget_interval != 0 && height.is_multiple_of(retarget_interval)
}

/// The consensus timewarp floor for a candidate at `height` extending a
/// parent stamped `parent_time`.
///
/// `Some(parent_time - MAX_TIMEWARP)` at a difficulty-adjustment boundary
/// on a BIP94 network, `None` elsewhere.
#[must_use]
pub fn bip94_timewarp_floor(network: Network, height: u32, parent_time: u32) -> Option<u32> {
    (network.enforce_bip94() && at_retarget_boundary(network, height))
        .then(|| parent_time.saturating_sub(MAX_TIMEWARP))
}

/// Compact proof-of-work target decode/encode and block-work helpers.
///
/// These mirror Bitcoin Core's `arith_uint256::SetCompact`/`GetCompact`
/// exactly, including sign-bit normalization and overflow classification.
pub(crate) mod pow {
    use bitcoin_rs_primitives::{CompactTarget, Hash256, Network};

    use crate::node::{BlockHeader, ChainWork};

    struct DecodedCompact {
        target: ChainWork,
        negative: bool,
    }

    fn decode_compact(bits: u32) -> DecodedCompact {
        let exponent = usize::from(u8::try_from(bits >> 24).unwrap_or(0));
        let mut mantissa = bits & 0x007f_ffff;
        let target = if exponent <= 3 {
            mantissa >>= 8 * (3 - exponent);
            ChainWork::from(mantissa)
        } else {
            let shift = 8 * (exponent - 3);
            if shift < 256 {
                ChainWork::from(mantissa) << shift
            } else {
                ChainWork::ZERO
            }
        };
        let negative = mantissa != 0 && bits & 0x0080_0000 != 0;

        DecodedCompact { target, negative }
    }

    /// Decodes a compact target, returning zero for negative encodings.
    #[must_use]
    pub(crate) fn compact_to_target(bits: CompactTarget) -> ChainWork {
        let decoded = decode_compact(bits.to_consensus());
        if decoded.negative {
            ChainWork::ZERO
        } else {
            decoded.target
        }
    }

    /// Returns `true` when a valid nonzero compact target is met by `hash`.
    /// The consensus hash bytes are interpreted as a little-endian integer.
    #[must_use]
    pub fn compact_is_met_by(bits: CompactTarget, hash: Hash256) -> bool {
        let target = compact_to_target(bits);
        target != ChainWork::ZERO && ChainWork::from_le_bytes(hash.to_le_bytes()) <= target
    }

    /// Returns `true` when `bits` decodes to a nonzero target at or below
    /// `network`'s proof-of-work limit.
    ///
    /// Core's `CheckProofOfWork` bounds (`pow.cpp:CheckProofOfWork`), minus
    /// the hash comparison [`compact_is_met_by`] performs.
    /// Difficulty-transition rules can accept any bits on
    /// `allow_min_difficulty_blocks` networks, so the network cap has to be
    /// checked on its own there.
    #[must_use]
    pub fn compact_within_pow_limit(network: Network, bits: CompactTarget) -> bool {
        let target = compact_to_target(bits);
        target != ChainWork::ZERO && target <= network.max_target()
    }

    /// The block-header proof of work: `~target / (target + 1) + 1`.
    #[must_use]
    pub(crate) fn work_from_header(header: &BlockHeader) -> ChainWork {
        let target = compact_to_target(header.bits);
        if target == ChainWork::ZERO {
            return ChainWork::ZERO;
        }
        (!target / (target + ChainWork::from(1u32))) + ChainWork::from(1u32)
    }

    /// Encodes a non-negative 256-bit target into compact consensus form.
    #[must_use]
    pub(crate) fn target_to_compact(target: ChainWork) -> CompactTarget {
        CompactTarget::from_consensus(get_compact(target, false))
    }

    fn get_compact(target: ChainWork, negative: bool) -> u32 {
        if target == ChainWork::ZERO {
            return 0;
        }

        let mut size = target.bit_len().div_ceil(8);
        let mut compact = if size <= 3 {
            u32::try_from(target.as_limbs()[0] << (8 * (3 - size))).unwrap_or(0)
        } else {
            u32::try_from((target >> (8 * (size - 3))).as_limbs()[0]).unwrap_or(0)
        };

        if compact & 0x0080_0000 != 0 {
            compact >>= 8;
            size += 1;
        }
        debug_assert_eq!(compact & !0x007f_ffff, 0);
        debug_assert!(size < 256);

        compact
            | (u32::try_from(size).unwrap_or(0) << 24)
            | if negative && compact & 0x007f_ffff != 0 {
                0x0080_0000
            } else {
                0
            }
    }
}

#[cfg(test)]
mod timestamp_tests {
    use super::{MAX_FUTURE_TIME_SECONDS, compact_is_met_by, validate_contextual_header};
    use crate::{
        ChainError,
        node::{BlockHeader, NodeStatus},
        tree::{BlockTree, hash_from_header},
    };
    use bitcoin_rs_primitives::{BlockHash, CompactTarget, Hash256, Network};

    const REGTEST_BITS: u32 = 0x207f_ffff;

    fn mine(prev_blockhash: BlockHash, height: u32, time: u32) -> BlockHeader {
        let mut merkle = [0_u8; 32];
        merkle[..4].copy_from_slice(&height.to_le_bytes());
        let mut header = BlockHeader {
            version: 1,
            prev_blockhash,
            merkle_root: Hash256::from_le_bytes(&merkle),
            time,
            bits: CompactTarget::from_consensus(REGTEST_BITS),
            nonce: 0,
        };
        while !compact_is_met_by(header.bits, header.compute_hash().0) {
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
        let header = mine(
            tip.compute_hash(),
            11,
            network_now + MAX_FUTURE_TIME_SECONDS,
        );

        assert!(
            super::current_unix_seconds() + MAX_FUTURE_TIME_SECONDS < header.time,
            "the host clock must reject this header, or the test proves nothing"
        );
        assert!(
            check(&tree, &header, network_now).is_ok(),
            "a header exactly at the bound relative to the supplied time is valid"
        );

        // One second past it is not.
        let beyond = mine(
            tip.compute_hash(),
            12,
            network_now + MAX_FUTURE_TIME_SECONDS + 1,
        );

        assert!(
            matches!(
                check(&tree, &beyond, network_now),
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
        let mut prev = BlockHash::default();
        let mut tip = mine(prev, 0, 0);
        for height in 0_u32..11 {
            let header = mine(prev, height, height);
            prev = header.compute_hash();
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
        let parent_id = tree
            .lookup(header.prev_blockhash.0)
            .ok_or(ChainError::MissingParent {
                prev_hash: header.prev_blockhash.0,
            })?;
        validate_contextual_header(tree, parent_id, header, Network::Regtest, now)
    }

    #[test]
    fn timestamp_equal_to_median_is_rejected() {
        let (tree, tip) = chain_with_median_five();
        let candidate = mine(tip.compute_hash(), 11, 5);
        assert!(matches!(
            check(&tree, &candidate, 1_000_000),
            Err(ChainError::TimestampTooEarly { median: 5, .. })
        ));
    }

    #[test]
    fn timestamp_one_past_median_is_accepted() {
        let (tree, tip) = chain_with_median_five();
        let candidate = mine(tip.compute_hash(), 11, 6);
        assert!(check(&tree, &candidate, 1_000_000).is_ok());
    }

    #[test]
    fn timestamp_exactly_at_the_drift_bound_is_accepted() {
        let (tree, tip) = chain_with_median_five();
        let now = 1_000_000_u32;
        let candidate = mine(tip.compute_hash(), 11, now + MAX_FUTURE_TIME_SECONDS);
        assert!(check(&tree, &candidate, now).is_ok());
    }

    #[test]
    fn timestamp_one_past_the_drift_bound_is_rejected() {
        let (tree, tip) = chain_with_median_five();
        let now = 1_000_000_u32;
        let candidate = mine(tip.compute_hash(), 11, now + MAX_FUTURE_TIME_SECONDS + 1);
        assert!(matches!(
            check(&tree, &candidate, now),
            Err(ChainError::TimestampTooFarAhead { .. })
        ));
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

#[cfg(test)]
mod contextual_header_tests {
    use super::{
        MAX_FUTURE_TIME_SECONDS, accept_headers, compact_is_met_by, next_work_required,
        validate_contextual_header,
    };
    use crate::{
        ChainError,
        node::{BlockHeader, NodeStatus},
        tree::{BlockTree, hash_from_header},
    };
    use bitcoin_rs_primitives::{BlockHash, CompactTarget, Hash256, Network};

    const REGTEST_BITS: u32 = 0x207f_ffff;
    const TESTNET4_POW_LIMIT: u32 = 0x1d00_ffff;

    fn mine_regtest(
        prev_blockhash: BlockHash,
        height: u32,
        time: u32,
        version: i32,
    ) -> BlockHeader {
        let mut merkle = [0_u8; 32];
        merkle[..4].copy_from_slice(&height.to_le_bytes());
        let mut header = BlockHeader {
            version,
            prev_blockhash,
            merkle_root: Hash256::from_le_bytes(&merkle),
            time,
            bits: CompactTarget::from_consensus(REGTEST_BITS),
            nonce: 0,
        };
        while !compact_is_met_by(header.bits, header.compute_hash().0) {
            header.nonce = header.nonce.wrapping_add(1);
        }
        header
    }

    fn extend_regtest(
        tree: &mut BlockTree,
        prev: &mut BlockHash,
        height: u32,
        version: i32,
        base_time: u32,
    ) {
        let network = Network::Regtest;
        let time = base_time + height * 600;
        let header = mine_regtest(*prev, height, time, version);
        accept_headers(tree, &[header], network, time)
            .unwrap_or_else(|e| panic!("fixture header at height {height} rejected: {e:?}"));
        *prev = header.compute_hash();
    }

    #[test]
    fn rejects_outdated_versions_after_activation() -> Result<(), Box<dyn std::error::Error>> {
        let network = Network::Regtest;
        let genesis = network.genesis_block();
        let base_time = genesis.header.time;
        let mut prev = genesis.block_hash();
        let mut tree = BlockTree::new();
        accept_headers(&mut tree, &[genesis.header], network, base_time)?;

        // Heights 1..=499 sit below every regtest activation height.
        for height in 1..=499_u32 {
            extend_regtest(&mut tree, &mut prev, height, 4, base_time);
        }

        // BIP34: version 1 is rejected once the candidate reaches height 500.
        let now = base_time + 500 * 600;
        let rejected = mine_regtest(prev, 500, now, 1);
        assert_eq!(
            accept_headers(&mut tree, &[rejected], network, now),
            Err(ChainError::BadVersion {
                version: 1,
                required: 2,
                height: 500
            })
        );
        assert_eq!(
            tree.lookup(hash_from_header(&rejected)),
            None,
            "a rejected header must not enter the tree"
        );
        let accepted = mine_regtest(prev, 500, now, 2);
        accept_headers(&mut tree, &[accepted], network, now)
            .map_err(|error| format!("version 2 is legal at height 500: {error:?}"))?;
        prev = accepted.compute_hash();

        // BIP66: version 2 is rejected at height 1251.
        for height in 501..=1250_u32 {
            extend_regtest(&mut tree, &mut prev, height, 2, base_time);
        }
        let now = base_time + 1251 * 600;
        let rejected = mine_regtest(prev, 1251, now, 2);
        assert_eq!(
            accept_headers(&mut tree, &[rejected], network, now),
            Err(ChainError::BadVersion {
                version: 2,
                required: 3,
                height: 1251
            })
        );
        let accepted = mine_regtest(prev, 1251, now, 3);
        accept_headers(&mut tree, &[accepted], network, now)
            .map_err(|error| format!("version 3 is legal at height 1251: {error:?}"))?;
        prev = accepted.compute_hash();

        // BIP65: version 3 is rejected at height 1351.
        for height in 1252..=1350_u32 {
            extend_regtest(&mut tree, &mut prev, height, 3, base_time);
        }
        let now = base_time + 1351 * 600;
        let rejected = mine_regtest(prev, 1351, now, 3);
        assert_eq!(
            accept_headers(&mut tree, &[rejected], network, now),
            Err(ChainError::BadVersion {
                version: 3,
                required: 4,
                height: 1351
            })
        );
        let accepted = mine_regtest(prev, 1351, now, 4);
        accept_headers(&mut tree, &[accepted], network, now)
            .map_err(|error| format!("version 4 is legal at height 1351: {error:?}"))?;
        Ok(())
    }

    #[test]
    fn rejects_testnet4_bip94_timewarp_candidate() -> Result<(), Box<dyn std::error::Error>> {
        let network = Network::Testnet4;
        let mut tree = BlockTree::new();
        let mut prev = BlockHash::default();
        let mut tip_time = 0;
        for height in 0..2016_u32 {
            let header = BlockHeader {
                version: 4,
                prev_blockhash: prev,
                merkle_root: Hash256::default(),
                time: 1_600_000_000 + height * 600,
                bits: CompactTarget::from_consensus(TESTNET4_POW_LIMIT),
                nonce: height,
            };
            prev = header.compute_hash();
            tree.insert_header_with_hash(
                header,
                hash_from_header(&header),
                NodeStatus::HeaderValid,
            )?;
            tip_time = header.time;
        }
        let parent_id = tree.lookup(prev.0).ok_or("fixture tip present")?;
        // Height 2016 is a difficulty-adjustment boundary on Testnet4, so the
        // candidate must carry the retargeted bits.
        let bits = next_work_required(&tree, parent_id, tip_time, network)?;
        let now = tip_time + MAX_FUTURE_TIME_SECONDS;
        let candidate = |time: u32| BlockHeader {
            version: 4,
            prev_blockhash: prev,
            merkle_root: Hash256::default(),
            time,
            bits,
            nonce: 0,
        };

        // More than `MAX_TIMEWARP` below the parent: rejected.
        assert_eq!(
            validate_contextual_header(&tree, parent_id, &candidate(tip_time - 601), network, now),
            Err(ChainError::TimewarpAttack {
                height: 2016,
                timestamp: tip_time - 601,
                minimum: tip_time - 600,
            })
        );
        // Exactly `MAX_TIMEWARP` below the parent: still valid.
        validate_contextual_header(&tree, parent_id, &candidate(tip_time - 600), network, now)
            .map_err(|error| {
                format!("a timestamp exactly at the timewarp floor is legal: {error:?}")
            })?;
        Ok(())
    }

    #[test]
    fn child_of_invalid_parent_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let network = Network::Regtest;
        let genesis = network.genesis_block();
        let base_time = genesis.header.time;
        let mut prev = genesis.block_hash();
        let mut tree = BlockTree::new();
        accept_headers(&mut tree, &[genesis.header], network, base_time)?;
        extend_regtest(&mut tree, &mut prev, 1, 4, base_time);
        let block_one = tree.lookup(prev.0).ok_or("block one is in the tree")?;
        tree.invalidate_subtree(block_one)?;

        let now = base_time + 2 * 600;
        let child = mine_regtest(prev, 2, now, 4);
        assert_eq!(
            accept_headers(&mut tree, &[child], network, now),
            Err(ChainError::InvalidParent { parent: block_one }),
            "a child of an invalidated header is refused, not accepted as invalid"
        );
        assert_eq!(
            tree.lookup(hash_from_header(&child)),
            None,
            "the refused child must not extend the invalid subtree"
        );
        Ok(())
    }
}
