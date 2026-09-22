use bitcoin_rs_consensus::MEDIAN_TIME_PAST_WINDOW;
use bitcoin_rs_primitives::{CompactTarget, Hash256, Network};

pub use pow::compact_is_met_by;
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
/// An already-present header not marked invalid is an idempotent input: the
/// header hash is derived and looked up before validation or insertion.
/// Known-invalid entries return [`ChainError::KnownInvalidHeader`]; otherwise
/// the existing [`NodeId`] is appended and the header is skipped, preserving a 1:1
/// correspondence between input headers and returned ids (including duplicate
/// Genesis on a non-empty tree) without relaxing validation or error
/// propagation for unknown headers, which continue through proof-of-work and
/// contextual nBits validation before insertion.
/// A header whose parent exists but is already marked invalid is rejected
/// with [`ChainError::InvalidParent`]: descendants of an invalidated subtree
/// must never enter the tree through this admission path.
///
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
            if matches!(tree.node(existing_id)?.status, NodeStatus::Invalid) {
                return Err(ChainError::KnownInvalidHeader { hash });
            }
            accepted.push(existing_id);
            continue;
        }
        validate_pow(header, hash, network)?;
        validate_empty_tree_root(tree, header, hash, network)?;
        validate_parent_status(tree, header)?;
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
        .median_time_past_at(parent_id, MEDIAN_TIME_PAST_WINDOW)
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
    if let Some(fork_bits) = ecash_fork_reset_bits(network, height) {
        return Ok(fork_bits);
    }
    let retarget_interval = network.retarget_interval();
    let is_retarget = retarget_interval != 0 && height.is_multiple_of(retarget_interval);
    if is_retarget {
        expected_retarget_bits(network, tree, parent_id, height, retarget_interval)
    } else {
        expected_non_retarget_bits(network, tree, parent_id, candidate_time, retarget_interval)
    }
}

/// The ecash fork's one-time proof-of-work reset, when this candidate is the fork block.
///
/// Core's `GetNextWorkRequired` short-circuits the block at `EcashHeight`:
/// its target is pinned to `EcashForkBits` instead of being derived from the
/// retarget arithmetic. The height is a retarget boundary, so this is the one
/// candidate height where the computed target and the enforced target would
/// otherwise diverge. Networks without an ecash fork never reset.
#[must_use]
fn ecash_fork_reset_bits(network: Network, height: u32) -> Option<CompactTarget> {
    let fork_height = network.ecash_fork_height()?;
    if u64::from(height) == fork_height {
        return Some(CompactTarget::from_consensus(network.ecash_fork_bits()?));
    }
    None
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

/// Rejects a candidate whose parent exists and is already marked invalid.
///
/// Insertion would silently inherit `NodeStatus::Invalid` and still report
/// the header as accepted; the admission path refuses it up front instead.
/// Unknown parents are left to `validate_candidate_nbits` and insertion.
fn validate_parent_status(tree: &BlockTree, header: &BlockHeader) -> Result<(), ChainError> {
    let prev_hash = prev_hash_from_header(header);
    let Some(parent_id) = tree.lookup(prev_hash) else {
        return Ok(());
    };
    if matches!(tree.node(parent_id)?.status, NodeStatus::Invalid) {
        return Err(ChainError::InvalidParent { prev_hash });
    }
    Ok(())
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

/// Compact proof-of-work target decode/encode and block-work helpers.
///
/// These mirror Bitcoin Core's `arith_uint256::SetCompact`/`GetCompact`
/// exactly, including sign-bit normalization and overflow classification.
pub(crate) mod pow {
    use bitcoin_rs_primitives::{CompactTarget, Hash256};

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
    use super::{MAX_FUTURE_TIME_SECONDS, compact_is_met_by, validate_header_timestamp};
    use crate::{
        ChainError,
        node::{BlockHeader, NodeStatus},
        tree::{BlockTree, hash_from_header},
    };
    use bitcoin_rs_primitives::{BlockHash, CompactTarget, Hash256};

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
            tip.compute_hash(),
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
        validate_header_timestamp(tree, header, hash_from_header(header), now)
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
    fn header_without_a_parent_in_the_tree_is_not_timestamp_checked() {
        let tree = BlockTree::new();
        let orphan = mine(BlockHash::default(), 0, 0);
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

#[cfg(test)]
mod ecash_fork_tests {
    use super::{ecash_fork_reset_bits, next_work_required, validate_header_nbits};
    use crate::{
        ChainError,
        node::{BlockHeader, NodeStatus},
        tree::BlockTree,
    };
    use bitcoin_rs_primitives::{BlockHash, CompactTarget, Hash256, Network};

    /// The ecash fork height: mainnet's shared history ends here and the next
    /// block pins its target to `FORK_BITS`.
    const FORK_HEIGHT: u32 = 967_680;
    const FORK_BITS: u32 = 0x1904_4b7e;
    const CHAIN_BITS: u32 = 0x2000_ffff;

    fn header_at(prev_blockhash: BlockHash, height: u32, bits: u32) -> BlockHeader {
        let mut merkle = [0_u8; 32];
        merkle[..4].copy_from_slice(&height.to_le_bytes());
        BlockHeader {
            version: 1,
            prev_blockhash,
            merkle_root: Hash256::from_le_bytes(&merkle),
            time: 1_700_000_000_u32
                .checked_add(height)
                .unwrap_or_else(|| panic!("fixture heights stay far from the u32 bound")),
            bits: CompactTarget::from_consensus(bits),
            nonce: 0,
        }
    }

    /// Index twin of [`FORK_HEIGHT`] for `Vec` indexing.
    fn idx(height: u32) -> usize {
        usize::try_from(height).unwrap_or_else(|_| panic!("fixture heights fit usize"))
    }

    /// Builds a header-only chain `0..=FORK_HEIGHT` (so candidates at
    /// `FORK_HEIGHT` and `FORK_HEIGHT + 1` have parents). Every shared-history
    /// block carries `CHAIN_BITS`; the block AT the fork height carries the
    /// fork bits, as every validated chain must. Insertion bypasses
    /// `accept_headers` so the fixture is not subject to the proof-of-work and
    /// `nBits` rules under test. Six hundred second spacing makes the
    /// 2016-block retarget timespan exactly the expected 14 days, so the
    /// ordinary retarget path recomputes the previous target unchanged.
    fn shared_history_chain() -> (BlockTree, Vec<crate::NodeId>) {
        let mut tree = BlockTree::new();
        let mut prev = BlockHash::default();
        let mut ids = Vec::with_capacity(idx(FORK_HEIGHT) + 1);
        for height in 0..=FORK_HEIGHT {
            let bits = if height == FORK_HEIGHT {
                FORK_BITS
            } else {
                CHAIN_BITS
            };
            let header = header_at(prev, height, bits);
            prev = header.compute_hash();
            let id = tree
                .insert_header(header, NodeStatus::HeaderValid)
                .unwrap_or_else(|error| panic!("fixture chain inserts: {error}"));
            ids.push(id);
        }
        (tree, ids)
    }

    #[test]
    fn fork_reset_bits_activate_exactly_at_the_fork_height() {
        assert_eq!(
            ecash_fork_reset_bits(Network::Betanet, FORK_HEIGHT - 1),
            None,
            "the block before the fork keeps ordinary rules"
        );
        assert_eq!(
            ecash_fork_reset_bits(Network::Betanet, FORK_HEIGHT),
            Some(CompactTarget::from_consensus(FORK_BITS)),
        );
        assert_eq!(
            ecash_fork_reset_bits(Network::Betanet, FORK_HEIGHT + 1),
            None,
            "the block after the fork returns to ordinary rules"
        );
        for height in [0, 1, 2016 * 479, FORK_HEIGHT + 2016] {
            assert_eq!(
                ecash_fork_reset_bits(Network::Mainnet, height),
                None,
                "networks without an ecash fork never reset at height {height}"
            );
        }
    }

    #[test]
    fn fork_boundary_enforces_fork_bits_while_neighbors_stay_ordinary() {
        let (tree, ids) = shared_history_chain();

        // The fork block itself: wrong bits are rejected with the fork bits as
        // the expected value; the exact fork bits are accepted.
        let fork_parent = ids[idx(FORK_HEIGHT - 1)];
        let prev = tree
            .node(fork_parent)
            .unwrap_or_else(|error| panic!("fixture node exists: {error}"))
            .header
            .compute_hash();
        let wrong = header_at(prev, FORK_HEIGHT, CHAIN_BITS);
        match validate_header_nbits(&tree, fork_parent, &wrong, Network::Betanet) {
            Err(ChainError::NbitsMismatch {
                actual,
                expected,
                height,
            }) => {
                assert_eq!(actual, CHAIN_BITS);
                assert_eq!(expected, FORK_BITS);
                assert_eq!(height, FORK_HEIGHT);
            }
            other => panic!("wrong fork-block bits must be an nbits mismatch, got {other:?}"),
        }
        let correct = header_at(prev, FORK_HEIGHT, FORK_BITS);
        assert!(
            validate_header_nbits(&tree, fork_parent, &correct, Network::Betanet).is_ok(),
            "the fork block at exactly the fork bits is valid"
        );

        // One before the fork: an ordinary non-retarget height carries the
        // parent's bits through.
        let before_parent = ids[idx(FORK_HEIGHT - 2)];
        let before_prev = tree
            .node(before_parent)
            .unwrap_or_else(|error| panic!("fixture node exists: {error}"))
            .header
            .compute_hash();
        let before = header_at(before_prev, FORK_HEIGHT - 1, CHAIN_BITS);
        assert_eq!(
            next_work_required(&tree, before_parent, before.time, Network::Betanet)
                .unwrap_or_else(|error| panic!("fixture chain computes: {error}")),
            CompactTarget::from_consensus(CHAIN_BITS),
        );

        // One after the fork: still an ordinary non-retarget height, so the
        // fork block's target simply carries forward.
        let after_parent = ids[idx(FORK_HEIGHT)];
        let after_prev = tree
            .node(after_parent)
            .unwrap_or_else(|error| panic!("fixture node exists: {error}"))
            .header
            .compute_hash();
        let after = header_at(after_prev, FORK_HEIGHT + 1, FORK_BITS);
        assert_eq!(
            next_work_required(&tree, after_parent, after.time, Network::Betanet)
                .unwrap_or_else(|error| panic!("fixture chain computes: {error}")),
            CompactTarget::from_consensus(FORK_BITS),
        );

        // Mainnet at the same height is a plain retarget boundary: the ordinary
        // DAA (whose result equals the previous period's computation) rules,
        // and it is emphatically not the fork reset.
        let prev_period_parent = ids[idx(FORK_HEIGHT - 1 - 2016)];
        let ordinary = next_work_required(
            &tree,
            prev_period_parent,
            1_700_000_000 + FORK_HEIGHT - 2016 + 600,
            Network::Mainnet,
        )
        .unwrap_or_else(|error| panic!("fixture chain computes: {error}"));
        let at_fork = next_work_required(
            &tree,
            fork_parent,
            1_700_000_000 + FORK_HEIGHT + 600,
            Network::Mainnet,
        )
        .unwrap_or_else(|error| panic!("fixture chain computes: {error}"));
        assert_eq!(
            at_fork, ordinary,
            "mainnet computes the same ordinary retarget at both boundaries"
        );
        assert_ne!(
            at_fork,
            CompactTarget::from_consensus(FORK_BITS),
            "mainnet must never produce the fork reset bits"
        );
    }
}
