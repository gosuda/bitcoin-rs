use bitcoin_rs_consensus::MAX_TIMEWARP;
use bitcoin_rs_primitives::{CompactTarget, Hash256, Network};

pub use pow::compact_is_met_by;
use pow::{compact_to_target, target_to_compact};

use crate::{
    ChainError,
    node::{BlockHeader, ChainWork, NodeId, NodeStatus},
    tree::{BlockTree, hash_from_header, prev_hash_from_header},
};

// Maximum live future drift from the caller's network-adjusted clock.
const MAX_FUTURE_TIME_SECONDS: u32 = 7200;

/// Selects which contextual header checks apply to a batch of headers.
///
/// Every mode runs the same checks; only the wall-clock future-drift ceiling
/// differs, because it depends on host time rather than chain history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeaderValidationMode {
    /// Live header admission: enforce the future-drift ceiling against the
    /// caller-supplied `now_secs`.
    LiveAdmission,
    /// Historical replay (checkpoint or journal restore): skip only the
    /// wall-clock future-drift check. Already-committed history must not
    /// become invalid solely because the host clock rolled backwards after
    /// publication.
    HistoricalReplay,
}

/// Outcome of admitting one inbound headers batch into the block tree.
pub enum HeaderAdmission {
    /// Batch accepted into the block tree.
    Accepted {
        /// Headers accepted from the batch.
        accepted: usize,
        /// Hash of the last accepted header, when any were admitted.
        announced_tip: Option<Hash256>,
        /// Height of `announced_tip` on the active chain, when resolvable.
        active_height: Option<i32>,
    },
    /// Header validation rejected the batch (peer-fault classification stays
    /// with the caller).
    Rejected(ChainError),
    /// Admission refused before validation (chain transition lock
    /// unavailable); batch dropped.
    Refused(Box<dyn core::error::Error + Send + Sync>),
}

/// Accepts a contiguous batch of headers after proof-of-work validation.
///
/// A header already in the tree is idempotent: a known-invalid one returns
/// [`ChainError::KnownInvalidHeader`], otherwise its existing [`NodeId`] is
/// appended, so the returned ids stay 1:1 with the input headers.
///
/// `now_secs` sets the live future-drift bound; historical replay ignores it.
pub fn accept_headers(
    tree: &mut BlockTree,
    headers: &[BlockHeader],
    network: Network,
    now_secs: u32,
    mode: HeaderValidationMode,
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
        // An empty tree only roots at the network's genesis hash.
        if tree.is_empty() {
            if hash != network.genesis_block_hash() {
                return Err(ChainError::MissingParent {
                    prev_hash: prev_hash_from_header(header),
                });
            }
            // The validated genesis root: the tree is empty, so the
            // header has no parent and no contextual rule applies.
            let id = tree.insert_header_with_hash(*header, hash, NodeStatus::HeaderValid)?;
            accepted.push(id);
            continue;
        }
        let prev_hash = prev_hash_from_header(header);
        let parent_id = match tree.lookup(prev_hash) {
            Some(parent_id) => parent_id,
            None => return Err(ChainError::MissingParent { prev_hash }),
        };
        if tree.node(parent_id)?.status == NodeStatus::Invalid {
            // Core's bad-prevblk gate precedes contextual validation.
            return Err(ChainError::InvalidParent { parent: parent_id });
        }
        validate_contextual_header(tree, parent_id, header, network, now_secs, mode)?;
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
/// Contextual nBits, median-time-past, BIP94 timewarp, future-time, and
/// version floors, in Core's order (`src/validation.cpp:4092-4126`). Header
/// admission and direct block connection both route through here; no caller
/// implements a second version, timewarp, or nBits predicate.
pub fn validate_contextual_header(
    tree: &BlockTree,
    parent_id: NodeId,
    header: &BlockHeader,
    network: Network,
    now_secs: u32,
    mode: HeaderValidationMode,
) -> Result<(), ChainError> {
    let parent = tree.node(parent_id)?;
    let height = parent
        .height
        .checked_add(1)
        .ok_or(ChainError::HeightOverflow { parent: parent_id })?;

    validate_header_nbits(tree, parent_id, header, network)?;

    let median = tree
        .median_time_past_at(parent_id)
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
    // (`src/validation.cpp:4100-4110`). Consensus applies it only where the
    // BIP94 deployment is active; the mining floor in
    // [`minimum_candidate_time`] applies it on every network as policy.
    if network.enforce_bip94()
        && let Some(minimum) = minimum_candidate_time(parent.header.time, height, network)
        && header.time < minimum
    {
        return Err(ChainError::TimewarpAttack {
            height,
            timestamp: header.time,
            minimum,
        });
    }

    // Future-drift ceiling. Historical replay skips only this check: a
    // checkpoint or journal record must not become invalid solely because
    // the host clock rolled backwards after publication.
    if mode == HeaderValidationMode::LiveAdmission {
        let max_allowed = now_secs.saturating_add(MAX_FUTURE_TIME_SECONDS);
        if header.time > max_allowed {
            return Err(ChainError::TimestampTooFarAhead {
                hash: hash_from_header(header),
                timestamp: header.time,
                max_allowed,
            });
        }
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

/// The timewarp floor a candidate at `height` inherits from its parent.
///
/// At a difficulty-adjustment boundary, the floor is `parent_time` minus
/// [`MAX_TIMEWARP`]; off one there is no floor. This is the one boundary
/// predicate and floor. Core's `GetMinimumTime` (`src/node/miner.cpp:42-49`)
/// applies it on every network as mining policy; consensus rejection
/// additionally requires the BIP94 deployment, which
/// [`validate_contextual_header`] gates on `network.enforce_bip94()`.
pub fn minimum_candidate_time(parent_time: u32, height: u32, network: Network) -> Option<u32> {
    let retarget_interval = network.retarget_interval();
    (retarget_interval != 0 && height.is_multiple_of(retarget_interval))
        .then(|| parent_time.saturating_sub(MAX_TIMEWARP))
}

/// Computes the compact target a block extending `parent_id` must carry.
///
/// This is the one next-work source: [`validate_header_nbits`] enforces
/// exactly this value, and template building reads it rather than recomputing
/// the arithmetic. Testnet minimum-difficulty recovery keys off
/// `candidate_time`.
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
        expected_retarget_bits(network, tree, parent_id)
    } else {
        expected_non_retarget_bits(network, tree, parent_id, candidate_time)
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
    let expected = next_work_required(tree, parent_id, header.time, network)?;
    let actual = header.bits;
    if actual == expected {
        return Ok(());
    }
    // `height` only reports the mismatch; resolve it on the failure path
    // since `next_work_required` already proved the parent resolves.
    let height = tree
        .node(parent_id)?
        .height
        .checked_add(1)
        .ok_or(ChainError::HeightOverflow { parent: parent_id })?;
    Err(ChainError::NbitsMismatch {
        actual: actual.to_consensus(),
        expected: expected.to_consensus(),
        height,
    })
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
    let retarget_interval = network.retarget_interval();
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
) -> Result<CompactTarget, ChainError> {
    let prev_node = tree.node(parent_id)?;
    if network.pow_no_retargeting() {
        return Ok(prev_node.header.bits);
    }

    let height = prev_node
        .height
        .checked_add(1)
        .ok_or(ChainError::HeightOverflow { parent: parent_id })?;
    let Some(anchor_height) = height.checked_sub(network.retarget_interval()) else {
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

fn pow_limit_bits(network: Network) -> CompactTarget {
    target_to_compact(network.max_target())
}

/// Core's `GetBlockProof`: `~target / (target + 1) + 1`, also used for chainwork.
#[must_use]
pub fn block_work(header: &BlockHeader) -> ChainWork {
    let target = pow::compact_to_target(header.bits);
    if target == ChainWork::ZERO {
        return ChainWork::ZERO;
    }
    (!target / (target + ChainWork::from(1u32))) + ChainWork::from(1u32)
}

/// Whether a difficulty transition from `old_bits` to `new_bits` at `height`
/// is permitted without consulting a stored chain.
///
/// Core's `PermittedDifficultyTransition` (`bitcoin-core/src/pow.cpp:89-136`),
/// which header presync runs while it holds no tree; the contextual check in
/// [`validate_header_nbits`] remains the full-consensus rule.
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

/// Compact proof-of-work target decode/encode helpers.
///
/// Mirrors Core's `arith_uint256::SetCompact`/`GetCompact`, with two
/// deliberate divergences that cannot accept a header Core rejects: an
/// overflowing shift folds to `ChainWork::ZERO` instead of surfacing
/// `pfOverflow`, and a sign-flagged encoding decodes to `ChainWork::ZERO`
/// instead of being rejected by name.
pub(crate) mod pow {
    use bitcoin_rs_primitives::{CompactTarget, Hash256};

    use crate::node::ChainWork;

    struct DecodedCompact {
        target: ChainWork,
        negative: bool,
    }

    fn decode_compact(bits: u32) -> DecodedCompact {
        let exponent = usize::try_from(bits >> 24).unwrap_or(0);
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

    /// Encodes a non-negative 256-bit target into compact consensus form.
    #[must_use]
    pub(crate) fn target_to_compact(target: ChainWork) -> CompactTarget {
        CompactTarget::from_consensus(get_compact(target))
    }

    /// Encodes a non-negative target, never setting the sign bit.
    fn get_compact(target: ChainWork) -> u32 {
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

        compact | (u32::try_from(size).unwrap_or(0) << 24)
    }
}

#[cfg(test)]
mod fixture {
    use super::compact_is_met_by;
    use crate::node::BlockHeader;
    use bitcoin_rs_primitives::{BlockHash, CompactTarget, Hash256};

    pub(super) fn mine_regtest(
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
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        };
        while !compact_is_met_by(header.bits, header.compute_hash().0) {
            header.nonce = header.nonce.wrapping_add(1);
        }
        header
    }
}

#[cfg(test)]
mod contextual_header_tests {
    use super::{
        HeaderValidationMode, MAX_FUTURE_TIME_SECONDS, accept_headers, fixture::mine_regtest,
        next_work_required, validate_contextual_header,
    };
    use crate::{
        ChainError,
        node::{BlockHeader, NodeStatus},
        tree::{BlockTree, hash_from_header},
    };
    use bitcoin_rs_primitives::{BlockHash, CompactTarget, Hash256, Network};

    const TESTNET4_POW_LIMIT: u32 = 0x1d00_ffff;

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
        accept_headers(
            tree,
            &[header],
            network,
            time,
            HeaderValidationMode::LiveAdmission,
        )
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
        accept_headers(
            &mut tree,
            &[genesis.header],
            network,
            base_time,
            HeaderValidationMode::LiveAdmission,
        )?;

        let mut filled = 0_u32;
        for (activation, stale, required) in [(500_u32, 1_i32, 2_i32), (1251, 2, 3), (1351, 3, 4)] {
            // Fill up to the activation height with headers that already meet
            // the floor, so only the candidate's version is under test.
            for height in filled + 1..activation {
                extend_regtest(&mut tree, &mut prev, height, required, base_time);
            }
            filled = activation;

            let now = base_time + activation * 600;
            let rejected = mine_regtest(prev, activation, now, stale);
            assert_eq!(
                accept_headers(
                    &mut tree,
                    &[rejected],
                    network,
                    now,
                    HeaderValidationMode::LiveAdmission
                ),
                Err(ChainError::BadVersion {
                    version: stale,
                    required,
                    height: activation
                })
            );
            assert_eq!(
                tree.lookup(hash_from_header(&rejected)),
                None,
                "a rejected header must not enter the tree"
            );

            let accepted = mine_regtest(prev, activation, now, required);
            accept_headers(
                &mut tree,
                &[accepted],
                network,
                now,
                HeaderValidationMode::LiveAdmission,
            )
            .map_err(|error| {
                format!("version {required} is legal at height {activation}: {error:?}")
            })?;
            prev = accepted.compute_hash();
        }
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
            validate_contextual_header(
                &tree,
                parent_id,
                &candidate(tip_time - 601),
                network,
                now,
                HeaderValidationMode::LiveAdmission
            ),
            Err(ChainError::TimewarpAttack {
                height: 2016,
                timestamp: tip_time - 601,
                minimum: tip_time - 600,
            })
        );
        // Exactly `MAX_TIMEWARP` below the parent: still valid.
        validate_contextual_header(
            &tree,
            parent_id,
            &candidate(tip_time - 600),
            network,
            now,
            HeaderValidationMode::LiveAdmission,
        )
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
        accept_headers(
            &mut tree,
            &[genesis.header],
            network,
            base_time,
            HeaderValidationMode::LiveAdmission,
        )?;
        extend_regtest(&mut tree, &mut prev, 1, 4, base_time);
        let block_one = tree.lookup(prev.0).ok_or("block one is in the tree")?;
        tree.invalidate_subtree(block_one)?;

        let now = base_time + 2 * 600;
        let child = mine_regtest(prev, 2, now, 4);
        assert_eq!(
            accept_headers(
                &mut tree,
                &[child],
                network,
                now,
                HeaderValidationMode::LiveAdmission
            ),
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

    #[test]
    fn wall_clock_conversion_handles_epoch_and_u32_boundaries() {
        use std::time::{Duration, UNIX_EPOCH};
        for (clock, expected) in [
            (UNIX_EPOCH - Duration::from_secs(1), 0),
            (UNIX_EPOCH, 0),
            (UNIX_EPOCH + Duration::from_secs(1), 1),
            (
                UNIX_EPOCH + Duration::from_secs(u64::from(u32::MAX)),
                u32::MAX,
            ),
            (
                UNIX_EPOCH + Duration::from_secs(u64::from(u32::MAX) + 1),
                u32::MAX,
            ),
        ] {
            assert_eq!(super::unix_seconds_at(clock), expected);
        }
    }

    /// Eleven headers with times 0..=10, so the tip's median time past is
    /// exactly 5. Insertion bypasses `accept_headers` so the fixture itself is
    /// not subject to the rules under test.
    fn chain_with_median_five() -> (BlockTree, BlockHeader) {
        let mut tree = BlockTree::new();
        let mut prev = BlockHash::default();
        let mut tip = mine_regtest(prev, 0, 0, 1);
        for height in 0_u32..11 {
            let header = mine_regtest(prev, height, height, 1);
            prev = header.compute_hash();
            let hash = hash_from_header(&header);
            tree.insert_header_with_hash(header, hash, NodeStatus::HeaderValid)
                .unwrap_or_else(|e| panic!("fixture header failed to insert: {e:?}"));
            tip = header;
        }
        (tree, tip)
    }

    // MTP binds in both modes; replay must ignore the caller's future ceiling.
    #[test]
    fn timestamp_bounds_hold_per_validation_mode() -> Result<(), Box<dyn std::error::Error>> {
        let (tree, tip) = chain_with_median_five();
        let parent_id = tree.lookup(tip.compute_hash().0).ok_or("tip in tree")?;
        let rolled_back = 1_000_u32;
        let far_future = 2_000_000_000_u32;

        let live = HeaderValidationMode::LiveAdmission;
        let replay = HeaderValidationMode::HistoricalReplay;
        let drifted = rolled_back + MAX_FUTURE_TIME_SECONDS + 100;
        let ceiling = far_future + MAX_FUTURE_TIME_SECONDS;
        let cases = [
            ("MTP equality", 11, 5, 1_000_000, live, false),
            ("above MTP", 11, 6, 1_000_000, live, true),
            ("replay MTP", 11, 5, 1_000_000, replay, false),
            (
                "below-host ceiling",
                11,
                1_000_000 + MAX_FUTURE_TIME_SECONDS,
                1_000_000,
                live,
                true,
            ),
            (
                "past below-host ceiling",
                11,
                1_000_001 + MAX_FUTURE_TIME_SECONDS,
                1_000_000,
                live,
                false,
            ),
            ("live drift", 11, drifted, rolled_back, live, false),
            ("replay drift", 11, drifted, rolled_back, replay, true),
            (
                "supplied clock ceiling",
                11,
                ceiling,
                far_future,
                live,
                true,
            ),
            ("one past ceiling", 12, ceiling + 1, far_future, live, false),
        ];
        assert!(
            super::current_unix_seconds() + MAX_FUTURE_TIME_SECONDS
                < far_future + MAX_FUTURE_TIME_SECONDS,
            "the host clock must reject the supplied-time case, or it proves nothing"
        );

        for (name, seed, time, now, mode, accepted) in cases {
            let header = mine_regtest(tip.compute_hash(), seed, time, 1);
            let result =
                validate_contextual_header(&tree, parent_id, &header, Network::Regtest, now, mode);
            if accepted {
                assert_eq!(result, Ok(()), "{name}");
            } else if time <= 5 {
                assert_eq!(
                    result,
                    Err(ChainError::TimestampTooEarly {
                        hash: hash_from_header(&header),
                        timestamp: time,
                        median: 5,
                    }),
                    "{name}"
                );
            } else {
                assert_eq!(
                    result,
                    Err(ChainError::TimestampTooFarAhead {
                        hash: hash_from_header(&header),
                        timestamp: time,
                        max_allowed: now + MAX_FUTURE_TIME_SECONDS,
                    }),
                    "{name}"
                );
            }
        }

        Ok(())
    }
}
