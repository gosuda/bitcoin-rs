pub(crate) mod context;

pub use context::HeaderContextError;

use bitcoin_rs_consensus::MAX_TIMEWARP;
use bitcoin_rs_consensus::primitives::{CompactTarget, Hash256, Network};

use pow::target_to_compact;
pub use pow::{compact_is_met_by, compact_to_target};

use crate::chain::{
    ChainError,
    node::{NodeId, NodeStatus},
    tree::{BlockTree, Inserted},
};
use bitcoin_rs_consensus::header_rules::{BlockHeader, ChainWork};

const MAX_FUTURE_TIME_SECONDS: u32 = 7200;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeaderValidationMode {
    LiveAdmission,
    HistoricalReplay,
}

pub enum HeaderAdmission {
    Accepted {
        accepted: usize,
        announced_tip: Option<Hash256>,
        active_height: Option<i32>,
        demoted_tip: Option<Hash256>,
    },
    Rejected(ChainError),
    Refused(HeaderRefusal),
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{cause}")]
pub struct HeaderRefusal {
    cause: String,
}

impl HeaderRefusal {
    #[must_use]
    pub fn from_cause(cause: &dyn core::fmt::Display) -> Self {
        Self {
            cause: cause.to_string(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AcceptHeaders {
    pub ids: Vec<NodeId>,
    pub demoted_tip: Option<Hash256>,
}

impl AcceptHeaders {
    fn push_inserted(&mut self, inserted: Inserted) {
        self.ids.push(inserted.id);
        self.demoted_tip = self.demoted_tip.or(inserted.demoted_tip);
    }
}

#[must_use]
pub fn demoted_tip_after_rejection(tree: &BlockTree, pre_tip: Option<Hash256>) -> Option<Hash256> {
    let pre_hash = pre_tip?;
    let pre_id = tree.lookup(pre_hash)?;
    let current = tree.tip()?;
    if current.hash == pre_hash {
        return None;
    }
    if tree.find_common_ancestor(pre_id, current.tip_id) == Some(pre_id) {
        return None;
    }
    Some(pre_hash)
}

pub fn accept_headers(
    tree: &mut BlockTree,
    headers: &[BlockHeader],
    network: Network,
    now_secs: u32,
    mode: HeaderValidationMode,
) -> Result<AcceptHeaders, ChainError> {
    let mut accepted = AcceptHeaders {
        ids: Vec::with_capacity(headers.len()),
        demoted_tip: None,
    };
    for header in headers {
        let hash = Hash256::from(header.compute_hash());
        if let Some(existing_id) = tree.lookup(hash) {
            if matches!(tree.node(existing_id)?.status, NodeStatus::Invalid) {
                return Err(ChainError::KnownInvalidHeader { hash });
            }
            accepted.ids.push(existing_id);
            continue;
        }
        validate_pow(header, hash, network)?;
        if tree.is_empty() {
            if hash != network.genesis_block_hash() {
                return Err(ChainError::MissingParent {
                    prev_hash: Hash256::from(header.prev_blockhash),
                });
            }
            let inserted = tree.insert_header_with_hash(*header, hash, NodeStatus::HeaderValid)?;
            accepted.push_inserted(inserted);
            continue;
        }
        let prev_hash = Hash256::from(header.prev_blockhash);
        let parent_id = match tree.lookup(prev_hash) {
            Some(parent_id) => parent_id,
            None => return Err(ChainError::MissingParent { prev_hash }),
        };
        if tree.node(parent_id)?.status == NodeStatus::Invalid {
            return Err(ChainError::InvalidParent { parent: parent_id });
        }
        validate_contextual_header(tree, parent_id, header, network, now_secs, mode)?;
        let inserted = tree.insert_header_with_hash(*header, hash, NodeStatus::HeaderValid)?;
        accepted.push_inserted(inserted);
    }
    Ok(accepted)
}

pub fn current_unix_seconds() -> u32 {
    unix_seconds_at(std::time::SystemTime::now())
}

fn unix_seconds_at(now: std::time::SystemTime) -> u32 {
    now.duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u32::try_from(elapsed.as_secs()).unwrap_or(u32::MAX)
        })
}

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
    validate_time_and_version(
        header,
        height,
        parent.header.time,
        median,
        network,
        now_secs,
        mode,
    )
}

fn validate_time_and_version(
    header: &BlockHeader,
    height: u32,
    parent_time: u32,
    median: u32,
    network: Network,
    now_secs: u32,
    mode: HeaderValidationMode,
) -> Result<(), ChainError> {
    if header.time <= median {
        return Err(ChainError::TimestampTooEarly {
            hash: Hash256::from(header.compute_hash()),
            timestamp: header.time,
            median,
        });
    }

    if network.enforce_bip94()
        && let Some(minimum) = minimum_candidate_time(parent_time, height, network)
        && header.time < minimum
    {
        return Err(ChainError::TimewarpAttack {
            height,
            timestamp: header.time,
            minimum,
        });
    }

    if mode == HeaderValidationMode::LiveAdmission {
        let max_allowed = now_secs.saturating_add(MAX_FUTURE_TIME_SECONDS);
        if header.time > max_allowed {
            return Err(ChainError::TimestampTooFarAhead {
                hash: Hash256::from(header.compute_hash()),
                timestamp: header.time,
                max_allowed,
            });
        }
    }

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

pub fn minimum_candidate_time(parent_time: u32, height: u32, network: Network) -> Option<u32> {
    let retarget_interval = network.retarget_interval();
    (retarget_interval != 0 && height.is_multiple_of(retarget_interval))
        .then(|| parent_time.saturating_sub(MAX_TIMEWARP))
}

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

pub fn validate_header_nbits(
    tree: &BlockTree,
    parent_id: NodeId,
    header: &BlockHeader,
    network: Network,
) -> Result<(), ChainError> {
    let expected = next_work_required(tree, parent_id, header.time, network)?;
    let height = tree
        .node(parent_id)?
        .height
        .checked_add(1)
        .ok_or(ChainError::HeightOverflow { parent: parent_id })?;
    validate_nbits(header.bits, expected, height)
}

fn validate_nbits(
    actual: CompactTarget,
    expected: CompactTarget,
    height: u32,
) -> Result<(), ChainError> {
    if actual == expected {
        return Ok(());
    }
    Err(ChainError::NbitsMismatch {
        actual: actual.to_consensus(),
        expected: expected.to_consensus(),
        height,
    })
}

pub fn validate_pow(
    header: &BlockHeader,
    hash: Hash256,
    network: Network,
) -> Result<(), ChainError> {
    if pow::compact_overflows(header.bits) {
        return Err(ChainError::TargetBitsOverflow {
            bits: header.bits.to_consensus(),
        });
    }
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
    if let Some(bits) = immediate_non_retarget_bits(network, &parent.header, candidate_time) {
        return Ok(bits);
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

fn immediate_non_retarget_bits(
    network: Network,
    parent: &BlockHeader,
    candidate_time: u32,
) -> Option<CompactTarget> {
    if !network.allow_min_difficulty_blocks() {
        return Some(parent.bits);
    }

    let min_difficulty_time = parent
        .time
        .saturating_add(network.target_spacing_seconds().saturating_mul(2));
    (candidate_time > min_difficulty_time).then(|| pow_limit_bits(network))
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
    Ok(calculate_retarget_bits(
        network,
        &prev_node.header,
        RetargetAnchor::from_header(&anchor_node.header),
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RetargetAnchor {
    time: u32,
    bits: CompactTarget,
}

impl RetargetAnchor {
    fn from_header(header: &BlockHeader) -> Self {
        Self {
            time: header.time,
            bits: header.bits,
        }
    }
}

fn calculate_retarget_bits(
    network: Network,
    parent: &BlockHeader,
    anchor: RetargetAnchor,
) -> CompactTarget {
    let expected_timespan = network.target_timespan_seconds();
    if expected_timespan == 0 {
        return parent.bits;
    }

    let actual_timespan = parent.time.saturating_sub(anchor.time);
    let min_timespan = expected_timespan / 4;
    let max_timespan = expected_timespan.saturating_mul(4);
    let actual_clamped = actual_timespan.clamp(min_timespan, max_timespan);

    let base_target = if network.enforce_bip94() {
        anchor.bits
    } else {
        parent.bits
    };
    let prev_target = compact_to_target(base_target);
    let actual_u256 = ChainWork::from(actual_clamped);
    let expected_u256 = ChainWork::from(expected_timespan);
    let max_target = network.max_target();
    let quotient = prev_target / expected_u256;
    let remainder = prev_target % expected_u256;
    let Some(scaled_quotient) = quotient.checked_mul(actual_u256) else {
        return pow_limit_bits(network);
    };
    let scaled_remainder = remainder.saturating_mul(actual_u256) / expected_u256;
    let new_target = scaled_quotient
        .saturating_add(scaled_remainder)
        .min(max_target);
    target_to_compact(new_target)
}

fn pow_limit_bits(network: Network) -> CompactTarget {
    target_to_compact(network.max_target())
}

#[must_use]
pub fn block_work(header: &BlockHeader) -> ChainWork {
    let target = pow::compact_to_target(header.bits);
    if target == ChainWork::ZERO || pow::compact_overflows(header.bits) {
        return ChainWork::ZERO;
    }
    (!target / (target + ChainWork::from(1u32))) + ChainWork::from(1u32)
}

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

pub mod pow {
    use bitcoin_rs_consensus::primitives::{CompactTarget, Hash256};

    use bitcoin_rs_consensus::header_rules::ChainWork;

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

    #[must_use]
    pub(crate) fn compact_overflows(bits: CompactTarget) -> bool {
        let raw = bits.to_consensus();
        let size = raw >> 24;
        let word = raw & 0x007f_ffff;
        word != 0 && (size > 34 || (word > 0xff && size > 33) || (word > 0xffff && size > 32))
    }

    #[must_use]
    pub fn compact_to_target(bits: CompactTarget) -> ChainWork {
        let decoded = decode_compact(bits.to_consensus());
        if decoded.negative {
            ChainWork::ZERO
        } else {
            decoded.target
        }
    }

    #[must_use]
    pub fn compact_is_met_by(bits: CompactTarget, hash: Hash256) -> bool {
        let target = compact_to_target(bits);
        target != ChainWork::ZERO && ChainWork::from_le_bytes(hash.to_le_bytes()) <= target
    }

    #[must_use]
    pub(crate) fn target_to_compact(target: ChainWork) -> CompactTarget {
        CompactTarget::from_consensus(get_compact(target))
    }

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
    use bitcoin_rs_consensus::header_rules::BlockHeader;
    use bitcoin_rs_consensus::primitives::{BlockHash, CompactTarget, Hash256};

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
        HeaderValidationMode, MAX_FUTURE_TIME_SECONDS, accept_headers, demoted_tip_after_rejection,
        fixture::mine_regtest, next_work_required, validate_contextual_header,
    };
    use crate::chain::test_error::TestError;
    use crate::chain::{ChainError, node::NodeStatus, tree::BlockTree};
    use bitcoin_rs_consensus::header_rules::BlockHeader;

    use bitcoin_rs_consensus::primitives::{BlockHash, CompactTarget, Hash256, Network};

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
    fn rejects_outdated_versions_after_activation() -> Result<(), TestError> {
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
                tree.lookup(Hash256::from(rejected.compute_hash())),
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
            )?;
            prev = accepted.compute_hash();
        }
        Ok(())
    }

    #[test]
    fn rejects_testnet4_bip94_timewarp_candidate() -> Result<(), TestError> {
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
                Hash256::from(header.compute_hash()),
                NodeStatus::HeaderValid,
            )?;
            tip_time = header.time;
        }
        let parent_id = tree.lookup(prev.0).ok_or("fixture tip present")?;
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
        validate_contextual_header(
            &tree,
            parent_id,
            &candidate(tip_time - 600),
            network,
            now,
            HeaderValidationMode::LiveAdmission,
        )?;
        Ok(())
    }

    #[test]
    fn child_of_invalid_parent_is_rejected() -> Result<(), TestError> {
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
            tree.lookup(Hash256::from(child.compute_hash())),
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

    fn chain_with_median_five() -> (BlockTree, BlockHeader) {
        let mut tree = BlockTree::new();
        let mut prev = BlockHash::default();
        let mut tip = mine_regtest(prev, 0, 0, 1);
        for height in 0_u32..11 {
            let header = mine_regtest(prev, height, height, 1);
            prev = header.compute_hash();
            let hash = Hash256::from(header.compute_hash());
            tree.insert_header_with_hash(header, hash, NodeStatus::HeaderValid)
                .unwrap_or_else(|e| panic!("fixture header failed to insert: {e:?}"));
            tip = header;
        }
        (tree, tip)
    }

    #[test]
    fn timestamp_bounds_hold_per_validation_mode() -> Result<(), TestError> {
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
                        hash: Hash256::from(header.compute_hash()),
                        timestamp: time,
                        median: 5,
                    }),
                    "{name}"
                );
            } else {
                assert_eq!(
                    result,
                    Err(ChainError::TimestampTooFarAhead {
                        hash: Hash256::from(header.compute_hash()),
                        timestamp: time,
                        max_allowed: now + MAX_FUTURE_TIME_SECONDS,
                    }),
                    "{name}"
                );
            }
        }

        Ok(())
    }

    #[test]
    fn partial_prefix_failure_preserves_demoted_tip_via_helper() -> Result<(), TestError> {
        let network = Network::Regtest;
        let genesis = network.genesis_block();
        let base_time = genesis.header.time;
        let mut tree = BlockTree::new();
        accept_headers(
            &mut tree,
            &[genesis.header],
            network,
            base_time,
            HeaderValidationMode::LiveAdmission,
        )?;
        let mut prev = genesis.block_hash();
        for height in 1..=2_u32 {
            extend_regtest(&mut tree, &mut prev, height, 4, base_time);
        }
        let pre_tip = tree.tip().map(|tip| tip.hash);

        let mut side_prev = genesis.block_hash();
        let mut batch = Vec::new();
        for height in [101_u32, 102, 103] {
            let header = mine_regtest(side_prev, height, base_time + height * 600, 4);
            side_prev = header.compute_hash();
            batch.push(header);
        }
        let garbage = BlockHash::from(Hash256::from_le_bytes(&[0xFF_u8; 32]));
        let tail = mine_regtest(garbage, 104, base_time + 104 * 600, 4);
        batch.push(tail);

        let now = base_time + 200 * 600;
        let result = accept_headers(
            &mut tree,
            &batch,
            network,
            now,
            HeaderValidationMode::LiveAdmission,
        );
        assert!(
            matches!(result, Err(ChainError::MissingParent { .. })),
            "the tail must fail after the prefix moved the tip, got {result:?}"
        );
        assert_eq!(
            demoted_tip_after_rejection(&tree, pre_tip),
            pre_tip,
            "the tip active before the batch is the preserved demotion"
        );

        let tip_now = tree.tip().map(|tip| tip.hash);
        let bad_child = mine_regtest(garbage, 999, now, 4);
        let linear = accept_headers(
            &mut tree,
            &[bad_child],
            network,
            now,
            HeaderValidationMode::LiveAdmission,
        );
        assert!(
            matches!(linear, Err(ChainError::MissingParent { .. })),
            "linear failure must also reject, got {linear:?}"
        );
        assert_eq!(
            demoted_tip_after_rejection(&tree, tip_now),
            None,
            "no movement means no demotion to preserve"
        );
        Ok(())
    }
}

#[cfg(test)]
mod compact_overflow_tests {
    #![expect(
        clippy::expect_used,
        reason = "independent-oracle fixture construction"
    )]

    use bitcoin_rs_consensus::primitives::{BlockHash, CompactTarget, Hash256, Network};

    use crate::chain::{ChainError, NodeStatus, validate_pow};
    use bitcoin_rs_consensus::header_rules::{BlockHeader, ChainWork};

    use super::compact_to_target;

    fn header_with_bits(bits: u32) -> BlockHeader {
        BlockHeader {
            version: 1,
            prev_blockhash: BlockHash::default(),
            merkle_root: Hash256::default(),
            time: 0,
            bits: CompactTarget::from_consensus(bits),
            nonce: 0,
        }
    }

    #[test]
    fn compact_overflow_bits_are_rejected_like_core_derive_target() {
        let header = header_with_bits(0x2200_0101);
        let hash = Hash256::default();
        let network = Network::Regtest;

        assert!(
            compact_to_target(header.bits) <= network.max_target(),
            "the wrapped target must sit inside the regtest limit, so only Core's overflow rule can \
         reject this encoding"
        );

        assert_eq!(
            validate_pow(&header, hash, network),
            Err(ChainError::TargetBitsOverflow {
                bits: header.bits.to_consensus(),
            }),
            "Bitcoin Core's SetCompact marks nBits 0x22000101 as overflowed (nSize 34 and nWord \
         0x0101 > 0xff) and CheckProofOfWork rejects every overflowed encoding as high-hash; \
         an all-zero hash below the wrapped target must not pass validation"
        );
    }

    #[test]
    fn overflow_bits_are_reported_with_the_offending_nbits() {
        for bits in [0x2300_0001_u32, 0x2101_0000] {
            let header = header_with_bits(bits);
            assert_eq!(
                validate_pow(&header, Hash256::default(), Network::Regtest),
                Err(ChainError::TargetBitsOverflow { bits }),
                "Bitcoin Core v31.1 SetCompact (src/arith_uint256.cpp) sets fOverflow for nBits \
             {bits:08x} and CheckProofOfWork (src/pow.cpp) refuses every overflowed encoding \
             before the powLimit comparison, so the refusal must carry the offending nBits \
             instead of a placeholder target"
            );
        }
    }

    #[test]
    fn core_set_compact_overflow_boundary_is_typed_not_placeholder() {
        use super::pow::compact_overflows;

        let near_boundary = header_with_bits(0x2100_ffff);
        assert!(
            !compact_overflows(near_boundary.bits),
            "nBits 0x2100ffff stays inside the 256-bit target at nSize 33 with nWord 0xffff, so \
         Core's SetCompact does not mark it overflowed"
        );
        let overflowing = header_with_bits(0x2101_0000);
        assert!(
            compact_overflows(overflowing.bits),
            "nBits 0x21010000 pushes nWord 0x10000 past 256 bits at nSize 33, as Core's SetCompact \
         marks it overflowed"
        );
    }

    #[test]
    fn overflow_bits_carry_no_chainwork() {
        let header = header_with_bits(0x2200_0101);
        assert_eq!(
            crate::chain::block_work(&header),
            ChainWork::ZERO,
            "Bitcoin Core's GetBlockProof returns zero for an overflowed compact encoding \
         (fOverflow makes it return 0); the truncated target must not earn chainwork"
        );
    }

    #[test]
    fn regtest_min_difficulty_bits_still_pass_and_insert() {
        let header = header_with_bits(0x207f_ffff);
        let hash = Hash256::default();
        assert_eq!(validate_pow(&header, hash, Network::Regtest), Ok(()));

        let mut chain = crate::chain::BlockTree::new();
        let id = chain
            .insert_header(header, NodeStatus::HeaderValid)
            .expect("genesis header inserts");
        assert_eq!(chain.node(id).expect("inserted node").height, 0);
    }

    #[test]
    fn every_core_overflow_clause_and_its_boundary_matches_set_compact() {
        use super::pow::compact_overflows;

        let overflow = |bits| compact_overflows(CompactTarget::from_consensus(bits));
        for (bits, clause) in [
            (0x2300_0001_u32, "nSize > 34"),
            (0x2200_0100, "nWord > 0xff and nSize > 33"),
            (0x2101_0000, "nWord > 0xffff and nSize > 32"),
        ] {
            assert!(overflow(bits), "nBits {bits:08x} overflows: {clause}");
            let network = Network::Regtest;
            let header = header_with_bits(bits);
            let hash = Hash256::default();
            assert_eq!(
                validate_pow(&header, hash, network),
                Err(ChainError::TargetBitsOverflow {
                    bits: header.bits.to_consensus(),
                }),
                "Bitcoin Core v31.1 SetCompact (src/arith_uint256.cpp) marks nBits {bits:08x} as \
             overflowed under {clause}, so CheckProofOfWork answers high-hash"
            );
        }
        for (bits, boundary) in [
            (0x2200_00ff_u32, "nSize 34 with nWord 0xff"),
            (0x2100_ffff, "nSize 33 with nWord 0xffff"),
            (0x2001_0000, "nSize 32 with nWord 0x10000"),
        ] {
            assert!(
                !overflow(bits),
                "nBits {bits:08x} stays inside the 256-bit target at {boundary}"
            );
        }
    }
}

#[cfg(test)]
mod retarget_rule_tests {
    #![expect(
        clippy::expect_used,
        reason = "independent-oracle fixture construction"
    )]

    use super::{HeaderValidationMode, accept_headers, next_work_required};
    use crate::chain::test_error::TestError;
    use crate::chain::{
        ChainError,
        node::{NodeId, NodeStatus},
        tree::BlockTree,
    };
    use bitcoin_rs_consensus::header_rules::{BlockHeader, ChainWork};
    use bitcoin_rs_consensus::primitives::{BlockHash, CompactTarget, Hash256, Network};

    const RETARGET_INTERVAL: u32 = 2016;
    const TARGET_TIMESPAN: u32 = 14 * 24 * 60 * 60;
    const TESTNET_POW_LIMIT_BITS: u32 = 0x1d00_ffff;

    use super::context::{HeaderContextError as CompactContextError, HeaderValidationContext as CompactHeaderContext};

    fn core_next_bits(history: &[BlockHeader], candidate_time: u32, network: Network) -> u32 {
        let height = u32::try_from(history.len()).expect("fixture height fits u32");
        let parent = history.last().expect("fixture contains its root");
        if height.is_multiple_of(RETARGET_INTERVAL) {
            if network.pow_no_retargeting() {
                return parent.bits.to_consensus();
            }
            let interval = usize::try_from(RETARGET_INTERVAL).expect("2016 fits usize");
            let first = history[history.len() - interval];
            let base_bits = if network.enforce_bip94() {
                first.bits
            } else {
                parent.bits
            };
            return core_calculate_next_work_required(
                parent.time,
                base_bits.to_consensus(),
                first.time,
            );
        }
        if !network.allow_min_difficulty_blocks() {
            return parent.bits.to_consensus();
        }
        let limit = core_get_compact(network.max_target());
        if candidate_time > parent.time.saturating_add(1200) {
            return limit;
        }
        for (index, header) in history.iter().enumerate().rev() {
            let height = u32::try_from(index).expect("fixture height fits u32");
            if height.is_multiple_of(RETARGET_INTERVAL) || header.bits.to_consensus() != limit {
                return header.bits.to_consensus();
            }
        }
        unreachable!("the genesis entry is a period boundary")
    }

    fn assert_compact_rejection(
        tree: &BlockTree,
        parent_id: NodeId,
        context: &mut CompactHeaderContext,
        header: BlockHeader,
        now_secs: u32,
        expected: ChainError,
    ) {
        let before = context.clone();
        let tree_result = super::validate_contextual_header(
            tree,
            parent_id,
            &header,
            context.network,
            now_secs,
            HeaderValidationMode::LiveAdmission,
        );
        assert_eq!(tree_result, Err(expected));
        assert_eq!(
            context.accept_contextual_header(
                &header,
                now_secs,
                HeaderValidationMode::LiveAdmission,
            ),
            tree_result.map_err(CompactContextError::Chain),
        );
        assert_eq!(*context, before);
    }

    fn header_with(prev: BlockHash, time: u32, bits: u32, nonce: u32) -> BlockHeader {
        BlockHeader {
            version: 4,
            prev_blockhash: prev,
            merkle_root: Hash256::default(),
            time,
            bits: CompactTarget::from_consensus(bits),
            nonce,
        }
    }

    fn chain_header(prev: &mut BlockHash, time: u32, bits: u32, height: u32) -> BlockHeader {
        let header = header_with(*prev, time, bits, height);
        *prev = header.compute_hash();
        header
    }

    fn build_retarget_chain(
        tree: &mut BlockTree,
        anchor_bits: u32,
        inner_bits: u32,
        anchor_time: u32,
        step_seconds: u32,
    ) -> Result<NodeId, TestError> {
        let mut prev = BlockHash::default();
        let mut tip = NodeId::new(u32::MAX);
        for height in 0..RETARGET_INTERVAL {
            let bits = if height == 0 { anchor_bits } else { inner_bits };
            let time = anchor_time + height.saturating_mul(step_seconds);
            let header = chain_header(&mut prev, time, bits, height);
            tip = tree.insert_header(header, NodeStatus::HeaderValid)?;
        }
        Ok(tip)
    }

    fn core_set_compact(bits: u32) -> (ChainWork, bool, bool) {
        let size = usize::try_from(bits >> 24).unwrap_or(0);
        let word = bits & 0x007f_ffff;
        let target = if size <= 3 {
            ChainWork::from(word >> (8 * (3 - size)))
        } else {
            let shift = 8 * (size - 3);
            if shift < 256 {
                ChainWork::from(word) << shift
            } else {
                ChainWork::ZERO
            }
        };
        let negative = word != 0 && bits & 0x0080_0000 != 0;
        let overflow =
            word != 0 && (size > 34 || (word > 0xff && size > 33) || (word > 0xffff && size > 32));
        (target, negative, overflow)
    }

    fn pow_limit_work() -> ChainWork {
        core_set_compact(TESTNET_POW_LIMIT_BITS).0
    }

    fn core_calculate_next_work_required(last_time: u32, base_bits: u32, first_time: u32) -> u32 {
        let mut actual = i64::from(last_time) - i64::from(first_time);
        let timespan = i64::from(TARGET_TIMESPAN);
        if actual < timespan / 4 {
            actual = timespan / 4;
        }
        if actual > timespan * 4 {
            actual = timespan * 4;
        }
        let actual_u32 = u32::try_from(actual).expect("clamped timespan fits u32");
        let (mut target, negative, overflow) = core_set_compact(base_bits);
        assert!(!negative && !overflow);
        target *= ChainWork::from(actual_u32);
        target /= ChainWork::from(TARGET_TIMESPAN);
        let limit = pow_limit_work();
        if target > limit {
            target = limit;
        }
        core_get_compact(target)
    }

    fn core_get_compact(target: ChainWork) -> u32 {
        let mut size = u32::try_from(target.bit_len().div_ceil(8)).expect("size fits u32");
        let mut compact: u32 = if size <= 3 {
            u32::try_from(target.as_limbs()[0] << (8 * (3 - size)))
                .expect("mantissa fits u32 when size <= 3")
        } else {
            u32::try_from((target >> (8 * (size - 3))).as_limbs()[0])
                .expect("three-byte window fits u32")
        };
        if compact & 0x0080_0000 != 0 {
            compact >>= 8;
            size += 1;
        }
        compact | (size << 24)
    }

    fn tree_shape(tree: &BlockTree) -> Vec<(Hash256, u32, NodeStatus, Option<NodeId>, ChainWork)> {
        let len = u32::try_from(tree.len()).expect("node count fits u32");
        (0..len)
            .map(|index| {
                let node = tree.node(NodeId::new(index)).expect("node exists");
                (
                    node.hash,
                    node.height,
                    node.status,
                    node.parent,
                    node.chainwork,
                )
            })
            .collect()
    }

    fn side_chain_retip(tree: &mut BlockTree) -> Result<NodeId, TestError> {
        let main_tip = build_retarget_chain(tree, 0x1b04_04cb, 0x1c0f_fffe, 1_600_000_000, 1)?;
        let mut fork = main_tip;
        for _ in 0..5 {
            fork = tree.parent_id(fork)?.ok_or(TestError::from("no parent"))?;
        }
        let mut cursor = fork;
        for depth in 0..6_u32 {
            let parent_hash = tree.node(cursor)?.hash;
            let parent_height = tree.node(cursor)?.height;
            let time = 1_600_000_000 + parent_height + 10_000_000 + depth;
            let header = header_with(BlockHash(parent_hash), time, 0x1c0f_fffe, 900_000 + depth);
            cursor = tree.insert_node(Some(cursor), header, NodeStatus::HeaderValid)?;
        }
        Ok(cursor)
    }

    #[test]
    fn side_chain_retarget_anchors_shared_height_zero_block() -> Result<(), TestError> {
        let network = Network::Testnet3;
        let mut tree = BlockTree::new();
        let side_tip = side_chain_retip(&mut tree)?;
        assert_eq!(tree.node(side_tip)?.height, RETARGET_INTERVAL);
        let retarget_parent = tree
            .parent_id(side_tip)?
            .ok_or(TestError::from("no parent"))?;
        let parent_time = tree.node(retarget_parent)?.header.time;
        let parent_bits = tree.node(retarget_parent)?.header.bits.to_consensus();
        let got = next_work_required(&tree, retarget_parent, 0, network)?.to_consensus();
        let want = core_calculate_next_work_required(parent_time, parent_bits, 1_600_000_000);
        assert_eq!(
            got, want,
            "side-chain retarget must anchor on the shared height-0 block"
        );
        let context = CompactHeaderContext::from_tree(&tree, retarget_parent, network)?;
        assert_eq!(
            context.next_bits(0).expect("fixture height").to_consensus(),
            want
        );
        Ok(())
    }

    #[test]
    fn bip94_retarget_scales_anchor_block_bits() -> Result<(), TestError> {
        let network = Network::Testnet4;
        let mut tree = BlockTree::new();
        let first_time = 1_600_000_000_u32;
        let tip = build_retarget_chain(
            &mut tree,
            0x1b04_04cb,
            TESTNET_POW_LIMIT_BITS,
            first_time,
            1,
        )?;
        let got = next_work_required(&tree, tip, 0, network)?.to_consensus();
        let want = core_calculate_next_work_required(
            first_time + RETARGET_INTERVAL - 1,
            0x1b04_04cb,
            first_time,
        );
        assert_eq!(
            got, want,
            "BIP94 scales the anchor block's bits, not the last block's"
        );
        let context = CompactHeaderContext::from_tree(&tree, tip, network)?;
        assert_eq!(
            context.next_bits(0).expect("fixture height").to_consensus(),
            want
        );
        Ok(())
    }

    #[test]
    fn testnet_min_difficulty_boundary_is_strict_and_walks_back() -> Result<(), TestError> {
        let network = Network::Testnet3;
        let mut tree = BlockTree::new();
        let mut prev = BlockHash::default();
        let mut times = vec![1_600_000_000_u32];
        for height in 1..8_u32 {
            let index = usize::try_from(height - 1).expect("index fits usize");
            let bits = if height == 5 {
                0x1b04_04cb
            } else {
                TESTNET_POW_LIMIT_BITS
            };
            let header = chain_header(&mut prev, times[index] + 700, bits, height);
            times.push(header.time);
            tree.insert_header(header, NodeStatus::HeaderValid)?;
        }
        let tip_id = tree.lookup(prev.0).ok_or(TestError::from("fixture tip"))?;

        let late = next_work_required(&tree, tip_id, times[7] + 1201, network)?.to_consensus();
        assert_eq!(late, TESTNET_POW_LIMIT_BITS);

        let exact = next_work_required(&tree, tip_id, times[7] + 1200, network)?.to_consensus();
        assert_eq!(exact, 0x1b04_04cb);

        let early = next_work_required(&tree, tip_id, times[7] + 60, network)?.to_consensus();
        assert_eq!(early, 0x1b04_04cb);
        let context = CompactHeaderContext::from_tree(&tree, tip_id, network)?;
        for (offset, expected) in [
            (1201, TESTNET_POW_LIMIT_BITS),
            (1200, 0x1b04_04cb),
            (60, 0x1b04_04cb),
        ] {
            assert_eq!(
                context
                    .next_bits(times[7] + offset)
                    .expect("fixture height")
                    .to_consensus(),
                expected,
            );
        }
        Ok(())
    }

    #[test]
    fn compact_context_matches_full_ancestry_across_two_difficulty_periods()
    -> Result<(), CompactContextError> {
        for network in [
            Network::Mainnet,
            Network::Testnet3,
            Network::Testnet4,
            Network::Regtest,
        ] {
            let genesis = network.genesis_block().header;
            let mut tree = BlockTree::new();
            let mut parent_id = tree.insert_header(genesis, NodeStatus::HeaderValid)?;
            let mut context = CompactHeaderContext::from_tree(&tree, parent_id, network)?;
            let mut history = vec![genesis];
            for height in 1..=2 * RETARGET_INTERVAL + 12 {
                context = CompactHeaderContext::decode_snapshot(network, &context.encode_snapshot())?;
                let parent = *history.last().expect("fixture root");
                let delayed =
                    height % 61 < 3 || height % RETARGET_INTERVAL == RETARGET_INTERVAL - 1;
                let time = parent.time + if delayed { 1201 } else { 1 };
                let expected_bits = core_next_bits(&history, time, network);
                assert_eq!(
                    next_work_required(&tree, parent_id, time, network)?.to_consensus(),
                    expected_bits,
                    "full ancestry at {network:?} height {height}",
                );
                assert_eq!(
                    context.next_bits(time)?.to_consensus(),
                    expected_bits,
                    "compact context at {network:?} height {height}",
                );
                let header = header_with(parent.compute_hash(), time, expected_bits, height);
                let full = super::validate_contextual_header(
                    &tree,
                    parent_id,
                    &header,
                    network,
                    time,
                    HeaderValidationMode::LiveAdmission,
                );
                assert_eq!(full, Ok(()));
                assert_eq!(
                    context.accept_contextual_header(
                        &header,
                        time,
                        HeaderValidationMode::LiveAdmission
                    ),
                    full.map_err(CompactContextError::Chain),
                );
                parent_id = tree.insert_header(header, NodeStatus::HeaderValid)?;
                history.push(header);
                assert_eq!(context.height, height);
                assert_eq!(context.chainwork, tree.node(parent_id)?.chainwork);
                assert_eq!(
                    Some(context.median_time_past()),
                    tree.median_time_past_at(parent_id)
                );
                if [1, 5, 10, 11, 2015, 2016, 2020, 4031, 4032].contains(&height) {
                    let resumed = CompactHeaderContext::from_tree(&tree, parent_id, network)?;
                    assert_eq!(resumed.next_bits(time + 1)?, context.next_bits(time + 1)?);
                    assert_eq!(resumed.median_time_past(), context.median_time_past());
                    assert_eq!(resumed.period_anchor, context.period_anchor);
                    assert_eq!(resumed.last_nonminimum_bits, context.last_nonminimum_bits);
                }
            }
        }
        Ok(())
    }

    #[test]
    fn compact_context_preserves_state_on_timestamp_difficulty_and_version_rejection()
    -> Result<(), CompactContextError> {
        let network = Network::Regtest;
        let genesis = network.genesis_block().header;
        let mut tree = BlockTree::new();
        let mut parent_id = tree.insert_header(genesis, NodeStatus::HeaderValid)?;
        let mut context = CompactHeaderContext::from_tree(&tree, parent_id, network)?;
        for height in 1..=1352 {
            let time = genesis.time + height * 600;
            let header = header_with(context.parent.compute_hash(), time, 0x207f_ffff, height);
            if height == 12 {
                let median = genesis.time + 6 * 600;
                let early = BlockHeader {
                    time: median,
                    ..header
                };
                assert_compact_rejection(
                    &tree,
                    parent_id,
                    &mut context,
                    early,
                    time,
                    ChainError::TimestampTooEarly {
                        hash: Hash256::from(early.compute_hash()),
                        timestamp: median,
                        median,
                    },
                );
                let future = BlockHeader {
                    time: time + 7201,
                    ..header
                };
                assert_compact_rejection(
                    &tree,
                    parent_id,
                    &mut context,
                    future,
                    time,
                    ChainError::TimestampTooFarAhead {
                        hash: Hash256::from(future.compute_hash()),
                        timestamp: time + 7201,
                        max_allowed: time + 7200,
                    },
                );
                let wrong_bits = BlockHeader {
                    bits: CompactTarget::from_consensus(0x207f_fffe),
                    ..header
                };
                assert_compact_rejection(
                    &tree,
                    parent_id,
                    &mut context,
                    wrong_bits,
                    time,
                    ChainError::NbitsMismatch {
                        actual: 0x207f_fffe,
                        expected: 0x207f_ffff,
                        height,
                    },
                );
                let mut replay = context.clone();
                replay.accept_contextual_header(
                    &future,
                    0,
                    HeaderValidationMode::HistoricalReplay,
                )?;
                super::validate_contextual_header(
                    &tree,
                    parent_id,
                    &future,
                    network,
                    0,
                    HeaderValidationMode::HistoricalReplay,
                )?;
            }
            for (activation, stale, required) in [(500, 1, 2), (1251, 2, 3), (1351, 3, 4)] {
                if height == activation {
                    assert_compact_rejection(
                        &tree,
                        parent_id,
                        &mut context,
                        BlockHeader {
                            version: stale,
                            ..header
                        },
                        time,
                        ChainError::BadVersion {
                            version: stale,
                            required,
                            height,
                        },
                    );
                }
            }
            context.accept_contextual_header(&header, time, HeaderValidationMode::LiveAdmission)?;
            super::validate_contextual_header(
                &tree,
                parent_id,
                &header,
                network,
                time,
                HeaderValidationMode::LiveAdmission,
            )?;
            parent_id = tree.insert_header(header, NodeStatus::HeaderValid)?;
        }
        Ok(())
    }

    #[test]
    fn compact_context_enforces_bip94_timewarp_floor_before_advancing_period()
    -> Result<(), CompactContextError> {
        let network = Network::Testnet4;
        let first_time = 1_600_000_000;
        let mut tree = BlockTree::new();
        let mut parent = BlockHash::default();
        let mut parent_id = NodeId::new(0);
        for height in 0..RETARGET_INTERVAL {
            let header = chain_header(
                &mut parent,
                first_time + height * 600,
                TESTNET_POW_LIMIT_BITS,
                height,
            );
            parent_id = tree.insert_header(header, NodeStatus::HeaderValid)?;
        }
        let mut context = CompactHeaderContext::from_tree(&tree, parent_id, network)?;
        let parent_time = first_time + (RETARGET_INTERVAL - 1) * 600;
        let expected_bits =
            core_calculate_next_work_required(parent_time, TESTNET_POW_LIMIT_BITS, first_time);
        let header = header_with(parent, parent_time - 601, expected_bits, RETARGET_INTERVAL);
        assert_compact_rejection(
            &tree,
            parent_id,
            &mut context,
            header,
            parent_time,
            ChainError::TimewarpAttack {
                height: RETARGET_INTERVAL,
                timestamp: parent_time - 601,
                minimum: parent_time - 600,
            },
        );
        let boundary = BlockHeader {
            time: parent_time - 600,
            ..header
        };
        context.accept_contextual_header(
            &boundary,
            parent_time,
            HeaderValidationMode::LiveAdmission,
        )?;
        super::validate_contextual_header(
            &tree,
            parent_id,
            &boundary,
            network,
            parent_time,
            HeaderValidationMode::LiveAdmission,
        )?;
        assert_eq!(context.period_anchor.time, parent_time - 600);
        assert_eq!(context.period_anchor.bits.to_consensus(), expected_bits);
        Ok(())
    }

    #[test]
    fn compact_context_rejects_discontinuity_and_overflow_without_mutation()
    -> Result<(), CompactContextError> {
        let network = Network::Regtest;
        let genesis = network.genesis_block().header;
        let mut tree = BlockTree::new();
        let parent_id = tree.insert_header(genesis, NodeStatus::HeaderValid)?;
        let mut context = CompactHeaderContext::from_tree(&tree, parent_id, network)?;
        let time = genesis.time + 600;
        let header = header_with(genesis.compute_hash(), time, 0x207f_ffff, 1);
        let orphan = BlockHeader {
            prev_blockhash: BlockHash::default(),
            ..header
        };
        let before = context.clone();
        assert_eq!(
            context.accept_contextual_header(&orphan, time, HeaderValidationMode::LiveAdmission),
            Err(CompactContextError::Chain(
                ChainError::NonContinuousHeader {
                    expected_prev: Hash256::from(genesis.compute_hash()),
                    actual_prev: Hash256::default(),
                }
            )),
        );
        assert_eq!(context, before);
        context.chainwork = !ChainWork::ZERO;
        let before = context.clone();
        assert_eq!(
            context.accept_contextual_header(&header, time, HeaderValidationMode::LiveAdmission),
            Err(CompactContextError::Chain(ChainError::ChainworkOverflow {
                hash: Hash256::from(header.compute_hash()),
            })),
        );
        assert_eq!(context, before);
        context.height = u32::MAX;
        let before = context.clone();
        assert_eq!(
            context.accept_contextual_header(&header, time, HeaderValidationMode::LiveAdmission),
            Err(CompactContextError::HeightOverflow {
                parent: Hash256::from(genesis.compute_hash())
            }),
        );
        assert_eq!(context, before);
        assert!(core::mem::size_of::<CompactHeaderContext>() <= 256);
        Ok(())
    }

    #[test]
    fn refused_header_leaves_tree_unchanged() -> Result<(), TestError> {
        let network = Network::Regtest;
        let genesis = network.genesis_block();
        let mut tree = BlockTree::new();
        let base_time = genesis.header.time;
        accept_headers(
            &mut tree,
            &[genesis.header],
            network,
            base_time,
            HeaderValidationMode::LiveAdmission,
        )?;
        let good = super::fixture::mine_regtest(genesis.block_hash(), 1, base_time + 600, 4);
        accept_headers(
            &mut tree,
            &[good],
            network,
            base_time + 600,
            HeaderValidationMode::LiveAdmission,
        )?;
        let good_hash = good.compute_hash();
        let good_id = tree
            .lookup(Hash256::from(good_hash))
            .ok_or(TestError::from("tip"))?;
        let child = super::fixture::mine_regtest(good_hash, 2, base_time + 1300, 4);
        accept_headers(
            &mut tree,
            &[child],
            network,
            base_time + 1300,
            HeaderValidationMode::LiveAdmission,
        )?;
        tree.invalidate_subtree(good_id)?;
        assert_eq!(tree.node(good_id)?.status, NodeStatus::Invalid);
        let before = tree_shape(&tree);
        let now = base_time + 1_000_000;

        let duplicate = accept_headers(
            &mut tree,
            &[good],
            network,
            base_time + 600,
            HeaderValidationMode::LiveAdmission,
        );
        assert!(matches!(
            duplicate,
            Err(ChainError::KnownInvalidHeader { .. })
        ));
        assert_eq!(tree_shape(&tree), before);

        let out_of_order_parent = super::fixture::mine_regtest(good_hash, 5, base_time + 1900, 4);
        let out_of_order_child = super::fixture::mine_regtest(
            out_of_order_parent.compute_hash(),
            6,
            base_time + 2500,
            4,
        );
        let res = accept_headers(
            &mut tree,
            &[out_of_order_child, out_of_order_parent],
            network,
            now,
            HeaderValidationMode::LiveAdmission,
        );
        assert!(matches!(res, Err(ChainError::MissingParent { .. })));
        assert_eq!(tree_shape(&tree), before);

        let orphan = super::fixture::mine_regtest(BlockHash::default(), 2, base_time + 700, 4);
        assert!(matches!(
            accept_headers(
                &mut tree,
                &[orphan],
                network,
                now,
                HeaderValidationMode::LiveAdmission
            ),
            Err(ChainError::MissingParent { .. })
        ));
        assert_eq!(tree_shape(&tree), before);

        let invalid_parent_child = super::fixture::mine_regtest(good_hash, 5, base_time + 2600, 4);
        assert!(matches!(
            accept_headers(&mut tree, &[invalid_parent_child], network, now, HeaderValidationMode::LiveAdmission),
            Err(ChainError::InvalidParent { parent } ) if parent == good_id
        ));
        assert_eq!(tree_shape(&tree), before);

        let early = super::fixture::mine_regtest(genesis.block_hash(), 1, base_time, 4);
        assert!(matches!(
            accept_headers(
                &mut tree,
                &[early],
                network,
                now,
                HeaderValidationMode::LiveAdmission
            ),
            Err(ChainError::TimestampTooEarly { .. })
        ));
        assert_eq!(tree_shape(&tree), before);

        let mismatched_bits = header_with(genesis.block_hash(), base_time + 2600, 0x0100_0000, 12);
        assert!(
            accept_headers(
                &mut tree,
                &[mismatched_bits],
                network,
                now,
                HeaderValidationMode::LiveAdmission
            )
            .is_err()
        );
        assert_eq!(tree_shape(&tree), before);

        let far_future = super::fixture::mine_regtest(genesis.block_hash(), 1, now + 7201, 4);
        assert!(matches!(
            accept_headers(
                &mut tree,
                &[far_future],
                network,
                now,
                HeaderValidationMode::LiveAdmission
            ),
            Err(ChainError::TimestampTooFarAhead { .. })
        ));
        assert_eq!(tree_shape(&tree), before);
        Ok(())
    }
}
