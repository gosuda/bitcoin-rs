use bitcoin_rs_consensus::MAX_TIMEWARP;
use bitcoin_rs_primitives::{CompactTarget, Hash256, Network};

use pow::target_to_compact;
pub use pow::{compact_is_met_by, compact_to_target};

use crate::{
    ChainError,
    node::{BlockHeader, ChainWork, NodeId, NodeStatus},
    tree::{BlockTree, Inserted},
};

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
    Refused(Box<dyn core::error::Error + Send + Sync>),
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
    if header.time <= median {
        return Err(ChainError::TimestampTooEarly {
            hash: Hash256::from(header.compute_hash()),
            timestamp: header.time,
            median,
        });
    }

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
    let actual = header.bits;
    if actual == expected {
        return Ok(());
    }
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

#[must_use]
pub fn block_work(header: &BlockHeader) -> ChainWork {
    let target = pow::compact_to_target(header.bits);
    if target == ChainWork::ZERO {
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
mod contextual_header_tests;
