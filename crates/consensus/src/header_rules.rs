use crate::MAX_TIMEWARP;
use crate::primitives::{CompactTarget, Hash256, Header, Network};

pub type ChainWork = ruint::Uint<256, 4>;
pub type BlockHeader = Header;

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone, Copy)]
pub enum HeaderRuleError {
    #[error("header {hash} has zero proof-of-work target")]
    ZeroTarget { hash: Hash256 },
    #[error("header {hash} target {target} exceeds network limit {max_target}")]
    TargetExceedsLimit {
        hash: Hash256,
        target: ChainWork,
        max_target: ChainWork,
    },
    #[error("nBits {bits:08x} overflows the 256-bit proof-of-work target")]
    TargetBitsOverflow { bits: u32 },
    #[error("header {hash} does not satisfy proof of work target {target}")]
    InvalidPow { hash: Hash256, target: ChainWork },
}

pub fn minimum_candidate_time(parent_time: u32, height: u32, network: Network) -> Option<u32> {
    let retarget_interval = network.retarget_interval();
    (retarget_interval != 0 && height.is_multiple_of(retarget_interval))
        .then(|| parent_time.saturating_sub(MAX_TIMEWARP))
}

pub fn validate_pow(
    header: &Header,
    hash: Hash256,
    network: Network,
) -> Result<(), HeaderRuleError> {
    if pow::compact_overflows(header.bits) {
        return Err(HeaderRuleError::TargetBitsOverflow {
            bits: header.bits.to_consensus(),
        });
    }
    let target = pow::compact_to_target(header.bits);
    if target == ChainWork::ZERO {
        return Err(HeaderRuleError::ZeroTarget { hash });
    }

    let max_target = network.max_target();
    if target > max_target {
        return Err(HeaderRuleError::TargetExceedsLimit {
            hash,
            target,
            max_target,
        });
    }

    if !pow::compact_is_met_by(header.bits, hash) {
        return Err(HeaderRuleError::InvalidPow { hash, target });
    }

    Ok(())
}

#[must_use]
pub fn block_work(header: &Header) -> ChainWork {
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

pub fn pow_limit_bits(network: Network) -> CompactTarget {
    pow::target_to_compact(network.max_target())
}
pub use pow::compact_is_met_by;

pub mod pow {
    use super::ChainWork;
    use crate::primitives::{CompactTarget, Hash256};

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
    pub fn compact_overflows(bits: CompactTarget) -> bool {
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
    pub fn target_to_compact(target: ChainWork) -> CompactTarget {
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
