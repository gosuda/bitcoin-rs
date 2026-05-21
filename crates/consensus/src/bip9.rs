use crate::ConsensusError;
const VERSIONBITS_TOP_MASK: u32 = 0xe000_0000;
const VERSIONBITS_TOP_BITS: u32 = 0x2000_0000;

/// Versionbits deployment parameters for a BIP9 deployment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deployment {
    /// Bit number signalled in the block version.
    pub bit: u8,
    /// Median-time-past at which signalling starts.
    pub start_time: u32,
    /// Median-time-past at which signalling times out.
    pub timeout: u32,
}
/// BIP9 deployment state at a given block height.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum DeploymentState {
    /// Initial state; deployment not yet started.
    Defined,
    /// Signalling window active; counting votes.
    Started,
    /// Threshold reached; activation pending.
    LockedIn,
    /// Deployment active. Terminal.
    Active,
    /// Deployment failed (timeout reached without lock-in). Terminal.
    Failed,
}

impl DeploymentState {
    /// Encodes this state as a stable cache tag.
    #[must_use]
    pub const fn cache_tag(self) -> u8 {
        match self {
            Self::Defined => 0,
            Self::Started => 1,
            Self::LockedIn => 2,
            Self::Active => 3,
            Self::Failed => 4,
        }
    }

    /// Decodes a stable cache tag.
    #[must_use]
    pub const fn from_cache_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::Defined),
            1 => Some(Self::Started),
            2 => Some(Self::LockedIn),
            3 => Some(Self::Active),
            4 => Some(Self::Failed),
            _ => None,
        }
    }
}

/// Extended deployment parameters for the BIP9 state machine.
///
/// `Deployment` (the older struct) carries only `bit`/`start_time`/`timeout`.
/// `DeploymentParams` adds `period` and `threshold` for the state machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeploymentParams {
    /// Bit number signalled in the block version.
    pub bit: u8,
    /// Median-time-past at which signalling starts.
    pub start_time: u32,
    /// Median-time-past at which signalling times out.
    pub timeout: u32,
    /// Block window size, typically 2016.
    pub period: u32,
    /// Signal count required for `LOCKED_IN`, typically 1916.
    pub threshold: u32,
}

impl DeploymentParams {
    /// Constructs from the simpler `Deployment` with the given window and threshold.
    #[must_use]
    pub const fn from_deployment(deployment: Deployment, period: u32, threshold: u32) -> Self {
        Self {
            bit: deployment.bit,
            start_time: deployment.start_time,
            timeout: deployment.timeout,
            period,
            threshold,
        }
    }
}

/// Read-only chain context the state machine queries.
///
/// The node crate implements this over `bitcoin_rs_chain::BlockTree`; the
/// consensus crate stays agnostic of storage layout.
pub trait DeploymentContext {
    /// Returns the block version field at `height`, or `None` if unknown.
    fn block_version(&self, height: u32) -> Option<i32>;

    /// Returns the median-time-past at `height` over `window` blocks, or `None` if unknown.
    fn median_time_past(&self, height: u32, window: usize) -> Option<u32>;
}

/// Computes the BIP9 deployment state at `height`.
///
/// Walks back to the most recent period boundary <= `height`, then
/// recursively computes the state at the parent boundary, applying
/// transition rules.
///
/// `mtp_window` is the BIP113 MTP window, typically 11.
///
/// Returns `Defined` when `height` is below the first period boundary
/// or when context can't supply the needed data.
#[must_use]
pub fn compute_state(
    ctx: &impl DeploymentContext,
    height: u32,
    params: DeploymentParams,
    mtp_window: usize,
) -> DeploymentState {
    if params.period == 0 {
        return DeploymentState::Defined;
    }

    let boundary = (height / params.period).saturating_mul(params.period);
    compute_state_at_boundary(ctx, boundary, params, mtp_window)
}

fn compute_state_at_boundary(
    ctx: &impl DeploymentContext,
    boundary: u32,
    params: DeploymentParams,
    mtp_window: usize,
) -> DeploymentState {
    if boundary == 0 {
        return DeploymentState::Defined;
    }

    let prior_boundary = boundary.saturating_sub(params.period);
    let prior_state = compute_state_at_boundary(ctx, prior_boundary, params, mtp_window);
    match prior_state {
        DeploymentState::Defined => {
            let Some(mtp) = ctx.median_time_past(boundary.saturating_sub(1), mtp_window) else {
                return DeploymentState::Defined;
            };

            if mtp >= params.timeout {
                DeploymentState::Failed
            } else if mtp >= params.start_time {
                DeploymentState::Started
            } else {
                DeploymentState::Defined
            }
        }
        DeploymentState::Started => {
            let Some(mtp) = ctx.median_time_past(boundary.saturating_sub(1), mtp_window) else {
                return DeploymentState::Started;
            };

            if mtp >= params.timeout {
                return DeploymentState::Failed;
            }

            let Some(mask) = 1_u32.checked_shl(u32::from(params.bit)) else {
                return DeploymentState::Started;
            };

            let window_start = prior_boundary.max(1);
            let window_end = boundary;
            let mut count = 0_u32;
            for height in window_start..window_end {
                let Some(version) = ctx.block_version(height) else {
                    continue;
                };
                let version = u32::from_ne_bytes(version.to_ne_bytes());
                let has_bip9_top_bits = version & VERSIONBITS_TOP_MASK == VERSIONBITS_TOP_BITS;
                if has_bip9_top_bits && version & mask != 0 {
                    count = count.saturating_add(1);
                }
            }

            if count >= params.threshold {
                DeploymentState::LockedIn
            } else {
                DeploymentState::Started
            }
        }
        DeploymentState::LockedIn | DeploymentState::Active => DeploymentState::Active,
        DeploymentState::Failed => DeploymentState::Failed,
    }
}

/// Checks that a block version signals an active BIP9 deployment when required.
pub fn check_bip9(
    version: i32,
    median_time_past: u32,
    deployment: Deployment,
) -> Result<(), ConsensusError> {
    if median_time_past < deployment.start_time || median_time_past >= deployment.timeout {
        return Ok(());
    }
    let bit = u32::from(deployment.bit);
    let Some(mask) = 1u32.checked_shl(bit) else {
        return Err(ConsensusError::Bip {
            bip: "BIP9",
            reason: format!("deployment bit {} is out of range", deployment.bit),
        });
    };
    let version = u32::from_ne_bytes(version.to_ne_bytes());
    if version & mask == 0 {
        return Err(ConsensusError::Bip {
            bip: "BIP9",
            reason: format!("version does not signal bit {}", deployment.bit),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        Deployment, DeploymentContext, DeploymentParams, DeploymentState, check_bip9, compute_state,
    };
    use std::collections::BTreeMap;

    struct SyntheticCtx {
        versions: BTreeMap<u32, i32>,
        mtps: BTreeMap<u32, u32>,
    }

    impl SyntheticCtx {
        fn new() -> Self {
            Self {
                versions: BTreeMap::new(),
                mtps: BTreeMap::new(),
            }
        }
    }

    impl DeploymentContext for SyntheticCtx {
        fn block_version(&self, height: u32) -> Option<i32> {
            self.versions.get(&height).copied()
        }

        fn median_time_past(&self, height: u32, _window: usize) -> Option<u32> {
            self.mtps.get(&height).copied()
        }
    }

    #[test]
    fn active_deployment_accepts_signalled_version() {
        let deployment = Deployment {
            bit: 1,
            start_time: 100,
            timeout: 200,
        };
        assert_eq!(check_bip9(2, 150, deployment), Ok(()));
    }

    #[test]
    fn active_deployment_rejects_missing_signal() {
        let deployment = Deployment {
            bit: 1,
            start_time: 100,
            timeout: 200,
        };
        assert!(check_bip9(0, 150, deployment).is_err());
    }

    #[test]
    fn deployment_starts_when_mtp_crosses_start_time() {
        let params = DeploymentParams {
            bit: 0,
            start_time: 100,
            timeout: 1000,
            period: 10,
            threshold: 8,
        };
        let mut ctx = SyntheticCtx::new();

        ctx.mtps.insert(9, 50);
        assert_eq!(
            compute_state(&ctx, 10, params, 11),
            DeploymentState::Defined
        );

        ctx.mtps.insert(9, 150);
        assert_eq!(
            compute_state(&ctx, 10, params, 11),
            DeploymentState::Started
        );
    }

    #[test]
    fn deployment_locks_in_when_threshold_reached() {
        let params = DeploymentParams {
            bit: 0,
            start_time: 0,
            timeout: 1_000_000,
            period: 10,
            threshold: 8,
        };
        let mut ctx = SyntheticCtx::new();

        ctx.mtps.insert(9, 100);
        ctx.mtps.insert(19, 200);
        for height in 10..20 {
            let version = if height < 18 { 0x2000_0001 } else { 0 };
            ctx.versions.insert(height, version);
        }

        assert_eq!(
            compute_state(&ctx, 20, params, 11),
            DeploymentState::LockedIn
        );

        ctx.mtps.insert(29, 300);
        assert_eq!(compute_state(&ctx, 30, params, 11), DeploymentState::Active);
    }

    #[test]
    fn deployment_does_not_count_signal_without_bip9_top_bits() {
        let params = DeploymentParams {
            bit: 0,
            start_time: 0,
            timeout: 1_000_000,
            period: 10,
            threshold: 8,
        };
        let mut ctx = SyntheticCtx::new();

        ctx.mtps.insert(9, 100);
        ctx.mtps.insert(19, 200);
        for height in 10..20 {
            ctx.versions.insert(height, 1);
        }

        assert_eq!(
            compute_state(&ctx, 20, params, 11),
            DeploymentState::Started
        );
    }

    #[test]
    fn deployment_state_cache_tags_are_stable() {
        let states = [
            DeploymentState::Defined,
            DeploymentState::Started,
            DeploymentState::LockedIn,
            DeploymentState::Active,
            DeploymentState::Failed,
        ];

        for (tag, state) in [
            (0_u8, states[0]),
            (1_u8, states[1]),
            (2_u8, states[2]),
            (3_u8, states[3]),
            (4_u8, states[4]),
        ] {
            assert_eq!(state.cache_tag(), tag);
            assert_eq!(DeploymentState::from_cache_tag(tag), Some(state));
        }
        assert_eq!(DeploymentState::from_cache_tag(5), None);
    }

    #[test]
    fn deployment_fails_on_timeout() {
        let params = DeploymentParams {
            bit: 0,
            start_time: 100,
            timeout: 500,
            period: 10,
            threshold: 8,
        };
        let mut ctx = SyntheticCtx::new();

        ctx.mtps.insert(9, 200);
        ctx.mtps.insert(19, 600);
        for height in 10..20 {
            ctx.versions.insert(height, 0);
        }

        assert_eq!(compute_state(&ctx, 20, params, 11), DeploymentState::Failed);
    }
}
