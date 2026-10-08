use bitcoin_rs_primitives::Network;

/// BIP9 signalling period length in blocks.
pub const BIP9_PERIOD: u32 = 2016;
/// Deployment id for CSV (BIP68/112/113).
pub const CSV_DEPLOYMENT_ID: u32 = 0;
/// Deployment id for Segwit (BIP141/143).
pub const SEGWIT_DEPLOYMENT_ID: u32 = 1;
const MAINNET_THRESHOLD: u32 = 1916;
const TESTNET3_THRESHOLD: u32 = 1512;
const VERSIONBITS_TOP_MASK: u32 = 0xe000_0000;
const VERSIONBITS_TOP_BITS: u32 = 0x2000_0000;

/// BIP9 deployment state at a given block height.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum DeploymentState {
    /// Initial state; deployment not yet started.
    Defined,
    /// Signalling window active; counting votes.
    Started,
    /// Threshold reached; activation pending.
    LockedIn,
    /// Deployment active.
    Active,
    /// Deployment failed (timeout reached without lock-in).
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

/// CSV/Segwit activation at one connect height.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SoftforkState {
    /// Whether CSV (BIP68/112/113) is active.
    pub csv_active: bool,
    /// Whether Segwit (BIP141/143) is active.
    pub segwit_active: bool,
}

/// Versionbits parameters for a named deployment on `network`.
#[must_use]
pub const fn deployment_params(network: Network, deployment_id: u32) -> Option<DeploymentParams> {
    let threshold = match network {
        Network::Mainnet => MAINNET_THRESHOLD,
        Network::Testnet3 => TESTNET3_THRESHOLD,
        Network::Testnet4 | Network::Signet | Network::Regtest => return None,
    };
    match deployment_id {
        CSV_DEPLOYMENT_ID => Some(DeploymentParams {
            bit: 0,
            start_time: match network {
                Network::Mainnet => 1_462_060_800,
                Network::Testnet3 => 1_456_790_400,
                Network::Testnet4 | Network::Signet | Network::Regtest => return None,
            },
            timeout: 1_493_596_800,
            period: BIP9_PERIOD,
            threshold,
        }),
        SEGWIT_DEPLOYMENT_ID => Some(DeploymentParams {
            bit: 1,
            start_time: match network {
                Network::Mainnet => 1_479_168_000,
                Network::Testnet3 => 1_462_060_800,
                Network::Testnet4 | Network::Signet | Network::Regtest => return None,
            },
            timeout: match network {
                Network::Mainnet => 1_510_704_000,
                Network::Testnet3 => 1_493_596_800,
                Network::Testnet4 | Network::Signet | Network::Regtest => return None,
            },
            period: BIP9_PERIOD,
            threshold,
        }),
        _ => None,
    }
}

/// Read-only chain context the state machine queries.
pub trait DeploymentContext {
    /// Returns the block version field at `height`, or `None` if unknown.
    fn block_version(&self, height: u32) -> Option<i32>;

    /// Returns the median-time-past at `height` over `window` blocks, or `None` if
    /// unknown.
    fn median_time_past(&self, height: u32, window: usize) -> Option<u32>;
}

/// Computes the BIP9 deployment state at `height`.
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
/// Builds the version field for a candidate block from already-resolved BIP9
/// states.
#[must_use]
pub fn versionbits_block_version(
    deployments: impl IntoIterator<Item = (u8, DeploymentState)>,
) -> i32 {
    let mut version = VERSIONBITS_TOP_BITS;
    for (bit, state) in deployments {
        if !matches!(state, DeploymentState::Started | DeploymentState::LockedIn) {
            continue;
        }
        if let Some(mask) = 1_u32.checked_shl(u32::from(bit))
            && mask & !VERSIONBITS_TOP_MASK != 0
        {
            version |= mask;
        }
    }
    i32::from_ne_bytes(version.to_ne_bytes())
}

#[cfg(test)]
mod tests {
    use super::{
        DeploymentContext, DeploymentParams, DeploymentState, compute_state,
        versionbits_block_version,
    };
    use std::collections::BTreeMap;

    struct SyntheticCtx {
        versions: BTreeMap<u32, i32>,
        mtps: BTreeMap<u32, u32>,
    }

    impl DeploymentContext for SyntheticCtx {
        fn block_version(&self, height: u32) -> Option<i32> {
            self.versions.get(&height).copied()
        }

        fn median_time_past(&self, height: u32, _window: usize) -> Option<u32> {
            self.mtps.get(&height).copied()
        }
    }

    type StateCase<'a> = (
        DeploymentParams,
        &'a [(u32, u32)],
        &'a [(u32, i32)],
        u32,
        DeploymentState,
    );

    #[test]
    fn deployment_state_machine_follows_mtp_and_signal_windows() {
        let params = |start_time, timeout| DeploymentParams {
            bit: 0,
            start_time,
            timeout,
            period: 10,
            threshold: 8,
        };
        let signalling: Vec<(u32, i32)> = (10..20)
            .map(|height| (height, if height < 18 { 0x2000_0001 } else { 0 }))
            .collect();
        let no_top_bits: Vec<(u32, i32)> = (10..20).map(|height| (height, 1)).collect();
        let silent: Vec<(u32, i32)> = (10..20).map(|height| (height, 0)).collect();

        let cases: [StateCase<'_>; 6] = [
            (
                params(100, 1000),
                &[(9, 50)],
                &[],
                10,
                DeploymentState::Defined,
            ),
            (
                params(100, 1000),
                &[(9, 150)],
                &[],
                10,
                DeploymentState::Started,
            ),
            (
                params(0, 1_000_000),
                &[(9, 100), (19, 200)],
                &signalling,
                20,
                DeploymentState::LockedIn,
            ),
            (
                params(0, 1_000_000),
                &[(9, 100), (19, 200), (29, 300)],
                &signalling,
                30,
                DeploymentState::Active,
            ),
            (
                params(0, 1_000_000),
                &[(9, 100), (19, 200)],
                &no_top_bits,
                20,
                DeploymentState::Started,
            ),
            (
                params(100, 500),
                &[(9, 200), (19, 600)],
                &silent,
                20,
                DeploymentState::Failed,
            ),
        ];

        for (params, mtps, versions, height, expected) in cases {
            let ctx = SyntheticCtx {
                versions: versions.iter().copied().collect(),
                mtps: mtps.iter().copied().collect(),
            };
            assert_eq!(
                compute_state(&ctx, height, params, 11),
                expected,
                "{params:?} at {height}"
            );
        }
    }

    #[test]
    fn deployment_state_cache_tags_are_stable() {
        for (tag, state) in [
            (0_u8, DeploymentState::Defined),
            (1, DeploymentState::Started),
            (2, DeploymentState::LockedIn),
            (3, DeploymentState::Active),
            (4, DeploymentState::Failed),
        ] {
            assert_eq!(state.cache_tag(), tag);
            assert_eq!(DeploymentState::from_cache_tag(tag), Some(state));
        }
        assert_eq!(DeploymentState::from_cache_tag(5), None);
    }

    #[test]
    fn candidate_version_signals_only_started_and_locked_in_deployments() {
        let version = versionbits_block_version([
            (0, DeploymentState::Defined),
            (1, DeploymentState::Started),
            (2, DeploymentState::LockedIn),
            (3, DeploymentState::Active),
            (4, DeploymentState::Failed),
            (31, DeploymentState::Started),
        ]);

        assert_eq!(u32::from_ne_bytes(version.to_ne_bytes()), 0x2000_0006);
    }
}
