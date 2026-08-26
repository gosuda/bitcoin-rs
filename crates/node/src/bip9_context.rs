//! One contextual consensus/chain source for the next block candidate.
//!
//! The consensus crate stays storage-agnostic via the `DeploymentContext`
//! trait; `BlockTreeContext` is the node-crate adapter that lets
//! `bitcoin_rs_consensus::compute_state` query historical block versions and
//! MTPs against the in-memory block tree. `MiningChainContext` resolves every
//! contextual fact a candidate needs — versionbits version, next work,
//! minimum time, and the BIP113 finality cutoff rule — from that one adapter,
//! and `check_candidate_header` dry-runs a proposal through the same
//! validators full validation applies. The tree's `Bip9Cache` memoizes only
//! this module's deployment-state walks.

use bitcoin::pow::CompactTarget;
use bitcoin_rs_chain::{
    BlockTree, CachedState, ChainError, header_sync,
    node::{BlockHeader, NodeId},
};
use bitcoin_rs_consensus::bip9::versionbits_block_version;
use bitcoin_rs_consensus::{DeploymentContext, DeploymentParams, DeploymentState, compute_state};
use bitcoin_rs_primitives::{Hash256, Network};

const MTP_WINDOW: usize = 11;
const BIP9_PERIOD: u32 = 2016;
const MAINNET_THRESHOLD: u32 = 1916;
const TESTNET3_THRESHOLD: u32 = 1512;
const CSV_DEPLOYMENT_ID: u32 = 0;
const SEGWIT_DEPLOYMENT_ID: u32 = 1;

/// Read-only adapter over a `BlockTree` rooted at a chosen tip.
///
/// All lookups walk backward from `start_tip_id` via parent pointers.
/// Callers typically pass the current chain tip as `start_tip_id` so
/// the adapter answers queries against the active chain.
pub struct BlockTreeContext<'a> {
    tree: &'a BlockTree,
    start_tip_id: NodeId,
}

impl<'a> BlockTreeContext<'a> {
    /// Constructs an adapter anchored at `start_tip_id` within `tree`.
    #[must_use]
    pub const fn new(tree: &'a BlockTree, start_tip_id: NodeId) -> Self {
        Self { tree, start_tip_id }
    }
}

/// Deployment ids this node tracks for versionbits; the cache and candidate
/// version never cover deployments outside this list.
const KNOWN_DEPLOYMENT_IDS: [u32; 2] = [CSV_DEPLOYMENT_ID, SEGWIT_DEPLOYMENT_ID];

/// Contextual facts for the block that would extend `previous_tip_id`.
///
/// The one source candidate builders and proposal checks consume: the
/// versionbits version, the next required work, the earliest legal timestamp,
/// and the inputs to BIP113 finality. Every field comes from the shared
/// consensus/chain primitives — [`versionbits_block_version`] over the cached
/// deployment states, [`header_sync::next_work_required`], and the tree's
/// median-time-past — so mining never re-derives what validation enforces.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MiningChainContext {
    /// Parent header hash in consensus little-endian storage order.
    pub previous_block_hash: Hash256,
    /// Height the candidate would have.
    pub height: u32,
    /// Versionbits candidate version: top bits set plus every `Started` or
    /// `LockedIn` deployment bit.
    pub version: i32,
    /// Compact target the candidate's nBits must equal.
    pub bits: CompactTarget,
    /// Earliest timestamp the candidate may carry: previous-tip MTP + 1.
    pub min_time: u32,
    /// Median time past of the previous tip over the BIP113 window.
    pub prev_median_time_past: u32,
    /// Whether CSV (BIP68/112/113) is active at the candidate's height.
    pub csv_active: bool,
    /// Whether Segwit (BIP141/143) is active at the candidate's height.
    pub segwit_active: bool,
}

impl MiningChainContext {
    /// Resolves the context for the block extending `previous_tip_id`.
    ///
    /// `candidate_time` is the timestamp the candidate would carry; it feeds
    /// the minimum-difficulty branch of [`header_sync::next_work_required`],
    /// exactly as the candidate's header time would during validation.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError::UnknownNode`] when `previous_tip_id` is not in
    /// the tree and [`ChainError::HeightOverflow`] at the last height.
    pub fn resolve(
        tree: &BlockTree,
        network: Network,
        previous_tip_id: NodeId,
        candidate_time: u32,
    ) -> Result<Self, ChainError> {
        let parent = tree.node(previous_tip_id)?;
        let height = parent
            .height
            .checked_add(1)
            .ok_or(ChainError::HeightOverflow {
                parent: previous_tip_id,
            })?;
        let softfork = contextual_softfork_state(tree, network, Some(previous_tip_id), height);
        let prev_median_time_past = tree
            .median_time_past_at(previous_tip_id, MTP_WINDOW)
            .ok_or(ChainError::UnknownNode {
                id: previous_tip_id,
            })?;
        Ok(Self {
            previous_block_hash: parent.hash,
            height,
            version: candidate_version(tree, network, previous_tip_id, height),
            bits: header_sync::next_work_required(tree, previous_tip_id, candidate_time, network)?,
            min_time: prev_median_time_past.saturating_add(1),
            prev_median_time_past,
            csv_active: softfork.csv_active,
            segwit_active: softfork.segwit_active,
        })
    }

    /// BIP113 locktime cutoff for a candidate carrying `candidate_time`.
    #[must_use]
    pub const fn locktime_cutoff(&self, candidate_time: u32) -> u32 {
        locktime_cutoff(self.csv_active, self.prev_median_time_past, candidate_time)
    }
}

/// BIP113 locktime-cutoff selection: the one rule every caller shares.
///
/// While CSV is active the cutoff is the previous tip's median-time-past;
/// before activation it is the candidate block's own header time. Apply paths,
/// templates, and proposal checks all feed this to
/// `bitcoin_rs_consensus::is_final_tx` so finality has one contextual
/// definition instead of per-callsite arithmetic.
#[must_use]
pub const fn locktime_cutoff(
    csv_active: bool,
    prev_median_time_past: u32,
    candidate_time: u32,
) -> u32 {
    if csv_active {
        prev_median_time_past
    } else {
        candidate_time
    }
}

/// Dry-run contextual check for a proposed block header.
///
/// Runs exactly the contextual validators full validation runs — nBits via
/// [`header_sync::validate_header_nbits`] and the median-time-past/future
/// bounds via [`header_sync::validate_header_timestamp`] — without mutating
/// the tree, so a proposal verdict and a later apply verdict cannot disagree
/// by construction.
///
/// # Errors
///
/// Propagates the underlying [`ChainError`] from either validator.
pub fn check_candidate_header(
    tree: &BlockTree,
    network: Network,
    previous_tip_id: NodeId,
    header: &BlockHeader,
    hash: Hash256,
    now_secs: u32,
) -> Result<(), ChainError> {
    header_sync::validate_header_nbits(tree, previous_tip_id, header, network)?;
    header_sync::validate_header_timestamp(tree, header, hash, now_secs)
}

/// CSV/Segwit contextual state for the block currently being connected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ContextualSoftforkState {
    pub(crate) csv_active: bool,
    pub(crate) segwit_active: bool,
}

/// Computes contextual CSV/Segwit state for a block that extends `previous_tip_id`.
#[must_use]
pub(crate) fn contextual_softfork_state(
    tree: &BlockTree,
    network: Network,
    previous_tip_id: Option<NodeId>,
    height: u32,
) -> ContextualSoftforkState {
    ContextualSoftforkState {
        csv_active: deployment_active(tree, network, previous_tip_id, height, CSV_DEPLOYMENT_ID)
            .unwrap_or_else(|| network.is_csv_active(height)),
        segwit_active: deployment_active(
            tree,
            network,
            previous_tip_id,
            height,
            SEGWIT_DEPLOYMENT_ID,
        )
        .unwrap_or_else(|| network.is_segwit_active(height)),
    }
}

fn deployment_active(
    tree: &BlockTree,
    network: Network,
    previous_tip_id: Option<NodeId>,
    height: u32,
    deployment_id: u32,
) -> Option<bool> {
    let params = deployment_params(network, deployment_id)?;
    let Some(previous_tip_id) = previous_tip_id else {
        return Some(false);
    };
    let ctx = BlockTreeContext::new(tree, previous_tip_id);
    Some(
        cached_deployment_state(tree, &ctx, previous_tip_id, height, deployment_id, params)
            == DeploymentState::Active,
    )
}

fn cached_deployment_state(
    tree: &BlockTree,
    ctx: &BlockTreeContext<'_>,
    previous_tip_id: NodeId,
    height: u32,
    deployment_id: u32,
    params: DeploymentParams,
) -> DeploymentState {
    let period_start = (height / params.period).saturating_mul(params.period);
    if period_start == 0 {
        return compute_state(ctx, height, params, MTP_WINDOW);
    }

    let anchor_height = period_start.saturating_sub(1);
    let Some(anchor_node) = tree.node_at_height_from(previous_tip_id, anchor_height) else {
        return compute_state(ctx, height, params, MTP_WINDOW);
    };
    if let Some(cached) = tree.cached_bip9_state(anchor_node, deployment_id)
        && let Some(state) = DeploymentState::from_cache_tag(cached.tag)
    {
        return state;
    }

    let state = compute_state(ctx, height, params, MTP_WINDOW);
    tree.cache_bip9_state(
        anchor_node,
        deployment_id,
        CachedState {
            tag: state.cache_tag(),
            since_height: period_start,
        },
    );
    state
}

/// Resolves the versionbits candidate version at `height` through the cached
/// deployment-state path, keeping the BIP9 cache owned by this one source.
fn candidate_version(
    tree: &BlockTree,
    network: Network,
    previous_tip_id: NodeId,
    height: u32,
) -> i32 {
    let ctx = BlockTreeContext::new(tree, previous_tip_id);
    versionbits_block_version(KNOWN_DEPLOYMENT_IDS.iter().filter_map(|&deployment_id| {
        deployment_params(network, deployment_id).map(|params| {
            let state =
                cached_deployment_state(tree, &ctx, previous_tip_id, height, deployment_id, params);
            (params.bit, state)
        })
    }))
}

fn deployment_params(network: Network, deployment_id: u32) -> Option<DeploymentParams> {
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

impl DeploymentContext for BlockTreeContext<'_> {
    fn block_version(&self, height: u32) -> Option<i32> {
        let node_id = self.tree.node_at_height_from(self.start_tip_id, height)?;
        let node = self.tree.node(node_id).ok()?;
        Some(node.header.version.to_consensus())
    }

    fn median_time_past(&self, height: u32, window: usize) -> Option<u32> {
        let node_id = self.tree.node_at_height_from(self.start_tip_id, height)?;
        self.tree.median_time_past_at(node_id, window)
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::block::{Header, Version};
    use bitcoin::hashes::Hash as _;
    use bitcoin::{BlockHash, CompactTarget, TxMerkleNode};
    use bitcoin_rs_chain::{BlockTree, ChainError, node::NodeStatus};
    use bitcoin_rs_consensus::DeploymentContext;
    use bitcoin_rs_primitives::{Hash256, Network};

    use super::{
        BlockTreeContext, MiningChainContext, check_candidate_header, contextual_softfork_state,
        locktime_cutoff,
    };

    fn synthetic_header(prev_blockhash: BlockHash, time: u32) -> Header {
        synthetic_header_with_version(prev_blockhash, time, 1)
    }

    fn synthetic_header_with_version(prev_blockhash: BlockHash, time: u32, version: i32) -> Header {
        Header {
            version: Version::from_consensus(version),
            prev_blockhash,
            merkle_root: TxMerkleNode::all_zeros(),
            time,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        }
    }

    #[test]
    fn block_version_returns_header_version_at_height() -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let header_0 = synthetic_header(BlockHash::all_zeros(), 1_000_000);
        let header_0_hash = header_0.block_hash();
        tree.insert_header(header_0, NodeStatus::HeaderValid)?;
        let header_1 = synthetic_header(header_0_hash, 1_000_600);
        let tip = tree.insert_header(header_1, NodeStatus::HeaderValid)?;
        let ctx = BlockTreeContext::new(&tree, tip);

        assert_eq!(ctx.block_version(0), Some(1));
        assert_eq!(ctx.block_version(1), Some(1));
        assert_eq!(ctx.block_version(99), None);
        Ok(())
    }

    #[test]
    fn median_time_past_returns_window_median() -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let mut prev = BlockHash::all_zeros();
        let mut tip = None;
        for i in 0..11_u32 {
            let header = synthetic_header(prev, 1_000_000 + i * 600);
            prev = header.block_hash();
            tip = Some(tree.insert_header(header, NodeStatus::HeaderValid)?);
        }
        let Some(tip) = tip else {
            panic!("chain has 11 blocks should yield a tip");
        };
        let ctx = BlockTreeContext::new(&tree, tip);
        let Some(mtp) = ctx.median_time_past(10, 11) else {
            panic!("chain has 11 blocks should yield a median time past");
        };

        assert_eq!(mtp, 1_003_000);
        Ok(())
    }

    #[test]
    fn mainnet_csv_activation_uses_cached_bip9_state() -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let tip = append_chain(&mut tree, 6048, 1_462_060_800, |height| {
            if (2016..3932).contains(&height) {
                0x2000_0001
            } else {
                0x2000_0000
            }
        })?;

        let state = contextual_softfork_state(&tree, Network::Mainnet, Some(tip), 6048);

        assert!(state.csv_active);
        assert!(!state.segwit_active);
        assert_eq!(tree.cached_bip9_state_len(), 2);
        let cached_state = contextual_softfork_state(&tree, Network::Mainnet, Some(tip), 6048);
        assert_eq!(cached_state, state);
        assert_eq!(tree.cached_bip9_state_len(), 2);
        Ok(())
    }

    #[test]
    fn testnet3_segwit_activation_uses_testnet_threshold() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut tree = BlockTree::new();
        let tip = append_chain(&mut tree, 6048, 1_462_060_800, |height| {
            if (2016..3528).contains(&height) {
                0x2000_0002
            } else {
                0x2000_0000
            }
        })?;

        let state = contextual_softfork_state(&tree, Network::Testnet3, Some(tip), 6048);

        assert!(!state.csv_active);
        assert!(state.segwit_active);
        assert_eq!(tree.cached_bip9_state_len(), 2);
        let cached_state = contextual_softfork_state(&tree, Network::Testnet3, Some(tip), 6048);
        assert_eq!(cached_state, state);
        assert_eq!(tree.cached_bip9_state_len(), 2);
        Ok(())
    }

    #[test]
    fn mining_context_resolves_regtest_candidate_facts() -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let chain_bits = CompactTarget::from_consensus(0x207f_fffe);
        let tip = append_chain_with_bits(&mut tree, 12, 1_000_000, |_| 0x2000_0000, chain_bits)?;
        let tip_hash = tree.node(tip)?.hash;
        let tip_time = 1_000_000 + 11 * 600;

        let context = MiningChainContext::resolve(&tree, Network::Regtest, tip, tip_time + 600)?;
        assert_eq!(context.previous_block_hash, tip_hash);
        assert_eq!(context.height, 12);
        // Regtest has no tracked deployments: only the versionbits top bits.
        assert_eq!(
            u32::from_ne_bytes(context.version.to_ne_bytes()),
            0x2000_0000
        );
        // Inside the 2*spacing window the candidate inherits the parent bits.
        assert_eq!(context.bits, chain_bits);
        // The 11-block window at the tip drops the oldest of 12 times
        // 1_000_000 + h*600, leaving median 1_000_000 + 6*600.
        assert_eq!(context.prev_median_time_past, 1_000_000 + 6 * 600);
        assert_eq!(context.min_time, 1_000_000 + 6 * 600 + 1);
        assert!(!context.csv_active);
        assert!(context.segwit_active);
        // CSV is inactive below regtest's height-432 activation, so the
        // cutoff is the candidate's own time.
        assert_eq!(context.locktime_cutoff(tip_time + 600), tip_time + 600);

        // A candidate timestamp past the 2*spacing window recovers minimum
        // difficulty: exactly the regtest proof-of-work limit.
        let recovered = MiningChainContext::resolve(&tree, Network::Regtest, tip, tip_time + 1201)?;
        assert_eq!(recovered.bits, CompactTarget::from_consensus(0x207f_ffff));

        // Resolving against a node the tree does not hold is an error, not a guess.
        let unknown = bitcoin_rs_chain::node::NodeId::new(u32::MAX);
        assert_eq!(
            MiningChainContext::resolve(&tree, Network::Regtest, unknown, 0),
            Err(ChainError::UnknownNode { id: unknown })
        );
        Ok(())
    }

    #[test]
    fn mining_context_version_signals_started_and_clears_active_bits()
    -> Result<(), Box<dyn std::error::Error>> {
        // Mainnet CSV: the period containing the query only just started, so
        // the deployment is Started and its bit must be signalled.
        let mut tree = BlockTree::new();
        let tip = append_chain(&mut tree, 3000, 1_462_060_800, |height| {
            if height >= 2016 {
                0x2000_0001
            } else {
                0x2000_0000
            }
        })?;
        let started =
            MiningChainContext::resolve(&tree, Network::Mainnet, tip, 1_462_060_800 + 3000 * 600)?;
        assert_eq!(
            u32::from_ne_bytes(started.version.to_ne_bytes()),
            0x2000_0001
        );
        assert!(!started.csv_active);
        assert_eq!(started.locktime_cutoff(7), 7);

        // Once CSV is Active its bit is cleared, exactly as Core's
        // ComputeBlockVersion does, and the cutoff becomes the previous tip's
        // median-time-past regardless of the candidate time.
        let mut tree = BlockTree::new();
        let tip = append_chain(&mut tree, 6048, 1_462_060_800, |height| {
            if (2016..3932).contains(&height) {
                0x2000_0001
            } else {
                0x2000_0000
            }
        })?;
        let active =
            MiningChainContext::resolve(&tree, Network::Mainnet, tip, 1_462_060_800 + 6048 * 600)?;
        assert_eq!(
            u32::from_ne_bytes(active.version.to_ne_bytes()),
            0x2000_0000
        );
        assert!(active.csv_active);
        assert_eq!(
            active.locktime_cutoff(u32::MAX),
            active.prev_median_time_past
        );
        Ok(())
    }

    #[test]
    fn locktime_cutoff_rule_switches_on_csv_activation() {
        assert_eq!(locktime_cutoff(true, 500, 999), 500);
        assert_eq!(locktime_cutoff(false, 500, 999), 999);
    }

    #[test]
    fn check_candidate_header_shares_full_validation_verdicts()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let chain_bits = CompactTarget::from_consensus(0x207f_fffe);
        let tip = append_chain_with_bits(&mut tree, 12, 1_000_000, |_| 0x2000_0000, chain_bits)?;
        let context = MiningChainContext::resolve(&tree, Network::Regtest, tip, 1_003_600 + 600)?;
        let tip_blockhash = BlockHash::from_byte_array(context.previous_block_hash.to_le_bytes());

        // The context's own facts satisfy the dry-run: what a candidate is
        // built from is exactly what validation accepts.
        let candidate = candidate_header(tip_blockhash, context.min_time, context.bits);
        let hash = Hash256::from_le_bytes(candidate.block_hash().as_byte_array());
        check_candidate_header(&tree, Network::Regtest, tip, &candidate, hash, u32::MAX)?;

        // Wrong bits draw the same error a full apply would produce.
        let bad_bits = candidate_header(
            tip_blockhash,
            context.min_time,
            CompactTarget::from_consensus(0x207f_fffd),
        );
        let hash = Hash256::from_le_bytes(bad_bits.block_hash().as_byte_array());
        assert!(matches!(
            check_candidate_header(&tree, Network::Regtest, tip, &bad_bits, hash, u32::MAX),
            Err(ChainError::NbitsMismatch { .. })
        ));

        // A timestamp at the previous-tip MTP is not strictly greater than it.
        let early = candidate_header(tip_blockhash, context.prev_median_time_past, context.bits);
        let hash = Hash256::from_le_bytes(early.block_hash().as_byte_array());
        assert!(matches!(
            check_candidate_header(&tree, Network::Regtest, tip, &early, hash, u32::MAX),
            Err(ChainError::TimestampTooEarly { .. })
        ));
        Ok(())
    }

    fn candidate_header(prev_blockhash: BlockHash, time: u32, bits: CompactTarget) -> Header {
        Header {
            version: Version::from_consensus(0x2000_0000),
            prev_blockhash,
            merkle_root: TxMerkleNode::all_zeros(),
            time,
            bits,
            nonce: 0,
        }
    }

    fn append_chain(
        tree: &mut BlockTree,
        len: u32,
        start_time: u32,
        version_at: impl Fn(u32) -> i32,
    ) -> Result<bitcoin_rs_chain::node::NodeId, Box<dyn std::error::Error>> {
        append_chain_with_bits(
            tree,
            len,
            start_time,
            version_at,
            CompactTarget::from_consensus(0x207f_ffff),
        )
    }

    fn append_chain_with_bits(
        tree: &mut BlockTree,
        len: u32,
        start_time: u32,
        version_at: impl Fn(u32) -> i32,
        bits: CompactTarget,
    ) -> Result<bitcoin_rs_chain::node::NodeId, Box<dyn std::error::Error>> {
        let mut prev = BlockHash::all_zeros();
        let mut tip = None;
        for height in 0..len {
            let mut header = synthetic_header_with_version(
                prev,
                start_time.saturating_add(height.saturating_mul(600)),
                version_at(height),
            );
            header.bits = bits;
            prev = header.block_hash();
            tip = Some(tree.insert_header(header, NodeStatus::HeaderValid)?);
        }
        let Some(tip) = tip else {
            panic!("synthetic chain length must be non-zero");
        };
        Ok(tip)
    }
}
