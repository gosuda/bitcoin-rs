//! Adapter implementing `bitcoin_rs_consensus::DeploymentContext`
//! over `bitcoin_rs_chain::BlockTree`.
//!
//! The consensus crate stays storage-agnostic via the
//! `DeploymentContext` trait; this adapter is the node-crate-side
//! implementation that lets `bitcoin_rs_consensus::compute_state` query
//! historical block versions + MTPs against the in-memory block tree.

use bitcoin_rs_chain::{BlockTree, CachedState, node::NodeId};
use bitcoin_rs_consensus::{DeploymentContext, DeploymentParams, DeploymentState, compute_state};
use bitcoin_rs_primitives::Network;

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
    use bitcoin_rs_chain::{BlockTree, node::NodeStatus};
    use bitcoin_rs_consensus::DeploymentContext;
    use bitcoin_rs_primitives::Network;

    use super::{BlockTreeContext, contextual_softfork_state};

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

    fn append_chain(
        tree: &mut BlockTree,
        len: u32,
        start_time: u32,
        version_at: impl Fn(u32) -> i32,
    ) -> Result<bitcoin_rs_chain::node::NodeId, Box<dyn std::error::Error>> {
        let mut prev = BlockHash::all_zeros();
        let mut tip = None;
        for height in 0..len {
            let header = synthetic_header_with_version(
                prev,
                start_time.saturating_add(height.saturating_mul(600)),
                version_at(height),
            );
            prev = header.block_hash();
            tip = Some(tree.insert_header(header, NodeStatus::HeaderValid)?);
        }
        let Some(tip) = tip else {
            panic!("synthetic chain length must be non-zero");
        };
        Ok(tip)
    }
}
