//! BIP9/softfork lookups over a [`BlockTree`].
//!
//! Consensus owns the state machine and deployment parameters. This module
//! owns the tree walk, the BIP9 cache, and the CSV/Segwit snapshot an apply
//! or mining caller needs at a connect height.

use bitcoin_rs_consensus::bip9::versionbits_block_version;
use bitcoin_rs_consensus::{
    CSV_DEPLOYMENT_ID, DeploymentContext, DeploymentParams, DeploymentState, SEGWIT_DEPLOYMENT_ID,
    SoftforkState, compute_state, deployment_params,
};
use bitcoin_rs_primitives::Network;

use crate::{BlockTree, CachedState, NodeId};

const MTP_WINDOW: usize = 11;
const KNOWN_DEPLOYMENT_IDS: [u32; 2] = [CSV_DEPLOYMENT_ID, SEGWIT_DEPLOYMENT_ID];

/// Read-only [`DeploymentContext`] over a [`BlockTree`] rooted at `tip_id`.
pub struct DeploymentView<'a> {
    tree: &'a BlockTree,
    tip_id: NodeId,
}

impl<'a> DeploymentView<'a> {
    /// Anchors lookups at `tip_id` within `tree`.
    #[must_use]
    pub const fn new(tree: &'a BlockTree, tip_id: NodeId) -> Self {
        Self { tree, tip_id }
    }
}

impl DeploymentContext for DeploymentView<'_> {
    fn block_version(&self, height: u32) -> Option<i32> {
        let node_id = self.tree.node_at_height_from(self.tip_id, height)?;
        let node = self.tree.node(node_id).ok()?;
        Some(node.header.version)
    }

    fn median_time_past(&self, height: u32, window: usize) -> Option<u32> {
        let node_id = self.tree.node_at_height_from(self.tip_id, height)?;
        self.tree.median_time_past_at(node_id, window)
    }
}

/// CSV/Segwit contextual state for the block that would extend `previous_tip_id`.
#[must_use]
pub fn softfork_state(
    tree: &BlockTree,
    network: Network,
    previous_tip_id: Option<NodeId>,
    height: u32,
) -> SoftforkState {
    SoftforkState {
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

/// Versionbits candidate version at `height`, using the tree's BIP9 cache.
#[must_use]
pub fn candidate_version(
    tree: &BlockTree,
    network: Network,
    previous_tip_id: NodeId,
    height: u32,
) -> i32 {
    let ctx = DeploymentView::new(tree, previous_tip_id);
    versionbits_block_version(KNOWN_DEPLOYMENT_IDS.iter().filter_map(|&deployment_id| {
        deployment_params(network, deployment_id).map(|params| {
            let state =
                cached_deployment_state(tree, &ctx, previous_tip_id, height, deployment_id, params);
            (params.bit, state)
        })
    }))
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
    let ctx = DeploymentView::new(tree, previous_tip_id);
    Some(
        cached_deployment_state(tree, &ctx, previous_tip_id, height, deployment_id, params)
            == DeploymentState::Active,
    )
}

fn cached_deployment_state(
    tree: &BlockTree,
    ctx: &DeploymentView<'_>,
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

#[cfg(test)]
mod tests {
    use crate::node::NodeStatus;
    use bitcoin_rs_consensus::DeploymentContext;
    use bitcoin_rs_primitives::{BlockHash, Hash256, Header, Network};

    use super::{DeploymentView, softfork_state};
    use crate::BlockTree;

    fn synthetic_header(prev_blockhash: BlockHash, time: u32) -> Header {
        synthetic_header_with_version(prev_blockhash, time, 1)
    }

    fn synthetic_header_with_version(prev_blockhash: BlockHash, time: u32, version: i32) -> Header {
        Header {
            version,
            prev_blockhash,
            merkle_root: Hash256::default(),
            time,
            bits: 0x207f_ffff,
            nonce: 0,
        }
    }

    #[test]
    fn block_version_returns_header_version_at_height() -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let header_0 = synthetic_header(BlockHash::default(), 1_000_000);
        let header_0_hash = header_0.compute_hash();
        tree.insert_header(header_0, NodeStatus::HeaderValid)?;
        let header_1 = synthetic_header(header_0_hash, 1_000_600);
        let tip = tree.insert_header(header_1, NodeStatus::HeaderValid)?;
        let ctx = DeploymentView::new(&tree, tip);

        assert_eq!(ctx.block_version(0), Some(1));
        assert_eq!(ctx.block_version(1), Some(1));
        assert_eq!(ctx.block_version(99), None);
        Ok(())
    }

    #[test]
    fn median_time_past_returns_window_median() -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let mut prev = BlockHash::default();
        let mut tip = None;
        for i in 0..11_u32 {
            let header = synthetic_header(prev, 1_000_000 + i * 600);
            prev = header.compute_hash();
            tip = Some(tree.insert_header(header, NodeStatus::HeaderValid)?);
        }
        let Some(tip) = tip else {
            panic!("chain has 11 blocks should yield a tip");
        };
        let ctx = DeploymentView::new(&tree, tip);
        let Some(mtp) = ctx.median_time_past(10, 11) else {
            panic!("chain has 11 blocks should yield a median time past");
        };

        assert_eq!(mtp, 1_003_000);
        Ok(())
    }

    #[test]
    fn mainnet_csv_activation_matches_consensus_thresholds()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let tip = append_chain(&mut tree, 6048, 1_462_060_800, |height| {
            if (2016..3932).contains(&height) {
                0x2000_0001
            } else {
                0x2000_0000
            }
        })?;

        let state = softfork_state(&tree, Network::Mainnet, Some(tip), 6048);

        assert!(state.csv_active);
        assert!(!state.segwit_active);
        Ok(())
    }

    #[test]
    fn testnet3_segwit_activation_matches_consensus_thresholds()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let tip = append_chain(&mut tree, 6048, 1_462_060_800, |height| {
            if (2016..3528).contains(&height) {
                0x2000_0002
            } else {
                0x2000_0000
            }
        })?;

        let state = softfork_state(&tree, Network::Testnet3, Some(tip), 6048);

        assert!(!state.csv_active);
        assert!(state.segwit_active);
        Ok(())
    }

    fn append_chain(
        tree: &mut BlockTree,
        len: u32,
        start_time: u32,
        version_at: impl Fn(u32) -> i32,
    ) -> Result<crate::NodeId, Box<dyn std::error::Error>> {
        let mut prev = BlockHash::default();
        let mut tip = None;
        for height in 0..len {
            let header = synthetic_header_with_version(
                prev,
                start_time.saturating_add(height.saturating_mul(600)),
                version_at(height),
            );
            prev = header.compute_hash();
            tip = Some(tree.insert_header(header, NodeStatus::HeaderValid)?);
        }
        let Some(tip) = tip else {
            panic!("synthetic chain length must be non-zero");
        };
        Ok(tip)
    }
}
