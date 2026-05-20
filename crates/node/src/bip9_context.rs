//! Adapter implementing `bitcoin_rs_consensus::DeploymentContext`
//! over `bitcoin_rs_chain::BlockTree`.
//!
//! The consensus crate stays storage-agnostic via the
//! `DeploymentContext` trait; this adapter is the node-crate-side
//! implementation that lets `bitcoin_rs_consensus::compute_state` query
//! historical block versions + MTPs against the in-memory block tree.

use bitcoin_rs_chain::{BlockTree, node::NodeId};
use bitcoin_rs_consensus::DeploymentContext;

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

    use super::BlockTreeContext;

    fn synthetic_header(prev_blockhash: BlockHash, time: u32) -> Header {
        Header {
            version: Version::ONE,
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
}
