use bitcoin_rs_consensus::primitives::{BlockHash, Hash256, Header};
use bitcoin_rs_execution::chain::BlockTree;
pub use bitcoin_rs_execution::events::ChainSnapshot;

use crate::{Node, NodeError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeaderInfo {
    pub header: Header,
    pub height: u32,
    pub chainwork: [u8; 32],
}

pub struct ChainSubscription {
    cursor: ChainSnapshot,
}

#[derive(Clone, Debug)]
pub struct ChainTarget {
    snapshot: ChainSnapshot,
    source: std::sync::Weak<bitcoin_rs_execution::Chainstate>,
}

impl ChainTarget {
    #[must_use]
    pub const fn snapshot(&self) -> ChainSnapshot {
        self.snapshot
    }
}

impl ChainSubscription {
    #[must_use]
    pub const fn cursor(&self) -> ChainSnapshot {
        self.cursor
    }
}

#[derive(Clone, Debug)]
pub struct ChainUpdate {
    pub previous: ChainSnapshot,
    pub current: ChainTarget,
    pub gap: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChainStep {
    Connected(BlockHeaderInfo),
    Disconnected(BlockHeaderInfo),
}

pub struct ChainReplay {
    pub steps: Vec<ChainStep>,
    pub position: BlockHash,
    pub target: ChainTarget,
    pub complete: bool,
}

const MAX_REPLAY_STEPS: usize = 256;
const MAX_ANCESTRY_HOPS: usize = 4096;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestError;
    use bitcoin_rs_consensus::primitives::{Block, BlockImage, Network};
    use bitcoin_rs_execution::chain::regtest_fixture;
    use std::{
        future::Future,
        task::{Context, Poll, Waker},
    };

    fn run<F: Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        match future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("node operation unexpectedly parked"),
        }
    }

    fn config(dir: &std::path::Path) -> crate::NodeConfig {
        let mut config = crate::NodeConfig::default_for_network(Network::Regtest);
        config.data_dir = dir.join("node");
        config.p2p.listen.clear();
        config.p2p.connect.clear();
        config.rpc.bind.set_port(0);
        config.observability.metrics_bind = None;
        config
    }

    fn block(parent: BlockHash, height: u32, tag: u32) -> Result<Block, TestError> {
        let txs = vec![regtest_fixture::coinbase(height)];
        let mut block = Block {
            header: Header {
                prev_blockhash: parent,
                version: 0x2000_0000,
                merkle_root: regtest_fixture::merkle_root(&txs)
                    .ok_or(TestError::Missing("merkle root"))?,
                time: 1_296_688_603 + height * 600 + tag,
                bits: Network::Regtest.genesis_block().header.bits,
                nonce: 0,
            },
            txs,
        };
        regtest_fixture::mine_block_to_declared_target(&mut block)?;
        Ok(block)
    }

    // EVT-06, MPS-04
    #[test]
    fn settled_poll_replays_gaps_disconnects_and_pinned_targets() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let node = run(Node::start(
            config(dir.path()),
            crate::RuntimeInputs::default(),
        ))?;
        let genesis = node.snapshot().tip_hash.into();
        let mut sub = node.subscribe_chain()?;
        assert!(node.poll_chain(&mut sub)?.is_none());
        let one = BlockImage::from_local(block(genesis, 1, 0)?);
        node.state.apply_block(&one)?;
        let update = node
            .poll_chain(&mut sub)?
            .ok_or(TestError::Missing("connect hint"))?;
        assert!(!update.gap);
        let pinned_one = update.current;
        let two = BlockImage::from_local(block(one.block_hash(), 2, 0)?);
        node.state.apply_block(&two)?;
        let three = BlockImage::from_local(block(two.block_hash(), 3, 0)?);
        node.state.apply_block(&three)?;
        let update = node
            .poll_chain(&mut sub)?
            .ok_or(TestError::Missing("gap hint"))?;
        assert!(update.gap);
        let first = node.replay_chain(genesis, &update.current, 1)?;
        assert_eq!(first.steps.len(), 1);
        assert!(!first.complete);
        let rest = node.replay_chain(first.position, &update.current, 2)?;
        assert!(rest.complete);
        assert!(
            rest.steps
                .iter()
                .all(|step| matches!(step, ChainStep::Connected(_)))
        );
        assert_eq!(
            node.replay_chain(genesis, &pinned_one, 1)?.position,
            one.block_hash()
        );
        crate::reorg::invalidate_block(
            &node.state.chainstate(),
            &node.state.chain_followers(),
            two.block_hash().into(),
        )?;
        let alternate = BlockImage::from_local(block(one.block_hash(), 2, 1)?);
        node.state.apply_block(&alternate)?;
        let target = node.pin_chain()?;
        let replay = node.replay_chain(three.block_hash(), &target, 10)?;
        assert!(replay.complete);
        assert!(
            matches!(&replay.steps[..], [ChainStep::Disconnected(a), ChainStep::Disconnected(b), ChainStep::Connected(c)] if a.height == 3 && b.height == 2 && c.header == alternate.header())
        );
        assert!(node.replay_chain(genesis, &target, 0).is_err());
        assert!(node.replay_chain(genesis, &target, 257).is_err());
        assert!(
            node.replay_chain(Hash256::from_le_bytes(&[42; 32]).into(), &target, 1)
                .is_err()
        );
        let snapshot = node.snapshot();
        run(node.shutdown())?;
        let reopened = run(Node::start(
            config(dir.path()),
            crate::RuntimeInputs::default(),
        ))?;
        let mut resumed = Node::resume_chain(snapshot);
        assert!(
            reopened
                .poll_chain(&mut resumed)?
                .is_some_and(|update| update.gap)
        );
        assert!(reopened.replay_chain(genesis, &target, 1).is_err());
        run(reopened.shutdown())?;
        Ok(())
    }

    // EVT-06
    #[test]
    fn unsettled_or_failed_chain_fences_never_publish_a_stable_hint() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let node = run(Node::start(
            config(dir.path()),
            crate::RuntimeInputs::default(),
        ))?;
        let mut sub = node.subscribe_chain()?;
        let before = sub.cursor();
        let chain = node.state.chainstate();
        let transition = chain.begin_transition()?;
        assert!(node.poll_chain(&mut sub).is_err());
        assert_eq!(sub.cursor(), before);
        drop(transition);
        let fence = node.state.mempool_gateway().begin_chain_change()?;
        assert!(node.pin_chain().is_err());
        fence.finish()?;
        assert!(node.poll_chain(&mut sub)?.is_none());
        let bad = block(before.tip_hash.into(), 1, 0)?;
        let mut bad = bad;
        bad.txs.clear();
        assert!(
            node.state
                .apply_block(&BlockImage::from_local(bad))
                .is_err()
        );
        assert_eq!(node.settled_snapshot()?, before);
        drop(node.state.mempool_gateway().begin_chain_change()?);
        assert!(node.poll_chain(&mut sub).is_err());
        assert_eq!(sub.cursor(), before);
        drop(node);
        Ok(())
    }
}

fn metadata(tree: &BlockTree, hash: Hash256) -> Result<BlockHeaderInfo, NodeError> {
    let node = tree
        .node_by_hash(hash)
        .ok_or_else(|| NodeError::NotFound(format!("header {hash}")))?;
    Ok(BlockHeaderInfo {
        header: node.header,
        height: node.height,
        chainwork: node.chainwork.to_be_bytes(),
    })
}

impl Node {
    pub fn block_header(&self, hash: BlockHash) -> Result<BlockHeaderInfo, NodeError> {
        let chain = self.state.chainstate();
        let reader = chain.block_tree_reader();
        metadata(&reader.read(), Hash256::from(hash))
    }

    pub fn settled_snapshot(&self) -> Result<ChainSnapshot, NodeError> {
        let stable = self.state.stable_read();
        let _guard = stable
            .try_lock_for(std::time::Duration::ZERO)
            .ok_or_else(|| NodeError::Unavailable("chain transition in progress".into()))?;
        self.ensure_chain_settled()?;
        Ok(self.snapshot())
    }

    pub fn subscribe_chain(&self) -> Result<ChainSubscription, NodeError> {
        Ok(ChainSubscription {
            cursor: self.settled_snapshot()?,
        })
    }

    pub fn pin_chain(&self) -> Result<ChainTarget, NodeError> {
        Ok(ChainTarget {
            snapshot: self.settled_snapshot()?,
            source: std::sync::Arc::downgrade(&self.state.chainstate()),
        })
    }

    #[must_use]
    pub const fn resume_chain(cursor: ChainSnapshot) -> ChainSubscription {
        ChainSubscription { cursor }
    }

    pub fn poll_chain(
        &self,
        subscription: &mut ChainSubscription,
    ) -> Result<Option<ChainUpdate>, NodeError> {
        let current = self.settled_snapshot()?;
        let previous = subscription.cursor;
        if previous == current {
            return Ok(None);
        }
        let adjacent = if previous.epoch != current.epoch {
            false
        } else if current.tip_height == previous.tip_height.saturating_add(1) {
            self.block_header(current.tip_hash.into())
                .is_ok_and(|info| info.header.prev_blockhash == BlockHash::from(previous.tip_hash))
        } else if previous.tip_height == current.tip_height.saturating_add(1) {
            self.block_header(previous.tip_hash.into())
                .is_ok_and(|info| info.header.prev_blockhash == BlockHash::from(current.tip_hash))
        } else {
            false
        };
        let gap = previous.epoch != current.epoch
            || previous.sequence.checked_add(1) != Some(current.sequence)
            || !adjacent;
        subscription.cursor = current;
        Ok(Some(ChainUpdate {
            previous,
            current: ChainTarget {
                snapshot: current,
                source: std::sync::Arc::downgrade(&self.state.chainstate()),
            },
            gap,
        }))
    }

    pub fn replay_chain(
        &self,
        from: BlockHash,
        target: &ChainTarget,
        limit: usize,
    ) -> Result<ChainReplay, NodeError> {
        if limit == 0 || limit > MAX_REPLAY_STEPS {
            return Err(NodeError::Unavailable(format!(
                "replay limit must be 1..={MAX_REPLAY_STEPS}"
            )));
        }
        let stable = self.state.stable_read();
        let _guard = stable
            .try_lock_for(std::time::Duration::ZERO)
            .ok_or_else(|| NodeError::Unavailable("chain transition in progress".into()))?;
        self.ensure_chain_settled()?;
        if !target
            .source
            .ptr_eq(&std::sync::Arc::downgrade(&self.state.chainstate()))
        {
            return Err(NodeError::Unavailable(
                "replay target belongs to another node run; re-pin".into(),
            ));
        }
        let pinned = target.snapshot;
        if pinned.epoch != self.snapshot().epoch || pinned.sequence > self.snapshot().sequence {
            return Err(NodeError::Unavailable(
                "re-pin replay target after restart".into(),
            ));
        }
        let chain = self.state.chainstate();
        let reader = chain.block_tree_reader();
        let tree = reader.read();
        let target_id = tree
            .lookup(pinned.tip_hash)
            .ok_or_else(|| NodeError::NotFound("replay target header".into()))?;
        if metadata(&tree, pinned.tip_hash)?.height != pinned.tip_height {
            return Err(NodeError::Unavailable(
                "replay target height mismatch".into(),
            ));
        }
        let mut position = from;
        let mut steps = Vec::new();
        let mut budget = MAX_ANCESTRY_HOPS;
        while Hash256::from(position) != pinned.tip_hash && steps.len() < limit {
            let old = metadata(&tree, position.into())?;
            let on_target = tree
                .node_at_height_from_bounded(target_id, old.height, &mut budget)
                .map_err(|_| {
                    NodeError::Unavailable("replay ancestry budget exceeded; re-pin target".into())
                })?
                .and_then(|id| tree.node(id).ok())
                .is_some_and(|node| node.hash == Hash256::from(position));
            if on_target {
                let next = tree
                    .node_at_height_from_bounded(target_id, old.height + 1, &mut budget)
                    .map_err(|_| {
                        NodeError::Unavailable(
                            "replay ancestry budget exceeded; re-pin target".into(),
                        )
                    })?
                    .and_then(|id| tree.node(id).ok())
                    .ok_or_else(|| NodeError::Unavailable("replay ancestry missing".into()))?;
                position = next.hash.into();
                steps.push(ChainStep::Connected(metadata(&tree, next.hash)?));
            } else {
                if old.height == 0 {
                    return Err(NodeError::Unavailable(
                        "replay chains have no common genesis".into(),
                    ));
                }
                position = old.header.prev_blockhash;
                steps.push(ChainStep::Disconnected(old));
            }
        }
        Ok(ChainReplay {
            steps,
            position,
            target: target.clone(),
            complete: Hash256::from(position) == pinned.tip_hash,
        })
    }

    fn ensure_chain_settled(&self) -> Result<(), NodeError> {
        if self.state.shutdown_reader().is_triggered()
            || self.state.mempool_gateway().stable_generation().is_none()
        {
            return Err(NodeError::Unavailable(
                "node is shutting down or requires chain recovery".into(),
            ));
        }
        Ok(())
    }
}
