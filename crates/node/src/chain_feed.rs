use bitcoin_rs_chain::BlockTree;
pub use bitcoin_rs_chainstate::events::ChainSnapshot;
use bitcoin_rs_primitives::{BlockHash, Hash256, Header};

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
    source: std::sync::Weak<bitcoin_rs_chainstate::Chainstate>,
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
#[path = "../tests/unit/chain_feed.rs"]
mod tests;

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
