//! Process-wide initial block download latch shared by RPC and P2P.

use std::sync::atomic::AtomicBool;

use crate::Network;
use crate::view::{BlockTreeReader, TipReader};

// Core's DEFAULT_MAX_TIP_AGE; this node does not expose -maxtipage.
const MAX_TIP_AGE_SECONDS: u64 = 24 * 60 * 60;

/// Initial block download state of the applied chain
/// (Core `ChainstateManager::IsInitialBlockDownload`).
///
/// Once the exit latches, every answer ordered after it is `false` for the
/// life of the process.
pub struct InitialBlockDownload {
    left: AtomicBool,
    applied_tip: TipReader,
    block_tree: BlockTreeReader,
}

impl InitialBlockDownload {
    /// Builds the latch over the node's published chain handles, starting
    /// active.
    #[must_use]
    pub fn new(applied_tip: TipReader, block_tree: BlockTreeReader) -> Self {
        Self {
            left: AtomicBool::new(false),
            applied_tip,
            block_tree,
        }
    }

    /// Whether the applied chain still counts as initial block download.
    ///
    /// Synced requires both at least `network`'s `nMinimumChainWork` and a tip
    /// no older than [`MAX_TIP_AGE_SECONDS`]: work alone would trust a stale
    /// chain, recency alone a cheap one claiming a recent timestamp. `now` is
    /// UNIX seconds from the caller, and `network` is read per call, so a
    /// network assigned after construction is honored.
    #[must_use]
    pub fn is_active(&self, now: u64, network: Network) -> bool {
        use core::sync::atomic::Ordering;

        if self.left.load(Ordering::Acquire) {
            return false;
        }
        if self.still_in_initial_block_download(now, network) {
            // A concurrent caller may have latched "left IBD" while the
            // predicate's unlocked reads ran; the latch wins so that once a
            // caller observes false, no caller ever answers true again.
            return !self.left.load(Ordering::Acquire);
        }
        self.left.store(true, Ordering::Release);
        false
    }

    /// The unlocked IBD predicate behind [`Self::is_active`]: minimum work,
    /// then tip freshness against the caller's clock.
    fn still_in_initial_block_download(&self, now: u64, network: Network) -> bool {
        let Some(tip) = self.applied_tip.load_full() else {
            return self.still_active();
        };
        // Big-endian, fixed width: byte order is numeric order.
        let work: [u8; 32] = tip.chainwork.to_be_bytes();
        if work < network.minimum_chain_work() {
            return self.still_active();
        }
        // `TipSnapshot` carries no timestamp, so the tip's header supplies it —
        // the same route `getdifficulty` takes to the tip's `bits`.
        let Some(tip_time) = self
            .block_tree
            .read()
            .node(tip.tip_id)
            .ok()
            .map(|node| node.header.time)
        else {
            return self.still_active();
        };
        u64::from(tip_time) < now.saturating_sub(MAX_TIP_AGE_SECONDS)
    }

    /// Answers active, unless a concurrent caller already latched the exit
    /// while this call paused on a superseded snapshot; the latched exit is
    /// the fresher answer and wins.
    fn still_active(&self) -> bool {
        use core::sync::atomic::Ordering;

        !self.left.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod initial_block_download_tests {
    use std::sync::Arc;

    use bitcoin_rs_primitives::{BlockHash, CompactTarget, Hash256, Network};

    use parking_lot::RwLock;

    use super::InitialBlockDownload;
    use crate::tree::BlockTree;
    use crate::view::{BlockTreeReader, TipReader};
    use crate::{BlockHeader, NodeStatus};

    const DAY: u64 = 24 * 60 * 60;

    // Two regtest headers have enough work only for regtest's zero floor.
    fn latch_with_tip_at(tip_time: u32) -> InitialBlockDownload {
        let applied_tip = Arc::new(arc_swap::ArcSwapOption::empty());
        let block_tree = Arc::new(RwLock::new(BlockTree::new()));
        let tip = {
            let mut tree = block_tree.write();
            let genesis = BlockHeader {
                version: 1,
                prev_blockhash: BlockHash::default(),
                merkle_root: Hash256::default(),
                time: 1_000_000,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            };
            let Ok(genesis_id) = tree.insert_node(None, genesis, NodeStatus::Active) else {
                panic!("genesis insert failed");
            };
            let child = BlockHeader {
                prev_blockhash: genesis.compute_hash(),
                time: tip_time,
                nonce: 1,
                ..genesis
            };
            let Ok(_child_id) = tree.insert_node(Some(genesis_id), child, NodeStatus::Active)
            else {
                panic!("child insert failed");
            };
            let Some(tip) = tree.tip() else {
                panic!("no tip published");
            };
            (*tip).clone()
        };
        applied_tip.store(Some(Arc::new(tip)));
        InitialBlockDownload::new(
            TipReader::new(applied_tip),
            BlockTreeReader::new(block_tree),
        )
    }

    #[test]
    fn a_node_that_has_applied_nothing_is_in_initial_block_download() {
        let applied_tip = Arc::new(arc_swap::ArcSwapOption::empty());
        let latch = InitialBlockDownload::new(
            TipReader::new(applied_tip),
            BlockTreeReader::new(Arc::new(RwLock::new(BlockTree::new()))),
        );
        assert!(latch.is_active(1_800_000_000, Network::Mainnet));
    }

    #[test]
    fn initial_sync_requires_the_network_work_floor_and_a_recent_tip() {
        let now = 1_800_000_000_u64;
        for (network, age, active) in [
            (Network::Mainnet, 60, true),
            (Network::Regtest, DAY + 60, true),
            (Network::Regtest, 60, false),
            (Network::Regtest, DAY, false),
            (Network::Regtest, DAY + 1, true),
        ] {
            let latch = latch_with_tip_at(u32::try_from(now - age).unwrap_or(u32::MAX));
            assert_eq!(
                latch.is_active(now, network),
                active,
                "{network:?}, age {age}"
            );
        }
    }

    #[test]
    fn is_active_judges_the_work_floor_of_the_network_the_caller_supplies() {
        let now = 1_800_000_000_u64;
        let latch = latch_with_tip_at(u32::try_from(now - 60).unwrap_or(u32::MAX));
        assert!(latch.is_active(now, Network::Mainnet));
        assert!(!latch.is_active(now, Network::Regtest));
    }

    #[test]
    fn leaving_initial_block_download_latches() {
        let now = 1_800_000_000_u64;
        let latch = latch_with_tip_at(u32::try_from(now - 60).unwrap_or(u32::MAX));
        assert!(!latch.is_active(now, Network::Regtest));

        // A latched node must not re-enter IBD when its tip becomes stale.
        assert!(
            !latch.is_active(now + 2 * DAY, Network::Regtest),
            "the answer must not flip back once the node has left initial sync"
        );
    }

    #[test]
    fn the_latch_does_not_fire_before_the_conditions_are_met() {
        let now = 1_800_000_000_u64;
        let latch = latch_with_tip_at(u32::try_from(now - DAY - 60).unwrap_or(u32::MAX));
        assert!(latch.is_active(now, Network::Regtest));
        // Same tip, asked later at a time when it *is* within the window.
        assert!(!latch.is_active(now - DAY, Network::Regtest));
    }
}
