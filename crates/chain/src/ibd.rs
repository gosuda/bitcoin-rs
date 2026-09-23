<<<<<<< HEAD
//! Initial block download state of the applied chain.
//!
//! The decision is chain state, so it lives beside the chain handles it reads:
//! one process-wide [`InitialBlockDownload`] latch shared by every consumer.
//! Bitcoin Core owns the same decision inside `ChainstateManager`
//! (`IsInitialBlockDownload`, `m_cached_is_ibd`); keeping one latch here means
//! RPC and P2P can never answer differently.

use std::sync::atomic::AtomicBool;

use crate::Network;
use crate::view::{BlockTreeReader, TipReader};

/// How stale the applied tip may be while the node still counts as synced.
///
/// Bitcoin Core's `DEFAULT_MAX_TIP_AGE`, 24 hours. Core exposes it as
/// `-maxtipage`; this node has no such option yet, so the default stands.
const MAX_TIP_AGE_SECONDS: u64 = 24 * 60 * 60;

/// Initial block download state of the applied chain
/// (Core `ChainstateManager::IsInitialBlockDownload`).
///
/// PRE: `applied_tip` and `block_tree` are the node's published handles; the
/// same instances stay shared for the life of the latch.
/// POST: [`Self::is_active`] reports whether the applied chain still counts
/// as initial block download, judged against the network the caller passes
/// to it.
/// INVARIANT: once the exit latches, every answer ordered after it is
/// `false` for the life of the process (Core `m_cached_is_ibd`); an active
/// verdict rechecks the latch, so an answer paused on a superseded snapshot
/// never reports active after a concurrently latched exit.
pub struct InitialBlockDownload {
    /// Whether this node has ever observed itself to be out of initial block
    /// download. Once set it is never cleared.
    ///
    /// Bitcoin Core latches the same way (`m_cached_is_ibd`, cleared once by
    /// `UpdateIBDStatus` and never set again) and logs "Leaving
    /// `InitialBlockDownload (latching to false)`" when it happens. Without the
    /// latch the answer oscillates: a synced node that has not seen a block for
    /// longer than the tip-age window would announce that it is back in initial
    /// sync, and callers treat that as "do not trust this node's data yet".
    /// An active verdict re-reads this flag before returning, so a call that
    /// judged a superseded tip yields to an exit another caller latched while
    /// it ran.
    left: AtomicBool,
    applied_tip: TipReader,
    block_tree: BlockTreeReader,
}

impl InitialBlockDownload {
    /// Builds the latch over node-owned chain handles.
    ///
    /// PRE: the readers observe the node whose downloads are being judged.
    /// POST: the latch starts active (Core leaves `m_cached_is_ibd` unset at
    /// startup); an absent applied tip always reports active.
    /// INVARIANT: construction copies no chain state; the readers share the
    /// node's published cells, never private copies.
    #[must_use]
    pub fn new(applied_tip: TipReader, block_tree: BlockTreeReader) -> Self {
        Self {
            left: AtomicBool::new(false),
            applied_tip,
            block_tree,
        }
    }

    /// PRE: `now` is UNIX seconds; `network` is the node's live configured
    ///   network, read at each call.
    /// POST: returns true while the applied tip is absent, carries less than
    ///   `network`'s minimum chain work, or is older than 24 hours
    ///   ([`MAX_TIP_AGE_SECONDS`]); the first false answer latches.
    /// INVARIANT: once the exit latches, later answers stay false for the
    ///   life of the process (Core `m_cached_is_ibd`); an active verdict
    ///   rechecks the latch before returning, so an answer that paused on a
    ///   superseded snapshot yields to a concurrently latched exit.
    ///
    /// The node counts as synced only when its applied tip carries at least
    /// the supplied network's `nMinimumChainWork` **and** carries a timestamp
    /// no older than `max_tip_age` (Core's 24-hour default). Both are
    /// required: work alone would trust a stale chain, and recency alone
    /// would trust a cheap one that simply claims a recent timestamp. The
    /// latch stores no network; every query supplies the node's live one, so
    /// a network assigned after construction is honored.
    ///
    /// `now` is UNIX seconds, taken by the caller so the decision itself stays a
    /// pure function of observable state.
    #[must_use]
    pub fn is_active(&self, now: u64, network: Network) -> bool {
        use core::sync::atomic::Ordering;

        if self.left.load(Ordering::Relaxed) {
            return false;
        }
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
        if u64::from(tip_time) < now.saturating_sub(MAX_TIP_AGE_SECONDS) {
            return self.still_active();
        }
        self.left.store(true, Ordering::Relaxed);
        false
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

    /// A latch whose applied tip is a real tree node stamped `tip_time`, so
    /// the tip has an age to be judged on. Chain work comes from the tree's own
    /// accounting, which for a two-block regtest chain is far below any
    /// production `nMinimumChainWork` — the `network` a query passes decides
    /// whether that floor holds the tip in initial block download.
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
                version: 1,
                prev_blockhash: genesis.compute_hash(),
                merkle_root: Hash256::default(),
                time: tip_time,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 1,
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
    fn a_recent_tip_without_the_networks_minimum_work_is_still_initial_block_download() {
        let now = 1_800_000_000_u64;
        // Timestamped one minute ago, so recency is satisfied and only the work
        // floor can be what decides. A two-block regtest-difficulty chain has
        // nowhere near mainnet's `nMinimumChainWork`.
        let latch = latch_with_tip_at(u32::try_from(now - 60).unwrap_or(u32::MAX));
        assert!(
            latch.is_active(now, Network::Mainnet),
            "a chain this cheap must not count as synced merely for being recent"
        );
    }

    #[test]
    fn is_active_judges_the_work_floor_of_the_network_the_caller_supplies() {
        let now = 1_800_000_000_u64;
        // One recent, cheap tip. Only the query's network separates the
        // answers: mainnet's `nMinimumChainWork` holds it in initial block
        // download, and regtest pins the floor at zero, so the same tip counts
        // as synced. The latch stores no network, so a caller that assembles a
        // context before its network is chosen is still judged by the network
        // it runs.
        let latch = latch_with_tip_at(u32::try_from(now - 60).unwrap_or(u32::MAX));
        assert!(latch.is_active(now, Network::Mainnet));
        assert!(!latch.is_active(now, Network::Regtest));
    }

    #[test]
    fn a_stale_tip_with_enough_work_is_still_initial_block_download() {
        let now = 1_800_000_000_u64;
        // Regtest's work floor is zero, so only the tip's age is left to decide.
        let latch = latch_with_tip_at(u32::try_from(now - DAY - 60).unwrap_or(u32::MAX));
        assert!(latch.is_active(now, Network::Regtest));
    }

    #[test]
    fn a_recent_tip_with_enough_work_exits_initial_block_download() {
        let now = 1_800_000_000_u64;
        let latch = latch_with_tip_at(u32::try_from(now - 60).unwrap_or(u32::MAX));
        assert!(!latch.is_active(now, Network::Regtest));
    }

    #[test]
    fn the_tip_age_boundary_is_twenty_four_hours() {
        let now = 1_800_000_000_u64;
        let at_the_edge = latch_with_tip_at(u32::try_from(now - DAY).unwrap_or(u32::MAX));
        assert!(
            !at_the_edge.is_active(now, Network::Regtest),
            "exactly `max_tip_age` old is still recent enough"
        );

        let past_the_edge = latch_with_tip_at(u32::try_from(now - DAY - 1).unwrap_or(u32::MAX));
        assert!(past_the_edge.is_active(now, Network::Regtest));
    }

    #[test]
    fn leaving_initial_block_download_latches() {
        let now = 1_800_000_000_u64;
        let latch = latch_with_tip_at(u32::try_from(now - 60).unwrap_or(u32::MAX));
        assert!(!latch.is_active(now, Network::Regtest));

        // Two days later, with no new block. Judged afresh the tip is stale and
        // the answer would flip back to `true`; latched, it does not. This is
        // the defect the field had — it went true again every time the node went
        // quiet, and callers read that as "resyncing, do not trust me".
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
||||||| parent of 071f4bd2 (Move the IBD decision into the chain crate)
=======
//! Initial block download state of the applied chain.
//!
//! The decision is chain state, so it lives beside the chain handles it reads:
//! one process-wide [`InitialBlockDownload`] latch shared by every consumer.
//! Bitcoin Core owns the same decision inside `ChainstateManager`
//! (`IsInitialBlockDownload`, `m_cached_is_ibd`); keeping one latch here means
//! RPC and P2P can never answer differently.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use arc_swap::ArcSwapOption;
use parking_lot::RwLock;

use crate::{BlockTree, Network, TipSnapshot};

/// How stale the applied tip may be while the node still counts as synced.
///
/// Bitcoin Core's `DEFAULT_MAX_TIP_AGE`, 24 hours. Core exposes it as
/// `-maxtipage`; this node has no such option yet, so the default stands.
const MAX_TIP_AGE_SECONDS: u64 = 24 * 60 * 60;

/// Initial block download state of the applied chain
/// (Core `ChainstateManager::IsInitialBlockDownload`).
///
/// PRE: `applied_tip` and `block_tree` are the node's published handles; the
/// same instances stay shared for the life of the latch.
/// POST: [`Self::is_active`] reports whether the applied chain still counts
/// as initial block download at the supplied time.
/// INVARIANT: once `is_active` returns `false`, it returns `false` for the
/// life of the process (Core `m_cached_is_ibd`).
pub struct InitialBlockDownload {
    /// Whether this node has ever observed itself to be out of initial block
    /// download. Once set it is never cleared.
    ///
    /// Bitcoin Core latches the same way (`m_cached_is_ibd`, cleared once by
    /// `UpdateIBDStatus` and never set again) and logs "Leaving
    /// `InitialBlockDownload (latching to false)`" when it happens. Without the
    /// latch the answer oscillates: a synced node that has not seen a block for
    /// longer than the tip-age window would announce that it is back in initial
    /// sync, and callers treat that as "do not trust this node's data yet".
    left: AtomicBool,
    applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    block_tree: Arc<RwLock<BlockTree>>,
    network: Network,
}

impl InitialBlockDownload {
    /// Builds the latch over node-owned chain handles.
    ///
    /// PRE: the handles belong to the node whose downloads are being judged.
    /// POST: the latch starts active (Core leaves `m_cached_is_ibd` unset at
    /// startup); an absent applied tip always reports active.
    /// INVARIANT: construction copies no chain state; the handles are shared.
    #[must_use]
    pub fn new(
        applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
        block_tree: Arc<RwLock<BlockTree>>,
        network: Network,
    ) -> Self {
        Self {
            left: AtomicBool::new(false),
            applied_tip,
            block_tree,
            network,
        }
    }

    /// PRE: `now` is UNIX seconds.
    /// POST: returns true while the applied tip is absent, carries less than
    ///   the network minimum chain work, or is older than 24 hours
    ///   ([`MAX_TIP_AGE_SECONDS`]); the first false answer latches.
    /// INVARIANT: once false, the answer stays false for the life of the
    ///   process (Core `m_cached_is_ibd`).
    ///
    /// The node counts as synced only when its applied tip carries at least
    /// the network's `nMinimumChainWork` **and** carries a timestamp no older
    /// than `max_tip_age` (Core's 24-hour default). Both are required: work
    /// alone would trust a stale chain, and recency alone would trust a cheap
    /// one that simply claims a recent timestamp.
    ///
    /// `now` is UNIX seconds, taken by the caller so the decision itself stays a
    /// pure function of observable state.
    #[must_use]
    pub fn is_active(&self, now: u64) -> bool {
        use core::sync::atomic::Ordering;

        if self.left.load(Ordering::Relaxed) {
            return false;
        }
        let Some(tip) = self.applied_tip.load_full() else {
            return true;
        };
        // Big-endian, fixed width: byte order is numeric order.
        let work: [u8; 32] = tip.chainwork.to_be_bytes();
        if work < self.network.minimum_chain_work() {
            return true;
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
            return true;
        };
        if u64::from(tip_time) < now.saturating_sub(MAX_TIP_AGE_SECONDS) {
            return true;
        }
        self.left.store(true, Ordering::Relaxed);
        false
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
    use crate::{BlockHeader, NodeStatus};

    const DAY: u64 = 24 * 60 * 60;

    /// A latch whose applied tip is a real tree node stamped `tip_time`, so
    /// the tip has an age to be judged on. Chain work comes from the tree's own
    /// accounting, which for a two-block regtest chain is far below any
    /// production `nMinimumChainWork` — hence the network parameter: regtest
    /// pins that floor at zero, mainnet does not.
    fn latch_with_tip_at(network: Network, tip_time: u32) -> InitialBlockDownload {
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
                version: 1,
                prev_blockhash: genesis.compute_hash(),
                merkle_root: Hash256::default(),
                time: tip_time,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 1,
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
        InitialBlockDownload::new(applied_tip, block_tree, network)
    }

    #[test]
    fn a_node_that_has_applied_nothing_is_in_initial_block_download() {
        let applied_tip = Arc::new(arc_swap::ArcSwapOption::empty());
        let latch = InitialBlockDownload::new(
            applied_tip,
            Arc::new(RwLock::new(BlockTree::new())),
            Network::Mainnet,
        );
        assert!(latch.is_active(1_800_000_000));
    }

    #[test]
    fn a_recent_tip_without_the_networks_minimum_work_is_still_initial_block_download() {
        let now = 1_800_000_000_u64;
        // Timestamped one minute ago, so recency is satisfied and only the work
        // floor can be what decides. A two-block regtest-difficulty chain has
        // nowhere near mainnet's `nMinimumChainWork`.
        let latch = latch_with_tip_at(
            Network::Mainnet,
            u32::try_from(now - 60).unwrap_or(u32::MAX),
        );
        assert!(
            latch.is_active(now),
            "a chain this cheap must not count as synced merely for being recent"
        );
    }

    #[test]
    fn a_stale_tip_with_enough_work_is_still_initial_block_download() {
        let now = 1_800_000_000_u64;
        // Regtest's work floor is zero, so only the tip's age is left to decide.
        let latch = latch_with_tip_at(
            Network::Regtest,
            u32::try_from(now - DAY - 60).unwrap_or(u32::MAX),
        );
        assert!(latch.is_active(now));
    }

    #[test]
    fn a_recent_tip_with_enough_work_has_left_initial_block_download() {
        let now = 1_800_000_000_u64;
        let latch = latch_with_tip_at(
            Network::Regtest,
            u32::try_from(now - 60).unwrap_or(u32::MAX),
        );
        assert!(!latch.is_active(now));
    }

    #[test]
    fn the_tip_age_boundary_is_twenty_four_hours() {
        let now = 1_800_000_000_u64;
        let at_the_edge = latch_with_tip_at(
            Network::Regtest,
            u32::try_from(now - DAY).unwrap_or(u32::MAX),
        );
        assert!(
            !at_the_edge.is_active(now),
            "exactly `max_tip_age` old is still recent enough"
        );

        let past_the_edge = latch_with_tip_at(
            Network::Regtest,
            u32::try_from(now - DAY - 1).unwrap_or(u32::MAX),
        );
        assert!(past_the_edge.is_active(now));
    }

    #[test]
    fn leaving_initial_block_download_latches() {
        let now = 1_800_000_000_u64;
        let latch = latch_with_tip_at(
            Network::Regtest,
            u32::try_from(now - 60).unwrap_or(u32::MAX),
        );
        assert!(!latch.is_active(now));

        // Two days later, with no new block. Judged afresh the tip is stale and
        // the answer would flip back to `true`; latched, it does not. This is
        // the defect the field had — it went true again every time the node went
        // quiet, and callers read that as "resyncing, do not trust me".
        assert!(
            !latch.is_active(now + 2 * DAY),
            "the answer must not flip back once the node has left initial sync"
        );
    }

    #[test]
    fn the_latch_does_not_fire_before_the_conditions_are_met() {
        let now = 1_800_000_000_u64;
        let latch = latch_with_tip_at(
            Network::Regtest,
            u32::try_from(now - DAY - 60).unwrap_or(u32::MAX),
        );
        assert!(latch.is_active(now));
        // Same tip, asked later at a time when it *is* within the window.
        assert!(!latch.is_active(now - DAY));
    }
}
>>>>>>> 071f4bd2 (Move the IBD decision into the chain crate)
