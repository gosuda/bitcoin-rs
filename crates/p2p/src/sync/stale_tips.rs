//! Bounded retention of recent stale tips for BIP332 relay.
//!
//! A stale tip is the newest header of a branch that is neither on the active
//! chain nor an extension of it. `BlockTree` keeps every header it has ever
//! admitted, so side-branch headers are only reachable by scanning the whole
//! tree; this module keeps the few that are worth announcing, as hashes.
//!
//! The tree stays the one authority over chain facts. The retainer stores a
//! hash, the tip's chainwork (a ranking key, immutable per node), and the order
//! it was learned in; height, status, ancestry, and the active chain are
//! always read from the `&BlockTree` each call receives. It never validates a
//! header, never admits one, and never mutates the tree: a retained tip is a
//! hint that can only make a node announce something it already holds.
//!
//! # Invariants
//!
//! - At most [`MAX_RETAINED_STALE_TIPS`] tips are held.
//! - Every call that receives a tree first drops tips that are no longer stale
//!   candidates (active, on or above the active chain, invalid, unknown, or
//!   more than [`STALETIP_RECENT_WINDOW`] blocks behind the active tip), so
//!   what it then reports is current for that tree.
//! - A tip and one of its ancestors are never both held: extending a retained
//!   branch replaces its tip, and a header below a retained tip is not learned.
//! - A peer is recorded as knowing a tip only while the tip is retained, so
//!   the per-peer record is bounded by the retention cap and cleared with the
//!   tip. "Knows" covers both directions: the peer announced the tip to us
//!   (never echo it back) and we announced it to the peer (never repeat it).
//! - Relay with a peer opens once ([`StaleTipRetainer::pending_for`]): the
//!   first call offers at most [`MAX_ADVERTISED_STALETIPS`] of the tips already
//!   held, every later call only tips learned after it. A peer therefore
//!   receives at most ten earlier tips however many are held, plus each tip
//!   learned while it is connected, once.
//!
//! # Locking
//!
//! One internal mutex, a leaf lock: callers hold at most their `BlockTree`
//! read guard when calling in, and no method calls back out except
//! [`StaleTipRetainer::pending_for`], which releases the mutex before invoking
//! its predicate.

use std::cmp::Reverse;
use std::collections::VecDeque;
use std::sync::Arc;

use bitcoin_rs_chain::{BlockTree, BlockTreeNode, ChainWork, NodeId, NodeStatus, TipSnapshot};
use bitcoin_rs_primitives::Hash256;
use hashbrown::HashMap;
use parking_lot::Mutex;

use super::BlockSync;
use crate::PeerSource;

/// Most stale tips held at once.
pub(crate) const MAX_RETAINED_STALE_TIPS: usize = 64;

/// Most blocks a stale tip may lie behind the active tip and still be relayed
/// (BIP332 `STALETIP_RECENT_WINDOW`).
pub(crate) const STALETIP_RECENT_WINDOW: u32 = 1000;

/// Most previously known stale tips advertised to a peer when relay with it
/// begins (BIP332 `MAX_ADVERTISED_STALETIPS`).
pub(crate) const MAX_ADVERTISED_STALETIPS: usize = 10;

/// One retained stale tip.
#[derive(Debug)]
struct Retained {
    hash: Hash256,
    /// Chainwork through the tip; the first ranking key.
    work: ChainWork,
    /// Learn order, larger is newer; the tie-break among equal work.
    sequence: u64,
    /// Peers that announced this tip to us or that we announced it to.
    known_by: Vec<PeerSource>,
}

impl Retained {
    /// Greatest chainwork first, then the most recently learned (BIP332).
    fn rank(&self) -> (ChainWork, u64) {
        (self.work, self.sequence)
    }

    fn mark_known(&mut self, peer: PeerSource) {
        if !self.known_by.contains(&peer) {
            self.known_by.push(peer);
        }
    }
}

#[derive(Debug, Default)]
struct State {
    tips: Vec<Retained>,
    next_sequence: u64,
    /// Peers relay has been opened with, and the learn sequence at that
    /// moment: only tips learned at or after it are offered again.
    opened: HashMap<PeerSource, u64>,
    /// Announcements peers sent whose branch the sync loop has not yet
    /// admitted, oldest first; at most [`MAX_RETAINED_STALE_TIPS`].
    heard: VecDeque<(Hash256, PeerSource)>,
}

impl State {
    /// Drops every tip that is no longer a stale candidate in `tree`.
    ///
    /// POST: each remaining tip satisfies [`stale_fork`].
    fn prune(&mut self, tree: &BlockTree) {
        let tip = tree.tip();
        self.tips.retain(|retained| {
            tip.as_deref().is_some_and(|tip| {
                tree.lookup(retained.hash)
                    .is_some_and(|id| stale_fork(tree, tip, id).is_some())
            })
        });
    }

    /// The retained tips, best first.
    fn ranked(&self) -> Vec<&Retained> {
        let mut ranked: Vec<&Retained> = self.tips.iter().collect();
        ranked.sort_by_key(|retained| Reverse(retained.rank()));
        ranked
    }

    /// Credits the peers that announced `hash` before it was admitted.
    fn absorb_heard(&mut self, hash: Hash256) {
        let Some(held) = self.tips.iter_mut().find(|held| held.hash == hash) else {
            return;
        };
        self.heard.retain(|&(tip, peer)| {
            if tip == hash {
                held.mark_known(peer);
                false
            } else {
                true
            }
        });
    }
}

/// Whether `node` is eligible by its own facts: valid, and no more than
/// [`STALETIP_RECENT_WINDOW`] blocks behind the active tip.
fn in_scope(node: &BlockTreeNode, tip: &TipSnapshot) -> bool {
    node.status != NodeStatus::Invalid
        && tip.height.saturating_sub(node.height) <= STALETIP_RECENT_WINDOW
}

/// The block where the branch ending at `id` leaves the active chain, when
/// `id` is a stale-tip candidate.
///
/// PRE: `tip` is `tree`'s active tip.
/// POST: `Some(fork)` iff `id` is in scope and is neither an ancestor of the
///   active tip (this covers the tip itself) nor a descendant of it; `fork` is
///   then the highest block the branch shares with the active chain. The cost
///   is the branch length when the tree's active-height index is trusted.
fn stale_fork(tree: &BlockTree, tip: &TipSnapshot, id: NodeId) -> Option<NodeId> {
    let node = tree.node(id).ok()?;
    if !in_scope(node, tip) {
        return None;
    }
    let fork = tree.find_common_ancestor(tip.tip_id, id)?;
    (fork != id && fork != tip.tip_id).then_some(fork)
}

/// Whether `ancestor` (at `ancestor_height`) lies on the ancestry of the block
/// hashed `descendant`, `ancestor` included.
fn on_ancestry_of(
    tree: &BlockTree,
    ancestor: NodeId,
    ancestor_height: u32,
    descendant: Hash256,
) -> bool {
    tree.lookup(descendant)
        .and_then(|id| tree.node_at_height_from(id, ancestor_height))
        == Some(ancestor)
}

/// The bounded set of recent stale tips and who already knows them.
///
/// Owned once per [`BlockSync`] and shared by `Arc` with the announcer and the
/// chain query that serves stale-tip headers. Interior mutability is one
/// mutex; see the module's locking note.
#[derive(Debug, Default)]
pub struct StaleTipRetainer {
    state: Mutex<State>,
}

impl StaleTipRetainer {
    /// Builds the retained set from the leaves already in `tree` (startup, or
    /// a restored branch store).
    ///
    /// POST: holds the best [`MAX_RETAINED_STALE_TIPS`] stale-candidate leaves
    /// by chainwork, ties to the newer slab entry; empty without an active
    /// tip. No peer knows any of them yet.
    pub(crate) fn seed(tree: &BlockTree) -> Self {
        let Some(tip) = tree.tip() else {
            return Self::default();
        };
        let mut next_sequence = 0_u64;
        let mut leaves = Vec::new();
        // Leaves arrive in ascending slab order, which is insertion order:
        // the position is the learn order.
        for (sequence, id) in (0_u64..).zip(tree.leaf_node_ids()) {
            next_sequence = sequence.saturating_add(1);
            let Ok(node) = tree.node(id) else {
                continue;
            };
            if in_scope(node, &tip) {
                leaves.push((
                    id,
                    Retained {
                        hash: node.hash,
                        work: node.chainwork,
                        sequence,
                        known_by: Vec::new(),
                    },
                ));
            }
        }
        leaves.sort_by_key(|(_, retained)| Reverse(retained.rank()));

        let mut tips = Vec::with_capacity(leaves.len().min(MAX_RETAINED_STALE_TIPS));
        for (id, retained) in leaves {
            if tips.len() == MAX_RETAINED_STALE_TIPS {
                break;
            }
            if stale_fork(tree, &tip, id).is_some() {
                tips.push(retained);
            }
        }
        Self {
            state: Mutex::new(State {
                tips,
                next_sequence,
                ..State::default()
            }),
        }
    }

    /// Records `hash`, a stale tip the caller just learned of, and returns
    /// whether it newly entered the retained set.
    ///
    /// Callers: header admission (the last header of an accepted branch, and
    /// the tip it displaced), a failed connect's displaced tip, and an
    /// invalidation's displaced tip.
    ///
    /// PRE: `hash` names the newest header of its branch in `tree` at call
    ///   time; `from` is the peer that announced it as a header chain, if one
    ///   did (a `staletip` announcer arrives through [`Self::note_heard`]).
    /// POST: `true` iff `hash` is a stale candidate in `tree` that was not
    ///   already held, no retained tip descends from it, and it outranked the
    ///   weakest tip when the set was full. Held ancestors of `hash` are
    ///   removed, and `from` plus every peer that was heard announcing `hash`
    ///   is recorded as knowing it. `false` for replays, active, invalid,
    ///   unknown, out-of-window, superseded, and outranked tips; the announcers
    ///   are still recorded when `hash` is already held, so a second announcer
    ///   is not echoed either.
    pub(crate) fn learn(&self, tree: &BlockTree, hash: Hash256, from: Option<PeerSource>) -> bool {
        let mut state = self.state.lock();
        state.prune(tree);
        if let Some(held) = state.tips.iter_mut().find(|held| held.hash == hash) {
            if let Some(peer) = from {
                held.mark_known(peer);
            }
            state.absorb_heard(hash);
            return false;
        }

        let (Some(tip), Some(id)) = (tree.tip(), tree.lookup(hash)) else {
            return false;
        };
        let (Some(fork), Ok(node)) = (stale_fork(tree, &tip, id), tree.node(id)) else {
            return false;
        };
        // A retained tip above `hash` already carries it.
        if state
            .tips
            .iter()
            .any(|held| on_ancestry_of(tree, id, node.height, held.hash))
        {
            return false;
        }

        // The branch grew past retained tips: they are superseded. The walk
        // ends at the fork, so it is as long as the branch.
        let mut cursor = node.parent;
        for _ in 0..tree.len() {
            let Some(ancestor) = cursor.filter(|&ancestor| ancestor != fork) else {
                break;
            };
            let Ok(ancestor_node) = tree.node(ancestor) else {
                break;
            };
            state.tips.retain(|held| held.hash != ancestor_node.hash);
            cursor = ancestor_node.parent;
        }

        let sequence = state.next_sequence;
        state.next_sequence = sequence.saturating_add(1);
        state.tips.push(Retained {
            hash,
            work: node.chainwork,
            sequence,
            known_by: from.into_iter().collect(),
        });
        if state.tips.len() > MAX_RETAINED_STALE_TIPS {
            let Some(weakest) = state
                .tips
                .iter()
                .enumerate()
                .min_by_key(|(_, held)| held.rank())
                .map(|(index, _)| index)
            else {
                return false;
            };
            if state.tips.swap_remove(weakest).hash == hash {
                return false;
            }
        }
        state.absorb_heard(hash);
        true
    }

    /// Notes that `peer` announced `hash` in a `staletip` whose branch the
    /// sync loop has not admitted yet, so the tip is not echoed to it once
    /// learned. Bounded: the oldest of [`MAX_RETAINED_STALE_TIPS`] unmatched
    /// notes is dropped first.
    pub(crate) fn note_heard(&self, peer: PeerSource, hash: Hash256) {
        let mut state = self.state.lock();
        if state.heard.contains(&(hash, peer)) {
            return;
        }
        if state.heard.len() == MAX_RETAINED_STALE_TIPS {
            state.heard.pop_front();
        }
        state.heard.push_back((hash, peer));
    }

    /// Drops every tip that is no longer a stale candidate in `tree`.
    pub(crate) fn prune(&self, tree: &BlockTree) {
        self.state.lock().prune(tree);
    }

    /// The retained tips to announce to `peer` now, best first.
    ///
    /// The first call for a peer opens relay with it: it offers at most
    /// [`MAX_ADVERTISED_STALETIPS`] of the tips already held, greatest
    /// chainwork first. Every later call offers only tips learned since, so a
    /// peer is never sent the backlog twice nor the part of it beyond the cap.
    ///
    /// PRE: call first for a peer once it has demonstrated a tip, so
    ///   `relayable` can choose a fork point it knows; opening is one-shot.
    /// POST: none of the returned tips is recorded as known by `peer`, and each
    ///   was accepted by `relayable`. `relayable` runs in rank order, outside
    ///   the mutex, and on opening only until the cap is met, so the work is
    ///   bounded by the cap plus the tips it rejects. A tip `relayable`
    ///   refuses stays offerable (a body still being fetched for a
    ///   `prefers_blocks` peer, say) until it is marked known or retired.
    ///   Nothing is marked known here: the caller marks each tip with
    ///   [`Self::mark_known`] after its send returned `Ok`.
    pub(crate) fn pending_for(
        &self,
        peer: PeerSource,
        mut relayable: impl FnMut(Hash256) -> bool,
    ) -> Vec<Hash256> {
        let (opening, offered) = {
            let mut state = self.state.lock();
            let opening = !state.opened.contains_key(&peer);
            let floor = state.opened.get(&peer).copied().unwrap_or(0);
            let offered: Vec<Hash256> = state
                .ranked()
                .into_iter()
                .filter(|held| held.sequence >= floor && !held.known_by.contains(&peer))
                .map(|held| held.hash)
                .collect();
            if opening {
                let opened_at = state.next_sequence;
                state.opened.insert(peer, opened_at);
            }
            (opening, offered)
        };
        let mut accepted = offered.into_iter().filter(|hash| relayable(*hash));
        if opening {
            accepted.by_ref().take(MAX_ADVERTISED_STALETIPS).collect()
        } else {
            accepted.collect()
        }
    }

    /// Whether `peer` is recorded as knowing the retained tip `hash`.
    pub(crate) fn knows(&self, peer: PeerSource, hash: Hash256) -> bool {
        self.state
            .lock()
            .tips
            .iter()
            .any(|held| held.hash == hash && held.known_by.contains(&peer))
    }

    /// Records that `peer` knows `hash`: call after a `staletip` for it was
    /// sent to `peer` and `peers.send` returned `Ok`. Does nothing for a tip
    /// that is not retained.
    pub(crate) fn mark_known(&self, peer: PeerSource, hash: Hash256) {
        if let Some(held) = self
            .state
            .lock()
            .tips
            .iter_mut()
            .find(|held| held.hash == hash)
        {
            held.mark_known(peer);
        }
    }

    /// Forgets `peer` after its session ends, so connection churn cannot grow
    /// the per-peer records.
    pub(crate) fn forget_peer(&self, peer: PeerSource) {
        let mut state = self.state.lock();
        for held in &mut state.tips {
            held.known_by.retain(|known| *known != peer);
        }
        state.opened.remove(&peer);
        state.heard.retain(|&(_, heard_from)| heard_from != peer);
    }
}

impl BlockSync {
    /// The stale-tip retainer, to hand to the announcer and the chain query
    /// that serve stale-tip relay. Seeded from the block tree at construction
    /// and kept across [`BlockSync::install_budget`].
    #[must_use]
    pub fn stale_tips(&self) -> Arc<StaleTipRetainer> {
        Arc::clone(&self.stale_tips)
    }

    /// Records a valid tip a chain transition displaced onto another branch,
    /// so it can be relayed as a stale tip. Returns whether it newly entered
    /// the retained set.
    ///
    /// For the transitions that report the displacement outside header
    /// admission, such as an RPC `invalidateblock`
    /// (`InvalidationOutcome::demoted_tip`): call after the invalid subtree is
    /// purged and the chain-transition guard is released. An invalid tip is
    /// never retained.
    pub fn record_demoted_tip(&self, hash: Hash256) -> bool {
        let tree = self.chain.block_tree();
        self.stale_tips.learn(&tree, hash, None)
    }

    /// Records what one header admission reported: the tip it displaced and
    /// the newest header it admitted, which is stale when its branch lost.
    ///
    /// `from` is the delivering connection of a headers message, so the
    /// branch's announcer is not echoed its own tip.
    pub(super) fn record_admitted_tips(
        &self,
        demoted_tip: Option<Hash256>,
        announced_tip: Option<Hash256>,
        from: Option<PeerSource>,
    ) {
        if demoted_tip.is_none() && announced_tip.is_none() {
            return;
        }
        let tree = self.chain.block_tree();
        if let Some(tip) = demoted_tip {
            self.stale_tips.learn(&tree, tip, None);
        }
        if let Some(tip) = announced_tip {
            self.stale_tips.learn(&tree, tip, from);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use bitcoin_rs_chain::regtest_fixture::mined_regtest_header;
    use bitcoin_rs_primitives::{BlockHash, Network};

    use super::*;

    type TestError = Box<dyn std::error::Error>;

    /// A block tree grown with mined regtest headers. Every header carries a
    /// unique time, so siblings under one parent are distinct blocks of equal
    /// work.
    struct Fixture {
        tree: BlockTree,
        genesis: NodeId,
        salt: u32,
    }

    #[derive(Clone, Copy)]
    struct Block {
        id: NodeId,
        hash: Hash256,
    }

    impl Fixture {
        fn new() -> Result<Self, TestError> {
            let mut tree = BlockTree::new();
            let genesis = tree.insert_node(
                None,
                Network::Regtest.genesis_block().header,
                NodeStatus::HeaderValid,
            )?;
            Ok(Self {
                tree,
                genesis,
                salt: 1,
            })
        }

        fn child_with(&mut self, parent: NodeId, status: NodeStatus) -> Result<Block, TestError> {
            let prev = self.tree.node(parent)?.hash;
            self.salt += 1;
            let header = mined_regtest_header(BlockHash::from(prev), self.salt)?;
            let id = self.tree.insert_node(Some(parent), header, status)?;
            Ok(Block {
                id,
                hash: self.tree.node(id)?.hash,
            })
        }

        fn child(&mut self, parent: NodeId) -> Result<Block, TestError> {
            self.child_with(parent, NodeStatus::HeaderValid)
        }

        /// `len` headers in a row above `from`; the blocks, lowest first.
        fn branch(&mut self, from: NodeId, len: usize) -> Result<Vec<Block>, TestError> {
            let mut blocks = Vec::with_capacity(len);
            let mut parent = from;
            for _ in 0..len {
                let block = self.child(parent)?;
                parent = block.id;
                blocks.push(block);
            }
            Ok(blocks)
        }

        /// A main chain of `len` blocks above genesis; `chain[i]` has height
        /// `i + 1`.
        fn main_chain(&mut self, len: usize) -> Result<Vec<Block>, TestError> {
            self.branch(self.genesis, len)
        }
    }

    fn hashes(blocks: &[Block]) -> Vec<Hash256> {
        blocks.iter().map(|block| block.hash).collect()
    }

    fn peer(port: u16) -> PeerSource {
        PeerSource::for_test(SocketAddr::from(([127, 0, 0, 1], port)))
    }

    /// The retained tips in `tree`, best first.
    fn candidates(retainer: &StaleTipRetainer, tree: &BlockTree) -> Vec<Hash256> {
        let mut state = retainer.state.lock();
        state.prune(tree);
        state.ranked().into_iter().map(|held| held.hash).collect()
    }

    fn held_by(retainer: &StaleTipRetainer, hash: Hash256) -> Option<usize> {
        retainer
            .state
            .lock()
            .tips
            .iter()
            .find(|held| held.hash == hash)
            .map(|held| held.known_by.len())
    }

    #[test]
    fn seed_ranks_recent_side_leaves_and_skips_active_and_invalid() -> Result<(), TestError> {
        let mut fixture = Fixture::new()?;
        let main = fixture.main_chain(30)?;
        // Height 25 -> 27 and height 10 -> 13: the first has more work.
        let near = fixture.branch(main[24].id, 2)?;
        let far = fixture.branch(main[9].id, 3)?;
        fixture.child_with(main[14].id, NodeStatus::Invalid)?;

        let retainer = StaleTipRetainer::seed(&fixture.tree);

        assert_eq!(
            candidates(&retainer, &fixture.tree),
            vec![near[1].hash, far[2].hash],
            "the active tip and the invalid leaf are not candidates"
        );
        Ok(())
    }

    #[test]
    fn seed_without_an_active_tip_retains_nothing() {
        let tree = BlockTree::new();
        assert_eq!(candidates(&StaleTipRetainer::seed(&tree), &tree), []);
    }

    #[test]
    fn seed_applies_the_recent_window_at_its_boundary() -> Result<(), TestError> {
        let mut fixture = Fixture::new()?;
        let main = fixture.main_chain(1005)?;
        // Active tip height 1005: a stale tip at height 5 is exactly 1000
        // behind, one at height 4 is 1001 behind.
        let inside = fixture.child(main[3].id)?;
        let outside = fixture.child(main[2].id)?;

        let retainer = StaleTipRetainer::seed(&fixture.tree);

        assert_eq!(candidates(&retainer, &fixture.tree), vec![inside.hash]);
        assert!(!retainer.learn(&fixture.tree, outside.hash, None));
        Ok(())
    }

    #[test]
    fn seed_keeps_the_newest_of_equal_work_up_to_the_cap() -> Result<(), TestError> {
        let mut fixture = Fixture::new()?;
        let main = fixture.main_chain(100)?;
        let mut leaves = Vec::new();
        for _ in 0..MAX_RETAINED_STALE_TIPS + 6 {
            leaves.push(fixture.child(main[49].id)?);
        }

        let retainer = StaleTipRetainer::seed(&fixture.tree);

        let mut expected = hashes(&leaves[6..]);
        expected.reverse();
        assert_eq!(candidates(&retainer, &fixture.tree), expected);
        Ok(())
    }

    #[test]
    fn learn_replaces_a_retained_parent_and_ignores_replays() -> Result<(), TestError> {
        let mut fixture = Fixture::new()?;
        let main = fixture.main_chain(20)?;
        let side = fixture.branch(main[9].id, 4)?;
        let retainer = StaleTipRetainer::seed(&fixture.tree);
        assert_eq!(candidates(&retainer, &fixture.tree), vec![side[3].hash]);

        let retainer = StaleTipRetainer::default();
        assert!(retainer.learn(&fixture.tree, side[0].hash, None));
        assert!(retainer.learn(&fixture.tree, side[1].hash, None));
        assert_eq!(candidates(&retainer, &fixture.tree), vec![side[1].hash]);

        // Replays of the held tip and of a header below it add nothing.
        assert!(!retainer.learn(&fixture.tree, side[1].hash, None));
        assert!(!retainer.learn(&fixture.tree, side[0].hash, None));

        // One announcement carrying two more headers supersedes the held tip
        // without the intermediate header ever being learned.
        assert!(retainer.learn(&fixture.tree, side[3].hash, None));
        assert_eq!(candidates(&retainer, &fixture.tree), vec![side[3].hash]);
        Ok(())
    }

    #[test]
    fn learn_refuses_active_ancestor_unknown_and_invalid_tips() -> Result<(), TestError> {
        let mut fixture = Fixture::new()?;
        let main = fixture.main_chain(20)?;
        let invalid = fixture.child_with(main[9].id, NodeStatus::Invalid)?;
        let retainer = StaleTipRetainer::default();

        assert!(
            !retainer.learn(&fixture.tree, main[19].hash, None),
            "active tip"
        );
        assert!(
            !retainer.learn(&fixture.tree, main[5].hash, None),
            "active ancestor"
        );
        assert!(
            !retainer.learn(&fixture.tree, Hash256::from_le_bytes(&[0xaa; 32]), None),
            "unknown to the tree"
        );
        assert!(
            !retainer.learn(&fixture.tree, invalid.hash, None),
            "invalid"
        );
        assert_eq!(candidates(&retainer, &fixture.tree), []);
        Ok(())
    }

    #[test]
    fn learn_without_an_active_tip_holds_nothing() {
        let retainer = StaleTipRetainer::default();
        let tree = BlockTree::new();
        assert!(!retainer.learn(&tree, Hash256::from_le_bytes(&[1; 32]), None));
    }

    #[test]
    fn a_branch_switch_demotes_the_old_tip_into_the_set_and_prunes_the_new_one()
    -> Result<(), TestError> {
        let mut fixture = Fixture::new()?;
        let main = fixture.main_chain(20)?;
        let old_tip = main[19];
        // Three blocks above height 18 reach height 21 and outweigh the old
        // tip, which the tree demotes.
        let heavier = fixture.branch(main[17].id, 3)?;
        assert_eq!(
            fixture.tree.tip().map(|tip| tip.hash),
            Some(heavier[2].hash)
        );

        let retainer = StaleTipRetainer::seed(&fixture.tree);
        assert_eq!(
            candidates(&retainer, &fixture.tree),
            vec![old_tip.hash],
            "restored demotion is found at startup"
        );

        let live = StaleTipRetainer::default();
        assert!(live.learn(&fixture.tree, old_tip.hash, None));
        assert_eq!(candidates(&live, &fixture.tree), vec![old_tip.hash]);

        // The old branch regains the lead: its tip is no longer stale and the
        // overtaken tip takes its place once the caller reports the demotion.
        let regained = fixture.branch(old_tip.id, 2)?;
        assert_eq!(
            fixture.tree.tip().map(|tip| tip.hash),
            Some(regained[1].hash)
        );
        assert_eq!(candidates(&live, &fixture.tree), []);
        assert!(live.learn(&fixture.tree, heavier[2].hash, None));
        assert_eq!(candidates(&live, &fixture.tree), vec![heavier[2].hash]);
        Ok(())
    }

    #[test]
    fn invalidating_a_side_branch_retires_its_tip() -> Result<(), TestError> {
        let mut fixture = Fixture::new()?;
        let main = fixture.main_chain(20)?;
        let side = fixture.branch(main[9].id, 2)?;
        let retainer = StaleTipRetainer::default();
        assert!(retainer.learn(&fixture.tree, side[1].hash, None));

        fixture.tree.invalidate_subtree(side[0].id)?;

        assert_eq!(candidates(&retainer, &fixture.tree), []);
        assert!(!retainer.learn(&fixture.tree, side[1].hash, None));
        Ok(())
    }

    #[test]
    fn tips_leave_the_set_as_the_active_chain_moves_past_the_window() -> Result<(), TestError> {
        let mut fixture = Fixture::new()?;
        let mut main = fixture.main_chain(10)?;
        // Height 9, so it stays while the active tip is at most 1009.
        let side = fixture.child(main[7].id)?;
        let retainer = StaleTipRetainer::default();
        assert!(retainer.learn(&fixture.tree, side.hash, None));

        let mut tip = main[9];
        for _ in 0..999 {
            tip = fixture.child(tip.id)?;
            main.push(tip);
        }
        assert_eq!(fixture.tree.tip().map(|tip| tip.height), Some(1009));
        assert_eq!(candidates(&retainer, &fixture.tree), vec![side.hash]);

        fixture.child(tip.id)?;
        assert_eq!(candidates(&retainer, &fixture.tree), []);
        Ok(())
    }

    #[test]
    fn capacity_evicts_the_weakest_oldest_and_refuses_weaker_newcomers() -> Result<(), TestError> {
        let mut fixture = Fixture::new()?;
        let main = fixture.main_chain(100)?;
        let retainer = StaleTipRetainer::default();
        let mut leaves = Vec::new();
        for _ in 0..MAX_RETAINED_STALE_TIPS + 6 {
            let leaf = fixture.child(main[49].id)?;
            assert!(retainer.learn(&fixture.tree, leaf.hash, None));
            leaves.push(leaf);
        }
        let mut expected = hashes(&leaves[6..]);
        expected.reverse();
        let held = candidates(&retainer, &fixture.tree);
        assert_eq!(held.len(), MAX_RETAINED_STALE_TIPS);
        assert_eq!(held, expected, "the six oldest equal-work tips left");

        // Less work than every held tip: refused, nothing displaced.
        let weaker = fixture.child(main[29].id)?;
        assert!(!retainer.learn(&fixture.tree, weaker.hash, None));
        assert_eq!(candidates(&retainer, &fixture.tree), expected);

        // More work: ranks first and displaces the weakest, oldest tip.
        let stronger = fixture.child(main[59].id)?;
        assert!(retainer.learn(&fixture.tree, stronger.hash, None));
        let held = candidates(&retainer, &fixture.tree);
        assert_eq!(held.len(), MAX_RETAINED_STALE_TIPS);
        assert_eq!(held[0], stronger.hash);
        assert!(!held.contains(&leaves[6].hash));
        assert_eq!(held[MAX_RETAINED_STALE_TIPS - 1], leaves[7].hash);
        Ok(())
    }

    #[test]
    fn announcers_are_never_echoed_and_sent_tips_are_not_repeated() -> Result<(), TestError> {
        let mut fixture = Fixture::new()?;
        let main = fixture.main_chain(20)?;
        let side = fixture.branch(main[9].id, 2)?;
        let (a, b, c) = (peer(1), peer(2), peer(3));
        let retainer = StaleTipRetainer::default();

        assert!(retainer.learn(&fixture.tree, side[0].hash, Some(a)));
        assert!(
            retainer.knows(a, side[0].hash),
            "the announcer is not echoed"
        );
        assert!(!retainer.knows(b, side[0].hash));

        retainer.mark_known(b, side[0].hash);
        retainer.mark_known(b, side[0].hash);
        assert!(retainer.knows(b, side[0].hash));
        assert_eq!(
            held_by(&retainer, side[0].hash),
            Some(2),
            "recorded once per peer"
        );

        // A second announcer of a held tip learns nothing new but is recorded.
        assert!(!retainer.learn(&fixture.tree, side[0].hash, Some(c)));
        assert!(retainer.knows(c, side[0].hash));

        // The branch grows: the longer tip is new to everyone, including the
        // peers that knew its parent, which is gone from the set.
        assert!(retainer.learn(&fixture.tree, side[1].hash, Some(b)));
        assert!(retainer.knows(b, side[1].hash));
        assert!(!retainer.knows(a, side[1].hash));
        assert!(
            !retainer.knows(a, side[0].hash),
            "the parent is no longer retained"
        );
        retainer.mark_known(a, side[0].hash);
        assert_eq!(
            held_by(&retainer, side[0].hash),
            None,
            "marking a gone tip is a no-op"
        );

        retainer.forget_peer(b);
        assert!(!retainer.knows(b, side[1].hash));
        assert_eq!(held_by(&retainer, side[1].hash), Some(0));
        Ok(())
    }

    #[test]
    fn relay_opens_once_with_at_most_ten_tips_and_then_offers_only_new_ones()
    -> Result<(), TestError> {
        let mut fixture = Fixture::new()?;
        let main = fixture.main_chain(100)?;
        let retainer = StaleTipRetainer::default();
        let mut leaves = Vec::new();
        for _ in 0..MAX_ADVERTISED_STALETIPS + 3 {
            let leaf = fixture.child(main[49].id)?;
            assert!(retainer.learn(&fixture.tree, leaf.hash, None));
            leaves.push(leaf);
        }
        let rejected = leaves[11];
        let peer = peer(9);
        retainer.mark_known(peer, leaves[12].hash);

        retainer.prune(&fixture.tree);
        let mut asked = Vec::new();
        let opening = retainer.pending_for(peer, |hash| {
            asked.push(hash);
            hash != rejected.hash
        });

        let expected: Vec<Hash256> = leaves[1..=10].iter().rev().map(|leaf| leaf.hash).collect();
        assert_eq!(
            opening, expected,
            "ranked, skipping the known and the refused"
        );
        assert_eq!(
            asked.len(),
            MAX_ADVERTISED_STALETIPS + 1,
            "the predicate stops once the cap is met"
        );
        assert!(!retainer.knows(peer, expected[0]), "offering marks nothing");

        // The backlog is never offered again, nor the part beyond the cap.
        let again = retainer.pending_for(peer, |_| panic!("no tip is pending"));
        assert_eq!(again, []);

        // A tip learned afterwards is offered, exactly once it is marked.
        let fresh = fixture.child(main[49].id)?;
        assert!(retainer.learn(&fixture.tree, fresh.hash, None));
        retainer.prune(&fixture.tree);
        assert_eq!(
            retainer.pending_for(peer, |_| false),
            Vec::<Hash256>::new(),
            "a refused tip, a body still being fetched, is not lost"
        );
        assert_eq!(retainer.pending_for(peer, |_| true), vec![fresh.hash]);
        retainer.mark_known(peer, fresh.hash);
        assert_eq!(retainer.pending_for(peer, |_| true), []);

        // A reconnecting peer is a new peer: it is opened again.
        retainer.forget_peer(peer);
        assert_eq!(
            retainer.pending_for(peer, |_| true).len(),
            MAX_ADVERTISED_STALETIPS
        );
        Ok(())
    }

    #[test]
    fn a_peer_that_announced_a_tip_before_admission_is_not_echoed_once_it_is_learned()
    -> Result<(), TestError> {
        let mut fixture = Fixture::new()?;
        let main = fixture.main_chain(20)?;
        let side = fixture.child(main[9].id)?;
        let (origin, other) = (peer(1), peer(2));
        let retainer = StaleTipRetainer::default();

        retainer.note_heard(origin, side.hash);
        retainer.note_heard(origin, side.hash);
        assert_eq!(
            retainer.state.lock().heard.len(),
            1,
            "one note per peer and tip"
        );
        assert!(
            !retainer.knows(origin, side.hash),
            "nothing is retained yet"
        );

        assert!(retainer.learn(&fixture.tree, side.hash, None));
        assert!(retainer.knows(origin, side.hash));
        assert!(!retainer.knows(other, side.hash));
        assert!(
            retainer.state.lock().heard.is_empty(),
            "the note was consumed"
        );
        Ok(())
    }

    #[test]
    fn unmatched_heard_notes_are_bounded_and_dropped_with_their_peer() {
        let retainer = StaleTipRetainer::default();
        let gone = peer(1);
        for index in 0..=MAX_RETAINED_STALE_TIPS {
            retainer.note_heard(
                peer(2),
                Hash256::from_le_bytes(&[u8::try_from(index).unwrap_or(0); 32]),
            );
        }
        retainer.note_heard(gone, Hash256::from_le_bytes(&[0xee; 32]));
        assert_eq!(retainer.state.lock().heard.len(), MAX_RETAINED_STALE_TIPS);

        retainer.forget_peer(gone);
        assert!(
            retainer
                .state
                .lock()
                .heard
                .iter()
                .all(|&(_, from)| from != gone)
        );
    }
}
