use std::net::SocketAddr;

use bitcoin_rs_chain::regtest_fixture::mined_regtest_header;
use bitcoin_rs_primitives::{BlockHash, Network};

use super::*;

type TestError = Box<dyn std::error::Error>;

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

    assert!(!retainer.learn(&fixture.tree, side[1].hash, None));
    assert!(!retainer.learn(&fixture.tree, side[0].hash, None));

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
fn a_branch_switch_demotes_the_old_tip_into_the_set_and_prunes_the_new_one() -> Result<(), TestError>
{
    let mut fixture = Fixture::new()?;
    let main = fixture.main_chain(20)?;
    let old_tip = main[19];
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

    let weaker = fixture.child(main[29].id)?;
    assert!(!retainer.learn(&fixture.tree, weaker.hash, None));
    assert_eq!(candidates(&retainer, &fixture.tree), expected);

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

    assert!(!retainer.learn(&fixture.tree, side[0].hash, Some(c)));
    assert!(retainer.knows(c, side[0].hash));

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
fn relay_opens_once_with_at_most_ten_tips_and_then_offers_only_new_ones() -> Result<(), TestError> {
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

    let retry = retainer.pending_for(peer, |_| true);
    assert_eq!(retry, expected, "unacked selected tips are offered again");
    for hash in &expected {
        retainer.mark_known(peer, *hash);
    }
    assert_eq!(
        retainer.pending_for(peer, |_| true),
        Vec::<Hash256>::new(),
        "acked selected tips leave no extra old beyond the cap"
    );

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
