use bitcoin_rs_primitives::{BlockHash, CompactTarget};

use super::{BlockTree, Hash256};
use crate::{
    ChainError, ChainTxCount,
    node::{BlockHeader, NodeId, NodeStatus},
};

fn extend(tree: &mut BlockTree, parent: NodeId, nonce: u32) -> Result<NodeId, ChainError> {
    let header = test_header(BlockHash(tree.node(parent)?.hash), nonce);
    tree.insert_node(Some(parent), header, NodeStatus::HeaderValid)
}

fn extend_with_fact(
    tree: &mut BlockTree,
    parent: NodeId,
    nonce: u32,
) -> Result<(NodeId, Option<Hash256>), ChainError> {
    let header = test_header(BlockHash(tree.node(parent)?.hash), nonce);
    let hash = Hash256::from(header.compute_hash());
    let inserted =
        tree.insert_node_with_hash(Some(parent), header, hash, NodeStatus::HeaderValid)?;
    Ok((inserted.id, inserted.demoted_tip))
}

fn extend_branch_with_facts(
    tree: &mut BlockTree,
    parent: NodeId,
    nonces: impl IntoIterator<Item = u32>,
) -> Result<Vec<(NodeId, Option<Hash256>)>, ChainError> {
    let mut cursor = parent;
    let mut steps = Vec::new();
    for nonce in nonces {
        let step = extend_with_fact(tree, cursor, nonce)?;
        cursor = step.0;
        steps.push(step);
    }
    Ok(steps)
}

fn demoted_facts(steps: &[(NodeId, Option<Hash256>)]) -> Vec<Option<Hash256>> {
    steps.iter().map(|(_, demoted)| *demoted).collect()
}

fn extend_branch(
    tree: &mut BlockTree,
    parent: NodeId,
    nonces: impl IntoIterator<Item = u32>,
) -> Result<Vec<NodeId>, ChainError> {
    let mut cursor = parent;
    let mut ids = Vec::new();
    for nonce in nonces {
        cursor = extend(tree, cursor, nonce)?;
        ids.push(cursor);
    }
    Ok(ids)
}

fn linear_chain(count: u32) -> Result<(BlockTree, Vec<NodeId>), ChainError> {
    let mut tree = BlockTree::new();
    let genesis = tree.insert_node(
        None,
        test_header(BlockHash::default(), 0),
        NodeStatus::HeaderValid,
    )?;
    let mut ids = vec![genesis];
    ids.extend(extend_branch(&mut tree, genesis, 1..=count)?);
    Ok((tree, ids))
}

fn timed_chain(count: u32) -> Result<(BlockTree, Vec<NodeId>, Vec<u32>), ChainError> {
    let mut tree = BlockTree::new();
    let mut prev_blockhash = BlockHash::default();
    let (mut ids, mut times) = (Vec::new(), Vec::new());
    for i in 0..count {
        let header = BlockHeader {
            version: 1,
            prev_blockhash,
            merkle_root: Hash256::default(),
            time: 1_000_000 + i * 600,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        };
        prev_blockhash = header.compute_hash();
        times.push(header.time);
        ids.push(tree.insert_header(header, NodeStatus::HeaderValid)?);
    }
    Ok((tree, ids, times))
}

#[test]
fn block_locator_falls_back_after_active_parent_mutation() -> Result<(), Box<dyn std::error::Error>>
{
    let (mut tree, ids) = linear_chain(2)?;
    let (a, c) = (ids[0], ids[2]);

    tree.node_mut(c)?.parent = Some(a);

    let expected = vec![tree.node(c)?.hash, tree.node(a)?.hash];
    assert_eq!(tree.block_locator(c, 3), expected);
    Ok(())
}

#[test]
fn block_locator_falls_back_on_same_height_fork_index_corruption()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut tree, ids) = linear_chain(2)?;
    let (genesis_id, main_child_id, main_tip_id) = (ids[0], ids[1], ids[2]);

    let fork_child_id = extend(&mut tree, genesis_id, 11)?;
    let fork_hash = tree.node(fork_child_id)?.hash;

    assert_eq!(tree.active_by_height.last(), Some(main_tip_id));
    assert_eq!(tree.active_by_height.get(1), Some(main_child_id));

    assert!(
        tree.active_by_height
            .replace_slot_for_test(1, fork_child_id)
    );

    let corrupted_locator = tree.block_locator(main_tip_id, 32);
    tree.active_by_height.taint();
    let parent_walk_locator = tree.block_locator(main_tip_id, 32);

    assert_eq!(corrupted_locator, parent_walk_locator);
    assert!(!corrupted_locator.contains(&fork_hash));
    assert_eq!(
        corrupted_locator,
        vec![
            tree.node(main_tip_id)?.hash,
            tree.node(main_child_id)?.hash,
            tree.node(genesis_id)?.hash,
        ]
    );
    Ok(())
}

#[test]
fn block_locator_rejects_coherent_side_fork_index_substitution()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut tree, main_ids) = linear_chain(40)?;

    let side_ids = extend_branch(&mut tree, main_ids[18], 1019..=1026)?;
    let side_hashes = side_ids
        .iter()
        .map(|id| tree.node(*id).map(|node| node.hash))
        .collect::<Result<Vec<_>, _>>()?;

    assert_eq!(tree.tip_id(), Some(main_ids[40]));
    assert!(tree.active_by_height.is_trusted());

    for (offset, side_id) in (0_u32..).zip(side_ids.iter()) {
        let height = 19 + offset;
        assert!(
            tree.active_by_height
                .replace_slot_for_test(height, *side_id)
        );
    }
    assert!(tree.active_by_height.is_tainted_for_test());

    let i24 = tree.active_by_height.get(24).ok_or("corrupted slot 24")?;
    let i23 = tree.active_by_height.get(23).ok_or("corrupted slot 23")?;
    let i25 = tree.active_by_height.get(25).ok_or("corrupted slot 25")?;
    assert_eq!(tree.node(i24)?.height, 24);
    assert_eq!(tree.node(i24)?.parent, Some(i23));
    assert_eq!(tree.node(i25)?.parent, Some(i24));

    for (offset, &side_id) in side_ids.iter().enumerate() {
        let height = 19 + u32::try_from(offset).map_err(|_| "side chain offset fits u32")?;
        assert_eq!(tree.node(side_id)?.height, height);
        if height == 19 {
            assert_eq!(tree.node(side_id)?.parent, Some(main_ids[18]));
        } else {
            assert_eq!(tree.node(side_id)?.parent, Some(side_ids[offset - 1]));
        }
    }

    let expected = locator_hashes_at_heights(&tree, &main_ids, &CORE_LOCATOR_HEIGHTS_40)?;
    assert_eq!(tree.block_locator(main_ids[40], 32), expected);
    for side_hash in &side_hashes {
        assert!(!expected.contains(side_hash));
    }
    Ok(())
}

#[test]
fn node_at_height_from_ignores_tainted_index_slot() -> Result<(), Box<dyn std::error::Error>> {
    let (mut tree, main_ids) = linear_chain(40)?;
    let side_id = extend(&mut tree, main_ids[18], 1019)?;

    assert!(tree.active_by_height.replace_slot_for_test(19, side_id));
    assert!(tree.active_by_height.is_tainted_for_test());

    assert_eq!(
        tree.node_at_height_from(main_ids[30], 19),
        Some(main_ids[19])
    );
    assert_ne!(tree.node_at_height_from(main_ids[30], 19), Some(side_id));
    Ok(())
}

#[test]
fn bounded_ancestry_rejects_side_parent_gap_before_index_shortcut()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut tree, main) = linear_chain(5)?;
    let side = extend_branch(&mut tree, main[0], 11..=13)?;
    let tip = *side.last().ok_or("no side tip")?;
    tree.node_mut(tip)?.parent = Some(main[0]);
    assert!(tree.active_by_height.is_trusted());
    assert_eq!(tree.node_at_height_from(tip, 1), None);
    assert_eq!(tree.node_at_height_from_bounded(tip, 1, &mut 8)?, None);
    Ok(())
}

#[test]
fn bounded_ancestry_counts_only_unindexed_parent_hops() -> Result<(), Box<dyn std::error::Error>> {
    let (mut tree, main) = linear_chain(10_000)?;
    let side = extend_branch(&mut tree, main[4000], 20_000..=24_095)?;
    let tip = *side.last().ok_or("no side tip")?;
    let mut short = 4095;
    assert_eq!(
        tree.node_at_height_from_bounded(tip, 0, &mut short),
        Err(crate::AncestryBudgetExceeded)
    );
    assert_eq!(short, 0);
    let mut exact = 4096;
    assert_eq!(
        tree.node_at_height_from_bounded(tip, 0, &mut exact)?,
        Some(main[0])
    );
    assert_eq!(exact, 0, "the indexed prefix requires no parent walk");
    assert_eq!(
        tree.node_at_height_from_bounded(main[10_000], 0, &mut exact)?,
        Some(main[0])
    );
    Ok(())
}

#[test]
fn node_at_height_from_indexes_active_prefix_but_walks_side_chain()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut tree, main_ids) = linear_chain(5)?;
    let mut side_ids = vec![main_ids[0]];
    side_ids.extend(extend_branch(&mut tree, main_ids[0], 11..=13)?);

    assert_eq!(tree.node_at_height_from(side_ids[3], 1), Some(side_ids[1]));

    let active_prefix = main_ids[4];
    let active_prefix_index = active_prefix.index().ok_or("invalid active prefix")?;
    tree.nodes
        .get_mut(active_prefix_index)
        .ok_or("missing active prefix")?
        .parent = None;
    assert_eq!(
        tree.node_at_height_from(active_prefix, 1),
        Some(main_ids[1])
    );
    Ok(())
}

#[test]
fn median_time_past_matches_an_independent_median_over_every_prefix()
-> Result<(), Box<dyn std::error::Error>> {
    let (tree, ids, times) = timed_chain(15)?;
    let tip = *ids.last().ok_or("chain has a tip")?;

    assert_eq!(tree.median_time_past_at(ids[10]), Some(1_003_000));
    for (height, &id) in ids.iter().enumerate() {
        assert_eq!(
            tree.median_time_past_at(id),
            Some(expected_median_time_past(&times[..=height], 11)),
            "height {height}"
        );
        assert_eq!(
            tree.median_time_past_before_height(tip, u32::try_from(height + 1)?),
            tree.median_time_past_at(id),
            "before height {}",
            height + 1
        );
    }
    assert_eq!(
        tree.median_time_past_at(crate::node::NodeId::new(u32::MAX)),
        None
    );

    assert_eq!(tree.median_time_past_before_height(tip, 0), None);
    assert_eq!(tree.median_time_past_before_height(tip, 1), Some(times[0]));
    Ok(())
}

fn expected_median_time_past(times_oldest_first: &[u32], window: usize) -> u32 {
    let take = window.min(times_oldest_first.len());
    let mut sample: Vec<u32> = times_oldest_first[times_oldest_first.len() - take..].to_vec();
    sample.sort_unstable();
    sample[sample.len() / 2]
}

#[test]
fn tip_id_returns_published_tip() -> Result<(), Box<dyn std::error::Error>> {
    let mut tree = BlockTree::new();
    let genesis_id = tree.insert_node(
        None,
        test_header(BlockHash::default(), 0),
        NodeStatus::Active,
    )?;

    assert_eq!(tree.tip_id(), Some(genesis_id));
    assert_eq!(tree.tip_height(), Some(0));
    assert_eq!(
        tree.tip().map(|tip| tip.hash),
        Some(tree.node(genesis_id)?.hash)
    );
    Ok(())
}

#[test]
fn node_at_height_from_uses_rebuilt_active_height_index_after_fork_switch()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut tree, main_ids) = linear_chain(2)?;
    let (genesis_id, main_child_id, main_tip_id) = (main_ids[0], main_ids[1], main_ids[2]);
    assert_eq!(
        tree.node_at_height_from(main_tip_id, 1),
        Some(main_child_id)
    );

    let fork_ids = extend_branch(&mut tree, genesis_id, 11..=13)?;
    let (fork_child_id, fork_tip_id) = (fork_ids[0], fork_ids[2]);

    assert_eq!(
        tree.node_at_height_from(fork_tip_id, 1),
        Some(fork_child_id)
    );
    assert_eq!(
        tree.active_node_at_height(1)
            .unwrap_or_else(|| panic!("missing active node at fork height"))
            .hash,
        tree.node(fork_child_id)?.hash
    );
    assert_eq!(
        tree.node_at_height_from(main_tip_id, 1),
        Some(main_child_id)
    );
    Ok(())
}

#[test]
fn a_fork_has_two_leaves_whose_common_ancestor_is_the_fork_point()
-> Result<(), Box<dyn std::error::Error>> {
    let mut tree = BlockTree::new();
    let genesis = test_header(BlockHash::default(), 0);
    let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
    let mut variant_a = test_header(genesis.compute_hash(), 1);
    variant_a.nonce = 1;
    let mut variant_b = test_header(genesis.compute_hash(), 2);
    variant_b.nonce = 2;
    let leaf_a = tree.insert_node(Some(genesis_id), variant_a, NodeStatus::HeaderValid)?;
    let leaf_b = tree.insert_node(Some(genesis_id), variant_b, NodeStatus::HeaderValid)?;

    assert_eq!(tree.find_common_ancestor(leaf_a, leaf_b), Some(genesis_id));

    let leaves = tree.leaf_node_ids();
    assert_eq!(
        leaves.len(),
        2,
        "expected two leaves on fork, got {leaves:?}"
    );
    assert!(leaves.contains(&leaf_a) && leaves.contains(&leaf_b));
    Ok(())
}

#[test]
fn find_common_ancestor_resolves_uneven_branches_after_index_taint()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut tree, trunk) = linear_chain(8)?;
    let side = extend_branch(&mut tree, trunk[2], 101..=103)?;
    let other = extend_branch(&mut tree, trunk[4], 201..=202)?;
    let cases = [
        (trunk[8], trunk[4], trunk[4]),
        (trunk[1], side[2], trunk[1]),
        (trunk[8], side[2], trunk[2]),
        (side[2], other[1], trunk[2]),
        (side[1], side[2], side[1]),
        (side[2], side[2], side[2]),
    ];
    assert!(tree.active_by_height.is_trusted());
    for tainted in [false, true] {
        if tainted {
            tree.node_mut(trunk[4])?.height = 100;
        }
        for (a, b, expected) in cases {
            assert_eq!(tree.find_common_ancestor(a, b), Some(expected));
            assert_eq!(tree.find_common_ancestor(b, a), Some(expected));
        }
    }
    Ok(())
}

#[test]
fn find_common_ancestor_refuses_disconnected_and_broken_chains()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut tree, a) = linear_chain(3)?;
    let b_root = tree.insert_node(
        None,
        test_header(BlockHash::default(), 101),
        NodeStatus::HeaderValid,
    )?;
    let b_tip = extend_branch(&mut tree, b_root, 102..=103)?[1];
    let unknown = NodeId::new(u32::MAX);
    for (left, right) in [(a[3], b_tip), (a[3], unknown), (unknown, a[3])] {
        assert_eq!(tree.find_common_ancestor(left, right), None);
    }
    tree.node_mut(a[1])?.parent = Some(unknown);
    assert_eq!(tree.find_common_ancestor(a[3], a[2]), None);
    tree.node_mut(a[1])?.parent = Some(a[2]);
    assert_eq!(tree.find_common_ancestor(a[3], b_tip), None);
    assert_eq!(tree.find_common_ancestor(b_tip, a[3]), None);
    Ok(())
}

#[test]
fn node_at_height_from_terminates_on_two_node_cycle_with_malformed_height()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut tree, ids) = linear_chain(1)?;
    let (a, b) = (ids[0], ids[1]);

    tree.node_mut(a)?.parent = Some(b);
    tree.node_mut(a)?.height = 2;

    assert_eq!(tree.node_at_height_from(b, 0), None);
    Ok(())
}

#[test]
fn refresh_active_height_index_clears_on_every_untrustworthy_chain_shape()
-> Result<(), Box<dyn std::error::Error>> {
    type Corruption = fn(&mut BlockTree, &[NodeId]) -> Result<(), ChainError>;
    let corruptions: [(&str, u32, Corruption); 3] = [
        ("parent cycle", 1, |tree, ids| {
            tree.node_mut(ids[0])?.parent = Some(ids[1]);
            Ok(())
        }),
        ("parent not in the tree", 2, |tree, ids| {
            tree.node_mut(ids[1])?.parent = Some(crate::node::NodeId::new(u32::MAX));
            Ok(())
        }),
        ("height disagrees with the walk", 2, |tree, ids| {
            tree.node_mut(ids[1])?.height = 99;
            Ok(())
        }),
    ];

    for (name, height, corrupt) in corruptions {
        let (mut tree, ids) = linear_chain(height)?;
        assert!(tree.active_by_height.is_trusted(), "{name} precondition");
        corrupt(&mut tree, &ids)?;
        let next = extend(&mut tree, ids[usize::try_from(height)?], height + 1)?;

        assert_eq!(tree.tip_id(), Some(next), "{name}");
        assert!(tree.active_by_height.is_empty_for_test(), "{name}");
        assert!(
            tree.active_node_at_height(1)
                .is_none_or(|node| node.height == 1),
            "{name}"
        );
    }
    Ok(())
}

const CORE_LOCATOR_HEIGHTS_40: [u32; 16] = [
    40, 39, 38, 37, 36, 35, 34, 33, 32, 31, 30, 29, 27, 23, 15, 0,
];

fn locator_hashes_at_heights(
    tree: &BlockTree,
    nodes: &[NodeId],
    heights: &[u32],
) -> Result<Vec<Hash256>, Box<dyn std::error::Error>> {
    let mut out = Vec::with_capacity(heights.len());
    for &height in heights {
        let idx = usize::try_from(height)?;
        let id = *nodes.get(idx).ok_or("node exists at height")?;
        out.push(tree.node(id)?.hash);
    }
    Ok(out)
}

#[test]
fn locator_doubles_only_after_more_than_ten() -> Result<(), Box<dyn std::error::Error>> {
    let (short, ids) = linear_chain(4)?;
    let mut short_expected: Vec<_> = (0..=4)
        .scan(BlockHash::default(), |prev, height| {
            let header = test_header(*prev, height);
            *prev = header.compute_hash();
            Some(Hash256::from(header.compute_hash()))
        })
        .collect();
    short_expected.reverse();
    assert_eq!(short.block_locator(ids[4], 32), short_expected);
    let (mut medium, ids) = linear_chain(25)?;
    let indexed = medium.block_locator(ids[25], 32);
    medium.active_by_height.taint();
    assert_eq!(medium.block_locator(ids[25], 32), indexed);
    let side = medium.block_locator(ids[10], 32);
    assert_eq!(side.first(), Some(&medium.node(ids[10])?.hash));
    let (mut tree, main_ids) = linear_chain(40)?;
    let tip_id = main_ids[40];
    assert_eq!(tree.tip_id(), Some(tip_id));

    let expected = locator_hashes_at_heights(&tree, &main_ids, &CORE_LOCATOR_HEIGHTS_40)?;

    assert!(tree.active_by_height.is_trusted());
    assert_eq!(tree.block_locator(tip_id, 32), expected);

    tree.active_by_height.taint();
    assert_eq!(tree.block_locator(tip_id, 32), expected);

    let side = *main_ids.get(10).ok_or("node exists at height 10")?;
    let side_locator = tree.block_locator(side, 32);
    assert_eq!(side_locator.first(), Some(&tree.node(side)?.hash));
    assert_eq!(side_locator.last(), Some(&tree.node(main_ids[0])?.hash));
    Ok(())
}

fn test_header(prev_blockhash: BlockHash, height: u32) -> BlockHeader {
    let mut merkle = [0_u8; 32];
    merkle[..4].copy_from_slice(&height.to_le_bytes());
    BlockHeader {
        version: 1,
        prev_blockhash,
        merkle_root: Hash256::from_le_bytes(&merkle),
        time: height,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce: height,
    }
}

#[test]
fn invalidate_subtree_marks_root_and_descendants_invalid_and_reselects_tip()
-> Result<(), Box<dyn std::error::Error>> {
    use bitcoin_rs_consensus::{CSV_DEPLOYMENT_ID, SEGWIT_DEPLOYMENT_ID};

    let (mut tree, main_ids) = linear_chain(2)?;
    let (genesis_id, a2_id) = (main_ids[0], main_ids[2]);

    let side_ids = extend_branch(&mut tree, genesis_id, 101..=103)?;
    let side_hashes = side_ids
        .iter()
        .map(|id| tree.node(*id).map(|node| node.hash))
        .collect::<Result<Vec<_>, _>>()?;

    for &id in main_ids.iter().chain(&side_ids) {
        for deployment_id in [CSV_DEPLOYMENT_ID, SEGWIT_DEPLOYMENT_ID] {
            tree.cache_bip9_state(id, deployment_id, 1);
        }
    }

    assert_eq!(tree.tip_id(), Some(side_ids[2]));
    assert_eq!(tree.active_by_height.get(1), Some(side_ids[0]));

    assert_eq!(tree.tip_after_invalidation(side_ids[0])?, Some(a2_id));
    assert_eq!(tree.tip_id(), Some(side_ids[2]));
    assert_eq!(tree.node(side_ids[0])?.status, NodeStatus::HeaderValid);

    let outcome = tree.invalidate_subtree(side_ids[0])?;
    let invalid_hashes = outcome.invalid;
    assert_eq!(
        outcome.demoted_tip, None,
        "the displaced tip sat in the invalid subtree: invalid, not stale"
    );
    assert_eq!(invalid_hashes.len(), 3);
    for (id, hash) in side_ids.iter().zip(side_hashes.iter()) {
        assert_eq!(tree.node(*id)?.status, NodeStatus::Invalid);
        assert!(invalid_hashes.contains(hash));
    }

    assert_eq!(tree.tip_id(), Some(a2_id));
    assert_eq!(tree.node(a2_id)?.status, NodeStatus::Active);
    assert_eq!(tree.active_by_height.get(2), Some(a2_id));
    assert!(tree.active_by_height.is_trusted());
    assert_ne!(tree.node(genesis_id)?.status, NodeStatus::Invalid);
    for deployment_id in [CSV_DEPLOYMENT_ID, SEGWIT_DEPLOYMENT_ID] {
        for &id in &side_ids {
            assert_eq!(tree.cached_bip9_state(id, deployment_id), None);
        }
        for &id in &main_ids {
            assert_eq!(tree.cached_bip9_state(id, deployment_id), Some(1));
        }
    }
    Ok(())
}

#[test]
fn invalidate_subtree_uses_insertion_order_for_equal_work_tie_break()
-> Result<(), Box<dyn std::error::Error>> {
    let mut tree = BlockTree::new();
    let genesis_id = tree.insert_node(
        None,
        test_header(BlockHash::default(), 0),
        NodeStatus::HeaderValid,
    )?;

    let mut fork_tips = Vec::new();
    for fork in 0..3 {
        let branch = extend_branch(&mut tree, genesis_id, [10 + fork, 20 + fork])?;
        fork_tips.push(branch[1]);
    }

    assert_eq!(tree.tip_id(), Some(fork_tips[0]));

    tree.invalidate_subtree(fork_tips[0])?;
    assert_eq!(tree.node(fork_tips[0])?.status, NodeStatus::Invalid);
    assert_eq!(tree.tip_id(), Some(fork_tips[1]));
    assert_eq!(tree.node(fork_tips[1])?.status, NodeStatus::Active);

    assert_eq!(tree.node(fork_tips[2])?.status, NodeStatus::HeaderValid);
    Ok(())
}

#[test]
fn insert_under_invalid_parent_is_invalid_and_does_not_publish()
-> Result<(), Box<dyn std::error::Error>> {
    let mut tree = BlockTree::new();
    let genesis = test_header(BlockHash::default(), 0);
    let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
    let genesis_hash = tree.node(genesis_id)?.hash;

    let a1 = test_header(BlockHash(genesis_hash), 1);
    let a1_id = tree.insert_node(Some(genesis_id), a1, NodeStatus::HeaderValid)?;
    let a1_hash = tree.node(a1_id)?.hash;
    let a2 = test_header(BlockHash(a1_hash), 2);
    let a2_id = tree.insert_node(Some(a1_id), a2, NodeStatus::HeaderValid)?;

    tree.invalidate_subtree(a1_id)?;
    assert_eq!(tree.node(a1_id)?.status, NodeStatus::Invalid);
    assert_eq!(tree.node(a2_id)?.status, NodeStatus::Invalid);
    assert_eq!(tree.tip_id(), Some(genesis_id));

    let a3 = test_header(BlockHash(a1_hash), 3);
    let a3_id = tree.insert_node(Some(a1_id), a3, NodeStatus::HeaderValid)?;
    assert_eq!(tree.node(a3_id)?.status, NodeStatus::Invalid);
    assert_eq!(tree.tip_id(), Some(genesis_id));
    Ok(())
}

#[test]
fn linear_extension_reports_no_demotion() -> Result<(), Box<dyn std::error::Error>> {
    let mut tree = BlockTree::new();
    let genesis = tree.insert_node(
        None,
        test_header(BlockHash::default(), 0),
        NodeStatus::HeaderValid,
    )?;
    let steps = extend_branch_with_facts(&mut tree, genesis, 1..=4)?;

    assert_eq!(demoted_facts(&steps), vec![None; 4]);
    assert_eq!(tree.tip_id(), Some(steps[3].0));
    assert_eq!(tree.node(steps[2].0)?.status, NodeStatus::Stale);
    assert_eq!(tree.node(genesis)?.status, NodeStatus::Stale);
    Ok(())
}

#[test]
fn side_branch_that_is_not_best_reports_no_demotion() -> Result<(), Box<dyn std::error::Error>> {
    let (mut tree, main) = linear_chain(2)?;
    let side = extend_branch_with_facts(&mut tree, main[0], 101..=102)?;

    assert_eq!(demoted_facts(&side), vec![None, None]);
    assert_eq!(tree.tip_id(), Some(main[2]));
    assert_eq!(tree.node(main[2])?.status, NodeStatus::Active);
    assert_eq!(tree.node(side[1].0)?.status, NodeStatus::HeaderValid);
    Ok(())
}

#[test]
fn branch_switch_reports_the_displaced_tip() -> Result<(), Box<dyn std::error::Error>> {
    let (mut tree, main) = linear_chain(2)?;
    let displaced = tree.node(main[2])?.hash;
    let side = extend_branch_with_facts(&mut tree, main[0], 101..=103)?;

    assert_eq!(demoted_facts(&side), vec![None, None, Some(displaced)]);
    assert_eq!(tree.tip_id(), Some(side[2].0));
    assert_eq!(tree.node(main[2])?.status, NodeStatus::Stale);
    Ok(())
}

#[test]
fn nested_reorg_reports_the_tip_active_before_each_switch() -> Result<(), Box<dyn std::error::Error>>
{
    let (mut tree, main) = linear_chain(2)?;
    let first_old = tree.node(main[2])?.hash;
    let second = extend_branch_with_facts(&mut tree, main[0], 101..=103)?;
    let second_tip = tree.node(second[2].0)?.hash;
    let third = extend_branch_with_facts(&mut tree, second[1].0, 201..=202)?;
    let third_tip = tree.node(third[1].0)?.hash;
    let fourth = extend_branch_with_facts(&mut tree, main[0], 301..=305)?;

    assert_eq!(demoted_facts(&second), vec![None, None, Some(first_old)]);
    assert_eq!(demoted_facts(&third), vec![None, Some(second_tip)]);
    assert_eq!(
        demoted_facts(&fourth),
        vec![None, None, None, None, Some(third_tip)],
        "each switch reports the tip active just before it, never an earlier one"
    );
    assert_eq!(tree.tip_id(), Some(fourth[4].0));
    Ok(())
}

#[test]
fn descendant_reached_through_a_zero_work_node_is_not_a_displacement()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut tree, main) = linear_chain(2)?;
    let tip_hash = tree.node(main[2])?.hash;
    let zero_work = BlockHeader {
        bits: CompactTarget::from_consensus(0),
        ..test_header(BlockHash(tip_hash), 50)
    };
    let zero_id = tree.insert_node(Some(main[2]), zero_work, NodeStatus::HeaderValid)?;
    assert_eq!(tree.tip_id(), Some(main[2]));

    let (descendant, demoted) = extend_with_fact(&mut tree, zero_id, 51)?;

    assert_eq!(demoted, None, "the old tip is the common ancestor");
    assert_eq!(tree.tip_id(), Some(descendant));
    assert_eq!(tree.node(main[2])?.status, NodeStatus::Stale);
    Ok(())
}

#[test]
fn invalidation_reports_a_valid_tip_it_displaces_onto_another_branch()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut tree, main) = linear_chain(2)?;
    let displaced = tree.node(main[2])?.hash;
    let mut heavy = Vec::new();
    let mut parent = main[0];
    for nonce in 101..=103 {
        let header = test_header(BlockHash(tree.node(parent)?.hash), nonce);
        parent = tree.insert_node(Some(parent), header, NodeStatus::Invalid)?;
        heavy.push(parent);
    }
    for &id in &heavy {
        tree.node_mut(id)?.status = NodeStatus::HeaderValid;
    }
    assert_eq!(tree.tip_id(), Some(main[2]));
    let doomed = extend(&mut tree, main[0], 201)?;
    let doomed_hash = tree.node(doomed)?.hash;

    let outcome = tree.invalidate_subtree(doomed)?;

    assert_eq!(outcome.invalid, vec![doomed_hash]);
    assert_eq!(outcome.demoted_tip, Some(displaced));
    assert_eq!(tree.tip_id(), Some(heavy[2]));
    assert_eq!(tree.node(main[2])?.status, NodeStatus::Stale);
    Ok(())
}

#[test]
fn invalidation_selecting_a_descendant_of_the_old_tip_reports_nothing()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut tree, main) = linear_chain(2)?;
    let held = test_header(BlockHash(tree.node(main[2])?.hash), 101);
    let descendant = tree.insert_node(Some(main[2]), held, NodeStatus::Invalid)?;
    tree.node_mut(descendant)?.status = NodeStatus::HeaderValid;
    let doomed = extend(&mut tree, main[0], 201)?;

    let outcome = tree.invalidate_subtree(doomed)?;

    assert_eq!(outcome.demoted_tip, None, "the old tip is an ancestor");
    assert_eq!(tree.tip_id(), Some(descendant));
    assert_eq!(tree.node(main[2])?.status, NodeStatus::Stale);
    Ok(())
}

#[test]
fn applied_transaction_counts_follow_each_nodes_parent() -> Result<(), Box<dyn std::error::Error>> {
    let mut tree = BlockTree::new();
    let genesis = test_header(BlockHash::default(), 0);
    let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
    assert_eq!(tree.node(genesis_id)?.chain_tx_count, ChainTxCount::UNKNOWN);

    tree.record_applied_tx_count(genesis_id, 1)?;
    assert_eq!(
        tree.node(genesis_id)?.chain_tx_count,
        ChainTxCount::established(1)
    );

    let genesis_hash = tree.node(genesis_id)?.hash;
    let main_header = test_header(BlockHash(genesis_hash), 1);
    let main_id = tree.insert_node(Some(genesis_id), main_header, NodeStatus::HeaderValid)?;
    let side_header = test_header(BlockHash(genesis_hash), 101);
    let side_id = tree.insert_node(Some(genesis_id), side_header, NodeStatus::HeaderValid)?;
    assert_eq!(tree.node(main_id)?.chain_tx_count, ChainTxCount::UNKNOWN);
    assert_eq!(tree.node(side_id)?.chain_tx_count, ChainTxCount::UNKNOWN);

    tree.record_applied_tx_count(main_id, 2)?;
    tree.record_applied_tx_count(side_id, 7)?;
    assert_eq!(
        tree.node(main_id)?.chain_tx_count,
        ChainTxCount::established(3)
    );
    assert_eq!(
        tree.node(side_id)?.chain_tx_count,
        ChainTxCount::established(8)
    );
    Ok(())
}

#[test]
fn unknown_parent_count_stays_unknown_until_authenticated_restore()
-> Result<(), Box<dyn std::error::Error>> {
    let mut tree = BlockTree::new();
    let genesis = test_header(BlockHash::default(), 0);
    let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
    let child_header = test_header(BlockHash(tree.node(genesis_id)?.hash), 1);
    let child_id = tree.insert_node(Some(genesis_id), child_header, NodeStatus::HeaderValid)?;

    tree.record_applied_tx_count(child_id, 3)?;
    assert_eq!(tree.node(child_id)?.chain_tx_count, ChainTxCount::UNKNOWN);

    tree.restore_chain_tx_count(genesis_id, ChainTxCount::established(11))?;
    tree.record_applied_tx_count(child_id, 3)?;
    assert_eq!(
        tree.node(child_id)?.chain_tx_count,
        ChainTxCount::established(14)
    );
    tree.restore_chain_tx_count(child_id, ChainTxCount::established(42))?;
    assert_eq!(
        tree.node(child_id)?.chain_tx_count,
        ChainTxCount::established(42)
    );
    Ok(())
}

#[test]
fn a_restored_wire_zero_stays_unknown_at_the_boundary() -> Result<(), Box<dyn std::error::Error>> {
    let mut tree = BlockTree::new();
    let genesis = test_header(BlockHash::default(), 0);
    let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
    tree.restore_chain_tx_count(genesis_id, ChainTxCount::from_wire(0))?;
    assert_eq!(tree.node(genesis_id)?.chain_tx_count, ChainTxCount::UNKNOWN);
    assert_eq!(tree.node(genesis_id)?.chain_tx_count.to_wire(), 0);
    Ok(())
}

#[test]
fn recording_a_count_refreshes_only_the_published_tip() -> Result<(), Box<dyn std::error::Error>> {
    let mut tree = BlockTree::new();
    let genesis = test_header(BlockHash::default(), 0);
    let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
    let genesis_hash = tree.node(genesis_id)?.hash;

    let main_header = test_header(BlockHash(genesis_hash), 1);
    let main_id = tree.insert_node(Some(genesis_id), main_header, NodeStatus::HeaderValid)?;
    let side_header = test_header(BlockHash(genesis_hash), 101);
    let side_id = tree.insert_node(Some(genesis_id), side_header, NodeStatus::HeaderValid)?;
    assert_eq!(tree.tip_id(), Some(main_id));
    assert_eq!(
        tree.tip().map(|tip| tip.chain_tx_count),
        Some(ChainTxCount::UNKNOWN)
    );

    tree.record_applied_tx_count(genesis_id, 1)?;
    assert_eq!(
        tree.tip().map(|tip| (tip.tip_id, tip.chain_tx_count)),
        Some((main_id, ChainTxCount::UNKNOWN))
    );

    tree.record_applied_tx_count(main_id, 2)?;
    assert_eq!(
        tree.tip().map(|tip| (tip.tip_id, tip.chain_tx_count)),
        Some((main_id, ChainTxCount::established(3)))
    );

    tree.restore_chain_tx_count(side_id, ChainTxCount::established(9))?;
    assert_eq!(
        tree.tip().map(|tip| (tip.tip_id, tip.chain_tx_count)),
        Some((main_id, ChainTxCount::established(3)))
    );

    tree.restore_chain_tx_count(main_id, ChainTxCount::established(5))?;
    assert_eq!(
        tree.tip().map(|tip| tip.chain_tx_count),
        Some(ChainTxCount::established(5))
    );
    Ok(())
}
