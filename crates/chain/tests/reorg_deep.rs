//! Deep reorganization planner integration tests.
use bitcoin::{
    BlockHash, TxMerkleNode,
    block::{Header as BlockHeader, Version},
    hashes::Hash as _,
    pow::CompactTarget,
};
use bitcoin_rs_chain::{BlockTree, CachedState, NodeId, NodeStatus, plan_reorg};

#[test]
fn plans_deep_reorg_to_common_fork() -> Result<(), Box<dyn std::error::Error>> {
    let mut tree = BlockTree::new();
    let genesis = mine_header(BlockHash::all_zeros(), 0, 0);
    let genesis_id = tree.insert_node(None, genesis, NodeStatus::Active)?;

    let mut trunk = vec![genesis_id];
    let mut parent = genesis_id;
    for height in 1..=100_u32 {
        let header = mine_child(&tree, parent, height, 0)?;
        parent = tree.insert_node(Some(parent), header, NodeStatus::HeaderValid)?;
        trunk.push(parent);
    }

    let fork = trunk[50];
    let mut branch_parent = fork;
    for height in 51..=100_u32 {
        let header = mine_child(&tree, branch_parent, height, 1)?;
        branch_parent = tree.insert_node(Some(branch_parent), header, NodeStatus::HeaderValid)?;
    }

    let plan = plan_reorg(&tree, trunk[100], branch_parent)?;

    assert_eq!(plan.ancestor, fork);
    assert_eq!(plan.disconnect.len(), 50);
    assert_eq!(plan.connect.len(), 50);
    assert_eq!(plan.disconnect.first().copied(), Some(trunk[100]));
    assert_eq!(plan.disconnect.last().copied(), Some(trunk[51]));
    assert_eq!(tree.node(plan.connect[0])?.height, 51);
    assert_eq!(
        tree.node(*plan.connect.last().ok_or("empty connect")?)?
            .height,
        100
    );
    Ok(())
}

#[test]
fn invalidate_subtree_clears_bip9_cache_entries_of_the_invalid_branch_only()
-> Result<(), Box<dyn std::error::Error>> {
    let mut tree = BlockTree::new();
    let genesis = mine_header(BlockHash::all_zeros(), 0, 0);
    let genesis_id = tree.insert_node(None, genesis, NodeStatus::Active)?;

    let mut trunk_tip = genesis_id;
    for height in 1..=3_u32 {
        let header = mine_child(&tree, trunk_tip, height, 0)?;
        trunk_tip = tree.insert_node(Some(trunk_tip), header, NodeStatus::HeaderValid)?;
    }
    let mut fork_tip = genesis_id;
    for height in 1..=2_u32 {
        let header = mine_child(&tree, fork_tip, height, 1)?;
        fork_tip = tree.insert_node(Some(fork_tip), header, NodeStatus::HeaderValid)?;
    }

    // Seed the cache the way the one contextual source does: one entry per
    // tracked deployment per node it resolved a state for.
    for (node_id, deployment_id) in [(trunk_tip, 0_u32), (fork_tip, 0), (fork_tip, 1)] {
        tree.cache_bip9_state(
            node_id,
            deployment_id,
            CachedState {
                tag: 1,
                since_height: 0,
            },
        );
    }
    assert_eq!(tree.cached_bip9_state_len(), 3);

    tree.invalidate_subtree(fork_tip)?;

    // Entries anchored on permanently invalid blocks are dropped; the entries
    // of the branch that remains active survive untouched.
    assert_eq!(tree.cached_bip9_state_len(), 1);
    assert!(tree.cached_bip9_state(trunk_tip, 0).is_some());
    assert!(tree.cached_bip9_state(fork_tip, 0).is_none());
    assert!(tree.cached_bip9_state(fork_tip, 1).is_none());
    Ok(())
}

fn mine_child(
    tree: &BlockTree,
    parent: NodeId,
    height: u32,
    branch: u8,
) -> Result<BlockHeader, Box<dyn std::error::Error>> {
    let parent_hash = BlockHash::from_byte_array(tree.node(parent)?.hash.to_le_bytes());
    Ok(mine_header(parent_hash, height, branch))
}

fn mine_header(prev_blockhash: BlockHash, height: u32, branch: u8) -> BlockHeader {
    let mut merkle = [0_u8; 32];
    merkle[..4].copy_from_slice(&height.to_le_bytes());
    merkle[4] = branch;
    let mut header = BlockHeader {
        version: Version::ONE,
        prev_blockhash,
        merkle_root: TxMerkleNode::from_byte_array(merkle),
        time: height,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce: 0,
    };
    while !header.target().is_met_by(header.block_hash()) {
        header.nonce = header.nonce.wrapping_add(1);
    }
    header
}
