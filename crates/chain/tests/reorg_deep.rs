//! Deep reorganization planner integration tests.
use bitcoin_rs_chain::{BlockHeader, BlockTree, NodeId, NodeStatus, plan_reorg};
use bitcoin_rs_primitives::{BlockHash, Hash256};

#[test]
fn plans_deep_reorg_to_common_fork() -> Result<(), Box<dyn std::error::Error>> {
    let mut tree = BlockTree::new();
    let genesis = mine_header(BlockHash::default(), 0, 0);
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

fn mine_child(
    tree: &BlockTree,
    parent: NodeId,
    height: u32,
    branch: u8,
) -> Result<BlockHeader, Box<dyn std::error::Error>> {
    let parent_hash = BlockHash::from(Hash256::from_le_bytes(
        &tree.node(parent)?.hash.to_le_bytes(),
    ));
    Ok(mine_header(parent_hash, height, branch))
}

/// Differential proof-of-work oracle: checks that the header hash satisfies
/// the compact target, using bitcoin's compact-target decode and comparison.
fn pow_is_met(bits: u32, hash: &BlockHash) -> bool {
    use bitcoin::hashes::Hash as _;
    let target =
        bitcoin::pow::Target::from_compact(bitcoin::pow::CompactTarget::from_consensus(bits));
    target.is_met_by(bitcoin::BlockHash::from_byte_array(*hash.as_bytes()))
}

fn mine_header(prev_blockhash: BlockHash, height: u32, branch: u8) -> BlockHeader {
    let mut merkle = [0_u8; 32];
    merkle[..4].copy_from_slice(&height.to_le_bytes());
    merkle[4] = branch;
    let mut header = BlockHeader {
        version: 1,
        prev_blockhash,
        merkle_root: Hash256::from_le_bytes(&merkle),
        time: height,
        bits: 0x207f_ffff,
        nonce: 0,
    };
    while !pow_is_met(header.bits, &header.compute_hash()) {
        header.nonce = header.nonce.wrapping_add(1);
    }
    header
}
