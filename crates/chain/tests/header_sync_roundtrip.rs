//! Header synchronization integration tests.
use bitcoin::{
    BlockHash, TxMerkleNode,
    block::{Header as BlockHeader, Version},
    hashes::Hash as _,
    pow::CompactTarget,
};
use bitcoin_rs_chain::header_sync::{next_work_required, validate_header_nbits};
use bitcoin_rs_chain::{
    BlockTree, ChainError, Network, NodeStatus, accept_headers, current_unix_seconds,
};
use bitcoin_rs_primitives::Hash256;

#[test]
fn accepts_valid_headers_across_batches_and_rejects_bad_bits()
-> Result<(), Box<dyn std::error::Error>> {
    let headers = mine_headers(100);
    let mut tree = BlockTree::new();

    let first = accept_headers(
        &mut tree,
        &headers[..40],
        Network::Regtest,
        current_unix_seconds(),
    )?;
    let second = accept_headers(
        &mut tree,
        &headers[40..],
        Network::Regtest,
        current_unix_seconds(),
    )?;

    assert_eq!(first.len(), 40);
    assert_eq!(second.len(), 60);
    let tip = tree.tip().ok_or("missing tip")?;
    assert_eq!(tip.height, 99);
    assert_eq!(
        tip.hash,
        tree.node(*second.last().ok_or("missing id")?)?.hash
    );

    let mut tampered = headers[0];
    tampered.bits = CompactTarget::from_consensus(0x2200_ffff);
    let err = match accept_headers(
        &mut BlockTree::new(),
        &[tampered],
        Network::Regtest,
        current_unix_seconds(),
    ) {
        Ok(_) => panic!("oversized target must be rejected"),
        Err(error) => error,
    };
    assert!(matches!(err, ChainError::TargetExceedsLimit { .. }));

    Ok(())
}

#[test]
fn rejects_post_genesis_header_as_empty_tree_root() {
    let genesis = genesis_header();
    let child = mine_header_with(
        genesis.block_hash(),
        1,
        genesis.time + Network::Regtest.target_spacing_seconds(),
        genesis.bits,
    );
    let prev_hash = Hash256::from_le_bytes(child.prev_blockhash.as_byte_array());
    let mut tree = BlockTree::new();

    let err = match accept_headers(
        &mut tree,
        &[child],
        Network::Regtest,
        current_unix_seconds(),
    ) {
        Ok(_) => panic!("post-genesis header must not become an empty-tree root"),
        Err(error) => error,
    };

    assert_eq!(err, ChainError::MissingParent { prev_hash });
    assert!(tree.is_empty());
}

#[test]
fn rejects_non_retarget_header_that_does_not_inherit_parent_bits_before_insertion()
-> Result<(), Box<dyn std::error::Error>> {
    let mut tree = BlockTree::new();
    let parent_bits = CompactTarget::from_consensus(0x207e_ffff);
    let easier_child_bits = CompactTarget::from_consensus(0x207f_ffff);
    let parent = mine_header_with(BlockHash::all_zeros(), 0, 0, parent_bits);
    let parent_id = tree.insert_node(None, parent, NodeStatus::HeaderValid)?;
    let child = mine_header_with(
        parent.block_hash(),
        1,
        Network::Regtest.target_spacing_seconds(),
        easier_child_bits,
    );

    let err = match accept_headers(
        &mut tree,
        &[child],
        Network::Regtest,
        current_unix_seconds(),
    ) {
        Ok(_) => panic!("non-retarget header must inherit parent nBits before insertion"),
        Err(error) => error,
    };

    assert!(matches!(err, ChainError::NbitsMismatch { .. }));
    let tip = tree.tip().ok_or("missing accepted parent tip")?;
    assert_eq!(tip.tip_id, parent_id);
    assert_eq!(tip.height, 0);
    assert_eq!(tree.len(), 1);
    Ok(())
}

#[test]
fn rejects_retarget_header_that_keeps_parent_bits_when_timespan_clamps()
-> Result<(), Box<dyn std::error::Error>> {
    let mut tree = BlockTree::new();
    let bits = CompactTarget::from_consensus(0x1d00_ffff);
    let interval = Network::Mainnet.retarget_interval();
    let mut prev_hash = BlockHash::all_zeros();
    let mut parent = None;
    let mut parent_id = None;

    for height in 0..interval {
        let header = raw_header_with(prev_hash, height, height, bits);
        let id = tree.insert_node(parent, header, NodeStatus::HeaderValid)?;
        prev_hash = header.block_hash();
        parent = Some(id);
        parent_id = Some(id);
    }

    let parent_id = parent_id.ok_or("missing retarget parent")?;
    let child = raw_header_with(prev_hash, interval, interval, bits);
    let err = match validate_header_nbits(&tree, parent_id, &child, Network::Mainnet) {
        Ok(()) => panic!("retarget header must use computed nBits, not parent nBits"),
        Err(error) => error,
    };

    let ChainError::NbitsMismatch {
        actual,
        expected,
        height,
    } = err
    else {
        panic!("expected nBits mismatch, got {err:?}");
    };
    assert_eq!(actual, bits.to_consensus());
    assert_eq!(height, interval);
    assert_ne!(
        expected, actual,
        "clamped retarget calculation must differ from parent nBits"
    );
    Ok(())
}

#[test]
fn next_work_required_is_exactly_what_validate_header_nbits_enforces()
-> Result<(), Box<dyn std::error::Error>> {
    let mut tree = BlockTree::new();
    let bits = CompactTarget::from_consensus(0x207e_ffff);
    let parent = raw_header_with(BlockHash::all_zeros(), 0, 0, bits);
    let parent_id = tree.insert_node(None, parent, NodeStatus::HeaderValid)?;
    let candidate_time = Network::Regtest.target_spacing_seconds();

    // The one next-work source: the bits a candidate builder reads are the
    // bits validation demands at the same parent and candidate time.
    let expected = next_work_required(&tree, parent_id, candidate_time, Network::Regtest)?;
    assert_eq!(expected, bits);

    let candidate = raw_header_with(parent.block_hash(), 1, candidate_time, expected);
    validate_header_nbits(&tree, parent_id, &candidate, Network::Regtest)?;

    let wrong = raw_header_with(
        parent.block_hash(),
        1,
        candidate_time,
        CompactTarget::from_consensus(0x207e_fffe),
    );
    let Err(err) = validate_header_nbits(&tree, parent_id, &wrong, Network::Regtest) else {
        return Err("bits other than next_work_required must be rejected".into());
    };
    assert!(
        matches!(err, ChainError::NbitsMismatch { expected, .. } if expected == bits.to_consensus())
    );
    Ok(())
}

#[test]
fn next_work_required_recovers_minimum_difficulty_past_the_spacing_window()
-> Result<(), Box<dyn std::error::Error>> {
    let mut tree = BlockTree::new();
    let bits = CompactTarget::from_consensus(0x1b0e_3ea6);
    let parent = raw_header_with(BlockHash::all_zeros(), 0, 0, bits);
    let parent_id = tree.insert_node(None, parent, NodeStatus::HeaderValid)?;
    let spacing = Network::Testnet3.target_spacing_seconds();

    // Within 2*spacing of the parent the difficulty carries over unchanged.
    assert_eq!(
        next_work_required(&tree, parent_id, spacing, Network::Testnet3)?,
        bits
    );

    // Past the window the testnet minimum-difficulty rule returns the
    // proof-of-work limit.
    assert_eq!(
        next_work_required(
            &tree,
            parent_id,
            spacing.saturating_mul(2).saturating_add(1),
            Network::Testnet3
        )?,
        CompactTarget::from_consensus(0x1d00_ffff)
    );
    Ok(())
}

#[test]
fn duplicate_genesis_in_overlapping_batch_returns_original_ids_and_inserts_only_new_nodes()
-> Result<(), Box<dyn std::error::Error>> {
    let headers = mine_headers(5);
    let mut tree = BlockTree::new();

    let first = accept_headers(
        &mut tree,
        &headers[..2],
        Network::Regtest,
        current_unix_seconds(),
    )?;
    assert_eq!(first.len(), 2);
    let genesis_id = first[0];
    let first_child_id = first[1];
    let tip_before = tree.tip().ok_or("missing tip after first batch")?;
    assert_eq!(tip_before.height, 1);

    let overlapping = [headers[0], headers[1], headers[2], headers[3], headers[4]];
    let second = accept_headers(
        &mut tree,
        &overlapping,
        Network::Regtest,
        current_unix_seconds(),
    )?;

    assert_eq!(second.len(), 5, "one returned id per input header");
    assert_eq!(
        second[0], genesis_id,
        "duplicate Genesis returns the original NodeId"
    );
    assert_eq!(
        second[1], first_child_id,
        "duplicate first child returns the original NodeId"
    );
    for (i, header) in overlapping.iter().enumerate() {
        let expected = Hash256::from_le_bytes(header.block_hash().as_byte_array());
        assert_eq!(
            tree.node(second[i])?.hash,
            expected,
            "returned NodeId at position {i} must map to the input header hash"
        );
    }

    assert_eq!(
        tree.len(),
        5,
        "only the three unknown descendants are inserted"
    );

    let tip = tree.tip().ok_or("missing tip after overlapping batch")?;
    assert_eq!(tip.height, 4);
    assert_eq!(tip.tip_id, *second.last().ok_or("missing last id")?);
    assert_eq!(tip.hash, tree.node(tip.tip_id)?.hash);
    Ok(())
}

#[test]
fn duplicate_equal_work_competing_child_returns_original_id_and_does_not_reorg()
-> Result<(), Box<dyn std::error::Error>> {
    let genesis = genesis_header();
    let active_child = mine_header_with(
        genesis.block_hash(),
        1,
        genesis.time + Network::Regtest.target_spacing_seconds(),
        genesis.bits,
    );
    let mut tree = BlockTree::new();

    let first = accept_headers(
        &mut tree,
        &[genesis, active_child],
        Network::Regtest,
        current_unix_seconds(),
    )?;
    assert_eq!(first.len(), 2);
    let active_tip_id = first[1];

    let tip_before = tree.tip().ok_or("missing tip after active child")?;
    assert_eq!(tip_before.height, 1);
    assert_eq!(tip_before.tip_id, active_tip_id);

    let competing = mine_header_with(
        genesis.block_hash(),
        1,
        genesis.time + 3 * Network::Regtest.target_spacing_seconds(),
        genesis.bits,
    );
    assert_ne!(
        active_child.block_hash(),
        competing.block_hash(),
        "competing child must have a different hash"
    );

    let second = accept_headers(
        &mut tree,
        &[competing],
        Network::Regtest,
        current_unix_seconds(),
    )?;
    assert_eq!(second.len(), 1);
    let competing_id = second[0];
    assert_ne!(
        competing_id, active_tip_id,
        "equal-work competing child is not the active tip"
    );

    assert_eq!(
        tree.node(competing_id)?.status,
        NodeStatus::HeaderValid,
        "equal-work competing child is valid but not active"
    );

    let tip_after = tree.tip().ok_or("missing tip after competing child")?;
    assert_eq!(
        tip_after.tip_id, active_tip_id,
        "active tip must not change"
    );
    assert_eq!(tip_after.height, 1);

    let node_count_before_resubmit = tree.len();

    let third = accept_headers(
        &mut tree,
        &[competing],
        Network::Regtest,
        current_unix_seconds(),
    )?;
    assert_eq!(third.len(), 1);
    assert_eq!(
        third[0], competing_id,
        "re-submitted competing header returns the original NodeId"
    );
    assert_eq!(
        tree.len(),
        node_count_before_resubmit,
        "re-submit does not create a node"
    );

    let tip_final = tree.tip().ok_or("missing tip after re-submit")?;
    assert_eq!(tip_final.tip_id, active_tip_id, "active tip is unchanged");
    assert_eq!(tip_final.height, 1);

    Ok(())
}

#[test]
fn invalid_unknown_suffix_after_duplicate_inputs_propagates_consensus_error_without_advancing_tip()
-> Result<(), Box<dyn std::error::Error>> {
    let headers = mine_headers(5);
    let mut tree = BlockTree::new();

    let first = accept_headers(
        &mut tree,
        &headers[..2],
        Network::Regtest,
        current_unix_seconds(),
    )?;
    let genesis_id = first[0];
    let first_child_id = first[1];
    let tip_before = tree.tip().ok_or("missing tip after first batch")?;
    assert_eq!(tip_before.height, 1);

    let mut invalid_unknown = headers[2];
    invalid_unknown.bits = CompactTarget::from_consensus(0x2200_ffff);

    let batch = [headers[0], headers[1], invalid_unknown];
    let err = match accept_headers(&mut tree, &batch, Network::Regtest, current_unix_seconds()) {
        Ok(_) => panic!("oversized-target suffix must be rejected"),
        Err(error) => error,
    };
    assert!(
        matches!(err, ChainError::TargetExceedsLimit { .. }),
        "expected TargetExceedsLimit for the unknown suffix, got {err:?}"
    );

    let tip_after = tree.tip().ok_or("missing tip after failed batch")?;
    assert_eq!(
        tip_after.tip_id, tip_before.tip_id,
        "tip must not advance when the unknown suffix fails validation"
    );
    assert_eq!(tip_after.height, 1);
    assert_eq!(
        tree.len(),
        2,
        "no new nodes inserted when the unknown suffix fails validation"
    );
    assert_eq!(tree.node(genesis_id)?.height, 0);
    assert_eq!(tree.node(first_child_id)?.height, 1);
    Ok(())
}

fn mine_headers(count: u32) -> Vec<BlockHeader> {
    let mut headers = Vec::new();
    let genesis = genesis_header();
    let mut prev = genesis.block_hash();
    headers.push(genesis);
    for height in 1..count {
        let header = mine_header(prev, height);
        prev = header.block_hash();
        headers.push(header);
    }
    headers
}

fn genesis_header() -> BlockHeader {
    bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest).header
}

/// Regtest genesis timestamp. Headers must advance past it, because the
/// median-time-past rule compares against the ancestors actually in the tree.
const GENESIS_TIME: u32 = 1_296_688_602;

fn mine_header(prev_blockhash: BlockHash, height: u32) -> BlockHeader {
    mine_header_with(
        prev_blockhash,
        height,
        GENESIS_TIME.saturating_add(height),
        CompactTarget::from_consensus(0x207f_ffff),
    )
}

fn mine_header_with(
    prev_blockhash: BlockHash,
    height: u32,
    time: u32,
    bits: CompactTarget,
) -> BlockHeader {
    let mut merkle = [0_u8; 32];
    merkle[..4].copy_from_slice(&height.to_le_bytes());
    let mut header = BlockHeader {
        version: Version::ONE,
        prev_blockhash,
        merkle_root: TxMerkleNode::from_byte_array(merkle),
        time,
        bits,
        nonce: 0,
    };
    while !header.target().is_met_by(header.block_hash()) {
        header.nonce = header.nonce.wrapping_add(1);
    }
    header
}

fn raw_header_with(
    prev_blockhash: BlockHash,
    height: u32,
    time: u32,
    bits: CompactTarget,
) -> BlockHeader {
    let mut merkle = [0_u8; 32];
    merkle[..4].copy_from_slice(&height.to_le_bytes());
    BlockHeader {
        version: Version::ONE,
        prev_blockhash,
        merkle_root: TxMerkleNode::from_byte_array(merkle),
        time,
        bits,
        nonce: 0,
    }
}
