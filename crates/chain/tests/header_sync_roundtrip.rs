//! Header synchronization integration tests.
use bitcoin_rs_chain::header_sync::{next_work_required, validate_header_nbits};
use bitcoin_rs_chain::{
    BlockHeader, BlockTree, ChainError, Network, NodeStatus, accept_headers, current_unix_seconds,
};

mod pow_oracle;
use bitcoin_rs_primitives::{BlockHash, CompactTarget, Hash256};
use pow_oracle::pow_is_met;

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
        genesis.compute_hash(),
        1,
        genesis.time + Network::Regtest.target_spacing_seconds(),
        genesis.bits,
    );
    let prev_hash = Hash256::from_le_bytes(child.prev_blockhash.as_bytes());
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
    let parent_bits = 0x207e_ffff_u32;
    let easier_child_bits = 0x207f_ffff_u32;
    let parent = mine_header_with(BlockHash::default(), 0, 0, parent_bits);
    let parent_id = tree.insert_node(None, parent, NodeStatus::HeaderValid)?;
    let child = mine_header_with(
        parent.compute_hash(),
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
    let bits = 0x1d00_ffff_u32;
    let interval = Network::Mainnet.retarget_interval();
    let mut prev_hash = BlockHash::default();
    let mut parent = None;
    let mut parent_id = None;

    for height in 0..interval {
        let header = raw_header_with(prev_hash, height, height, bits);
        let id = tree.insert_node(parent, header, NodeStatus::HeaderValid)?;
        prev_hash = header.compute_hash();
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
    assert_eq!(actual, bits);
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
    let bits = 0x207e_ffff_u32;
    let parent = raw_header_with(BlockHash::default(), 0, 0, bits);
    let parent_id = tree.insert_node(None, parent, NodeStatus::HeaderValid)?;
    let candidate_time = Network::Regtest.target_spacing_seconds();

    // The one next-work source: the bits a candidate builder reads are the
    // bits validation demands at the same parent and candidate time.
    let expected = next_work_required(&tree, parent_id, candidate_time, Network::Regtest)?;
    assert_eq!(expected, bits);

    let candidate = raw_header_with(parent.compute_hash(), 1, candidate_time, expected);
    validate_header_nbits(&tree, parent_id, &candidate, Network::Regtest)?;

    let wrong = raw_header_with(parent.compute_hash(), 1, candidate_time, 0x207e_fffe_u32);
    let Err(err) = validate_header_nbits(&tree, parent_id, &wrong, Network::Regtest) else {
        return Err("bits other than next_work_required must be rejected".into());
    };
    assert!(matches!(err, ChainError::NbitsMismatch { expected, .. } if expected == bits));
    Ok(())
}

#[test]
fn next_work_required_recovers_minimum_difficulty_past_the_spacing_window()
-> Result<(), Box<dyn std::error::Error>> {
    let mut tree = BlockTree::new();
    let bits = 0x1b0e_3ea6_u32;
    let parent = raw_header_with(BlockHash::default(), 0, 0, bits);
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
        0x1d00_ffff_u32
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
        let expected = Hash256::from_le_bytes(header.compute_hash().as_bytes());
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
        genesis.compute_hash(),
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
        genesis.compute_hash(),
        1,
        genesis.time + 3 * Network::Regtest.target_spacing_seconds(),
        genesis.bits,
    );
    assert_ne!(
        active_child.compute_hash(),
        competing.compute_hash(),
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
    let mut prev = genesis.compute_hash();
    headers.push(genesis);
    for height in 1..count {
        let header = mine_header(prev, height);
        prev = header.compute_hash();
        headers.push(header);
    }
    headers
}

fn genesis_header() -> BlockHeader {
    Network::Regtest.genesis_block().header
}

/// Regtest genesis timestamp. Headers must advance past it, because the
/// median-time-past rule compares against the ancestors actually in the tree.
const GENESIS_TIME: u32 = 1_296_688_602;

fn mine_header(prev_blockhash: BlockHash, height: u32) -> BlockHeader {
    mine_header_with(
        prev_blockhash,
        height,
        GENESIS_TIME.saturating_add(height),
        0x207f_ffff,
    )
}

fn mine_header_with(
    prev_blockhash: BlockHash,
    height: u32,
    time: u32,
    bits: impl Into<CompactTarget>,
) -> BlockHeader {
    let bits = bits.into();
    let mut merkle = [0_u8; 32];
    merkle[..4].copy_from_slice(&height.to_le_bytes());
    let mut header = BlockHeader {
        version: 1,
        prev_blockhash,
        merkle_root: Hash256::from_le_bytes(&merkle),
        time,
        bits,
        nonce: 0,
    };
    while !pow_is_met(header.bits, &header.compute_hash()) {
        header.nonce = header.nonce.wrapping_add(1);
    }
    header
}

fn raw_header_with(
    prev_blockhash: BlockHash,
    height: u32,
    time: u32,
    bits: impl Into<CompactTarget>,
) -> BlockHeader {
    let bits = bits.into();
    let mut merkle = [0_u8; 32];
    merkle[..4].copy_from_slice(&height.to_le_bytes());
    BlockHeader {
        version: 1,
        prev_blockhash,
        merkle_root: Hash256::from_le_bytes(&merkle),
        time,
        bits,
        nonce: 0,
    }
}

const MAINNET_POW_LIMIT_BITS: u32 = 0x1d00_ffff;
const MAINNET_POW_LIMIT_DIV_4_BITS: u32 = 0x1c3f_ffc0;
const DAA_ANCHOR_TIME: u32 = 1_600_000_000;

fn pow_limit_bits(network: Network) -> u32 {
    target_to_compact_lossy(network.max_target())
}

fn target_to_compact_lossy(target: bitcoin_rs_chain::ChainWork) -> u32 {
    if target == bitcoin_rs_chain::ChainWork::ZERO {
        return 0;
    }
    let mut size = target.bit_len().div_ceil(8);
    let mut compact = if size <= 3 {
        u32::try_from(target.as_limbs()[0] << (8 * (3 - size))).unwrap_or(0)
    } else {
        u32::try_from((target >> (8 * (size - 3))).as_limbs()[0]).unwrap_or(0)
    };
    if compact & 0x0080_0000 != 0 {
        compact >>= 8;
        size += 1;
    }
    compact | (u32::try_from(size).unwrap_or(0) << 24)
}

/// Independent `SetCompact` decoder: the test oracle for difficulty
/// expectations. Hand-rolled against the encoding spec, never importing the
/// production decoder, so a decoder regression cannot move both sides of an
/// assertion together.
fn decode_compact_to_target(bits: u32) -> bitcoin_rs_chain::ChainWork {
    use bitcoin_rs_chain::ChainWork;
    let exponent = usize::from(u8::try_from(bits >> 24).unwrap_or(0));
    let mut mantissa = bits & 0x007f_ffff;
    let target = if exponent <= 3 {
        mantissa >>= 8 * (3 - exponent);
        ChainWork::from(mantissa)
    } else {
        let shift = 8 * (exponent - 3);
        if shift < 256 {
            ChainWork::from(mantissa) << shift
        } else {
            ChainWork::ZERO
        }
    };
    if mantissa != 0 && bits & 0x0080_0000 != 0 {
        ChainWork::ZERO
    } else {
        target
    }
}

fn scaled_pow_limit_bits(network: Network, divisor: u64) -> u32 {
    let limit = decode_compact_to_target(pow_limit_bits(network));
    target_to_compact_lossy(limit / bitcoin_rs_chain::ChainWork::from(divisor))
}

fn retarget_bits_for_test(
    network: Network,
    previous_bits: u32,
    actual_timespan: u32,
    expected_timespan: u32,
) -> u32 {
    let actual_timespan = actual_timespan.clamp(expected_timespan / 4, expected_timespan * 4);
    let previous_target = decode_compact_to_target(previous_bits);
    let actual = bitcoin_rs_chain::ChainWork::from(actual_timespan);
    let expected = bitcoin_rs_chain::ChainWork::from(expected_timespan);
    let target = ((previous_target / expected) * actual)
        + (((previous_target % expected) * actual) / expected);
    target_to_compact_lossy(target.min(decode_compact_to_target(pow_limit_bits(network))))
}

fn seed_headers(
    tree: &mut BlockTree,
    headers: &[(u32, u32)],
) -> Result<(bitcoin_rs_chain::NodeId, BlockHash), Box<dyn std::error::Error>> {
    let mut parent = None;
    let mut previous_hash = BlockHash::default();
    let mut tip = None;
    for (height, &(bits, time)) in headers.iter().enumerate() {
        let height = u32::try_from(height)?;
        let header = raw_header_with(previous_hash, height, time, bits);
        let node_id = tree.insert_node(parent, header, NodeStatus::HeaderValid)?;
        previous_hash = tree.node(node_id)?.hash.into();
        parent = Some(node_id);
        tip = Some(node_id);
    }
    Ok((tip.ok_or("empty header seed")?, previous_hash))
}

fn seed_period(
    tree: &mut BlockTree,
    bits: u32,
    anchor_time: u32,
    tip_time: u32,
    tip_height: u32,
) -> Result<(bitcoin_rs_chain::NodeId, BlockHash), Box<dyn std::error::Error>> {
    let headers: Vec<_> = (0..=tip_height)
        .map(|height| {
            (
                bits,
                anchor_time.saturating_add(
                    u32::try_from(
                        u64::from(tip_time - anchor_time) * u64::from(height)
                            / u64::from(tip_height),
                    )
                    .unwrap_or(u32::MAX),
                ),
            )
        })
        .collect();
    seed_headers(tree, &headers)
}

#[allow(clippy::needless_pass_by_value)]
fn assert_nbits_mismatch(result: Result<(), ChainError>, actual: u32, expected: u32, height: u32) {
    assert!(matches!(
        result,
        Err(ChainError::NbitsMismatch {
            actual: got_actual,
            expected: got_expected,
            height: got_height,
        }) if got_actual == actual && got_expected == expected && got_height == height
    ));
}

#[test]
fn daa_non_retarget_height_requires_parent_bits() -> Result<(), Box<dyn std::error::Error>> {
    let mut tree = BlockTree::new();
    let (parent_id, _) = seed_period(
        &mut tree,
        MAINNET_POW_LIMIT_BITS,
        DAA_ANCHOR_TIME,
        DAA_ANCHOR_TIME + 600,
        1,
    )?;
    let parent_hash = tree.node(parent_id)?.hash.into();
    let header = raw_header_with(
        parent_hash,
        2,
        DAA_ANCHOR_TIME + 1_200,
        MAINNET_POW_LIMIT_DIV_4_BITS,
    );
    assert_nbits_mismatch(
        validate_header_nbits(&tree, parent_id, &header, Network::Mainnet),
        MAINNET_POW_LIMIT_DIV_4_BITS,
        MAINNET_POW_LIMIT_BITS,
        2,
    );
    Ok(())
}

#[test]
fn daa_retarget_accepts_expected_bits_at_boundary() -> Result<(), Box<dyn std::error::Error>> {
    let mut tree = BlockTree::new();
    let interval = Network::Mainnet.retarget_interval();
    let expected_timespan = interval * 600;
    let (parent_id, _) = seed_period(
        &mut tree,
        MAINNET_POW_LIMIT_BITS,
        DAA_ANCHOR_TIME,
        DAA_ANCHOR_TIME + expected_timespan,
        interval - 1,
    )?;
    let header = raw_header_with(
        tree.node(parent_id)?.hash.into(),
        interval,
        DAA_ANCHOR_TIME + expected_timespan + 600,
        MAINNET_POW_LIMIT_BITS,
    );
    assert_eq!(
        validate_header_nbits(&tree, parent_id, &header, Network::Mainnet),
        Ok(())
    );
    Ok(())
}

#[test]
fn daa_retarget_rejects_wrong_bits_at_boundary() -> Result<(), Box<dyn std::error::Error>> {
    let mut tree = BlockTree::new();
    let interval = Network::Mainnet.retarget_interval();
    let expected_timespan = interval * 600;
    let (parent_id, _) = seed_period(
        &mut tree,
        MAINNET_POW_LIMIT_BITS,
        DAA_ANCHOR_TIME,
        DAA_ANCHOR_TIME + expected_timespan,
        interval - 1,
    )?;
    let header = raw_header_with(
        tree.node(parent_id)?.hash.into(),
        interval,
        DAA_ANCHOR_TIME + expected_timespan + 600,
        MAINNET_POW_LIMIT_DIV_4_BITS,
    );
    assert_nbits_mismatch(
        validate_header_nbits(&tree, parent_id, &header, Network::Mainnet),
        MAINNET_POW_LIMIT_DIV_4_BITS,
        MAINNET_POW_LIMIT_BITS,
        interval,
    );
    Ok(())
}

#[test]
fn daa_retarget_clamps_fast_timespan_to_quarter_target() -> Result<(), Box<dyn std::error::Error>> {
    let mut tree = BlockTree::new();
    let interval = Network::Mainnet.retarget_interval();
    let expected_timespan = interval * 600;
    let (parent_id, _) = seed_period(
        &mut tree,
        MAINNET_POW_LIMIT_BITS,
        DAA_ANCHOR_TIME,
        DAA_ANCHOR_TIME + expected_timespan / 4 - 1,
        interval - 1,
    )?;
    let header = raw_header_with(
        tree.node(parent_id)?.hash.into(),
        interval,
        DAA_ANCHOR_TIME + expected_timespan,
        MAINNET_POW_LIMIT_DIV_4_BITS,
    );
    assert_eq!(
        validate_header_nbits(&tree, parent_id, &header, Network::Mainnet),
        Ok(())
    );
    Ok(())
}

#[test]
fn daa_retarget_clamps_slow_timespan_to_quadruple_target() -> Result<(), Box<dyn std::error::Error>>
{
    let mut tree = BlockTree::new();
    let interval = Network::Mainnet.retarget_interval();
    let expected_timespan = interval * 600;
    let start_bits = scaled_pow_limit_bits(Network::Mainnet, 16);
    let expected_bits = retarget_bits_for_test(
        Network::Mainnet,
        start_bits,
        expected_timespan * 4 + 1,
        expected_timespan,
    );
    let (parent_id, _) = seed_period(
        &mut tree,
        start_bits,
        DAA_ANCHOR_TIME,
        DAA_ANCHOR_TIME + expected_timespan * 4 + 1,
        interval - 1,
    )?;
    let header = raw_header_with(
        tree.node(parent_id)?.hash.into(),
        interval,
        DAA_ANCHOR_TIME + expected_timespan * 4 + 600,
        expected_bits,
    );
    assert_eq!(
        validate_header_nbits(&tree, parent_id, &header, Network::Mainnet),
        Ok(())
    );
    Ok(())
}

#[test]
fn testnet_allows_min_difficulty_after_time_gap() -> Result<(), Box<dyn std::error::Error>> {
    let mut tree = BlockTree::new();
    let regular_bits = MAINNET_POW_LIMIT_DIV_4_BITS;
    let min_bits = pow_limit_bits(Network::Testnet3);
    let (parent_id, _) = seed_headers(
        &mut tree,
        &[
            (regular_bits, DAA_ANCHOR_TIME),
            (regular_bits, DAA_ANCHOR_TIME + 600),
        ],
    )?;
    let header = raw_header_with(
        tree.node(parent_id)?.hash.into(),
        2,
        DAA_ANCHOR_TIME + 1_801,
        min_bits,
    );
    assert_eq!(
        validate_header_nbits(&tree, parent_id, &header, Network::Testnet3),
        Ok(())
    );
    Ok(())
}

#[test]
fn testnet_timely_block_after_min_difficulty_inherits_last_non_min_bits()
-> Result<(), Box<dyn std::error::Error>> {
    let mut tree = BlockTree::new();
    let regular_bits = MAINNET_POW_LIMIT_DIV_4_BITS;
    let min_bits = pow_limit_bits(Network::Testnet3);
    let (parent_id, _) = seed_headers(
        &mut tree,
        &[
            (regular_bits, DAA_ANCHOR_TIME),
            (regular_bits, DAA_ANCHOR_TIME + 600),
            (min_bits, DAA_ANCHOR_TIME + 1_801),
        ],
    )?;
    let timely_time = DAA_ANCHOR_TIME + 2_400;
    let accepted = raw_header_with(
        tree.node(parent_id)?.hash.into(),
        3,
        timely_time,
        regular_bits,
    );
    assert_eq!(
        validate_header_nbits(&tree, parent_id, &accepted, Network::Testnet3),
        Ok(())
    );
    let rejected = raw_header_with(tree.node(parent_id)?.hash.into(), 3, timely_time, min_bits);
    assert_nbits_mismatch(
        validate_header_nbits(&tree, parent_id, &rejected, Network::Testnet3),
        min_bits,
        regular_bits,
        3,
    );
    Ok(())
}

#[test]
fn mainnet_rejects_min_difficulty_after_time_gap() -> Result<(), Box<dyn std::error::Error>> {
    let mut tree = BlockTree::new();
    let regular_bits = MAINNET_POW_LIMIT_DIV_4_BITS;
    let min_bits = pow_limit_bits(Network::Mainnet);
    let (parent_id, _) = seed_headers(
        &mut tree,
        &[
            (regular_bits, DAA_ANCHOR_TIME),
            (regular_bits, DAA_ANCHOR_TIME + 600),
        ],
    )?;
    let header = raw_header_with(
        tree.node(parent_id)?.hash.into(),
        2,
        DAA_ANCHOR_TIME + 1_801,
        min_bits,
    );
    assert_nbits_mismatch(
        validate_header_nbits(&tree, parent_id, &header, Network::Mainnet),
        min_bits,
        regular_bits,
        2,
    );
    Ok(())
}

#[test]
fn testnet_min_difficulty_does_not_override_retarget_boundary()
-> Result<(), Box<dyn std::error::Error>> {
    let mut tree = BlockTree::new();
    let interval = Network::Testnet3.retarget_interval();
    let expected_timespan = interval * 600;
    let regular_bits = MAINNET_POW_LIMIT_DIV_4_BITS;
    let min_bits = pow_limit_bits(Network::Testnet3);
    let (parent_id, _) = seed_period(
        &mut tree,
        regular_bits,
        DAA_ANCHOR_TIME,
        DAA_ANCHOR_TIME + expected_timespan,
        interval - 1,
    )?;
    let header = raw_header_with(
        tree.node(parent_id)?.hash.into(),
        interval,
        DAA_ANCHOR_TIME + expected_timespan + 1_201,
        min_bits,
    );
    assert_nbits_mismatch(
        validate_header_nbits(&tree, parent_id, &header, Network::Testnet3),
        min_bits,
        regular_bits,
        interval,
    );
    Ok(())
}

#[test]
fn testnet4_retarget_uses_first_period_bits_after_min_difficulty_tip()
-> Result<(), Box<dyn std::error::Error>> {
    let mut tree = BlockTree::new();
    let network = Network::Testnet4;
    let interval = network.retarget_interval();
    let expected_timespan = interval * 600;
    let first_period_bits = scaled_pow_limit_bits(network, 16);
    let min_bits = pow_limit_bits(network);
    let mut headers = Vec::with_capacity(usize::try_from(interval).unwrap_or(usize::MAX));
    for height in 0..interval {
        let bits = if height == interval - 1 {
            min_bits
        } else {
            first_period_bits
        };
        headers.push((
            bits,
            DAA_ANCHOR_TIME.saturating_add(
                u32::try_from(
                    u64::from(expected_timespan) * u64::from(height) / u64::from(interval - 1),
                )
                .unwrap_or(u32::MAX),
            ),
        ));
    }
    let (parent_id, _) = seed_headers(&mut tree, &headers)?;
    let expected_bits = retarget_bits_for_test(
        network,
        first_period_bits,
        expected_timespan,
        expected_timespan,
    );
    let header = raw_header_with(
        tree.node(parent_id)?.hash.into(),
        interval,
        DAA_ANCHOR_TIME + expected_timespan + 600,
        expected_bits,
    );
    assert_eq!(
        validate_header_nbits(&tree, parent_id, &header, network),
        Ok(())
    );
    Ok(())
}

#[test]
fn daa_retarget_caps_slow_timespan_at_pow_limit() -> Result<(), Box<dyn std::error::Error>> {
    let mut tree = BlockTree::new();
    let network = Network::Mainnet;
    let interval = network.retarget_interval();
    let expected_timespan = interval * 600;
    let (parent_id, _) = seed_period(
        &mut tree,
        MAINNET_POW_LIMIT_BITS,
        DAA_ANCHOR_TIME,
        DAA_ANCHOR_TIME + expected_timespan * 4,
        interval - 1,
    )?;
    let header = raw_header_with(
        tree.node(parent_id)?.hash.into(),
        interval,
        DAA_ANCHOR_TIME + expected_timespan * 4 + 600,
        MAINNET_POW_LIMIT_BITS,
    );
    assert_eq!(
        validate_header_nbits(&tree, parent_id, &header, network),
        Ok(())
    );
    Ok(())
}
