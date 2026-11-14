#![expect(
    clippy::expect_used,
    reason = "independent-oracle fixture construction"
)]

use super::{HeaderValidationMode, accept_headers, next_work_required};
use crate::chain::test_error::TestError;
use crate::chain::{
    ChainError,
    node::{NodeId, NodeStatus},
    tree::BlockTree,
};
use bitcoin_rs_consensus::header_rules::{BlockHeader, ChainWork};
use bitcoin_rs_consensus::primitives::{BlockHash, CompactTarget, Hash256, Network};

const RETARGET_INTERVAL: u32 = 2016;
const TARGET_TIMESPAN: u32 = 14 * 24 * 60 * 60;
const TESTNET_POW_LIMIT_BITS: u32 = 0x1d00_ffff;

fn header_with(prev: BlockHash, time: u32, bits: u32, nonce: u32) -> BlockHeader {
    BlockHeader {
        version: 4,
        prev_blockhash: prev,
        merkle_root: Hash256::default(),
        time,
        bits: CompactTarget::from_consensus(bits),
        nonce,
    }
}

fn chain_header(prev: &mut BlockHash, time: u32, bits: u32, height: u32) -> BlockHeader {
    let header = header_with(*prev, time, bits, height);
    *prev = header.compute_hash();
    header
}

fn build_retarget_chain(
    tree: &mut BlockTree,
    anchor_bits: u32,
    inner_bits: u32,
    anchor_time: u32,
    step_seconds: u32,
) -> Result<NodeId, TestError> {
    let mut prev = BlockHash::default();
    let mut tip = NodeId::new(u32::MAX);
    for height in 0..RETARGET_INTERVAL {
        let bits = if height == 0 { anchor_bits } else { inner_bits };
        let time = anchor_time + height.saturating_mul(step_seconds);
        let header = chain_header(&mut prev, time, bits, height);
        tip = tree.insert_header(header, NodeStatus::HeaderValid)?;
    }
    Ok(tip)
}

fn core_set_compact(bits: u32) -> (ChainWork, bool, bool) {
    let size = usize::try_from(bits >> 24).unwrap_or(0);
    let word = bits & 0x007f_ffff;
    let target = if size <= 3 {
        ChainWork::from(word >> (8 * (3 - size)))
    } else {
        let shift = 8 * (size - 3);
        if shift < 256 {
            ChainWork::from(word) << shift
        } else {
            ChainWork::ZERO
        }
    };
    let negative = word != 0 && bits & 0x0080_0000 != 0;
    let overflow =
        word != 0 && (size > 34 || (word > 0xff && size > 33) || (word > 0xffff && size > 32));
    (target, negative, overflow)
}

fn pow_limit_work() -> ChainWork {
    core_set_compact(TESTNET_POW_LIMIT_BITS).0
}

fn core_calculate_next_work_required(last_time: u32, base_bits: u32, first_time: u32) -> u32 {
    let mut actual = i64::from(last_time) - i64::from(first_time);
    let timespan = i64::from(TARGET_TIMESPAN);
    if actual < timespan / 4 {
        actual = timespan / 4;
    }
    if actual > timespan * 4 {
        actual = timespan * 4;
    }
    let actual_u32 = u32::try_from(actual).expect("clamped timespan fits u32");
    let (mut target, negative, overflow) = core_set_compact(base_bits);
    assert!(!negative && !overflow);
    target *= ChainWork::from(actual_u32);
    target /= ChainWork::from(TARGET_TIMESPAN);
    let limit = pow_limit_work();
    if target > limit {
        target = limit;
    }
    core_get_compact(target)
}

fn core_get_compact(target: ChainWork) -> u32 {
    let mut size = u32::try_from(target.bit_len().div_ceil(8)).expect("size fits u32");
    let mut compact: u32 = if size <= 3 {
        u32::try_from(target.as_limbs()[0] << (8 * (3 - size)))
            .expect("mantissa fits u32 when size <= 3")
    } else {
        u32::try_from((target >> (8 * (size - 3))).as_limbs()[0])
            .expect("three-byte window fits u32")
    };
    if compact & 0x0080_0000 != 0 {
        compact >>= 8;
        size += 1;
    }
    compact | (size << 24)
}

fn tree_shape(tree: &BlockTree) -> Vec<(Hash256, u32, NodeStatus, Option<NodeId>, ChainWork)> {
    let len = u32::try_from(tree.len()).expect("node count fits u32");
    (0..len)
        .map(|index| {
            let node = tree.node(NodeId::new(index)).expect("node exists");
            (
                node.hash,
                node.height,
                node.status,
                node.parent,
                node.chainwork,
            )
        })
        .collect()
}

fn side_chain_retip(tree: &mut BlockTree) -> Result<NodeId, TestError> {
    let main_tip = build_retarget_chain(tree, 0x1b04_04cb, 0x1c0f_fffe, 1_600_000_000, 1)?;
    let mut fork = main_tip;
    for _ in 0..5 {
        fork = tree.parent_id(fork)?.ok_or(TestError::from("no parent"))?;
    }
    let mut cursor = fork;
    for depth in 0..6_u32 {
        let parent_hash = tree.node(cursor)?.hash;
        let parent_height = tree.node(cursor)?.height;
        let time = 1_600_000_000 + parent_height + 10_000_000 + depth;
        let header = header_with(BlockHash(parent_hash), time, 0x1c0f_fffe, 900_000 + depth);
        cursor = tree.insert_node(Some(cursor), header, NodeStatus::HeaderValid)?;
    }
    Ok(cursor)
}

#[test]
fn side_chain_retarget_anchors_shared_height_zero_block() -> Result<(), TestError> {
    let network = Network::Testnet3;
    let mut tree = BlockTree::new();
    let side_tip = side_chain_retip(&mut tree)?;
    assert_eq!(tree.node(side_tip)?.height, RETARGET_INTERVAL);
    let retarget_parent = tree
        .parent_id(side_tip)?
        .ok_or(TestError::from("no parent"))?;
    let parent_time = tree.node(retarget_parent)?.header.time;
    let parent_bits = tree.node(retarget_parent)?.header.bits.to_consensus();
    let got = next_work_required(&tree, retarget_parent, 0, network)?.to_consensus();
    let want = core_calculate_next_work_required(parent_time, parent_bits, 1_600_000_000);
    assert_eq!(
        got, want,
        "side-chain retarget must anchor on the shared height-0 block"
    );
    Ok(())
}

#[test]
fn bip94_retarget_scales_anchor_block_bits() -> Result<(), TestError> {
    let network = Network::Testnet4;
    let mut tree = BlockTree::new();
    let first_time = 1_600_000_000_u32;
    let tip = build_retarget_chain(
        &mut tree,
        0x1b04_04cb,
        TESTNET_POW_LIMIT_BITS,
        first_time,
        1,
    )?;
    let got = next_work_required(&tree, tip, 0, network)?.to_consensus();
    let want = core_calculate_next_work_required(
        first_time + RETARGET_INTERVAL - 1,
        0x1b04_04cb,
        first_time,
    );
    assert_eq!(
        got, want,
        "BIP94 scales the anchor block's bits, not the last block's"
    );
    Ok(())
}

#[test]
fn testnet_min_difficulty_boundary_is_strict_and_walks_back() -> Result<(), TestError> {
    let network = Network::Testnet3;
    let mut tree = BlockTree::new();
    let mut prev = BlockHash::default();
    let mut times = vec![1_600_000_000_u32];
    for height in 1..8_u32 {
        let index = usize::try_from(height - 1).expect("index fits usize");
        let bits = if height == 5 {
            0x1b04_04cb
        } else {
            TESTNET_POW_LIMIT_BITS
        };
        let header = chain_header(&mut prev, times[index] + 700, bits, height);
        times.push(header.time);
        tree.insert_header(header, NodeStatus::HeaderValid)?;
    }
    let tip_id = tree.lookup(prev.0).ok_or(TestError::from("fixture tip"))?;

    let late = next_work_required(&tree, tip_id, times[7] + 1201, network)?.to_consensus();
    assert_eq!(late, TESTNET_POW_LIMIT_BITS);

    let exact = next_work_required(&tree, tip_id, times[7] + 1200, network)?.to_consensus();
    assert_eq!(exact, 0x1b04_04cb);

    let early = next_work_required(&tree, tip_id, times[7] + 60, network)?.to_consensus();
    assert_eq!(early, 0x1b04_04cb);
    Ok(())
}

#[test]
fn refused_header_leaves_tree_unchanged() -> Result<(), TestError> {
    let network = Network::Regtest;
    let genesis = network.genesis_block();
    let mut tree = BlockTree::new();
    let base_time = genesis.header.time;
    accept_headers(
        &mut tree,
        &[genesis.header],
        network,
        base_time,
        HeaderValidationMode::LiveAdmission,
    )?;
    let good = super::fixture::mine_regtest(genesis.block_hash(), 1, base_time + 600, 4);
    accept_headers(
        &mut tree,
        &[good],
        network,
        base_time + 600,
        HeaderValidationMode::LiveAdmission,
    )?;
    let good_hash = good.compute_hash();
    let good_id = tree
        .lookup(Hash256::from(good_hash))
        .ok_or(TestError::from("tip"))?;
    let child = super::fixture::mine_regtest(good_hash, 2, base_time + 1300, 4);
    accept_headers(
        &mut tree,
        &[child],
        network,
        base_time + 1300,
        HeaderValidationMode::LiveAdmission,
    )?;
    tree.invalidate_subtree(good_id)?;
    assert_eq!(tree.node(good_id)?.status, NodeStatus::Invalid);
    let before = tree_shape(&tree);
    let now = base_time + 1_000_000;

    let duplicate = accept_headers(
        &mut tree,
        &[good],
        network,
        base_time + 600,
        HeaderValidationMode::LiveAdmission,
    );
    assert!(matches!(
        duplicate,
        Err(ChainError::KnownInvalidHeader { .. })
    ));
    assert_eq!(tree_shape(&tree), before);

    let out_of_order_parent = super::fixture::mine_regtest(good_hash, 5, base_time + 1900, 4);
    let out_of_order_child =
        super::fixture::mine_regtest(out_of_order_parent.compute_hash(), 6, base_time + 2500, 4);
    let res = accept_headers(
        &mut tree,
        &[out_of_order_child, out_of_order_parent],
        network,
        now,
        HeaderValidationMode::LiveAdmission,
    );
    assert!(matches!(res, Err(ChainError::MissingParent { .. })));
    assert_eq!(tree_shape(&tree), before);

    let orphan = super::fixture::mine_regtest(BlockHash::default(), 2, base_time + 700, 4);
    assert!(matches!(
        accept_headers(
            &mut tree,
            &[orphan],
            network,
            now,
            HeaderValidationMode::LiveAdmission
        ),
        Err(ChainError::MissingParent { .. })
    ));
    assert_eq!(tree_shape(&tree), before);

    let invalid_parent_child = super::fixture::mine_regtest(good_hash, 5, base_time + 2600, 4);
    assert!(matches!(
        accept_headers(&mut tree, &[invalid_parent_child], network, now, HeaderValidationMode::LiveAdmission),
        Err(ChainError::InvalidParent { parent } ) if parent == good_id
    ));
    assert_eq!(tree_shape(&tree), before);

    let early = super::fixture::mine_regtest(genesis.block_hash(), 1, base_time, 4);
    assert!(matches!(
        accept_headers(
            &mut tree,
            &[early],
            network,
            now,
            HeaderValidationMode::LiveAdmission
        ),
        Err(ChainError::TimestampTooEarly { .. })
    ));
    assert_eq!(tree_shape(&tree), before);

    let mismatched_bits = header_with(genesis.block_hash(), base_time + 2600, 0x0100_0000, 12);
    assert!(
        accept_headers(
            &mut tree,
            &[mismatched_bits],
            network,
            now,
            HeaderValidationMode::LiveAdmission
        )
        .is_err()
    );
    assert_eq!(tree_shape(&tree), before);

    let far_future = super::fixture::mine_regtest(genesis.block_hash(), 1, now + 7201, 4);
    assert!(matches!(
        accept_headers(
            &mut tree,
            &[far_future],
            network,
            now,
            HeaderValidationMode::LiveAdmission
        ),
        Err(ChainError::TimestampTooFarAhead { .. })
    ));
    assert_eq!(tree_shape(&tree), before);
    Ok(())
}
