use super::{
    HeaderValidationMode, MAX_FUTURE_TIME_SECONDS, accept_headers, demoted_tip_after_rejection,
    fixture::mine_regtest, next_work_required, validate_contextual_header,
};
use crate::{
    ChainError,
    node::{BlockHeader, NodeStatus},
    tree::BlockTree,
};
use bitcoin_rs_primitives::{BlockHash, CompactTarget, Hash256, Network};

const TESTNET4_POW_LIMIT: u32 = 0x1d00_ffff;

fn extend_regtest(
    tree: &mut BlockTree,
    prev: &mut BlockHash,
    height: u32,
    version: i32,
    base_time: u32,
) {
    let network = Network::Regtest;
    let time = base_time + height * 600;
    let header = mine_regtest(*prev, height, time, version);
    accept_headers(
        tree,
        &[header],
        network,
        time,
        HeaderValidationMode::LiveAdmission,
    )
    .unwrap_or_else(|e| panic!("fixture header at height {height} rejected: {e:?}"));
    *prev = header.compute_hash();
}

#[test]
fn rejects_outdated_versions_after_activation() -> Result<(), Box<dyn std::error::Error>> {
    let network = Network::Regtest;
    let genesis = network.genesis_block();
    let base_time = genesis.header.time;
    let mut prev = genesis.block_hash();
    let mut tree = BlockTree::new();
    accept_headers(
        &mut tree,
        &[genesis.header],
        network,
        base_time,
        HeaderValidationMode::LiveAdmission,
    )?;

    let mut filled = 0_u32;
    for (activation, stale, required) in [(500_u32, 1_i32, 2_i32), (1251, 2, 3), (1351, 3, 4)] {
        for height in filled + 1..activation {
            extend_regtest(&mut tree, &mut prev, height, required, base_time);
        }
        filled = activation;

        let now = base_time + activation * 600;
        let rejected = mine_regtest(prev, activation, now, stale);
        assert_eq!(
            accept_headers(
                &mut tree,
                &[rejected],
                network,
                now,
                HeaderValidationMode::LiveAdmission
            ),
            Err(ChainError::BadVersion {
                version: stale,
                required,
                height: activation
            })
        );
        assert_eq!(
            tree.lookup(Hash256::from(rejected.compute_hash())),
            None,
            "a rejected header must not enter the tree"
        );

        let accepted = mine_regtest(prev, activation, now, required);
        accept_headers(
            &mut tree,
            &[accepted],
            network,
            now,
            HeaderValidationMode::LiveAdmission,
        )
        .map_err(|error| {
            format!("version {required} is legal at height {activation}: {error:?}")
        })?;
        prev = accepted.compute_hash();
    }
    Ok(())
}

#[test]
fn rejects_testnet4_bip94_timewarp_candidate() -> Result<(), Box<dyn std::error::Error>> {
    let network = Network::Testnet4;
    let mut tree = BlockTree::new();
    let mut prev = BlockHash::default();
    let mut tip_time = 0;
    for height in 0..2016_u32 {
        let header = BlockHeader {
            version: 4,
            prev_blockhash: prev,
            merkle_root: Hash256::default(),
            time: 1_600_000_000 + height * 600,
            bits: CompactTarget::from_consensus(TESTNET4_POW_LIMIT),
            nonce: height,
        };
        prev = header.compute_hash();
        tree.insert_header_with_hash(
            header,
            Hash256::from(header.compute_hash()),
            NodeStatus::HeaderValid,
        )?;
        tip_time = header.time;
    }
    let parent_id = tree.lookup(prev.0).ok_or("fixture tip present")?;
    let bits = next_work_required(&tree, parent_id, tip_time, network)?;
    let now = tip_time + MAX_FUTURE_TIME_SECONDS;
    let candidate = |time: u32| BlockHeader {
        version: 4,
        prev_blockhash: prev,
        merkle_root: Hash256::default(),
        time,
        bits,
        nonce: 0,
    };

    assert_eq!(
        validate_contextual_header(
            &tree,
            parent_id,
            &candidate(tip_time - 601),
            network,
            now,
            HeaderValidationMode::LiveAdmission
        ),
        Err(ChainError::TimewarpAttack {
            height: 2016,
            timestamp: tip_time - 601,
            minimum: tip_time - 600,
        })
    );
    validate_contextual_header(
        &tree,
        parent_id,
        &candidate(tip_time - 600),
        network,
        now,
        HeaderValidationMode::LiveAdmission,
    )
    .map_err(|error| format!("a timestamp exactly at the timewarp floor is legal: {error:?}"))?;
    Ok(())
}

#[test]
fn child_of_invalid_parent_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let network = Network::Regtest;
    let genesis = network.genesis_block();
    let base_time = genesis.header.time;
    let mut prev = genesis.block_hash();
    let mut tree = BlockTree::new();
    accept_headers(
        &mut tree,
        &[genesis.header],
        network,
        base_time,
        HeaderValidationMode::LiveAdmission,
    )?;
    extend_regtest(&mut tree, &mut prev, 1, 4, base_time);
    let block_one = tree.lookup(prev.0).ok_or("block one is in the tree")?;
    tree.invalidate_subtree(block_one)?;

    let now = base_time + 2 * 600;
    let child = mine_regtest(prev, 2, now, 4);
    assert_eq!(
        accept_headers(
            &mut tree,
            &[child],
            network,
            now,
            HeaderValidationMode::LiveAdmission
        ),
        Err(ChainError::InvalidParent { parent: block_one }),
        "a child of an invalidated header is refused, not accepted as invalid"
    );
    assert_eq!(
        tree.lookup(Hash256::from(child.compute_hash())),
        None,
        "the refused child must not extend the invalid subtree"
    );
    Ok(())
}

#[test]
fn wall_clock_conversion_handles_epoch_and_u32_boundaries() {
    use std::time::{Duration, UNIX_EPOCH};
    for (clock, expected) in [
        (UNIX_EPOCH - Duration::from_secs(1), 0),
        (UNIX_EPOCH, 0),
        (UNIX_EPOCH + Duration::from_secs(1), 1),
        (
            UNIX_EPOCH + Duration::from_secs(u64::from(u32::MAX)),
            u32::MAX,
        ),
        (
            UNIX_EPOCH + Duration::from_secs(u64::from(u32::MAX) + 1),
            u32::MAX,
        ),
    ] {
        assert_eq!(super::unix_seconds_at(clock), expected);
    }
}

fn chain_with_median_five() -> (BlockTree, BlockHeader) {
    let mut tree = BlockTree::new();
    let mut prev = BlockHash::default();
    let mut tip = mine_regtest(prev, 0, 0, 1);
    for height in 0_u32..11 {
        let header = mine_regtest(prev, height, height, 1);
        prev = header.compute_hash();
        let hash = Hash256::from(header.compute_hash());
        tree.insert_header_with_hash(header, hash, NodeStatus::HeaderValid)
            .unwrap_or_else(|e| panic!("fixture header failed to insert: {e:?}"));
        tip = header;
    }
    (tree, tip)
}

#[test]
fn timestamp_bounds_hold_per_validation_mode() -> Result<(), Box<dyn std::error::Error>> {
    let (tree, tip) = chain_with_median_five();
    let parent_id = tree.lookup(tip.compute_hash().0).ok_or("tip in tree")?;
    let rolled_back = 1_000_u32;
    let far_future = 2_000_000_000_u32;

    let live = HeaderValidationMode::LiveAdmission;
    let replay = HeaderValidationMode::HistoricalReplay;
    let drifted = rolled_back + MAX_FUTURE_TIME_SECONDS + 100;
    let ceiling = far_future + MAX_FUTURE_TIME_SECONDS;
    let cases = [
        ("MTP equality", 11, 5, 1_000_000, live, false),
        ("above MTP", 11, 6, 1_000_000, live, true),
        ("replay MTP", 11, 5, 1_000_000, replay, false),
        (
            "below-host ceiling",
            11,
            1_000_000 + MAX_FUTURE_TIME_SECONDS,
            1_000_000,
            live,
            true,
        ),
        (
            "past below-host ceiling",
            11,
            1_000_001 + MAX_FUTURE_TIME_SECONDS,
            1_000_000,
            live,
            false,
        ),
        ("live drift", 11, drifted, rolled_back, live, false),
        ("replay drift", 11, drifted, rolled_back, replay, true),
        (
            "supplied clock ceiling",
            11,
            ceiling,
            far_future,
            live,
            true,
        ),
        ("one past ceiling", 12, ceiling + 1, far_future, live, false),
    ];
    assert!(
        super::current_unix_seconds() + MAX_FUTURE_TIME_SECONDS
            < far_future + MAX_FUTURE_TIME_SECONDS,
        "the host clock must reject the supplied-time case, or it proves nothing"
    );

    for (name, seed, time, now, mode, accepted) in cases {
        let header = mine_regtest(tip.compute_hash(), seed, time, 1);
        let result =
            validate_contextual_header(&tree, parent_id, &header, Network::Regtest, now, mode);
        if accepted {
            assert_eq!(result, Ok(()), "{name}");
        } else if time <= 5 {
            assert_eq!(
                result,
                Err(ChainError::TimestampTooEarly {
                    hash: Hash256::from(header.compute_hash()),
                    timestamp: time,
                    median: 5,
                }),
                "{name}"
            );
        } else {
            assert_eq!(
                result,
                Err(ChainError::TimestampTooFarAhead {
                    hash: Hash256::from(header.compute_hash()),
                    timestamp: time,
                    max_allowed: now + MAX_FUTURE_TIME_SECONDS,
                }),
                "{name}"
            );
        }
    }

    Ok(())
}

#[test]
fn partial_prefix_failure_preserves_demoted_tip_via_helper()
-> Result<(), Box<dyn std::error::Error>> {
    let network = Network::Regtest;
    let genesis = network.genesis_block();
    let base_time = genesis.header.time;
    let mut tree = BlockTree::new();
    accept_headers(
        &mut tree,
        &[genesis.header],
        network,
        base_time,
        HeaderValidationMode::LiveAdmission,
    )?;
    let mut prev = genesis.block_hash();
    for height in 1..=2_u32 {
        extend_regtest(&mut tree, &mut prev, height, 4, base_time);
    }
    let pre_tip = tree.tip().map(|tip| tip.hash);

    let mut side_prev = genesis.block_hash();
    let mut batch = Vec::new();
    for height in [101_u32, 102, 103] {
        let header = mine_regtest(side_prev, height, base_time + height * 600, 4);
        side_prev = header.compute_hash();
        batch.push(header);
    }
    let garbage = BlockHash::from(Hash256::from_le_bytes(&[0xFF_u8; 32]));
    let tail = mine_regtest(garbage, 104, base_time + 104 * 600, 4);
    batch.push(tail);

    let now = base_time + 200 * 600;
    let result = accept_headers(
        &mut tree,
        &batch,
        network,
        now,
        HeaderValidationMode::LiveAdmission,
    );
    assert!(
        matches!(result, Err(ChainError::MissingParent { .. })),
        "the tail must fail after the prefix moved the tip, got {result:?}"
    );
    assert_eq!(
        demoted_tip_after_rejection(&tree, pre_tip),
        pre_tip,
        "the tip active before the batch is the preserved demotion"
    );

    let tip_now = tree.tip().map(|tip| tip.hash);
    let bad_child = mine_regtest(garbage, 999, now, 4);
    let linear = accept_headers(
        &mut tree,
        &[bad_child],
        network,
        now,
        HeaderValidationMode::LiveAdmission,
    );
    assert!(
        matches!(linear, Err(ChainError::MissingParent { .. })),
        "linear failure must also reject, got {linear:?}"
    );
    assert_eq!(
        demoted_tip_after_rejection(&tree, tip_now),
        None,
        "no movement means no demotion to preserve"
    );
    Ok(())
}
