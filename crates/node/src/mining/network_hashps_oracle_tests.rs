use super::estimate_network_hashps;
use super::hash_ps_at;
use bitcoin_rs_chain::BlockTree;
use bitcoin_rs_chain::NodeId;
use bitcoin_rs_chain::NodeStatus;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_mining::MiningControlError;
use bitcoin_rs_primitives::BlockHash;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::Header;
use bitcoin_rs_primitives::Network;

const BITS: u32 = 0x207f_ffff;

fn header(prev: BlockHash, time: u32) -> Header {
    use bitcoin_rs_primitives::CompactTarget;
    Header {
        version: 1,
        prev_blockhash: prev,
        merkle_root: Hash256::default(),
        time,
        bits: CompactTarget::from_consensus(BITS),
        nonce: 0,
    }
}

fn append(tree: &mut BlockTree, prev: BlockHash, time: u32) -> NodeId {
    tree.insert_header(header(prev, time), NodeStatus::HeaderValid)
        .unwrap_or_else(|err| panic!("insert header at time {time}: {err}"))
}

fn snapshot(tree: &BlockTree, tip_id: NodeId) -> TipSnapshot {
    let node = tree
        .node(tip_id)
        .unwrap_or_else(|err| panic!("missing tip {tip_id:?}: {err}"));
    TipSnapshot {
        tip_id,
        height: node.height,
        chainwork: node.chainwork,
        hash: node.hash,
    }
}

fn work_to_f64(work: bitcoin_rs_chain::ChainWork) -> f64 {
    let bytes: [u8; 32] = work.to_be_bytes();
    bytes
        .iter()
        .fold(0.0_f64, |acc, &byte| acc.mul_add(256.0, f64::from(byte)))
}

/// Independent Core parent-walk, not the height-range implementation under test.
fn core_getnetworkhashps(tree: &BlockTree, start_id: NodeId, lookup: i64, network: Network) -> f64 {
    let start = tree
        .node(start_id)
        .unwrap_or_else(|err| panic!("missing start: {err}"));
    if start.height == 0 {
        return 0.0;
    }
    let mut walk = if lookup == -1 {
        i64::from(start.height) % i64::from(network.retarget_interval()) + 1
    } else {
        lookup
    };
    if walk > i64::from(start.height) {
        walk = i64::from(start.height);
    }
    let walk = u32::try_from(walk).unwrap_or_else(|_| panic!("walk fits u32"));
    let mut min_time = start.header.time;
    let mut max_time = min_time;
    let mut earliest_id = start_id;
    for _ in 0..walk {
        earliest_id = tree
            .node(earliest_id)
            .unwrap_or_else(|err| panic!("missing walked node: {err}"))
            .parent
            .unwrap_or_else(|| panic!("Core walks `lookup` parents; chain too short"));
        let time = tree
            .node(earliest_id)
            .unwrap_or_else(|err| panic!("missing parent: {err}"))
            .header
            .time;
        min_time = min_time.min(time);
        max_time = max_time.max(time);
    }
    if min_time == max_time {
        return 0.0;
    }
    let earliest = tree
        .node(earliest_id)
        .unwrap_or_else(|err| panic!("missing earliest: {err}"));
    let work = work_to_f64(start.chainwork.saturating_sub(earliest.chainwork));
    work / f64::from(max_time.saturating_sub(min_time))
}

fn assert_matches_core(
    tree: &BlockTree,
    tip: &TipSnapshot,
    lookup: i64,
    height: i64,
    network: Network,
) {
    let start_id = if height < 0 {
        tip.tip_id
    } else {
        let requested = u32::try_from(height).unwrap_or_else(|_| panic!("height fits u32"));
        tree.node_at_height_from(tip.tip_id, requested)
            .unwrap_or_else(|| panic!("missing height {height}"))
    };
    let expected = core_getnetworkhashps(tree, start_id, lookup, network);
    let got = estimate_network_hashps(tree, Some(start_id), lookup, network);
    assert!(
        (got - expected).abs() < 1e-9,
        "lookup={lookup} height={height}: got {got}, Core oracle {expected}"
    );
}

#[test]
fn estimate_network_hashps_matches_core_getnetworkhashps() {
    let mut tree = BlockTree::new();
    // Non-monotonic times: height 2 goes backwards so min/max ≠ first/last.
    let times = [1_000_000_u32, 1_000_600, 1_000_300, 1_001_200, 1_001_800];
    let mut prev = BlockHash::default();
    let mut tip_id = None;
    for &time in &times {
        let id = append(&mut tree, prev, time);
        prev = tree
            .node(id)
            .unwrap_or_else(|err| panic!("inserted node: {err}"))
            .header
            .compute_hash();
        tip_id = Some(id);
    }
    let tip_id = tip_id.unwrap_or_else(|| panic!("chain has a tip"));
    let tip = snapshot(&tree, tip_id);
    let network = Network::Regtest;

    assert_matches_core(&tree, &tip, 2, -1, network);
    assert_matches_core(&tree, &tip, 1, 3, network);
    assert_matches_core(&tree, &tip, -1, -1, network);
    assert_matches_core(&tree, &tip, 120, -1, network);

    let genesis_id = tree
        .node_at_height_from(tip.tip_id, 0)
        .unwrap_or_else(|| panic!("genesis height is on the tip"));
    let genesis = estimate_network_hashps(&tree, Some(genesis_id), 120, network);
    assert!(
        genesis.abs() < f64::EPSILON,
        "Core returns 0 at genesis, got {genesis}"
    );

    let retarget_lookup = i64::from(tip.height) % i64::from(network.retarget_interval()) + 1;
    let via_minus_one = estimate_network_hashps(&tree, Some(tip.tip_id), -1, network);
    let via_explicit = estimate_network_hashps(&tree, Some(tip.tip_id), retarget_lookup, network);
    assert!(
        (via_minus_one - via_explicit).abs() < 1e-9,
        "-1 lookback must equal height % interval + 1 ({retarget_lookup})"
    );
}

#[test]
// CONTRACT: docs/contracts/external-api.md#API-06
fn hash_ps_at_rejects_a_height_the_tip_cannot_resolve() {
    let mut tree = BlockTree::new();
    let genesis = append(&mut tree, BlockHash::default(), 1_000_000);
    let mut stale = snapshot(&tree, genesis);
    stale.height = 4;
    match hash_ps_at(&tree, Some(&stale), 120, 3, Network::Regtest) {
        Err(MiningControlError::InvalidRequest(message)) => {
            assert_eq!(message.as_str(), "Block does not exist at specified height");
        }
        other => panic!("unresolvable height must be invalid, got {other:?}"),
    }
}

#[test]
fn hashes_per_second_divides_work_by_elapsed_seconds() {
    let mut work = [0_u8; 32];
    work[31] = 120;
    let rate = super::hashes_per_second(work, 60);
    assert!(
        (rate - 2.0).abs() < f64::EPSILON,
        "120 work over 60s must be 2.0 hashes/s, got {rate}"
    );
    let zero_elapsed = super::hashes_per_second(work, 0);
    assert!(
        zero_elapsed.abs() < f64::EPSILON,
        "zero elapsed must report 0.0 hashes/s, got {zero_elapsed}"
    );
    let negative_elapsed = super::hashes_per_second(work, -1);
    assert!(
        negative_elapsed.abs() < f64::EPSILON,
        "negative elapsed must report 0.0 hashes/s, got {negative_elapsed}"
    );
}
