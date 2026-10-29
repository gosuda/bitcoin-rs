use std::hint::black_box;
use std::sync::Arc;

use bitcoin_rs_chain::{BlockTree, BlockTreeReader, ChainWork, NodeStatus, TipReader, block_work};
use bitcoin_rs_p2p::sync::{HeaderAnchor, HeadersSyncPhase, HeadersSyncState};
use bitcoin_rs_p2p::{ActiveChainQuery, ChainQuery};
use bitcoin_rs_primitives::{
    BlockHash, CompactTarget, Hash256, Header, HeadersSyncParams, Network,
};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use parking_lot::RwLock;

const PAGE: usize = 2_000;

const EASY_BITS: CompactTarget = CompactTarget::from_consensus(0x207f_ffff);

const FIXTURE_TIME: u32 = 1_700_000_000;

fn mine_header(prev: BlockHash, height: u32) -> Header {
    let mut merkle = [0_u8; 32];
    merkle[..4].copy_from_slice(&height.to_le_bytes());
    let mut header = Header {
        version: 4,
        prev_blockhash: prev,
        merkle_root: Hash256::from_le_bytes(&merkle),
        time: FIXTURE_TIME.saturating_add(height),
        bits: EASY_BITS,
        nonce: height,
    };
    if let Err(error) =
        bitcoin_rs_chain::regtest_fixture::mine_header_to_declared_target(&mut header)
    {
        panic!("easy regtest target must be reachable: {error}");
    }
    header
}

fn mine_chain(fork: &Header, fork_height: u32, len: usize) -> Vec<Header> {
    let mut prev = fork.compute_hash();
    (0..len)
        .map(|index| {
            let offset = u32::try_from(index).unwrap_or(u32::MAX);
            let header = mine_header(prev, fork_height + offset + 1);
            prev = header.compute_hash();
            header
        })
        .collect()
}

fn total_work(headers: &[Header]) -> ChainWork {
    headers
        .iter()
        .fold(ChainWork::ZERO, |sum, header| sum + block_work(header))
}

fn anchor(fork: &Header) -> HeaderAnchor {
    HeaderAnchor {
        network: Network::Regtest,
        height: 0,
        hash: Hash256::from(fork.compute_hash()),
        header: *fork,
        chain_work: ChainWork::ZERO,
        median_time_past: fork.time,
        locator: vec![Hash256::from(fork.compute_hash())],
    }
}

fn regtest_params() -> HeadersSyncParams {
    Network::Regtest.headers_sync_params()
}

fn plain_header(prev: BlockHash, height: u32) -> Header {
    let mut merkle = [0_u8; 32];
    merkle[..4].copy_from_slice(&height.to_le_bytes());
    Header {
        version: 1,
        prev_blockhash: prev,
        merkle_root: Hash256::from_le_bytes(&merkle),
        time: FIXTURE_TIME.saturating_add(height),
        bits: EASY_BITS,
        nonce: height,
    }
}

#[expect(clippy::expect_used, reason = "fixture setup must fail loudly")]
fn presync_collect(c: &mut Criterion) {
    let genesis = mine_header(BlockHash::default(), 0);
    let chain = mine_chain(&genesis, 0, 10 * PAGE);
    let floor = total_work(&chain) + total_work(&chain);
    let start = anchor(&genesis);
    let params = regtest_params();

    let mut group = c.benchmark_group("headers_presync");
    group.bench_function("presync_collect_20k", |b| {
        b.iter_batched(
            || HeadersSyncState::new(start.clone(), floor, params, [0x5a; 16]),
            |mut state| {
                for page in chain.chunks(PAGE) {
                    let result = state
                        .process(page, page.len() == PAGE)
                        .expect("a valid chain must collect without error");
                    black_box(result.phase);
                }
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

#[expect(clippy::expect_used, reason = "fixture setup must fail loudly")]
fn redownload_replay(c: &mut Criterion) {
    let genesis = mine_header(BlockHash::default(), 0);
    let chain = mine_chain(&genesis, 0, 10 * PAGE);
    let floor = total_work(&chain);
    let start = anchor(&genesis);
    let params = regtest_params();

    let collected = &chain[..];
    let mut group = c.benchmark_group("headers_presync");
    group.bench_function("redownload_replay_20k", |b| {
        b.iter_batched(
            || {
                let mut state = HeadersSyncState::new(start.clone(), floor, params, [0x5a; 16]);
                let mut phase = HeadersSyncPhase::Presync;
                for page in collected.chunks(PAGE) {
                    phase = state
                        .process(page, true)
                        .expect("collection must reach the floor without error")
                        .phase;
                }
                assert_eq!(phase, HeadersSyncPhase::Redownload, "setup must cross");
                state
            },
            |mut state| {
                let mut released = 0_usize;
                for page in chain.chunks(PAGE) {
                    let result = state
                        .process(page, page.len() == PAGE)
                        .expect("the replay of the same chain must verify");
                    released += result.ready_headers.len();
                    if result.phase == HeadersSyncPhase::Final {
                        break;
                    }
                }
                assert!(released > 0, "the verified replay must commit");
                black_box(released);
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

#[expect(clippy::expect_used, reason = "fixture setup must fail loudly")]
fn serve_headers_page(c: &mut Criterion) {
    let genesis = plain_header(BlockHash::default(), 0);
    let genesis_hash = genesis.compute_hash();
    let mut prev = genesis_hash;
    let mut tree = BlockTree::new();
    let mut parent = tree
        .insert_node(None, genesis, NodeStatus::Active)
        .expect("fixture genesis");

    for height in 1..(10 * PAGE) {
        let header = plain_header(prev, u32::try_from(height).unwrap_or(u32::MAX));
        prev = header.compute_hash();
        parent = tree
            .insert_node(Some(parent), header, NodeStatus::Active)
            .expect("fixture header");
    }
    let block_tree = BlockTreeReader::new(Arc::new(RwLock::new(tree)));
    let applied_tip = TipReader::new(Arc::new(arc_swap::ArcSwapOption::empty()));
    applied_tip.store(block_tree.read().tip());
    let query = ActiveChainQuery::new(block_tree, applied_tip, Network::Regtest);
    let locator = [genesis_hash];

    c.bench_function("serve_headers_page", |b| {
        b.iter(|| {
            let served = query.headers_after(&locator, BlockHash::default(), PAGE);
            black_box(served.len())
        });
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = presync_collect, redownload_replay, serve_headers_page
);
criterion_main!(benches);
