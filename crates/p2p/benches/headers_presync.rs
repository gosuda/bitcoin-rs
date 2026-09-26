//! Criterion benches for the header download-twice state machine and the
//! `getheaders` serving window.
//!
//! `presync_collect` and `redownload_replay` measure the two-pass machinery
//! this change adds; the base tree has no equivalent path, so those two
//! report absolute medians only. `serve_headers_page` measures the serving
//! window that both trees answer: its head-versus-base medians are the
//! no-regression evidence for the per-request gate on the changed hot path.

use std::hint::black_box;
use std::sync::Arc;

use bitcoin_rs_chain::{BlockTree, ChainWork, NodeStatus, block_work, compact_is_met_by};
use bitcoin_rs_p2p::sync::{HeaderAnchor, HeadersSyncPhase, HeadersSyncState};
use bitcoin_rs_p2p::{ActiveChainQuery, ChainQuery};
use bitcoin_rs_primitives::{
    BlockHash, CompactTarget, Hash256, Header, HeadersSyncParams, Network,
};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use parking_lot::RwLock;

/// The wire page size a full `headers` message carries
/// (`net_processing.h:48-57`).
const PAGE: usize = 2_000;

/// Regtest's minimum-difficulty compact target: the cheapest proof of work
/// the consensus rules allow, so fixture mining costs about one hash.
const EASY_BITS: CompactTarget = CompactTarget::from_consensus(0x207f_ffff);

/// A fixed base timestamp, so no bench ever reads the wall clock.
const FIXTURE_TIME: u32 = 1_700_000_000;

/// Mines one regtest-easy fixture header on `prev` at height `height`.
/// Version 4: regtest raises the minimum block version at heights 500,
/// 1251, and 1351, and these fixture chains are longer than all of them.
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
    while !compact_is_met_by(EASY_BITS, Hash256::from(header.compute_hash())) {
        header.nonce = header.nonce.wrapping_add(1);
    }
    header
}

/// Mines a regtest-easy chain of `len` headers on `fork`, starting at
/// height `fork_height + 1`.
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

/// The total proof of work a fixture chain carries.
fn total_work(headers: &[Header]) -> ChainWork {
    headers
        .iter()
        .fold(ChainWork::ZERO, |sum, header| sum + block_work(header))
}

/// The fork point a fixture sync anchors on.
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

/// Regtest's own commitment period and redownload buffer, so the benches
/// measure the configuration the network actually runs.
fn regtest_params() -> HeadersSyncParams {
    Network::Regtest.headers_sync_params()
}

/// One plain fixture header for the serving bench: the serving path reads
/// the tree and never validates proof of work, so the fixture skips mining.
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

/// Feeds a whole below-floor chain through the collection pass: continuity,
/// proof of work, permitted-difficulty, and cumulative-work checks, plus one
/// salted commitment bit every `commitment_period` heights.
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
                    black_box((&state, result.phase));
                }
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

/// Collects one chain to the floor, then replays it: commitment verification
/// at the salted offsets, compressed buffering, and the release of the
/// committed prefix. The second pass ends - as it does on the wire - the
/// moment the replayed work crosses the floor and the buffer drains.
#[expect(clippy::expect_used, reason = "fixture setup must fail loudly")]
fn redownload_replay(c: &mut Criterion) {
    let genesis = mine_header(BlockHash::default(), 0);
    let chain = mine_chain(&genesis, 0, 10 * PAGE);
    let floor = total_work(&chain[..5 * PAGE]);
    let start = anchor(&genesis);
    let params = regtest_params();

    // The setup pass leaves the state at the crossing, waiting for the
    // replay; criterion times only the replay itself. The crossing lands
    // exactly at the end of the fifth page, and REDOWNLOAD restarts at the
    // anchor, so the timed loop replays the whole chain.
    let collected = &chain[..5 * PAGE];
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

/// Serves one full `getheaders` page from an active 20,000-header regtest
/// chain. Serving reads the tree only — no proof-of-work check runs on the
/// way out — so the fixture uses plain headers, exactly like the base arm:
/// the same file minus the constructor's `Network` argument, compiled in a
/// throwaway base checkout. Head and base then answer byte-identical
/// requests, and the only difference measured is this change's per-request
/// tip-chainwork floor test.
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
    let query = ActiveChainQuery::new(Arc::new(RwLock::new(tree)), Network::Regtest);
    let locator = [genesis_hash];

    c.bench_function("serve_headers_page", |b| {
        b.iter(|| {
            let served = query.headers_after(&locator, BlockHash::default(), PAGE);
            black_box(served)
        });
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = presync_collect, redownload_replay, serve_headers_page
);
criterion_main!(benches);
