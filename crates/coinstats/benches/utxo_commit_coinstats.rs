//! Synthetic UTXO commit benchmark with and without the coinstats listener.
// PERF: Criterion emits public harness items whose docs are irrelevant to the benchmark report.
#![allow(missing_docs)]

use std::hint::black_box;

use bitcoin::{Amount, ScriptBuf};
use bitcoin_rs_coinstats::{CoinStats, CoinStatsListener};
use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut};
use bitcoin_rs_utxo::{BlockChanges, UtxoAdd, UtxoChangeListener, UtxoSet};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use parking_lot::RwLock;

const PRELOAD_HEIGHT: u32 = 1;
const ADD_HEIGHT: u32 = 2;
const OP_COUNT: u64 = 10_000;
const CASE_SEED: u64 = 0x00ab_cdef;
const COMMIT_BLOCK_SEED: u64 = 0x0012_3456;

#[derive(Clone, Copy)]
enum ListenerKind {
    None,
    Noop,
    Accounting,
    CoinStats,
}

struct NoopListener;

impl UtxoChangeListener for NoopListener {
    fn on_insert(&self, _op: &OutPoint, _txout: &TxOut, _height: u32, _coinbase: bool) {}

    fn on_remove(&self, _op: &OutPoint, _txout: &TxOut, _height: u32) {}
}

#[derive(Default)]
struct AccountingStats {
    total_amount: u64,
    bogo_size: u64,
    utxo_count: u64,
}

struct AccountingListener {
    stats: RwLock<AccountingStats>,
}

impl AccountingListener {
    fn new() -> Self {
        Self {
            stats: RwLock::new(AccountingStats::default()),
        }
    }
}

impl UtxoChangeListener for AccountingListener {
    fn on_insert(&self, _op: &OutPoint, txout: &TxOut, _height: u32, _coinbase: bool) {
        let mut stats = self.stats.write();
        stats.total_amount = stats.total_amount.saturating_add(txout.value.to_sat());
        stats.bogo_size = stats.bogo_size.saturating_add(simple_bogo_size(txout));
        stats.utxo_count = stats.utxo_count.saturating_add(1);
    }

    fn on_remove(&self, _op: &OutPoint, txout: &TxOut, _height: u32) {
        let mut stats = self.stats.write();
        stats.total_amount = stats.total_amount.saturating_sub(txout.value.to_sat());
        stats.bogo_size = stats.bogo_size.saturating_sub(simple_bogo_size(txout));
        stats.utxo_count = stats.utxo_count.saturating_sub(1);
    }
}

fn simple_bogo_size(txout: &TxOut) -> u64 {
    let script_len = u64::try_from(txout.script_pubkey.len()).unwrap_or(u64::MAX);
    36_u64
        .saturating_add(4)
        .saturating_add(8)
        .saturating_add(2)
        .saturating_add(script_len)
}

const fn next_u64(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

fn txid(seed: u64) -> Hash256 {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    bytes[8..16].copy_from_slice(&seed.rotate_left(11).to_le_bytes());
    bytes[16..24].copy_from_slice(&seed.wrapping_mul(0x9e37_79b9_7f4a_7c15).to_le_bytes());
    bytes[24..32].copy_from_slice(&seed.wrapping_add(0xd1b5_4a32_d192_ed03).to_le_bytes());
    Hash256::from_le_bytes(&bytes)
}

fn txout(seed: u64) -> TxOut {
    let mut script = Vec::with_capacity(34);
    script.extend_from_slice(&[0x00, 0x20]);
    script.extend_from_slice(&txid(seed).to_le_bytes());
    TxOut {
        value: Amount::from_sat(5_000 + seed),
        script_pubkey: ScriptBuf::from_bytes(script),
    }
}

fn synthetic_case(seed: u64, listener_kind: ListenerKind) -> (UtxoSet, BlockChanges) {
    let mut set = UtxoSet::new();
    match listener_kind {
        ListenerKind::None => {}
        ListenerKind::Noop => set.set_listener(Box::new(NoopListener)),
        ListenerKind::Accounting => set.set_listener(Box::new(AccountingListener::new())),
        ListenerKind::CoinStats => {
            set.set_listener(Box::new(CoinStatsListener::new(CoinStats::new())));
        }
    }

    let mut preload = BlockChanges::default();
    let mut changes = BlockChanges::default();
    let mut rng = seed;

    for _ in 0_u64..OP_COUNT {
        let spend_seed = next_u64(&mut rng);
        let outpoint = OutPoint::new(txid(spend_seed), 0);
        preload.add(UtxoAdd::new(
            outpoint,
            txout(spend_seed),
            false,
            PRELOAD_HEIGHT,
        ));
        changes.remove(outpoint);
    }

    if let Err(error) = set.commit_block(&preload, &txid(seed)) {
        panic!("synthetic preload failed: {error}");
    }

    for i in 0_u64..OP_COUNT {
        let add_seed = next_u64(&mut rng).wrapping_add(i);
        let outpoint = OutPoint::new(txid(add_seed), 0);
        changes.add(UtxoAdd::new(outpoint, txout(add_seed), false, ADD_HEIGHT));
    }

    (set, changes)
}

fn utxo_commit_coinstats(c: &mut Criterion) {
    let mut group = c.benchmark_group("utxo_commit_coinstats");
    let block_hash = txid(COMMIT_BLOCK_SEED);

    group.bench_function("no_listener", |b| {
        b.iter_batched(
            || synthetic_case(CASE_SEED, ListenerKind::None),
            |(set, changes)| {
                if let Err(error) = set.commit_block(black_box(&changes), black_box(&block_hash)) {
                    panic!("synthetic commit failed: {error}");
                }
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("noop_listener", |b| {
        b.iter_batched(
            || synthetic_case(CASE_SEED, ListenerKind::Noop),
            |(set, changes)| {
                if let Err(error) = set.commit_block(black_box(&changes), black_box(&block_hash)) {
                    panic!("synthetic commit failed: {error}");
                }
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("accounting_listener", |b| {
        b.iter_batched(
            || synthetic_case(CASE_SEED, ListenerKind::Accounting),
            |(set, changes)| {
                if let Err(error) = set.commit_block(black_box(&changes), black_box(&block_hash)) {
                    panic!("synthetic commit failed: {error}");
                }
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("coinstats_listener", |b| {
        b.iter_batched(
            || synthetic_case(CASE_SEED, ListenerKind::CoinStats),
            |(set, changes)| {
                if let Err(error) = set.commit_block(black_box(&changes), black_box(&block_hash)) {
                    panic!("synthetic commit failed: {error}");
                }
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(benches, utxo_commit_coinstats);
criterion_main!(benches);
