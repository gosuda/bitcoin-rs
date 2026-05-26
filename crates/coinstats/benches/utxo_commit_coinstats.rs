//! Synthetic UTXO commit benchmark with and without the coinstats listener.
// PERF: Criterion emits public harness items whose docs are irrelevant to the benchmark report.
#![allow(missing_docs)]

use std::hint::black_box;

use bitcoin::{Amount, ScriptBuf, consensus::Encodable};
use bitcoin_rs_coinstats::{CoinStats, CoinStatsListener, MuHash3072};
use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut};
use bitcoin_rs_utxo::{BlockChanges, UtxoAdd, UtxoChangeListener, UtxoKey, UtxoSet};
use criterion::{
    BatchSize, BenchmarkGroup, Criterion, criterion_group, criterion_main, measurement::WallTime,
};
use parking_lot::RwLock;
use zerocopy::IntoBytes;

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
    ShardedCounters,
    ShardedEncodeOnly,
    ShardedMuhashOnly,
    ShardedCoinStats,
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

#[derive(Default)]
struct EncodeOnlyStats {
    total_bytes: u64,
    operations: u64,
}

struct ShardedCountersListener {
    shards: Vec<RwLock<AccountingStats>>,
}

struct ShardedEncodeOnlyListener {
    shards: Vec<RwLock<EncodeOnlyStats>>,
}

struct ShardedMuhashOnlyListener {
    shards: Vec<RwLock<MuHash3072>>,
}

struct ShardedCoinStatsListener {
    shards: Vec<RwLock<CoinStats>>,
}

struct DirectCase {
    stats: CoinStats,
    spends: Vec<UtxoAdd>,
    adds: Vec<UtxoAdd>,
}

struct PreEncodedCase {
    spend_bytes: Vec<Vec<u8>>,
    add_bytes: Vec<Vec<u8>>,
}

impl AccountingListener {
    fn new() -> Self {
        Self {
            stats: RwLock::new(AccountingStats::default()),
        }
    }
}

impl ShardedCountersListener {
    fn new() -> Self {
        let shards = (0..UtxoKey::SHARD_COUNT)
            .map(|_| RwLock::new(AccountingStats::default()))
            .collect();
        Self { shards }
    }

    fn shard(&self, op: &OutPoint) -> &RwLock<AccountingStats> {
        let index = usize::from(UtxoKey::from_txid(&op.txid).shard());
        &self.shards[index]
    }
}

impl ShardedEncodeOnlyListener {
    fn new() -> Self {
        let shards = (0..UtxoKey::SHARD_COUNT)
            .map(|_| RwLock::new(EncodeOnlyStats::default()))
            .collect();
        Self { shards }
    }

    fn shard(&self, op: &OutPoint) -> &RwLock<EncodeOnlyStats> {
        let index = usize::from(UtxoKey::from_txid(&op.txid).shard());
        &self.shards[index]
    }

    fn encode(&self, op: &OutPoint, txout: &TxOut, height: u32, coinbase: bool) {
        let bytes = bench_coin_hash_bytes(op, txout, height, coinbase);
        let byte_count = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        black_box(bytes.as_slice());

        let mut stats = self.shard(op).write();
        stats.total_bytes = stats.total_bytes.saturating_add(byte_count);
        stats.operations = stats.operations.saturating_add(1);
    }
}

impl ShardedMuhashOnlyListener {
    fn new() -> Self {
        let shards = (0..UtxoKey::SHARD_COUNT)
            .map(|_| RwLock::new(MuHash3072::new()))
            .collect();
        Self { shards }
    }

    fn shard(&self, op: &OutPoint) -> &RwLock<MuHash3072> {
        let index = usize::from(UtxoKey::from_txid(&op.txid).shard());
        &self.shards[index]
    }
}

impl ShardedCoinStatsListener {
    fn new() -> Self {
        let shards = (0..UtxoKey::SHARD_COUNT)
            .map(|_| RwLock::new(CoinStats::new()))
            .collect();
        Self { shards }
    }

    fn shard(&self, op: &OutPoint) -> &RwLock<CoinStats> {
        let index = usize::from(UtxoKey::from_txid(&op.txid).shard());
        &self.shards[index]
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

impl UtxoChangeListener for ShardedCountersListener {
    fn on_insert(&self, op: &OutPoint, txout: &TxOut, _height: u32, _coinbase: bool) {
        let mut stats = self.shard(op).write();
        stats.total_amount = stats.total_amount.saturating_add(txout.value.to_sat());
        stats.bogo_size = stats.bogo_size.saturating_add(simple_bogo_size(txout));
        stats.utxo_count = stats.utxo_count.saturating_add(1);
    }

    fn on_remove(&self, op: &OutPoint, txout: &TxOut, _height: u32) {
        let mut stats = self.shard(op).write();
        stats.total_amount = stats.total_amount.saturating_sub(txout.value.to_sat());
        stats.bogo_size = stats.bogo_size.saturating_sub(simple_bogo_size(txout));
        stats.utxo_count = stats.utxo_count.saturating_sub(1);
    }
}

impl UtxoChangeListener for ShardedEncodeOnlyListener {
    fn on_insert(&self, op: &OutPoint, txout: &TxOut, height: u32, coinbase: bool) {
        self.encode(op, txout, height, coinbase);
    }

    fn on_remove(&self, op: &OutPoint, txout: &TxOut, height: u32) {
        self.encode(op, txout, height, false);
    }

    fn on_remove_coin(&self, op: &OutPoint, txout: &TxOut, height: u32, coinbase: bool) {
        self.encode(op, txout, height, coinbase);
    }
}

impl UtxoChangeListener for ShardedMuhashOnlyListener {
    fn on_insert(&self, op: &OutPoint, _txout: &TxOut, _height: u32, _coinbase: bool) {
        self.shard(op).write().insert(op.as_bytes());
    }

    fn on_remove(&self, op: &OutPoint, _txout: &TxOut, _height: u32) {
        self.shard(op).write().remove(op.as_bytes());
    }

    fn on_remove_coin(&self, op: &OutPoint, _txout: &TxOut, _height: u32, _coinbase: bool) {
        // This isolates MuHash arithmetic in the commit callback shape; it is not
        // measuring CoinStats' exact coin encoding semantics.
        self.shard(op).write().remove(op.as_bytes());
    }
}

impl UtxoChangeListener for ShardedCoinStatsListener {
    fn on_insert(&self, op: &OutPoint, txout: &TxOut, height: u32, coinbase: bool) {
        self.shard(op)
            .write()
            .insert_utxo(op, txout, height, coinbase);
    }

    fn on_remove(&self, op: &OutPoint, txout: &TxOut, height: u32) {
        self.shard(op).write().remove_utxo(op, txout, height, false);
    }

    fn on_remove_coin(&self, op: &OutPoint, txout: &TxOut, height: u32, coinbase: bool) {
        self.shard(op)
            .write()
            .remove_utxo(op, txout, height, coinbase);
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

fn bench_coin_hash_bytes(op: &OutPoint, txout: &TxOut, height: u32, coinbase: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(36 + 4 + txout.script_pubkey.len() + 16);
    out.extend_from_slice(op.as_bytes());
    let coinbase_bit = u32::from(coinbase);
    out.extend_from_slice(&((height << 1) | coinbase_bit).to_le_bytes());
    if txout.consensus_encode(&mut out).is_err() {
        unreachable!("vec-backed consensus encoder is infallible");
    }
    out
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
        ListenerKind::ShardedCounters => {
            set.set_listener(Box::new(ShardedCountersListener::new()));
        }
        ListenerKind::ShardedEncodeOnly => {
            set.set_listener(Box::new(ShardedEncodeOnlyListener::new()));
        }
        ListenerKind::ShardedMuhashOnly => {
            set.set_listener(Box::new(ShardedMuhashOnlyListener::new()));
        }
        ListenerKind::ShardedCoinStats => {
            set.set_listener(Box::new(ShardedCoinStatsListener::new()));
        }
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

fn synthetic_direct_case(seed: u64) -> DirectCase {
    let mut stats = CoinStats::new();
    let mut spends = Vec::with_capacity(usize::try_from(OP_COUNT).unwrap_or(usize::MAX));
    let mut adds = Vec::with_capacity(usize::try_from(OP_COUNT).unwrap_or(usize::MAX));
    let mut rng = seed;

    for _ in 0_u64..OP_COUNT {
        let spend_seed = next_u64(&mut rng);
        let outpoint = OutPoint::new(txid(spend_seed), 0);
        let spend = UtxoAdd::new(outpoint, txout(spend_seed), false, PRELOAD_HEIGHT);
        stats.insert_utxo(&spend.outpoint, &spend.txout, spend.height, spend.coinbase);
        spends.push(spend);
    }

    for i in 0_u64..OP_COUNT {
        let add_seed = next_u64(&mut rng).wrapping_add(i);
        let outpoint = OutPoint::new(txid(add_seed), 0);
        adds.push(UtxoAdd::new(outpoint, txout(add_seed), false, ADD_HEIGHT));
    }

    DirectCase {
        stats,
        spends,
        adds,
    }
}

fn synthetic_preencoded_case(seed: u64) -> PreEncodedCase {
    let direct = synthetic_direct_case(seed);
    let spend_bytes = direct
        .spends
        .iter()
        .map(|spend| {
            bench_coin_hash_bytes(&spend.outpoint, &spend.txout, spend.height, spend.coinbase)
        })
        .collect();
    let add_bytes = direct
        .adds
        .iter()
        .map(|add| bench_coin_hash_bytes(&add.outpoint, &add.txout, add.height, add.coinbase))
        .collect();

    PreEncodedCase {
        spend_bytes,
        add_bytes,
    }
}

fn bench_commit_case(
    group: &mut BenchmarkGroup<'_, WallTime>,
    name: &'static str,
    listener_kind: ListenerKind,
    block_hash: &Hash256,
) {
    group.bench_function(name, |b| {
        b.iter_batched(
            || synthetic_case(CASE_SEED, listener_kind),
            |(set, changes)| {
                if let Err(error) = set.commit_block(black_box(&changes), black_box(block_hash)) {
                    panic!("synthetic commit failed: {error}");
                }
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_direct_coinstats(group: &mut BenchmarkGroup<'_, WallTime>) {
    group.bench_function("direct_coinstats_insert_remove", |b| {
        b.iter_batched(
            || synthetic_direct_case(CASE_SEED),
            |case| {
                let DirectCase {
                    mut stats,
                    spends,
                    adds,
                } = case;
                for spend in &spends {
                    stats.remove_utxo(&spend.outpoint, &spend.txout, spend.height, spend.coinbase);
                }
                for add in &adds {
                    stats.insert_utxo(&add.outpoint, &add.txout, add.height, add.coinbase);
                }
                black_box(stats);
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_direct_encode_only(group: &mut BenchmarkGroup<'_, WallTime>) {
    group.bench_function("direct_coinstats_encode_only", |b| {
        b.iter_batched(
            || synthetic_direct_case(CASE_SEED),
            |case| {
                let DirectCase { spends, adds, .. } = case;
                let mut encoded = Vec::with_capacity(spends.len().saturating_add(adds.len()));
                for spend in &spends {
                    encoded.push(bench_coin_hash_bytes(
                        &spend.outpoint,
                        &spend.txout,
                        spend.height,
                        spend.coinbase,
                    ));
                }
                for add in &adds {
                    encoded.push(bench_coin_hash_bytes(
                        &add.outpoint,
                        &add.txout,
                        add.height,
                        add.coinbase,
                    ));
                }
                black_box(encoded);
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_direct_muhash_preencoded(group: &mut BenchmarkGroup<'_, WallTime>) {
    group.bench_function("direct_coinstats_muhash_preencoded", |b| {
        b.iter_batched(
            || synthetic_preencoded_case(CASE_SEED),
            |case| {
                let mut muhash = MuHash3072::new();
                for bytes in &case.spend_bytes {
                    muhash.remove(bytes);
                }
                for bytes in &case.add_bytes {
                    muhash.insert(bytes);
                }
                black_box(muhash);
            },
            BatchSize::SmallInput,
        );
    });
}

fn utxo_commit_coinstats(c: &mut Criterion) {
    let mut group = c.benchmark_group("utxo_commit_coinstats");
    let block_hash = txid(COMMIT_BLOCK_SEED);

    bench_commit_case(&mut group, "no_listener", ListenerKind::None, &block_hash);
    bench_commit_case(&mut group, "noop_listener", ListenerKind::Noop, &block_hash);
    bench_commit_case(
        &mut group,
        "accounting_listener",
        ListenerKind::Accounting,
        &block_hash,
    );
    bench_commit_case(
        &mut group,
        "sharded_counter_listener",
        ListenerKind::ShardedCounters,
        &block_hash,
    );
    bench_commit_case(
        &mut group,
        "sharded_encode_only_listener",
        ListenerKind::ShardedEncodeOnly,
        &block_hash,
    );
    bench_commit_case(
        &mut group,
        "sharded_muhash_only_listener",
        ListenerKind::ShardedMuhashOnly,
        &block_hash,
    );
    bench_commit_case(
        &mut group,
        "sharded_coinstats_listener",
        ListenerKind::ShardedCoinStats,
        &block_hash,
    );
    bench_commit_case(
        &mut group,
        "coinstats_listener",
        ListenerKind::CoinStats,
        &block_hash,
    );
    bench_direct_coinstats(&mut group);
    bench_direct_encode_only(&mut group);
    bench_direct_muhash_preencoded(&mut group);

    group.finish();
}

criterion_group!(benches, utxo_commit_coinstats);
criterion_main!(benches);
