#![allow(missing_docs)]

use std::hint::black_box;

use bitcoin::{Amount, ScriptBuf};
use bitcoin_rs_coinstats::{CoinStats, CoinStatsListener, MuHash3072};
use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut};
use bitcoin_rs_utxo::{
    BlockChanges, UtxoAdd, UtxoChangeListener, UtxoInserted, UtxoRemoved, UtxoSet,
};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use zerocopy::IntoBytes;

const ENTRY_COUNT: usize = 8_192;
const SMALL_EVENT_ENTRY_COUNT: usize = 512;

#[derive(Clone)]
struct CoinFixture {
    outpoints: Vec<OutPoint>,
    same_txid_outpoints: Vec<OutPoint>,
    txouts: Vec<TxOut>,
    encoded: Vec<Vec<u8>>,
}

impl CoinFixture {
    fn new() -> Self {
        let mut outpoints = Vec::with_capacity(ENTRY_COUNT);
        let mut same_txid_outpoints = Vec::with_capacity(ENTRY_COUNT);
        let mut txouts = Vec::with_capacity(ENTRY_COUNT);
        let mut encoded = Vec::with_capacity(ENTRY_COUNT);
        let shared_txid = txid(ENTRY_COUNT);
        for index in 0..ENTRY_COUNT {
            let outpoint = OutPoint::new(txid(index), u32::try_from(index % 64).unwrap_or(0));
            let same_txid_outpoint = OutPoint::new(shared_txid, u32::try_from(index).unwrap_or(0));
            let txout = txout(index);
            encoded.push(preencoded_coin(&outpoint, &txout, 100, true));
            outpoints.push(outpoint);
            same_txid_outpoints.push(same_txid_outpoint);
            txouts.push(txout);
        }
        Self {
            outpoints,
            same_txid_outpoints,
            txouts,
            encoded,
        }
    }

    fn insertions(&self) -> Vec<UtxoInserted<'_>> {
        insertions_for(&self.outpoints, &self.txouts)
    }

    fn same_txid_insertions(&self) -> Vec<UtxoInserted<'_>> {
        insertions_for(&self.same_txid_outpoints, &self.txouts)
    }

    fn removals(&self) -> Vec<UtxoRemoved> {
        removals_for(&self.outpoints, &self.txouts)
    }

    fn same_txid_removals(&self) -> Vec<UtxoRemoved> {
        removals_for(&self.same_txid_outpoints, &self.txouts)
    }

    fn inserted_stats(&self) -> CoinStats {
        inserted_stats_for(&self.outpoints, &self.txouts)
    }

    fn same_txid_inserted_stats(&self) -> CoinStats {
        inserted_stats_for(&self.same_txid_outpoints, &self.txouts)
    }
}

fn insertions_for<'a>(outpoints: &'a [OutPoint], txouts: &'a [TxOut]) -> Vec<UtxoInserted<'a>> {
    outpoints
        .iter()
        .zip(txouts)
        .map(|(outpoint, txout)| UtxoInserted::new(outpoint, txout, 100, true))
        .collect()
}

fn removals_for(outpoints: &[OutPoint], txouts: &[TxOut]) -> Vec<UtxoRemoved> {
    outpoints
        .iter()
        .zip(txouts)
        .map(|(outpoint, txout)| UtxoRemoved::new(*outpoint, txout.clone(), 100, true))
        .collect()
}

fn inserted_stats_for(outpoints: &[OutPoint], txouts: &[TxOut]) -> CoinStats {
    let mut stats = CoinStats::new();
    for (outpoint, txout) in outpoints.iter().zip(txouts) {
        stats.insert_utxo(outpoint, txout, 100, true);
    }
    stats
}

fn coinstats_hotpath(c: &mut Criterion) {
    let fixture = CoinFixture::new();
    let insertions = fixture.insertions();
    let same_txid_insertions = fixture.same_txid_insertions();
    let removals = fixture.removals();
    let same_txid_removals = fixture.same_txid_removals();
    let inserted_stats = fixture.inserted_stats();
    let same_txid_inserted_stats = fixture.same_txid_inserted_stats();

    bench_insert_paths(c, &fixture, &insertions, &same_txid_insertions);
    bench_remove_paths(
        c,
        &fixture,
        &removals,
        &same_txid_removals,
        &inserted_stats,
        &same_txid_inserted_stats,
    );
    bench_commit_fanout(c, &fixture, &inserted_stats);
}

fn bench_insert_paths(
    c: &mut Criterion,
    fixture: &CoinFixture,
    insertions: &[UtxoInserted<'_>],
    same_txid_insertions: &[UtxoInserted<'_>],
) {
    c.bench_function("coinstats/muhash_insert_preencoded_8192", |b| {
        b.iter(|| {
            let mut muhash = MuHash3072::new();
            for bytes in &fixture.encoded {
                muhash.insert(black_box(bytes));
            }
            black_box(muhash.finalize_hash());
        });
    });

    c.bench_function("coinstats/insert_utxo_8192", |b| {
        b.iter(|| {
            let mut stats = CoinStats::new();
            for (outpoint, txout) in fixture.outpoints.iter().zip(&fixture.txouts) {
                stats.insert_utxo(black_box(outpoint), black_box(txout), 100, true);
            }
            black_box(stats.muhash.finalize_hash());
        });
    });

    c.bench_function("coinstats/listener_insert_coins_8192", |b| {
        b.iter_batched(
            || CoinStatsListener::new(CoinStats::new()),
            |listener| {
                listener.on_insert_coins(black_box(insertions));
                black_box(listener.snapshot().muhash.finalize_hash());
            },
            BatchSize::SmallInput,
        );
    });

    c.bench_function("coinstats/listener_insert_same_txid_coins_8192", |b| {
        b.iter_batched(
            || CoinStatsListener::new(CoinStats::new()),
            |listener| {
                listener.on_insert_coins(black_box(same_txid_insertions));
                black_box(listener.snapshot().muhash.finalize_hash());
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_remove_paths(
    c: &mut Criterion,
    fixture: &CoinFixture,
    removals: &[UtxoRemoved],
    same_txid_removals: &[UtxoRemoved],
    inserted_stats: &CoinStats,
    same_txid_inserted_stats: &CoinStats,
) {
    c.bench_function("coinstats/muhash_remove_preencoded_8192", |b| {
        b.iter_batched(
            || {
                let mut muhash = MuHash3072::new();
                for bytes in &fixture.encoded {
                    muhash.insert(bytes);
                }
                muhash
            },
            |mut muhash| {
                for bytes in &fixture.encoded {
                    muhash.remove(black_box(bytes));
                }
                black_box(muhash.finalize_hash());
            },
            BatchSize::SmallInput,
        );
    });

    c.bench_function("coinstats/remove_utxo_8192", |b| {
        b.iter_batched(
            || inserted_stats.clone(),
            |mut stats| {
                for (outpoint, txout) in fixture.outpoints.iter().zip(&fixture.txouts) {
                    stats.remove_utxo(black_box(outpoint), black_box(txout), 100, true);
                }
                black_box(stats.muhash.finalize_hash());
            },
            BatchSize::SmallInput,
        );
    });

    c.bench_function("coinstats/listener_remove_coins_8192", |b| {
        b.iter_batched(
            || CoinStatsListener::new(inserted_stats.clone()),
            |listener| {
                listener.on_remove_coins(black_box(removals));
                black_box(listener.snapshot().muhash.finalize_hash());
            },
            BatchSize::SmallInput,
        );
    });

    c.bench_function("coinstats/listener_remove_same_txid_coins_8192", |b| {
        b.iter_batched(
            || CoinStatsListener::new(same_txid_inserted_stats.clone()),
            |listener| {
                listener.on_remove_coins(black_box(same_txid_removals));
                black_box(listener.snapshot().muhash.finalize_hash());
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_commit_fanout(c: &mut Criterion, fixture: &CoinFixture, inserted_stats: &CoinStats) {
    c.bench_function("coinstats/utxo_commit_listener_fanout_8192", |b| {
        b.iter_batched(
            || coinstats_listener_commit_case(fixture, inserted_stats),
            |(set, changes)| {
                set.commit_block(black_box(&changes), &txid(0xfeed_cafe))
                    .unwrap_or_else(|error| panic!("coinstats listener commit failed: {error}"));
            },
            BatchSize::SmallInput,
        );
    });

    c.bench_function("coinstats/utxo_commit_listener_two_shard_8192", |b| {
        b.iter_batched(
            coinstats_listener_two_shard_commit_case,
            |(set, changes)| {
                set.commit_block(black_box(&changes), &txid(0xfeed_cafe))
                    .unwrap_or_else(|error| panic!("coinstats two-shard commit failed: {error}"));
            },
            BatchSize::SmallInput,
        );
    });
    c.bench_function("coinstats/utxo_commit_listener_two_shard_512", |b| {
        b.iter_batched(
            || coinstats_listener_two_shard_commit_case_with_count(SMALL_EVENT_ENTRY_COUNT),
            |(set, changes)| {
                set.commit_block(black_box(&changes), &txid(0xfeed_cafe))
                    .unwrap_or_else(|error| {
                        panic!("coinstats small two-shard commit failed: {error}")
                    });
            },
            BatchSize::SmallInput,
        );
    });

    c.bench_function("coinstats/utxo_commit_two_shard_8192", |b| {
        b.iter_batched(
            coinstats_two_shard_commit_case,
            |(set, changes)| {
                set.commit_block(black_box(&changes), &txid(0xfeed_cafe))
                    .unwrap_or_else(|error| panic!("coinstats two-shard commit failed: {error}"));
            },
            BatchSize::SmallInput,
        );
    });
}

fn coinstats_listener_commit_case(
    fixture: &CoinFixture,
    stats: &CoinStats,
) -> (UtxoSet, BlockChanges) {
    let mut set = UtxoSet::new();
    let mut preload = BlockChanges::with_capacity(ENTRY_COUNT, 0);
    for (outpoint, txout) in fixture.outpoints.iter().zip(&fixture.txouts) {
        preload.add(UtxoAdd::new(*outpoint, txout.clone(), true, 100));
    }
    set.commit_block(&preload, &txid(0xabcd_1234))
        .unwrap_or_else(|error| panic!("coinstats listener preload failed: {error}"));
    set.set_listener(Box::new(CoinStatsListener::new(stats.clone())));

    let mut changes = BlockChanges::with_capacity(ENTRY_COUNT, ENTRY_COUNT);
    for outpoint in &fixture.outpoints {
        changes.remove(*outpoint);
    }
    for index in 0..ENTRY_COUNT {
        let add_index = index.saturating_add(ENTRY_COUNT);
        changes.add(UtxoAdd::new(
            OutPoint::new(txid(add_index), u32::try_from(add_index % 64).unwrap_or(0)),
            txout(add_index),
            false,
            101,
        ));
    }

    (set, changes)
}

fn coinstats_listener_two_shard_commit_case() -> (UtxoSet, BlockChanges) {
    coinstats_two_shard_commit_case_with_listener(ENTRY_COUNT, true)
}

fn coinstats_two_shard_commit_case() -> (UtxoSet, BlockChanges) {
    coinstats_two_shard_commit_case_with_listener(ENTRY_COUNT, false)
}

fn coinstats_listener_two_shard_commit_case_with_count(count: usize) -> (UtxoSet, BlockChanges) {
    coinstats_two_shard_commit_case_with_listener(count, true)
}

fn coinstats_two_shard_commit_case_with_listener(
    count: usize,
    with_listener: bool,
) -> (UtxoSet, BlockChanges) {
    let mut set = UtxoSet::new();
    let mut preload = BlockChanges::with_capacity(count, 0);
    let mut stats = CoinStats::new();
    for index in 0..count {
        let outpoint = OutPoint::new(two_shard_txid(index), 0);
        let txout = txout(index);
        stats.insert_utxo(&outpoint, &txout, 100, true);
        preload.add(UtxoAdd::new(outpoint, txout, true, 100));
    }
    set.commit_block(&preload, &txid(0xabcd_1234))
        .unwrap_or_else(|error| panic!("coinstats two-shard preload failed: {error}"));
    if with_listener {
        set.set_listener(Box::new(CoinStatsListener::new(stats)));
    }

    let mut changes = BlockChanges::with_capacity(count, count);
    for index in 0..count {
        changes.remove(OutPoint::new(two_shard_txid(index), 0));
    }
    for index in 0..count {
        let add_index = index.saturating_add(count);
        changes.add(UtxoAdd::new(
            OutPoint::new(two_shard_txid(add_index), 0),
            txout(add_index),
            false,
            101,
        ));
    }

    (set, changes)
}

fn preencoded_coin(op: &OutPoint, txout: &TxOut, height: u32, coinbase: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(36 + 4 + 8 + 9 + txout.script_pubkey.len());
    out.extend_from_slice(op.as_bytes());
    let coinbase_bit = u32::from(coinbase);
    out.extend_from_slice(&((height << 1) | coinbase_bit).to_le_bytes());
    out.extend_from_slice(&txout.value.to_sat().to_le_bytes());
    encode_compact_size_into(&mut out, txout.script_pubkey.len());
    out.extend_from_slice(txout.script_pubkey.as_bytes());
    out
}

fn encode_compact_size_into(out: &mut Vec<u8>, len: usize) {
    if let Ok(byte_len) = u8::try_from(len)
        && byte_len < 0xfd
    {
        out.push(byte_len);
        return;
    }
    if let Ok(word_len) = u16::try_from(len) {
        out.push(0xfd);
        out.extend_from_slice(&word_len.to_le_bytes());
        return;
    }
    if let Ok(dword_len) = u32::try_from(len) {
        out.push(0xfe);
        out.extend_from_slice(&dword_len.to_le_bytes());
        return;
    }
    let qword_len = u64::try_from(len).unwrap_or(u64::MAX);
    out.push(0xff);
    out.extend_from_slice(&qword_len.to_le_bytes());
}

fn txout(index: usize) -> TxOut {
    let mut script = Vec::with_capacity(34);
    script.extend_from_slice(&[0x00, 0x20]);
    script.extend_from_slice(&txid(index).to_le_bytes());
    TxOut {
        value: Amount::from_sat(50_000 + u64::try_from(index).unwrap_or(u64::MAX)),
        script_pubkey: ScriptBuf::from_bytes(script),
    }
}

fn txid(index: usize) -> Hash256 {
    let seed = u64::try_from(index).unwrap_or(u64::MAX);
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    bytes[8..16].copy_from_slice(&seed.rotate_left(11).to_le_bytes());
    bytes[16..24].copy_from_slice(&seed.wrapping_mul(0x9e37_79b9_7f4a_7c15).to_le_bytes());
    bytes[24..32].copy_from_slice(&seed.wrapping_add(0xd1b5_4a32_d192_ed03).to_le_bytes());
    Hash256::from_le_bytes(&bytes)
}

fn two_shard_txid(index: usize) -> Hash256 {
    let mut bytes = txid(index).to_le_bytes();
    bytes[0] = u8::try_from(index % 2).unwrap_or(0);
    Hash256::from_le_bytes(&bytes)
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets = coinstats_hotpath
}
criterion_main!(benches);
