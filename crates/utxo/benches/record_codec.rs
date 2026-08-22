//! Paired benchmark for the v4 and v5 `UtxoRecord` payload codecs.
//!
//! This set carries a third acceptance criterion beyond equivalence and speed:
//! **bytes**. v5 exists because a mainnet attribution run put the UTXO set at
//! 77.4% of process RSS (`docs/benchmarks/utxo-memory.md`), so a codec that is
//! lossless and faster but not smaller has missed. Every group therefore sets
//! Criterion's throughput to the encoded payload size, and the harness prints
//! the size table before measuring.
//!
//! Both arms run over one fixture in one group, so the reported spread is the
//! change and not rebuild drift against a stored baseline.
// PERF: Criterion emits public harness items whose docs are irrelevant here.
#![allow(missing_docs)]
// A fixture that fails to encode has no meaningful degraded mode.
#![allow(clippy::expect_used)]

use std::hint::black_box;

use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_utxo::{OneUtxoOut, RecordCodec};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};

/// Live outputs per record measured on a real chainstate at height 412,732.
/// The txid amortizes over this, so it is the number the payload size is most
/// sensitive to.
const MEASURED_OUTPUTS_PER_RECORD: usize = 4;

fn txid() -> Hash256 {
    Hash256::from_le_bytes(&[0x3c; 32])
}

/// Mainnet script mix by share of the UTXO set: P2WPKH 22 B, P2PKH 25 B,
/// P2SH 23 B, P2TR 34 B.
fn script(index: usize) -> Vec<u8> {
    let len = match index % 4 {
        0 => 22,
        1 => 25,
        2 => 23,
        _ => 34,
    };
    let tag = u8::try_from(index % 251).unwrap_or(0);
    core::iter::repeat_n(tag, len).collect()
}

/// Owned outputs shaped like a real record: small vouts, heights in the
/// 800k range, and amounts that are mostly round numbers of satoshis.
fn outputs(count: usize) -> Vec<(u32, u64, Vec<u8>, bool, u32)> {
    (0..count)
        .map(|index| {
            let value = if index % 3 == 0 {
                // Round: what Core's amount transform exists for.
                u64::try_from(index + 1).unwrap_or(1) * 10_000_000
            } else {
                // Not round: costs one extra bit and no more.
                u64::try_from(index).unwrap_or(0) * 7_919 + 54_321
            };
            (
                u32::try_from(index).unwrap_or(0),
                value,
                script(index),
                index == 0,
                800_000 + u32::try_from(index).unwrap_or(0),
            )
        })
        .collect()
}

fn views(owned: &[(u32, u64, Vec<u8>, bool, u32)]) -> Vec<OneUtxoOut<'_>> {
    owned
        .iter()
        .map(|(vout, value, script, coinbase, height)| OneUtxoOut {
            vout: *vout,
            value: *value,
            script_pubkey: script,
            coinbase: *coinbase,
            height: *height,
        })
        .collect()
}

fn bench_codec(c: &mut Criterion, count: usize) {
    let owned = outputs(count);
    let views = views(&owned);

    let encoded_v4 = RecordCodec::encode_v4(txid(), &views).expect("v4 encodes");
    let encoded_v5 = RecordCodec::encode_v5(txid(), &views).expect("v5 encodes");

    // The size result, printed rather than merely measured: Criterion reports
    // time, and time is not what this change is for.
    let saved = encoded_v4.len().saturating_sub(encoded_v5.len());
    println!(
        "record_codec/outputs_{count}: v4 {} B, v5 {} B, saved {} B ({:.2} B/output, {:.1}%)",
        encoded_v4.len(),
        encoded_v5.len(),
        saved,
        f64::from(u32::try_from(saved).unwrap_or(0)) / f64::from(u32::try_from(count).unwrap_or(1)),
        100.0 * f64::from(u32::try_from(saved).unwrap_or(0))
            / f64::from(u32::try_from(encoded_v4.len()).unwrap_or(1)),
    );

    let mut group = c.benchmark_group(format!("record_codec/encode/outputs_{count}"));
    group.throughput(Throughput::Bytes(
        u64::try_from(encoded_v4.len()).unwrap_or(0),
    ));
    group.bench_function("before_v4", |b| {
        b.iter(|| black_box(RecordCodec::encode_v4(txid(), black_box(&views)).expect("encodes")));
    });
    group.throughput(Throughput::Bytes(
        u64::try_from(encoded_v5.len()).unwrap_or(0),
    ));
    group.bench_function("after_v5", |b| {
        b.iter(|| black_box(RecordCodec::encode_v5(txid(), black_box(&views)).expect("encodes")));
    });
    group.finish();

    let mut group = c.benchmark_group(format!("record_codec/decode_all/outputs_{count}"));
    group.throughput(Throughput::Bytes(
        u64::try_from(encoded_v4.len()).unwrap_or(0),
    ));
    group.bench_function("before_v4", |b| {
        b.iter(|| black_box(RecordCodec::decode_v4(black_box(&encoded_v4)).expect("decodes")));
    });
    group.throughput(Throughput::Bytes(
        u64::try_from(encoded_v5.len()).unwrap_or(0),
    ));
    group.bench_function("after_v5", |b| {
        b.iter(|| black_box(RecordCodec::decode_v5(black_box(&encoded_v5)).expect("decodes")));
    });
    group.finish();

    // The operation that actually dominates: every spent input resolves one
    // output by vout through `Shard::get`/`get_entry`/`get_meta`. Decoding a
    // whole record is the snapshot and rescan path, which is rare by
    // comparison, so a codec judged only on `decode_all` is judged on the wrong
    // thing.
    //
    // `hit_last` is the worst case (the whole record is walked first) and
    // `miss` is the shape a spend takes when the record still holds other live
    // outputs.
    let last = u32::try_from(count.saturating_sub(1)).unwrap_or(0);
    for (label, needle) in [("hit_first", 0), ("hit_last", last), ("miss", u32::MAX)] {
        let mut group =
            c.benchmark_group(format!("record_codec/find_output/{label}/outputs_{count}"));
        group.bench_function("before_v4", |b| {
            b.iter(|| {
                black_box(RecordCodec::find_v4(black_box(&encoded_v4), black_box(needle)).ok())
            });
        });
        group.bench_function("after_v5", |b| {
            b.iter(|| {
                black_box(RecordCodec::find_v5(black_box(&encoded_v5), black_box(needle)).ok())
            });
        });
        group.finish();
    }
}

fn record_codec(c: &mut Criterion) {
    // 1 is the single-output record, MEASURED_OUTPUTS_PER_RECORD the chainstate
    // average, and 256 the batch-payout shape `utxo_commit`'s lookup arms use.
    // The intermediate points exist because the two layouts cross over: v5
    // trades a fixed setup cost for a per-output scan that is far cheaper, so
    // which one wins depends on how many outputs the record holds. Reporting
    // only one size would let either arm look like the answer.
    for count in [1, MEASURED_OUTPUTS_PER_RECORD, 16, 64, 256] {
        bench_codec(c, count);
    }
}

criterion_group!(benches, record_codec);
criterion_main!(benches);
