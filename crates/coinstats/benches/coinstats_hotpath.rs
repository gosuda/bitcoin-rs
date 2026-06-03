#![allow(missing_docs)]

use std::hint::black_box;

use bitcoin::{Amount, ScriptBuf};
use bitcoin_rs_coinstats::{CoinStats, CoinStatsListener, MuHash3072};
use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut};
use bitcoin_rs_utxo::{UtxoChangeListener, UtxoInserted};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use zerocopy::IntoBytes;

const ENTRY_COUNT: usize = 8_192;

#[derive(Clone)]
struct CoinFixture {
    outpoints: Vec<OutPoint>,
    txouts: Vec<TxOut>,
    encoded: Vec<Vec<u8>>,
}

impl CoinFixture {
    fn new() -> Self {
        let mut outpoints = Vec::with_capacity(ENTRY_COUNT);
        let mut txouts = Vec::with_capacity(ENTRY_COUNT);
        let mut encoded = Vec::with_capacity(ENTRY_COUNT);
        for index in 0..ENTRY_COUNT {
            let outpoint = OutPoint::new(txid(index), u32::try_from(index % 64).unwrap_or(0));
            let txout = txout(index);
            encoded.push(preencoded_coin(&outpoint, &txout, 100, true));
            outpoints.push(outpoint);
            txouts.push(txout);
        }
        Self {
            outpoints,
            txouts,
            encoded,
        }
    }

    fn insertions(&self) -> Vec<UtxoInserted<'_>> {
        self.outpoints
            .iter()
            .zip(&self.txouts)
            .map(|(outpoint, txout)| UtxoInserted::new(outpoint, txout, 100, true))
            .collect()
    }
}

fn coinstats_hotpath(c: &mut Criterion) {
    let fixture = CoinFixture::new();
    let insertions = fixture.insertions();

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
                listener.on_insert_coins(black_box(&insertions));
                black_box(listener.snapshot().muhash.finalize_hash());
            },
            BatchSize::SmallInput,
        );
    });
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

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets = coinstats_hotpath
}
criterion_main!(benches);
