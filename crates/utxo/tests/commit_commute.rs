//! Phase-0b consensus guard: UTXO commit must be invariant under batching.
//!
//! `commit_adds_and_removes` (crates/utxo/src/set.rs) splits on combined op count: a
//! small commit runs serially per shard; a large one fans the *same* per-shard
//! `commit_batch` across a `rayon::scope`. Both paths MUST converge to byte-identical
//! UTXO state — every Phase-1 optimization touching commit parallelism rests on this,
//! so it is pinned here against the un-optimized tree (red->green before such a change).
//!
//! Rather than mirror the private split threshold (which would drift), the test asserts
//! the stronger underlying property: committing the same net changes under *several*
//! chunkings yields identical state. Small chunks exercise the serial path; the
//! whole-set chunk (`ENTRY_COUNT`, well above the default 2048 split) exercises the
//! parallel path. Each result is also checked against an independent `HashMap` oracle,
//! so the paths cannot be *equally* wrong.

use bitcoin::{Amount, ScriptBuf};
use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut};
use bitcoin_rs_utxo::{BlockChanges, UtxoAdd, UtxoError, UtxoSet, hash_serialized_3};
use hashbrown::HashMap;

/// Workload size. Kept well above the default serial/parallel split (2048 ops) so the
/// whole-set commit (`usize::MAX` chunk) reaches the parallel path.
const ENTRY_COUNT: usize = 6_000;

/// Chunkings to commit the identical net change set under. Spans both sides of any
/// plausible split threshold; the result must be identical across all of them.
const BATCHES: [usize; 5] = [16, 256, 2048, 4096, usize::MAX];

#[derive(Copy, Clone)]
enum ShardShape {
    /// Spread across all 256 shards (seed's low byte distributes naturally).
    Uniform,
    /// Only shards 0 and 1 active.
    TwoShard,
    /// Every entry funnelled into one shard (stresses the single-shard fast path and
    /// the one-chunk parallel case).
    Concentrated,
}

#[derive(Clone)]
struct Entry {
    op: OutPoint,
    txout: TxOut,
    coinbase: bool,
    height: u32,
}

const fn next_u64(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

fn shaped_txid(seed: u64, index: usize, shape: ShardShape) -> Hash256 {
    // `seed` advances every entry, so the full txid is unique regardless of the shard
    // byte; `index` only selects which shard the entry lands in.
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    bytes[8..16].copy_from_slice(&seed.rotate_left(17).to_le_bytes());
    bytes[16..24].copy_from_slice(&seed.wrapping_mul(0x9e37_79b9_7f4a_7c15).to_le_bytes());
    bytes[24..32].copy_from_slice(&seed.wrapping_add(0xd1b5_4a32_d192_ed03).to_le_bytes());
    match shape {
        ShardShape::Uniform => {} // keep seed-derived low byte (uniform across shards)
        ShardShape::TwoShard => bytes[0] = u8::from(!index.is_multiple_of(2)),
        ShardShape::Concentrated => bytes[0] = 0x2a,
    }
    Hash256::from_le_bytes(&bytes)
}

fn txout(seed: u64) -> TxOut {
    let mut script = Vec::with_capacity(34);
    script.extend_from_slice(&[0x00, 0x20]);
    script.extend_from_slice(&seed.to_le_bytes());
    script.extend_from_slice(&seed.rotate_left(7).to_le_bytes());
    script.extend_from_slice(&seed.wrapping_mul(0x2545_f491_4f6c_dd1d).to_le_bytes());
    script.extend_from_slice(&seed.wrapping_add(0x9e37_79b9_7f4a_7c15).to_le_bytes());
    TxOut {
        value: Amount::from_sat(5_000 + (seed % 1_000_000)),
        script_pubkey: ScriptBuf::from_bytes(script),
    }
}

fn workload(shape: ShardShape) -> Vec<Entry> {
    let mut rng = 0x1234_5678_9abc_def0_u64;
    let mut entries = Vec::with_capacity(ENTRY_COUNT);
    for index in 0..ENTRY_COUNT {
        let seed = next_u64(&mut rng);
        entries.push(Entry {
            op: OutPoint::new(shaped_txid(seed, index, shape), 0),
            txout: txout(seed),
            coinbase: false,
            height: 2,
        });
    }
    entries
}

/// Commits `entries`, then spends `spends`, committing in chunks of `batch` ops so the
/// caller selects how far the commit fans out. The block hash is metadata only
/// (tracing, never folded into UTXO state), so a constant is fine.
fn run(entries: &[Entry], spends: &[OutPoint], batch: usize) -> Result<UtxoSet, UtxoError> {
    let set = UtxoSet::new();
    let block_hash = Hash256::from_le_bytes(&[0x11_u8; 32]);
    for chunk in entries.chunks(batch) {
        let mut changes = BlockChanges::with_capacity(chunk.len(), 0);
        for entry in chunk {
            changes.add(UtxoAdd::new(
                entry.op,
                entry.txout.clone(),
                entry.coinbase,
                entry.height,
            ));
        }
        set.commit_block(&changes, &block_hash)?;
    }
    for chunk in spends.chunks(batch) {
        let mut changes = BlockChanges::with_capacity(0, chunk.len());
        for op in chunk {
            changes.remove(*op);
        }
        set.commit_block(&changes, &block_hash)?;
    }
    Ok(set)
}

fn assert_commute(shape: ShardShape) -> Result<(), UtxoError> {
    let entries = workload(shape);
    // Spend the first half; the rest stay live.
    let spends: Vec<OutPoint> = entries
        .iter()
        .take(entries.len() / 2)
        .map(|entry| entry.op)
        .collect();

    // Independent oracle: the net set after adds-minus-spends.
    let mut model: HashMap<OutPoint, TxOut> = HashMap::new();
    for entry in &entries {
        model.insert(entry.op, entry.txout.clone());
    }
    for op in &spends {
        model.remove(op);
    }

    // Commit the identical net changes under every chunking; all must converge.
    let mut reference_hash: Option<Hash256> = None;
    for batch in BATCHES {
        let set = run(&entries, &spends, batch)?;

        let hash = hash_serialized_3(&set)?;
        match reference_hash {
            None => reference_hash = Some(hash),
            Some(expected) => {
                assert_eq!(
                    hash, expected,
                    "commit state diverged at batch size {batch}"
                );
            }
        }

        assert_eq!(
            set.len(),
            model.len(),
            "batch {batch}: live-output count diverged from the model",
        );
        for (op, expected) in &model {
            assert_eq!(
                set.get(op).as_ref(),
                Some(expected),
                "batch {batch}: lost or corrupted a live output",
            );
        }
        for op in &spends {
            assert!(
                set.get(op).is_none(),
                "batch {batch}: spent output left live"
            );
        }
    }
    Ok(())
}

#[test]
fn commit_commutes_uniform() -> Result<(), UtxoError> {
    assert_commute(ShardShape::Uniform)
}

#[test]
fn commit_commutes_two_shard() -> Result<(), UtxoError> {
    assert_commute(ShardShape::TwoShard)
}

#[test]
fn commit_commutes_concentrated() -> Result<(), UtxoError> {
    assert_commute(ShardShape::Concentrated)
}
