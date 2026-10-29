//! Shared chunk-order fingerprint for the MRP benches.
//!
//! Deduplicated implementation of the snapshot chunk-order diagnostic shared by
//! `crates/mempool/benches/insert_fill.rs` and `crates/mining/benches/candidate.rs`.
//!
//! Each owning bench includes this file by the relative `#[path =
//! "../../../tools/benchmark-support/snapshot_order.rs"]` attribute, so identical bytes
//! ship in every control. The module is pinned in `bench_fingerprints` across all five
//! source trees.
//!
//! Contract: `docs/benchmarks/measured-campaign.md#control-trees`. -
//! `snapshot_order_fingerprint` is a diagnostic identity signal only, not a
//! collision-free equality proof: structural assertions (residency, topological order)
//! carry equivalence; matching fingerprints are supporting evidence. -
//! `assert_snapshot_topological` is the structural half of chunk-order equivalence:
//! every ancestor position precedes its entry and the snapshot names every live entry
//! exactly once. - `FNV_OFFSET`, `fold_u64`, and `fold_bytes` are the deterministic
//! FNV-1a folds shared by every `--mrp-verify` fingerprint line.
//!
//! Standard-library hashers randomise their keys, so they cannot serve as cross-arm
//! fingerprints. Benches reuse these folds for their local body and projection
//! fingerprints, preserving every emitted fingerprint.
//!
//! The measured operations and output schema are unchanged: moving these
//! bodies here preserves all fingerprints and assertions byte for byte.

use bitcoin_rs_mempool::Mempool;

pub(crate) const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;

pub(crate) fn fold_u64(state: u64, value: u64) -> u64 {
    let mut state = state;
    for byte in value.to_le_bytes() {
        state ^= u64::from(byte);
        state = state.wrapping_mul(0x100_0000_01B3);
    }
    state
}

pub(crate) fn fold_bytes(state: u64, bytes: &[u8]) -> u64 {
    let mut state = state;
    for &byte in bytes {
        state ^= u64::from(byte);
        state = state.wrapping_mul(0x100_0000_01B3);
    }
    state
}

pub(crate) fn snapshot_order_fingerprint(pool: &Mempool) -> u64 {
    let snapshot = pool.mining_snapshot();
    let mut state = FNV_OFFSET;
    state = fold_u64(state, snapshot.sequence);
    state = fold_u64(state, snapshot.fee_delta_sequence);
    for entry in &snapshot.entries {
        state = fold_bytes(state, entry.txid.as_bytes());
        state = fold_u64(state, entry.fee);
        state = fold_u64(state, entry.weight);
        state = fold_u64(state, entry.fee_delta.cast_unsigned());
        for &ancestor in &entry.ancestors {
            state = fold_u64(state, u64::from(ancestor));
        }
    }
    state
}

pub(crate) fn assert_snapshot_topological(pool: &Mempool) {
    let snapshot = pool.mining_snapshot();
    for (index, entry) in snapshot.entries.iter().enumerate() {
        let index = u32::try_from(index).expect("snapshot fits u32");
        for &ancestor in &entry.ancestors {
            assert!(
                ancestor < index,
                "ancestor position {ancestor} must precede entry {index}"
            );
        }
    }
    assert_eq!(
        snapshot.entries.len(),
        pool.len(),
        "the snapshot must name every live entry exactly once"
    );
}
