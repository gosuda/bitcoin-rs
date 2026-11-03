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
