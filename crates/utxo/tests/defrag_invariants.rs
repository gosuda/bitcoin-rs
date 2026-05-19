//! Defragmentation invariant coverage under churn.
use bitcoin::{Amount, ScriptBuf};
use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut};
use bitcoin_rs_utxo::{BlockChanges, UtxoAdd, UtxoSet, aggregate_hash};

const fn next_u64(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

fn txid(seed: u64) -> Hash256 {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    bytes[8..16].copy_from_slice(&seed.rotate_left(31).to_le_bytes());
    bytes[16..24].copy_from_slice(&seed.wrapping_mul(0xbf58_476d_1ce4_e5b9).to_le_bytes());
    bytes[24..32].copy_from_slice(&seed.wrapping_add(0x9e37_79b9_7f4a_7c15).to_le_bytes());
    Hash256::from_le_bytes(&bytes)
}

fn txout(seed: u64) -> TxOut {
    let mut script = Vec::with_capacity(10);
    script.extend_from_slice(&[0x51, 0x08]);
    script.extend_from_slice(&seed.to_le_bytes());
    TxOut {
        value: Amount::from_sat(10_000 + seed),
        script_pubkey: ScriptBuf::from_bytes(script),
    }
}

#[test]
fn defrag_preserves_live_entries_and_reaches_high_water_plateau()
-> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let mut live = Vec::<(OutPoint, TxOut)>::new();
    let mut rng = 0x1234_5678_9abc_def0_u64;
    let mut pending = BlockChanges::default();

    for i in 0_u64..5_000 {
        if !live.is_empty() && next_u64(&mut rng) & 1 == 0 {
            let live_len = u64::try_from(live.len())?;
            let idx = usize::try_from(next_u64(&mut rng) % live_len)?;
            let (outpoint, _txout) = live.swap_remove(idx);
            pending.remove(outpoint);
        } else {
            let seed = i + 100_000;
            let outpoint = OutPoint::new(txid(seed), u32::try_from(seed % 7)?);
            let txout = txout(seed);
            live.push((outpoint, txout.clone()));
            pending.add(UtxoAdd::new(outpoint, txout, false, 300));
        }

        if i % 64 == 63 {
            set.commit_block(&pending, &txid(i))?;
            pending = BlockChanges::default();
        }
    }
    if !pending.is_empty() {
        set.commit_block(&pending, &txid(5_001))?;
    }

    let before = aggregate_hash(&set)?;
    for _ in 0..bitcoin_rs_utxo::UtxoKey::SHARD_COUNT {
        set.defrag_one_shard();
    }
    let high_water_after_first_pass = set.arena_high_water_by_shard();
    for _ in 0..bitcoin_rs_utxo::UtxoKey::SHARD_COUNT {
        set.defrag_one_shard();
    }

    assert_eq!(aggregate_hash(&set)?, before);
    assert_eq!(set.arena_high_water_by_shard(), high_water_after_first_pass);
    for (outpoint, txout) in live {
        assert_eq!(set.get(&outpoint), Some(txout));
    }

    Ok(())
}
