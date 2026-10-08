//! Public commit/get coverage for the UTXO set.

use bitcoin_rs_primitives::{Amount, Hash256, OutPoint, TxOut, varint};
use bitcoin_rs_utxo::contract::{BlockChanges, UtxoAdd};
use bitcoin_rs_utxo::{UtxoError, UtxoSet};
use sha2::{Digest, Sha256};

/// One live output as the tests describe it: outpoint, payload, coinbase flag,
/// creating height.
type Entry = (OutPoint, TxOut, bool, u32);
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn txid(seed: u64) -> Hash256 {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    bytes[8..16].copy_from_slice(&seed.rotate_left(17).to_le_bytes());
    bytes[16..24].copy_from_slice(&seed.wrapping_mul(0x9e37_79b9_7f4a_7c15).to_le_bytes());
    bytes[24..32].copy_from_slice(&seed.wrapping_add(0xa5a5_a5a5_a5a5_a5a5).to_le_bytes());
    Hash256::from_le_bytes(&bytes)
}

fn txout(seed: u64) -> TxOut {
    let mut script = Vec::with_capacity(10);
    script.extend_from_slice(&[0x51, 0x20]);
    script.extend_from_slice(&seed.to_le_bytes());
    TxOut {
        value: Amount::from_sat(1_000 + seed),
        script_pubkey: script.into(),
    }
}

/// A script one byte past the record ceiling, the cheapest way to make a
/// commit fail inside the shard pass.
fn oversized_txout(value: u64) -> TxOut {
    TxOut {
        value: Amount::from_sat(value),
        script_pubkey: vec![0; usize::from(u16::MAX) + 1].into(),
    }
}

fn txid_with_prefix(prefix: u64, suffix: u64) -> Hash256 {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&prefix.to_le_bytes());
    bytes[8..16].copy_from_slice(&suffix.to_le_bytes());
    bytes[16..24].copy_from_slice(&suffix.rotate_left(11).to_le_bytes());
    bytes[24..32].copy_from_slice(&suffix.wrapping_mul(17).to_le_bytes());
    Hash256::from_le_bytes(&bytes)
}

fn txid_in_shard(shard: u8, suffix: u64) -> Hash256 {
    let mut bytes = [0_u8; 32];
    bytes[0] = shard;
    bytes[1..9].copy_from_slice(&suffix.to_le_bytes());
    bytes[9..17].copy_from_slice(&suffix.rotate_left(13).to_le_bytes());
    bytes[17..25].copy_from_slice(&suffix.wrapping_mul(29).to_le_bytes());
    Hash256::from_le_bytes(&bytes)
}

fn expected_hash_serialized_3(entries: &[Entry]) -> Result<Hash256, Box<dyn std::error::Error>> {
    let mut sorted: Vec<&Entry> = entries.iter().collect();
    sorted.sort_unstable_by(|left, right| {
        left.0
            .txid
            .0
            .to_le_bytes()
            .cmp(&right.0.txid.0.to_le_bytes())
            .then_with(|| {
                let left_vout = left.0.vout;
                let right_vout = right.0.vout;
                left_vout.cmp(&right_vout)
            })
    });

    let mut engine = Sha256::new();
    for (outpoint, txout, coinbase, height) in sorted {
        engine.update(outpoint.txid.0.to_le_bytes());
        engine.update(outpoint.vout.to_le_bytes());
        let code = (*height << 1) | u32::from(*coinbase);
        engine.update(code.to_le_bytes());
        engine.update(txout.value.to_le_bytes());
        let script = txout.script_pubkey.as_slice();
        let script_len = u64::try_from(script.len())?;
        let encoded_len = varint::encode(script_len);
        engine.update(encoded_len.as_slice());
        engine.update(script);
    }

    let first = engine.finalize();
    let second = Sha256::digest(first);
    let bytes: [u8; 32] = second.into();
    Ok(Hash256::from_le_bytes(&bytes))
}

fn borrowed_changes<'a>(adds: &'a [Entry], removes: &[OutPoint]) -> BlockChanges<&'a TxOut> {
    let mut changes = BlockChanges::with_capacity(adds.len(), removes.len());
    for remove in removes {
        changes.remove(*remove);
    }
    for (outpoint, txout, coinbase, height) in adds {
        changes.add(UtxoAdd::new(*outpoint, txout, *coinbase, *height));
    }
    changes
}

fn owned_changes(adds: &[Entry], removes: &[OutPoint]) -> BlockChanges {
    let mut changes = BlockChanges::with_capacity(adds.len(), removes.len());
    for remove in removes {
        changes.remove(*remove);
    }
    for (outpoint, txout, coinbase, height) in adds {
        changes.add(UtxoAdd::new(*outpoint, txout.clone(), *coinbase, *height));
    }
    changes
}

/// Commits one block through the public contract, with the payloads owned or
/// borrowed from the caller. Both shapes must behave identically.
fn commit(
    set: &UtxoSet,
    adds: &[Entry],
    removes: &[OutPoint],
    block: &Hash256,
    borrowed: bool,
) -> Result<(), UtxoError> {
    if borrowed {
        bitcoin_rs_utxo::contract::commit_block_changes(
            set,
            &borrowed_changes(adds, removes),
            block,
        )
    } else {
        bitcoin_rs_utxo::contract::commit_block_changes(set, &owned_changes(adds, removes), block)
    }
}

#[test]
fn owned_and_borrowed_commits_match_independent_state_hashes() -> TestResult {
    use bitcoin_rs_utxo::stats::{CoinStats, CoinStatsListener};

    for shard_count in [1_u8, 20] {
        for with_listener in [false, true] {
            let mut owned = UtxoSet::new();
            let mut borrowed = UtxoSet::new();
            if with_listener {
                owned.track_coin_stats(CoinStatsListener::new(CoinStats::new()));
                borrowed.track_coin_stats(CoinStatsListener::new(CoinStats::new()));
            }
            let mut entries: Vec<Entry> = (0_u8..64)
                .map(|index| {
                    let outpoint = OutPoint::new(
                        txid_in_shard(index % shard_count, u64::from(index)).into(),
                        u32::from(index),
                    );
                    (outpoint, txout(u64::from(index)), index % 2 == 0, 100)
                })
                .collect();
            let mut removes = Vec::new();
            for round in 0..2 {
                commit(&owned, &entries, &removes, &txid(round), false)?;
                commit(&borrowed, &entries, &removes, &txid(round), true)?;
                let expected = expected_hash_serialized_3(&entries)?;
                assert_eq!(owned.lock_stable_view().hash_serialized_3()?, expected);
                assert_eq!(borrowed.lock_stable_view().hash_serialized_3()?, expected);
                removes = entries.drain(..16).map(|entry| entry.0).collect();
                for (_, txout, coinbase, height) in &mut entries {
                    txout.value = Amount::from_sat(77);
                    *coinbase = !*coinbase;
                    *height += 1;
                }
            }
        }
    }
    Ok(())
}

/// A commit that fails inside the shard pass must leave the set exactly as it
/// was: no remove applied, no earlier add of the same commit applied. Covers
/// the owned and borrowed payload shapes and the single-shard and multi-shard
/// commit paths, which reject in different places.
#[test]
fn an_invalid_add_rejects_the_whole_commit_in_every_commit_path() -> TestResult {
    for cross_shard in [false, true] {
        for borrowed in [false, true] {
            let far_shard = u8::from(cross_shard);
            let set = UtxoSet::new();
            let retained = OutPoint::new(txid_in_shard(0, 100).into(), 0);
            let peer = OutPoint::new(txid_in_shard(far_shard, 101).into(), 0);
            let retained_txout = txout(100);
            let peer_txout = txout(101);
            let preload = [
                (retained, retained_txout.clone(), false, 10),
                (peer, peer_txout.clone(), false, 10),
            ];
            commit(&set, &preload, &[], &txid(102), borrowed)?;

            let valid_add = OutPoint::new(txid_in_shard(0, 200).into(), 0);
            let invalid_add = OutPoint::new(txid_in_shard(far_shard, 201).into(), 0);
            let adds = [
                (valid_add, txout(200), false, 11),
                (invalid_add, oversized_txout(201), false, 11),
            ];
            let error = match commit(&set, &adds, &[retained], &txid(103), borrowed) {
                Ok(()) => return Err("oversized script unexpectedly committed".into()),
                Err(error) => error,
            };
            assert!(
                matches!(
                    error,
                    UtxoError::ScriptTooLarge { len } if len == usize::from(u16::MAX) + 1
                ),
                "unexpected error: {error}"
            );
            assert_eq!(
                set.get(&retained),
                Some(retained_txout),
                "a rejected commit applied its removes"
            );
            assert_eq!(set.get(&peer), Some(peer_txout));
            assert_eq!(
                set.get(&valid_add),
                None,
                "a rejected commit applied an earlier add"
            );
            assert_eq!(set.get(&invalid_add), None);
            assert_eq!(set.len(), 2);
        }
    }
    Ok(())
}

/// Every output-level boundary the record encoding has a case for, carried
/// through the public API: the metadata each read surface reports, the
/// serialization hash, and the per-vout spend path.
#[test]
fn output_boundaries_roundtrip_through_get_scan_and_spend() -> TestResult {
    // Scripts stay distinct so each one selects exactly its own output in a
    // scan; vouts cross the inline-partition and directory-width boundaries.
    let cases: [(u32, u64, bool, u32, Vec<u8>); 6] = [
        (0, 100, false, 0, Vec::new()),
        (63, 200, true, 123, vec![0x51]),
        (64, 300, true, 301, vec![0x00; 34]),
        (65, 0, false, 840_000, vec![0x6a]),
        (1_000, 500, true, u32::MAX, vec![0x52; 10_000]),
        (
            u32::MAX,
            2_099_999_999_999_999,
            false,
            u32::MAX,
            vec![0x51; 520],
        ),
    ];
    let live = txid(88);
    let set = UtxoSet::new();
    let entries: Vec<Entry> = cases
        .iter()
        .map(|(vout, value, coinbase, height, script)| {
            (
                OutPoint::new(live.into(), *vout),
                TxOut {
                    value: Amount::from_sat(*value),
                    script_pubkey: script.clone().into(),
                },
                *coinbase,
                *height,
            )
        })
        .collect();
    commit(&set, &entries, &[], &txid(90), false)?;

    assert_eq!(set.record_count(), 1, "one txid must hold one record");
    assert_eq!(set.len(), entries.len());
    assert_eq!(
        set.lock_stable_view().hash_serialized_3()?,
        expected_hash_serialized_3(&entries)?
    );
    assert!(set.has_live_outputs_for_txid(&live));
    assert!(!set.has_live_outputs_for_txid(&txid(89)));

    for (outpoint, txout, coinbase, height) in &entries {
        assert_eq!(set.get(outpoint).as_ref(), Some(txout));
        let entry = set
            .get_entry(outpoint)
            .ok_or("expected a committed output to be live")?;
        assert_eq!(&entry.txout, txout);
        assert_eq!(entry.coinbase, *coinbase, "coinbase lost at {outpoint:?}");
        assert_eq!(entry.height, *height, "height lost at {outpoint:?}");

        let scan = set.scan_script_pubkeys(std::slice::from_ref(&txout.script_pubkey))?;
        assert_eq!(scan.txouts, entries.len());
        assert_eq!(scan.unspents.len(), 1, "scan matched the wrong outputs");
        assert_eq!(scan.unspents[0].outpoint, *outpoint);
        assert_eq!(scan.unspents[0].txout, *txout);
        assert_eq!(scan.unspents[0].coinbase, *coinbase);
        assert_eq!(scan.unspents[0].height, *height);
    }

    // One vout at a time: the record survives until its last output leaves.
    for (index, (outpoint, _txout, _coinbase, _height)) in entries.iter().enumerate() {
        assert!(set.has_live_outputs_for_txid(&live));
        let block = txid(91 + u64::try_from(index)?);
        commit(&set, &[], std::slice::from_ref(outpoint), &block, false)?;
        assert_eq!(set.get(outpoint), None);
    }
    assert!(!set.has_live_outputs_for_txid(&live));
    assert_eq!(set.record_count(), 0);
    assert!(set.is_empty());
    Ok(())
}

#[test]
fn high_vout_full_record_delete_removes_all_outputs_in_one_commit() -> TestResult {
    let set = UtxoSet::new();
    let live = txid(93);
    let adds: Vec<Entry> = (64_u32..128)
        .map(|vout| {
            (
                OutPoint::new(live.into(), vout),
                txout(1_000 + u64::from(vout)),
                false,
                302,
            )
        })
        .collect();
    let removes: Vec<OutPoint> = adds.iter().map(|entry| entry.0).collect();
    commit(&set, &adds, &[], &txid(94), false)?;
    assert_eq!(set.record_count(), 1);
    assert_eq!(set.len(), 64);

    commit(&set, &[], &removes, &txid(95), false)?;

    for remove in &removes {
        assert_eq!(set.get(remove), None);
    }
    assert!(!set.has_live_outputs_for_txid(&live));
    assert_eq!(set.record_count(), 0);
    assert!(set.is_empty());
    Ok(())
}

/// The set keys on the full txid, so two txids sharing a prefix must stay
/// independent through partial spends and the full-record delete path.
#[test]
fn a_shared_txid_prefix_keeps_records_and_deletes_independent() -> TestResult {
    for reverse in [false, true] {
        let prefix = 0xfeed_face_cafe_beef_u64;
        let set = UtxoSet::new();
        let first = txid_with_prefix(prefix, if reverse { 2 } else { 1 });
        let second = txid_with_prefix(prefix, if reverse { 1 } else { 2 });
        let first_a = OutPoint::new(first.into(), 0);
        let first_b = OutPoint::new(first.into(), 1);
        let peer = OutPoint::new(second.into(), 0);
        let first_b_txout = txout(102);
        let peer_txout = txout(202);
        let mut adds = [
            (first_a, txout(101), false, 1),
            (first_b, first_b_txout.clone(), false, 1),
            (peer, peer_txout.clone(), false, 1),
        ];
        if reverse {
            adds.reverse();
        }
        commit(&set, &adds, &[], &txid(300), false)?;

        commit(&set, &[], &[first_a], &txid(301), false)?;
        assert_eq!(set.get(&first_a), None);
        assert_eq!(set.get(&first_b), Some(first_b_txout));
        assert_eq!(set.get(&peer), Some(peer_txout.clone()));

        // Emptying the first record must not take its prefix peer with it.
        commit(&set, &[], &[first_b], &txid(302), false)?;
        assert_eq!(set.get(&peer), Some(peer_txout));
        assert!(!set.has_live_outputs_for_txid(&first));
        assert!(set.has_live_outputs_for_txid(&second));
        assert_eq!(set.record_count(), 1);
        assert_eq!(set.len(), 1);
    }
    Ok(())
}

#[test]
fn duplicate_remove_does_not_fast_delete_unspent_vout() -> TestResult {
    let set = UtxoSet::new();
    let live = txid(700);
    let removed = OutPoint::new(live.into(), 0);
    let retained = OutPoint::new(live.into(), 1);
    let retained_txout = txout(701);
    let adds = [
        (removed, txout(700), false, 1),
        (retained, retained_txout.clone(), false, 1),
    ];
    commit(&set, &adds, &[], &txid(702), false)?;

    commit(&set, &[], &[removed, removed], &txid(703), false)?;

    assert_eq!(set.get(&removed), None);
    assert_eq!(set.get(&retained), Some(retained_txout));
    assert!(set.has_live_outputs_for_txid(&live));
    assert_eq!(set.record_count(), 1);
    assert_eq!(set.len(), 1);
    Ok(())
}
