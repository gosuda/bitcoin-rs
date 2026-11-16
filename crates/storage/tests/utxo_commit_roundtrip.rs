use bitcoin_rs_consensus::primitives::{Amount, Hash256, OutPoint, TxOut};
use bitcoin_rs_storage::utxo::contract::{BlockChanges, UtxoAdd, populate_block_changes};
use bitcoin_rs_storage::utxo::{UtxoError, UtxoReader};
use bitcoin_rs_storage::{CoinStore, MemoryKvStore};
use std::sync::Arc;
type Entry = (OutPoint, TxOut, bool, u32);
use crate::support::utxo::{TestError, TestResult};

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

type CommitPath = fn(&CoinStore, &[Entry], &[OutPoint], &Hash256) -> Result<(), UtxoError>;

fn commit_borrowed(
    store: &CoinStore,
    adds: &[Entry],
    removes: &[OutPoint],
    _block: &Hash256,
) -> Result<(), UtxoError> {
    populate_block_changes(store, &borrowed_changes(adds, removes))
}

fn commit_owned(
    store: &CoinStore,
    adds: &[Entry],
    removes: &[OutPoint],
    _block: &Hash256,
) -> Result<(), UtxoError> {
    populate_block_changes(store, &owned_changes(adds, removes))
}

#[test]
fn owned_and_borrowed_commits_preserve_coin_fields() -> TestResult {
    for shard_count in [1_u8, 20] {
        let store1 = Arc::new(MemoryKvStore::new());
        let owned = Arc::new(CoinStore::open(store1, 64 * 1024 * 1024));
        let store2 = Arc::new(MemoryKvStore::new());
        let borrowed = Arc::new(CoinStore::open(store2, 64 * 1024 * 1024));

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
            commit_owned(&owned, &entries, &removes, &txid(round))?;
            commit_borrowed(&borrowed, &entries, &removes, &txid(round))?;
            let reader_owned = UtxoReader::from_coin_store(Arc::clone(&owned));
            let reader_borrowed = UtxoReader::from_coin_store(Arc::clone(&borrowed));
            for (outpoint, txout, coinbase, height) in &entries {
                let expected = Some((txout.clone(), *coinbase, *height));
                assert_eq!(
                    reader_owned.get_entry(outpoint)?.map(|coin| (
                        coin.txout,
                        coin.coinbase,
                        coin.height
                    )),
                    expected
                );
                assert_eq!(
                    reader_borrowed.get_entry(outpoint)?.map(|coin| (
                        coin.txout,
                        coin.coinbase,
                        coin.height
                    )),
                    expected
                );
            }
            for outpoint in &removes {
                assert_eq!(reader_owned.get(outpoint)?, None);
                assert_eq!(reader_borrowed.get(outpoint)?, None);
            }
            removes = entries.drain(..16).map(|entry| entry.0).collect();
            for (_, txout, coinbase, height) in &mut entries {
                txout.value = Amount::from_sat(77);
                *coinbase = !*coinbase;
                *height += 1;
            }
        }
    }
    Ok(())
}

#[test]
fn an_invalid_add_rejects_the_whole_commit_in_every_commit_path() -> TestResult {
    let commit_paths: [CommitPath; 2] = [commit_owned, commit_borrowed];
    for cross_shard in [false, true] {
        let far_shard = u8::from(cross_shard);
        for commit in commit_paths {
            let store = Arc::new(MemoryKvStore::new());
            let coin_store = Arc::new(CoinStore::open(store, 64 * 1024 * 1024));
            let reader = UtxoReader::from_coin_store(Arc::clone(&coin_store));
            let retained = OutPoint::new(txid_in_shard(0, 100).into(), 0);
            let peer = OutPoint::new(txid_in_shard(far_shard, 101).into(), 0);
            let retained_txout = txout(100);
            let peer_txout = txout(101);
            let preload = [
                (retained, retained_txout.clone(), false, 10),
                (peer, peer_txout.clone(), false, 10),
            ];
            commit_owned(&coin_store, &preload, &[], &txid(102))?;

            let valid_add = OutPoint::new(txid_in_shard(0, 200).into(), 0);
            let invalid_add = OutPoint::new(txid_in_shard(far_shard, 201).into(), 0);
            let adds = [
                (valid_add, txout(200), false, 11),
                (invalid_add, oversized_txout(201), false, 11),
            ];
            let error = match commit(&coin_store, &adds, &[retained], &txid(103)) {
                Ok(()) => {
                    return Err(TestError::UnexpectedSuccess(
                        "oversized script unexpectedly committed",
                    ));
                }
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
                reader.get(&retained)?,
                Some(retained_txout),
                "a rejected commit applied its removes"
            );
            assert_eq!(reader.get(&peer)?, Some(peer_txout));
            assert_eq!(
                reader.get(&valid_add)?,
                None,
                "a rejected commit applied an earlier add"
            );
            assert_eq!(reader.get(&invalid_add)?, None);
        }
    }
    Ok(())
}

#[test]
fn output_boundaries_roundtrip_through_get_scan_and_spend() -> TestResult {
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
    let store = Arc::new(MemoryKvStore::new());
    let coin_store = Arc::new(CoinStore::open(store, 64 * 1024 * 1024));
    let reader = UtxoReader::from_coin_store(Arc::clone(&coin_store));
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
    commit_owned(&coin_store, &entries, &[], &txid(90))?;

    assert!(reader.has_live_outputs_for_txid(&live)?);
    assert!(!reader.has_live_outputs_for_txid(&txid(89))?);

    for (outpoint, txout, coinbase, height) in &entries {
        assert_eq!(reader.get(outpoint)?.as_ref(), Some(txout));
        let entry = reader
            .get_entry(outpoint)?
            .ok_or(TestError::Missing("expected a committed output to be live"))?;
        assert_eq!(&entry.txout, txout);
        assert_eq!(entry.coinbase, *coinbase, "coinbase lost at {outpoint:?}");
        assert_eq!(entry.height, *height, "height lost at {outpoint:?}");
    }

    let view = reader.lock_stable_view()?;
    let mut remaining: std::collections::HashSet<_> =
        entries.iter().map(|(outpoint, ..)| *outpoint).collect();
    let mut scan_failure: Option<TestError> = None;
    view.for_each_all(|outpoint, script| {
        assert!(
            remaining.remove(outpoint),
            "unexpected or duplicate output {outpoint:?}"
        );
        if scan_failure.is_some() {
            return;
        }
        let Some((_, txout, coinbase, height)) = entries
            .iter()
            .find(|(expected_outpoint, ..)| expected_outpoint == outpoint)
        else {
            scan_failure = Some(TestError::Missing(
                "scanned output does not belong to the supplied inputs",
            ));
            return;
        };
        assert_eq!(script, txout.script_pubkey.as_slice());
        let Some(coin) = view.get_entry(outpoint) else {
            scan_failure = Some(TestError::Missing("scanned coin must be live"));
            return;
        };
        assert_eq!(
            (&coin.txout, coin.coinbase, coin.height),
            (txout, *coinbase, *height)
        );
    });
    if let Some(failure) = scan_failure {
        return Err(failure);
    }
    assert!(remaining.is_empty());
    drop(view);

    for (index, (outpoint, _txout, _coinbase, _height)) in entries.iter().enumerate() {
        assert!(reader.has_live_outputs_for_txid(&live)?);
        let block = txid(91 + u64::try_from(index)?);
        commit_owned(&coin_store, &[], std::slice::from_ref(outpoint), &block)?;
        assert_eq!(reader.get(outpoint)?, None);
    }
    assert!(!reader.has_live_outputs_for_txid(&live)?);
    Ok(())
}

#[test]
fn high_vout_full_record_delete_removes_all_outputs_in_one_commit() -> TestResult {
    let store = Arc::new(MemoryKvStore::new());
    let coin_store = Arc::new(CoinStore::open(store, 64 * 1024 * 1024));
    let reader = UtxoReader::from_coin_store(Arc::clone(&coin_store));
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
    commit_owned(&coin_store, &adds, &[], &txid(94))?;

    commit_owned(&coin_store, &[], &removes, &txid(95))?;

    for remove in &removes {
        assert_eq!(reader.get(remove)?, None);
    }
    assert!(!reader.has_live_outputs_for_txid(&live)?);
    Ok(())
}

#[test]
fn a_shared_txid_prefix_keeps_records_and_deletes_independent() -> TestResult {
    for reverse in [false, true] {
        let prefix = 0xfeed_face_cafe_beef_u64;
        let store = Arc::new(MemoryKvStore::new());
        let coin_store = Arc::new(CoinStore::open(store, 64 * 1024 * 1024));
        let reader = UtxoReader::from_coin_store(Arc::clone(&coin_store));
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
        commit_owned(&coin_store, &adds, &[], &txid(300))?;

        commit_owned(&coin_store, &[], &[first_a], &txid(301))?;
        assert_eq!(reader.get(&first_a)?, None);
        assert_eq!(reader.get(&first_b)?, Some(first_b_txout));
        assert_eq!(reader.get(&peer)?, Some(peer_txout.clone()));

        commit_owned(&coin_store, &[], &[first_b], &txid(302))?;
        assert_eq!(reader.get(&peer)?, Some(peer_txout));
        assert!(!reader.has_live_outputs_for_txid(&first)?);
        assert!(reader.has_live_outputs_for_txid(&second)?);
    }
    Ok(())
}

#[test]
fn duplicate_remove_does_not_fast_delete_unspent_vout() -> TestResult {
    let store = Arc::new(MemoryKvStore::new());
    let coin_store = Arc::new(CoinStore::open(store, 64 * 1024 * 1024));
    let reader = UtxoReader::from_coin_store(Arc::clone(&coin_store));
    let live = txid(700);
    let removed = OutPoint::new(live.into(), 0);
    let retained = OutPoint::new(live.into(), 1);
    let retained_txout = txout(701);
    let adds = [
        (removed, txout(700), false, 1),
        (retained, retained_txout.clone(), false, 1),
    ];
    commit_owned(&coin_store, &adds, &[], &txid(702))?;

    commit_owned(&coin_store, &[], &[removed, removed], &txid(703))?;

    assert_eq!(reader.get(&removed)?, None);
    assert_eq!(reader.get(&retained)?, Some(retained_txout));
    assert!(reader.has_live_outputs_for_txid(&live)?);
    Ok(())
}

#[test]
fn coin_store_scans_b_framed_values_matching_oracle() -> TestResult {
    use bitcoin_rs_storage::utxo::record::{B_FRAMING_FLAG, RecordFraming, UtxoRecord};
    use bitcoin_rs_storage::{ColumnFamily, KvStore};

    let store: Arc<dyn KvStore> = Arc::new(MemoryKvStore::new());
    let coin_store = Arc::new(CoinStore::open(Arc::clone(&store), 64 * 1024 * 1024));

    let txid1 = txid(1);
    let txid2 = txid(2);
    let out1_0 = OutPoint::new(txid1.into(), 0);
    let out1_1 = OutPoint::new(txid1.into(), 1);
    let out2_0 = OutPoint::new(txid2.into(), 0);

    let txout1_0 = txout(10);
    let txout1_1 = txout(20);
    let txout2_0 = txout(30);

    let adds1 = [
        (out1_0, txout1_0.clone(), false, 100),
        (out1_1, txout1_1.clone(), true, 100),
        (out2_0, txout2_0.clone(), false, 100),
    ];
    commit_owned(&coin_store, &adds1, &[], &txid(101))?;

    let spend_out1_0 = [out1_0];
    let txid3 = txid(3);
    let out3_0 = OutPoint::new(txid3.into(), 0);
    let txout3_0 = txout(40);
    let adds2 = [(out3_0, txout3_0.clone(), false, 101)];
    commit_owned(&coin_store, &adds2, &spend_out1_0, &txid(102))?;

    let mut scanned_rows = 0;
    for item in store
        .iter_prefix(ColumnFamily::Coins, &[])
        .map_err(UtxoError::from)?
    {
        let (key, value) = item.map_err(UtxoError::from)?;
        scanned_rows += 1;

        assert!(value.len() > 36, "coin row must have header");
        assert_eq!(
            value[36] & B_FRAMING_FLAG,
            B_FRAMING_FLAG,
            "engine coin row must have b-framing discriminator set"
        );

        let record = UtxoRecord::from_encoded(value.to_vec().into_boxed_slice())?;
        assert_eq!(record.framing(), RecordFraming::B);

        let mut key_bytes = [0_u8; 32];
        key_bytes.copy_from_slice(&key);
        let row_txid = Hash256::from_le_bytes(&key_bytes);
        assert_eq!(record.txid(), row_txid);

        if row_txid == txid1 {
            assert_eq!(record.output_count(), 1);
            let out = record
                .find_output(1)
                .ok_or(TestError::Missing("out1_1 must exist"))?;
            assert_eq!(out.value, txout1_1.value.to_sat());
            assert_eq!(out.script_pubkey, txout1_1.script_pubkey.as_slice());
            assert!(out.coinbase);
            assert_eq!(out.height, 100);
            assert!(record.find_output(0).is_none());
        } else if row_txid == txid2 {
            assert_eq!(record.output_count(), 1);
            let out = record
                .find_output(0)
                .ok_or(TestError::Missing("out2_0 must exist"))?;
            assert_eq!(out.value, txout2_0.value.to_sat());
            assert_eq!(out.script_pubkey, txout2_0.script_pubkey.as_slice());
            assert!(!out.coinbase);
            assert_eq!(out.height, 100);
        } else if row_txid == txid3 {
            assert_eq!(record.output_count(), 1);
            let out = record
                .find_output(0)
                .ok_or(TestError::Missing("out3_0 must exist"))?;
            assert_eq!(out.value, txout3_0.value.to_sat());
            assert_eq!(out.script_pubkey, txout3_0.script_pubkey.as_slice());
            assert!(!out.coinbase);
            assert_eq!(out.height, 101);
        } else {
            panic!("unexpected txid {row_txid:?}");
        }
    }
    assert_eq!(scanned_rows, 3);

    Ok(())
}
