use std::collections::BTreeMap;
use std::sync::Arc;

use bitcoin_rs_storage::{
    BatchOp, CoinKey, CoinStatsFeed, CoinStore, ColumnFamily, KvStore, PersistFault, RocksDbStore,
    StorageError, WindowDelta,
};
use bytes::Bytes;

use crate::support::TestResult;

#[test]
fn multi_get_returns_input_order_absence_and_duplicates() -> TestResult {
    let temp = tempfile::TempDir::new()?;
    let store = RocksDbStore::open(temp.path())?;

    let mut oracle: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    for i in 0_u8..16 {
        let key = vec![i; 4];
        let value = vec![i.wrapping_mul(7); 40];
        store.put(ColumnFamily::Coins, &key, &value)?;
        oracle.insert(key, value);
    }
    let absent = vec![0xff_u8; 4];
    let expected = |key: &[u8]| oracle.get(key).cloned();

    let ascending: Vec<Vec<u8>> = oracle.keys().cloned().collect();
    let refs: Vec<&[u8]> = ascending.iter().map(Vec::as_slice).collect();
    let got = store.multi_get(ColumnFamily::Coins, &refs)?;
    assert_eq!(got.len(), ascending.len());
    for (key, value) in ascending.iter().zip(&got) {
        assert_eq!(value.as_deref(), expected(key).as_deref(), "key {key:?}");
    }

    let query = [
        absent.clone(),
        vec![5_u8; 4],
        vec![0_u8; 4],
        vec![15_u8; 4],
        vec![5_u8; 4],
        absent.clone(),
        vec![7_u8; 4],
    ];
    let refs: Vec<&[u8]> = query.iter().map(Vec::as_slice).collect();
    let got = store.multi_get(ColumnFamily::Coins, &refs)?;
    let expected_order: Vec<Option<Bytes>> = query
        .iter()
        .map(|key| expected(key).map(Bytes::from))
        .collect();
    assert_eq!(got, expected_order);

    assert!(store.multi_get(ColumnFamily::Coins, &[])?.is_empty());
    Ok(())
}

#[test]
fn multi_get_is_isolated_per_column_family() -> TestResult {
    let temp = tempfile::TempDir::new()?;
    let store = RocksDbStore::open(temp.path())?;
    let key = [9_u8; 8];
    store.put(ColumnFamily::Coins, &key, b"coins-value")?;
    store.put(ColumnFamily::BlockHeaders, &key, b"headers-value")?;

    let got = store.multi_get(ColumnFamily::Coins, &[&key])?;
    assert_eq!(got, vec![Some(Bytes::from_static(b"coins-value"))]);

    let got = store.multi_get(ColumnFamily::BlockHeaders, &[&key])?;
    assert_eq!(got, vec![Some(Bytes::from_static(b"headers-value"))]);

    let got = store.multi_get(ColumnFamily::ScriptLive, &[&key])?;
    assert_eq!(got, vec![None]);
    Ok(())
}

fn coin_key(seed: u8) -> CoinKey {
    let mut bytes = [0_u8; 32];
    bytes[0] = seed;
    for (index, byte) in bytes.iter_mut().enumerate().skip(1) {
        *byte = seed
            .wrapping_mul(31)
            .wrapping_add(u8::try_from(index % 251).unwrap_or(0));
    }
    CoinKey(bytes)
}

fn committed_delta(key: CoinKey, value: Bytes) -> WindowDelta {
    WindowDelta {
        records: vec![(key, Some(value))],
    }
}

#[test]
fn coin_store_multi_get_merges_cache_and_engine_in_input_order() -> TestResult {
    let temp = tempfile::TempDir::new()?;
    let store: Arc<dyn KvStore> = Arc::new(RocksDbStore::open(temp.path())?);
    let mut seeded: Vec<(CoinKey, Bytes)> = Vec::new();
    for i in 0_u8..8 {
        let key = coin_key(i);
        let value = Bytes::from(vec![i; 96]);
        store.put(ColumnFamily::Coins, key.as_bytes(), &value)?;
        seeded.push((key, value));
    }

    let coins = CoinStore::open(Arc::clone(&store), 64 * 1024);
    let committed = seeded[3].clone();
    coins.install_committed(
        &committed_delta(committed.0, committed.1.clone()),
        CoinStatsFeed::default(),
    );

    let query = [
        coin_key(9),
        seeded[3].0,
        seeded[0].0,
        seeded[5].0,
        seeded[3].0,
    ];
    let got = coins.multi_get(&query)?;
    let expected = vec![
        None,
        Some(committed.1.clone()),
        Some(seeded[0].1.clone()),
        Some(seeded[5].1.clone()),
        Some(committed.1.clone()),
    ];
    assert_eq!(got, expected);

    assert!(
        coins.cache().lookup(&seeded[0].0).is_some(),
        "engine hit arms the cache"
    );
    assert!(coins.cache().lookup(&seeded[5].0).is_some());
    assert!(
        coins.cache().lookup(&coin_key(9)).is_none(),
        "absence never resides"
    );
    assert_eq!(coins.get(&seeded[2].0)?, Some(seeded[2].1.clone()));
    Ok(())
}

#[test]
fn append_window_writes_engine_batch_without_cache_change() -> TestResult {
    let temp = tempfile::TempDir::new()?;
    let store: Arc<dyn KvStore> = Arc::new(RocksDbStore::open(temp.path())?);
    let created = coin_key(1);
    let created_value = Bytes::from(vec![7_u8; 64]);
    let spent = coin_key(2);
    let spent_value = Bytes::from(vec![8_u8; 64]);
    store.put(ColumnFamily::Coins, created.as_bytes(), &created_value)?;
    store.put(ColumnFamily::Coins, spent.as_bytes(), &spent_value)?;
    let created_and_spent = coin_key(3);
    let spent_final = Bytes::from(vec![9_u8; 64]);

    let coins = CoinStore::open(Arc::clone(&store), 16 * 1024);
    let mut delta = WindowDelta::default();
    delta.push_final(created_and_spent, None);
    delta.push_final(spent, Some(spent_final.clone()));
    delta.push_final(created, Some(created_value.clone()));

    let mut inspected = store.new_batch();
    coins.append_window(&mut inspected, &delta)?;
    let ops = inspected.into_ops();
    assert_eq!(ops.len(), 3);
    assert!(
        matches!(&ops[0], BatchOp::Delete { cf: ColumnFamily::Coins, key } if key == created_and_spent.as_bytes()),
        "create-and-spend commits as a delete"
    );
    assert!(
        matches!(&ops[1], BatchOp::Put { cf: ColumnFamily::Coins, key, value } if key == spent.as_bytes() && value == &spent_final)
    );
    assert!(
        matches!(&ops[2], BatchOp::Put { cf: ColumnFamily::Coins, key, value } if key == created.as_bytes() && value == &created_value)
    );

    let mut batch = store.new_batch();
    coins.append_window(&mut batch, &delta)?;
    store.write(batch)?;
    assert!(
        coins.cache().lookup(&created_and_spent).is_none(),
        "append never installs into the cache"
    );
    assert!(coins.cache().lookup(&spent).is_none());
    assert_eq!(
        store.get(ColumnFamily::Coins, created_and_spent.as_bytes())?,
        None
    );
    assert_eq!(
        store.get(ColumnFamily::Coins, spent.as_bytes())?,
        Some(spent_final.to_vec())
    );
    Ok(())
}

#[test]
fn install_ordering_touches_cache_only_after_durable_success() -> TestResult {
    let temp = tempfile::TempDir::new()?;
    let store: Arc<dyn KvStore> = Arc::new(RocksDbStore::open(temp.path())?);
    let created = coin_key(1);
    let created_value = Bytes::from(vec![7_u8; 64]);
    store.put(ColumnFamily::Coins, created.as_bytes(), &created_value)?;
    let created_and_spent = coin_key(3);
    let spent_once = Bytes::from(vec![4_u8; 32]);

    let coins = CoinStore::open(Arc::clone(&store), 16 * 1024);
    let mut delta = WindowDelta::default();
    delta.push_final(created_and_spent, Some(spent_once.clone()));
    delta.push_final(created, None);

    store.arm_persist_fault(PersistFault::FailApply);
    let mut batch = store.new_batch();
    coins.append_window(&mut batch, &delta)?;
    let outcome = store.write_durable(batch);
    assert!(outcome.is_err(), "injected apply fault must fail the batch");
    assert!(
        coins.cache().lookup(&created_and_spent).is_none(),
        "failed batch leaves the cache untouched"
    );
    assert!(coins.cache().lookup(&created).is_none());
    assert_eq!(
        store.get(ColumnFamily::Coins, created_and_spent.as_bytes())?,
        None,
        "failed batch leaves the engine untouched"
    );
    assert_eq!(
        store.get(ColumnFamily::Coins, created.as_bytes())?,
        Some(created_value.to_vec())
    );

    let mut batch = store.new_batch();
    coins.append_window(&mut batch, &delta)?;
    store.write_durable(batch)?;
    assert!(
        coins.cache().lookup(&created_and_spent).is_none(),
        "a durable receipt alone does not install"
    );
    assert_eq!(store.get(ColumnFamily::Coins, created.as_bytes())?, None);

    coins.install_committed(&delta, CoinStatsFeed::default());
    assert_eq!(
        coins.cache().lookup(&created_and_spent),
        Some(spent_once.clone())
    );
    assert!(
        coins.cache().lookup(&created).is_none(),
        "committed delete drops any entry"
    );
    assert_eq!(coins.get(&created_and_spent)?, Some(spent_once));
    Ok(())
}

#[test]
fn ingest_sorted_replaces_values_rejects_unsorted_and_clears_cache() -> TestResult {
    let temp = tempfile::TempDir::new()?;
    let store: Arc<dyn KvStore> = Arc::new(RocksDbStore::open(temp.path())?);
    let coins = CoinStore::open(store, 16 * 1024);
    let k1 = coin_key(1);
    let k2 = coin_key(2);
    let v1 = Bytes::from(vec![1_u8; 40]);
    let v2 = Bytes::from(vec![2_u8; 40]);

    coins.ingest_sorted([(k1, v1.clone()), (k2, v2.clone())].into_iter())?;
    assert_eq!(coins.get(&k1)?, Some(v1));
    assert_eq!(coins.get(&k2)?, Some(v2));

    let stale = Bytes::from_static(b"stale-value");
    coins.install_committed(
        &committed_delta(k1, stale.clone()),
        CoinStatsFeed::default(),
    );
    assert_eq!(coins.cache().lookup(&k1), Some(stale));

    let v1_new = Bytes::from(vec![5_u8; 40]);
    let k3 = coin_key(5);
    let v3 = Bytes::from(vec![3_u8; 40]);
    coins.ingest_sorted([(k1, v1_new.clone()), (k3, v3)].into_iter())?;
    assert_eq!(coins.cache().lookup(&k1), None, "ingest clears the cache");
    assert_eq!(coins.get(&k1)?, Some(v1_new));

    let outcome = coins.ingest_sorted(
        [
            (k3, Bytes::from_static(b"x")),
            (k1, Bytes::from_static(b"y")),
        ]
        .into_iter(),
    );
    assert!(
        matches!(
            outcome,
            Err(StorageError::InvalidOperation(
                "coin ingest keys must be strictly increasing"
            ))
        ),
        "unsorted ingest must fail closed"
    );
    Ok(())
}

#[test]
fn oversized_committed_replacement_evicts_old_resident_entry() -> TestResult {
    let temp = tempfile::TempDir::new()?;
    let store: Arc<dyn KvStore> = Arc::new(RocksDbStore::open(temp.path())?);
    let coins = CoinStore::open(store, 16 * 1024);
    let k = coin_key(4);
    let v_old = Bytes::from(vec![1_u8; 256]);
    coins.install_committed(&committed_delta(k, v_old.clone()), CoinStatsFeed::default());
    assert_eq!(coins.cache().lookup(&k), Some(v_old));

    let v_huge = Bytes::from(vec![2_u8; 32 * 1024]);
    coins.install_committed(&committed_delta(k, v_huge), CoinStatsFeed::default());
    assert_eq!(
        coins.cache().lookup(&k),
        None,
        "oversized replacement must purge prior resident entry"
    );
    Ok(())
}

#[test]
fn stale_read_fill_does_not_overwrite_newer_commit_or_resurrect_delete() -> TestResult {
    let temp = tempfile::TempDir::new()?;
    let store: Arc<dyn KvStore> = Arc::new(RocksDbStore::open(temp.path())?);
    let coins = CoinStore::open(store, 16 * 1024);
    let k = coin_key(7);
    let stale_epoch = coins.cache().epoch(k.shard());

    let v_committed = Bytes::from_static(b"committed-latest");
    coins.install_committed(
        &committed_delta(k, v_committed.clone()),
        CoinStatsFeed::default(),
    );
    assert_eq!(coins.cache().lookup(&k), Some(v_committed.clone()));

    let v_stale = Bytes::from_static(b"stale-read-value");
    coins
        .cache()
        .fill_after_read_guarded(&k, v_stale.clone(), stale_epoch);
    assert_eq!(
        coins.cache().lookup(&k),
        Some(v_committed),
        "stale read fill must be rejected by epoch guard"
    );

    let epoch_before_delete = coins.cache().epoch(k.shard());
    let mut delete_delta = WindowDelta::default();
    delete_delta.push_final(k, None);
    coins.install_committed(&delete_delta, CoinStatsFeed::default());
    assert_eq!(coins.cache().lookup(&k), None);

    coins
        .cache()
        .fill_after_read_guarded(&k, v_stale, epoch_before_delete);
    assert_eq!(
        coins.cache().lookup(&k),
        None,
        "stale read fill must not resurrect deleted coin"
    );
    Ok(())
}

#[test]
fn committed_record_with_440_outputs_survives_store_reopen() -> TestResult {
    use bitcoin_rs_consensus::primitives::Hash256;
    use bitcoin_rs_storage::utxo::record::{OwnedUtxoOut, UtxoRecord};

    const OUTPUT_COUNT: u32 = 440;
    let temp = tempfile::TempDir::new()?;
    let key = coin_key(11);
    let expected: Vec<OwnedUtxoOut> = (0..OUTPUT_COUNT)
        .map(|vout| OwnedUtxoOut::new(vout, u64::from(vout) + 1, vec![0x51, 0x21], false, 3))
        .collect();
    let record = UtxoRecord::from_owned_outputs(Hash256::from_le_bytes(&key.0), &expected)?;
    let encoded = Bytes::copy_from_slice(record.bytes());

    {
        let store: Arc<dyn KvStore> = Arc::new(RocksDbStore::open(temp.path())?);
        let coins = CoinStore::open(Arc::clone(&store), 1 << 20);
        let mut delta = WindowDelta::default();
        delta.push_final(key, Some(encoded.clone()));
        let mut batch = store.new_batch();
        coins.append_window(&mut batch, &delta)?;
        store.write_durable(batch)?;
    }

    let store: Arc<dyn KvStore> = Arc::new(RocksDbStore::open(temp.path())?);
    let reopened = CoinStore::open(store, 1 << 20);
    let bytes = reopened.get(&key)?.ok_or(StorageError::InvalidOperation(
        "coin record must survive reopen",
    ))?;
    assert_eq!(bytes, encoded, "reopened record bytes must match");

    let decoded = UtxoRecord::from_encoded(bytes.to_vec().into_boxed_slice())?;
    assert_eq!(
        decoded.output_count(),
        usize::try_from(OUTPUT_COUNT).unwrap_or(0)
    );
    let observed: Vec<(u32, u64, Vec<u8>)> = decoded
        .outputs()
        .map(|out| (out.vout, out.value, out.script_pubkey.to_vec()))
        .collect();
    let wanted: Vec<(u32, u64, Vec<u8>)> = expected
        .iter()
        .map(|out| (out.vout, out.value, out.script_pubkey.clone()))
        .collect();
    assert_eq!(observed, wanted, "every output must round-trip");
    Ok(())
}

#[test]
fn duplicate_final_images_match_last_engine_write_and_stats() -> TestResult {
    use bitcoin_rs_consensus::primitives::Hash256;
    use bitcoin_rs_storage::utxo::record::{OwnedUtxoOut, UtxoRecord};
    use bitcoin_rs_storage::utxo::stats::{CoinStats, CoinStatsListener};

    for delete_final in [false, true] {
        let temp = tempfile::TempDir::new()?;
        let store: Arc<dyn KvStore> = Arc::new(RocksDbStore::open(temp.path())?);
        let coins = CoinStore::open(Arc::clone(&store), 1 << 20);
        let listener = CoinStatsListener::new(CoinStats::new());
        coins.track_coin_stats(listener.clone());
        let key = coin_key(20);
        let other = coin_key(21);
        let image = |key: CoinKey, amount| -> TestResult<Bytes> {
            let record = UtxoRecord::from_owned_outputs(
                Hash256::from_le_bytes(&key.0),
                &[OwnedUtxoOut::new(0, amount, vec![0x51], false, 3)],
            )?;
            Ok(Bytes::copy_from_slice(record.bytes()))
        };
        let initial = WindowDelta {
            records: vec![
                (key, Some(image(key, 100)?)),
                (other, Some(image(other, 700)?)),
            ],
        };
        let feed = coins.plan_stats_feed(&initial)?;
        let mut batch = store.new_batch();
        coins.append_window(&mut batch, &initial)?;
        store.write_durable(batch)?;
        coins.install_committed(&initial, feed);

        let final_image = if delete_final {
            None
        } else {
            Some(image(key, 250)?)
        };
        let delta = WindowDelta {
            records: vec![
                (key, Some(image(key, 900)?)),
                (key, None),
                (key, final_image.clone()),
            ],
        };
        let feed = coins.plan_stats_feed(&delta)?;
        let mut batch = store.new_batch();
        coins.append_window(&mut batch, &delta)?;
        store.write_durable(batch)?;
        coins.install_committed(&delta, feed);

        assert_eq!(
            store
                .get(ColumnFamily::Coins, key.as_bytes())?
                .map(Bytes::from),
            final_image
        );
        assert_eq!(coins.get(&key)?, final_image);
        let stats = listener.snapshot();
        assert_eq!(stats.utxo_count, if delete_final { 1 } else { 2 });
        assert_eq!(stats.total_amount, if delete_final { 700 } else { 950 });
    }
    Ok(())
}
