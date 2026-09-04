//! Contract tests for the dedicated redb transaction-index store.

#![cfg(feature = "redb")]

use bitcoin_rs_storage::{
    ColumnFamily, KvStore, PrefixScanLimit, StorageError, WriteBatch, WriteCondition,
};

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

const MAX_SCAN: PrefixScanLimit = PrefixScanLimit {
    max_rows: 10_000,
    max_bytes: 10_000_000,
};

fn key_12(counter: u32) -> [u8; 12] {
    let mut k = [0u8; 12];
    k[0..4].copy_from_slice(&counter.to_le_bytes());
    k
}

fn header_80(counter: u32) -> [u8; 80] {
    let mut h = [0u8; 80];
    h[0..4].copy_from_slice(&counter.to_le_bytes());
    h
}

fn script_live_44(counter: u32) -> [u8; 44] {
    let mut k = [0u8; 44];
    k[0..4].copy_from_slice(&counter.to_le_bytes());
    k[40..].copy_from_slice(&counter.to_le_bytes());
    k
}

fn row_count<S: KvStore>(store: &S, cf: ColumnFamily) -> Result<usize, StorageError> {
    store
        .scan_prefix_bounded(cf, &[], MAX_SCAN)
        .map(|scan| scan.rows.len())
}

fn assert_invalid<T>(result: Result<T, StorageError>) {
    match result {
        Err(StorageError::InvalidOperation(_)) => {}
        Err(error) => panic!("expected InvalidOperation, got {error}"),
        Ok(_) => panic!("expected InvalidOperation, got success"),
    }
}

#[test]
fn txindex_all_six_family_roundtrips() -> TestResult<()> {
    let temp = tempfile::TempDir::new()?;
    let store = bitcoin_rs_storage::open_redb_tx_index_store(temp.path())?;

    let confirmed = key_12(1);
    store.put(ColumnFamily::TxConfirmed, &confirmed, b"")?;
    assert_eq!(
        store.get(ColumnFamily::TxConfirmed, &confirmed)?,
        Some(Vec::new())
    );

    let funding = key_12(2);
    store.put(ColumnFamily::Funding, &funding, b"")?;
    assert_eq!(
        store.get(ColumnFamily::Funding, &funding)?,
        Some(Vec::new())
    );

    let spending = key_12(3);
    store.put(ColumnFamily::Spending, &spending, b"")?;
    assert_eq!(
        store.get(ColumnFamily::Spending, &spending)?,
        Some(Vec::new())
    );

    let header = header_80(4);
    store.put(ColumnFamily::BlockHeaders, &header, b"")?;
    assert_eq!(
        store.get(ColumnFamily::BlockHeaders, &header)?,
        Some(Vec::new())
    );

    let live = script_live_44(5);
    store.put(ColumnFamily::ScriptLive, &live, b"")?;
    assert_eq!(
        store.get(ColumnFamily::ScriptLive, &live)?,
        Some(Vec::new())
    );

    let meta_key = b"version";
    let meta_value = b"1";
    store.put(ColumnFamily::UtxoMeta, meta_key, meta_value)?;
    assert_eq!(
        store.get(ColumnFamily::UtxoMeta, meta_key)?,
        Some(meta_value.to_vec())
    );

    let mut batch = store.new_batch();
    batch.delete(ColumnFamily::TxConfirmed, &confirmed);
    batch.delete(ColumnFamily::Funding, &funding);
    batch.delete(ColumnFamily::Spending, &spending);
    batch.delete(ColumnFamily::BlockHeaders, &header);
    batch.delete(ColumnFamily::ScriptLive, &live);
    batch.delete(ColumnFamily::UtxoMeta, meta_key);
    store.write(batch)?;

    for cf in [
        ColumnFamily::TxConfirmed,
        ColumnFamily::Funding,
        ColumnFamily::Spending,
        ColumnFamily::BlockHeaders,
        ColumnFamily::ScriptLive,
        ColumnFamily::UtxoMeta,
    ] {
        assert_eq!(row_count(&store, cf)?, 0);
    }
    Ok(())
}

#[test]
fn txindex_script_live_roundtrips_with_empty_value() -> TestResult<()> {
    let temp = tempfile::TempDir::new()?;
    let store = bitcoin_rs_storage::open_redb_tx_index_store(temp.path())?;

    let live = script_live_44(1);
    store.put(ColumnFamily::ScriptLive, &live, b"")?;
    assert_eq!(
        store.get(ColumnFamily::ScriptLive, &live)?,
        Some(Vec::new())
    );

    // Non-empty values are rejected for the fixed-width ScriptLive table.
    assert_invalid(store.put(ColumnFamily::ScriptLive, &script_live_44(2), b"value"));

    // Wrong key length is rejected before touching the database.
    assert_invalid(store.put(ColumnFamily::ScriptLive, &live[..12], b""));

    Ok(())
}

#[test]
fn generic_redb_store_enforces_script_live_row_contract() -> TestResult<()> {
    let temp = tempfile::TempDir::new()?;
    let store = bitcoin_rs_storage::RedbStore::open(temp.path())?;

    let live = script_live_44(1);
    store.put(ColumnFamily::ScriptLive, &live, b"")?;
    assert_eq!(
        store.get(ColumnFamily::ScriptLive, &live)?,
        Some(Vec::new())
    );

    // The generic store must reject the same invalid ScriptLive rows as the
    // dedicated txindex store: non-empty values and wrong-width keys.
    assert_invalid(store.put(ColumnFamily::ScriptLive, &script_live_44(2), b"value"));
    assert_invalid(store.put(ColumnFamily::ScriptLive, &live[..12], b""));

    let mut batch = store.new_batch();
    batch.put(ColumnFamily::ScriptLive, &script_live_44(3), b"value");
    assert_invalid(store.write(batch));
    assert_eq!(
        store.get(ColumnFamily::ScriptLive, &script_live_44(3))?,
        None
    );

    Ok(())
}

#[test]
fn txindex_position_values_follow_authoritative_rows() -> TestResult<()> {
    let temp = tempfile::TempDir::new()?;
    let store = bitcoin_rs_storage::open_redb_tx_index_store(temp.path())?;
    let confirmed = key_12(1);
    let funding = key_12(2);

    let mut batch = store.new_batch();
    batch.put(ColumnFamily::TxConfirmed, &confirmed, b"tx-position");
    batch.put(ColumnFamily::Funding, &funding, b"funding-position");
    store.write(batch)?;

    assert_eq!(
        store.get(ColumnFamily::TxConfirmed, &confirmed)?,
        Some(b"tx-position".to_vec())
    );
    assert_eq!(
        store.get(ColumnFamily::Funding, &funding)?,
        Some(b"funding-position".to_vec())
    );
    let rows = store
        .iter_prefix(ColumnFamily::TxConfirmed, &confirmed[..4])?
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(rows, vec![(confirmed.to_vec(), b"tx-position".to_vec())]);
    let scan = store.scan_prefix_bounded(ColumnFamily::Funding, &funding[..4], MAX_SCAN)?;
    assert_eq!(
        scan.rows,
        vec![(funding.to_vec(), b"funding-position".to_vec())]
    );

    store.put(ColumnFamily::TxConfirmed, &confirmed, b"")?;
    assert_eq!(
        store.get(ColumnFamily::TxConfirmed, &confirmed)?,
        Some(Vec::new())
    );

    let mut batch = store.new_batch();
    batch.delete(ColumnFamily::Funding, &funding);
    store.write(batch)?;
    store.put(ColumnFamily::Funding, &funding, b"")?;
    assert_eq!(
        store.get(ColumnFamily::Funding, &funding)?,
        Some(Vec::new())
    );

    let confirmed_2 = key_12(2);
    store.put(ColumnFamily::TxConfirmed, &confirmed_2, b"stale")?;
    let mut batch = store.new_batch();
    batch.delete_range(ColumnFamily::TxConfirmed, &confirmed, &key_12(3));
    store.write(batch)?;
    store.put(ColumnFamily::TxConfirmed, &confirmed_2, b"")?;
    assert_eq!(
        store.get(ColumnFamily::TxConfirmed, &confirmed_2)?,
        Some(Vec::new())
    );

    store.put(ColumnFamily::Funding, &key_12(3), b"abcd")?;
    let bounded = store.scan_prefix_bounded(
        ColumnFamily::Funding,
        &key_12(3),
        PrefixScanLimit {
            max_rows: 1,
            max_bytes: 15,
        },
    )?;
    assert_eq!(bounded.rows, vec![(key_12(3).to_vec(), b"abcd".to_vec())]);
    assert!(bounded.complete);
    Ok(())
}

#[test]
fn spending_rows_round_trip_values() -> TestResult<()> {
    let temp = tempfile::TempDir::new()?;
    let store = bitcoin_rs_storage::open_redb_tx_index_store(temp.path())?;
    let spending = key_12(3);
    let value = b"position";

    store.put(ColumnFamily::Spending, &spending, value)?;
    assert_eq!(
        store.get(ColumnFamily::Spending, &spending)?,
        Some(value.to_vec())
    );
    assert_eq!(
        store
            .scan_prefix_bounded(ColumnFamily::Spending, &spending[..4], MAX_SCAN)?
            .rows,
        vec![(spending.to_vec(), value.to_vec())]
    );

    let mut batch = store.new_batch();
    batch.delete(ColumnFamily::Spending, &spending);
    store.write(batch)?;
    assert_eq!(store.get(ColumnFamily::Spending, &spending)?, None);

    store.put(ColumnFamily::Spending, &spending, b"")?;
    assert_eq!(
        store.get(ColumnFamily::Spending, &spending)?,
        Some(Vec::new())
    );
    Ok(())
}

#[test]
fn txindex_fixed_prefix_boundaries_12() -> TestResult<()> {
    let temp = tempfile::TempDir::new()?;
    let store = bitcoin_rs_storage::open_redb_tx_index_store(temp.path())?;

    let zero = [0u8; 12];
    let mut zero_one = zero;
    zero_one[11] = 0x01;
    let mut one = zero;
    one[0] = 0x01;
    let mut one_ff = zero;
    one_ff[0] = 0x01;
    one_ff[1..].fill(0xff);
    let mut ff = zero;
    ff[0] = 0xff;
    let ff_ff = [0xffu8; 12];

    let mut batch = store.new_batch();
    for key in [&zero, &zero_one, &one, &one_ff, &ff, &ff_ff] {
        batch.put(ColumnFamily::TxConfirmed, key.as_slice(), b"");
    }
    store.write(batch)?;

    let all = store.scan_prefix_bounded(ColumnFamily::TxConfirmed, &[], MAX_SCAN)?;
    assert!(all.complete);
    assert_eq!(all.rows.len(), 6);

    let prefix_zero = store.scan_prefix_bounded(ColumnFamily::TxConfirmed, &[0x00], MAX_SCAN)?;
    assert!(prefix_zero.complete);
    let zero_keys: Vec<_> = prefix_zero.rows.iter().map(|(k, _)| k.clone()).collect();
    assert_eq!(zero_keys, vec![zero.to_vec(), zero_one.to_vec()]);

    let prefix_one = store.scan_prefix_bounded(ColumnFamily::TxConfirmed, &[0x01], MAX_SCAN)?;
    assert!(prefix_one.complete);
    let one_keys: Vec<_> = prefix_one.rows.iter().map(|(k, _)| k.clone()).collect();
    assert_eq!(one_keys, vec![one.to_vec(), one_ff.to_vec()]);

    let prefix_ff = store.scan_prefix_bounded(ColumnFamily::TxConfirmed, &[0xff], MAX_SCAN)?;
    assert!(prefix_ff.complete);
    let ff_keys: Vec<_> = prefix_ff.rows.iter().map(|(k, _)| k.clone()).collect();
    assert_eq!(ff_keys, vec![ff.to_vec(), ff_ff.to_vec()]);

    // Adjacent prefixes are disjoint.
    assert!(zero_keys.iter().all(|k| !one_keys.contains(k)));

    // Exact 12-byte prefix matches one row.
    let exact = store.scan_prefix_bounded(ColumnFamily::TxConfirmed, &zero, MAX_SCAN)?;
    assert!(exact.complete);
    assert_eq!(exact.rows.len(), 1);

    // Prefix longer than the fixed key width is rejected.
    assert_invalid(store.iter_prefix(ColumnFamily::TxConfirmed, &[0x00; 13]));
    assert_invalid(store.scan_prefix_bounded(ColumnFamily::TxConfirmed, &[0x00; 13], MAX_SCAN));

    Ok(())
}

#[test]
fn txindex_fixed_prefix_boundaries_80() -> TestResult<()> {
    let temp = tempfile::TempDir::new()?;
    let store = bitcoin_rs_storage::open_redb_tx_index_store(temp.path())?;

    let zero = [0u8; 80];
    let mut zero_one = zero;
    zero_one[79] = 0x01;
    let mut one = zero;
    one[0] = 0x01;
    let mut one_ff = zero;
    one_ff[0] = 0x01;
    one_ff[1..].fill(0xff);
    let mut ff = zero;
    ff[0] = 0xff;
    let ff_ff = [0xffu8; 80];

    let mut batch = store.new_batch();
    for key in [&zero, &zero_one, &one, &one_ff, &ff, &ff_ff] {
        batch.put(ColumnFamily::BlockHeaders, key.as_slice(), b"");
    }
    store.write(batch)?;

    let prefix_zero = store.scan_prefix_bounded(ColumnFamily::BlockHeaders, &[0x00], MAX_SCAN)?;
    assert!(prefix_zero.complete);
    let zero_keys: Vec<_> = prefix_zero.rows.iter().map(|(k, _)| k.clone()).collect();
    assert_eq!(zero_keys, vec![zero.to_vec(), zero_one.to_vec()]);

    let prefix_one = store.scan_prefix_bounded(ColumnFamily::BlockHeaders, &[0x01], MAX_SCAN)?;
    assert!(prefix_one.complete);
    let one_keys: Vec<_> = prefix_one.rows.iter().map(|(k, _)| k.clone()).collect();
    assert_eq!(one_keys, vec![one.to_vec(), one_ff.to_vec()]);

    let prefix_ff = store.scan_prefix_bounded(ColumnFamily::BlockHeaders, &[0xff], MAX_SCAN)?;
    assert!(prefix_ff.complete);
    let ff_keys: Vec<_> = prefix_ff.rows.iter().map(|(k, _)| k.clone()).collect();
    assert_eq!(ff_keys, vec![ff.to_vec(), ff_ff.to_vec()]);

    // Adjacent prefixes are disjoint.
    assert!(zero_keys.iter().all(|k| !one_keys.contains(k)));

    // Exact 80-byte prefix matches one row.
    let exact = store.scan_prefix_bounded(ColumnFamily::BlockHeaders, &zero, MAX_SCAN)?;
    assert!(exact.complete);
    assert_eq!(exact.rows.len(), 1);

    // Prefix longer than the fixed key width is rejected.
    assert_invalid(store.iter_prefix(ColumnFamily::BlockHeaders, &[0x00; 81]));
    assert_invalid(store.scan_prefix_bounded(ColumnFamily::BlockHeaders, &[0x00; 81], MAX_SCAN));

    Ok(())
}

#[test]
fn txindex_bounded_scan_empty_values() -> TestResult<()> {
    let temp = tempfile::TempDir::new()?;
    let store = bitcoin_rs_storage::open_redb_tx_index_store(temp.path())?;

    let mut batch = store.new_batch();
    for i in 0..5u32 {
        batch.put(ColumnFamily::TxConfirmed, &key_12(i), b"");
    }
    store.write(batch)?;

    let limited = store.scan_prefix_bounded(
        ColumnFamily::TxConfirmed,
        &[],
        PrefixScanLimit {
            max_rows: 2,
            max_bytes: usize::MAX,
        },
    )?;
    assert_eq!(limited.rows.len(), 2);
    assert!(!limited.complete);

    let byte_limited = store.scan_prefix_bounded(
        ColumnFamily::TxConfirmed,
        &[],
        PrefixScanLimit {
            max_rows: usize::MAX,
            max_bytes: 24,
        },
    )?;
    assert_eq!(byte_limited.rows.len(), 2);
    assert!(!byte_limited.complete);

    let exact = store.scan_prefix_bounded(
        ColumnFamily::TxConfirmed,
        &[],
        PrefixScanLimit {
            max_rows: 5,
            max_bytes: usize::MAX,
        },
    )?;
    assert_eq!(exact.rows.len(), 5);
    assert!(exact.complete);

    // Every fixed-table value is synthesized as empty.
    for (_key, value) in exact.rows {
        assert!(value.is_empty());
    }

    Ok(())
}

#[test]
fn txindex_mixed_batch_ordering_and_interleaved_cf() -> TestResult<()> {
    let temp = tempfile::TempDir::new()?;
    let store = bitcoin_rs_storage::open_redb_tx_index_store(temp.path())?;

    let k1 = key_12(1);
    let k2 = key_12(2);
    let k3 = key_12(3);
    let k4 = key_12(4);

    // Put, overwrite, delete, and put within one column family.
    let mut batch = store.new_batch();
    batch.put(ColumnFamily::TxConfirmed, &k1, b"");
    batch.put(ColumnFamily::TxConfirmed, &k2, b"");
    batch.delete(ColumnFamily::TxConfirmed, &k1);
    batch.put(ColumnFamily::TxConfirmed, &k3, b"");
    batch.delete_range(ColumnFamily::TxConfirmed, &k2, &k3); // deletes k2 only
    batch.put(ColumnFamily::TxConfirmed, &k4, b"");
    store.write(batch)?;

    let confirmed = store.scan_prefix_bounded(ColumnFamily::TxConfirmed, &[], MAX_SCAN)?;
    let keys: Vec<_> = confirmed.rows.into_iter().map(|(k, _)| k).collect();
    assert_eq!(keys, vec![k3.to_vec(), k4.to_vec()]);

    // Interleave operations across TxConfirmed and Funding.
    let mut f1 = key_12(0);
    f1[0] = 0x10;
    let mut f2 = key_12(0);
    f2[0] = 0x11;
    let mut batch = store.new_batch();
    batch.put(ColumnFamily::TxConfirmed, &k1, b"");
    batch.put(ColumnFamily::Funding, &f1, b"");
    batch.delete(ColumnFamily::TxConfirmed, &k1);
    batch.put(ColumnFamily::Funding, &f2, b"");
    batch.delete(ColumnFamily::Funding, &f1);
    batch.put(ColumnFamily::TxConfirmed, &k2, b"");
    store.write(batch)?;

    assert!(store.get(ColumnFamily::TxConfirmed, &k1)?.is_none());
    assert!(store.get(ColumnFamily::TxConfirmed, &k2)?.is_some());
    assert!(store.get(ColumnFamily::Funding, &f1)?.is_none());
    assert!(store.get(ColumnFamily::Funding, &f2)?.is_some());

    Ok(())
}

#[test]
fn txindex_invalid_operation_aborts_transaction() -> TestResult<()> {
    let temp = tempfile::TempDir::new()?;
    let store = bitcoin_rs_storage::open_redb_tx_index_store(temp.path())?;

    // Invalid key length aborts a batch that already has a valid op.
    let mut batch = store.new_batch();
    let valid = key_12(1);
    batch.put(ColumnFamily::TxConfirmed, &valid, b"");
    batch.put(ColumnFamily::TxConfirmed, &[0u8; 11], b"");
    assert_invalid(store.write(batch));
    assert!(store.get(ColumnFamily::TxConfirmed, &valid)?.is_none());

    // Non-empty value on a unit-valued fixed-width table aborts the batch.
    let mut batch = store.new_batch();
    batch.put(ColumnFamily::TxConfirmed, &valid, b"");
    batch.put(ColumnFamily::Spending, &key_12(2), b"non-empty");
    batch.put(ColumnFamily::ScriptLive, &script_live_44(2), b"non-empty");
    assert_invalid(store.write(batch));
    assert!(store.get(ColumnFamily::TxConfirmed, &valid)?.is_none());
    assert!(store.get(ColumnFamily::Spending, &key_12(2))?.is_none());
    assert!(
        store
            .get(ColumnFamily::ScriptLive, &script_live_44(2))?
            .is_none()
    );

    let mut batch = store.new_batch();
    batch.put(ColumnFamily::TxConfirmed, &valid, b"");
    let header = header_80(2);
    batch.put(ColumnFamily::BlockHeaders, &header, b"non-empty");
    assert_invalid(store.write(batch));
    assert!(store.get(ColumnFamily::TxConfirmed, &valid)?.is_none());
    assert!(store.get(ColumnFamily::BlockHeaders, &header)?.is_none());

    // Delete with an invalid key length aborts the batch.
    let mut batch = store.new_batch();
    batch.put(ColumnFamily::Spending, &key_12(3), b"");
    batch.delete(ColumnFamily::Spending, &[0u8; 13]);
    assert_invalid(store.write(batch));
    assert!(store.get(ColumnFamily::Spending, &key_12(3))?.is_none());

    // Delete range with non-exact-width bounds aborts the batch.
    let mut batch = store.new_batch();
    batch.put(ColumnFamily::BlockHeaders, &header_80(1), b"");
    batch.delete_range(ColumnFamily::BlockHeaders, &[0u8; 79], &[0u8; 80]);
    assert_invalid(store.write(batch));
    assert!(
        store
            .get(ColumnFamily::BlockHeaders, &header_80(1))?
            .is_none()
    );

    Ok(())
}

#[test]
fn txindex_unsupported_column_families_rejected() -> TestResult<()> {
    let temp = tempfile::TempDir::new()?;
    let store = bitcoin_rs_storage::open_redb_tx_index_store(temp.path())?;

    for cf in [
        ColumnFamily::TxMempool,
        ColumnFamily::Coinstats,
        ColumnFamily::BlockTree,
        ColumnFamily::BlockBodies,
        ColumnFamily::UndoData,
    ] {
        assert_invalid(store.get(cf, b"key"));
        assert_invalid(store.put(cf, b"key", b"value"));
        assert_invalid(store.iter_prefix(cf, b"key"));
        assert_invalid(store.scan_prefix_bounded(cf, b"key", MAX_SCAN));
        assert_invalid(store.write_durable_if(
            &[WriteCondition::Equals {
                cf,
                key: b"key",
                expected: b"value",
            }],
            store.new_batch(),
        ));
    }

    Ok(())
}

#[test]
fn txindex_snapshot_isolation() -> TestResult<()> {
    let temp = tempfile::TempDir::new()?;
    let store = bitcoin_rs_storage::open_redb_tx_index_store(temp.path())?;

    let k1 = key_12(1);
    store.put(ColumnFamily::TxConfirmed, &k1, b"old")?;

    let snapshot = store.snapshot()?;

    let k2 = key_12(2);
    let mut batch = store.new_batch();
    batch.put(ColumnFamily::TxConfirmed, &k1, b"new");
    batch.put(ColumnFamily::TxConfirmed, &k2, b"second");
    store.write(batch)?;

    let snap_scan = snapshot.scan_prefix_bounded(ColumnFamily::TxConfirmed, &[], MAX_SCAN)?;
    assert_eq!(snap_scan.rows, vec![(k1.to_vec(), b"old".to_vec())]);

    let fresh = store.snapshot()?;
    let fresh_scan = fresh.scan_prefix_bounded(ColumnFamily::TxConfirmed, &[], MAX_SCAN)?;
    assert_eq!(
        fresh_scan.rows,
        vec![
            (k1.to_vec(), b"new".to_vec()),
            (k2.to_vec(), b"second".to_vec()),
        ]
    );

    let snap_scan2 = snapshot.scan_prefix_bounded(ColumnFamily::TxConfirmed, &[], MAX_SCAN)?;
    assert_eq!(snap_scan2.rows, vec![(k1.to_vec(), b"old".to_vec())]);
    Ok(())
}

#[test]
fn txindex_durable_reopen() -> TestResult<()> {
    let temp = tempfile::TempDir::new()?;
    let k = key_12(42);
    let h = header_80(42);
    let meta_key = b"watermark";
    let meta_value = b"123:abcd";

    {
        let store = bitcoin_rs_storage::open_redb_tx_index_store(temp.path())?;
        let mut batch = store.new_batch();
        batch.put(ColumnFamily::TxConfirmed, &k, b"");
        batch.put(ColumnFamily::BlockHeaders, &h, b"");
        batch.put(ColumnFamily::UtxoMeta, meta_key, meta_value);
        store.write(batch)?;
    }

    let store = bitcoin_rs_storage::open_redb_tx_index_store(temp.path())?;
    assert!(store.get(ColumnFamily::TxConfirmed, &k)?.is_some());
    assert!(store.get(ColumnFamily::BlockHeaders, &h)?.is_some());
    assert_eq!(
        store.get(ColumnFamily::UtxoMeta, meta_key)?,
        Some(meta_value.to_vec())
    );

    Ok(())
}

#[test]
fn txindex_deferred_write_flush_and_reopen() -> TestResult<()> {
    let temp = tempfile::TempDir::new()?;
    let store = bitcoin_rs_storage::open_redb_tx_index_store(temp.path())?;

    let k = key_12(7);
    let mut batch = store.new_batch();
    batch.put(ColumnFamily::Funding, &k, b"");
    store.write_deferred(batch)?;
    assert!(store.get(ColumnFamily::Funding, &k)?.is_some());

    store.flush()?;
    drop(store);

    let reopened = bitcoin_rs_storage::open_redb_tx_index_store(temp.path())?;
    assert!(reopened.get(ColumnFamily::Funding, &k)?.is_some());

    Ok(())
}

#[test]
fn txindex_write_durable_if_roundtrip() -> TestResult<()> {
    let temp = tempfile::TempDir::new()?;
    let store = bitcoin_rs_storage::open_redb_tx_index_store(temp.path())?;

    // Paired fixed+value tables: mismatch preserves the authoritative row and
    // its value twin, exact match removes both, repeat claims stay false.
    let confirmed = key_12(1);
    store.put(ColumnFamily::TxConfirmed, &confirmed, b"position")?;
    assert!(!store.write_durable_if(
        &[WriteCondition::Equals {
            cf: ColumnFamily::TxConfirmed,
            key: &confirmed,
            expected: b"wrong",
        }],
        store.new_batch(),
    )?);
    assert_eq!(
        store.get(ColumnFamily::TxConfirmed, &confirmed)?,
        Some(b"position".to_vec())
    );
    let mut batch = store.new_batch();
    batch.put(ColumnFamily::TxConfirmed, &key_12(99), b"swept");
    batch.put(ColumnFamily::UtxoMeta, b"side", b"effect");
    assert!(!store.write_durable_if(
        &[WriteCondition::Equals {
            cf: ColumnFamily::TxConfirmed,
            key: &confirmed,
            expected: b"stale-position",
        }],
        batch,
    )?);
    assert_eq!(store.get(ColumnFamily::TxConfirmed, &key_12(99))?, None);
    assert_eq!(store.get(ColumnFamily::UtxoMeta, b"side")?, None);
    let mut batch = store.new_batch();
    batch.delete(ColumnFamily::TxConfirmed, &confirmed);
    assert!(store.write_durable_if(
        &[WriteCondition::Equals {
            cf: ColumnFamily::TxConfirmed,
            key: &confirmed,
            expected: b"position",
        }],
        batch,
    )?);
    assert_eq!(store.get(ColumnFamily::TxConfirmed, &confirmed)?, None);
    assert!(!store.write_durable_if(
        &[WriteCondition::Equals {
            cf: ColumnFamily::TxConfirmed,
            key: &confirmed,
            expected: b"position",
        }],
        store.new_batch(),
    )?);
    Ok(())
}

#[test]
fn txindex_write_durable_if_unit_tables() -> TestResult<()> {
    let temp = tempfile::TempDir::new()?;
    let store = bitcoin_rs_storage::open_redb_tx_index_store(temp.path())?;

    // Empty values are represented by absent entries in paired value tables.
    let funding = key_12(2);
    store.put(ColumnFamily::Funding, &funding, b"")?;
    assert!(!store.write_durable_if(
        &[WriteCondition::Equals {
            cf: ColumnFamily::Funding,
            key: &funding,
            expected: b"nonempty",
        }],
        store.new_batch(),
    )?);
    assert!(store.get(ColumnFamily::Funding, &funding)?.is_some());
    let mut batch = store.new_batch();
    batch.delete(ColumnFamily::Funding, &funding);
    assert!(store.write_durable_if(
        &[WriteCondition::Equals {
            cf: ColumnFamily::Funding,
            key: &funding,
            expected: b"",
        }],
        batch,
    )?);
    assert_eq!(store.get(ColumnFamily::Funding, &funding)?, None);

    let spending = key_12(3);
    store.put(ColumnFamily::Spending, &spending, b"")?;
    let mut batch = store.new_batch();
    batch.delete(ColumnFamily::Spending, &spending);
    assert!(store.write_durable_if(
        &[WriteCondition::Equals {
            cf: ColumnFamily::Spending,
            key: &spending,
            expected: b"",
        }],
        batch,
    )?);
    assert_eq!(store.get(ColumnFamily::Spending, &spending)?, None);

    let header = header_80(4);
    store.put(ColumnFamily::BlockHeaders, &header, b"")?;
    let mut batch = store.new_batch();
    batch.delete(ColumnFamily::BlockHeaders, &header);
    assert!(store.write_durable_if(
        &[WriteCondition::Equals {
            cf: ColumnFamily::BlockHeaders,
            key: &header,
            expected: b"",
        }],
        batch,
    )?);
    assert_eq!(store.get(ColumnFamily::BlockHeaders, &header)?, None);

    let live = script_live_44(5);
    store.put(ColumnFamily::ScriptLive, &live, b"")?;
    let mut batch = store.new_batch();
    batch.delete(ColumnFamily::ScriptLive, &live);
    assert!(store.write_durable_if(
        &[WriteCondition::Equals {
            cf: ColumnFamily::ScriptLive,
            key: &live,
            expected: b"",
        }],
        batch,
    )?);
    assert_eq!(store.get(ColumnFamily::ScriptLive, &live)?, None);
    Ok(())
}

#[test]
fn txindex_write_durable_if_metadata_and_widths() -> TestResult<()> {
    let temp = tempfile::TempDir::new()?;
    let store = bitcoin_rs_storage::open_redb_tx_index_store(temp.path())?;

    // Byte-keyed metadata compares real values.
    let meta_key = b"cursor";
    store.put(ColumnFamily::UtxoMeta, meta_key, b"52-bytes-of-cursor")?;
    assert!(!store.write_durable_if(
        &[WriteCondition::Equals {
            cf: ColumnFamily::UtxoMeta,
            key: meta_key,
            expected: b"different",
        }],
        store.new_batch(),
    )?);
    let mut batch = store.new_batch();
    batch.delete(ColumnFamily::UtxoMeta, meta_key);
    assert!(store.write_durable_if(
        &[WriteCondition::Equals {
            cf: ColumnFamily::UtxoMeta,
            key: meta_key,
            expected: b"52-bytes-of-cursor",
        }],
        batch,
    )?);
    assert_eq!(store.get(ColumnFamily::UtxoMeta, meta_key)?, None);

    // Absent claims work per family too.
    let absent = key_12(5);
    let mut batch = store.new_batch();
    batch.put(ColumnFamily::TxConfirmed, &absent, b"");
    assert!(store.write_durable_if(
        &[WriteCondition::Absent {
            cf: ColumnFamily::TxConfirmed,
            key: &absent,
        }],
        batch,
    )?);
    assert_eq!(
        store.get(ColumnFamily::TxConfirmed, &absent)?,
        Some(Vec::new())
    );

    // Wrong-width keys are rejected before any transaction begins.
    assert_invalid(store.write_durable_if(
        &[WriteCondition::Equals {
            cf: ColumnFamily::Spending,
            key: &[0u8; 11],
            expected: b"",
        }],
        store.new_batch(),
    ));
    assert_invalid(store.write_durable_if(
        &[WriteCondition::Equals {
            cf: ColumnFamily::BlockHeaders,
            key: &[0u8; 79],
            expected: b"",
        }],
        store.new_batch(),
    ));
    assert_invalid(store.write_durable_if(
        &[WriteCondition::Equals {
            cf: ColumnFamily::ScriptLive,
            key: &[0u8; 43],
            expected: b"",
        }],
        store.new_batch(),
    ));

    // Every condition is validated before the transaction begins, not only
    // the first: a valid lead condition does not admit a bad-width follower,
    // and the rejected batch touches nothing.
    let untouched = key_12(6);
    let mut batch = store.new_batch();
    batch.put(ColumnFamily::TxConfirmed, &untouched, b"touched");
    assert_invalid(store.write_durable_if(
        &[
            WriteCondition::Absent {
                cf: ColumnFamily::TxConfirmed,
                key: &untouched,
            },
            WriteCondition::Equals {
                cf: ColumnFamily::Spending,
                key: &[0u8; 11],
                expected: b"",
            },
        ],
        batch,
    ));
    assert_eq!(store.get(ColumnFamily::TxConfirmed, &untouched)?, None);

    Ok(())
}

#[test]
fn txindex_isolated_from_legacy_redb_store() -> TestResult<()> {
    let temp = tempfile::TempDir::new()?;

    // Populate the generic RedbStore tables and metadata.
    {
        let store = bitcoin_rs_storage::RedbStore::open(temp.path())?;
        store.put(
            ColumnFamily::BlockBodies,
            b"old-body-key",
            b"old-body-value",
        )?;
        store.put(ColumnFamily::UtxoMeta, b"old-meta-key", b"old-meta-value")?;
    }

    // Open the TxIndex store on the same database and add index rows.
    {
        let store = bitcoin_rs_storage::open_redb_tx_index_store(temp.path())?;
        let k = key_12(9);
        let h = header_80(9);
        let mut batch = store.new_batch();
        batch.put(ColumnFamily::TxConfirmed, &k, b"");
        batch.put(ColumnFamily::BlockHeaders, &h, b"");
        batch.put(ColumnFamily::UtxoMeta, b"txindex-meta", b"txindex-value");
        store.write(batch)?;
    }

    // The legacy RedbStore still sees its original data and is unaffected.
    {
        let store = bitcoin_rs_storage::RedbStore::open(temp.path())?;
        assert_eq!(
            store.get(ColumnFamily::BlockBodies, b"old-body-key")?,
            Some(b"old-body-value".to_vec())
        );
        assert_eq!(
            store.get(ColumnFamily::UtxoMeta, b"old-meta-key")?,
            Some(b"old-meta-value".to_vec())
        );
    }

    // The TxIndex store still sees its own data after the legacy store reopens.
    {
        let store = bitcoin_rs_storage::open_redb_tx_index_store(temp.path())?;
        assert!(store.get(ColumnFamily::TxConfirmed, &key_12(9))?.is_some());
        assert!(
            store
                .get(ColumnFamily::BlockHeaders, &header_80(9))?
                .is_some()
        );
        assert_eq!(
            store.get(ColumnFamily::UtxoMeta, b"txindex-meta")?,
            Some(b"txindex-value".to_vec())
        );
    }

    Ok(())
}
