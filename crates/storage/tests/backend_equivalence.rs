//! Cross-backend equivalence tests for the storage abstraction.

use bitcoin_rs_storage::{ColumnFamily, KvIter, KvPair, KvStore, StorageError, WriteBatch};
use sha2::{Digest, Sha256};

const ROWS: u32 = 10_000;
const DELETE_ROWS: u32 = 1_000;
const RANGE_START_INDEX: usize = 1_000;
const RANGE_END_INDEX: usize = 1_500;
const PREFIX: &[u8] = &[0];

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

fn run_equivalence_suite<S: KvStore>(store: S) -> Result<[u8; 32], StorageError> {
    insert_rows(&store)?;
    verify_rows(&store)?;
    verify_prefix_iteration(&store)?;
    delete_first_rows(&store)?;
    verify_first_rows_deleted(&store)?;
    delete_range_slice(&store)?;
    store.flush()?;
    let hash = aggregate_hash(&store)?;
    drop(store);
    Ok(hash)
}

fn insert_rows(store: &impl KvStore) -> Result<(), StorageError> {
    let mut batch = store.new_batch();
    for cf in ColumnFamily::ALL.iter().copied() {
        for counter in 0_u32..ROWS {
            let key = counter.to_le_bytes();
            let value = format!("{cf:?}-{counter}").into_bytes();
            batch.put(cf, &key, &value);
        }
    }
    store.write(batch)
}

fn verify_rows(store: &impl KvStore) -> Result<(), StorageError> {
    for cf in ColumnFamily::ALL.iter().copied() {
        for counter in 0_u32..ROWS {
            let key = counter.to_le_bytes();
            let expected = format!("{cf:?}-{counter}").into_bytes();
            assert_eq!(store.get(cf, &key)?, Some(expected));
        }
    }
    Ok(())
}

fn verify_prefix_iteration(store: &impl KvStore) -> Result<(), StorageError> {
    for cf in ColumnFamily::ALL.iter().copied() {
        let mut expected = (0_u32..ROWS)
            .filter_map(|counter| {
                let key = counter.to_le_bytes();
                key.starts_with(PREFIX)
                    .then(|| (key.to_vec(), format!("{cf:?}-{counter}").into_bytes()))
            })
            .collect::<Vec<_>>();
        expected.sort_by(|left, right| left.0.cmp(&right.0));
        let actual = collect_iter(store.iter_prefix(cf, PREFIX)?)?;
        assert_eq!(actual, expected);
    }
    Ok(())
}

fn delete_first_rows(store: &impl KvStore) -> Result<(), StorageError> {
    let mut batch = store.new_batch();
    for cf in ColumnFamily::ALL.iter().copied() {
        for counter in 0_u32..DELETE_ROWS {
            batch.delete(cf, &counter.to_le_bytes());
        }
    }
    store.write(batch)
}

fn verify_first_rows_deleted(store: &impl KvStore) -> Result<(), StorageError> {
    for cf in ColumnFamily::ALL.iter().copied() {
        for counter in 0_u32..DELETE_ROWS {
            assert_eq!(store.get(cf, &counter.to_le_bytes())?, None);
        }
    }
    Ok(())
}

fn delete_range_slice(store: &impl KvStore) -> Result<(), StorageError> {
    let mut range_deleted = Vec::new();
    let mut batch = store.new_batch();
    for cf in ColumnFamily::ALL.iter().copied() {
        let rows = collect_iter(store.iter_prefix(cf, &[])?)?;
        let start = rows
            .get(RANGE_START_INDEX)
            .ok_or(StorageError::InvalidOperation("range start missing"))?
            .0
            .clone();
        let end = rows
            .get(RANGE_END_INDEX)
            .ok_or(StorageError::InvalidOperation("range end missing"))?
            .0
            .clone();
        range_deleted.extend(
            rows[RANGE_START_INDEX..RANGE_END_INDEX]
                .iter()
                .map(|(key, _)| (cf, key.clone())),
        );
        batch.delete_range(cf, &start, &end);
    }
    store.write(batch)?;

    for (cf, key) in range_deleted {
        assert_eq!(store.get(cf, &key)?, None);
    }
    Ok(())
}

fn aggregate_hash(store: &impl KvStore) -> Result<[u8; 32], StorageError> {
    let mut rows = Vec::new();
    for cf in ColumnFamily::ALL.iter().copied() {
        for item in store.iter_prefix(cf, &[])? {
            let (key, value) = item?;
            rows.push((cf, key, value));
        }
    }
    rows.sort_by(|left, right| {
        left.0
            .index()
            .cmp(&right.0.index())
            .then_with(|| left.1.cmp(&right.1))
            .then_with(|| left.2.cmp(&right.2))
    });

    let mut hasher = Sha256::new();
    for (cf, key, value) in rows {
        hasher.update(cf.name().as_bytes());
        hasher.update([0]);
        hasher.update(key);
        hasher.update([0]);
        hasher.update(value);
        hasher.update([0]);
    }
    Ok(hasher.finalize().into())
}

fn collect_iter(iterator: KvIter<'_>) -> Result<Vec<KvPair>, StorageError> {
    iterator.collect()
}

fn hash_hex(hash: &[u8; 32]) -> String {
    let mut hex = String::with_capacity(64);
    for byte in hash {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

#[cfg(feature = "rocksdb")]
#[test]
fn rocksdb_equivalence_hash() -> TestResult<()> {
    let temp = tempfile::TempDir::new()?;
    let hash = run_equivalence_suite(bitcoin_rs_storage::RocksDbStore::open(temp.path())?)?;
    eprintln!("rocksdb aggregate hash: {}", hash_hex(&hash));
    Ok(())
}

#[cfg(feature = "fjall")]
#[test]
fn fjall_equivalence_hash() -> TestResult<()> {
    let temp = tempfile::TempDir::new()?;
    let hash = run_equivalence_suite(bitcoin_rs_storage::FjallStore::open(temp.path())?)?;
    eprintln!("fjall aggregate hash: {}", hash_hex(&hash));
    Ok(())
}

#[cfg(feature = "redb")]
#[test]
fn redb_equivalence_hash() -> TestResult<()> {
    let temp = tempfile::TempDir::new()?;
    let hash = run_equivalence_suite(bitcoin_rs_storage::RedbStore::open(temp.path())?)?;
    eprintln!("redb aggregate hash: {}", hash_hex(&hash));
    Ok(())
}

#[cfg(feature = "mdbx")]
#[test]
fn mdbx_equivalence_hash() -> TestResult<()> {
    let temp = tempfile::TempDir::new()?;
    let hash = run_equivalence_suite(bitcoin_rs_storage::MdbxStore::open(temp.path())?)?;
    eprintln!("mdbx aggregate hash: {}", hash_hex(&hash));
    Ok(())
}

#[cfg(all(feature = "rocksdb", feature = "fjall", feature = "redb"))]
#[test]
fn portable_backends_have_identical_aggregate_hashes() -> TestResult<()> {
    let rocks_temp = tempfile::TempDir::new()?;
    let fjall_temp = tempfile::TempDir::new()?;
    let redb_temp = tempfile::TempDir::new()?;

    let rocksdb =
        run_equivalence_suite(bitcoin_rs_storage::RocksDbStore::open(rocks_temp.path())?)?;
    let fjall = run_equivalence_suite(bitcoin_rs_storage::FjallStore::open(fjall_temp.path())?)?;
    let redb = run_equivalence_suite(bitcoin_rs_storage::RedbStore::open(redb_temp.path())?)?;

    eprintln!("rocksdb aggregate hash: {}", hash_hex(&rocksdb));
    eprintln!("fjall aggregate hash: {}", hash_hex(&fjall));
    eprintln!("redb aggregate hash: {}", hash_hex(&redb));

    assert_eq!(rocksdb, fjall);
    assert_eq!(rocksdb, redb);
    Ok(())
}
