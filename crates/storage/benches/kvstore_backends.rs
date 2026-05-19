//! Criterion benchmarks for the storage backends.
// SPEC: Criterion generates undocumented harness functions in bench targets.
#![allow(missing_docs)]

use std::{hint::black_box, path::Path};

use bitcoin_rs_storage::{ColumnFamily, KvStore, StorageError, WriteBatch};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};

const WRITE_ROWS: u32 = 1_000_000;
const READ_ROWS: u32 = 1_000_000;
const PREFIX_ROWS: u32 = 100_000;
const MIXED_THREADS: usize = 16;
const MIXED_ROWS_PER_THREAD: u32 = 62_500;

fn bench_sequential_writes_1m<S, Open>(c: &mut Criterion, backend: &str, open: Open)
where
    S: KvStore,
    Open: Fn(&Path) -> Result<S, StorageError> + Copy,
{
    c.bench_function(&format!("{backend}/bench_sequential_writes_1m"), |b| {
        b.iter_batched(
            || {
                let temp = must(tempfile::TempDir::new());
                let store = must(open(temp.path()));
                (temp, store)
            },
            |(_temp, store)| {
                let mut batch = store.new_batch();
                for counter in 0_u32..WRITE_ROWS {
                    let key = counter.to_le_bytes();
                    batch.put(ColumnFamily::TxConfirmed, &key, &key);
                }
                must(store.write(batch));
                must(store.flush());
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_random_writes_1m<S, Open>(c: &mut Criterion, backend: &str, open: Open)
where
    S: KvStore,
    Open: Fn(&Path) -> Result<S, StorageError> + Copy,
{
    c.bench_function(&format!("{backend}/bench_random_writes_1m"), |b| {
        b.iter_batched(
            || {
                let temp = must(tempfile::TempDir::new());
                let store = must(open(temp.path()));
                (temp, store)
            },
            |(_temp, store)| {
                let mut batch = store.new_batch();
                let mut state = 0x9e37_79b9_u32;
                for _ in 0_u32..WRITE_ROWS {
                    state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                    let key = state.to_le_bytes();
                    batch.put(ColumnFamily::TxConfirmed, &key, &key);
                }
                must(store.write(batch));
                must(store.flush());
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_point_get_1m<S, Open>(c: &mut Criterion, backend: &str, open: Open)
where
    S: KvStore,
    Open: Fn(&Path) -> Result<S, StorageError> + Copy,
{
    let temp = must(tempfile::TempDir::new());
    let store = must(open(temp.path()));
    write_rows(&store, READ_ROWS);

    c.bench_function(&format!("{backend}/bench_point_get_1m"), |b| {
        b.iter(|| {
            for counter in 0_u32..READ_ROWS {
                let key = counter.to_le_bytes();
                black_box(must(store.get(ColumnFamily::TxConfirmed, &key)));
            }
        });
    });
}

fn bench_prefix_iter_100k<S, Open>(c: &mut Criterion, backend: &str, open: Open)
where
    S: KvStore,
    Open: Fn(&Path) -> Result<S, StorageError> + Copy,
{
    let temp = must(tempfile::TempDir::new());
    let store = must(open(temp.path()));
    let mut batch = store.new_batch();
    for counter in 0_u32..PREFIX_ROWS {
        let key = prefixed_key(counter);
        batch.put(ColumnFamily::TxConfirmed, &key, &key);
    }
    must(store.write(batch));

    c.bench_function(&format!("{backend}/bench_prefix_iter_100k"), |b| {
        b.iter(|| {
            let iterator = must(store.iter_prefix(ColumnFamily::TxConfirmed, &[0x7f]));
            let rows = must(iterator.collect::<Result<Vec<_>, _>>());
            black_box(rows);
        });
    });
}

fn bench_mixed_16thread_workload<S, Open>(c: &mut Criterion, backend: &str, open: Open)
where
    S: KvStore,
    Open: Fn(&Path) -> Result<S, StorageError> + Copy,
{
    let temp = must(tempfile::TempDir::new());
    let store = must(open(temp.path()));
    write_rows(&store, MIXED_ROWS_PER_THREAD);

    c.bench_function(&format!("{backend}/bench_mixed_16thread_workload"), |b| {
        b.iter(|| {
            rayon::scope(|scope| {
                for thread in 0_usize..MIXED_THREADS {
                    let store_ref = &store;
                    scope.spawn(move |_| {
                        let thread_u32 = match u32::try_from(thread) {
                            Ok(value) => value,
                            Err(error) => panic!("thread index conversion failed: {error}"),
                        };
                        let mut batch = store_ref.new_batch();
                        for counter in 0_u32..MIXED_ROWS_PER_THREAD {
                            let read_key = counter.to_le_bytes();
                            black_box(must(store_ref.get(ColumnFamily::TxConfirmed, &read_key)));
                            let write_key = counter
                                .wrapping_add(thread_u32.wrapping_mul(MIXED_ROWS_PER_THREAD))
                                .to_le_bytes();
                            batch.put(ColumnFamily::TxMempool, &write_key, &read_key);
                        }
                        must(store_ref.write(batch));
                    });
                }
            });
            must(store.flush());
        });
    });
}

fn write_rows(store: &impl KvStore, rows: u32) {
    let mut batch = store.new_batch();
    for counter in 0_u32..rows {
        let key = counter.to_le_bytes();
        batch.put(ColumnFamily::TxConfirmed, &key, &key);
    }
    must(store.write(batch));
    must(store.flush());
}

fn prefixed_key(counter: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(5);
    key.push(0x7f);
    key.extend_from_slice(&counter.to_le_bytes());
    key
}

fn must<T, E: std::fmt::Display>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("benchmark setup failed: {error}"),
    }
}

fn benches(c: &mut Criterion) {
    #[cfg(feature = "rocksdb")]
    {
        bench_sequential_writes_1m::<bitcoin_rs_storage::RocksDbStore, _>(c, "rocksdb", |path| {
            bitcoin_rs_storage::RocksDbStore::open(path)
        });
        bench_random_writes_1m::<bitcoin_rs_storage::RocksDbStore, _>(c, "rocksdb", |path| {
            bitcoin_rs_storage::RocksDbStore::open(path)
        });
        bench_point_get_1m::<bitcoin_rs_storage::RocksDbStore, _>(c, "rocksdb", |path| {
            bitcoin_rs_storage::RocksDbStore::open(path)
        });
        bench_prefix_iter_100k::<bitcoin_rs_storage::RocksDbStore, _>(c, "rocksdb", |path| {
            bitcoin_rs_storage::RocksDbStore::open(path)
        });
        bench_mixed_16thread_workload::<bitcoin_rs_storage::RocksDbStore, _>(
            c,
            "rocksdb",
            |path| bitcoin_rs_storage::RocksDbStore::open(path),
        );
    }

    #[cfg(feature = "fjall")]
    {
        bench_sequential_writes_1m::<bitcoin_rs_storage::FjallStore, _>(c, "fjall", |path| {
            bitcoin_rs_storage::FjallStore::open(path)
        });
        bench_random_writes_1m::<bitcoin_rs_storage::FjallStore, _>(c, "fjall", |path| {
            bitcoin_rs_storage::FjallStore::open(path)
        });
        bench_point_get_1m::<bitcoin_rs_storage::FjallStore, _>(c, "fjall", |path| {
            bitcoin_rs_storage::FjallStore::open(path)
        });
        bench_prefix_iter_100k::<bitcoin_rs_storage::FjallStore, _>(c, "fjall", |path| {
            bitcoin_rs_storage::FjallStore::open(path)
        });
        bench_mixed_16thread_workload::<bitcoin_rs_storage::FjallStore, _>(c, "fjall", |path| {
            bitcoin_rs_storage::FjallStore::open(path)
        });
    }

    #[cfg(feature = "redb")]
    {
        bench_sequential_writes_1m::<bitcoin_rs_storage::RedbStore, _>(c, "redb", |path| {
            bitcoin_rs_storage::RedbStore::open(path)
        });
        bench_random_writes_1m::<bitcoin_rs_storage::RedbStore, _>(c, "redb", |path| {
            bitcoin_rs_storage::RedbStore::open(path)
        });
        bench_point_get_1m::<bitcoin_rs_storage::RedbStore, _>(c, "redb", |path| {
            bitcoin_rs_storage::RedbStore::open(path)
        });
        bench_prefix_iter_100k::<bitcoin_rs_storage::RedbStore, _>(c, "redb", |path| {
            bitcoin_rs_storage::RedbStore::open(path)
        });
        bench_mixed_16thread_workload::<bitcoin_rs_storage::RedbStore, _>(c, "redb", |path| {
            bitcoin_rs_storage::RedbStore::open(path)
        });
    }

    #[cfg(feature = "mdbx")]
    {
        bench_sequential_writes_1m::<bitcoin_rs_storage::MdbxStore, _>(c, "mdbx", |path| {
            bitcoin_rs_storage::MdbxStore::open(path)
        });
        bench_random_writes_1m::<bitcoin_rs_storage::MdbxStore, _>(c, "mdbx", |path| {
            bitcoin_rs_storage::MdbxStore::open(path)
        });
        bench_point_get_1m::<bitcoin_rs_storage::MdbxStore, _>(c, "mdbx", |path| {
            bitcoin_rs_storage::MdbxStore::open(path)
        });
        bench_prefix_iter_100k::<bitcoin_rs_storage::MdbxStore, _>(c, "mdbx", |path| {
            bitcoin_rs_storage::MdbxStore::open(path)
        });
        bench_mixed_16thread_workload::<bitcoin_rs_storage::MdbxStore, _>(c, "mdbx", |path| {
            bitcoin_rs_storage::MdbxStore::open(path)
        });
    }
}

criterion_group!(kvstore_backends, benches);
criterion_main!(kvstore_backends);
