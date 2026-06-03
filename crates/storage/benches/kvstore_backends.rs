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
const SINGLE_BLOCK_BODY_PUT_ROWS: u32 = 1_000;
const BLOCK_BODY_VALUE_BYTES: usize = 16 * 1024;

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

fn bench_single_block_body_puts_1k<S, Open>(c: &mut Criterion, backend: &str, open: Open)
where
    S: KvStore,
    Open: Fn(&Path) -> Result<S, StorageError> + Copy,
{
    c.bench_function(&format!("{backend}/bench_single_block_body_puts_1k"), |b| {
        b.iter_batched(
            || {
                let temp = must(tempfile::TempDir::new());
                let store = must(open(temp.path()));
                let value = vec![0xa5; BLOCK_BODY_VALUE_BYTES];
                (temp, store, value)
            },
            |(_temp, store, value)| {
                for counter in 0_u32..SINGLE_BLOCK_BODY_PUT_ROWS {
                    let key = block_body_like_key(counter);
                    must(store.put(ColumnFamily::BlockBodies, &key, &value));
                }
                must(store.flush());
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_single_block_body_batch_puts_1k<S, Open>(c: &mut Criterion, backend: &str, open: Open)
where
    S: KvStore,
    Open: Fn(&Path) -> Result<S, StorageError> + Copy,
{
    c.bench_function(
        &format!("{backend}/bench_single_block_body_batch_puts_1k"),
        |b| {
            b.iter_batched(
                || {
                    let temp = must(tempfile::TempDir::new());
                    let store = must(open(temp.path()));
                    let value = vec![0xa5; BLOCK_BODY_VALUE_BYTES];
                    (temp, store, value)
                },
                |(_temp, store, value)| {
                    let mut batch = store.new_batch();
                    for counter in 0_u32..SINGLE_BLOCK_BODY_PUT_ROWS {
                        let key = block_body_like_key(counter);
                        batch.put(ColumnFamily::BlockBodies, &key, &value);
                    }
                    must(store.write(batch));
                    must(store.flush());
                },
                BatchSize::SmallInput,
            );
        },
    );
}

fn bench_single_block_body_gets_1k<S, Open>(c: &mut Criterion, backend: &str, open: Open)
where
    S: KvStore,
    Open: Fn(&Path) -> Result<S, StorageError> + Copy,
{
    let temp = must(tempfile::TempDir::new());
    let store = must(open(temp.path()));
    let value = vec![0xa5; BLOCK_BODY_VALUE_BYTES];
    for counter in 0_u32..SINGLE_BLOCK_BODY_PUT_ROWS {
        let key = block_body_like_key(counter);
        must(store.put(ColumnFamily::BlockBodies, &key, &value));
    }
    must(store.flush());

    c.bench_function(&format!("{backend}/bench_single_block_body_gets_1k"), |b| {
        b.iter(|| {
            for counter in 0_u32..SINGLE_BLOCK_BODY_PUT_ROWS {
                let key = block_body_like_key(counter);
                black_box(must(store.get(ColumnFamily::BlockTree, &key)));
            }
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

fn block_body_like_key(height: u32) -> [u8; 37] {
    let mut key = [0_u8; 37];
    key[0] = b'b';
    key[1..5].copy_from_slice(&height.to_be_bytes());
    // Keep this bench crate independent of pruning while preserving the same key shape.
    for chunk in key[5..].chunks_exact_mut(size_of::<u32>()) {
        chunk.copy_from_slice(&height.to_le_bytes());
    }
    key
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

fn bench_backend<S, Open>(c: &mut Criterion, backend: &str, open: Open)
where
    S: KvStore,
    Open: Fn(&Path) -> Result<S, StorageError> + Copy,
{
    bench_sequential_writes_1m::<S, _>(c, backend, open);
    bench_random_writes_1m::<S, _>(c, backend, open);
    bench_point_get_1m::<S, _>(c, backend, open);
    bench_prefix_iter_100k::<S, _>(c, backend, open);
    bench_mixed_16thread_workload::<S, _>(c, backend, open);
    bench_single_block_body_puts_1k::<S, _>(c, backend, open);
    bench_single_block_body_batch_puts_1k::<S, _>(c, backend, open);
    bench_single_block_body_gets_1k::<S, _>(c, backend, open);
}

fn benches(c: &mut Criterion) {
    #[cfg(feature = "rocksdb")]
    bench_backend::<bitcoin_rs_storage::RocksDbStore, _>(c, "rocksdb", |path| {
        bitcoin_rs_storage::RocksDbStore::open(path)
    });

    #[cfg(feature = "fjall")]
    bench_backend::<bitcoin_rs_storage::FjallStore, _>(c, "fjall", |path| {
        bitcoin_rs_storage::FjallStore::open(path)
    });

    #[cfg(feature = "redb")]
    bench_backend::<bitcoin_rs_storage::RedbStore, _>(c, "redb", |path| {
        bitcoin_rs_storage::RedbStore::open(path)
    });

    #[cfg(feature = "mdbx")]
    bench_backend::<bitcoin_rs_storage::MdbxStore, _>(c, "mdbx", |path| {
        bitcoin_rs_storage::MdbxStore::open(path)
    });
}

criterion_group!(kvstore_backends, benches);
criterion_main!(kvstore_backends);
