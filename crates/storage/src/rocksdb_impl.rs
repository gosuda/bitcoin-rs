use crate::batch::{BatchOp, BufferedWriteBatch};
use bytes::Bytes;
use rust_rocksdb::checkpoint::Checkpoint;
use rust_rocksdb::{
    BlockBasedOptions, Cache, ColumnFamilyDescriptor, DBCompressionType, Direction, FlushOptions,
    IngestExternalFileOptions, IteratorMode, Options, PrefixRange, ReadOptions, SstFileWriter,
    WriteBatch as RocksWriteBatch, WriteOptions,
};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::{ColumnFamily, KvSnapshot, KvStore, StorageError, WriteCondition};

const DEFAULT_BLOCK_SIZE: usize = 4 * 1024 * 1024;
const COINS_BLOCK_SIZE: usize = 64 * 1024;
pub const ROCKSDB_DEFAULT_CACHE_BYTES: u64 = 256 * 1024 * 1024;
const LEGACY_COLUMN_FAMILIES: [&str; 1] = ["coin_records"];
const BLOOM_BITS_PER_KEY: f64 = 10.0;
const WRITE_BUFFER_SIZE: usize = 128 << 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WriteDurability {
    Default,
    Deferred,
    Durable,
}

impl WriteDurability {
    const fn label(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Deferred => "deferred",
            Self::Durable => "durable",
        }
    }

    const fn syncs(self) -> bool {
        matches!(self, Self::Durable)
    }
}

pub struct RocksDbStore {
    db: rust_rocksdb::DB,
    write_lock: parking_lot::Mutex<()>,
    cache: Cache,
    #[cfg(any(test, feature = "test-seam"))]
    faults: crate::trait_::PersistFaultSlot,
    /// Last field: drops after the database handle above has closed.
    guard: Option<crate::StoreGuard>,
}

impl RocksDbStore {
    #[must_use]
    pub fn guarded_by(self, guard: crate::StoreGuard) -> Self {
        assert!(
            self.guard.is_none(),
            "a RocksDB store takes exactly one lifetime guard"
        );
        Self {
            guard: Some(guard),
            ..self
        }
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        Self::open_with_cache(path, ROCKSDB_DEFAULT_CACHE_BYTES)
    }

    pub fn open_with_cache(path: impl AsRef<Path>, cache_bytes: u64) -> Result<Self, StorageError> {
        let cache_bytes = if cache_bytes == 0 {
            ROCKSDB_DEFAULT_CACHE_BYTES
        } else {
            cache_bytes
        };
        let cache_bytes = usize::try_from(cache_bytes).unwrap_or(usize::MAX);
        metrics::gauge!("storage.cache_capacity_bytes", "backend" => "rocksdb").set(
            bitcoin_rs_consensus::primitives::u64_to_f64(
                u64::try_from(cache_bytes).unwrap_or(u64::MAX),
            ),
        );
        let mut db_options = Options::default();
        db_options.create_if_missing(true);
        db_options.create_missing_column_families(true);
        db_options.set_compression_type(DBCompressionType::Lz4);
        db_options.set_atomic_flush(false);

        let cache = Cache::new_lru_cache(cache_bytes);
        let cf_options_for = |block_size: usize| {
            let mut table_options = BlockBasedOptions::default();
            table_options.set_block_size(block_size);
            table_options.set_block_cache(&cache);
            table_options.set_bloom_filter(BLOOM_BITS_PER_KEY, false);
            table_options.set_cache_index_and_filter_blocks(true);
            let mut cf_options = Options::default();
            cf_options.set_compression_type(DBCompressionType::Lz4);
            cf_options.set_write_buffer_size(WRITE_BUFFER_SIZE);
            cf_options.set_block_based_table_factory(&table_options);
            cf_options
        };
        let default_cf_options = cf_options_for(DEFAULT_BLOCK_SIZE);
        let coins_cf_options = cf_options_for(COINS_BLOCK_SIZE);

        let on_disk = rust_rocksdb::DB::list_cf(&db_options, path.as_ref()).unwrap_or_default();
        let legacy = LEGACY_COLUMN_FAMILIES
            .iter()
            .filter(|name| on_disk.iter().any(|found| found == *name))
            .map(|name| ColumnFamilyDescriptor::new(*name, default_cf_options.clone()));
        let descriptors = ColumnFamily::ALL
            .iter()
            .copied()
            .map(|cf| {
                let options = match cf {
                    ColumnFamily::Coins => coins_cf_options.clone(),
                    _ => default_cf_options.clone(),
                };
                ColumnFamilyDescriptor::new(cf.name(), options)
            })
            .chain(legacy);
        let db = rust_rocksdb::DB::open_cf_descriptors(&db_options, path, descriptors)
            .map_err(StorageError::backend)?;
        Ok(Self {
            db,
            write_lock: parking_lot::Mutex::new(()),
            cache,
            #[cfg(any(test, feature = "test-seam"))]
            faults: crate::trait_::PersistFaultSlot::default(),
            guard: None,
        })
    }

    fn cf_handle(&self, cf: ColumnFamily) -> Result<&rust_rocksdb::ColumnFamily, StorageError> {
        self.db
            .cf_handle(cf.name())
            .ok_or(StorageError::UnknownColumnFamily(cf))
    }

    fn rocks_batch(&self, batch: BufferedWriteBatch) -> Result<RocksWriteBatch, StorageError> {
        let mut rocks_batch = RocksWriteBatch::default();
        let mut handles = [None; ColumnFamily::ALL.len()];
        for op in batch.ops {
            match op {
                BatchOp::Put { cf, key, value } => {
                    rocks_batch.put_cf(cached_cf_handle(self, &mut handles, cf)?, key, value);
                }
                BatchOp::Delete { cf, key } => {
                    rocks_batch.delete_cf(cached_cf_handle(self, &mut handles, cf)?, key);
                }
                BatchOp::DeleteRange { cf, start, end } => {
                    rocks_batch.delete_range_cf(
                        cached_cf_handle(self, &mut handles, cf)?,
                        start,
                        end,
                    );
                }
            }
        }
        Ok(rocks_batch)
    }

    fn write_with_durability(
        &self,
        batch: BufferedWriteBatch,
        durability: WriteDurability,
    ) -> Result<(), StorageError> {
        count_write(durability.label(), batch.encoded_bytes);
        #[cfg(any(test, feature = "test-seam"))]
        if let Some(fault) = self.faults.take_at(crate::trait_::PersistBoundary::Apply) {
            return Err(fault.injected_error());
        }
        #[cfg(any(test, feature = "test-seam"))]
        let sync_fault = if durability.syncs() {
            self.faults.take_at(crate::trait_::PersistBoundary::Sync)
        } else {
            None
        };
        #[cfg(any(test, feature = "test-seam"))]
        let effective_sync = sync_fault.is_none() && durability.syncs();
        #[cfg(not(any(test, feature = "test-seam")))]
        let effective_sync = durability.syncs();
        let rocks_batch = self.rocks_batch(batch)?;
        let outcome = if effective_sync {
            let mut write_options = WriteOptions::default();
            write_options.set_sync(true);
            self.db
                .write_opt(&rocks_batch, &write_options)
                .map_err(StorageError::backend)
        } else {
            self.db.write(&rocks_batch).map_err(StorageError::backend)
        };
        outcome?;
        #[cfg(any(test, feature = "test-seam"))]
        if let Some(fault) = sync_fault {
            return Err(fault.injected_error());
        }
        Ok(())
    }
}

impl KvStore for RocksDbStore {
    fn get_bounded(
        &self,
        cf: ColumnFamily,
        key: &[u8],
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>, crate::BoundedReadError> {
        self.db
            .get_pinned_cf(self.cf_handle(cf)?, key)
            .map_err(StorageError::backend)?
            .map(|value| crate::error::copy_bounded(&value, max_bytes))
            .transpose()
    }

    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.db
            .get_cf(self.cf_handle(cf)?, key)
            .map_err(StorageError::backend)
    }

    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<crate::trait_::KvIter<'a>, StorageError> {
        let handle = self.cf_handle(cf)?;
        let prefix = prefix.to_vec();
        let iterator = self.db.iterator_cf_opt(
            handle,
            ReadOptions::default(),
            IteratorMode::From(&prefix, Direction::Forward),
        );
        Ok(Box::new(
            iterator
                .map(|item| {
                    item.map(|(key, value)| (key.to_vec(), value.to_vec()))
                        .map_err(StorageError::backend)
                })
                .take_while(move |item| match item {
                    Ok((key, _)) => key.starts_with(&prefix),
                    Err(_) => true,
                }),
        ))
    }

    fn scan_prefix_from_bounded(
        &self,
        cf: ColumnFamily,
        prefix: &[u8],
        start: &[u8],
        limit: crate::PrefixScanLimit,
    ) -> Result<crate::PrefixScan, StorageError> {
        let rows = self
            .db
            .iterator_cf_opt(
                self.cf_handle(cf)?,
                ReadOptions::default(),
                IteratorMode::From(core::cmp::max(start, prefix), Direction::Forward),
            )
            .map(|item| item.map_err(StorageError::backend));
        crate::trait_::collect_bounded_prefix(rows, prefix, limit)
    }

    fn new_batch(&self) -> BufferedWriteBatch {
        BufferedWriteBatch::default()
    }

    fn put(&self, cf: ColumnFamily, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        let _guard = self.write_lock.lock();
        self.db
            .put_cf(self.cf_handle(cf)?, key, value)
            .map_err(StorageError::backend)
    }

    fn write(&self, batch: BufferedWriteBatch) -> Result<(), StorageError> {
        let _guard = self.write_lock.lock();
        self.write_with_durability(batch, WriteDurability::Default)
    }

    fn write_deferred(&self, batch: BufferedWriteBatch) -> Result<(), StorageError> {
        let _guard = self.write_lock.lock();
        self.write_with_durability(batch, WriteDurability::Deferred)
    }

    fn write_durable(&self, batch: BufferedWriteBatch) -> Result<(), StorageError> {
        let _guard = self.write_lock.lock();
        self.write_with_durability(batch, WriteDurability::Durable)
    }

    fn write_durable_if(
        &self,
        conditions: &[WriteCondition<'_>],
        batch: BufferedWriteBatch,
    ) -> Result<bool, StorageError> {
        let _guard = self.write_lock.lock();
        let mut handles = [None; ColumnFamily::ALL.len()];
        for condition in conditions {
            let (cf, key) = condition.location();
            let handle = cached_cf_handle(self, &mut handles, cf)?;
            let current = self.db.get_cf(handle, key).map_err(StorageError::backend)?;
            if !condition.matches(current.as_deref()) {
                return Ok(false);
            }
        }
        self.write_with_durability(batch, WriteDurability::Durable)?;
        Ok(true)
    }

    fn flush(&self) -> Result<(), StorageError> {
        metrics::counter!("storage.flushes_total", "backend" => "rocksdb").increment(1);
        #[cfg(any(test, feature = "test-seam"))]
        if let Some(fault) = self.faults.take_at(crate::trait_::PersistBoundary::Flush) {
            return Err(fault.injected_error());
        }
        self.db.flush_wal(true).map_err(StorageError::backend)
    }

    fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError> {
        Ok(Box::new(RocksDbSnapshot {
            db: self,
            snapshot: self.db.snapshot(),
        }))
    }

    #[cfg(any(test, feature = "test-seam"))]
    fn arm_persist_fault(&self, fault: crate::PersistFault) {
        self.faults.arm(fault);
    }

    fn multi_get(
        &self,
        cf: ColumnFamily,
        keys: &[&[u8]],
    ) -> Result<Vec<Option<Bytes>>, StorageError> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }

        let handle = self.cf_handle(cf)?;
        let read_options = ReadOptions::default();
        let is_sorted = keys.windows(2).all(|w| w[0] <= w[1]);

        if is_sorted {
            let results =
                self.db
                    .batched_multi_get_cf_opt(handle, keys.iter().copied(), true, &read_options);
            let mut out = Vec::with_capacity(results.len());
            for res in results {
                match res {
                    Ok(Some(pinned)) => out.push(Some(Bytes::copy_from_slice(&pinned))),
                    Ok(None) => out.push(None),
                    Err(e) => return Err(StorageError::backend(e)),
                }
            }
            Ok(out)
        } else {
            let mut indexed: Vec<(usize, &&[u8])> = keys.iter().enumerate().collect();
            indexed.sort_by_key(|(_, a)| *a);
            let sorted_keys: Vec<&[u8]> = indexed.iter().map(|(_, k)| **k).collect();

            let results = self.db.batched_multi_get_cf_opt(
                handle,
                sorted_keys.iter().copied(),
                true,
                &read_options,
            );

            let mut out = vec![None; keys.len()];
            for ((orig_idx, _), res) in indexed.into_iter().zip(results) {
                match res {
                    Ok(Some(pinned)) => out[orig_idx] = Some(Bytes::copy_from_slice(&pinned)),
                    Ok(None) => out[orig_idx] = None,
                    Err(e) => return Err(StorageError::backend(e)),
                }
            }
            Ok(out)
        }
    }

    fn ingest_sorted(
        &self,
        cf: ColumnFamily,
        rows: &mut dyn Iterator<Item = (Vec<u8>, Vec<u8>)>,
        scratch: &Path,
    ) -> Result<u64, StorageError> {
        const TARGET_BYTES: u64 = 256 * 1024 * 1024;

        let _guard = self.write_lock.lock();
        let cf_handle = self.cf_handle(cf)?;
        std::fs::create_dir_all(scratch).map_err(StorageError::Io)?;

        let mut writer_opts = Options::default();
        writer_opts.set_compression_type(DBCompressionType::Lz4);

        let mut sst_paths: Vec<std::path::PathBuf> = Vec::new();
        let call_id = NEXT_INGEST_ID.fetch_add(1, Ordering::SeqCst);
        let mut file_idx = 0usize;
        let mut current_writer: Option<SstFileWriter<'_>> = None;
        let mut writer_rows = 0u64;
        let mut total_count = 0u64;
        let mut prev_key: Option<Vec<u8>> = None;

        for (k, v) in rows {
            if let Some(prev) = &prev_key {
                if k.as_slice() <= prev.as_slice() {
                    remove_scratch_files(&sst_paths);
                    return Err(StorageError::InvalidOperation(
                        "keys not strictly ascending",
                    ));
                }
            }

            let row_bytes = u64::try_from(k.len().saturating_add(v.len())).unwrap_or(u64::MAX);

            if row_bytes >= TARGET_BYTES {
                if let Some(mut w) = current_writer.take() {
                    if writer_rows > 0 {
                        w.finish().map_err(|e| {
                            remove_scratch_files(&sst_paths);
                            StorageError::backend(e)
                        })?;
                    }
                    writer_rows = 0;
                }

                let (mut solo_writer, path) =
                    create_sst_writer(scratch, call_id, file_idx, &writer_opts).inspect_err(
                        |_| {
                            remove_scratch_files(&sst_paths);
                        },
                    )?;
                sst_paths.push(path);
                file_idx += 1;
                solo_writer.put(&k, &v).map_err(|e| {
                    let _ = solo_writer.finish();
                    remove_scratch_files(&sst_paths);
                    StorageError::backend(e)
                })?;
                solo_writer.finish().map_err(|e| {
                    remove_scratch_files(&sst_paths);
                    StorageError::backend(e)
                })?;
            } else {
                if let Some(mut w) = current_writer.take() {
                    if writer_rows > 0 && w.file_size() >= TARGET_BYTES {
                        w.finish().map_err(|e| {
                            remove_scratch_files(&sst_paths);
                            StorageError::backend(e)
                        })?;
                        writer_rows = 0;
                    } else {
                        current_writer = Some(w);
                    }
                }

                if current_writer.is_none() {
                    let (w, path) = create_sst_writer(scratch, call_id, file_idx, &writer_opts)
                        .inspect_err(|_| {
                            remove_scratch_files(&sst_paths);
                        })?;
                    sst_paths.push(path);
                    file_idx += 1;
                    current_writer = Some(w);
                    writer_rows = 0;
                }

                let Some(writer) = current_writer.as_mut() else {
                    remove_scratch_files(&sst_paths);
                    return Err(StorageError::InvalidOperation("writer unavailable"));
                };
                writer.put(&k, &v).map_err(|e| {
                    let _ = writer.finish();
                    remove_scratch_files(&sst_paths);
                    StorageError::backend(e)
                })?;
                writer_rows += 1;
            }

            prev_key = Some(k);
            total_count += 1;
        }

        if let Some(mut w) = current_writer.take() {
            if writer_rows > 0 {
                w.finish().map_err(|e| {
                    remove_scratch_files(&sst_paths);
                    StorageError::backend(e)
                })?;
            }
        }

        if total_count > 0 && !sst_paths.is_empty() {
            let mut ingest_opts = IngestExternalFileOptions::default();
            ingest_opts.set_move_files(true);
            self.db
                .ingest_external_file_cf_opts(cf_handle, &ingest_opts, sst_paths.clone())
                .map_err(|e| {
                    remove_scratch_files(&sst_paths);
                    StorageError::backend(e)
                })?;
        }

        Ok(total_count)
    }

    fn delete_range(&self, cf: ColumnFamily, start: &[u8], end: &[u8]) -> Result<(), StorageError> {
        if start >= end {
            return Ok(());
        }
        let _guard = self.write_lock.lock();
        let cf_handle = self.cf_handle(cf)?;

        #[cfg(any(test, feature = "test-seam"))]
        if let Some(fault) = self.faults.take_at(crate::trait_::PersistBoundary::Apply) {
            return Err(fault.injected_error());
        }
        #[cfg(any(test, feature = "test-seam"))]
        let sync_fault = self.faults.take_at(crate::trait_::PersistBoundary::Sync);
        #[cfg(any(test, feature = "test-seam"))]
        let effective_sync = sync_fault.is_none();
        #[cfg(not(any(test, feature = "test-seam")))]
        let effective_sync = true;

        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(effective_sync);

        self.db
            .delete_range_cf_opt(cf_handle, start, end, &write_opts)
            .map_err(StorageError::backend)?;

        #[cfg(any(test, feature = "test-seam"))]
        if let Some(fault) = sync_fault {
            return Err(fault.injected_error());
        }

        Ok(())
    }

    fn checkpoint(&self, dir: &Path) -> Result<(), StorageError> {
        let mut flush_options = FlushOptions::default();
        flush_options.set_wait(true);
        for family in ColumnFamily::ALL {
            let handle = self.cf_handle(*family)?;
            self.db
                .flush_cf_opt(handle, &flush_options)
                .map_err(StorageError::backend)?;
        }
        let cp = Checkpoint::new(&self.db).map_err(StorageError::backend)?;
        cp.create_checkpoint(dir).map_err(StorageError::backend)?;
        for entry in std::fs::read_dir(dir).map_err(StorageError::Io)? {
            let entry = entry.map_err(StorageError::Io)?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if name.ends_with(".log") {
                std::fs::remove_file(entry.path()).map_err(StorageError::Io)?;
            }
        }
        Ok(())
    }

    fn engine_cache_bytes(&self) -> u64 {
        let block_cache = u64::try_from(self.cache.get_usage()).unwrap_or(u64::MAX);
        let memtables = self
            .db
            .property_int_value("rocksdb.cur-size-all-mem-tables")
            .ok()
            .flatten()
            .unwrap_or(0);
        block_cache.saturating_add(memtables)
    }
}
static NEXT_INGEST_ID: AtomicU64 = AtomicU64::new(1);

fn create_sst_writer<'opts>(
    scratch: &Path,
    call_id: u64,
    index: usize,
    opts: &'opts Options,
) -> Result<(SstFileWriter<'opts>, std::path::PathBuf), StorageError> {
    let path = scratch.join(format!("ingest-{call_id}-{index}.sst"));
    let mut writer = SstFileWriter::create(opts);
    writer.open(&path).map_err(StorageError::backend)?;
    Ok((writer, path))
}

fn remove_scratch_files(paths: &[std::path::PathBuf]) {
    for path in paths {
        let _ = std::fs::remove_file(path);
    }
}

fn count_write(durability: &'static str, encoded_bytes: usize) {
    metrics::counter!("storage.writes_total", "backend" => "rocksdb", "durability" => durability)
        .increment(1);
    metrics::histogram!("storage.write_bytes", "backend" => "rocksdb").record(
        bitcoin_rs_consensus::primitives::u64_to_f64(
            u64::try_from(encoded_bytes).unwrap_or(u64::MAX),
        ),
    );
}

fn cached_cf_handle<'store>(
    store: &'store RocksDbStore,
    handles: &mut [Option<&'store rust_rocksdb::ColumnFamily>],
    cf: ColumnFamily,
) -> Result<&'store rust_rocksdb::ColumnFamily, StorageError> {
    let slot = handles
        .get_mut(cf.index())
        .ok_or(StorageError::UnknownColumnFamily(cf))?;
    if slot.is_none() {
        *slot = Some(store.cf_handle(cf)?);
    }
    slot.ok_or(StorageError::UnknownColumnFamily(cf))
}

struct RocksDbSnapshot<'a> {
    db: &'a RocksDbStore,
    snapshot: rust_rocksdb::Snapshot<'a>,
}

impl KvSnapshot for RocksDbSnapshot<'_> {
    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.snapshot
            .get_cf(self.db.cf_handle(cf)?, key)
            .map_err(StorageError::backend)
    }

    fn get_many_sorted(
        &self,
        cf: ColumnFamily,
        keys: &[&[u8]],
    ) -> Result<Vec<Option<Vec<u8>>>, StorageError> {
        if keys.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(StorageError::InvalidOperation(
                "snapshot batch keys are not strictly ascending",
            ));
        }

        let mut read_options = ReadOptions::default();
        read_options.set_snapshot(&self.snapshot);
        self.db
            .db
            .batched_multi_get_cf_slice_opt(
                self.db.cf_handle(cf)?,
                keys.iter().copied(),
                true,
                &read_options,
            )
            .into_iter()
            .map(|result| {
                result
                    .map(|value| value.map(|pinned| pinned.as_ref().to_vec()))
                    .map_err(StorageError::backend)
            })
            .collect()
    }

    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<crate::trait_::KvIter<'a>, StorageError> {
        let handle = self.db.cf_handle(cf)?;
        let prefix = prefix.to_vec();
        let iterator = self.snapshot.iterator_cf_opt(
            handle,
            ReadOptions::default(),
            IteratorMode::From(&prefix, Direction::Forward),
        );
        Ok(Box::new(
            iterator
                .map(|item| {
                    item.map(|(key, value)| (key.to_vec(), value.to_vec()))
                        .map_err(StorageError::backend)
                })
                .take_while(move |item| match item {
                    Ok((key, _)) => key.starts_with(&prefix),
                    Err(_) => true,
                }),
        ))
    }

    fn last_prefix(
        &self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<Option<crate::KvPair>, StorageError> {
        let handle = self.db.cf_handle(cf)?;
        let prefix = prefix.to_vec();
        let mut read_opts = ReadOptions::default();
        read_opts.set_iterate_range(PrefixRange(prefix.as_slice()));
        let mut iterator = self
            .snapshot
            .iterator_cf_opt(handle, read_opts, IteratorMode::End);
        if let Some(item) = iterator.next() {
            let (key, value) = item.map_err(StorageError::backend)?;
            let key_slice: &[u8] = &key;
            let prefix_slice: &[u8] = &prefix;
            if key_slice.starts_with(prefix_slice) {
                return Ok(Some((key.to_vec(), value.to_vec())));
            }
            return Ok(None);
        }
        Ok(None)
    }

    fn scan_prefix_from_bounded(
        &self,
        cf: ColumnFamily,
        prefix: &[u8],
        start: &[u8],
        limit: crate::PrefixScanLimit,
    ) -> Result<crate::PrefixScan, StorageError> {
        let rows = self
            .snapshot
            .iterator_cf_opt(
                self.db.cf_handle(cf)?,
                ReadOptions::default(),
                IteratorMode::From(core::cmp::max(start, prefix), Direction::Forward),
            )
            .map(|item| item.map_err(StorageError::backend));
        crate::trait_::collect_bounded_prefix(rows, prefix, limit)
    }
}
