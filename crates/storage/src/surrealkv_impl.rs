use crate::batch::{BatchOp, BufferedWriteBatch};
use crate::{
    BoundedReadError, ColumnFamily, KvIter, KvPair, KvSnapshot, KvStore, PrefixScan,
    PrefixScanLimit, StorageError, WriteCondition,
};
use bytes::Bytes;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use surrealkv::LSMIterator;

pub const SURREALKV_DEFAULT_CACHE_BYTES: u64 = 256 * 1024 * 1024;
pub(crate) const SURREALKV_DEFAULT_MAX_MEMTABLE_BYTES: usize = 64 * 1024 * 1024;
const INGEST_BATCH_TARGET_BYTES: usize = 64 * 1024 * 1024;

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
}
fn sync_dir(dir: &Path) -> Result<(), StorageError> {
    #[cfg(unix)]
    {
        std::fs::File::open(dir)
            .and_then(|f| f.sync_all())
            .map_err(StorageError::Io)?;
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

fn write_durable_marker(path: &Path, content: &[u8]) -> Result<(), StorageError> {
    use std::io::Write;
    let mut file = std::fs::File::create(path).map_err(StorageError::Io)?;
    file.write_all(content).map_err(StorageError::Io)?;
    file.sync_all().map_err(StorageError::Io)?;
    if let Some(parent) = path.parent() {
        sync_dir(parent)?;
    }
    Ok(())
}

enum BridgeRequest {
    Commit {
        txn: surrealkv::Transaction,
        reply: std::sync::mpsc::SyncSender<Result<(), StorageError>>,
    },
    Close {
        reply: std::sync::mpsc::SyncSender<Result<(), StorageError>>,
    },
}

struct BridgeQueue {
    queue: parking_lot::Mutex<VecDeque<BridgeRequest>>,
    not_full: parking_lot::Condvar,
    notify: Arc<tokio::sync::Notify>,
    capacity: usize,
    closed: AtomicBool,
}

impl BridgeQueue {
    fn send(&self, req: BridgeRequest) -> Result<(), StorageError> {
        let mut guard = self.queue.lock();
        if self.closed.load(Ordering::Acquire) {
            return Err(StorageError::Backend(
                "surrealkv bridge is closed".to_string(),
            ));
        }
        while guard.len() >= self.capacity {
            self.not_full.wait(&mut guard);
            if self.closed.load(Ordering::Acquire) {
                return Err(StorageError::Backend(
                    "surrealkv bridge is closed".to_string(),
                ));
            }
        }
        guard.push_back(req);
        drop(guard);
        self.notify.notify_one();
        Ok(())
    }
}

pub(crate) const ITER_PREFIX_PAGE_SIZE: usize = 64;

#[derive(Clone)]
enum CloseState {
    Open,
    Closing,
    Closed(Result<(), String>),
}

struct BridgeHandle {
    queue: Arc<BridgeQueue>,
    worker_thread: parking_lot::Mutex<Option<std::thread::JoinHandle<()>>>,
    close_state: parking_lot::Mutex<CloseState>,
    close_cond: parking_lot::Condvar,
    rt_handle: tokio::runtime::Handle,
}

impl BridgeHandle {
    fn start(
        path: PathBuf,
        cache_bytes: u64,
        max_memtable: usize,
    ) -> Result<(Self, Arc<surrealkv::Tree>), StorageError> {
        let notify = Arc::new(tokio::sync::Notify::new());
        let queue = Arc::new(BridgeQueue {
            queue: parking_lot::Mutex::new(VecDeque::new()),
            not_full: parking_lot::Condvar::new(),
            notify: Arc::clone(&notify),
            capacity: 1024,
            closed: AtomicBool::new(false),
        });

        let (init_tx, init_rx) = std::sync::mpsc::sync_channel::<
            Result<(Arc<surrealkv::Tree>, tokio::runtime::Handle), StorageError>,
        >(1);
        let worker_queue = Arc::clone(&queue);

        let thread_handle = std::thread::Builder::new()
            .name("surrealkv-rt".to_string())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_time()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        let _ = init_tx.send(Err(StorageError::backend(e)));
                        return;
                    }
                };
                let handle = rt.handle().clone();

                rt.block_on(async move {
                    let tree_res = surrealkv::TreeBuilder::new()
                        .with_path(path)
                        .with_enable_vlog(false)
                        .with_block_cache_capacity(cache_bytes)
                        .with_max_memtable_size(max_memtable)
                        .build_async()
                        .await
                        .map_err(StorageError::backend);

                    let tree = match tree_res {
                        Ok(t) => {
                            let tree_arc = Arc::new(t);
                            let _ = init_tx.send(Ok((Arc::clone(&tree_arc), handle)));
                            tree_arc
                        }
                        Err(e) => {
                            let _ = init_tx.send(Err(e));
                            return;
                        }
                    };

                    loop {
                        let req = {
                            let mut guard = worker_queue.queue.lock();
                            let item = guard.pop_front();
                            if item.is_some() {
                                worker_queue.not_full.notify_one();
                            }
                            item
                        };

                        match req {
                            Some(BridgeRequest::Commit { mut txn, reply }) => {
                                let res = txn.commit().await.map_err(|e| match e {
                                    surrealkv::Error::TransactionWriteConflict => {
                                        StorageError::Backend(
                                            "transaction write conflict".to_string(),
                                        )
                                    }
                                    other => StorageError::backend(other),
                                });
                                let _ = reply.send(res);
                            }
                            Some(BridgeRequest::Close { reply }) => {
                                let res = tree.close().await.map_err(StorageError::backend);
                                let _ = reply.send(res);
                                break;
                            }
                            None => {
                                worker_queue.notify.notified().await;
                            }
                        }
                    }
                });
            })
            .map_err(StorageError::Io)?;

        let (tree, rt_handle) = init_rx.recv().map_err(|_| {
            StorageError::Backend("surrealkv runtime worker failed to init".to_string())
        })??;

        let handle = Self {
            queue,
            worker_thread: parking_lot::Mutex::new(Some(thread_handle)),
            close_state: parking_lot::Mutex::new(CloseState::Open),
            close_cond: parking_lot::Condvar::new(),
            rt_handle,
        };

        Ok((handle, tree))
    }

    fn commit(&self, txn: surrealkv::Transaction) -> Result<(), StorageError> {
        let (reply_tx, reply_rx) = std::sync::mpsc::sync_channel(1);
        self.queue.send(BridgeRequest::Commit {
            txn,
            reply: reply_tx,
        })?;
        reply_rx
            .recv()
            .map_err(|_| StorageError::Backend("surrealkv runtime worker hung up".to_string()))?
    }

    fn is_closed(&self) -> bool {
        self.queue.closed.load(Ordering::Acquire)
    }

    fn close(&self) -> Result<(), StorageError> {
        let mut state = self.close_state.lock();
        loop {
            match &*state {
                CloseState::Closed(Ok(())) => return Ok(()),
                CloseState::Closed(Err(msg)) => return Err(StorageError::Backend(msg.clone())),
                CloseState::Closing => {
                    self.close_cond.wait(&mut state);
                }
                CloseState::Open => {
                    *state = CloseState::Closing;
                    break;
                }
            }
        }
        drop(state);

        let res = self.execute_close();

        let mut state = self.close_state.lock();
        *state = match &res {
            Ok(()) => CloseState::Closed(Ok(())),
            Err(e) => CloseState::Closed(Err(e.to_string())),
        };
        self.close_cond.notify_all();
        res
    }

    fn execute_close(&self) -> Result<(), StorageError> {
        self.queue.closed.store(true, Ordering::SeqCst);
        let (reply_tx, reply_rx) = std::sync::mpsc::sync_channel(1);
        {
            let mut guard = self.queue.queue.lock();
            guard.push_back(BridgeRequest::Close { reply: reply_tx });
            self.queue.not_full.notify_all();
        }
        self.queue.notify.notify_one();
        let res = reply_rx
            .recv()
            .map_err(|_| StorageError::Backend("surrealkv runtime worker hung up".to_string()))
            .and_then(|r| r);

        let handle = self.worker_thread.lock().take();
        if let Some(h) = handle {
            if h.join().is_err() {
                return Err(StorageError::Backend(
                    "surrealkv runtime worker panicked during shutdown".to_string(),
                ));
            }
        }
        res
    }

    pub(crate) fn stream_prefix(
        &self,
        txn: Arc<surrealkv::Transaction>,
        cf: ColumnFamily,
        prefix: Vec<u8>,
    ) -> Result<crate::KvIter<'static>, StorageError> {
        if self.is_closed() {
            return Err(StorageError::Backend(
                "surrealkv store is closed".to_string(),
            ));
        }
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Vec<crate::KvPair>, StorageError>>(2);
        let start = prefixed_key(cf, &prefix);
        let end = prefix_end(cf, &prefix);

        self.rt_handle.spawn(async move {
            let mut cursor = start;
            loop {
                let (page, next_cursor, err, exhausted) =
                    fetch_stream_page(&txn, cf, &prefix, &cursor, &end);

                if let Some(e) = err {
                    let _ = tx.send(Err(e)).await;
                    break;
                }

                if !page.is_empty() && tx.send(Ok(page)).await.is_err() {
                    break;
                }

                if exhausted {
                    break;
                }

                match next_cursor {
                    Some(c) if c < end => cursor = c,
                    _ => break,
                }

                tokio::task::yield_now().await;
            }
        });

        Ok(Box::new(SurrealKvPagedIter {
            rx,
            current_page: Vec::new().into_iter(),
            finished: false,
        }))
    }
}

fn fetch_stream_page(
    txn: &surrealkv::Transaction,
    cf: ColumnFamily,
    prefix: &[u8],
    cursor: &[u8],
    end: &[u8],
) -> (
    Vec<crate::KvPair>,
    Option<Vec<u8>>,
    Option<StorageError>,
    bool,
) {
    let iter = match txn.range(cursor, end) {
        Ok(i) => i,
        Err(e) => return (Vec::new(), None, Some(StorageError::backend(e)), true),
    };
    let mut stream = LsmStreamIter {
        iter,
        cf,
        prefix: prefix.to_vec(),
        initialized: false,
        _phantom: std::marker::PhantomData,
    };
    let mut page = Vec::with_capacity(ITER_PREFIX_PAGE_SIZE);
    let mut err = None;
    while page.len() < ITER_PREFIX_PAGE_SIZE {
        match stream.next() {
            Some(Ok(pair)) => page.push(pair),
            Some(Err(e)) => {
                err = Some(e);
                break;
            }
            None => break,
        }
    }
    let exhausted = page.len() < ITER_PREFIX_PAGE_SIZE && err.is_none();
    let next_cursor = if let Some((last_k, _)) = page.last() {
        let mut next_k = prefixed_key(cf, last_k);
        next_k.push(0);
        Some(next_k)
    } else {
        None
    };
    (page, next_cursor, err, exhausted)
}

pub struct SurrealKvStore {
    tree: Arc<surrealkv::Tree>,
    bridge: Arc<BridgeHandle>,
    write_lock: parking_lot::Mutex<()>,
    configured_cache_capacity: u64,
    configured_max_memtable_size: usize,
    path: PathBuf,
    #[cfg(any(test, feature = "test-seam"))]
    faults: crate::trait_::PersistFaultSlot,
    guard: Option<crate::StoreGuard>,
}

impl SurrealKvStore {
    #[must_use]
    pub fn guarded_by(mut self, guard: crate::StoreGuard) -> Self {
        assert!(
            self.guard.is_none(),
            "a store takes exactly one lifetime guard"
        );
        self.guard = Some(guard);
        self
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        Self::open_with_cache(path, SURREALKV_DEFAULT_CACHE_BYTES)
    }

    pub fn open_with_cache(path: impl AsRef<Path>, cache_bytes: u64) -> Result<Self, StorageError> {
        let path = path.as_ref().to_path_buf();
        std::fs::create_dir_all(&path).map_err(StorageError::Io)?;

        let engine_marker = path.join("ENGINE");
        if !engine_marker.exists() {
            write_durable_marker(&engine_marker, b"surrealkv\n")?;
        }

        let cache_bytes = if cache_bytes == 0 {
            SURREALKV_DEFAULT_CACHE_BYTES
        } else {
            cache_bytes
        };
        let max_memtable = SURREALKV_DEFAULT_MAX_MEMTABLE_BYTES;

        metrics::gauge!("storage.cache_capacity_bytes", "backend" => "surrealkv")
            .set(bitcoin_rs_consensus::primitives::u64_to_f64(cache_bytes));

        let (bridge, tree) = BridgeHandle::start(path.clone(), cache_bytes, max_memtable)?;

        Ok(Self {
            tree,
            bridge: Arc::new(bridge),
            write_lock: parking_lot::Mutex::new(()),
            configured_cache_capacity: cache_bytes,
            configured_max_memtable_size: max_memtable,
            path,
            #[cfg(any(test, feature = "test-seam"))]
            faults: crate::trait_::PersistFaultSlot::default(),
            guard: None,
        })
    }

    pub fn close(&self) -> Result<(), StorageError> {
        self.bridge.close()
    }

    fn check_open(&self) -> Result<(), StorageError> {
        if self.bridge.is_closed() {
            return Err(StorageError::Backend(
                "surrealkv store is closed".to_string(),
            ));
        }
        Ok(())
    }

    fn write_with_durability(
        &self,
        batch: BufferedWriteBatch,
        durability: WriteDurability,
    ) -> Result<(), StorageError> {
        self.check_open()?;
        let mut txn = self
            .tree
            .begin_with_mode(surrealkv::Mode::ReadWrite)
            .map_err(StorageError::backend)?;

        let mut encoded_bytes = 0usize;
        for op in batch.into_ops() {
            match op {
                BatchOp::Put { cf, key, value } => {
                    encoded_bytes = encoded_bytes.saturating_add(key.len() + value.len());
                    let prefixed = prefixed_key(cf, &key);
                    txn.set(&prefixed, &*value).map_err(StorageError::backend)?;
                }
                BatchOp::Delete { cf, key } => {
                    encoded_bytes = encoded_bytes.saturating_add(key.len());
                    let prefixed = prefixed_key(cf, &key);
                    txn.delete(&prefixed).map_err(StorageError::backend)?;
                }
                BatchOp::DeleteRange { cf, start, end } => {
                    encoded_bytes = encoded_bytes
                        .saturating_add(start.len())
                        .saturating_add(end.len());
                    let start_prefixed = prefixed_key(cf, &start);
                    let end_prefixed = prefixed_key(cf, &end);
                    txn.delete_range(&start_prefixed, &end_prefixed)
                        .map_err(StorageError::backend)?;
                }
            }
        }

        match durability {
            WriteDurability::Default | WriteDurability::Deferred => {
                txn.set_durability(surrealkv::Durability::Eventual);
            }
            WriteDurability::Durable => {
                txn.set_durability(surrealkv::Durability::Immediate);
            }
        }

        count_write(durability.label(), encoded_bytes);
        self.bridge.commit(txn)
    }

    pub fn multi_get(
        &self,
        cf: ColumnFamily,
        keys: &[&[u8]],
    ) -> Result<Vec<Option<Bytes>>, StorageError> {
        self.check_open()?;
        let txn = self
            .tree
            .begin_with_mode(surrealkv::Mode::ReadOnly)
            .map_err(StorageError::backend)?;
        let mut out = Vec::with_capacity(keys.len());
        let mut prefixed = Vec::with_capacity(65);
        for key in keys {
            prefixed.clear();
            prefixed.push(cf_to_u8(cf));
            prefixed.extend_from_slice(key);
            let val = txn.get(&prefixed).map_err(StorageError::backend)?;
            out.push(val.map(Bytes::from));
        }
        Ok(out)
    }

    pub fn ingest_sorted(
        &self,
        cf: ColumnFamily,
        rows: &mut dyn Iterator<Item = (Vec<u8>, Vec<u8>)>,
        _scratch: &Path,
    ) -> Result<u64, StorageError> {
        self.check_open()?;
        let _guard = self.write_lock.lock();
        let mut count = 0u64;
        let mut batch_bytes = 0usize;
        let mut txn = self
            .tree
            .begin_with_mode(surrealkv::Mode::WriteOnly)
            .map_err(StorageError::backend)?;
        txn.set_durability(surrealkv::Durability::Eventual);
        let mut peekable = rows.peekable();
        let mut prev_key: Option<Vec<u8>> = None;

        while let Some((k, v)) = peekable.next() {
            if let Some(prev) = &prev_key {
                if k.as_slice() <= prev.as_slice() {
                    return Err(StorageError::InvalidOperation(
                        "keys not strictly ascending",
                    ));
                }
            }
            let row_bytes = 1 + k.len() + v.len();
            let is_last = peekable.peek().is_none();
            let is_oversized = row_bytes >= INGEST_BATCH_TARGET_BYTES;

            if batch_bytes > 0
                && (batch_bytes.saturating_add(row_bytes) > INGEST_BATCH_TARGET_BYTES
                    || is_oversized)
            {
                self.bridge.commit(txn)?;
                txn = self
                    .tree
                    .begin_with_mode(surrealkv::Mode::WriteOnly)
                    .map_err(StorageError::backend)?;
                txn.set_durability(surrealkv::Durability::Eventual);
                batch_bytes = 0;
            }

            let mut prefixed = Vec::with_capacity(1 + k.len());
            prefixed.push(cf_to_u8(cf));
            prefixed.extend_from_slice(&k);
            txn.set(&prefixed, &v).map_err(StorageError::backend)?;
            count += 1;
            prev_key = Some(k);

            if is_last {
                txn.set_durability(surrealkv::Durability::Immediate);
            }

            if is_oversized {
                self.bridge.commit(txn)?;
                txn = self
                    .tree
                    .begin_with_mode(surrealkv::Mode::WriteOnly)
                    .map_err(StorageError::backend)?;
                txn.set_durability(surrealkv::Durability::Eventual);
                batch_bytes = 0;
            } else {
                batch_bytes = batch_bytes.saturating_add(row_bytes);
            }
        }

        if batch_bytes > 0 {
            self.bridge.commit(txn)?;
        }
        Ok(count)
    }

    pub fn delete_range(
        &self,
        cf: ColumnFamily,
        start: &[u8],
        end: &[u8],
    ) -> Result<(), StorageError> {
        self.check_open()?;
        let _guard = self.write_lock.lock();
        let mut txn = self
            .tree
            .begin_with_mode(surrealkv::Mode::ReadWrite)
            .map_err(StorageError::backend)?;
        txn.set_durability(surrealkv::Durability::Immediate);
        let start_prefixed = prefixed_key(cf, start);
        let end_prefixed = prefixed_key(cf, end);
        txn.delete_range(&start_prefixed, &end_prefixed)
            .map_err(StorageError::backend)?;
        self.bridge.commit(txn)
    }

    pub fn checkpoint(&self, dir: &Path) -> Result<(), StorageError> {
        self.check_open()?;
        self.tree
            .create_checkpoint(dir)
            .map_err(StorageError::backend)?;
        let engine_file = dir.join("ENGINE");
        if !engine_file.exists() {
            write_durable_marker(&engine_file, b"surrealkv\n")?;
        }
        sync_dir(dir)?;
        Ok(())
    }

    pub fn engine_cache_bytes(&self) -> u64 {
        self.configured_cache_capacity
            .saturating_add(u64::try_from(self.configured_max_memtable_size).unwrap_or(u64::MAX))
    }
}

impl Drop for SurrealKvStore {
    fn drop(&mut self) {
        if let Err(error) = self.close() {
            tracing::error!(
                path = %self.path.display(),
                %error,
                "surrealkv close failed during drop"
            );
        }
    }
}

impl KvStore for SurrealKvStore {
    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.check_open()?;
        let txn = self
            .tree
            .begin_with_mode(surrealkv::Mode::ReadOnly)
            .map_err(StorageError::backend)?;
        let prefixed = prefixed_key(cf, key);
        txn.get(&prefixed).map_err(StorageError::backend)
    }

    fn get_bounded(
        &self,
        cf: ColumnFamily,
        key: &[u8],
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>, BoundedReadError> {
        self.check_open()?;
        let txn = self
            .tree
            .begin_with_mode(surrealkv::Mode::ReadOnly)
            .map_err(StorageError::backend)?;
        let prefixed = prefixed_key(cf, key);
        let end = single_key_successor(&prefixed);
        let mut iter = txn.range(&prefixed, &end).map_err(StorageError::backend)?;
        if !iter.seek_first().map_err(StorageError::backend)? || !iter.valid() {
            return Ok(None);
        }
        if iter.key().user_key() != prefixed.as_slice() {
            return Ok(None);
        }
        let val_cow = iter.value_ref().map_err(StorageError::backend)?;
        if val_cow.len() > max_bytes {
            return Err(BoundedReadError::Limit {
                size: val_cow.len(),
                limit: max_bytes,
            });
        }
        Ok(Some(val_cow.into_owned()))
    }

    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<KvIter<'a>, StorageError> {
        self.check_open()?;
        let txn = Arc::new(
            self.tree
                .begin_with_mode(surrealkv::Mode::ReadOnly)
                .map_err(StorageError::backend)?,
        );
        self.bridge.stream_prefix(txn, cf, prefix.to_vec())
    }

    fn scan_prefix_bounded(
        &self,
        cf: ColumnFamily,
        prefix: &[u8],
        limit: PrefixScanLimit,
    ) -> Result<PrefixScan, StorageError> {
        self.scan_prefix_from_bounded(cf, prefix, prefix, limit)
    }

    fn scan_prefix_from_bounded(
        &self,
        cf: ColumnFamily,
        prefix: &[u8],
        start: &[u8],
        limit: PrefixScanLimit,
    ) -> Result<PrefixScan, StorageError> {
        self.check_open()?;
        let eff_start = core::cmp::max(start, prefix);
        let start_key = prefixed_key(cf, eff_start);
        let end_key = prefix_end(cf, prefix);
        if start_key >= end_key {
            return Ok(PrefixScan {
                rows: Vec::new(),
                complete: true,
            });
        }
        let txn = self
            .tree
            .begin_with_mode(surrealkv::Mode::ReadOnly)
            .map_err(StorageError::backend)?;
        let mut iter = txn
            .range(&start_key, &end_key)
            .map_err(StorageError::backend)?;

        let mut rows = Vec::new();
        let mut bytes = 0usize;
        let mut complete = true;

        if iter.seek_first().map_err(StorageError::backend)? {
            while iter.valid() {
                let user_key = iter.key().user_key();
                if user_key.is_empty() || user_key[0] != cf_to_u8(cf) {
                    break;
                }
                let logical_key = &user_key[1..];
                if !logical_key.starts_with(prefix) {
                    break;
                }
                let val = iter.value().map_err(StorageError::backend)?;
                let row_bytes = logical_key.len().saturating_add(val.len());
                let next_bytes = bytes.saturating_add(row_bytes);
                if rows.len() >= limit.max_rows
                    || (!rows.is_empty() && next_bytes > limit.max_bytes)
                {
                    complete = false;
                    break;
                }
                rows.push((logical_key.to_vec(), val));
                bytes = next_bytes;
                if !iter.next().map_err(StorageError::backend)? {
                    break;
                }
            }
        }
        Ok(PrefixScan { rows, complete })
    }

    fn new_batch(&self) -> BufferedWriteBatch {
        BufferedWriteBatch::default()
    }

    fn put(&self, cf: ColumnFamily, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        let mut batch = self.new_batch();
        batch.put(cf, key, value);
        self.write(batch)
    }

    fn put_value(&self, cf: ColumnFamily, key: &[u8], value: Bytes) -> Result<(), StorageError> {
        let mut batch = self.new_batch();
        batch.put_value(cf, key, value);
        self.write(batch)
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
        self.check_open()?;
        let _guard = self.write_lock.lock();
        let mut txn = self
            .tree
            .begin_with_mode(surrealkv::Mode::ReadWrite)
            .map_err(StorageError::backend)?;

        for condition in conditions {
            let (cf, key) = condition.location();
            let prefixed = prefixed_key(cf, key);
            let current = txn.get_for_update(&prefixed).map_err(|e| match e {
                surrealkv::Error::TransactionWriteConflict => {
                    StorageError::Backend("transaction write conflict".to_string())
                }
                other => StorageError::backend(other),
            })?;
            if !condition.matches(current.as_deref()) {
                return Ok(false);
            }
        }

        let mut encoded_bytes = 0usize;
        for op in batch.into_ops() {
            match op {
                BatchOp::Put { cf, key, value } => {
                    encoded_bytes = encoded_bytes.saturating_add(key.len() + value.len());
                    let prefixed = prefixed_key(cf, &key);
                    txn.set(&prefixed, &*value).map_err(StorageError::backend)?;
                }
                BatchOp::Delete { cf, key } => {
                    encoded_bytes = encoded_bytes.saturating_add(key.len());
                    let prefixed = prefixed_key(cf, &key);
                    txn.delete(&prefixed).map_err(StorageError::backend)?;
                }
                BatchOp::DeleteRange { cf, start, end } => {
                    encoded_bytes = encoded_bytes
                        .saturating_add(start.len())
                        .saturating_add(end.len());
                    let start_prefixed = prefixed_key(cf, &start);
                    let end_prefixed = prefixed_key(cf, &end);
                    txn.delete_range(&start_prefixed, &end_prefixed)
                        .map_err(StorageError::backend)?;
                }
            }
        }

        txn.set_durability(surrealkv::Durability::Immediate);
        count_write("durable", encoded_bytes);
        self.bridge.commit(txn)?;
        Ok(true)
    }

    fn flush(&self) -> Result<(), StorageError> {
        self.check_open()?;
        metrics::counter!("storage.flushes_total", "backend" => "surrealkv").increment(1);
        #[cfg(any(test, feature = "test-seam"))]
        if let Some(fault) = self.faults.take_at(crate::trait_::PersistBoundary::Flush) {
            return Err(StorageError::Io(std::io::Error::other(format!(
                "injected persistence fault {fault:?}"
            ))));
        }
        self.tree.flush_wal(true).map_err(StorageError::backend)
    }

    fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError> {
        self.check_open()?;
        let txn = self
            .tree
            .begin_with_mode(surrealkv::Mode::ReadOnly)
            .map_err(StorageError::backend)?;
        Ok(Box::new(SurrealKvSnapshot {
            txn: Arc::new(txn),
            bridge: Arc::clone(&self.bridge),
        }))
    }

    fn multi_get(
        &self,
        cf: ColumnFamily,
        keys: &[&[u8]],
    ) -> Result<Vec<Option<Bytes>>, StorageError> {
        self.multi_get(cf, keys)
    }

    fn ingest_sorted(
        &self,
        cf: ColumnFamily,
        rows: &mut dyn Iterator<Item = (Vec<u8>, Vec<u8>)>,
        scratch: &Path,
    ) -> Result<u64, StorageError> {
        self.ingest_sorted(cf, rows, scratch)
    }

    fn delete_range(&self, cf: ColumnFamily, start: &[u8], end: &[u8]) -> Result<(), StorageError> {
        self.delete_range(cf, start, end)
    }

    fn checkpoint(&self, dir: &Path) -> Result<(), StorageError> {
        self.checkpoint(dir)
    }

    fn engine_cache_bytes(&self) -> u64 {
        self.engine_cache_bytes()
    }

    #[cfg(any(test, feature = "test-seam"))]
    fn arm_persist_fault(&self, fault: crate::PersistFault) {
        self.faults.arm(fault);
    }
}

pub(crate) struct SurrealKvSnapshot {
    txn: Arc<surrealkv::Transaction>,
    bridge: Arc<BridgeHandle>,
}

impl KvSnapshot for SurrealKvSnapshot {
    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let prefixed = prefixed_key(cf, key);
        self.txn.get(&prefixed).map_err(StorageError::backend)
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
        let mut out = Vec::with_capacity(keys.len());
        let mut prefixed = Vec::with_capacity(65);
        for key in keys {
            prefixed.clear();
            prefixed.push(cf_to_u8(cf));
            prefixed.extend_from_slice(key);
            let val = self.txn.get(&prefixed).map_err(StorageError::backend)?;
            out.push(val);
        }
        Ok(out)
    }

    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<KvIter<'a>, StorageError> {
        self.bridge
            .stream_prefix(Arc::clone(&self.txn), cf, prefix.to_vec())
    }

    fn last_prefix(&self, cf: ColumnFamily, prefix: &[u8]) -> Result<Option<KvPair>, StorageError> {
        let start = prefixed_key(cf, prefix);
        let end = prefix_end(cf, prefix);
        let mut iter = self
            .txn
            .range(&start, &end)
            .map_err(StorageError::backend)?;
        if !iter.seek_last().map_err(StorageError::backend)? || !iter.valid() {
            return Ok(None);
        }
        let user_key = iter.key().user_key();
        if user_key.is_empty() || user_key[0] != cf_to_u8(cf) {
            return Ok(None);
        }
        let logical_key = &user_key[1..];
        if !logical_key.starts_with(prefix) {
            return Ok(None);
        }
        let val = iter.value().map_err(StorageError::backend)?;
        Ok(Some((logical_key.to_vec(), val)))
    }

    fn scan_prefix_bounded(
        &self,
        cf: ColumnFamily,
        prefix: &[u8],
        limit: PrefixScanLimit,
    ) -> Result<PrefixScan, StorageError> {
        self.scan_prefix_from_bounded(cf, prefix, prefix, limit)
    }

    fn scan_prefix_from_bounded(
        &self,
        cf: ColumnFamily,
        prefix: &[u8],
        start: &[u8],
        limit: PrefixScanLimit,
    ) -> Result<PrefixScan, StorageError> {
        let eff_start = core::cmp::max(start, prefix);
        let start_key = prefixed_key(cf, eff_start);
        let end_key = prefix_end(cf, prefix);
        if start_key >= end_key {
            return Ok(PrefixScan {
                rows: Vec::new(),
                complete: true,
            });
        }
        let mut iter = self
            .txn
            .range(&start_key, &end_key)
            .map_err(StorageError::backend)?;
        let mut rows = Vec::new();
        let mut bytes = 0usize;
        let mut complete = true;

        if iter.seek_first().map_err(StorageError::backend)? {
            while iter.valid() {
                let user_key = iter.key().user_key();
                if user_key.is_empty() || user_key[0] != cf_to_u8(cf) {
                    break;
                }
                let logical_key = &user_key[1..];
                if !logical_key.starts_with(prefix) {
                    break;
                }
                let val = iter.value().map_err(StorageError::backend)?;
                let row_bytes = logical_key.len().saturating_add(val.len());
                let next_bytes = bytes.saturating_add(row_bytes);
                if rows.len() >= limit.max_rows
                    || (!rows.is_empty() && next_bytes > limit.max_bytes)
                {
                    complete = false;
                    break;
                }
                rows.push((logical_key.to_vec(), val));
                bytes = next_bytes;
                if !iter.next().map_err(StorageError::backend)? {
                    break;
                }
            }
        }
        Ok(PrefixScan { rows, complete })
    }
}

struct LsmStreamIter<'a, I: surrealkv::LSMIterator> {
    iter: I,
    cf: ColumnFamily,
    prefix: Vec<u8>,
    initialized: bool,
    _phantom: std::marker::PhantomData<&'a ()>,
}

impl<I: surrealkv::LSMIterator> Iterator for LsmStreamIter<'_, I> {
    type Item = Result<KvPair, StorageError>;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.initialized {
            self.initialized = true;
            match self.iter.seek_first() {
                Ok(true) => {}
                Ok(false) => return None,
                Err(e) => return Some(Err(StorageError::backend(e))),
            }
        } else {
            match self.iter.next() {
                Ok(true) => {}
                Ok(false) => return None,
                Err(e) => return Some(Err(StorageError::backend(e))),
            }
        }

        if !self.iter.valid() {
            return None;
        }

        let user_key = self.iter.key().user_key();
        if user_key.is_empty() || user_key[0] != cf_to_u8(self.cf) {
            return None;
        }
        let logical_key = &user_key[1..];
        if !logical_key.starts_with(&self.prefix) {
            return None;
        }

        match self.iter.value() {
            Ok(v) => Some(Ok((logical_key.to_vec(), v))),
            Err(e) => Some(Err(StorageError::backend(e))),
        }
    }
}

struct SurrealKvPagedIter {
    rx: tokio::sync::mpsc::Receiver<Result<Vec<KvPair>, StorageError>>,
    current_page: std::vec::IntoIter<KvPair>,
    finished: bool,
}

impl Iterator for SurrealKvPagedIter {
    type Item = Result<KvPair, StorageError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        loop {
            if let Some(item) = self.current_page.next() {
                return Some(Ok(item));
            }
            match self.rx.blocking_recv() {
                Some(Ok(page)) => {
                    if page.is_empty() {
                        self.finished = true;
                        return None;
                    }
                    self.current_page = page.into_iter();
                }
                Some(Err(e)) => {
                    self.finished = true;
                    return Some(Err(e));
                }
                None => {
                    self.finished = true;
                    return None;
                }
            }
        }
    }
}

#[inline]
const fn cf_to_u8(cf: ColumnFamily) -> u8 {
    match cf {
        ColumnFamily::TxConfirmed => 0,
        ColumnFamily::TxMempool => 1,
        ColumnFamily::BlockHeaders => 2,
        ColumnFamily::Funding => 3,
        ColumnFamily::Spending => 4,
        ColumnFamily::Coinstats => 5,
        ColumnFamily::BlockTree => 6,
        ColumnFamily::UtxoMeta => 7,
        ColumnFamily::BlockBodies => 8,
        ColumnFamily::UndoData => 9,
        ColumnFamily::ScriptLive => 10,
        ColumnFamily::Coins => 11,
        ColumnFamily::PoolLedger => 12,
    }
}

#[inline]
fn prefixed_key(cf: ColumnFamily, key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + key.len());
    out.push(cf_to_u8(cf));
    out.extend_from_slice(key);
    out
}

#[inline]
fn prefix_end(cf: ColumnFamily, prefix: &[u8]) -> Vec<u8> {
    let mut end = Vec::with_capacity(1 + prefix.len());
    end.push(cf_to_u8(cf));
    end.extend_from_slice(prefix);
    for i in (0..end.len()).rev() {
        if end[i] < 255 {
            end[i] += 1;
            end.truncate(i + 1);
            return end;
        }
    }
    vec![cf_to_u8(cf) + 1]
}

#[inline]
fn single_key_successor(prefixed: &[u8]) -> Vec<u8> {
    let mut end = prefixed.to_vec();
    for i in (0..end.len()).rev() {
        if end[i] < 255 {
            end[i] += 1;
            end.truncate(i + 1);
            return end;
        }
    }
    let mut out = prefixed.to_vec();
    out.push(0);
    out
}

fn count_write(durability: &'static str, encoded_bytes: usize) {
    metrics::counter!("storage.writes_total", "backend" => "surrealkv", "durability" => durability)
        .increment(1);
    metrics::histogram!("storage.write_bytes", "backend" => "surrealkv").record(
        bitcoin_rs_consensus::primitives::u64_to_f64(
            u64::try_from(encoded_bytes).unwrap_or(u64::MAX),
        ),
    );
}
