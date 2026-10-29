//! Stage 2 portable `TxLookup` bundle lifecycle over real Fjall stores.

#![cfg(feature = "fjall")]
#![expect(
    clippy::expect_used,
    reason = "test: fixture setup failures abort the test with context"
)]

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use arc_swap::{ArcSwap, ArcSwapOption};
use bitcoin::{
    Amount, ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode, TxOut, Witness,
    block::{Header as BtcHeader, Version},
    consensus::encode::serialize,
    hashes::Hash as _,
    pow::CompactTarget,
    script::Builder,
};
use bitcoin_rs_chain::{
    BlockBodyReadError, BlockBodySource, BlockTree, BlockTreeReader, ChainTxCount, NodeStatus,
    TipReader, TipSnapshot,
};
use bitcoin_rs_index::portable::{IndexBundleDirective, IndexBundleRequest};
use bitcoin_rs_index::reconcile::{ChainCursorSource, ConsumerCursor};
use bitcoin_rs_index::runtime::{
    DEFAULT_BATCH_LIMITS, DerivedIndexLifecycle, DerivedIndexOpenSpec, DerivedIndexQueryAdapter,
    DerivedIndexRuntime, DerivedIndexWorker, Generation, IndexAheadSink,
    open_derived_index_store_on_worker,
};
use bitcoin_rs_index::{
    DerivedIndexQuery, IndexCapabilities, IndexCapability, IndexReader, IndexWatermark, Indexer,
};
use bitcoin_rs_primitives::{BlockHash, Hash256, Network, Txid};
use bitcoin_rs_storage::block_body::BlockBodyStore;
use bitcoin_rs_storage::pruning::{HistoryAccess, RetentionBudget, RetentionRegistry};
use bitcoin_rs_storage::{
    BatchOp, BufferedWriteBatch, ColumnFamily, FjallStore, KvIter, KvPair, KvSnapshot, KvStore,
    PrefixScan, PrefixScanLimit, StorageBackend, StorageError, WriteCondition,
};
use parking_lot::RwLock;

const MANIFEST: &str = "manifest.json";
const ARTIFACT: &str = "txlookup-v1.dat";
const STORE_CACHE_BYTES: u64 = 8 << 20;
const CANCEL_POLL_RECORDS: usize = 4_096;
const IMPORT_BATCH_ROWS: usize = 65_536;

static NEXT_EPOCH: AtomicU64 = AtomicU64::new(1);

type BodyMap = HashMap<(u32, [u8; 32]), Vec<u8>>;

struct ChainFixture {
    tree: Arc<RwLock<BlockTree>>,
    bodies: Arc<BodyMap>,
    tip: Arc<TipSnapshot>,
    txids: Vec<(Txid, u32)>,
}

impl ChainFixture {
    /// `blocks` blocks above genesis, each holding a coinbase plus `extra`
    fn new(blocks: u32, extra: usize) -> Self {
        let mut tree = BlockTree::new();
        let mut bodies = BodyMap::new();
        let mut txids = Vec::new();
        let mut prev = [0_u8; 32];
        let mut tip_id = None;
        for height in 0..=blocks {
            let block = mine_block(prev, height, if height == 0 { 0 } else { extra });
            let bytes = serialize(&block);
            let parsed: bitcoin_rs_primitives::Block =
                bitcoin_rs_primitives::deserialize(&bytes).expect("fixture block decodes");
            let header: bitcoin_rs_primitives::Header =
                bitcoin_rs_primitives::deserialize(&serialize(&block.header))
                    .expect("80-byte header");
            let id = tree
                .insert_header(header, NodeStatus::HeaderValid)
                .expect("fixture header links to its parent");
            tree.record_applied_tx_count(
                id,
                u64::try_from(parsed.txs.len()).expect("transaction count fits u64"),
            )
            .expect("fixture node exists");
            txids.extend(parsed.txids().into_iter().map(|txid| (txid, height)));
            let hash = block.block_hash().to_byte_array();
            bodies.insert((height, hash), bytes);
            prev = hash;
            tip_id = Some(id);
        }
        let tip_id = tip_id.expect("genesis is always mined");
        let tip = {
            let node = tree.node(tip_id).expect("tip node");
            Arc::new(TipSnapshot {
                tip_id,
                height: node.height,
                chainwork: node.chainwork,
                hash: node.hash,
                chain_tx_count: node.chain_tx_count,
            })
        };
        Self {
            tree: Arc::new(RwLock::new(tree)),
            bodies: Arc::new(bodies),
            tip,
            txids,
        }
    }

    fn restarted(self) -> Self {
        {
            let mut tree = self.tree.write();
            let mut cursor = tree.node(self.tip.tip_id).expect("tip node").parent;
            while let Some(id) = cursor {
                cursor = tree.node(id).expect("ancestor node").parent;
                tree.restore_chain_tx_count(id, ChainTxCount::UNKNOWN)
                    .expect("ancestor node exists");
            }
        }
        self
    }

    fn tx_row_keys(&self) -> usize {
        self.txids
            .iter()
            .map(|(txid, height)| {
                let bytes = Hash256::from(*txid).to_le_bytes();
                let mut prefix = [0_u8; 8];
                prefix.copy_from_slice(&bytes[..8]);
                (prefix, *height)
            })
            .collect::<HashSet<_>>()
            .len()
    }

    fn tip_watermark(&self) -> IndexWatermark {
        IndexWatermark {
            height: self.tip.height,
            hash: self.tip.hash.to_le_bytes(),
        }
    }
}

fn coinbase(height: u32) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: bitcoin::OutPoint::null(),
            script_sig: Builder::new()
                .push_int(i64::from(height))
                .push_int(0)
                .into_script(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

/// A non-coinbase transaction whose id is unique per `(height, index)`.
fn filler(height: u32, index: usize) -> Transaction {
    let index = u32::try_from(index).expect("filler index fits u32");
    let mut seed = [0x5a_u8; 32];
    seed[..4].copy_from_slice(&height.to_le_bytes());
    seed[4..8].copy_from_slice(&index.to_le_bytes());
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: bitcoin::OutPoint {
                txid: bitcoin::Txid::from_byte_array(seed),
                vout: index,
            },
            script_sig: Builder::new()
                .push_int(i64::from(height))
                .push_int(i64::from(index))
                .into_script(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

fn mine_block(prev: [u8; 32], height: u32, extra: usize) -> bitcoin::Block {
    let mut txdata = Vec::with_capacity(extra + 1);
    txdata.push(coinbase(height));
    txdata.extend((0..extra).map(|index| filler(height, index)));
    let mut block = bitcoin::Block {
        header: BtcHeader {
            version: Version::ONE,
            prev_blockhash: bitcoin::BlockHash::from_byte_array(prev),
            merkle_root: TxMerkleNode::all_zeros(),
            time: height,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata,
    };
    block.header.merkle_root = block
        .compute_merkle_root()
        .unwrap_or_else(TxMerkleNode::all_zeros);
    while block.header.validate_pow(block.header.target()).is_err() {
        block.header.nonce = block.header.nonce.wrapping_add(1);
    }
    block
}

#[derive(Default)]
struct Probe {
    reconciling: AtomicBool,
}

impl ChainCursorSource for Probe {
    fn cursor(&self) -> ConsumerCursor {
        self.reconciling.store(true, Ordering::Release);
        ConsumerCursor {
            epoch: 0,
            sequence: 0,
            height: 0,
            hash: Hash256::from_le_bytes(&[0_u8; 32]),
        }
    }
}

struct NoIndexAhead;

impl IndexAheadSink for NoIndexAhead {
    fn report_index_ahead(
        &self,
        _capability: &str,
        _index_height: u32,
        _tip_height: u32,
        _tip_hash_be: &str,
        _index_hash_be: &str,
        _depth: u32,
        _unix_secs: u64,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
}

#[derive(Debug, Default)]
struct BodyLoadCounter {
    total: AtomicU64,
    per_height: Mutex<HashMap<u32, u64>>,
}

struct SourceBodies {
    bodies: Arc<BodyMap>,
    hidden: HashSet<u32>,
    trip: Option<Arc<AtomicBool>>,
    witness: Option<(PathBuf, Arc<AtomicBool>)>,
    loads: Option<Arc<BodyLoadCounter>>,
}

impl SourceBodies {
    fn body(&self, height: u32, hash: BlockHash) -> Option<&[u8]> {
        if let Some((path, seen)) = &self.witness {
            if path.exists() {
                seen.store(true, Ordering::Release);
            }
        }
        if let Some(trip) = &self.trip {
            trip.store(true, Ordering::Release);
        }
        if self.hidden.contains(&height) {
            return None;
        }
        self.bodies
            .get(&(height, Hash256::from(hash).to_le_bytes()))
            .map(Vec::as_slice)
    }
}

impl BlockBodySource for SourceBodies {
    fn block_body(
        &self,
        height: u32,
        hash: BlockHash,
    ) -> Result<Option<Vec<u8>>, BlockBodyReadError> {
        if let Some(loads) = &self.loads {
            loads.total.fetch_add(1, Ordering::Relaxed);
            *loads
                .per_height
                .lock()
                .expect("body load counts are readable")
                .entry(height)
                .or_default() += 1;
        }
        Ok(self.body(height, hash).map(<[u8]>::to_vec))
    }

    fn block_body_range(
        &self,
        height: u32,
        hash: BlockHash,
        offset: u32,
        len: u32,
    ) -> Option<Vec<u8>> {
        let body = self.body(height, hash)?;
        let start = usize::try_from(offset).ok()?;
        let end = start.checked_add(usize::try_from(len).ok()?)?;
        body.get(start..end).map(<[u8]>::to_vec)
    }
}

struct StoreBodies {
    bodies: Arc<BodyMap>,
    serve: bool,
    from_height: u32,
    probe: Arc<Probe>,
}

impl BlockBodyStore for StoreBodies {
    fn persist_block_body(
        &self,
        _height: u32,
        _hash: Hash256,
        _body: &[u8],
    ) -> Result<(), StorageError> {
        Ok(())
    }

    fn load_block_body(&self, height: u32, hash: Hash256) -> Result<Option<Vec<u8>>, StorageError> {
        self.probe.reconciling.store(true, Ordering::Release);
        if !self.serve || height < self.from_height {
            return Ok(None);
        }
        Ok(self.bodies.get(&(height, hash.to_le_bytes())).cloned())
    }

    fn undo_record(&self, _height: u32, _hash: Hash256) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(None)
    }

    fn sync(&self) -> Result<(), StorageError> {
        Ok(())
    }
}

struct CrashAfterBulkImport {
    inner: FjallStore,
    crashed: AtomicBool,
}

impl CrashAfterBulkImport {
    fn admit(&self, batch: BufferedWriteBatch) -> Result<(Vec<BatchOp>, bool), StorageError> {
        if self.crashed.load(Ordering::Acquire) {
            return Err(StorageError::backend(
                "injected crash after a bulk import batch",
            ));
        }
        let ops = batch.into_ops();
        let tx_rows = ops
            .iter()
            .filter(|op| {
                matches!(
                    op,
                    BatchOp::Put {
                        cf: ColumnFamily::TxConfirmed,
                        ..
                    }
                )
            })
            .count();
        Ok((ops, tx_rows >= IMPORT_BATCH_ROWS / 2))
    }

    fn rebuild(ops: Vec<BatchOp>) -> BufferedWriteBatch {
        let mut batch = BufferedWriteBatch::default();
        for op in ops {
            match op {
                BatchOp::Put { cf, key, value } => batch.put_value(cf, &key, value),
                BatchOp::Delete { cf, key } => batch.delete(cf, &key),
                BatchOp::DeleteRange { cf, start, end } => batch.delete_range(cf, &start, &end),
            }
        }
        batch
    }

    fn crash_if(&self, bulk: bool) {
        if bulk {
            self.crashed.store(true, Ordering::Release);
        }
    }
}

impl KvStore for CrashAfterBulkImport {
    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.get(cf, key)
    }

    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<KvIter<'a>, StorageError> {
        self.inner.iter_prefix(cf, prefix)
    }

    fn scan_prefix_from_bounded(
        &self,
        cf: ColumnFamily,
        prefix: &[u8],
        start: &[u8],
        limit: PrefixScanLimit,
    ) -> Result<PrefixScan, StorageError> {
        self.inner
            .scan_prefix_from_bounded(cf, prefix, start, limit)
    }

    fn new_batch(&self) -> BufferedWriteBatch {
        self.inner.new_batch()
    }

    fn write(&self, batch: BufferedWriteBatch) -> Result<(), StorageError> {
        let (ops, bulk) = self.admit(batch)?;
        self.inner.write(Self::rebuild(ops))?;
        self.crash_if(bulk);
        Ok(())
    }

    fn write_durable(&self, batch: BufferedWriteBatch) -> Result<(), StorageError> {
        let (ops, bulk) = self.admit(batch)?;
        self.inner.write_durable(Self::rebuild(ops))?;
        self.crash_if(bulk);
        Ok(())
    }

    fn write_durable_if(
        &self,
        conditions: &[WriteCondition<'_>],
        batch: BufferedWriteBatch,
    ) -> Result<bool, StorageError> {
        let (ops, bulk) = self.admit(batch)?;
        let applied = self
            .inner
            .write_durable_if(conditions, Self::rebuild(ops))?;
        self.crash_if(applied && bulk);
        Ok(applied)
    }

    fn flush(&self) -> Result<(), StorageError> {
        self.inner.flush()
    }

    fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError> {
        self.inner.snapshot()
    }

    fn arm_persist_fault(&self, fault: bitcoin_rs_storage::PersistFault) {
        self.inner.arm_persist_fault(fault);
    }
}

#[derive(Clone, Copy, Default)]
enum Bodies {
    #[default]
    All,
    Hidden(u32),
    NoSource,
}

#[derive(Default)]
struct Start {
    bundle: IndexBundleDirective,
    backfill: bool,
    backfill_from: u32,
    bodies: Bodies,
    cancel_on_body_read: bool,
    crash_after_bulk_import: bool,
    witness: Option<(PathBuf, Arc<AtomicBool>)>,
    body_loads: Option<Arc<BodyLoadCounter>>,
}

struct Node {
    runtime: Arc<DerivedIndexRuntime>,
    lifecycle: Arc<ArcSwap<DerivedIndexLifecycle>>,
    adapter: DerivedIndexQueryAdapter,
    probe: Arc<Probe>,
    worker: Option<DerivedIndexWorker>,
}

fn restore(dir: &Path) -> IndexBundleDirective {
    IndexBundleDirective::Restore(IndexBundleRequest {
        dir: dir.to_path_buf(),
        network: Network::Regtest,
    })
}

fn export(dir: &Path) -> IndexBundleDirective {
    IndexBundleDirective::Export(IndexBundleRequest {
        dir: dir.to_path_buf(),
        network: Network::Regtest,
    })
}

impl Node {
    fn start(fixture: &ChainFixture, data_dir: &Path, start: Start) -> Self {
        let epoch = NEXT_EPOCH.fetch_add(1, Ordering::Relaxed);
        let (wake_tx, wake_rx) = crossbeam_channel::bounded(1);
        let runtime = Arc::new(DerivedIndexRuntime::new(wake_tx));
        let lifecycle = Arc::new(ArcSwap::from_pointee(DerivedIndexLifecycle::Opening));
        let adapter = DerivedIndexQueryAdapter::new(Arc::clone(&lifecycle));
        let probe = Arc::new(Probe::default());
        let shutdown = Arc::new(AtomicBool::new(false));
        let crash = start.crash_after_bulk_import;
        let spec = DerivedIndexOpenSpec {
            data_dir: data_dir.to_path_buf(),
            namespace: "txindex",
            storage_backend: StorageBackend::Fjall,
            epoch,
            enabled: IndexCapabilities::TX_LOOKUP,
            rollback_rebuild_cutover: u32::MAX,
            canonical_data_root: data_dir.to_path_buf(),
            open_store: Arc::new(move |dir| {
                let inner = FjallStore::open_with_cache(dir, STORE_CACHE_BYTES)
                    .map_err(bitcoin_rs_index::runtime::DerivedIndexWorkerError::Storage)?;
                if crash {
                    let store = Arc::new(CrashAfterBulkImport {
                        inner,
                        crashed: AtomicBool::new(false),
                    });
                    open_derived_index_store_on_worker(store, DEFAULT_BATCH_LIMITS, epoch)
                } else {
                    open_derived_index_store_on_worker(Arc::new(inner), DEFAULT_BATCH_LIMITS, epoch)
                }
            }),
            utxo: None,
            chain_transition: None,
            bundle: start.bundle,
            seed_slot: None,
        };
        let body_store: Arc<dyn BlockBodyStore> = Arc::new(StoreBodies {
            bodies: Arc::clone(&fixture.bodies),
            serve: start.backfill,
            from_height: start.backfill_from,
            probe: Arc::clone(&probe),
        });
        let body_source: Option<Arc<dyn BlockBodySource>> = match start.bodies {
            Bodies::NoSource => None,
            Bodies::All | Bodies::Hidden(_) => Some(Arc::new(SourceBodies {
                bodies: Arc::clone(&fixture.bodies),
                hidden: match start.bodies {
                    Bodies::Hidden(height) => HashSet::from([height]),
                    Bodies::All | Bodies::NoSource => HashSet::new(),
                },
                trip: start.cancel_on_body_read.then(|| Arc::clone(&shutdown)),
                witness: start.witness,
                loads: start.body_loads,
            })),
        };
        let chain_events: Arc<dyn ChainCursorSource> = probe.clone();
        let index_ahead: Arc<dyn IndexAheadSink> = Arc::new(NoIndexAhead);
        let worker = DerivedIndexWorker::spawn_with_open(
            Arc::clone(&runtime),
            spec,
            Arc::clone(&lifecycle),
            Generation::new(epoch),
            TipReader::new(Arc::new(ArcSwapOption::new(Some(Arc::clone(&fixture.tip))))),
            BlockTreeReader::new(Arc::clone(&fixture.tree)),
            Some(body_store),
            HistoryAccess::new(
                Arc::new(RetentionRegistry::new()),
                RetentionBudget::Unlimited,
            ),
            body_source,
            chain_events,
            index_ahead,
            shutdown,
            wake_rx,
        )
        .expect("spawn txindex worker");
        Self {
            runtime,
            lifecycle,
            adapter,
            probe,
            worker: Some(worker),
        }
    }

    fn finished(&self) -> bool {
        self.worker
            .as_ref()
            .is_none_or(DerivedIndexWorker::is_finished)
    }

    fn failure(&self) -> Option<String> {
        match &**self.lifecycle.load() {
            DerivedIndexLifecycle::Failed(reason) => Some(reason.to_string()),
            _ => None,
        }
    }

    fn synced_at(&self, height: u32) -> bool {
        matches!(
            self.adapter.index_info(),
            Ok(info) if info.synced && info.best_block_height == height
        )
    }

    fn wait_synced(&self, height: u32) {
        wait_until("txindex synced at the tip", || {
            assert!(
                !self.finished(),
                "worker exited before sync: {:?}",
                self.failure()
            );
            self.runtime.wake();
            self.synced_at(height)
        });
    }

    fn wait_reconciling(&self) {
        wait_until("worker to enter reconciliation", || {
            assert!(
                !self.finished(),
                "worker exited before reconciliation: {:?}",
                self.failure()
            );
            self.runtime.wake();
            self.probe.reconciling.load(Ordering::Acquire)
        });
    }

    fn wait_finished(&self) {
        wait_until("worker exit", || self.finished());
    }

    fn stop(mut self) {
        if let Some(worker) = self.worker.take() {
            worker.join();
        }
    }
}

fn wait_until(what: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(300);
    while !ready() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Durable {
    tx_confirmed: Vec<KvPair>,
    headers: Vec<KvPair>,
    watermark: Option<IndexWatermark>,
    floor: Option<u32>,
}

fn durable(data_dir: &Path) -> Durable {
    let store = Arc::new(
        FjallStore::open_with_cache(data_dir.join("txindex"), STORE_CACHE_BYTES)
            .expect("reopen txindex store"),
    );
    let rows = |cf| {
        store
            .iter_prefix(cf, &[])
            .expect("iterate column family")
            .collect::<Result<Vec<_>, _>>()
            .expect("read column family")
    };
    let tx_confirmed = rows(ColumnFamily::TxConfirmed);
    let headers = rows(ColumnFamily::BlockHeaders);
    let indexer = Indexer::new(Arc::clone(&store));
    let snapshot = indexer.snapshot().expect("index snapshot");
    let watermark = snapshot
        .capability_watermark(IndexCapability::TxLookup)
        .expect("txlookup watermark");
    let floor = watermark.map(|_| {
        snapshot
            .capability_floor(IndexCapability::TxLookup)
            .expect("txlookup floor")
    });
    Durable {
        tx_confirmed,
        headers,
        watermark,
        floor,
    }
}

fn read_dir_files(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut files: Vec<_> = fs::read_dir(dir)
        .expect("list bundle directory")
        .map(|entry| {
            let path = entry.expect("directory entry").path();
            let bytes = fs::read(&path).expect("read bundle file");
            (path, bytes)
        })
        .collect();
    files.sort();
    files
}

fn copy_bundle(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("create bundle copy");
    for name in [MANIFEST, ARTIFACT] {
        fs::copy(from.join(name), to.join(name)).expect("copy bundle file");
    }
}

fn backfilled_source(fixture: &ChainFixture, source: &Path) -> Durable {
    let node = Node::start(
        fixture,
        source,
        Start {
            backfill: true,
            ..Start::default()
        },
    );
    node.wait_synced(fixture.tip.height);
    node.stop();
    let state = durable(source);
    assert_eq!(state.watermark, Some(fixture.tip_watermark()));
    assert_eq!(state.floor, Some(0));
    assert_eq!(state.tx_confirmed.len(), fixture.tx_row_keys());
    state
}

fn exported_bundle(fixture: &ChainFixture, source: &Path, bundle: &Path) {
    let node = Node::start(
        fixture,
        source,
        Start {
            bundle: export(bundle),
            backfill: true,
            ..Start::default()
        },
    );
    node.wait_reconciling();
    node.stop();
    assert!(
        bundle.join(MANIFEST).is_file(),
        "export published no manifest"
    );
    assert!(
        bundle.join(ARTIFACT).is_file(),
        "export published no artifact"
    );
}

fn assert_untouched_fresh(receiver: &Path) {
    let state = durable(receiver);
    assert!(
        state.tx_confirmed.is_empty(),
        "a refused or withheld restore wrote {} TxConfirmed rows",
        state.tx_confirmed.len()
    );
    assert_eq!(state.watermark, None);
}

#[test]
fn export_then_restore_serves_the_same_queries_as_backfill() {
    let fixture = ChainFixture::new(6, 40);
    let root = tempfile::tempdir().expect("tempdir");
    let (source, receiver, bundle, again) = (
        root.path().join("source"),
        root.path().join("receiver"),
        root.path().join("bundle"),
        root.path().join("re-export"),
    );
    let source_state = backfilled_source(&fixture, &source);
    exported_bundle(&fixture, &source, &bundle);
    let bundle_files = read_dir_files(&bundle);

    let source_node = Node::start(
        &fixture,
        &source,
        Start {
            backfill: true,
            ..Start::default()
        },
    );
    let restored = Node::start(
        &fixture,
        &receiver,
        Start {
            bundle: restore(&bundle),
            ..Start::default()
        },
    );
    source_node.wait_synced(fixture.tip.height);
    restored.wait_synced(fixture.tip.height);
    for (txid, height) in &fixture.txids {
        let expected = source_node.adapter.transaction_height(txid);
        assert_eq!(expected, Ok(Some(*height)));
        assert_eq!(restored.adapter.transaction_height(txid), expected);
        let served = restored.adapter.transaction(txid);
        assert!(matches!(&served, Ok(Some(tx)) if tx.txid() == *txid));
        assert_eq!(served, source_node.adapter.transaction(txid));
    }
    let absent = Txid::from(Hash256::from_le_bytes(&[0xa5_u8; 32]));
    assert_eq!(restored.adapter.transaction(&absent), Ok(None));
    assert_eq!(source_node.adapter.transaction(&absent), Ok(None));
    assert_eq!(
        restored.adapter.index_info(),
        source_node.adapter.index_info()
    );
    restored.stop();
    source_node.stop();

    assert_eq!(durable(&receiver), source_state);
    assert_eq!(
        read_dir_files(&bundle),
        bundle_files,
        "restore mutated the bundle"
    );

    exported_bundle(&fixture, &receiver, &again);
    assert_eq!(
        fs::read(again.join(ARTIFACT)).expect("re-exported artifact"),
        fs::read(bundle.join(ARTIFACT)).expect("original artifact"),
    );
    assert_eq!(
        fs::read(again.join(MANIFEST)).expect("re-exported manifest"),
        fs::read(bundle.join(MANIFEST)).expect("original manifest"),
    );
}

#[test]
fn restore_below_a_restarted_receivers_tip_then_reconciles_forward() {
    let bundle_chain = ChainFixture::new(5, 25);
    let receiver_chain = ChainFixture::new(7, 25).restarted();
    let base = bundle_chain.tip.height;
    assert!(
        receiver_chain
            .bodies
            .contains_key(&(base, bundle_chain.tip.hash.to_le_bytes())),
        "the receiver must hold the bundle's base block"
    );
    let root = tempfile::tempdir().expect("tempdir");
    let (source, truth, receiver, bundle) = (
        root.path().join("source"),
        root.path().join("truth"),
        root.path().join("receiver"),
        root.path().join("bundle"),
    );
    let source_state = backfilled_source(&bundle_chain, &source);
    exported_bundle(&bundle_chain, &source, &bundle);
    let truth_state = backfilled_source(&receiver_chain, &truth);

    let withheld = root.path().join("receiver-withheld");
    let node = Node::start(
        &receiver_chain,
        &withheld,
        Start {
            bundle: restore(&bundle),
            bodies: Bodies::Hidden(receiver_chain.tip.height),
            ..Start::default()
        },
    );
    node.wait_reconciling();
    node.stop();
    assert_untouched_fresh(&withheld);

    let node = Node::start(
        &receiver_chain,
        &receiver,
        Start {
            bundle: restore(&bundle),
            ..Start::default()
        },
    );
    node.wait_reconciling();
    node.stop();
    assert_eq!(
        durable(&receiver),
        source_state,
        "the bundle must be restored through its base"
    );

    let node = Node::start(
        &receiver_chain,
        &receiver,
        Start {
            backfill: true,
            backfill_from: base + 1,
            ..Start::default()
        },
    );
    node.wait_synced(receiver_chain.tip.height);
    for (txid, height) in &receiver_chain.txids {
        assert_eq!(node.adapter.transaction_height(txid), Ok(Some(*height)));
    }
    node.stop();
    assert_eq!(durable(&receiver), truth_state);
}

#[test]
fn damaged_bundles_are_refused_before_any_write_or_reset() {
    type Damage = fn(&Path, u64);
    let fixture = ChainFixture::new(5, 30);
    let root = tempfile::tempdir().expect("tempdir");
    let (source, bundle) = (root.path().join("source"), root.path().join("bundle"));
    let source_state = backfilled_source(&fixture, &source);
    exported_bundle(&fixture, &source, &bundle);
    let artifact_len = fs::metadata(bundle.join(ARTIFACT))
        .expect("artifact metadata")
        .len();

    let damages: [(&str, Damage); 6] = [
        ("payload-bit-flip", |dir, len| {
            flip_byte(&dir.join(ARTIFACT), len - 1);
        }),
        ("header-bit-flip", |dir, _| {
            flip_byte(&dir.join(ARTIFACT), 10);
        }),
        ("artifact-truncated", |dir, len| {
            fs::OpenOptions::new()
                .write(true)
                .open(dir.join(ARTIFACT))
                .and_then(|file| file.set_len(len - 1))
                .expect("truncate artifact");
        }),
        ("artifact-extended", |dir, _| {
            let mut bytes = fs::read(dir.join(ARTIFACT)).expect("read artifact");
            bytes.push(0);
            fs::write(dir.join(ARTIFACT), bytes).expect("extend artifact");
        }),
        ("manifest-truncated", |dir, _| {
            let bytes = fs::read(dir.join(MANIFEST)).expect("read manifest");
            fs::write(dir.join(MANIFEST), &bytes[..bytes.len() / 2]).expect("truncate manifest");
        }),
        ("artifact-missing", |dir, _| {
            fs::remove_file(dir.join(ARTIFACT)).expect("remove artifact");
        }),
    ];

    for (name, damage) in damages {
        let damaged = root.path().join(format!("bundle-{name}"));
        copy_bundle(&bundle, &damaged);
        damage(&damaged, artifact_len);
        let damaged_files = read_dir_files(&damaged);

        let receiver = root.path().join(format!("receiver-{name}"));
        let node = Node::start(
            &fixture,
            &receiver,
            Start {
                bundle: restore(&damaged),
                ..Start::default()
            },
        );
        node.wait_reconciling();
        assert!(
            !node.synced_at(fixture.tip.height),
            "{name}: a refused bundle made the index ready"
        );
        node.stop();
        assert_untouched_fresh(&receiver);
        assert_eq!(
            read_dir_files(&damaged),
            damaged_files,
            "{name}: bundle rewritten"
        );

        let ready = Node::start(
            &fixture,
            &source,
            Start {
                bundle: restore(&damaged),
                backfill: true,
                ..Start::default()
            },
        );
        ready.wait_reconciling();
        ready.wait_synced(fixture.tip.height);
        ready.stop();
        assert_eq!(
            durable(&source),
            source_state,
            "{name}: ready index changed"
        );
    }
}

fn flip_byte(path: &Path, offset: u64) {
    let mut bytes = fs::read(path).expect("read artifact");
    let index = usize::try_from(offset).expect("offset fits usize");
    bytes[index] ^= 0x01;
    fs::write(path, bytes).expect("rewrite artifact");
}

#[test]
fn export_preserves_a_preexisting_destination() {
    let fixture = ChainFixture::new(4, 20);
    let root = tempfile::tempdir().expect("tempdir");
    let source = root.path().join("source");
    let source_state = backfilled_source(&fixture, &source);

    let with_manifest = root.path().join("has-manifest");
    fs::create_dir_all(&with_manifest).expect("create destination");
    fs::write(with_manifest.join(MANIFEST), b"operator manifest").expect("seed manifest");
    fs::write(with_manifest.join("notes.txt"), b"operator notes").expect("seed notes");

    let with_artifact = root.path().join("has-artifact");
    fs::create_dir_all(&with_artifact).expect("create destination");
    fs::write(with_artifact.join(ARTIFACT), b"operator artifact").expect("seed artifact");

    for destination in [&with_manifest, &with_artifact] {
        let before = read_dir_files(destination);
        let node = Node::start(
            &fixture,
            &source,
            Start {
                bundle: export(destination),
                backfill: true,
                ..Start::default()
            },
        );
        node.wait_reconciling();
        node.stop();
        assert_eq!(
            read_dir_files(destination),
            before,
            "export touched preexisting files in {}",
            destination.display()
        );
    }
    assert_eq!(durable(&source), source_state);

    let fresh = root.path().join("fresh");
    exported_bundle(&fixture, &source, &fresh);
}

#[test]
fn export_loads_each_block_body_once_across_pages() {
    let fixture = ChainFixture::new(15, 150);
    let rows = fixture.tx_row_keys();
    assert!(
        rows > CANCEL_POLL_RECORDS / 4,
        "fixture holds {rows} rows, too few to span export pages"
    );
    let root = tempfile::tempdir().expect("tempdir");
    let (source, receiver, bundle) = (
        root.path().join("source"),
        root.path().join("receiver"),
        root.path().join("bundle"),
    );
    let source_state = backfilled_source(&fixture, &source);

    let loads = Arc::new(BodyLoadCounter::default());
    let node = Node::start(
        &fixture,
        &source,
        Start {
            bundle: export(&bundle),
            backfill: true,
            body_loads: Some(Arc::clone(&loads)),
            ..Start::default()
        },
    );
    node.wait_reconciling();
    node.stop();
    assert!(
        bundle.join(MANIFEST).is_file(),
        "export published no manifest"
    );
    assert!(
        bundle.join(ARTIFACT).is_file(),
        "export published no artifact"
    );

    let per_height = loads
        .per_height
        .lock()
        .expect("body load counts are readable");
    let covered: Vec<u32> = (0..=fixture.tip.height).collect();
    assert_eq!(
        per_height.len(),
        covered.len(),
        "export touched {} bodies for {} covered heights: {per_height:?}",
        per_height.len(),
        covered.len(),
    );
    for height in covered {
        assert_eq!(
            per_height.get(&height),
            Some(&1),
            "block body at height {height} was loaded {:?} times, want exactly once",
            per_height.get(&height),
        );
    }

    let node = Node::start(
        &fixture,
        &receiver,
        Start {
            bundle: restore(&bundle),
            ..Start::default()
        },
    );
    node.wait_synced(fixture.tip.height);
    node.stop();
    assert_eq!(durable(&receiver), source_state);
}

#[test]
fn cancelled_export_removes_only_its_own_staging() {
    let fixture = ChainFixture::new(3, 2 * CANCEL_POLL_RECORDS / 3 + 1);
    assert!(fixture.txids.len() > CANCEL_POLL_RECORDS);
    let root = tempfile::tempdir().expect("tempdir");
    let (source, bundle) = (root.path().join("source"), root.path().join("bundle"));
    let source_state = backfilled_source(&fixture, &source);
    fs::create_dir_all(&bundle).expect("create destination");
    fs::write(bundle.join("notes.txt"), b"operator notes").expect("seed notes");
    let before = read_dir_files(&bundle);
    let staged = Arc::new(AtomicBool::new(false));

    let node = Node::start(
        &fixture,
        &source,
        Start {
            bundle: export(&bundle),
            backfill: true,
            cancel_on_body_read: true,
            witness: Some((bundle.join(ARTIFACT), Arc::clone(&staged))),
            ..Start::default()
        },
    );
    node.wait_finished();
    node.stop();
    assert!(
        staged.load(Ordering::Acquire),
        "export was cancelled before it created its artifact"
    );
    assert_eq!(
        read_dir_files(&bundle),
        before,
        "cancelled export left staging"
    );
    assert_eq!(durable(&source), source_state);

    exported_bundle(&fixture, &source, &bundle);
    assert_eq!(
        fs::read(bundle.join("notes.txt")).expect("operator notes"),
        b"operator notes"
    );
}

#[test]
fn cancelled_restore_writes_nothing_and_restart_completes() {
    let fixture = ChainFixture::new(3, 2 * CANCEL_POLL_RECORDS / 3 + 1);
    let root = tempfile::tempdir().expect("tempdir");
    let (source, receiver, bundle) = (
        root.path().join("source"),
        root.path().join("receiver"),
        root.path().join("bundle"),
    );
    let source_state = backfilled_source(&fixture, &source);
    exported_bundle(&fixture, &source, &bundle);

    let node = Node::start(
        &fixture,
        &receiver,
        Start {
            bundle: restore(&bundle),
            cancel_on_body_read: true,
            ..Start::default()
        },
    );
    node.wait_finished();
    node.stop();
    assert_untouched_fresh(&receiver);

    let node = Node::start(
        &fixture,
        &receiver,
        Start {
            bundle: restore(&bundle),
            ..Start::default()
        },
    );
    node.wait_synced(fixture.tip.height);
    node.stop();
    assert_eq!(durable(&receiver), source_state);
}

#[test]
fn missing_bodies_withhold_readiness_until_ordinary_backfill() {
    let fixture = ChainFixture::new(5, 25);
    let root = tempfile::tempdir().expect("tempdir");
    let (source, bundle) = (root.path().join("source"), root.path().join("bundle"));
    let source_state = backfilled_source(&fixture, &source);
    exported_bundle(&fixture, &source, &bundle);
    let (probe_txid, _) = fixture.txids[1];

    for (name, bodies) in [
        ("hidden-body", Bodies::Hidden(3)),
        ("no-body-source", Bodies::NoSource),
    ] {
        let receiver = root.path().join(format!("receiver-{name}"));
        let node = Node::start(
            &fixture,
            &receiver,
            Start {
                bundle: restore(&bundle),
                bodies,
                ..Start::default()
            },
        );
        node.wait_reconciling();
        assert!(
            !node.synced_at(fixture.tip.height),
            "{name}: withheld bundle made the index ready"
        );
        assert!(
            !matches!(node.adapter.transaction_height(&probe_txid), Ok(Some(_))),
            "{name}: withheld bundle served a lookup"
        );
        node.stop();
        assert_untouched_fresh(&receiver);

        let node = Node::start(
            &fixture,
            &receiver,
            Start {
                backfill: true,
                ..Start::default()
            },
        );
        node.wait_synced(fixture.tip.height);
        node.stop();
        assert_eq!(durable(&receiver), source_state, "{name}: backfill differs");
    }
}

#[test]
fn interrupted_import_is_cleared_on_restart_and_restore_retries() {
    let blocks = 24_u32;
    let per_block = IMPORT_BATCH_ROWS / 24 + 200;
    let fixture = ChainFixture::new(blocks, per_block);
    assert!(fixture.txids.len() > IMPORT_BATCH_ROWS);
    let root = tempfile::tempdir().expect("tempdir");
    let (source, receiver, bundle) = (
        root.path().join("source"),
        root.path().join("receiver"),
        root.path().join("bundle"),
    );
    let source_state = backfilled_source(&fixture, &source);
    exported_bundle(&fixture, &source, &bundle);

    let node = Node::start(
        &fixture,
        &receiver,
        Start {
            bundle: restore(&bundle),
            crash_after_bulk_import: true,
            ..Start::default()
        },
    );
    node.wait_finished();
    assert!(
        node.failure().is_some(),
        "an import that cannot commit must fail the worker"
    );
    node.stop();
    let interrupted = durable(&receiver);
    let headers = usize::try_from(blocks + 1).expect("header count fits usize");
    assert_eq!(
        interrupted.tx_confirmed.len(),
        IMPORT_BATCH_ROWS - headers,
        "the injected crash must leave exactly the first import batch on disk"
    );
    let source_rows: HashSet<_> = source_state.tx_confirmed.iter().collect();
    assert!(
        interrupted
            .tx_confirmed
            .iter()
            .all(|row| source_rows.contains(row)),
        "partial import rows must be bundle rows"
    );
    assert_eq!(interrupted.watermark, None, "partial import became ready");

    let node = Node::start(&fixture, &receiver, Start::default());
    node.wait_reconciling();
    assert!(!node.synced_at(fixture.tip.height));
    node.stop();
    assert_untouched_fresh(&receiver);

    let node = Node::start(
        &fixture,
        &receiver,
        Start {
            bundle: restore(&bundle),
            ..Start::default()
        },
    );
    node.wait_synced(fixture.tip.height);
    node.stop();
    assert_eq!(durable(&receiver), source_state);
}
