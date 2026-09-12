use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use bitcoin_rs_chain::NodeStatus;
use bitcoin_rs_primitives::Network;
use bitcoin_rs_primitives::consensus_bytes;
use bitcoin_rs_storage::StorageError;

use super::*;
use bitcoin_rs_storage::block_body::BlockBodyReader;
use bitcoin_rs_storage::block_body::BlockBodyStore;

struct SessionBodyStore {
    height: u32,
    hash: Hash256,
    body: Vec<u8>,
    readers: AtomicUsize,
    prefetches: AtomicUsize,
    session_loads: AtomicUsize,
    direct_loads: AtomicUsize,
}

struct SessionBodyReader<'a> {
    store: &'a SessionBodyStore,
    pending: Option<(u32, Hash256)>,
}

impl BlockBodyReader for SessionBodyReader<'_> {
    fn prefetch_positions(&mut self, requests: &[(u32, Hash256)]) -> Result<(), StorageError> {
        let [request] = requests else {
            return Err(StorageError::InvalidOperation(
                "session test expects one prefetched position",
            ));
        };
        if self.pending.replace(*request).is_some() {
            return Err(StorageError::InvalidOperation(
                "session test position was not consumed",
            ));
        }
        self.store.prefetches.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    fn load_block_body(
        &mut self,
        height: u32,
        hash: Hash256,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        if self.pending.take() != Some((height, hash)) {
            return Err(StorageError::InvalidOperation(
                "session body loaded without matching prefetch",
            ));
        }
        self.store.session_loads.fetch_add(1, Ordering::AcqRel);
        Ok((height == self.store.height && hash == self.store.hash)
            .then(|| self.store.body.clone()))
    }
}

impl BlockBodyStore for SessionBodyStore {
    fn persist_block_body(
        &self,
        _height: u32,
        _hash: Hash256,
        _body: &[u8],
    ) -> Result<(), StorageError> {
        Ok(())
    }

    fn load_block_body(
        &self,
        _height: u32,
        _hash: Hash256,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        self.direct_loads.fetch_add(1, Ordering::AcqRel);
        Err(StorageError::InvalidOperation(
            "direct body load must not be used",
        ))
    }

    fn reader(&self) -> Result<Box<dyn BlockBodyReader + '_>, StorageError> {
        self.readers.fetch_add(1, Ordering::AcqRel);
        Ok(Box::new(SessionBodyReader {
            store: self,
            pending: None,
        }))
    }

    fn sync(&self) -> Result<(), StorageError> {
        Ok(())
    }
}

#[test]
fn catch_up_uses_one_body_reader_session() -> Result<(), Box<dyn std::error::Error>> {
    let block = Network::Regtest.genesis_block();
    let hash = block.block_hash().0;
    let mut tree = BlockTree::new();
    let tip_id = tree.insert_header(block.header, NodeStatus::HeaderValid)?;
    let node = tree.node(tip_id)?;
    let tip = TipSnapshot {
        tip_id,
        height: node.height,
        chainwork: node.chainwork,
        hash: node.hash,
    };

    let tree = Arc::new(RwLock::new(tree));
    let applied_tip = Arc::new(arc_swap::ArcSwapOption::empty());
    applied_tip.store(Some(Arc::new(tip.clone())));
    let (wake_tx, wake_rx) = crossbeam_channel::bounded(1);
    let runtime = Arc::new(DerivedIndexRuntime::new(wake_tx));
    let data_dir = tempfile::tempdir()?;
    let index_store = Arc::new(bitcoin_rs_storage::FjallStore::open(data_dir.path())?);
    let writer: Arc<dyn TxIndexWriter> = Arc::new(parking_lot::RwLock::new(
        bitcoin_rs_index::IndexWriter::open(index_store, 1)?,
    ));
    let body_store = Arc::new(SessionBodyStore {
        height: tip.height,
        hash,
        body: consensus_bytes(&block),
        readers: AtomicUsize::new(0),
        prefetches: AtomicUsize::new(0),
        session_loads: AtomicUsize::new(0),
        direct_loads: AtomicUsize::new(0),
    });
    let (fence, watermarks) = writer.fenced_watermarks()?;
    let worker = Worker {
        runtime,
        writer,
        applied_tip,
        block_tree: tree,
        body_store: Some(body_store.clone()),
        batch_limits: DEFAULT_BATCH_LIMITS,
        enabled: IndexCapabilities::HISTORICAL,
        wake_rx,
        chain_events: detached_chain_publisher(),
        reporter: test_recovery_reporter(data_dir.path()).0,
        quiet_period: Duration::ZERO,
        batch_delay: Duration::ZERO,
        // The body-reader session test never exercises reset routing;
        // `u32::MAX` keeps every stale watermark on the per-block rewind.
        rollback_rebuild_cutover: u32::MAX,
        utxo: None,
        chain_transition: None,
    };
    let mut pending = None;

    assert!(matches!(
        worker.catch_up_to(
            &tip,
            fence,
            watermarks,
            None,
            IndexCapabilities::HISTORICAL,
            &mut pending
        )?,
        ReconcileAction::Buffered
    ));
    assert_eq!(body_store.readers.load(Ordering::Acquire), 1);
    assert_eq!(body_store.prefetches.load(Ordering::Acquire), 1);
    assert_eq!(body_store.session_loads.load(Ordering::Acquire), 1);
    assert_eq!(body_store.direct_loads.load(Ordering::Acquire), 0);
    Ok(())
}
