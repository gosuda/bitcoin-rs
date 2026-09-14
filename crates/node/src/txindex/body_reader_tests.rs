use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use bitcoin::{
    Amount, Block, BlockHash, ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode, TxOut, Witness,
    block::{Header as BlockHeader, Version},
    consensus::encode::serialize,
    hashes::Hash as _,
    pow::CompactTarget,
    script::Builder,
};

use bitcoin_rs_chain::NodeStatus;
use bitcoin_rs_primitives::Network;
use bitcoin_rs_primitives::consensus_bytes;
use bitcoin_rs_storage::StorageError;

use hashbrown::HashMap;

use super::*;
use bitcoin_rs_storage::block_body::BlockBodyReader;
use bitcoin_rs_storage::block_body::BlockBodyStore;

/// Mirrors `IndexedBlockBodyReader`'s strictly sequential prefetch cursor:
/// one prefetched window must be fully consumed in order before the next
/// `prefetch_positions` call.
struct SessionBodyStore {
    bodies: HashMap<(u32, [u8; 32]), Vec<u8>>,
    readers: AtomicUsize,
    prefetches: AtomicUsize,
    session_loads: AtomicUsize,
    direct_loads: AtomicUsize,
}

struct SessionBodyReader<'a> {
    store: &'a SessionBodyStore,
    entries: Vec<(u32, Hash256)>,
    next: usize,
}

impl BlockBodyReader for SessionBodyReader<'_> {
    fn prefetch_positions(&mut self, requests: &[(u32, Hash256)]) -> Result<(), StorageError> {
        if self.next != self.entries.len() {
            return Err(StorageError::InvalidOperation(
                "prefetched body positions were not fully consumed",
            ));
        }
        self.entries = requests.to_vec();
        self.next = 0;
        self.store.prefetches.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    fn load_block_body(
        &mut self,
        height: u32,
        hash: Hash256,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let Some(&(expected_height, expected_hash)) = self.entries.get(self.next) else {
            return Err(StorageError::InvalidOperation(
                "prefetched body positions are exhausted",
            ));
        };
        if expected_height != height || expected_hash != hash {
            return Err(StorageError::InvalidOperation(
                "prefetched body position consumed out of order",
            ));
        }
        self.next += 1;
        self.store.session_loads.fetch_add(1, Ordering::AcqRel);
        Ok(self
            .store
            .bodies
            .get(&(height, hash.to_le_bytes()))
            .cloned())
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
            entries: Vec::new(),
            next: 0,
        }))
    }

    fn sync(&self) -> Result<(), StorageError> {
        Ok(())
    }
}

fn session_body_store(bodies: HashMap<(u32, [u8; 32]), Vec<u8>>) -> Arc<SessionBodyStore> {
    Arc::new(SessionBodyStore {
        bodies,
        readers: AtomicUsize::new(0),
        prefetches: AtomicUsize::new(0),
        session_loads: AtomicUsize::new(0),
        direct_loads: AtomicUsize::new(0),
    })
}

fn test_worker(
    tree: BlockTree,
    tip: &TipSnapshot,
    body_store: Arc<SessionBodyStore>,
    data_dir: &std::path::Path,
) -> (Worker, Arc<dyn TxIndexWriter>) {
    let tree = Arc::new(RwLock::new(tree));
    let applied_tip = Arc::new(arc_swap::ArcSwapOption::empty());
    applied_tip.store(Some(Arc::new(tip.clone())));
    let (wake_tx, wake_rx) = crossbeam_channel::bounded(1);
    let runtime = Arc::new(DerivedIndexRuntime::new(wake_tx));
    let index_store = Arc::new(bitcoin_rs_storage::FjallStore::open(data_dir).expect("fjall open"));
    let writer: Arc<dyn TxIndexWriter> = Arc::new(parking_lot::RwLock::new(
        bitcoin_rs_index::IndexWriter::open(index_store, 1).expect("index writer open"),
    ));
    let worker = Worker {
        runtime,
        writer: Arc::clone(&writer),
        applied_tip,
        block_tree: tree,
        body_store: Some(body_store),
        batch_limits: DEFAULT_BATCH_LIMITS,
        enabled: IndexCapabilities::HISTORICAL,
        wake_rx,
        chain_events: detached_chain_publisher(),
        reporter: test_recovery_reporter(data_dir).0,
        quiet_period: Duration::ZERO,
        batch_delay: Duration::ZERO,
        // These tests never exercise reset routing; `u32::MAX` keeps every
        // stale watermark on the per-block rewind.
        rollback_rebuild_cutover: u32::MAX,
        utxo: None,
        chain_transition: None,
    };
    (worker, writer)
}

/// Runs `catch_up_to` passes until the worker reports `CaughtUp`.
fn catch_up(worker: &Worker, writer: &Arc<dyn TxIndexWriter>, tip: &TipSnapshot) {
    let mut pending = None;
    for _ in 0..64 {
        let (fence, watermarks) = writer.fenced_watermarks().expect("watermarks");
        match worker
            .catch_up_to(
                tip,
                fence,
                watermarks,
                watermarks.tx_lookup,
                IndexCapabilities::HISTORICAL,
                &mut pending,
            )
            .expect("catch-up pass")
        {
            ReconcileAction::CaughtUp => return,
            ReconcileAction::Progressed | ReconcileAction::Buffered => {}
            ReconcileAction::Stalled => panic!("worker stalled"),
        }
    }
    panic!("worker did not converge");
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

    let mut bodies = HashMap::new();
    bodies.insert((tip.height, hash.to_le_bytes()), consensus_bytes(&block));
    let body_store = session_body_store(bodies);
    let data_dir = tempfile::tempdir()?;
    let (worker, writer) = test_worker(tree, &tip, body_store.clone(), data_dir.path());
    let mut pending = None;

    let (fence, watermarks) = writer.fenced_watermarks()?;
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

fn coinbase_tx(height: u32, pad: usize) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: bitcoin::OutPoint::null(),
            script_sig: Builder::new().push_int(i64::from(height)).into_script(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x6a_u8; pad]),
        }],
    }
}

fn tree_header(block: &Block) -> bitcoin_rs_primitives::Header {
    bitcoin_rs_primitives::Header::consensus_decode(&serialize(&block.header))
        .expect("80-byte header")
}

fn padded_block(prev_hash: Hash256, height: u32, pad: usize) -> (Block, Hash256) {
    let prev_blockhash = BlockHash::from_byte_array(prev_hash.to_le_bytes());
    let mut block = Block {
        header: BlockHeader {
            version: Version::ONE,
            prev_blockhash,
            merkle_root: TxMerkleNode::all_zeros(),
            time: height,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata: vec![coinbase_tx(height, pad)],
    };
    block.header.merkle_root = block
        .compute_merkle_root()
        .unwrap_or_else(TxMerkleNode::all_zeros);
    let hash = Hash256::from_le_bytes(block.block_hash().as_byte_array());
    (block, hash)
}

/// Regression for #1032: a body that crosses `PREPARE_CHUNK_BYTES` has already
/// been consumed from the reader's strictly sequential prefetch cursor, so it
/// must be retained rather than left at the front of `identities`. Each block
/// here carries a ~1 MiB coinbase output so the byte cap trips inside a single
/// prefetch window; before the fix the next sub-chunk loaded a stale cursor
/// entry and failed with "prefetched body position consumed out of order".
#[test]
fn catch_up_retains_every_body_the_prefetch_cursor_hands_out()
-> Result<(), Box<dyn std::error::Error>> {
    const BLOCKS: u32 = 40;
    const BODY_PAD: usize = 1 << 20;

    let mut tree = BlockTree::new();
    let mut bodies = HashMap::new();
    let mut prev = Hash256::from_le_bytes(&[0_u8; 32]);
    let mut tip_id = None;
    for height in 0..BLOCKS {
        let (block, hash) = padded_block(prev, height, BODY_PAD);
        tip_id = Some(tree.insert_header(tree_header(&block), NodeStatus::HeaderValid)?);
        bodies.insert((height, hash.to_le_bytes()), serialize(&block));
        prev = hash;
    }
    let tip_id = tip_id.expect("tip");
    let node = tree.node(tip_id)?;
    let tip = TipSnapshot {
        tip_id,
        height: node.height,
        chainwork: node.chainwork,
        hash: node.hash,
    };

    let body_store = session_body_store(bodies);
    let data_dir = tempfile::tempdir()?;
    let (worker, writer) = test_worker(tree, &tip, body_store.clone(), data_dir.path());

    catch_up(&worker, &writer, &tip);

    let watermarks = writer.fenced_watermarks()?.1;
    assert_eq!(
        watermarks.tx_lookup,
        Some(IndexWatermark {
            height: tip.height,
            hash: tip.hash.to_le_bytes(),
        }),
        "tx_lookup watermark"
    );
    assert_eq!(
        body_store.session_loads.load(Ordering::Acquire),
        usize::try_from(BLOCKS)?
    );
    assert_eq!(body_store.prefetches.load(Ordering::Acquire), 1);
    assert_eq!(body_store.readers.load(Ordering::Acquire), 1);
    assert_eq!(body_store.direct_loads.load(Ordering::Acquire), 0);
    Ok(())
}
