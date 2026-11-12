use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use arc_swap::{ArcSwap, ArcSwapOption};
use bitcoin::blockdata::block::Header as BtcHeader;
use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash;
use bitcoin::script::Builder;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, CompactTarget, ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode, TxOut, Witness,
};
use bitcoin_rs_consensus::latch::LatchWriter;
use bitcoin_rs_consensus::primitives::layout::ParsedBlock;
use bitcoin_rs_consensus::primitives::{BlockHash, Hash256, Txid};
use bitcoin_rs_execution::chain::{BlockTree, BlockTreeReader, NodeStatus, TipReader, TipSnapshot};
use bitcoin_rs_projection::IndexCapabilities;
use bitcoin_rs_projection::portable::IndexBundleDirective;
use bitcoin_rs_projection::query_api::DerivedIndexQuery;
use bitcoin_rs_projection::reconcile::{ChainCursorSource, ConsumerCursor};
use bitcoin_rs_projection::runtime::{
    DEFAULT_BATCH_LIMITS, DerivedIndexLifecycle, DerivedIndexOpenSpec, DerivedIndexQueryAdapter,
    DerivedIndexRuntime, DerivedIndexWorker, Generation, IndexAheadError, IndexAheadSink,
    open_derived_index_store_on_worker,
};
use bitcoin_rs_storage::block_body::{BlockBodyReadError, BlockBodySource, BlockBodyStore};
use bitcoin_rs_storage::pruning::{HistoryAccess, RetentionBudget, RetentionRegistry};
use bitcoin_rs_storage::{
    Bytes, CommittedBlock, CommittedFacts, CreatedOutput, RocksDbStore, SpentPrevout,
    StorageBackend, StorageError, TxFacts,
};
use parking_lot::RwLock;

type BodyMap = HashMap<(u32, [u8; 32]), Vec<u8>>;

struct CountingBlockBodyStore {
    bodies: Arc<RwLock<BodyMap>>,
    load_count: Arc<AtomicU64>,
}

impl BlockBodyStore for CountingBlockBodyStore {
    fn persist_block_body(
        &self,
        _height: u32,
        _hash: Hash256,
        _body: &[u8],
    ) -> Result<(), StorageError> {
        Ok(())
    }

    fn load_block_body(&self, height: u32, hash: Hash256) -> Result<Option<Vec<u8>>, StorageError> {
        self.load_count.fetch_add(1, Ordering::SeqCst);
        let guard = self.bodies.read();
        Ok(guard.get(&(height, hash.to_le_bytes())).cloned())
    }

    fn undo_record(&self, _height: u32, _hash: Hash256) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(None)
    }

    fn sync(&self) -> Result<(), StorageError> {
        Ok(())
    }
}

struct PassthroughBodySource {
    bodies: Arc<RwLock<BodyMap>>,
    calls: Arc<AtomicU64>,
}

impl BlockBodySource for PassthroughBodySource {
    fn block_body(
        &self,
        height: u32,
        hash: BlockHash,
    ) -> Result<Option<Vec<u8>>, BlockBodyReadError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let guard = self.bodies.read();
        Ok(guard
            .get(&(height, Hash256::from(hash).to_le_bytes()))
            .cloned())
    }

    fn block_body_range(
        &self,
        height: u32,
        hash: BlockHash,
        offset: u32,
        len: u32,
    ) -> Option<Vec<u8>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let guard = self.bodies.read();
        let body = guard.get(&(height, Hash256::from(hash).to_le_bytes()))?;
        let start = usize::try_from(offset).ok()?;
        let end = start.checked_add(usize::try_from(len).ok()?)?;
        body.get(start..end).map(<[u8]>::to_vec)
    }
}

#[derive(Default)]
struct TestProbe;

impl ChainCursorSource for TestProbe {
    fn cursor(&self) -> ConsumerCursor {
        ConsumerCursor {
            epoch: 0,
            sequence: 0,
            height: 0,
            hash: Hash256::from_le_bytes(&[0_u8; 32]),
        }
    }
}

struct TestIndexAhead;

impl IndexAheadSink for TestIndexAhead {
    fn report_index_ahead(
        &self,
        _capability: &str,
        _index_height: u32,
        _tip_height: u32,
        _tip_hash_be: &str,
        _index_hash_be: &str,
        _depth: u32,
        _unix_secs: u64,
    ) -> Result<(), IndexAheadError> {
        Ok(())
    }
}

fn make_coinbase(height: u32) -> Transaction {
    Transaction {
        version: Version::ONE,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: bitcoin::OutPoint::null(),
            script_sig: Builder::new().push_int(i64::from(height)).into_script(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_000_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

fn make_tx(prev_txid: [u8; 32], prev_vout: u32, value: u64) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: bitcoin::OutPoint {
                txid: bitcoin::Txid::from_byte_array(prev_txid),
                vout: prev_vout,
            },
            script_sig: Builder::new().push_int(1).into_script(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::from_bytes(vec![0x52]),
        }],
    }
}

fn mine_test_block(prev: [u8; 32], height: u32, txs: Vec<Transaction>) -> bitcoin::Block {
    let mut txdata = Vec::with_capacity(txs.len() + 1);
    txdata.push(make_coinbase(height));
    txdata.extend(txs);
    let mut block = bitcoin::Block {
        header: BtcHeader {
            version: bitcoin::block::Version::ONE,
            prev_blockhash: bitcoin::BlockHash::from_byte_array(prev),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 1_700_000_000 + height,
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

#[expect(
    clippy::expect_used,
    reason = "fixture decodes local regtest bytes with checked shapes"
)]
fn block_to_facts(
    block: &bitcoin::Block,
    height: u32,
    commit_id: u64,
    undo_scripts: &HashMap<([u8; 32], u32), (u64, Bytes)>,
) -> CommittedFacts {
    let bytes = serialize(block);
    let parsed = ParsedBlock::parse_exact(&bytes).expect("valid block layout");
    let header_bytes = serialize(&block.header);
    let header: [u8; 80] = header_bytes[..80].try_into().expect("80 bytes header");
    let hash = block.block_hash().to_byte_array();
    let parent_hash = block.header.prev_blockhash.to_byte_array();

    let mut ptxs = parsed.transactions().iter();
    let mut txs = Vec::new();
    for (idx, tx) in block.txdata.iter().enumerate() {
        let ptx = ptxs.next().expect("ptx exists");
        let txid = tx.compute_txid().to_byte_array();
        let offset = ptx.span().start();
        let len = ptx.span().len();

        let mut inputs = Vec::new();
        if idx > 0 {
            for input in &tx.input {
                let prev_txid = input.previous_output.txid.to_byte_array();
                let prev_vout = input.previous_output.vout;
                let (value, script) = undo_scripts
                    .get(&(prev_txid, prev_vout))
                    .cloned()
                    .unwrap_or((0, Bytes::from_static(&[0x51])));
                inputs.push(SpentPrevout {
                    txid: prev_txid,
                    vout: prev_vout,
                    value,
                    script,
                    height: 0,
                    coinbase: false,
                });
            }
        }

        let mut outputs = Vec::new();
        for (vout, out) in tx.output.iter().enumerate() {
            let vout_u32 = u32::try_from(vout).expect("vout fits u32");
            outputs.push(CreatedOutput {
                vout: vout_u32,
                value: out.value.to_sat(),
                script: Bytes::copy_from_slice(out.script_pubkey.as_bytes()),
            });
        }

        txs.push(TxFacts {
            txid,
            offset,
            len,
            inputs,
            outputs,
        });
    }

    CommittedFacts {
        commit_id,
        blocks: vec![CommittedBlock {
            height,
            hash,
            parent_hash,
            header,
            txs,
        }],
    }
}

// PRJ-01
#[test]
#[expect(
    clippy::expect_used,
    reason = "the harness asserts wiring invariants on local fixtures"
)]
fn live_index_path_reads_zero_block_bodies() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let data_dir = temp_dir.path();
    let load_counter = Arc::new(AtomicU64::new(0));
    let source_calls = Arc::new(AtomicU64::new(0));
    let mut tree = BlockTree::new();
    let bodies = Arc::new(RwLock::new(BodyMap::new()));

    let genesis = mine_test_block([0_u8; 32], 0, Vec::new());
    let gen_bytes = serialize(&genesis);
    let gen_hash = genesis.block_hash().to_byte_array();
    let gen_header: bitcoin_rs_consensus::primitives::Header =
        bitcoin_rs_consensus::primitives::deserialize(&serialize(&genesis.header)).expect("header");
    let gen_id = tree
        .insert_header(gen_header, NodeStatus::HeaderValid)
        .expect("insert genesis");
    tree.record_applied_tx_count(gen_id, 1).expect("tx count");
    bodies.write().insert((0, gen_hash), gen_bytes);

    let b1_tx = make_tx(
        genesis.txdata[0].compute_txid().to_byte_array(),
        0,
        49_000_000,
    );
    let b1 = mine_test_block(gen_hash, 1, vec![b1_tx]);
    let b1_bytes = serialize(&b1);
    let b1_hash = b1.block_hash().to_byte_array();
    let b1_header: bitcoin_rs_consensus::primitives::Header =
        bitcoin_rs_consensus::primitives::deserialize(&serialize(&b1.header)).expect("header");
    let b1_id = tree
        .insert_header(b1_header, NodeStatus::HeaderValid)
        .expect("insert b1");
    tree.record_applied_tx_count(b1_id, 2).expect("tx count");
    bodies.write().insert((1, b1_hash), b1_bytes);

    let b2 = mine_test_block(b1_hash, 2, Vec::new());
    let b2_bytes = serialize(&b2);
    let b2_hash = b2.block_hash().to_byte_array();
    let b2_header: bitcoin_rs_consensus::primitives::Header =
        bitcoin_rs_consensus::primitives::deserialize(&serialize(&b2.header)).expect("header");
    let b2_id = tree
        .insert_header(b2_header, NodeStatus::HeaderValid)
        .expect("insert b2");
    tree.record_applied_tx_count(b2_id, 3).expect("tx count");
    bodies.write().insert((2, b2_hash), b2_bytes);

    let tip_node = tree.node(b2_id).expect("tip node");
    let tip = Arc::new(TipSnapshot {
        tip_id: b2_id,
        height: tip_node.height,
        chainwork: tip_node.chainwork,
        hash: tip_node.hash,
        chain_tx_count: tip_node.chain_tx_count,
    });
    let tip_reader = TipReader::new(Arc::new(ArcSwapOption::new(Some(tip))));
    let tree_reader = BlockTreeReader::new(Arc::new(RwLock::new(tree)));

    let body_store: Arc<dyn BlockBodyStore> = Arc::new(CountingBlockBodyStore {
        bodies: Arc::clone(&bodies),
        load_count: Arc::clone(&load_counter),
    });
    let body_source: Arc<dyn BlockBodySource> = Arc::new(PassthroughBodySource {
        bodies: Arc::clone(&bodies),
        calls: Arc::clone(&source_calls),
    });

    let (wake_tx, wake_rx) = crossbeam_channel::bounded(1);
    let runtime = Arc::new(DerivedIndexRuntime::new(wake_tx.clone()));
    let lifecycle = Arc::new(ArcSwap::from_pointee(DerivedIndexLifecycle::Opening));
    let adapter = DerivedIndexQueryAdapter::new(Arc::clone(&lifecycle));
    let shutdown = Arc::new(LatchWriter::new());

    let (facts_tx, facts_rx) = crossbeam_channel::bounded(16);
    let facts_charge = bitcoin_rs_storage::budget::ChargeHandle::new(
        Arc::new(bitcoin_rs_storage::budget::UnboundedBudget),
        bitcoin_rs_storage::budget::BudgetOwner::FactsQueue,
    );
    let facts_gap = Arc::new(AtomicBool::new(false));

    let spec = DerivedIndexOpenSpec {
        scripthash_limit: bitcoin_rs_projection::runtime::DEFAULT_SCRIPTHASH_LIMIT,
        data_dir: data_dir.to_path_buf(),
        namespace: "txindex",
        storage_backend: StorageBackend::RocksDb,
        epoch: 1,
        enabled: IndexCapabilities::TX_LOOKUP,
        rollback_rebuild_cutover: u32::MAX,
        canonical_data_root: data_dir.to_path_buf(),
        open_store: Arc::new(move |dir| {
            let inner = RocksDbStore::open_with_cache(dir, 16 * 1024 * 1024)
                .map_err(bitcoin_rs_projection::runtime::DerivedIndexWorkerError::Storage)?;
            open_derived_index_store_on_worker(Arc::new(inner), DEFAULT_BATCH_LIMITS, 1)
        }),
        bundle: IndexBundleDirective::None,
        facts_rx: Some(facts_rx),
        facts_charge: Some(facts_charge),
        query_charge: None,
        facts_gap: Some(facts_gap),
        cpu: None,
    };

    let worker = DerivedIndexWorker::spawn_with_open(
        Arc::clone(&runtime),
        spec,
        Arc::clone(&lifecycle),
        Generation::new(1),
        tip_reader,
        None,
        tree_reader,
        Some(body_store),
        HistoryAccess::new(
            Arc::new(RetentionRegistry::new()),
            RetentionBudget::Unlimited,
        ),
        Some(body_source),
        Arc::new(TestProbe),
        Arc::new(TestIndexAhead),
        shutdown.reader(),
        wake_rx,
    )
    .expect("worker spawns");

    let mut undo_map = HashMap::new();
    undo_map.insert(
        (genesis.txdata[0].compute_txid().to_byte_array(), 0),
        (50_000_000, Bytes::from_static(&[0x51])),
    );

    let facts0 = block_to_facts(&genesis, 0, 1, &undo_map);
    let facts1 = block_to_facts(&b1, 1, 2, &undo_map);
    let facts2 = block_to_facts(&b2, 2, 3, &undo_map);

    facts_tx.send(Arc::new(facts0)).expect("send facts0");
    facts_tx.send(Arc::new(facts1)).expect("send facts1");
    facts_tx.send(Arc::new(facts2)).expect("send facts2");
    let _ = wake_tx.try_send(());

    let start = Instant::now();
    loop {
        if start.elapsed() > Duration::from_secs(10) {
            panic!("timed out waiting for index catch up");
        }
        if let Ok(info) = adapter.index_info() {
            if info.synced && info.best_block_height == 2 {
                assert_eq!(info.applied_height, 2);
                assert_eq!(info.verified_height, 2);
                assert_eq!(info.coverage_height, 2);
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    // PRJ-01
    let reads = load_counter.load(Ordering::SeqCst);
    assert_eq!(
        reads, 0,
        "live index path must read zero block bodies, but read {reads}"
    );
    assert_eq!(
        source_calls.load(Ordering::SeqCst),
        0,
        "live index path must not read bodies through the body source either"
    );

    let b1_txid = Txid::from(Hash256::from_le_bytes(
        &b1.txdata[1].compute_txid().to_byte_array(),
    ));
    let queried = adapter.transaction(&b1_txid).expect("query transaction");
    assert!(
        queried.is_some(),
        "transaction from facts must be queryable"
    );

    shutdown.trigger();
    worker.join();
}
