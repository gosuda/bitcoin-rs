use crate::runtime::DerivedIndexRuntime;

// SNP-08
#[test]
fn only_heights_without_historical_facts_await_them() -> Result<(), TestError> {
    let (wake_tx, _wake_rx) = crossbeam_channel::bounded(1);
    let runtime = DerivedIndexRuntime::new(wake_tx);
    assert!(!runtime.awaits_historical_facts(0));

    runtime.set_historical_window(200, 50);
    assert!(!runtime.awaits_historical_facts(49));
    assert!(runtime.awaits_historical_facts(50));
    assert!(runtime.awaits_historical_facts(200));
    assert!(!runtime.awaits_historical_facts(201));

    runtime.note_historical_facts(60);
    assert!(!runtime.awaits_historical_facts(60));
    assert!(runtime.awaits_historical_facts(61));

    runtime.note_historical_facts(10);
    assert!(runtime.awaits_historical_facts(61));
    Ok(())
}

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use arc_swap::ArcSwapOption;
use bitcoin::{
    Amount, Block, ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode, TxOut, Witness,
    absolute::LockTime,
    block::{Header as BlockHeader, Version},
    consensus::encode::serialize,
    hashes::Hash as _,
    pow::CompactTarget,
    script::Builder,
    transaction::Version as TxVersion,
};
use bitcoin_rs_consensus::latch::LatchReader;
use bitcoin_rs_consensus::primitives::Hash256;
use bitcoin_rs_consensus::primitives::layout::{
    parse_exact_call_count, reset_parse_exact_call_count,
};
use bitcoin_rs_execution::chain::{BlockTree, BlockTreeReader, NodeStatus, TipReader, TipSnapshot};
use bitcoin_rs_storage::block_body::BlockBodyStore;
use bitcoin_rs_storage::budget::CpuShares;
use bitcoin_rs_storage::pruning::{HistoryAccess, RetentionBudget, RetentionRegistry};
use bitcoin_rs_storage::{CommittedBlock, CommittedFacts, RocksDbStore, StorageError, TxFacts};
use parking_lot::{Mutex, RwLock};

use crate::IndexCapabilities;
use crate::portable::TestError;
use crate::reconcile::{ChainCursorSource, ConsumerCursor};
use crate::runtime::{DEFAULT_BATCH_LIMITS, IndexAheadError, IndexAheadSink, Worker};

type BodyMap = hashbrown::HashMap<(u32, [u8; 32]), Vec<u8>>;

struct CountingBodies {
    bodies: Mutex<BodyMap>,
    loads: AtomicU64,
}

impl BlockBodyStore for CountingBodies {
    fn persist_block_body(
        &self,
        height: u32,
        hash: Hash256,
        body: &[u8],
    ) -> Result<(), StorageError> {
        self.bodies
            .lock()
            .insert((height, hash.to_le_bytes()), body.to_vec());
        Ok(())
    }

    fn load_block_body(&self, height: u32, hash: Hash256) -> Result<Option<Vec<u8>>, StorageError> {
        self.loads.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .bodies
            .lock()
            .get(&(height, hash.to_le_bytes()))
            .cloned())
    }

    fn undo_record(&self, _height: u32, _hash: Hash256) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(None)
    }

    fn sync(&self) -> Result<(), StorageError> {
        Ok(())
    }
}

struct StillCursor;

impl ChainCursorSource for StillCursor {
    fn cursor(&self) -> ConsumerCursor {
        ConsumerCursor {
            epoch: 0,
            sequence: 0,
            height: 0,
            hash: Hash256::from_le_bytes(&[0; 32]),
        }
    }
}

struct DropEvidence;

impl IndexAheadSink for DropEvidence {
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

fn snp08_block(prev: Hash256, height: u32) -> Block {
    let coinbase = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
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
    };
    let mut block = Block {
        header: BlockHeader {
            version: Version::ONE,
            prev_blockhash: bitcoin::BlockHash::from_byte_array(prev.to_le_bytes()),
            merkle_root: TxMerkleNode::all_zeros(),
            time: height,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata: vec![coinbase],
    };
    block.header.merkle_root = block
        .compute_merkle_root()
        .unwrap_or(TxMerkleNode::all_zeros());
    block
}

fn snp08_facts(block: &Block, height: u32, parent: [u8; 32]) -> Result<CommittedBlock, TestError> {
    let header: [u8; 80] = serialize(&block.header)[..80]
        .try_into()
        .map_err(|_| TestError::Missing("80-byte header"))?;
    Ok(CommittedBlock {
        height,
        hash: block.block_hash().to_byte_array(),
        parent_hash: parent,
        header,
        txs: block
            .txdata
            .iter()
            .map(|tx| TxFacts {
                txid: tx.compute_txid().to_byte_array(),
                offset: 81,
                len: 60,
                inputs: Vec::new(),
                outputs: Vec::new(),
            })
            .collect(),
    })
}

// SNP-08
#[test]
fn heights_above_the_base_come_only_from_committed_facts() -> Result<(), TestError> {
    use bitcoin_rs_consensus::primitives::deserialize;

    let bodies = Arc::new(CountingBodies {
        bodies: Mutex::new(hashbrown::HashMap::new()),
        loads: AtomicU64::new(0),
    });
    let mut tree = BlockTree::new();
    let mut facts: Vec<CommittedBlock> = Vec::new();
    let mut prev = Hash256::from_le_bytes(&[0; 32]);
    let mut tip_id = None;
    for height in 0..=3 {
        let block = snp08_block(prev, height);
        let bytes = serialize(&block);
        let hash = Hash256::from_le_bytes(&block.block_hash().to_byte_array());
        let header =
            deserialize::<bitcoin_rs_consensus::primitives::Header>(&serialize(&block.header))?;
        let node_id = tree.insert_header(header, NodeStatus::HeaderValid)?;
        bodies
            .bodies
            .lock()
            .insert((height, hash.to_le_bytes()), bytes);
        facts.push(snp08_facts(&block, height, prev.to_le_bytes())?);
        prev = hash;
        if height == 3 {
            tip_id = Some(node_id);
        }
    }
    let tip_id = tip_id.ok_or("height three inserted")?;
    let node = tree.node(tip_id)?;
    let tip = Arc::new(TipSnapshot {
        tip_id,
        height: node.height,
        chainwork: node.chainwork,
        hash: node.hash,
        chain_tx_count: node.chain_tx_count,
    });
    let index_dir = tempfile::tempdir()?;
    let store = Arc::new(RocksDbStore::open(index_dir.path())?);
    let writer: Arc<dyn crate::TxIndexWriter> = Arc::new(parking_lot::RwLock::new(
        crate::IndexWriter::open(Arc::clone(&store), 1)?
            .with_seal_scratch(index_dir.path().join("seal-scratch")),
    ));
    let applied_tip = Arc::new(ArcSwapOption::empty());
    applied_tip.store(Some(Arc::clone(&tip)));
    let (wake_tx, wake_rx) = crossbeam_channel::bounded(16);
    let runtime = Arc::new(DerivedIndexRuntime::new(wake_tx));
    runtime.set_historical_window(1, 0);
    let (facts_tx, facts_rx) = crossbeam_channel::bounded(8);
    let shared_bodies = Arc::clone(&bodies);
    let body_store: Arc<dyn BlockBodyStore> = shared_bodies;
    let mut worker = Worker {
        runtime: Arc::clone(&runtime),
        writer: Arc::clone(&writer),
        applied_tip: TipReader::new(Arc::clone(&applied_tip)),
        block_tree: BlockTreeReader::new(Arc::new(RwLock::new(tree))),
        body_store: Some(body_store),
        history: HistoryAccess::new(
            Arc::new(RetentionRegistry::new()),
            RetentionBudget::Unlimited,
        ),
        batch_limits: DEFAULT_BATCH_LIMITS,
        enabled: IndexCapabilities::TX_LOOKUP,
        chain_events: Arc::new(StillCursor),
        reporter: Arc::new(DropEvidence),
        shutdown: LatchReader::fixture_never(),
        wake_rx,
        quiet_period: Duration::ZERO,
        batch_delay: Duration::ZERO,
        rollback_rebuild_cutover: u32::MAX,
        seed_history_lease: parking_lot::Mutex::new(None),
        facts_rx: None,
        facts_charge: None,
        facts_gap: None,
        cpu: Some(Arc::new(CpuShares::new(1, 1))),
        buffered_facts: parking_lot::Mutex::new(hashbrown::HashMap::new()),
    };
    worker.facts_rx = Some(facts_rx);
    reset_parse_exact_call_count();
    let mut pending = None;
    let mut stalled = false;
    for _ in 0..8 {
        match worker
            .reconcile_once(&mut pending)
            .map_err(|_| TestError::Missing("reconcile_once"))?
        {
            crate::runtime::ReconcileAction::Stalled => {
                stalled = true;
                break;
            }
            crate::runtime::ReconcileAction::Progressed
            | crate::runtime::ReconcileAction::Buffered
            | crate::runtime::ReconcileAction::CaughtUp => continue,
        }
    }
    assert!(
        stalled,
        "the worker must stall while heights await historical facts"
    );
    assert_eq!(
        bodies.loads.load(Ordering::SeqCst),
        0,
        "heights awaiting historical facts must not read block bodies"
    );
    for (index, block) in facts.iter().enumerate() {
        facts_tx
            .send(Arc::new(CommittedFacts {
                commit_id: u64::try_from(index)? + 1,
                blocks: vec![block.clone()],
            }))
            .map_err(|_| TestError::Missing("facts send"))?;
        if block.height <= 1 {
            runtime.note_historical_facts(block.height);
        }
        runtime.wake();
    }
    for _ in 0..64 {
        match worker
            .reconcile_once(&mut pending)
            .map_err(|_| TestError::Missing("reconcile_once"))?
        {
            crate::runtime::ReconcileAction::CaughtUp => break,
            crate::runtime::ReconcileAction::Progressed
            | crate::runtime::ReconcileAction::Buffered
            | crate::runtime::ReconcileAction::Stalled => continue,
        }
    }
    let watermarks = writer.fenced_watermarks()?.1;
    assert_eq!(
        watermarks.tx_lookup,
        Some(crate::IndexWatermark {
            height: 3,
            hash: facts[3].hash,
        }),
        "catch-up must reach the tip"
    );
    assert_eq!(
        bodies.loads.load(Ordering::SeqCst),
        0,
        "heights above the base fed by facts must make zero block-body reads"
    );
    assert_eq!(
        parse_exact_call_count(),
        0,
        "the facts-only catch-up must not parse a block body"
    );
    Ok(())
}
