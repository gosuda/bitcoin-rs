//! Recovery-contract tests for the txindex worker (`docs/contracts/recovery.md`).
//!
//! Each test drives `Worker::reconcile_once` against an authoritative
//! `BlockTree` plus applied tip and observes only the contract surface: the
//! durable watermarks, the published `ReconcilePhase`, and the rollback
//! evidence (`WarningStore` plus `chain-rollback-event.json`).

use hashbrown::HashMap;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwapOption;
use bitcoin::{
    Amount, Block, BlockHash, ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode, TxOut, Witness,
    block::Header as BlockHeader, block::Version, consensus::encode::serialize, hashes::Hash as _,
    pow::CompactTarget, script::Builder,
};
use bitcoin_rs_chain::{BlockTree, NodeId, NodeStatus, TipSnapshot};
use bitcoin_rs_index::IndexCapabilities;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_storage::{FjallStore, StorageError};
use parking_lot::{Mutex, RwLock};

use super::*;
use crate::apply::PruneBodyStore;
use crate::recovery_evidence::{RollbackEventKind, WarningStore, read_marker};

type BodyMap = HashMap<(u32, [u8; 32]), Vec<u8>>;

struct MapBodyStore {
    bodies: Mutex<BodyMap>,
}

impl PruneBodyStore for MapBodyStore {
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
        Ok(self
            .bodies
            .lock()
            .get(&(height, hash.to_le_bytes()))
            .cloned())
    }

    fn sync(&self) -> Result<(), StorageError> {
        Ok(())
    }
}

fn coinbase_tx(height: u32, extra: i64) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: bitcoin::OutPoint::null(),
            script_sig: Builder::new()
                .push_int(i64::from(height))
                .push_int(extra)
                .into_script(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::new(),
        }],
    }
}

fn tree_header(block: &Block) -> bitcoin_rs_primitives::Header {
    bitcoin_rs_primitives::Header::consensus_decode(&serialize(&block.header))
        .expect("80-byte header")
}

fn mine_block(prev_hash: Hash256, height: u32, extra: i64) -> (Block, Hash256) {
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
        txdata: vec![coinbase_tx(height, extra)],
    };
    block.header.merkle_root = block
        .compute_merkle_root()
        .unwrap_or_else(TxMerkleNode::all_zeros);
    let hash = Hash256::from_le_bytes(block.block_hash().as_byte_array());
    (block, hash)
}

/// Genesis with two rival branches: `A` (`extra = 0`) and `B` (`extra = 1`),
/// each `len` blocks long. Every body is present in the store.
struct ForkFixture {
    tree: Arc<RwLock<BlockTree>>,
    bodies: Arc<MapBodyStore>,
    a: Vec<(NodeId, Hash256)>,
    b: Vec<(NodeId, Hash256)>,
}

impl ForkFixture {
    fn new(len: u32) -> Self {
        let mut tree = BlockTree::new();
        let mut bodies = BodyMap::new();
        let (genesis, genesis_hash) = mine_block(Hash256::from_le_bytes(&[0_u8; 32]), 0, 0);
        tree.insert_header(tree_header(&genesis), NodeStatus::HeaderValid)
            .expect("genesis");
        bodies.insert((0, genesis_hash.to_le_bytes()), serialize(&genesis));
        let mut branch = |extra: i64| {
            let mut prev = genesis_hash;
            let mut ids = Vec::new();
            for height in 1..=len {
                let (block, hash) = mine_block(prev, height, extra);
                let id = tree
                    .insert_header(tree_header(&block), NodeStatus::HeaderValid)
                    .expect("branch header");
                bodies.insert((height, hash.to_le_bytes()), serialize(&block));
                ids.push((id, hash));
                prev = hash;
            }
            ids
        };
        let a = branch(0);
        let b = branch(1);
        Self {
            tree: Arc::new(RwLock::new(tree)),
            bodies: Arc::new(MapBodyStore {
                bodies: Mutex::new(bodies),
            }),
            a,
            b,
        }
    }

    fn tip(&self, (node_id, _): (NodeId, Hash256)) -> Arc<TipSnapshot> {
        let tree = self.tree.read();
        let node = tree.node(node_id).expect("node");
        Arc::new(TipSnapshot {
            tip_id: node_id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
        })
    }
}

struct Harness {
    _index_dir: tempfile::TempDir,
    evidence_dir: tempfile::TempDir,
    writer: Arc<dyn TxIndexWriter>,
    applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    runtime: Arc<TxIndexRuntime>,
    warnings: Arc<WarningStore>,
    worker: Worker,
}

impl Harness {
    fn new(fixture: &ForkFixture, rollback_rebuild_cutover: u32) -> Self {
        let index_dir = tempfile::tempdir().expect("index dir");
        let evidence_dir = tempfile::tempdir().expect("evidence dir");
        let store = Arc::new(FjallStore::open(index_dir.path()).expect("fjall open"));
        let writer: Arc<dyn TxIndexWriter> = Arc::new(parking_lot::Mutex::new(
            bitcoin_rs_index::IndexWriter::open(store, 1).expect("index writer open"),
        ));
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let (wake_tx, wake_rx) = crossbeam_channel::bounded(16);
        let runtime = Arc::new(TxIndexRuntime::new(wake_tx));
        let (reporter, warnings) = test_recovery_reporter(evidence_dir.path());
        let body_store: Arc<dyn PruneBodyStore> = fixture.bodies.clone();
        let worker = Worker {
            runtime: Arc::clone(&runtime),
            writer: Arc::clone(&writer),
            applied_tip: Arc::clone(&applied_tip),
            block_tree: Arc::clone(&fixture.tree),
            body_store: Some(body_store),
            batch_limits: DEFAULT_BATCH_LIMITS,
            enabled: IndexCapabilities::HISTORICAL,
            chain_events: detached_chain_publisher(),
            reporter,
            wake_rx,
            quiet_period: Duration::ZERO,
            batch_delay: Duration::ZERO,
            rollback_rebuild_cutover,
            utxo: None,
            chain_transition: None,
        };
        Self {
            _index_dir: index_dir,
            evidence_dir,
            writer,
            applied_tip,
            runtime,
            warnings,
            worker,
        }
    }

    fn set_tip(&self, tip: &Arc<TipSnapshot>) {
        self.applied_tip.store(Some(Arc::clone(tip)));
    }

    /// Runs passes until the worker reports `CaughtUp`, bounded so a
    /// non-converging worker fails the test instead of hanging it.
    fn settle(&self, pending: &mut Option<PendingForward>) {
        for _ in 0..64 {
            match self.worker.reconcile_once(pending).expect("reconcile pass") {
                ReconcileAction::CaughtUp => return,
                ReconcileAction::Progressed | ReconcileAction::Buffered => {}
                ReconcileAction::Stalled => panic!("worker stalled"),
            }
        }
        panic!("worker did not converge");
    }

    fn watermarks(&self) -> IndexWatermarks {
        self.writer.fenced_watermarks().expect("watermarks").1
    }

    fn assert_at(&self, tip: &TipSnapshot) {
        let expected = Some(IndexWatermark {
            height: tip.height,
            hash: tip.hash.to_le_bytes(),
        });
        let watermarks = self.watermarks();
        assert_eq!(watermarks.tx_lookup, expected, "tx_lookup watermark");
        assert_eq!(
            watermarks.script_history, expected,
            "script_history watermark"
        );
        assert_eq!(self.runtime.phase(), ReconcilePhase::FORWARD);
    }

    fn index_ahead_marker(&self) -> Option<RollbackEventKind> {
        let genesis = bitcoin_rs_chain::Network::Regtest
            .genesis_block_hash()
            .to_string_be();
        read_marker(self.evidence_dir.path(), &genesis).map(|event| event.event)
    }
}

/// `RCV-03`: a watermark on an abandoned branch within the cutover rewinds
/// block by block to the common ancestor, then replays the active branch.
#[test]
fn shallow_reorg_rewinds_to_common_ancestor_then_replays() {
    let f = ForkFixture::new(2);
    let h = Harness::new(&f, u32::MAX);
    let mut pending = None;

    let a2 = f.tip(f.a[1]);
    h.set_tip(&a2);
    h.settle(&mut pending);
    h.assert_at(&a2);

    let b2 = f.tip(f.b[1]);
    h.set_tip(&b2);
    h.settle(&mut pending);
    h.assert_at(&b2);

    // Same height on both branches: not "ahead", so no rollback evidence.
    assert!(h.warnings.warnings().is_empty());
    assert!(h.index_ahead_marker().is_none());
}

/// `RCV-04`: a watermark above the applied tip is an operator-visible
/// rollback event — one warning and one durable marker per pass, naming the
/// exact block identities on both sides — and the rows are rewound.
#[test]
fn index_ahead_of_restored_tip_is_reported_once_and_rewound() {
    let f = ForkFixture::new(3);
    let h = Harness::new(&f, u32::MAX);
    let mut pending = None;

    let a3 = f.tip(f.a[2]);
    h.set_tip(&a3);
    h.settle(&mut pending);
    h.assert_at(&a3);

    // Chainstate restored to an older checkpoint on the same branch.
    let a1 = f.tip(f.a[0]);
    h.set_tip(&a1);
    h.settle(&mut pending);
    h.assert_at(&a1);

    assert_eq!(
        h.warnings.warnings().len(),
        1,
        "one warning per rollback pass"
    );
    match h.index_ahead_marker() {
        Some(RollbackEventKind::IndexWatermarkAhead {
            capability,
            restored_height,
            restored_hash,
            old_height,
            old_hash,
            gap,
        }) => {
            assert_eq!(capability, "tx_lookup,script_history");
            assert_eq!((restored_height, old_height, gap), (1, 3, 2));
            assert_eq!(restored_hash, a1.hash.to_string_be());
            assert_eq!(old_hash, a3.hash.to_string_be());
        }
        other => panic!("expected IndexWatermarkAhead marker, got {other:?}"),
    }
}

/// `RCV-05`: a rollback deeper than the cutover resets the selected
/// capabilities and rebuilds from genesis; the rebuild phase stays published
/// until the reset capabilities reach the applied tip again.
#[test]
fn deep_rollback_rebuilds_and_publishes_rebuild_phase_until_caught_up() {
    let f = ForkFixture::new(3);
    let h = Harness::new(&f, 1);
    let mut pending = None;

    let a3 = f.tip(f.a[2]);
    h.set_tip(&a3);
    h.settle(&mut pending);
    h.assert_at(&a3);

    // Depth 3 to the common ancestor (genesis) exceeds cutover 1.
    let b3 = f.tip(f.b[2]);
    h.set_tip(&b3);
    let first = h.worker.reconcile_once(&mut pending).expect("reset pass");
    assert!(!matches!(first, ReconcileAction::CaughtUp));
    assert_eq!(
        h.runtime.phase(),
        ReconcilePhase::FORWARD.with_leg(IndexCapabilities::HISTORICAL, ReconcileLeg::Rebuilding)
    );
    let watermarks = h.watermarks();
    assert!(
        watermarks.tx_lookup.is_none_or(|w| w.height < 3),
        "reset discarded the stale rows"
    );

    h.settle(&mut pending);
    h.assert_at(&b3);
    assert!(
        h.index_ahead_marker().is_none(),
        "equal height is not ahead"
    );
}

/// `RCV-06`: the applied tip moving while a rebuild is in flight does not
/// restart or abort the rebuild; the worker converges on the new tip.
#[test]
fn tip_change_during_rebuild_converges_on_new_tip() {
    let f = ForkFixture::new(3);
    let h = Harness::new(&f, 0);
    let mut pending = None;

    let a3 = f.tip(f.a[2]);
    h.set_tip(&a3);
    h.settle(&mut pending);

    let b3 = f.tip(f.b[2]);
    h.set_tip(&b3);
    h.worker.reconcile_once(&mut pending).expect("reset pass");
    assert_eq!(
        h.runtime.phase().rebuilding(),
        IndexCapabilities::HISTORICAL
    );

    // Canonical chain returns to A while the rebuild toward B is underway.
    h.set_tip(&a3);
    h.settle(&mut pending);
    h.assert_at(&a3);
}

/// `RCV-07`: a rewind whose disconnected body is missing cannot produce
/// exact-identity deletions; the affected capabilities reset and rebuild
/// from canonical bodies instead of failing the worker.
#[test]
fn missing_disconnected_body_routes_rewind_to_rebuild() {
    let f = ForkFixture::new(2);
    let h = Harness::new(&f, u32::MAX);
    let mut pending = None;

    let a2 = f.tip(f.a[1]);
    h.set_tip(&a2);
    h.settle(&mut pending);

    f.bodies.bodies.lock().remove(&(2, f.a[1].1.to_le_bytes()));
    let b2 = f.tip(f.b[1]);
    h.set_tip(&b2);
    h.worker.reconcile_once(&mut pending).expect("reset pass");
    assert_eq!(
        h.runtime.phase().rebuilding(),
        IndexCapabilities::HISTORICAL
    );
    h.settle(&mut pending);
    h.assert_at(&b2);
}

/// `RCV-05`: capabilities carry independent watermarks, so one may rebuild
/// while its sibling rewinds. The rebuild leg outlives the rollback loop and
/// is published until the reset rows reach the applied tip.
#[test]
fn selective_rebuild_leg_survives_sibling_rollback() {
    let f = ForkFixture::new(3);
    let mut h = Harness::new(&f, 1);
    let mut pending = None;

    h.worker.enabled = IndexCapabilities::SCRIPT_HISTORY;
    h.set_tip(&f.tip(f.a[0]));
    h.settle(&mut pending);
    h.worker.enabled = IndexCapabilities::TX_LOOKUP;
    let a3 = f.tip(f.a[2]);
    h.set_tip(&a3);
    h.settle(&mut pending);
    let watermarks = h.watermarks();
    assert_eq!(watermarks.tx_lookup.map(|w| w.height), Some(3));
    assert_eq!(watermarks.script_history.map(|w| w.height), Some(1));

    // tx_lookup is three blocks off B (beyond cutover 1): rebuild.
    // script_history is one block off B (within cutover): rewind.
    h.worker.enabled = IndexCapabilities::HISTORICAL;
    let b3 = f.tip(f.b[2]);
    h.set_tip(&b3);
    let first = h.worker.reconcile_once(&mut pending).expect("reset pass");
    assert!(!matches!(first, ReconcileAction::CaughtUp));
    assert_eq!(
        h.runtime.phase(),
        ReconcilePhase::FORWARD.with_leg(IndexCapabilities::TX_LOOKUP, ReconcileLeg::Rebuilding)
    );
    assert_eq!(
        h.watermarks().script_history.map(|w| w.height),
        Some(0),
        "rewound to genesis"
    );

    h.settle(&mut pending);
    h.assert_at(&b3);
}

/// `RCV-02`: an absent applied tip (headers-only start) is a position the
/// index must not be ahead of; every row is rewound.
#[test]
fn absent_tip_rewinds_index_to_empty() {
    let f = ForkFixture::new(1);
    let h = Harness::new(&f, u32::MAX);
    let mut pending = None;

    let a1 = f.tip(f.a[0]);
    h.set_tip(&a1);
    h.settle(&mut pending);

    h.applied_tip.store(None);
    h.settle(&mut pending);
    let watermarks = h.watermarks();
    assert_eq!(watermarks.tx_lookup, None);
    assert_eq!(watermarks.script_history, None);
    assert_eq!(h.runtime.phase(), ReconcilePhase::FORWARD);
}
