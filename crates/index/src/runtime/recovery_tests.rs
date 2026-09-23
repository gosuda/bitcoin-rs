//! Recovery-contract tests for the txindex worker (`docs/contracts/recovery.md`).
//!
//! Each test drives `Worker::reconcile_once` against an authoritative
//! `BlockTree` plus applied tip and observes only the contract surface: the
//! durable watermarks, the published `ReconcilePhase`, and the rollback
//! evidence reported through the `IndexAheadSink` seam.

use crate::reconcile::{ReconcileLeg, ReconcilePhase};
use arc_swap::ArcSwapOption;

use bitcoin::{
    Amount, Block, BlockHash, ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode, TxOut, Witness,
    block::{Header as BlockHeader, Version},
    consensus::encode::serialize,
    hashes::Hash as _,
    pow::CompactTarget,
    script::Builder,
};

use bitcoin_rs_chain::{BlockTree, NodeId, NodeStatus, TipSnapshot};

use crate::IndexCapabilities;

use bitcoin_rs_primitives::Hash256;

use bitcoin_rs_storage::{FjallStore, StorageError, block_body::BlockBodyStore};

use hashbrown::HashMap;

use parking_lot::{Mutex, RwLock};

use std::{sync::Arc, time::Duration};

use super::*;

type BodyMap = HashMap<(u32, [u8; 32]), Vec<u8>>;

struct MapBodyStore {
    bodies: Mutex<BodyMap>,
}

impl BlockBodyStore for MapBodyStore {
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
    writer: Arc<dyn TxIndexWriter>,
    applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    runtime: Arc<DerivedIndexRuntime>,
    evidence: Arc<RecordedIndexAhead>,
    retention: Arc<bitcoin_rs_storage::RetentionRegistry>,
    worker: Worker,
}

impl Harness {
    fn new(fixture: &ForkFixture, rollback_rebuild_cutover: u32) -> Self {
        Self::with_enabled(
            fixture,
            rollback_rebuild_cutover,
            IndexCapabilities::HISTORICAL,
        )
    }

    fn with_enabled(
        fixture: &ForkFixture,
        rollback_rebuild_cutover: u32,
        enabled: IndexCapabilities,
    ) -> Self {
        let index_dir = tempfile::tempdir().expect("index dir");
        let store = Arc::new(FjallStore::open(index_dir.path()).expect("fjall open"));
        let writer: Arc<dyn TxIndexWriter> = Arc::new(parking_lot::RwLock::new(
            crate::IndexWriter::open(store, 1).expect("index writer open"),
        ));
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let (wake_tx, wake_rx) = crossbeam_channel::bounded(16);
        let runtime = Arc::new(DerivedIndexRuntime::new(wake_tx));
        let evidence = RecordedIndexAhead::new();
        let reporter: Arc<dyn IndexAheadSink> = evidence.clone();
        let body_store: Arc<dyn BlockBodyStore> = fixture.bodies.clone();
        let utxo = enabled
            .script_live
            .then(|| Arc::new(bitcoin_rs_utxo::UtxoSet::new()));
        let chain_transition = enabled.script_live.then(|| Arc::new(Mutex::new(())));
        let retention = Arc::new(bitcoin_rs_storage::RetentionRegistry::new());
        let worker = Worker {
            runtime: Arc::clone(&runtime),
            writer: Arc::clone(&writer),
            applied_tip: Arc::clone(&applied_tip),
            block_tree: Arc::clone(&fixture.tree),
            body_store: Some(body_store),
            batch_limits: DEFAULT_BATCH_LIMITS,
            enabled,
            chain_events: Arc::new(TestChainCursor),
            reporter,
            wake_rx,
            quiet_period: Duration::ZERO,
            batch_delay: Duration::ZERO,
            rollback_rebuild_cutover,
            utxo,
            chain_transition,
            retention: Arc::new(bitcoin_rs_storage::RetentionAccess::new(Arc::clone(
                &retention,
            ))),
            retention_lease: parking_lot::Mutex::new(None),
        };
        Self {
            _index_dir: index_dir,
            writer,
            applied_tip,
            runtime,
            evidence,
            retention,
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

    /// The recorded `report_index_ahead` call, if any:
    /// `(capability, index_height, tip_height, tip_hash_be, index_hash_be,
    /// depth)`.
    fn index_ahead_call(&self) -> Option<(String, u32, u32, String, String, u32)> {
        self.evidence
            .calls
            .lock()
            .first()
            .map(|(cap, ih, th, thb, ihb, d, _)| {
                (cap.clone(), *ih, *th, thb.clone(), ihb.clone(), *d)
            })
    }
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
        h.evidence.calls.lock().len(),
        1,
        "one warning per rollback pass"
    );
    match h.index_ahead_call() {
        Some((capability, index_height, tip_height, tip_hash_be, index_hash_be, depth)) => {
            assert_eq!(capability, "tx_lookup,script_history");
            assert_eq!((tip_height, index_height, depth), (1, 3, 2));
            assert_eq!(tip_hash_be, a1.hash.to_string_be());
            assert_eq!(index_hash_be, a3.hash.to_string_be());
        }
        other => panic!("expected IndexWatermarkAhead report, got {other:?}"),
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
    assert!(h.index_ahead_call().is_none(), "equal height is not ahead");
}

/// `IDX-10`: a body missing above the prune line is transient absence. The
/// pass stalls — the bounded quiet-period retry — no terminal failure is
/// raised, the required history stays pinned by a live retention lease, and
/// completion releases that authority exactly once.
#[test]
fn transient_missing_body_stalls_under_a_live_retention_lease() {
    let f = ForkFixture::new(3);
    let h = Harness::new(&f, u32::MAX);
    let mut pending = None;

    let a2_hash = f.a[1].1;
    let removed = f.bodies.bodies.lock().remove(&(2, a2_hash.to_le_bytes()));
    assert!(removed.is_some(), "fixture body at height 2");

    let a3 = f.tip(f.a[2]);
    h.set_tip(&a3);
    let stalled = h
        .worker
        .reconcile_once(&mut pending)
        .expect("transient absence is not an error");
    assert!(matches!(stalled, ReconcileAction::Stalled));

    // The backfill pinned the history it still needs...
    assert_eq!(h.retention.active_leases(), 1);
    assert_eq!(h.retention.retention_floor(), Some(0));
    // ...and nothing was marked permanently lost.
    assert_eq!(h.retention.pruned_below(), 0);

    // The body returns (writer lag resolves); the backfill converges and
    // hands retention authority back exactly once.
    f.bodies
        .bodies
        .lock()
        .insert((2, a2_hash.to_le_bytes()), removed.expect("removed body"));
    h.settle(&mut pending);
    h.assert_at(&a3);
    assert_eq!(h.retention.active_leases(), 0);
    assert_eq!(h.retention.retention_floor(), None);
}

/// `IDX-10`: a required body below the recorded prune line is permanently
/// gone. The first catch-up pass fails the affected families with an
/// actionable reason naming the first required height and the prune line —
/// never a retry-forever stall — and no lease is granted for history that
/// cannot exist.
#[test]
fn backfill_below_prune_line_fails_closed_on_first_pass() {
    let f = ForkFixture::new(3);
    let h = Harness::new(&f, u32::MAX);
    let mut pending = None;

    // History through height 1 was pruned before the index ever ran.
    h.retention.record_pruned_below(2);
    let a3 = f.tip(f.a[2]);
    h.set_tip(&a3);

    let action = h
        .worker
        .reconcile_once(&mut pending)
        .expect("the leg splits terminally; the worker does not crash");
    assert!(matches!(action, ReconcileAction::Progressed));
    // Every enabled family is history-requiring, so all of them go
    // terminal and the published leg marks them Failed.
    assert_eq!(h.runtime.terminal_families(), IndexCapabilities::HISTORICAL);
    assert_eq!(
        h.runtime.phase(),
        ReconcilePhase::FORWARD.with_leg(IndexCapabilities::HISTORICAL, ReconcileLeg::Failed)
    );
    let message = h.runtime.terminal_message().expect("actionable reason");
    assert!(
        message.contains("permanently unavailable")
            && message.contains("height 0, hash")
            && message.contains("pruned below line 2"),
        "reason must name the first required height and the prune line: {message}"
    );
    // The first required height is genesis: bind the hash so incorrect
    // diagnostics cannot pass the test.
    assert!(
        message.contains(&genesis_hash_be_string(&f)),
        "reason must name the genesis hash: {message}"
    );
    // No lease was granted for history that cannot exist.
    assert_eq!(h.retention.active_leases(), 0);
}

/// Big-endian hex of the fixture's genesis hash, as the missing-history
/// reason renders it.
fn genesis_hash_be_string(f: &ForkFixture) -> String {
    let (a0, _) = f.a[0];
    let tree = f.tree.read();
    let parent = tree
        .parent_id(a0)
        .expect("parent lookup")
        .expect("genesis id");
    let node = tree.node(parent).expect("genesis node");
    Hash256::from_le_bytes(node.hash.as_byte_array()).to_string_be()
}

/// `IDX-10`: in a Full-mode forward leg over permanently pruned history,
/// the history-requiring families go `Failed` while `ScriptLive` resets,
/// reseeds from the authoritative UTXO view, and keeps serving. The worker
/// stays up: capability independence (#645) survives a terminal family.
#[test]
fn full_mode_pruned_history_fails_families_but_keeps_serving_script_live() {
    let f = ForkFixture::new(3);
    let all = IndexCapabilities {
        tx_lookup: true,
        script_history: true,
        script_live: true,
    };
    let h = Harness::with_enabled(&f, u32::MAX, all);
    let mut pending = None;

    h.retention.record_pruned_below(2);
    let a3 = f.tip(f.a[2]);
    h.set_tip(&a3);

    // Pass 1: the seed gate reseeds ScriptLive from the UTXO view — live
    // is the only family without a durable watermark, so no forward leg
    // runs yet.
    let action = h.worker.reconcile_once(&mut pending).expect("seed pass");
    assert!(matches!(action, ReconcileAction::Progressed));
    assert_eq!(h.runtime.terminal_families(), IndexCapabilities::NONE);

    // Pass 2: the historical leg (start 0, below the frontier) hits the
    // missing genesis body and splits — the history-requiring families go
    // terminal while live keeps serving.
    let action = h.worker.reconcile_once(&mut pending).expect("leg split");
    assert!(matches!(action, ReconcileAction::Progressed));
    let historical_only = IndexCapabilities {
        tx_lookup: true,
        script_history: true,
        script_live: false,
    };
    assert_eq!(h.runtime.terminal_families(), historical_only);
    assert_eq!(
        h.runtime.phase(),
        ReconcilePhase::FORWARD.with_leg(historical_only, ReconcileLeg::Failed)
    );

    // Remaining passes: the failed families are never selected again and
    // the worker converges over the surviving live family.
    h.settle(&mut pending);

    let watermarks = h.watermarks();
    assert_eq!(
        watermarks.script_live,
        Some(IndexWatermark {
            height: a3.height,
            hash: a3.hash.to_le_bytes(),
        }),
        "live reseeded at the tip"
    );
    assert_eq!(watermarks.tx_lookup, None, "failed family stays failed");
    assert_eq!(h.retention.active_leases(), 0, "authority fully released");
}

/// `IDX-10`: every worker exit releases the retention authority exactly once
/// through the `Drop` fallback — cancellation and worker replacement cannot
/// leak a pin.
#[test]
fn worker_drop_releases_retention_authority_once() {
    let f = ForkFixture::new(3);
    let h = Harness::new(&f, u32::MAX);
    let retention = Arc::clone(&h.retention);
    let mut pending = None;

    let a2_hash = f.a[1].1;
    let removed = f.bodies.bodies.lock().remove(&(2, a2_hash.to_le_bytes()));
    assert!(removed.is_some(), "fixture body at height 2");
    let a3 = f.tip(f.a[2]);
    h.set_tip(&a3);
    let stalled = h
        .worker
        .reconcile_once(&mut pending)
        .expect("transient absence is not an error");
    assert!(matches!(stalled, ReconcileAction::Stalled));
    assert_eq!(retention.active_leases(), 1);

    // Replacing (dropping) the worker releases its pin; no explicit release
    // ran on this path.
    drop(h);
    assert_eq!(retention.active_leases(), 0);
    assert_eq!(retention.retention_floor(), None);
}
