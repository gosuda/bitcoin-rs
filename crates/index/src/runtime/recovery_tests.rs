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
use crate::IndexCapability;

use bitcoin_rs_primitives::Hash256;

use bitcoin_rs_storage::pruning::{HistoryAccess, RetentionBudget, RetentionRegistry};
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
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

fn tree_header(block: &Block) -> bitcoin_rs_primitives::Header {
    bitcoin_rs_primitives::deserialize::<bitcoin_rs_primitives::Header>(&serialize(&block.header))
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
    if height > 0 {
        let mut spend = coinbase_tx(height, extra);
        spend.input[0].previous_output = bitcoin::OutPoint {
            txid: coinbase_tx(height - 1, if height == 1 { 0 } else { extra }).compute_txid(),
            vout: 0,
        };
        block.txdata.push(spend);
    }
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
            chain_tx_count: node.chain_tx_count,
        })
    }
}

struct Harness {
    _index_dir: tempfile::TempDir,
    writer: Arc<dyn TxIndexWriter>,
    applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    runtime: Arc<DerivedIndexRuntime>,
    evidence: Arc<RecordedIndexAhead>,
    /// The pruning authority this worker reads through.
    retention: Arc<RetentionRegistry>,
    worker: Worker,
}

#[test]
fn unavailable_filter_history_preserves_sibling_indexes_and_filter_watermark() {
    let fixture = ForkFixture::new(2);
    for pruned in [false, true] {
        let harness = Harness::with_enabled(
            &fixture,
            u32::MAX,
            IndexCapabilities::HISTORICAL.with_compact_filters(true),
        );
        harness.set_tip(&fixture.tip(fixture.a[1]));
        if pruned {
            harness.retention.reserve(1).commit(1);
        }
        harness.settle(&mut None);
        harness.assert_at(&fixture.tip(fixture.a[1]));
        assert!(harness.runtime.compact_filter_failure.read().is_some());
        assert!(!harness.runtime.should_stop());
        assert!(harness.watermarks().compact_filters.is_none());
        assert!(harness.writer.consumer_cursor().expect("cursor").is_none());

        harness.set_tip(&fixture.tip(fixture.b[1]));
        harness.settle(&mut None);
        harness.assert_at(&fixture.tip(fixture.b[1]));
        assert!(harness.watermarks().compact_filters.is_none());
    }
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
            .contains(IndexCapability::ScriptLive)
            .then(|| bitcoin_rs_utxo::UtxoReader::new(Arc::new(bitcoin_rs_utxo::UtxoSet::new())));
        let chain_transition = enabled
            .contains(IndexCapability::ScriptLive)
            .then(|| bitcoin_rs_chain::TransitionDomain::new().stable_read());
        let retention = Arc::new(RetentionRegistry::new());
        let worker = Worker {
            runtime: Arc::clone(&runtime),
            writer: Arc::clone(&writer),
            applied_tip: bitcoin_rs_chain::TipReader::new(Arc::clone(&applied_tip)),
            block_tree: bitcoin_rs_chain::BlockTreeReader::new(Arc::clone(&fixture.tree)),
            body_store: Some(body_store),
            history: HistoryAccess::new(Arc::clone(&retention), RetentionBudget::Unlimited),
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

#[test]
fn missing_undo_during_filter_rollback_does_not_reset_filters_or_stop_siblings() {
    struct SpentScript;
    impl crate::SpentCoinScripts for SpentScript {
        fn script_bytes(&self, _: &[u8; 32], _: u32) -> Option<&[u8]> {
            Some(&[0x51])
        }
    }
    let f = ForkFixture::new(2);
    let h = Harness::with_enabled(
        &f,
        u32::MAX,
        IndexCapabilities::HISTORICAL.with_compact_filters(true),
    );
    let a2 = f.tip(f.a[1]);

    let identities = h.worker.collect_target_chain(&a2, 0, 2).expect("chain");
    let mut batch = PreparedBatch::new(DEFAULT_BATCH_LIMITS);
    for identity in identities {
        let body = f.bodies.bodies.lock()[&(identity.height, identity.hash)].clone();
        let prepared = h
            .writer
            .prepare_block_with_spent_scripts(
                h.worker.enabled,
                identity.height,
                identity.hash,
                &body,
                &SpentScript,
            )
            .expect("prepare");
        assert!(batch.try_push(prepared).is_ok());
    }
    let fence = h.writer.fenced_watermarks().expect("fence").0;
    h.writer
        .commit_forward_with_cursor(fence, batch, crate::ConsumerCursorUpdate::Keep)
        .expect("initial filter publication");
    let original = h.watermarks().compact_filters;
    h.set_tip(&f.tip(f.b[1]));
    h.settle(&mut None);
    h.assert_at(&f.tip(f.b[1]));
    assert_eq!(
        h.watermarks().compact_filters,
        original,
        "preserve failed capability data"
    );
    assert!(h.runtime.compact_filter_failure.read().is_some());
    assert!(!h.runtime.should_stop());
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

/// The pruning authority, not the worker, decides whether absent history is
/// permanent. A height the frontier names as deleted routes to a rebuild
/// anchored at the first surviving row; a height the authority granted and
/// the store cannot yet show is a wait.
#[test]
fn pruned_history_rebuilds_from_the_frontier_and_absent_history_waits() {
    let f = ForkFixture::new(3);
    let h = Harness::new(&f, u32::MAX);
    let mut pending = None;
    let a3 = f.tip(f.a[2]);
    h.set_tip(&a3);
    h.settle(&mut pending);
    h.assert_at(&a3);

    h.retention.reserve(2).commit(2);

    let b3 = f.tip(f.b[2]);
    h.set_tip(&b3);
    let action = h.worker.reconcile_once(&mut pending).expect("rebuild pass");
    assert!(!matches!(action, ReconcileAction::CaughtUp));
    assert_eq!(
        h.runtime.phase(),
        ReconcilePhase::FORWARD.with_leg(IndexCapabilities::HISTORICAL, ReconcileLeg::Rebuilding),
        "the frontier answer must publish a rebuild, not a stall or a plain rollback"
    );
    let anchored = Some(IndexWatermark {
        height: 1,
        hash: f.b[0].1.to_le_bytes(),
    });
    let watermarks = h.watermarks();
    assert_eq!(
        watermarks.tx_lookup, anchored,
        "the durable watermark is anchored at the first surviving height"
    );
    assert_eq!(watermarks.script_history, anchored);

    h.settle(&mut pending);
    h.assert_at(&b3);
    assert!(h.index_ahead_call().is_none(), "equal height is not ahead");

    let f = ForkFixture::new(3);
    let h = Harness::new(&f, u32::MAX);
    let mut pending = None;
    let a3 = f.tip(f.a[2]);
    h.set_tip(&a3);
    h.settle(&mut pending);
    f.bodies.bodies.lock().remove(&(3, f.a[2].1.to_le_bytes()));
    let a1 = f.tip(f.a[0]);
    h.set_tip(&a1);
    let action = h.worker.reconcile_once(&mut pending).expect("wait pass");
    assert!(
        matches!(action, ReconcileAction::Stalled),
        "transient absence under a grant must not rebuild, got {action:?}"
    );
    assert_eq!(
        h.watermarks().tx_lookup,
        Some(IndexWatermark {
            height: 3,
            hash: a3.hash.to_le_bytes(),
        }),
        "the consumer keeps its derived rows while it waits"
    );
}
