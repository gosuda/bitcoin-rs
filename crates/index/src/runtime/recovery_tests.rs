//! Recovery-contract tests for the txindex worker (`docs/contracts/recovery.md`).
//!
//! Each test drives `Worker::reconcile_once` against an authoritative
//! `BlockTree` plus applied tip and observes only the contract surface: the
//! durable watermarks, the published `ReconcilePhase`, and the rollback
//! evidence reported through the `IndexAheadSink` seam.
//!
//! The forward group-scheduling and undo-anchor tests (`IDX-06`, `IDX-07` in
//! `docs/contracts/indexing.md`) share this harness; one drives the real
//! `Worker::run` loop.

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
use bitcoin_rs_storage::{
    FjallStore, InMemoryUndoStore, StorageError, UndoStore as _, block_body::BlockBodyStore,
};

use hashbrown::{HashMap, HashSet};

use parking_lot::{Mutex, RwLock};

use std::{sync::Arc, time::Duration};

use super::*;

type BodyMap = HashMap<(u32, [u8; 32]), Vec<u8>>;

struct MapBodyStore {
    bodies: Mutex<BodyMap>,
    undo: InMemoryUndoStore,
    /// Undo reads that fail with a storage error instead of answering.
    undo_read_failures: Mutex<HashSet<(u32, [u8; 32])>>,
    /// Shutdown is requested when a body read finds nothing, so a test can
    /// stop the worker at the exact moment a body proves absent.
    stop_on_absent_body: Mutex<Option<Arc<DerivedIndexRuntime>>>,
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
        let body = self
            .bodies
            .lock()
            .get(&(height, hash.to_le_bytes()))
            .cloned();
        if body.is_none()
            && let Some(runtime) = self.stop_on_absent_body.lock().as_ref()
        {
            runtime.request_shutdown();
        }
        Ok(body)
    }

    fn undo_record(&self, height: u32, hash: Hash256) -> Result<Option<Vec<u8>>, StorageError> {
        let key = (height, hash.to_le_bytes());
        if self.undo_read_failures.lock().contains(&key) {
            return Err(StorageError::backend("injected undo read failure"));
        }
        self.undo.load_undo(height, hash)
    }

    fn sync(&self) -> Result<(), StorageError> {
        Ok(())
    }
}

fn coinbase_undo(bodies: &BodyMap) -> InMemoryUndoStore {
    struct FixtureCoins {
        coins: hashbrown::HashMap<(bitcoin_rs_primitives::Txid, u32), bitcoin_rs_utxo::UtxoCoin>,
    }
    impl bitcoin_rs_utxo::contract::SpentOutputLookup for FixtureCoins {
        fn entry(
            &self,
            outpoint: &bitcoin_rs_primitives::OutPoint,
        ) -> Option<&bitcoin_rs_utxo::UtxoCoin> {
            self.coins.get(&(outpoint.txid, outpoint.vout))
        }
    }

    // Every non-genesis fixture block spends its parent coinbase output, so the
    // spent-coin source resolves against the outputs the fixtures create.
    let mut coins = hashbrown::HashMap::new();
    for ((height, _), body) in bodies {
        let block: bitcoin_rs_primitives::Block =
            bitcoin_rs_primitives::deserialize(body).expect("fixture body");
        for tx in &block.txs {
            let txid = tx.txid();
            let coinbase = tx.is_coinbase();
            for (vout, txout) in tx.outputs.iter().enumerate() {
                let vout = u32::try_from(vout).expect("fixture vout fits u32");
                coins.insert(
                    (txid, vout),
                    bitcoin_rs_utxo::UtxoCoin {
                        outpoint: bitcoin_rs_primitives::OutPoint { txid, vout },
                        txout: txout.clone(),
                        coinbase,
                        height: *height,
                    },
                );
            }
        }
    }
    let lookup = FixtureCoins { coins };

    let store = InMemoryUndoStore::default();
    for ((height, hash), body) in bodies {
        let block: bitcoin_rs_primitives::Block =
            bitcoin_rs_primitives::deserialize(body).expect("fixture body");
        let txids = block
            .txs
            .iter()
            .map(bitcoin_rs_primitives::Tx::txid)
            .collect::<Vec<_>>();
        let (_, undo, _) = bitcoin_rs_utxo::contract::build_block_changes(
            &block,
            *height,
            &txids,
            None,
            1,
            0,
            &lookup,
            None,
            crate::MAX_LIVE_SCRIPT_SIZE,
        )
        .expect("fixture changes");
        bitcoin_rs_utxo::contract::persist_block_undo(
            &store,
            *height,
            Hash256::from_le_bytes(hash),
            &undo,
        )
        .expect("fixture undo");
    }
    store
}

/// Every output of the blocks connected so far, as the UTXO set the undo
/// records are built against.
#[derive(Default)]
struct BranchCoins(Vec<bitcoin_rs_utxo::UtxoCoin>);

impl bitcoin_rs_utxo::contract::SpentOutputLookup for BranchCoins {
    fn entry(
        &self,
        outpoint: &bitcoin_rs_primitives::OutPoint,
    ) -> Option<&bitcoin_rs_utxo::UtxoCoin> {
        self.0.iter().find(|coin| coin.outpoint == *outpoint)
    }
}

impl BranchCoins {
    fn connect(
        &mut self,
        height: u32,
        block: &bitcoin_rs_primitives::Block,
        txids: &[bitcoin_rs_primitives::Txid],
    ) {
        for (tx, txid) in block.txs.iter().zip(txids) {
            for (vout, txout) in tx.outputs.iter().enumerate() {
                self.0.push(bitcoin_rs_utxo::UtxoCoin {
                    outpoint: bitcoin_rs_primitives::OutPoint::new(
                        *txid,
                        u32::try_from(vout).expect("vout"),
                    ),
                    txout: txout.clone(),
                    coinbase: tx.is_coinbase(),
                    height,
                });
            }
        }
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
    genesis: Hash256,
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
                undo: coinbase_undo(&bodies),
                bodies: Mutex::new(bodies),
                undo_read_failures: Mutex::default(),
                stop_on_absent_body: Mutex::default(),
            }),
            genesis: genesis_hash,
            a,
            b,
        }
    }

    /// Body-store key of the branch-`A` block at `height`; height 0 is genesis.
    fn a_key(&self, height: u32) -> (u32, [u8; 32]) {
        if height == 0 {
            return (0, self.genesis.to_le_bytes());
        }
        let index = usize::try_from(height - 1).expect("height index");
        (height, self.a[index].1.to_le_bytes())
    }

    /// Removes the bodies of heights `0..=through` on branch `A`, as a node
    /// that started from a snapshot at `through` lacks them. Returns them so
    /// a test can restore the history.
    fn take_bodies(&self, through: u32) -> BodyMap {
        let mut bodies = self.bodies.bodies.lock();
        (0..=through)
            .filter_map(|height| {
                let key = self.a_key(height);
                bodies.remove(&key).map(|body| (key, body))
            })
            .collect()
    }

    fn restore_bodies(&self, lost: BodyMap) {
        self.bodies.bodies.lock().extend(lost);
    }

    /// Persists the undo record the chainstate would hold for every non-genesis
    /// branch-`A` block, built with the UTXO contract from the outputs of the
    /// blocks before it.
    fn persist_undo(&self) {
        let store = InMemoryUndoStore::default();
        let mut coins = BranchCoins::default();
        let tip_height = u32::try_from(self.a.len()).expect("branch length");
        for height in 0..=tip_height {
            let key = self.a_key(height);
            let block = {
                let bodies = self.bodies.bodies.lock();
                bitcoin_rs_primitives::deserialize::<bitcoin_rs_primitives::Block>(&bodies[&key])
                    .expect("fixture block")
            };
            let txids = block.txids();
            if height > 0 {
                let (_, undo, _) = bitcoin_rs_utxo::contract::build_block_changes(
                    &block,
                    height,
                    &txids,
                    None,
                    0,
                    0,
                    &coins,
                    None,
                    crate::MAX_LIVE_SCRIPT_SIZE,
                )
                .expect("undo batch");
                let record = bitcoin_rs_utxo::contract::persist_block_undo(
                    &store,
                    height,
                    Hash256::from_le_bytes(&key.1),
                    &undo,
                )
                .expect("undo record");
                self.bodies
                    .undo
                    .persist_undo(height, Hash256::from_le_bytes(&key.1), record.as_bytes())
                    .expect("fixture undo");
            }
            coins.connect(height, &block, &txids);
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
            IndexCapabilities::TX_LOOKUP.with_compact_filters(true),
        );
        // Filter preparation needs spent-script undo for every block; remove
        // the a-branch records so the capability reports unavailable.
        for (i, entry) in fixture.a.iter().enumerate() {
            let height = u32::try_from(i).expect("fixture height fits u32") + 1;
            fixture
                .bodies
                .undo
                .remove_archived(height, fixture.tip(*entry).hash);
        }
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
        // A later reorg still rolls back and catches up both body-only indexes.
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

    /// Runs passes until the worker reports `Stalled`, bounded so a hot
    /// `Progressed` loop fails the test. `CaughtUp` is a failure too: this is
    /// for states where some capability is still owed rows.
    fn settle_stalled(&self, pending: &mut Option<PendingForward>) {
        for _ in 0..16 {
            match self.worker.reconcile_once(pending).expect("reconcile pass") {
                ReconcileAction::Stalled => return,
                ReconcileAction::Progressed | ReconcileAction::Buffered => {}
                ReconcileAction::CaughtUp => panic!("a capability still owed rows is caught up"),
            }
        }
        panic!("worker kept progressing instead of waiting");
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
        if self.worker.enabled.contains(IndexCapability::ScriptHistory) {
            assert_eq!(
                watermarks.script_history, expected,
                "script_history watermark"
            );
        }
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
        IndexCapabilities::TX_LOOKUP.with_compact_filters(true),
    );
    let a2 = f.tip(f.a[1]);
    // Publish valid filter rows from the fixture's known spent script. The
    // history store has bodies but no undo when the worker later rolls back.
    f.bodies.undo.remove_archived(2, a2.hash);
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

/// The pruning authority, not the worker, decides whether absent history is
/// permanent. A height the frontier names as deleted routes to a rebuild
/// anchored at the first surviving row; a height the authority granted and
/// the store cannot yet show is a wait.
#[test]
fn pruned_history_rebuilds_from_the_frontier_and_absent_history_waits() {
    // Pruned below the frontier: the owner says gone. The rollback hits the
    // frontier, the capabilities reset, and the rebuild anchors at the first
    // surviving height — then the forward leg actually converges on the new
    // tip instead of stalling on rows that never return.
    let f = ForkFixture::new(3);
    let h = Harness::new(&f, u32::MAX);
    let mut pending = None;
    let a3 = f.tip(f.a[2]);
    h.set_tip(&a3);
    h.settle(&mut pending);
    h.assert_at(&a3);

    // Commit the frontier at 2: heights below it are permanently gone.
    h.retention.reserve(2).commit(2);

    // Move the tip to the rival branch. The rollback unwinds to height 1,
    // where the frontier refuses the body read, so the owner routes the
    // index to a rebuild anchored at height 1 on the B branch.
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

    // The leg converges: the rebuilt index covers the retained heights and
    // reports the B tip, proving the anchor let it restart above the
    // frontier rather than resetting forever.
    h.settle(&mut pending);
    h.assert_at(&b3);
    assert!(h.index_ahead_call().is_none(), "equal height is not ahead");

    // Granted but absent: the owner says the history is retained, so the
    // worker waits and keeps the rows it already derived.
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

/// A broken rollback must fail this test instead of looping indefinitely.
struct OneUndoRead {
    bodies: Arc<MapBodyStore>,
    reads: std::sync::atomic::AtomicUsize,
}

impl BlockBodyStore for OneUndoRead {
    fn persist_block_body(
        &self,
        height: u32,
        hash: Hash256,
        body: &[u8],
    ) -> Result<(), StorageError> {
        self.bodies.persist_block_body(height, hash, body)
    }

    fn load_block_body(&self, height: u32, hash: Hash256) -> Result<Option<Vec<u8>>, StorageError> {
        self.bodies.load_block_body(height, hash)
    }

    fn undo_record(&self, height: u32, hash: Hash256) -> Result<Option<Vec<u8>>, StorageError> {
        if self.reads.fetch_add(1, Ordering::SeqCst) != 0 {
            return Err(StorageError::Backend(
                "rollback repeated an unavailable undo read".into(),
            ));
        }
        self.bodies.undo_record(height, hash)
    }

    fn sync(&self) -> Result<(), StorageError> {
        self.bodies.sync()
    }
}

#[test]
fn history_rollback_missing_or_corrupt_undo_fails_once_without_resetting_rows() {
    for enabled in [IndexCapabilities::HISTORICAL, IndexCapabilities::ALL] {
        for corrupt in [false, true] {
            let f = ForkFixture::new(2);
            let mut h = Harness::with_enabled(&f, u32::MAX, enabled);
            let mut pending = None;
            let a2 = f.tip(f.a[1]);
            h.set_tip(&a2);
            h.settle(&mut pending);
            let before = h.writer.fenced_watermarks().expect("fence");
            if corrupt {
                f.bodies
                    .undo
                    .persist_undo(2, a2.hash, b"bad undo")
                    .expect("corrupt row");
            } else {
                f.bodies.undo.remove_archived(2, a2.hash);
            }
            let reads = Arc::new(OneUndoRead {
                bodies: Arc::clone(&f.bodies),
                reads: std::sync::atomic::AtomicUsize::new(0),
            });
            h.worker.body_store = Some(reads.clone());
            h.set_tip(&f.tip(f.a[0]));
            let result = h.worker.reconcile_once(&mut pending);
            assert!(matches!(
                result,
                Err(DerivedIndexWorkerError::UndoUnavailable { height: 2, hash }) if hash == a2.hash
            ));
            assert_eq!(reads.reads.load(Ordering::SeqCst), 1);
            assert_eq!(
                h.writer.fenced_watermarks().expect("unchanged fence"),
                before,
                "no durable reset, cursor change or watermark advance on unavailable History undo"
            );
        }
    }
}

#[test]
fn live_only_rollback_without_undo_still_reseeds_from_utxo() {
    let f = ForkFixture::new(2);
    let mut h = Harness::with_enabled(&f, u32::MAX, IndexCapabilities::SCRIPT_LIVE);
    let mut pending = None;
    let a2 = f.tip(f.a[1]);
    h.set_tip(&a2);
    h.settle(&mut pending);
    f.bodies.undo.remove_archived(2, a2.hash);
    let reads = Arc::new(OneUndoRead {
        bodies: Arc::clone(&f.bodies),
        reads: std::sync::atomic::AtomicUsize::new(0),
    });
    h.worker.body_store = Some(reads.clone());
    let a1 = f.tip(f.a[0]);
    h.set_tip(&a1);
    h.settle(&mut pending);
    assert_eq!(reads.reads.load(Ordering::SeqCst), 1);
    assert_eq!(
        h.watermarks().script_live,
        Some(IndexWatermark {
            height: a1.height,
            hash: a1.hash.to_le_bytes()
        })
    );
    assert_eq!(h.watermarks().script_history, None);
    assert_eq!(h.runtime.phase(), ReconcilePhase::FORWARD);
}

/// The watermark a capability holds once it has reached `tip`.
fn at(tip: &TipSnapshot) -> IndexWatermark {
    IndexWatermark {
        height: tip.height,
        hash: tip.hash.to_le_bytes(),
    }
}

/// Polls `ready` on a monotonic deadline; the wait is scheduling mechanics,
/// not an assertion about duration.
fn wait_until(what: &str, mut ready: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while !ready() {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Requests worker shutdown when dropped, so a failing test cancels the run
/// loop it owns instead of leaving it polling.
struct StopOnDrop(Arc<DerivedIndexRuntime>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.request_shutdown();
    }
}

/// Four `A` blocks on a node whose history prefix is gone: bodies `0..=2` are
/// absent, `ScriptLive` is seeded at height 2, and the applied tip is height
/// 4. The history families wait on their absent first body while `ScriptLive`
/// has everything its own range needs. Returns the lost prefix.
fn held_prefix() -> (ForkFixture, Harness, BodyMap) {
    let f = ForkFixture::new(4);
    f.persist_undo();
    let h = Harness::with_enabled(&f, u32::MAX, IndexCapabilities::TX_AND_SCRIPTS);
    let lost = f.take_bodies(2);
    h.set_tip(&f.tip(f.a[1]));
    h.settle_stalled(&mut None);
    assert_eq!(h.watermarks().script_live, Some(at(&f.tip(f.a[1]))));
    h.set_tip(&f.tip(f.a[3]));
    (f, h, lost)
}

/// An absent body holds back only the capability group that needs it: the
/// group ahead of it follows the tip, the worker waits instead of reporting
/// caught-up or spinning, and the prefix arriving needs no reset.
#[test]
fn absent_prefix_body_holds_back_only_its_own_group() {
    let (f, h, lost) = held_prefix();
    let a4 = f.tip(f.a[3]);
    let mut pending = None;

    h.settle_stalled(&mut pending);
    let held = h.watermarks();
    assert_eq!(
        held.script_live,
        Some(at(&a4)),
        "the ready group follows the tip past the absent prefix"
    );
    assert_eq!(held.tx_lookup, None);
    assert_eq!(held.script_history, None);

    for _ in 0..3 {
        assert!(matches!(
            h.worker.reconcile_once(&mut pending),
            Ok(ReconcileAction::Stalled)
        ));
    }

    f.restore_bodies(lost);
    h.settle(&mut pending);
    h.assert_at(&a4);
    assert_eq!(h.watermarks().script_live, Some(at(&a4)));
}

/// A stop requested while the absent body is read ends the pass: the ready
/// group is not run after it.
#[test]
fn shutdown_after_an_absent_body_does_not_run_a_higher_group() {
    let (f, h, _lost) = held_prefix();
    *f.bodies.stop_on_absent_body.lock() = Some(Arc::clone(&h.runtime));

    assert!(matches!(
        h.worker.reconcile_once(&mut None),
        Ok(ReconcileAction::Stalled)
    ));
    assert!(h.runtime.should_stop());
    assert_eq!(
        h.watermarks().script_live,
        Some(at(&f.tip(f.a[1]))),
        "the stopped pass left the ready group where it was"
    );
}

/// A deferred history grant is a wait, not an absent body: the group whose
/// heights the owner has not reserved does not run around it.
#[test]
fn deferred_history_grant_does_not_run_a_higher_group() {
    let (f, h, _lost) = held_prefix();
    let mut pending = None;

    // The reservation covers heights below 1, which defers the history
    // group's grant at height 0. `ScriptLive` asks from height 3 and would be
    // granted.
    let reservation = h.retention.reserve(1);
    assert!(matches!(
        h.worker.reconcile_once(&mut pending),
        Ok(ReconcileAction::Stalled)
    ));
    assert_eq!(h.watermarks().script_live, Some(at(&f.tip(f.a[1]))));

    drop(reservation);
    h.settle_stalled(&mut pending);
    assert_eq!(h.watermarks().script_live, Some(at(&f.tip(f.a[3]))));
}

/// One body withheld from the store, with the key needed to restore it.
struct AbsentBody {
    key: (u32, [u8; 32]),
    body: Vec<u8>,
}

/// 300 `A` blocks: `ScriptLive` is seeded at height 290, the applied tip is
/// height 300, and the body at height 280 is absent. The history families'
/// first 256-body window is whole and the second is not, so their leg retains
/// a prefix and then meets the absent body. Returns the withheld body.
fn retained_prefix() -> (ForkFixture, Harness, AbsentBody) {
    let f = ForkFixture::new(300);
    f.persist_undo();
    let h = Harness::with_enabled(&f, u32::MAX, IndexCapabilities::TX_AND_SCRIPTS);
    h.set_tip(&f.tip(f.a[289]));
    // Seeds `ScriptLive` at height 290 before any body is read.
    assert!(matches!(
        h.worker.reconcile_once(&mut None),
        Ok(ReconcileAction::Progressed)
    ));
    let key = f.a_key(280);
    let body = f
        .bodies
        .bodies
        .lock()
        .remove(&key)
        .expect("body at height 280");
    h.set_tip(&f.tip(f.a[299]));
    (f, h, AbsentBody { key, body })
}

/// Rows retained ahead of an absent body wait for their deadline and commit
/// even though the body never arrives. No other group runs while they are
/// retained, and they never outlive a fence change.
#[test]
fn retained_prefix_commits_before_any_group_switch_and_never_outlives_a_fence_change() {
    let (f, h, _absent) = retained_prefix();
    let a255 = Some(at(&f.tip(f.a[254])));
    let a290 = Some(at(&f.tip(f.a[289])));
    let mut pending = None;

    // The first window is admitted and the second meets the absent body: the
    // prefix is retained for its deadline and the ready group does not run.
    assert!(matches!(
        h.worker.reconcile_once(&mut pending),
        Ok(ReconcileAction::Buffered)
    ));
    assert!(pending.is_some());
    let retained = h.watermarks();
    assert_eq!(retained.tx_lookup, None);
    assert_eq!(retained.script_live, a290);

    // Another writer commits. The retained rows belong to a dead fence, so
    // they are discarded and no group runs on the stale capture.
    let (fence, _) = h.writer.fenced_watermarks().expect("fence");
    h.writer
        .commit_consumer_cursor(fence, &h.worker.chain_events.cursor().to_bytes())
        .expect("foreign commit");
    assert!(matches!(
        h.worker.reconcile_once(&mut pending),
        Ok(ReconcileAction::Stalled)
    ));
    assert!(pending.is_none());
    let discarded = h.watermarks();
    assert_eq!(discarded.tx_lookup, None);
    assert_eq!(discarded.script_live, a290);

    // Re-derived on the fresh fence, the prefix is retained again and then
    // commits at its deadline.
    assert!(matches!(
        h.worker.reconcile_once(&mut pending),
        Ok(ReconcileAction::Buffered)
    ));
    assert!(matches!(
        h.worker.reconcile_once(&mut pending),
        Ok(ReconcileAction::Progressed)
    ));
    let flushed = h.watermarks();
    assert_eq!(flushed.tx_lookup, a255);
    assert_eq!(flushed.script_history, a255);
    assert_eq!(flushed.script_live, a290);

    // Only then does the next pass reach the ready group.
    h.settle_stalled(&mut pending);
    let end = h.watermarks();
    assert_eq!(end.script_live, Some(at(&f.tip(f.a[299]))));
    assert_eq!(end.tx_lookup, a255);
}

/// Through the real run loop: the retained prefix commits at its deadline,
/// the ready group follows the tip, and the worker, waiting only on its own
/// quiet period, notices the absent body arriving without any wake.
#[test]
fn run_loop_commits_a_retained_prefix_and_retries_an_absent_body_without_a_wake() {
    let (f, mut h, absent) = retained_prefix();
    h.worker.batch_delay = Duration::from_millis(50);
    h.worker.quiet_period = Duration::from_millis(20);
    let writer = Arc::clone(&h.writer);
    let runtime = Arc::clone(&h.runtime);
    let watermarks = move || writer.fenced_watermarks().expect("watermarks").1;
    let a255 = Some(at(&f.tip(f.a[254])));
    let a300 = Some(at(&f.tip(f.a[299])));

    let worker = h.worker;
    let run = std::thread::spawn(move || worker.run());
    let _cancel = StopOnDrop(Arc::clone(&runtime));

    wait_until("the prefix commit and the ready group", || {
        let marks = watermarks();
        marks.tx_lookup == a255 && marks.script_live == a300
    });
    f.bodies.bodies.lock().insert(absent.key, absent.body);
    wait_until("the history families to catch up", || {
        let marks = watermarks();
        marks.tx_lookup == a300 && marks.script_history == a300 && marks.script_live == a300
    });

    runtime.request_shutdown();
    run.join().expect("worker thread").expect("worker run");
}

/// Forward `ScriptLive` follows its undo anchors. A missing or unreadable
/// record resets only `ScriptLive`, which reseeds at the tip while its
/// siblings keep their rows and finish from bodies alone.
#[test]
fn forward_script_live_follows_undo_present_missing_or_corrupt() {
    #[derive(Clone, Copy)]
    enum Undo {
        Present,
        Missing,
        Corrupt,
    }
    for undo in [Undo::Present, Undo::Missing, Undo::Corrupt] {
        let f = ForkFixture::new(5);
        f.persist_undo();
        let h = Harness::with_enabled(&f, u32::MAX, IndexCapabilities::TX_AND_SCRIPTS);
        let (a2, a5) = (f.tip(f.a[1]), f.tip(f.a[4]));
        h.set_tip(&a2);
        h.settle(&mut None);

        let key = f.a_key(4);
        match undo {
            Undo::Present => {}
            Undo::Missing => {
                f.bodies
                    .undo
                    .remove_archived(key.0, Hash256::from_le_bytes(key.1));
            }
            Undo::Corrupt => {
                let mut record = f
                    .bodies
                    .undo
                    .load_undo(key.0, Hash256::from_le_bytes(key.1))
                    .expect("undo load")
                    .expect("fixture undo");
                // An unsupported version byte can never decode.
                record[0] ^= 0xff;
                f.bodies
                    .undo
                    .persist_undo(key.0, Hash256::from_le_bytes(key.1), &record)
                    .expect("fixture undo");
            }
        }
        h.set_tip(&a5);
        let mut pending = None;

        if !matches!(undo, Undo::Present) {
            assert!(matches!(
                h.worker.reconcile_once(&mut pending),
                Ok(ReconcileAction::Stalled)
            ));
            assert!(pending.is_none());
            let reset = h.watermarks();
            assert_eq!(reset.script_live, None, "ScriptLive is reset");
            assert_eq!(reset.tx_lookup, Some(at(&a2)), "siblings keep their rows");
            assert_eq!(reset.script_history, Some(at(&a2)));
        }
        h.settle(&mut pending);
        h.assert_at(&a5);
        assert_eq!(h.watermarks().script_live, Some(at(&a5)));
    }
}

/// An anchor failure anywhere in a window is handled before any block is
/// admitted, so it outranks a preparation failure at a lower height: the
/// reset happens and no preparation error surfaces.
#[test]
fn anchor_failure_outranks_an_earlier_preparation_failure() {
    let f = ForkFixture::new(6);
    f.persist_undo();
    let h = Harness::with_enabled(&f, u32::MAX, IndexCapabilities::SCRIPT_LIVE);
    h.set_tip(&f.tip(f.a[1]));
    h.settle(&mut None);

    // Height 3's body does not parse; height 5 has no undo record.
    f.bodies.bodies.lock().insert(f.a_key(3), vec![0; 10]);
    {
        let key = f.a_key(5);
        f.bodies
            .undo
            .remove_archived(key.0, Hash256::from_le_bytes(key.1));
    }
    h.set_tip(&f.tip(f.a[5]));

    assert!(matches!(
        h.worker.reconcile_once(&mut None),
        Ok(ReconcileAction::Stalled)
    ));
    assert_eq!(h.watermarks().script_live, None);
}

/// Without an anchor failure, blocks admit in height order: the block before
/// a preparation failure commits and the failure keeps its own error.
#[test]
fn preparation_failure_keeps_its_height_after_committed_successes() {
    let f = ForkFixture::new(6);
    f.persist_undo();
    let mut h = Harness::with_enabled(&f, u32::MAX, IndexCapabilities::SCRIPT_LIVE);
    h.set_tip(&f.tip(f.a[1]));
    h.settle(&mut None);

    f.bodies.bodies.lock().insert(f.a_key(4), vec![0; 10]);
    // One row fills a batch, so each block commits as soon as it is admitted.
    h.worker.batch_limits = PreparedBatchLimits {
        max_rows: 1,
        max_bytes: BATCH_BYTE_LIMIT,
    };
    h.set_tip(&f.tip(f.a[5]));
    let mut pending = None;

    assert!(matches!(
        h.worker.reconcile_once(&mut pending),
        Ok(ReconcileAction::Progressed)
    ));
    let committed = Some(at(&f.tip(f.a[2])));
    assert_eq!(h.watermarks().script_live, committed);
    assert!(matches!(
        h.worker.reconcile_once(&mut pending),
        Err(DerivedIndexWorkerError::Index(IndexError::BlockParse(_)))
    ));
    assert_eq!(h.watermarks().script_live, committed);
}

/// An undo read that fails is not a missing record: the lowest-height anchor
/// failure keeps its identity and `ScriptLive` is not reset.
#[test]
fn undo_read_failure_is_not_a_missing_undo() {
    let f = ForkFixture::new(5);
    f.persist_undo();
    let h = Harness::with_enabled(&f, u32::MAX, IndexCapabilities::SCRIPT_LIVE);
    h.set_tip(&f.tip(f.a[1]));
    h.settle(&mut None);

    // The read failure at height 4 decides over the missing record at 5.
    f.bodies.undo_read_failures.lock().insert(f.a_key(4));
    {
        let key = f.a_key(5);
        f.bodies
            .undo
            .remove_archived(key.0, Hash256::from_le_bytes(key.1));
    }
    h.set_tip(&f.tip(f.a[4]));

    assert!(matches!(
        h.worker.reconcile_once(&mut None),
        Err(DerivedIndexWorkerError::Storage(_))
    ));
    assert_eq!(h.watermarks().script_live, Some(at(&f.tip(f.a[1]))));
}
