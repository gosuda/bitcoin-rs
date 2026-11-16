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

use bitcoin_rs_execution::chain::{BlockTree, NodeId, NodeStatus, TipSnapshot};

use crate::IndexCapabilities;

use bitcoin_rs_consensus::primitives::Hash256;

use bitcoin_rs_storage::pruning::{HistoryAccess, RetentionBudget, RetentionRegistry};
use bitcoin_rs_storage::utxo::SnapshotCoinObserver as _;
use bitcoin_rs_storage::{
    InMemoryUndoStore, RocksDbStore, StorageError, block_body::BlockBodyStore,
};

use hashbrown::{HashMap, HashSet};

use parking_lot::{Mutex, RwLock};

use std::{sync::Arc, time::Duration};

use super::*;

type BodyMap = HashMap<(u32, [u8; 32]), Vec<u8>>;

#[derive(Debug, thiserror::Error)]
enum RecoveryTestError {
    #[error(transparent)]
    Storage(#[from] bitcoin_rs_storage::StorageError),
    #[error(transparent)]
    Index(#[from] crate::IndexError),
    #[error(transparent)]
    LiveValue(#[from] crate::types::ScriptLiveValueError),
    #[error("live row key fails to decode")]
    BadLiveRow,
}

struct MapBodyStore {
    bodies: Mutex<BodyMap>,
    undo: Mutex<BodyMap>,
    undo_read_failures: Mutex<HashSet<(u32, [u8; 32])>>,
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
        Ok(self.undo.lock().get(&key).cloned())
    }

    fn sync(&self) -> Result<(), StorageError> {
        Ok(())
    }
}

#[derive(Default)]
struct BranchCoins(Vec<bitcoin_rs_storage::utxo::UtxoCoin>);

impl bitcoin_rs_storage::utxo::contract::SpentOutputLookup for BranchCoins {
    fn entry(
        &self,
        outpoint: &bitcoin_rs_consensus::primitives::OutPoint,
    ) -> Option<&bitcoin_rs_storage::utxo::UtxoCoin> {
        self.0.iter().find(|coin| coin.outpoint == *outpoint)
    }
}

impl BranchCoins {
    fn connect(
        &mut self,
        height: u32,
        block: &bitcoin_rs_consensus::primitives::Block,
        txids: &[bitcoin_rs_consensus::primitives::Txid],
    ) {
        for (tx, txid) in block.txs.iter().zip(txids) {
            for (vout, txout) in tx.outputs.iter().enumerate() {
                self.0.push(bitcoin_rs_storage::utxo::UtxoCoin {
                    outpoint: bitcoin_rs_consensus::primitives::OutPoint::new(
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

fn tree_header(block: &Block) -> bitcoin_rs_consensus::primitives::Header {
    bitcoin_rs_consensus::primitives::deserialize::<bitcoin_rs_consensus::primitives::Header>(
        &serialize(&block.header),
    )
    .expect("80-byte header")
}

fn mine_block(prev_hash: Hash256, height: u32, extra: i64, prev_extra: i64) -> (Block, Hash256) {
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
            txid: coinbase_tx(height - 1, prev_extra).compute_txid(),
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

pub(super) struct ForkFixture {
    tree: Arc<RwLock<BlockTree>>,
    bodies: Arc<MapBodyStore>,
    genesis: Hash256,
    pub(super) a: Vec<(NodeId, Hash256)>,
    b: Vec<(NodeId, Hash256)>,
}

impl ForkFixture {
    pub(super) fn new(len: u32) -> Self {
        let mut tree = BlockTree::new();
        let mut bodies = BodyMap::new();
        let (genesis, genesis_hash) = mine_block(Hash256::from_le_bytes(&[0_u8; 32]), 0, 0, 0);
        tree.insert_header(tree_header(&genesis), NodeStatus::HeaderValid)
            .expect("genesis");
        bodies.insert((0, genesis_hash.to_le_bytes()), serialize(&genesis));
        let mut branch = |extra: i64| {
            let mut prev = genesis_hash;
            let mut ids = Vec::new();
            for height in 1..=len {
                let prev_extra = if height == 1 { 0 } else { extra };
                let (block, hash) = mine_block(prev, height, extra, prev_extra);
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
                undo: Mutex::default(),
                undo_read_failures: Mutex::default(),
                stop_on_absent_body: Mutex::default(),
            }),
            genesis: genesis_hash,
            a,
            b,
        }
    }

    fn a_key(&self, height: u32) -> (u32, [u8; 32]) {
        if height == 0 {
            return (0, self.genesis.to_le_bytes());
        }
        let index = usize::try_from(height - 1).expect("height index");
        (height, self.a[index].1.to_le_bytes())
    }

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

    fn branch_key(&self, branch: &[(NodeId, Hash256)], height: u32) -> (u32, [u8; 32]) {
        if height == 0 {
            return (0, self.genesis.to_le_bytes());
        }
        let index = usize::try_from(height - 1).expect("height index");
        (height, branch[index].1.to_le_bytes())
    }

    fn persist_branch_undo(&self, branch: &[(NodeId, Hash256)]) {
        let store = InMemoryUndoStore::default();
        let mut coins = BranchCoins::default();
        let tip_height = u32::try_from(branch.len()).expect("branch length");
        for height in 0..=tip_height {
            let key = self.branch_key(branch, height);
            let block = {
                let bodies = self.bodies.bodies.lock();
                bitcoin_rs_consensus::primitives::deserialize::<
                    bitcoin_rs_consensus::primitives::Block,
                >(&bodies[&key])
                .expect("fixture block")
            };
            let txids = block.txids();
            let image = bitcoin_rs_consensus::primitives::BlockImage::from_local(block.clone());
            if height > 0 {
                let (_, undo, _) = bitcoin_rs_storage::utxo::contract::build_block_changes(
                    &bitcoin_rs_storage::utxo::contract::BlockChangeInputs {
                        block: &image,
                        height,
                        txids: &txids,
                        same_block_spent: None,
                        add_capacity: 0,
                        remove_capacity: 0,
                        max_script_size: crate::MAX_LIVE_SCRIPT_SIZE,
                    },
                    &coins,
                )
                .expect("undo batch");
                let record = bitcoin_rs_storage::utxo::contract::persist_block_undo(
                    &store,
                    height,
                    Hash256::from_le_bytes(&key.1),
                    &undo,
                )
                .expect("undo record");
                self.bodies
                    .undo
                    .lock()
                    .insert(key, record.as_bytes().to_vec());
            }
            coins.connect(height, &block, &txids);
        }
    }
    pub(super) fn persist_undo(&self) {
        self.persist_branch_undo(&self.a.clone());
        self.persist_branch_undo(&self.b.clone());
    }

    fn fork_from_a(&self, fork_height: u32, len: u32) -> Vec<(NodeId, Hash256)> {
        let shared = usize::try_from(fork_height).expect("fork height");
        let mut branch: Vec<(NodeId, Hash256)> = self.a[..shared].to_vec();
        let mut prev = branch.last().map_or(self.genesis, |(_, hash)| *hash);
        for height in fork_height + 1..=len {
            let prev_extra = if height == fork_height + 1 { 0 } else { 2 };
            let (block, hash) = mine_block(prev, height, 2, prev_extra);
            let id = self
                .tree
                .write()
                .insert_header(tree_header(&block), NodeStatus::HeaderValid)
                .expect("fork header");
            self.bodies
                .bodies
                .lock()
                .insert((height, hash.to_le_bytes()), serialize(&block));
            branch.push((id, hash));
            prev = hash;
        }
        branch
    }

    pub(super) fn tip(&self, (node_id, _): (NodeId, Hash256)) -> Arc<TipSnapshot> {
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
    store: Arc<RocksDbStore>,
    writer: Arc<dyn TxIndexWriter>,
    applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    runtime: Arc<DerivedIndexRuntime>,
    evidence: Arc<RecordedIndexAhead>,
    retention: Arc<RetentionRegistry>,
    worker: Worker,
}

// IDX-07
#[test]
fn missing_undo_pauses_the_tail_group_and_resumes_to_bulk() {
    const TIP: u32 = 20;
    const MISSING: u32 = 10;
    let f = ForkFixture::new(TIP);
    f.persist_undo();
    let key = f.a_key(MISSING);
    let record = f
        .bodies
        .undo
        .lock()
        .remove(&key)
        .expect("undo record for the missing height");
    let h = Harness::with_enabled(
        &f,
        u32::MAX,
        IndexCapabilities::HISTORICAL.with_compact_filters(true),
    );
    let tip = f.tip(f.a[usize::try_from(TIP - 1).expect("index")]);
    h.set_tip(&tip);
    h.settle(&mut None);

    let paused = h.watermarks();
    assert_eq!(
        paused.tx_lookup, paused.script_history,
        "the tail group moves together"
    );
    assert_eq!(
        paused.tx_lookup, paused.compact_filters,
        "the tail group moves together"
    );
    assert!(
        paused
            .tx_lookup
            .is_none_or(|watermark| watermark.height < MISSING),
        "the tail group stops before the missing height: {paused:?}"
    );
    assert!(h.runtime.compact_filter_failure.read().is_some());
    assert!(h.runtime.script_history_failure.read().is_some());
    assert!(h.runtime.tx_lookup_failure.read().is_some());
    assert!(!h.runtime.should_stop(), "the worker keeps running");

    f.bodies.undo.lock().insert(key, record);
    h.settle(&mut None);
    h.assert_at(&tip);
    assert!(
        h.runtime.undo_gap().is_none(),
        "the gap clears once the undo row returns"
    );
    assert_chain_matches_bulk(&h.store, &f, TIP);
}

fn assert_chain_matches_bulk(live: &RocksDbStore, f: &ForkFixture, tip: u32) {
    let blocks = committed_chain(f, &f.a, 0, tip);
    let oracle = bulk_oracle(&blocks);
    let bulk_view =
        crate::segment::SegmentSnapshot::open(oracle.store.snapshot().expect("bulk snapshot"))
            .expect("bulk view");
    let live_view = crate::segment::SegmentSnapshot::open(live.snapshot().expect("live snapshot"))
        .expect("live view");
    assert_eq!(
        winner_answers(&live_view, &blocks),
        winner_answers(&bulk_view, &blocks),
        "resumed index answers equal the bulk build of the chain"
    );
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
        let store = Arc::new(RocksDbStore::open(index_dir.path()).expect("rocksdb open"));
        Self::on_store(fixture, rollback_rebuild_cutover, enabled, index_dir, store)
    }

    fn on_store(
        fixture: &ForkFixture,
        rollback_rebuild_cutover: u32,
        enabled: IndexCapabilities,
        index_dir: tempfile::TempDir,
        store: Arc<RocksDbStore>,
    ) -> Self {
        let writer: Arc<dyn TxIndexWriter> = Arc::new(parking_lot::RwLock::new(
            crate::IndexWriter::open(Arc::clone(&store), 1)
                .expect("index writer open")
                .with_seal_scratch(index_dir.path().join("seal-scratch")),
        ));
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let (wake_tx, wake_rx) = crossbeam_channel::bounded(16);
        let runtime = DerivedIndexRuntime::new(wake_tx);
        let evidence = RecordedIndexAhead::new();
        let reporter: Arc<dyn IndexAheadSink> = evidence.clone();
        let body_store: Arc<dyn BlockBodyStore> = fixture.bodies.clone();
        let retention = Arc::new(RetentionRegistry::new());
        let worker = Worker {
            runtime: Arc::clone(&runtime),
            writer: Arc::clone(&writer),
            applied_tip: bitcoin_rs_execution::chain::TipReader::new(Arc::clone(&applied_tip)),
            block_tree: bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::clone(
                &fixture.tree,
            )),
            body_store: Some(body_store),
            history: HistoryAccess::new(Arc::clone(&retention), RetentionBudget::Unlimited),
            batch_limits: DEFAULT_BATCH_LIMITS,
            enabled,
            chain_events: Arc::new(TestChainCursor),
            reporter,
            shutdown: bitcoin_rs_consensus::latch::LatchReader::fixture_never(),
            wake_rx,
            quiet_period: Duration::ZERO,
            batch_delay: Duration::ZERO,
            rollback_rebuild_cutover,
            seed_history_lease: parking_lot::Mutex::new(None),
            facts_rx: None,
            facts_charge: None,
            facts_gap: None,
            cpu: None,
            buffered_facts: parking_lot::Mutex::new(hashbrown::HashMap::new()),
        };
        Self {
            _index_dir: index_dir,
            store,
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
        if self.worker.enabled.contains(IndexCapability::ScriptHistory)
            && self.runtime.script_history_failure.read().is_none()
        {
            assert_eq!(
                watermarks.script_history, expected,
                "script_history watermark"
            );
        }
        assert_eq!(self.runtime.phase(), ReconcilePhase::FORWARD);
    }

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

// IDX-07
#[test]
fn missing_undo_pauses_the_tail_group_at_the_fork_point() {
    struct SpentScript;
    impl crate::SpentCoins for SpentScript {
        fn spent_coin(&self, _: &[u8; 32], _: u32) -> Option<crate::SpentCoin<'_>> {
            Some(crate::SpentCoin {
                script: &[0x51],
                value: 0,
                height: 0,
                coinbase: false,
            })
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
    h.set_tip(&f.tip(f.b[1]));
    h.settle(&mut None);
    let watermarks = h.watermarks();
    for (name, mark) in [
        ("tx_lookup", watermarks.tx_lookup),
        ("script_history", watermarks.script_history),
        ("compact_filters", watermarks.compact_filters),
    ] {
        assert_eq!(
            mark.map(|watermark| watermark.height),
            Some(0),
            "{name} pauses at the fork point: the forward block has no undo record"
        );
    }
    assert!(
        h.runtime.compact_filter_failure.read().is_some(),
        "compact_filter_failure records the pause of the forward block"
    );
    assert!(
        h.runtime.script_history_failure.read().is_some(),
        "script_history_failure records the pause of the forward block"
    );
    assert!(
        h.runtime.tx_lookup_failure.read().is_some(),
        "tx_lookup_failure records the pause of the forward block"
    );
    assert_eq!(
        h.runtime.undo_gap(),
        Some((1, f.b[0].1)),
        "the gap names the forward block height and hash"
    );
    assert_eq!(h.runtime.phase(), ReconcilePhase::FORWARD);
    assert!(!h.runtime.should_stop());
}

// EVT-04, IDX-07
#[test]
fn unavailable_filter_history_preserves_sibling_indexes_and_filter_watermark() {
    let fixture = ForkFixture::new(2);
    fixture.persist_undo();
    for pruned in [false, true] {
        let harness = Harness::with_enabled(
            &fixture,
            u32::MAX,
            IndexCapabilities::HISTORICAL.with_compact_filters(true),
        );
        if pruned {
            harness.retention.reserve(1).commit(1);
        }
        harness.set_tip(&fixture.tip(fixture.a[1]));
        harness.settle(&mut None);
        harness.assert_at(&fixture.tip(fixture.a[1]));
        if pruned {
            assert!(harness.runtime.compact_filter_failure.read().is_some());
        } else {
            assert!(harness.runtime.compact_filter_failure.read().is_none());
            assert_eq!(
                harness.watermarks().compact_filters,
                Some(at(&fixture.tip(fixture.a[1]))),
                "filters advance when history is retained"
            );
        }
        assert!(!harness.runtime.should_stop());
        harness.set_tip(&fixture.tip(fixture.b[1]));
        harness.settle(&mut None);
        harness.assert_at(&fixture.tip(fixture.b[1]));
        if pruned {
            assert!(harness.watermarks().compact_filters.is_none());
        } else {
            assert_eq!(
                harness.watermarks().compact_filters,
                Some(at(&fixture.tip(fixture.b[1]))),
                "filters follow the reorg when history is retained"
            );
        }
    }
}

// IDX-06, IDX-07
#[test]
fn rollback_without_undo_preserves_script_history_and_rewinds_siblings() {
    let f = ForkFixture::new(3);
    f.persist_undo();
    let h = Harness::with_enabled(&f, u32::MAX, IndexCapabilities::HISTORICAL);
    let a3 = f.tip(f.a[2]);
    h.set_tip(&a3);
    h.settle(&mut None);
    h.assert_at(&a3);

    for height in 1..=3 {
        f.bodies.undo.lock().remove(&f.a_key(height));
    }
    let a1 = f.tip(f.a[0]);
    h.set_tip(&a1);
    h.settle(&mut None);

    assert_eq!(
        h.watermarks().tx_lookup,
        Some(at(&a1)),
        "TxLookup rolls back without the undo anchor"
    );
    assert_eq!(
        h.watermarks().script_history,
        Some(at(&a1)),
        "the tail group rewinds together: ScriptHistory moves with TxLookup"
    );
    assert!(h.runtime.script_history_failure.read().is_none());
    assert!(!h.runtime.should_stop());
}

#[test]
fn index_ahead_of_restored_tip_is_reported_once_and_rewound() {
    let f = ForkFixture::new(3);
    f.persist_undo();
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
        Some((_capability, index_height, tip_height, tip_hash_be, index_hash_be, depth)) => {
            assert_eq!((tip_height, index_height, depth), (1, 3, 2));
            assert_eq!(tip_hash_be, a1.hash.to_string_be());
            assert_eq!(index_hash_be, a3.hash.to_string_be());
        }
        other => panic!("expected IndexWatermarkAhead report, got {other:?}"),
    }
}

// RCV-05
#[test]
fn deep_rollback_rebuilds_and_publishes_rebuild_phase_until_caught_up() {
    let f = ForkFixture::new(3);
    f.persist_undo();
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
    for _ in 0..64 {
        let action = h.worker.reconcile_once(&mut pending).expect("rebuild pass");
        if matches!(action, ReconcileAction::CaughtUp) {
            break;
        }
        assert!(!matches!(action, ReconcileAction::Stalled));
        assert_eq!(
            h.runtime.phase(),
            ReconcilePhase::FORWARD
                .with_leg(IndexCapabilities::HISTORICAL, ReconcileLeg::Rebuilding)
        );
    }
    h.assert_at(&b3);
    let blocks = committed_chain(&f, &f.b, 0, b3.height);
    let oracle = bulk_oracle(&blocks);
    let bulk_view =
        crate::segment::SegmentSnapshot::open(oracle.store.snapshot().expect("bulk snapshot"))
            .expect("bulk view");
    let live_view =
        crate::segment::SegmentSnapshot::open(h.store.snapshot().expect("live snapshot"))
            .expect("live view");
    assert_eq!(
        winner_answers(&live_view, &blocks),
        winner_answers(&bulk_view, &blocks),
        "rebuilt transaction positions and script history equal an independent bulk build"
    );
    let abandoned = committed_chain(&f, &f.a, 1, a3.height);
    assert_eq!(
        winner_answers(&live_view, &abandoned),
        winner_answers(&bulk_view, &abandoned),
        "abandoned branch answers equal the winning-chain bulk build"
    );
    assert!(h.index_ahead_call().is_none(), "equal height is not ahead");
}

// RCV-07
#[test]
fn pruned_history_rebuilds_from_the_frontier_and_absent_history_waits() {
    let f = ForkFixture::new(3);
    f.persist_undo();
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
    f.persist_undo();
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

pub(super) fn at(tip: &TipSnapshot) -> IndexWatermark {
    IndexWatermark {
        height: tip.height,
        hash: tip.hash.to_le_bytes(),
    }
}

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

struct StopOnDrop(Arc<DerivedIndexRuntime>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.request_shutdown();
    }
}

fn held_prefix() -> (ForkFixture, SeedCellHarness, BodyMap) {
    let f = ForkFixture::new(4);
    f.persist_undo();
    let h = SeedCellHarness::new(&f, IndexCapabilities::TX_AND_SCRIPTS);
    let lost = f.take_bodies(2);
    let tip = f.tip(f.a[1]);
    h.stage_seed_rows(&tip, 32);
    h.set_tip(&tip);
    h.settle_stalled(&mut None);
    assert_eq!(h.watermarks().script_live, Some(at(&tip)));
    h.set_tip(&f.tip(f.a[3]));
    (f, h, lost)
}

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

#[test]
fn deferred_history_grant_does_not_run_a_higher_group() {
    let (f, h, _lost) = held_prefix();
    let mut pending = None;

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

struct AbsentBody {
    key: (u32, [u8; 32]),
    body: Vec<u8>,
}

fn retained_prefix() -> (ForkFixture, SeedCellHarness, AbsentBody) {
    let f = ForkFixture::new(300);
    f.persist_undo();
    let h = SeedCellHarness::new(&f, IndexCapabilities::TX_AND_SCRIPTS);
    let tip = f.tip(f.a[289]);
    h.stage_seed_rows(&tip, 32);
    h.set_tip(&tip);
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

#[test]
fn retained_prefix_commits_before_any_group_switch_and_never_outlives_a_fence_change() {
    let (f, h, _absent) = retained_prefix();
    let a279 = Some(at(&f.tip(f.a[278])));
    let a290 = Some(at(&f.tip(f.a[289])));
    let mut pending = None;

    assert!(matches!(
        h.worker.reconcile_once(&mut pending),
        Ok(ReconcileAction::Buffered)
    ));
    assert!(pending.is_some());
    let retained = h.watermarks();
    assert_eq!(retained.tx_lookup, None);
    assert_eq!(retained.script_live, a290);

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

    assert!(matches!(
        h.worker.reconcile_once(&mut pending),
        Ok(ReconcileAction::Buffered)
    ));
    assert!(matches!(
        h.worker.reconcile_once(&mut pending),
        Ok(ReconcileAction::Progressed)
    ));
    let flushed = h.watermarks();
    assert_eq!(flushed.tx_lookup, a279);
    assert_eq!(flushed.script_history, a279);
    assert_eq!(flushed.script_live, a290);

    h.settle_stalled(&mut pending);
    let end = h.watermarks();
    assert_eq!(end.script_live, Some(at(&f.tip(f.a[299]))));
    assert_eq!(end.tx_lookup, a279);
}

#[test]
fn run_loop_commits_a_retained_prefix_and_retries_an_absent_body_without_a_wake() {
    let (f, mut h, absent) = retained_prefix();
    h.worker.batch_delay = Duration::from_millis(50);
    h.worker.quiet_period = Duration::from_millis(20);
    let writer = Arc::clone(&h.writer);
    let runtime = Arc::clone(&h.runtime);
    let watermarks = move || writer.fenced_watermarks().expect("watermarks").1;
    let a279 = Some(at(&f.tip(f.a[278])));
    let a300 = Some(at(&f.tip(f.a[299])));

    let worker = h.worker;
    let run = std::thread::spawn(move || worker.run());
    let _cancel = StopOnDrop(Arc::clone(&runtime));

    wait_until("the prefix commit and the ready group", || {
        let marks = watermarks();
        marks.tx_lookup == a279 && marks.script_live == a300
    });
    f.bodies.bodies.lock().insert(absent.key, absent.body);
    wait_until("the history families to catch up", || {
        let marks = watermarks();
        marks.tx_lookup == a300 && marks.script_history == a300 && marks.script_live == a300
    });

    runtime.request_shutdown();
    run.join().expect("worker thread").expect("worker run");
}

type LiveCoin = (ScriptHash, [u8; 32], u32, u64, u32, bool);

struct UnspentCoin {
    script: Vec<u8>,
    value: u64,
    height: u32,
    coinbase: bool,
}
type UnspentMap = hashbrown::HashMap<([u8; 32], u32), UnspentCoin>;

fn unspent_live_coins(blocks: &[bitcoin_rs_storage::CommittedBlock]) -> Vec<LiveCoin> {
    let mut unspent: UnspentMap = hashbrown::HashMap::new();
    for block in blocks {
        if block.height == 0 {
            continue;
        }
        apply_live_block(&mut unspent, block);
    }
    let mut coins: Vec<LiveCoin> = unspent
        .into_iter()
        .map(|((txid, vout), coin)| {
            (
                ScriptHash::from_script_bytes(&coin.script),
                txid,
                vout,
                coin.value,
                coin.height,
                coin.coinbase,
            )
        })
        .collect();
    coins.sort_by(|a, b| a.1.cmp(&b.1).then(a.2.cmp(&b.2)));
    coins
}

fn apply_live_block(unspent: &mut UnspentMap, block: &bitcoin_rs_storage::CommittedBlock) {
    for tx in &block.txs {
        let coinbase =
            tx.inputs.len() == 1 && tx.inputs[0].txid == [0u8; 32] && tx.inputs[0].vout == u32::MAX;
        spend_live_inputs(unspent, tx);
        create_live_outputs(unspent, tx, block.height, coinbase);
    }
}

fn spend_live_inputs(unspent: &mut UnspentMap, tx: &bitcoin_rs_storage::TxFacts) {
    for input in &tx.inputs {
        if input.txid == [0u8; 32] && input.vout == u32::MAX {
            continue;
        }
        unspent.remove(&(input.txid, input.vout));
    }
}

fn create_live_outputs(
    unspent: &mut UnspentMap,
    tx: &bitcoin_rs_storage::TxFacts,
    height: u32,
    coinbase: bool,
) {
    for output in &tx.outputs {
        let admitted = !matches!(output.script.first(), Some(0x6a))
            && output.script.len() <= crate::MAX_LIVE_SCRIPT_SIZE;
        if !admitted {
            continue;
        }
        unspent.insert(
            (tx.txid, output.vout),
            UnspentCoin {
                script: output.script.to_vec(),
                value: output.value,
                height,
                coinbase,
            },
        );
    }
}

// IDX-06, IDX-07
#[test]
fn script_live_undo_gap_pauses_the_group_and_resumes_to_bulk() -> Result<(), RecoveryTestError> {
    #[derive(Clone, Copy)]
    enum Undo {
        Present,
        Missing,
        Corrupt,
    }
    const MISSING: u32 = 4;
    for undo in [Undo::Present, Undo::Missing, Undo::Corrupt] {
        let f = ForkFixture::new(5);
        f.persist_undo();
        let h = SeedCellHarness::new(&f, IndexCapabilities::TX_AND_SCRIPTS);
        let (a2, a5) = (f.tip(f.a[1]), f.tip(f.a[4]));
        let seed_blocks = committed_chain(&f, &f.a, 0, 2);
        let staged: Vec<Vec<u8>> = unspent_live_coins(&seed_blocks)
            .iter()
            .map(|(scripthash, txid, vout, value, height, coinbase)| {
                let outpoint = bitcoin_rs_consensus::primitives::OutPoint::new(
                    bitcoin_rs_consensus::primitives::Txid(Hash256::from_le_bytes(txid)),
                    *vout,
                );
                let coin =
                    crate::types::ScriptLiveCoin::new(*scripthash, *value, *height, *coinbase);
                let row = crate::types::ScriptLiveRow::new(*scripthash, &outpoint);
                let mut bytes = row.as_bytes().to_vec();
                let Ok(encoded) = coin.encode_value() else {
                    panic!("the seed coin must encode");
                };
                bytes.extend_from_slice(&encoded);
                bytes
            })
            .collect();
        h.writer.stage_script_live_rows(&mut staged.into_iter())?;
        h.writer
            .publish_script_live_seed(at(&a2))
            .expect("publish seed at h-1");
        h.set_tip(&a2);
        h.settle(&mut None);

        let key = f.a_key(MISSING);
        let original = f.bodies.undo.lock().get(&key).cloned();
        match undo {
            Undo::Present => {}
            Undo::Missing => {
                f.bodies.undo.lock().remove(&key);
            }
            Undo::Corrupt => {
                let mut undo = f.bodies.undo.lock();
                let Some(record) = undo.get_mut(&key) else {
                    panic!("the undo record must exist to corrupt it");
                };
                record[0] ^= 0xff;
            }
        }
        assert_eq!(
            h.watermarks().script_live,
            Some(at(&a2)),
            "ScriptLive is seeded at h-1 before the gap"
        );
        h.set_tip(&a5);
        let mut pending = None;
        if matches!(undo, Undo::Present) {
            h.settle(&mut pending);
        } else {
            for _ in 0..64 {
                match h
                    .worker
                    .reconcile_once(&mut pending)
                    .expect("the pass returns instead of halting")
                {
                    ReconcileAction::CaughtUp | ReconcileAction::Stalled => break,
                    ReconcileAction::Progressed | ReconcileAction::Buffered => {}
                }
            }
            let paused = h.watermarks();
            assert_eq!(
                paused.script_live,
                Some(at(&a2)),
                "ScriptLive pauses at h-1 without a reset"
            );
            assert_eq!(
                paused.tx_lookup, paused.script_history,
                "the tail group moves together"
            );
            assert!(
                paused
                    .tx_lookup
                    .is_some_and(|watermark| watermark.height < MISSING),
                "the tail group stops before the missing height: {paused:?}"
            );
            assert!(h.runtime.script_history_failure.read().is_some());
            assert_eq!(
                h.runtime.undo_gap().map(|(height, _)| height),
                Some(MISSING),
                "the gap names the missing height"
            );
            if let Some(record) = original {
                f.bodies.undo.lock().insert(key, record);
            }
        }
        h.settle(&mut pending);
        assert_eq!(h.watermarks().tx_lookup, Some(at(&a5)));
        assert_eq!(h.watermarks().script_history, Some(at(&a5)));
        assert_eq!(h.watermarks().script_live, Some(at(&a5)));
        assert!(
            h.runtime.undo_gap().is_none(),
            "the gap clears once the undo row returns"
        );
        assert_chain_matches_bulk(&h.store, &f, 5);
        let snapshot = h.store.snapshot()?;
        let mut live: Vec<LiveCoin> = Vec::new();
        for item in snapshot.iter_prefix(ColumnFamily::ScriptLive, &[])? {
            let (key, value) = item?;
            if key.len() != crate::types::SCRIPT_LIVE_ROW_SIZE {
                continue;
            }
            let Some(row) = crate::types::ScriptLiveRow::from_db_row(&key) else {
                return Err(RecoveryTestError::BadLiveRow);
            };
            let outpoint = row.outpoint();
            let coin = crate::types::ScriptLiveCoin::decode_value(&value)?;
            live.push((
                coin.scripthash,
                *outpoint.txid.as_bytes(),
                outpoint.vout,
                coin.value,
                coin.height,
                coin.coinbase,
            ));
        }
        live.sort_by(|a, b| a.1.cmp(&b.1).then(a.2.cmp(&b.2)));
        assert_eq!(
            live,
            unspent_live_coins(&committed_chain(&f, &f.a, 0, 5)),
            "ScriptLive contents equal the unspent set at the tip"
        );
    }
    Ok(())
}

// IDX-06
#[test]
fn anchor_failure_outranks_an_earlier_preparation_failure() {
    let f = ForkFixture::new(6);
    f.persist_undo();
    let h = Harness::with_enabled(&f, u32::MAX, IndexCapabilities::SCRIPT_LIVE);
    h.set_tip(&f.tip(f.a[1]));
    h.settle(&mut None);

    f.bodies.bodies.lock().insert(f.a_key(3), vec![0; 10]);
    f.bodies.undo.lock().remove(&f.a_key(5));
    h.set_tip(&f.tip(f.a[5]));

    assert!(matches!(
        h.worker.reconcile_once(&mut None),
        Ok(ReconcileAction::Progressed)
    ));
    assert_eq!(
        h.runtime.undo_gap().map(|(height, _)| height),
        Some(5),
        "the anchor failure at height 5 is the recorded gap"
    );
    assert_eq!(
        h.watermarks().script_live,
        Some(at(&f.tip(f.a[1]))),
        "block 3 cannot be prepared, so ScriptLive stops at height 2"
    );
}

#[test]
fn preparation_failure_keeps_its_height_after_committed_successes() {
    let f = ForkFixture::new(6);
    f.persist_undo();
    let mut h = Harness::with_enabled(&f, u32::MAX, IndexCapabilities::SCRIPT_LIVE);
    h.set_tip(&f.tip(f.a[1]));
    h.settle(&mut None);

    f.bodies.bodies.lock().insert(f.a_key(4), vec![0; 10]);
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

// IDX-07
#[test]
fn undo_read_failure_is_not_a_missing_undo() {
    let f = ForkFixture::new(5);
    f.persist_undo();
    let h = Harness::with_enabled(&f, u32::MAX, IndexCapabilities::SCRIPT_LIVE);
    h.set_tip(&f.tip(f.a[1]));
    h.settle(&mut None);

    f.bodies.undo_read_failures.lock().insert(f.a_key(4));
    f.bodies.undo.lock().remove(&f.a_key(5));
    h.set_tip(&f.tip(f.a[4]));

    assert!(matches!(
        h.worker.reconcile_once(&mut None),
        Err(DerivedIndexWorkerError::Storage(_))
    ));
    assert_eq!(h.watermarks().script_live, Some(at(&f.tip(f.a[1]))));
}

// IDX-07
#[test]
fn script_live_pruned_terminal_keeps_worker_alive() {
    let f = ForkFixture::new(4);
    f.persist_undo();
    let h = SeedCellHarness::new(&f, IndexCapabilities::TX_AND_SCRIPTS);
    h.set_tip(&f.tip(f.a[0]));
    let mut pending = None;
    h.settle(&mut pending);
    h.assert_at(&f.tip(f.a[0]));

    h.retention.reserve(3).commit(3);
    h.set_tip(&f.tip(f.a[2]));
    let mut flagged = false;
    for _ in 0..16 {
        match h.worker.reconcile_once(&mut pending).expect("prune pass") {
            ReconcileAction::CaughtUp
            | ReconcileAction::Progressed
            | ReconcileAction::Buffered
            | ReconcileAction::Stalled => {}
        }
        assert!(!h.runtime.should_stop(), "worker stays alive");
        assert!(
            h.runtime.failure_message().is_none(),
            "no global worker failure"
        );
        if let Some(outage) = h.runtime.script_live_failure() {
            assert_eq!(
                outage,
                ScriptLiveOutage::HistoryPruned,
                "pruned history is the terminal ScriptLive reason"
            );
            flagged = true;
        }
    }
    assert!(flagged, "pruned frontier raises terminal unavailable");
    let t = f.tip(f.a[2]);
    assert_eq!(
        h.watermarks().tx_lookup,
        Some(at(&t)),
        "other groups progress"
    );
    assert_eq!(h.watermarks().script_history, Some(at(&t)));
    assert_eq!(
        h.watermarks().script_live,
        None,
        "live waits for a replacement artifact after the old view is reset"
    );
    let mut converged_once = false;
    for _ in 0..16 {
        match h.worker.reconcile_once(&mut pending).expect("replay pass") {
            ReconcileAction::CaughtUp
            | ReconcileAction::Progressed
            | ReconcileAction::Buffered
            | ReconcileAction::Stalled => {}
        }
        assert!(!h.runtime.should_stop(), "worker stays alive");
        assert!(
            h.runtime.failure_message().is_none(),
            "no global worker failure"
        );
        if h.watermarks().tx_lookup == Some(at(&t)) && h.watermarks().script_history == Some(at(&t))
        {
            converged_once = true;
        }
    }
    assert!(converged_once, "other groups converge");

    h.stage_seed_rows(&t, 32);
    h.settle(&mut pending);
    assert!(
        h.runtime.script_live_failure().is_none(),
        "take clears the flag"
    );
    assert_eq!(h.watermarks().script_live, Some(at(&t)));
    h.assert_at(&t);
}

// IDX-06
#[test]
fn seed_first_leg_runs_under_the_held_history_pin() {
    let registry = Arc::new(RetentionRegistry::new());
    let access = HistoryAccess::new(Arc::clone(&registry), RetentionBudget::Depth(288));
    let lease = access.request_history(2).expect("grant at 2");
    assert_eq!(lease.floor(), Some(2));
    assert_eq!(registry.active_leases(), 1);
    lease.advance(4);
    assert_eq!(lease.floor(), Some(4), "progress moves the pin");
    drop(lease);
    assert_eq!(registry.retention_floor(), None);
    assert_eq!(registry.active_leases(), 0);

    let f = ForkFixture::new(4);
    f.persist_undo();
    let h = SeedCellHarness::new(&f, IndexCapabilities::TX_AND_SCRIPTS);
    let h_tip = f.tip(f.a[1]);
    h.stage_seed_rows(&h_tip, 32);
    h.set_tip(&f.tip(f.a[3]));
    let absent = f.a_key(3);
    let withheld = f
        .bodies
        .bodies
        .lock()
        .remove(&absent)
        .expect("withheld body");
    let mut pending = None;
    let first = h.worker.reconcile_once(&mut pending).expect("take");
    assert!(
        !matches!(first, ReconcileAction::CaughtUp),
        "take plus seed never completes the pass"
    );
    assert_eq!(
        h.watermarks().script_live,
        Some(at(&h_tip)),
        "seed commits H before the first leg"
    );
    for _ in 0..16 {
        match h.worker.reconcile_once(&mut pending).expect("stalled leg") {
            ReconcileAction::CaughtUp
            | ReconcileAction::Progressed
            | ReconcileAction::Buffered
            | ReconcileAction::Stalled => {}
        }
        assert!(
            h.retention.active_leases() <= 1,
            "a stalled leg holds at most the single pin"
        );
        assert!(h.runtime.failure_message().is_none());
    }
    f.bodies.bodies.lock().insert(absent, withheld);
    h.settle(&mut pending);
    let t = f.tip(f.a[3]);
    assert_eq!(h.watermarks().script_live, Some(at(&t)));
    h.assert_at(&t);
    assert_eq!(h.retention.active_leases(), 0, "progress past H releases");
    assert_eq!(h.retention.retention_floor(), None);
}

pub(super) struct SeedCellHarness {
    _index_dir: tempfile::TempDir,
    store: Arc<RocksDbStore>,
    writer: Arc<dyn TxIndexWriter>,
    applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    pub(super) runtime: Arc<DerivedIndexRuntime>,
    retention: Arc<RetentionRegistry>,
    worker: Worker,
}

impl SeedCellHarness {
    pub(super) fn new(fixture: &ForkFixture, enabled: IndexCapabilities) -> Self {
        let index_dir = tempfile::tempdir().expect("index dir");
        let store = Arc::new(RocksDbStore::open(index_dir.path()).expect("rocksdb open"));
        let writer: Arc<dyn TxIndexWriter> = Arc::new(parking_lot::RwLock::new(
            crate::IndexWriter::open(Arc::clone(&store), 1).expect("index writer open"),
        ));
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let (wake_tx, wake_rx) = crossbeam_channel::bounded(16);
        let runtime = DerivedIndexRuntime::new(wake_tx);
        let reporter: Arc<dyn IndexAheadSink> = RecordedIndexAhead::new();
        let body_store: Arc<dyn BlockBodyStore> = fixture.bodies.clone();
        let retention = Arc::new(RetentionRegistry::new());
        let worker = Worker {
            runtime: Arc::clone(&runtime),
            writer: Arc::clone(&writer),
            applied_tip: bitcoin_rs_execution::chain::TipReader::new(Arc::clone(&applied_tip)),
            block_tree: bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::clone(
                &fixture.tree,
            )),
            body_store: Some(body_store),
            history: HistoryAccess::new(Arc::clone(&retention), RetentionBudget::Depth(288)),
            batch_limits: DEFAULT_BATCH_LIMITS,
            enabled,
            chain_events: Arc::new(TestChainCursor),
            reporter,
            shutdown: bitcoin_rs_consensus::latch::LatchReader::fixture_never(),
            wake_rx,
            quiet_period: Duration::ZERO,
            batch_delay: Duration::ZERO,
            rollback_rebuild_cutover: u32::MAX,
            seed_history_lease: parking_lot::Mutex::new(None),
            facts_rx: None,
            facts_charge: None,
            facts_gap: None,
            cpu: None,
            buffered_facts: parking_lot::Mutex::new(hashbrown::HashMap::new()),
        };
        Self {
            _index_dir: index_dir,
            store,
            writer,
            applied_tip,
            runtime,
            retention,
            worker,
        }
    }

    pub(super) fn stage_seed_rows(&self, tip: &TipSnapshot, count: u64) {
        let session = self
            .runtime
            .script_live_seed()
            .begin_session()
            .expect("seed session open");
        {
            let mut observer = session.observer();
            for i in 0..count {
                let mut txid = [0_u8; 32];
                txid[..8].copy_from_slice(&i.to_le_bytes());
                observer.observe_coin(bitcoin_rs_storage::utxo::SnapshotCoin {
                    txid: Hash256::from_le_bytes(&txid),
                    vout: 0,
                    value: 1_000 + i,
                    script_pubkey: &[0x51],
                    height: tip.height,
                    coinbase: false,
                });
            }
        }
        assert!(session.take_error().is_none(), "staging must not fail");
        session.publish(IndexWatermark {
            height: tip.height,
            hash: tip.hash.to_le_bytes(),
        });
    }

    pub(super) fn set_tip(&self, tip: &Arc<TipSnapshot>) {
        self.applied_tip.store(Some(Arc::clone(tip)));
    }

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

    pub(super) fn watermarks(&self) -> IndexWatermarks {
        self.writer.fenced_watermarks().expect("watermarks").1
    }

    pub(super) fn live_row_count(&self) -> usize {
        self.store
            .iter_prefix(ColumnFamily::ScriptLive, &[])
            .expect("live scan")
            .filter_map(std::result::Result::ok)
            .count()
    }

    pub(super) fn stalled_pass(&self, pending: &mut Option<PendingForward>) -> bool {
        matches!(
            self.worker.reconcile_once(pending).expect("reconcile pass"),
            ReconcileAction::Stalled
        )
    }

    pub(super) fn assert_at(&self, tip: &TipSnapshot) {
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
    }

    pub(super) fn settle(&self, pending: &mut Option<PendingForward>) {
        for _ in 0..64 {
            assert!(
                self.retention.active_leases() <= 1,
                "single live history pin at every instant"
            );
            match self.worker.reconcile_once(pending).expect("reconcile pass") {
                ReconcileAction::CaughtUp => return,
                ReconcileAction::Progressed | ReconcileAction::Buffered => {}
                ReconcileAction::Stalled => panic!("worker stalled"),
            }
        }
        panic!("worker did not converge");
    }
}

// EVT-03
#[test]
fn malformed_stored_consumer_cursor_never_causes_panic_and_overwrites_cleanly()
-> Result<(), RecoveryTestError> {
    let f = ForkFixture::new(3);
    f.persist_undo();
    let h = Harness::with_enabled(&f, u32::MAX, IndexCapabilities::TX_LOOKUP);
    let mut tip = (*f.tip(f.a[0])).clone();
    tip.height = 0;
    tip.hash = Hash256::from_le_bytes(&[0; 32]);
    h.applied_tip.store(Some(Arc::new(tip)));
    let expected = IndexWatermark {
        height: 0,
        hash: [0; 32],
    };
    h.writer
        .anchor_watermark(IndexCapabilities::TX_LOOKUP, expected, 0)
        .expect("anchor");

    let mut fixed = [0u8; crate::reconcile::CURSOR_BYTE_LEN];
    fixed[..8].copy_from_slice(&0u64.to_le_bytes());
    fixed[8..16].copy_from_slice(&0u64.to_le_bytes());
    fixed[16..20].copy_from_slice(&0u32.to_le_bytes());
    fixed[20..].copy_from_slice(&[0u8; 32]);
    for malformed in [
        &b""[..],
        &b"\xff"[..],
        &b"corrupt-cursor-bytes"[..],
        &[0xaa; 51][..],
        &[0xbb; crate::reconcile::CURSOR_BYTE_LEN][..],
    ] {
        let (fence, _) = h.writer.fenced_watermarks().expect("fence");
        h.writer
            .commit_consumer_cursor(fence, malformed)
            .expect("commit malformed cursor");

        let commit = h
            .worker
            .persist_chain_cursor()
            .expect("persist must not panic on malformed cursor");
        assert!(matches!(commit, CursorCommit::Settled));

        let stored = h
            .writer
            .consumer_cursor()
            .expect("read cursor")
            .expect("cursor exists");
        assert_eq!(
            stored.len(),
            52,
            "the durable cursor is exactly the EVT-03 layout"
        );
        assert_eq!(stored, fixed, "the overwrite pins the EVT-03 field order");
    }
    let (fence, _) = h.writer.fenced_watermarks().expect("fence");
    for oversized in [
        &[0xbb; crate::reconcile::CURSOR_BYTE_LEN + 1][..],
        &[0xcc; 1024][..],
    ] {
        assert!(
            matches!(
                h.writer.commit_consumer_cursor(fence, oversized),
                Err(crate::IndexError::CursorLength { .. })
            ),
            "a cursor wider than the reserved width is refused before any write"
        );
    }
    assert_eq!(
        h.writer.consumer_cursor()?,
        Some(fixed.to_vec()),
        "an oversized cursor is refused before any write"
    );
    Ok(())
}

// PRJ-04
#[test]
fn buffered_facts_below_index_progress_are_evicted() {
    use bitcoin_rs_storage::CommittedBlock;

    let f = ForkFixture::new(2);
    let mut h = Harness::with_enabled(&f, u32::MAX, IndexCapabilities::TX_LOOKUP);
    let (_facts_tx, facts_rx) = crossbeam_channel::bounded(8);
    h.worker.facts_rx = Some(facts_rx);

    let a2 = f.tip(f.a[1]);
    let identities = h
        .worker
        .collect_target_chain(&a2, 1, 2)
        .expect("target chain from height one");
    let stale = CommittedBlock {
        height: 0,
        hash: [0x77; 32],
        parent_hash: [0_u8; 32],
        header: [0_u8; 80],
        txs: Vec::new(),
    };
    let window = CommittedBlock {
        height: identities[0].height,
        hash: identities[0].hash,
        parent_hash: identities[0].parent_hash,
        header: [0_u8; 80],
        txs: Vec::new(),
    };
    let stale_key = (stale.hash, stale.height);
    let window_key = (window.hash, window.height);
    {
        let mut guard = h.worker.buffered_facts.lock();
        guard.insert(stale_key, stale);
        guard.insert(window_key, window);
    }

    let prepared = h
        .worker
        .try_prepare_from_facts(&identities, IndexCapabilities::TX_LOOKUP)
        .expect("facts preparation");
    assert_eq!(
        prepared.map(|blocks| blocks.len()),
        Some(1),
        "the fact inside the requested window must serve the fast path"
    );
    let guard = h.worker.buffered_facts.lock();
    assert!(
        !guard.contains_key(&stale_key),
        "facts below the requested height must be evicted instead of accumulating"
    );
    assert!(
        guard.contains_key(&window_key),
        "a fact stays buffered until admission consumes it"
    );
    drop(guard);
}

// BUD-06, BUD-07
#[test]
fn buffered_facts_hold_their_charge_while_the_queue_refills() {
    use bitcoin_rs_storage::CommittedBlock;
    use bitcoin_rs_storage::CommittedFacts;
    use bitcoin_rs_storage::budget::BudgetCharge;
    use bitcoin_rs_storage::budget::BudgetError;
    use bitcoin_rs_storage::budget::BudgetOwner;
    use bitcoin_rs_storage::budget::ChargeHandle;
    use std::sync::Mutex as StdMutex;

    struct Ledger {
        outstanding: StdMutex<u64>,
        capacity: u64,
    }
    impl BudgetCharge for Ledger {
        fn reserve_bytes(&self, _: BudgetOwner, bytes: u64) -> Result<(), BudgetError> {
            let mut outstanding = self.outstanding.lock().expect("ledger lock");
            let next = outstanding.saturating_add(bytes);
            if next > self.capacity {
                return Err(BudgetError::BudgetExhausted);
            }
            *outstanding = next;
            Ok(())
        }
        fn allocate_bytes(&self, _: BudgetOwner, _: u64) -> Result<(), BudgetError> {
            Ok(())
        }
        fn release_bytes(&self, _: BudgetOwner, bytes: u64) {
            let mut outstanding = self.outstanding.lock().expect("ledger lock");
            *outstanding = outstanding.saturating_sub(bytes);
        }
        fn available_bytes(&self, _: BudgetOwner) -> u64 {
            self.capacity - *self.outstanding.lock().expect("ledger lock")
        }
    }

    fn probe_block(height: u32, hash: u8) -> CommittedBlock {
        CommittedBlock {
            height,
            hash: [hash; 32],
            parent_hash: [hash.wrapping_sub(1); 32],
            header: [0_u8; 80],
            txs: Vec::new(),
        }
    }

    let f = ForkFixture::new(2);
    let mut h = Harness::with_enabled(&f, u32::MAX, IndexCapabilities::TX_LOOKUP);
    let facts = Arc::new(CommittedFacts {
        commit_id: 1,
        blocks: vec![probe_block(1, 1)],
    });
    let facts_size = facts.size_bytes();
    let capacity = facts_size * 4;
    let ledger: Arc<dyn BudgetCharge> = Arc::new(Ledger {
        outstanding: StdMutex::new(0),
        capacity,
    });
    let charge = ChargeHandle::new(Arc::clone(&ledger), BudgetOwner::FactsQueue);
    let (facts_tx, facts_rx) = crossbeam_channel::bounded(8);
    h.worker.facts_rx = Some(facts_rx);
    h.worker.facts_charge = Some(charge.clone());

    let mut refused = false;
    for index in 0..16_u8 {
        if charge.charge(facts_size).is_err() {
            refused = true;
            break;
        }
        if facts_tx
            .send(Arc::new(CommittedFacts {
                commit_id: u64::from(index) + 2,
                blocks: vec![probe_block(1, index + 2)],
            }))
            .is_err()
        {
            break;
        }
        let prepared = h
            .worker
            .try_prepare_from_facts(&[], IndexCapabilities::TX_LOOKUP)
            .expect("facts drain");
        assert!(prepared.is_none(), "no identities requested");
    }
    assert!(
        refused,
        "the sender budget must refuse while buffered facts are retained without a charge"
    );

    let buffered: u64 = h
        .worker
        .buffered_facts
        .lock()
        .values()
        .map(|block| block.size_bytes())
        .sum();
    assert_eq!(
        ledger.available_bytes(BudgetOwner::FactsQueue),
        capacity - buffered,
        "every retained buffered block must hold a ledger charge"
    );
}

// IDX-06
#[test]
fn facts_batch_overflow_keeps_the_unadmitted_suffix() {
    let f = ForkFixture::new(4);
    let mut h = Harness::with_enabled(&f, u32::MAX, IndexCapabilities::TX_LOOKUP);
    let blocks = committed_chain(&f, &f.a, 0, 2);
    f.bodies.bodies.lock().clear();
    let tip = f.tip(f.a[1]);
    h.set_tip(&tip);
    let (facts_tx, facts_rx) = crossbeam_channel::bounded(8);
    h.worker.facts_rx = Some(facts_rx);
    h.worker.batch_limits = PreparedBatchLimits {
        max_rows: 1,
        max_bytes: usize::MAX,
    };
    for (index, block) in blocks.iter().enumerate() {
        facts_tx
            .send(Arc::new(bitcoin_rs_storage::CommittedFacts {
                commit_id: u64::try_from(index).expect("index fits") + 1,
                blocks: vec![block.clone()],
            }))
            .expect("facts send");
    }
    let mut pending = None;
    for _ in 0..8 {
        if matches!(
            h.worker.reconcile_once(&mut pending).expect("reconcile"),
            ReconcileAction::CaughtUp
        ) {
            break;
        }
    }
    assert_eq!(
        h.watermarks().tx_lookup,
        Some(IndexWatermark {
            height: 2,
            hash: blocks[2].hash,
        }),
        "every facts block must reach the watermark despite the one-row batch limit"
    );
}

use bitcoin_rs_storage::{ColumnFamily, KvStore};

const SEGMENT_FAMILIES: [ColumnFamily; 6] = [
    ColumnFamily::TxDir,
    ColumnFamily::ScriptDict,
    ColumnFamily::ScriptPost,
    ColumnFamily::SpendDir,
    ColumnFamily::ScriptStats,
    ColumnFamily::Filters,
];

fn sealed_at(store: &RocksDbStore) -> Vec<crate::segment::SealedGen> {
    let snapshot = store.snapshot().expect("snapshot");
    crate::segment::sealed_generations(snapshot.as_ref(), IndexCapability::TxLookup)
        .expect("sealed generations")
}

fn generation_rows(store: &RocksDbStore, sealed_id: u64) -> Vec<(ColumnFamily, Vec<u8>, Vec<u8>)> {
    let snapshot = store.snapshot().expect("snapshot");
    let prefix = sealed_id.to_be_bytes();
    let mut rows = Vec::new();
    for cf in SEGMENT_FAMILIES {
        for item in snapshot.iter_prefix(cf, &prefix).expect("scan") {
            let (key, value) = item.expect("row");
            rows.push((cf, key, value));
        }
    }
    rows
}

type CreatedCoin = (Vec<u8>, u64, u32, bool);

#[derive(Default)]
struct CreatedCoinMap(HashMap<([u8; 32], u32), CreatedCoin>);

impl CreatedCoinMap {
    fn insert_block(&mut self, block: &bitcoin_rs_storage::CommittedBlock) {
        for tx in &block.txs {
            let coinbase = tx.inputs.is_empty();
            for output in &tx.outputs {
                self.0.insert(
                    (tx.txid, output.vout),
                    (output.script.to_vec(), output.value, block.height, coinbase),
                );
            }
        }
    }
}

impl crate::index::SpentCoins for CreatedCoinMap {
    fn spent_coin(&self, txid: &[u8; 32], vout: u32) -> Option<crate::index::SpentCoin<'_>> {
        self.0
            .get(&(*txid, vout))
            .map(
                |(script, value, height, coinbase)| crate::index::SpentCoin {
                    script,
                    value: *value,
                    height: *height,
                    coinbase: *coinbase,
                },
            )
    }
}

fn committed_chain(
    f: &ForkFixture,
    branch: &[(NodeId, Hash256)],
    first_height: u32,
    last_height: u32,
) -> Vec<bitcoin_rs_storage::CommittedBlock> {
    let bodies = f.bodies.bodies.lock();
    let mut created = CreatedCoinMap::default();
    let mut out = Vec::new();
    for height in 0..=last_height {
        let index = usize::try_from(height).expect("height fits usize");
        let hash = if height == 0 {
            f.genesis
        } else {
            branch[index - 1].1
        };
        let parent = match height {
            0 => Hash256::from_le_bytes(&[0_u8; 32]),
            1 => f.genesis,
            _ => branch[index - 2].1,
        };
        let body = bodies
            .get(&(height, hash.to_le_bytes()))
            .expect("fixture body");
        let image = crate::index::parse_body(body).expect("fixture body parses");
        let block = {
            let facts = crate::index::BodyFacts {
                height,
                needs_scripts: true,
                spent_coins: &created,
            };
            crate::index::committed_block_from_image(
                &image,
                hash.to_le_bytes(),
                parent.to_le_bytes(),
                &facts,
            )
            .expect("committed block")
        };
        let parsed: bitcoin::Block = match bitcoin::consensus::encode::deserialize(body) {
            Ok(block) => block,
            Err(_) => panic!("the fixture body must deserialize as a consensus block"),
        };
        assert_eq!(
            block.txs.len(),
            parsed.txdata.len(),
            "the image parse and the consensus decode agree on the tx count"
        );
        for (tx, parsed_tx) in block.txs.iter().zip(&parsed.txdata) {
            assert_eq!(
                tx.txid,
                parsed_tx.compute_txid().to_byte_array(),
                "the txid matches the consensus crate"
            );
        }
        created.insert_block(&block);
        if height >= first_height {
            out.push(block);
        }
    }
    out
}

fn assert_sealed_matches_bulk(store: &RocksDbStore, f: &ForkFixture, branch: &[(NodeId, Hash256)]) {
    let sealed = sealed_at(store);
    assert_eq!(
        sealed.len(),
        1,
        "one tail-bound seal publishes one generation"
    );
    let segment = sealed[0];
    let blocks = committed_chain(
        f,
        branch,
        segment.coverage.first_height,
        segment.coverage.last_height,
    );
    let bulk_dir = tempfile::tempdir().expect("bulk dir");
    let scratch = tempfile::tempdir().expect("bulk scratch");
    let bulk_store = RocksDbStore::open(bulk_dir.path()).expect("bulk store");
    let builder = crate::segment::bulk_builder::BulkSegmentBuilder::new(
        Arc::new(bitcoin_rs_storage::budget::UnboundedBudget),
        None,
        scratch.path().to_path_buf(),
    )
    .without_filter();
    let bulk_builder_coverage = builder
        .build_and_ingest(&bulk_store, segment.gen_id, &blocks)
        .expect("bulk build");
    assert_eq!(
        bulk_builder_coverage, segment.coverage,
        "bulk coverage matches the sealed segment"
    );
    let sealed_rows = generation_rows(store, segment.gen_id);
    let bulk_rows = generation_rows(&bulk_store, segment.gen_id);
    let per_family = |rows: &[(ColumnFamily, Vec<u8>, Vec<u8>)]| {
        SEGMENT_FAMILIES
            .iter()
            .map(|cf| rows.iter().filter(|row| row.0 == *cf).count())
            .collect::<Vec<_>>()
    };
    let posting_items = |rows: &[(ColumnFamily, Vec<u8>, Vec<u8>)]| {
        rows.iter()
            .filter(|row| row.0 == ColumnFamily::ScriptPost)
            .map(|row| {
                crate::segment::format::decode_posting_items(&row.2).map_or(0, |items| items.len())
            })
            .sum::<usize>()
    };
    assert_eq!(
        posting_items(&sealed_rows),
        posting_items(&bulk_rows),
        "posting items"
    );
    assert_eq!(
        per_family(&sealed_rows),
        per_family(&bulk_rows),
        "per-family row counts"
    );
    if let Some(index) = sealed_rows
        .iter()
        .zip(bulk_rows.iter())
        .position(|(a, b)| a != b)
    {
        let (sealed_cf, sealed_key, sealed_value) = &sealed_rows[index];
        let (bulk_cf, bulk_key, bulk_value) = &bulk_rows[index];
        panic!(
            "first differing sealed row {index}: sealed {sealed_cf:?} {sealed_key:?} ({} bytes) != bulk {bulk_cf:?} {bulk_key:?} ({} bytes)",
            sealed_value.len(),
            bulk_value.len()
        );
    }
}

// PRJ-05
#[test]
fn sync_past_the_tail_bound_seals_one_generation_equal_to_bulk() {
    let f = ForkFixture::new(2100);
    f.persist_undo();
    let h = Harness::new(&f, u32::MAX);
    let mut pending = None;
    let tip = f.tip(f.a[2099]);
    h.set_tip(&tip);
    h.settle(&mut pending);
    h.assert_at(&tip);
    assert_sealed_matches_bulk(&h.store, &f, &f.a);
}

// REO-04
#[test]
fn deep_reorg_through_the_runtime_retires_exactly_the_affected_generation() {
    let f = ForkFixture::new(2100);
    f.persist_undo();
    let h = Harness::new(&f, u32::MAX);
    let mut pending = None;
    let a = f.tip(f.a[2099]);
    h.set_tip(&a);
    h.settle(&mut pending);
    h.assert_at(&a);
    let affected = sealed_at(&h.store);
    assert_eq!(affected.len(), 1, "the sync seals one generation");
    let affected_id = affected[0].gen_id;
    assert!(!generation_rows(&h.store, affected_id).is_empty());

    let b = f.tip(f.b[2099]);
    h.set_tip(&b);
    h.settle(&mut pending);
    h.assert_at(&b);
    assert!(
        sealed_at(&h.store)
            .iter()
            .all(|segment| segment.gen_id != affected_id),
        "the affected generation leaves the published set"
    );
    let left: Vec<ColumnFamily> = generation_rows(&h.store, affected_id)
        .iter()
        .map(|(cf, _, _)| *cf)
        .collect();
    assert!(left.is_empty(), "affected rows left in {left:?}");
    assert_answers_match_bulk(&h.store, &f, &f.b, 1, 2100);
}

// RCV-04
#[test]
fn crash_between_seal_steps_recovers_on_reopen() -> Result<(), RecoveryTestError> {
    use crate::segment::{SealFault, arm_seal_fault};
    let f = ForkFixture::new(2100);
    f.persist_undo();
    let h = Harness::new(&f, u32::MAX);
    let mut pending = None;
    let tip = f.tip(f.a[2099]);
    h.set_tip(&tip);
    arm_seal_fault(Some(SealFault::AfterCommitted));
    let mut failed = false;
    for _ in 0..64 {
        match h.worker.reconcile_once(&mut pending) {
            Ok(ReconcileAction::CaughtUp) => break,
            Ok(_) => {}
            Err(DerivedIndexWorkerError::Index(crate::IndexError::InjectedFault {
                stage: "seal",
            })) => {
                failed = true;
                break;
            }
            Err(other) => {
                panic!("the seal fault must surface as the injected seal fault, got {other:?}")
            }
        }
    }
    arm_seal_fault(None);
    assert!(failed, "the injected seal fault must surface");
    let Harness {
        _index_dir: index_dir,
        store,
        writer,
        worker,
        ..
    } = h;
    drop(worker);
    drop(writer);
    drop(store);
    let store = Arc::new(RocksDbStore::open(index_dir.path())?);
    let h = Harness::on_store(
        &f,
        u32::MAX,
        IndexCapabilities::HISTORICAL,
        index_dir,
        store,
    );
    h.set_tip(&tip);
    let mut pending = None;
    h.settle(&mut pending);
    h.assert_at(&tip);
    assert_eq!(
        sealed_at(&h.store).len(),
        1,
        "recovery publishes one generation"
    );
    assert_sealed_matches_bulk(&h.store, &f, &f.a);
    Ok(())
}

type TxAnswer = (Vec<(u32, TxPosition)>, Vec<Vec<(Vec<u8>, Vec<u8>)>>);

struct BulkOracle {
    _dirs: (tempfile::TempDir, tempfile::TempDir),
    store: RocksDbStore,
}

fn bulk_oracle(blocks: &[bitcoin_rs_storage::CommittedBlock]) -> BulkOracle {
    let bulk_dir = tempfile::tempdir().expect("bulk dir");
    let scratch = tempfile::tempdir().expect("bulk scratch");
    let store = RocksDbStore::open(bulk_dir.path()).expect("bulk store");
    let builder = crate::segment::bulk_builder::BulkSegmentBuilder::new(
        Arc::new(bitcoin_rs_storage::budget::UnboundedBudget),
        None,
        scratch.path().to_path_buf(),
    );
    let coverage = builder
        .build_and_ingest(&store, 1, blocks)
        .expect("bulk build");
    let next_ordinal: usize = blocks.iter().map(|block| block.txs.len()).sum();
    crate::segment::publish_sealed(
        &store,
        1,
        coverage,
        u32::try_from(next_ordinal).expect("ordinal count"),
        IndexCapabilities::HISTORICAL,
    )
    .expect("publish bulk generation");
    BulkOracle {
        _dirs: (bulk_dir, scratch),
        store,
    }
}

fn winner_answers(
    view: &crate::segment::SegmentSnapshot<'_>,
    blocks: &[bitcoin_rs_storage::CommittedBlock],
) -> Vec<TxAnswer> {
    let mut answers = Vec::new();
    let mut histories = std::collections::HashMap::new();
    for block in blocks {
        for tx in &block.txs {
            let txid = bitcoin_rs_consensus::primitives::Txid(Hash256::from_le_bytes(&tx.txid));
            let positions = view.tx_answer_for_test(&txid).expect("tx answer");
            let outputs = tx
                .outputs
                .iter()
                .map(|output| {
                    let hash = ScriptHash::from_script_bytes(&output.script);
                    histories
                        .entry(hash.to_byte_array())
                        .or_insert_with(|| {
                            view.history_answer_for_test(hash).expect("history answer")
                        })
                        .clone()
                })
                .collect();
            answers.push((positions, outputs));
        }
    }
    answers
}

fn audited_height(height: u32, cut: u32, rewound_from: u32) -> bool {
    height.is_multiple_of(500)
        || height.abs_diff(cut) <= 1
        || height.saturating_add(2) >= rewound_from
}

fn assert_answers_match_bulk(
    live: &RocksDbStore,
    f: &ForkFixture,
    winner: &[(NodeId, Hash256)],
    rewound_from: u32,
    tip: u32,
) {
    let cut = tip - crate::segment::format::REORG_WINDOW_BLOCKS;
    let blocks = committed_chain(f, winner, 0, tip);
    let oracle = bulk_oracle(&blocks);
    let audited: Vec<bitcoin_rs_storage::CommittedBlock> = blocks
        .iter()
        .filter(|block| audited_height(block.height, cut, rewound_from))
        .cloned()
        .collect();
    let bulk_view =
        crate::segment::SegmentSnapshot::open(oracle.store.snapshot().expect("bulk snapshot"))
            .expect("bulk view");
    let live_view = crate::segment::SegmentSnapshot::open(live.snapshot().expect("live snapshot"))
        .expect("live view");
    let live_answers = winner_answers(&live_view, &audited);
    let bulk_answers = winner_answers(&bulk_view, &audited);
    assert_eq!(
        live_answers, bulk_answers,
        "winning chain answers equal the bulk build over the same blocks"
    );
    let rewound = committed_chain(f, &f.a, rewound_from, tip);
    let rewound_live = winner_answers(&live_view, &rewound);
    assert_eq!(
        rewound_live,
        winner_answers(&bulk_view, &rewound),
        "rewound blocks answer as the bulk build does"
    );
    assert!(
        rewound_live
            .iter()
            .all(|(positions, _)| positions.is_empty()),
        "rewound transactions leave no tx lookup answer"
    );
}

// PRJ-05, REO-04
#[test]
fn shallow_reorg_after_seal_keeps_the_segment_and_rewinds_the_tail() {
    const TIP: u32 = 2100;
    const FORK: u32 = 2098;
    let f = ForkFixture::new(TIP);
    f.persist_undo();
    let winner = f.fork_from_a(FORK, TIP);
    f.persist_branch_undo(&winner);
    let h = Harness::new(&f, u32::MAX);
    let mut pending = None;
    let first = f.tip(f.a[usize::try_from(TIP - 1).expect("index")]);
    h.set_tip(&first);
    h.settle(&mut pending);
    h.assert_at(&first);
    let sealed = sealed_at(&h.store);
    assert_eq!(sealed.len(), 1, "the sync seals one stable prefix");
    let segment = sealed[0];
    assert_eq!(segment.coverage.first_height, 0);
    assert!(
        segment.coverage.last_height < FORK,
        "the fork lies above the sealed coverage"
    );
    let sealed_rows = generation_rows(&h.store, segment.gen_id);

    let reorged = f.tip(winner[usize::try_from(TIP - 1).expect("index")]);
    h.set_tip(&reorged);
    h.settle(&mut pending);
    h.assert_at(&reorged);
    assert_eq!(
        sealed_at(&h.store),
        sealed,
        "the sealed segment stays published"
    );
    assert_eq!(
        generation_rows(&h.store, segment.gen_id),
        sealed_rows,
        "sealed rows are untouched by the shallow reorg"
    );
    assert_answers_match_bulk(&h.store, &f, &winner, FORK + 1, TIP);
}

// PRJ-05, REO-04
#[test]
fn reorg_past_the_retained_tail_retires_the_newest_segment_and_matches_bulk() {
    const TIP: u32 = crate::segment::format::TAIL_MAX_BLOCKS;
    const FORK: u32 =
        crate::segment::format::TAIL_MAX_BLOCKS - crate::segment::format::REORG_WINDOW_BLOCKS - 2;
    let f = ForkFixture::new(TIP);
    f.persist_undo();
    let winner = f.fork_from_a(FORK, TIP);
    f.persist_branch_undo(&winner);
    let h = Harness::new(&f, u32::MAX);
    let mut pending = None;
    let first = f.tip(f.a[usize::try_from(TIP - 1).expect("index")]);
    h.set_tip(&first);
    h.settle(&mut pending);
    h.assert_at(&first);
    let sealed = sealed_at(&h.store);
    assert_eq!(sealed.len(), 1, "the sync seals one stable prefix");
    let retired = sealed[0].gen_id;
    assert!(
        sealed[0].coverage.last_height > FORK,
        "the fork lands inside the newest sealed segment"
    );

    let reorged = f.tip(winner[usize::try_from(TIP - 1).expect("index")]);
    h.set_tip(&reorged);
    h.settle(&mut pending);
    h.assert_at(&reorged);
    assert!(
        sealed_at(&h.store)
            .iter()
            .all(|segment| segment.gen_id != retired),
        "the newest segment leaves the published set"
    );
    assert!(
        generation_rows(&h.store, retired).is_empty(),
        "retired rows are gone"
    );
    assert_answers_match_bulk(&h.store, &f, &winner, FORK + 1, TIP);
}
