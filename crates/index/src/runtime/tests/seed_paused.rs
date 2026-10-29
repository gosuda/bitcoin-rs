//! Paused-write, poison, lease, and demand proofs for the immutable snapshot
//! `ScriptLive` seed.
//!
//! Contract: `.outline/requirements/immutable-snapshot-scriptlive-seed.md`
//! section 8, rows 1, 2, 3, 4, 6, 7, 15. This module is the S3 seed harness
//! (`crates/index/src/runtime/tests/seed_paused.rs`). It needs the S2 worker
//! dispatch (`Worker.seed_slot` / `Worker.seed_bundle`, the
//! `script_live_failure` seam) and is registered by the `P1WorkerSeed` owner;
//! the parent gates the union after S2 lands.
//!
//! Every test below drives the actual `Worker` and real stores (fjall,
//! `BlockTree`, the real pruning registry, real sealed snapshot bytes).
//! Nothing here mocks the seed codec or the cell: witnesses come only from
//! `write_snapshot_witnessed` / `read_snapshot_strict_v4_witnessed`, demand
//! lives in a real `SeedSlot`, and leases come from a real
//! `RetentionRegistry`.

use super::super::*;

use bitcoin::hashes::Hash as _;
use bitcoin::{
    Block, BlockHash, ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode, TxOut, Witness,
    block::{Header as BlockHeader, Version},
    pow::CompactTarget,
    script::Builder,
};
use bitcoin_rs_chain::{BlockTree, NodeId, NodeStatus, TipSnapshot};
use bitcoin_rs_primitives::{Amount, Hash256, OutPoint};
use bitcoin_rs_storage::block_body::BlockBodyStore;
use bitcoin_rs_storage::pruning::{
    HistoryAccess, HistoryUnavailable, RetentionBudget, RetentionRegistry,
};
use bitcoin_rs_storage::{
    ColumnFamily, FjallStore, InMemoryUndoStore, KvStore, PrefixScanLimit, StorageError,
};
use bitcoin_rs_utxo::contract::{BlockChanges, SpentOutputLookup, UtxoAdd, commit_block_changes};
use bitcoin_rs_utxo::{
    OfferOutcome, SeedOfferCell, SeedSlot, UtxoSet, VerifiedSnapshotArtifact,
    read_snapshot_strict_v4_witnessed, write_snapshot_witnessed,
};
use parking_lot::{Mutex, RwLock};
use std::io::{Seek, Write};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{Receiver, Sender};
use std::time::Duration;

use crate::writer::{PortableImportProduce, ScriptLiveSeedProduce};
use crate::{
    IndexCapabilities, IndexError, IndexWatermark, IndexWatermarks, IndexWriteFence, PreparedBatch,
    PreparedBlock,
};

/// Distinct txid space for synthetic seed coins; never collides with the
/// fixture chain's computed bitcoin txids.
fn synthetic_txid(seed: u64) -> Hash256 {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    bytes[8..16].copy_from_slice(&seed.rotate_left(23).to_le_bytes());
    bytes[16..24].copy_from_slice(&seed.wrapping_mul(0x94d0_49bb_1331_11eb).to_le_bytes());
    bytes[24..32].copy_from_slice(&seed.wrapping_add(0x0123_4567_89ab_cdef).to_le_bytes());
    Hash256::from_le_bytes(&bytes)
}

/// Builds `n` synthetic live coins plus the exact `(outpoint, script)` list
/// the seed stream must replay.
fn seed_coin_set(n: u64) -> (UtxoSet, Vec<(OutPoint, Vec<u8>)>) {
    let set = UtxoSet::new();
    let mut changes = BlockChanges::default();
    let mut coins = Vec::new();
    for i in 0..n {
        let txid = synthetic_txid(1_000_000 + i);
        let script = vec![0x51, u8::try_from(i % 251).expect("script byte")];
        let outpoint = OutPoint::new(txid.into(), 0);
        changes.add(UtxoAdd::new(
            outpoint,
            bitcoin_rs_primitives::TxOut {
                value: Amount::from_sat(1_000 + i),
                script_pubkey: script.clone().into(),
            },
            false,
            2,
        ));
        coins.push((outpoint, script));
    }
    commit_block_changes(&set, &changes, &synthetic_txid(999)).expect("commit seed coins");
    (set, coins)
}

/// Mints a real sealed artifact: witnessed encode, witnessed strict decode of
/// the same bytes, then seals the same descriptor the decode consumed.
fn mint_seed_artifact(
    set: &UtxoSet,
    tip: Hash256,
    height: u32,
) -> (VerifiedSnapshotArtifact, bitcoin_rs_utxo::V4Witness) {
    let mut bytes = Vec::new();
    let (_, (), witness) =
        write_snapshot_witnessed(set, &tip, height, &mut bytes, ()).expect("witnessed encode");
    let witness = witness.expect("valid encode mints a witness");
    let mut file = tempfile::tempfile().expect("artifact file");
    file.write_all(&bytes).expect("write artifact bytes");
    file.rewind().expect("rewind artifact");
    let (_, (), read_witness) =
        read_snapshot_strict_v4_witnessed(&mut file, ()).expect("witnessed decode");
    assert_eq!(
        read_witness.sha256(),
        witness.sha256(),
        "decode binds the same bytes"
    );
    let artifact = VerifiedSnapshotArtifact::seal(
        file,
        read_witness,
        bitcoin_rs_utxo::SeedProvenance::AssumeUtxoArchive {
            base: tip.to_le_bytes(),
        },
    );
    assert_eq!(artifact.tip(), (height, tip));
    (artifact, witness)
}

/// Exact expected `ScriptLive` row keys for `(outpoint, script)` coins.
fn expected_live_keys(coins: &[(OutPoint, Vec<u8>)]) -> Vec<Vec<u8>> {
    let mut keys: Vec<Vec<u8>> = coins
        .iter()
        .map(|(outpoint, script)| {
            crate::types::ScriptLiveRow::new(ScriptHash::from_script_bytes(script), outpoint)
                .as_bytes()
                .to_vec()
        })
        .collect();
    keys.sort();
    keys
}

/// Every durable `ScriptLive` row key in the store, in key order.
fn scan_live_keys(store: &FjallStore) -> Vec<Vec<u8>> {
    let scan = store
        .scan_prefix_bounded(
            ColumnFamily::ScriptLive,
            &[],
            PrefixScanLimit {
                max_rows: 8_000_000,
                max_bytes: usize::MAX,
            },
        )
        .expect("scan live rows");
    assert!(scan.complete, "live scan fits the test budget");
    let mut keys: Vec<Vec<u8>> = scan.rows.into_iter().map(|(key, _)| key).collect();
    keys.sort();
    keys
}

/// One-shot gate parked inside the writer: after the 4,097th emitted coin
/// (the first intermediate commit is durable) it signals the test and holds
/// the stream open until released. The test commits into a real authoritative
/// set while held. The seed path takes no UTXO locks at all; the old
/// `seed_live_from_utxo` held the stable view across DB writes and would
/// block that commit until the stream drained.
struct GatedSeedGate {
    started: Option<Sender<()>>,
    release: Receiver<()>,
}

/// Test-only writer wrapper: pure delegation except a gated
/// `seed_script_live_stream`. Never a mock: every byte still flows through
/// the real writer over the real store.
struct GatedWriter {
    inner: Arc<dyn TxIndexWriter>,
    gate: Arc<Mutex<Option<GatedSeedGate>>>,
}

/// Releases the held seed stream even when the test unwinds, so a failing
/// assertion can never hang the worker thread on the gate.
struct ReleaseOnDrop(Option<Sender<()>>);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        if let Some(tx) = self.0.take() {
            let _ = tx.send(());
        }
    }
}

impl TxIndexWriter for GatedWriter {
    fn fenced_watermarks(&self) -> Result<(IndexWriteFence, IndexWatermarks), IndexError> {
        self.inner.fenced_watermarks()
    }

    fn prepare_block_with_spent_scripts(
        &self,
        capabilities: IndexCapabilities,
        height: u32,
        hash: [u8; 32],
        body: &[u8],
        spent_scripts: &dyn crate::SpentCoinScripts,
    ) -> Result<PreparedBlock, IndexError> {
        self.inner
            .prepare_block_with_spent_scripts(capabilities, height, hash, body, spent_scripts)
    }

    fn seed_script_live_stream(
        &self,
        produce: &mut ScriptLiveSeedProduce<'_>,
        tip: IndexWatermark,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<usize, IndexError> {
        let gate = self.gate.lock().take();
        match gate {
            None => self.inner.seed_script_live_stream(produce, tip, cancelled),
            Some(mut gate) => {
                let mut emitted = 0usize;
                self.inner.seed_script_live_stream(
                    &mut |emit: &mut dyn FnMut(OutPoint, ScriptHash) -> Result<(), IndexError>| {
                        let mut counting = |outpoint: OutPoint, hash: ScriptHash| {
                            emitted += 1;
                            if emitted == 4_097 {
                                if let Some(tx) = gate.started.take() {
                                    let _ = tx.send(());
                                }
                                let _ = gate.release.recv_timeout(Duration::from_secs(60));
                            }
                            emit(outpoint, hash)
                        };
                        produce(&mut counting)
                    },
                    tip,
                    cancelled,
                )
            }
        }
    }

    fn import_tx_lookup_stream(
        &self,
        produce: &mut PortableImportProduce<'_>,
        base: IndexWatermark,
        floor: u32,
    ) -> Result<usize, IndexError> {
        self.inner.import_tx_lookup_stream(produce, base, floor)
    }

    fn commit_forward_with_cursor(
        &self,
        fence: IndexWriteFence,
        batch: PreparedBatch,
        cursor: crate::ConsumerCursorUpdate<'_>,
    ) -> Result<IndexWatermark, IndexError> {
        self.inner.commit_forward_with_cursor(fence, batch, cursor)
    }

    fn commit_rollback_one_for_with_cursor_with_spent_scripts(
        &self,
        fence: IndexWriteFence,
        capabilities: IndexCapabilities,
        prev: Option<IndexWatermark>,
        body: &[u8],
        cursor: crate::ConsumerCursorUpdate<'_>,
        spent_scripts: &dyn crate::SpentCoinScripts,
    ) -> Result<(), IndexError> {
        self.inner
            .commit_rollback_one_for_with_cursor_with_spent_scripts(
                fence,
                capabilities,
                prev,
                body,
                cursor,
                spent_scripts,
            )
    }

    fn reset_capabilities(&self, capabilities: IndexCapabilities) -> Result<(), IndexError> {
        self.inner.reset_capabilities(capabilities)
    }

    fn reset_interrupted_script_live_seed(&self) -> Result<bool, IndexError> {
        self.inner.reset_interrupted_script_live_seed()
    }

    fn anchor_watermark(
        &self,
        capabilities: IndexCapabilities,
        watermark: IndexWatermark,
        floor: u32,
    ) -> Result<(), IndexError> {
        self.inner.anchor_watermark(capabilities, watermark, floor)
    }

    fn consumer_cursor(&self) -> Result<Option<Vec<u8>>, IndexError> {
        self.inner.consumer_cursor()
    }

    fn commit_consumer_cursor(
        &self,
        fence: IndexWriteFence,
        cursor: &[u8],
    ) -> Result<(), IndexError> {
        self.inner.commit_consumer_cursor(fence, cursor)
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
            value: bitcoin::Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
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

fn tree_header(block: &Block) -> bitcoin_rs_primitives::Header {
    bitcoin_rs_primitives::deserialize::<bitcoin_rs_primitives::Header>(
        &bitcoin::consensus::encode::serialize(&block.header),
    )
    .expect("80-byte header")
}

type BodyMap = hashbrown::HashMap<(u32, [u8; 32]), Vec<u8>>;

struct SeedBodyStore {
    bodies: Mutex<BodyMap>,
    undo: Mutex<BodyMap>,
}

impl BlockBodyStore for SeedBodyStore {
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

    fn undo_record(&self, height: u32, hash: Hash256) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.undo.lock().get(&(height, hash.to_le_bytes())).cloned())
    }

    fn sync(&self) -> Result<(), StorageError> {
        Ok(())
    }
}

#[derive(Default)]
struct SeedBranchCoins(Vec<bitcoin_rs_utxo::UtxoCoin>);

impl SpentOutputLookup for SeedBranchCoins {
    fn entry(
        &self,
        outpoint: &bitcoin_rs_primitives::OutPoint,
    ) -> Option<&bitcoin_rs_utxo::UtxoCoin> {
        self.0.iter().find(|coin| coin.outpoint == *outpoint)
    }
}

impl SeedBranchCoins {
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

/// Two rival branches over one shared genesis; every body is present.
struct SeedFixture {
    tree: Arc<RwLock<BlockTree>>,
    bodies: Arc<SeedBodyStore>,
    genesis: Hash256,
    a: Vec<(NodeId, Hash256)>,
    b: Vec<(NodeId, Hash256)>,
}

impl SeedFixture {
    fn new(len: u32) -> Self {
        let mut tree = BlockTree::new();
        let mut bodies = BodyMap::new();
        let (genesis, genesis_hash) = mine_block(Hash256::from_le_bytes(&[0_u8; 32]), 0, 0);
        tree.insert_header(tree_header(&genesis), NodeStatus::HeaderValid)
            .expect("genesis");
        bodies.insert(
            (0, genesis_hash.to_le_bytes()),
            bitcoin::consensus::encode::serialize(&genesis),
        );
        let mut branch = |extra: i64| {
            let mut prev = genesis_hash;
            let mut ids = Vec::new();
            for height in 1..=len {
                let (block, hash) = mine_block(prev, height, extra);
                let id = tree
                    .insert_header(tree_header(&block), NodeStatus::HeaderValid)
                    .expect("branch header");
                bodies.insert(
                    (height, hash.to_le_bytes()),
                    bitcoin::consensus::encode::serialize(&block),
                );
                ids.push((id, hash));
                prev = hash;
            }
            ids
        };
        let a = branch(0);
        let b = branch(1);
        Self {
            tree: Arc::new(RwLock::new(tree)),
            bodies: Arc::new(SeedBodyStore {
                bodies: Mutex::new(bodies),
                undo: Mutex::default(),
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

    fn body(&self, height: u32, hash: Hash256) -> Vec<u8> {
        self.bodies
            .bodies
            .lock()
            .get(&(height, hash.to_le_bytes()))
            .expect("fixture body")
            .clone()
    }

    /// Persists undo records for every non-genesis block of branch A.
    fn persist_branch_a_undo(&self) {
        self.persist_branch_undo(&self.a.clone());
    }

    /// Persists undo records for every non-genesis block of branch B.
    fn persist_branch_b_undo(&self) {
        self.persist_branch_undo(&self.b.clone());
    }

    fn persist_branch_undo(&self, branch: &[(NodeId, Hash256)]) {
        let store = InMemoryUndoStore::default();
        let mut coins = SeedBranchCoins::default();
        let tip_height = u32::try_from(branch.len()).expect("branch length");
        for height in 0..=tip_height {
            let key = if height == 0 {
                (0, self.genesis.to_le_bytes())
            } else {
                let index = usize::try_from(height - 1).expect("height index");
                (height, branch[index].1.to_le_bytes())
            };
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
                    .lock()
                    .insert(key, record.as_bytes().to_vec());
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

/// Worker harness with a real seed cell: the worker takes, wants, and rests
/// through `seed_slot`; the bundle and lease stay worker-private.
struct SeedHarness {
    _index_dir: tempfile::TempDir,
    store: Arc<FjallStore>,
    writer: Arc<dyn TxIndexWriter>,
    applied_tip: Arc<arc_swap::ArcSwapOption<TipSnapshot>>,
    runtime: Arc<DerivedIndexRuntime>,
    retention: Arc<RetentionRegistry>,
    cell: SeedOfferCell,
    utxo_set: Arc<UtxoSet>,
    gate: Arc<Mutex<Option<GatedSeedGate>>>,
    worker: Worker,
}

impl SeedHarness {
    /// Builds a harness over `source`: the authoritative set the seed
    /// artifact was minted from. Concurrent applies in the paused-seed proof
    /// commit into this same set, so the proof exercises the real
    /// source-state concurrency instead of an unrelated empty set.
    fn new(fixture: &SeedFixture, enabled: IndexCapabilities, source: Arc<UtxoSet>) -> Self {
        let index_dir = tempfile::tempdir().expect("index dir");
        let store = Arc::new(FjallStore::open(index_dir.path()).expect("fjall open"));
        let inner: Arc<dyn TxIndexWriter> = Arc::new(RwLock::new(
            crate::IndexWriter::open(Arc::clone(&store), 1).expect("index writer open"),
        ));
        let gate = Arc::new(Mutex::new(None));
        let writer: Arc<dyn TxIndexWriter> = Arc::new(GatedWriter {
            inner,
            gate: Arc::clone(&gate),
        });
        let applied_tip = Arc::new(arc_swap::ArcSwapOption::empty());
        let (wake_tx, wake_rx) = crossbeam_channel::bounded(16);
        let runtime = Arc::new(DerivedIndexRuntime::new(wake_tx));
        let reporter: Arc<dyn IndexAheadSink> = RecordedIndexAhead::new();
        let body_store: Arc<dyn BlockBodyStore> = fixture.bodies.clone();
        let retention = Arc::new(RetentionRegistry::new());
        let cell: SeedOfferCell = Arc::new(SeedSlot::new());
        let utxo_set = source;
        let worker = Worker {
            runtime: Arc::clone(&runtime),
            writer: Arc::clone(&writer),
            applied_tip: bitcoin_rs_chain::TipReader::new(Arc::clone(&applied_tip)),
            block_tree: bitcoin_rs_chain::BlockTreeReader::new(Arc::clone(&fixture.tree)),
            body_store: Some(body_store),
            history: HistoryAccess::new(Arc::clone(&retention), RetentionBudget::Depth(288)),
            batch_limits: DEFAULT_BATCH_LIMITS,
            enabled,
            chain_events: Arc::new(TestChainCursor),
            reporter,
            wake_rx,
            quiet_period: Duration::ZERO,
            batch_delay: Duration::ZERO,
            rollback_rebuild_cutover: u32::MAX,
            seed_slot: Some(cell.clone()),
            seed_bundle: Mutex::new(None),
        };
        Self {
            _index_dir: index_dir,
            store,
            writer,
            applied_tip,
            runtime,
            retention,
            cell,
            utxo_set,
            gate,
            worker,
        }
    }

    /// Arms the one-shot stream hold for the next seed: after the 4,097th
    /// emitted coin the worker signals `started` and waits for `release`.
    fn arm_seed_gate(&self, started: Sender<()>, release: Receiver<()>) {
        *self.gate.lock() = Some(GatedSeedGate {
            started: Some(started),
            release,
        });
    }

    fn set_tip(&self, tip: &Arc<TipSnapshot>) {
        self.applied_tip.store(Some(Arc::clone(tip)));
    }

    fn watermarks(&self) -> IndexWatermarks {
        self.writer.fenced_watermarks().expect("watermarks").1
    }

    /// Runs passes until `CaughtUp`, asserting the worker never errors, never
    /// publishes global failure, and never holds more than one history pin.
    fn settle(&self, pending: &mut Option<PendingForward>) {
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

fn at(tip: &TipSnapshot) -> IndexWatermark {
    IndexWatermark {
        height: tip.height,
        hash: tip.hash.to_le_bytes(),
    }
}

/// Commits one `TX_LOOKUP` block as an ordinary forward write (an `apply`
/// analog): fresh fence, prepare, admit, commit.
fn commit_lookup_block(writer: &Arc<dyn TxIndexWriter>, height: u32, hash: [u8; 32], body: &[u8]) {
    let (fence, _) = writer.fenced_watermarks().expect("fence");
    let mut batch = PreparedBatch::new(DEFAULT_BATCH_LIMITS);
    let prepared = writer
        .prepare_block_with_spent_scripts(
            IndexCapabilities::TX_LOOKUP,
            height,
            hash,
            body,
            &crate::NoSpentScripts,
        )
        .expect("prepare lookup block");
    assert!(batch.try_push(prepared).is_ok(), "admit single block");
    writer
        .commit_forward_with_cursor(fence, batch, crate::ConsumerCursorUpdate::Keep)
        .expect("commit lookup block");
}

/// Net live coins of branch-A heights `through..=to` on top of `base`: every
/// block adds its coinbase and spend outputs and spends the previous
/// coinbase. All fixture scripts are `[0x51]`.
fn expected_chain_live(
    fixture: &SeedFixture,
    through: u32,
    to: u32,
    base: &[(OutPoint, Vec<u8>)],
) -> Vec<(OutPoint, Vec<u8>)> {
    use hashbrown::HashMap;
    let mut live: HashMap<([u8; 32], u32), Vec<u8>> = HashMap::new();
    for (outpoint, script) in base {
        live.insert((*outpoint.txid.as_bytes(), outpoint.vout), script.clone());
    }
    for height in through..=to {
        let key = fixture.a_key(height);
        let body = fixture.body(height, Hash256::from_le_bytes(&key.1));
        let block = bitcoin_rs_primitives::deserialize::<bitcoin_rs_primitives::Block>(&body)
            .expect("fixture block");
        let txids = block.txids();
        assert_eq!(txids.len(), 2, "fixture block shape");
        for txid in &txids {
            live.insert((*txid.as_bytes(), 0), vec![0x51]);
        }
        if height > 0 {
            let prev_key = fixture.a_key(height - 1);
            let prev_body = fixture.body(height - 1, Hash256::from_le_bytes(&prev_key.1));
            let prev_block =
                bitcoin_rs_primitives::deserialize::<bitcoin_rs_primitives::Block>(&prev_body)
                    .expect("prev fixture block");
            let prev_coinbase = prev_block.txids()[0];
            live.remove(&(*prev_coinbase.as_bytes(), 0));
        }
    }
    live.into_iter()
        .map(|((txid, vout), script)| {
            (
                OutPoint::new(
                    bitcoin_rs_primitives::Txid::from(Hash256::from_le_bytes(&txid)),
                    vout,
                ),
                script,
            )
        })
        .collect()
}

/// Row 1: a paused seed write permits concurrent applies and a retiring
/// publication, keeps the watermark `None`, then resumes to H and catches up
/// to T with rows equal to the post-hoc live set at T.
///
/// Phase A holds the seed for real: the gate fires after the 4,097th emit
/// (the first intermediate commit is durable) and the test commits into a
/// real authoritative set while held. The seed path takes no UTXO locks at
/// all; the old `seed_live_from_utxo` held the stable view across DB writes
/// and would block that commit until the stream drained. Phase B stops the
/// worker and lands ordinary applies plus a retiring publication while the
/// bundle is retained.
#[test]
#[expect(clippy::too_many_lines, reason = "Paused seed lifecycle proof")]
fn seed_paused_write_permits_apply_and_retires_generation() {
    let fixture = SeedFixture::new(4);
    fixture.persist_branch_a_undo();

    // Token at H = 2 over real sealed bytes; the worker must take it. The
    // harness runs over the same minted set, so the concurrent apply below
    // proves source-state concurrency instead of touching an empty set.
    let (source, coins) = seed_coin_set(20_000);
    let source = Arc::new(source);
    let harness = SeedHarness::new(
        &fixture,
        IndexCapabilities::TX_AND_SCRIPTS,
        Arc::clone(&source),
    );
    let tip_a2 = fixture.tip(fixture.a[1]);
    let (artifact, _) = mint_seed_artifact(&source, tip_a2.hash, tip_a2.height);
    harness.cell.want();
    assert_eq!(harness.cell.offer(artifact), OfferOutcome::Stored);

    harness.set_tip(&tip_a2);
    let (start_tx, start_rx) = std::sync::mpsc::channel();
    let (rel_tx, rel_rx) = std::sync::mpsc::channel();
    harness.arm_seed_gate(start_tx, rel_rx);
    let mut pending = None;
    std::thread::scope(|scope| {
        let pass = scope.spawn(|| harness.worker.reconcile_once(&mut pending));
        // Phase A: the gate holds the stream open after the first
        // intermediate commit landed rows without a watermark.
        assert!(
            start_rx.recv_timeout(Duration::from_secs(30)).is_ok(),
            "seed reached its first intermediate commit"
        );
        let hold = ReleaseOnDrop(Some(rel_tx));
        let mut changes = BlockChanges::default();
        let mut applied = Vec::new();
        for i in 0..3u64 {
            let txid = synthetic_txid(2_000_000 + i);
            let outpoint = OutPoint::new(txid.into(), 0);
            changes.add(UtxoAdd::new(
                outpoint,
                bitcoin_rs_primitives::TxOut {
                    value: Amount::from_sat(5_000 + i),
                    script_pubkey: vec![0x52].into(),
                },
                false,
                2,
            ));
            applied.push(outpoint);
        }
        commit_block_changes(&harness.utxo_set, &changes, &synthetic_txid(4242))
            .expect("concurrent apply while seed held");
        // The apply landed in the minted source set the seed streams from,
        // not an unrelated empty set: this is the concurrency under proof.
        assert!(Arc::ptr_eq(&harness.utxo_set, &source));
        for outpoint in &applied {
            assert!(
                harness.utxo_set.get(outpoint).is_some(),
                "concurrent coin is live in the source set"
            );
        }
        assert!(scan_live_keys(&harness.store).len() >= 4_096);
        assert!(!harness.runtime.should_stop());
        assert!(harness.runtime.failure_message().is_none());
        drop(hold);
        // Phase B: ordinary applies land while the seed is paused.
        harness.runtime.request_shutdown();
        match pass.join().expect("pass thread") {
            Ok(_) | Err(DerivedIndexWorkerError::Stopped) => {}
            Err(error) => panic!("unexpected pass error: {error:?}"),
        }
    });
    // The stop retained the bundle: no watermark, one pin, demand consumed.
    assert!(harness.cell.take().is_none(), "no second take");
    let (artifact_state, lease_floor) = {
        let guard = harness.worker.seed_bundle.lock();
        let bundle = guard.as_ref().expect("stopped seed keeps the bundle");
        (
            bundle
                .artifact
                .as_ref()
                .map(bitcoin_rs_utxo::VerifiedSnapshotArtifact::tip),
            bundle.lease.as_ref().expect("pin kept").floor(),
        )
    };
    assert_eq!(lease_floor, Some(tip_a2.height), "the pin still covers H");
    assert_eq!(harness.retention.active_leases(), 1);
    if harness.watermarks().script_live.is_none() {
        assert_eq!(
            artifact_state,
            Some((tip_a2.height, tip_a2.hash)),
            "paused mid-stream with the same bytes"
        );
    } else {
        assert_eq!(artifact_state, None, "seed committed as the stop landed");
        assert_eq!(harness.watermarks().script_live, Some(at(&tip_a2)));
    }
    assert!(harness.runtime.failure_message().is_none());

    for height in 0..=1u32 {
        let key = fixture.a_key(height);
        let body = fixture.body(height, Hash256::from_le_bytes(&key.1));
        commit_lookup_block(&harness.writer, height, key.1, &body);
    }
    // Retiring publication: the next height commits on the new fence.
    let retire = fixture.a_key(2);
    let retire_body = fixture.body(2, Hash256::from_le_bytes(&retire.1));
    commit_lookup_block(&harness.writer, 2, retire.1, &retire_body);
    if harness.watermarks().script_live.is_none() {
        assert_eq!(harness.watermarks().script_live, None);
    } else {
        assert_eq!(harness.watermarks().script_live, Some(at(&tip_a2)));
    }
    harness.runtime.shutdown.store(false, Ordering::Release);

    // Resume with the same bundle: no second take, one pin, converge at H.
    for _ in 0..64 {
        assert!(harness.cell.take().is_none(), "no second take");
        assert!(
            harness.retention.active_leases() <= 1,
            "single live history pin at every instant"
        );
        match harness.worker.reconcile_once(&mut pending).expect("resume") {
            ReconcileAction::CaughtUp => break,
            ReconcileAction::Progressed | ReconcileAction::Buffered => {}
            ReconcileAction::Stalled => panic!("resume stalled"),
        }
        assert!(harness.runtime.failure_message().is_none());
    }
    assert_eq!(harness.watermarks().script_live, Some(at(&tip_a2)));

    // Catch up H to T; rows equal the post-hoc live set at T.
    harness.set_tip(&fixture.tip(fixture.a[3]));
    harness.settle(&mut pending);
    let tip_a4 = fixture.tip(fixture.a[3]);
    assert_eq!(harness.watermarks().script_live, Some(at(&tip_a4)));
    assert_eq!(harness.watermarks().tx_lookup, Some(at(&tip_a4)));
    assert_eq!(harness.watermarks().script_history, Some(at(&tip_a4)));
    assert_eq!(harness.retention.active_leases(), 0);
    let expected = expected_live_keys(&expected_chain_live(&fixture, 3, 4, &coins));
    assert_eq!(scan_live_keys(&harness.store), expected);
}

/// Row 2: flipping one script byte, one txid byte, or truncating the file
/// each yields `Integrity` with no watermark; a swapped generation file
/// never pairs with the accepted witness; the poisoned bundle is dropped and
/// the remaining families still converge by replay.
#[test]
#[expect(clippy::too_many_lines, reason = "Artifact integrity matrix proof")]
fn seed_tamper_variants_yield_integrity_without_watermark() {
    let (set, _coins) = seed_coin_set(200);
    let tip_hash = synthetic_txid(77);
    let mut bytes = Vec::new();
    let (_, (), witness) =
        write_snapshot_witnessed(&set, &tip_hash, 9, &mut bytes, ()).expect("encode");
    let witness = witness.expect("valid encode mints a witness");

    // One script byte flipped: lengths, counts, tip, and trailer still parse.
    let mut script_flip = bytes.clone();
    let flip_at = script_flip.len() / 2;
    script_flip[flip_at] ^= 0x01;
    // One txid byte flipped.
    let mut txid_flip = bytes.clone();
    txid_flip[52] ^= 0x01;
    // Cut through the final record as well as the 384-byte trailer, so the
    // traversal cannot emit the complete coin set before detecting the loss.
    let truncated = bytes[..bytes.len() - 400].to_vec();
    let original_bytes = bytes.clone();

    for (index, corrupted) in [&script_flip, &txid_flip, &truncated]
        .into_iter()
        .enumerate()
    {
        let mut file = tempfile::tempfile().expect("artifact file");
        file.write_all(corrupted).expect("write corrupted");
        file.rewind().expect("rewind");
        let mut artifact = VerifiedSnapshotArtifact::seal(
            file,
            witness,
            bitcoin_rs_utxo::SeedProvenance::AssumeUtxoArchive {
                base: tip_hash.to_le_bytes(),
            },
        );
        let mut emitted = 0usize;
        let result = artifact.for_each_coin_raw(
            &mut |_: &OutPoint, _: &[u8]| {
                emitted += 1;
                Ok::<(), StorageError>(())
            },
            &|| false,
        );
        assert!(
            matches!(result, Err(bitcoin_rs_utxo::RawSeedError::Integrity)),
            "tampered bytes never traverse"
        );
        if index == 2 {
            assert!(emitted < 200, "truncation stops the traversal early");
        }
    }

    // Swap between commit and open: the sealed descriptor still reads the
    // accepted bytes even after the path is replaced.
    let dir = tempfile::tempdir().expect("generation dir");
    let path = dir.path().join("utxo-v4.dat");
    std::fs::write(&path, &original_bytes).expect("stage generation");
    let read_file = std::fs::File::open(&path).expect("open generation");
    let mut read_clone = read_file;
    let (_, (), read_witness) =
        read_snapshot_strict_v4_witnessed(&mut read_clone, ()).expect("decode staged");
    let mut artifact = VerifiedSnapshotArtifact::seal(
        read_clone,
        read_witness,
        bitcoin_rs_utxo::SeedProvenance::AssumeUtxoArchive {
            base: tip_hash.to_le_bytes(),
        },
    );
    let swap = dir.path().join("swap.dat");
    std::fs::write(&swap, vec![0xff; original_bytes.len()]).expect("stage swap");
    std::fs::rename(&swap, &path).expect("swap generation");
    let mut count = 0usize;
    artifact
        .for_each_coin_raw(
            &mut |_: &OutPoint, _: &[u8]| {
                count += 1;
                Ok::<(), StorageError>(())
            },
            &|| false,
        )
        .expect("sealed descriptor pins the accepted bytes");
    assert_eq!(count, 200, "every accepted coin replays from the held fd");

    // Worker take of a swapped artifact: poison drops the bundle, mints no
    // watermark, and the remaining families still converge by replay.
    let fixture = SeedFixture::new(3);
    fixture.persist_branch_a_undo();
    let harness = SeedHarness::new(
        &fixture,
        IndexCapabilities::TX_AND_SCRIPTS,
        Arc::new(UtxoSet::new()),
    );
    let mut poisoned_file = tempfile::tempfile().expect("poison file");
    poisoned_file
        .write_all(&script_flip)
        .expect("write poisoned");
    poisoned_file.rewind().expect("rewind poisoned");
    let poisoned = VerifiedSnapshotArtifact::seal(
        poisoned_file,
        witness,
        bitcoin_rs_utxo::SeedProvenance::AssumeUtxoArchive {
            base: tip_hash.to_le_bytes(),
        },
    );
    harness.cell.want();
    assert_eq!(harness.cell.offer(poisoned), OfferOutcome::Stored);
    harness.set_tip(&fixture.tip(fixture.a[2]));
    let mut pending = None;
    let first = harness.worker.reconcile_once(&mut pending).expect("take");
    assert!(
        !matches!(first, ReconcileAction::CaughtUp),
        "poison never completes the pass"
    );
    assert!(
        harness.worker.seed_bundle.lock().is_none(),
        "poison drops the bundle"
    );
    assert_eq!(
        harness.watermarks().script_live,
        None,
        "poison mints no watermark"
    );
    assert!(
        harness.runtime.script_live_failure().is_none(),
        "poison is not terminal unavailable"
    );
    assert!(harness.runtime.failure_message().is_none());
    harness.settle(&mut pending);
    let tip = fixture.tip(fixture.a[2]);
    assert_eq!(harness.watermarks().tx_lookup, Some(at(&tip)));
    assert_eq!(harness.watermarks().script_history, Some(at(&tip)));
    assert_eq!(
        harness.watermarks().script_live,
        Some(at(&tip)),
        "replay reconverges after poison"
    );
}

/// Row 3: the digest comparison is load-bearing. A length-preserving single
/// script-byte flip passes every other binding check (length, tip, height,
/// record and output counts all still agree), so only the digest comparison
/// can refuse it; deleting that comparison must fail this test.
#[test]
fn seed_mutation_check_digest_removal_fails() {
    let (set, _) = seed_coin_set(64);
    let tip_hash = synthetic_txid(78);
    let mut bytes = Vec::new();
    let (_, (), witness) =
        write_snapshot_witnessed(&set, &tip_hash, 11, &mut bytes, ()).expect("encode");
    let witness = witness.expect("valid encode mints a witness");

    let mut flipped = bytes.clone();
    let midpoint = flipped.len() / 2;
    flipped[midpoint] ^= 0x01;
    // Every non-digest binding still agrees: same length, and the strict read
    // still accepts with identical counts.
    assert_eq!(
        u64::try_from(flipped.len()).expect("len"),
        witness.byte_len()
    );
    let mut cursor = flipped.as_slice();
    let (load, (), _) =
        read_snapshot_strict_v4_witnessed(&mut cursor, ()).expect("flipped still parses");
    assert_eq!(load.tip_hash, tip_hash);
    assert_eq!(load.height, 11);
    assert_eq!(
        u64::try_from(load.set.record_count()).expect("records"),
        witness.record_count()
    );
    assert_eq!(
        u64::try_from(load.set.len()).expect("outputs"),
        witness.output_count()
    );
    // Yet the sealed traversal refuses: the digest no longer matches.
    let mut file = tempfile::tempfile().expect("artifact file");
    file.write_all(&flipped).expect("write flipped");
    file.rewind().expect("rewind");
    let mut artifact = VerifiedSnapshotArtifact::seal(
        file,
        witness,
        bitcoin_rs_utxo::SeedProvenance::AssumeUtxoArchive {
            base: tip_hash.to_le_bytes(),
        },
    );
    let result =
        artifact.for_each_coin_raw(
            &mut |_: &OutPoint, _: &[u8]| Ok::<(), StorageError>(()),
            &|| false,
        );
    assert!(
        matches!(result, Err(bitcoin_rs_utxo::RawSeedError::Integrity)),
        "only the digest comparison refuses a length-preserving flip"
    );
}

/// Row 4: a stop while paused retains the bundle. The same bundle resumes
/// with no second take and one pin, and converges with exact rows.
#[test]
fn seed_stop_while_paused_retains_bundle() {
    let fixture = SeedFixture::new(4);
    fixture.persist_branch_a_undo();
    let harness = SeedHarness::new(
        &fixture,
        IndexCapabilities::TX_AND_SCRIPTS,
        Arc::new(UtxoSet::new()),
    );

    let (set, coins) = seed_coin_set(20_000);
    let tip_a2 = fixture.tip(fixture.a[1]);
    let (artifact, _) = mint_seed_artifact(&set, tip_a2.hash, tip_a2.height);
    harness.cell.want();
    assert_eq!(harness.cell.offer(artifact), OfferOutcome::Stored);

    harness.set_tip(&tip_a2);
    let (start_tx, start_rx) = std::sync::mpsc::channel();
    let (rel_tx, rel_rx) = std::sync::mpsc::channel();
    harness.arm_seed_gate(start_tx, rel_rx);
    let mut pending = None;
    let outcome = std::thread::scope(|scope| {
        let pass = scope.spawn(|| harness.worker.reconcile_once(&mut pending));
        assert!(
            start_rx.recv_timeout(Duration::from_secs(30)).is_ok(),
            "seed reached its first intermediate commit"
        );
        let hold = ReleaseOnDrop(Some(rel_tx));
        harness.runtime.request_shutdown();
        drop(hold);
        pass.join().expect("pass thread")
    });
    match outcome {
        Ok(_) | Err(DerivedIndexWorkerError::Stopped) => {}
        Err(error) => panic!("unexpected pass error: {error:?}"),
    }
    // The stop retained the bundle: same artifact tip, same pin, no take left.
    assert!(harness.cell.take().is_none(), "no second take");
    let (artifact_state, lease_floor) = {
        let guard = harness.worker.seed_bundle.lock();
        let bundle = guard.as_ref().expect("stopped seed keeps the bundle");
        (
            bundle
                .artifact
                .as_ref()
                .map(bitcoin_rs_utxo::VerifiedSnapshotArtifact::tip),
            bundle.lease.as_ref().expect("pin kept").floor(),
        )
    };
    assert_eq!(
        lease_floor,
        Some(tip_a2.height),
        "no second lease while the held pin covers H"
    );
    if harness.watermarks().script_live.is_none() {
        assert_eq!(
            artifact_state,
            Some((tip_a2.height, tip_a2.hash)),
            "same bundle, same bytes"
        );
    } else {
        assert_eq!(artifact_state, None, "seed committed as the stop landed");
        assert_eq!(harness.watermarks().script_live, Some(at(&tip_a2)));
    }
    assert_eq!(harness.retention.active_leases(), 1);
    assert!(harness.runtime.failure_message().is_none());

    // Resume with the same bundle and converge with exact rows.
    harness.runtime.shutdown.store(false, Ordering::Release);
    for _ in 0..64 {
        assert!(harness.cell.take().is_none(), "no second take");
        assert!(
            harness.retention.active_leases() <= 1,
            "single live history pin at every instant"
        );
        match harness.worker.reconcile_once(&mut pending).expect("resume") {
            ReconcileAction::CaughtUp => break,
            ReconcileAction::Progressed | ReconcileAction::Buffered => {}
            ReconcileAction::Stalled => panic!("resume stalled"),
        }
        assert!(harness.runtime.failure_message().is_none());
    }
    assert_eq!(harness.watermarks().script_live, Some(at(&tip_a2)));

    // Catch up H to T with the same bundle lineage and exact rows.
    harness.set_tip(&fixture.tip(fixture.a[3]));
    harness.settle(&mut pending);
    let tip_a4 = fixture.tip(fixture.a[3]);
    assert_eq!(harness.watermarks().script_live, Some(at(&tip_a4)));
    assert_eq!(harness.retention.active_leases(), 0);
    let expected = expected_live_keys(&expected_chain_live(&fixture, 3, 4, &coins));
    assert_eq!(scan_live_keys(&harness.store), expected);
}

/// Catch-up holds at most one live seed lease: a live pin above the selected
/// lower start is dropped once the lower grant lands (it pins a superset
/// while the committed seed watermark already covers that height), so one
/// pass leaves no parked seed lease behind and at most one live pin.
#[test]
fn catch_up_drops_subsumed_seed_lease_for_lower_start() {
    let fixture = SeedFixture::new(4);
    fixture.persist_branch_a_undo();
    let harness = SeedHarness::new(
        &fixture,
        IndexCapabilities::TX_AND_SCRIPTS,
        Arc::new(UtxoSet::new()),
    );
    // Plant a committed-seed-style bundle: artifact consumed, live pin at H.
    let tip_a2 = fixture.tip(fixture.a[1]);
    let seed_lease = harness
        .worker
        .history
        .request_history(tip_a2.height)
        .expect("seed pin");
    *harness.worker.seed_bundle.lock() = Some(SeedBundle {
        artifact: None,
        lease: Some(seed_lease),
    });
    harness.set_tip(&fixture.tip(fixture.a[3]));
    let mut pending = None;
    harness.worker.reconcile_once(&mut pending).expect("pass");
    assert!(
        harness
            .worker
            .seed_bundle
            .lock()
            .as_ref()
            .is_none_or(|bundle| bundle.lease.is_none()),
        "subsumed seed pin drained, never parked beside the fresh grant"
    );
    assert!(
        harness.retention.active_leases() <= 1,
        "single live history pin at every instant"
    );
}

/// A scoped `ScriptLive` outage reloads the fence and watermarks after its
/// reset: the pre-reset capture still names the erased watermark, so
/// selecting legs from it would treat `ScriptLive` as synced and answer
/// `CaughtUp` while storage holds no watermark. With fresh tuples the reset
/// family replays instead.
#[test]
fn script_live_reset_reloads_watermarks_before_selection() {
    let fixture = SeedFixture::new(4);
    fixture.persist_branch_a_undo();
    let harness = SeedHarness::new(
        &fixture,
        IndexCapabilities::TX_AND_SCRIPTS,
        Arc::new(UtxoSet::new()),
    );
    let (set, _coins) = seed_coin_set(5_000);
    let tip_a2 = fixture.tip(fixture.a[1]);
    let (artifact, _) = mint_seed_artifact(&set, tip_a2.hash, tip_a2.height);
    harness.cell.want();
    assert_eq!(harness.cell.offer(artifact), OfferOutcome::Stored);
    harness.set_tip(&tip_a2);
    let mut pending = None;
    for _ in 0..64 {
        match harness.worker.reconcile_once(&mut pending).expect("seed") {
            ReconcileAction::CaughtUp => break,
            ReconcileAction::Progressed | ReconcileAction::Buffered => {}
            ReconcileAction::Stalled => panic!("seed stalled"),
        }
    }
    assert_eq!(harness.watermarks().script_live, Some(at(&tip_a2)));

    // Withhold one body on the replay path so the post-reset leg retains
    // rows instead of converging past the erased watermark in one pass.
    let absent = fixture.a_key(1);
    let withheld = fixture
        .bodies
        .bodies
        .lock()
        .remove(&absent)
        .expect("withheld body");
    harness
        .runtime
        .fail_script_live(&DerivedIndexWorkerError::ScriptLiveHistoryPruned);
    let action = harness.worker.reconcile_once(&mut pending).expect("pass");
    fixture.bodies.bodies.lock().insert(absent, withheld);
    assert!(
        matches!(action, ReconcileAction::Buffered),
        "reset family replays, never claims caught-up on a stale capture"
    );
    assert!(pending.is_some(), "prefix retained for its deadline");
}

/// Row 6: a prune pass refuses history at or above a live pin; a forced
/// budget expiry answers `Pruned` (never a `MissingBody` spin); `Reserved`
/// waits; `Shutdown` stops. With nothing grantable at the frontier the worker
/// reports terminal unavailable and stays alive.
#[test]
fn seed_prune_while_paused_refuses_at_or_above_floor() {
    // Boundary discipline on a live pin: the reserve folds the pin, the pin
    // is never crossed, and expiry answers Pruned.
    let registry = Arc::new(RetentionRegistry::new());
    let access = HistoryAccess::new(Arc::clone(&registry), RetentionBudget::Depth(288));
    let pin = access.request_history(2).expect("grant at 2");
    assert_eq!(pin.floor(), Some(2));
    assert_eq!(registry.retention_floor(), Some(2));
    // A reserve above the pin folds to the pin: rows at the pin survive.
    let reservation = registry.reserve(7);
    assert_eq!(registry.retention_floor(), Some(2));
    assert!(access.request_history(2).is_ok(), "pin still grants");
    drop(reservation);
    // Below a committed line is gone; the line itself still grants.
    registry.reserve(7).commit(7);
    assert!(matches!(
        access.request_history(3),
        Err(HistoryUnavailable::Pruned { .. })
    ));
    assert!(access.request_history(7).is_ok(), "the line itself grants");
    drop(pin);
    // Forced expiry: a held pin that lags beyond its budget answers Pruned.
    let registry = Arc::new(RetentionRegistry::new());
    let access = HistoryAccess::new(Arc::clone(&registry), RetentionBudget::Depth(288));
    let pin = access.request_history(2).expect("grant at 2");
    registry.reserve(300).commit(300);
    assert_eq!(pin.floor(), None, "the lagging pin expired");
    assert!(matches!(
        access.request_history(2),
        Err(HistoryUnavailable::Pruned { .. })
    ));
    drop(pin);
    // A provisional reservation waits; shutdown stops.
    let registry = Arc::new(RetentionRegistry::new());
    let access = HistoryAccess::new(Arc::clone(&registry), RetentionBudget::Depth(288));
    let reservation = registry.reserve(5);
    assert!(matches!(
        access.request_history(3),
        Err(HistoryUnavailable::Reserved { .. })
    ));
    drop(reservation);
    assert!(access.request_history(3).is_ok(), "release unblocks");
    registry.shutdown();
    assert!(matches!(
        access.request_history(0),
        Err(HistoryUnavailable::Shutdown)
    ));

    // Worker fallback: pruned history never spins on MissingBody. With no
    // token and nothing grantable at the frontier, ScriptLive reports
    // terminal unavailable while the worker stays alive and stall-safe.
    let fixture = SeedFixture::new(3);
    fixture.persist_branch_a_undo();
    let harness = SeedHarness::new(
        &fixture,
        IndexCapabilities::TX_AND_SCRIPTS,
        Arc::new(UtxoSet::new()),
    );
    harness.retention.reserve(1).commit(1);
    harness.set_tip(&fixture.tip(fixture.a[2]));
    let mut pending = None;
    for _ in 0..16 {
        match harness
            .worker
            .reconcile_once(&mut pending)
            .expect("prune pass")
        {
            ReconcileAction::CaughtUp
            | ReconcileAction::Progressed
            | ReconcileAction::Buffered
            | ReconcileAction::Stalled => {}
        }
        assert!(!harness.runtime.should_stop());
        assert!(harness.runtime.failure_message().is_none());
    }
    assert!(
        harness.runtime.script_live_failure().is_some(),
        "pruned frontier raises terminal unavailable"
    );
    assert_eq!(
        harness.watermarks().script_live,
        None,
        "nothing grantable mints no watermark"
    );
}

/// Row 7: a sub-H reorg rolls back through the pinned undo and converges.
/// Undo presence is load-bearing: without the H undo the live family resets
/// while siblings keep their rows; with it, the rewind crosses branches.
#[test]
fn seed_reorg_below_h_rolls_back_through_pinned_undo() {
    let fixture = SeedFixture::new(4);
    fixture.persist_branch_a_undo();
    fixture.persist_branch_b_undo();
    let harness = SeedHarness::new(
        &fixture,
        IndexCapabilities::TX_AND_SCRIPTS,
        Arc::new(UtxoSet::new()),
    );

    // Token-seeded at H = 2, then the tip crosses to the rival branch. The
    // only reset-free path is a rewind through the H and H-1 undos: the
    // rollback cutover is disabled and every undo is present.
    let (set, _) = seed_coin_set(64);
    let tip_a2 = fixture.tip(fixture.a[1]);
    let (artifact, _) = mint_seed_artifact(&set, tip_a2.hash, tip_a2.height);
    harness.cell.want();
    assert_eq!(harness.cell.offer(artifact), OfferOutcome::Stored);
    harness.set_tip(&tip_a2);
    let mut pending = None;
    harness.settle(&mut pending);
    assert_eq!(harness.watermarks().script_live, Some(at(&tip_a2)));

    harness.set_tip(&fixture.tip(fixture.b[2]));
    harness.settle(&mut pending);
    let tip_b3 = fixture.tip(fixture.b[2]);
    assert_eq!(harness.watermarks().script_live, Some(at(&tip_b3)));
    assert_eq!(harness.watermarks().tx_lookup, Some(at(&tip_b3)));
    assert_eq!(harness.watermarks().script_history, Some(at(&tip_b3)));
    assert!(harness.runtime.failure_message().is_none());

    // Control: without the H undo the same reorg resets live, proving the
    // rollback above actually rode the pinned undo.
    let control = SeedFixture::new(4);
    control.persist_branch_a_undo();
    control.persist_branch_b_undo();
    control.bodies.undo.lock().remove(&control.a_key(2));
    let denied = SeedHarness::new(
        &control,
        IndexCapabilities::TX_AND_SCRIPTS,
        Arc::new(UtxoSet::new()),
    );
    let control_tip = control.tip(control.a[1]);
    let (initial_set, _) = seed_coin_set(64);
    let (initial, _) = mint_seed_artifact(&initial_set, control_tip.hash, control_tip.height);
    denied.cell.want();
    assert_eq!(denied.cell.offer(initial), OfferOutcome::Stored);
    denied.set_tip(&control_tip);
    let mut pending = None;
    denied.settle(&mut pending);
    let tip_b3 = control.tip(control.b[2]);
    denied.set_tip(&tip_b3);
    let mut saw_reset = false;
    for _ in 0..16 {
        match denied
            .worker
            .reconcile_once(&mut pending)
            .expect("reset pass")
        {
            ReconcileAction::CaughtUp
            | ReconcileAction::Progressed
            | ReconcileAction::Buffered
            | ReconcileAction::Stalled => {}
        }
        if denied.watermarks().script_live.is_none() {
            saw_reset = true;
            break;
        }
    }
    let (replacement_set, _) = seed_coin_set(64);
    let (replacement, _) = mint_seed_artifact(&replacement_set, tip_b3.hash, tip_b3.height);
    denied.cell.want();
    assert_eq!(denied.cell.offer(replacement), OfferOutcome::Stored);
    for _ in 0..64 {
        match denied.worker.reconcile_once(&mut pending).expect("pass") {
            ReconcileAction::CaughtUp => break,
            ReconcileAction::Progressed | ReconcileAction::Buffered => {}
            ReconcileAction::Stalled => panic!("control stalled"),
        }
        if denied.watermarks().script_live.is_none() {
            saw_reset = true;
        }
    }
    assert!(saw_reset, "missing H undo resets live mid-reorg");
    assert_eq!(denied.watermarks().script_live, Some(at(&tip_b3)));
}

/// Row 15: publication and import offers with a `Dormant` cell open no file
/// and store nothing; with an `Offered` cell the newer file is closed and
/// the queued tip is kept. A token that arrives while a pending batch holds
/// `ScriptLive` rows waits; once replay clears past its tip, a stale token is
/// discarded.
#[test]
fn seed_offer_skipped_without_demand() {
    // Dormant arrival: the producer pre-check fails, so nothing opens.
    let cell: SeedOfferCell = Arc::new(SeedSlot::new());
    assert!(!cell.is_wanted());
    let mut opens = 0usize;
    if cell.is_wanted() {
        opens += 1;
    }
    assert_eq!(opens, 0, "dormant arrival opens no file");
    assert!(cell.take().is_none());

    // Offered arrival: the first tip wins; the newer file is dropped.
    let (set_a, _) = seed_coin_set(8);
    let tip_a = synthetic_txid(501);
    let (artifact_a, _) = mint_seed_artifact(&set_a, tip_a, 3);
    let (set_b, _) = seed_coin_set(8);
    let tip_b = synthetic_txid(502);
    let (artifact_b, _) = mint_seed_artifact(&set_b, tip_b, 4);
    cell.want();
    assert!(cell.is_wanted());
    assert_eq!(cell.offer(artifact_a), OfferOutcome::Stored);
    assert!(!cell.is_wanted(), "offered cell wants nothing more");
    assert_eq!(cell.offer(artifact_b), OfferOutcome::Skipped);
    let queued = cell.take().expect("queued tip");
    assert_eq!(queued.tip(), (3, tip_a), "first stored tip wins");
    assert!(cell.take().is_none());
    assert!(!cell.is_wanted(), "take clears demand with the artifact");

    // Worker side: a token queued while a pending batch holds ScriptLive
    // rows waits for replay; a token older than replayed rows is discarded.
    let fixture = SeedFixture::new(12);
    fixture.persist_branch_a_undo();
    let harness = SeedHarness::new(
        &fixture,
        IndexCapabilities::TX_AND_SCRIPTS,
        Arc::new(UtxoSet::new()),
    );
    harness.set_tip(&fixture.tip(fixture.a[11]));
    // Withhold one body so the first window is retained with ScriptLive rows.
    let absent = fixture.a_key(8);
    let withheld = fixture
        .bodies
        .bodies
        .lock()
        .remove(&absent)
        .expect("withheld body");
    let mut pending = None;
    assert!(matches!(
        harness.worker.reconcile_once(&mut pending),
        Ok(ReconcileAction::Buffered)
    ));
    assert!(pending.is_some(), "prefix retained for its deadline");
    let (stale_set, _) = seed_coin_set(16);
    let tip_a5 = fixture.tip(fixture.a[4]);
    let (stale_token, _) = mint_seed_artifact(&stale_set, tip_a5.hash, tip_a5.height);
    harness.cell.want();
    assert_eq!(harness.cell.offer(stale_token), OfferOutcome::Stored);
    assert!(matches!(
        harness.worker.reconcile_once(&mut pending),
        Ok(ReconcileAction::Progressed | ReconcileAction::Buffered)
    ));
    assert!(
        harness.cell.take().is_some(),
        "token waits while replay holds ScriptLive rows"
    );
    // Re-stage it: replay now clears past its tip, so it is stale on take.
    let (stale_set, _) = seed_coin_set(16);
    let (stale_token, _) = mint_seed_artifact(&stale_set, tip_a5.hash, tip_a5.height);
    harness.cell.want();
    assert_eq!(harness.cell.offer(stale_token), OfferOutcome::Stored);
    fixture.bodies.bodies.lock().insert(absent, withheld);
    harness.settle(&mut pending);
    let tip_a12 = fixture.tip(fixture.a[11]);
    assert_eq!(harness.watermarks().script_live, Some(at(&tip_a12)));
    assert!(
        harness.cell.take().is_none(),
        "replay superseded the stale token"
    );
    let expected = expected_live_keys(&expected_chain_live(&fixture, 1, 12, &[]));
    assert_eq!(scan_live_keys(&harness.store), expected);
}

/// Cancellation is polled at entry, every 4,096 rows, and before the final
/// watermark commit; a trip returns `Cancelled` with no watermark so the
/// caller can retry with the same coins.
#[test]
fn seed_stream_polls_cancellation_and_leaves_no_watermark() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Arc::new(FjallStore::open(dir.path()).expect("fjall open"));
    let mut writer = crate::IndexWriter::open(Arc::clone(&store), 1).expect("writer open");
    let scripthash = ScriptHash::from_script_bytes(&[0x51]);
    let tip = IndexWatermark {
        height: 7,
        hash: [0x07; 32],
    };
    // Immediate cancellation writes nothing.
    let immediate = writer.seed_script_live_stream(
        &mut |_: &mut dyn FnMut(OutPoint, ScriptHash) -> Result<(), IndexError>| Ok(()),
        tip,
        &|| true,
    );
    assert!(
        matches!(immediate, Err(IndexError::Cancelled)),
        "entry poll must stop before any write: {immediate:?}"
    );
    assert!(
        writer
            .watermarks()
            .expect("watermarks")
            .script_live
            .is_none(),
        "a cancelled entry must not stamp the watermark"
    );

    // Mid-stream cancellation stops at the next 4,096 boundary.
    let coins: Vec<(OutPoint, ScriptHash)> = (0..9_000_u32)
        .map(|v| {
            let mut bytes = [0x77_u8; 32];
            bytes[..4].copy_from_slice(&v.to_le_bytes());
            (
                OutPoint::new(Hash256::from_le_bytes(&bytes).into(), 0),
                scripthash,
            )
        })
        .collect();
    let seen = std::cell::Cell::new(0_u64);
    let mut next = 0_usize;
    let mid = writer.seed_script_live_stream(
        &mut |emit: &mut dyn FnMut(OutPoint, ScriptHash) -> Result<(), IndexError>| {
            while next < coins.len() {
                let (outpoint, hash) = coins[next];
                next += 1;
                seen.set(seen.get() + 1);
                emit(outpoint, hash)?;
            }
            Ok(())
        },
        tip,
        &|| seen.get() >= 5_000,
    );
    assert!(
        matches!(mid, Err(IndexError::Cancelled)),
        "mid-stream stop must report cancellation: {mid:?}"
    );
    assert!(
        writer
            .watermarks()
            .expect("watermarks")
            .script_live
            .is_none(),
        "a cancelled stream must not stamp the watermark"
    );

    // The retry's opening reset clears the cancelled prefix; the same coins
    // commit and stamp the watermark.
    let written = writer.seed_script_live(coins, tip).expect("retry seed");
    assert_eq!(written, 9_000, "retry must commit every coin");
    assert_eq!(
        writer.watermarks().expect("watermarks").script_live,
        Some(tip)
    );
}
