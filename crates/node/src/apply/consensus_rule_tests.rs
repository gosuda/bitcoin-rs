mod fixtures_behavior;
mod fixtures_notifications;
mod fixtures_transitions;
mod fixtures_validation;

use super::*;
use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::BlockTree;
#[cfg(test)]
use bitcoin_rs_chain::node::NodeStatus;
use bitcoin_rs_mining::MiningControlError;
use bitcoin_rs_primitives::BlockHash;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::Header;
use bitcoin_rs_primitives::OutPoint;
use bitcoin_rs_primitives::TxIn;
#[cfg(test)]
use bitcoin_rs_script::script::push_int;
#[cfg(test)]
use bitcoin_rs_utxo::BlockChanges;
#[cfg(test)]
use bitcoin_rs_utxo::UtxoAdd;
use bitcoin_rs_utxo::UtxoSet;
#[cfg(test)]
use fixtures_behavior::apply_followed;
#[cfg(test)]
use fixtures_behavior::apply_handles;
#[cfg(test)]
use fixtures_behavior::apply_handles_for_network;
#[cfg(test)]
use fixtures_behavior::apply_handles_with_assume_valid;
#[cfg(test)]
use fixtures_behavior::assert_nbits_error;
use fixtures_behavior::block_with_prev_hash_and_transactions;
#[cfg(test)]
use fixtures_behavior::block_with_transaction;
#[cfg(test)]
use fixtures_behavior::block_with_transactions;
use fixtures_behavior::empty_apply_handles_for_network;
#[cfg(test)]
use fixtures_behavior::empty_utxo;
#[cfg(test)]
use fixtures_behavior::excess_value_spend_block;
#[cfg(test)]
use fixtures_behavior::fixture_txid;
#[cfg(test)]
use fixtures_behavior::height_one_prepared;
#[cfg(test)]
use fixtures_behavior::kernel_block_of;
#[cfg(test)]
#[cfg(feature = "kernel")]
use fixtures_behavior::p2sh_template_bare_spend_block;
#[cfg(test)]
use fixtures_behavior::retarget_bits_for_test;
#[cfg(test)]
use fixtures_behavior::seed_block_tree_with_times;
#[cfg(test)]
use fixtures_behavior::softfork_state;
#[cfg(test)]
use fixtures_behavior::spending_transaction_with_version;
#[cfg(test)]
use fixtures_behavior::transaction;
#[cfg(test)]
use fixtures_behavior::tx_plan;
#[cfg(test)]
use fixtures_behavior::utxo_with_output;
#[cfg(test)]
use fixtures_behavior::utxo_with_outputs_at_height;
#[cfg(test)]
use fixtures_behavior::validation_context;
#[cfg(test)]
use fixtures_behavior::wait_until;
#[cfg(test)]
use fixtures_notifications::apply_block_with_a_fee_paying_transaction;
#[cfg(test)]
use fixtures_notifications::zmq_followers;
#[cfg(test)]
use fixtures_transitions::assert_reorg_load_failure_preserved_state;
#[cfg(test)]
use fixtures_transitions::disconnect_followed;
use fixtures_transitions::generation_unavailable;
#[cfg(test)]
use fixtures_transitions::one_block_window_fixture;
#[cfg(test)]
use fixtures_transitions::reorg_body_loading_fixture;
#[cfg(test)]
use fixtures_validation::apply_coinbase_only_block;
#[cfg(test)]
use fixtures_validation::assert_bip_error;
#[cfg(test)]
use fixtures_validation::assert_bip_error_reason_contains;
#[cfg(test)]
use fixtures_validation::bad_script_spend_block;
#[cfg(test)]
use fixtures_validation::block_with_pow_header;
#[cfg(test)]
use fixtures_validation::coinbase_transaction_with_height;
#[cfg(test)]
use fixtures_validation::duplicate_spend_block;
#[cfg(test)]
use fixtures_validation::op_return_script;
#[cfg(test)]
use fixtures_validation::op_true_script;
#[cfg(test)]
use fixtures_validation::pow_header;
#[cfg(test)]
use fixtures_validation::pow_limit_bits;
#[cfg(test)]
use fixtures_validation::scaled_pow_limit_bits;
#[cfg(test)]
use fixtures_validation::seed_block_tree_for_bip68_time;
#[cfg(test)]
use fixtures_validation::seed_block_tree_for_bip68_time_at_height;
#[cfg(test)]
use fixtures_validation::seed_known_bip34_activation_chain;
#[cfg(test)]
use fixtures_validation::seed_pow_chain;
#[cfg(test)]
use fixtures_validation::seed_pow_chain_with_headers;
#[cfg(test)]
use fixtures_validation::seed_pow_period_with_tip_bits;
#[cfg(test)]
use fixtures_validation::spending_transaction_to_script;
#[cfg(test)]
use fixtures_validation::txids_merkle_root;
use hashbrown::HashMap;
use parking_lot::Mutex;
use parking_lot::RwLock;
use std::sync::Arc;

const BIP68_TEST_PREVOUT_HEIGHT: u32 = 100;
const BIP68_TEST_PREVOUT_MTP: u32 = 1_000_000;
const MAINNET_POW_LIMIT_BITS: u32 = 0x1d00_ffff;
const MAINNET_POW_LIMIT_DIV_4_BITS: u32 = 0x1c3f_ffc0;
const DAA_ANCHOR_TIME: u32 = 1_600_000_000;

/// A store that refuses every write, to prove the undo persistence is a
/// real gate rather than a best-effort side effect.
#[derive(Debug, Default)]
struct RejectingUndoStore;

impl UndoStore for RejectingUndoStore {
    fn persist_undo(
        &self,
        _height: u32,
        _hash: Hash256,
        _record: &[u8],
    ) -> Result<(), bitcoin_rs_storage::StorageError> {
        Err(bitcoin_rs_storage::StorageError::Backend(
            "injected undo write failure".to_owned(),
        ))
    }

    fn load_undo(
        &self,
        _height: u32,
        _hash: Hash256,
    ) -> Result<Option<Vec<u8>>, bitcoin_rs_storage::StorageError> {
        Ok(None)
    }

    fn arm_disconnect(
        &self,
        _height: u32,
        _hash: Hash256,
    ) -> Result<(), bitcoin_rs_storage::StorageError> {
        Err(bitcoin_rs_storage::StorageError::Backend(
            "injected marker write failure".to_owned(),
        ))
    }

    fn complete_disconnect(
        &self,
        _height: u32,
        _hash: Hash256,
    ) -> Result<(), bitcoin_rs_storage::StorageError> {
        Err(bitcoin_rs_storage::StorageError::Backend(
            "injected marker completion failure".to_owned(),
        ))
    }

    fn disarm_disconnect(&self) -> Result<(), bitcoin_rs_storage::StorageError> {
        Err(bitcoin_rs_storage::StorageError::Backend(
            "injected marker clear failure".to_owned(),
        ))
    }

    fn load_disconnect_marker(
        &self,
    ) -> Result<Option<DisconnectMarker>, bitcoin_rs_storage::StorageError> {
        Ok(None)
    }
}

#[derive(Debug, Default)]
struct CompleteRejectingUndoStore {
    inner: InMemoryUndoStore,
}

impl UndoStore for CompleteRejectingUndoStore {
    fn persist_undo(
        &self,
        height: u32,
        hash: Hash256,
        record: &[u8],
    ) -> Result<(), bitcoin_rs_storage::StorageError> {
        self.inner.persist_undo(height, hash, record)
    }

    fn load_undo(
        &self,
        height: u32,
        hash: Hash256,
    ) -> Result<Option<Vec<u8>>, bitcoin_rs_storage::StorageError> {
        self.inner.load_undo(height, hash)
    }

    fn arm_disconnect(
        &self,
        height: u32,
        hash: Hash256,
    ) -> Result<(), bitcoin_rs_storage::StorageError> {
        self.inner.arm_disconnect(height, hash)
    }

    fn complete_disconnect(
        &self,
        _height: u32,
        _hash: Hash256,
    ) -> Result<(), bitcoin_rs_storage::StorageError> {
        Err(bitcoin_rs_storage::StorageError::Backend(
            "injected marker completion failure".to_owned(),
        ))
    }

    fn disarm_disconnect(&self) -> Result<(), bitcoin_rs_storage::StorageError> {
        self.inner.disarm_disconnect()
    }

    fn load_disconnect_marker(
        &self,
    ) -> Result<Option<DisconnectMarker>, bitcoin_rs_storage::StorageError> {
        self.inner.load_disconnect_marker()
    }
}

// --- txindex worker failure isolation fixture ---
/// A `TxIndex` writer/reader that lets the worker start up cleanly through
/// the current fence API and then fails on the next `fenced_watermarks`
/// call. This models a durable-index write fault that appears after the
/// runtime has already committed to an asynchronous worker.
struct FailAfterStartupTxIndex {
    fence: bitcoin_rs_index::IndexWriteFence,
    watermarks: bitcoin_rs_index::IndexWatermarks,
    fenced_calls: std::sync::atomic::AtomicUsize,
    fail: std::sync::atomic::AtomicBool,
}

impl FailAfterStartupTxIndex {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = Arc::new(bitcoin_rs_storage::FjallStore::open(temp.path())?);
        let mut writer = bitcoin_rs_index::IndexWriter::open(store, 1)?;
        let (fence, watermarks) = writer.fenced_watermarks()?;
        Ok(Self {
            fence,
            watermarks,
            fenced_calls: std::sync::atomic::AtomicUsize::new(0),
            fail: std::sync::atomic::AtomicBool::new(false),
        })
    }
}

impl bitcoin_rs_index::writer::TxIndexWriter for FailAfterStartupTxIndex {
    fn fenced_watermarks(
        &self,
    ) -> Result<
        (
            bitcoin_rs_index::IndexWriteFence,
            bitcoin_rs_index::IndexWatermarks,
        ),
        bitcoin_rs_index::IndexError,
    > {
        if self.fail.load(std::sync::atomic::Ordering::Acquire) {
            return Err(bitcoin_rs_index::IndexError::UnsupportedRollback);
        }
        self.fenced_calls
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        Ok((self.fence, self.watermarks))
    }

    fn commit_forward_with_cursor(
        &self,
        _fence: bitcoin_rs_index::IndexWriteFence,
        _batch: bitcoin_rs_index::PreparedBatch,
        _cursor: bitcoin_rs_index::ConsumerCursorUpdate<'_>,
    ) -> Result<bitcoin_rs_index::IndexWatermark, bitcoin_rs_index::IndexError> {
        Err(bitcoin_rs_index::IndexError::UnsupportedRollback)
    }

    fn prepare_block_with_spent_scripts(
        &self,
        _capabilities: bitcoin_rs_index::IndexCapabilities,
        _height: u32,
        _hash: [u8; 32],
        _body: &[u8],
        _spent_scripts: &dyn bitcoin_rs_index::SpentCoinScripts,
    ) -> Result<bitcoin_rs_index::PreparedBlock, bitcoin_rs_index::IndexError> {
        Err(bitcoin_rs_index::IndexError::UnsupportedRollback)
    }

    fn consumer_cursor(&self) -> Result<Option<Vec<u8>>, bitcoin_rs_index::IndexError> {
        Err(bitcoin_rs_index::IndexError::UnsupportedRollback)
    }

    fn commit_consumer_cursor(
        &self,
        _fence: bitcoin_rs_index::IndexWriteFence,
        _cursor: &[u8],
    ) -> Result<(), bitcoin_rs_index::IndexError> {
        Err(bitcoin_rs_index::IndexError::UnsupportedRollback)
    }
    fn commit_rollback_one_for_with_cursor_with_spent_scripts(
        &self,
        _fence: bitcoin_rs_index::IndexWriteFence,
        _capabilities: bitcoin_rs_index::IndexCapabilities,
        _prev: Option<bitcoin_rs_index::IndexWatermark>,
        _body: &[u8],
        _cursor: bitcoin_rs_index::ConsumerCursorUpdate<'_>,
        _spent_scripts: &dyn bitcoin_rs_index::SpentCoinScripts,
    ) -> Result<(), bitcoin_rs_index::IndexError> {
        Err(bitcoin_rs_index::IndexError::UnsupportedRollback)
    }
}

impl bitcoin_rs_index::IndexReader for FailAfterStartupTxIndex {
    fn snapshot(
        &self,
    ) -> Result<Box<dyn bitcoin_rs_index::TxIndexSnapshot + '_>, bitcoin_rs_index::IndexError> {
        Err(bitcoin_rs_index::IndexError::UnsupportedRollback)
    }
}

pub(super) fn coinbase_transaction(seed: u8) -> Tx {
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid::default(), u32::MAX),
            script_sig: Script::from_bytes(vec![seed, seed]),
            sequence: Sequence::from_consensus(u32::MAX),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: Script::new(),
        }],
        lock_time: LockTime::from_consensus(0),
    }
}

pub(super) fn mined_block_with_prev_hash_and_transactions(
    prev_blockhash: BlockHash,
    txdata: Vec<Tx>,
) -> Result<Block, Box<dyn std::error::Error>> {
    let mut block = block_with_prev_hash_and_transactions(prev_blockhash, txdata);
    loop {
        if compact_is_met_by(block.header.bits, block.header.compute_hash().0) {
            return Ok(block);
        }
        block.header.nonce = block
            .header
            .nonce
            .checked_add(1)
            .ok_or_else(|| std::io::Error::other("test block nonce exhausted"))?;
    }
}

#[allow(clippy::arc_with_non_send_sync)]
pub(super) fn empty_apply_handles() -> Chainstate {
    empty_apply_handles_for_network(Network::Mainnet)
}

/// In-memory bodies, so a branch switch can reload the blocks it needs.
#[derive(Default)]
pub(super) struct MapBodyStore {
    pub(super) bodies: parking_lot::RwLock<HashMap<(u32, bitcoin_rs_primitives::Hash256), Vec<u8>>>,
    pub(super) failed_reads: parking_lot::RwLock<HashSet<(u32, bitcoin_rs_primitives::Hash256)>>,
    /// Bodies that succeed on the first read but fail on every subsequent
    /// read, simulating a storage failure between the preflight and
    /// execution passes of a streamed reorg.
    pub(super) fail_on_second_read:
        parking_lot::RwLock<HashSet<(u32, bitcoin_rs_primitives::Hash256)>>,
    read_counts: parking_lot::RwLock<HashMap<(u32, bitcoin_rs_primitives::Hash256), u32>>,
}

struct ReorgBodyLoadingFixture {
    handles: Chainstate,
    utxo: Arc<UtxoSet>,
    bodies: Arc<MapBodyStore>,
    target: bitcoin_rs_chain::NodeId,
    losing: Block,
    applied: TipSnapshot,
}

impl bitcoin_rs_storage::block_body::BlockBodyStore for MapBodyStore {
    fn load_block_body(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        if self.failed_reads.read().contains(&(height, hash)) {
            return Err(StorageError::Backend(
                "injected block-body read failure".to_owned(),
            ));
        }
        if self.fail_on_second_read.read().contains(&(height, hash)) {
            let mut counts = self.read_counts.write();
            let count = counts.entry((height, hash)).or_insert(0);
            *count += 1;
            if *count >= 2 {
                return Err(StorageError::Backend(
                    "injected second-read failure".to_owned(),
                ));
            }
        }
        Ok(self.bodies.read().get(&(height, hash)).cloned())
    }

    fn persist_block_body(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
        body: &[u8],
    ) -> Result<(), StorageError> {
        self.bodies.write().insert((height, hash), body.to_vec());
        Ok(())
    }

    fn sync(&self) -> Result<(), StorageError> {
        Ok(())
    }
}

#[derive(Debug, Default)]
struct RecordingSequencePublisher {
    events: Mutex<Vec<(Hash256, u8, u32)>>,
    next_sequence: Mutex<u32>,
}

impl crate::ZmqPublisher for RecordingSequencePublisher {
    fn publish_hashblock(&self, _hash: Hash256) {}

    fn publish_hashtx(&self, _txid: Txid) {}

    fn publish_rawblock(&self, _bytes: &[u8]) {}

    fn publish_rawtx(&self, _bytes: &[u8]) {}

    fn publish_sequence(&self, event: crate::SequenceEvent) {
        let (hash, label) = match event {
            crate::SequenceEvent::Connected(hash) => (hash, b'C'),
            crate::SequenceEvent::Disconnected(hash) => (hash, b'D'),
            // Test-fake arms for the mempool `A`/`R` events; the
            // production payload mapping lives in `bitcoin_rs_rpc::zmq`.
            crate::SequenceEvent::Added(txid, _) => (Hash256::from(txid), b'A'),
            crate::SequenceEvent::Removed(txid, _) => (Hash256::from(txid), b'R'),
        };
        let mut next_sequence = self.next_sequence.lock();
        self.events.lock().push((hash, label, *next_sequence));
        *next_sequence += 1;
    }
}

struct BlockingBodyStore {
    body: Vec<u8>,
    entered: std::sync::Barrier,
    release: std::sync::Barrier,
    block_once: AtomicBool,
}

impl bitcoin_rs_storage::block_body::BlockBodyStore for BlockingBodyStore {
    fn load_block_body(
        &self,
        _height: u32,
        _hash: Hash256,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        if self.block_once.swap(false, Ordering::AcqRel) {
            self.entered.wait();
            self.release.wait();
        }
        Ok(Some(self.body.clone()))
    }

    fn persist_block_body(
        &self,
        _height: u32,
        _hash: Hash256,
        _body: &[u8],
    ) -> Result<(), StorageError> {
        Ok(())
    }

    fn sync(&self) -> Result<(), StorageError> {
        Ok(())
    }
}

#[derive(Debug)]
struct AppliedTipVisiblePublisher {
    applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    expected: Hash256,
    seen: Mutex<Vec<Hash256>>,
}

impl crate::ZmqPublisher for AppliedTipVisiblePublisher {
    fn publish_hashblock(&self, _hash: Hash256) {}

    fn publish_hashtx(&self, _txid: Txid) {}

    fn publish_rawblock(&self, _bytes: &[u8]) {}

    fn publish_rawtx(&self, _bytes: &[u8]) {}

    fn publish_sequence(&self, event: crate::SequenceEvent) {
        if let crate::SequenceEvent::Connected(hash) = event {
            assert_eq!(
                self.applied_tip.load_full().as_deref().map(|tip| tip.hash),
                Some(self.expected),
                "applied tip must be visible before publishing C"
            );
            self.seen.lock().push(hash);
        }
    }
}

struct TransitionHeldPublisher {
    entered: std::sync::Arc<std::sync::Barrier>,
    release: std::sync::Arc<std::sync::Barrier>,
}

impl core::fmt::Debug for TransitionHeldPublisher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("TransitionHeldPublisher")
    }
}

impl crate::ZmqPublisher for TransitionHeldPublisher {
    fn publish_hashblock(&self, _hash: Hash256) {
        self.entered.wait();
        self.release.wait();
    }

    fn publish_hashtx(&self, _txid: Txid) {}

    fn publish_rawblock(&self, _bytes: &[u8]) {}

    fn publish_rawtx(&self, _bytes: &[u8]) {}
}

#[allow(clippy::arc_with_non_send_sync)]
pub(super) fn apply_handles_without_tx_index(network: Network, utxo: Arc<UtxoSet>) -> Chainstate {
    let mempool: Arc<RwLock<bitcoin_rs_mempool::Mempool>> = Arc::new(RwLock::new(
        bitcoin_rs_mempool::Mempool::new(bitcoin_rs_mempool::MempoolLimits::default()),
    ));
    let mempool_gateway = bitcoin_rs_mempool::MempoolGateway::shared(Arc::clone(&mempool));
    Chainstate::new(
        network,
        Arc::new(ArcSwapOption::empty()),
        Arc::new(ArcSwapOption::empty()),
        Arc::new(RwLock::new(BlockTree::new())),
        utxo,
        Arc::new(bitcoin_rs_utxo::stats::CoinStatsListener::new(
            bitcoin_rs_utxo::stats::CoinStats::default(),
        )),
        mempool,
        mempool_gateway,
        Arc::new(crate::state::ChainEventPublisher::detached(0).0),
    )
}

#[derive(Debug, Default)]
struct RecordingRawTxPublisher {
    raw_txs: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl crate::ZmqPublisher for RecordingRawTxPublisher {
    fn wants_rawtx(&self) -> bool {
        true
    }

    fn publish_hashblock(&self, _hash: Hash256) {}

    fn publish_hashtx(&self, _txid: Txid) {}

    fn publish_rawblock(&self, _bytes: &[u8]) {}

    fn publish_rawtx(&self, bytes: &[u8]) {
        self.raw_txs.lock().push(bytes.to_vec());
    }
}

#[derive(Debug, Default)]
struct RecordingRawBlockPublisher {
    raw_block: Arc<Mutex<Option<Vec<u8>>>>,
}

impl crate::ZmqPublisher for RecordingRawBlockPublisher {
    fn wants_rawtx(&self) -> bool {
        false
    }

    fn wants_rawblock(&self) -> bool {
        true
    }

    fn publish_hashblock(&self, _hash: Hash256) {}

    fn publish_hashtx(&self, _txid: Txid) {}

    fn publish_rawblock(&self, bytes: &[u8]) {
        *self.raw_block.lock() = Some(bytes.to_vec());
    }

    fn publish_rawtx(&self, _bytes: &[u8]) {
        panic!("rawtx publish should be skipped when wants_rawtx is false");
    }
}

#[derive(Debug, Default)]
struct PanickingOptOutPublisher;

impl crate::ZmqPublisher for PanickingOptOutPublisher {
    fn wants_notifications(&self) -> bool {
        false
    }

    fn publish_hashblock(&self, _hash: Hash256) {
        panic!("hashblock publish should be skipped");
    }

    fn publish_hashtx(&self, _txid: Txid) {
        panic!("hashtx publish should be skipped");
    }

    fn publish_rawblock(&self, _bytes: &[u8]) {
        panic!("rawblock publish should be skipped");
    }

    fn publish_rawtx(&self, _bytes: &[u8]) {
        panic!("rawtx publish should be skipped");
    }
}

#[derive(Debug, Default)]
struct PanickingNoRawblockPublisher;

impl crate::ZmqPublisher for PanickingNoRawblockPublisher {
    fn wants_notifications(&self) -> bool {
        true
    }

    fn wants_rawtx(&self) -> bool {
        false
    }

    fn wants_rawblock(&self) -> bool {
        false
    }

    fn publish_hashblock(&self, _hash: Hash256) {}

    fn publish_hashtx(&self, _txid: Txid) {}

    fn publish_rawblock(&self, _bytes: &[u8]) {
        panic!("rawblock publish should be skipped when wants_rawblock is false");
    }

    fn publish_rawtx(&self, _bytes: &[u8]) {
        panic!("rawtx publish should be skipped when wants_rawtx is false");
    }
}

/// A fake template coordinator recording generation publications.
struct RecordingGenerationControl {
    published: Mutex<usize>,
}

impl bitcoin_rs_mining::MiningControl for RecordingGenerationControl {
    fn get_block_template(
        &self,
        _request: bitcoin_rs_mining::BlockTemplateRequest,
    ) -> Result<bitcoin_rs_mining::BlockTemplateResult, MiningControlError> {
        Err(generation_unavailable())
    }

    fn mining_info(&self) -> Result<bitcoin_rs_mining::MiningInfo, MiningControlError> {
        Err(generation_unavailable())
    }

    fn network_hash_ps(&self, _lookup: i64, _height: i64) -> Result<f64, MiningControlError> {
        Err(generation_unavailable())
    }

    fn submit_block(
        &self,
        _block: Block,
    ) -> Result<bitcoin_rs_mining::BlockValidationResult, MiningControlError> {
        Err(generation_unavailable())
    }

    fn submit_header(
        &self,
        _header: bitcoin_rs_primitives::Header,
    ) -> Result<(), MiningControlError> {
        Err(generation_unavailable())
    }

    fn publish_generation(&self) {
        *self.published.lock() += 1;
    }

    fn generate(
        &self,
        _request: bitcoin_rs_mining::GenerateRequest,
    ) -> Result<Vec<bitcoin_rs_mining::GeneratedBlock>, MiningControlError> {
        Err(generation_unavailable())
    }
}

/// Failure-injecting undo store: every persist fails, everything else
/// delegates to a real in-memory store.
struct FailingUndoPersist {
    inner: InMemoryUndoStore,
}

impl UndoStore for FailingUndoPersist {
    fn persist_undo(
        &self,
        _height: u32,
        _hash: bitcoin_rs_primitives::Hash256,
        _record: &[u8],
    ) -> Result<(), bitcoin_rs_storage::StorageError> {
        Err(bitcoin_rs_storage::StorageError::backend(
            "injected undo-persist failure",
        ))
    }

    fn load_undo(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<Option<Vec<u8>>, bitcoin_rs_storage::StorageError> {
        self.inner.load_undo(height, hash)
    }

    fn arm_disconnect(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<(), bitcoin_rs_storage::StorageError> {
        self.inner.arm_disconnect(height, hash)
    }

    fn complete_disconnect(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<(), bitcoin_rs_storage::StorageError> {
        self.inner.complete_disconnect(height, hash)
    }

    fn disarm_disconnect(&self) -> Result<(), bitcoin_rs_storage::StorageError> {
        self.inner.disarm_disconnect()
    }

    fn load_disconnect_marker(
        &self,
    ) -> Result<Option<DisconnectMarker>, bitcoin_rs_storage::StorageError> {
        self.inner.load_disconnect_marker()
    }
}

#[cfg(test)]
mod behavior_1;

#[cfg(test)]
mod behavior_2;

#[cfg(test)]
mod behavior_3;

#[cfg(test)]
mod transitions_1;

#[cfg(test)]
mod transitions_2;

#[cfg(test)]
mod transitions_3;

#[cfg(test)]
mod transitions_4;

#[cfg(test)]
mod transitions_5;

#[cfg(test)]
mod validation_1;

#[cfg(test)]
mod validation_2;

#[cfg(test)]
mod validation_3;

#[cfg(test)]
mod validation_4;

#[cfg(test)]
mod validation_5;

#[cfg(test)]
mod persistence_1;

#[cfg(test)]
mod notifications_1;
