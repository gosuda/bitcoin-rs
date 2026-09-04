//! P2P transaction ingress consumer for the node.
//!
//! Each transaction is admitted through the one
//! [`MempoolGateway::admit_transaction`](bitcoin_rs_mempool::MempoolGateway::admit_transaction)
//! path RPC uses: policy, then consensus verification under
//! [`VerifyFlags::STANDARD`](bitcoin_rs_script::VerifyFlags), then insert.
//!
//! # Ordering and side effects
//!
//! Admission commits before any relay or mining wake. Only an accepted
//! mutation triggers relay (an `inv` announcement to peers) and a mining
//! template wake (`publish_generation`). Rejected, duplicate, and
//! conflicting admissions produce neither side effect — the consumer
//! drops the transaction silently, matching Core's relay policy for
//! peer-submitted transactions that fail acceptance.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::{BlockTree, TipSnapshot};
use bitcoin_rs_mempool::{
    AdmissionOrigin, AdmissionRequest, AdmitError, AdmitOutcome, MempoolGateway, PeerToken,
    standardness::{PackageTxContext, is_standard_tx},
};
use bitcoin_rs_mining::MiningControl;
use bitcoin_rs_primitives::{
    Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxOut, Txid, Witness,
};
use bitcoin_rs_utxo::UtxoSet;
use crossbeam_channel::Receiver;
use hashbrown::HashMap;
use parking_lot::{Mutex, RwLock};

use crate::state::NodeState;
use crate::tx_admission::TxAdmission;
use crate::tx_relay::{PeerRelaySink, TxRelayQueue, spawn_tx_relay_worker};

/// The drain poll interval when the channel is empty.
const TX_INGRESS_POLL: Duration = Duration::from_millis(100);
/// Bounded capacity of the outbound tx-relay queue.
const TX_RELAY_QUEUE_CAPACITY: usize = 1024;
/// Same generation/sequence retry budget as RPC `sendrawtransaction`.
const MAX_ADMISSION_RETRIES: usize = 4;

/// Join handles and the shared relay queue returned by
/// [`spawn_tx_ingress_consumer`].
pub struct TxIngressHandles {
    /// The ingress consumer thread.
    pub ingress: std::thread::JoinHandle<()>,
    /// The outbound `inv` relay worker started by the same spawn.
    pub relay: std::thread::JoinHandle<()>,
    /// Cloneable producer side of the relay queue. Production startup
    /// attaches this to the gateway observer so RPC-admitted transactions
    /// announce through the same worker.
    pub queue: TxRelayQueue,
}

/// Spawns the single tx-ingress consumer thread.
///
/// The thread drains [`bitcoin_rs_p2p::InboundTx`] items from the bounded
/// channel and admits each through [`MempoolGateway::admit_transaction`].
/// Only accepted mutations trigger relay and mining wake.
///
/// # Arguments
///
/// * `state` — the shared node state (borrows utxo, transactions, peers).
/// * `gateway` — the one mempool gateway (shared with RPC and apply paths).
/// * `mining_control` — the mining coordinator for template wake.
/// * `shutdown` — the process-wide shutdown flag.
/// * `tx_rx` — the shared bounded receiver for inbound peer transactions.
pub fn spawn_tx_ingress_consumer(
    state: &NodeState,
    gateway: Arc<MempoolGateway>,
    mining_control: Arc<dyn MiningControl>,
    shutdown: Arc<AtomicBool>,
    tx_rx: Arc<Mutex<Receiver<bitcoin_rs_p2p::InboundTx>>>,
    tx_admission: Arc<TxAdmission>,
) -> std::io::Result<TxIngressHandles> {
    let utxo = state.utxo();
    let transactions = state.transactions();
    let peer_table = state.peer_table();
    let applied_tip = state.applied_tip();
    let block_tree = state.block_tree();
    let (relay, relay_rx) = TxRelayQueue::new(TX_RELAY_QUEUE_CAPACITY);
    let relay_sink = PeerRelaySink::new(Arc::clone(&peer_table));
    let relay_handle = spawn_tx_relay_worker(relay_sink, relay_rx, Arc::clone(&shutdown))?;
    let queue = relay.clone();
    let handle = std::thread::Builder::new()
        .name("bitcoin-rs-tx-ingress".to_owned())
        .spawn(move || {
            let consumer = TxIngressConsumer {
                utxo,
                transactions,
                peer_table,
                mempool_gateway: gateway,
                mining_control,
                relay,
                tx_admission,
                applied_tip,
                block_tree,
            };
            while !shutdown.load(Ordering::Relaxed) {
                loop {
                    let retries = consumer.tx_admission.take_orphan_retries();
                    if retries.is_empty() {
                        break;
                    }
                    for (tx, source) in retries {
                        consumer.process_one(bitcoin_rs_p2p::InboundTx::new((*tx).clone(), source));
                    }
                }
                let recv = {
                    let guard = tx_rx.lock();
                    guard.recv_timeout(TX_INGRESS_POLL)
                };
                match recv {
                    Ok(inbound) => {
                        consumer.process_one(inbound);
                    }
                    Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
                    Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
                }
            }
        })?;
    Ok(TxIngressHandles {
        ingress: handle,
        relay: relay_handle,
        queue,
    })
}

/// The single consumer that evaluates and admits peer transactions.
struct TxIngressConsumer {
    utxo: Arc<UtxoSet>,
    transactions: Arc<parking_lot::RwLock<hashbrown::HashMap<Txid, Tx>>>,
    peer_table: Arc<bitcoin_rs_p2p::PeerTable>,
    mempool_gateway: Arc<MempoolGateway>,
    mining_control: Arc<dyn MiningControl>,
    /// Outbound relay queue: enqueues `inv` announcements for the relay
    /// worker without blocking mempool admission.
    relay: TxRelayQueue,
    /// Orphan map and recent-rejects cache for inbound tx admission.
    tx_admission: Arc<TxAdmission>,
    /// Applied chain tip; admission height and median-time-past follow this.
    applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    block_tree: Arc<RwLock<BlockTree>>,
}

impl TxIngressConsumer {
    /// Processes one inbound transaction: admit through the gateway, and on
    /// accepted only — relay inv and wake mining.
    fn process_one(&self, inbound: bitcoin_rs_p2p::InboundTx) {
        let tx = inbound.tx;
        let source = inbound.source;
        let txid = tx.txid();
        let wtxid = tx.wtxid();

        // Recent-rejects: skip re-evaluation of a tx we already rejected.
        // The Inv filter also suppresses getdata for these, but a tx may
        // arrive through a relay path that bypassed the filter.
        if self.tx_admission.is_rejected(Hash256::from(txid))
            || self.tx_admission.is_rejected(Hash256::from(wtxid))
        {
            tracing::trace!(%txid, "p2p tx in recent-rejects; skipping");
            return;
        }

        // Already in mempool: silently succeed, no relay (Core does not
        // re-announce known transactions).
        {
            let pool = self.mempool_gateway.read();
            if pool.contains_txid(&txid) {
                tracing::trace!(%txid, "p2p tx already in mempool; skipping");
                return;
            }
        }

        // Already confirmed: silently drop.
        if self.transactions.read().contains_key(&txid) {
            tracing::trace!(%txid, "p2p tx already confirmed; skipping");
            return;
        }

        self.admit_and_relay(tx, source, txid, wtxid);
    }

    fn reject_or_hold_orphan(
        &self,
        tx: Tx,
        source: bitcoin_rs_p2p::PeerSource,
        txid: Txid,
        wtxid: bitcoin_rs_primitives::Wtxid,
        reason: Option<bitcoin_rs_mempool::standardness::AcceptanceRejectReason>,
    ) {
        if matches!(
            reason,
            Some(bitcoin_rs_mempool::standardness::AcceptanceRejectReason::MissingInputs)
        ) {
            if is_coinbase(&tx) {
                tracing::debug!(%txid, "p2p coinbase rejected; not held as orphan");
                self.tx_admission.record_reject(txid, wtxid);
                return;
            }
            let policy = self.mempool_gateway.read().policy_snapshot();
            if let Err(error) = is_standard_tx(&tx, &policy.standardness) {
                tracing::debug!(
                    %txid,
                    %error,
                    "p2p missing-input tx failed standardness; not held as orphan"
                );
                self.tx_admission.record_reject(txid, wtxid);
                return;
            }
            let held = Arc::new(tx);
            self.tx_admission.record_orphan(&held, source);
            self.request_missing_parents(&held, source);
            tracing::debug!(%txid, "p2p tx missing inputs; held as orphan");
            return;
        }
        tracing::debug!(%txid, ?reason, "p2p tx rejected by mempool policy; not relaying");
        self.tx_admission.record_reject(txid, wtxid);
    }

    fn admit_and_relay(
        &self,
        tx: Tx,
        source: bitcoin_rs_p2p::PeerSource,
        txid: Txid,
        wtxid: bitcoin_rs_primitives::Wtxid,
    ) {
        let token = PeerToken {
            addr: source.addr,
            connection_id: source.connection_id().get(),
        };
        let origin = AdmissionOrigin::Peer(token);
        let tx = Arc::new(tx);
        for _ in 0..MAX_ADMISSION_RETRIES {
            let Some(generation) = self.mempool_gateway.stable_generation() else {
                continue;
            };
            let (sequence, mempool_prevouts) = {
                let pool = self.mempool_gateway.read();
                if pool.contains_txid(&txid) {
                    return;
                }
                (pool.sequence_number(), resolve_mempool_prevouts(&pool, &tx))
            };
            let (context, prevouts) = self.resolve_full_context(&tx, &mempool_prevouts);
            if context.missing_inputs {
                self.reject_or_hold_orphan(
                    (*tx).clone(),
                    source,
                    txid,
                    wtxid,
                    Some(bitcoin_rs_mempool::standardness::AcceptanceRejectReason::MissingInputs),
                );
                return;
            }
            let request = AdmissionRequest {
                tx: Arc::clone(&tx),
                context,
                prevouts,
                locktime_cutoff: self.locktime_cutoff(),
                max_feerate_sat_per_kvb: None,
                time: unix_time_secs(),
                height: self.applied_height(),
                origin,
                expected_generation: generation,
                expected_sequence: sequence,
            };
            match self.mempool_gateway.admit_transaction(request) {
                Ok(AdmitOutcome::Committed(result)) => {
                    let accepted = result.changes.iter().any(|change| {
                        change.txid == Hash256::from(txid)
                            && matches!(
                                change.outcome,
                                bitcoin_rs_mempool::MutationOutcome::Accepted
                            )
                    });
                    if accepted {
                        self.relay
                            .announce(txid, wtxid, Some(source.connection_id().get()));
                        self.mining_control.publish_generation();
                        tracing::trace!(%txid, "p2p tx admitted and relayed");
                    }
                    return;
                }
                Ok(AdmitOutcome::AlreadyKnown) => return,
                Err(AdmitError::GenerationChanged | AdmitError::MempoolChanged) => continue,
                Err(AdmitError::Policy(
                    bitcoin_rs_mempool::standardness::AcceptanceRejectReason::MissingInputs,
                )) => {
                    self.reject_or_hold_orphan(
                        (*tx).clone(),
                        source,
                        txid,
                        wtxid,
                        Some(
                            bitcoin_rs_mempool::standardness::AcceptanceRejectReason::MissingInputs,
                        ),
                    );
                    return;
                }
                Err(AdmitError::Policy(reason)) => {
                    tracing::debug!(%txid, %reason, "p2p tx rejected by mempool policy; not relaying");
                    self.tx_admission.record_reject(txid, wtxid);
                    return;
                }
                Err(AdmitError::Consensus) => {
                    tracing::debug!(%txid, "p2p tx failed consensus verification; not relaying");
                    self.tx_admission.record_reject(txid, wtxid);
                    return;
                }
            }
        }
        tracing::debug!(%txid, "p2p tx admission retry exhausted; not relaying");
    }

    /// Combines mempool-dependent prevouts (captured under a read guard) with
    /// UTXO-set prevouts (resolved without a pool guard).
    fn resolve_full_context(
        &self,
        tx: &Tx,
        mempool_prevouts: &HashMap<OutPoint, TxOut>,
    ) -> (PackageTxContext, Vec<(OutPoint, TxOut)>) {
        let mut missing_inputs = false;
        let mut input_value = 0_u64;
        let mut prevouts: Vec<(OutPoint, TxOut)> = Vec::new();

        for input in &tx.inputs {
            if input.previous_output == OutPoint::default() || input.previous_output.is_null() {
                missing_inputs = true;
                continue;
            }
            if let Some(output) = mempool_prevouts.get(&input.previous_output) {
                input_value = input_value.saturating_add(output.value.to_sat());
                prevouts.push((input.previous_output, output.clone()));
                continue;
            }
            if let Some(live) = self.utxo.get_entry(&input.previous_output) {
                input_value = input_value.saturating_add(live.txout.value.to_sat());
                prevouts.push((input.previous_output, live.txout.clone()));
                continue;
            }
            missing_inputs = true;
        }

        let output_value = tx.outputs.iter().fold(0_u64, |sum, output| {
            sum.saturating_add(output.value.to_sat())
        });
        let fee = input_value.saturating_sub(output_value);
        let vsize = u32::try_from(tx.vsize()).unwrap_or(u32::MAX);
        let sigop_cost = bitcoin_rs_script::count_tx_legacy(tx);

        (
            PackageTxContext {
                fee,
                vsize,
                sigop_cost,
                missing_inputs,
            },
            prevouts,
        )
    }

    /// Asks the delivering peer for each missing parent via `getdata`.
    ///
    /// Prevouts only carry the parent txid, so the request is always
    /// txid-typed even when the peer negotiated BIP339.
    fn request_missing_parents(&self, tx: &Tx, source: bitcoin_rs_p2p::PeerSource) {
        use bitcoin::p2p::message_blockdata::Inventory;

        let Some(lease) = self.peer_table.lease(source.addr) else {
            return;
        };
        if !lease.is_current(source) {
            return;
        }
        let mut parent_ids = hashbrown::HashSet::new();
        {
            let pool = self.mempool_gateway.read();
            for input in &tx.inputs {
                let prevout = input.previous_output;
                if prevout.is_null() || prevout == OutPoint::default() {
                    continue;
                }
                if pool.contains_txid(&prevout.txid) || self.utxo.get_entry(&prevout).is_some() {
                    continue;
                }
                parent_ids.insert(prevout.txid);
            }
        }
        let items: Vec<Inventory> = parent_ids
            .into_iter()
            .map(|txid| {
                Inventory::Transaction(bitcoin::hashes::Hash::from_byte_array(*txid.as_bytes()))
            })
            .collect();
        if items.is_empty() {
            return;
        }
        if let Err(error) = lease.send(bitcoin_rs_p2p::Message::GetData(items)) {
            tracing::debug!(
                peer_addr = %source.addr,
                %error,
                "orphan parent getdata not sent"
            );
        }
    }

    /// Returns the current applied tip height.
    fn applied_height(&self) -> u32 {
        self.applied_tip.load().as_ref().map_or(0, |tip| tip.height)
    }

    /// Median-time-past of the applied tip for BIP113 finality, or zero
    /// when no tip is published.
    fn locktime_cutoff(&self) -> u32 {
        let Some(tip) = self.applied_tip.load_full() else {
            return 0;
        };
        self.block_tree
            .read()
            .median_time_past_at(tip.tip_id, 11)
            .unwrap_or(0)
    }
}

fn resolve_mempool_prevouts(
    pool: &bitcoin_rs_mempool::Mempool,
    tx: &Tx,
) -> HashMap<OutPoint, TxOut> {
    let mut prevouts = HashMap::new();
    for input in &tx.inputs {
        if input.previous_output == OutPoint::default() || input.previous_output.is_null() {
            continue;
        }
        if let Some(parent) = pool.transaction_by_txid(&input.previous_output.txid)
            && let Ok(vout) = usize::try_from(input.previous_output.vout)
            && let Some(output) = parent.outputs.get(vout)
        {
            prevouts.insert(input.previous_output, output.clone());
        }
    }
    prevouts
}

fn unix_time_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Core's `IsCoinBase`: one input spending the null prevout.
fn is_coinbase(tx: &Tx) -> bool {
    tx.inputs.len() == 1 && tx.inputs[0].previous_output.is_null()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use bitcoin_rs_mempool::{
        Mempool, MempoolEntry, MempoolLimits, MempoolObserver, MutationEnvelope, MutationOutcome,
    };
    use bitcoin_rs_primitives::{Block, OutPoint, TxIn, TxOut};
    use parking_lot::{Mutex, RwLock};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::AtomicUsize;
    /// A recording mining control that counts `publish_generation` calls.
    struct RecordingMining {
        publishes: AtomicUsize,
    }

    impl RecordingMining {
        fn new() -> Self {
            Self {
                publishes: AtomicUsize::new(0),
            }
        }

        fn publish_count(&self) -> usize {
            self.publishes.load(Ordering::Relaxed)
        }
    }

    impl MiningControl for RecordingMining {
        fn get_block_template(
            &self,
            _request: bitcoin_rs_mining::BlockTemplateRequest,
        ) -> Result<bitcoin_rs_mining::BlockTemplateResult, bitcoin_rs_mining::MiningControlError>
        {
            Err(bitcoin_rs_mining::MiningControlError::Failed(
                "not implemented".to_owned().into(),
            ))
        }

        fn mining_info(
            &self,
        ) -> Result<bitcoin_rs_mining::MiningInfo, bitcoin_rs_mining::MiningControlError> {
            Err(bitcoin_rs_mining::MiningControlError::Failed(
                "not implemented".to_owned().into(),
            ))
        }

        fn network_hash_ps(
            &self,
            _lookup: i64,
            _height: i64,
        ) -> Result<f64, bitcoin_rs_mining::MiningControlError> {
            Err(bitcoin_rs_mining::MiningControlError::Failed(
                "not implemented".to_owned().into(),
            ))
        }

        fn submit_block(
            &self,
            _block: Block,
        ) -> Result<bitcoin_rs_mining::BlockValidationResult, bitcoin_rs_mining::MiningControlError>
        {
            Err(bitcoin_rs_mining::MiningControlError::Failed(
                "not implemented".to_owned().into(),
            ))
        }

        fn publish_generation(&self) {
            self.publishes.fetch_add(1, Ordering::Relaxed);
        }

        fn generate(
            &self,
            _request: bitcoin_rs_mining::GenerateRequest,
        ) -> Result<Vec<bitcoin_rs_mining::GeneratedBlock>, bitcoin_rs_mining::MiningControlError>
        {
            Err(bitcoin_rs_mining::MiningControlError::Failed(
                "not implemented".to_owned().into(),
            ))
        }
    }

    /// Builds a valid coinbase tx for testing (no inputs, one output).
    fn coinbase_tx(value: u64) -> Tx {
        Tx {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::default(),
                script_sig: vec![0x51].into(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(value),
                script_pubkey: vec![0x6A].into(),
            }],
            lock_time: LockTime::ZERO,
        }
    }

    /// Builds a tx that spends a known UTXO, passing standardness and
    /// script checks. Empty `scriptSig` plus an `OP_TRUE` prevout satisfy
    /// `SCRIPT_VERIFY_CLEANSTACK`; the `OP_RETURN` payload pads the
    /// non-witness size to the 65-byte standardness floor.
    fn spending_tx() -> Tx {
        let parent_txid = Txid::from(Hash256::from_le_bytes(&[0xAA; 32]));
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: parent_txid,
                    vout: 0,
                },
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: vec![0x6A, 0x04, 0xAA, 0xBB, 0xCC, 0xDD].into(),
            }],
            lock_time: LockTime::ZERO,
        }
    }

    /// Creates a consumer with a pre-funded UTXO so `spending_tx` passes
    /// standardness (`missing-inputs`) checks.
    fn make_consumer_with_utxo(
        gateway: &Arc<MempoolGateway>,
        mining: Arc<RecordingMining>,
    ) -> TxIngressConsumer {
        use bitcoin_rs_utxo::{BlockChanges, UtxoAdd};
        let utxo = Arc::new(UtxoSet::new());
        let parent_txid = Txid::from(Hash256::from_le_bytes(&[0xAA; 32]));
        let mut changes = BlockChanges::with_capacity(1, 0);
        changes.add(UtxoAdd::new(
            OutPoint {
                txid: parent_txid,
                vout: 0,
            },
            TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: vec![0x51].into(),
            },
            false,
            100,
        ));
        utxo.commit_block(&changes, &Hash256::from_le_bytes(&[0xBB; 32]))
            .expect("utxo commit must succeed");
        let transactions = Arc::new(RwLock::new(hashbrown::HashMap::new()));
        let (relay, _relay_rx) = TxRelayQueue::new(TX_RELAY_QUEUE_CAPACITY);
        TxIngressConsumer {
            utxo,
            transactions,
            peer_table: Arc::new(bitcoin_rs_p2p::PeerTable::new()),
            mempool_gateway: Arc::clone(gateway),
            mining_control: mining,
            relay,
            tx_admission: Arc::new(TxAdmission::new(Arc::clone(gateway))),
            applied_tip: Arc::new(ArcSwapOption::empty()),
            block_tree: Arc::new(RwLock::new(BlockTree::new())),
        }
    }

    /// Builds a `PeerSource` for testing.
    fn test_source() -> bitcoin_rs_p2p::PeerSource {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18_333);
        let lease = bitcoin_rs_p2p::PeerLease::new(
            crossbeam_channel::unbounded::<bitcoin_rs_p2p::Message>().0,
        );
        lease.source(addr)
    }

    /// Creates a minimal consumer for testing.
    fn make_consumer(
        gateway: &Arc<MempoolGateway>,
        mining: Arc<RecordingMining>,
    ) -> TxIngressConsumer {
        let utxo = Arc::new(UtxoSet::new());
        let transactions = Arc::new(RwLock::new(hashbrown::HashMap::new()));
        let (relay, _relay_rx) = TxRelayQueue::new(TX_RELAY_QUEUE_CAPACITY);
        TxIngressConsumer {
            utxo,
            transactions,
            peer_table: Arc::new(bitcoin_rs_p2p::PeerTable::new()),
            mempool_gateway: Arc::clone(gateway),
            mining_control: mining,
            relay,
            tx_admission: Arc::new(TxAdmission::new(Arc::clone(gateway))),
            applied_tip: Arc::new(ArcSwapOption::empty()),
            block_tree: Arc::new(RwLock::new(BlockTree::new())),
        }
    }

    /// Test: the consumer carries the exact originating `ConnectionId` through
    /// to the admission gateway. A mutation admitted from a peer must carry
    /// the `PeerToken` with the correct `connection_id`.
    #[test]
    fn consumer_preserves_exact_connection_id() {
        struct OriginRecorder {
            captured: Arc<Mutex<Option<bitcoin_rs_mempool::AdmissionOrigin>>>,
        }
        impl MempoolObserver for OriginRecorder {
            fn on_mutation(&self, envelope: &MutationEnvelope) {
                if envelope
                    .result
                    .changes
                    .iter()
                    .any(|c| matches!(c.outcome, MutationOutcome::Accepted))
                {
                    *self.captured.lock() = Some(envelope.origin);
                }
            }
        }
        let pool = Arc::new(RwLock::new(Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            ..MempoolLimits::default()
        })));

        let recorded_origin = Arc::new(Mutex::new(None));
        let gateway = MempoolGateway::shared_with(
            Arc::clone(&pool),
            Arc::new(OriginRecorder {
                captured: Arc::clone(&recorded_origin),
            }),
        );

        let source = test_source();
        let expected_conn_id = source.connection_id();

        let tx = spending_tx();
        let inbound = bitcoin_rs_p2p::InboundTx::new(tx, source);

        let mining = Arc::new(RecordingMining::new());
        let consumer = make_consumer_with_utxo(&gateway, mining);

        consumer.process_one(inbound);

        let origin = recorded_origin.lock().take();
        assert!(
            origin.is_some(),
            "an accepted mutation must publish an origin"
        );
        if let Some(bitcoin_rs_mempool::AdmissionOrigin::Peer(token)) = origin {
            assert_eq!(
                token.connection_id,
                expected_conn_id.get(),
                "the admission origin must carry the exact ConnectionId from the delivering peer"
            );
        } else {
            panic!("accepted peer tx must carry AdmissionOrigin::Peer");
        }
    }

    /// Test: a rejected transaction does not relay and does not wake mining.
    #[test]
    fn rejected_tx_does_not_relay_or_wake_mining() {
        let pool = Arc::new(RwLock::new(Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 1_000_000,
            ..MempoolLimits::default()
        })));
        let gateway = MempoolGateway::shared(Arc::clone(&pool));

        let source = test_source();
        let tx = coinbase_tx(50_000);
        let inbound = bitcoin_rs_p2p::InboundTx::new(tx, source);

        let mining = Arc::new(RecordingMining::new());
        let consumer = make_consumer(&gateway, Arc::clone(&mining));

        consumer.process_one(inbound);

        assert_eq!(
            mining.publish_count(),
            0,
            "rejected tx must not wake mining"
        );
    }

    /// Test: a duplicate transaction (already in mempool) does not relay
    /// and does not wake mining.
    #[test]
    fn duplicate_tx_does_not_relay_or_wake_mining() {
        let pool = Arc::new(RwLock::new(Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            ..MempoolLimits::default()
        })));
        let gateway = MempoolGateway::shared(Arc::clone(&pool));

        let tx = coinbase_tx(50_000);
        let txid = tx.txid();
        let entry = MempoolEntry::new(Arc::new(tx.clone()), 100, 0, 1, 0);
        gateway.insert_entry(AdmissionOrigin::Rpc, entry).unwrap();

        let source = test_source();
        let inbound = bitcoin_rs_p2p::InboundTx::new(tx, source);

        let mining = Arc::new(RecordingMining::new());
        let consumer = make_consumer(&gateway, Arc::clone(&mining));

        consumer.process_one(inbound);

        assert_eq!(
            mining.publish_count(),
            0,
            "duplicate tx must not wake mining"
        );
        assert!(
            gateway.read().contains_txid(&txid),
            "the original entry must still be in the mempool"
        );
    }

    /// Test: an accepted transaction does relay and wake mining.
    #[test]
    fn accepted_tx_relays_and_wakes_mining() {
        let pool = Arc::new(RwLock::new(Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            ..MempoolLimits::default()
        })));
        let gateway = MempoolGateway::shared(Arc::clone(&pool));

        let source = test_source();
        let tx = spending_tx();
        let inbound = bitcoin_rs_p2p::InboundTx::new(tx, source);

        let mining = Arc::new(RecordingMining::new());
        let consumer = make_consumer_with_utxo(&gateway, Arc::clone(&mining));

        consumer.process_one(inbound);

        assert_eq!(
            mining.publish_count(),
            1,
            "accepted tx must wake mining exactly once"
        );
    }

    #[test]
    fn coinbase_is_rejected_not_orphaned() {
        let pool = Arc::new(RwLock::new(Mempool::new(MempoolLimits::default())));
        let gateway = MempoolGateway::shared(Arc::clone(&pool));
        let mining = Arc::new(RecordingMining::new());
        let consumer = make_consumer(&gateway, mining);
        let coinbase = Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid::default(), u32::MAX),
                script_sig: vec![0x00].into(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: vec![0x6A].into(),
            }],
            lock_time: LockTime::ZERO,
        };
        let txid = coinbase.txid();
        consumer.process_one(bitcoin_rs_p2p::InboundTx::new(coinbase, test_source()));
        assert_eq!(
            consumer.tx_admission.orphan_count(),
            0,
            "a peer coinbase must not consume orphan quota"
        );
        assert!(
            consumer.tx_admission.is_rejected(Hash256::from(txid)),
            "a peer coinbase must enter recent-rejects"
        );
    }

    #[test]
    fn non_final_tx_is_rejected_not_admitted() {
        let pool = Arc::new(RwLock::new(Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            ..MempoolLimits::default()
        })));
        let gateway = MempoolGateway::shared(Arc::clone(&pool));
        let mining = Arc::new(RecordingMining::new());
        let consumer = make_consumer_with_utxo(&gateway, mining);
        let mut tx = spending_tx();
        tx.lock_time = LockTime::from_consensus(100);
        tx.inputs[0].sequence = Sequence::from_consensus(0xFFFF_FFFE);
        let txid = tx.txid();
        consumer.process_one(bitcoin_rs_p2p::InboundTx::new(tx, test_source()));
        assert!(
            !gateway.read().contains_txid(&txid),
            "a non-final peer tx must not enter the mempool"
        );
        assert!(
            consumer.tx_admission.is_rejected(Hash256::from(txid)),
            "a non-final peer tx must enter recent-rejects"
        );
    }

    #[test]
    fn oversized_missing_input_tx_is_rejected_not_orphaned() {
        let pool = Arc::new(RwLock::new(Mempool::new(MempoolLimits::default())));
        let gateway = MempoolGateway::shared(Arc::clone(&pool));
        let mining = Arc::new(RecordingMining::new());
        let consumer = make_consumer(&gateway, mining);
        let parent = Txid::from(Hash256::from_le_bytes(&[0xCC; 32]));
        // Witness counts 1× toward BIP141 weight. A 400_000-byte stack
        // item puts the body over the 400k standard cap so MissingInputs
        // cannot consume orphan quota.
        let tx = Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(parent, 0),
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: vec![vec![0; 400_000]].into(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: vec![0x6A, 0x04, 0xAA, 0xBB, 0xCC, 0xDD].into(),
            }],
            lock_time: LockTime::ZERO,
        };
        assert!(
            tx.weight() > 400_000,
            "the fixture must exceed MAX_STANDARD_TX_WEIGHT"
        );
        let txid = tx.txid();
        consumer.process_one(bitcoin_rs_p2p::InboundTx::new(tx, test_source()));
        assert_eq!(
            consumer.tx_admission.orphan_count(),
            0,
            "a non-standard missing-input body must not consume orphan quota"
        );
        assert!(
            consumer.tx_admission.is_rejected(Hash256::from(txid)),
            "a non-standard missing-input body must enter recent-rejects"
        );
    }
}
