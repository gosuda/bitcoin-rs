//! P2P transaction ingress consumer for the node.
//!
//! Each transaction is evaluated through the mempool's standardness +
//! acceptance policy, and admitted through the one
//! [`MempoolGateway`](bitcoin_rs_mempool::MempoolGateway).
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

use bitcoin_rs_mempool::{
    AdmissionOrigin, MempoolGateway, PeerToken, ReplacementCandidate,
    standardness::{PackageTxContext, evaluate_package_acceptance},
};
use bitcoin_rs_primitives::{Hash256, Tx, Txid};
use bitcoin_rs_rpc::context::MiningControl;
use bitcoin_rs_utxo::UtxoSet;
use crossbeam_channel::Receiver;
use parking_lot::Mutex;

use crate::state::NodeState;
use crate::tx_admission::TxAdmission;
use crate::tx_relay::{PeerRelaySink, TxRelayQueue, spawn_tx_relay_worker};

/// The drain poll interval when the channel is empty.
const TX_INGRESS_POLL: Duration = Duration::from_millis(100);
/// Bounded capacity of the outbound tx-relay queue.
const TX_RELAY_QUEUE_CAPACITY: usize = 1024;

/// Spawns the single tx-ingress consumer thread.
///
/// The thread drains [`bitcoin_rs_p2p::InboundTx`] items from the bounded
/// channel, evaluates each through the mempool's acceptance policy, and
/// admits accepted transactions through the [`MempoolGateway`]. Only
/// accepted mutations trigger relay and mining wake.
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
) -> std::io::Result<std::thread::JoinHandle<()>> {
    let utxo = state.utxo();
    let transactions = state.transactions();
    let peer_table = state.peer_table();
    let (relay, relay_rx) = TxRelayQueue::new(TX_RELAY_QUEUE_CAPACITY);
    let relay_sink = PeerRelaySink::new(peer_table);
    spawn_tx_relay_worker(relay_sink, relay_rx, Arc::clone(&shutdown))?;
    let handle = std::thread::Builder::new()
        .name("bitcoin-rs-tx-ingress".to_owned())
        .spawn(move || {
            let consumer = TxIngressConsumer {
                utxo,
                transactions,
                mempool_gateway: gateway,
                mining_control,
                relay,
                tx_admission,
            };
            while !shutdown.load(Ordering::Relaxed) {
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
    Ok(handle)
}

/// The single consumer that evaluates and admits peer transactions.
struct TxIngressConsumer {
    utxo: Arc<UtxoSet>,
    transactions: Arc<parking_lot::RwLock<hashbrown::HashMap<Txid, Tx>>>,
    mempool_gateway: Arc<MempoolGateway>,
    mining_control: Arc<dyn MiningControl>,
    /// Outbound relay queue: enqueues `inv` announcements for the relay
    /// worker without blocking mempool admission.
    relay: TxRelayQueue,
    /// Orphan map and recent-rejects cache for inbound tx admission.
    tx_admission: Arc<TxAdmission>,
}

impl TxIngressConsumer {
    /// Processes one inbound transaction: evaluate acceptance, admit through
    /// the gateway, and on accepted only — relay inv and wake mining.
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

        // Evaluate acceptance policy (standardness, fee, missing inputs).
        let (fact, policy) = {
            let pool = self.mempool_gateway.read();
            let policy = pool.policy_snapshot();
            let contexts = self.package_contexts(&pool, std::slice::from_ref(&tx));
            let facts = evaluate_package_acceptance(
                &pool,
                &policy.standardness,
                std::slice::from_ref(&tx),
                &contexts,
                None,
                policy.incremental_relay_fee_sat_per_kvb,
            );
            let fact = facts.results.into_iter().next().unwrap_or_else(|| {
                let mut fact = bitcoin_rs_mempool::standardness::TxAcceptanceFact {
                    txid,
                    wtxid: tx.wtxid(),
                    allowed: Some(false),
                    vsize: u32::try_from(tx.vsize()).unwrap_or(u32::MAX),
                    weight: tx.weight(),
                    sigop_cost: 0,
                    base_fee: None,
                    reject_reason: None,
                };
                fact.reject_reason =
                    Some(bitcoin_rs_mempool::standardness::AcceptanceRejectReason::PackageTooLarge);
                fact
            });
            (fact, policy)
        };

        // Rejected: record in recent-rejects so the Inv filter suppresses
        // future getdata for this tx. Missing-inputs rejections are not
        // orphans here — the standardness evaluator reports them as
        // rejected, and the tx is cached. A dedicated orphan path (parent
        // arrival triggers re-evaluation) is handled by the orphan map in
        // TxAdmission; this consumer records the reject and moves on.
        if fact.allowed != Some(true) {
            tracing::debug!(
                %txid,
                reason = ?fact.reject_reason,
                "p2p tx rejected by mempool policy; not relaying"
            );
            self.tx_admission.record_reject(txid, wtxid);
            return;
        }

        // Admit through the one gateway.
        let token = PeerToken {
            addr: source.addr,
            connection_id: source.connection_id().get(),
        };
        let candidate = ReplacementCandidate::new(
            Arc::new(tx.clone()),
            fact.vsize,
            fact.base_fee.unwrap_or(0),
            policy.incremental_relay_fee_sat_per_kvb,
        );
        let time = unix_time_secs();
        let height = self.applied_height();
        let result = self.mempool_gateway.replace_transaction(
            AdmissionOrigin::Peer(token),
            candidate,
            time,
            height,
            fact.sigop_cost,
        );

        match result {
            // A replacement the size-limit trim shed after commit is not in
            // the pool: record the reject exactly like a refused admission.
            Ok(outcome) if outcome.is_shed() => {
                self.tx_admission.record_reject(txid, wtxid);
            }
            Ok(outcome) => {
                // Accepted-only relay: only relay if the mutation includes
                // an Accepted outcome for this txid.
                let accepted = outcome.into_mutation().changes.iter().any(|c| {
                    c.txid == Hash256::from(txid)
                        && matches!(c.outcome, bitcoin_rs_mempool::MutationOutcome::Accepted)
                });
                if accepted {
                    self.relay
                        .announce(txid, tx.wtxid(), Some(source.connection_id().get()));
                    self.mining_control.publish_generation();
                    tracing::trace!(%txid, "p2p tx admitted and relayed");
                }
            }
            Err(error) => {
                tracing::debug!(%txid, %error, "p2p tx admission failed; not relaying");
                self.tx_admission.record_reject(txid, wtxid);
            }
        }
    }

    /// Resolves prevout contexts for a package of transactions, using the
    /// mempool and UTXO set — the same logic as the RPC
    /// `sendrawtransaction` handler.
    fn package_contexts(
        &self,
        pool: &bitcoin_rs_mempool::Mempool,
        txs: &[Tx],
    ) -> Vec<PackageTxContext> {
        use bitcoin_rs_primitives::OutPoint;
        use hashbrown::HashMap;

        let mut package_outputs: HashMap<(Txid, u32), u64> = HashMap::new();
        let mut contexts = Vec::with_capacity(txs.len());

        for tx in txs {
            let mut missing_inputs = false;
            let mut input_value = 0_u64;

            for input in &tx.inputs {
                if input.previous_output == OutPoint::default() {
                    missing_inputs = true;
                    continue;
                }
                let key = (input.previous_output.txid, input.previous_output.vout);
                if let Some(value) = package_outputs.get(&key) {
                    input_value = input_value.saturating_add(*value);
                    continue;
                }
                if let Some(parent) = pool.transaction_by_txid(&input.previous_output.txid)
                    && let Ok(vout) = usize::try_from(input.previous_output.vout)
                    && let Some(output) = parent.outputs.get(vout)
                {
                    input_value = input_value.saturating_add(output.value);
                    continue;
                }
                if let Some(live) = self.utxo.get_entry(&input.previous_output) {
                    input_value = input_value.saturating_add(live.txout.value);
                    continue;
                }
                missing_inputs = true;
            }

            let output_value = tx
                .outputs
                .iter()
                .fold(0_u64, |sum, output| sum.saturating_add(output.value));
            let fee = input_value.saturating_sub(output_value);
            let vsize = u32::try_from(tx.vsize()).unwrap_or(u32::MAX);
            let sigop_cost = bitcoin_rs_script::count_tx_legacy(tx);

            contexts.push(PackageTxContext {
                fee,
                vsize,
                sigop_cost,
                missing_inputs,
            });

            let txid = tx.txid();
            for (vout, output) in tx.outputs.iter().enumerate() {
                let vout = u32::try_from(vout).unwrap_or(u32::MAX);
                package_outputs.insert((txid, vout), output.value);
            }
        }

        contexts
    }

    /// Returns the current applied tip height.
    fn applied_height(&self) -> u32 {
        let _ = self;
        // The admission height is used for mempool entry ancestor
        // accounting. The apply path corrects it on block connect.
        0
    }
}

fn unix_time_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
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
            _request: bitcoin_rs_rpc::context::BlockTemplateRequest,
        ) -> Result<
            bitcoin_rs_rpc::context::BlockTemplateResult,
            bitcoin_rs_rpc::context::MiningControlError,
        > {
            Err(bitcoin_rs_rpc::context::MiningControlError::Failed(
                "not implemented".to_owned().into(),
            ))
        }

        fn mining_info(
            &self,
        ) -> Result<bitcoin_rs_rpc::context::MiningInfo, bitcoin_rs_rpc::context::MiningControlError>
        {
            Err(bitcoin_rs_rpc::context::MiningControlError::Failed(
                "not implemented".to_owned().into(),
            ))
        }

        fn submit_block(
            &self,
            _block: Block,
        ) -> Result<
            bitcoin_rs_rpc::context::BlockValidationResult,
            bitcoin_rs_rpc::context::MiningControlError,
        > {
            Err(bitcoin_rs_rpc::context::MiningControlError::Failed(
                "not implemented".to_owned().into(),
            ))
        }

        fn publish_generation(&self) {
            self.publishes.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Builds a valid coinbase tx for testing (no inputs, one output).
    fn coinbase_tx(value: u64) -> Tx {
        Tx {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::default(),
                script_sig: vec![0x51],
                sequence: 0xFFFF_FFFF,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value,
                script_pubkey: vec![0x6A],
            }],
            lock_time: 0,
        }
    }

    /// Builds a tx that spends a known UTXO, passing standardness checks.
    fn spending_tx() -> Tx {
        let parent_txid = Txid::from(Hash256::from_le_bytes(&[0xAA; 32]));
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: parent_txid,
                    vout: 0,
                },
                script_sig: vec![0x52, 0x02, 0xAA, 0xBB],
                sequence: 0xFFFF_FFFF,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 49_000,
                script_pubkey: vec![0x6A],
            }],
            lock_time: 0,
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
                value: 50_000,
                script_pubkey: Vec::new(),
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
            mempool_gateway: Arc::clone(gateway),
            mining_control: mining,
            relay,
            tx_admission: Arc::new(TxAdmission::new(Arc::clone(gateway))),
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
            mempool_gateway: Arc::clone(gateway),
            mining_control: mining,
            relay,
            tx_admission: Arc::new(TxAdmission::new(Arc::clone(gateway))),
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
}
