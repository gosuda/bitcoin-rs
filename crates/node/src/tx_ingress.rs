//! Wires inbound peer transactions to mempool admission and committed outcomes.
//!
//! Mempool owns preparation, policy, orphan/reject state and retry progress.
//! P2P owns inventory, parent requests and the bounded relay worker. This loop
//! owns only channel draining and ordering admission results before consumers.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::{BlockTree, TipSnapshot};
use bitcoin_rs_mempool::{AdmissionOrigin, MempoolGateway, PeerToken, SubmitError, SubmitOutcome};
use bitcoin_rs_mining::MiningControl;
use bitcoin_rs_p2p::TxRelayQueue;
use bitcoin_rs_primitives::{Hash256, Txid, Wtxid};
use bitcoin_rs_rpc::context::ChainAdmissionView;
use bitcoin_rs_utxo::UtxoSet;
use crossbeam_channel::Receiver;
use parking_lot::{Mutex, RwLock};

use crate::state::NodeState;

/// Empty ingress polling also gives mempool-owned ready work a bounded wake.
const TX_INGRESS_POLL: Duration = Duration::from_millis(100);

/// Starts the ingress consumer over an already-owned P2P relay queue.
///
/// The caller registers each worker with teardown immediately after spawning.
/// A later startup failure therefore cannot lose an earlier worker's handle.
pub fn spawn_tx_ingress_consumer(
    state: &NodeState,
    gateway: Arc<MempoolGateway>,
    mining_control: Arc<dyn MiningControl>,
    shutdown: Arc<AtomicBool>,
    tx_rx: Arc<Mutex<Receiver<bitcoin_rs_p2p::InboundTx>>>,
    relay: TxRelayQueue,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    let consumer = TxIngressConsumer {
        utxo: state.utxo(),
        peer_table: state.peer_table(),
        mempool_gateway: gateway,
        mining_control,
        relay,
        applied_tip: state.applied_tip(),
        block_tree: state.block_tree(),
    };
    std::thread::Builder::new()
        .name("bitcoin-rs-tx-ingress".to_owned())
        .spawn(move || {
            while !shutdown.load(Ordering::Relaxed) {
                // One bounded pass: transient retries remain with mempool and
                // cannot starve fresh ingress or shutdown by spinning here.
                let made_progress = consumer.process_retries();
                // A committed retry may have readied the next generation of
                // children. Yield to ingress, then continue without imposing
                // one poll interval per dependency level. Transient failures
                // still wait, and shutdown is checked on every bounded pass.
                let timeout = if made_progress {
                    Duration::ZERO
                } else {
                    TX_INGRESS_POLL
                };
                let recv = tx_rx.lock().recv_timeout(timeout);
                match recv {
                    Ok(inbound) => consumer.process_one(inbound),
                    Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
                    Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
                }
            }
        })
}

struct TxIngressConsumer {
    utxo: Arc<UtxoSet>,
    peer_table: Arc<bitcoin_rs_p2p::PeerTable>,
    mempool_gateway: Arc<MempoolGateway>,
    mining_control: Arc<dyn MiningControl>,
    relay: TxRelayQueue,
    applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    block_tree: Arc<RwLock<BlockTree>>,
}

impl TxIngressConsumer {
    fn chain_view(&self) -> ChainAdmissionView<'_> {
        ChainAdmissionView::new(&self.utxo, &self.applied_tip, &self.block_tree)
    }

    fn process_one(&self, inbound: bitcoin_rs_p2p::InboundTx) {
        let source: PeerToken = inbound.source.into();
        let txid = inbound.tx.txid();
        let wtxid = inbound.tx.wtxid();
        let outcome = self.mempool_gateway.submit_transaction(
            Arc::new(inbound.tx),
            AdmissionOrigin::Peer(source),
            None,
            unix_time_secs(),
            &self.chain_view(),
        );
        self.dispatch_outcome(txid, wtxid, source, outcome);
    }

    fn process_retries(&self) -> bool {
        let retries = self
            .mempool_gateway
            .retry_orphans(&self.chain_view(), unix_time_secs());
        let made_progress = retries
            .iter()
            .any(|retry| matches!(retry.result, Ok(SubmitOutcome::Committed(_))));
        for retry in retries {
            self.dispatch_outcome(retry.txid, retry.wtxid, retry.source, retry.result);
        }
        made_progress
    }

    fn dispatch_outcome(
        &self,
        txid: Txid,
        wtxid: Wtxid,
        source: PeerToken,
        outcome: Result<SubmitOutcome, SubmitError>,
    ) {
        match outcome {
            Ok(SubmitOutcome::Committed(result)) => {
                if result.changes.iter().any(|change| {
                    change.txid == Hash256::from(txid)
                        && matches!(
                            change.outcome,
                            bitcoin_rs_mempool::MutationOutcome::Accepted
                        )
                }) {
                    self.relay.announce(txid, wtxid, Some(source.connection_id));
                    self.mining_control.publish_generation();
                }
            }
            Ok(SubmitOutcome::Held { missing_parents }) => {
                bitcoin_rs_p2p::request_missing_parents(&self.peer_table, source, &missing_parents);
            }
            Ok(SubmitOutcome::AlreadyKnown | SubmitOutcome::AlreadyConfirmed) => {}
            Err(error) => tracing::debug!(%txid, ?error, "peer transaction not admitted"),
        }
    }
}

fn unix_time_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use bitcoin_rs_mempool::{
        Mempool, MempoolEntry, MempoolLimits, MempoolObserver, MutationEnvelope, MutationOutcome,
    };
    use bitcoin_rs_p2p::DEFAULT_TX_RELAY_QUEUE_CAPACITY;
    use bitcoin_rs_primitives::{Block, OutPoint, Tx, TxIn, TxOut};
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
                script_sig: Vec::new(),
                sequence: 0xFFFF_FFFF,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 49_000,
                script_pubkey: vec![0x6A, 0x04, 0xAA, 0xBB, 0xCC, 0xDD],
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
                script_pubkey: vec![0x51],
            },
            false,
            100,
        ));
        utxo.commit_block(&changes, &Hash256::from_le_bytes(&[0xBB; 32]))
            .expect("utxo commit must succeed");
        let (relay, _relay_rx) = TxRelayQueue::new(DEFAULT_TX_RELAY_QUEUE_CAPACITY);
        TxIngressConsumer {
            utxo,
            peer_table: Arc::new(bitcoin_rs_p2p::PeerTable::new()),
            mempool_gateway: Arc::clone(gateway),
            mining_control: mining,
            relay,
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
        let (relay, _relay_rx) = TxRelayQueue::new(DEFAULT_TX_RELAY_QUEUE_CAPACITY);
        TxIngressConsumer {
            utxo,
            peer_table: Arc::new(bitcoin_rs_p2p::PeerTable::new()),
            mempool_gateway: Arc::clone(gateway),
            mining_control: mining,
            relay,
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
                script_sig: vec![0x00],
                sequence: 0xFFFF_FFFF,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 50_000,
                script_pubkey: vec![0x6A],
            }],
            lock_time: 0,
        };
        let txid = coinbase.txid();
        consumer.process_one(bitcoin_rs_p2p::InboundTx::new(coinbase, test_source()));
        assert_eq!(
            consumer.mempool_gateway.orphan_count(),
            0,
            "a peer coinbase must not consume orphan quota"
        );
        assert!(
            consumer.mempool_gateway.is_rejected(Hash256::from(txid)),
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
        tx.lock_time = 100;
        tx.inputs[0].sequence = 0xFFFF_FFFE;
        let txid = tx.txid();
        consumer.process_one(bitcoin_rs_p2p::InboundTx::new(tx, test_source()));
        assert!(
            !gateway.read().contains_txid(&txid),
            "a non-final peer tx must not enter the mempool"
        );
        assert!(
            consumer.mempool_gateway.is_rejected(Hash256::from(txid)),
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
                script_sig: Vec::new(),
                sequence: 0xFFFF_FFFF,
                witness: vec![vec![0; 400_000]],
            }],
            outputs: vec![TxOut {
                value: 1_000,
                script_pubkey: vec![0x6A, 0x04, 0xAA, 0xBB, 0xCC, 0xDD],
            }],
            lock_time: 0,
        };
        assert!(
            tx.weight() > 400_000,
            "the fixture must exceed MAX_STANDARD_TX_WEIGHT"
        );
        let txid = tx.txid();
        let wtxid = tx.wtxid();
        consumer.process_one(bitcoin_rs_p2p::InboundTx::new(tx, test_source()));
        assert_eq!(
            consumer.mempool_gateway.orphan_count(),
            0,
            "a non-standard missing-input body must not consume orphan quota"
        );
        assert!(
            consumer.mempool_gateway.is_rejected(Hash256::from(wtxid)),
            "the oversized witness body must enter recent-rejects"
        );
        assert!(
            !consumer.mempool_gateway.have_tx(Hash256::from(txid), false),
            "a smaller witness variant must remain requestable"
        );
    }
}
