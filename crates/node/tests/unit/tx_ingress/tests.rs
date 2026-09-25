// CONTRACT: `docs/contracts/mempool-mutations.md#MPL-04` owns peer admission,
// orphan/reject lifecycle, connection attribution, generation fencing, and retries.
use super::*;
use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::BlockTree;
use bitcoin_rs_chainstate::events::ChainEventPublisher;
use bitcoin_rs_mempool::{
    Mempool, MempoolEntry, MempoolLimits, MempoolObserver, MutationEnvelope, MutationOutcome,
};
use bitcoin_rs_p2p::DEFAULT_TX_RELAY_QUEUE_CAPACITY;
use bitcoin_rs_primitives::{
    Amount, Block, LockTime, Network, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Witness,
};
use bitcoin_rs_utxo::UtxoSet;
use parking_lot::{Mutex, RwLock};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::AtomicUsize;

#[derive(Default)]
struct RecordingMining {
    publishes: AtomicUsize,
}

impl MiningControl for RecordingMining {
    fn get_block_template(
        &self,
        _request: bitcoin_rs_mining::BlockTemplateRequest,
    ) -> Result<bitcoin_rs_mining::BlockTemplateResult, bitcoin_rs_mining::MiningControlError> {
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

    fn submit_header(
        &self,
        _header: bitcoin_rs_primitives::Header,
    ) -> Result<(), bitcoin_rs_mining::MiningControlError> {
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
    ) -> Result<Vec<bitcoin_rs_mining::GeneratedBlock>, bitcoin_rs_mining::MiningControlError> {
        Err(bitcoin_rs_mining::MiningControlError::Failed(
            "not implemented".to_owned().into(),
        ))
    }
}

fn coinbase_tx(value: u64) -> Tx {
    Tx {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid::default(), u32::MAX),
            script_sig: Script::from_bytes(vec![0x51]),
            sequence: Sequence::from_consensus(0xFFFF_FFFF),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: Script::from_bytes(vec![0x6A]),
        }],
        lock_time: LockTime::from_consensus(0),
    }
}

// Empty `scriptSig` plus an `OP_TRUE` prevout satisfy `SCRIPT_VERIFY_CLEANSTACK`;
// the `OP_RETURN` payload pads the non-witness size to the 65-byte floor.
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
            sequence: Sequence::from_consensus(0xFFFF_FFFF),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(49_000),
            script_pubkey: Script::from_bytes(vec![0x6A, 0x04, 0xAA, 0xBB, 0xCC, 0xDD]),
        }],
        lock_time: LockTime::from_consensus(0),
    }
}

fn zero_fee_gateway() -> Arc<MempoolGateway> {
    MempoolGateway::shared(Arc::new(RwLock::new(Mempool::new(MempoolLimits {
        min_relay_fee_sat_per_kvb: 0,
        ..MempoolLimits::default()
    }))))
}

fn make_consumer(gateway: &Arc<MempoolGateway>, mining: Arc<RecordingMining>) -> TxIngressConsumer {
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
            script_pubkey: Script::from_bytes(vec![0x51]),
        },
        false,
        100,
    ));
    utxo.commit_block(&changes, &Hash256::from_le_bytes(&[0xBB; 32]))
        .expect("utxo commit must succeed");
    let chainstate = Arc::new(bitcoin_rs_chainstate::Chainstate::new(
        Network::Regtest,
        Arc::new(ArcSwapOption::empty()),
        Arc::new(ArcSwapOption::empty()),
        Arc::new(RwLock::new(BlockTree::new())),
        utxo,
        Arc::new(bitcoin_rs_utxo::stats::CoinStatsListener::new(
            bitcoin_rs_utxo::stats::CoinStats::default(),
        )),
        Arc::new(ChainEventPublisher::detached(0)),
    ));
    let (relay, _relay_rx) = TxRelayQueue::new(DEFAULT_TX_RELAY_QUEUE_CAPACITY);
    TxIngressConsumer {
        chainstate,
        peer_table: Arc::new(bitcoin_rs_p2p::PeerTable::new()),
        mempool_gateway: Arc::clone(gateway),
        mining_control: mining,
        relay,
    }
}

fn test_source() -> bitcoin_rs_p2p::PeerSource {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18_333);
    let lease =
        bitcoin_rs_p2p::PeerLease::new(crossbeam_channel::unbounded::<bitcoin_rs_p2p::Message>().0);
    lease.source(addr)
}

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

    let mining = Arc::new(RecordingMining::default());
    let consumer = make_consumer(&gateway, mining);

    consumer.process_one(inbound);

    let origin = recorded_origin.lock().take();
    assert!(origin.is_some());
    if let Some(bitcoin_rs_mempool::AdmissionOrigin::Peer(token)) = origin {
        assert_eq!(token.connection_id, expected_conn_id.get());
    } else {
        panic!("accepted peer tx must carry AdmissionOrigin::Peer");
    }
}

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

    let mining = Arc::new(RecordingMining::default());
    let consumer = make_consumer(&gateway, Arc::clone(&mining));

    consumer.process_one(inbound);

    assert_eq!(mining.publishes.load(Ordering::Relaxed), 0);
}

#[test]
fn duplicate_tx_does_not_relay_or_wake_mining() {
    let gateway = zero_fee_gateway();

    let tx = coinbase_tx(50_000);
    let txid = tx.txid();
    let entry = MempoolEntry::new(Arc::new(tx.clone()), 100, 0, 1, 0, 0);
    gateway.insert_entry(AdmissionOrigin::Rpc, entry).unwrap();

    let source = test_source();
    let inbound = bitcoin_rs_p2p::InboundTx::new(tx, source);

    let mining = Arc::new(RecordingMining::default());
    let consumer = make_consumer(&gateway, Arc::clone(&mining));

    consumer.process_one(inbound);

    assert_eq!(mining.publishes.load(Ordering::Relaxed), 0);
    assert!(gateway.read().contains_txid(&txid));
}

#[test]
fn accepted_tx_relays_and_wakes_mining() {
    let gateway = zero_fee_gateway();

    let source = test_source();
    let tx = spending_tx();
    let inbound = bitcoin_rs_p2p::InboundTx::new(tx, source);

    let mining = Arc::new(RecordingMining::default());
    let consumer = make_consumer(&gateway, Arc::clone(&mining));

    consumer.process_one(inbound);

    assert_eq!(mining.publishes.load(Ordering::Relaxed), 1);
}

#[test]
fn coinbase_is_rejected_not_orphaned() {
    let gateway = MempoolGateway::shared(Arc::new(RwLock::new(Mempool::new(
        MempoolLimits::default(),
    ))));
    let mining = Arc::new(RecordingMining::default());
    let consumer = make_consumer(&gateway, mining);
    let coinbase = coinbase_tx(50_000);
    let txid = coinbase.txid();
    consumer.process_one(bitcoin_rs_p2p::InboundTx::new(coinbase, test_source()));
    assert_eq!(consumer.mempool_gateway.orphan_count(), 0);
    assert!(consumer.mempool_gateway.is_rejected(Hash256::from(txid)));
}

#[test]
fn non_final_tx_is_rejected_not_admitted() {
    let gateway = zero_fee_gateway();
    let mining = Arc::new(RecordingMining::default());
    let consumer = make_consumer(&gateway, mining);
    let mut tx = spending_tx();
    tx.lock_time = LockTime::from_consensus(100);
    tx.inputs[0].sequence = Sequence::from_consensus(0xFFFF_FFFE);
    let txid = tx.txid();
    consumer.process_one(bitcoin_rs_p2p::InboundTx::new(tx, test_source()));
    assert!(!gateway.read().contains_txid(&txid));
    assert!(consumer.mempool_gateway.is_rejected(Hash256::from(txid)));
}

#[test]
fn oversized_missing_input_tx_is_rejected_not_orphaned() {
    let gateway = MempoolGateway::shared(Arc::new(RwLock::new(Mempool::new(
        MempoolLimits::default(),
    ))));
    let mining = Arc::new(RecordingMining::default());
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
            sequence: Sequence::from_consensus(0xFFFF_FFFF),
            witness: Witness::from_stack(vec![vec![0; 400_000]]),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: Script::from_bytes(vec![0x6A, 0x04, 0xAA, 0xBB, 0xCC, 0xDD]),
        }],
        lock_time: LockTime::from_consensus(0),
    };
    assert!(
        tx.weight() > 400_000,
        "the fixture must exceed MAX_STANDARD_TX_WEIGHT"
    );
    let txid = tx.txid();
    let wtxid = tx.wtxid();
    consumer.process_one(bitcoin_rs_p2p::InboundTx::new(tx, test_source()));
    assert_eq!(consumer.mempool_gateway.orphan_count(), 0);
    assert!(consumer.mempool_gateway.is_rejected(Hash256::from(wtxid)));
    assert!(!consumer.mempool_gateway.have_tx(Hash256::from(txid), false));
}

#[test]
fn retry_poll_evicts_an_orphan_after_its_connection_is_gone() {
    let gateway = MempoolGateway::shared(Arc::new(RwLock::new(Mempool::new(
        MempoolLimits::default(),
    ))));
    let mining = Arc::new(RecordingMining::default());
    let consumer = make_consumer(&gateway, mining);
    // Spend an unfunded parent so the tx lands in the orphan pool.
    let mut orphan = spending_tx();
    orphan.inputs[0].previous_output =
        OutPoint::new(Txid::from(Hash256::from_le_bytes(&[0xEE; 32])), 0);
    let txid = orphan.txid();

    // The fixture source was never registered in this consumer's peer table,
    // which models a connection disappearing before the next ingress poll.
    consumer.process_one(bitcoin_rs_p2p::InboundTx::new(orphan, test_source()));
    assert_eq!(gateway.orphan_count(), 1);

    assert!(!consumer.process_retries());
    assert_eq!(gateway.orphan_count(), 0);
    assert!(!gateway.have_tx(Hash256::from(txid), false));
}
