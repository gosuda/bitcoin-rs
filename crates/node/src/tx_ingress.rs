use std::sync::Arc;
use std::time::Duration;

use crate::p2p::TxRelayQueue;
use bitcoin_rs_chain::chain::{BlockTreeReader, TipReader};
use bitcoin_rs_consensus::primitives::{Hash256, Network, Txid, Wtxid};
use bitcoin_rs_mempool::{AdmissionOrigin, MempoolGateway, PeerToken, SubmitError, SubmitOutcome};
use bitcoin_rs_storage::utxo::UtxoReader;
use bitcoin_rs_wire::context::ChainAdmissionView;
use bitcoin_rs_wire::mining::MiningControl;
use crossbeam_channel::Receiver;

use crate::state::NodeState;

const TX_INGRESS_POLL: Duration = Duration::from_millis(100);

pub fn spawn_tx_ingress_consumer(
    state: &NodeState,
    gateway: Arc<MempoolGateway>,
    mining_control: Arc<dyn MiningControl>,
    shutdown: bitcoin_rs_consensus::latch::LatchReader,
    tx_rx: Receiver<crate::p2p::InboundBody>,
    relay: TxRelayQueue,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    let chainstate = state.chainstate();
    let consumer = TxIngressConsumer {
        utxo: chainstate.utxo_reader(),
        applied_tip: chainstate.applied_tip_reader(),
        block_tree: chainstate.block_tree_reader(),
        network: chainstate.network(),
        peer_table: state.peer_table(),
        tx_policy: Arc::clone(&state.tx_policy),
        mempool_gateway: gateway,
        mining_control,
        relay,
    };
    std::thread::Builder::new()
        .name("bitcoin-rs-tx-ingress".to_owned())
        .spawn(move || run_consumer_loop(&consumer, &shutdown, &tx_rx))
}

fn run_consumer_loop(
    consumer: &TxIngressConsumer,
    shutdown: &bitcoin_rs_consensus::latch::LatchReader,
    tx_rx: &Receiver<crate::p2p::InboundBody>,
) {
    while !shutdown.is_triggered() {
        let made_progress = consumer.process_retries();
        if made_progress {
            match tx_rx.try_recv() {
                Ok(body) => consumer.process_body(body),
                Err(crossbeam_channel::TryRecvError::Empty) => {}
                Err(crossbeam_channel::TryRecvError::Disconnected) => break,
            }
        } else {
            crossbeam_channel::select! {
                recv(tx_rx) -> recv => match recv {
                    Ok(body) => consumer.process_body(body),
                    Err(_) => break,
                },
                recv(shutdown.closed()) -> _ => break,
                recv(crossbeam_channel::after(TX_INGRESS_POLL)) -> _ => {}
            }
        }
    }
}

struct TxIngressConsumer {
    utxo: UtxoReader,
    applied_tip: TipReader,
    block_tree: BlockTreeReader,
    network: Network,
    peer_table: Arc<bitcoin_rs_p2p::PeerTable>,
    pub(crate) tx_policy: Arc<crate::p2p::NodeTxPolicy>,
    mempool_gateway: Arc<MempoolGateway>,
    mining_control: Arc<dyn MiningControl>,
    relay: TxRelayQueue,
}

impl TxIngressConsumer {
    fn chain_view(&self) -> ChainAdmissionView {
        ChainAdmissionView::new(
            self.utxo.clone(),
            self.applied_tip.clone(),
            self.block_tree.clone(),
            self.network,
        )
    }

    fn process_body(&self, body: crate::p2p::InboundBody) {
        match body {
            crate::p2p::InboundBody::Tx(inbound) => self.process_one(inbound),
            crate::p2p::InboundBody::Package(package) => self.process_package(*package),
        }
    }

    fn process_package(&self, package: crate::p2p::InboundPackage) {
        let source = package.source();
        let opened = match package.open() {
            crate::p2p::PackageOpening::Opened(opened) => opened,
            crate::p2p::PackageOpening::Refused(rejection) => {
                tracing::debug!(refusal = %rejection.refusal, "peer package refused before admission");
                self.tx_policy.package_response_rejected(
                    rejection.token,
                    &crate::p2p::RefTxInventory(self.mempool_gateway.as_ref()),
                );
                return;
            }
        };
        if opened.overrun() > 0 {
            metrics::counter!("node.package_charge_overrun").increment(opened.overrun());
        }
        let (token, txs) = opened.into_parts();
        let identities: Vec<(Txid, Wtxid)> = txs.iter().map(|tx| (tx.txid(), tx.wtxid())).collect();
        let peer: PeerToken = crate::p2p::peer_token(source);
        let outcome = self.mempool_gateway.submit_peer_package(
            &txs,
            peer,
            bitcoin_rs_consensus::primitives::unix_time_secs(),
            &self.chain_view(),
        );
        drop(txs);
        self.tx_policy.package_response_completed(
            token,
            &crate::p2p::RefTxInventory(self.mempool_gateway.as_ref()),
        );
        match outcome {
            Ok(result) => {
                if self.announce_package(&identities, peer, &result) {
                    self.peer_table.note_useful_transaction(source);
                }
            }
            Err(error) => tracing::debug!(?error, "peer package not admitted"),
        }
    }

    fn announce_package(
        &self,
        identities: &[(Txid, Wtxid)],
        source: PeerToken,
        result: &bitcoin_rs_mempool::MutationResult,
    ) -> bool {
        let mut subject_accepted = false;
        let mut published = false;
        for (index, change) in result.changes.iter().enumerate() {
            if !matches!(
                change.outcome,
                bitcoin_rs_mempool::MutationOutcome::Accepted
            ) {
                continue;
            }
            let Some((txid, wtxid)) = identities
                .iter()
                .find(|(txid, _)| Hash256::from(*txid) == change.txid)
            else {
                continue;
            };
            if let Some(sequence) = result.sequence_of(index) {
                self.relay
                    .announce(*txid, *wtxid, Some(source.connection_id), sequence);
                published = true;
            }
            subject_accepted |= identities.last().is_some_and(|(last, _)| last == txid);
        }
        if published {
            self.mining_control.publish_generation();
        }
        subject_accepted
    }

    fn process_one(&self, inbound: bitcoin_rs_p2p::InboundTx) {
        let source: PeerToken = crate::p2p::peer_token(inbound.source);
        let txid = inbound.tx.txid();
        let wtxid = inbound.tx.wtxid();
        let outcome = self.mempool_gateway.submit_transaction(
            Arc::new(inbound.tx),
            AdmissionOrigin::Peer(source),
            None,
            bitcoin_rs_consensus::primitives::unix_time_secs(),
            &self.chain_view(),
        );
        self.tx_policy
            .transaction_response_completed(inbound.source, txid, wtxid);
        if self.dispatch_inbound_outcome(txid, wtxid, source, outcome) {
            self.peer_table.note_useful_transaction(inbound.source);
        }
        self.tx_policy.poll_transaction_response(
            &crate::p2p::RefTxInventory(self.mempool_gateway.as_ref()),
            txid,
            wtxid,
        );
    }

    fn process_retries(&self) -> bool {
        let now = bitcoin_rs_consensus::primitives::unix_time_secs();
        let live_peers = self
            .peer_table
            .live_sessions()
            .into_iter()
            .map(crate::p2p::peer_token);
        self.mempool_gateway.maintain_orphans(now, live_peers);
        let retries = self.mempool_gateway.retry_orphans(&self.chain_view(), now);
        let made_progress = retries
            .iter()
            .any(|retry| matches!(retry.result, Ok(SubmitOutcome::Committed(_))));
        for retry in retries {
            self.dispatch_retry_outcome(retry.txid, retry.wtxid, retry.source, retry.result);
        }
        made_progress
    }

    fn dispatch_inbound_outcome(
        &self,
        txid: Txid,
        wtxid: Wtxid,
        source: PeerToken,
        outcome: Result<SubmitOutcome, SubmitError>,
    ) -> bool {
        match outcome {
            Ok(SubmitOutcome::Held { missing_parents }) => {
                let package_requested = self
                    .peer_table
                    .package_relay_versions_for_endpoint(source.endpoint, source.connection_id)
                    & bitcoin_rs_p2p::packages::PKG_RELAY_ANC
                    != 0
                    && self.tx_policy.request_package_info(
                        crate::p2p::peer_source(source),
                        wtxid,
                        &missing_parents,
                    );
                if !package_requested && !self.tx_policy.has_live_package_solicitation(wtxid) {
                    self.tx_policy
                        .request_missing_parents(crate::p2p::peer_source(source), &missing_parents);
                }
                false
            }
            other => self.dispatch_common_outcome(txid, wtxid, source, other),
        }
    }

    fn dispatch_retry_outcome(
        &self,
        txid: Txid,
        wtxid: Wtxid,
        source: PeerToken,
        outcome: Result<SubmitOutcome, SubmitError>,
    ) -> bool {
        match outcome {
            Ok(SubmitOutcome::Held { missing_parents }) => {
                if !self.tx_policy.has_live_package_solicitation(wtxid) {
                    self.tx_policy
                        .request_missing_parents(crate::p2p::peer_source(source), &missing_parents);
                }
                false
            }
            other => self.dispatch_common_outcome(txid, wtxid, source, other),
        }
    }

    fn dispatch_common_outcome(
        &self,
        txid: Txid,
        wtxid: Wtxid,
        source: PeerToken,
        outcome: Result<SubmitOutcome, SubmitError>,
    ) -> bool {
        match outcome {
            Ok(SubmitOutcome::Committed(result)) => {
                let Some(index) = result.changes.iter().position(|change| {
                    change.txid == Hash256::from(txid)
                        && matches!(
                            change.outcome,
                            bitcoin_rs_mempool::MutationOutcome::Accepted
                        )
                }) else {
                    return false;
                };
                if let Some(sequence) = result.sequence_of(index) {
                    self.relay
                        .announce(txid, wtxid, Some(source.connection_id), sequence);
                    self.mining_control.publish_generation();
                }
                true
            }
            Ok(SubmitOutcome::Held { .. } | SubmitOutcome::AlreadyKnown) => false,
            Ok(SubmitOutcome::AlreadyConfirmed) => {
                self.tx_policy.forget_known_transaction(txid, wtxid);
                false
            }
            Err(error) => {
                tracing::debug!(%txid, ?error, "peer transaction not admitted");
                false
            }
        }
    }
}

#[cfg(test)]
#[expect(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::p2p::DEFAULT_TX_RELAY_QUEUE_CAPACITY;
    use arc_swap::ArcSwapOption;
    use bitcoin::hashes::Hash as _;
    use bitcoin_rs_chain::chain::BlockTree;
    use bitcoin_rs_consensus::ValidationEngine;
    use bitcoin_rs_consensus::primitives::{
        Amount, LockTime, Network, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Witness,
    };
    use bitcoin_rs_mempool::{
        BodyInterest, Mempool, MempoolEntry, MempoolLimits, MempoolObserver, MutationEnvelope,
        MutationOutcome,
    };
    use bitcoin_rs_wire::mining::FakeMiningControl;
    use parking_lot::{Mutex, RwLock};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    fn coinbase_tx(value: u64) -> Tx {
        Tx {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(vec![0x51]),
                sequence: Sequence::from_consensus(0xFFFF_FFFF),
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(value),
                script_pubkey: Script::from_bytes(vec![0x6A]),
            }],
            lock_time: LockTime::ZERO,
        }
    }

    fn spending_tx() -> Tx {
        let parent_txid = Txid::from(Hash256::from_le_bytes(&[0xAA; 32]));
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: parent_txid,
                    vout: 0,
                },
                script_sig: Script::from_bytes(vec![0x01, 0x51]),
                sequence: Sequence::from_consensus(0xFFFF_FFFF),
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: Script::from_bytes(vec![0x6A, 0x04, 0xAA, 0xBB, 0xCC, 0xDD]),
            }],
            lock_time: LockTime::ZERO,
        }
    }

    fn zero_fee_gateway() -> Arc<MempoolGateway> {
        Arc::new(MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits {
                min_relay_fee_sat_per_kvb: 0,
                ..MempoolLimits::default()
            }))),
            None,
            ValidationEngine::Native,
            None,
        ))
    }

    fn make_consumer(
        gateway: &Arc<MempoolGateway>,
        mining: &Arc<FakeMiningControl>,
    ) -> (
        TxIngressConsumer,
        crossbeam_channel::Receiver<crate::p2p::RelayRequest>,
    ) {
        use bitcoin_rs_storage::utxo::contract::{BlockChanges, UtxoAdd};
        let parent_txid = Txid::from(Hash256::from_le_bytes(&[0xAA; 32]));
        let mut changes = BlockChanges::with_capacity(1, 0);
        changes.add(UtxoAdd::new(
            OutPoint {
                txid: parent_txid,
                vout: 0,
            },
            TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: Script::from_bytes(
                    bitcoin::ScriptBuf::from_bytes(vec![0x51])
                        .to_p2sh()
                        .into_bytes(),
                ),
            },
            false,
            100,
        ));
        let store = Arc::new(bitcoin_rs_storage::MemoryKvStore::new());
        let coin_store = Arc::new(bitcoin_rs_storage::CoinStore::open(store, 64 * 1024 * 1024));
        bitcoin_rs_storage::utxo::contract::populate_block_changes(&coin_store, &changes)
            .expect("utxo commit must succeed");
        let (relay, relay_rx) = TxRelayQueue::new(DEFAULT_TX_RELAY_QUEUE_CAPACITY);
        let table = Arc::new(bitcoin_rs_p2p::PeerTable::new());
        let tx_policy = Arc::new(crate::p2p::NodeTxPolicy::with_table(Arc::clone(&table)));
        let consumer = TxIngressConsumer {
            utxo: bitcoin_rs_storage::utxo::UtxoReader::from_coin_store(coin_store),
            applied_tip: TipReader::new(Arc::new(ArcSwapOption::empty())),
            block_tree: BlockTreeReader::new(Arc::new(RwLock::new(BlockTree::new()))),
            network: Network::Regtest,
            peer_table: Arc::clone(&table),
            tx_policy,
            mempool_gateway: Arc::clone(gateway),
            mining_control: mining.clone(),
            relay,
        };
        (consumer, relay_rx)
    }

    fn test_source() -> bitcoin_rs_p2p::PeerSource {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18_333);
        let (queue, _frames) = crossbeam_channel::unbounded::<bitcoin_rs_p2p::QueuedFrame>();
        let lease = bitcoin_rs_p2p::PeerLease::new(queue);
        lease.source_ip(addr)
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
        let gateway = Arc::new(MempoolGateway::new(
            Arc::clone(&pool),
            Some((
                Arc::new(OriginRecorder {
                    captured: Arc::clone(&recorded_origin),
                }),
                BodyInterest::Metadata,
            )),
            ValidationEngine::Native,
            None,
        ));

        let source = test_source();
        let expected_conn_id = source.connection_id();

        let tx = spending_tx();
        let inbound = bitcoin_rs_p2p::InboundTx::new(tx, source);

        let mining = FakeMiningControl::unavailable("not implemented");
        let (consumer, _relay_rx) = make_consumer(&gateway, &mining);

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
        let gateway = Arc::new(MempoolGateway::new(
            Arc::clone(&pool),
            None,
            ValidationEngine::Native,
            None,
        ));

        let source = test_source();
        let tx = coinbase_tx(50_000);
        let inbound = bitcoin_rs_p2p::InboundTx::new(tx, source);

        let mining = FakeMiningControl::unavailable("not implemented");
        let (consumer, relay_rx) = make_consumer(&gateway, &mining);

        consumer.process_one(inbound);
        assert_eq!(mining.publish_count(), 0);
        assert!(
            relay_rx.try_recv().is_err(),
            "a rejected tx must not be announced for relay"
        );
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

        let mining = FakeMiningControl::unavailable("not implemented");
        let (consumer, relay_rx) = make_consumer(&gateway, &mining);

        consumer.process_one(inbound);
        assert_eq!(mining.publish_count(), 0);
        assert!(
            relay_rx.try_recv().is_err(),
            "a duplicate tx must not be re-announced for relay"
        );
        assert!(gateway.read().contains_txid(&txid));
    }

    #[test]
    fn accepted_tx_relays_and_wakes_mining() {
        let gateway = zero_fee_gateway();

        let source = test_source();
        let tx = spending_tx();
        let txid = tx.txid();
        let inbound = bitcoin_rs_p2p::InboundTx::new(tx, source);

        let mining = FakeMiningControl::unavailable("not implemented");
        let (consumer, relay_rx) = make_consumer(&gateway, &mining);

        consumer.process_one(inbound);

        assert_eq!(mining.publish_count(), 1);
        let announced = relay_rx
            .try_recv()
            .expect("an accepted tx must be announced for relay");
        assert_eq!(announced.txid, txid);
    }

    #[test]
    fn held_orphan_uses_ancestor_package_only_for_negotiated_peers() {
        let gateway = zero_fee_gateway();
        let mining = FakeMiningControl::unavailable("not implemented");
        let (consumer, _relay_rx) = make_consumer(&gateway, &mining);
        let table = Arc::clone(&consumer.peer_table);

        let anc_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18_334);
        let (anc_sender, anc_receiver) =
            crossbeam_channel::unbounded::<bitcoin_rs_p2p::QueuedFrame>();
        let anc_lease = bitcoin_rs_p2p::PeerLease::new(anc_sender);
        let anc_source = anc_lease.source_ip(anc_addr);
        let anc_endpoint = bitcoin_rs_p2p::PeerEndpoint::Ip(anc_addr);
        assert!(!table.register(anc_endpoint, anc_lease));
        assert!(table.seed_package_relay(anc_source, bitcoin_rs_p2p::packages::PKG_RELAY_ANC));

        let mut anc_orphan = spending_tx();
        let anc_parent = Txid::from(Hash256::from_le_bytes(&[0xCC; 32]));
        anc_orphan.inputs[0].previous_output = OutPoint::new(anc_parent, 0);
        let anc_subject = anc_orphan.wtxid();
        consumer.process_one(bitcoin_rs_p2p::InboundTx::new(anc_orphan, anc_source));

        let anc_message = anc_receiver
            .try_recv()
            .expect("negotiated peer receives ancestor solicitation")
            .into_message();
        assert!(matches!(
            anc_message,
            bitcoin_rs_p2p::Message::GetData(items)
                if items == vec![bitcoin::p2p::message_blockdata::Inventory::Unknown {
                    inv_type: bitcoin_rs_p2p::packages::MSG_ANCPKGINFO,
                    hash: anc_subject.0.to_le_bytes(),
                }]
        ));
        assert!(anc_receiver.try_recv().is_err());

        let ordinary_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18_335);
        let (ordinary_sender, ordinary_receiver) =
            crossbeam_channel::unbounded::<bitcoin_rs_p2p::QueuedFrame>();
        let ordinary_lease = bitcoin_rs_p2p::PeerLease::new(ordinary_sender);
        let ordinary_source = ordinary_lease.source_ip(ordinary_addr);
        let ordinary_endpoint = bitcoin_rs_p2p::PeerEndpoint::Ip(ordinary_addr);
        assert!(!table.register(ordinary_endpoint, ordinary_lease));

        let mut ordinary_orphan = spending_tx();
        let ordinary_parent = Txid::from(Hash256::from_le_bytes(&[0xDD; 32]));
        ordinary_orphan.inputs[0].previous_output = OutPoint::new(ordinary_parent, 0);
        consumer.process_one(bitcoin_rs_p2p::InboundTx::new(
            ordinary_orphan,
            ordinary_source,
        ));

        let ordinary_message = ordinary_receiver
            .try_recv()
            .expect("non-negotiated peer keeps parent fetching")
            .into_message();
        assert!(matches!(
            ordinary_message,
            bitcoin_rs_p2p::Message::GetData(items)
                if matches!(items.as_slice(), [bitcoin::p2p::message_blockdata::Inventory::Transaction(_)])
        ));
        assert!(ordinary_receiver.try_recv().is_err());
    }

    #[test]
    fn coinbase_is_rejected_not_orphaned() {
        let gateway = Arc::new(MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            None,
            ValidationEngine::Native,
            None,
        ));
        let mining = FakeMiningControl::unavailable("not implemented");
        let (consumer, _relay_rx) = make_consumer(&gateway, &mining);
        let coinbase = coinbase_tx(50_000);
        let txid = coinbase.txid();
        consumer.process_one(bitcoin_rs_p2p::InboundTx::new(coinbase, test_source()));
        assert_eq!(consumer.mempool_gateway.orphan_count(), 0);
        assert!(consumer.mempool_gateway.is_rejected(Hash256::from(txid)));
    }

    #[test]
    fn non_final_tx_is_rejected_not_admitted() {
        let gateway = zero_fee_gateway();
        let mining = FakeMiningControl::unavailable("not implemented");
        let (consumer, _relay_rx) = make_consumer(&gateway, &mining);
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
        let gateway = Arc::new(MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            None,
            ValidationEngine::Native,
            None,
        ));
        let mining = FakeMiningControl::unavailable("not implemented");
        let (consumer, _relay_rx) = make_consumer(&gateway, &mining);
        let parent = Txid::from(Hash256::from_le_bytes(&[0xCC; 32]));
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
            lock_time: LockTime::ZERO,
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
        let gateway = Arc::new(MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            None,
            ValidationEngine::Native,
            None,
        ));
        let mining = FakeMiningControl::unavailable("not implemented");
        let (consumer, _relay_rx) = make_consumer(&gateway, &mining);
        let mut orphan = spending_tx();
        orphan.inputs[0].previous_output =
            OutPoint::new(Txid::from(Hash256::from_le_bytes(&[0xEE; 32])), 0);
        let txid = orphan.txid();

        consumer.process_one(bitcoin_rs_p2p::InboundTx::new(orphan, test_source()));
        assert_eq!(gateway.orphan_count(), 1);

        assert!(!consumer.process_retries());
        assert_eq!(gateway.orphan_count(), 0);
        assert!(!gateway.have_tx(Hash256::from(txid), false));
    }

    #[test]
    fn consumer_processes_admitted_package_and_publishes_generation() {
        use crate::p2p::{InboundBody, PackageCapacity};
        use bitcoin_rs_consensus::primitives::encode::ConsensusEncode;

        let pool = Arc::new(RwLock::new(Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            ..MempoolLimits::default()
        })));
        let gateway = Arc::new(MempoolGateway::new(
            Arc::clone(&pool),
            None,
            ValidationEngine::Native,
            None,
        ));
        let mining = Arc::new(FakeMiningControl::default());
        let (consumer, _relay_rx) = make_consumer(&gateway, &mining);
        let table = Arc::clone(&consumer.peer_table);

        let mut parent = spending_tx();
        parent.outputs[0].script_pubkey = Script::from_bytes(vec![
            0xA9, 0x14, 0xDA, 0x17, 0x45, 0xE9, 0xB5, 0x49, 0xBD, 0x0B, 0xFA, 0x1A, 0x56, 0x99,
            0x71, 0xC7, 0x7E, 0xBA, 0x30, 0xCD, 0x5A, 0x4B, 0x87,
        ]);
        let parent_txid = parent.txid();
        let child = Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(parent_txid, 0),
                script_sig: Script::from_bytes(vec![0x01, 0x51]),
                sequence: Sequence::from_consensus(0xFFFF_FFFF),
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(48_000),
                script_pubkey: Script::from_bytes(vec![0x6A, 0x04, 0x11, 0x22, 0x33, 0x44]),
            }],
            lock_time: LockTime::ZERO,
        };
        let child_wtxid = child.wtxid();
        let child_txid = child.txid();

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 19_333);
        let (queue, _frames) = crossbeam_channel::unbounded();
        let lease = bitcoin_rs_p2p::PeerLease::new(queue);
        let source = lease.source_ip(addr);
        let endpoint = bitcoin_rs_p2p::PeerEndpoint::Ip(addr);
        table.register(endpoint, lease.clone());
        let version = bitcoin::p2p::message_network::VersionMessage {
            version: 70016,
            services: bitcoin::p2p::ServiceFlags::NETWORK | bitcoin::p2p::ServiceFlags::WITNESS,
            timestamp: 0,
            receiver: bitcoin::p2p::Address::new(&addr, bitcoin::p2p::ServiceFlags::NONE),
            sender: bitcoin::p2p::Address::new(&addr, bitcoin::p2p::ServiceFlags::NONE),
            nonce: 1,
            user_agent: "/test/".into(),
            start_height: 0,
            relay: true,
        };
        table.publish_info(
            endpoint,
            &lease,
            bitcoin_rs_p2p::PeerInfo::inbound_from_version(
                addr,
                addr,
                &version,
                0,
                0,
                std::sync::Arc::new(bitcoin_rs_p2p::PeerCounters::default()),
            ),
        );

        assert!(
            consumer
                .tx_policy
                .request_package_info(source, child_wtxid, &[])
        );
        assert!(consumer.tx_policy.request_package_transactions(
            source,
            child_wtxid,
            vec![parent.wtxid(), child_wtxid]
        ));

        let mut payload = Vec::new();
        payload.extend_from_slice(&bitcoin_rs_consensus::primitives::varint::encode(2));
        parent.consensus_encode(&mut payload);
        child.consensus_encode(&mut payload);
        let payload = bytes::Bytes::from(payload);

        let capacity = PackageCapacity::new(100_000);
        let inbound = consumer
            .tx_policy
            .admit_package(
                &capacity,
                &crate::p2p::RefTxInventory(&consumer.mempool_gateway),
                source,
                payload,
            )
            .expect("package admission must succeed");
        assert_eq!(capacity.held(), 1);
        assert!(capacity.reserved() > 0);

        consumer.process_body(InboundBody::Package(Box::new(inbound)));

        assert!(gateway.read().contains_txid(&parent_txid));
        assert!(gateway.read().contains_txid(&child_txid));
        assert_eq!(mining.publish_count(), 1);

        assert_eq!(capacity.reserved(), 0);
        assert_eq!(capacity.held(), 0);
        let _teardown = consumer.tx_policy.clear_package_claims(&capacity);
    }

    fn publish_peer_info(
        table: &bitcoin_rs_p2p::PeerTable,
        endpoint: bitcoin_rs_p2p::PeerEndpoint,
        lease: &bitcoin_rs_p2p::PeerLease,
        addr: SocketAddr,
    ) {
        let version = bitcoin::p2p::message_network::VersionMessage {
            version: 70016,
            services: bitcoin::p2p::ServiceFlags::NETWORK | bitcoin::p2p::ServiceFlags::WITNESS,
            timestamp: 0,
            receiver: bitcoin::p2p::Address::new(&addr, bitcoin::p2p::ServiceFlags::NONE),
            sender: bitcoin::p2p::Address::new(&addr, bitcoin::p2p::ServiceFlags::NONE),
            nonce: 1,
            user_agent: "/test/".into(),
            start_height: 0,
            relay: true,
        };
        table.publish_info(
            endpoint,
            lease,
            bitcoin_rs_p2p::PeerInfo::inbound_from_version(
                addr,
                addr,
                &version,
                0,
                0,
                std::sync::Arc::new(bitcoin_rs_p2p::PeerCounters::default()),
            ),
        );
    }

    fn negotiated_peer(
        table: &bitcoin_rs_p2p::PeerTable,
        port: u16,
    ) -> (
        bitcoin_rs_p2p::PeerSource,
        crossbeam_channel::Receiver<bitcoin_rs_p2p::QueuedFrame>,
    ) {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let (sender, receiver) = crossbeam_channel::unbounded::<bitcoin_rs_p2p::QueuedFrame>();
        let lease = bitcoin_rs_p2p::PeerLease::new(sender);
        let source = lease.source_ip(addr);
        let endpoint = bitcoin_rs_p2p::PeerEndpoint::Ip(addr);
        assert!(!table.register(endpoint, lease.clone()));
        publish_peer_info(table, endpoint, &lease, addr);
        assert!(table.seed_package_relay(source, bitcoin_rs_p2p::packages::PKG_RELAY_ANC));
        (source, receiver)
    }

    fn orphan_spending(parent: Txid) -> Tx {
        let mut orphan = spending_tx();
        orphan.inputs[0].previous_output = OutPoint::new(parent, 0);
        orphan
    }

    fn parent_getdata(parent: Txid) -> bitcoin_rs_p2p::Message {
        bitcoin_rs_p2p::Message::GetData(vec![
            bitcoin::p2p::message_blockdata::Inventory::Transaction(
                bitcoin::Txid::from_byte_array(*parent.as_bytes()),
            ),
        ])
    }

    fn parent_witness_getdata(parent: Txid) -> bitcoin_rs_p2p::Message {
        bitcoin_rs_p2p::Message::GetData(vec![
            bitcoin::p2p::message_blockdata::Inventory::WitnessTransaction(
                bitcoin::Txid::from_byte_array(*parent.as_bytes()),
            ),
        ])
    }

    #[test]
    fn refused_solicitation_at_in_flight_cap_queues_parents_for_retry() {
        let gateway = zero_fee_gateway();
        let mining = FakeMiningControl::unavailable("not implemented");
        let (consumer, _relay_rx) = make_consumer(&gateway, &mining);
        let table = Arc::clone(&consumer.peer_table);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18_336);
        let (sender, receiver) = crossbeam_channel::unbounded::<bitcoin_rs_p2p::QueuedFrame>();
        let lease = bitcoin_rs_p2p::PeerLease::new(sender);
        let source = lease.source_ip(addr);
        let endpoint = bitcoin_rs_p2p::PeerEndpoint::Ip(addr);
        assert!(!table.register(endpoint, lease.clone()));
        publish_peer_info(&table, endpoint, &lease, addr);
        assert!(table.seed_package_relay(source, bitcoin_rs_p2p::packages::PKG_RELAY_ANC));

        let mut fillers = Vec::new();
        for n in 0u32..100 {
            let mut hash = [0u8; 32];
            hash[..4].copy_from_slice(&n.to_le_bytes());
            let filler = Wtxid(Hash256::from_le_bytes(&hash));
            fillers.push(filler);
            assert!(consumer.tx_policy.request_package_info(source, filler, &[]));
        }
        for _ in 0..100 {
            let _ = receiver
                .try_recv()
                .expect("filler solicitation queued")
                .into_message();
        }

        let parent = Txid::from(Hash256::from_le_bytes(&[0xCC; 32]));
        let subject = orphan_spending(parent).wtxid();
        consumer.process_one(bitcoin_rs_p2p::InboundTx::new(
            orphan_spending(parent),
            source,
        ));
        assert!(receiver.try_recv().is_err());
        assert_eq!(consumer.mempool_gateway.orphan_count(), 1);
        let (other, other_receiver) = negotiated_peer(&table, 18_341);
        assert!(consumer.tx_policy.request_package_info(other, subject, &[]));
        assert!(matches!(
            other_receiver
                .try_recv()
                .expect("alternate solicitation queued")
                .into_message(),
            bitcoin_rs_p2p::Message::GetData(_)
        ));

        assert!(consumer.tx_policy.release_package_info(
            source,
            fillers[0],
            &crate::p2p::RefTxInventory(&consumer.mempool_gateway)
        ));
        consumer
            .tx_policy
            .poll_transaction_requests(&crate::p2p::RefTxInventory(&consumer.mempool_gateway));
        assert_eq!(
            receiver
                .try_recv()
                .expect("queued parents are retried")
                .into_message(),
            parent_witness_getdata(parent)
        );
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn unanswered_solicitation_suppresses_duplicate_parent_requests() {
        let gateway = zero_fee_gateway();
        let mining = FakeMiningControl::unavailable("not implemented");
        let (consumer, _relay_rx) = make_consumer(&gateway, &mining);
        let table = Arc::clone(&consumer.peer_table);
        let addr_a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18_337);
        let (sender_a, receiver_a) = crossbeam_channel::unbounded::<bitcoin_rs_p2p::QueuedFrame>();
        let lease_a = bitcoin_rs_p2p::PeerLease::new(sender_a);
        let source_a = lease_a.source_ip(addr_a);
        assert!(!table.register(bitcoin_rs_p2p::PeerEndpoint::Ip(addr_a), lease_a));
        assert!(table.seed_package_relay(source_a, bitcoin_rs_p2p::packages::PKG_RELAY_ANC));
        let addr_b = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18_338);
        let (sender_b, receiver_b) = crossbeam_channel::unbounded::<bitcoin_rs_p2p::QueuedFrame>();
        let lease_b = bitcoin_rs_p2p::PeerLease::new(sender_b);
        let source_b = lease_b.source_ip(addr_b);
        assert!(!table.register(bitcoin_rs_p2p::PeerEndpoint::Ip(addr_b), lease_b));
        assert!(table.seed_package_relay(source_b, bitcoin_rs_p2p::packages::PKG_RELAY_ANC));

        let parent = Txid::from(Hash256::from_le_bytes(&[0xCC; 32]));
        let subject = orphan_spending(parent).wtxid();
        assert!(
            consumer
                .tx_policy
                .request_package_info(source_b, subject, &[parent])
        );
        assert!(matches!(
            receiver_b
                .try_recv()
                .expect("solicitation queued")
                .into_message(),
            bitcoin_rs_p2p::Message::GetData(_)
        ));

        consumer.process_one(bitcoin_rs_p2p::InboundTx::new(
            orphan_spending(parent),
            source_a,
        ));
        assert!(receiver_a.try_recv().is_err());
        assert_eq!(consumer.mempool_gateway.orphan_count(), 1);
        assert!(consumer.tx_policy.release_package_info(
            source_b,
            subject,
            &crate::p2p::RefTxInventory(&consumer.mempool_gateway)
        ));
        assert!(receiver_b.try_recv().is_err());
    }

    #[test]
    fn closed_owner_solicitation_falls_back_to_live_supplier_parents() {
        let gateway = zero_fee_gateway();
        let mining = FakeMiningControl::unavailable("not implemented");
        let (consumer, _relay_rx) = make_consumer(&gateway, &mining);
        let table = Arc::clone(&consumer.peer_table);
        let addr_a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18_339);
        let (sender_a, receiver_a) = crossbeam_channel::unbounded::<bitcoin_rs_p2p::QueuedFrame>();
        let lease_a = bitcoin_rs_p2p::PeerLease::new(sender_a);
        let source_a = lease_a.source_ip(addr_a);
        assert!(!table.register(bitcoin_rs_p2p::PeerEndpoint::Ip(addr_a), lease_a.clone()));
        assert!(table.seed_package_relay(source_a, bitcoin_rs_p2p::packages::PKG_RELAY_ANC));
        let addr_b = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18_340);
        let (sender_b, receiver_b) = crossbeam_channel::unbounded::<bitcoin_rs_p2p::QueuedFrame>();
        let lease_b = bitcoin_rs_p2p::PeerLease::new(sender_b);
        let source_b = lease_b.source_ip(addr_b);
        assert!(!table.register(bitcoin_rs_p2p::PeerEndpoint::Ip(addr_b), lease_b));
        assert!(table.seed_package_relay(source_b, bitcoin_rs_p2p::packages::PKG_RELAY_ANC));

        let parent = Txid::from(Hash256::from_le_bytes(&[0xCC; 32]));
        let subject = orphan_spending(parent).wtxid();
        assert!(
            consumer
                .tx_policy
                .request_package_info(source_a, subject, &[parent])
        );
        assert!(matches!(
            receiver_a
                .try_recv()
                .expect("solicitation queued")
                .into_message(),
            bitcoin_rs_p2p::Message::GetData(_)
        ));
        lease_a.cancel();

        consumer.process_one(bitcoin_rs_p2p::InboundTx::new(
            orphan_spending(parent),
            source_b,
        ));
        assert_eq!(
            receiver_b
                .try_recv()
                .expect("live supplier gets the parents")
                .into_message(),
            parent_getdata(parent)
        );
        assert!(receiver_a.try_recv().is_err() && receiver_b.try_recv().is_err());
        assert_eq!(consumer.mempool_gateway.orphan_count(), 1);
        assert_eq!(
            subject,
            orphan_spending(parent).wtxid(),
            "subject identity is stable across the fallback"
        );
    }

    #[test]
    fn tx_ingress_consumer_stops_promptly_on_cancellation() {
        let gateway = zero_fee_gateway();
        let mining = Arc::new(FakeMiningControl::default());
        let (consumer, _relay_rx) = make_consumer(&gateway, &mining);
        let writer = bitcoin_rs_consensus::latch::LatchWriter::new();
        let shutdown = writer.reader();
        let (_tx, tx_rx) = crossbeam_channel::bounded(1);
        let (done_tx, done_rx) = crossbeam_channel::bounded(1);
        let handle = std::thread::spawn(move || {
            run_consumer_loop(&consumer, &shutdown, &tx_rx);
            let _ = done_tx.send(());
        });
        std::thread::sleep(Duration::from_millis(5));
        writer.trigger();
        let res = done_rx.recv_timeout(Duration::from_millis(50));
        assert!(
            res.is_ok(),
            "tx ingress consumer did not exit promptly: timed out waiting for trigger"
        );
        assert!(handle.join().is_ok(), "thread panicked");
    }
}
