use std::sync::Arc;
use std::time::Duration;

use crate::p2p::TxRelayQueue;
use bitcoin_rs_consensus::primitives::{Hash256, Network, Txid, Wtxid};
use bitcoin_rs_execution::chain::{BlockTreeReader, TipReader};
use bitcoin_rs_mempool::{AdmissionOrigin, MempoolGateway, PeerToken, SubmitError, SubmitOutcome};
use bitcoin_rs_serving::context::ChainAdmissionView;
use bitcoin_rs_serving::mining::MiningControl;
use bitcoin_rs_storage::utxo::UtxoReader;
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
    peer_table: Arc<bitcoin_rs_wire::PeerTable>,
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

    fn process_one(&self, inbound: bitcoin_rs_wire::InboundTx) {
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
                    & bitcoin_rs_wire::packages::PKG_RELAY_ANC
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
mod tests;
