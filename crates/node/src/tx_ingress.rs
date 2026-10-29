use std::sync::Arc;
use std::time::Duration;

use bitcoin_rs_chain::{BlockTreeReader, TipReader};
use bitcoin_rs_mempool::{AdmissionOrigin, MempoolGateway, PeerToken, SubmitError, SubmitOutcome};
use bitcoin_rs_mining::MiningControl;
use bitcoin_rs_p2p::TxRelayQueue;
use bitcoin_rs_primitives::{Hash256, Network, Txid, Wtxid};
use bitcoin_rs_rpc::context::ChainAdmissionView;
use bitcoin_rs_utxo::UtxoReader;
use crossbeam_channel::Receiver;

use crate::state::NodeState;

const TX_INGRESS_POLL: Duration = Duration::from_millis(100);

pub fn spawn_tx_ingress_consumer(
    state: &NodeState,
    gateway: Arc<MempoolGateway>,
    mining_control: Arc<dyn MiningControl>,
    shutdown: impl Into<bitcoin_rs_chain::LatchReader>,
    tx_rx: Receiver<bitcoin_rs_p2p::InboundBody>,
    relay: TxRelayQueue,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    let shutdown = shutdown.into();
    let chainstate = state.chainstate();
    let consumer = TxIngressConsumer {
        utxo: chainstate.utxo_reader(),
        applied_tip: chainstate.applied_tip_reader(),
        block_tree: chainstate.block_tree_reader(),
        network: chainstate.network(),
        peer_table: state.peer_table(),
        mempool_gateway: gateway,
        mining_control,
        relay,
    };
    std::thread::Builder::new()
        .name("bitcoin-rs-tx-ingress".to_owned())
        .spawn(move || {
            while !shutdown.load() {
                let made_progress = consumer.process_retries();
                let timeout = if made_progress {
                    Duration::ZERO
                } else {
                    TX_INGRESS_POLL
                };
                let recv = tx_rx.recv_timeout(timeout);
                match recv {
                    Ok(body) => consumer.process_body(body),
                    Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
                    Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
                }
            }
        })
}

struct TxIngressConsumer {
    utxo: UtxoReader,
    applied_tip: TipReader,
    block_tree: BlockTreeReader,
    network: Network,
    peer_table: Arc<bitcoin_rs_p2p::PeerTable>,
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

    fn process_body(&self, body: bitcoin_rs_p2p::InboundBody) {
        match body {
            bitcoin_rs_p2p::InboundBody::Tx(inbound) => self.process_one(inbound),
            bitcoin_rs_p2p::InboundBody::Package(package) => self.process_package(*package),
        }
    }

    fn process_package(&self, package: bitcoin_rs_p2p::InboundPackage) {
        let source = package.source();
        let opened = match package.open() {
            bitcoin_rs_p2p::PackageOpening::Opened(opened) => opened,
            bitcoin_rs_p2p::PackageOpening::Refused(rejection) => {
                tracing::debug!(refusal = %rejection.refusal, "peer package refused before admission");
                self.peer_table
                    .package_response_rejected(rejection.token, self.mempool_gateway.as_ref());
                return;
            }
        };
        if opened.overrun() > 0 {
            metrics::counter!("node.package_charge_overrun").increment(opened.overrun());
        }
        let (token, txs) = opened.into_parts();
        let identities: Vec<(Txid, Wtxid)> = txs.iter().map(|tx| (tx.txid(), tx.wtxid())).collect();
        let peer: PeerToken = source.into();
        let outcome = self.mempool_gateway.submit_peer_package(
            &txs,
            peer,
            bitcoin_rs_primitives::unix_time_secs(),
            &self.chain_view(),
        );
        drop(txs);
        self.peer_table
            .package_response_completed(token, self.mempool_gateway.as_ref());
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
        let source: PeerToken = inbound.source.into();
        let txid = inbound.tx.txid();
        let wtxid = inbound.tx.wtxid();
        let outcome = self.mempool_gateway.submit_transaction(
            Arc::new(inbound.tx),
            AdmissionOrigin::Peer(source),
            None,
            bitcoin_rs_primitives::unix_time_secs(),
            &self.chain_view(),
        );
        self.peer_table
            .transaction_response_completed(inbound.source, txid, wtxid);
        if self.dispatch_outcome(txid, wtxid, source, outcome, true) {
            self.peer_table.note_useful_transaction(inbound.source);
        }
        self.peer_table
            .poll_transaction_response(self.mempool_gateway.as_ref(), txid, wtxid);
    }

    fn process_retries(&self) -> bool {
        let now = bitcoin_rs_primitives::unix_time_secs();
        let live_peers = self
            .peer_table
            .live_sessions()
            .into_iter()
            .map(PeerToken::from);
        self.mempool_gateway.maintain_orphans(now, live_peers);
        let retries = self.mempool_gateway.retry_orphans(&self.chain_view(), now);
        let made_progress = retries
            .iter()
            .any(|retry| matches!(retry.result, Ok(SubmitOutcome::Committed(_))));
        for retry in retries {
            self.dispatch_outcome(retry.txid, retry.wtxid, retry.source, retry.result, false);
        }
        made_progress
    }

    fn dispatch_outcome(
        &self,
        txid: Txid,
        wtxid: Wtxid,
        source: PeerToken,
        outcome: Result<SubmitOutcome, SubmitError>,
        allow_package_request: bool,
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
            Ok(SubmitOutcome::Held { missing_parents }) => {
                let package_requested = allow_package_request
                    && self.peer_table.package_relay_versions(source)
                        & bitcoin_rs_p2p::packages::PKG_RELAY_ANC
                        != 0
                    && bitcoin_rs_p2p::inv::request_package_info(
                        &self.peer_table,
                        source,
                        wtxid,
                        &missing_parents,
                    );
                if !package_requested && !self.peer_table.has_live_package_solicitation(wtxid) {
                    bitcoin_rs_p2p::request_missing_parents(
                        &self.peer_table,
                        source,
                        &missing_parents,
                    );
                }
                false
            }
            Ok(SubmitOutcome::AlreadyConfirmed) => {
                self.peer_table.forget_known_transaction(txid, wtxid);
                false
            }
            Ok(SubmitOutcome::AlreadyKnown) => false,
            Err(error) => {
                tracing::debug!(%txid, ?error, "peer transaction not admitted");
                false
            }
        }
    }
}

#[cfg(test)]
#[expect(clippy::expect_used, clippy::unwrap_used)]
#[path = "../tests/unit/tx_ingress/tests.rs"]
mod tests;
