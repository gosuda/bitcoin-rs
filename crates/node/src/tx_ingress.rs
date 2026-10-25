//! Wires inbound peer transactions and packages to mempool admission and
//! committed outcomes.
//!
//! Mempool owns preparation, policy, orphan/reject state and retry progress.
//! P2P owns inventory, parent requests, the package request claims and charge
//! ledger, and the bounded relay worker. This loop owns only channel draining
//! and ordering admission results before consumers. It is the single decoder
//! of package bodies: one package at a time is decoded and admitted here.

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

    /// Decodes and admits one peer package, then releases it exactly once.
    ///
    /// PRE: `package` was accepted by the listener: its claim is `Enqueued`
    ///   and its frame and decoded bytes are charged.
    /// POST: the package reached the gateway once (`submit_peer_package`) or
    ///   never; either way its charge and claim are released through exactly
    ///   one of `package_response_rejected` / `package_response_completed`.
    /// INVARIANT: the gateway receives the peer-supplied order and decides
    ///   atomically; a refusal leaves membership and observer order unchanged.
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
        // The gateway has answered, `Ok` or `Err`: the body is finished with.
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

    /// Announces every member the package committed and returns whether its
    /// subject (the last member) is among them.
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
        // The gateway has classified this body. Release its announcement and
        // request slot before a Held outcome queues missing parent requests.
        self.peer_table
            .transaction_response_completed(inbound.source, txid, wtxid);
        if self.dispatch_outcome(txid, wtxid, source, outcome, true) {
            // Core credits a peer only here, not when a retried orphan of it
            // is accepted later.
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

    /// Acts on a classified peer transaction and returns whether `txid`
    /// itself entered the mempool.
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
                if allow_package_request
                    && self.peer_table.package_relay_versions(source)
                        & bitcoin_rs_p2p::packages::PKG_RELAY_ANC
                        != 0
                {
                    bitcoin_rs_p2p::inv::request_package_info(&self.peer_table, source, wtxid);
                } else {
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
