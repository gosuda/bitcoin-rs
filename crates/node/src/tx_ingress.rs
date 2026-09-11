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
        let now = unix_time_secs();
        let live_peers =
            self.peer_table
                .live_connections()
                .into_iter()
                .map(|(addr, connection_id)| PeerToken {
                    addr,
                    connection_id: connection_id.get(),
                });
        self.mempool_gateway.maintain_orphans(now, live_peers);
        let retries = self.mempool_gateway.retry_orphans(&self.chain_view(), now);
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
mod tests;
