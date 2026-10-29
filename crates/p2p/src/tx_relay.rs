//! Outbound transaction relay worker.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

#[cfg(test)]
use crate::PeerLease;
#[cfg(test)]
use bitcoin_rs_mempool::BodyInterest;
use bitcoin_rs_mempool::{
    AdmissionOrigin, MempoolGateway, MempoolObserver, MutationEnvelope, MutationOutcome,
};
use bitcoin_rs_primitives::{Txid, Wtxid};
use crossbeam_channel::{Receiver, Sender, TrySendError};

pub const DEFAULT_TX_RELAY_QUEUE_CAPACITY: usize = 1024;

const RELAY_POLL: Duration = Duration::from_millis(100);
const INITIAL_BROADCAST_RETRY: Duration = Duration::from_secs(1);
const INITIAL_BROADCAST_BATCH: usize = 1024;

#[derive(Clone, Copy, Debug)]
pub struct RelayRequest {
    pub txid: Txid,
    /// Accepted transaction's witness identifier for BIP339 peers.
    pub wtxid: Wtxid,
    pub source: Option<u64>,
    pub sequence: u64,
}

impl RelayRequest {
    #[must_use]
    pub fn new(txid: Txid, wtxid: Wtxid, source: Option<u64>, sequence: u64) -> Self {
        Self {
            txid,
            wtxid,
            source,
            sequence,
        }
    }
}

#[derive(Clone)]
pub struct TxRelayQueue {
    tx: Sender<RelayRequest>,
    enqueued: Arc<AtomicU64>,
    dropped: Arc<AtomicU64>,
}

impl TxRelayQueue {
    #[must_use]
    pub fn new(capacity: usize) -> (Self, Receiver<RelayRequest>) {
        let (tx, rx) = crossbeam_channel::bounded(capacity);
        let queue = Self {
            tx,
            enqueued: Arc::new(AtomicU64::new(0)),
            dropped: Arc::new(AtomicU64::new(0)),
        };
        (queue, rx)
    }

    pub fn announce(&self, txid: Txid, wtxid: Wtxid, source: Option<u64>, sequence: u64) -> bool {
        let request = RelayRequest::new(txid, wtxid, source, sequence);
        match self.tx.try_send(request) {
            Ok(()) => {
                self.enqueued.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
            Err(TrySendError::Disconnected(_)) => false,
        }
    }

    #[must_use]
    pub fn enqueued(&self) -> u64 {
        self.enqueued.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

pub struct LocalTxRelayObserver {
    relay: TxRelayQueue,
    gateway: Weak<MempoolGateway>,
}

impl LocalTxRelayObserver {
    #[must_use]
    pub fn new(relay: TxRelayQueue, gateway: Weak<MempoolGateway>) -> Self {
        Self { relay, gateway }
    }
}

impl MempoolObserver for LocalTxRelayObserver {
    fn on_mutation(&self, envelope: &MutationEnvelope) {
        if !matches!(
            envelope.origin,
            AdmissionOrigin::Rpc | AdmissionOrigin::Esplora | AdmissionOrigin::Reorg
        ) {
            return;
        }
        let Some(gateway) = self.gateway.upgrade() else {
            return;
        };
        for (index, change) in envelope.result.changes.iter().enumerate() {
            if !matches!(change.outcome, MutationOutcome::Accepted) {
                continue;
            }
            let txid = Txid(change.txid);
            let Some(sequence) = envelope.result.sequence_of(index) else {
                continue;
            };
            let wtxid = gateway
                .read()
                .entry_by_txid_at_sequence(&txid, sequence)
                .map(|entry| entry.wtxid);
            if let Some(wtxid) = wtxid {
                self.relay.announce(txid, wtxid, None, sequence);
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RelayOutcome {
    pub attempted: usize,
    pub excluded: usize,
    pub saturated: usize,
}

pub trait RelaySink: Send + Sync {
    fn poll(&self, _gateway: &MempoolGateway) {}

    fn announce_inv(
        &self,
        txid: Txid,
        wtxid: Wtxid,
        exclude: Option<u64>,
        sequence: u64,
    ) -> RelayOutcome;
}

pub struct PeerRelaySink {
    peers: Arc<crate::PeerTable>,
    ibd: Option<(
        Arc<bitcoin_rs_chain::InitialBlockDownload>,
        bitcoin_rs_primitives::Network,
    )>,
}

impl PeerRelaySink {
    #[must_use]
    pub fn new(peers: Arc<crate::PeerTable>) -> Self {
        Self { peers, ibd: None }
    }

    #[must_use]
    pub fn with_ibd(
        mut self,
        ibd: Arc<bitcoin_rs_chain::InitialBlockDownload>,
        network: bitcoin_rs_primitives::Network,
    ) -> Self {
        self.ibd = Some((ibd, network));
        self
    }
}

impl RelaySink for PeerRelaySink {
    fn poll(&self, gateway: &MempoolGateway) {
        use bitcoin::secp256k1::rand::SeedableRng as _;
        let ibd = crate::block_announce::ibd_active(self.ibd.as_ref());
        if !ibd {
            self.peers.poll_transaction_requests(gateway);
        }
        let mut rng = bitcoin::secp256k1::rand::rngs::StdRng::from_entropy();
        self.peers
            .poll_transaction_relay(gateway, std::time::Instant::now(), ibd, &mut rng);
    }

    fn announce_inv(
        &self,
        txid: Txid,
        wtxid: Wtxid,
        exclude: Option<u64>,
        sequence: u64,
    ) -> RelayOutcome {
        use bitcoin::secp256k1::rand::SeedableRng as _;
        let mut rng = bitcoin::secp256k1::rand::rngs::StdRng::from_entropy();
        let outcome = self.peers.queue_transaction_relay(
            RelayRequest::new(txid, wtxid, exclude, sequence),
            std::time::Instant::now(),
            &mut rng,
        );
        if outcome.saturated > 0 {
            tracing::debug!(%txid, peers = outcome.saturated, "transaction relay pending budget full");
        }
        outcome
    }
}

/// INVARIANT: the check does not mutate the mempool, relay queue, or
/// observer state. The read guard is released before this function
/// returns, so no caller holds it while it sends to peers.
fn transaction_is_live(gateway: &MempoolGateway, request: &RelayRequest) -> bool {
    gateway
        .read()
        .entry_by_txid_at_sequence(&request.txid, request.sequence)
        .is_some()
}

fn retry_initial_broadcast(
    gateway: &MempoolGateway,
    sink: &dyn RelaySink,
    cursor: &mut Option<Wtxid>,
) {
    let requests: Vec<_> = gateway
        .read()
        .unbroadcast_transactions_after(*cursor)
        .take(INITIAL_BROADCAST_BATCH)
        .map(|(txid, wtxid, sequence)| RelayRequest::new(txid, wtxid, None, sequence))
        .collect();
    *cursor = if requests.len() < INITIAL_BROADCAST_BATCH {
        None
    } else {
        requests.last().map(|request| request.wtxid)
    };
    for request in requests {
        if transaction_is_live(gateway, &request) {
            sink.announce_inv(request.txid, request.wtxid, None, request.sequence);
        }
    }
}

/// INVARIANT: no mempool guard is held while `sink` sends to peers.
#[cfg(test)]
pub(crate) fn drain_relay_queue(
    rx: &Receiver<RelayRequest>,
    sink: &dyn RelaySink,
    gateway: &MempoolGateway,
) -> usize {
    let mut processed = 0;
    while let Ok(request) = rx.try_recv() {
        if transaction_is_live(gateway, &request) {
            sink.announce_inv(
                request.txid,
                request.wtxid,
                request.source,
                request.sequence,
            );
        }
        processed += 1;
    }
    processed
}

/// INVARIANT: no mempool guard is held while `sink` sends to peers.
///
/// The worker applies the same send-time rule as `drain_relay_queue` and never retains a
/// strong gateway reference while it waits for queue input.
pub fn spawn_tx_relay_worker<S: RelaySink + 'static>(
    sink: S,
    rx: Receiver<RelayRequest>,
    gateway: Weak<MempoolGateway>,
    shutdown: impl Into<bitcoin_rs_chain::LatchReader>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    let shutdown = shutdown.into();
    std::thread::Builder::new()
        .name("bitcoin-rs-tx-relay".to_owned())
        .spawn(move || {
            let mut next_initial = std::time::Instant::now() + INITIAL_BROADCAST_RETRY;
            let mut initial_cursor = None;
            while !shutdown.load() {
                {
                    let Some(gateway) = gateway.upgrade() else {
                        break;
                    };
                    sink.poll(&gateway);
                    if std::time::Instant::now() >= next_initial {
                        retry_initial_broadcast(&gateway, &sink, &mut initial_cursor);
                        next_initial = std::time::Instant::now() + INITIAL_BROADCAST_RETRY;
                    }
                }
                match rx.recv_timeout(RELAY_POLL) {
                    Ok(request) => {
                        let Some(gateway) = gateway.upgrade() else {
                            break;
                        };
                        if transaction_is_live(&gateway, &request) {
                            sink.announce_inv(
                                request.txid,
                                request.wtxid,
                                request.source,
                                request.sequence,
                            );
                        }
                    }
                    Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
                    Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
                }
            }
        })
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests;
