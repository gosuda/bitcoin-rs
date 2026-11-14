pub mod block_announce;
pub mod block_stager;
pub mod chain_query;
pub mod download_window;
pub mod sync;
pub mod tx_policy;
pub mod tx_relay;

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::as_conversions,
    reason = "relocated p2p orchestration test fixtures"
)]
mod block_forward_tests;
#[cfg(test)]
mod compact_blocks_tests;
#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "relocated p2p orchestration test fixtures"
)]
mod dispatch_tests;
#[cfg(test)]
#[expect(
    clippy::as_conversions,
    reason = "relocated p2p orchestration test fixtures"
)]
mod header_ingress_tests;
#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "relocated p2p orchestration test fixtures"
)]
mod inv_tests;
#[cfg(test)]
mod loopback_serving_tests;
#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::as_conversions,
    reason = "relocated p2p orchestration test fixtures"
)]
mod writer_shutdown_tests;

pub use block_announce::{
    BlockAnnounceConfig, BlockAnnounceQueue, BlockAnnounceReceiver, BlockAnnouncer,
    MAX_BLOCKS_TO_ANNOUNCE, MAX_HIGH_BANDWIDTH_PEERS, spawn_block_announce_worker,
};
pub(crate) use block_stager::BlockStager;
pub use chain_query::{ActiveChainQuery, RecentBlockSlot};
pub use download_window::default_sync_budget;
pub use sync::{BlockSync, StaleTipRetainer, SyncChain};
pub use tx_policy::{
    InboundBody, InboundPackage, MAX_DECODED_PACKAGES_PER_PEER, NodeTxPolicy, OpenedPackage,
    PackageCapacity, PackageCharge, PackageOpening, PackagePlan, PackageRefusal, PackageRejection,
    PackageTeardown, PackageToken, TxPolicy, plan_package_charge,
};
pub use tx_relay::{
    DEFAULT_TX_RELAY_QUEUE_CAPACITY, LocalTxRelayObserver, PeerRelaySink, RelayOutcome,
    RelayRequest, RelaySink, TxRelayQueue, spawn_tx_relay_worker,
};

use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin_rs_consensus::primitives::{Hash256, Header, Network, Tx, Txid, Wtxid};
use bitcoin_rs_wire::compact_blocks::CompactBlockHints;
use bitcoin_rs_wire::connection::{PeerRemote, PeerSource};
use bitcoin_rs_wire::dispatch::TxInventory;
use bitcoin_rs_wire::inbound::{BlockMemoryCredit, InboundBlock};
use bitcoin_rs_wire::listener::{
    BlockAnnounceObserver, BlockSyncObserver, IbdState, TxIngressObserver, TxPolicyObserver,
};
use bitcoin_rs_wire::wire::{Message, PeerError};
use crossbeam_channel::Sender;
use std::sync::Arc;
pub fn peer_token(source: PeerSource) -> bitcoin_rs_mempool::PeerToken {
    bitcoin_rs_mempool::PeerToken {
        endpoint: source.endpoint,
        addr: PeerRemote::from(source).endpoint(),
        connection_id: source.connection_id.get(),
    }
}

pub fn peer_source(token: bitcoin_rs_mempool::PeerToken) -> PeerSource {
    PeerSource::from_raw(token.endpoint, token.connection_id)
}

pub struct NodeIbd(pub Arc<bitcoin_rs_execution::chain::InitialBlockDownload>);

impl IbdState for NodeIbd {
    fn is_ibd(&self, now: u64, network: Network) -> bool {
        self.0.is_active(now, network)
    }
}

pub struct NodeTxInventory(pub Arc<bitcoin_rs_mempool::MempoolGateway>);

impl TxInventory for NodeTxInventory {
    fn transaction_sent(&self, wtxid: Wtxid) {
        self.0.mark_broadcast(wtxid);
    }
    fn transaction_send_committed(&self, wtxid: Wtxid) {
        self.0.commit_broadcast(wtxid);
    }
    fn transaction_send_failed(&self, wtxid: Wtxid) {
        self.0.restore_unbroadcast(wtxid);
    }
    fn resident_ancestor_package(&self, wtxid: Wtxid) -> Option<Vec<Wtxid>> {
        bitcoin_rs_mempool::MempoolGateway::ancestor_package_wtxids(&self.0, wtxid)
    }
    fn resident_package(&self, wtxids: &[Wtxid]) -> Option<Vec<Arc<Tx>>> {
        bitcoin_rs_mempool::MempoolGateway::resident_package(&self.0, wtxids)
    }
    fn have_tx(&self, hash: Hash256, hash_is_wtxid: bool) -> bool {
        bitcoin_rs_mempool::MempoolGateway::have_tx(&self.0, hash, hash_is_wtxid)
    }
    fn get_tx(&self, txid: Txid) -> Option<Tx> {
        bitcoin_rs_mempool::MempoolGateway::get_tx(&self.0, txid)
    }
    fn get_tx_by_wtxid(&self, wtxid: Wtxid) -> Option<Tx> {
        bitcoin_rs_mempool::MempoolGateway::get_tx_by_wtxid(&self.0, wtxid)
    }
}

pub struct RefTxInventory<'a>(pub &'a bitcoin_rs_mempool::MempoolGateway);

impl TxInventory for RefTxInventory<'_> {
    fn transaction_sent(&self, wtxid: Wtxid) {
        self.0.mark_broadcast(wtxid);
    }
    fn transaction_send_committed(&self, wtxid: Wtxid) {
        self.0.commit_broadcast(wtxid);
    }
    fn transaction_send_failed(&self, wtxid: Wtxid) {
        self.0.restore_unbroadcast(wtxid);
    }
    fn resident_ancestor_package(&self, wtxid: Wtxid) -> Option<Vec<Wtxid>> {
        bitcoin_rs_mempool::MempoolGateway::ancestor_package_wtxids(self.0, wtxid)
    }
    fn resident_package(&self, wtxids: &[Wtxid]) -> Option<Vec<Arc<Tx>>> {
        bitcoin_rs_mempool::MempoolGateway::resident_package(self.0, wtxids)
    }
    fn have_tx(&self, hash: Hash256, hash_is_wtxid: bool) -> bool {
        bitcoin_rs_mempool::MempoolGateway::have_tx(self.0, hash, hash_is_wtxid)
    }
    fn get_tx(&self, txid: Txid) -> Option<Tx> {
        bitcoin_rs_mempool::MempoolGateway::get_tx(self.0, txid)
    }
    fn get_tx_by_wtxid(&self, wtxid: Wtxid) -> Option<Tx> {
        bitcoin_rs_mempool::MempoolGateway::get_tx_by_wtxid(self.0, wtxid)
    }
}

impl CompactBlockHints for NodeTxInventory {
    fn for_each_identity(&self, f: &mut dyn FnMut(Txid, Wtxid)) {
        bitcoin_rs_mempool::MempoolGateway::for_each_reconstruction_identity(&self.0, f);
    }
    fn get_tx_by_txid(&self, txid: Txid) -> Option<Tx> {
        bitcoin_rs_mempool::MempoolGateway::reconstruction_tx_by_txid(&self.0, txid)
    }
    fn get_tx_by_wtxid(&self, wtxid: Wtxid) -> Option<Tx> {
        bitcoin_rs_mempool::MempoolGateway::reconstruction_tx_by_wtxid(&self.0, wtxid)
    }
}

impl CompactBlockHints for RefTxInventory<'_> {
    fn for_each_identity(&self, f: &mut dyn FnMut(Txid, Wtxid)) {
        bitcoin_rs_mempool::MempoolGateway::for_each_reconstruction_identity(self.0, f);
    }
    fn get_tx_by_txid(&self, txid: Txid) -> Option<Tx> {
        bitcoin_rs_mempool::MempoolGateway::reconstruction_tx_by_txid(self.0, txid)
    }
    fn get_tx_by_wtxid(&self, wtxid: Wtxid) -> Option<Tx> {
        bitcoin_rs_mempool::MempoolGateway::reconstruction_tx_by_wtxid(self.0, wtxid)
    }
}

pub struct NodeTxIngress {
    inbound_tx: Sender<InboundBody>,
    package_capacity: PackageCapacity,
    tx_policy: Arc<NodeTxPolicy>,
    inventory: Arc<NodeTxInventory>,
    cancel: bitcoin_rs_consensus::latch::LatchReader,
}

impl NodeTxIngress {
    pub fn new(
        inbound_tx: Sender<InboundBody>,
        package_capacity: PackageCapacity,
        tx_policy: Arc<NodeTxPolicy>,
        inventory: Arc<NodeTxInventory>,
        cancel: bitcoin_rs_consensus::latch::LatchReader,
    ) -> Self {
        Self {
            inbound_tx,
            package_capacity,
            tx_policy,
            inventory,
            cancel,
        }
    }
}

impl TxIngressObserver for NodeTxIngress {
    fn on_inbound_tx(&self, source: PeerSource, tx: Tx, memory_credit: Option<BlockMemoryCredit>) {
        let body = InboundBody::from(
            bitcoin_rs_wire::InboundTx::new(tx, source).with_memory_credit(memory_credit),
        );
        if self.cancel.is_triggered() {
            return;
        }
        let dropped = match self.inbound_tx.try_send(body) {
            Ok(()) => None,
            Err(crossbeam_channel::TrySendError::Full(b)) => Some(b),
            Err(crossbeam_channel::TrySendError::Disconnected(b)) => Some(b),
        };
        if let Some(InboundBody::Tx(inbound)) = dropped {
            let source = inbound.source;
            let txid = inbound.tx.txid();
            let wtxid = inbound.tx.wtxid();
            drop(inbound);
            self.tx_policy
                .transaction_response_completed(source, txid, wtxid);
            self.tx_policy
                .poll_transaction_response(self.inventory.as_ref(), txid, wtxid);
        }
    }

    fn on_inbound_package(
        &self,
        source: PeerSource,
        payload: bytes::Bytes,
    ) -> Result<(), PeerError> {
        let package = match self.tx_policy.admit_package(
            &self.package_capacity,
            self.inventory.as_ref(),
            source,
            payload,
        ) {
            Ok(pkg) => pkg,
            Err(refusal) if refusal.is_peer_fault() => {
                return Err(PeerError::Protocol(
                    "malformed package in violation of protocol",
                ));
            }
            Err(_) => return Ok(()),
        };
        let body = InboundBody::from(package);
        if self.cancel.is_triggered() {
            return Ok(());
        }
        let refused = match self.inbound_tx.try_send(body) {
            Ok(()) => None,
            Err(crossbeam_channel::TrySendError::Full(b)) => Some(b),
            Err(crossbeam_channel::TrySendError::Disconnected(b)) => Some(b),
        };
        if let Some(InboundBody::Package(pkg)) = refused {
            self.tx_policy
                .package_response_rejected(pkg.into_token(), self.inventory.as_ref());
        }
        Ok(())
    }
}

impl TxPolicyObserver for NodeTxPolicy {
    fn announce_transactions(&self, source: PeerSource, items: &[Inventory]) {
        self.announce_transactions(source, items);
    }

    fn request_parent_transactions(&self, source: PeerSource, items: &[Inventory]) -> bool {
        self.request_parent_transactions(source, items)
    }

    fn transaction_not_found(
        &self,
        source: PeerSource,
        items: &[Inventory],
        inventory: &dyn TxInventory,
    ) {
        self.transaction_not_found(source, items, inventory);
    }

    fn poll_transaction_requests(&self, inventory: &dyn TxInventory) {
        self.poll_transaction_requests(inventory);
    }

    fn transaction_peer_disconnected(&self, source: PeerSource, inventory: &dyn TxInventory) {
        self.transaction_peer_disconnected(source, inventory);
    }

    fn note_transaction_inventory(&self, source: PeerSource, items: &[Inventory]) {
        self.note_transaction_inventory(source, items);
    }

    fn request_package_transactions(&self, source: PeerSource, subject: Wtxid, wtxids: Vec<Wtxid>) {
        self.request_package_transactions(source, subject, wtxids);
    }

    fn release_package_info(
        &self,
        source: PeerSource,
        subject: Wtxid,
        inventory: &dyn TxInventory,
    ) {
        self.release_package_info(source, subject, inventory);
    }

    fn receive_fee_filter(&self, source: PeerSource, rate: i64) {
        self.receive_fee_filter(source, rate);
    }
}

impl BlockSyncObserver for sync::BlockSync {
    fn announce_block(&self, source: PeerSource, hash: Hash256) {
        self.announce_block(source, hash);
    }
    fn block_not_found(&self, source: PeerSource, items: &[Inventory]) -> bool {
        self.block_not_found(source, items)
    }
    fn note_header_response_received(&self, source: PeerSource) {
        self.note_header_response_received(source);
    }
    fn owns_body_fetch(&self, source: PeerSource, hash: Hash256) -> bool {
        self.owns_body_fetch(source, hash)
    }
    fn compact_reconstruction_admissible(&self, source: PeerSource, header: &Header) -> bool {
        self.compact_reconstruction_admissible(source, header)
    }
    fn enqueue_owned_body_fetch(
        &self,
        source: PeerSource,
        hash: Hash256,
        follow_up: &mut dyn FnMut() -> bool,
    ) -> bool {
        self.enqueue_owned_body_fetch(source, hash, follow_up)
    }
    fn note_stale_tip_heard(&self, source: PeerSource, tip_hash: Hash256) {
        self.stale_tips().note_heard(source, tip_hash);
    }
    fn allow_extra_full_relay_dial(&self) -> bool {
        self.allow_extra_full_relay_dial()
    }
    fn is_downloading_bodies(&self, source: PeerSource) -> bool {
        self.is_downloading_bodies(source)
    }
}

impl BlockAnnounceObserver for block_announce::BlockAnnouncer {
    fn on_peer_ready(&self) {
        self.on_peer_ready();
    }
    fn on_peer_disconnected(&self, source: PeerSource) {
        self.on_peer_disconnected(source);
    }
    fn reconcile_high_bandwidth_peers(&self) {
        self.reconcile_high_bandwidth_peers();
    }
}
