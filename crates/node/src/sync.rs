//! Block download orchestrator.
//!
//! Reads the shared apply handles / peer registry / outbound-channel handles
//! and, when a peer reports a longer chain, sends `getheaders` toward
//! that peer. Inbound `headers` batches are drained into the shared
//! [`bitcoin_rs_chain::BlockTree`]; inbound full blocks are applied through
//! [`crate::apply::apply_block`].

use alloc::sync::Arc;
use alloc::vec::Vec;
use std::net::SocketAddr;

use bitcoin::BlockHash;
use bitcoin::hashes::Hash as _;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_blockdata::GetHeadersMessage;
use bitcoin_rs_p2p::{Message, PeerInfo};
use bitcoin_rs_primitives::Hash256;
use crossbeam_channel::{Receiver, Sender};
use hashbrown::HashMap;
use parking_lot::{Mutex, RwLock};

/// Maximum number of locator entries we ever send.
const LOCATOR_MAX_ENTRIES: usize = 32;
/// Wire protocol version we advertise on outbound `getheaders`.
const PROTOCOL_VERSION: u32 = 70_016;

/// Block download orchestrator.
pub struct BlockSync {
    handles: crate::apply::ApplyHandles,
    peers: Arc<RwLock<Vec<PeerInfo>>>,
    peer_outbound: Arc<RwLock<HashMap<SocketAddr, Sender<Message>>>>,
    inbound_headers_rx: Arc<Mutex<Receiver<Vec<bitcoin::block::Header>>>>,
    inbound_blocks_rx: Arc<Mutex<Receiver<bitcoin::Block>>>,
}

impl BlockSync {
    /// Constructs a new orchestrator over the supplied shared handles.
    #[must_use]
    pub const fn new(
        handles: crate::apply::ApplyHandles,
        peers: Arc<RwLock<Vec<PeerInfo>>>,
        peer_outbound: Arc<RwLock<HashMap<SocketAddr, Sender<Message>>>>,
        inbound_headers_rx: Arc<Mutex<Receiver<Vec<bitcoin::block::Header>>>>,
        inbound_blocks_rx: Arc<Mutex<Receiver<bitcoin::Block>>>,
    ) -> Self {
        Self {
            handles,
            peers,
            peer_outbound,
            inbound_headers_rx,
            inbound_blocks_rx,
        }
    }

    /// Runs one orchestrator tick: picks a sync peer, builds a locator,
    /// pushes `getheaders` into the peer's outbound channel.
    pub fn tick(&self) {
        self.drain_inbound_headers();
        self.drain_inbound_blocks();
        let our_height = self
            .handles
            .applied_tip
            .load_full()
            .map_or(0, |tip| tip.height);
        let Some(target) = self.pick_sync_peer(our_height) else {
            tracing::trace!(our_height, "block sync: no peer above current height");
            return;
        };
        let locator = self.build_locator();
        let locator_hashes: Vec<BlockHash> = locator
            .into_iter()
            .map(|hash| BlockHash::from_byte_array(hash.to_le_bytes()))
            .collect();
        let msg = NetworkMessage::GetHeaders(GetHeadersMessage::new(
            locator_hashes,
            BlockHash::all_zeros(),
        ));
        let tx = {
            let outbound = self.peer_outbound.read();
            outbound.get(&target.addr).cloned()
        };
        let Some(tx) = tx else {
            tracing::warn!(
                peer_addr = %target.addr,
                "block sync: target peer no longer has outbound channel"
            );
            return;
        };
        if tx.send(msg).is_err() {
            tracing::warn!(
                peer_addr = %target.addr,
                "block sync: outbound channel disconnected"
            );
            return;
        }
        tracing::debug!(
            peer_addr = %target.addr,
            our_height,
            target_height = target.start_height,
            protocol_version = PROTOCOL_VERSION,
            "block sync: sent getheaders"
        );
    }

    fn drain_inbound_headers(&self) {
        let receiver = self.inbound_headers_rx.lock();
        let mut total_headers = 0_usize;
        while let Ok(batch) = receiver.try_recv() {
            let batch_len = batch.len();
            total_headers = total_headers.saturating_add(batch_len);
            let mut tree = self.handles.block_tree.write();
            match bitcoin_rs_chain::accept_headers(&mut tree, &batch, self.handles.network) {
                Ok(node_ids) => {
                    tracing::debug!(
                        accepted = node_ids.len(),
                        received = batch_len,
                        "block sync: accepted inbound headers batch",
                    );
                }
                Err(error) => {
                    tracing::warn!(
                        received = batch_len,
                        %error,
                        "block sync: rejected inbound headers batch",
                    );
                }
            }
        }
        if total_headers > 0 {
            tracing::debug!(total_headers, "block sync: drained inbound headers");
        }
    }

    fn drain_inbound_blocks(&self) {
        let receiver = self.inbound_blocks_rx.lock();
        let mut applied = 0_usize;
        let mut failed = 0_usize;
        while let Ok(block) = receiver.try_recv() {
            match crate::apply::apply_block(&self.handles, &block) {
                Ok(tip) => {
                    applied += 1;
                    tracing::debug!(
                        height = tip.height,
                        %tip.hash,
                        "block sync: applied inbound block"
                    );
                }
                Err(error) => {
                    failed += 1;
                    tracing::warn!(
                        %error,
                        "block sync: failed to apply inbound block"
                    );
                }
            }
        }
        if applied > 0 || failed > 0 {
            tracing::debug!(applied, failed, "block sync: drained inbound blocks");
        }
    }

    fn pick_sync_peer(&self, our_height: u32) -> Option<PeerInfo> {
        let peers = self.peers.read();
        peers
            .iter()
            .filter(|peer| {
                u32::try_from(peer.start_height)
                    .ok()
                    .is_some_and(|height| height > our_height)
            })
            .max_by_key(|peer| peer.start_height)
            .cloned()
    }

    fn build_locator(&self) -> Vec<Hash256> {
        if let Some(tip) = self.handles.chain_tip.load_full() {
            return self
                .handles
                .block_tree
                .read()
                .block_locator(tip.tip_id, LOCATOR_MAX_ENTRIES);
        }
        alloc::vec![self.handles.network.genesis_block_hash()]
    }
}
