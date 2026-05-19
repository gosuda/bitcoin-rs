//! Block download orchestrator.
//!
//! Reads the shared chain-tip / peer registry / outbound-channel handles
//! and, when a peer reports a longer chain, sends `getheaders` toward
//! that peer. The response-side (handling `headers` and `block` messages
//! to import blocks via `crate::import::import_block`) lands in a
//! follow-up.

use alloc::sync::Arc;
use alloc::vec::Vec;
use std::net::SocketAddr;

use arc_swap::ArcSwapOption;
use bitcoin::BlockHash;
use bitcoin::hashes::Hash as _;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_blockdata::GetHeadersMessage;
use bitcoin_rs_chain::{BlockTree, TipSnapshot};
use bitcoin_rs_p2p::{Message, PeerInfo};
use bitcoin_rs_primitives::{Hash256, Network};
use crossbeam_channel::Sender;
use hashbrown::HashMap;
use parking_lot::RwLock;

/// Maximum number of locator entries we ever send.
const LOCATOR_MAX_ENTRIES: usize = 32;
/// Wire protocol version we advertise on outbound `getheaders`.
const PROTOCOL_VERSION: u32 = 70_016;

/// Block download orchestrator.
pub struct BlockSync {
    chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
    peers: Arc<RwLock<Vec<PeerInfo>>>,
    peer_outbound: Arc<RwLock<HashMap<SocketAddr, Sender<Message>>>>,
    block_tree: Arc<RwLock<BlockTree>>,
    network: Network,
}

impl BlockSync {
    /// Constructs a new orchestrator over the supplied shared handles.
    #[must_use]
    pub const fn new(
        chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
        peers: Arc<RwLock<Vec<PeerInfo>>>,
        peer_outbound: Arc<RwLock<HashMap<SocketAddr, Sender<Message>>>>,
        block_tree: Arc<RwLock<BlockTree>>,
        network: Network,
    ) -> Self {
        Self {
            chain_tip,
            peers,
            peer_outbound,
            block_tree,
            network,
        }
    }

    /// Runs one orchestrator tick: picks a sync peer, builds a locator,
    /// pushes `getheaders` into the peer's outbound channel.
    pub fn tick(&self) {
        let our_height = self.chain_tip.load_full().map_or(0, |tip| tip.height);
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
        if let Some(tip) = self.chain_tip.load_full() {
            return self
                .block_tree
                .read()
                .block_locator(tip.tip_id, LOCATOR_MAX_ENTRIES);
        }
        alloc::vec![self.network.genesis_block_hash()]
    }
}
