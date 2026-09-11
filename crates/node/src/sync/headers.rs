//! Header request ownership, locator construction, and inbound header admission.

use super::BlockSync;
use super::HEADER_REQUEST_TIMEOUT;
use super::LOCATOR_MAX_ENTRIES;
use super::PROTOCOL_VERSION;
use super::PendingHeaderRequest;
use super::peers::active_demonstrated_height;
use super::peers::is_peer_fault;
use super::peers::outranks;
use super::peers::sync_peer_candidate;
use alloc::vec::Vec;
use bitcoin::hashes::Hash;
use bitcoin::p2p::message_blockdata::GetHeadersMessage;
use bitcoin_rs_p2p::InboundHeaders;
use bitcoin_rs_p2p::Message;
use bitcoin_rs_p2p::PeerSource;
use bitcoin_rs_p2p::download_window::SyncPeer;
use bitcoin_rs_primitives::Hash256;
use std::net::SocketAddr;
use std::time::Instant;

impl BlockSync {
    #[allow(clippy::too_many_lines)]
    pub(super) fn drain_inbound_headers(&self) {
        let receiver = self.inbound_headers_rx.lock();
        let mut total_headers = 0_usize;
        while let Ok(InboundHeaders { headers, source }) = receiver.try_recv() {
            let batch_len = headers.len();
            total_headers = total_headers.saturating_add(batch_len);

            // A response consumes the current peer's request even when header
            // acceptance rejects it; otherwise sync stalls until timeout.
            if let Some(source) = source {
                if self.peer_table.is_current(source) {
                    let mut pending = self.pending_getheaders.lock();
                    if pending.is_some_and(|request| request.peer_addr == source.addr) {
                        *pending = None;
                    }
                }
            }

            let mut tree = self.handles.block_tree.write();
            let acceptance = bitcoin_rs_chain::accept_headers(
                &mut tree,
                &headers,
                self.handles.network,
                bitcoin_rs_chain::current_unix_seconds(),
            );
            match acceptance {
                Ok(node_ids) => {
                    let announced_tip = node_ids
                        .last()
                        .and_then(|id| tree.node(*id).ok())
                        .map(|node| node.hash);
                    let active_height =
                        tree.tip()
                            .zip(announced_tip)
                            .and_then(|(active_tip, hash)| {
                                tree.active_height_of(active_tip.tip_id, hash)
                                    .and_then(|height| i32::try_from(height).ok())
                            });
                    self.handles.assume_valid_gate.evaluate(&tree);
                    drop(tree);
                    if let (Some(tip_hash), Some(source)) = (announced_tip, source) {
                        self.peer_table
                            .note_announced_tip(source, tip_hash, active_height);
                    }
                    self.refresh_active_peer_credit();
                    tracing::debug!(
                        accepted = node_ids.len(),
                        received = batch_len,
                        "block sync: accepted inbound headers batch",
                    );
                }
                Err(error) if is_peer_fault(&error) => {
                    drop(tree);
                    let mut blamed_peer = None;
                    if let Some(source) = source {
                        let mut window = self.download_window.lock();
                        if self.peer_table.disconnect_source(source) {
                            window.mark_peer_unresponsive(source.addr, Instant::now());
                            blamed_peer = Some(source.addr);
                        }
                    }
                    if let Some(peer_addr) = blamed_peer {
                        tracing::warn!(
                            peer_addr = %peer_addr,
                            received = batch_len,
                            %error,
                            "block sync: peer served invalid headers; disconnecting",
                        );
                    } else {
                        tracing::warn!(
                            received = batch_len,
                            %error,
                            "block sync: rejected source-less or stale headers batch",
                        );
                    }
                }
                Err(error) => {
                    drop(tree);
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

    pub(super) fn refresh_active_peer_credit(&self) {
        let sessions = self.peer_table.sessions();
        let updates: Vec<(PeerSource, i32)> = {
            let tree = self.handles.block_tree.read();
            let Some(active_tip) = tree.tip() else {
                return;
            };
            sessions
                .into_iter()
                .filter_map(|session| {
                    let info = session.info?;
                    let height = active_demonstrated_height(
                        &tree,
                        active_tip.tip_id,
                        &session.demonstrated_tips,
                    )?;
                    let height = i32::try_from(height).ok()?;
                    (height > info.best_known_height)
                        .then_some((session.lease.source(session.addr), height))
                })
                .collect()
        };
        for (source, height) in updates {
            self.peer_table.note_announced_height(source, height);
        }
    }

    /// Requests the next header batch from the highest peer above the applied
    /// tip, using a locator taken after `drain_inbound_headers` so it reflects
    /// headers accepted this tick.
    ///
    /// Called at the end of `tick`, after the getdata fan-out. Position is
    /// deliberate: peers observe getdata before getheaders within a tick, which
    /// several sync tests assert. Ordering carries no protocol meaning, but
    /// both messages leave in the same tick either way, so there is no
    /// throughput reason to prefer the other order.
    pub(super) fn request_headers_from_best_peer(&self) {
        let applied_tip = self.handles.applied_tip.load_full();
        let applied_height = applied_tip.as_ref().map_or(0, |tip| tip.height);
        let chain_tip = self.handles.chain_tip.load_full();
        let header_height = chain_tip.as_ref().map_or(applied_height, |tip| tip.height);
        let mut header_peer: Option<SyncPeer> = None;
        for peer in self.peer_table.infos() {
            let Some(candidate) = sync_peer_candidate(&peer, applied_height) else {
                continue;
            };
            if header_peer.is_none_or(|current| outranks(current, candidate)) {
                header_peer = Some(candidate);
            }
        }
        if let Some(peer) = header_peer {
            let peer_best_height = u32::try_from(peer.best_known_height).unwrap_or(0);
            if peer_best_height > header_height {
                self.send_getheaders(peer.addr, header_height, peer.best_known_height);
            }
        }
    }

    pub(super) fn send_getheaders(
        &self,
        sync_peer_addr: SocketAddr,
        our_height: u32,
        target_height: i32,
    ) {
        let locator = self.build_locator();
        let Some(locator_tip_hash) = locator.first().copied() else {
            return;
        };
        let target_height = u32::try_from(target_height).unwrap_or(0);
        let now = Instant::now();
        let _window = self.download_window.lock();
        if self.has_pending_getheaders(sync_peer_addr, locator_tip_hash, target_height, now) {
            tracing::trace!(
                peer_addr = %sync_peer_addr,
                our_height,
                target_height,
                "block sync: getheaders already pending",
            );
            return;
        }
        let locator_hashes: Vec<bitcoin::BlockHash> = locator
            .into_iter()
            .map(|hash| bitcoin::BlockHash::from_byte_array(*hash.as_byte_array()))
            .collect();
        let msg = Message::GetHeaders(GetHeadersMessage::new(
            locator_hashes,
            bitcoin::BlockHash::all_zeros(),
        ));
        let tx = self.peer_table.lease(sync_peer_addr);
        let Some(tx) = tx else {
            tracing::warn!(
                peer_addr = %sync_peer_addr,
                "block sync: target peer no longer has outbound channel"
            );
            return;
        };
        if tx.send(msg).is_err() {
            tracing::warn!(
                peer_addr = %sync_peer_addr,
                "block sync: outbound channel disconnected"
            );
            return;
        }
        *self.pending_getheaders.lock() = Some(PendingHeaderRequest {
            peer_addr: sync_peer_addr,
            locator_tip_hash,
            target_height,
            requested_at: now,
        });
        tracing::debug!(
            peer_addr = %sync_peer_addr,
            our_height,
            target_height,
            protocol_version = PROTOCOL_VERSION,
            "block sync: sent getheaders"
        );
    }

    pub(super) fn has_pending_getheaders(
        &self,
        peer_addr: SocketAddr,
        locator_tip_hash: Hash256,
        target_height: u32,
        now: Instant,
    ) -> bool {
        let pending = *self.pending_getheaders.lock();
        let Some(pending) = pending else {
            return false;
        };
        pending.peer_addr == peer_addr
            && pending.locator_tip_hash == locator_tip_hash
            && pending.target_height == target_height
            && now.duration_since(pending.requested_at) < HEADER_REQUEST_TIMEOUT
    }

    pub(super) fn build_locator(&self) -> Vec<Hash256> {
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
