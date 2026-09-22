//! Header request ownership, locator construction, and inbound header admission.

use super::BlockSync;
use super::HEADER_REQUEST_TIMEOUT;
use super::IdleFrontierProbeOutcome;
use super::LOCATOR_MAX_ENTRIES;
use super::PROTOCOL_VERSION;
use super::PendingHeaderRequest;
use super::chain::HeaderAdmission;
use super::frontier::SyncFrontier;
use super::peers::active_demonstrated_height;
use super::peers::is_peer_fault;
use super::peers::outranks;
use super::peers::sync_peer_candidate;
use crate::InboundHeaders;
use crate::Message;
use crate::PeerSource;
use crate::download_window::SyncPeer;
use bitcoin::hashes::Hash;
use bitcoin::p2p::message_blockdata::GetHeadersMessage;
use bitcoin_rs_primitives::Hash256;
use std::time::Instant;
use std::vec::Vec;

impl BlockSync {
    pub(super) fn drain_inbound_headers(&self) {
        let receiver = self.inbound_headers_rx.lock();
        let mut total_headers = 0_usize;
        while let Ok(InboundHeaders { headers, source }) = receiver.try_recv() {
            let batch_len = headers.len();
            total_headers = total_headers.saturating_add(batch_len);

            // A nonempty response consumes the request even when rejected.
            // An empty response supplies no new capability: retain its
            // deadline so idle discovery is paced and rotates to another peer.
            if let Some(source) = source.filter(|_| !headers.is_empty()) {
                if self.peer_table.is_current(source) {
                    let mut pending = self.pending_getheaders.lock();
                    if pending.is_some_and(|request| request.source == source) {
                        *pending = None;
                    }
                }
            }

            // Header admission moves the header tip, which the apply path
            // reads under the transition; the implementation holds that lock
            // inside `admit_headers` until commit.
            match self.chain.admit_headers(&headers) {
                HeaderAdmission::Accepted {
                    accepted,
                    announced_tip,
                    active_height,
                } => {
                    if let (Some(tip_hash), Some(source)) = (announced_tip, source) {
                        self.peer_table
                            .note_announced_tip(source, tip_hash, active_height);
                    }
                    self.refresh_active_peer_credit();
                    tracing::debug!(
                        accepted,
                        received = batch_len,
                        "block sync: accepted inbound headers batch",
                    );
                }
                HeaderAdmission::Rejected(error) if is_peer_fault(&error) => {
                    let mut blamed_peer = None;
                    if let Some(source) = source {
                        if self.peer_table.disconnect_source(source) {
                            self.body_sync
                                .lock()
                                .window
                                .mark_peer_unresponsive(source.addr, Instant::now());
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
                HeaderAdmission::Rejected(error) => {
                    tracing::warn!(
                        received = batch_len,
                        %error,
                        "block sync: rejected inbound headers batch",
                    );
                }
                HeaderAdmission::Refused(error) => {
                    tracing::debug!(%error, "block sync: header admission refused; dropping batch");
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
            let tree = self.chain.block_tree().read();
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
    /// `exclude` carries the source whose probe send failed this tick, so the
    /// same-tick fallback cannot retry it.
    pub(super) fn request_headers_from_best_peer(
        &self,
        frontier: &SyncFrontier,
        exclude: Option<PeerSource>,
    ) {
        if !self.frontier_chain_is_current(frontier) {
            return;
        }
        let applied_height = frontier.applied_tip.as_ref().map_or(0, |tip| tip.height);
        let header_height = frontier
            .header_tip
            .as_ref()
            .map_or(applied_height, |tip| tip.height);
        let mut header_peer: Option<(PeerSource, SyncPeer)> = None;
        for peer in &frontier.usable_peers {
            let Some(candidate) = sync_peer_candidate(&peer.info, applied_height) else {
                continue;
            };
            let source = peer.source;
            if exclude.is_some_and(|excluded| excluded == source) {
                continue;
            }
            if header_peer
                .as_ref()
                .is_none_or(|(_, current)| outranks(*current, candidate))
            {
                header_peer = Some((source, candidate));
            }
        }
        if let Some((source, peer)) = header_peer {
            let peer_best_height = u32::try_from(peer.best_known_height).unwrap_or(0);
            if peer_best_height > header_height {
                self.send_getheaders(
                    source,
                    header_height,
                    peer.best_known_height,
                    self.build_locator(),
                );
            }
        }
    }

    /// P2P-05: learn current peer capability when the known-header gap has no
    /// body work on the apply frontier: the probe fires only when the
    /// apply-frontier block itself is neither in flight nor staged. Staged
    /// successors behind an unowned or rejected frontier are stuck inventory
    /// awaiting the staged-body timeout, not progress. Start at the applied
    /// chain so a peer at our header tip returns branch evidence. Reuse the
    /// existing header-request deadline.
    pub(super) fn probe_idle_frontier(
        &self,
        frontier: &SyncFrontier,
        now: Instant,
    ) -> IdleFrontierProbeOutcome {
        if !self.frontier_chain_is_current(frontier) {
            return IdleFrontierProbeOutcome::NotSent;
        }
        let (Some(applied), Some(headers), Some(required)) = (
            frontier.applied_tip.as_ref(),
            frontier.header_tip.as_ref(),
            frontier.next_required,
        ) else {
            return IdleFrontierProbeOutcome::NotSent;
        };
        if applied.hash == headers.hash
            || self.apply_halted.load(std::sync::atomic::Ordering::Acquire)
        {
            return IdleFrontierProbeOutcome::NotSent;
        }
        // Body dispatch runs before this action. Revalidate the observed hash
        // so a successful getdata publication suppresses the recovery probe.
        {
            let state = self.body_sync.lock();
            if state.window.contains_pending(&required.hash)
                || state.stager.contains(&required.hash)
            {
                return IdleFrontierProbeOutcome::NotSent;
            }
        }
        let pending = frontier.header_request;
        if pending.is_some_and(|request| {
            now.saturating_duration_since(request.requested_at) < HEADER_REQUEST_TIMEOUT
                && frontier
                    .usable_peers
                    .iter()
                    .any(|peer| peer.source == request.source)
        }) {
            return IdleFrontierProbeOutcome::Sent;
        }
        let required = bitcoin::p2p::ServiceFlags::NETWORK.to_u64()
            | bitcoin::p2p::ServiceFlags::WITNESS.to_u64();
        let eligible = || {
            frontier
                .usable_peers
                .iter()
                .filter(|peer| peer.info.services & required == required)
        };
        // Rotate after the existing request expires, without a second queue.
        let session = eligible()
            .filter(|peer| pending.is_none_or(|request| peer.source.addr > request.source.addr))
            .min_by_key(|peer| peer.source.addr)
            .or_else(|| eligible().min_by_key(|peer| peer.source.addr));
        let Some(peer) = session else {
            return IdleFrontierProbeOutcome::NotSent;
        };
        let source = peer.source;
        // Anchor on the active chain at the applied height, not on the
        // applied tip's branch. During a deep header-first reorg the applied
        // tip may still sit on the losing branch. A locator from that branch
        // can match only at a common ancestor more than the 2,000-header wire
        // page behind us, so every probe repeats the same insufficient page
        // and never demonstrates a height above the applied tip.
        let locator = {
            let tree = self.chain.block_tree().read();
            let Some(active_anchor) = tree.node_at_height_from(headers.tip_id, applied.height)
            else {
                return IdleFrontierProbeOutcome::NotSent;
            };
            tree.block_locator(active_anchor, LOCATOR_MAX_ENTRIES)
        };
        let sent = self.send_getheaders(
            source,
            applied.height,
            i32::try_from(headers.height).unwrap_or(i32::MAX),
            locator,
        );
        if sent {
            metrics::counter!("node.sync.idle_frontier_probes").increment(1);
            IdleFrontierProbeOutcome::Sent
        } else {
            IdleFrontierProbeOutcome::SendFailed(source)
        }
    }

    pub(super) fn send_getheaders(
        &self,
        source: crate::PeerSource,
        our_height: u32,
        target_height: i32,
        locator: Vec<Hash256>,
    ) -> bool {
        let Some(locator_tip_hash) = locator.first().copied() else {
            return false;
        };
        let target_height = u32::try_from(target_height).unwrap_or(0);
        let now = Instant::now();
        if self.has_pending_getheaders(now) {
            tracing::trace!(
                peer_addr = %source.addr,
                our_height,
                target_height,
                "block sync: getheaders already pending",
            );
            return false;
        }
        let locator_hashes: Vec<bitcoin::BlockHash> = locator
            .into_iter()
            .map(|hash| bitcoin::BlockHash::from_byte_array(*hash.as_byte_array()))
            .collect();
        let msg = Message::GetHeaders(GetHeadersMessage::new(
            locator_hashes,
            bitcoin::BlockHash::all_zeros(),
        ));
        let tx = self.peer_table.lease_source(source);
        let Some(tx) = tx else {
            tracing::warn!(
                peer_addr = %source.addr,
                "block sync: target peer no longer has outbound channel"
            );
            return false;
        };
        let mut sent = false;
        self.peer_table.with_current(source, || {
            if tx.send(msg).is_ok() {
                *self.pending_getheaders.lock() = Some(PendingHeaderRequest {
                    source,
                    locator_tip_hash,
                    target_height,
                    requested_at: now,
                });
                sent = true;
            }
        });
        if !sent {
            tracing::warn!(
                peer_addr = %source.addr,
                "block sync: outbound channel disconnected"
            );
            // The send failure means this connection is gone: evict it so the
            // scheduler cannot re-pick a dead peer every tick. The identity
            // check inside `disconnect_source` keeps a same-address
            // replacement untouched, and only then is a pending request keyed
            // to this address dropped so a fast reconnect does not inherit a
            // stale deadline gate.
            if self.peer_table.disconnect_source(source) {
                let mut pending = self.pending_getheaders.lock();
                if pending.is_some_and(|request| request.source == source) {
                    *pending = None;
                }
            }
            return false;
        }
        tracing::debug!(
            peer_addr = %source.addr,
            our_height,
            target_height,
            protocol_version = PROTOCOL_VERSION,
            "block sync: sent getheaders"
        );
        true
    }

    pub(super) fn has_pending_getheaders(&self, now: Instant) -> bool {
        let pending = *self.pending_getheaders.lock();
        let Some(pending) = pending else {
            return false;
        };
        now.duration_since(pending.requested_at) < HEADER_REQUEST_TIMEOUT
    }

    pub(super) fn build_locator(&self) -> Vec<Hash256> {
        if let Some(tip) = self.chain.chain_tip().load_full() {
            return self
                .chain
                .block_tree()
                .read()
                .block_locator(tip.tip_id, LOCATOR_MAX_ENTRIES);
        }
        std::vec![self.chain.network().genesis_block_hash()]
    }
}
