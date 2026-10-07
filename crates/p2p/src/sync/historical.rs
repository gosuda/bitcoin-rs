//! Bounded delivery of pinned snapshot history beside the foreground window.

use std::time::{Duration, Instant};

use bitcoin::hashes::Hash as _;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin_rs_primitives::Hash256;

use super::BlockSync;
use crate::download_window::{BlockDownloadPolicy, serves_requested_height};
use crate::{InboundBlock, Message, PeerSource};

#[derive(Clone, Copy)]
pub(super) struct HistoricalRequest {
    pub(super) hash: Hash256,
    pub(super) source: PeerSource,
    pub(super) sent: Instant,
}

const RETRY_AFTER: Duration = Duration::from_secs(30);

impl BlockSync {
    pub(super) fn advance_historical(&self) {
        let _work = self.historical_work.lock();
        let required = match self.chain.advance_historical() {
            Ok(required) => required,
            Err(error) => {
                tracing::error!(%error, "historical validation stopped");
                *self.historical_request.lock() = None;
                return;
            }
        };
        let Some((height, hash)) = required else {
            *self.historical_request.lock() = None;
            return;
        };
        let pending = *self.historical_request.lock();
        let now = Instant::now();
        if pending.as_ref().is_some_and(|request| {
            request.hash == hash
                && self.peer_table.is_current(request.source)
                && now.duration_since(request.sent) < RETRY_AFTER
        }) {
            return;
        }
        let previous_source = pending.map(|request| request.source);
        *self.historical_request.lock() = None;
        let policy = BlockDownloadPolicy {
            ibd: self.ibd.clone(),
            network: self.chain.network(),
            requested_height: height,
        };
        let mut peers = self.peer_table.infos();
        // Prefer a different live connection after an expired request.
        peers.sort_by_key(|info| previous_source.is_some_and(|source| source.addr == info.addr));
        for info in peers {
            if !serves_requested_height(&info, &policy) {
                continue;
            }
            let Some(source) = self.peer_table.ready_source(info.addr) else {
                continue;
            };
            let message = Message::GetData(vec![Inventory::WitnessBlock(
                bitcoin::BlockHash::from_byte_array(hash.to_le_bytes()),
            )]);
            if self
                .peer_table
                .send_then(source, message, || {
                    *self.historical_request.lock() = Some(HistoricalRequest {
                        hash,
                        source,
                        sent: now,
                    });
                })
                .is_ok()
            {
                break;
            }
        }
    }

    pub(super) fn receive_historical(&self, inbound: &InboundBlock) -> bool {
        let _work = self.historical_work.lock();
        let pending = *self.historical_request.lock();
        if pending.as_ref().is_none_or(|request| {
            request.hash != inbound.block.block_hash().0 || inbound.source != Some(request.source)
        }) {
            return false;
        }
        // Reject corrupted deliveries without treating their committed header
        // as invalid. Retain the lease on failure, so retry waits out the
        // deadline and prefers another peer rather than hammering this one.
        let result = self
            .chain
            .check_body_binding(&inbound.block)
            .and_then(|()| {
                self.chain
                    .connect_historical(&inbound.block, inbound.serialized.clone())
            });
        if let Err(error) = result {
            tracing::warn!(%error, "historical body rejected");
        } else {
            *self.historical_request.lock() = None;
        }
        true
    }
}
