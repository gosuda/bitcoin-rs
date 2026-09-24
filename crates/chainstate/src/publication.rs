//! Applied-tip publication: the tip, its certified count, and the chain event.

use super::Chainstate;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_primitives::Block;
use std::sync::Arc;
use std::sync::atomic::Ordering;

/// Publishes one applied tip and records the chain event that names it.
///
/// The tip carries the cumulative transaction count its durable commit
/// certified, so publication stores one value read from one source and cannot
/// publish a tip and a count from different commits. Extracted so the grouped
/// window path can publish a committed prefix in order after its durable
/// batch — the exact values the batch certified.
pub(super) fn publish_applied(
    handles: &Chainstate,
    tip: &TipSnapshot,
    kind: crate::events::HintKind,
) {
    handles.applied_tip.store(Some(Arc::new(tip.clone())));
    handles.chain_events.record(kind, tip.height, tip.hash);
    handles
        .chain_tx_count
        .store(tip.chain_tx_count.to_wire(), Ordering::Relaxed);
}

/// The `tx_count` delta one block contributes to coinstats.
///
/// One function, used by connect and by disconnect. Two copies of this
/// expression would be two chances for the rewind to subtract something the
/// apply never added.
pub(super) fn tx_count_delta_for(block: &Block) -> u64 {
    u64::try_from(block.txs.len()).unwrap_or(u64::MAX)
}
