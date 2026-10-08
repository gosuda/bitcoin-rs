//! Applied-tip publication: the tip, its certified count, and the chain event.

use super::Chainstate;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_primitives::Block;
use std::sync::Arc;

/// Publishes one applied tip and records the chain event that names it.
pub(super) fn publish_applied(
    handles: &Chainstate,
    tip: &TipSnapshot,
    kind: crate::events::HintKind,
) {
    handles.applied_tip.store(Some(Arc::new(tip.clone())));
    handles.chain_events.record(kind, tip.height, tip.hash);
}

/// The `tx_count` delta one block contributes to coinstats.
pub(super) fn tx_count_delta_for(block: &Block) -> u64 {
    u64::try_from(block.txs.len()).unwrap_or(u64::MAX)
}
