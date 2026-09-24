//! Coherent applied-tip and chain-transaction-count publication.

use super::AppliedPublication;
use super::Chainstate;
use bitcoin_rs_chain::{ChainTxCount, TipSnapshot};
use bitcoin_rs_primitives::Block;
use std::sync::Arc;
use std::sync::atomic::Ordering;

/// Publishes one connected block: the applied tip, the chain event, and the
/// cumulative count its durable commit certified, under one seqlock
/// publication.
///
/// Extracted so the grouped window path can publish a committed prefix in
/// order after its durable batch — the exact values the batch certified.
pub(super) fn publish_connect(
    handles: &Chainstate,
    tip: &TipSnapshot,
    chain_tx_count: ChainTxCount,
) {
    let _publication = begin_applied_publication(handles);
    handles.applied_tip.store(Some(Arc::new(tip.clone())));
    handles
        .chain_events
        .record(crate::events::HintKind::Connected, tip.height, tip.hash);
    handles
        .chain_tx_count
        .store(chain_tx_count.to_wire(), Ordering::Relaxed);
}

/// Publishes the parent tip after a disconnect, with the cumulative count its
/// durable commit certified, under one seqlock publication.
pub(super) fn publish_disconnect(
    handles: &Chainstate,
    parent_tip: &TipSnapshot,
    chain_tx_count: ChainTxCount,
) {
    let _publication = begin_applied_publication(handles);
    handles
        .applied_tip
        .store(Some(Arc::new(parent_tip.clone())));
    handles.chain_events.record(
        crate::events::HintKind::Disconnected,
        parent_tip.height,
        parent_tip.hash,
    );
    handles
        .chain_tx_count
        .store(chain_tx_count.to_wire(), Ordering::Relaxed);
}

pub(super) fn begin_applied_publication(handles: &Chainstate) -> AppliedPublication<'_> {
    let previous = handles.applied_seq.fetch_add(1, Ordering::AcqRel);
    debug_assert_eq!(
        previous & 1,
        0,
        "applied-pair publication is exclusive under the transition lock"
    );
    AppliedPublication {
        seq: &handles.applied_seq,
    }
}

/// The `tx_count` delta one block contributes to coinstats.
///
/// One function, used by connect and by disconnect. Two copies of this
/// expression would be two chances for the rewind to subtract something the
/// apply never added.
pub(super) fn tx_count_delta_for(block: &Block) -> u64 {
    u64::try_from(block.txs.len()).unwrap_or(u64::MAX)
}

/// The cumulative count a connect commits and then publishes.
///
/// [`ChainTxCount::advance`] owns the arithmetic; this only reports the one
/// transition an operator needs to know about: a count that was known and
/// stopped being one means the count and the chain have diverged.
pub(super) fn certified_advance(
    known: ChainTxCount,
    height: u32,
    tx_count_delta: u64,
) -> ChainTxCount {
    let advanced = known.advance(height, tx_count_delta);
    if known.get().is_some() && advanced.get().is_none() {
        tracing::warn!(
            height,
            tx_count_delta,
            "cumulative chain transaction count overflowed; marking it unknown"
        );
    }
    advanced
}

/// The cumulative count a disconnect commits and then publishes.
///
/// [`ChainTxCount::rewind`] owns the arithmetic; a subtraction that would go
/// below zero means the count and the chain have diverged, and an admitted
/// absence is reported rather than a silently clamped total.
pub(super) fn certified_rewind(known: ChainTxCount, tx_count_delta: u64) -> ChainTxCount {
    let rewound = known.rewind(tx_count_delta);
    if known.get().is_some() && rewound.get().is_none() {
        tracing::warn!(
            tx_count_delta,
            "cumulative chain transaction count fell below zero; marking it unknown"
        );
    }
    rewound
}
