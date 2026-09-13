//! Coherent applied-tip and chain-transaction-count publication.

use super::AppliedPublication;
use super::Chainstate;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_primitives::Block;
use std::sync::Arc;
use std::sync::atomic::Ordering;

/// Publishes one connected block: the applied tip, the chain event, and the
/// advanced chain tx count, under one seqlock publication.
///
/// Extracted so the grouped window path can publish a committed prefix in
/// order after its durable batch — the exact values the batch certified.
pub(super) fn publish_connect(handles: &Chainstate, tip: &TipSnapshot, tx_count_delta: u64) {
    let _publication = begin_applied_publication(handles);
    handles.applied_tip.store(Some(Arc::new(tip.clone())));
    handles
        .chain_events
        .record(crate::state::HintKind::Connected, tip.height, tip.hash);
    advance_chain_tx_count(handles, tip.height, tx_count_delta);
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

/// Carries the cumulative transaction count forward across a connected block.
///
/// Zero means *unknown*, so a count that is already unknown stays unknown
/// rather than restarting from this block and pretending to be a chain total.
/// Genesis is the one block that can establish the count from nothing: there is
/// no chain below it.
pub(super) fn advance_chain_tx_count(handles: &Chainstate, height: u32, tx_count_delta: u64) {
    let advanced = advanced_chain_tx_count(handles, height, tx_count_delta);
    handles.chain_tx_count.store(advanced, Ordering::Relaxed);
}

/// The cumulative count a connected block will publish, without storing it.
///
/// The durable-head commit names this value one step before publication
/// does, and the two must agree byte for byte. Zero means *unknown*, per
/// the convention on `advance_chain_tx_count`.
pub(super) fn advanced_chain_tx_count(
    handles: &Chainstate,
    height: u32,
    tx_count_delta: u64,
) -> u64 {
    advanced_chain_tx_count_from(
        handles.chain_tx_count.load(Ordering::Relaxed),
        height,
        tx_count_delta,
    )
}

/// The pure form, from an explicit known count: the grouped window path
/// advances from the staged prefix's count, which publication has not
/// stored yet.
pub(super) fn advanced_chain_tx_count_from(known: u64, height: u32, tx_count_delta: u64) -> u64 {
    if known == 0 && height != 0 {
        return 0;
    }
    known.checked_add(tx_count_delta).unwrap_or_else(|| {
        tracing::warn!(
            known,
            tx_count_delta,
            "cumulative chain transaction count overflowed; marking it unknown"
        );
        0
    })
}

/// Takes a disconnected block's transactions back out of the cumulative count.
///
/// An unknown count stays unknown. A subtraction that would go below zero means
/// the count and the chain have diverged, and a silently clamped total is worse
/// than an admitted absence, so that case resets to unknown.
pub(super) fn rewind_chain_tx_count(handles: &Chainstate, tx_count_delta: u64) {
    let rewound = rewound_chain_tx_count(handles, tx_count_delta);
    handles.chain_tx_count.store(rewound, Ordering::Relaxed);
}

/// The cumulative count a disconnect will publish, without storing it.
///
/// The durable-head commit names this value one step before publication
/// does, and the two must agree byte for byte.
pub(super) fn rewound_chain_tx_count(handles: &Chainstate, tx_count_delta: u64) -> u64 {
    let known = handles.chain_tx_count.load(Ordering::Relaxed);
    if known == 0 {
        return 0;
    }
    known.checked_sub(tx_count_delta).unwrap_or_else(|| {
        tracing::warn!(
            known,
            tx_count_delta,
            "cumulative chain transaction count fell below zero; marking it unknown"
        );
        0
    })
}
