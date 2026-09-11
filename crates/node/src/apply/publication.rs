//! Coherent applied-tip and chain-transaction-count publication.

use super::AppliedPublication;
use super::Chainstate;
use bitcoin_rs_primitives::Block;
use std::sync::atomic::Ordering;

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
    let known = handles.chain_tx_count.load(Ordering::Relaxed);
    if known == 0 && height != 0 {
        return;
    }
    let advanced = known.checked_add(tx_count_delta).unwrap_or_else(|| {
        tracing::warn!(
            known,
            tx_count_delta,
            "cumulative chain transaction count overflowed; marking it unknown"
        );
        0
    });
    handles.chain_tx_count.store(advanced, Ordering::Relaxed);
}

/// Takes a disconnected block's transactions back out of the cumulative count.
///
/// An unknown count stays unknown. A subtraction that would go below zero means
/// the count and the chain have diverged, and a silently clamped total is worse
/// than an admitted absence, so that case resets to unknown.
pub(super) fn rewind_chain_tx_count(handles: &Chainstate, tx_count_delta: u64) {
    let known = handles.chain_tx_count.load(Ordering::Relaxed);
    if known == 0 {
        return;
    }
    let rewound = known.checked_sub(tx_count_delta).unwrap_or_else(|| {
        tracing::warn!(
            known,
            tx_count_delta,
            "cumulative chain transaction count fell below zero; marking it unknown"
        );
        0
    });
    handles.chain_tx_count.store(rewound, Ordering::Relaxed);
}
