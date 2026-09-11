//! Counter recovery contract: [`docs/contracts/recovery.md#rcv-06-chain-transaction-count`].
//! Zero means unknown (including legacy datadirs), rewinds that underflow remain
//! unknown, and additions that overflow are unknown rather than wrapping.

use super::*;

fn handles() -> Chainstate {
    super::consensus_rule_tests::empty_apply_handles()
}

#[test]
fn genesis_establishes_the_count_from_nothing() {
    let handles = handles();
    assert_eq!(handles.chain_tx_count.load(Ordering::Relaxed), 0);
    advance_chain_tx_count(&handles, 0, 1);
    assert_eq!(handles.chain_tx_count.load(Ordering::Relaxed), 1);
}

#[test]
fn an_unknown_count_stays_unknown_above_genesis() {
    let handles = handles();
    // A datadir written before the counter existed restores as unknown.
    // Accumulating from here would produce a small number that looks like a
    // chain total and is not one — worse than admitting we do not know.
    advance_chain_tx_count(&handles, 900_000, 2_500);
    assert_eq!(handles.chain_tx_count.load(Ordering::Relaxed), 0);
}

#[test]
fn a_known_count_advances_and_rewinds_by_the_same_delta() {
    let handles = handles();
    advance_chain_tx_count(&handles, 0, 1);
    advance_chain_tx_count(&handles, 1, 7);
    advance_chain_tx_count(&handles, 2, 3);
    assert_eq!(handles.chain_tx_count.load(Ordering::Relaxed), 11);

    rewind_chain_tx_count(&handles, 3);
    assert_eq!(handles.chain_tx_count.load(Ordering::Relaxed), 8);
    rewind_chain_tx_count(&handles, 7);
    assert_eq!(handles.chain_tx_count.load(Ordering::Relaxed), 1);
}

#[test]
fn rewinding_an_unknown_count_leaves_it_unknown() {
    let handles = handles();
    rewind_chain_tx_count(&handles, 5);
    assert_eq!(handles.chain_tx_count.load(Ordering::Relaxed), 0);
}

#[test]
fn a_rewind_past_zero_admits_it_does_not_know_rather_than_clamping() {
    let handles = handles();
    advance_chain_tx_count(&handles, 0, 4);
    // Only reachable if the count and the chain have diverged. A clamp to
    // some small number would keep reporting a confident wrong total.
    rewind_chain_tx_count(&handles, 9);
    assert_eq!(handles.chain_tx_count.load(Ordering::Relaxed), 0);
}

#[test]
fn an_advance_past_u64_marks_the_count_unknown_instead_of_wrapping() {
    let handles = handles();
    handles
        .chain_tx_count
        .store(u64::MAX - 1, Ordering::Relaxed);

    advance_chain_tx_count(&handles, 900_000, 3);

    assert_eq!(handles.chain_tx_count.load(Ordering::Relaxed), 0);
}
