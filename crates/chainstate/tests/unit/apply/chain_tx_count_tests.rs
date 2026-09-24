//! Counter recovery contract: [`docs/contracts/recovery.md#rcv-06-chain-transaction-count`].
//! Zero means unknown (including legacy datadirs), rewinds that underflow remain
//! unknown, and additions that overflow are unknown rather than wrapping.
//!
//! [`ChainTxCount`] is the one implementation of that arithmetic; these cases
//! pin it through the type's public surface.

use super::*;

#[test]
fn genesis_establishes_the_count_from_nothing() {
    assert_eq!(ChainTxCount::UNKNOWN, ChainTxCount::from_wire(0));
    assert_eq!(
        ChainTxCount::UNKNOWN.advance(0, 1),
        ChainTxCount::established(1)
    );
}

#[test]
fn an_unknown_count_stays_unknown_above_genesis() {
    // A datadir written before the counter existed restores as unknown.
    // Accumulating from here would produce a small number that looks like a
    // chain total and is not one — worse than admitting we do not know.
    assert_eq!(
        ChainTxCount::UNKNOWN.advance(900_000, 2_500),
        ChainTxCount::UNKNOWN
    );
}

#[test]
fn a_known_count_advances_and_rewinds_by_the_same_delta() {
    let counted = ChainTxCount::UNKNOWN
        .advance(0, 1)
        .advance(1, 7)
        .advance(2, 3);
    assert_eq!(counted, ChainTxCount::established(11));

    let rewound = counted.rewind(3).rewind(7);
    assert_eq!(rewound, ChainTxCount::established(1));
}

#[test]
fn rewinding_an_unknown_count_leaves_it_unknown() {
    assert_eq!(ChainTxCount::UNKNOWN.rewind(5), ChainTxCount::UNKNOWN);
}

#[test]
fn a_rewind_past_zero_admits_it_does_not_know_rather_than_clamping() {
    // Only reachable if the count and the chain have diverged. A clamp to
    // some small number would keep reporting a confident wrong total.
    assert_eq!(
        ChainTxCount::established(4).rewind(9),
        ChainTxCount::UNKNOWN
    );
}

#[test]
fn an_advance_past_u64_marks_the_count_unknown_instead_of_wrapping() {
    assert_eq!(
        ChainTxCount::established(u64::MAX - 1).advance(900_000, 3),
        ChainTxCount::UNKNOWN
    );
}

#[test]
fn the_wire_encoding_round_trips_the_unknown_sentinel() {
    assert_eq!(ChainTxCount::from_wire(0), ChainTxCount::UNKNOWN);
    assert_eq!(ChainTxCount::UNKNOWN.to_wire(), 0);
    assert_eq!(ChainTxCount::from_wire(11).get(), Some(11));
    assert_eq!(ChainTxCount::established(11).to_wire(), 11);
}
