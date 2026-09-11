//! Contract coverage for reconciliation invariants in
//! [`docs/contracts/indexing.md`](../../../docs/contracts/indexing.md).
//! The tests below cover exact watermark alignment (`IDX-03`), selective
//! capability reset (`IDX-04`), reorganization rollback (`IDX-06`), isolated
//! rebuild behavior (`IDX-07`), and positional cursor reconciliation.

use super::{
    ActiveChainView, CURSOR_BYTE_LEN, ChainIdentity, ChainTip, ConsumerCursor, ReconcileLeg,
    ReconcilePhase, ReconcilePlan, SelectedWatermark, plan, plan_from_identity,
    selected_watermark,
};
use crate::{IndexCapabilities, IndexWatermark, IndexWatermarks};
use bitcoin_rs_primitives::Hash256;

const A: IndexWatermark = IndexWatermark {
    height: 10,
    hash: [0x11; 32],
};
const SAME_HEIGHT_FORK: IndexWatermark = IndexWatermark {
    height: 10,
    hash: [0x22; 32],
};
const NEXT_HEIGHT: IndexWatermark = IndexWatermark {
    height: 11,
    hash: [0x33; 32],
};

const ACTIVE: Hash256 = Hash256::from_le_bytes(&[0x41; 32]);
const ORPHAN: Hash256 = Hash256::from_le_bytes(&[0x42; 32]);
const MISSING: Hash256 = Hash256::from_le_bytes(&[0x43; 32]);
const TARGET: Hash256 = Hash256::from_le_bytes(&[0x44; 32]);

const fn capabilities(mask: u8) -> IndexCapabilities {
    IndexCapabilities {
        tx_lookup: mask & 1 != 0,
        script_history: mask & 2 != 0,
        script_live: mask & 4 != 0,
    }
}

struct FixtureChain {
    resolve_orphan_ancestor: bool,
}

impl ActiveChainView for FixtureChain {
    fn contains(&self, position: Hash256) -> bool {
        position == ACTIVE || position == ORPHAN
    }

    fn position_on_active_chain(&self, position: Hash256, height: u32) -> bool {
        position == ACTIVE && height == 9
    }

    fn common_ancestor_height(&self, position: Hash256) -> Option<u32> {
        (self.resolve_orphan_ancestor && position == ORPHAN).then_some(4)
    }
}

/// IDX-03: selected capabilities must share one exact durable watermark.
#[test]
fn selection_matches_exact_pairwise_equality_for_every_subset() {
    let states = [None, Some(A), Some(SAME_HEIGHT_FORK), Some(NEXT_HEIGHT)];
    for tx_lookup in states {
        for script_history in states {
            for script_live in states {
                let watermarks = IndexWatermarks {
                    tx_lookup,
                    script_history,
                    script_live,
                };
                for mask in 0..8 {
                    let selected = capabilities(mask);
                    let agree = (!selected.tx_lookup
                        || !selected.script_history
                        || tx_lookup == script_history)
                        && (!selected.tx_lookup
                            || !selected.script_live
                            || tx_lookup == script_live)
                        && (!selected.script_history
                            || !selected.script_live
                            || script_history == script_live);
                    let expected = if mask == 0 || !agree {
                        SelectedWatermark::Invalid
                    } else if selected.tx_lookup {
                        SelectedWatermark::Valid(tx_lookup)
                    } else if selected.script_history {
                        SelectedWatermark::Valid(script_history)
                    } else {
                        SelectedWatermark::Valid(script_live)
                    };
                    assert_eq!(selected_watermark(watermarks, selected), expected);
                }
            }
        }
    }
}

/// IDX-03: no selected capability is distinct from an initialized empty cursor.
#[test]
fn empty_selection_is_not_an_uninitialized_selection() {
    let watermarks = IndexWatermarks {
        tx_lookup: None,
        script_history: None,
        script_live: None,
    };
    assert_eq!(
        selected_watermark(watermarks, capabilities(0)),
        SelectedWatermark::Invalid
    );
    assert_eq!(
        selected_watermark(watermarks, capabilities(1)),
        SelectedWatermark::Valid(None)
    );
}

/// IDX-03: watermark identity includes both height and block hash.
#[test]
fn same_height_different_hash_is_not_alignment() {
    let watermarks = IndexWatermarks {
        tx_lookup: Some(A),
        script_history: Some(SAME_HEIGHT_FORK),
        script_live: Some(A),
    };
    assert_eq!(
        selected_watermark(watermarks, capabilities(3)),
        SelectedWatermark::Invalid
    );
    assert_eq!(
        selected_watermark(watermarks, capabilities(4)),
        SelectedWatermark::Valid(Some(A))
    );
}

/// IDX-04: resetting one capability preserves sibling reconciliation state.
#[test]
fn phase_changes_only_selected_capabilities() {
    let original = ReconcilePhase {
        tx_lookup: ReconcileLeg::Forward,
        script_history: ReconcileLeg::RollingBack {
            from_height: 100,
            to_height: 90,
        },
        script_live: ReconcileLeg::Rebuilding,
    };
    for mask in 0..8 {
        let selected = capabilities(mask);
        let updated = original.with_leg(selected, ReconcileLeg::Rebuilding);
        assert_eq!(
            updated.tx_lookup,
            if selected.tx_lookup {
                ReconcileLeg::Rebuilding
            } else {
                original.tx_lookup
            }
        );
        assert_eq!(
            updated.script_history,
            if selected.script_history {
                ReconcileLeg::Rebuilding
            } else {
                original.script_history
            }
        );
        assert_eq!(updated.script_live, ReconcileLeg::Rebuilding);
    }
}

/// IDX-06 and IDX-07: rollback completion does not cancel an independent rebuild.
#[test]
fn finishing_rollback_preserves_independent_rebuild() {
    let phase = ReconcilePhase {
        tx_lookup: ReconcileLeg::RollingBack {
            from_height: 100,
            to_height: 90,
        },
        script_history: ReconcileLeg::Rebuilding,
        script_live: ReconcileLeg::Forward,
    }
    .rollbacks_finished();
    assert_eq!(phase.tx_lookup, ReconcileLeg::Forward);
    assert_eq!(phase.script_history, ReconcileLeg::Rebuilding);
    assert_eq!(phase.script_live, ReconcileLeg::Forward);
    assert_eq!(phase.rebuilding(), capabilities(2));
    assert_eq!(phase.rolling_back(), None);
}

/// IDX-06: rollback progress covers every active capability rollback.
#[test]
fn rollback_progress_covers_every_active_rollback() {
    let phase = ReconcilePhase {
        tx_lookup: ReconcileLeg::RollingBack {
            from_height: 100,
            to_height: 90,
        },
        script_history: ReconcileLeg::RollingBack {
            from_height: 120,
            to_height: 95,
        },
        script_live: ReconcileLeg::Rebuilding,
    };
    assert_eq!(phase.rolling_back(), Some((120, 90)));
    assert_eq!(phase.rebuilding(), capabilities(4));
    assert_eq!(ReconcilePhase::default(), ReconcilePhase::FORWARD);
}

#[test]
fn consumer_cursor_round_trips_exactly() {
    let cursor = ConsumerCursor {
        epoch: 7,
        sequence: 11,
        height: 123,
        hash: Hash256::from_le_bytes(&[0x52; 32]),
    };
    let bytes = cursor.to_bytes();
    assert_eq!(bytes.len(), CURSOR_BYTE_LEN);
    assert_eq!(ConsumerCursor::from_bytes(&bytes), Some(cursor));
    assert!(ConsumerCursor::from_bytes(&bytes[..CURSOR_BYTE_LEN - 1]).is_none());
}

#[test]
fn positional_planner_distinguishes_forward_rollback_and_rebuild() {
    let target = ChainTip {
        hash: TARGET,
        height: 12,
    };
    let cursor = |hash, height| ConsumerCursor {
        epoch: 1,
        sequence: 1,
        height,
        hash,
    };
    let resolved = FixtureChain {
        resolve_orphan_ancestor: true,
    };
    assert_eq!(
        plan(&cursor(ACTIVE, 9), target, &resolved),
        ReconcilePlan::Forward { from_height: 10 }
    );
    assert_eq!(
        plan(&cursor(ORPHAN, 9), target, &resolved),
        ReconcilePlan::RollbackAndForward { ancestor_height: 4 }
    );
    assert_eq!(
        plan(&cursor(MISSING, 9), target, &resolved),
        ReconcilePlan::Rebuild
    );

    let unresolved = FixtureChain {
        resolve_orphan_ancestor: false,
    };
    assert_eq!(
        plan(&cursor(ORPHAN, 9), target, &unresolved),
        ReconcilePlan::Rebuild,
        "missing ancestry must not invent genesis as a common ancestor"
    );
}

#[test]
fn publisher_identity_cannot_claim_caught_up_against_a_different_target() {
    let identity = ChainIdentity {
        epoch: 3,
        sequence: 5,
        tip_hash: ACTIVE,
        tip_height: 9,
    };
    let cursor = ConsumerCursor::from_identity(&identity);
    let chain = FixtureChain {
        resolve_orphan_ancestor: true,
    };
    assert_eq!(
        plan_from_identity(
            &cursor,
            &identity,
            ChainTip {
                hash: TARGET,
                height: 12,
            },
            &chain,
        ),
        ReconcilePlan::Forward { from_height: 10 }
    );
    assert_eq!(
        plan_from_identity(
            &cursor,
            &identity,
            ChainTip {
                hash: ACTIVE,
                height: 9,
            },
            &chain,
        ),
        ReconcilePlan::CaughtUp
    );
}
