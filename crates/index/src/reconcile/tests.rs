use super::{ReconcileLeg, ReconcilePhase, SelectedWatermark, selected_watermark};
use crate::{IndexCapabilities, IndexWatermark, IndexWatermarks};

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

const fn capabilities(mask: u8) -> IndexCapabilities {
    IndexCapabilities {
        tx_lookup: mask & 1 != 0,
        script_history: mask & 2 != 0,
        script_live: mask & 4 != 0,
    }
}

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
                    // Independent, pairwise statement of the contract. In particular,
                    // None is a selected state, not an item to filter out.
                    let agree = (!selected.tx_lookup
                        || !selected.script_history
                        || tx_lookup == script_history)
                        && (!selected.tx_lookup || !selected.script_live || tx_lookup == script_live)
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
    // A lagging or forked History capability cannot gate a Live-only selection.
    assert_eq!(
        selected_watermark(watermarks, capabilities(4)),
        SelectedWatermark::Valid(Some(A))
    );
}

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
