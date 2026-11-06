//! Kani formal verification harnesses for schema admission and conversion lifecycle.
//!
//! Models the future schema epoch 3 target while live storage remains at epoch 2 per `fs.rs`.
//! Standalone design model proofs under Hoare/Dijkstra contracts, not an
//! implementation-refinement claim.

use super::{
    Action, MarkerClassification, Mode, ModelInputs, NUM_CELLS, NUM_CELLS_U8, Outcome, Phase,
    State, safety, step,
};

fn any_marker() -> MarkerClassification {
    let val: u8 = kani::any();
    kani::assume(val < 5);
    match val {
        0 => MarkerClassification::Absent,
        1 => MarkerClassification::Malformed,
        2 => MarkerClassification::RetiredEpoch2,
        3 => MarkerClassification::CurrentEpoch3,
        _ => MarkerClassification::FutureEpoch,
    }
}

fn any_mode() -> Mode {
    if kani::any() {
        Mode::NodeAdmission
    } else {
        Mode::OfflineConversion
    }
}

fn any_inputs() -> ModelInputs {
    ModelInputs {
        mode: any_mode(),
        source_marker: any_marker(),
        source_dir_empty: kani::any(),
        dest_initially_empty: kani::any(),
        paths_disjoint: kani::any(),
        initial_source_contents: kani::any(),
    }
}

fn any_phase() -> Phase {
    let p: u8 = kani::any();
    kani::assume(p < 11);
    match p {
        0 => Phase::Admission,
        1 => Phase::Copying,
        2 => Phase::Verifying,
        3 => Phase::SyncingRequiredFiles,
        4 => Phase::DeletingScratch,
        5 => Phase::RenamingMarker,
        6 => Phase::PublishedPendingSync,
        7 => Phase::NodeInitWritingTemp,
        8 => Phase::NodeInitRenaming,
        9 => Phase::NodeInitPendingSync,
        _ => Phase::Terminal,
    }
}

fn any_outcome() -> Outcome {
    let o: u8 = kani::any();
    kani::assume(o < 5);
    match o {
        0 => Outcome::Pending,
        1 => Outcome::Refused,
        2 => Outcome::PrepublicationFailure,
        3 => Outcome::PublicationUnknown,
        _ => Outcome::Success,
    }
}

fn any_action() -> Action {
    let idx: u8 = kani::any();
    kani::assume(idx < 18);
    let byte: u8 = kani::any();
    match idx {
        0 => Action::RejectAdmission,
        1 => Action::ConvertAcceptAdmission,
        2 => Action::NodeOpenDirect,
        3 => Action::NodeInitStart,
        4 => Action::NodeInitWriteTempSuccess,
        5 => Action::NodeInitWriteTempFailure,
        6 => Action::NodeInitRenameSuccess,
        7 => Action::NodeInitRenameFailure,
        8 => Action::CopyCell,
        9 => Action::CorruptCopyCell(byte),
        10 => Action::VerifyCell,
        11 => Action::PrepubIoFailure,
        12 => Action::SyncRequiredFilesSuccess,
        13 => Action::DeleteScratchSuccess,
        14 => Action::PublishMarkerRename,
        15 => Action::FinalSyncSuccess,
        16 => Action::FinalSyncFailure,
        _ => Action::Stutter,
    }
}

fn any_state() -> State {
    let dest_marker_present: bool = kani::any();
    let dest_marker = if dest_marker_present {
        Some(any_marker())
    } else {
        None
    };
    State {
        inputs: any_inputs(),
        source_marker: any_marker(),
        source_contents: kani::any(),
        dest_cells: kani::any(),
        dest_marker,
        phase: any_phase(),
        outcome: any_outcome(),
        copy_cursor: kani::any(),
        verify_cursor: kani::any(),
        required_files_durable: kani::any(),
        scratch_deleted: kani::any(),
        observed_final_sync: kani::any(),
    }
}

// RCV-09
#[kani::proof]
fn init_satisfies_safety() {
    let inputs = any_inputs();
    let state = State::init(inputs);
    assert!(safety(&state));
}

// RCV-09
#[kani::proof]
fn step_preserves_safety_induction() {
    let state = any_state();
    kani::assume(safety(&state));
    let action = any_action();
    let next = step(&state, action);
    assert!(safety(&next));
}

// RCV-09
#[kani::proof]
fn source_contents_strictly_immutable() {
    let state = any_state();
    kani::assume(safety(&state));
    let action = any_action();
    let next = step(&state, action);
    assert_eq!(next.source_contents, state.inputs.initial_source_contents);
}

// RCV-09
#[kani::proof]
fn node_never_opens_wrong_marker() {
    let state = any_state();
    kani::assume(safety(&state));
    let action = any_action();
    let next = step(&state, action);
    if next.engine_opened() {
        assert_eq!(next.inputs.mode, Mode::NodeAdmission);
        assert_eq!(next.source_marker, MarkerClassification::CurrentEpoch3);
        if next.inputs.source_marker == MarkerClassification::Absent {
            assert!(next.observed_final_sync);
        } else {
            assert!(!next.observed_final_sync);
        }
    }
}

// RCV-09
#[kani::proof]
fn output_marker_implies_verified_durability_and_scratch_removed() {
    let state = any_state();
    kani::assume(safety(&state));
    let action = any_action();
    let next = step(&state, action);
    if next.dest_marker.is_some() {
        assert_eq!(next.dest_marker, Some(MarkerClassification::CurrentEpoch3));
        assert_eq!(next.dest_cells, next.inputs.initial_source_contents);
        assert_eq!(next.verify_cursor, NUM_CELLS_U8);
        assert!(next.required_files_durable);
        assert!(next.scratch_deleted);
    }
}

// RCV-09
#[kani::proof]
fn success_implies_final_sync() {
    let state = any_state();
    kani::assume(safety(&state));
    let action = any_action();
    let next = step(&state, action);
    if next.outcome == Outcome::Success {
        match next.inputs.mode {
            Mode::OfflineConversion => {
                assert_eq!(next.dest_marker, Some(MarkerClassification::CurrentEpoch3));
                assert!(next.observed_final_sync);
            }
            Mode::NodeAdmission => {
                assert_eq!(next.source_marker, MarkerClassification::CurrentEpoch3);
                if next.inputs.source_marker == MarkerClassification::Absent {
                    assert!(next.observed_final_sync);
                } else {
                    assert!(!next.observed_final_sync);
                }
            }
        }
    }
}

// RCV-09
#[kani::proof]
fn refusal_destination_safety() {
    let state = any_state();
    kani::assume(safety(&state));
    let action = any_action();
    let next = step(&state, action);
    if next.outcome == Outcome::Refused {
        assert_eq!(next.source_marker, next.inputs.source_marker);
        assert!(next.dest_marker.is_none());
        assert_eq!(next.copy_cursor, 0);
        assert_eq!(next.dest_cells, [0; NUM_CELLS]);
        assert!(!next.engine_opened());
    }
}
