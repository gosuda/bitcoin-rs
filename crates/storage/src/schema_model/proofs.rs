//! Kani formal verification harnesses for the schema epoch 6 lifecycle.
//!
//! Models the schema epoch 6 design (`CURRENT_SCHEMA_VERSION = 6`, coins in
//! the engine `coins` keyspace, snapshot-base checkpoint in place of the archive),
//! matching live storage in `fs.rs`. Standalone design model proofs under
//! Hoare/Dijkstra contracts, not an implementation-refinement claim.

use super::{
    Action, HEIGHT_MAX, MarkerClassification, Mode, ModelInputs, NUM_CELLS, NUM_CELLS_U8,
    NUM_HEIGHTS, Outcome, Phase, State, safety, step,
};

fn any_marker() -> MarkerClassification {
    let val: u8 = kani::any();
    kani::assume(val < 7);
    match val {
        0 => MarkerClassification::Absent,
        1 => MarkerClassification::Malformed,
        2 => MarkerClassification::RetiredEpoch3,
        3 => MarkerClassification::RetiredEpoch4,
        4 => MarkerClassification::RetiredEpoch5,
        5 => MarkerClassification::CurrentEpoch6,
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

fn any_height_pair() -> (u8, u8) {
    let checkpoint_height: u8 = kani::any();
    kani::assume(checkpoint_height <= HEIGHT_MAX);
    let durable_head: u8 = kani::any();
    kani::assume(checkpoint_height <= durable_head && durable_head <= HEIGHT_MAX);
    (checkpoint_height, durable_head)
}

fn any_inputs() -> ModelInputs {
    let (checkpoint_height, durable_head) = any_height_pair();
    let checkpoint_coins: u8 = kani::any();
    let mut block_data_present = [false; NUM_HEIGHTS];
    let mut block_undo_delta = [0_u8; NUM_HEIGHTS];
    for h in 0..NUM_HEIGHTS {
        block_data_present[h] = kani::any();
        block_undo_delta[h] = kani::any();
        if h as u8 <= checkpoint_height {
            block_data_present[h] = true;
            block_undo_delta[h] = checkpoint_coins;
        }
    }
    ModelInputs {
        mode: any_mode(),
        source_marker: any_marker(),
        source_dir_empty: kani::any(),
        dest_initially_empty: kani::any(),
        paths_disjoint: kani::any(),
        initial_source_contents: kani::any(),
        checkpoint_height,
        durable_head,
        checkpoint_complete: kani::any(),
        block_data_present,
        checkpoint_coins,
        block_undo_delta,
    }
}

fn any_phase() -> Phase {
    let p: u8 = kani::any();
    kani::assume(p < 14);
    match p {
        0 => Phase::Admission,
        1 => Phase::Copying,
        2 => Phase::Verifying,
        3 => Phase::CopyingRequiredFiles,
        4 => Phase::IngestingCheckpoint,
        5 => Phase::Replaying,
        6 => Phase::ReplayDone,
        7 => Phase::DeletingScratch,
        8 => Phase::RenamingMarker,
        9 => Phase::PublishedPendingSync,
        10 => Phase::NodeInitWritingTemp,
        11 => Phase::NodeInitRenaming,
        12 => Phase::NodeInitPendingSync,
        _ => Phase::Terminal,
    }
}

fn any_outcome() -> Outcome {
    let o: u8 = kani::any();
    kani::assume(o < 7);
    let height: u8 = kani::any();
    match o {
        0 => Outcome::Pending,
        1 => Outcome::Refused,
        2 => Outcome::RefusedNoCheckpoint,
        3 => Outcome::MissingData { height },
        4 => Outcome::PrepublicationFailure,
        5 => Outcome::PublicationUnknown,
        _ => Outcome::Success,
    }
}

fn any_action() -> Action {
    let idx: u8 = kani::any();
    kani::assume(idx < 22);
    let byte: u8 = kani::any();
    match idx {
        0 => Action::RejectAdmission,
        1 => Action::RefuseMissingCheckpoint,
        2 => Action::ConvertAcceptAdmission,
        3 => Action::NodeOpenDirect,
        4 => Action::NodeInitStart,
        5 => Action::NodeInitWriteTempSuccess,
        6 => Action::NodeInitWriteTempFailure,
        7 => Action::NodeInitRenameSuccess,
        8 => Action::NodeInitRenameFailure,
        9 => Action::CopyCell,
        10 => Action::CorruptCopyCell(byte),
        11 => Action::VerifyCell,
        12 => Action::PrepubIoFailure,
        13 => Action::CopyRequiredFiles,
        14 => Action::LoadCheckpointCoins,
        15 => Action::ReplayBlock,
        16 => Action::MissingBlockDataAbort,
        17 => Action::DeleteScratchSuccess,
        18 => Action::PublishMarkerRename,
        19 => Action::FinalSyncSuccess,
        20 => Action::FinalSyncFailure,
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
    let inputs = any_inputs();
    let replay_applied: u8 = kani::any();
    kani::assume(replay_applied <= inputs.durable_head.saturating_sub(inputs.checkpoint_height));
    State {
        inputs,
        source_marker: any_marker(),
        source_contents: kani::any(),
        dest_cells: kani::any(),
        dest_coins: kani::any(),
        dest_marker,
        phase: any_phase(),
        outcome: any_outcome(),
        copy_cursor: kani::any(),
        verify_cursor: kani::any(),
        replay_applied,
        required_files_durable: kani::any(),
        scratch_deleted: kani::any(),
        journal_copied: kani::any(),
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

// RCV-10
#[kani::proof]
fn journal_is_never_copied() {
    let state = any_state();
    kani::assume(safety(&state));
    let action = any_action();
    let next = step(&state, action);
    assert!(!next.journal_copied);
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
        assert_eq!(next.source_marker, MarkerClassification::CurrentEpoch6);
        if next.inputs.source_marker == MarkerClassification::Absent {
            assert!(next.observed_final_sync);
        } else {
            assert!(!next.observed_final_sync);
        }
    }
}

// RCV-09, RCV-10
#[kani::proof]
fn output_marker_implies_verified_ingest_replay_durability_and_scratch_removed() {
    let state = any_state();
    kani::assume(safety(&state));
    let action = any_action();
    let next = step(&state, action);
    if next.dest_marker.is_some() {
        assert_eq!(next.dest_marker, Some(MarkerClassification::CurrentEpoch6));
        assert_eq!(next.dest_cells, next.inputs.initial_source_contents);
        assert_eq!(next.verify_cursor, NUM_CELLS_U8);
        assert_eq!(
            next.dest_coins,
            next.inputs.oracle_coins(next.inputs.durable_head)
        );
        assert_eq!(
            next.replay_applied,
            next.inputs.durable_head - next.inputs.checkpoint_height
        );
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
    if matches!(next.outcome, Outcome::Success) {
        match next.inputs.mode {
            Mode::OfflineConversion => {
                assert_eq!(next.dest_marker, Some(MarkerClassification::CurrentEpoch6));
                assert_eq!(
                    next.dest_coins,
                    next.inputs.oracle_coins(next.inputs.durable_head)
                );
                assert!(next.observed_final_sync);
            }
            Mode::NodeAdmission => {
                assert_eq!(next.source_marker, MarkerClassification::CurrentEpoch6);
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
    if matches!(next.outcome, Outcome::Refused) {
        assert_eq!(next.source_marker, next.inputs.source_marker);
        assert!(next.dest_marker.is_none());
        assert_eq!(next.copy_cursor, 0);
        assert_eq!(next.dest_cells, [0; NUM_CELLS]);
        assert_eq!(next.dest_coins, 0);
        assert!(!next.engine_opened());
    }
}

// RCV-10
#[kani::proof]
fn missing_checkpoint_fails_closed_before_writes() {
    let state = any_state();
    kani::assume(safety(&state));
    let action = any_action();
    let next = step(&state, action);
    if matches!(next.outcome, Outcome::RefusedNoCheckpoint) {
        assert!(!next.inputs.checkpoint_complete);
        assert!(next.source_marker.is_convertible());
        assert!(next.dest_marker.is_none());
        assert_eq!(next.dest_cells, [0; NUM_CELLS]);
        assert_eq!(next.dest_coins, 0);
        assert_eq!(next.copy_cursor, 0);
        assert_eq!(next.verify_cursor, 0);
        assert!(!next.required_files_durable);
        assert!(!next.scratch_deleted);
        assert!(!next.observed_final_sync);
    }
}

// RCV-10
#[kani::proof]
fn missing_block_data_aborts_before_publication() {
    let state = any_state();
    kani::assume(safety(&state));
    let action = any_action();
    let next = step(&state, action);
    if let Outcome::MissingData { height } = next.outcome {
        let aborted_height = next.inputs.checkpoint_height + next.replay_applied + 1;
        assert_eq!(height, aborted_height);
        assert!(!next.inputs.block_data_present[usize::from(height)]);
        assert!(next.dest_marker.is_none());
        assert!(!next.observed_final_sync);
        assert!(height <= next.inputs.durable_head);
    }
}

// RCV-10
#[kani::proof]
fn replayed_coins_come_from_checkpoint_or_replay_oracle() {
    let state = any_state();
    kani::assume(safety(&state));
    let action = any_action();
    let next = step(&state, action);
    if next.dest_marker.is_some() || matches!(next.phase, Phase::Replaying | Phase::ReplayDone) {
        let position = next.replay_position().min(next.inputs.durable_head);
        assert_eq!(next.dest_coins, next.inputs.oracle_coins(position));
    }
}
