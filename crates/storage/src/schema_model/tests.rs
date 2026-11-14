use super::{
    Action, MarkerClassification, Mode, ModelInputs, NUM_CELLS, Outcome, Phase, State, safety, step,
};

fn converter_inputs(marker: MarkerClassification) -> ModelInputs {
    ModelInputs {
        mode: Mode::OfflineConversion,
        source_marker: marker,
        source_dir_empty: false,
        dest_initially_empty: true,
        paths_disjoint: true,
        initial_source_contents: [5, 6, 7, 8],
        checkpoint_height: 0,
        durable_head: 1,
        checkpoint_complete: true,
        block_data_present: [true, true],
        checkpoint_coins: 9,
        block_undo_delta: [9, 12],
    }
}

fn node_inputs(marker: MarkerClassification, dir_empty: bool) -> ModelInputs {
    ModelInputs {
        mode: Mode::NodeAdmission,
        source_marker: marker,
        source_dir_empty: dir_empty,
        dest_initially_empty: false,
        paths_disjoint: false,
        initial_source_contents: [10, 20, 30, 40],
        checkpoint_height: 0,
        durable_head: 1,
        checkpoint_complete: true,
        block_data_present: [true, true],
        checkpoint_coins: 9,
        block_undo_delta: [9, 12],
    }
}

fn copy_and_verify(mut s: State) -> State {
    for _ in 0..NUM_CELLS {
        s = step(&s, Action::CopyCell);
    }
    for _ in 0..NUM_CELLS {
        s = step(&s, Action::VerifyCell);
    }
    s
}

fn run_pipeline(mut s: State) -> State {
    s = step(&s, Action::ConvertAcceptAdmission);
    s = copy_and_verify(s);
    s = step(&s, Action::CopyRequiredFiles);
    s = step(&s, Action::LoadCheckpointCoins);
    s = step(&s, Action::ReplayBlock);
    s = step(&s, Action::DeleteScratchSuccess);
    s = step(&s, Action::PublishMarkerRename);
    s
}

fn state_at_stage(stage: Phase) -> State {
    let inputs = converter_inputs(MarkerClassification::RetiredEpoch3);
    let mut s = State::init(inputs);
    s = step(&s, Action::ConvertAcceptAdmission);
    if stage == Phase::Copying {
        return step(&s, Action::CopyCell);
    }
    for _ in 0..NUM_CELLS {
        s = step(&s, Action::CopyCell);
    }
    if stage == Phase::Verifying {
        return step(&s, Action::VerifyCell);
    }
    for _ in 0..NUM_CELLS {
        s = step(&s, Action::VerifyCell);
    }
    if stage == Phase::CopyingRequiredFiles {
        return s;
    }
    s = step(&s, Action::CopyRequiredFiles);
    if stage == Phase::IngestingCheckpoint {
        return s;
    }
    s = step(&s, Action::LoadCheckpointCoins);
    if stage == Phase::Replaying {
        return s;
    }
    s = step(&s, Action::ReplayBlock);
    if stage == Phase::ReplayDone {
        return s;
    }
    s = step(&s, Action::DeleteScratchSuccess);
    if stage == Phase::RenamingMarker {
        return s;
    }
    s = step(&s, Action::PublishMarkerRename);
    if stage == Phase::PublishedPendingSync {
        return s;
    }
    s
}

// RCV-09
#[test]
fn node_exact_current_opens_without_alteration() {
    let inputs = node_inputs(MarkerClassification::CurrentEpoch6, false);
    let s0 = State::init(inputs);
    assert!(safety(&s0));
    let s1 = step(&s0, Action::NodeOpenDirect);
    assert!(safety(&s1));
    assert_eq!(s1.outcome, Outcome::Success);
    assert!(s1.engine_opened());
    assert_eq!(s1.source_marker, MarkerClassification::CurrentEpoch6);
    assert_eq!(s1.source_contents, [10, 20, 30, 40]);
    assert_eq!(s1.dest_marker, None);
    assert!(!s1.observed_final_sync);
}

// RCV-09
#[test]
fn node_absent_empty_initializes_marker_and_opens() {
    let inputs = node_inputs(MarkerClassification::Absent, true);
    let s0 = State::init(inputs);
    assert!(safety(&s0));
    let s1 = step(&s0, Action::NodeInitStart);
    assert!(safety(&s1));
    assert_eq!(s1.phase, Phase::NodeInitWritingTemp);
    assert_eq!(s1.source_marker, MarkerClassification::Absent);

    let s2 = step(&s1, Action::NodeInitWriteTempSuccess);
    assert!(safety(&s2));
    assert_eq!(s2.phase, Phase::NodeInitRenaming);

    let s3 = step(&s2, Action::NodeInitRenameSuccess);
    assert!(safety(&s3));
    assert_eq!(s3.phase, Phase::NodeInitPendingSync);
    assert_eq!(s3.source_marker, MarkerClassification::CurrentEpoch6);
    assert!(!s3.engine_opened());

    let s4 = step(&s3, Action::FinalSyncSuccess);
    assert!(safety(&s4));
    assert_eq!(s4.outcome, Outcome::Success);
    assert!(s4.engine_opened());
    assert_eq!(s4.source_marker, MarkerClassification::CurrentEpoch6);
    assert_eq!(s4.source_contents, [10, 20, 30, 40]);
    assert!(s4.observed_final_sync);
}

// RCV-09
#[test]
fn node_absent_empty_init_fails_before_rename_prepublication_failure() {
    let inputs = node_inputs(MarkerClassification::Absent, true);
    let s0 = State::init(inputs);
    let s1 = step(&s0, Action::NodeInitStart);
    let s2 = step(&s1, Action::NodeInitWriteTempFailure);
    assert!(safety(&s2));
    assert_eq!(s2.outcome, Outcome::PrepublicationFailure);
    assert_eq!(s2.source_marker, MarkerClassification::Absent);
    assert!(!s2.engine_opened());
    assert!(!s2.observed_final_sync);
}

// RCV-09
#[test]
fn node_absent_empty_init_rename_failure_prepublication_failure() {
    let inputs = node_inputs(MarkerClassification::Absent, true);
    let s0 = State::init(inputs);
    let s1 = step(&s0, Action::NodeInitStart);
    let s2 = step(&s1, Action::NodeInitWriteTempSuccess);
    let s3 = step(&s2, Action::NodeInitRenameFailure);
    assert!(safety(&s3));
    assert_eq!(s3.outcome, Outcome::PrepublicationFailure);
    assert_eq!(s3.source_marker, MarkerClassification::Absent);
    assert!(!s3.engine_opened());
}

// RCV-09
#[test]
fn node_absent_empty_final_sync_fails_after_rename_publication_unknown() {
    let inputs = node_inputs(MarkerClassification::Absent, true);
    let s0 = State::init(inputs);
    let s1 = step(&s0, Action::NodeInitStart);
    let s2 = step(&s1, Action::NodeInitWriteTempSuccess);
    let s3 = step(&s2, Action::NodeInitRenameSuccess);
    let s4 = step(&s3, Action::FinalSyncFailure);
    assert!(safety(&s4));
    assert_eq!(s4.outcome, Outcome::PublicationUnknown);
    assert_eq!(s4.source_marker, MarkerClassification::CurrentEpoch6);
    assert!(!s4.engine_opened());
    assert!(!s4.observed_final_sync);
}

// RCV-09
#[test]
fn node_refuses_all_non_current_marker_classes() {
    let non_current_cases = [
        (MarkerClassification::Absent, false),
        (MarkerClassification::Malformed, true),
        (MarkerClassification::Malformed, false),
        (MarkerClassification::RetiredEpoch3, true),
        (MarkerClassification::RetiredEpoch3, false),
        (MarkerClassification::RetiredEpoch4, true),
        (MarkerClassification::RetiredEpoch4, false),
        (MarkerClassification::RetiredEpoch5, true),
        (MarkerClassification::RetiredEpoch5, false),
        (MarkerClassification::FutureEpoch, true),
        (MarkerClassification::FutureEpoch, false),
    ];

    for (marker, empty) in non_current_cases {
        assert!(marker.refusal_names_converter());
        let inputs = node_inputs(marker, empty);
        let s0 = State::init(inputs);
        assert!(safety(&s0));
        let s1 = step(&s0, Action::RejectAdmission);
        assert!(safety(&s1));
        assert_eq!(s1.outcome, Outcome::Refused);
        assert_eq!(s1.source_marker, marker);
        assert_eq!(s1.source_contents, [10, 20, 30, 40]);
        assert!(!s1.engine_opened());
        assert!(!marker.is_current());
    }

    assert!(MarkerClassification::CurrentEpoch6.is_current());
    assert!(!MarkerClassification::CurrentEpoch6.refusal_names_converter());
}

#[test]
fn node_out_of_turn_actions_stutter() {
    let inputs = node_inputs(MarkerClassification::CurrentEpoch6, false);
    let s0 = State::init(inputs);
    let s1 = step(&s0, Action::ConvertAcceptAdmission);
    assert_eq!(s0, s1);
    let s2 = step(&s0, Action::CopyCell);
    assert_eq!(s0, s2);
    let s3 = step(&s0, Action::PublishMarkerRename);
    assert_eq!(s0, s3);
    let s4 = step(&s0, Action::RejectAdmission);
    assert_eq!(s0, s4);
    let s5 = step(&s0, Action::NodeInitStart);
    assert_eq!(s0, s5);
}

// RCV-09
#[test]
fn converter_refuses_path_collision() {
    let inputs = ModelInputs {
        paths_disjoint: false,
        ..converter_inputs(MarkerClassification::RetiredEpoch3)
    };
    let s0 = State::init(inputs);
    assert!(safety(&s0));
    let s1 = step(&s0, Action::RejectAdmission);
    assert!(safety(&s1));
    assert_eq!(s1.outcome, Outcome::Refused);
    assert_eq!(s1.dest_marker, None);
    assert_eq!(s1.dest_cells, [0; NUM_CELLS]);
    assert_eq!(s1.copy_cursor, 0);
}

// RCV-09
#[test]
fn converter_refuses_destination_nonempty() {
    let inputs = ModelInputs {
        dest_initially_empty: false,
        ..converter_inputs(MarkerClassification::RetiredEpoch3)
    };
    let s0 = State::init(inputs);
    assert!(safety(&s0));
    let s1 = step(&s0, Action::RejectAdmission);
    assert!(safety(&s1));
    assert_eq!(s1.outcome, Outcome::Refused);
    assert_eq!(s1.dest_marker, None);
    assert_eq!(s1.dest_cells, [0; NUM_CELLS]);
    assert_eq!(s1.copy_cursor, 0);
}

// RCV-09
#[test]
fn converter_refuses_non_convertible_markers() {
    let non_convertible = [
        MarkerClassification::Absent,
        MarkerClassification::Malformed,
        MarkerClassification::FutureEpoch,
    ];
    for marker in non_convertible {
        assert!(!marker.is_convertible());
        let inputs = converter_inputs(marker);
        let s0 = State::init(inputs);
        assert!(safety(&s0));
        let s1 = step(&s0, Action::RejectAdmission);
        assert!(safety(&s1));
        assert_eq!(s1.outcome, Outcome::Refused);
        assert_eq!(s1.dest_marker, None);
        assert_eq!(s1.dest_cells, [0; NUM_CELLS]);
    }

    assert!(MarkerClassification::RetiredEpoch3.is_convertible());
    assert!(MarkerClassification::RetiredEpoch4.is_convertible());
    assert!(MarkerClassification::RetiredEpoch5.is_convertible());
    assert!(MarkerClassification::CurrentEpoch6.is_convertible());
}

// RCV-09, RCV-10
#[test]
fn converter_refuses_missing_checkpoint_before_writes() {
    let inputs = ModelInputs {
        checkpoint_complete: false,
        ..converter_inputs(MarkerClassification::RetiredEpoch3)
    };
    let s0 = State::init(inputs);
    assert!(safety(&s0));
    let s1 = step(&s0, Action::RefuseMissingCheckpoint);
    assert!(safety(&s1));
    assert_eq!(s1.outcome, Outcome::RefusedNoCheckpoint);
    assert_eq!(s1.source_marker, MarkerClassification::RetiredEpoch3);
    assert_eq!(s1.dest_marker, None);
    assert_eq!(s1.dest_cells, [0; NUM_CELLS]);
    assert_eq!(s1.dest_coins, 0);
    assert_eq!(s1.copy_cursor, 0);
    assert_eq!(s1.verify_cursor, 0);
    assert!(!s1.required_files_durable);
    assert!(!s1.scratch_deleted);
    assert!(!s1.journal_copied);
    assert!(!s1.observed_final_sync);
    let s2 = step(&s1, Action::ConvertAcceptAdmission);
    assert_eq!(s1, s2);
}

// RCV-09
#[test]
fn converter_corruption_at_every_cell() {
    for corrupt_idx in 0..NUM_CELLS {
        let mut s = State::init(converter_inputs(MarkerClassification::RetiredEpoch3));
        assert!(safety(&s));
        s = step(&s, Action::ConvertAcceptAdmission);
        assert!(safety(&s));

        for cell in 0..NUM_CELLS {
            if cell == corrupt_idx {
                s = step(&s, Action::CorruptCopyCell(99));
            } else {
                s = step(&s, Action::CopyCell);
            }
            assert!(safety(&s));
        }
        assert_eq!(s.phase, Phase::Verifying);

        for _ in 0..corrupt_idx {
            s = step(&s, Action::VerifyCell);
            assert!(safety(&s));
            assert_eq!(s.phase, Phase::Verifying);
        }

        s = step(&s, Action::VerifyCell);
        assert!(safety(&s));
        assert_eq!(s.outcome, Outcome::PrepublicationFailure);
        assert_eq!(s.dest_marker, None);
        assert!(!s.has_success_receipt());
    }
}

// RCV-09
#[test]
fn converter_prepublication_io_failures() {
    let failure_stages = [
        Phase::Copying,
        Phase::Verifying,
        Phase::CopyingRequiredFiles,
        Phase::IngestingCheckpoint,
        Phase::Replaying,
        Phase::ReplayDone,
        Phase::RenamingMarker,
    ];

    for stage in failure_stages {
        let mut s = state_at_stage(stage);
        assert_eq!(s.phase, stage);
        s = step(&s, Action::PrepubIoFailure);
        assert!(safety(&s));
        assert_eq!(s.outcome, Outcome::PrepublicationFailure);
        assert_eq!(s.dest_marker, None);
        assert!(!s.has_success_receipt());
        assert!(!s.observed_final_sync);
    }
}

// RCV-09, RCV-10
#[test]
fn converter_final_sync_ambiguity() {
    let mut s = State::init(converter_inputs(MarkerClassification::RetiredEpoch3));
    s = run_pipeline(s);
    assert_eq!(s.phase, Phase::PublishedPendingSync);
    assert_eq!(s.dest_marker, Some(MarkerClassification::CurrentEpoch6));
    assert_eq!(s.dest_coins, 12);
    assert!(safety(&s));

    s = step(&s, Action::FinalSyncFailure);
    assert!(safety(&s));
    assert_eq!(s.outcome, Outcome::PublicationUnknown);
    assert_eq!(s.dest_marker, Some(MarkerClassification::CurrentEpoch6));
    assert_eq!(s.dest_cells, [5, 6, 7, 8]);
    assert_eq!(s.dest_coins, 12);
    assert!(s.required_files_durable);
    assert!(s.scratch_deleted);
    assert!(!s.has_success_receipt());
    assert!(!s.observed_final_sync);
}

// RCV-09, RCV-10
#[test]
fn converter_successful_current_epoch_copy() {
    let mut s = State::init(converter_inputs(MarkerClassification::CurrentEpoch6));
    assert!(safety(&s));
    s = run_pipeline(s);
    s = step(&s, Action::FinalSyncSuccess);

    assert!(safety(&s));
    assert_eq!(s.outcome, Outcome::Success);
    assert_eq!(s.dest_marker, Some(MarkerClassification::CurrentEpoch6));
    assert_eq!(s.dest_cells, [5, 6, 7, 8]);
    assert_eq!(s.dest_coins, 12);
    assert!(s.required_files_durable);
    assert!(s.scratch_deleted);
    assert!(!s.journal_copied);
    assert!(s.has_success_receipt());
    assert!(s.observed_final_sync);
    assert_eq!(s.source_contents, [5, 6, 7, 8]);
    assert_eq!(s.source_marker, MarkerClassification::CurrentEpoch6);
    assert_eq!(s.dest_coins, s.inputs.oracle_coins(s.inputs.durable_head));
}

// RCV-09, RCV-10
#[test]
fn converter_successful_retired_epoch3_migration() {
    let mut s = State::init(converter_inputs(MarkerClassification::RetiredEpoch3));
    assert!(safety(&s));
    s = run_pipeline(s);
    s = step(&s, Action::FinalSyncSuccess);

    assert!(safety(&s));
    assert_eq!(s.outcome, Outcome::Success);
    assert_eq!(s.dest_marker, Some(MarkerClassification::CurrentEpoch6));
    assert_eq!(s.dest_cells, [5, 6, 7, 8]);
    assert!(s.required_files_durable);
    assert!(s.scratch_deleted);
    assert!(s.has_success_receipt());
    assert!(s.observed_final_sync);
    assert_eq!(s.source_marker, MarkerClassification::RetiredEpoch3);
    assert_eq!(s.source_contents, [5, 6, 7, 8]);
}
// RCV-09, RCV-10
#[test]
fn converter_successful_retired_epoch5_migration() {
    let mut s = State::init(converter_inputs(MarkerClassification::RetiredEpoch5));
    assert!(safety(&s));
    s = run_pipeline(s);
    s = step(&s, Action::FinalSyncSuccess);
    assert!(safety(&s));
    assert_eq!(s.outcome, Outcome::Success);
    assert_eq!(s.dest_marker, Some(MarkerClassification::CurrentEpoch6));
    assert_eq!(s.dest_cells, [5, 6, 7, 8]);
    assert!(s.required_files_durable);
    assert!(s.scratch_deleted);
    assert!(s.has_success_receipt());
    assert!(s.observed_final_sync);
    assert_eq!(s.source_marker, MarkerClassification::RetiredEpoch5);
    assert_eq!(s.source_contents, [5, 6, 7, 8]);
}

// RCV-10
#[test]
fn replayed_coins_follow_the_oracle_from_ingest_through_publish() {
    let mut s = State::init(converter_inputs(MarkerClassification::RetiredEpoch3));
    s = step(&s, Action::ConvertAcceptAdmission);
    s = copy_and_verify(s);
    s = step(&s, Action::CopyRequiredFiles);

    s = step(&s, Action::LoadCheckpointCoins);
    assert!(safety(&s));
    assert_eq!(s.phase, Phase::Replaying);
    assert_eq!(s.dest_coins, s.inputs.checkpoint_coins);
    assert_eq!(s.dest_coins, s.inputs.oracle_coins(s.replay_position()));
    assert_eq!(s.replay_applied, 0);

    s = step(&s, Action::ReplayBlock);
    assert!(safety(&s));
    assert_eq!(s.phase, Phase::ReplayDone);
    assert_eq!(s.dest_coins, s.inputs.oracle_coins(1));
    assert_eq!(s.dest_coins, s.inputs.oracle_coins(s.replay_position()));

    s = step(&s, Action::DeleteScratchSuccess);
    s = step(&s, Action::PublishMarkerRename);
    assert!(safety(&s));
    assert_eq!(s.dest_coins, s.inputs.oracle_coins(s.inputs.durable_head));
}

// RCV-10
#[test]
fn checkpoint_at_head_ingests_without_replay() {
    let inputs = ModelInputs {
        checkpoint_height: 1,
        durable_head: 1,
        block_data_present: [true, true],
        checkpoint_coins: 9,
        block_undo_delta: [9, 9],
        ..converter_inputs(MarkerClassification::RetiredEpoch3)
    };
    let mut s = State::init(inputs);
    assert!(safety(&s));
    assert_eq!(s.inputs.oracle_coins(1), 9);
    s = step(&s, Action::ConvertAcceptAdmission);
    s = copy_and_verify(s);
    s = step(&s, Action::CopyRequiredFiles);
    s = step(&s, Action::LoadCheckpointCoins);
    assert!(safety(&s));
    assert_eq!(s.phase, Phase::ReplayDone);
    assert_eq!(s.dest_coins, 9);
    assert_eq!(s.dest_coins, s.inputs.oracle_coins(s.inputs.durable_head));
    assert_eq!(s.replay_applied, 0);

    let s_before = s;
    s = step(&s, Action::ReplayBlock);
    assert_eq!(s, s_before);
    s = step(&s, Action::DeleteScratchSuccess);
    s = step(&s, Action::PublishMarkerRename);
    s = step(&s, Action::FinalSyncSuccess);
    assert!(safety(&s));
    assert_eq!(s.outcome, Outcome::Success);
    assert_eq!(s.dest_coins, s.inputs.oracle_coins(s.inputs.durable_head));
}

// RCV-10
#[test]
fn missing_block_data_aborts_before_publication() {
    let inputs = ModelInputs {
        block_data_present: [true, false],
        ..converter_inputs(MarkerClassification::RetiredEpoch3)
    };
    let mut s = State::init(inputs);
    assert!(safety(&s));
    s = step(&s, Action::ConvertAcceptAdmission);
    s = copy_and_verify(s);
    s = step(&s, Action::CopyRequiredFiles);
    s = step(&s, Action::LoadCheckpointCoins);
    assert_eq!(s.phase, Phase::Replaying);

    let stutter = step(&s, Action::ReplayBlock);
    assert_eq!(s, stutter);

    s = step(&s, Action::MissingBlockDataAbort);
    assert!(safety(&s));
    assert_eq!(s.outcome, Outcome::MissingData { height: 1 });
    assert_eq!(s.dest_marker, None);
    assert!(!s.observed_final_sync);
    assert!(!s.has_success_receipt());
    assert_eq!(s.dest_cells, [5, 6, 7, 8]);
    for action in Action::ALL {
        assert_eq!(step(&s, action), s);
    }
}

// RCV-10
#[test]
fn journal_is_never_copied() {
    let mut s = State::init(converter_inputs(MarkerClassification::RetiredEpoch3));
    assert!(safety(&s));
    assert!(!s.journal_copied);
    s = step(&s, Action::ConvertAcceptAdmission);
    s = copy_and_verify(s);
    s = step(&s, Action::CopyRequiredFiles);
    assert!(s.required_files_durable);
    assert!(!s.journal_copied);
    assert!(safety(&s));
    s = step(&s, Action::LoadCheckpointCoins);
    s = step(&s, Action::ReplayBlock);
    s = step(&s, Action::DeleteScratchSuccess);
    s = step(&s, Action::PublishMarkerRename);
    s = step(&s, Action::FinalSyncSuccess);
    assert!(safety(&s));
    assert_eq!(s.outcome, Outcome::Success);
    assert!(!s.journal_copied);
    for action in Action::ALL {
        assert!(!step(&s, action).journal_copied);
    }
}

// RCV-09, RCV-10
#[test]
fn terminal_outcomes_absorb_all_actions() {
    let mut s = State::init(converter_inputs(MarkerClassification::CurrentEpoch6));
    s = run_pipeline(s);
    s = step(&s, Action::FinalSyncSuccess);
    assert!(s.is_terminal());

    for action in Action::ALL {
        let next = step(&s, action);
        assert_eq!(next, s);
    }
}

#[test]
fn invalid_actions_stutter() {
    let s0 = State::init(converter_inputs(MarkerClassification::RetiredEpoch3));
    let s1 = step(&s0, Action::PublishMarkerRename);
    assert_eq!(s0, s1);
    let s2 = step(&s0, Action::DeleteScratchSuccess);
    assert_eq!(s0, s2);
    let s3 = step(&s0, Action::CopyRequiredFiles);
    assert_eq!(s0, s3);
    let s4 = step(&s0, Action::LoadCheckpointCoins);
    assert_eq!(s0, s4);
    let s5 = step(&s0, Action::ReplayBlock);
    assert_eq!(s0, s5);
    let s6 = step(&s0, Action::MissingBlockDataAbort);
    assert_eq!(s0, s6);
    let s7 = step(&s0, Action::FinalSyncSuccess);
    assert_eq!(s0, s7);
    let s8 = step(&s0, Action::FinalSyncFailure);
    assert_eq!(s0, s8);
    let s9 = step(&s0, Action::Stutter);
    assert_eq!(s0, s9);
}

// RCV-09
#[test]
fn empty_namespaces_representable_by_content_identity() {
    let inputs = ModelInputs {
        initial_source_contents: [0, 42, 0, 99],
        ..converter_inputs(MarkerClassification::CurrentEpoch6)
    };
    let mut s = State::init(inputs);
    s = run_pipeline(s);
    s = step(&s, Action::FinalSyncSuccess);

    assert_eq!(s.outcome, Outcome::Success);
    assert_eq!(s.dest_cells, [0, 42, 0, 99]);
    assert_eq!(s.dest_marker, Some(MarkerClassification::CurrentEpoch6));
}
