use super::{
    Action, MarkerClassification, Mode, ModelInputs, NUM_CELLS, Outcome, Phase, State, safety, step,
};

fn state_at_stage(stage: Phase) -> State {
    let inputs = ModelInputs {
        mode: Mode::OfflineConversion,
        source_marker: MarkerClassification::RetiredEpoch2,
        source_dir_empty: false,
        dest_initially_empty: true,
        paths_disjoint: true,
        initial_source_contents: [5, 6, 7, 8],
    };
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
    if stage == Phase::SyncingRequiredFiles {
        return s;
    }
    s = step(&s, Action::SyncRequiredFilesSuccess);
    if stage == Phase::DeletingScratch {
        return s;
    }
    s = step(&s, Action::DeleteScratchSuccess);
    s
}

// RCV-09
#[test]
fn node_exact_current_opens_without_alteration() {
    let inputs = ModelInputs {
        mode: Mode::NodeAdmission,
        source_marker: MarkerClassification::CurrentEpoch3,
        source_dir_empty: false,
        dest_initially_empty: false,
        paths_disjoint: false,
        initial_source_contents: [10, 20, 30, 40],
    };
    let s0 = State::init(inputs);
    assert!(safety(&s0));
    let s1 = step(&s0, Action::NodeOpenDirect);
    assert!(safety(&s1));
    assert_eq!(s1.outcome, Outcome::Success);
    assert!(s1.engine_opened());
    assert_eq!(s1.source_marker, MarkerClassification::CurrentEpoch3);
    assert_eq!(s1.source_contents, [10, 20, 30, 40]);
    assert_eq!(s1.dest_marker, None);
    assert!(!s1.observed_final_sync);
}

// RCV-09
#[test]
fn node_absent_empty_initializes_marker_and_opens() {
    let inputs = ModelInputs {
        mode: Mode::NodeAdmission,
        source_marker: MarkerClassification::Absent,
        source_dir_empty: true,
        dest_initially_empty: false,
        paths_disjoint: false,
        initial_source_contents: [10, 20, 30, 40],
    };
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
    assert_eq!(s3.source_marker, MarkerClassification::CurrentEpoch3);
    assert!(!s3.engine_opened());

    let s4 = step(&s3, Action::FinalSyncSuccess);
    assert!(safety(&s4));
    assert_eq!(s4.outcome, Outcome::Success);
    assert!(s4.engine_opened());
    assert_eq!(s4.source_marker, MarkerClassification::CurrentEpoch3);
    assert_eq!(s4.source_contents, [10, 20, 30, 40]);
    assert!(s4.observed_final_sync);
}

// RCV-09
#[test]
fn node_absent_empty_init_fails_before_rename_prepublication_failure() {
    let inputs = ModelInputs {
        mode: Mode::NodeAdmission,
        source_marker: MarkerClassification::Absent,
        source_dir_empty: true,
        dest_initially_empty: false,
        paths_disjoint: false,
        initial_source_contents: [10, 20, 30, 40],
    };
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
    let inputs = ModelInputs {
        mode: Mode::NodeAdmission,
        source_marker: MarkerClassification::Absent,
        source_dir_empty: true,
        dest_initially_empty: false,
        paths_disjoint: false,
        initial_source_contents: [10, 20, 30, 40],
    };
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
    let inputs = ModelInputs {
        mode: Mode::NodeAdmission,
        source_marker: MarkerClassification::Absent,
        source_dir_empty: true,
        dest_initially_empty: false,
        paths_disjoint: false,
        initial_source_contents: [10, 20, 30, 40],
    };
    let s0 = State::init(inputs);
    let s1 = step(&s0, Action::NodeInitStart);
    let s2 = step(&s1, Action::NodeInitWriteTempSuccess);
    let s3 = step(&s2, Action::NodeInitRenameSuccess);
    let s4 = step(&s3, Action::FinalSyncFailure);
    assert!(safety(&s4));
    assert_eq!(s4.outcome, Outcome::PublicationUnknown);
    assert_eq!(s4.source_marker, MarkerClassification::CurrentEpoch3);
    assert!(!s4.engine_opened());
    assert!(!s4.observed_final_sync);
}

// RCV-09
#[test]
fn node_refuses_all_non_current_non_empty_marker_classes() {
    let non_current_cases = [
        (MarkerClassification::Absent, false),
        (MarkerClassification::Malformed, true),
        (MarkerClassification::Malformed, false),
        (MarkerClassification::RetiredEpoch2, true),
        (MarkerClassification::RetiredEpoch2, false),
        (MarkerClassification::FutureEpoch, true),
        (MarkerClassification::FutureEpoch, false),
    ];

    for (marker, empty) in non_current_cases {
        let inputs = ModelInputs {
            mode: Mode::NodeAdmission,
            source_marker: marker,
            source_dir_empty: empty,
            dest_initially_empty: false,
            paths_disjoint: false,
            initial_source_contents: [11, 22, 33, 44],
        };
        let s0 = State::init(inputs);
        assert!(safety(&s0));
        let s1 = step(&s0, Action::RejectAdmission);
        assert!(safety(&s1));
        assert_eq!(s1.outcome, Outcome::Refused);
        assert_eq!(s1.source_marker, marker);
        assert_eq!(s1.source_contents, [11, 22, 33, 44]);
        assert!(!s1.engine_opened());
    }
}

#[test]
fn node_out_of_turn_actions_stutter() {
    let inputs = ModelInputs {
        mode: Mode::NodeAdmission,
        source_marker: MarkerClassification::CurrentEpoch3,
        source_dir_empty: false,
        dest_initially_empty: false,
        paths_disjoint: false,
        initial_source_contents: [1, 2, 3, 4],
    };
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
        mode: Mode::OfflineConversion,
        source_marker: MarkerClassification::RetiredEpoch2,
        source_dir_empty: false,
        dest_initially_empty: true,
        paths_disjoint: false,
        initial_source_contents: [1, 2, 3, 4],
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
        mode: Mode::OfflineConversion,
        source_marker: MarkerClassification::RetiredEpoch2,
        source_dir_empty: false,
        dest_initially_empty: false,
        paths_disjoint: true,
        initial_source_contents: [1, 2, 3, 4],
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
        let inputs = ModelInputs {
            mode: Mode::OfflineConversion,
            source_marker: marker,
            source_dir_empty: false,
            dest_initially_empty: true,
            paths_disjoint: true,
            initial_source_contents: [1, 2, 3, 4],
        };
        let s0 = State::init(inputs);
        assert!(safety(&s0));
        let s1 = step(&s0, Action::RejectAdmission);
        assert!(safety(&s1));
        assert_eq!(s1.outcome, Outcome::Refused);
        assert_eq!(s1.dest_marker, None);
        assert_eq!(s1.dest_cells, [0; NUM_CELLS]);
    }
}

// RCV-09
#[test]
fn converter_corruption_at_every_cell() {
    for corrupt_idx in 0..NUM_CELLS {
        let inputs = ModelInputs {
            mode: Mode::OfflineConversion,
            source_marker: MarkerClassification::RetiredEpoch2,
            source_dir_empty: false,
            dest_initially_empty: true,
            paths_disjoint: true,
            initial_source_contents: [11, 22, 33, 44],
        };
        let mut s = State::init(inputs);
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
        Phase::SyncingRequiredFiles,
        Phase::DeletingScratch,
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
    }
}

// RCV-09
#[test]
fn converter_final_sync_ambiguity() {
    let inputs = ModelInputs {
        mode: Mode::OfflineConversion,
        source_marker: MarkerClassification::RetiredEpoch2,
        source_dir_empty: false,
        dest_initially_empty: true,
        paths_disjoint: true,
        initial_source_contents: [5, 6, 7, 8],
    };
    let mut s = State::init(inputs);
    s = step(&s, Action::ConvertAcceptAdmission);
    for _ in 0..NUM_CELLS {
        s = step(&s, Action::CopyCell);
    }
    for _ in 0..NUM_CELLS {
        s = step(&s, Action::VerifyCell);
    }
    s = step(&s, Action::SyncRequiredFilesSuccess);
    s = step(&s, Action::DeleteScratchSuccess);
    s = step(&s, Action::PublishMarkerRename);
    assert_eq!(s.phase, Phase::PublishedPendingSync);
    assert_eq!(s.dest_marker, Some(MarkerClassification::CurrentEpoch3));
    assert!(safety(&s));

    s = step(&s, Action::FinalSyncFailure);
    assert!(safety(&s));
    assert_eq!(s.outcome, Outcome::PublicationUnknown);
    assert_eq!(s.dest_marker, Some(MarkerClassification::CurrentEpoch3));
    assert_eq!(s.dest_cells, [5, 6, 7, 8]);
    assert!(s.required_files_durable);
    assert!(s.scratch_deleted);
    assert!(!s.has_success_receipt());
    assert!(!s.observed_final_sync);
}

// RCV-09
#[test]
fn converter_successful_current_epoch_copy() {
    let inputs = ModelInputs {
        mode: Mode::OfflineConversion,
        source_marker: MarkerClassification::CurrentEpoch3,
        source_dir_empty: false,
        dest_initially_empty: true,
        paths_disjoint: true,
        initial_source_contents: [1, 2, 3, 4],
    };
    let mut s = State::init(inputs);
    assert!(safety(&s));
    s = step(&s, Action::ConvertAcceptAdmission);
    for _ in 0..NUM_CELLS {
        s = step(&s, Action::CopyCell);
    }
    for _ in 0..NUM_CELLS {
        s = step(&s, Action::VerifyCell);
    }
    s = step(&s, Action::SyncRequiredFilesSuccess);
    s = step(&s, Action::DeleteScratchSuccess);
    s = step(&s, Action::PublishMarkerRename);
    s = step(&s, Action::FinalSyncSuccess);

    assert!(safety(&s));
    assert_eq!(s.outcome, Outcome::Success);
    assert_eq!(s.dest_marker, Some(MarkerClassification::CurrentEpoch3));
    assert_eq!(s.dest_cells, [1, 2, 3, 4]);
    assert!(s.required_files_durable);
    assert!(s.scratch_deleted);
    assert!(s.has_success_receipt());
    assert!(s.observed_final_sync);
    assert_eq!(s.source_contents, [1, 2, 3, 4]);
    assert_eq!(s.source_marker, MarkerClassification::CurrentEpoch3);
}

// RCV-09
#[test]
fn converter_successful_retired_epoch2_migration() {
    let inputs = ModelInputs {
        mode: Mode::OfflineConversion,
        source_marker: MarkerClassification::RetiredEpoch2,
        source_dir_empty: false,
        dest_initially_empty: true,
        paths_disjoint: true,
        initial_source_contents: [101, 102, 103, 104],
    };
    let mut s = State::init(inputs);
    assert!(safety(&s));
    s = step(&s, Action::ConvertAcceptAdmission);
    for _ in 0..NUM_CELLS {
        s = step(&s, Action::CopyCell);
    }
    for _ in 0..NUM_CELLS {
        s = step(&s, Action::VerifyCell);
    }
    s = step(&s, Action::SyncRequiredFilesSuccess);
    s = step(&s, Action::DeleteScratchSuccess);
    s = step(&s, Action::PublishMarkerRename);
    s = step(&s, Action::FinalSyncSuccess);

    assert!(safety(&s));
    assert_eq!(s.outcome, Outcome::Success);
    assert_eq!(s.dest_marker, Some(MarkerClassification::CurrentEpoch3));
    assert_eq!(s.dest_cells, [101, 102, 103, 104]);
    assert!(s.required_files_durable);
    assert!(s.scratch_deleted);
    assert!(s.has_success_receipt());
    assert!(s.observed_final_sync);
    assert_eq!(s.source_marker, MarkerClassification::RetiredEpoch2);
    assert_eq!(s.source_contents, [101, 102, 103, 104]);
}

#[test]
fn terminal_outcomes_absorb_all_actions() {
    let inputs = ModelInputs {
        mode: Mode::OfflineConversion,
        source_marker: MarkerClassification::CurrentEpoch3,
        source_dir_empty: false,
        dest_initially_empty: true,
        paths_disjoint: true,
        initial_source_contents: [1, 2, 3, 4],
    };
    let mut s = State::init(inputs);
    s = step(&s, Action::ConvertAcceptAdmission);
    for _ in 0..NUM_CELLS {
        s = step(&s, Action::CopyCell);
    }
    for _ in 0..NUM_CELLS {
        s = step(&s, Action::VerifyCell);
    }
    s = step(&s, Action::SyncRequiredFilesSuccess);
    s = step(&s, Action::DeleteScratchSuccess);
    s = step(&s, Action::PublishMarkerRename);
    s = step(&s, Action::FinalSyncSuccess);
    assert!(s.is_terminal());

    for action in Action::ALL {
        let next = step(&s, action);
        assert_eq!(next, s);
    }
}

#[test]
fn invalid_actions_stutter() {
    let inputs = ModelInputs {
        mode: Mode::OfflineConversion,
        source_marker: MarkerClassification::RetiredEpoch2,
        source_dir_empty: false,
        dest_initially_empty: true,
        paths_disjoint: true,
        initial_source_contents: [1, 2, 3, 4],
    };
    let s0 = State::init(inputs);
    let s1 = step(&s0, Action::PublishMarkerRename);
    assert_eq!(s0, s1);
    let s2 = step(&s0, Action::DeleteScratchSuccess);
    assert_eq!(s0, s2);
    let s3 = step(&s0, Action::SyncRequiredFilesSuccess);
    assert_eq!(s0, s3);
    let s4 = step(&s0, Action::FinalSyncSuccess);
    assert_eq!(s0, s4);
    let s5 = step(&s0, Action::FinalSyncFailure);
    assert_eq!(s0, s5);
    let s6 = step(&s0, Action::Stutter);
    assert_eq!(s0, s6);
}

// RCV-09
#[test]
fn empty_namespaces_representable_by_content_identity() {
    let inputs = ModelInputs {
        mode: Mode::OfflineConversion,
        source_marker: MarkerClassification::CurrentEpoch3,
        source_dir_empty: false,
        dest_initially_empty: true,
        paths_disjoint: true,
        initial_source_contents: [0, 42, 0, 99],
    };
    let mut s = State::init(inputs);
    s = step(&s, Action::ConvertAcceptAdmission);
    for _ in 0..NUM_CELLS {
        s = step(&s, Action::CopyCell);
    }
    for _ in 0..NUM_CELLS {
        s = step(&s, Action::VerifyCell);
    }
    s = step(&s, Action::SyncRequiredFilesSuccess);
    s = step(&s, Action::DeleteScratchSuccess);
    s = step(&s, Action::PublishMarkerRename);
    s = step(&s, Action::FinalSyncSuccess);

    assert_eq!(s.outcome, Outcome::Success);
    assert_eq!(s.dest_cells, [0, 42, 0, 99]);
    assert_eq!(s.dest_marker, Some(MarkerClassification::CurrentEpoch3));
}
