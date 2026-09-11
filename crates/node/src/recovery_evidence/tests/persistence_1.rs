use super::*;

// -----------------------------------------------------------------------
// Contract: docs/contracts/recovery.md RCV-01 (derived positions remain distinct and visible)
// -----------------------------------------------------------------------

#[test]
fn checkpoint_and_index_warnings_coexist() {
    let store = WarningStore::new();

    // Set checkpoint warning.
    store.set_checkpoint("checkpoint fallback at 200");
    // Add index warning.
    store.add_index("index 'txindex' watermark at 250 is 150 block(s) ahead");

    let warnings = store.warnings();
    assert_eq!(warnings.len(), 2, "both warning classes coexist");
    assert_eq!(
        warnings[0], "checkpoint fallback at 200",
        "checkpoint warning is first"
    );
    assert!(warnings[1].contains("txindex"), "index warning is second");
}

#[test]
fn index_update_preserves_checkpoint_warning() {
    let store = WarningStore::new();

    store.set_checkpoint("checkpoint fallback at 200");
    store.add_index("index 'txindex' watermark at 250 is 150 block(s) ahead");

    // Another index report should preserve the checkpoint warning.
    store.add_index("index 'scriptindex' watermark at 300 is 200 block(s) ahead");

    let warnings = store.warnings();
    assert_eq!(warnings.len(), 3, "checkpoint + two index warnings");
    assert_eq!(
        warnings[0], "checkpoint fallback at 200",
        "checkpoint warning preserved after index update"
    );
}

// -----------------------------------------------------------------------
// Contract: docs/contracts/recovery.md RCV-03 (durable evidence and prior-or-whole recovery)
// -----------------------------------------------------------------------

#[test]
fn marker_round_trips() {
    let dir = tempfile::tempdir().expect("tempdir");
    let genesis = "aaaa";

    let event = ChainRollbackEvent::new(
        genesis,
        5,
        1000,
        RollbackEventKind::CheckpointFallback {
            restored_height: 100,
            restored_hash: "aaa".to_owned(),
            source: "checkpoint".to_owned(),
            old_height: 200,
            old_hash: "bbb".to_owned(),
        },
    );
    write_marker(dir.path(), &event).expect("write marker");
    let read = read_marker(dir.path(), genesis);
    assert_eq!(read, Some(event), "marker round-trips");
}

#[test]
fn marker_last_event_wins_preserves_prev() {
    let dir = tempfile::tempdir().expect("tempdir");
    let genesis = "aaaa";

    let e1 = ChainRollbackEvent::new(
        genesis,
        5,
        1000,
        RollbackEventKind::CheckpointFallback {
            restored_height: 100,
            restored_hash: "aaa".to_owned(),
            source: "checkpoint".to_owned(),
            old_height: 200,
            old_hash: "bbb".to_owned(),
        },
    );
    let e2 = ChainRollbackEvent::new(
        genesis,
        5,
        2000,
        RollbackEventKind::IndexWatermarkAhead {
            capability: "txindex".to_owned(),
            restored_height: 100,
            restored_hash: "aaa".to_owned(),
            old_height: 250,
            old_hash: "ccc".to_owned(),
            gap: 150,
        },
    );

    write_marker(dir.path(), &e1).expect("write e1");
    write_marker(dir.path(), &e2).expect("write e2");

    // Current is e2 (last-event-wins).
    assert_eq!(read_marker(dir.path(), genesis), Some(e2));

    // .prev is e1.
    std::fs::remove_file(dir.path().join(MARKER_FILE)).expect("remove current");
    assert_eq!(
        read_marker(dir.path(), genesis),
        Some(e1),
        ".prev preserves prior event"
    );
}

// -----------------------------------------------------------------------
// Contract: docs/contracts/recovery.md RCV-04 (recovery publication and index failure outcomes)
// -----------------------------------------------------------------------

#[test]
fn reporter_report_checkpoint_fallback_writes_marker_and_warns() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Arc::new(WarningStore::new());
    let reporter = RecoveryReporter::new(
        Arc::clone(&store),
        dir.path().to_path_buf(),
        "aaaa".to_owned(),
        5,
    );

    reporter
        .report_checkpoint_fallback(200, 100, "aaa", "checkpoint", "bbb", 1000)
        .expect("report");

    // Warning snapshot has checkpoint warning.
    let warnings = store.warnings();
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("height 200"));

    // Marker is on disk.
    let marker = read_marker(dir.path(), "aaaa");
    assert!(marker.is_some(), "marker written");
}

#[test]
fn reporter_report_index_ahead_writes_marker_and_warns() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Arc::new(WarningStore::new());
    let reporter = RecoveryReporter::new(
        Arc::clone(&store),
        dir.path().to_path_buf(),
        "aaaa".to_owned(),
        5,
    );

    reporter
        .report_index_ahead("txindex", 250, 100, "aaa", "ccc", 150, 1000)
        .expect("report");

    // Warning snapshot has index warning.
    let warnings = store.warnings();
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("txindex"));

    // Marker is on disk.
    let marker = read_marker(dir.path(), "aaaa");
    assert!(marker.is_some(), "marker written");
}

// -----------------------------------------------------------------------
// Contract: docs/contracts/recovery.md RCV-01 and RCV-04 (checkpoint/index reconciliation)
// -----------------------------------------------------------------------

#[test]
fn checkpoint_fallback_with_index_far_ahead_converges_and_warns() {
    // Simulates the boot scenario: checkpoint restored at height K,
    // older-epoch witness at N>K, and txindex watermark above K.
    // Both warning classes must coexist in one snapshot after reopen.
    let store = Arc::new(WarningStore::new());
    let dir = tempfile::tempdir().expect("tempdir");
    let genesis = "aaaa";

    // Write an older-epoch witness at height 200.
    let witness = AppliedTipWitness::new(genesis, 1, 200, "bbb", 1000);
    write_witness(dir.path(), &witness).expect("write witness");

    // Boot: read witness, detect checkpoint fallback (restored at 100).
    let read = read_witness(dir.path(), genesis).expect("witness loads");
    let fallback = detect_checkpoint_fallback(&read, 5, genesis, 100);
    assert_eq!(fallback, Some((200, 100)), "checkpoint fallback detected");

    // Report checkpoint fallback.
    let reporter = RecoveryReporter::new(
        Arc::clone(&store),
        dir.path().to_path_buf(),
        genesis.to_owned(),
        5,
    );
    reporter
        .report_checkpoint_fallback(200, 100, "aaa", "checkpoint", "bbb", 2000)
        .expect("report checkpoint fallback");

    // Index watermark ahead: txindex at 250, restored at 100, gap 150.
    reporter
        .report_index_ahead("txindex", 250, 100, "aaa", "ccc", 150, 3000)
        .expect("report index ahead");

    // Both warning classes coexist in one snapshot.
    let warnings = store.warnings();
    assert_eq!(
        warnings.len(),
        2,
        "both checkpoint and index warnings present"
    );
    assert!(
        warnings[0].contains("height 200"),
        "checkpoint fallback is first"
    );
    assert!(warnings[1].contains("txindex"), "index warning is second");

    // Marker is on disk.
    let marker = read_marker(dir.path(), genesis);
    assert!(marker.is_some(), "event marker written");
}

// -----------------------------------------------------------------------
// Contract: docs/contracts/recovery.md RCV-04 (index watermark failure does not block chain progress)
// -----------------------------------------------------------------------

#[test]
fn marker_write_failure_fails_only_the_reporting_index() {
    // When the marker write fails from the index path, the warning is
    // still set in memory (operator can see it), but the error is
    // returned so the caller can fail only that index capability.
    // The checkpoint warning (if any) must survive.
    let store = Arc::new(WarningStore::new());
    let dir = tempfile::tempdir().expect("tempdir");
    let genesis = "aaaa";

    // Set a checkpoint warning first.
    store.set_checkpoint("checkpoint fallback at 200");

    let _reporter = RecoveryReporter::new(
        Arc::clone(&store),
        dir.path().to_path_buf(),
        genesis.to_owned(),
        5,
    );

    // Make the data dir read-only so marker write fails.
    // We simulate this by pointing the reporter at a non-existent
    // parent directory.
    let bad_dir = dir.path().join("nonexistent");
    let bad_reporter = RecoveryReporter::new(Arc::clone(&store), bad_dir, genesis.to_owned(), 5);

    // Index report fails (marker write to nonexistent dir).
    let result = bad_reporter.report_index_ahead("txindex", 250, 100, "aaa", "ccc", 150, 1000);
    assert!(result.is_err(), "marker write failure must return an error");

    // The warning was still set in memory before the marker write.
    let warnings = store.warnings();
    assert_eq!(
        warnings.len(),
        2,
        "checkpoint warning survives index marker failure; index warning was set"
    );
    assert_eq!(
        warnings[0], "checkpoint fallback at 200",
        "checkpoint warning preserved"
    );
    assert!(
        warnings[1].contains("txindex"),
        "index warning was set before marker failure"
    );

    // The node (chain RPC) stays live: the store is still usable.
    let snapshot = store.load();
    assert_eq!(
        snapshot.warnings().len(),
        2,
        "warning store is still readable after marker failure"
    );
}

#[test]
fn foreign_genesis_marker_current_cannot_displace_valid_prev() {
    let dir = tempfile::tempdir().expect("tempdir");
    let genesis = "aaaa";
    let mk = |epoch: u64, time: u64| {
        ChainRollbackEvent::new(
            genesis,
            epoch,
            time,
            RollbackEventKind::CheckpointFallback {
                restored_height: 100,
                restored_hash: "aaa".to_owned(),
                source: "checkpoint".to_owned(),
                old_height: 200,
                old_hash: "bbb".to_owned(),
            },
        )
    };
    let e1 = mk(1, 1000);
    let e2 = mk(2, 2000);

    write_marker(dir.path(), &e1).expect("write e1");
    write_marker(dir.path(), &e2).expect("write e2 -> e1 to .prev");

    // Plant a parseable foreign-genesis marker current.
    let foreign = ChainRollbackEvent::new(
        "bbbb",
        3,
        3000,
        RollbackEventKind::CheckpointFallback {
            restored_height: 100,
            restored_hash: "aaa".to_owned(),
            source: "checkpoint".to_owned(),
            old_height: 200,
            old_hash: "bbb".to_owned(),
        },
    );
    std::fs::write(
        dir.path().join(MARKER_FILE),
        format!("{}\n", foreign.to_json()).as_bytes(),
    )
    .expect("plant foreign marker current");

    let e3 = mk(4, 4000);
    write_marker(dir.path(), &e3).expect("write e3 over foreign current");
    assert_eq!(read_marker(dir.path(), genesis), Some(e3));

    std::fs::remove_file(dir.path().join(MARKER_FILE)).expect("remove current");
    assert_eq!(
        read_marker(dir.path(), genesis),
        Some(e1),
        "valid ma