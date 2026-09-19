// CONTRACT: `docs/contracts/recovery.md#RCV-12` owns evidence identity/codec,
// atomic marker publication, warning-before-marker ordering, and marker
// refusal semantics; `RCV-04` owns crash behavior. These tests are proof,
// not policy.
use super::*;

const G: &str = "aaaa";

fn witness_file(dir: &Path) -> PathBuf {
    dir.join(WITNESS_FILE)
}
fn witness_prev(dir: &Path) -> PathBuf {
    dir.join(format!("{WITNESS_FILE}.prev"))
}
fn witness_tmp(dir: &Path) -> PathBuf {
    dir.join(format!("{WITNESS_FILE}.tmp"))
}
fn marker_file(dir: &Path) -> PathBuf {
    dir.join(MARKER_FILE)
}

/// Reads back the most recent valid marker event. The runtime never reads
/// the marker (it is write-only audit evidence at runtime); these tests pin
/// the write protocol, so the oracle lives here instead of production.
fn read_marker(dir: &Path, genesis_hash: &str) -> Option<ChainRollbackEvent> {
    read_sidecar(dir, MARKER_FILE, |data| {
        ChainRollbackEvent::decode(data, genesis_hash)
    })
}

fn fallback_event(genesis: &str, epoch: u64, time: u64) -> ChainRollbackEvent {
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
}

#[test]
fn witness_round_trips_and_falls_back_to_prev() {
    let dir = tempfile::tempdir().expect("tempdir");
    let genesis = "000000000019d6689c085ae165831e93";
    let w1 = AppliedTipWitness::new(genesis, 1, 100, "aaa", 1000);
    let w2 = AppliedTipWitness::new(genesis, 2, 200, "bbb", 2000);

    write_witness(dir.path(), &w1).expect("write w1");
    assert_eq!(read_witness(dir.path(), genesis), Some(w1.clone()));

    write_witness(dir.path(), &w2).expect("write w2");
    assert_eq!(read_witness(dir.path(), genesis), Some(w2));

    std::fs::remove_file(witness_file(dir.path())).expect("remove current");
    assert_eq!(
        read_witness(dir.path(), genesis),
        Some(w1),
        "falls back to .prev when current is missing"
    );
}

#[test]
fn malformed_current_falls_back_to_valid_prev() {
    let dir = tempfile::tempdir().expect("tempdir");
    let w1 = AppliedTipWitness::new(G, 1, 100, "aaa", 1000);
    let w2 = AppliedTipWitness::new(G, 2, 200, "bbb", 2000);
    write_witness(dir.path(), &w1).expect("write w1");
    write_witness(dir.path(), &w2).expect("write w2 -> w1 to .prev");
    std::fs::write(witness_file(dir.path()), b"corrupt-garbage").expect("corrupt current");
    assert_eq!(
        read_witness(dir.path(), G),
        Some(w1),
        "malformed current falls back to valid .prev"
    );

    let e1 = fallback_event(G, 1, 1000);
    let e2 = fallback_event(G, 2, 2000);
    write_marker(dir.path(), &e1).expect("write e1");
    write_marker(dir.path(), &e2).expect("write e2 -> e1 to .prev");
    std::fs::write(marker_file(dir.path()), b"corrupt-garbage").expect("corrupt current");
    assert_eq!(
        read_marker(dir.path(), G),
        Some(e1),
        "malformed marker current falls back to valid .prev"
    );
}

#[test]
fn foreign_genesis_or_future_epoch_witness_is_ignored() {
    let dir = tempfile::tempdir().expect("tempdir");

    let w = AppliedTipWitness::new("bbbb", 1, 100, "aaa", 1000);
    write_witness(dir.path(), &w).expect("write");
    assert_eq!(
        read_witness(dir.path(), G),
        None,
        "foreign genesis witness is ignored"
    );

    let dir2 = tempfile::tempdir().expect("tempdir");
    let w2 = AppliedTipWitness::new(G, 10, 100, "aaa", 1000);
    write_witness(dir2.path(), &w2).expect("write");
    assert_eq!(read_witness(dir2.path(), G), Some(w2.clone()));
    assert!(
        !checkpoint_fallback(&w2, 5, 50),
        "future-epoch witness is not eligible for detection"
    );
}

// `write` step 8 and RCV-03 require staged, non-authoritative tails not to
// survive a returned failure.
#[test]
fn witness_rotation_failure_removes_staged_temp() {
    let dir = tempfile::tempdir().expect("tempdir");
    let w1 = AppliedTipWitness::new(G, 1, 100, "aaa", 1000);
    write_witness(dir.path(), &w1).expect("write current");

    std::fs::create_dir(witness_prev(dir.path())).expect("block prev rotation");
    let w2 = AppliedTipWitness::new(G, 2, 200, "bbb", 2000);
    assert!(
        write_witness(dir.path(), &w2).is_err(),
        "rotation failure must propagate"
    );
    assert!(
        !witness_tmp(dir.path()).exists(),
        "returned failure must remove staged temp"
    );
    assert_eq!(
        read_witness(dir.path(), G),
        Some(w1),
        "failed rotation keeps the current witness readable"
    );
}

#[test]
fn witness_stage_failure_preserves_bounded_current_prev() {
    let dir = tempfile::tempdir().expect("tempdir");
    let w1 = AppliedTipWitness::new(G, 1, 100, "aaa", 1000);

    write_witness(dir.path(), &w1).expect("write w1");
    std::fs::write(witness_tmp(dir.path()), b"garbage").expect("stale temp");

    let w2 = AppliedTipWitness::new(G, 2, 200, "bbb", 2000);
    write_witness(dir.path(), &w2).expect("write w2 after stale temp");
    std::fs::remove_file(witness_file(dir.path())).expect("remove current");
    assert_eq!(
        read_witness(dir.path(), G),
        Some(w1.clone()),
        ".prev preserved after successful write"
    );

    write_witness(dir.path(), &w2).expect("restore w2");

    // An invalid current must not rotate over a valid .prev.
    std::fs::write(witness_file(dir.path()), b"corrupt-garbage").expect("corrupt current");
    let w3 = AppliedTipWitness::new(G, 3, 300, "ccc", 3000);
    write_witness(dir.path(), &w3).expect("write w3 over corrupt current");
    assert_eq!(read_witness(dir.path(), G), Some(w3));
    std::fs::remove_file(witness_file(dir.path())).expect("remove current");
    assert_eq!(
        read_witness(dir.path(), G),
        Some(w1),
        ".prev preserves last valid .prev, not corrupt garbage"
    );
}

#[test]
fn same_genesis_older_epoch_higher_witness_warns() {
    let witness = AppliedTipWitness::new(G, 1, 200, "bbb", 1000);
    assert!(
        checkpoint_fallback(&witness, 5, 100),
        "same-genesis, older-epoch, higher witness must warn"
    );
}

#[test]
fn equal_or_lower_witness_does_not_warn() {
    let witness_equal = AppliedTipWitness::new(G, 1, 100, "ccc", 1000);
    assert!(!checkpoint_fallback(&witness_equal, 5, 100));

    let witness_lower = AppliedTipWitness::new(G, 1, 50, "ddd", 1000);
    assert!(!checkpoint_fallback(&witness_lower, 5, 100));
}

#[test]
fn index_update_preserves_checkpoint_warning() {
    let publisher = RecoveryEvidencePublisher::new(PathBuf::new(), G.to_owned(), 5);
    publisher.update(|w| w.checkpoint = Some("checkpoint fallback at 200".to_owned()));
    publisher.update(|w| {
        w.index
            .push("index 'txindex' watermark at 250 is 150 block(s) ahead".to_owned());
        w.index
            .push("index 'scriptindex' watermark at 300 is 200 block(s) ahead".to_owned());
    });

    let warnings = publisher.warnings();
    assert_eq!(warnings.len(), 3, "checkpoint + two index warnings");
    assert_eq!(warnings[0], "checkpoint fallback at 200");
}

#[test]
fn repeated_index_ahead_report_is_deduplicated() {
    let dir = tempfile::tempdir().expect("tempdir");
    let publisher = RecoveryEvidencePublisher::new(dir.path().to_path_buf(), G.to_owned(), 5);

    publisher
        .publish_index_ahead("txindex", 250, 100, "aaa", "ccc", 150, 1000)
        .expect("publish");
    publisher
        .publish_index_ahead("txindex", 250, 100, "aaa", "ccc", 150, 1000)
        .expect("publish");

    let warnings = publisher.warnings();
    assert_eq!(
        warnings.len(),
        1,
        "exact duplicate index warning is deduplicated"
    );
}

#[test]
fn getblockchaininfo_reports_atomic_rollback_warnings() {
    let publisher = RecoveryEvidencePublisher::new(PathBuf::new(), G.to_owned(), 5);
    publisher.update(|w| {
        w.checkpoint = Some("checkpoint fallback at 200".to_owned());
        w.index
            .push("index 'txindex' watermark at 250 is 150 block(s) ahead".to_owned());
        w.index
            .push("index 'scriptindex' watermark at 300 is 200 block(s) ahead".to_owned());
        w.index.sort();
    });

    let warnings = publisher.warnings();
    assert_eq!(warnings.len(), 3);
    assert_eq!(warnings[0], "checkpoint fallback at 200");
    assert!(warnings[1].contains("scriptindex"), "sorted");
    assert!(warnings[2].contains("txindex"));
}

#[test]
fn marker_last_event_wins_preserves_prev() {
    let dir = tempfile::tempdir().expect("tempdir");
    let e1 = fallback_event(G, 5, 1000);
    let e2 = ChainRollbackEvent::new(
        G,
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
    assert_eq!(read_marker(dir.path(), G), Some(e2));

    std::fs::remove_file(marker_file(dir.path())).expect("remove current");
    assert_eq!(
        read_marker(dir.path(), G),
        Some(e1),
        ".prev preserves prior event"
    );
}

#[test]
fn checkpoint_fallback_with_index_far_ahead_converges_and_warns() {
    let dir = tempfile::tempdir().expect("tempdir");

    let witness = AppliedTipWitness::new(G, 1, 200, "bbb", 1000);
    write_witness(dir.path(), &witness).expect("write witness");
    let read_back = read_witness(dir.path(), G).expect("witness loads");
    assert!(checkpoint_fallback(&read_back, 5, 100));

    let publisher = RecoveryEvidencePublisher::new(dir.path().to_path_buf(), G.to_owned(), 5);
    publisher
        .publish_checkpoint_fallback(200, 100, "aaa", "checkpoint", "bbb", 2000)
        .expect("publish checkpoint fallback");
    publisher
        .publish_index_ahead("txindex", 250, 100, "aaa", "ccc", 150, 3000)
        .expect("publish index ahead");

    let warnings = publisher.warnings();
    assert_eq!(warnings.len(), 2, "both warning classes present");
    assert!(warnings[0].contains("height 200"));
    assert!(warnings[1].contains("txindex"));
    assert!(read_marker(dir.path(), G).is_some());
}

// RCV-12: marker failure returns an error while the warning already set
// stays process-visible, and a prior checkpoint warning is preserved.
#[test]
fn index_marker_failure_preserves_checkpoint_warning() {
    let dir = tempfile::tempdir().expect("tempdir");
    let publisher = RecoveryEvidencePublisher::new(dir.path().join("nonexistent"), G.to_owned(), 5);
    publisher.update(|w| w.checkpoint = Some("checkpoint fallback at height 200".to_owned()));

    let result = publisher.publish_index_ahead("txindex", 250, 100, "aaa", "ccc", 150, 1000);
    assert!(result.is_err(), "marker write failure must return an error");

    let warnings = publisher.warnings();
    assert_eq!(
        warnings.len(),
        2,
        "checkpoint warning survives index marker failure"
    );
    assert!(warnings[0].contains("height 200"));
    assert!(warnings[1].contains("txindex"));
}

#[test]
fn oversized_evidence_file_is_ignored() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_witness(dir.path(), &AppliedTipWitness::new(G, 1, 100, "aaa", 1000)).expect("write");

    std::fs::write(witness_file(dir.path()), "x".repeat(MAX_FILE_BYTES + 1)).expect("overwrite");
    assert_eq!(
        read_witness(dir.path(), G),
        None,
        "oversized file is ignored"
    );
}

#[test]
fn oversized_witness_write_is_rejected_without_rotating() {
    let dir = tempfile::tempdir().expect("tempdir");
    let w1 = AppliedTipWitness::new(G, 1, 100, "aaa", 1000);
    write_witness(dir.path(), &w1).expect("write w1");

    let big = AppliedTipWitness::new(G, 2, 200, "a".repeat(MAX_FILE_BYTES), 2000);
    let error = write_witness(dir.path(), &big).unwrap_err();
    assert!(
        matches!(error, EvidenceError::TooLarge { .. }),
        "oversized write is rejected, got {error:?}"
    );
    assert_eq!(
        read_witness(dir.path(), G),
        Some(w1),
        "rejected write leaves current untouched"
    );
    assert!(
        !witness_tmp(dir.path()).exists(),
        "rejected write stages no tmp tail"
    );

    let event = fallback_event(G, 3, 3000);
    write_marker(dir.path(), &event).expect("write marker");
    let big_event = ChainRollbackEvent::new(
        G,
        4,
        4000,
        RollbackEventKind::CheckpointFallback {
            restored_height: 100,
            restored_hash: "a".repeat(MAX_FILE_BYTES),
            source: "checkpoint".to_owned(),
            old_height: 200,
            old_hash: "bbb".to_owned(),
        },
    );
    assert!(
        matches!(
            write_marker(dir.path(), &big_event).unwrap_err(),
            EvidenceError::TooLarge { .. }
        ),
        "oversized marker is rejected"
    );
    assert_eq!(
        read_marker(dir.path(), G),
        Some(event),
        "rejected marker leaves current untouched"
    );
}

#[test]
fn foreign_format_write_is_rejected_without_rotating() {
    let dir = tempfile::tempdir().expect("tempdir");
    let w1 = AppliedTipWitness::new(G, 1, 100, "aaa", 1000);
    write_witness(dir.path(), &w1).expect("write w1");

    let mut bad = AppliedTipWitness::new(G, 2, 200, "bbb", 2000);
    bad.format = "9".to_owned();
    let error = write_witness(dir.path(), &bad).unwrap_err();
    assert!(
        matches!(error, EvidenceError::InvalidRecord),
        "unwritable record is rejected, got {error:?}"
    );
    assert_eq!(
        read_witness(dir.path(), G),
        Some(w1),
        "rejected write leaves current untouched"
    );
    assert!(
        !witness_tmp(dir.path()).exists(),
        "rejected write stages no tmp tail"
    );
}

// Semantic rotation: a parseable but foreign-genesis or wrong-format current
// cannot displace a valid .prev.
#[test]
fn foreign_genesis_current_cannot_displace_valid_prev() {
    let dir = tempfile::tempdir().expect("tempdir");
    let w1 = AppliedTipWitness::new(G, 1, 100, "aaa", 1000);
    let w2 = AppliedTipWitness::new(G, 2, 200, "bbb", 2000);

    write_witness(dir.path(), &w1).expect("write w1");
    write_witness(dir.path(), &w2).expect("write w2 -> w1 to .prev");
    assert_eq!(read_witness(dir.path(), G), Some(w2.clone()));

    let foreign = AppliedTipWitness::new("bbbb", 3, 300, "ccc", 3000);
    let foreign_bytes = format!("{}\n", serde_json::to_string(&foreign).unwrap());
    std::fs::write(witness_file(dir.path()), foreign_bytes.as_bytes())
        .expect("plant foreign current");
    assert!(
        serde_json::from_slice::<AppliedTipWitness>(
            &std::fs::read(witness_file(dir.path())).unwrap()
        )
        .is_ok(),
        "foreign current is parseable JSON"
    );

    let w3 = AppliedTipWitness::new(G, 4, 400, "ddd", 4000);
    write_witness(dir.path(), &w3).expect("write w3 over foreign current");
    assert_eq!(read_witness(dir.path(), G), Some(w3.clone()));

    std::fs::remove_file(witness_file(dir.path())).expect("remove current");
    assert_eq!(
        read_witness(dir.path(), G),
        Some(w1.clone()),
        "valid .prev survives; foreign current never displaced it"
    );
    let raw = std::fs::read(witness_prev(dir.path())).expect(".prev bytes");
    assert_eq!(
        AppliedTipWitness::decode(&raw, G).map(|w| w.genesis_hash),
        Some(G.to_owned()),
        ".prev is the valid record, never the foreign one"
    );

    // Same contract for a wrong-format current.
    let dir2 = tempfile::tempdir().expect("tempdir");
    write_witness(dir2.path(), &w1).expect("write w1");
    write_witness(dir2.path(), &w2).expect("write w2 -> w1 to .prev");
    let mut wrong_format = w2;
    wrong_format.format = "999".to_owned();
    std::fs::write(
        witness_file(dir2.path()),
        format!("{}\n", serde_json::to_string(&wrong_format).unwrap()).as_bytes(),
    )
    .expect("plant wrong-format current");
    write_witness(dir2.path(), &w3).expect("write w3 over wrong-format current");
    std::fs::remove_file(witness_file(dir2.path())).expect("remove current");
    assert_eq!(
        read_witness(dir2.path(), G),
        Some(w1),
        "valid .prev survives a wrong-format current"
    );
}
