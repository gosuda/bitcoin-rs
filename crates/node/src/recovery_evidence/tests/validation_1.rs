// CONTRACT: `docs/contracts/recovery.md#RCV-12` owns recovery-evidence
// identity/codec and marker refusal semantics; `RCV-04` owns crash behavior.
use super::*;

// -----------------------------------------------------------------------
// A2.1: Witness and marker file codec tests
// -----------------------------------------------------------------------

#[test]
fn witness_round_trips_and_falls_back_to_prev() {
    let dir = tempfile::tempdir().expect("tempdir");
    let genesis = "000000000019d6689c085ae165831e93";
    let w1 = AppliedTipWitness::new(genesis, 1, 100, "aaa", 1000);
    let w2 = AppliedTipWitness::new(genesis, 2, 200, "bbb", 2000);

    // Write w1 as current.
    write_witness(dir.path(), &w1).expect("write w1");
    let read = read_witness(dir.path(), genesis);
    assert_eq!(read, Some(w1.clone()), "current witness loads");

    // Write w2: rotates w1 to .prev, w2 becomes current.
    write_witness(dir.path(), &w2).expect("write w2");
    let read = read_witness(dir.path(), genesis);
    assert_eq!(read, Some(w2), "new current loads");

    // Remove current — .prev (w1) should load.
    std::fs::remove_file(dir.path().join(WITNESS_FILE)).expect("remove current");
    let read = read_witness(dir.path(), genesis);
    assert_eq!(
        read,
        Some(w1),
        "falls back to .prev when current is missing"
    );
}

#[test]
fn foreign_genesis_or_future_epoch_witness_is_ignored() {
    let dir = tempfile::tempdir().expect("tempdir");
    let genesis = "aaaa";
    let foreign = "bbbb";

    // Foreign genesis — written directly, not through read_witness validation.
    let w = AppliedTipWitness::new(foreign, 1, 100, "aaa", 1000);
    write_witness(dir.path(), &w).expect("write");
    // read_witness with our genesis should return None (foreign genesis).
    assert_eq!(
        read_witness(dir.path(), genesis),
        None,
        "foreign genesis witness is ignored"
    );

    // Same genesis, future epoch — should be readable but not eligible
    // for detection.
    let dir2 = tempfile::tempdir().expect("tempdir");
    let w2 = AppliedTipWitness::new(genesis, 10, 100, "aaa", 1000);
    write_witness(dir2.path(), &w2).expect("write");
    // read_witness returns the witness (it's valid format + genesis),
    // but detect_checkpoint_fallback rejects it (future epoch).
    let read = read_witness(dir2.path(), genesis);
    assert_eq!(read, Some(w2.clone()), "same-genesis witness loads");
    assert_eq!(
        detect_checkpoint_fallback(&w2, 5, genesis, 50),
        None,
        "future-epoch witness is not eligible for detection"
    );
}

// -----------------------------------------------------------------------
// A2.1: Bounded file protocol tests
// -----------------------------------------------------------------------

// `write_bounded` protocol step 8 and recovery contract RCV-03 require
// staged, non-authoritative tails not to survive a returned failure.
#[test]
fn witness_rotation_failure_removes_staged_temp() {
    let dir = tempfile::tempdir().expect("tempdir");
    let genesis = "aaaa";
    let w1 = AppliedTipWitness::new(genesis, 1, 100, "aaa", 1000);
    write_witness(dir.path(), &w1).expect("write current");

    // A directory at the .prev path makes current -> .prev rotation fail
    // after the replacement has already been staged and fsynced.
    std::fs::create_dir(dir.path().join(WITNESS_PREV)).expect("block prev rotation");
    let w2 = AppliedTipWitness::new(genesis, 2, 200, "bbb", 2000);
    assert!(
        write_witness(dir.path(), &w2).is_err(),
        "rotation failure must propagate"
    );
    assert!(
        !dir.path().join(WITNESS_TMP).exists(),
        "returned failure must remove staged temp"
    );
    assert_eq!(
        read_witness(dir.path(), genesis),
        Some(w1),
        "failed rotation keeps the current witness readable"
    );
}

#[test]
fn witness_stage_failure_preserves_bounded_current_prev() {
    let dir = tempfile::tempdir().expect("tempdir");
    let genesis = "aaaa";
    let w1 = AppliedTipWitness::new(genesis, 1, 100, "aaa", 1000);

    // Write a valid current.
    write_witness(dir.path(), &w1).expect("write w1");
    assert_eq!(
        read_witness(dir.path(), genesis),
        Some(w1.clone()),
        "current loads"
    );

    // Simulate a write failure: leave a stale temp file.
    std::fs::write(dir.path().join(WITNESS_TMP), b"garbage").expect("stale temp");

    // A subsequent write should clean up the stale temp and succeed.
    let w2 = AppliedTipWitness::new(genesis, 2, 200, "bbb", 2000);
    write_witness(dir.path(), &w2).expect("write w2 after stale temp");
    assert_eq!(read_witness(dir.path(), genesis), Some(w2.clone()));
    // .prev should be w1.
    std::fs::remove_file(dir.path().join(WITNESS_FILE)).expect("remove current");
    assert_eq!(
        read_witness(dir.path(), genesis),
        Some(w1.clone()),
        ".prev preserved after successful write"
    );

    // Restore w2 as current so .prev is w1 and current is w2.
    write_witness(dir.path(), &w2).expect("restore w2");
    assert_eq!(read_witness(dir.path(), genesis), Some(w2));
    // .prev is now w1 again (w2 was current, rotated w1 to .prev).

    // Corrupt the current file (w2) so it is invalid. A new write must
    // NOT rotate the invalid current over the valid .prev (w1).
    std::fs::write(dir.path().join(WITNESS_FILE), b"corrupt-garbage").expect("corrupt current");
    let w3 = AppliedTipWitness::new(genesis, 3, 300, "ccc", 3000);
    write_witness(dir.path(), &w3).expect("write w3 over corrupt current");
    // Current is now w3.
    assert_eq!(read_witness(dir.path(), genesis), Some(w3));
    // .prev must be w1 (the valid .prev), not the corrupt garbage.
    std::fs::remove_file(dir.path().join(WITNESS_FILE)).expect("remove current");
    assert_eq!(
        read_witness(dir.path(), genesis),
        Some(w1),
        ".prev preserves last valid .prev, not corrupt garbage"
    );
}

// -----------------------------------------------------------------------
// A2.3: Detection logic tests
// -----------------------------------------------------------------------

#[test]
fn same_genesis_older_epoch_higher_witness_warns() {
    let genesis = "aaaa";
    // Witness at height 200, epoch 1 (older).
    let witness = AppliedTipWitness::new(genesis, 1, 200, "bbb", 1000);
    // Current epoch is 5, restored height is 100.
    let result = detect_checkpoint_fallback(&witness, 5, genesis, 100);
    assert_eq!(
        result,
        Some((200, 100)),
        "same-genesis, older-epoch, higher witness must warn"
    );
}

#[test]
fn equal_or_lower_witness_does_not_warn() {
    let genesis = "aaaa";

    // Equal height, different hash — no warning.
    let witness_equal = AppliedTipWitness::new(genesis, 1, 100, "ccc", 1000);
    assert_eq!(
        detect_checkpoint_fallback(&witness_equal, 5, genesis, 100),
        None,
        "equal height does not warn even with different hash"
    );

    // Lower height — no warning.
    let witness_lower = AppliedTipWitness::new(genesis, 1, 50, "ddd", 1000);
    assert_eq!(
        detect_checkpoint_fallback(&witness_lower, 5, genesis, 100),
        None,
        "lower height does not warn"
    );
}

#[test]
fn repeated_index_ahead_report_is_deduplicated() {
    let store = WarningStore::new();
    let msg = "index 'txindex' watermark at 250 is 150 block(s) ahead";

    store.add_index(msg);
    store.add_index(msg); // exact duplicate

    let warnings = store.warnings();
    assert_eq!(
        warnings.len(),
        1,
        "exact duplicate index warning is deduplicated"
    );
    assert_eq!(warnings[0], msg);
}
