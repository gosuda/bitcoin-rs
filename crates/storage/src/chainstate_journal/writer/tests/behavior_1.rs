use super::*;
use std::io::Write;

// Contract: docs/contracts/chainstate-journal-v1.md, JW-BOOT-1.
#[test]
fn writer_bootstrap_uses_chainstate_journal_config_defaults() -> TestResult {
    let writer = open_fresh("config-defaults", Arc::new(CountingStore::new()))?;
    let defaults = super::super::JournalPolicy::default();

    assert_eq!(writer.batch_blocks, defaults.batch_blocks);
    assert_eq!(writer.batch_seconds, defaults.batch_seconds);
    assert_eq!(writer.rotate_bytes, defaults.rotate_mib * 1024 * 1024);
    assert_eq!(
        writer.max_journal_bytes,
        defaults.max_journal_mib * 1024 * 1024
    );
    assert_eq!(writer.max_lag_blocks, defaults.max_lag_blocks);
    assert_eq!(writer.max_lag_seconds, defaults.max_lag_seconds);

    Ok(())
}

// Contract: docs/contracts/chainstate-journal-v1.md, JW-REC-1.
#[test]
fn torn_tail_beyond_head_is_ignored_on_reopen() -> TestResult {
    let store = Arc::new(CountingStore::new());
    let dir;
    {
        let mut writer = open_fresh("torn-tail", Arc::clone(&store))?;
        writer.append(&sample_record(1))?;
        writer.flush_to(1)?;
        dir = writer.dir.try_clone()?;
        // Simulate a torn append after the head: raw bytes past the cursor.
        let mut options = cap_std::fs::OpenOptions::new();
        options.append(true).create(true);
        let mut file = dir.open_with(segment_name(writer.segment_gen), &options)?;
        file.write_all(&[0xde, 0xad, 0xbe, 0xef])?;
        file.sync_all()?;
    }
    // Reopen: the torn tail must be truncated away without error.
    let writer = JournalWriter::open(dir, store)?;
    assert_eq!(writer.head().height, 1);
    Ok(())
}

// Contract: docs/contracts/chainstate-journal-v1.md, JW-REC-1.
#[test]
fn partial_append_truncates_and_retries_idempotently() -> TestResult {
    let store = Arc::new(CountingStore::new());
    let dir;
    let record = sample_record(1);
    {
        let mut writer = open_fresh("idempotent", Arc::clone(&store))?;
        // Buffer record 1 but crash before any boundary (drop = crash).
        writer.append(&record)?;
        dir = writer.dir.try_clone()?;
    }
    // After the crash, record 1 may have reached the page cache but was
    // never covered by a durable head. Reopening truncates to the head
    // cursor; the caller replays record 1 into the same place.
    let mut writer = JournalWriter::open(dir, Arc::clone(&store))?;
    writer.append(&record)?;
    writer.flush_to(1)?;
    assert_eq!(writer.head().height, 1);
    assert_eq!(writer.head().record_count, 1);
    Ok(())
}

// Contract: docs/contracts/chainstate-journal-v1.md, JW-ORDER-1.
#[test]
fn append_failure_blocks_the_next_apply_before_an_untracked_hole_grows() -> TestResult {
    let store = Arc::new(CountingStore::new());
    let mut writer = open_fresh("append-gap", store)?;
    writer.inject_failpoint(JournalWriterFailpoint::SegmentAppend);

    assert!(writer.append(&sample_record(1)).is_err());
    writer.failpoint = None;

    assert!(matches!(
        writer.prepare_for_apply(),
        Err(JournalWriterError::AppendGap { height: 1 })
    ));
    assert!(matches!(
        writer.append(&sample_record(2)),
        Err(JournalWriterError::AppendGap { height: 1 })
    ));
    assert_eq!(writer.head().height, 0);
    Ok(())
}

// Contract: docs/contracts/chainstate-journal-v1.md, JW-ORDER-1.
#[test]
fn out_of_order_append_blocks_the_next_apply() -> TestResult {
    let store = Arc::new(CountingStore::new());
    let mut writer = open_fresh("out-of-order-gap", store)?;

    assert!(matches!(
        writer.append(&sample_record(2)),
        Err(JournalWriterError::OutOfOrder {
            got: 2,
            expected: 1
        })
    ));
    assert!(matches!(
        writer.prepare_for_apply(),
        Err(JournalWriterError::AppendGap { height: 2 })
    ));
    assert!(matches!(
        writer.append(&sample_record(1)),
        Err(JournalWriterError::AppendGap { height: 2 })
    ));
    assert_eq!(writer.head().height, 0);
    Ok(())
}

#[test]
fn partial_append_rolls_back_tail_and_restart_can_retry() -> TestResult {
    let store = Arc::new(CountingStore::new());
    let dir;
    {
        let mut writer = open_fresh("partial-append-gap", Arc::clone(&store))?;
        writer.inject_failpoint(JournalWriterFailpoint::SegmentAppendPartial);

        assert!(writer.append(&sample_record(1)).is_err());
        let segment = writer.dir.open(segment_name(writer.segment_gen))?;
        assert_eq!(segment.metadata()?.len(), writer.segment_offset);
        assert_eq!(writer.segment_offset, writer.head().offset);
        assert!(matches!(
            writer.prepare_for_apply(),
            Err(JournalWriterError::AppendGap { height: 1 })
        ));
        dir = writer.dir.try_clone()?;
    }

    let mut reopened = JournalWriter::open(dir, store)?;
    reopened.append(&sample_record(1))?;
    reopened.flush_to(1)?;
    assert_eq!(reopened.head().height, 1);
    Ok(())
}

#[test]
fn failed_rewind_truncation_blocks_appends_until_restart() -> TestResult {
    let store = Arc::new(CountingStore::new());
    let dir;
    {
        let mut writer = open_fresh("rewind-truncate-gap", Arc::clone(&store))?;
        writer.append(&sample_record(1))?;
        writer.append(&sample_record(2))?;
        writer.flush_to(2)?;
        writer.inject_failpoint(JournalWriterFailpoint::RewindTruncate);

        assert!(writer.rewind_to(1, [1; 32], [0; 32], 3).is_err());
        writer.failpoint = None;
        let persisted = HeadMarker::deserialize(&writer.dir.read("head.json")?)?;
        assert_eq!(persisted.height, 1);
        assert!(matches!(
            writer.prepare_for_apply(),
            Err(JournalWriterError::AppendGap { height: 2 })
        ));
        assert!(matches!(
            writer.append(&sample_record(2)),
            Err(JournalWriterError::AppendGap { height: 2 })
        ));
        dir = writer.dir.try_clone()?;
    }

    let mut reopened = JournalWriter::open(dir, store)?;
    reopened.append(&sample_record(2))?;
    reopened.flush_to(2)?;
    assert_eq!(reopened.head().height, 2);
    Ok(())
}

// Contract: docs/contracts/chainstate-journal-v1.md, JW-ROT-1.
#[test]
fn rotation_keeps_cursor_invariants() -> TestResult {
    let store = Arc::new(CountingStore::new());
    let mut writer = open_fresh("rotation", Arc::clone(&store))?;
    // Rotate exactly once, before the second append.
    let first = sample_record(1);
    writer.rotate_bytes = u64::try_from(encode_record(&first)?.len())?;
    writer.append(&first)?;
    writer.append(&sample_record(2))?;
    assert_eq!(writer.segment_gen, 1, "rotation bumped the generation");
    // head must stay valid across the rotation.
    writer.flush_to(2)?;
    assert_eq!(writer.head().height, 2);
    assert_eq!(writer.head().journal_gen, 1);
    // Zero-padded naming: lexicographic == numeric.
    let names: Vec<String> = (0..3).map(segment_name).collect();
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted, "zero-padded segments sort numerically");
    Ok(())
}

// Contract: docs/contracts/chainstate-journal-v1.md, JW-FAIL-1.
#[test]
fn failpoints_fire_documented_errors() -> TestResult {
    for boundary in [
        JournalWriterFailpoint::SegmentAppend,
        JournalWriterFailpoint::SegmentAppendPartial,
        JournalWriterFailpoint::StorageFlush,
        JournalWriterFailpoint::SegmentSync,
        JournalWriterFailpoint::HeadTempWrite,
        JournalWriterFailpoint::HeadTempSync,
        JournalWriterFailpoint::HeadRename,
        JournalWriterFailpoint::HeadDirSync,
    ] {
        let store = Arc::new(CountingStore::new());
        let mut writer = open_fresh("failpoints", Arc::clone(&store))?;
        writer.inject_failpoint(boundary);
        // Append failpoints fire immediately; durability failures fire only
        // when the explicit batch boundary is advanced.
        let append_result = writer.append(&sample_record(1));
        let result = if matches!(
            boundary,
            JournalWriterFailpoint::SegmentAppend | JournalWriterFailpoint::SegmentAppendPartial
        ) {
            append_result
        } else {
            append_result?;
            writer.flush_to(1)
        };
        assert!(result.is_err(), "{boundary:?} did not fire");
        // ...and head.json must still reflect height 0 (no advancement).
        assert_eq!(writer.head().height, 0, "{boundary:?} advanced the head");
    }
    Ok(())
}

// Contract: docs/contracts/chainstate-journal-v1.md, JW-LIFE-1.
#[test]
fn freeze_rejects_appends_and_compaction_flow_completes() -> TestResult {
    let store = Arc::new(CountingStore::new());
    let mut writer = open_fresh("freeze", Arc::clone(&store))?;
    writer.append(&sample_record(1))?;
    writer.freeze()?;
    assert_eq!(writer.state(), WriterState::Frozen);
    let Err(error) = writer.append(&sample_record(2)) else {
        return Err("frozen writer accepted an append".into());
    };
    assert!(matches!(error, JournalWriterError::NotOpen { .. }));
    writer.compact_to_checkpoint(1, 1, [1; 32], [0; 32], 3, true)?;
    writer.resume()?;
    assert_eq!(writer.state(), WriterState::Open);
    writer.append(&sample_record(2))?;
    Ok(())
}

// Contract: docs/contracts/chainstate-journal-v1.md, JW-MARK-2.
#[test]
fn recovery_progress_compaction_preserves_full_revalidation_marker() -> TestResult {
    let store = Arc::new(CountingStore::new());
    let mut writer = open_fresh("progress-marker", store)?;
    writer.dir.write(
        FULL_REVALIDATION_MARKER,
        b"journal fork crossed below checkpoint base\n",
    )?;

    writer.freeze()?;
    writer.compact_to_checkpoint(1, 0, [1; 32], [0; 32], 0, false)?;
    writer.resume()?;

    assert!(writer.dir.open(FULL_REVALIDATION_MARKER).is_ok());
    Ok(())
}

// Contract: docs/contracts/chainstate-journal-v1.md, JW-ORDER-1.
#[test]
fn recovery_compaction_cannot_clear_an_append_gap() -> TestResult {
    let store = Arc::new(CountingStore::new());
    let mut writer = open_fresh("progress-append-gap", store)?;
    writer.mark_append_gap(1);

    assert!(matches!(
        writer.freeze(),
        Err(JournalWriterError::AppendGap { height: 1 })
    ));
    assert_eq!(writer.state(), WriterState::Open);
    assert!(matches!(
        writer.compact_to_checkpoint(1, 0, [1; 32], [0; 32], 0, false),
        Err(JournalWriterError::NotOpen {
            state: "not frozen"
        })
    ));
    assert!(matches!(
        writer.prepare_for_apply(),
        Err(JournalWriterError::AppendGap { height: 1 })
    ));

    // Compaction itself also owns the guard. Even if an internal caller
    // poisons an already-frozen writer, it cannot commit a new base that a
    // restart would reopen without the in-memory append-gap latch.
    let store = Arc::new(CountingStore::new());
    let mut frozen = open_fresh("frozen-progress-append-gap", store)?;
    frozen.freeze()?;
    frozen.mark_append_gap(1);
    assert!(matches!(
        frozen.compact_to_checkpoint(1, 0, [1; 32], [0; 32], 0, false),
        Err(JournalWriterError::AppendGap { height: 1 })
    ));
    Ok(())
}

// Contract: docs/contracts/recovery.md, RCV-02; chainstate-journal-v1.md, JW-MARK-2.
#[test]
fn cold_retention_removes_all_invalidated_generations_and_preserves_recovery() -> TestResult {
    let store = Arc::new(CountingStore::new());
    let mut writer = open_fresh("cold-retention-generations", Arc::clone(&store))?;
    writer.max_journal_bytes = 1024 * 1024;
    let marker = b"force full validation\n";
    writer.dir.write(FULL_REVALIDATION_MARKER, marker)?;
    writer.dir.write(segment_name(0), [])?;
    writer.dir.write("operator-note", b"preserve")?;
    writer.dir.write("segment-invalid.log", b"not a segment")?;
    let head_before = writer.dir.read("head.json")?;

    // Span directory iterator buffers and sparse generation numbers. Cleanup
    // must enumerate the existing names, not walk up to the largest generation.
    for generation in (1..=2048).chain(std::iter::once(u64::MAX)) {
        writer.dir.write(segment_name(generation), [0; 512])?;
    }
    assert!(writer.requires_compaction()?);

    writer.prepare_for_apply()?;

    for generation in (1..=2048).chain(std::iter::once(u64::MAX)) {
        assert_eq!(
            writer
                .dir
                .metadata(segment_name(generation))
                .err()
                .map(|error| error.kind()),
            Some(std::io::ErrorKind::NotFound),
            "invalidated generation {generation} survived retention relief"
        );
    }
    assert_eq!(writer.dir.read(FULL_REVALIDATION_MARKER)?, marker);
    assert_eq!(writer.dir.read("head.json")?, head_before);
    assert_eq!(writer.dir.read(segment_name(0))?, Vec::<u8>::new());
    assert_eq!(writer.dir.read("operator-note")?, b"preserve");
    assert_eq!(writer.dir.read("segment-invalid.log")?, b"not a segment");
    assert!(!writer.requires_compaction()?);

    // Relief leaves the active append cursor usable and its next durable
    // record recoverable, without retiring the cold-revalidation marker.
    writer.append(&sample_record(1))?;
    writer.flush_to(1)?;
    let dir = writer.dir.try_clone()?;
    drop(writer);
    let reopened = JournalWriter::open(dir, store)?;
    assert_eq!(reopened.head().height, 1);
    assert_eq!(reopened.head().journal_gen, 0);
    assert_eq!(reopened.head().record_count, 1);
    assert_eq!(reopened.dir.read(FULL_REVALIDATION_MARKER)?, marker);
    Ok(())
}

#[test]
fn failed_boundary_retries_before_next_apply_below_lag_limit() -> TestResult {
    let store = Arc::new(CountingStore::new());
    let mut writer = open_fresh("boundary-retry", Arc::clone(&store))?;
    writer.configure(super::super::JournalPolicy {
        batch_blocks: 1,
        batch_seconds: Duration::from_mins(1),
        rotate_mib: 1,
        max_journal_mib: 10,
        max_lag_blocks: 10,
        max_lag_seconds: Duration::from_mins(1),
    })?;
    store.set_fail_flush(true);
    assert!(matches!(
        writer.append(&sample_record(1)),
        Err(JournalWriterError::StorageFlush(_))
    ));
    assert_eq!(writer.head().height, 0);

    store.set_fail_flush(false);
    writer.prepare_for_apply()?;
    assert_eq!(
        writer.head().height,
        1,
        "the failed automatic boundary must be retried before another apply"
    );
    Ok(())
}

#[test]
fn rotation_head_never_names_a_missing_segment() -> TestResult {
    let store = Arc::new(CountingStore::new());
    let dir;
    {
        let mut writer = open_fresh("rotation-crash", Arc::clone(&store))?;
        let first = sample_record(1);
        writer.rotate_bytes = u64::try_from(encode_record(&first)?.len())?;
        writer.append(&first)?;
        writer.flush_to(1)?;
        writer.inject_failpoint(JournalWriterFailpoint::HeadTempWrite);
        assert!(writer.append(&sample_record(2)).is_err());
        dir = writer.dir.try_clone()?;
    }

    let mut reopened = JournalWriter::open(dir, store)?;
    assert_eq!(reopened.head().journal_gen, 0);
    assert_eq!(reopened.head().height, 1);
    reopened.append(&sample_record(2))?;
    reopened.flush_to(2)?;
    assert_eq!(reopened.head().height, 2);
    Ok(())
}
