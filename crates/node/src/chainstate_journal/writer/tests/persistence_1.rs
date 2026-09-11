use super::*;

// Contract references: docs/contracts/chainstate-journal-v1.md, JW-MARK-1,
// JW-DUR-1, JW-RET-1, and JW-LIFE-1. Each test below is tagged at its
// boundary so persistence expectations remain traceable when semantics evolve.
#[test]
// JW-MARK-1.
fn clear_full_revalidation_marker_unlinks_then_treats_absence_as_success() -> TestResult {
    let dir = tempfile::tempdir()?;
    let journal_dir = dir.path().join(JOURNAL_DIR_NAME);
    let marker = journal_dir.join(FULL_REVALIDATION_MARKER);
    std::fs::create_dir_all(&journal_dir)?;
    std::fs::write(&marker, b"journal fork crossed below checkpoint base\n")?;

    clear_full_revalidation_marker_at(dir.path())?;
    assert!(!marker.exists());
    clear_full_revalidation_marker_at(dir.path())?;
    Ok(())
}

#[test]
fn marker_clear_retry_syncs_directory_after_prior_sync_failure() -> TestResult {
    let dir = tempfile::tempdir()?;
    let journal_path = dir.path().join(JOURNAL_DIR_NAME);
    std::fs::create_dir_all(&journal_path)?;
    std::fs::write(
        journal_path.join(FULL_REVALIDATION_MARKER),
        b"journal fork crossed below checkpoint base\n",
    )?;
    let journal_dir = cap_std::fs::Dir::open_ambient_dir(&journal_path, ambient_authority())?;

    let first = clear_full_revalidation_marker_with_sync(&journal_dir, |_| {
        Err(std::io::Error::other("injected directory sync failure"))
    });
    assert!(matches!(first, Err(JournalWriterError::Io(_))));

    let sync_calls = std::cell::Cell::new(0_u32);
    clear_full_revalidation_marker_with_sync(&journal_dir, |_| {
        sync_calls.set(sync_calls.get() + 1);
        Ok(())
    })?;
    assert_eq!(sync_calls.get(), 1, "retry must re-sync the directory");
    Ok(())
}

#[test]
// JW-DUR-1.
fn head_never_advances_without_counted_storage_flush() -> TestResult {
    let store = Arc::new(CountingStore::new());
    let mut writer = open_fresh("flush-order", Arc::clone(&store))?;
    let flushes_at_open = store.flush_count();

    // Fail the storage dependency: append still succeeds (buffered), but
    // the automatic boundary must not publish a head.
    store.set_fail_flush(true);
    writer.append(&sample_record(1))?;
    store.set_fail_flush(false);

    // Force the boundary now: flush counted, head publishable.
    writer.flush_to(1)?;
    assert_eq!(store.flush_count(), flushes_at_open + 1);
    assert_eq!(writer.head().height, 1);
    Ok(())
}

#[test]
// JW-DUR-1.
fn configured_lag_limits_retry_persistent_flush_failures() -> TestResult {
    let store = Arc::new(CountingStore::new());
    let mut writer = open_fresh("lag-backpressure", Arc::clone(&store))?;
    writer.configure(
        1,
        Duration::from_secs(10),
        1,
        10,
        1,
        Duration::from_secs(10),
    )?;
    store.set_fail_flush(true);
    assert!(matches!(
        writer.append(&sample_record(1)),
        Err(JournalWriterError::StorageFlush(_))
    ));
    assert!(matches!(
        writer.prepare_for_apply(),
        Err(JournalWriterError::StorageFlush(_))
    ));
    assert_eq!(writer.head().height, 0);

    store.set_fail_flush(false);
    writer.prepare_for_apply()?;
    assert_eq!(writer.head().height, 1);
    Ok(())
}

#[test]
fn configured_lag_time_forces_pre_apply_durability() -> TestResult {
    let store = Arc::new(CountingStore::new());
    let mut writer = open_fresh("lag-time", store)?;
    writer.configure(
        10,
        Duration::from_secs(10),
        1,
        10,
        10,
        Duration::from_secs(1),
    )?;
    writer.append(&sample_record(1))?;
    writer.last_boundary = Instant::now()
        .checked_sub(Duration::from_secs(2))
        .ok_or("test instant underflow")?;
    writer.prepare_for_apply()?;
    assert_eq!(writer.head().height, 1);
    Ok(())
}

#[test]
// JW-RET-1.
fn retention_limit_blocks_until_checkpoint_compaction() -> TestResult {
    let store = Arc::new(CountingStore::new());
    let mut writer = open_fresh("retention", store)?;
    writer.configure(
        10,
        Duration::from_secs(10),
        1,
        1,
        10,
        Duration::from_secs(10),
    )?;
    let name = segment_name(writer.segment_gen);
    let mut options = cap_std::fs::OpenOptions::new();
    options.write(true).create(true);
    writer.dir.open_with(name, &options)?.set_len(1024 * 1024)?;
    assert!(writer.requires_compaction()?);
    assert!(matches!(
        writer.prepare_for_apply(),
        Err(JournalWriterError::RetentionLimit { .. })
    ));

    writer.freeze()?;
    writer.compact_to_checkpoint(1, 0, [1; 32], [0; 32], 0)?;
    writer.resume()?;
    assert!(!writer.requires_compaction()?);
    writer.prepare_for_apply()?;
    Ok(())
}

#[test]
// JW-LIFE-1.
fn freeze_failures_restore_open_state_for_retry() -> TestResult {
    for boundary in [
        JournalWriterFailpoint::StorageFlush,
        JournalWriterFailpoint::SegmentSync,
        JournalWriterFailpoint::HeadTempWrite,
        JournalWriterFailpoint::HeadTempSync,
        JournalWriterFailpoint::HeadRename,
        JournalWriterFailpoint::HeadDirSync,
    ] {
        let store = Arc::new(CountingStore::new());
        let mut writer = open_fresh("freeze-retry", store)?;
        writer.append(&sample_record(1))?;
        writer.inject_failpoint(boundary);
        assert!(writer.freeze().is_err(), "{boundary:?} did not fail");
        assert_eq!(writer.state(), WriterState::Open);
        writer.failpoint = None;
        writer.append(&sample_record(2))?;
        writer.freeze()?;
        assert_eq!(writer.head().height, 2);
    }
    Ok(())
}

#[test]
fn resume_failure_does_not_strand_frozen_writer() -> TestResult {
    let store = Arc::new(CountingStore::new());
    let mut writer = open_fresh("resume-retry", store)?;
    writer.append(&sample_record(1))?;
    writer.freeze()?;
    writer.inject_failpoint(JournalWriterFailpoint::HeadTempWrite);
    assert!(writer.resume().is_err());
    assert_eq!(writer.state(), WriterState::Open);
    writer.failpoint = None;
    writer.append(&sample_record(2))?;
    writer.freeze()?;
    assert_eq!(writer.head().height, 2);
    Ok(())
}
