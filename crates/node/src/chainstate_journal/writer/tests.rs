use std::error::Error;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bitcoin_rs_storage::{
    ColumnFamily, KvIter, KvSnapshot, KvStore, StorageError, WriteBatch, WriteCondition,
};
use cap_std::ambient_authority;
use parking_lot::Mutex;

use super::*;
use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut, Txid};

use crate::chainstate_journal::record::{Coin, Mutation};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[test]
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

/// Counts `flush()` calls and can fail them, proving the §2.3 order:
/// the head marker must never advance without a counted flush.
struct CountingStore {
    flushes: AtomicU64,
    fail_flush: Mutex<bool>,
}

impl CountingStore {
    fn new() -> Self {
        Self {
            flushes: AtomicU64::new(0),
            fail_flush: Mutex::new(false),
        }
    }

    fn flush_count(&self) -> u64 {
        self.flushes.load(Ordering::SeqCst)
    }

    fn set_fail_flush(&self, fail: bool) {
        *self.fail_flush.lock() = fail;
    }
}

impl KvStore for CountingStore {
    type WriteBatch = NoopBatch;

    fn get(&self, _cf: ColumnFamily, _key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(None)
    }

    fn iter_prefix<'a>(
        &'a self,
        _cf: ColumnFamily,
        _prefix: &[u8],
    ) -> Result<KvIter<'a>, StorageError> {
        Ok(Box::new(std::iter::empty()))
    }

    fn new_batch(&self) -> Self::WriteBatch {
        NoopBatch
    }

    fn write(&self, _batch: Self::WriteBatch) -> Result<(), StorageError> {
        Ok(())
    }

    fn write_durable_if(
        &self,
        _conditions: &[WriteCondition<'_>],
        _batch: Self::WriteBatch,
    ) -> Result<bool, StorageError> {
        Ok(true)
    }

    fn flush(&self) -> Result<(), StorageError> {
        self.flushes.fetch_add(1, Ordering::SeqCst);
        if *self.fail_flush.lock() {
            return Err(StorageError::InvalidOperation("injected flush failure"));
        }
        Ok(())
    }

    fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError> {
        unreachable!("unused in writer tests")
    }

    fn arm_persist_fault(&self, _fault: bitcoin_rs_storage::PersistFault) {
        unreachable!("unused in writer tests")
    }
}

struct NoopBatch;

impl WriteBatch for NoopBatch {
    fn put(&mut self, _cf: ColumnFamily, _key: &[u8], _value: &[u8]) {}
    fn delete(&mut self, _cf: ColumnFamily, _key: &[u8]) {}
    fn delete_range(&mut self, _cf: ColumnFamily, _start: &[u8], _end: &[u8]) {}
}

fn temp_dir(tag: &str) -> TestResult<cap_std::fs::Dir> {
    let path = std::env::temp_dir().join(format!("journal-writer-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path)?;
    Ok(cap_std::fs::Dir::open_ambient_dir(
        &path,
        ambient_authority(),
    )?)
}

fn sample_record(height: u32) -> JournalRecord {
    JournalRecord {
        height,
        block_hash: [u8::try_from(height).unwrap_or(9); 32],
        prev_hash: [u8::try_from(height.wrapping_sub(1)).unwrap_or(8); 32],
        block_tx_count: 3,
        coin_stats_height_delta: 1,
        raw_header: [0; 80],
        mutations: vec![
            Mutation::Create {
                coin: Coin {
                    outpoint: OutPoint::new(
                        Txid(Hash256::from_le_bytes(
                            &[u8::try_from(height).unwrap_or(9); 32],
                        )),
                        height,
                    ),
                    txout: TxOut {
                        value: u64::from(height),
                        script_pubkey: vec![0x51],
                    },
                    height,
                    coinbase: true,
                },
            },
            Mutation::Spend {
                coin: Coin {
                    outpoint: OutPoint::new(
                        Txid(Hash256::from_le_bytes(
                            &[u8::try_from(height.wrapping_sub(1)).unwrap_or(8); 32],
                        )),
                        height.wrapping_sub(1),
                    ),
                    txout: TxOut {
                        value: u64::from(height),
                        script_pubkey: vec![0x51],
                    },
                    height: height.wrapping_sub(1),
                    coinbase: false,
                },
            },
        ],
    }
}

fn open_fresh(tag: &str, store: Arc<CountingStore>) -> TestResult<JournalWriter<CountingStore>> {
    let dir = temp_dir(tag)?;
    Ok(JournalWriter::initialize(
        dir,
        store,
        0,
        (0, 0),
        0,
        [1; 32],
        [0; 32],
        0,
    )?)
}

#[test]
fn writer_bootstrap_uses_chainstate_journal_config_defaults() -> TestResult {
    let writer = open_fresh("config-defaults", Arc::new(CountingStore::new()))?;
    let defaults = crate::config::ChainstateJournalConfig::default();

    assert_eq!(writer.batch_blocks, defaults.blocks);
    assert_eq!(writer.batch_seconds, Duration::from_secs(defaults.seconds));
    assert_eq!(writer.rotate_bytes, defaults.rotate_mib * 1024 * 1024);
    assert_eq!(
        writer.max_journal_bytes,
        defaults.max_journal_mib * 1024 * 1024
    );
    assert_eq!(writer.max_lag_blocks, defaults.max_lag_blocks);
    assert_eq!(
        writer.max_lag_seconds,
        Duration::from_secs(defaults.max_lag_seconds)
    );
    Ok(())
}

#[test]
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
    writer.compact_to_checkpoint(1, 1, [1; 32], [0; 32], 3)?;
    writer.resume()?;
    assert_eq!(writer.state(), WriterState::Open);
    writer.append(&sample_record(2))?;
    Ok(())
}

#[test]
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
fn failed_boundary_retries_before_next_apply_below_lag_limit() -> TestResult {
    let store = Arc::new(CountingStore::new());
    let mut writer = open_fresh("boundary-retry", Arc::clone(&store))?;
    writer.configure(1, Duration::from_mins(1), 1, 10, 10, Duration::from_mins(1))?;
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
