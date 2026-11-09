use super::*;
use bitcoin_rs_storage::committed_facts::TxFacts;
use bitcoin_rs_storage::{Bytes, RocksDbStore};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

struct RecordingBudget {
    cpu: Arc<CpuShares>,
    reserves: AtomicUsize,
}

impl BudgetCharge for RecordingBudget {
    fn reserve_bytes(&self, owner: BudgetOwner, _bytes: u64) -> Result<(), BudgetError> {
        assert_eq!(owner, BudgetOwner::IndexBuilder);
        assert_eq!(
            self.cpu.background_in_flight(),
            1,
            "build must hold the cpu permit inside reserve"
        );
        self.reserves.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn allocate_bytes(&self, _owner: BudgetOwner, _bytes: u64) -> Result<(), BudgetError> {
        Ok(())
    }

    fn release_bytes(&self, _owner: BudgetOwner, _bytes: u64) {}

    fn available_bytes(&self, _owner: BudgetOwner) -> u64 {
        u64::MAX
    }
}

/// A byte pool that refuses once drained and records the peak
/// outstanding charge so tests can assert the retained-memory bound.
struct PoolBudget {
    capacity: u64,
    remaining: AtomicU64,
    peak_outstanding: AtomicU64,
}

impl PoolBudget {
    fn new(capacity: u64) -> Self {
        Self {
            capacity,
            remaining: AtomicU64::new(capacity),
            peak_outstanding: AtomicU64::new(0),
        }
    }

    fn note(&self) {
        let outstanding = self
            .capacity
            .saturating_sub(self.remaining.load(Ordering::SeqCst));
        let mut peak = self.peak_outstanding.load(Ordering::SeqCst);
        while outstanding > peak {
            match self.peak_outstanding.compare_exchange(
                peak,
                outstanding,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(actual) => peak = actual,
            }
        }
    }
}

impl BudgetCharge for PoolBudget {
    fn reserve_bytes(&self, _owner: BudgetOwner, bytes: u64) -> Result<(), BudgetError> {
        let mut current = self.remaining.load(Ordering::SeqCst);
        loop {
            if current < bytes {
                return Err(BudgetError::BudgetExhausted);
            }
            match self.remaining.compare_exchange(
                current,
                current - bytes,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => {
                    self.note();
                    return Ok(());
                }
                Err(actual) => current = actual,
            }
        }
    }

    fn allocate_bytes(&self, owner: BudgetOwner, _bytes: u64) -> Result<(), BudgetError> {
        let _unused = owner;
        Ok(())
    }

    fn release_bytes(&self, _owner: BudgetOwner, bytes: u64) {
        self.remaining.fetch_add(bytes, Ordering::SeqCst);
        let _unused = self.remaining.load(Ordering::SeqCst);
    }

    fn available_bytes(&self, _owner: BudgetOwner) -> u64 {
        self.remaining.load(Ordering::SeqCst)
    }
}

fn synthetic_blocks(count: u32) -> Vec<CommittedBlock> {
    let mut blocks = Vec::new();
    for height in 1..=count {
        let mut hash = [0u8; 32];
        hash[..4].copy_from_slice(&height.to_be_bytes());
        let mut txs = Vec::new();
        for t in 0..3u32 {
            let mut txid = [0u8; 32];
            txid[..4].copy_from_slice(&height.to_be_bytes());
            txid[4..8].copy_from_slice(&t.to_be_bytes());
            let script = Bytes::copy_from_slice(b"\x51spill_test_script_padding_padding00");
            txs.push(TxFacts {
                txid,
                offset: t.saturating_mul(100),
                len: 90,
                inputs: Vec::new(),
                outputs: vec![CreatedOutput {
                    vout: 0,
                    value: 5_000,
                    script,
                }],
            });
        }
        blocks.push(CommittedBlock {
            height,
            hash,
            parent_hash: [0u8; 32],
            header: [0u8; 80],
            txs,
        });
    }
    blocks
}

#[test]
fn background_scoring_runs_under_a_cpu_permit() {
    let cpu = Arc::new(CpuShares::new(2, 1));
    let recording = Arc::new(RecordingBudget {
        cpu: Arc::clone(&cpu),
        reserves: AtomicUsize::new(0),
    });
    let budget = recording.clone();
    let scratch = tempfile::tempdir().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let store = RocksDbStore::open(dir.path()).unwrap();
    let builder =
        BulkSegmentBuilder::new(budget, Some(Arc::clone(&cpu)), scratch.path().to_path_buf());
    let mut stream = builder.stream(1);
    for block in &synthetic_blocks(4) {
        stream.push_block(block).unwrap();
    }
    stream.finish(&store).unwrap();
    assert!(recording.reserves.load(Ordering::SeqCst) > 0);
    drop(stream);
    assert_eq!(cpu.background_in_flight(), 0);
}

#[test]
fn single_worker_host_runs_background_scoring_without_a_permit() {
    let cpu = Arc::new(CpuShares::new(1, 1));
    assert!(cpu.try_acquire_background().is_none());
    let budget: Arc<dyn BudgetCharge> = Arc::new(UnboundedBudget);
    let scratch = tempfile::tempdir().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let store = RocksDbStore::open(dir.path()).unwrap();
    let builder =
        BulkSegmentBuilder::new(budget, Some(Arc::clone(&cpu)), scratch.path().to_path_buf());
    let mut stream = builder.stream(1);
    for block in &synthetic_blocks(2) {
        stream.push_block(block).unwrap();
    }
    stream.finish(&store).unwrap();
    assert_eq!(cpu.background_in_flight(), 0);
}

const POOL_BYTES: u64 = 16 * 1024;

#[test]
fn tiny_budget_spills_runs_and_matches_unbounded_bytes() {
    let blocks = synthetic_blocks(60);
    let bounded = run_build(PoolBudget::new(POOL_BYTES), &blocks);
    let unbounded = run_build(PoolBudget::new(u64::MAX), &blocks);
    assert!(bounded.spills > 0, "tiny budget must spill sorted runs");
    assert!(
        bounded.retained_max <= POOL_BYTES + 4096,
        "retained {} exceeded pool plus one row",
        bounded.retained_max
    );
    assert_eq!(bounded.digests, unbounded.digests);
    assert_eq!(
        bounded.leftover_files, 0,
        "runs must be cleaned after finish"
    );
}

#[test]
fn dropped_stream_cleans_spill_runs() {
    let scratch = tempfile::tempdir().unwrap();
    {
        let builder = BulkSegmentBuilder::new(
            Arc::new(PoolBudget::new(8 * 1024)),
            None,
            scratch.path().to_path_buf(),
        );
        let mut stream = builder.stream(1);
        for block in &synthetic_blocks(30) {
            stream.push_block(block).unwrap();
        }
        assert!(stream.total_runs_spilled() > 0);
    }
    let leftovers = std::fs::read_dir(scratch.path())
        .unwrap()
        .filter_map(|entry| entry.ok())
        .count();
    assert_eq!(leftovers, 0, "drop must remove spill runs");
}

struct BuildOutcome {
    digests: Vec<[u8; 32]>,
    spills: usize,
    leftover_files: usize,
    retained_max: u64,
}

fn run_build(budget: PoolBudget, blocks: &[CommittedBlock]) -> BuildOutcome {
    let pool = Arc::new(budget);
    let scratch = tempfile::tempdir().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let store = RocksDbStore::open(dir.path()).unwrap();
    let builder = BulkSegmentBuilder::new(pool.clone(), None, scratch.path().to_path_buf());
    let mut stream = builder.stream(1);
    for block in blocks {
        stream.push_block(block).unwrap();
    }
    stream.finish(&store).unwrap();
    let spills = stream.total_runs_spilled();
    let retained_max = pool.peak_outstanding.load(Ordering::SeqCst);
    let cfs = [
        ColumnFamily::TxDir,
        ColumnFamily::ScriptDict,
        ColumnFamily::ScriptPost,
        ColumnFamily::SpendDir,
        ColumnFamily::ScriptStats,
        ColumnFamily::Filters,
    ];
    let snapshot = store.snapshot().unwrap();
    let mut digests = Vec::new();
    for cf in cfs {
        let mut hasher = Sha256::new();
        let iter = snapshot.iter_prefix(cf, &[]).unwrap();
        for item in iter.flatten() {
            hasher.update(
                u32::try_from(item.0.len())
                    .unwrap_or(u32::MAX)
                    .to_le_bytes(),
            );
            hasher.update(&item.0);
            hasher.update(
                u32::try_from(item.1.len())
                    .unwrap_or(u32::MAX)
                    .to_le_bytes(),
            );
            hasher.update(&item.1);
        }
        digests.push(hasher.finalize().into());
    }
    let leftover_files = std::fs::read_dir(scratch.path())
        .unwrap()
        .filter_map(|entry| entry.ok())
        .count();
    BuildOutcome {
        digests,
        spills,
        leftover_files,
        retained_max,
    }
}

// PRJ-03
#[test]
fn disabled_filters_skip_bulk_filter_build() {
    let blocks = synthetic_blocks(3);
    BULK_FILTER_BUILDS.with(|builds| builds.set(0));
    let scratch = tempfile::tempdir().unwrap();
    let rows = BulkSegmentBuilder::new(
        Arc::new(UnboundedBudget),
        None,
        scratch.path().to_path_buf(),
    )
    .without_filter()
    .build_generation_rows(1, &blocks)
    .unwrap();
    assert_eq!(BULK_FILTER_BUILDS.with(std::cell::Cell::get), 0);
    assert_eq!(rows.filters.len(), 0);
    BULK_FILTER_BUILDS.with(|builds| builds.set(0));
    let scratch = tempfile::tempdir().unwrap();
    let rows = BulkSegmentBuilder::new(
        Arc::new(UnboundedBudget),
        None,
        scratch.path().to_path_buf(),
    )
    .build_generation_rows(1, &blocks)
    .unwrap();
    assert_eq!(BULK_FILTER_BUILDS.with(std::cell::Cell::get), blocks.len());
    for (_, value) in &rows.filters {
        let (_, _, _, filter) = crate::segment::format::decode_filter_value(value).unwrap();
        assert!(!filter.is_empty());
    }
}

#[derive(Debug, thiserror::Error)]
enum StreamError {
    #[error(transparent)]
    Build(#[from] BulkBuilderError),
    #[error(transparent)]
    Storage(#[from] bitcoin_rs_storage::StorageError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Int(#[from] std::num::TryFromIntError),
    #[error("test scratch has no multi-row spill run")]
    NoMultiRowRun,
}

fn spill_row_count(bytes: &[u8]) -> Option<usize> {
    let mut count = 0usize;
    let mut at = 0usize;
    while at < bytes.len() {
        let key_len =
            usize::try_from(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?)).ok()?;
        let value_len = usize::try_from(u32::from_le_bytes(
            bytes.get(at + 4..at + 8)?.try_into().ok()?,
        ))
        .ok()?;
        at = at
            .checked_add(8)?
            .checked_add(key_len)?
            .checked_add(value_len)?;
        if at > bytes.len() {
            return None;
        }
        count = count.saturating_add(1);
    }
    (at == bytes.len()).then_some(count)
}

// PRJ-09
#[test]
fn truncated_run_fails_finish_without_fake_key() -> Result<(), StreamError> {
    let pool = Arc::new(PoolBudget::new(POOL_BYTES));
    let scratch = tempfile::tempdir()?;
    let dir = tempfile::tempdir()?;
    let store = RocksDbStore::open(dir.path())?;
    let builder = BulkSegmentBuilder::new(pool.clone(), None, scratch.path().to_path_buf());
    let mut stream = builder.stream(1);
    for block in &synthetic_blocks(60) {
        stream.push_block(block)?;
    }
    let mut runs: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(scratch.path())? {
        runs.push(entry?.path());
    }
    runs.sort();
    let mut victim: Option<PathBuf> = None;
    for path in &runs {
        let bytes = std::fs::read(path)?;
        if spill_row_count(&bytes).is_some_and(|count| count > 1) {
            victim = Some(path.clone());
            break;
        }
    }
    let Some(victim) = victim else {
        return Err(StreamError::NoMultiRowRun);
    };
    let len = std::fs::metadata(&victim)?.len();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&victim)?
        .set_len(len - 1)?;
    match stream.finish(&store) {
        Ok(_) => panic!("finish must fail over a run file truncated mid-row"),
        Err(error) => assert!(
            matches!(error, BulkBuilderError::Io(_)),
            "truncation must surface as a typed io failure, got {error:?}"
        ),
    }
    let snapshot = store.snapshot()?;
    let families = [
        ColumnFamily::TxDir,
        ColumnFamily::ScriptDict,
        ColumnFamily::ScriptPost,
        ColumnFamily::SpendDir,
        ColumnFamily::ScriptStats,
        ColumnFamily::Filters,
    ];
    for cf in families {
        let rows = snapshot.iter_prefix(cf, &[])?;
        for row in rows.flatten() {
            assert_ne!(
                &row.0[..],
                &[0xFFu8; 8][..],
                "a truncated run must not ingest a fake key"
            );
        }
    }
    Ok(())
}

// PRJ-09
#[test]
fn second_builder_keeps_first_builder_runs() -> Result<(), StreamError> {
    let pool = Arc::new(PoolBudget::new(POOL_BYTES));
    let scratch = tempfile::tempdir()?;
    let builder = BulkSegmentBuilder::new(pool.clone(), None, scratch.path().to_path_buf());
    let mut first = builder.stream(1);
    for block in &synthetic_blocks(60) {
        first.push_block(block)?;
    }
    assert!(
        first.total_runs_spilled() > 0,
        "tiny budget must spill sorted runs"
    );
    let before: Vec<PathBuf> = std::fs::read_dir(scratch.path())?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .collect();
    assert!(!before.is_empty(), "spilled runs must exist on disk");
    let _second = builder.stream(2);
    for path in &before {
        assert!(
            path.exists(),
            "a live builder run must survive a second builder"
        );
    }
    Ok(())
}

// PRJ-09
#[test]
fn header_cut_run_fails_finish() -> Result<(), StreamError> {
    let pool = Arc::new(PoolBudget::new(POOL_BYTES));
    let scratch = tempfile::tempdir()?;
    let dir = tempfile::tempdir()?;
    let store = RocksDbStore::open(dir.path())?;
    let builder = BulkSegmentBuilder::new(pool.clone(), None, scratch.path().to_path_buf());
    let mut stream = builder.stream(1);
    for block in &synthetic_blocks(60) {
        stream.push_block(block)?;
    }
    let mut runs: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(scratch.path())? {
        runs.push(entry?.path());
    }
    runs.sort();
    let mut victim: Option<(PathBuf, u64)> = None;
    for path in &runs {
        let bytes = std::fs::read(path)?;
        if spill_row_count(&bytes).is_some_and(|count| count > 1) {
            let key_len = usize::try_from(u32::from_le_bytes(
                bytes
                    .get(..4)
                    .ok_or(StreamError::NoMultiRowRun)?
                    .try_into()
                    .map_err(|_| StreamError::NoMultiRowRun)?,
            ))?;
            let value_len = usize::try_from(u32::from_le_bytes(
                bytes
                    .get(4..8)
                    .ok_or(StreamError::NoMultiRowRun)?
                    .try_into()
                    .map_err(|_| StreamError::NoMultiRowRun)?,
            ))?;
            let cut = u64::try_from(8usize.saturating_add(key_len).saturating_add(value_len))?
                .saturating_add(2);
            victim = Some((path.clone(), cut));
            break;
        }
    }
    let Some((victim, cut)) = victim else {
        return Err(StreamError::NoMultiRowRun);
    };
    let len = std::fs::metadata(&victim)?.len();
    assert!(cut < len, "the header cut must stay inside the file");
    std::fs::OpenOptions::new()
        .write(true)
        .open(&victim)?
        .set_len(cut)?;
    match stream.finish(&store) {
        Ok(_) => panic!("finish must fail over a run file cut inside its header"),
        Err(error) => assert!(
            matches!(error, BulkBuilderError::Io(_)),
            "a header cut must surface as a typed io failure, got {error:?}"
        ),
    }
    Ok(())
}

// PRJ-09
#[test]
fn bounded_fan_in_matches_sorted_reference() -> Result<(), StreamError> {
    reset_cursor_peak();
    const ROWS: u64 = 24;
    let scratch = tempfile::tempdir()?;
    let mut sorter = SpillSorter::new(
        Arc::new(PoolBudget::new(0)),
        BudgetOwner::IndexBuilder,
        scratch.path().to_path_buf(),
        0xA022,
        "fanin",
    );
    let mut pushed: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for order in 0..ROWS {
        let key = ((order * 7) % ROWS).to_be_bytes().to_vec();
        let value = (((order * 7) % ROWS) ^ 0x9e37).to_be_bytes().to_vec();
        sorter.push_row(key.clone(), value.clone())?;
        pushed.push((key, value));
    }
    let merged = sorter.collect_rows()?;
    let mut expected = pushed;
    expected.sort();
    assert_eq!(merged, expected);
    assert!(
        cursor_peak() <= 16,
        "merge held more open runs than the fan-in bound"
    );
    Ok(())
}
