use super::*;
use bitcoin_rs_storage::committed_facts::TxFacts;
use bitcoin_rs_storage::{Bytes, RocksDbStore};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, PartialEq, Eq)]
struct TxDirEntry {
    txid: [u8; 32],
    height: u32,
    block_hash: [u8; 32],
    ordinal: u32,
    offset: u32,
    len: u32,
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

const POOL_BYTES: u64 = 16 * 1024;
const POOL_SLACK_BYTES: u64 = 4096;

// PRJ-09
#[test]
fn tiny_budget_spills_runs_and_matches_unbounded_bytes() -> Result<(), StreamError> {
    let blocks = synthetic_blocks(60);
    let bounded = run_build(PoolBudget::new(POOL_BYTES), &blocks)?;
    let unbounded = run_build(PoolBudget::new(u64::MAX), &blocks)?;
    assert!(bounded.spills > 0, "tiny budget must spill sorted runs");
    assert!(
        unbounded.retained_max > POOL_BYTES + POOL_SLACK_BYTES,
        "fixture must exceed the pool or the bound proves nothing"
    );
    assert!(
        bounded.retained_max <= POOL_BYTES + POOL_SLACK_BYTES,
        "retained {} exceeded pool plus one row",
        bounded.retained_max
    );
    assert_eq!(bounded.digests, unbounded.digests);
    assert_eq!(
        bounded.leftover_files, 0,
        "runs must be cleaned after finish"
    );
    Ok(())
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

fn run_build(budget: PoolBudget, blocks: &[CommittedBlock]) -> Result<BuildOutcome, StreamError> {
    let pool = Arc::new(budget);
    let scratch = tempfile::tempdir().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let store = RocksDbStore::open(dir.path()).unwrap();
    let builder = BulkSegmentBuilder::new(pool.clone(), None, scratch.path().to_path_buf());
    let mut stream = builder.stream(1);
    for block in blocks {
        stream.push_block(block)?;
    }
    stream.finish(&store)?;
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
    let snapshot = store.snapshot()?;
    let mut digests = Vec::new();
    for cf in cfs {
        let mut hasher = Sha256::new();
        let iter = snapshot.iter_prefix(cf, &[])?;
        for item in iter {
            let (key, value) = item?;
            hasher.update(u32::try_from(key.len())?.to_le_bytes());
            hasher.update(&key);
            hasher.update(u32::try_from(value.len())?.to_le_bytes());
            hasher.update(&value);
        }
        digests.push(hasher.finalize().into());
    }
    let mut leftover_files = 0;
    for entry in std::fs::read_dir(scratch.path())? {
        entry?;
        leftover_files += 1;
    }
    Ok(BuildOutcome {
        digests,
        spills,
        leftover_files,
        retained_max,
    })
}

// PRJ-03
#[test]
fn disabled_filters_skip_bulk_filter_build() {
    let blocks = synthetic_blocks(3);
    let scratch = tempfile::tempdir().unwrap();
    let rows = BulkSegmentBuilder::new(
        Arc::new(UnboundedBudget),
        None,
        scratch.path().to_path_buf(),
    )
    .without_filter()
    .build_generation_rows(1, &blocks)
    .unwrap();
    assert_eq!(rows.filters.len(), 0);
    let scratch = tempfile::tempdir().unwrap();
    let rows = BulkSegmentBuilder::new(
        Arc::new(UnboundedBudget),
        None,
        scratch.path().to_path_buf(),
    )
    .build_generation_rows(1, &blocks)
    .unwrap();
    assert_eq!(rows.filters.len(), blocks.len());
    for (_, value) in &rows.filters {
        let (_, _, _, filter) = crate::segment::format::decode_filter_value(value).unwrap();
        assert!(!filter.is_empty());
    }
}
// PRJ-03
#[test]
fn tx_dir_gated_by_capabilities() -> Result<(), BulkBuilderError> {
    let blocks = synthetic_blocks(2);
    let scratch = tempfile::tempdir()?;
    let full = BulkSegmentBuilder::new(
        Arc::new(UnboundedBudget),
        None,
        scratch.path().to_path_buf(),
    )
    .build_generation_rows(1, &blocks)?;
    let mut found: Vec<TxDirEntry> = Vec::new();
    for (key, value) in &full.tx_dir {
        let Some((_, txid, height)) = crate::segment::format::decode_tx_dir_key(key) else {
            continue;
        };
        let Some((block_hash, ordinal, offset, len)) =
            crate::segment::format::decode_tx_dir_value(value)
        else {
            return Err(BulkBuilderError::InvalidBlockSequence);
        };
        found.push(TxDirEntry {
            txid,
            height,
            block_hash,
            ordinal,
            offset,
            len,
        });
    }
    let mut expected: Vec<TxDirEntry> = Vec::new();
    let mut ordinal = 0;
    for block in &blocks {
        for tx in &block.txs {
            expected.push(TxDirEntry {
                txid: tx.txid,
                height: block.height,
                block_hash: block.hash,
                ordinal,
                offset: tx.offset,
                len: tx.len,
            });
            ordinal += 1;
        }
    }
    assert_eq!(found, expected);
    let scratch = tempfile::tempdir()?;
    let gated = BulkSegmentBuilder::new(
        Arc::new(UnboundedBudget),
        None,
        scratch.path().to_path_buf(),
    )
    .without_tx_dir()
    .build_generation_rows(1, &blocks)?;
    assert!(gated.tx_dir.is_empty());
    assert_eq!(gated.filters.len(), blocks.len());
    Ok(())
}

// PRJ-07
#[test]
fn duplicate_txid_spends_resolve_to_the_creation_before_each_spend() -> Result<(), BulkBuilderError>
{
    let dup = [0xaa; 32];
    let script = |byte: u8| Bytes::copy_from_slice(&[byte]);
    let output = |byte: u8| CreatedOutput {
        vout: 0,
        value: 5_000,
        script: script(byte),
    };
    let spend = |height: u32| SpentPrevout {
        txid: dup,
        vout: 0,
        value: 5_000,
        script: script(0x51),
        height,
        coinbase: false,
    };
    let block = |height: u32, txs: Vec<TxFacts>| CommittedBlock {
        height,
        hash: {
            let mut hash = [0u8; 32];
            hash[..4].copy_from_slice(&height.to_be_bytes());
            hash
        },
        parent_hash: [0u8; 32],
        header: [0u8; 80],
        txs,
    };
    let tx = |txid: [u8; 32], inputs: Vec<SpentPrevout>| TxFacts {
        txid,
        offset: 0,
        len: 100,
        inputs,
        outputs: vec![output(0x52)],
    };
    let blocks = vec![
        block(1, vec![tx(dup, Vec::new())]),
        block(2, vec![tx([0xbb; 32], vec![spend(1)])]),
        block(3, vec![tx(dup, Vec::new())]),
        block(4, vec![tx([0xcc; 32], vec![spend(3)])]),
    ];

    let scratch = tempfile::tempdir()?;
    let generation = BulkSegmentBuilder::new(
        Arc::new(UnboundedBudget),
        None,
        scratch.path().to_path_buf(),
    )
    .build_generation_rows(1, &blocks)?;

    let creations: Vec<u32> = generation
        .tx_dir
        .iter()
        .filter_map(|(key, value)| {
            let (_, txid, _height) = crate::segment::format::decode_tx_dir_key(key)?;
            if txid != dup {
                return None;
            }
            let (_hash, ordinal, _offset, _len) =
                crate::segment::format::decode_tx_dir_value(value)?;
            Some(ordinal)
        })
        .collect();
    assert_eq!(
        creations,
        vec![0, 2],
        "the range recreates the txid at ordinals 0 and 2"
    );

    let rows = &generation.spend_dir;
    assert_eq!(rows.len(), 2, "each spend names its own preceding creation");
    assert_eq!(
        crate::segment::format::decode_spend_dir_key(&rows[0].0),
        Some((1, 0, 0)),
        "the spend at ordinal 1 resolves to the first creation"
    );
    assert_eq!(
        crate::segment::format::decode_spend_dir_value(&rows[0].1),
        Some(1)
    );
    assert_eq!(
        crate::segment::format::decode_spend_dir_key(&rows[1].0),
        Some((1, 2, 0)),
        "the spend at ordinal 3 resolves to the recreation, not the first creation"
    );
    assert_eq!(
        crate::segment::format::decode_spend_dir_value(&rows[1].1),
        Some(3)
    );
    Ok(())
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
        for row in rows {
            let (_key, value) = row?;
            assert!(
                !value.is_empty(),
                "a truncated run must not commit the poison row"
            );
        }
    }
    Ok(())
}

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
    const ROW_BYTES: u64 = 8 + 8 + 64;
    let scratch = tempfile::tempdir()?;
    let mut sorter = SpillSorter::new(
        Arc::new(PoolBudget::new(ROW_BYTES)),
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
        sorter.spilled > MAX_MERGE_FAN_IN,
        "fixture must force a consolidation pass"
    );
    assert!(
        cursor_peak() <= MAX_MERGE_FAN_IN,
        "merge held more open runs than the fan-in bound"
    );
    Ok(())
}
