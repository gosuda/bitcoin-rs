//! Separate process required by the process-global System allocator and live-byte high-water mark.

use bitcoin_rs_index::segment::bulk_builder::{BulkBuilderError, BulkSegmentBuilder};
use bitcoin_rs_index::segment::format::*;
use bitcoin_rs_storage::budget::{BudgetCharge, BudgetError, BudgetOwner};
use bitcoin_rs_storage::committed_facts::{CommittedBlock, CreatedOutput, TxFacts};
use bitcoin_rs_storage::{
    BufferedWriteBatch, Bytes, ColumnFamily, FactsScript, KvIter, KvSnapshot, KvStore, PrefixScan,
    PrefixScanLimit, StorageError, WriteCondition,
};
use sha2::{Digest, Sha256};
use std::alloc::{GlobalAlloc, Layout, System};
use std::path::Path;
use std::sync::atomic::{AtomicIsize, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

struct LiveAllocator;
static LIVE: AtomicIsize = AtomicIsize::new(0);
static PEAK: AtomicIsize = AtomicIsize::new(0);

fn account(delta: isize) {
    let mut previous = LIVE.load(Ordering::SeqCst);
    let live = loop {
        let Some(next) = previous.checked_add(delta).filter(|next| *next >= 0) else {
            std::process::abort();
        };
        match LIVE.compare_exchange(previous, next, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => break next,
            Err(current) => previous = current,
        }
    };
    PEAK.fetch_max(live, Ordering::SeqCst);
}

fn allocation_bytes(bytes: usize) -> isize {
    let Ok(bytes) = isize::try_from(bytes) else {
        std::process::abort();
    };
    bytes
}

// SAFETY: all operations delegate to System with the caller's unchanged pointer and layout.
unsafe impl GlobalAlloc for LiveAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: GlobalAlloc's caller supplies a valid layout.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            account(allocation_bytes(layout.size()));
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: GlobalAlloc's caller supplies a valid layout.
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            account(allocation_bytes(layout.size()));
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: GlobalAlloc's caller supplies the live allocation's layout.
        unsafe { System.dealloc(ptr, layout) };
        account(-allocation_bytes(layout.size()));
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        // SAFETY: GlobalAlloc's caller supplies a live allocation and valid new size.
        let next = unsafe { System.realloc(ptr, layout, size) };
        if !next.is_null() {
            let Some(delta) = allocation_bytes(size).checked_sub(allocation_bytes(layout.size()))
            else {
                std::process::abort();
            };
            account(delta);
        }
        next
    }
}

#[global_allocator]
static ALLOCATOR: LiveAllocator = LiveAllocator;

fn begin_stage() -> isize {
    let baseline = LIVE.load(Ordering::SeqCst);
    PEAK.store(baseline, Ordering::SeqCst);
    baseline
}

fn end_stage(baseline: isize) -> Result<usize, ProofError> {
    let delta = PEAK
        .load(Ordering::SeqCst)
        .checked_sub(baseline)
        .ok_or(ProofError::ArithmeticOverflow("stage high-water delta"))?;
    Ok(usize::try_from(delta)?)
}

#[derive(Debug, thiserror::Error)]
enum ProofError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Builder(#[from] BulkBuilderError),
    #[error(transparent)]
    Integer(#[from] std::num::TryFromIntError),
    #[error(transparent)]
    Slice(#[from] std::array::TryFromSliceError),
    #[error("validation state lock poisoned")]
    Poisoned(#[source] std::sync::PoisonError<()>),
    #[error("malformed persisted row: {0}")]
    Malformed(&'static str),
    #[error("arithmetic overflow: {0}")]
    ArithmeticOverflow(&'static str),
}

impl From<ProofError> for StorageError {
    fn from(error: ProofError) -> Self {
        Self::Io(std::io::Error::other(error))
    }
}

const SORT_BYTES: u64 = 16 * 1024;
const SCRIPT: &[u8] = b"\x51single_script_allocation_proof";

struct Pool(AtomicU64);
impl BudgetCharge for Pool {
    fn reserve_bytes(&self, _: BudgetOwner, bytes: u64) -> Result<(), BudgetError> {
        self.0
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(bytes)
            })
            .map(|_| ())
            .map_err(|_| BudgetError::BudgetExhausted)
    }
    fn allocate_bytes(&self, _: BudgetOwner, _: u64) -> Result<(), BudgetError> {
        Ok(())
    }
    fn release_bytes(&self, _: BudgetOwner, bytes: u64) {
        self.0.fetch_add(bytes, Ordering::SeqCst);
    }
    fn available_bytes(&self, _: BudgetOwner) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

#[derive(Default)]
struct Observed {
    dicts: usize,
    stats: usize,
    upper: u32,
    chunks: usize,
    largest_chunk: usize,
    tx_rows: usize,
    posting_events: u32,
}

struct ValidatingSink {
    events: u32,
    ordinals: u32,
    observed: Mutex<Observed>,
}

fn unsupported<T>() -> Result<T, StorageError> {
    Err(StorageError::InvalidOperation(
        "allocation proof sink supports only sorted ingestion",
    ))
}

impl KvStore for ValidatingSink {
    fn get(&self, _: ColumnFamily, _: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        unsupported()
    }
    fn iter_prefix<'a>(&'a self, _: ColumnFamily, _: &[u8]) -> Result<KvIter<'a>, StorageError> {
        unsupported()
    }
    fn scan_prefix_from_bounded(
        &self,
        _: ColumnFamily,
        _: &[u8],
        _: &[u8],
        _: PrefixScanLimit,
    ) -> Result<PrefixScan, StorageError> {
        unsupported()
    }
    fn new_batch(&self) -> BufferedWriteBatch {
        panic!("unexpected batch write")
    }
    fn write(&self, _: BufferedWriteBatch) -> Result<(), StorageError> {
        unsupported()
    }
    fn write_durable_if(
        &self,
        _: &[WriteCondition<'_>],
        _: BufferedWriteBatch,
    ) -> Result<bool, StorageError> {
        unsupported()
    }
    fn flush(&self) -> Result<(), StorageError> {
        unsupported()
    }
    fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError> {
        unsupported()
    }
    fn multi_get(&self, _: ColumnFamily, _: &[&[u8]]) -> Result<Vec<Option<Bytes>>, StorageError> {
        unsupported()
    }
    fn delete_range(&self, _: ColumnFamily, _: &[u8], _: &[u8]) -> Result<(), StorageError> {
        unsupported()
    }
    fn checkpoint(&self, _: &Path) -> Result<(), StorageError> {
        unsupported()
    }
    fn engine_cache_bytes(&self) -> u64 {
        0
    }
    fn arm_persist_fault(&self, _: bitcoin_rs_storage::PersistFault) {
        panic!("unexpected persistence fault")
    }

    fn ingest_sorted(
        &self,
        cf: ColumnFamily,
        rows: &mut dyn Iterator<Item = (Vec<u8>, Vec<u8>)>,
        _: &Path,
    ) -> Result<u64, StorageError> {
        let mut state = self.observed.lock().map_err(|error| {
            drop(error.into_inner());
            ProofError::Poisoned(std::sync::PoisonError::new(()))
        })?;
        let mut count = 0;
        for (key, value) in rows {
            count += 1;
            match cf {
                ColumnFamily::ScriptDict => {
                    assert_eq!(
                        decode_script_dict_key(&key),
                        Some((1, Sha256::digest(SCRIPT).into()))
                    );
                    assert_eq!(decode_script_dict_value(&value), Some(0));
                    state.dicts += 1;
                }
                ColumnFamily::ScriptStats => {
                    assert_eq!(key, encode_script_stats_key(1, 0));
                    assert_eq!(value.len(), 32);
                    let word = |offset| -> Result<u64, ProofError> {
                        Ok(u64::from_le_bytes(value[offset..offset + 8].try_into()?))
                    };
                    assert_eq!(
                        (word(0)?, word(8)?, word(16)?, word(24)?),
                        (u64::from(self.events), 0, 7 * u64::from(self.events), 0)
                    );
                    state.stats += 1;
                }
                ColumnFamily::ScriptPost => {
                    state.observe_chunk(&key, &value, self.ordinals)?;
                }
                ColumnFamily::TxDir => {
                    if *key
                        .get(8)
                        .ok_or(ProofError::Malformed("transaction key kind"))?
                        == TX_KIND_ORDINAL
                    {
                        let ordinal = u32::from_be_bytes(
                            key.get(9..13)
                                .ok_or(ProofError::Malformed("transaction ordinal key"))?
                                .try_into()
                                .map_err(ProofError::from)?,
                        );
                        let (txid, height, _, _) = decode_tx_ordinal_value(&value)
                            .ok_or(ProofError::Malformed("transaction ordinal value"))?;
                        assert_eq!(
                            ordinal,
                            u32::try_from(state.tx_rows).map_err(ProofError::from)?
                        );
                        assert_eq!(height, 1);
                        assert_eq!(&txid[..4], &ordinal.to_be_bytes());
                        state.tx_rows += 1;
                    }
                }
                _ => panic!("unexpected nonempty family: {cf:?}"),
            }
        }
        Ok(count)
    }
}

impl Observed {
    fn observe_chunk(&mut self, key: &[u8], value: &[u8], ordinals: u32) -> Result<(), ProofError> {
        if ordinals > 1 {
            assert!(value.len() <= SCRIPT_POST_CHUNK_MAX_BYTES);
        }
        let (generation, script, base) =
            decode_script_post_chunk_key(key).ok_or(ProofError::Malformed("posting chunk key"))?;
        assert_eq!((generation, script), (1, 0));
        let mut bytes = value;
        let mut ordinal = base;
        let mut last: Option<u32> = None;
        while !bytes.is_empty() {
            let (delta, used) =
                decode_uvarint(bytes).ok_or(ProofError::Malformed("posting ordinal delta"))?;
            bytes = bytes
                .get(used..)
                .ok_or(ProofError::Malformed("posting ordinal delta length"))?;
            let (&flags, rest) = bytes
                .split_first()
                .ok_or(ProofError::Malformed("posting flags"))?;
            bytes = rest;
            assert_eq!(flags, POSTING_FLAG_FUNDING);
            if let Some(previous) = last {
                ordinal = ordinal
                    .checked_add(delta)
                    .ok_or(ProofError::ArithmeticOverflow("posting ordinal delta"))?;
                assert_eq!(
                    ordinal,
                    if ordinals == 1 {
                        previous
                    } else {
                        previous
                            .checked_add(1)
                            .ok_or(ProofError::ArithmeticOverflow("next posting ordinal"))?
                    },
                    "posting ordinal must match the fixture event order"
                );
            } else {
                assert_eq!(delta, 0);
            }
            self.posting_events += 1;
            last = Some(ordinal);
        }
        assert_eq!(
            last.ok_or(ProofError::Malformed("empty posting chunk"))?
                .checked_add(1)
                .ok_or(ProofError::ArithmeticOverflow("posting upper bound"))?,
            self.upper,
            "chunks must cover every ordinal exactly, newest first"
        );
        self.upper = base;
        self.chunks += 1;
        self.largest_chunk = self.largest_chunk.max(value.len());
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
enum EventShape {
    ManyOrdinals,
    SameOrdinal,
}

impl EventShape {
    fn ordinals(self, events: u32) -> u32 {
        match self {
            Self::ManyOrdinals => events,
            Self::SameOrdinal => 1,
        }
    }

    fn outputs(self, events: u32) -> u32 {
        match self {
            Self::ManyOrdinals => 1,
            Self::SameOrdinal => events,
        }
    }
}

fn fixture(events: u32, shape: EventShape) -> CommittedBlock {
    let ordinals = shape.ordinals(events);
    let txs = (0..ordinals)
        .map(|ordinal| {
            let mut txid = [0; 32];
            txid[..4].copy_from_slice(&ordinal.to_be_bytes());
            TxFacts {
                txid,
                offset: ordinal,
                len: 1,
                inputs: Vec::new(),
                outputs: (0..shape.outputs(events))
                    .map(|vout| CreatedOutput {
                        vout,
                        value: 7,
                        script: FactsScript::copy_from_slice(SCRIPT),
                    })
                    .collect(),
            }
        })
        .collect();
    CommittedBlock {
        height: 1,
        hash: [1; 32],
        parent_hash: [0; 32],
        header: [0; 80],
        txs,
    }
}

fn measure(events: u32, shape: EventShape) -> Result<usize, ProofError> {
    let block = fixture(events, shape);
    let scratch = tempfile::tempdir()?;
    let sink = ValidatingSink {
        events,
        ordinals: shape.ordinals(events),
        observed: Mutex::new(Observed {
            upper: shape.ordinals(events),
            ..Observed::default()
        }),
    };
    let builder = BulkSegmentBuilder::new(
        Arc::new(Pool(AtomicU64::new(SORT_BYTES))),
        None,
        scratch.path().to_path_buf(),
    )
    .without_filter();
    let mut stream = builder.stream(1);
    let input_baseline = begin_stage();
    stream.push_block(&block)?;
    let input_peak = end_stage(input_baseline)?;
    begin_stage();
    stream.finish(&sink)?;
    let finish_peak = end_stage(input_baseline)?;
    let state = sink.observed.lock().map_err(|error| {
        drop(error.into_inner());
        ProofError::Poisoned(std::sync::PoisonError::new(()))
    })?;
    assert_eq!(
        (state.dicts, state.stats, state.upper, state.tx_rows),
        (1, 1, 0, usize::try_from(sink.ordinals)?)
    );
    assert_eq!(state.posting_events, events);
    assert!(state.chunks > 0);
    eprintln!(
        "events={events} shape={shape:?} push_live_peak={input_peak} finish_live_peak={finish_peak} largest_chunk={}",
        state.largest_chunk
    );
    Ok(input_peak.max(finish_peak))
}

// PRJ-09
fn main() -> Result<(), ProofError> {
    let measurements = [EventShape::ManyOrdinals, EventShape::SameOrdinal]
        .map(|shape| Ok::<_, ProofError>((measure(1024, shape)?, measure(32768, shape)?)));
    let merge_cursor_bytes = 2 * 16 * (8192 + 1024);
    let sorter_and_chunk_bytes = 4 * usize::try_from(SORT_BYTES)? + 8 * SCRIPT_POST_CHUNK_MAX_BYTES;
    let growth_bound = merge_cursor_bytes + sorter_and_chunk_bytes;
    for measurement in measurements {
        let (small, large) = measurement?;
        assert!(
            large <= small + growth_bound,
            "bulk stages retained input-sized allocations: small={small}, large={large}, fixed merge/sorter/chunk allowance={growth_bound}"
        );
    }
    Ok(())
}
