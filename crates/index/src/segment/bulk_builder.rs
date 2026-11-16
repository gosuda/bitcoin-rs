//! Bounded external sort for bulk index generation (`PRJ-09`).
//!
//! Rows stream through per-family spill sorters charged to
//! `BudgetOwner::IndexBuilder`. When the shared budget pool refuses the next
//! row, the sorted in-memory buffer spills to one run file in the scratch
//! directory and its bytes are released; output is a partitioned k-way merge
//! over the runs plus the sorted remainder, streamed into `ingest_sorted`.
//! Rows are unique per family, so run order is total. Scratch runs carry no
//! durability: a crash invalidates the whole build, and a fresh builder
//! sweeps stale run files before its first spill.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashSet};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};

#[cfg(test)]
use bitcoin_rs_storage::budget::UnboundedBudget;
use bitcoin_rs_storage::budget::{
    BackgroundCpuPermit, BudgetCharge, BudgetError, BudgetOwner, CpuShares,
};
use bitcoin_rs_storage::committed_facts::{CommittedBlock, CreatedOutput, SpentPrevout};
use bitcoin_rs_storage::{ColumnFamily, KvStore};
use hashbrown::HashMap;
use sha2::{Digest, Sha256};

use super::Coverage;
use super::format::*;
use crate::{IndexCapabilities, IndexCapability};
#[cfg(test)]
thread_local! {
    pub(crate) static BULK_FILTER_BUILDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[derive(Debug, thiserror::Error)]
pub enum BulkBuilderError {
    #[error("storage error: {0}")]
    Storage(#[from] bitcoin_rs_storage::StorageError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("index builder budget refused the retained window: {0}")]
    Budget(BudgetError),
    #[error("empty block range")]
    EmptyRange,
    #[error("invalid block sequence")]
    InvalidBlockSequence,
    #[error("segment row exceeds the spill run length prefix")]
    RowTooLarge,
}

pub struct GenerationRows {
    pub coverage: Coverage,
    pub tx_dir: SegmentRows,
    pub script_dict: SegmentRows,
    pub script_post: SegmentRows,
    pub spend_dir: SegmentRows,
    pub script_stats: SegmentRows,
    pub filters: SegmentRows,
}

pub(super) type SegmentRows = Vec<(Vec<u8>, Vec<u8>)>;
type MergeHeapEntry = (Vec<u8>, Vec<u8>, usize);
type MergedRow = (Vec<u8>, Vec<u8>);

pub struct BulkSegmentBuilder {
    budget: Arc<dyn BudgetCharge>,
    cpu: Option<Arc<CpuShares>>,
    scratch_dir: PathBuf,
    build_filter: bool,
    capabilities: IndexCapabilities,
}

impl BulkSegmentBuilder {
    #[must_use]
    pub fn new(
        budget: Arc<dyn BudgetCharge>,
        cpu: Option<Arc<CpuShares>>,
        scratch_dir: PathBuf,
    ) -> Self {
        Self {
            budget,
            cpu,
            scratch_dir,
            build_filter: true,
            capabilities: IndexCapabilities::ALL,
        }
    }

    #[must_use]
    pub fn with_tx_dir(mut self) -> Self {
        self.capabilities = self.capabilities.insert(IndexCapability::TxLookup);
        self.capabilities = self.capabilities.insert(IndexCapability::ScriptHistory);
        self
    }

    #[must_use]
    pub fn without_tx_dir(mut self) -> Self {
        self.capabilities = self.capabilities.without(IndexCapability::TxLookup);
        self.capabilities = self.capabilities.without(IndexCapability::ScriptHistory);
        self
    }
    #[must_use]
    pub fn with_filter(self) -> Self {
        self.set_build_filter(true)
    }

    #[must_use]
    pub fn without_filter(self) -> Self {
        self.set_build_filter(false)
    }

    fn set_build_filter(mut self, build: bool) -> Self {
        self.build_filter = build;
        self
    }

    /// In-memory reference build: materializes every row and is meant for
    /// proofs and small corpora. The bounded path is [`Self::stream`] into
    /// [`StreamingSegmentBuilder::finish`].
    // PRJ-09
    pub fn build_generation_rows(
        &self,
        gen_id: u64,
        blocks: &[CommittedBlock],
    ) -> Result<GenerationRows, BulkBuilderError> {
        let mut stream = self.stream(gen_id);
        for block in blocks {
            stream.push_block(block)?;
        }
        stream.finish_rows()
    }

    // PRJ-09
    pub fn build_and_ingest<S: KvStore + ?Sized>(
        &self,
        store: &S,
        gen_id: u64,
        blocks: &[CommittedBlock],
    ) -> Result<Coverage, BulkBuilderError> {
        let mut stream = self.stream(gen_id);
        for block in blocks {
            stream.push_block(block)?;
        }
        stream.finish(store)
    }

    #[must_use]
    pub fn stream(&self, gen_id: u64) -> StreamingSegmentBuilder {
        let permit = self
            .cpu
            .as_ref()
            .and_then(|cpu| cpu.try_acquire_background());
        let mut stream = StreamingSegmentBuilder::new(
            gen_id,
            Arc::clone(&self.budget),
            permit,
            self.scratch_dir.clone(),
            self.build_filter,
        );
        stream.capabilities = self.capabilities;
        stream
    }
}

/// Push/finish builder over the bounded external sort. `finish` ingests
/// straight from the merged runs; `finish_rows` materializes the whole
/// generation for in-memory consumers.
pub struct StreamingSegmentBuilder {
    gen_id: u64,
    _permit: Option<BackgroundCpuPermit>,
    tx_dir: SpillSorter,
    spend_candidates: SpillSorter,
    occurrences: SpillSorter,
    spend_dir: SpillSorter,
    script_dict: SpillSorter,
    script_post: SpillSorter,
    script_stats: SpillSorter,
    filters: SpillSorter,
    first_height: Option<u32>,
    last_height: u32,
    last_hash: [u8; 32],
    ordinal: u32,
    occurrence_seq: u32,
    prev_filter_header: [u8; 32],
    build_filter: bool,
    capabilities: IndexCapabilities,
    scratch_dir: PathBuf,
    builder_serial: u64,
}

fn next_builder_serial() -> u64 {
    static SERIAL: AtomicU64 = AtomicU64::new(0);
    let serial = SERIAL.fetch_add(1, Ordering::Relaxed);
    if let Ok(mut live) = LIVE_BUILDER_SERIALS.lock() {
        live.insert(serial);
    }
    serial
}

static LIVE_BUILDER_SERIALS: LazyLock<Mutex<HashSet<u64>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

const RUN_FILE_PREFIX: &str = "segbuild-";
const ROW_CHARGE_OVERHEAD: u64 = 64;
const MAX_MERGE_FAN_IN: usize = 16;

fn serial_of_run_file(name: &str) -> Option<u64> {
    let rest = name.strip_prefix(RUN_FILE_PREFIX)?;
    let (serial, _) = rest.split_at_checked(16)?;
    u64::from_str_radix(serial, 16).ok()
}

fn sweep_stale_runs(scratch_dir: &Path) {
    let live = LIVE_BUILDER_SERIALS
        .lock()
        .map(|guard| guard.clone())
        .unwrap_or_default();
    let Ok(entries) = std::fs::read_dir(scratch_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with(RUN_FILE_PREFIX) {
            continue;
        }
        if let Some(serial) = serial_of_run_file(&name) {
            if live.contains(&serial) {
                continue;
            }
        }
        let _unused = std::fs::remove_file(entry.path());
    }
}

impl StreamingSegmentBuilder {
    fn new(
        gen_id: u64,
        budget: Arc<dyn BudgetCharge>,
        permit: Option<BackgroundCpuPermit>,
        scratch_dir: PathBuf,
        build_filter: bool,
    ) -> Self {
        let builder_serial = next_builder_serial();
        sweep_stale_runs(&scratch_dir);
        let owner = BudgetOwner::IndexBuilder;
        let sorter_ids = [
            "txdir", "cands", "occur", "spend", "dict", "post", "stats", "filtr",
        ];
        let mut next_sorter = 0usize;
        let mut maker = || {
            let sorter_id = sorter_ids[next_sorter];
            next_sorter += 1;
            SpillSorter::new(
                Arc::clone(&budget),
                owner,
                scratch_dir.clone(),
                builder_serial,
                sorter_id,
            )
        };
        Self {
            gen_id,
            _permit: permit,
            tx_dir: maker(),
            spend_candidates: maker(),
            occurrences: maker(),
            spend_dir: maker(),
            script_dict: maker(),
            script_post: maker(),
            script_stats: maker(),
            filters: maker(),
            first_height: None,
            last_height: 0,
            last_hash: [0; 32],
            ordinal: 0,
            occurrence_seq: 0,
            prev_filter_header: [0; 32],
            build_filter,
            capabilities: IndexCapabilities::ALL,
            scratch_dir,
            builder_serial,
        }
    }

    #[must_use]
    pub fn total_runs_spilled(&self) -> usize {
        self.tx_dir.spilled
            + self.spend_candidates.spilled
            + self.occurrences.spilled
            + self.spend_dir.spilled
            + self.script_dict.spilled
            + self.script_post.spilled
            + self.script_stats.spilled
            + self.filters.spilled
    }

    pub fn push_block(&mut self, block: &CommittedBlock) -> Result<(), BulkBuilderError> {
        if self.first_height.is_some() && block.height != self.last_height.saturating_add(1) {
            return Err(BulkBuilderError::InvalidBlockSequence);
        }
        self.first_height.get_or_insert(block.height);

        for tx in &block.txs {
            let ordinal = self.ordinal;
            self.ordinal = self.ordinal.saturating_add(1);
            let needs_tx_dir = self.capabilities.contains(IndexCapability::TxLookup)
                || self.capabilities.contains(IndexCapability::ScriptHistory);
            if needs_tx_dir {
                let tx_key = encode_tx_dir_key(self.gen_id, &tx.txid, block.height);
                let tx_val = encode_tx_dir_value(&block.hash, ordinal, tx.offset, tx.len);
                self.tx_dir.push_row(tx_key.to_vec(), tx_val.to_vec())?;
                let rev_key = encode_tx_ordinal_key(self.gen_id, ordinal);
                let rev_val = encode_tx_ordinal_value(&tx.txid, block.height, tx.offset, tx.len);
                self.tx_dir.push_row(rev_key.to_vec(), rev_val.to_vec())?;
            }
            if self.capabilities.contains(IndexCapability::ScriptHistory) {
                self.push_inputs(ordinal, &tx.inputs)?;
                self.push_outputs(ordinal, &tx.outputs)?;
            }
        }

        if self.build_filter {
            let (filter, filter_hash, header) = self.build_block_filter(block);
            self.prev_filter_header = header;
            let filter_key = encode_filter_key(self.gen_id, block.height);
            let filter_val = encode_filter_value(&block.hash, &filter_hash, &header, &filter);
            self.filters.push_row(filter_key.to_vec(), filter_val)?;
        }

        self.last_height = block.height;
        self.last_hash = block.hash;
        Ok(())
    }

    fn push_inputs(
        &mut self,
        ordinal: u32,
        inputs: &[SpentPrevout],
    ) -> Result<(), BulkBuilderError> {
        for input in inputs {
            if input.txid == [0u8; 32] && input.vout == u32::MAX {
                continue;
            }
            let mut candidate_key = Vec::with_capacity(40);
            candidate_key.extend_from_slice(&input.txid);
            candidate_key.extend_from_slice(&ordinal.to_be_bytes());
            candidate_key.extend_from_slice(&input.vout.to_be_bytes());
            self.spend_candidates.push_row(candidate_key, Vec::new())?;
            self.push_occurrence(&input.script, ordinal, POSTING_FLAG_SPENDING, input.value)?;
        }
        Ok(())
    }

    fn push_outputs(
        &mut self,
        ordinal: u32,
        outputs: &[CreatedOutput],
    ) -> Result<(), BulkBuilderError> {
        for output in outputs {
            self.push_occurrence(&output.script, ordinal, POSTING_FLAG_FUNDING, output.value)?;
        }
        Ok(())
    }

    fn push_occurrence(
        &mut self,
        script: &[u8],
        ordinal: u32,
        flags: u8,
        sats: u64,
    ) -> Result<(), BulkBuilderError> {
        if flags == POSTING_FLAG_FUNDING && script.first() == Some(&0x6a) {
            return Ok(());
        }
        let hash: [u8; 32] = Sha256::digest(script).into();
        let seq = self.occurrence_seq;
        self.occurrence_seq = self.occurrence_seq.saturating_add(1);
        let mut key = Vec::with_capacity(41);
        key.extend_from_slice(&hash);
        key.extend_from_slice(&ordinal.to_be_bytes());
        key.extend_from_slice(&seq.to_be_bytes());
        key.push(flags);
        self.occurrences.push_row(key, sats.to_le_bytes().to_vec())
    }

    fn build_block_filter(&self, block: &CommittedBlock) -> (Vec<u8>, [u8; 32], [u8; 32]) {
        #[cfg(test)]
        BULK_FILTER_BUILDS.with(|builds| builds.set(builds.get() + 1));

        use bitcoin_rs_consensus::primitives::encode;

        let mut k0_bytes = [0u8; 8];
        k0_bytes.copy_from_slice(&block.hash[..8]);
        let k0 = u64::from_le_bytes(k0_bytes);

        let mut k1_bytes = [0u8; 8];
        k1_bytes.copy_from_slice(&block.hash[8..16]);
        let k1 = u64::from_le_bytes(k1_bytes);

        let mut filter = Vec::new();
        let mut writer = bitcoin::bip158::GcsFilterWriter::new(&mut filter, k0, k1, 784_931, 19);
        let mut created: HashMap<([u8; 32], u32), &[u8]> = HashMap::new();

        for tx in &block.txs {
            for input in &tx.inputs {
                if input.txid == [0u8; 32] && input.vout == u32::MAX {
                    continue;
                }
                if let Some(&script) = created.get(&(input.txid, input.vout)) {
                    writer.add_element(script);
                } else if !input.script.is_empty() {
                    writer.add_element(&input.script);
                }
            }

            for output in &tx.outputs {
                created.insert((tx.txid, output.vout), &output.script);
                if !output.script.is_empty() && output.script[0] != 0x6a {
                    writer.add_element(&output.script);
                }
            }
        }
        let _ = writer.finish();
        let filter_hash = encode::double_sha256(&filter).to_le_bytes();
        let header = self.filter_header(&filter_hash);
        (filter, filter_hash, header)
    }

    fn filter_header(&self, filter_hash: &[u8; 32]) -> [u8; 32] {
        use bitcoin_rs_consensus::primitives::encode;
        let mut header_input = [0u8; 64];
        header_input[..32].copy_from_slice(filter_hash);
        header_input[32..].copy_from_slice(&self.prev_filter_header);
        encode::double_sha256(&header_input).to_le_bytes()
    }

    // PRJ-09
    pub fn finish<S: KvStore + ?Sized>(&mut self, store: &S) -> Result<Coverage, BulkBuilderError> {
        let coverage = self.coverage()?;
        self.resolve_spends()?;
        self.emit_script_rows()?;

        let families = [
            (&mut self.tx_dir, ColumnFamily::TxDir),
            (&mut self.script_dict, ColumnFamily::ScriptDict),
            (&mut self.script_post, ColumnFamily::ScriptPost),
            (&mut self.spend_dir, ColumnFamily::SpendDir),
            (&mut self.script_stats, ColumnFamily::ScriptStats),
            (&mut self.filters, ColumnFamily::Filters),
        ];
        for (sorter, cf) in families {
            let mut rows = sorter.sorted_into_rows()?;
            let ingested = store.ingest_sorted(cf, &mut rows, &self.scratch_dir);
            if let Some(error) = rows.take_error() {
                return Err(error);
            }
            ingested?;
            sorter.release();
        }
        self.release_all();
        Ok(coverage)
    }

    // PRJ-09
    pub fn finish_rows(&mut self) -> Result<GenerationRows, BulkBuilderError> {
        let coverage = self.coverage()?;
        self.resolve_spends()?;
        self.emit_script_rows()?;

        let tx_dir = self.tx_dir.collect_rows()?;
        let script_dict = self.script_dict.collect_rows()?;
        let script_post = self.script_post.collect_rows()?;
        let spend_dir = self.spend_dir.collect_rows()?;
        let script_stats = self.script_stats.collect_rows()?;
        let filters = self.filters.collect_rows()?;
        self.release_all();
        Ok(GenerationRows {
            coverage,
            tx_dir,
            script_dict,
            script_post,
            spend_dir,
            script_stats,
            filters,
        })
    }

    fn coverage(&self) -> Result<Coverage, BulkBuilderError> {
        let Some(first_height) = self.first_height else {
            return Err(BulkBuilderError::EmptyRange);
        };
        Ok(Coverage::new(
            first_height,
            self.last_height,
            self.last_hash,
        ))
    }

    /// Merge-joins spend candidates against the sorted transaction
    /// directory: in-generation creations resolve to the newest creation
    /// ordinal strictly before the spending transaction (BIP30 duplicates
    /// included), older coins leave no spender row, and spends ordered by
    /// ordinal share one forward directory cursor.
    fn resolve_spends(&mut self) -> Result<(), BulkBuilderError> {
        self.tx_dir.finalize()?;
        self.spend_candidates.finalize()?;
        let mut directory = DirectoryScan {
            rows: self.tx_dir.sorted_rows()?,
            front: None,
        };
        directory.front = next_directory_row(&mut directory.rows)?;
        let mut candidates = self.spend_candidates.sorted_rows()?;
        let mut group_txid: Option<[u8; 32]> = None;
        let mut creation: Option<u32> = None;
        while let Some(candidate) = candidates.try_next()? {
            let (spent_txid, spending_ordinal, vout) = decode_candidate(&candidate)?;
            if group_txid != Some(spent_txid) {
                group_txid = Some(spent_txid);
                creation = None;
                advance_directory_to(&mut directory, spent_txid)?;
            }
            while let Some((txid, ordinal)) = directory.front {
                if txid != spent_txid || ordinal >= spending_ordinal {
                    break;
                }
                creation = Some(ordinal);
                directory.front = next_directory_row(&mut directory.rows)?;
            }
            let Some(creation_ordinal) = creation else {
                continue;
            };
            let spend_key = encode_spend_dir_key(self.gen_id, creation_ordinal, vout);
            let spend_val = encode_spend_dir_value(spending_ordinal);
            self.spend_dir
                .push_row(spend_key.to_vec(), spend_val.to_vec())?;
        }
        Ok(())
    }

    /// Drains script occurrences in hash order, assigns dense dictionary
    /// ids, and emits stats and size-chunked postings per script.
    fn emit_script_rows(&mut self) -> Result<(), BulkBuilderError> {
        self.occurrences.finalize()?;
        let mut merged = self.occurrences.sorted_rows()?;
        let mut script_id: u32 = 0;
        let mut group: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        let mut group_hash: Option<[u8; 32]> = None;
        while let Some(row) = merged.try_next()? {
            let hash: [u8; 32] = row.0[..32]
                .try_into()
                .map_err(|_| BulkBuilderError::InvalidBlockSequence)?;
            match group_hash {
                Some(existing) if existing == hash => {}
                Some(_) => {
                    self.flush_script_group(&group, script_id)?;
                    script_id = script_id.saturating_add(1);
                    group.clear();
                    group_hash = Some(hash);
                }
                None => group_hash = Some(hash),
            }
            group.push(row);
        }
        if group_hash.is_some() {
            self.flush_script_group(&group, script_id)?;
        }
        Ok(())
    }

    fn flush_script_group(
        &mut self,
        group: &[(Vec<u8>, Vec<u8>)],
        script_id: u32,
    ) -> Result<(), BulkBuilderError> {
        let Some(hash) = group.first().map(|row| decode_script_hash(&row.0)) else {
            return Ok(());
        };
        let hash = hash?;
        let dict_key = encode_script_dict_key(self.gen_id, &hash);
        self.script_dict.push_row(
            dict_key.to_vec(),
            encode_script_dict_value(script_id).to_vec(),
        )?;

        let mut stats = ScriptStats::default();
        let mut items = Vec::with_capacity(group.len());
        let mut last_ordinal = 0u32;
        for (key, value) in group {
            let ordinal = decode_be_u32(&key[32..36])?;
            let flags = decode_flags(key)?;
            let sats = u64::from_le_bytes(decode_array8(value)?);
            if flags == POSTING_FLAG_FUNDING {
                stats.funded_count = stats.funded_count.saturating_add(1);
                stats.funded_sats = stats.funded_sats.saturating_add(sats);
            } else if flags == POSTING_FLAG_SPENDING {
                stats.spent_count = stats.spent_count.saturating_add(1);
                stats.spent_sats = stats.spent_sats.saturating_add(sats);
            }
            let delta = ordinal.saturating_sub(last_ordinal);
            last_ordinal = ordinal;
            items.push(PostingItem {
                delta_ordinal: delta,
                flags,
            });
        }
        let stats_key = encode_script_stats_key(self.gen_id, script_id);
        self.script_stats.push_row(
            stats_key.to_vec(),
            encode_script_stats_value(&stats).to_vec(),
        )?;
        for (key, value) in chunk_postings(self.gen_id, script_id, items) {
            self.script_post.push_row(key, value)?;
        }
        Ok(())
    }

    fn release_all(&mut self) {
        self.spend_candidates.release();
        self.occurrences.release();
    }
}

impl Drop for StreamingSegmentBuilder {
    fn drop(&mut self) {
        self.release_all();
        if let Ok(mut live) = LIVE_BUILDER_SERIALS.lock() {
            live.remove(&self.builder_serial);
        }
    }
}

fn decode_script_hash(key: &[u8]) -> Result<[u8; 32], BulkBuilderError> {
    key[..32]
        .try_into()
        .map_err(|_| BulkBuilderError::InvalidBlockSequence)
}

fn decode_candidate(
    candidate: &(Vec<u8>, Vec<u8>),
) -> Result<([u8; 32], u32, u32), BulkBuilderError> {
    let key = &candidate.0;
    if key.len() != 40 {
        return Err(BulkBuilderError::InvalidBlockSequence);
    }
    let txid: [u8; 32] = key[..32]
        .try_into()
        .map_err(|_| BulkBuilderError::InvalidBlockSequence)?;
    let spending_ordinal = u32::from_be_bytes(decode_array4(&key[32..36])?);
    let vout = u32::from_be_bytes(decode_array4(&key[36..40])?);
    Ok((txid, spending_ordinal, vout))
}

struct DirectoryScan {
    rows: SortedRows,
    front: Option<([u8; 32], u32)>,
}

fn advance_directory_to(
    directory: &mut DirectoryScan,
    spent_txid: [u8; 32],
) -> Result<Option<([u8; 32], u32)>, BulkBuilderError> {
    while let Some((txid, ordinal)) = directory.front {
        if txid >= spent_txid {
            return Ok(Some((txid, ordinal)));
        }
        directory.front = next_directory_row(&mut directory.rows)?;
    }
    Ok(None)
}

fn next_directory_row(rows: &mut SortedRows) -> Result<Option<([u8; 32], u32)>, BulkBuilderError> {
    while let Some(row) = rows.try_next()? {
        let Some((_, txid, _)) = decode_tx_dir_key(&row.0) else {
            continue;
        };
        if row.1.len() >= 36 {
            let ordinal = u32::from_be_bytes(decode_array4(&row.1[32..36])?);
            return Ok(Some((txid, ordinal)));
        }
    }
    Ok(None)
}

fn decode_array4(bytes: &[u8]) -> Result<[u8; 4], BulkBuilderError> {
    bytes
        .try_into()
        .map_err(|_| BulkBuilderError::InvalidBlockSequence)
}

fn decode_array8(bytes: &[u8]) -> Result<[u8; 8], BulkBuilderError> {
    bytes
        .try_into()
        .map_err(|_| BulkBuilderError::InvalidBlockSequence)
}

fn decode_be_u32(bytes: &[u8]) -> Result<u32, BulkBuilderError> {
    Ok(u32::from_be_bytes(decode_array4(bytes)?))
}

fn decode_flags(key: &[u8]) -> Result<u8, BulkBuilderError> {
    key.last()
        .copied()
        .ok_or(BulkBuilderError::InvalidBlockSequence)
}

struct RetainedCharge {
    charge: Arc<dyn BudgetCharge>,
    owner: BudgetOwner,
    held: u64,
}

impl RetainedCharge {
    fn take(&mut self, bytes: u64) -> Result<(), BudgetError> {
        self.charge.reserve_bytes(self.owner, bytes)?;
        self.charge.allocate_bytes(self.owner, bytes)?;
        self.held = self.held.saturating_add(bytes);
        Ok(())
    }

    fn give_back(&mut self, bytes: u64) {
        let released = bytes.min(self.held);
        self.charge.release_bytes(self.owner, released);
        self.held -= released;
    }
}

impl Drop for RetainedCharge {
    fn drop(&mut self) {
        self.give_back(self.held);
    }
}

/// One family's rows: an in-memory buffer charged to the shared budget pool,
/// spilled to a sorted run file when the pool refuses the next row. A row
/// the pool cannot hold even after a spill stays buffered uncharged, so a
/// valid logical row is never rejected and retained memory stays bounded by
/// the pool plus one row per sorter.
struct SpillSorter {
    charge: RetainedCharge,
    scratch_dir: PathBuf,
    file_prefix: String,
    buffer: Vec<(Vec<u8>, Vec<u8>)>,
    buffered_bytes: u64,
    runs: Vec<PathBuf>,
    next_run_id: usize,
    spilled: usize,
    finalized: bool,
}

impl SpillSorter {
    fn new(
        charge: Arc<dyn BudgetCharge>,
        owner: BudgetOwner,
        scratch_dir: PathBuf,
        builder_serial: u64,
        sorter_id: &str,
    ) -> Self {
        Self {
            charge: RetainedCharge {
                charge,
                owner,
                held: 0,
            },
            scratch_dir,
            file_prefix: format!("{RUN_FILE_PREFIX}{builder_serial:016x}-{sorter_id}-"),
            buffer: Vec::new(),
            buffered_bytes: 0,
            runs: Vec::new(),
            next_run_id: 0,
            spilled: 0,
            finalized: false,
        }
    }

    fn row_bytes(key: &[u8], value: &[u8]) -> u64 {
        u64::try_from(key.len().saturating_add(value.len()))
            .unwrap_or(u64::MAX)
            .saturating_add(ROW_CHARGE_OVERHEAD)
    }

    fn push_row(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), BulkBuilderError> {
        let bytes = Self::row_bytes(&key, &value);
        match self.charge.take(bytes) {
            Ok(()) => {}
            Err(BudgetError::BudgetExhausted) => {
                self.spill()?;
                if let Err(other) = self.charge.take(bytes)
                    && !matches!(other, BudgetError::BudgetExhausted)
                {
                    return Err(BulkBuilderError::Budget(other));
                }
            }
            Err(other) => return Err(BulkBuilderError::Budget(other)),
        }
        self.buffered_bytes = self.buffered_bytes.saturating_add(bytes);
        self.buffer.push((key, value));
        Ok(())
    }

    fn spill(&mut self) -> Result<(), BulkBuilderError> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        self.buffer
            .sort_unstable_by(|left, right| left.0.cmp(&right.0));
        let path = self
            .scratch_dir
            .join(format!("{}{:06}", self.file_prefix, self.next_run_id));
        self.next_run_id = self.next_run_id.saturating_add(1);
        let file = std::fs::File::create(&path)?;
        let mut writer = BufWriter::new(file);
        for (key, value) in &self.buffer {
            let key_len = u32::try_from(key.len()).map_err(|_| BulkBuilderError::RowTooLarge)?;
            let value_len =
                u32::try_from(value.len()).map_err(|_| BulkBuilderError::RowTooLarge)?;
            writer.write_all(&key_len.to_le_bytes())?;
            writer.write_all(&value_len.to_le_bytes())?;
            writer.write_all(key)?;
            writer.write_all(value)?;
        }
        writer.flush()?;
        drop(writer);
        self.runs.push(path);
        self.spilled = self.spilled.saturating_add(1);
        self.charge.give_back(self.buffered_bytes);
        self.buffered_bytes = 0;
        self.buffer = Vec::new();
        Ok(())
    }

    fn finalize(&mut self) -> Result<(), BulkBuilderError> {
        if !self.finalized {
            self.spill()?;
            self.buffer
                .sort_unstable_by(|left, right| left.0.cmp(&right.0));
            self.consolidate()?;
            self.finalized = true;
        }
        Ok(())
    }

    fn consolidate(&mut self) -> Result<(), BulkBuilderError> {
        while self.runs.len() > MAX_MERGE_FAN_IN {
            let count = self.runs.len().min(MAX_MERGE_FAN_IN);
            let path = self
                .scratch_dir
                .join(format!("{}{:06}", self.file_prefix, self.next_run_id));
            self.next_run_id = self.next_run_id.saturating_add(1);
            if let Err(error) = merge_run_prefix(&self.runs[..count], &path) {
                let _unused = std::fs::remove_file(&path);
                return Err(error);
            }
            for input in self.runs.drain(..count) {
                let _unused = std::fs::remove_file(input);
            }
            self.runs.push(path);
        }
        Ok(())
    }

    /// Non-consuming ascending stream over runs plus a clone of the sorted
    /// remainder; the clone is bounded by the budget window.
    fn sorted_rows(&mut self) -> Result<SortedRows, BulkBuilderError> {
        self.finalize()?;
        SortedRows::open(&self.runs, self.buffer.clone())
    }

    /// Consuming ascending stream used by ingestion.
    fn sorted_into_rows(&mut self) -> Result<SortedRows, BulkBuilderError> {
        self.finalize()?;
        SortedRows::open(&self.runs, std::mem::take(&mut self.buffer))
    }

    fn collect_rows(&mut self) -> Result<SegmentRows, BulkBuilderError> {
        let mut merged = self.sorted_into_rows()?;
        let mut rows = SegmentRows::new();
        while let Some(row) = merged.try_next()? {
            rows.push(row);
        }
        self.release();
        Ok(rows)
    }

    fn release(&mut self) {
        for path in std::mem::take(&mut self.runs) {
            let _unused = std::fs::remove_file(path);
        }
        self.buffered_bytes = 0;
        self.buffer = Vec::new();
    }
}

impl Drop for SpillSorter {
    fn drop(&mut self) {
        for path in std::mem::take(&mut self.runs) {
            let _unused = std::fs::remove_file(path);
        }
    }
}

fn merge_run_prefix(inputs: &[PathBuf], out: &Path) -> Result<(), BulkBuilderError> {
    let mut cursors = inputs
        .iter()
        .map(|path| RunCursor::open(path))
        .collect::<Result<Vec<_>, _>>()?;
    let mut heap: BinaryHeap<Reverse<MergeHeapEntry>> = BinaryHeap::with_capacity(cursors.len());
    for (index, cursor) in cursors.iter_mut().enumerate() {
        if let Some((key, value)) = cursor.current.take() {
            heap.push(Reverse((key, value, index)));
        }
    }
    let file = std::fs::File::create(out)?;
    let mut writer = BufWriter::new(file);
    while let Some(Reverse((key, value, index))) = heap.pop() {
        let key_len = u32::try_from(key.len()).map_err(|_| BulkBuilderError::RowTooLarge)?;
        let value_len = u32::try_from(value.len()).map_err(|_| BulkBuilderError::RowTooLarge)?;
        writer.write_all(&key_len.to_le_bytes())?;
        writer.write_all(&value_len.to_le_bytes())?;
        writer.write_all(&key)?;
        writer.write_all(&value)?;
        cursors[index].advance()?;
        if let Some((key, value)) = cursors[index].current.take() {
            heap.push(Reverse((key, value, index)));
        }
    }
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
thread_local! {
    static OPEN_RUN_CURSORS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static PEAK_RUN_CURSORS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_cursor_peak() {
    OPEN_RUN_CURSORS.with(|open| open.set(0));
    PEAK_RUN_CURSORS.with(|peak| peak.set(0));
}

#[cfg(test)]
pub(crate) fn cursor_peak() -> usize {
    PEAK_RUN_CURSORS.with(|peak| peak.get())
}
type RunRow = Option<(Vec<u8>, Vec<u8>)>;

struct RunCursor {
    reader: BufReader<std::fs::File>,
    current: Option<(Vec<u8>, Vec<u8>)>,
}

impl RunCursor {
    fn open(path: &Path) -> Result<Self, BulkBuilderError> {
        let file = std::fs::File::open(path)?;
        let mut reader = BufReader::new(file);
        let current = Self::read_row(&mut reader)?;
        #[cfg(test)]
        OPEN_RUN_CURSORS.with(|open| {
            let held = open.get().saturating_add(1);
            open.set(held);
            PEAK_RUN_CURSORS.with(|peak| peak.set(peak.get().max(held)));
        });
        Ok(Self { reader, current })
    }

    fn read_row(reader: &mut BufReader<std::fs::File>) -> Result<RunRow, BulkBuilderError> {
        let mut first = [0u8; 1];
        match reader.read_exact(&mut first) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        }
        let mut rest = [0u8; 3];
        reader.read_exact(&mut rest)?;
        let mut len_buf = [0u8; 4];
        len_buf[0] = first[0];
        len_buf[1..].copy_from_slice(&rest);
        let key_len = usize::try_from(u32::from_le_bytes(len_buf))
            .map_err(|_| BulkBuilderError::RowTooLarge)?;
        reader.read_exact(&mut len_buf)?;
        let value_len = usize::try_from(u32::from_le_bytes(len_buf))
            .map_err(|_| BulkBuilderError::RowTooLarge)?;
        let mut key = vec![0u8; key_len];
        reader.read_exact(&mut key)?;
        let mut value = vec![0u8; value_len];
        reader.read_exact(&mut value)?;
        Ok(Some((key, value)))
    }

    fn advance(&mut self) -> Result<(), BulkBuilderError> {
        self.current = Self::read_row(&mut self.reader)?;
        Ok(())
    }
}

#[cfg(test)]
impl Drop for RunCursor {
    fn drop(&mut self) {
        OPEN_RUN_CURSORS.with(|open| open.set(open.get().saturating_sub(1)));
    }
}

/// Ascending row stream over the spilled runs plus the sorted in-memory
/// remainder (`PRJ-09` partitioned merge).
///
/// Fallible merge: a run read failure is recorded and the infallible pull
/// then yields one duplicate of the last row, so `ingest_sorted` sees keys
/// that are not strictly ascending, discards its scratch output, and commits
/// nothing; `take_error` reports the typed failure instead of the fake row.
struct SortedRows {
    runs: Vec<RunCursor>,
    buffer: std::vec::IntoIter<(Vec<u8>, Vec<u8>)>,
    poison: Option<Vec<u8>>,
    error: Option<BulkBuilderError>,
}

impl SortedRows {
    fn open(runs: &[PathBuf], buffer: Vec<(Vec<u8>, Vec<u8>)>) -> Result<Self, BulkBuilderError> {
        let cursors = runs
            .iter()
            .map(|path| RunCursor::open(path))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            runs: cursors,
            buffer: buffer.into_iter(),
            poison: None,
            error: None,
        })
    }

    fn peek_min(&self) -> Option<usize> {
        let mut min: Option<(&[u8], usize)> = None;
        for (index, run) in self.runs.iter().enumerate() {
            if let Some((key, _)) = &run.current {
                if min.is_none_or(|best| key.as_slice() < best.0) {
                    min = Some((key.as_slice(), index));
                }
            }
        }
        if let Some((key, _)) = self.buffer.as_slice().first() {
            if min.is_none_or(|best| key.as_slice() < best.0) {
                min = Some((key.as_slice(), usize::MAX));
            }
        }
        min.map(|(_, source)| source)
    }

    fn try_next(&mut self) -> Result<Option<MergedRow>, BulkBuilderError> {
        if let Some(error) = self.error.take() {
            return Err(error);
        }
        let Some(source) = self.peek_min() else {
            return Ok(None);
        };
        if source == usize::MAX {
            return Ok(self.buffer.next());
        }
        let Some((key, value)) = self.runs[source].current.take() else {
            return Ok(None);
        };
        if let Err(error) = self.runs[source].advance() {
            self.poison = Some(key.clone());
            self.error = Some(error);
        }
        Ok(Some((key, value)))
    }

    fn take_error(&mut self) -> Option<BulkBuilderError> {
        self.error.take()
    }
}

impl Iterator for SortedRows {
    type Item = (Vec<u8>, Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(key) = self.poison.take() {
            return Some((key, Vec::new()));
        }
        match self.try_next() {
            Ok(row) => row,
            Err(error) => {
                self.error = Some(error);
                self.poison.take().map(|key| (key, Vec::new()))
            }
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used)]
#[path = "bulk_builder_tests.rs"]
mod tests;

#[cfg(test)]
mod cpu_reserve_tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct RecordingBudget {
        cpu: Arc<CpuShares>,
        observed_min: AtomicU32,
        observed_max: AtomicU32,
    }

    impl BudgetCharge for RecordingBudget {
        fn reserve_bytes(&self, _owner: BudgetOwner, _bytes: u64) -> Result<(), BudgetError> {
            let in_flight = self.cpu.background_in_flight();
            self.observed_min.fetch_min(in_flight, Ordering::SeqCst);
            self.observed_max.fetch_max(in_flight, Ordering::SeqCst);
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

    #[derive(Debug, thiserror::Error)]
    enum CpuTestError {
        #[error(transparent)]
        Build(#[from] BulkBuilderError),
        #[error(transparent)]
        Io(#[from] std::io::Error),
    }

    fn sample_block() -> CommittedBlock {
        CommittedBlock {
            height: 0,
            hash: [1u8; 32],
            parent_hash: [0u8; 32],
            header: [0u8; 80],
            txs: Vec::new(),
        }
    }

    // BUD-04
    #[test]
    fn background_scoring_runs_under_a_cpu_permit() -> Result<(), CpuTestError> {
        let cpu = Arc::new(CpuShares::new(2, 1));
        let budget = Arc::new(RecordingBudget {
            cpu: Arc::clone(&cpu),
            observed_min: AtomicU32::new(u32::MAX),
            observed_max: AtomicU32::new(0),
        });
        let dir = tempfile::tempdir()?;
        let builder = BulkSegmentBuilder::new(
            budget.clone(),
            Some(Arc::clone(&cpu)),
            dir.path().to_path_buf(),
        );
        let rows = builder.build_generation_rows(1, &[sample_block()])?;
        assert_eq!(
            budget.observed_min.load(Ordering::SeqCst),
            1,
            "the bulk build must hold one background CPU permit while it runs"
        );
        assert_eq!(
            cpu.background_in_flight(),
            0,
            "the permit releases on return"
        );
        drop(rows);
        Ok(())
    }

    // BUD-05
    #[test]
    fn single_worker_host_runs_background_scoring_without_a_permit() -> Result<(), CpuTestError> {
        let cpu = Arc::new(CpuShares::new(1, 1));
        let budget = Arc::new(RecordingBudget {
            cpu: Arc::clone(&cpu),
            observed_min: AtomicU32::new(u32::MAX),
            observed_max: AtomicU32::new(0),
        });
        let dir = tempfile::tempdir()?;
        let builder = BulkSegmentBuilder::new(
            budget.clone(),
            Some(Arc::clone(&cpu)),
            dir.path().to_path_buf(),
        );
        let rows = builder.build_generation_rows(1, &[sample_block()])?;
        assert_eq!(cpu.foreground_reserve(), 1);
        assert_eq!(budget.observed_max.load(Ordering::SeqCst), 0);
        drop(rows);
        Ok(())
    }
}
