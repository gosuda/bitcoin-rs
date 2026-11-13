//! Mutable tail: generation-0 rows for heights above the newest sealed
//! generation (PRJ-05). Each forward block appends its rows and one undo log
//! to the caller's batch, so tail rows and the watermark publish together. A
//! shallow reorg replays the log backwards in the batch that rewinds the
//! watermark. A seal cuts the stable prefix off the tail using the same logs.

use super::format::{self, PostingItem, REORG_WINDOW_BLOCKS, ScriptStats, TAIL_RETAIN_MAX_BYTES};
use super::{Coverage, SealedGen, sealed_generations};
use crate::{IndexCapabilities, IndexCapability, IndexError};
use bitcoin_rs_storage::committed_facts::{CommittedBlock, CreatedOutput, SpentPrevout};
use bitcoin_rs_storage::{BufferedWriteBatch, ColumnFamily, KvSnapshot};
use sha2::Digest as _;
use std::collections::VecDeque;

pub(crate) const LOG_PREFIX: &[u8] = b"tail/log/";
pub(crate) const LOG_END: &[u8] = b"tail/log0";
const LOG_HEADER_LEN: usize = 44;
const LOG_CODE_STATS: u8 = 6;
const LOG_CODE_HASH: u8 = 7;
const HASH_OP_LEN: u64 = 33;
const STATS_OP_LEN: u64 = 14;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Family {
    TxDir,
    ScriptDict,
    ScriptPost,
    SpendDir,
    Filters,
}

impl Family {
    const fn column_family(self) -> ColumnFamily {
        match self {
            Self::TxDir => ColumnFamily::TxDir,
            Self::ScriptDict => ColumnFamily::ScriptDict,
            Self::ScriptPost => ColumnFamily::ScriptPost,
            Self::SpendDir => ColumnFamily::SpendDir,
            Self::Filters => ColumnFamily::Filters,
        }
    }

    const fn code(self) -> u8 {
        match self {
            Self::TxDir => 0,
            Self::ScriptDict => 1,
            Self::ScriptPost => 2,
            Self::SpendDir => 3,
            Self::Filters => 5,
        }
    }

    const fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            0 => Self::TxDir,
            1 => Self::ScriptDict,
            2 => Self::ScriptPost,
            3 => Self::SpendDir,
            5 => Self::Filters,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TailBlock {
    pub height: u32,
    pub bytes: u64,
}

/// In-memory view of the tail, rebuilt from generation-0 rows, the undo logs,
/// and the sealed descriptors (`IndexWriter::open`).
#[derive(Clone, Debug, Default)]
pub struct TailWriterState {
    pub at: Option<(u32, [u8; 32])>,
    pub next_ordinal: u32,
    pub prev_filter_header: [u8; 32],
    pub txid_to_ordinal: hashbrown::HashMap<[u8; 32], u32>,
    pub script_id_map: hashbrown::HashMap<[u8; 32], u32>,
    pub next_script_id: u32,
    pub script_stats: hashbrown::HashMap<u32, ScriptStats>,
    pub posting_slots: hashbrown::HashMap<u32, u32>,
    pub window: VecDeque<TailBlock>,
    pub sealed: Vec<SealedGen>,
    pub next_gen_id: u64,
}

impl TailWriterState {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn newest(&self) -> Option<SealedGen> {
        self.sealed.last().copied()
    }

    #[must_use]
    pub fn first_height(&self) -> Option<u32> {
        self.window.front().map(|block| block.height)
    }

    #[must_use]
    pub fn tail_blocks(&self) -> usize {
        self.window.len()
    }

    #[must_use]
    pub fn tail_bytes(&self) -> u64 {
        self.window
            .iter()
            .fold(0_u64, |total, block| total.saturating_add(block.bytes))
    }

    #[must_use]
    pub fn retention_cut(&self) -> Option<u32> {
        let mut bytes = 0_u64;
        let max_blocks = usize::try_from(REORG_WINDOW_BLOCKS).unwrap_or(usize::MAX);
        for (kept, block) in self.window.iter().rev().enumerate() {
            let next_bytes = bytes.saturating_add(block.bytes);
            if kept >= max_blocks || next_bytes > TAIL_RETAIN_MAX_BYTES {
                return Some(block.height);
            }
            bytes = next_bytes;
        }
        None
    }

    /// Whether `blocks` more blocks of `bytes` in total keep the tail within
    /// both bounds (PRJ-05).
    #[must_use]
    pub fn admits(&self, blocks: usize, bytes: u64) -> bool {
        let max_blocks = usize::try_from(format::TAIL_MAX_BLOCKS).unwrap_or(usize::MAX);
        let max_bytes = u64::try_from(format::TAIL_MAX_BYTES).unwrap_or(u64::MAX);
        self.tail_blocks().saturating_add(blocks) <= max_blocks
            && self.tail_bytes().saturating_add(bytes) <= max_bytes
    }

    /// The cut that must seal before a block of `incoming` bytes appends
    /// (PRJ-05): the retention cut, raised until the kept suffix leaves room
    /// for the block within both bounds. `None` only for an empty window.
    #[must_use]
    pub fn cut_before_append(&self, incoming: u64) -> Option<u32> {
        let max_kept = usize::try_from(format::TAIL_MAX_BLOCKS).unwrap_or(usize::MAX) - 1;
        let max_bytes = u64::try_from(format::TAIL_MAX_BYTES).unwrap_or(u64::MAX);
        let mut kept_bytes = 0_u64;
        let mut fitted = None;
        for (kept_blocks, block) in self.window.iter().rev().enumerate() {
            let next_bytes = kept_bytes.saturating_add(block.bytes);
            if kept_blocks + 1 > max_kept || next_bytes.saturating_add(incoming) > max_bytes {
                fitted = Some(block.height);
                break;
            }
            kept_bytes = next_bytes;
        }
        match (self.retention_cut(), fitted) {
            (Some(retained), Some(fit)) => Some(retained.max(fit)),
            (retained, fit) => retained.or(fit),
        }
    }

    pub fn pop_newest_block(&mut self) {
        self.window.pop_back();
    }

    #[must_use]
    pub fn bounds(&self) -> TailBounds {
        TailBounds {
            newest: self.newest(),
            first_height: self.first_height(),
            at: self.at,
        }
    }
}

/// Publication bounds written into `gen/<cap>` descriptors.
#[derive(Clone, Copy, Debug, Default)]
pub struct TailBounds {
    pub newest: Option<SealedGen>,
    pub first_height: Option<u32>,
    pub at: Option<(u32, [u8; 32])>,
}

/// Resolves creation ordinals of transactions that no longer live in the tail.
pub trait CreationOrdinals {
    fn creation_ordinal(&self, txid: &[u8; 32]) -> Result<Option<u32>, IndexError>;
}

/// Resolves through the sealed generations of one captured snapshot.
pub struct SealedTxOrdinals<'a> {
    pub snapshot: &'a dyn KvSnapshot,
    pub gens: &'a [SealedGen],
}

impl CreationOrdinals for SealedTxOrdinals<'_> {
    fn creation_ordinal(&self, txid: &[u8; 32]) -> Result<Option<u32>, IndexError> {
        for sealed in self.gens.iter().rev() {
            let mut prefix =
                format::tx_dir_kind_prefix(sealed.gen_id, format::TX_KIND_TXID).to_vec();
            prefix.extend_from_slice(txid);
            let mut latest = None;
            for item in self.snapshot.iter_prefix(ColumnFamily::TxDir, &prefix)? {
                let (key, value) = item?;
                if format::decode_tx_dir_key(&key).is_none() {
                    continue;
                }
                if let Some((_, ordinal, _, _)) = format::decode_tx_dir_value(&value) {
                    latest = Some(ordinal);
                }
            }
            if latest.is_some() {
                return Ok(latest);
            }
        }
        Ok(None)
    }
}

/// Resolver for callers that hold no sealed generations.
pub struct NoSealedTxOrdinals;

impl CreationOrdinals for NoSealedTxOrdinals {
    fn creation_ordinal(&self, _txid: &[u8; 32]) -> Result<Option<u32>, IndexError> {
        Ok(None)
    }
}

/// Resolves every creation to ordinal zero. Planning uses it so every spend
/// row a block can emit is counted, including spends of outputs that live
/// in the tail or in a sealed generation.
pub struct AllCreated;

impl CreationOrdinals for AllCreated {
    fn creation_ordinal(&self, _txid: &[u8; 32]) -> Result<Option<u32>, IndexError> {
        Ok(Some(0))
    }
}

/// Undo-log recorder. Row keys are inserted, so undo deletes them; stats
/// changes are logged as deltas so that a sealed prefix can be subtracted.
struct Recorder<'a> {
    batch: &'a mut BufferedWriteBatch,
    log: Vec<u8>,
    bytes: u64,
}

impl Recorder<'_> {
    fn put(&mut self, family: Family, key: &[u8], value: &[u8]) {
        self.batch.put(family.column_family(), key, value);
        self.log.push(family.code());
        push_len_prefixed(&mut self.log, key);
        let row_bytes = u64::try_from(key.len().saturating_add(value.len())).unwrap_or(u64::MAX);
        self.bytes = self.bytes.saturating_add(row_bytes);
    }

    fn stats_delta(&mut self, script_id: u32, funding: bool, sats: u64) {
        self.log.push(LOG_CODE_STATS);
        self.log.extend_from_slice(&script_id.to_le_bytes());
        self.log.push(u8::from(funding));
        self.log.extend_from_slice(&sats.to_le_bytes());
        self.bytes = self.bytes.saturating_add(STATS_OP_LEN);
    }
    fn hash_anchor(&mut self, hash: &[u8; 32]) {
        self.log.push(LOG_CODE_HASH);
        self.log.extend_from_slice(hash);
        self.bytes = self.bytes.saturating_add(HASH_OP_LEN);
    }
}

fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
}

fn log_key(height: u32) -> Vec<u8> {
    let mut key = LOG_PREFIX.to_vec();
    key.extend_from_slice(&height.to_be_bytes());
    key
}

pub(crate) fn log_key_for(height: u32) -> Vec<u8> {
    log_key(height)
}

fn log_height(key: &[u8]) -> Option<u32> {
    let rest = key.strip_prefix(LOG_PREFIX)?;
    Some(u32::from_be_bytes(rest.try_into().ok()?))
}

/// Upper bound on the tail bytes one block adds: row bytes plus its undo log
/// (PRJ-05). Every dictionary, spend, and posting row is counted as new, so
/// the bound never undercounts what `append_tail_block` records.
#[must_use]
pub fn block_tail_bytes_bound(block: &CommittedBlock) -> u64 {
    let row = |key: usize, value: usize| u64::try_from(2 * key + value + 5).unwrap_or(u64::MAX);
    let posting = format::encode_posting_items(&[PostingItem {
        delta_ordinal: u32::MAX,
        flags: format::POSTING_FLAG_SPENDING,
    }]);
    let occurrence = row(format::encode_script_post_key(0, 0, 0).len(), posting.len())
        + 2 * STATS_OP_LEN
        + u64::try_from(format::SCRIPT_STATS_KEY_LEN + format::SCRIPT_STATS_VALUE_LEN)
            .unwrap_or(u64::MAX);
    let dict = row(
        format::encode_script_dict_key(0, &[0; 32]).len(),
        format::encode_script_dict_value(0).len(),
    );
    let spend = row(
        format::encode_spend_dir_key(0, 0, 0).len(),
        format::encode_spend_dir_value(0).len(),
    );
    let tx_rows = row(
        format::encode_tx_dir_key(0, &[0; 32], 0).len(),
        format::encode_tx_dir_value(&[0; 32], 0, 0, 0).len(),
    ) + row(
        format::encode_tx_ordinal_key(0, 0).len(),
        format::encode_tx_ordinal_value(&[0; 32], 0, 0, 0).len(),
    );
    let mut total = u64::try_from(LOG_HEADER_LEN)
        .unwrap_or(0)
        .saturating_add(HASH_OP_LEN);
    let mut elements = 0_usize;
    for tx in &block.txs {
        total = total.saturating_add(tx_rows);
        for input in &tx.inputs {
            if input.txid == [0u8; 32] && input.vout == u32::MAX {
                continue;
            }
            elements += 1;
            total = total.saturating_add(spend);
            total = total.saturating_add(dict.saturating_add(occurrence));
        }
        for output in &tx.outputs {
            elements += 1;
            if output.script.first() != Some(&0x6a) {
                total = total.saturating_add(dict.saturating_add(occurrence));
            }
        }
    }
    const GCS_BYTES_PER_ELEMENT: usize = 3;
    const GCS_SLACK_BYTES: usize = 16;
    let filter_bytes = elements
        .saturating_mul(GCS_BYTES_PER_ELEMENT)
        .saturating_add(GCS_SLACK_BYTES);
    let filter_value = format::encode_filter_value(&[0; 32], &[0; 32], &[0; 32], &[]).len();
    let filter = row(
        format::encode_filter_key(0, 0).len(),
        filter_value.saturating_add(filter_bytes),
    );
    total.saturating_add(filter)
}

/// Rows of one block that depend on the block alone: the compact filter and
/// the hashes of the scripts the append keys its dictionary by. Prepare
/// builds them once; the tail append consumes them, so no path builds a
/// block's filter or hashes its scripts twice.
pub(crate) struct PreparedTail {
    pub(crate) has_filter: bool,
    pub(crate) capabilities: IndexCapabilities,
    pub(crate) filter_bytes: Vec<u8>,
    pub(crate) filter_hash: [u8; 32],
    pub(crate) inputs: Vec<Vec<Option<[u8; 32]>>>,
    pub(crate) outputs: Vec<Vec<Option<[u8; 32]>>>,
}

impl PreparedTail {
    pub(crate) fn new_gated(
        block: &CommittedBlock,
        needs_filter: bool,
        needs_hashes: bool,
    ) -> Self {
        let (filter_bytes, filter_hash) = if needs_filter {
            build_filter(block)
        } else {
            Default::default()
        };
        let inputs = block
            .txs
            .iter()
            .map(|tx| {
                tx.inputs
                    .iter()
                    .map(|input| {
                        (needs_hashes && !is_coinbase_marker(&input.txid, input.vout))
                            .then(|| script_hash(&input.script))
                    })
                    .collect()
            })
            .collect();
        let outputs = block
            .txs
            .iter()
            .map(|tx| {
                tx.outputs
                    .iter()
                    .map(|output| {
                        (needs_hashes && output.script.first() != Some(&0x6a))
                            .then(|| script_hash(&output.script))
                    })
                    .collect()
            })
            .collect();
        Self {
            has_filter: needs_filter,
            capabilities: {
                let mut caps = IndexCapabilities::TX_LOOKUP;
                if needs_filter {
                    caps = caps.insert(IndexCapability::CompactFilters);
                }
                if needs_hashes {
                    caps = caps.insert(IndexCapability::ScriptHistory);
                }
                caps
            },
            filter_bytes,
            filter_hash,
            inputs,
            outputs,
        }
    }
    pub(crate) fn for_capabilities(
        block: &CommittedBlock,
        capabilities: IndexCapabilities,
    ) -> Self {
        let needs_filter = capabilities.contains(IndexCapability::CompactFilters);
        let needs_hashes = capabilities.contains(IndexCapability::ScriptHistory);
        let mut prepared = Self::new_gated(block, needs_filter, needs_hashes);
        prepared.capabilities = capabilities;
        prepared
    }
}

fn script_hash(script: &[u8]) -> [u8; 32] {
    #[cfg(test)]
    SCRIPT_HASH_BUILDS.with(|builds| builds.set(builds.get() + 1));
    sha2::Sha256::digest(script).into()
}

fn is_coinbase_marker(txid: &[u8; 32], vout: u32) -> bool {
    *txid == [0u8; 32] && vout == u32::MAX
}

#[cfg(test)]
thread_local! {
    pub(crate) static FILTER_BUILDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    pub(crate) static SCRIPT_HASH_BUILDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Appends one committed block to the tail (PRJ-05). Rows, the undo log, and
/// the state advance together; the caller commits the batch.
pub fn append_tail_block(
    batch: &mut BufferedWriteBatch,
    block: &CommittedBlock,
    state: &mut TailWriterState,
    older: &dyn CreationOrdinals,
) -> Result<(), IndexError> {
    let prepared = PreparedTail::new_gated(block, true, true);
    append_prepared_tail_block(batch, block, &prepared, state, older, None)
}

/// Appends one block whose block-only rows were prepared from `block`.
pub(crate) fn append_prepared_tail_block(
    batch: &mut BufferedWriteBatch,
    block: &CommittedBlock,
    prepared: &PreparedTail,
    state: &mut TailWriterState,
    older: &dyn CreationOrdinals,
    existing_log: Option<&[u8]>,
) -> Result<(), IndexError> {
    if let Some(value) = existing_log {
        let ops =
            value
                .get(LOG_HEADER_LEN..)
                .and_then(parse_log)
                .ok_or(IndexError::CorruptTailLog {
                    height: block.height,
                })?;
        if !ops
            .iter()
            .any(|op| matches!(op, LogOp::Hash { hash } if *hash == block.hash))
        {
            return Err(IndexError::CorruptTailLog {
                height: block.height,
            });
        }
    }
    let mut rec = Recorder {
        batch,
        log: Vec::new(),
        bytes: 0,
    };
    rec.hash_anchor(&block.hash);
    let mut block_next_ordinal =
        existing_log.map_or(state.next_ordinal, |value| read_u32_le(value, 0));
    for (tx, (input_hashes, output_hashes)) in block
        .txs
        .iter()
        .zip(prepared.inputs.iter().zip(&prepared.outputs))
    {
        let ordinal =
            if let Some(ordinal) = existing_log.and_then(|_| state.txid_to_ordinal.get(&tx.txid)) {
                *ordinal
            } else if needs_transaction_directory(prepared) {
                let ordinal = state.next_ordinal;
                state.next_ordinal = state.next_ordinal.saturating_add(1);
                ordinal
            } else {
                state.next_ordinal
            };
        if needs_transaction_directory(prepared) {
            block_next_ordinal = block_next_ordinal.max(ordinal.saturating_add(1));
        }
        let needs_tx_dir = prepared.capabilities.contains(IndexCapability::TxLookup)
            || prepared
                .capabilities
                .contains(IndexCapability::ScriptHistory);
        if needs_tx_dir && (existing_log.is_none() || !state.txid_to_ordinal.contains_key(&tx.txid))
        {
            state.txid_to_ordinal.insert(tx.txid, ordinal);
            let tx_key = format::encode_tx_dir_key(0, &tx.txid, block.height);
            let tx_val = format::encode_tx_dir_value(&block.hash, ordinal, tx.offset, tx.len);
            rec.put(Family::TxDir, &tx_key, &tx_val);
            let rev_key = format::encode_tx_ordinal_key(0, ordinal);
            let rev_val =
                format::encode_tx_ordinal_value(&tx.txid, block.height, tx.offset, tx.len);
            rec.put(Family::TxDir, &rev_key, &rev_val);
        }
        if prepared
            .capabilities
            .contains(IndexCapability::ScriptHistory)
        {
            let spends = SpendingInputs {
                ordinal,
                prevouts: &tx.inputs,
                hashes: input_hashes,
            };
            append_inputs(&mut rec, spends, state, older)?;
            let funding = FundingOutputs {
                ordinal,
                outputs: &tx.outputs,
                hashes: output_hashes,
            };
            append_outputs(&mut rec, funding, state);
        }
    }
    if prepared.has_filter {
        append_filter(&mut rec, block, prepared, state);
    }

    let block_bytes = rec
        .bytes
        .saturating_add(existing_log.map_or(0, |value| read_u64_le(value, 36)));
    let log = std::mem::take(&mut rec.log);
    let prior_ops = existing_log
        .and_then(|value| value.get(LOG_HEADER_LEN..))
        .unwrap_or(&[]);
    let mut value = Vec::with_capacity(LOG_HEADER_LEN + prior_ops.len() + log.len());
    value.extend_from_slice(&block_next_ordinal.to_le_bytes());
    value.extend_from_slice(&state.prev_filter_header);
    value.extend_from_slice(&block_bytes.to_le_bytes());
    value.extend_from_slice(prior_ops);
    value.extend_from_slice(&log);
    rec.batch
        .put(ColumnFamily::IdxMeta, &log_key(block.height), &value);

    let value_len = u64::try_from(value.len()).unwrap_or(u64::MAX);
    let retained = TailBlock {
        height: block.height,
        bytes: block_bytes.saturating_add(value_len),
    };
    if let Some(prior) = state
        .window
        .iter_mut()
        .find(|entry| entry.height == block.height)
    {
        *prior = retained;
    } else {
        let at = state
            .window
            .partition_point(|entry| entry.height < block.height);
        state.window.insert(at, retained);
    }
    state.at = Some((block.height, block.hash));
    Ok(())
}

fn needs_transaction_directory(prepared: &PreparedTail) -> bool {
    prepared.capabilities.contains(IndexCapability::TxLookup)
        || prepared
            .capabilities
            .contains(IndexCapability::ScriptHistory)
}

/// The spending inputs of one transaction, with the script hash of each.
struct SpendingInputs<'a> {
    ordinal: u32,
    prevouts: &'a [SpentPrevout],
    hashes: &'a [Option<[u8; 32]>],
}

/// The created outputs of one transaction, with the script hash of each.
struct FundingOutputs<'a> {
    ordinal: u32,
    outputs: &'a [CreatedOutput],
    hashes: &'a [Option<[u8; 32]>],
}

fn append_inputs(
    rec: &mut Recorder<'_>,
    spends: SpendingInputs<'_>,
    state: &mut TailWriterState,
    older: &dyn CreationOrdinals,
) -> Result<(), IndexError> {
    for (input, hash) in spends.prevouts.iter().zip(spends.hashes) {
        if is_coinbase_marker(&input.txid, input.vout) {
            continue;
        }
        let creation = match state.txid_to_ordinal.get(&input.txid) {
            Some(&ordinal) => Some(ordinal),
            None => older.creation_ordinal(&input.txid)?,
        };
        if let Some(creation_ord) = creation {
            let key = format::encode_spend_dir_key(0, creation_ord, input.vout);
            let val = format::encode_spend_dir_value(spends.ordinal);
            rec.put(Family::SpendDir, &key, &val);
        }
        if let Some(hash) = hash {
            let script_id = script_id_for(rec, hash, state);
            record_occurrence(
                rec,
                script_id,
                spends.ordinal,
                format::POSTING_FLAG_SPENDING,
                input.value,
                state,
            );
        }
    }
    Ok(())
}

fn append_outputs(
    rec: &mut Recorder<'_>,
    funding: FundingOutputs<'_>,
    state: &mut TailWriterState,
) {
    for (output, hash) in funding.outputs.iter().zip(funding.hashes) {
        if let Some(hash) = hash {
            let script_id = script_id_for(rec, hash, state);
            record_occurrence(
                rec,
                script_id,
                funding.ordinal,
                format::POSTING_FLAG_FUNDING,
                output.value,
                state,
            );
        }
    }
}

fn script_id_for(rec: &mut Recorder<'_>, hash: &[u8; 32], state: &mut TailWriterState) -> u32 {
    if let Some(&id) = state.script_id_map.get(hash) {
        return id;
    }
    let id = state.next_script_id;
    state.next_script_id = state.next_script_id.saturating_add(1);
    state.script_id_map.insert(*hash, id);
    rec.put(
        Family::ScriptDict,
        &format::encode_script_dict_key(0, hash),
        &format::encode_script_dict_value(id),
    );
    id
}

fn record_occurrence(
    rec: &mut Recorder<'_>,
    script_id: u32,
    ordinal: u32,
    flags: u8,
    sats: u64,
    state: &mut TailWriterState,
) {
    let slot = state.posting_slots.entry(script_id).or_insert(0);
    let post_key = format::encode_script_post_key(0, script_id, *slot);
    *slot = slot.saturating_add(1);
    let post_val = format::encode_posting_items(&[PostingItem {
        delta_ordinal: ordinal,
        flags,
    }]);
    rec.put(Family::ScriptPost, &post_key, &post_val);

    let funding = flags == format::POSTING_FLAG_FUNDING;
    rec.stats_delta(script_id, funding, sats);
    let stats = state.script_stats.entry(script_id).or_default();
    apply_delta(stats, funding, sats);
    let key = format::encode_script_stats_key(0, script_id);
    let value = format::encode_script_stats_value(stats);
    let row_bytes = u64::try_from(key.len().saturating_add(value.len())).unwrap_or(u64::MAX);
    rec.bytes = rec.bytes.saturating_add(row_bytes);
    rec.batch.put(ColumnFamily::ScriptStats, &key, &value);
}

fn apply_delta(stats: &mut ScriptStats, funding: bool, sats: u64) {
    if funding {
        stats.funded_count = stats.funded_count.saturating_add(1);
        stats.funded_sats = stats.funded_sats.saturating_add(sats);
    } else {
        stats.spent_count = stats.spent_count.saturating_add(1);
        stats.spent_sats = stats.spent_sats.saturating_add(sats);
    }
}

fn minus(current: ScriptStats, delta: ScriptStats) -> Option<ScriptStats> {
    Some(ScriptStats {
        funded_count: current.funded_count.checked_sub(delta.funded_count)?,
        spent_count: current.spent_count.checked_sub(delta.spent_count)?,
        funded_sats: current.funded_sats.checked_sub(delta.funded_sats)?,
        spent_sats: current.spent_sats.checked_sub(delta.spent_sats)?,
    })
}

fn is_zero(stats: &ScriptStats) -> bool {
    stats.funded_count == 0
        && stats.spent_count == 0
        && stats.funded_sats == 0
        && stats.spent_sats == 0
}

/// Builds the compact filter of `block` (BIP 158 basic) and its hash.
fn build_filter(block: &CommittedBlock) -> (Vec<u8>, [u8; 32]) {
    #[cfg(test)]
    FILTER_BUILDS.with(|builds| builds.set(builds.get() + 1));
    let mut k0_b = [0u8; 8];
    k0_b.copy_from_slice(&block.hash[..8]);
    let k0 = u64::from_le_bytes(k0_b);
    let mut k1_b = [0u8; 8];
    k1_b.copy_from_slice(&block.hash[8..16]);
    let k1 = u64::from_le_bytes(k1_b);

    let mut filter_bytes = Vec::new();
    let mut writer = bitcoin::bip158::GcsFilterWriter::new(&mut filter_bytes, k0, k1, 784_931, 19);
    let mut created: hashbrown::HashMap<([u8; 32], u32), &[u8]> = hashbrown::HashMap::new();
    for tx in &block.txs {
        for input in &tx.inputs {
            if is_coinbase_marker(&input.txid, input.vout) {
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
    let filter_hash =
        bitcoin_rs_consensus::primitives::encode::double_sha256(&filter_bytes).to_le_bytes();
    (filter_bytes, filter_hash)
}

fn append_filter(
    rec: &mut Recorder<'_>,
    block: &CommittedBlock,
    prepared: &PreparedTail,
    state: &mut TailWriterState,
) {
    let mut hdr_in = [0u8; 64];
    hdr_in[..32].copy_from_slice(&prepared.filter_hash);
    hdr_in[32..].copy_from_slice(&state.prev_filter_header);
    let header = bitcoin_rs_consensus::primitives::encode::double_sha256(&hdr_in).to_le_bytes();
    state.prev_filter_header = header;

    let key = format::encode_filter_key(0, block.height);
    let val = format::encode_filter_value(
        &block.hash,
        &prepared.filter_hash,
        &header,
        &prepared.filter_bytes,
    );
    rec.put(Family::Filters, &key, &val);
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum LogOp {
    Row {
        family: Family,
        key: Vec<u8>,
    },
    Stats {
        script_id: u32,
        funding: bool,
        sats: u64,
    },
    Hash {
        hash: [u8; 32],
    },
}

fn parse_log(mut bytes: &[u8]) -> Option<Vec<LogOp>> {
    let mut ops = Vec::new();
    while let Some((&code, rest)) = bytes.split_first() {
        if code == LOG_CODE_STATS {
            let script_id = u32::from_le_bytes(rest.get(..4)?.try_into().ok()?);
            let funding = *rest.get(4)? == 1;
            let sats = u64::from_le_bytes(rest.get(5..13)?.try_into().ok()?);
            ops.push(LogOp::Stats {
                script_id,
                funding,
                sats,
            });
            bytes = rest.get(13..)?;
        } else if code == LOG_CODE_HASH {
            let hash: [u8; 32] = rest.get(..32)?.try_into().ok()?;
            ops.push(LogOp::Hash { hash });
            bytes = rest.get(32..)?;
        } else {
            let family = Family::from_code(code)?;
            let (key, rest) = take_len_prefixed(rest)?;
            ops.push(LogOp::Row {
                family,
                key: key.to_vec(),
            });
            bytes = rest;
        }
    }
    Some(ops)
}

fn take_len_prefixed(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let len = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?);
    let len = usize::try_from(len).ok()?;
    let body = bytes.get(4..)?;
    Some((body.get(..len)?, body.get(len..)?))
}

/// Replays the undo log of `height` backwards into `batch` and deletes the
/// log row. Stats are restored by subtracting the logged deltas. Returns
/// `false` when the tail holds no block at `height`.
pub fn unwind_tail_block(
    batch: &mut BufferedWriteBatch,
    snapshot: &dyn KvSnapshot,
    height: u32,
) -> Result<bool, IndexError> {
    let key = log_key(height);
    let Some(value) = snapshot.get(ColumnFamily::IdxMeta, &key)? else {
        return Ok(false);
    };
    let ops = parse_log(value.get(LOG_HEADER_LEN..).unwrap_or(&[]))
        .ok_or(IndexError::CorruptTailLog { height })?;
    let mut deltas: hashbrown::HashMap<u32, ScriptStats> = hashbrown::HashMap::new();
    let mut anchored = false;
    for op in ops {
        match op {
            LogOp::Row { family, key } => batch.delete(family.column_family(), &key),
            LogOp::Hash { .. } => {
                anchored = true;
            }
            LogOp::Stats {
                script_id,
                funding,
                sats,
            } => apply_delta(deltas.entry(script_id).or_default(), funding, sats),
        }
    }
    if !anchored {
        return Err(IndexError::CorruptTailLog { height });
    }
    for (script_id, delta) in deltas {
        let stats_key = format::encode_script_stats_key(0, script_id);
        let current = read_stats(snapshot, script_id)?;
        let remaining = minus(current, delta).ok_or(IndexError::CorruptTailLog { height })?;
        if is_zero(&remaining) {
            batch.delete(ColumnFamily::ScriptStats, &stats_key);
        } else {
            batch.put(
                ColumnFamily::ScriptStats,
                &stats_key,
                &format::encode_script_stats_value(&remaining),
            );
        }
    }
    batch.delete(ColumnFamily::IdxMeta, &key);
    Ok(true)
}

fn read_stats(snapshot: &dyn KvSnapshot, script_id: u32) -> Result<ScriptStats, IndexError> {
    let key = format::encode_script_stats_key(0, script_id);
    Ok(snapshot
        .get(ColumnFamily::ScriptStats, &key)?
        .as_deref()
        .and_then(format::decode_script_stats_value)
        .unwrap_or_default())
}

/// Stable-prefix cut of the tail (PRJ-05): the rows, stats, and logs of every
/// tail height at or below `cut`, planned from the undo logs.
pub(crate) struct PrefixCut {
    pub(crate) first: u32,
    pub(crate) cut: u32,
    pub(crate) cut_hash: [u8; 32],
    pub(crate) next_ordinal: u32,
    pub(crate) rows: Vec<(Family, Vec<u8>, Vec<u8>)>,
    pub(crate) script_hashes: hashbrown::HashMap<u32, [u8; 32]>,
    pub(crate) prefix_stats: hashbrown::HashMap<u32, ScriptStats>,
    pub(crate) dict_deletes: Vec<[u8; 32]>,
    pub(crate) gen0_stats: Vec<(u32, Option<ScriptStats>)>,
    pub(crate) log_keys: Vec<Vec<u8>>,
    pub(crate) tail_first: Option<u32>,
    pub(crate) tail_at: Option<(u32, [u8; 32])>,
}

/// Plans the cut of every tail height at or below `cut` (PRJ-05). The planner
/// reads only the logs and generation-0 rows, so a re-run after a crash
/// before the cut batch lands plans the same cut.
pub(crate) fn plan_prefix_cut(
    snapshot: &dyn KvSnapshot,
    cut: u32,
) -> Result<PrefixCut, IndexError> {
    let mut logs: Vec<(u32, Vec<u8>)> = Vec::new();
    let mut tip_height = None;
    for item in snapshot.iter_prefix(ColumnFamily::IdxMeta, LOG_PREFIX)? {
        let (key, value) = item?;
        let Some(height) = log_height(&key) else {
            continue;
        };
        tip_height = Some(height);
        if height <= cut {
            logs.push((height, value));
        }
    }
    let first = logs
        .first()
        .map(|(height, _)| *height)
        .ok_or(IndexError::CorruptTailLog { height: cut })?;
    let contiguous = logs.iter().enumerate().all(|(offset, (height, _))| {
        u32::try_from(offset)
            .ok()
            .and_then(|o| first.checked_add(o))
            == Some(*height)
    });
    if !contiguous || logs.last().map(|(height, _)| *height) != Some(cut) {
        return Err(IndexError::CorruptTailLog { height: cut });
    }

    let mut rows = Vec::new();
    let mut prefix_stats: hashbrown::HashMap<u32, ScriptStats> = hashbrown::HashMap::new();
    let mut next_ordinal = 0_u32;
    let mut log_hashes: hashbrown::HashMap<u32, [u8; 32]> = hashbrown::HashMap::new();
    for (height, value) in &logs {
        if *height == cut {
            next_ordinal = read_u32_le(value, 0);
        }
        let ops = parse_log(value.get(LOG_HEADER_LEN..).unwrap_or(&[]))
            .ok_or(IndexError::CorruptTailLog { height: *height })?;
        for op in ops {
            match op {
                LogOp::Hash { hash } => {
                    log_hashes.insert(*height, hash);
                }
                LogOp::Row { family, key } => {
                    if family == Family::ScriptDict {
                        continue;
                    }
                    let row = snapshot
                        .get(family.column_family(), &key)?
                        .ok_or(IndexError::CorruptTailLog { height: *height })?;
                    rows.push((family, key, row));
                }
                LogOp::Stats {
                    script_id,
                    funding,
                    sats,
                } => apply_delta(prefix_stats.entry(script_id).or_default(), funding, sats),
            }
        }
    }
    let cut_hash = log_hashes
        .get(&cut)
        .copied()
        .ok_or(IndexError::CorruptTailLog { height: cut })?;

    let mut script_hashes: hashbrown::HashMap<u32, [u8; 32]> = hashbrown::HashMap::new();
    if !prefix_stats.is_empty() {
        for item in snapshot.iter_prefix(ColumnFamily::ScriptDict, &0u64.to_be_bytes())? {
            let (key, value) = item?;
            if let (Some((_, hash)), Some(id)) = (
                format::decode_script_dict_key(&key),
                format::decode_script_dict_value(&value),
            ) {
                if prefix_stats.contains_key(&id) {
                    script_hashes.insert(id, hash);
                }
            }
        }
    }

    let mut gen0_stats = Vec::new();
    let mut dict_deletes = Vec::new();
    for (&script_id, delta) in &prefix_stats {
        let remaining = minus(read_stats(snapshot, script_id)?, *delta)
            .ok_or(IndexError::CorruptTailLog { height: cut })?;
        let hash = *script_hashes
            .get(&script_id)
            .ok_or(IndexError::CorruptTailLog { height: cut })?;
        if is_zero(&remaining) {
            gen0_stats.push((script_id, None));
            dict_deletes.push(hash);
        } else {
            gen0_stats.push((script_id, Some(remaining)));
        }
    }

    let tip = tip_height.ok_or(IndexError::CorruptTailLog { height: cut })?;
    let tail_first = (tip > cut).then(|| cut.saturating_add(1));
    let tail_at = if tip == cut {
        Some((tip, cut_hash))
    } else {
        Some((tip, log_hash_for(snapshot, tip)?))
    };
    let log_keys = logs.iter().map(|(height, _)| log_key(*height)).collect();

    Ok(PrefixCut {
        first,
        cut,
        cut_hash,
        next_ordinal,
        rows,
        script_hashes,
        prefix_stats,
        dict_deletes,
        gen0_stats,
        log_keys,
        tail_first,
        tail_at,
    })
}

/// Removes the cut rows, deltas, dictionary entries, and logs from generation
/// zero, in the caller's batch.
pub(crate) fn cut_generation_zero(batch: &mut BufferedWriteBatch, plan: &PrefixCut) {
    for (family, key, _) in &plan.rows {
        batch.delete(family.column_family(), key);
    }
    for hash in &plan.dict_deletes {
        batch.delete(
            ColumnFamily::ScriptDict,
            &format::encode_script_dict_key(0, hash),
        );
    }
    for (script_id, remaining) in &plan.gen0_stats {
        let key = format::encode_script_stats_key(0, *script_id);
        match remaining {
            Some(stats) => batch.put(
                ColumnFamily::ScriptStats,
                &key,
                &format::encode_script_stats_value(stats),
            ),
            None => batch.delete(ColumnFamily::ScriptStats, &key),
        }
    }
    for key in &plan.log_keys {
        batch.delete(ColumnFamily::IdxMeta, key);
    }
}

const TAIL_SEALED: [IndexCapability; 3] = [
    IndexCapability::TxLookup,
    IndexCapability::ScriptHistory,
    IndexCapability::CompactFilters,
];

fn newest_tail_sealed(snapshot: &dyn KvSnapshot) -> Result<Option<SealedGen>, IndexError> {
    let mut newest: Option<SealedGen> = None;
    for capability in TAIL_SEALED {
        if let Some(sealed) = sealed_generations(snapshot, capability)?.last() {
            if newest.is_none_or(|current| sealed.gen_id > current.gen_id) {
                newest = Some(*sealed);
            }
        }
    }
    Ok(newest)
}

/// The generation id the next segment takes: the stored counter, or one past
/// the newest sealed tail-bound generation when the counter is behind.
pub fn next_gen_id(snapshot: &dyn KvSnapshot) -> Result<u64, IndexError> {
    let after_sealed =
        newest_tail_sealed(snapshot)?.map_or(1, |newest| newest.gen_id.saturating_add(1));
    let stored_next = snapshot
        .get(ColumnFamily::IdxMeta, crate::segment::SEAL_NEXT_GEN_KEY)?
        .and_then(|bytes| <[u8; 8]>::try_from(bytes.as_slice()).ok())
        .map_or(1, u64::from_le_bytes);
    Ok(stored_next.max(after_sealed))
}

/// Rebuilds the tail state from generation-0 rows, the undo logs, and the
/// sealed descriptors (`IndexWriter::open`).
pub fn load(snapshot: &dyn KvSnapshot) -> Result<TailWriterState, IndexError> {
    let sealed = sealed_generations(snapshot, IndexCapability::TxLookup)?;
    let mut state = TailWriterState {
        next_gen_id: next_gen_id(snapshot)?,
        sealed,
        ..TailWriterState::default()
    };

    let mut last_log: Option<(u32, Vec<u8>)> = None;
    for item in snapshot.iter_prefix(ColumnFamily::IdxMeta, LOG_PREFIX)? {
        let (key, value) = item?;
        let Some(height) = log_height(&key) else {
            continue;
        };
        let block_bytes = read_u64_le(&value, 36);
        let value_len = u64::try_from(value.len()).unwrap_or(u64::MAX);
        state.window.push_back(TailBlock {
            height,
            bytes: block_bytes.saturating_add(value_len),
        });
        state.next_ordinal = state.next_ordinal.max(read_u32_le(&value, 0));
        last_log = Some((height, value));
    }

    let gen0 = 0u64.to_be_bytes();
    let txid_gen0 = format::tx_dir_kind_prefix(0, format::TX_KIND_TXID);
    for item in snapshot.iter_prefix(ColumnFamily::TxDir, &txid_gen0)? {
        let (key, value) = item?;
        let (Some((_, txid, _)), Some((_, ordinal, _, _))) = (
            format::decode_tx_dir_key(&key),
            format::decode_tx_dir_value(&value),
        ) else {
            continue;
        };
        state.txid_to_ordinal.insert(txid, ordinal);
        state.next_ordinal = state.next_ordinal.max(ordinal.saturating_add(1));
    }
    for item in snapshot.iter_prefix(ColumnFamily::ScriptDict, &gen0)? {
        let (key, value) = item?;
        if let (Some((_, hash)), Some(id)) = (
            format::decode_script_dict_key(&key),
            format::decode_script_dict_value(&value),
        ) {
            state.script_id_map.insert(hash, id);
            state.next_script_id = state.next_script_id.max(id.saturating_add(1));
        }
    }
    for item in snapshot.iter_prefix(ColumnFamily::ScriptStats, &gen0)? {
        let (key, value) = item?;
        if let (Some((_, id)), Some(stats)) = (
            format::decode_script_stats_key(&key),
            format::decode_script_stats_value(&value),
        ) {
            state.script_stats.insert(id, stats);
        }
    }
    for item in snapshot.iter_prefix(ColumnFamily::ScriptPost, &gen0)? {
        let (key, _value) = item?;
        if let Some((_, id, chunk)) = format::decode_script_post_key(&key) {
            let slot = state.posting_slots.entry(id).or_insert(0);
            *slot = (*slot).max(chunk.saturating_add(1));
        }
    }

    match last_log {
        Some((height, value)) => {
            let mut log_hash = None;
            if let Some(ops) = parse_log(value.get(LOG_HEADER_LEN..).unwrap_or(&[])) {
                for op in ops {
                    if let LogOp::Hash { hash } = op {
                        log_hash = Some(hash);
                    }
                }
            }
            let hash = log_hash.ok_or(IndexError::CorruptTailLog { height })?;
            state.at = Some((height, hash));
        }
        None => {
            if let Some(newest) = newest_tail_sealed(snapshot)? {
                let last = newest.coverage.last_height;
                state.at = Some((last, newest.coverage.last_hash));
            }
        }
    }
    for capability in [IndexCapability::TxLookup, IndexCapability::ScriptHistory] {
        for generation in sealed_generations(snapshot, capability)? {
            state.next_ordinal = state.next_ordinal.max(generation.next_ordinal);
        }
    }
    state.prev_filter_header = filter_chain_head(snapshot)?;
    Ok(state)
}

fn read_u32_le(bytes: &[u8], at: usize) -> u32 {
    bytes
        .get(at..at + 4)
        .and_then(|slice| <[u8; 4]>::try_from(slice).ok())
        .map_or(0, u32::from_le_bytes)
}

fn read_u64_le(bytes: &[u8], at: usize) -> u64 {
    bytes
        .get(at..at + 8)
        .and_then(|slice| <[u8; 8]>::try_from(slice).ok())
        .map_or(0, u64::from_le_bytes)
}
fn log_hash_for(snapshot: &dyn KvSnapshot, height: u32) -> Result<[u8; 32], IndexError> {
    let key = log_key(height);
    let Some(value) = snapshot.get(ColumnFamily::IdxMeta, &key)? else {
        return Err(IndexError::CorruptTailLog { height });
    };
    let ops = parse_log(value.get(LOG_HEADER_LEN..).unwrap_or(&[]))
        .ok_or(IndexError::CorruptTailLog { height })?;
    for op in ops {
        if let LogOp::Hash { hash } = op {
            return Ok(hash);
        }
    }
    Err(IndexError::CorruptTailLog { height })
}

fn filter_chain_head(snapshot: &dyn KvSnapshot) -> Result<[u8; 32], IndexError> {
    let gen_zero = format::encode_filter_key(0, 0);
    let mut head = None;
    for item in snapshot.iter_prefix(ColumnFamily::Filters, &gen_zero[..8])? {
        let (_, value) = item?;
        if let Some((_, _, header, _)) = format::decode_filter_value(&value) {
            head = Some(header);
        }
    }
    if let Some(header) = head {
        return Ok(header);
    }
    let mut sealed: std::collections::BTreeMap<u64, u32> = std::collections::BTreeMap::new();
    for capability in TAIL_SEALED {
        for record in sealed_generations(snapshot, capability)? {
            sealed.insert(record.gen_id, record.coverage.last_height);
        }
    }
    for (gen_id, height) in sealed.iter().rev() {
        let key = format::encode_filter_key(*gen_id, *height);
        if let Some(value) = snapshot.get(ColumnFamily::Filters, &key)? {
            return Ok(
                format::decode_filter_value(&value).map_or([0u8; 32], |(_, _, header, _)| header)
            );
        }
    }
    Ok([0u8; 32])
}

/// Writes the `gen/<cap>` descriptor of every capability in `capabilities`
/// (`PRJ-05`, reader contract): the newest sealed generation plus the live
/// tail bounds. An empty tail encodes `tail_lo > tail_hi`.
pub fn put_generation_descriptors(
    batch: &mut BufferedWriteBatch,
    capabilities: impl IntoIterator<Item = IndexCapability>,
    bounds: TailBounds,
) {
    let hi = bounds.at.map_or(0, |(height, _)| height);
    let lo = bounds.first_height.unwrap_or_else(|| hi.saturating_add(1));
    let tail_hash = bounds.at.map_or([0u8; 32], |(_, hash)| hash);
    let (gen_id, coverage) = bounds.newest.map_or_else(
        || (0, Coverage::new(0, 0, [0u8; 32])),
        |newest| (newest.gen_id, newest.coverage),
    );
    let desc = super::GenerationDescriptor {
        gen_id,
        coverage,
        tail: super::TailDescriptor {
            tail_lo: lo,
            tail_hi: hi,
            tail_hash,
        },
    };
    for capability in capabilities {
        if capability == IndexCapability::ScriptLive {
            continue;
        }
        batch.put(
            ColumnFamily::IdxMeta,
            &super::meta_gen_key(capability),
            &super::IndexGeneration::encode_meta_value(&desc),
        );
    }
}
