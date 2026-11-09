//! Mutable tail: generation-0 rows for heights above the newest sealed
//! generation (PRJ-05). Each forward block appends its rows and one undo log
//! to the caller's batch, so tail rows and the watermark publish together. A
//! shallow reorg replays the log backwards in the batch that rewinds the
//! watermark.

use super::format::{self, PostingItem, ScriptStats};
use super::{Coverage, SealedGen, sealed_generations};
use crate::{IndexCapability, IndexError};
use bitcoin_rs_storage::committed_facts::{CommittedBlock, CreatedOutput, SpentPrevout};
use bitcoin_rs_storage::{BufferedWriteBatch, ColumnFamily, KvSnapshot};
use sha2::Digest as _;

/// Key prefix of one undo log per tail block: `tail/log/` || height BE4.
pub(crate) const LOG_PREFIX: &[u8] = b"tail/log/";
/// Exclusive end of the `tail/log/` key range.
pub(crate) const LOG_END: &[u8] = b"tail/log0";
/// Log value header: next ordinal LE4 || filter header 32.
const LOG_HEADER_LEN: usize = 36;

/// Tail families in undo-log codes. Only these families carry tail rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    TxDir,
    ScriptDict,
    ScriptPost,
    SpendDir,
    ScriptStats,
    Filters,
}

impl Family {
    const fn column_family(self) -> ColumnFamily {
        match self {
            Self::TxDir => ColumnFamily::TxDir,
            Self::ScriptDict => ColumnFamily::ScriptDict,
            Self::ScriptPost => ColumnFamily::ScriptPost,
            Self::SpendDir => ColumnFamily::SpendDir,
            Self::ScriptStats => ColumnFamily::ScriptStats,
            Self::Filters => ColumnFamily::Filters,
        }
    }

    const fn code(self) -> u8 {
        match self {
            Self::TxDir => 0,
            Self::ScriptDict => 1,
            Self::ScriptPost => 2,
            Self::SpendDir => 3,
            Self::ScriptStats => 4,
            Self::Filters => 5,
        }
    }

    const fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            0 => Self::TxDir,
            1 => Self::ScriptDict,
            2 => Self::ScriptPost,
            3 => Self::SpendDir,
            4 => Self::ScriptStats,
            5 => Self::Filters,
            _ => return None,
        })
    }
}

/// In-memory view of the tail, rebuilt from generation-0 rows after restart
/// and kept in step with every committed append.
#[derive(Clone, Debug, Default)]
pub struct TailWriterState {
    /// Watermark height and hash the state describes.
    pub at: Option<(u32, [u8; 32])>,
    /// Lowest tail height; `None` when the tail holds no blocks.
    pub first_height: Option<u32>,
    /// Chain-global ordinal of the next transaction.
    pub next_ordinal: u32,
    pub prev_filter_header: [u8; 32],
    pub txid_to_ordinal: hashbrown::HashMap<[u8; 32], u32>,
    pub script_id_map: hashbrown::HashMap<[u8; 32], u32>,
    pub script_stats: hashbrown::HashMap<u32, ScriptStats>,
    pub posting_slots: hashbrown::HashMap<u32, u32>,
    pub tail_blocks: u32,
    pub tail_bytes: u64,
    /// Sealed generations of the index, ascending by generation id.
    pub sealed: Vec<SealedGen>,
    pub next_gen_id: u64,
}

impl TailWriterState {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The newest sealed generation, if any.
    #[must_use]
    pub fn newest(&self) -> Option<SealedGen> {
        self.sealed.last().copied()
    }

    /// Descriptor bounds for the current tail.
    #[must_use]
    pub fn bounds(&self) -> TailBounds {
        TailBounds {
            newest: self.newest(),
            first_height: self.first_height,
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
            let mut prefix = sealed.gen_id.to_be_bytes().to_vec();
            prefix.extend_from_slice(txid);
            for item in self.snapshot.iter_prefix(ColumnFamily::TxDir, &prefix)? {
                let (key, value) = item?;
                if key.len() != format::TX_DIR_KEY_LEN {
                    continue;
                }
                if let Some((_, ordinal, _, _)) = format::decode_tx_dir_value(&value) {
                    return Ok(Some(ordinal));
                }
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

/// Undo-log recorder: writes each row and the prior value it replaces.
struct Recorder<'a> {
    batch: &'a mut BufferedWriteBatch,
    log: Vec<u8>,
}

impl Recorder<'_> {
    fn put(&mut self, family: Family, key: &[u8], value: &[u8], prior: Option<&[u8]>) {
        self.batch.put(family.column_family(), key, value);
        self.log.push(family.code());
        self.log.push(u8::from(prior.is_some()));
        push_len_prefixed(&mut self.log, key);
        if let Some(prior) = prior {
            push_len_prefixed(&mut self.log, prior);
        }
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

fn log_height(key: &[u8]) -> Option<u32> {
    let rest = key.strip_prefix(LOG_PREFIX)?;
    Some(u32::from_be_bytes(rest.try_into().ok()?))
}

/// Appends one committed block to the tail (PRJ-05). Rows, the undo log, and
/// the state advance together; the caller commits the batch.
pub fn append_tail_block(
    batch: &mut BufferedWriteBatch,
    block: &CommittedBlock,
    state: &mut TailWriterState,
    older: &dyn CreationOrdinals,
) -> Result<(), IndexError> {
    let mut rec = Recorder {
        batch,
        log: Vec::new(),
    };
    for tx in &block.txs {
        let ordinal = state.next_ordinal;
        state.next_ordinal = state.next_ordinal.saturating_add(1);
        state.txid_to_ordinal.insert(tx.txid, ordinal);

        let tx_key = format::encode_tx_dir_key(0, &tx.txid, block.height);
        let tx_val = format::encode_tx_dir_value(&block.hash, ordinal, tx.offset, tx.len);
        rec.put(Family::TxDir, &tx_key, &tx_val, None);
        let rev_key = format::encode_tx_ordinal_key(0, ordinal);
        let rev_val = format::encode_tx_ordinal_value(&tx.txid, block.height, tx.offset, tx.len);
        rec.put(Family::TxDir, &rev_key, &rev_val, None);

        append_inputs(&mut rec, ordinal, &tx.inputs, state, older)?;
        append_outputs(&mut rec, ordinal, &tx.outputs, state);
    }
    append_filter(&mut rec, block, state);

    let mut value = Vec::with_capacity(LOG_HEADER_LEN + rec.log.len());
    value.extend_from_slice(&state.next_ordinal.to_le_bytes());
    value.extend_from_slice(&state.prev_filter_header);
    value.extend_from_slice(&rec.log);
    rec.batch
        .put(ColumnFamily::IdxMeta, &log_key(block.height), &value);

    state.tail_blocks = state.tail_blocks.saturating_add(1);
    state.tail_bytes = state
        .tail_bytes
        .saturating_add(u64::try_from(value.len()).unwrap_or(u64::MAX));
    state.first_height.get_or_insert(block.height);
    state.at = Some((block.height, block.hash));
    Ok(())
}

fn append_inputs(
    rec: &mut Recorder<'_>,
    spending_ordinal: u32,
    inputs: &[SpentPrevout],
    state: &mut TailWriterState,
    older: &dyn CreationOrdinals,
) -> Result<(), IndexError> {
    for input in inputs {
        if input.txid == [0u8; 32] && input.vout == u32::MAX {
            continue;
        }
        let creation = match state.txid_to_ordinal.get(&input.txid) {
            Some(&ordinal) => Some(ordinal),
            None => older.creation_ordinal(&input.txid)?,
        };
        if let Some(creation_ord) = creation {
            let key = format::encode_spend_dir_key(0, creation_ord, input.vout);
            let val = format::encode_spend_dir_value(spending_ordinal);
            rec.put(Family::SpendDir, &key, &val, None);
        }
        if !input.script.is_empty() {
            let hash: [u8; 32] = sha2::Sha256::digest(&input.script).into();
            let script_id = script_id_for(rec, &hash, state);
            record_occurrence(
                rec,
                script_id,
                spending_ordinal,
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
    ordinal: u32,
    outputs: &[CreatedOutput],
    state: &mut TailWriterState,
) {
    for output in outputs {
        if !output.script.is_empty() && output.script[0] != 0x6a {
            let hash: [u8; 32] = sha2::Sha256::digest(&output.script).into();
            let script_id = script_id_for(rec, &hash, state);
            record_occurrence(
                rec,
                script_id,
                ordinal,
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
    let Ok(id) = u32::try_from(state.script_id_map.len()) else {
        return u32::MAX;
    };
    state.script_id_map.insert(*hash, id);
    rec.put(
        Family::ScriptDict,
        &format::encode_script_dict_key(0, hash),
        &format::encode_script_dict_value(id),
        None,
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
    rec.put(Family::ScriptPost, &post_key, &post_val, None);

    let prior = state.script_stats.get(&script_id).copied();
    let mut stats = prior.unwrap_or_default();
    if flags == format::POSTING_FLAG_FUNDING {
        stats.funded_count = stats.funded_count.saturating_add(1);
        stats.funded_sats = stats.funded_sats.saturating_add(sats);
    } else {
        stats.spent_count = stats.spent_count.saturating_add(1);
        stats.spent_sats = stats.spent_sats.saturating_add(sats);
    }
    let stats_key = format::encode_script_stats_key(0, script_id);
    let stats_val = format::encode_script_stats_value(&stats);
    let prior_val = prior.map(|old| format::encode_script_stats_value(&old));
    rec.put(
        Family::ScriptStats,
        &stats_key,
        &stats_val,
        prior_val
            .as_ref()
            .map(<[u8; format::SCRIPT_STATS_VALUE_LEN]>::as_slice),
    );
    state.script_stats.insert(script_id, stats);
}

fn append_filter(rec: &mut Recorder<'_>, block: &CommittedBlock, state: &mut TailWriterState) {
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
    let filter_hash =
        bitcoin_rs_consensus::primitives::encode::double_sha256(&filter_bytes).to_le_bytes();
    let mut hdr_in = [0u8; 64];
    hdr_in[..32].copy_from_slice(&filter_hash);
    hdr_in[32..].copy_from_slice(&state.prev_filter_header);
    let header = bitcoin_rs_consensus::primitives::encode::double_sha256(&hdr_in).to_le_bytes();
    state.prev_filter_header = header;

    let key = format::encode_filter_key(0, block.height);
    let val = format::encode_filter_value(&block.hash, &filter_hash, &header, &filter_bytes);
    rec.put(Family::Filters, &key, &val, None);
}

/// Replays the undo log of `height` backwards into `batch` and deletes the
/// log row. Returns `false` when the tail holds no block at `height`.
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
    for (family, row_key, prior) in ops.iter().rev() {
        match prior {
            Some(prior) => batch.put(family.column_family(), row_key, prior),
            None => batch.delete(family.column_family(), row_key),
        }
    }
    batch.delete(ColumnFamily::IdxMeta, &key);
    Ok(true)
}

type LogOp = (Family, Vec<u8>, Option<Vec<u8>>);

fn parse_log(mut bytes: &[u8]) -> Option<Vec<LogOp>> {
    let mut ops = Vec::new();
    while let Some((&code, rest)) = bytes.split_first() {
        let family = Family::from_code(code)?;
        let (&has_prior, rest) = rest.split_first()?;
        let (key, rest) = take_len_prefixed(rest)?;
        let (prior, rest) = if has_prior == 1 {
            let (prior, rest) = take_len_prefixed(rest)?;
            (Some(prior.to_vec()), rest)
        } else {
            (None, rest)
        };
        ops.push((family, key.to_vec(), prior));
        bytes = rest;
    }
    Some(ops)
}

fn take_len_prefixed(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let len = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?);
    let len = usize::try_from(len).ok()?;
    let body = bytes.get(4..)?;
    Some((body.get(..len)?, body.get(len..)?))
}

/// The generation id the next segment takes: the stored counter, or one past
/// the newest sealed TxLookup generation when the counter is behind.
pub fn next_gen_id(snapshot: &dyn KvSnapshot) -> Result<u64, IndexError> {
    let sealed = sealed_generations(snapshot, IndexCapability::TxLookup)?;
    let stored_next = snapshot
        .get(ColumnFamily::IdxMeta, crate::segment::SEAL_NEXT_GEN_KEY)?
        .and_then(|bytes| <[u8; 8]>::try_from(bytes.as_slice()).ok())
        .map_or(1, u64::from_le_bytes);
    let after_sealed = sealed
        .last()
        .map_or(1, |newest| newest.gen_id.saturating_add(1));
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
        state.tail_blocks = state.tail_blocks.saturating_add(1);
        state.tail_bytes = state
            .tail_bytes
            .saturating_add(u64::try_from(value.len()).unwrap_or(u64::MAX));
        state.first_height.get_or_insert(height);
        last_log = Some((height, value));
    }

    let gen0 = 0u64.to_be_bytes();
    for item in snapshot.iter_prefix(ColumnFamily::TxDir, &gen0)? {
        let (key, value) = item?;
        if key.len() != format::TX_DIR_KEY_LEN {
            continue;
        }
        let (Some((_, txid, _)), Some((_, ordinal, _, _))) = (
            format::decode_tx_dir_key(&key),
            format::decode_tx_dir_value(&value),
        ) else {
            continue;
        };
        state.txid_to_ordinal.insert(txid, ordinal);
    }
    for item in snapshot.iter_prefix(ColumnFamily::ScriptDict, &gen0)? {
        let (key, value) = item?;
        if let (Some((_, hash)), Some(id)) = (
            format::decode_script_dict_key(&key),
            format::decode_script_dict_value(&value),
        ) {
            state.script_id_map.insert(hash, id);
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
            state.next_ordinal = read_u32_le(&value, 0);
            state.prev_filter_header = read_hash(&value, 4);
            state.at = filter_block_hash(snapshot, 0, height)?.map(|hash| (height, hash));
        }
        None => {
            if let Some(newest) = state.newest() {
                let last = newest.coverage.last_height;
                state.next_ordinal = newest.next_ordinal;
                state.at = Some((last, newest.coverage.last_hash));
                state.prev_filter_header = filter_header(snapshot, newest.gen_id, last)?;
            }
        }
    }
    Ok(state)
}

fn read_u32_le(bytes: &[u8], at: usize) -> u32 {
    bytes
        .get(at..at + 4)
        .and_then(|slice| <[u8; 4]>::try_from(slice).ok())
        .map_or(0, u32::from_le_bytes)
}

fn read_hash(bytes: &[u8], at: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    if let Some(slice) = bytes.get(at..at + 32) {
        out.copy_from_slice(slice);
    }
    out
}

fn filter_block_hash(
    snapshot: &dyn KvSnapshot,
    gen_id: u64,
    height: u32,
) -> Result<Option<[u8; 32]>, IndexError> {
    let key = format::encode_filter_key(gen_id, height);
    let Some(value) = snapshot.get(ColumnFamily::Filters, &key)? else {
        return Ok(None);
    };
    Ok(format::decode_filter_value(&value).map(|(hash, _, _, _)| hash))
}

fn filter_header(
    snapshot: &dyn KvSnapshot,
    gen_id: u64,
    height: u32,
) -> Result<[u8; 32], IndexError> {
    let key = format::encode_filter_key(gen_id, height);
    let Some(value) = snapshot.get(ColumnFamily::Filters, &key)? else {
        return Ok([0u8; 32]);
    };
    Ok(format::decode_filter_value(&value).map_or([0u8; 32], |(_, _, header, _)| header))
}

/// Pops the top tail block from the in-memory state after its log is
/// unwound. Callers drop the cached state after the batch commits.
pub fn bounds_after_unwind(state: &TailWriterState, height: u32, hash: [u8; 32]) -> TailBounds {
    let first_height = if state.tail_blocks > 1 {
        state.first_height
    } else {
        None
    };
    let at = height.checked_sub(1).map(|prev| (prev, hash));
    TailBounds {
        newest: state.newest(),
        first_height,
        at,
    }
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
