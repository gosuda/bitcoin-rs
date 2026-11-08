pub mod bulk_builder;
pub mod format;
#[cfg(test)]
mod tests;

use crate::IndexCapability;
use sha2::Digest as _;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Coverage {
    pub first_height: u32,
    pub last_height: u32,
    pub last_hash: [u8; 32],
}

impl Coverage {
    #[must_use]
    pub const fn new(first_height: u32, last_height: u32, last_hash: [u8; 32]) -> Self {
        Self {
            first_height,
            last_height,
            last_hash,
        }
    }

    #[must_use]
    pub fn to_bytes(&self) -> [u8; 40] {
        let mut out = [0u8; 40];
        out[0..4].copy_from_slice(&self.first_height.to_le_bytes());
        out[4..8].copy_from_slice(&self.last_height.to_le_bytes());
        out[8..40].copy_from_slice(&self.last_hash);
        out
    }

    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 40 {
            return None;
        }
        let first_height = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
        let last_height = u32::from_le_bytes(bytes[4..8].try_into().ok()?);
        let mut last_hash = [0u8; 32];
        last_hash.copy_from_slice(&bytes[8..40]);
        Some(Self {
            first_height,
            last_height,
            last_hash,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TailDescriptor {
    pub tail_lo: u32,
    pub tail_hi: u32,
    pub tail_hash: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenerationDescriptor {
    pub gen_id: u64,
    pub coverage: Coverage,
    pub tail: TailDescriptor,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegmentRef {
    pub gen_id: u64,
    pub capability: IndexCapability,
    pub coverage: Coverage,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexGeneration {
    pub id: u64,
    pub segments: [Option<SegmentRef>; 4],
    pub tail: TailDescriptor,
}

impl IndexGeneration {
    pub const VALUE_LEN: usize = 88;

    #[must_use]
    pub fn encode_meta_value(desc: &GenerationDescriptor) -> [u8; Self::VALUE_LEN] {
        let mut out = [0u8; Self::VALUE_LEN];
        out[0..8].copy_from_slice(&desc.gen_id.to_le_bytes());
        out[8..48].copy_from_slice(&desc.coverage.to_bytes());
        out[48..52].copy_from_slice(&desc.tail.tail_lo.to_le_bytes());
        out[52..56].copy_from_slice(&desc.tail.tail_hi.to_le_bytes());
        out[56..88].copy_from_slice(&desc.tail.tail_hash);
        out
    }

    #[must_use]
    pub fn decode_meta_value(bytes: &[u8]) -> Option<GenerationDescriptor> {
        if bytes.len() < Self::VALUE_LEN {
            return None;
        }
        let gen_id = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
        let coverage = Coverage::from_bytes(&bytes[8..48])?;
        let tail_lo = u32::from_le_bytes(bytes[48..52].try_into().ok()?);
        let tail_hi = u32::from_le_bytes(bytes[52..56].try_into().ok()?);
        let mut tail_hash = [0u8; 32];
        tail_hash.copy_from_slice(&bytes[56..88]);
        Some(GenerationDescriptor {
            gen_id,
            coverage,
            tail: TailDescriptor {
                tail_lo,
                tail_hi,
                tail_hash,
            },
        })
    }
}

#[must_use]
pub fn meta_gen_key(capability: IndexCapability) -> Vec<u8> {
    let mut key = b"gen/".to_vec();
    key.extend_from_slice(capability.name().as_bytes());
    key
}

pub const SEAL_STAGING_KEY: &[u8] = b"seal/staging";
pub const SEAL_COMMITTED_KEY: &[u8] = b"seal/committed";

const RETIRE_TOMBSTONE_PREFIX: &[u8] = b"retire/";

const SEALED_FAMILIES: [bitcoin_rs_storage::ColumnFamily; 6] = [
    bitcoin_rs_storage::ColumnFamily::TxDir,
    bitcoin_rs_storage::ColumnFamily::ScriptDict,
    bitcoin_rs_storage::ColumnFamily::ScriptPost,
    bitcoin_rs_storage::ColumnFamily::SpendDir,
    bitcoin_rs_storage::ColumnFamily::ScriptStats,
    bitcoin_rs_storage::ColumnFamily::Filters,
];

/// Test-only fault injection points for the seal protocol; production code
/// never arms them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealFault {
    AfterStaging = 1,
    AfterIngest = 2,
    AfterCommitted = 3,
    AfterClear = 4,
    AfterPublish = 5,
}

impl SealFault {
    const fn code(self) -> u8 {
        match self {
            Self::AfterStaging => 1,
            Self::AfterIngest => 2,
            Self::AfterCommitted => 3,
            Self::AfterClear => 4,
            Self::AfterPublish => 5,
        }
    }
}

/// Test-only fault injection points for the retire protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetireFault {
    AfterTombstone = 1,
    AfterClear = 2,
    AfterDescriptor = 3,
}

impl RetireFault {
    const fn code(self) -> u8 {
        match self {
            Self::AfterTombstone => 1,
            Self::AfterClear => 2,
            Self::AfterDescriptor => 3,
        }
    }
}

thread_local! {
    static SEAL_FAULT: core::cell::Cell<u8> = const { core::cell::Cell::new(0) };
    static RETIRE_FAULT: core::cell::Cell<u8> = const { core::cell::Cell::new(0) };
}

pub fn arm_seal_fault(fault: Option<SealFault>) {
    let value = fault.map_or(0, SealFault::code);
    SEAL_FAULT.with(|cell| cell.set(value));
}

pub fn arm_retire_fault(fault: Option<RetireFault>) {
    let value = fault.map_or(0, RetireFault::code);
    RETIRE_FAULT.with(|cell| cell.set(value));
}

fn seal_fault(stage: SealFault) -> Result<(), crate::IndexError> {
    if SEAL_FAULT.with(core::cell::Cell::get) == stage.code() {
        return Err(crate::IndexError::InjectedFault { stage: "seal" });
    }
    Ok(())
}

fn retire_fault(stage: RetireFault) -> Result<(), crate::IndexError> {
    if RETIRE_FAULT.with(core::cell::Cell::get) == stage.code() {
        return Err(crate::IndexError::InjectedFault { stage: "retire" });
    }
    Ok(())
}

fn seal_marker_value(gen_id: u64, coverage: &Coverage) -> [u8; 48] {
    let mut out = [0u8; 48];
    out[..8].copy_from_slice(&gen_id.to_le_bytes());
    out[8..48].copy_from_slice(&coverage.to_bytes());
    out
}

fn decode_seal_marker(bytes: &[u8]) -> Option<(u64, Coverage)> {
    if bytes.len() < 48 {
        return None;
    }
    let gen_id = u64::from_le_bytes(bytes[..8].try_into().ok()?);
    let coverage = Coverage::from_bytes(&bytes[8..48])?;
    Some((gen_id, coverage))
}

fn retirement_families(capability: IndexCapability) -> &'static [bitcoin_rs_storage::ColumnFamily] {
    match capability {
        IndexCapability::TxLookup => &[bitcoin_rs_storage::ColumnFamily::TxDir],
        IndexCapability::ScriptHistory => &[
            bitcoin_rs_storage::ColumnFamily::ScriptDict,
            bitcoin_rs_storage::ColumnFamily::ScriptPost,
            bitcoin_rs_storage::ColumnFamily::SpendDir,
            bitcoin_rs_storage::ColumnFamily::ScriptStats,
        ],
        IndexCapability::ScriptLive => &[bitcoin_rs_storage::ColumnFamily::ScriptLive],
        IndexCapability::CompactFilters => &[bitcoin_rs_storage::ColumnFamily::Filters],
    }
}

fn retire_tombstone_key(capability: IndexCapability, gen_id: u64) -> Vec<u8> {
    let mut key = RETIRE_TOMBSTONE_PREFIX.to_vec();
    key.extend_from_slice(&gen_id.to_be_bytes());
    key.extend_from_slice(capability.name().as_bytes());
    key
}

fn decode_tombstone_key(key: &[u8]) -> Option<(Vec<u8>, u64, IndexCapability)> {
    let rest = key.strip_prefix(RETIRE_TOMBSTONE_PREFIX)?;
    if rest.len() < 9 {
        return None;
    }
    let gen_id = u64::from_be_bytes(rest[..8].try_into().ok()?);
    let name = core::str::from_utf8(&rest[8..]).ok()?;
    let capability = IndexCapability::ALL
        .into_iter()
        .find(|capability| capability.name() == name)?;
    Some((key.to_vec(), gen_id, capability))
}

// REO-04, REO-05
pub fn retire_generation<S: bitcoin_rs_storage::KvStore>(
    store: &S,
    capability: IndexCapability,
    gen_id: u64,
) -> Result<(), crate::IndexError> {
    let start = format::gen_prefix_start(gen_id);
    let end = format::gen_prefix_end(gen_id);

    let mut tombstone_batch = store.new_batch();
    tombstone_batch.put(
        bitcoin_rs_storage::ColumnFamily::IdxMeta,
        &retire_tombstone_key(capability, gen_id),
        &[],
    );
    store.write_durable(tombstone_batch)?;
    retire_fault(RetireFault::AfterTombstone)?;

    for &cf in retirement_families(capability) {
        store.delete_range(cf, &start, &end)?;
    }
    retire_fault(RetireFault::AfterClear)?;

    let mut batch = store.new_batch();
    batch.delete(
        bitcoin_rs_storage::ColumnFamily::IdxMeta,
        &meta_gen_key(capability),
    );
    batch.delete(
        bitcoin_rs_storage::ColumnFamily::IdxMeta,
        &retire_tombstone_key(capability, gen_id),
    );
    store.write_durable(batch)?;
    retire_fault(RetireFault::AfterDescriptor)?;

    Ok(())
}

#[derive(Default)]
pub struct TailWriterState {
    pub current_ordinal: u32,
    pub prev_filter_header: [u8; 32],
    pub txid_to_ordinal: hashbrown::HashMap<[u8; 32], u32>,
    pub script_id_map: hashbrown::HashMap<[u8; 32], u32>,
    pub script_stats: hashbrown::HashMap<u32, format::ScriptStats>,
    pub posting_slots: hashbrown::HashMap<u32, u32>,
}

impl TailWriterState {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

// PRJ-05
pub fn append_tail_block(
    batch: &mut bitcoin_rs_storage::BufferedWriteBatch,
    block: &bitcoin_rs_storage::committed_facts::CommittedBlock,
    state: &mut TailWriterState,
) {
    for tx in &block.txs {
        let ordinal = state.current_ordinal;
        state.current_ordinal = state.current_ordinal.saturating_add(1);
        state.txid_to_ordinal.insert(tx.txid, ordinal);

        let tx_key = format::encode_tx_dir_key(0, &tx.txid, block.height);
        let tx_val = format::encode_tx_dir_value(&block.hash, ordinal, tx.offset, tx.len);
        batch.put(bitcoin_rs_storage::ColumnFamily::TxDir, &tx_key, &tx_val);

        append_tail_inputs(batch, ordinal, &tx.inputs, state);
        append_tail_outputs(batch, ordinal, &tx.outputs, state);
    }

    append_tail_filter(batch, block, state);
}

fn append_tail_inputs(
    batch: &mut bitcoin_rs_storage::BufferedWriteBatch,
    spending_ordinal: u32,
    inputs: &[bitcoin_rs_storage::committed_facts::SpentPrevout],
    state: &mut TailWriterState,
) {
    for input in inputs {
        if input.txid == [0u8; 32] && input.vout == u32::MAX {
            continue;
        }
        if let Some(&creation_ord) = state.txid_to_ordinal.get(&input.txid) {
            let key = format::encode_spend_dir_key(0, creation_ord, input.vout);
            let val = format::encode_spend_dir_value(spending_ordinal);
            batch.put(bitcoin_rs_storage::ColumnFamily::SpendDir, &key, &val);
        }
        if !input.script.is_empty() {
            let hash: [u8; 32] = sha2::Sha256::digest(&input.script).into();
            let script_id = get_or_insert_tail_script_id(&hash, state, batch);
            record_tail_occurrence(
                batch,
                script_id,
                spending_ordinal,
                format::POSTING_FLAG_SPENDING,
                input.value,
                state,
            );
        }
    }
}

fn append_tail_outputs(
    batch: &mut bitcoin_rs_storage::BufferedWriteBatch,
    ordinal: u32,
    outputs: &[bitcoin_rs_storage::committed_facts::CreatedOutput],
    state: &mut TailWriterState,
) {
    for output in outputs {
        if !output.script.is_empty() && output.script[0] != 0x6a {
            let hash: [u8; 32] = sha2::Sha256::digest(&output.script).into();
            let script_id = get_or_insert_tail_script_id(&hash, state, batch);
            record_tail_occurrence(
                batch,
                script_id,
                ordinal,
                format::POSTING_FLAG_FUNDING,
                output.value,
                state,
            );
        }
    }
}

fn get_or_insert_tail_script_id(
    hash: &[u8; 32],
    state: &mut TailWriterState,
    batch: &mut bitcoin_rs_storage::BufferedWriteBatch,
) -> u32 {
    if let Some(&id) = state.script_id_map.get(hash) {
        id
    } else {
        let Ok(id) = u32::try_from(state.script_id_map.len()) else {
            return u32::MAX;
        };
        state.script_id_map.insert(*hash, id);
        let key = format::encode_script_dict_key(0, hash);
        let val = format::encode_script_dict_value(id);
        batch.put(bitcoin_rs_storage::ColumnFamily::ScriptDict, &key, &val);
        id
    }
}

fn record_tail_occurrence(
    batch: &mut bitcoin_rs_storage::BufferedWriteBatch,
    script_id: u32,
    ordinal: u32,
    flags: u8,
    sats: u64,
    state: &mut TailWriterState,
) {
    let slot = state.posting_slots.entry(script_id).or_insert(0);
    let post_key = format::encode_script_post_key(0, script_id, *slot);
    *slot = slot.saturating_add(1);
    let post_val = format::encode_posting_items(&[format::PostingItem {
        delta_ordinal: ordinal,
        flags,
    }]);
    batch.put(
        bitcoin_rs_storage::ColumnFamily::ScriptPost,
        &post_key,
        &post_val,
    );

    let stats = state.script_stats.entry(script_id).or_default();
    if flags == format::POSTING_FLAG_FUNDING {
        stats.funded_count = stats.funded_count.saturating_add(1);
        stats.funded_sats = stats.funded_sats.saturating_add(sats);
    } else {
        stats.spent_count = stats.spent_count.saturating_add(1);
        stats.spent_sats = stats.spent_sats.saturating_add(sats);
    }
    let stats_key = format::encode_script_stats_key(0, script_id);
    let stats_val = format::encode_script_stats_value(stats);
    batch.put(
        bitcoin_rs_storage::ColumnFamily::ScriptStats,
        &stats_key,
        &stats_val,
    );
}

fn append_tail_filter(
    batch: &mut bitcoin_rs_storage::BufferedWriteBatch,
    block: &bitcoin_rs_storage::committed_facts::CommittedBlock,
    state: &mut TailWriterState,
) {
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
    batch.put(bitcoin_rs_storage::ColumnFamily::Filters, &key, &val);
}

fn seal_rekey_simple_family(
    snapshot: &dyn bitcoin_rs_storage::KvSnapshot,
    cf: bitcoin_rs_storage::ColumnFamily,
    gen_id: u64,
) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut rows = Vec::new();
    let tail_prefix = 0u64.to_be_bytes();
    let gen_prefix = gen_id.to_be_bytes();
    let Ok(iter) = snapshot.iter_prefix(cf, &tail_prefix) else {
        return rows;
    };
    for item in iter {
        let Ok((mut k, v)) = item else {
            continue;
        };
        if k.len() >= 8 {
            k[..8].copy_from_slice(&gen_prefix);
            rows.push((k, v));
        }
    }
    rows
}

struct SealedScripts {
    dict_rows: Vec<(Vec<u8>, Vec<u8>)>,
    post_rows: Vec<(Vec<u8>, Vec<u8>)>,
    stats_rows: Vec<(Vec<u8>, Vec<u8>)>,
}

fn seal_repack_scripts(
    snapshot: &dyn bitcoin_rs_storage::KvSnapshot,
    gen_id: u64,
) -> SealedScripts {
    let tail_prefix = 0u64.to_be_bytes();
    let mut old_to_new_id = hashbrown::HashMap::<u32, u32>::new();
    let mut dict_rows = Vec::new();

    if let Ok(iter) =
        snapshot.iter_prefix(bitcoin_rs_storage::ColumnFamily::ScriptDict, &tail_prefix)
    {
        for (dense_idx, item) in iter.enumerate() {
            let Ok((k, v)) = item else {
                continue;
            };
            if k.len() >= 8 {
                let Ok(new_id) = u32::try_from(dense_idx) else {
                    continue;
                };
                if let Some(old_id) = format::decode_script_dict_value(&v) {
                    old_to_new_id.insert(old_id, new_id);
                }
                let mut new_key = k;
                new_key[..8].copy_from_slice(&gen_id.to_be_bytes());
                dict_rows.push((new_key, format::encode_script_dict_value(new_id).to_vec()));
            }
        }
    }

    let mut stats_rows = Vec::new();
    if let Ok(iter) =
        snapshot.iter_prefix(bitcoin_rs_storage::ColumnFamily::ScriptStats, &tail_prefix)
    {
        for item in iter {
            let Ok((k, v)) = item else {
                continue;
            };
            if let Some((_, old_id)) = format::decode_script_stats_key(&k) {
                if let Some(&new_id) = old_to_new_id.get(&old_id) {
                    let new_key = format::encode_script_stats_key(gen_id, new_id);
                    stats_rows.push((new_key.to_vec(), v));
                }
            }
        }
    }

    let mut occurrences_by_new_id = hashbrown::HashMap::<u32, Vec<format::PostingItem>>::new();
    if let Ok(iter) =
        snapshot.iter_prefix(bitcoin_rs_storage::ColumnFamily::ScriptPost, &tail_prefix)
    {
        for item in iter {
            let Ok((k, v)) = item else {
                continue;
            };
            if let Some((_, old_id, _)) = format::decode_script_post_key(&k) {
                if let Some(&new_id) = old_to_new_id.get(&old_id) {
                    if let Some(items) = format::decode_posting_items(&v) {
                        occurrences_by_new_id
                            .entry(new_id)
                            .or_default()
                            .extend(items);
                    }
                }
            }
        }
    }

    let mut post_rows = Vec::new();
    for (new_id, mut items) in occurrences_by_new_id {
        items.sort_unstable_by_key(|it| it.delta_ordinal);
        let mut repacked_items = Vec::with_capacity(items.len());
        let mut last_ordinal = 0u32;
        for it in items {
            let ordinal = it.delta_ordinal;
            let delta = ordinal.saturating_sub(last_ordinal);
            last_ordinal = ordinal;
            repacked_items.push(format::PostingItem {
                delta_ordinal: delta,
                flags: it.flags,
            });
        }

        post_rows.extend(format::chunk_postings(gen_id, new_id, repacked_items));
    }

    SealedScripts {
        dict_rows,
        post_rows,
        stats_rows,
    }
}

// PRJ-05, PRJ-09
pub fn seal_tail_generation<S: bitcoin_rs_storage::KvStore>(
    store: &S,
    gen_id: u64,
    coverage: Coverage,
    scratch: &std::path::Path,
) -> Result<(), crate::IndexError> {
    let snapshot = store.snapshot().map_err(crate::IndexError::Storage)?;

    let mut tx_dir_rows = seal_rekey_simple_family(
        snapshot.as_ref(),
        bitcoin_rs_storage::ColumnFamily::TxDir,
        gen_id,
    );
    let mut spend_dir_rows = seal_rekey_simple_family(
        snapshot.as_ref(),
        bitcoin_rs_storage::ColumnFamily::SpendDir,
        gen_id,
    );
    let mut filter_rows = seal_rekey_simple_family(
        snapshot.as_ref(),
        bitcoin_rs_storage::ColumnFamily::Filters,
        gen_id,
    );

    let sealed_scripts = seal_repack_scripts(snapshot.as_ref(), gen_id);
    let mut dict_rows = sealed_scripts.dict_rows;
    let mut post_rows = sealed_scripts.post_rows;
    let mut stats_rows = sealed_scripts.stats_rows;
    drop(snapshot);

    tx_dir_rows.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    spend_dir_rows.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    filter_rows.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    dict_rows.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    post_rows.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    stats_rows.sort_unstable_by(|a, b| a.0.cmp(&b.0));

    let mut staging_batch = store.new_batch();
    staging_batch.put(
        bitcoin_rs_storage::ColumnFamily::IdxMeta,
        SEAL_STAGING_KEY,
        &seal_marker_value(gen_id, &coverage),
    );
    store.write_durable(staging_batch)?;
    seal_fault(SealFault::AfterStaging)?;

    ingest_family_rows(
        store,
        bitcoin_rs_storage::ColumnFamily::TxDir,
        tx_dir_rows,
        scratch,
    )?;
    ingest_family_rows(
        store,
        bitcoin_rs_storage::ColumnFamily::SpendDir,
        spend_dir_rows,
        scratch,
    )?;
    ingest_family_rows(
        store,
        bitcoin_rs_storage::ColumnFamily::Filters,
        filter_rows,
        scratch,
    )?;
    ingest_family_rows(
        store,
        bitcoin_rs_storage::ColumnFamily::ScriptDict,
        dict_rows,
        scratch,
    )?;
    ingest_family_rows(
        store,
        bitcoin_rs_storage::ColumnFamily::ScriptPost,
        post_rows,
        scratch,
    )?;
    ingest_family_rows(
        store,
        bitcoin_rs_storage::ColumnFamily::ScriptStats,
        stats_rows,
        scratch,
    )?;
    seal_fault(SealFault::AfterIngest)?;

    let mut committed_batch = store.new_batch();
    committed_batch.put(
        bitcoin_rs_storage::ColumnFamily::IdxMeta,
        SEAL_COMMITTED_KEY,
        &seal_marker_value(gen_id, &coverage),
    );
    store.write_durable(committed_batch)?;
    seal_fault(SealFault::AfterCommitted)?;

    clear_tail(store)?;
    seal_fault(SealFault::AfterClear)?;
    publish_descriptors(store, gen_id, coverage)?;
    seal_fault(SealFault::AfterPublish)?;
    remove_seal_markers(store)?;
    Ok(())
}

fn clear_tail<S: bitcoin_rs_storage::KvStore>(store: &S) -> Result<(), crate::IndexError> {
    let start = 0u64.to_be_bytes();
    let end = 1u64.to_be_bytes();
    for &cf in &SEALED_FAMILIES {
        store.delete_range(cf, &start, &end)?;
    }
    Ok(())
}

fn publish_descriptors<S: bitcoin_rs_storage::KvStore>(
    store: &S,
    gen_id: u64,
    coverage: Coverage,
) -> Result<(), crate::IndexError> {
    let desc = GenerationDescriptor {
        gen_id,
        coverage,
        tail: TailDescriptor {
            tail_lo: coverage.last_height.saturating_add(1),
            tail_hi: coverage.last_height,
            tail_hash: coverage.last_hash,
        },
    };
    let mut batch = store.new_batch();
    for cap in IndexCapability::ALL {
        batch.put(
            bitcoin_rs_storage::ColumnFamily::IdxMeta,
            &meta_gen_key(cap),
            &IndexGeneration::encode_meta_value(&desc),
        );
    }
    store
        .write_durable(batch)
        .map_err(crate::IndexError::Storage)
}

fn remove_seal_markers<S: bitcoin_rs_storage::KvStore>(store: &S) -> Result<(), crate::IndexError> {
    let mut batch = store.new_batch();
    batch.delete(bitcoin_rs_storage::ColumnFamily::IdxMeta, SEAL_STAGING_KEY);
    batch.delete(
        bitcoin_rs_storage::ColumnFamily::IdxMeta,
        SEAL_COMMITTED_KEY,
    );
    store
        .write_durable(batch)
        .map_err(crate::IndexError::Storage)
}

/// Completes or rolls back an interrupted seal, then finishes any
/// tombstoned retirement. A seal staged without its committed marker rolls
/// back to the intact tail; once the committed marker exists the sealed
/// rows win and the tail clears, descriptors publish, and markers remove.
// PRJ-05, REO-04
pub fn recover_segments<S: bitcoin_rs_storage::KvStore>(
    store: &S,
) -> Result<(), crate::IndexError> {
    let snapshot = store.snapshot().map_err(crate::IndexError::Storage)?;
    let staging = snapshot
        .get(bitcoin_rs_storage::ColumnFamily::IdxMeta, SEAL_STAGING_KEY)?
        .filter(|bytes| bytes.len() >= 48);
    let committed = snapshot
        .get(
            bitcoin_rs_storage::ColumnFamily::IdxMeta,
            SEAL_COMMITTED_KEY,
        )?
        .filter(|bytes| bytes.len() >= 48);
    drop(snapshot);

    let staged = staging.as_deref().map_or_else(
        || Err(crate::IndexError::InvalidSealMarker),
        |bytes| decode_seal_marker(bytes).ok_or(crate::IndexError::InvalidSealMarker),
    );
    if let Some(bytes) = committed.as_deref() {
        let (gen_id, coverage) =
            decode_seal_marker(bytes).ok_or(crate::IndexError::InvalidSealMarker)?;
        complete_seal(store, gen_id, coverage)?;
        if staged.is_err() {
            return Err(crate::IndexError::InvalidSealMarker);
        }
    } else if let Ok((gen_id, _coverage)) = staged {
        rollback_seal(store, gen_id)?;
    }
    recover_retirements(store)
}

fn complete_seal<S: bitcoin_rs_storage::KvStore>(
    store: &S,
    gen_id: u64,
    coverage: Coverage,
) -> Result<(), crate::IndexError> {
    clear_tail(store)?;
    publish_descriptors(store, gen_id, coverage)?;
    remove_seal_markers(store)
}

fn rollback_seal<S: bitcoin_rs_storage::KvStore>(
    store: &S,
    gen_id: u64,
) -> Result<(), crate::IndexError> {
    let start = format::gen_prefix_start(gen_id);
    let end = format::gen_prefix_end(gen_id);
    for &cf in &SEALED_FAMILIES {
        store.delete_range(cf, &start, &end)?;
    }
    let mut batch = store.new_batch();
    batch.delete(bitcoin_rs_storage::ColumnFamily::IdxMeta, SEAL_STAGING_KEY);
    store
        .write_durable(batch)
        .map_err(crate::IndexError::Storage)
}

fn recover_retirements<S: bitcoin_rs_storage::KvStore>(store: &S) -> Result<(), crate::IndexError> {
    let snapshot = store.snapshot().map_err(crate::IndexError::Storage)?;
    let mut tombstones = Vec::new();
    for item in snapshot.iter_prefix(
        bitcoin_rs_storage::ColumnFamily::IdxMeta,
        RETIRE_TOMBSTONE_PREFIX,
    )? {
        let (key, _value) = item?;
        if let Some((key, gen_id, capability)) = decode_tombstone_key(&key) {
            tombstones.push((key, gen_id, capability));
        }
    }
    drop(snapshot);

    for (key, gen_id, capability) in tombstones {
        let start = format::gen_prefix_start(gen_id);
        let end = format::gen_prefix_end(gen_id);
        for &cf in retirement_families(capability) {
            store.delete_range(cf, &start, &end)?;
        }
        let mut batch = store.new_batch();
        batch.delete(
            bitcoin_rs_storage::ColumnFamily::IdxMeta,
            &meta_gen_key(capability),
        );
        batch.delete(bitcoin_rs_storage::ColumnFamily::IdxMeta, &key);
        store.write_durable(batch)?;
    }
    Ok(())
}

fn ingest_family_rows<S: bitcoin_rs_storage::KvStore>(
    store: &S,
    cf: bitcoin_rs_storage::ColumnFamily,
    rows: Vec<(Vec<u8>, Vec<u8>)>,
    scratch: &std::path::Path,
) -> Result<(), crate::IndexError> {
    let mut row_iter = rows.into_iter();
    store
        .ingest_sorted(cf, &mut row_iter, scratch)
        .map_err(crate::IndexError::Storage)?;
    Ok(())
}
