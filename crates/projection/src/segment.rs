pub mod bulk_builder;
pub mod format;
pub mod tail;
pub use tail::{
    CreationOrdinals, NoSealedTxOrdinals, SealedTxOrdinals, TailWriterState, append_tail_block,
};
#[cfg(test)]
mod tests;

use crate::{IndexCapabilities, IndexCapability};

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

/// One sealed segment of a capability (`PRJ-05`): its coverage and the first
/// chain-global ordinal after it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SealedGen {
    pub gen_id: u64,
    pub coverage: Coverage,
    pub next_ordinal: u32,
}

/// Length of a sealed segment record: coverage (40) plus next ordinal (4).
pub const SEALED_RECORD_LEN: usize = 44;

#[must_use]
pub fn sealed_gen_prefix(capability: IndexCapability) -> Vec<u8> {
    let mut key = b"gen/".to_vec();
    key.extend_from_slice(capability.name().as_bytes());
    key.push(b'/');
    key
}

#[must_use]
pub fn sealed_gen_key(capability: IndexCapability, gen_id: u64) -> Vec<u8> {
    let mut key = sealed_gen_prefix(capability);
    key.extend_from_slice(&gen_id.to_be_bytes());
    key
}

#[must_use]
pub fn encode_sealed_gen(sealed: &SealedGen) -> [u8; SEALED_RECORD_LEN] {
    let mut out = [0u8; SEALED_RECORD_LEN];
    out[..40].copy_from_slice(&sealed.coverage.to_bytes());
    out[40..44].copy_from_slice(&sealed.next_ordinal.to_le_bytes());
    out
}

fn decode_sealed_gen(gen_id: u64, bytes: &[u8]) -> Option<SealedGen> {
    if bytes.len() < SEALED_RECORD_LEN {
        return None;
    }
    Some(SealedGen {
        gen_id,
        coverage: Coverage::from_bytes(&bytes[..40])?,
        next_ordinal: u32::from_le_bytes(bytes[40..44].try_into().ok()?),
    })
}

/// Sealed segments of `capability`, ascending by generation id.
pub fn sealed_generations(
    snapshot: &dyn bitcoin_rs_storage::KvSnapshot,
    capability: IndexCapability,
) -> Result<Vec<SealedGen>, crate::IndexError> {
    let prefix = sealed_gen_prefix(capability);
    let mut out = Vec::new();
    for item in snapshot.iter_prefix(bitcoin_rs_storage::ColumnFamily::IdxMeta, &prefix)? {
        let (key, value) = item?;
        let Some(id_bytes) = key.get(prefix.len()..) else {
            continue;
        };
        let Ok(id_array) = <[u8; 8]>::try_from(id_bytes) else {
            continue;
        };
        if let Some(sealed) = decode_sealed_gen(u64::from_be_bytes(id_array), &value) {
            out.push(sealed);
        }
    }
    out.sort_unstable_by_key(|sealed| sealed.gen_id);
    Ok(out)
}

pub const SEAL_STAGING_KEY: &[u8] = b"seal/staging";
pub const SEAL_COMMITTED_KEY: &[u8] = b"seal/committed";
pub const SEAL_NEXT_GEN_KEY: &[u8] = b"seal/next_gen";

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

const SEAL_MARKER_LEN: usize = 53;

fn seal_marker_value(
    gen_id: u64,
    coverage: &Coverage,
    capabilities: IndexCapabilities,
    next_ordinal: u32,
) -> [u8; SEAL_MARKER_LEN] {
    let mut out = [0u8; SEAL_MARKER_LEN];
    out[..8].copy_from_slice(&gen_id.to_le_bytes());
    out[8..48].copy_from_slice(&coverage.to_bytes());
    out[48] = capabilities.to_mask();
    out[49..53].copy_from_slice(&next_ordinal.to_le_bytes());
    out
}

fn decode_seal_marker(bytes: &[u8]) -> Option<(u64, Coverage, IndexCapabilities, u32)> {
    if bytes.len() < SEAL_MARKER_LEN {
        return None;
    }
    let gen_id = u64::from_le_bytes(bytes[..8].try_into().ok()?);
    let coverage = Coverage::from_bytes(&bytes[8..48])?;
    let capabilities = IndexCapabilities::from_mask(bytes[48]).ok()?;
    let next_ordinal = u32::from_le_bytes(bytes[49..53].try_into().ok()?);
    Some((gen_id, coverage, capabilities, next_ordinal))
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

/// Marker-first retirement of one sealed segment: the tombstone is durable
/// before any row clears, so recovery finishes an interrupted retirement on
/// open. Rows and the segment record never survive without the tombstone.
// REO-04, REO-05
pub fn retire_generation_rows<S: bitcoin_rs_storage::KvStore>(
    store: &S,
    capability: IndexCapability,
    gen_id: u64,
) -> Result<(), crate::IndexError> {
    let mut tombstone_batch = store.new_batch();
    tombstone_batch.put(
        bitcoin_rs_storage::ColumnFamily::IdxMeta,
        &retire_tombstone_key(capability, gen_id),
        &[],
    );
    store.write_durable(tombstone_batch)?;
    retire_fault(RetireFault::AfterTombstone)?;
    clear_retirement_rows(store, capability, gen_id)?;
    retire_fault(RetireFault::AfterClear)?;
    Ok(())
}

/// Retires one sealed segment end to end: rows, then the record, the
/// descriptor, and the tombstone in one batch.
pub fn retire_generation<S: bitcoin_rs_storage::KvStore>(
    store: &S,
    capability: IndexCapability,
    gen_id: u64,
) -> Result<(), crate::IndexError> {
    retire_generation_rows(store, capability, gen_id)?;
    let snapshot = store.snapshot().map_err(crate::IndexError::Storage)?;
    let mut state = tail::load(snapshot.as_ref())?;
    drop(snapshot);
    state.sealed.retain(|sealed| sealed.gen_id != gen_id);
    let mut batch = store.new_batch();
    batch.delete(
        bitcoin_rs_storage::ColumnFamily::IdxMeta,
        &sealed_gen_key(capability, gen_id),
    );
    batch.delete(
        bitcoin_rs_storage::ColumnFamily::IdxMeta,
        &retire_tombstone_key(capability, gen_id),
    );
    tail::put_generation_descriptors(&mut batch, [capability], state.bounds());
    store.write_durable(batch)?;
    retire_fault(RetireFault::AfterDescriptor)?;
    Ok(())
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
    capabilities: IndexCapabilities,
    scratch: &std::path::Path,
) -> Result<(), crate::IndexError> {
    let snapshot = store.snapshot().map_err(crate::IndexError::Storage)?;
    let next_ordinal = tail::load(snapshot.as_ref())?.next_ordinal;

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
        &seal_marker_value(gen_id, &coverage, capabilities, next_ordinal),
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
        &seal_marker_value(gen_id, &coverage, capabilities, next_ordinal),
    );
    store.write_durable(committed_batch)?;
    seal_fault(SealFault::AfterCommitted)?;

    clear_tail(store)?;
    seal_fault(SealFault::AfterClear)?;
    publish_sealed(store, gen_id, coverage, next_ordinal, capabilities)?;
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
    store
        .delete_range(
            bitcoin_rs_storage::ColumnFamily::IdxMeta,
            tail::LOG_PREFIX,
            tail::LOG_END,
        )
        .map_err(crate::IndexError::Storage)
}

/// Publishes the sealed segment record and the `gen/<cap>` descriptor in one
/// batch. The tail is empty afterwards, so `tail_lo > tail_hi`.
fn publish_sealed<S: bitcoin_rs_storage::KvStore>(
    store: &S,
    gen_id: u64,
    coverage: Coverage,
    next_ordinal: u32,
    capabilities: IndexCapabilities,
) -> Result<(), crate::IndexError> {
    let sealed = SealedGen {
        gen_id,
        coverage,
        next_ordinal,
    };
    let record = encode_sealed_gen(&sealed);
    let mut batch = store.new_batch();
    batch.put(
        bitcoin_rs_storage::ColumnFamily::IdxMeta,
        SEAL_NEXT_GEN_KEY,
        &gen_id.saturating_add(1).to_le_bytes(),
    );
    let segment_caps = capabilities
        .iter()
        .filter(|capability| *capability != IndexCapability::ScriptLive);
    for capability in capabilities.iter() {
        if capability == IndexCapability::ScriptLive {
            continue;
        }
        batch.put(
            bitcoin_rs_storage::ColumnFamily::IdxMeta,
            &sealed_gen_key(capability, gen_id),
            &record,
        );
    }
    tail::put_generation_descriptors(
        &mut batch,
        segment_caps,
        tail::TailBounds {
            newest: Some(sealed),
            first_height: None,
            at: Some((coverage.last_height, coverage.last_hash)),
        },
    );
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
        .filter(|bytes| bytes.len() >= SEAL_MARKER_LEN);
    let committed = snapshot
        .get(
            bitcoin_rs_storage::ColumnFamily::IdxMeta,
            SEAL_COMMITTED_KEY,
        )?
        .filter(|bytes| bytes.len() >= SEAL_MARKER_LEN);
    drop(snapshot);

    let staged = staging.as_deref().map_or_else(
        || Err(crate::IndexError::InvalidSealMarker),
        |bytes| decode_seal_marker(bytes).ok_or(crate::IndexError::InvalidSealMarker),
    );
    if let Some(bytes) = committed.as_deref() {
        let (gen_id, coverage, capabilities, next_ordinal) =
            decode_seal_marker(bytes).ok_or(crate::IndexError::InvalidSealMarker)?;
        clear_tail(store)?;
        publish_sealed(store, gen_id, coverage, next_ordinal, capabilities)?;
        remove_seal_markers(store)?;
        if staged.is_err() {
            return Err(crate::IndexError::InvalidSealMarker);
        }
    } else if let Ok((gen_id, _coverage, _capabilities, _next)) = staged {
        rollback_seal(store, gen_id)?;
    }
    recover_retirements(store)
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

/// Finishes every tombstoned retirement: rows first, then the record, the
/// descriptor, and the tombstone in one batch.
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
        finish_retirement(store, &key, gen_id, capability)?;
    }
    Ok(())
}

fn finish_retirement<S: bitcoin_rs_storage::KvStore>(
    store: &S,
    tombstone: &[u8],
    gen_id: u64,
    capability: IndexCapability,
) -> Result<(), crate::IndexError> {
    clear_retirement_rows(store, capability, gen_id)?;
    let snapshot = store.snapshot().map_err(crate::IndexError::Storage)?;
    let mut state = tail::load(snapshot.as_ref())?;
    drop(snapshot);
    state.sealed.retain(|sealed| sealed.gen_id != gen_id);
    let mut batch = store.new_batch();
    batch.delete(
        bitcoin_rs_storage::ColumnFamily::IdxMeta,
        &sealed_gen_key(capability, gen_id),
    );
    batch.delete(bitcoin_rs_storage::ColumnFamily::IdxMeta, tombstone);
    tail::put_generation_descriptors(&mut batch, [capability], state.bounds());
    store
        .write_durable(batch)
        .map_err(crate::IndexError::Storage)
}

fn clear_retirement_rows<S: bitcoin_rs_storage::KvStore>(
    store: &S,
    capability: IndexCapability,
    gen_id: u64,
) -> Result<(), crate::IndexError> {
    let start = format::gen_prefix_start(gen_id);
    let end = format::gen_prefix_end(gen_id);
    let snapshot = store.snapshot().map_err(crate::IndexError::Storage)?;
    let mut families = retirement_families(capability).to_vec();
    for other in IndexCapability::ALL {
        if other == capability || other == IndexCapability::ScriptLive {
            continue;
        }
        let built = snapshot
            .get(
                bitcoin_rs_storage::ColumnFamily::IdxMeta,
                &sealed_gen_key(other, gen_id),
            )?
            .is_some();
        if !built {
            families.extend_from_slice(retirement_families(other));
        }
    }
    drop(snapshot);
    for cf in families {
        store.delete_range(cf, &start, &end)?;
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

/// Clears a retired segment's record and tombstone in the caller's batch.
pub fn clear_retirement_markers(
    batch: &mut bitcoin_rs_storage::BufferedWriteBatch,
    capability: IndexCapability,
    gen_id: u64,
) {
    batch.delete(
        bitcoin_rs_storage::ColumnFamily::IdxMeta,
        &sealed_gen_key(capability, gen_id),
    );
    batch.delete(
        bitcoin_rs_storage::ColumnFamily::IdxMeta,
        &retire_tombstone_key(capability, gen_id),
    );
}

/// Key range covering every sealed segment record of `capability`.
#[must_use]
pub fn sealed_gen_range(capability: IndexCapability) -> (Vec<u8>, Vec<u8>) {
    let start = sealed_gen_prefix(capability);
    let mut end = start.clone();
    if let Some(last) = end.last_mut() {
        *last += 1;
    }
    (start, end)
}
