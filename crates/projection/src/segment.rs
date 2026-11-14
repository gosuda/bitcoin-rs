pub mod bulk_builder;
pub mod format;
pub mod import;
mod read;
pub mod spill;
pub mod tail;
pub(crate) use read::{RecordPage, SegmentSnapshot};
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
    AfterPublish = 4,
}

impl SealFault {
    const fn code(self) -> u8 {
        match self {
            Self::AfterStaging => 1,
            Self::AfterIngest => 2,
            Self::AfterCommitted => 3,
            Self::AfterPublish => 4,
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
/// Families a retirement may clear for `capability` in a commit that retires
/// every capability in `retiring`: a shared family survives while a capability
/// outside `retiring` still publishes this generation.
// REO-05
fn retirement_target_families(
    snapshot: &dyn bitcoin_rs_storage::KvSnapshot,
    retiring: IndexCapabilities,
    capability: IndexCapability,
    gen_id: u64,
) -> Result<Vec<bitcoin_rs_storage::ColumnFamily>, crate::IndexError> {
    let mut families = retirement_families(capability).to_vec();
    let mut published: Vec<bitcoin_rs_storage::ColumnFamily> = Vec::new();
    for other in IndexCapability::ALL {
        if other == capability {
            continue;
        }
        let built = snapshot
            .get(
                bitcoin_rs_storage::ColumnFamily::IdxMeta,
                &sealed_gen_key(other, gen_id),
            )?
            .is_some();
        if !built {
            if other != IndexCapability::ScriptLive {
                families.extend_from_slice(retirement_families(other));
            }
        } else if !retiring.contains(other) {
            published.extend_from_slice(other.column_families());
        }
    }
    families.retain(|family| !published.contains(family));
    Ok(families)
}

/// Stages the retirement of one sealed generation for every capability in
/// `capabilities` in the caller's commit batch: the tombstones first, then the
/// row range deletes and marker clears. The batch commits atomically with the
/// watermark rewind, so a crash leaves the watermark and the rows in agreement
/// either way.
// REO-04, REO-05
pub fn stage_retirement<S: bitcoin_rs_storage::KvStore>(
    store: &S,
    batch: &mut bitcoin_rs_storage::BufferedWriteBatch,
    capabilities: IndexCapabilities,
    gen_id: u64,
) -> Result<(), crate::IndexError> {
    for capability in capabilities.iter() {
        batch.put(
            bitcoin_rs_storage::ColumnFamily::IdxMeta,
            &retire_tombstone_key(capability, gen_id),
            &[],
        );
    }
    retire_fault(RetireFault::AfterTombstone)?;
    let snapshot = store.snapshot().map_err(crate::IndexError::Storage)?;
    let start = format::gen_prefix_start(gen_id);
    let end = format::gen_prefix_end(gen_id);
    for capability in capabilities.iter() {
        for family in
            retirement_target_families(snapshot.as_ref(), capabilities, capability, gen_id)?
        {
            batch.delete_range(family, &start, &end);
        }
        batch.delete(
            bitcoin_rs_storage::ColumnFamily::IdxMeta,
            &sealed_gen_key(capability, gen_id),
        );
        batch.delete(
            bitcoin_rs_storage::ColumnFamily::IdxMeta,
            &retire_tombstone_key(capability, gen_id),
        );
    }
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

struct SealedRows {
    tx_dir: Vec<(Vec<u8>, Vec<u8>)>,
    spend_dir: Vec<(Vec<u8>, Vec<u8>)>,
    filters: Vec<(Vec<u8>, Vec<u8>)>,
    dict: Vec<(Vec<u8>, Vec<u8>)>,
    post: Vec<(Vec<u8>, Vec<u8>)>,
    stats: Vec<(Vec<u8>, Vec<u8>)>,
}

fn rekey_generation(key: &[u8], gen_id: u64) -> Option<Vec<u8>> {
    let mut out = key.to_vec();
    out.get_mut(..8)?.copy_from_slice(&gen_id.to_be_bytes());
    Some(out)
}

fn sealed_rows(plan: &tail::PrefixCut, gen_id: u64) -> SealedRows {
    let mut out = SealedRows {
        tx_dir: Vec::new(),
        spend_dir: Vec::new(),
        filters: Vec::new(),
        dict: Vec::new(),
        post: Vec::new(),
        stats: Vec::new(),
    };
    let mut posts: hashbrown::HashMap<u32, Vec<format::PostingItem>> = hashbrown::HashMap::new();
    for (family, key, value) in &plan.rows {
        let target = match family {
            tail::Family::TxDir => Some(&mut out.tx_dir),
            tail::Family::SpendDir => Some(&mut out.spend_dir),
            tail::Family::Filters => Some(&mut out.filters),
            tail::Family::ScriptPost => None,
            tail::Family::ScriptDict => None,
        };
        match (family, target) {
            (tail::Family::ScriptPost, _) => {
                if let (Some((_, old_id, _)), Some(items)) = (
                    format::decode_script_post_key(key),
                    format::decode_posting_items(value),
                ) {
                    posts.entry(old_id).or_default().extend(items);
                }
            }
            (_, Some(rows)) => {
                if let Some(new_key) = rekey_generation(key, gen_id) {
                    rows.push((new_key, value.clone()));
                }
            }
            _ => {}
        }
    }

    let mut prefix_scripts: Vec<([u8; 32], u32)> = plan
        .script_hashes
        .iter()
        .map(|(&old_id, &hash)| (hash, old_id))
        .collect();
    prefix_scripts.sort_unstable();
    let mut new_ids = hashbrown::HashMap::<u32, u32>::new();
    for (dense, (hash, old_id)) in prefix_scripts.into_iter().enumerate() {
        let Ok(new_id) = u32::try_from(dense) else {
            continue;
        };
        new_ids.insert(old_id, new_id);
        out.dict.push((
            format::encode_script_dict_key(gen_id, &hash).to_vec(),
            format::encode_script_dict_value(new_id).to_vec(),
        ));
        if let Some(stats) = plan.prefix_stats.get(&old_id) {
            out.stats.push((
                format::encode_script_stats_key(gen_id, new_id).to_vec(),
                format::encode_script_stats_value(stats).to_vec(),
            ));
        }
    }

    for (old_id, mut items) in posts {
        let Some(&new_id) = new_ids.get(&old_id) else {
            continue;
        };
        items.sort_unstable_by_key(|item| item.delta_ordinal);
        let mut last_ordinal = 0u32;
        let mut repacked = Vec::with_capacity(items.len());
        for item in items {
            let delta = item.delta_ordinal.saturating_sub(last_ordinal);
            last_ordinal = item.delta_ordinal;
            repacked.push(format::PostingItem {
                delta_ordinal: delta,
                flags: item.flags,
            });
        }
        out.post
            .extend(format::chunk_postings(gen_id, new_id, repacked));
    }
    out
}

// PRJ-03, PRJ-05, PRJ-09, REO-04
pub fn seal_tail_generation<S: bitcoin_rs_storage::KvStore>(
    store: &S,
    gen_id: u64,
    cut: u32,
    capabilities: IndexCapabilities,
    scratch: &std::path::Path,
) -> Result<(), crate::IndexError> {
    let snapshot = store.snapshot().map_err(crate::IndexError::Storage)?;
    let plan = tail::plan_prefix_cut(snapshot.as_ref(), cut)?;
    let mut capabilities = capabilities;
    for capability in IndexCapability::ALL {
        if capability == IndexCapability::ScriptLive
            || snapshot
                .get(
                    bitcoin_rs_storage::ColumnFamily::IdxMeta,
                    &meta_gen_key(capability),
                )?
                .is_none()
        {
            continue;
        }
        if plan.rows.iter().any(|(family, _, _)| match capability {
            IndexCapability::TxLookup => *family == tail::Family::TxDir,
            IndexCapability::ScriptHistory => matches!(
                family,
                tail::Family::TxDir
                    | tail::Family::ScriptDict
                    | tail::Family::ScriptPost
                    | tail::Family::SpendDir
            ),
            IndexCapability::CompactFilters => *family == tail::Family::Filters,
            IndexCapability::ScriptLive => false,
        }) {
            capabilities = capabilities.insert(capability);
        }
    }
    drop(snapshot);
    let coverage = Coverage::new(plan.first, plan.cut, plan.cut_hash);
    let mut rows = sealed_rows(&plan, gen_id);
    for list in [
        &mut rows.tx_dir,
        &mut rows.spend_dir,
        &mut rows.filters,
        &mut rows.dict,
        &mut rows.post,
        &mut rows.stats,
    ] {
        list.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    }

    let mut staging_batch = store.new_batch();
    staging_batch.put(
        bitcoin_rs_storage::ColumnFamily::IdxMeta,
        SEAL_STAGING_KEY,
        &seal_marker_value(gen_id, &coverage, capabilities, plan.next_ordinal),
    );
    store.write_durable(staging_batch)?;
    seal_fault(SealFault::AfterStaging)?;

    ingest_family_rows(
        store,
        bitcoin_rs_storage::ColumnFamily::TxDir,
        rows.tx_dir,
        scratch,
    )?;
    ingest_family_rows(
        store,
        bitcoin_rs_storage::ColumnFamily::SpendDir,
        rows.spend_dir,
        scratch,
    )?;
    ingest_family_rows(
        store,
        bitcoin_rs_storage::ColumnFamily::Filters,
        rows.filters,
        scratch,
    )?;
    ingest_family_rows(
        store,
        bitcoin_rs_storage::ColumnFamily::ScriptDict,
        rows.dict,
        scratch,
    )?;
    ingest_family_rows(
        store,
        bitcoin_rs_storage::ColumnFamily::ScriptPost,
        rows.post,
        scratch,
    )?;
    ingest_family_rows(
        store,
        bitcoin_rs_storage::ColumnFamily::ScriptStats,
        rows.stats,
        scratch,
    )?;
    seal_fault(SealFault::AfterIngest)?;

    let mut committed_batch = store.new_batch();
    committed_batch.put(
        bitcoin_rs_storage::ColumnFamily::IdxMeta,
        SEAL_COMMITTED_KEY,
        &seal_marker_value(gen_id, &coverage, capabilities, plan.next_ordinal),
    );
    store.write_durable(committed_batch)?;
    seal_fault(SealFault::AfterCommitted)?;

    commit_cut(store, &plan, gen_id, coverage, capabilities)?;
    seal_fault(SealFault::AfterPublish)?;
    remove_seal_markers(store)?;
    Ok(())
}

fn commit_cut<S: bitcoin_rs_storage::KvStore>(
    store: &S,
    plan: &tail::PrefixCut,
    gen_id: u64,
    coverage: Coverage,
    capabilities: IndexCapabilities,
) -> Result<(), crate::IndexError> {
    let sealed = SealedGen {
        gen_id,
        coverage,
        next_ordinal: plan.next_ordinal,
    };
    let mut batch = store.new_batch();
    tail::cut_generation_zero(&mut batch, plan);
    put_sealed_records(
        &mut batch,
        &sealed,
        capabilities,
        tail::TailBounds {
            newest: Some(sealed),
            first_height: plan.tail_first,
            at: plan.tail_at,
        },
    );
    store
        .write_durable(batch)
        .map_err(crate::IndexError::Storage)
}

fn put_sealed_records(
    batch: &mut bitcoin_rs_storage::BufferedWriteBatch,
    sealed: &SealedGen,
    capabilities: IndexCapabilities,
    bounds: tail::TailBounds,
) {
    let record = encode_sealed_gen(sealed);
    batch.put(
        bitcoin_rs_storage::ColumnFamily::IdxMeta,
        SEAL_NEXT_GEN_KEY,
        &sealed.gen_id.saturating_add(1).to_le_bytes(),
    );
    let segment_caps: Vec<IndexCapability> = capabilities
        .iter()
        .filter(|capability| *capability != IndexCapability::ScriptLive)
        .collect();
    for &capability in &segment_caps {
        batch.put(
            bitcoin_rs_storage::ColumnFamily::IdxMeta,
            &sealed_gen_key(capability, sealed.gen_id),
            &record,
        );
    }
    tail::put_generation_descriptors(batch, segment_caps, bounds);
}

pub fn publish_sealed<S: bitcoin_rs_storage::KvStore>(
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
    let mut batch = store.new_batch();
    put_sealed_records(
        &mut batch,
        &sealed,
        capabilities,
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

pub fn publish_bulk_generation<S: bitcoin_rs_storage::KvStore + ?Sized>(
    store: &S,
    gen_id: u64,
    coverage: Coverage,
    next_ordinal: u32,
    capabilities: IndexCapabilities,
) -> Result<(), crate::IndexError> {
    let descriptor = bulk_generation_descriptor(gen_id, coverage);
    let mut batch = store.new_batch();
    batch.put(
        bitcoin_rs_storage::ColumnFamily::UtxoMeta,
        crate::INDEX_FORMAT_VERSION_KEY,
        &crate::INDEX_FORMAT_VERSION_VALUE,
    );
    if next_ordinal == 0 {
        for capability in IndexCapability::ALL {
            batch.put(
                bitcoin_rs_storage::ColumnFamily::IdxMeta,
                &meta_gen_key(capability),
                &IndexGeneration::encode_meta_value(&descriptor),
            );
        }
    } else {
        let sealed = SealedGen {
            gen_id,
            coverage,
            next_ordinal,
        };
        put_sealed_records(
            &mut batch,
            &sealed,
            capabilities,
            tail::TailBounds {
                newest: Some(sealed),
                first_height: None,
                at: Some((coverage.last_height, coverage.last_hash)),
            },
        );
        crate::index::put_bulk_publish_marks(
            &mut batch,
            capabilities,
            crate::IndexWatermark {
                height: coverage.last_height,
                hash: coverage.last_hash,
            },
            coverage.first_height,
        );
        batch.put(
            bitcoin_rs_storage::ColumnFamily::IdxMeta,
            &meta_gen_key(IndexCapability::ScriptLive),
            &IndexGeneration::encode_meta_value(&descriptor),
        );
    }
    store
        .write_durable(batch)
        .map_err(crate::IndexError::Storage)
}

fn bulk_generation_descriptor(gen_id: u64, coverage: Coverage) -> GenerationDescriptor {
    GenerationDescriptor {
        gen_id,
        coverage,
        tail: TailDescriptor {
            tail_lo: coverage.last_height.saturating_add(1),
            tail_hi: coverage.last_height,
            tail_hash: coverage.last_hash,
        },
    }
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
        let (gen_id, coverage, capabilities, _next_ordinal) =
            decode_seal_marker(bytes).ok_or(crate::IndexError::InvalidSealMarker)?;
        let snapshot = store.snapshot().map_err(crate::IndexError::Storage)?;
        let landed = snapshot
            .get(
                bitcoin_rs_storage::ColumnFamily::IdxMeta,
                &tail::log_key_for(coverage.first_height),
            )?
            .is_none();
        drop(snapshot);
        if !landed {
            let snapshot = store.snapshot().map_err(crate::IndexError::Storage)?;
            let plan = tail::plan_prefix_cut(snapshot.as_ref(), coverage.last_height)?;
            drop(snapshot);
            commit_cut(store, &plan, gen_id, coverage, capabilities)?;
        }
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
    let snapshot = store.snapshot().map_err(crate::IndexError::Storage)?;
    let families = retirement_target_families(
        snapshot.as_ref(),
        IndexCapabilities::from_iter([capability]),
        capability,
        gen_id,
    )?;
    drop(snapshot);
    let start = format::gen_prefix_start(gen_id);
    let end = format::gen_prefix_end(gen_id);
    for family in families {
        store.delete_range(family, &start, &end)?;
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
