pub mod bulk_builder;
pub mod format;
#[cfg(any(test, verification, kani))]
pub mod proofs;
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

#[derive(Default)]
pub struct TailWriterState {
    pub current_ordinal: u32,
    pub prev_filter_header: [u8; 32],
    pub txid_to_ordinal: hashbrown::HashMap<[u8; 32], u32>,
    pub script_id_map: hashbrown::HashMap<[u8; 32], u32>,
    pub script_stats: hashbrown::HashMap<u32, format::ScriptStats>,
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
    let post_key = format::encode_script_post_key(0, script_id, ordinal);
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
    for tx in &block.txs {
        for output in &tx.outputs {
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

        let mut chunk_idx = 0u32;
        let mut chunk = Vec::new();
        for item in repacked_items {
            chunk.push(item);
            if chunk.len() >= format::SCRIPT_POST_CHUNK_MAX_BYTES / 4 {
                let key = format::encode_script_post_key(gen_id, new_id, chunk_idx);
                let val = format::encode_posting_items(&chunk);
                post_rows.push((key.to_vec(), val));
                chunk.clear();
                chunk_idx = chunk_idx.saturating_add(1);
            }
        }
        let key = format::encode_script_post_key(gen_id, new_id, chunk_idx);
        let val = format::encode_posting_items(&chunk);
        post_rows.push((key.to_vec(), val));
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
        .map_err(crate::IndexError::Storage)?;

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

    store
        .delete_range(cf, &0u64.to_be_bytes(), &1u64.to_be_bytes())
        .map_err(crate::IndexError::Storage)?;

    Ok(())
}
