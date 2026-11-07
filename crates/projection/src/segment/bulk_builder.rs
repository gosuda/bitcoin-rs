use std::path::PathBuf;

use bitcoin_rs_storage::committed_facts::{CommittedBlock, CreatedOutput, SpentPrevout};
use bitcoin_rs_storage::{ColumnFamily, KvStore};
use hashbrown::HashMap;
use sha2::{Digest, Sha256};

use super::Coverage;
use super::format::*;

#[derive(Debug, thiserror::Error)]
pub enum BulkBuilderError {
    #[error("storage error: {0}")]
    Storage(#[from] bitcoin_rs_storage::StorageError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("empty block range")]
    EmptyRange,
    #[error("invalid block sequence")]
    InvalidBlockSequence,
}

pub struct GenerationRows {
    pub coverage: Coverage,
    pub tx_dir: Vec<(Vec<u8>, Vec<u8>)>,
    pub script_dict: Vec<(Vec<u8>, Vec<u8>)>,
    pub script_post: Vec<(Vec<u8>, Vec<u8>)>,
    pub spend_dir: Vec<(Vec<u8>, Vec<u8>)>,
    pub script_stats: Vec<(Vec<u8>, Vec<u8>)>,
    pub filters: Vec<(Vec<u8>, Vec<u8>)>,
}

pub struct BulkSegmentBuilder {
    pub memory_budget: usize,
    pub scratch_dir: PathBuf,
}

struct Occurrence {
    ordinal: u32,
    flags: u8,
    sats: u64,
}

struct TxOccurrences {
    tx_dir_rows: Vec<(Vec<u8>, Vec<u8>)>,
    spend_dir_rows: Vec<(Vec<u8>, Vec<u8>)>,
    script_occurrences: HashMap<[u8; 32], Vec<Occurrence>>,
}

struct ScriptRows {
    script_dict: Vec<(Vec<u8>, Vec<u8>)>,
    script_post: Vec<(Vec<u8>, Vec<u8>)>,
    script_stats: Vec<(Vec<u8>, Vec<u8>)>,
}

impl BulkSegmentBuilder {
    #[must_use]
    pub fn new(memory_budget: usize, scratch_dir: PathBuf) -> Self {
        Self {
            memory_budget,
            scratch_dir,
        }
    }

    // PRJ-09
    pub fn build_generation_rows(
        &self,
        gen_id: u64,
        blocks: &[CommittedBlock],
    ) -> Result<GenerationRows, BulkBuilderError> {
        let coverage = validate_blocks(blocks)?;

        let mut tx_data = collect_tx_and_occurrences(gen_id, blocks);
        let mut filter_rows = build_filter_rows(gen_id, blocks);
        let mut script_rows = build_script_rows(gen_id, tx_data.script_occurrences)?;

        tx_data.tx_dir_rows.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        tx_data
            .spend_dir_rows
            .sort_unstable_by(|a, b| a.0.cmp(&b.0));
        filter_rows.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        script_rows
            .script_dict
            .sort_unstable_by(|a, b| a.0.cmp(&b.0));
        script_rows
            .script_post
            .sort_unstable_by(|a, b| a.0.cmp(&b.0));
        script_rows
            .script_stats
            .sort_unstable_by(|a, b| a.0.cmp(&b.0));

        Ok(GenerationRows {
            coverage,
            tx_dir: tx_data.tx_dir_rows,
            script_dict: script_rows.script_dict,
            script_post: script_rows.script_post,
            spend_dir: tx_data.spend_dir_rows,
            script_stats: script_rows.script_stats,
            filters: filter_rows,
        })
    }

    // PRJ-09
    pub fn build_and_ingest<S: KvStore>(
        &self,
        store: &S,
        gen_id: u64,
        blocks: &[CommittedBlock],
    ) -> Result<Coverage, BulkBuilderError> {
        let rows = self.build_generation_rows(gen_id, blocks)?;

        let mut tx_iter = rows.tx_dir.into_iter();
        store.ingest_sorted(ColumnFamily::TxDir, &mut tx_iter, &self.scratch_dir)?;

        let mut dict_iter = rows.script_dict.into_iter();
        store.ingest_sorted(ColumnFamily::ScriptDict, &mut dict_iter, &self.scratch_dir)?;

        let mut post_iter = rows.script_post.into_iter();
        store.ingest_sorted(ColumnFamily::ScriptPost, &mut post_iter, &self.scratch_dir)?;

        let mut spend_iter = rows.spend_dir.into_iter();
        store.ingest_sorted(ColumnFamily::SpendDir, &mut spend_iter, &self.scratch_dir)?;

        let mut stats_iter = rows.script_stats.into_iter();
        store.ingest_sorted(
            ColumnFamily::ScriptStats,
            &mut stats_iter,
            &self.scratch_dir,
        )?;

        let mut filter_iter = rows.filters.into_iter();
        store.ingest_sorted(ColumnFamily::Filters, &mut filter_iter, &self.scratch_dir)?;

        Ok(rows.coverage)
    }
}

fn validate_blocks(blocks: &[CommittedBlock]) -> Result<Coverage, BulkBuilderError> {
    let (Some(first), Some(last)) = (blocks.first(), blocks.last()) else {
        return Err(BulkBuilderError::EmptyRange);
    };
    for window in blocks.windows(2) {
        if window[1].height != window[0].height.saturating_add(1) {
            return Err(BulkBuilderError::InvalidBlockSequence);
        }
    }
    Ok(Coverage::new(first.height, last.height, last.hash))
}

fn collect_tx_and_occurrences(gen_id: u64, blocks: &[CommittedBlock]) -> TxOccurrences {
    let mut tx_dir_rows = Vec::new();
    let mut spend_dir_rows = Vec::new();
    let mut script_occurrences: HashMap<[u8; 32], Vec<Occurrence>> = HashMap::new();
    let mut txid_to_ordinal: HashMap<[u8; 32], u32> = HashMap::new();
    let mut current_ordinal: u32 = 0;

    for block in blocks {
        for tx in &block.txs {
            let ordinal = current_ordinal;
            current_ordinal = current_ordinal.saturating_add(1);
            txid_to_ordinal.insert(tx.txid, ordinal);

            let key = encode_tx_dir_key(gen_id, &tx.txid, block.height);
            let val = encode_tx_dir_value(&block.hash, ordinal, tx.offset, tx.len);
            tx_dir_rows.push((key.to_vec(), val.to_vec()));

            process_tx_inputs(
                gen_id,
                ordinal,
                &tx.inputs,
                &txid_to_ordinal,
                &mut spend_dir_rows,
                &mut script_occurrences,
            );
            process_tx_outputs(ordinal, &tx.outputs, &mut script_occurrences);
        }
    }

    TxOccurrences {
        tx_dir_rows,
        spend_dir_rows,
        script_occurrences,
    }
}

fn process_tx_inputs(
    gen_id: u64,
    ordinal: u32,
    inputs: &[SpentPrevout],
    txid_to_ordinal: &HashMap<[u8; 32], u32>,
    spend_dir_rows: &mut Vec<(Vec<u8>, Vec<u8>)>,
    script_occurrences: &mut HashMap<[u8; 32], Vec<Occurrence>>,
) {
    for input in inputs {
        if input.txid == [0u8; 32] && input.vout == u32::MAX {
            continue;
        }
        if let Some(&creation_ord) = txid_to_ordinal.get(&input.txid) {
            let key = encode_spend_dir_key(gen_id, creation_ord, input.vout);
            let val = encode_spend_dir_value(ordinal);
            spend_dir_rows.push((key.to_vec(), val.to_vec()));
        }
        if !input.script.is_empty() {
            let script_hash: [u8; 32] = Sha256::digest(&input.script).into();
            script_occurrences
                .entry(script_hash)
                .or_default()
                .push(Occurrence {
                    ordinal,
                    flags: POSTING_FLAG_SPENDING,
                    sats: input.value,
                });
        }
    }
}

fn process_tx_outputs(
    ordinal: u32,
    outputs: &[CreatedOutput],
    script_occurrences: &mut HashMap<[u8; 32], Vec<Occurrence>>,
) {
    for output in outputs {
        if !output.script.is_empty() && output.script[0] != 0x6a {
            let script_hash: [u8; 32] = Sha256::digest(&output.script).into();
            script_occurrences
                .entry(script_hash)
                .or_default()
                .push(Occurrence {
                    ordinal,
                    flags: POSTING_FLAG_FUNDING,
                    sats: output.value,
                });
        }
    }
}

fn build_script_rows(
    gen_id: u64,
    mut script_occurrences: HashMap<[u8; 32], Vec<Occurrence>>,
) -> Result<ScriptRows, BulkBuilderError> {
    let mut sorted_hashes: Vec<[u8; 32]> = script_occurrences.keys().copied().collect();
    sorted_hashes.sort_unstable();

    let mut script_dict = Vec::with_capacity(sorted_hashes.len());
    let mut script_stats = Vec::with_capacity(sorted_hashes.len());
    let mut script_post = Vec::new();

    for (dense_id, script_hash) in sorted_hashes.into_iter().enumerate() {
        let script_id =
            u32::try_from(dense_id).map_err(|_| BulkBuilderError::InvalidBlockSequence)?;
        let dict_key = encode_script_dict_key(gen_id, &script_hash);
        let dict_val = encode_script_dict_value(script_id);
        script_dict.push((dict_key.to_vec(), dict_val.to_vec()));

        let mut occurrences = script_occurrences.remove(&script_hash).unwrap_or_default();
        occurrences.sort_unstable_by_key(|o| o.ordinal);

        let (stats, posting_items) = summarize_occurrences(&occurrences);
        let stats_key = encode_script_stats_key(gen_id, script_id);
        let stats_val = encode_script_stats_value(&stats);
        script_stats.push((stats_key.to_vec(), stats_val.to_vec()));

        emit_posting_chunks(gen_id, script_id, posting_items, &mut script_post);
    }

    Ok(ScriptRows {
        script_dict,
        script_post,
        script_stats,
    })
}

fn summarize_occurrences(occurrences: &[Occurrence]) -> (ScriptStats, Vec<PostingItem>) {
    let mut stats = ScriptStats::default();
    let mut posting_items = Vec::with_capacity(occurrences.len());
    let mut last_ordinal = 0u32;

    for occ in occurrences {
        if occ.flags == POSTING_FLAG_FUNDING {
            stats.funded_count = stats.funded_count.saturating_add(1);
            stats.funded_sats = stats.funded_sats.saturating_add(occ.sats);
        } else if occ.flags == POSTING_FLAG_SPENDING {
            stats.spent_count = stats.spent_count.saturating_add(1);
            stats.spent_sats = stats.spent_sats.saturating_add(occ.sats);
        }

        let delta = occ.ordinal.saturating_sub(last_ordinal);
        last_ordinal = occ.ordinal;
        posting_items.push(PostingItem {
            delta_ordinal: delta,
            flags: occ.flags,
        });
    }

    (stats, posting_items)
}

fn emit_posting_chunks(
    gen_id: u64,
    script_id: u32,
    posting_items: Vec<PostingItem>,
    script_post: &mut Vec<(Vec<u8>, Vec<u8>)>,
) {
    let mut chunk_idx = 0u32;
    let mut chunk_items = Vec::new();
    for item in posting_items {
        chunk_items.push(item);
        if chunk_items.len() >= SCRIPT_POST_CHUNK_MAX_BYTES / 4 {
            let post_key = encode_script_post_key(gen_id, script_id, chunk_idx);
            let post_val = encode_posting_items(&chunk_items);
            script_post.push((post_key.to_vec(), post_val));
            chunk_items.clear();
            chunk_idx = chunk_idx.saturating_add(1);
        }
    }
    let post_key = encode_script_post_key(gen_id, script_id, chunk_idx);
    let post_val = encode_posting_items(&chunk_items);
    script_post.push((post_key.to_vec(), post_val));
}

fn build_filter_rows(gen_id: u64, blocks: &[CommittedBlock]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut rows = Vec::with_capacity(blocks.len());
    let mut prev_header = [0u8; 32];

    for block in blocks {
        let (filter, filter_hash, filter_header) = build_block_filter(block, &prev_header);
        prev_header = filter_header;

        let key = encode_filter_key(gen_id, block.height);
        let val = encode_filter_value(&block.hash, &filter_hash, &filter_header, &filter);
        rows.push((key.to_vec(), val));
    }

    rows
}

fn build_block_filter(
    block: &CommittedBlock,
    prev_header: &[u8; 32],
) -> (Vec<u8>, [u8; 32], [u8; 32]) {
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
    let mut header_input = [0u8; 64];
    header_input[..32].copy_from_slice(&filter_hash);
    header_input[32..].copy_from_slice(prev_header);
    let header = encode::double_sha256(&header_input).to_le_bytes();
    (filter, filter_hash, header)
}
