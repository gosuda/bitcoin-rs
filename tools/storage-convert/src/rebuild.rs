use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::{Path, PathBuf};

use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash as _;
use bitcoin_rs_consensus::primitives::Hash256;
use bitcoin_rs_projection::IndexCapability;
use bitcoin_rs_projection::segment::bulk_builder::BulkSegmentBuilder;
use bitcoin_rs_projection::segment::{
    Coverage, GenerationDescriptor, IndexGeneration, TailDescriptor, meta_gen_key,
};
use bitcoin_rs_storage::committed_facts::{CommittedBlock, CreatedOutput, SpentPrevout, TxFacts};
use bitcoin_rs_storage::{ColumnFamily, KvStore, block_undo_key};
use bytes::Bytes;

use crate::error::ConvertError;
use crate::report::{FamilyResetReport, RebuildIndexReport};
use crate::target::open_destination_store;

const CURRENT_EPOCH: u32 = 3;
const CURRENT_SCHEMA_MAX_BYTES: u64 = 16;
const BLOCK_FILE_MAGIC: [u8; 4] = *b"BRSB";
const RECORD_HEADER_LEN: usize = 44;
const MAX_BLOCK_RECORD_BYTES: usize = 4 * 1024 * 1024;

struct ScratchGuard {
    path: PathBuf,
}

impl ScratchGuard {
    fn create(path: PathBuf) -> Result<Self, std::io::Error> {
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path)?;
        Ok(Self { path })
    }
}

impl Drop for ScratchGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

pub(crate) fn run_rebuild_index(datadir: &Path) -> Result<RebuildIndexReport, ConvertError> {
    if !datadir.is_dir() {
        return Err(ConvertError::InvalidOperation(format!(
            "datadir '{}' is not a directory",
            datadir.display()
        )));
    }
    read_datadir_epoch(datadir)?;
    let txindex_dir = datadir.join("txindex");
    if !txindex_dir.is_dir() {
        return Err(ConvertError::InvalidOperation(format!(
            "datadir '{}' has no txindex namespace to rebuild",
            datadir.display()
        )));
    }
    let engine = match bitcoin_rs_storage::detect_engine(&txindex_dir)? {
        Some(engine) => engine,
        None => {
            let chainstate_dir = datadir.join("chainstate");
            match bitcoin_rs_storage::detect_engine(&chainstate_dir)? {
                Some(engine) => engine,
                None => {
                    return Err(ConvertError::IncompatibleData(format!(
                        "cannot detect storage engine for datadir '{}': txindex is empty and chainstate engine is missing or unrecognized",
                        datadir.display()
                    )));
                }
            }
        }
    };
    let store = open_destination_store(&txindex_dir, engine)?;
    let reset = bitcoin_rs_projection::reset_offline(store.as_ref())
        .map_err(|error| ConvertError::IncompatibleData(error.to_string()))?;

    let scratch_guard = ScratchGuard::create(datadir.join("txindex_rebuild_scratch"))?;
    let chainstate_dir = datadir.join("chainstate");
    let chainstate_store: Option<Box<dyn KvStore>> = if chainstate_dir.is_dir() {
        open_destination_store(&chainstate_dir, engine).ok()
    } else {
        None
    };

    let blocks = scan_retained_blocks(&datadir.join("blocks"), chainstate_store.as_deref())?;

    let builder = BulkSegmentBuilder::new(64 * 1024 * 1024, scratch_guard.path.clone());
    let gen_id = 1u64;

    let coverage = if blocks.is_empty() {
        Coverage::new(0, 0, [0u8; 32])
    } else {
        builder
            .build_and_ingest(store.as_ref(), gen_id, &blocks)
            .map_err(|_| {
                ConvertError::Storage(bitcoin_rs_storage::StorageError::InvalidOperation(
                    "rebuild index build failed",
                ))
            })?
    };

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
    batch.put(
        ColumnFamily::UtxoMeta,
        bitcoin_rs_projection::INDEX_FORMAT_VERSION_KEY,
        &bitcoin_rs_projection::INDEX_FORMAT_VERSION_VALUE,
    );
    for cap in IndexCapability::ALL {
        batch.put(
            ColumnFamily::IdxMeta,
            &meta_gen_key(cap),
            &IndexGeneration::encode_meta_value(&desc),
        );
    }
    store.write_durable(batch).map_err(ConvertError::Storage)?;
    drop(scratch_guard);

    Ok(RebuildIndexReport {
        datadir: datadir.display().to_string(),
        engine: engine.as_str().to_owned(),
        format_version: reset.format_version,
        families: reset
            .families
            .into_iter()
            .map(|(cf, rows_removed)| FamilyResetReport {
                family: cf.name().to_owned(),
                rows_removed,
            })
            .collect(),
    })
}

fn read_datadir_epoch(datadir: &Path) -> Result<(), ConvertError> {
    let path = datadir.join("CURRENT_SCHEMA");
    let mut file = match std::fs::File::open(&path) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Err(ConvertError::UnknownEpoch(0));
        }
        Err(err) => return Err(ConvertError::Io(err)),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > CURRENT_SCHEMA_MAX_BYTES {
        return Err(ConvertError::UnknownEpoch(0));
    }
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    let epoch: u32 = text
        .trim()
        .parse()
        .map_err(|_| ConvertError::UnknownEpoch(0))?;
    if epoch != CURRENT_EPOCH {
        return Err(ConvertError::UnknownEpoch(epoch));
    }
    Ok(())
}

fn scan_retained_blocks(
    blocks_dir: &Path,
    chainstate_store: Option<&dyn KvStore>,
) -> Result<Vec<CommittedBlock>, ConvertError> {
    if !blocks_dir.is_dir() {
        return Ok(Vec::new());
    }

    let mut entries = std::fs::read_dir(blocks_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name();
            let s = name.to_string_lossy();
            s.starts_with("blk") && s.ends_with(".dat")
        })
        .collect::<Vec<_>>();
    entries.sort_by_key(|e| e.file_name());

    let mut blocks = Vec::new();
    for entry in entries {
        read_blocks_from_file(&entry.path(), chainstate_store, &mut blocks)?;
    }

    blocks.sort_by_key(|b| b.height);
    Ok(blocks)
}

fn read_blocks_from_file(
    path: &Path,
    chainstate_store: Option<&dyn KvStore>,
    blocks: &mut Vec<CommittedBlock>,
) -> Result<(), ConvertError> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut header_buf = [0u8; RECORD_HEADER_LEN];

    while reader.read_exact(&mut header_buf).is_ok() {
        if header_buf[..4] != BLOCK_FILE_MAGIC {
            break;
        }
        let len_u32 = u32::from_le_bytes(header_buf[4..8].try_into().unwrap_or([0u8; 4]));
        let height = u32::from_le_bytes(header_buf[8..12].try_into().unwrap_or([0u8; 4]));
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&header_buf[12..44]);

        let Ok(body_len) = usize::try_from(len_u32) else {
            break;
        };
        if body_len > MAX_BLOCK_RECORD_BYTES {
            break;
        }

        let mut body = vec![0u8; body_len];
        reader.read_exact(&mut body)?;

        let undo_scripts = load_undo_scripts(chainstate_store, height, hash);

        if let Some(block) = parse_committed_block(&body, height, hash, &undo_scripts) {
            blocks.push(block);
        }
    }
    Ok(())
}

type UndoMap = HashMap<([u8; 32], u32), (u64, Vec<u8>)>;

fn load_undo_scripts(store: Option<&dyn KvStore>, height: u32, hash: [u8; 32]) -> UndoMap {
    let mut map = HashMap::new();
    let Some(store) = store else {
        return map;
    };
    let block_hash = Hash256::from_le_bytes(&hash);
    let key = block_undo_key(height, block_hash);
    let Ok(Some(bytes)) = store.get(ColumnFamily::UndoData, &key) else {
        return map;
    };
    let Ok(batch) = bitcoin_rs_storage::utxo::contract::decode_undo_record(&bytes, block_hash)
    else {
        return map;
    };
    for add in batch.restores() {
        let prev_txid = add.outpoint.txid.0.to_le_bytes();
        let prev_vout = add.outpoint.vout;
        let script = add.txout.script_pubkey.as_bytes().to_vec();
        map.insert((prev_txid, prev_vout), (add.txout.value.to_sat(), script));
    }
    map
}

fn parse_committed_block(
    body: &[u8],
    height: u32,
    hash: [u8; 32],
    undo_scripts: &UndoMap,
) -> Option<CommittedBlock> {
    let parsed: bitcoin::Block = deserialize(body).ok()?;
    let parent_hash = parsed.header.prev_blockhash.to_byte_array();
    let header_bytes: [u8; 80] = bitcoin::consensus::serialize(&parsed.header)
        .try_into()
        .ok()?;

    let mut same_block_created: HashMap<([u8; 32], u32), (u64, Bytes)> = HashMap::new();
    for tx in &parsed.txdata {
        let txid = tx.compute_txid().to_byte_array();
        for (vout, out) in tx.output.iter().enumerate() {
            if let Ok(vout_u32) = u32::try_from(vout) {
                same_block_created.insert(
                    (txid, vout_u32),
                    (
                        out.value.to_sat(),
                        Bytes::copy_from_slice(out.script_pubkey.as_bytes()),
                    ),
                );
            }
        }
    }

    let mut txs = Vec::with_capacity(parsed.txdata.len());
    for (tx_idx, tx) in parsed.txdata.iter().enumerate() {
        let txid = tx.compute_txid().to_byte_array();
        let inputs = if tx_idx == 0 {
            Vec::new()
        } else {
            tx.input
                .iter()
                .map(|inp| {
                    let prev_txid = inp.previous_output.txid.to_byte_array();
                    let prev_vout = inp.previous_output.vout;
                    let (val, script) =
                        if let Some((v, s)) = same_block_created.get(&(prev_txid, prev_vout)) {
                            (*v, s.clone())
                        } else if let Some((v, s)) = undo_scripts.get(&(prev_txid, prev_vout)) {
                            (*v, Bytes::copy_from_slice(s))
                        } else {
                            (0, Bytes::copy_from_slice(inp.script_sig.as_bytes()))
                        };
                    SpentPrevout {
                        txid: prev_txid,
                        vout: prev_vout,
                        value: val,
                        script,
                        height: 0,
                        coinbase: false,
                    }
                })
                .collect()
        };

        let outputs = tx
            .output
            .iter()
            .enumerate()
            .filter_map(|(vout, out)| {
                let vout_u32 = u32::try_from(vout).ok()?;
                Some(CreatedOutput {
                    vout: vout_u32,
                    value: out.value.to_sat(),
                    script: Bytes::copy_from_slice(out.script_pubkey.as_bytes()),
                })
            })
            .collect();

        txs.push(TxFacts {
            txid,
            offset: 0,
            len: 0,
            inputs,
            outputs,
        });
    }

    Some(CommittedBlock {
        height,
        hash,
        parent_hash,
        header: header_bytes,
        txs,
    })
}
