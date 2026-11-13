use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use bitcoin_rs_consensus::primitives::BlockImage;
use bitcoin_rs_consensus::primitives::Hash256;
use bitcoin_rs_projection::IndexCapabilities;
use bitcoin_rs_projection::segment::Coverage;
use bitcoin_rs_projection::segment::bulk_builder::BulkSegmentBuilder;
use bitcoin_rs_storage::budget::{BudgetCharge, BudgetError, BudgetOwner};
use bitcoin_rs_storage::committed_facts::{CommittedBlock, CreatedOutput, SpentPrevout, TxFacts};
use bitcoin_rs_storage::durable_head::{DURABLE_HEAD_KEY, DurableHead};
use bitcoin_rs_storage::utxo::contract::decode_undo_record;
use bitcoin_rs_storage::{ColumnFamily, KvStore, StorageBackend, block_undo_key};
use bytes::Bytes;
use sha2::{Digest, Sha256};

use crate::error::ConvertError;
use crate::fs_util::check_symlink_final_component;
use crate::report::{FamilyResetReport, RebuildIndexReport};
use crate::target::open_destination_store;

use bitcoin_rs_storage::checkpoint::CURRENT_SCHEMA_VERSION;
const CURRENT_SCHEMA_MAX_BYTES: u64 = 16;
const BLOCK_FILE_MAGIC: [u8; 4] = *b"BRSB";
const RECORD_HEADER_LEN: usize = 44;
const RECORD_HEADER_LEN_U64: u64 = 44;
const BLOCK_HEADER_LEN: usize = 80;
const MAX_BLOCK_RECORD_BYTES: usize = 4 * 1024 * 1024;
const MAX_BLOCK_RECORD_BYTES_U64: u64 = 4 * 1024 * 1024;
const ZERO_HASH: [u8; 32] = [0u8; 32];

/// Refuses any reservation past `cap`, so the index builder spills sorted runs instead of exceeding the operator's budget.
struct RebuildBudget {
    cap: u64,
    ledger: Mutex<RebuildLedger>,
    refusals: AtomicU64,
}

#[derive(Default)]
struct RebuildLedger {
    reserved: u64,
    charged: u64,
}

impl RebuildBudget {
    fn new(cap: u64) -> Self {
        Self {
            cap,
            ledger: Mutex::new(RebuildLedger::default()),
            refusals: AtomicU64::new(0),
        }
    }

    fn refusals(&self) -> u64 {
        self.refusals.load(Ordering::SeqCst)
    }

    fn lock(&self) -> MutexGuard<'_, RebuildLedger> {
        self.ledger.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn headroom(&self, ledger: &RebuildLedger) -> u64 {
        self.cap
            .saturating_sub(ledger.reserved.saturating_add(ledger.charged))
    }
}

impl BudgetCharge for RebuildBudget {
    fn reserve_bytes(&self, _owner: BudgetOwner, bytes: u64) -> Result<(), BudgetError> {
        let mut ledger = self.lock();
        if bytes > self.headroom(&ledger) {
            self.refusals.fetch_add(1, Ordering::SeqCst);
            return Err(BudgetError::BudgetExhausted);
        }
        ledger.reserved = ledger.reserved.saturating_add(bytes);
        Ok(())
    }

    fn allocate_bytes(&self, _owner: BudgetOwner, bytes: u64) -> Result<(), BudgetError> {
        let mut ledger = self.lock();
        if bytes > ledger.reserved {
            return Err(BudgetError::UnreservedAllocation);
        }
        ledger.reserved = ledger.reserved.saturating_sub(bytes);
        ledger.charged = ledger.charged.saturating_add(bytes);
        Ok(())
    }

    fn release_bytes(&self, _owner: BudgetOwner, bytes: u64) {
        let mut ledger = self.lock();
        ledger.charged = ledger.charged.saturating_sub(bytes);
    }

    fn available_bytes(&self, _owner: BudgetOwner) -> u64 {
        let ledger = self.lock();
        self.headroom(&ledger)
    }

    fn ensure_available_bytes(&self, owner: BudgetOwner, bytes: u64) -> Result<(), BudgetError> {
        if bytes > self.available_bytes(owner) {
            return Err(BudgetError::BudgetExhausted);
        }
        Ok(())
    }
}

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

struct RecordRef {
    parent: [u8; 32],
    height: u32,
    file: usize,
    offset: u64,
    len: u32,
}

struct BlockArchive {
    files: Vec<PathBuf>,
    records: HashMap<[u8; 32], RecordRef>,
}

struct Frame {
    len: u32,
    height: u32,
    hash: [u8; 32],
    parent: [u8; 32],
    record_end: u64,
}

type PrevoutMap = HashMap<([u8; 32], u32), (u64, Bytes, u32, bool)>;

const GENERATION_FAMILIES: [ColumnFamily; 6] = [
    ColumnFamily::TxDir,
    ColumnFamily::ScriptDict,
    ColumnFamily::ScriptPost,
    ColumnFamily::SpendDir,
    ColumnFamily::ScriptStats,
    ColumnFamily::Filters,
];

const GENERATION_KEY_LIMIT: [u8; 32] = [0xFF; 32];
const GENERATION_META_START: &[u8] = b"gen/";
const GENERATION_META_END: &[u8] = b"gen0";

fn clear_generations(store: &dyn KvStore) -> Result<(), ConvertError> {
    store.delete_range(
        ColumnFamily::IdxMeta,
        GENERATION_META_START,
        GENERATION_META_END,
    )?;
    for cf in GENERATION_FAMILIES {
        store.delete_range(cf, &[], &GENERATION_KEY_LIMIT)?;
    }
    Ok(())
}

pub(crate) fn run_rebuild_index(
    datadir: &Path,
    budget_bytes: usize,
) -> Result<RebuildIndexReport, ConvertError> {
    if !datadir.is_dir() {
        return Err(ConvertError::InvalidOperation(format!(
            "datadir '{}' is not a directory",
            datadir.display()
        )));
    }
    read_datadir_epoch(datadir)?;
    let txindex_dir = datadir.join("txindex");
    check_symlink_final_component(&txindex_dir)?;
    if !txindex_dir.is_dir() {
        return Err(ConvertError::InvalidOperation(format!(
            "datadir '{}' has no txindex namespace to rebuild",
            datadir.display()
        )));
    }
    let chainstate_dir = datadir.join("chainstate");
    let engine = detect_engine(&txindex_dir, &chainstate_dir, datadir)?;
    let store = open_destination_store(&txindex_dir, engine)?;
    let chainstate_store: Option<Box<dyn KvStore>> = if chainstate_dir.is_dir() {
        Some(open_destination_store(&chainstate_dir, engine)?)
    } else {
        None
    };
    let head = load_durable_head(chainstate_store.as_deref())?;
    let archive = scan_archive(&datadir.join("blocks"))?;
    let canonical = canonical_chain(&archive, head)?;
    for hash in &canonical {
        let _block = committed_block(chainstate_store.as_deref(), &archive, hash)?;
    }
    let reset = bitcoin_rs_projection::reset_offline(store.as_ref())
        .map_err(|error| ConvertError::IncompatibleData(error.to_string()))?;
    clear_generations(store.as_ref())?;
    let gen_id = 1u64;

    let scratch_dir = datadir.join("txindex_rebuild_scratch");
    check_symlink_final_component(&scratch_dir)?;
    let scratch_guard = ScratchGuard::create(scratch_dir)?;
    let budget = std::sync::Arc::new(RebuildBudget::new(
        u64::try_from(budget_bytes).unwrap_or(u64::MAX),
    ));
    let builder = BulkSegmentBuilder::new(budget.clone(), None, scratch_guard.path.clone());
    let from_genesis = canonical
        .first()
        .is_some_and(|hash| archive.records[hash].height == 0);
    let capabilities = IndexCapabilities::TX_AND_SCRIPTS.with_compact_filters(from_genesis);
    let builder = if from_genesis {
        builder
    } else {
        builder.without_filter()
    };
    let mut stream = builder.stream(gen_id);
    let mut blocks = 0u64;
    let mut tx_total = 0usize;
    for hash in &canonical {
        let block = committed_block(chainstate_store.as_deref(), &archive, hash)?;
        tx_total = tx_total.saturating_add(block.txs.len());
        stream.push_block(&block)?;
        blocks = blocks.saturating_add(1);
    }
    let coverage = if blocks == 0 {
        Coverage::new(0, 0, [0u8; 32])
    } else {
        stream.finish(store.as_ref())?
    };
    let next_ordinal = u32::try_from(tx_total).unwrap_or(u32::MAX);
    bitcoin_rs_projection::segment::publish_bulk_generation(
        store.as_ref(),
        gen_id,
        coverage,
        next_ordinal,
        capabilities,
    )
    .map_err(|error| ConvertError::IncompatibleData(error.to_string()))?;
    drop(scratch_guard);

    Ok(RebuildIndexReport {
        datadir: datadir.display().to_string(),
        engine: engine.as_str().to_owned(),
        format_version: reset.format_version,
        blocks,
        budget_refusals: budget.refusals(),
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

fn detect_engine(
    txindex_dir: &Path,
    chainstate_dir: &Path,
    datadir: &Path,
) -> Result<StorageBackend, ConvertError> {
    if let Some(engine) = bitcoin_rs_storage::detect_engine(txindex_dir)? {
        return Ok(engine);
    }
    if let Some(engine) = bitcoin_rs_storage::detect_engine(chainstate_dir)? {
        return Ok(engine);
    }
    Err(ConvertError::IncompatibleData(format!(
        "cannot detect storage engine for datadir '{}': txindex is empty and chainstate engine is missing or unrecognized",
        datadir.display()
    )))
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
    if epoch != CURRENT_SCHEMA_VERSION {
        return Err(ConvertError::UnknownEpoch(epoch));
    }
    Ok(())
}

fn load_durable_head(store: Option<&dyn KvStore>) -> Result<Option<DurableHead>, ConvertError> {
    let Some(store) = store else {
        return Ok(None);
    };
    let Some(bytes) = store.get(ColumnFamily::UtxoMeta, DURABLE_HEAD_KEY)? else {
        return Ok(None);
    };
    DurableHead::decode(&bytes).map(Some).ok_or_else(|| {
        ConvertError::IncompatibleData("chainstate durable head is unreadable".to_owned())
    })
}

fn scan_archive(blocks_dir: &Path) -> Result<BlockArchive, ConvertError> {
    let mut files = Vec::new();
    if blocks_dir.is_dir() {
        let mut entries = std::fs::read_dir(blocks_dir)?
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                name.starts_with("blk") && name.ends_with(".dat")
            })
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.file_name());
        files = entries
            .into_iter()
            .map(|entry| entry.path())
            .collect::<Vec<_>>();
    }
    let mut records = HashMap::new();
    for (file_no, path) in files.iter().enumerate() {
        scan_block_file(path, file_no, &mut records)?;
    }
    Ok(BlockArchive { files, records })
}

fn scan_block_file(
    path: &Path,
    file_no: usize,
    records: &mut HashMap<[u8; 32], RecordRef>,
) -> Result<(), ConvertError> {
    let file_name = path.display().to_string();
    let file = File::open(path)?;
    let file_len = file.metadata()?.len();
    let mut reader = BufReader::new(file);
    let mut offset = 0u64;
    let mut index = 0u64;
    while offset < file_len {
        let frame = read_frame(&mut reader, &file_name, index, offset, file_len)?;
        index_record(records, file_no, offset, &frame)?;
        offset = frame.record_end;
        index += 1;
    }
    Ok(())
}

fn read_frame(
    reader: &mut BufReader<File>,
    file_name: &str,
    index: u64,
    offset: u64,
    file_len: u64,
) -> Result<Frame, ConvertError> {
    if file_len - offset < RECORD_HEADER_LEN_U64 {
        return Err(ConvertError::TruncatedBlockRecord {
            file: file_name.to_owned(),
            index,
        });
    }
    let mut header = [0u8; RECORD_HEADER_LEN];
    reader.read_exact(&mut header)?;
    if header[..4] != BLOCK_FILE_MAGIC {
        return Err(ConvertError::BadBlockMagic {
            file: file_name.to_owned(),
            index,
        });
    }
    let len = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
    let height = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&header[12..44]);
    let len_usize = usize::try_from(len).map_err(|_| ConvertError::OversizeBlockRecord {
        file: file_name.to_owned(),
        index,
        len,
        max: MAX_BLOCK_RECORD_BYTES_U64,
    })?;
    if len_usize > MAX_BLOCK_RECORD_BYTES {
        return Err(ConvertError::OversizeBlockRecord {
            file: file_name.to_owned(),
            index,
            len,
            max: MAX_BLOCK_RECORD_BYTES_U64,
        });
    }
    if len_usize < BLOCK_HEADER_LEN {
        return Err(ConvertError::UnparseableBlock {
            height,
            hash: hex(&hash),
            reason: "record body is shorter than a block header".to_owned(),
        });
    }
    let record_end = offset
        .checked_add(RECORD_HEADER_LEN_U64)
        .and_then(|header_end| header_end.checked_add(u64::from(len)))
        .filter(|end| *end <= file_len)
        .ok_or_else(|| ConvertError::TruncatedBlockRecord {
            file: file_name.to_owned(),
            index,
        })?;
    let mut body_header = [0u8; BLOCK_HEADER_LEN];
    reader.read_exact(&mut body_header)?;
    let computed = double_sha256(&body_header);
    if computed != hash {
        return Err(ConvertError::BlockHashMismatch {
            height,
            recorded: hex(&hash),
            computed: hex(&computed),
        });
    }
    let mut parent = [0u8; 32];
    parent.copy_from_slice(&body_header[4..36]);
    reader.seek(SeekFrom::Start(record_end))?;
    Ok(Frame {
        len,
        height,
        hash,
        parent,
        record_end,
    })
}

fn index_record(
    records: &mut HashMap<[u8; 32], RecordRef>,
    file: usize,
    offset: u64,
    frame: &Frame,
) -> Result<(), ConvertError> {
    match records.entry(frame.hash) {
        Entry::Occupied(existing) => {
            let existing = existing.get();
            if existing.parent != frame.parent
                || existing.height != frame.height
                || existing.len != frame.len
            {
                return Err(ConvertError::ConflictingBlockRecord {
                    height: frame.height,
                    hash: hex(&frame.hash),
                });
            }
            Ok(())
        }
        Entry::Vacant(slot) => {
            slot.insert(RecordRef {
                parent: frame.parent,
                height: frame.height,
                file,
                offset,
                len: frame.len,
            });
            Ok(())
        }
    }
}

fn canonical_chain(
    archive: &BlockArchive,
    head: Option<DurableHead>,
) -> Result<Vec<[u8; 32]>, ConvertError> {
    let Some(head) = head else {
        if archive.records.is_empty() {
            return Ok(Vec::new());
        }
        return Err(ConvertError::MissingDurableHead);
    };
    if head.height == 0 {
        return Ok(Vec::new());
    }
    let mut chain = Vec::new();
    let mut cursor = head.tip.to_le_bytes();
    let mut height = head.height;
    loop {
        let Some(record) = archive.records.get(&cursor) else {
            if chain.is_empty() {
                return Err(ConvertError::MissingTipRecord {
                    height,
                    hash: hex(&cursor),
                });
            }
            if archive.records.values().any(|other| other.height <= height) {
                return Err(ConvertError::CanonicalChainBroken {
                    height,
                    hash: hex(&cursor),
                    reason: "the archived parent is missing while earlier blocks remain",
                });
            }
            break;
        };
        if record.height != height {
            return Err(ConvertError::BlockHeightMismatch {
                recorded: record.height,
                expected: height,
                hash: hex(&cursor),
            });
        }
        chain.push(cursor);
        if record.parent == ZERO_HASH {
            if height != 0 {
                return Err(ConvertError::CanonicalChainBroken {
                    height,
                    hash: hex(&cursor),
                    reason: "the record claims the zero parent above height zero",
                });
            }
            break;
        }
        if height == 0 {
            return Err(ConvertError::CanonicalChainBroken {
                height,
                hash: hex(&cursor),
                reason: "the record claims a parent below height zero",
            });
        }
        height -= 1;
        cursor = record.parent;
    }
    chain.reverse();
    Ok(chain)
}

fn committed_block(
    store: Option<&dyn KvStore>,
    archive: &BlockArchive,
    hash: &[u8; 32],
) -> Result<CommittedBlock, ConvertError> {
    let record = archive.records.get(hash).ok_or_else(|| {
        ConvertError::IncompatibleData(
            "canonical block is absent from the archive index".to_owned(),
        )
    })?;
    let body = read_record_body(archive, record)?;
    let image = BlockImage::from_raw(Bytes::from(body)).map_err(|error| {
        ConvertError::UnparseableBlock {
            height: record.height,
            hash: hex(hash),
            reason: error.to_string(),
        }
    })?;
    let computed = image.block_hash().0.to_le_bytes();
    if computed != *hash {
        return Err(ConvertError::BlockHashMismatch {
            height: record.height,
            recorded: hex(hash),
            computed: hex(&computed),
        });
    }
    let mut prevouts = load_undo_prevouts(store, record.height, *hash)?;
    let txs = (0..image.tx_count())
        .map(|index| tx_facts(&image, index, record.height, hash, &mut prevouts))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CommittedBlock {
        height: record.height,
        hash: *hash,
        parent_hash: image.header().prev_blockhash.0.to_le_bytes(),
        header: image.header_bytes(),
        txs,
    })
}

fn tx_facts(
    image: &BlockImage,
    index: usize,
    height: u32,
    block_hash: &[u8; 32],
    prevouts: &mut PrevoutMap,
) -> Result<TxFacts, ConvertError> {
    let tx = image.tx(index);
    let txid = *tx.txid().as_bytes();
    let coinbase = tx.is_coinbase();
    let inputs = if coinbase {
        Vec::new()
    } else {
        tx_inputs(&tx, height, block_hash, prevouts)?
    };
    let outputs = tx_outputs(&tx, txid, height, coinbase, prevouts)?;
    Ok(TxFacts {
        txid,
        offset: tx.layout().span().start(),
        len: tx.layout().span().len(),
        inputs,
        outputs,
    })
}

fn tx_inputs(
    tx: &bitcoin_rs_consensus::primitives::TransactionView<'_>,
    height: u32,
    block_hash: &[u8; 32],
    prevouts: &PrevoutMap,
) -> Result<Vec<SpentPrevout>, ConvertError> {
    let mut inputs = Vec::with_capacity(tx.input_count());
    for index in 0..tx.input_count() {
        let outpoint = tx.input_outpoint(index);
        let prev_txid = *outpoint.txid.as_bytes();
        let (value, script, coin_height, coinbase) = prevouts
            .get(&(prev_txid, outpoint.vout))
            .cloned()
            .ok_or_else(|| ConvertError::MissingUndoRow {
                height,
                hash: hex(block_hash),
                txid: hex(&prev_txid),
                vout: outpoint.vout,
            })?;
        inputs.push(SpentPrevout {
            txid: prev_txid,
            vout: outpoint.vout,
            value,
            script,
            height: coin_height,
            coinbase,
        });
    }
    Ok(inputs)
}

fn tx_outputs(
    tx: &bitcoin_rs_consensus::primitives::TransactionView<'_>,
    txid: [u8; 32],
    height: u32,
    coinbase: bool,
    prevouts: &mut PrevoutMap,
) -> Result<Vec<CreatedOutput>, ConvertError> {
    let mut outputs = Vec::with_capacity(tx.output_count());
    for index in 0..tx.output_count() {
        let vout = u32::try_from(index).map_err(|_| span_overflow())?;
        let script = Bytes::copy_from_slice(tx.output_script(index));
        let value = tx.output_value(index).to_sat();
        prevouts.insert((txid, vout), (value, script.clone(), height, coinbase));
        outputs.push(CreatedOutput {
            vout,
            value,
            script,
        });
    }
    Ok(outputs)
}

fn span_overflow() -> ConvertError {
    ConvertError::IncompatibleData("transaction span exceeds u32".to_owned())
}

fn read_record_body(archive: &BlockArchive, record: &RecordRef) -> Result<Vec<u8>, ConvertError> {
    let path = archive.files.get(record.file).ok_or_else(|| {
        ConvertError::IncompatibleData("archive record names an absent block file".to_owned())
    })?;
    let mut file = File::open(path)?;
    let body_offset = record
        .offset
        .checked_add(RECORD_HEADER_LEN_U64)
        .ok_or_else(|| ConvertError::IncompatibleData("archive offset overflow".to_owned()))?;
    file.seek(SeekFrom::Start(body_offset))?;
    let mut body = vec![
        0u8;
        usize::try_from(record.len).map_err(|_| {
            ConvertError::IncompatibleData("archive record length exceeds usize".to_owned())
        })?
    ];
    file.read_exact(&mut body)?;
    Ok(body)
}

fn load_undo_prevouts(
    store: Option<&dyn KvStore>,
    height: u32,
    hash: [u8; 32],
) -> Result<PrevoutMap, ConvertError> {
    let mut prevouts = PrevoutMap::new();
    let Some(store) = store else {
        return Ok(prevouts);
    };
    let block_hash = Hash256::from_le_bytes(&hash);
    let Some(bytes) = store.get(ColumnFamily::UndoData, &block_undo_key(height, block_hash))?
    else {
        return Ok(prevouts);
    };
    let batch = decode_undo_record(&bytes, block_hash).map_err(|source| {
        ConvertError::UnreadableUndoRow {
            height,
            hash: hex(&hash),
            source,
        }
    })?;
    for add in batch.restores() {
        prevouts.insert(
            (*add.outpoint.txid.as_bytes(), add.outpoint.vout),
            (
                add.txout.value.to_sat(),
                Bytes::copy_from_slice(&add.txout.script_pubkey),
                add.height,
                add.coinbase,
            ),
        );
    }
    Ok(prevouts)
}

fn double_sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(Sha256::digest(bytes));
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rebuild_accepts_current_epoch_datadir() -> Result<(), String> {
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let marker = dir.path().join("CURRENT_SCHEMA");
        let contents = format!("{CURRENT_SCHEMA_VERSION}\n");
        std::fs::write(&marker, contents.as_bytes()).map_err(|e| e.to_string())?;
        read_datadir_epoch(dir.path()).map_err(|e| e.to_string())?;
        Ok(())
    }
}
