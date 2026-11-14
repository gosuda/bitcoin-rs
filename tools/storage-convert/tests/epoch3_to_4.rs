use std::collections::HashMap;
use std::fs::{self, File};
use std::path::Path;
use tempfile::tempdir;

use bitcoin_rs_consensus::primitives::{
    Amount, Block, BlockImage, CompactTarget, ConsensusEncode, Hash256, Header, LockTime, OutPoint,
    Script, Sequence, Tx, TxIn, TxOut, Txid, Witness, hex::hex_encode,
};
use bitcoin_rs_storage::checkpoint::{
    CHECKPOINT_ROOT, COINSTATS_FILE, CURRENT_FILE, CheckpointManifestV1, CurrentV1, HEADERS_FILE,
    MANIFEST_FILE,
};
const UTXO_FILE: &str = "utxo-v4.dat";
use bitcoin_rs_storage::durable_head::{DURABLE_HEAD_KEY, DurableHead};
use bitcoin_rs_storage::pruning::{block_body_key, block_undo_key};
use bitcoin_rs_storage::utxo::contract::{
    BlockChangeInputs, SpentOutputLookup, build_block_changes,
};
use bitcoin_rs_storage::utxo::record::{OwnedUtxoOut, UtxoRecord};
use bitcoin_rs_storage::utxo::snapshot::{SnapshotLoad, read_snapshot_strict_v4};
use bitcoin_rs_storage::utxo::{UtxoCoin, UtxoSet};
use bitcoin_rs_storage::{ColumnFamily, FlatFileBlockStore, KvStore, RocksDbStore};
use sha2::{Digest, Sha256};

use super::support::error::{TestError, TestResult};
use super::support::harness::{parse_report, recursive_dir_digest, run_converter};
use super::support::oracle::write_schema_marker;

fn encode_undo_v1(
    batch: &bitcoin_rs_storage::utxo::contract::UndoBatch,
    block_hash: Hash256,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(1);
    out.extend_from_slice(&block_hash.to_le_bytes());
    let restores = batch.restores();
    let restore_len = u32::try_from(restores.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&restore_len.to_le_bytes());
    for add in restores {
        let outpoint = add.outpoint;
        let txid = outpoint.txid;
        let vout = outpoint.vout;
        out.extend_from_slice(txid.as_bytes());
        out.extend_from_slice(&vout.to_le_bytes());
        add.txout.consensus_encode(&mut out);
        out.push(u8::from(add.coinbase));
        out.extend_from_slice(&add.height.to_le_bytes());
    }
    let removes = batch.removes();
    let remove_len = u32::try_from(removes.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&remove_len.to_le_bytes());
    for outpoint in removes {
        let txid = outpoint.txid;
        let vout = outpoint.vout;
        out.extend_from_slice(txid.as_bytes());
        out.extend_from_slice(&vout.to_le_bytes());
    }
    out
}
struct MapSpentLookup<'a>(&'a HashMap<OutPoint, UtxoCoin>);

impl SpentOutputLookup for MapSpentLookup<'_> {
    fn entry(&self, outpoint: &OutPoint) -> Option<&UtxoCoin> {
        self.0.get(outpoint)
    }
}

pub(crate) struct Epoch3FixtureAnchor {
    pub tip: Hash256,
    pub snapshot: SnapshotLoad,
}

fn fixture_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/epoch3-regtest")
}

fn copy_fixture(from: &Path, to: &Path) -> TestResult<()> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let destination = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_fixture(&entry.path(), &destination)?;
        } else {
            fs::copy(entry.path(), destination)?;
        }
    }
    Ok(())
}

/// Stages the checked-in canonical epoch-3 regtest datadir at `root` and
/// returns the anchored checkpoint facts read back from the staged manifest
/// and snapshot, so callers never invent tip, height, or count values.
pub(crate) fn stage_canonical_epoch3_source(root: &Path) -> TestResult<Epoch3FixtureAnchor> {
    copy_fixture(&fixture_dir(), root)?;
    let generation = root.join(CHECKPOINT_ROOT).join("gen-00000000000000000001");
    let manifest: CheckpointManifestV1 =
        sonic_rs::from_slice(&fs::read(generation.join(MANIFEST_FILE))?)
            .map_err(|error| TestError::Assertion(format!("fixture manifest: {error}")))?;
    let tip = Hash256::from_str_be(&manifest.applied_tip.hash)
        .map_err(|error| TestError::Assertion(format!("fixture applied tip: {error}")))?;
    let utxo = manifest
        .utxo
        .as_ref()
        .ok_or_else(|| TestError::Assertion("fixture manifest lacks a utxo payload".into()))?;
    let mut snapshot_file = File::open(generation.join(&utxo.file))?;
    let snapshot = read_snapshot_strict_v4(&mut snapshot_file)
        .map_err(|error| TestError::Assertion(format!("fixture snapshot: {error}")))?;
    if snapshot.height != manifest.applied_tip.height || snapshot.tip_hash != tip {
        return Err(TestError::Assertion(
            "fixture snapshot contradicts its manifest anchor".into(),
        ));
    }
    Ok(Epoch3FixtureAnchor { tip, snapshot })
}

/// First coin of the staged snapshot in a deterministic (txid, vout) order,
/// returned with the same owned fields the converter reconstructs.
fn first_snapshot_coin(snapshot: &SnapshotLoad) -> TestResult<(Hash256, OwnedUtxoOut)> {
    let mut records = snapshot.set.all_records();
    records.sort_by_key(|record| record.txid().to_le_bytes());
    let record = records
        .first()
        .ok_or_else(|| TestError::Assertion("fixture snapshot holds no coin records".into()))?;
    let coin = record
        .outputs()
        .next()
        .ok_or_else(|| TestError::Assertion("fixture snapshot record holds no outputs".into()))?;
    Ok((
        record.txid(),
        OwnedUtxoOut {
            vout: coin.vout,
            value: coin.value,
            script_pubkey: coin.script_pubkey.to_vec(),
            coinbase: coin.coinbase,
            height: coin.height,
        },
    ))
}

fn read_durable_head(store: &RocksDbStore) -> TestResult<DurableHead> {
    let raw = store
        .get(ColumnFamily::UtxoMeta, DURABLE_HEAD_KEY)?
        .ok_or_else(|| TestError::Assertion("staged source lacks a durable head".into()))?;
    DurableHead::decode(&raw)
        .ok_or_else(|| TestError::Assertion("staged durable head is undecodable".into()))
}

/// Moves the staged canonical head to a real suffix block without touching
/// the source's commit id or assumeutxo state.
fn promote_durable_head(
    store: &RocksDbStore,
    base: &DurableHead,
    height: u32,
    tip: Hash256,
    chain_tx_count: u64,
) -> TestResult<DurableHead> {
    let mut head = *base;
    head.height = height;
    head.tip = tip;
    head.chain_tx_count = chain_tx_count;
    store.put(ColumnFamily::UtxoMeta, DURABLE_HEAD_KEY, &head.encode())?;
    Ok(head)
}

fn append_block_and_undo(
    root: &Path,
    cs_store: &RocksDbStore,
    height: u32,
    prev_hash: Hash256,
    txs: Vec<Tx>,
    utxo_set: &UtxoSet,
) -> TestResult<(Block, Hash256)> {
    let header = Header {
        version: 1,
        prev_blockhash: bitcoin_rs_consensus::primitives::BlockHash(prev_hash),
        merkle_root: Hash256::from_le_bytes(&[0u8; 32]),
        time: 1_700_000_000 + height,
        bits: CompactTarget::from_consensus(0x1d00ffff),
        nonce: txs.first().map_or(height, |tx| {
            let bytes = Hash256::from(tx.txid());
            let head = bytes.as_byte_array();
            u32::from_le_bytes([head[0], head[1], head[2], head[3]])
        }),
    };
    let block = Block { header, txs };
    let block_hash = block.block_hash();
    let block_hash_256 = Hash256::from(block_hash);

    let mut body_bytes = Vec::new();
    block.consensus_encode(&mut body_bytes);

    let blocks_dir = root.join("blocks");
    fs::create_dir_all(&blocks_dir)?;
    let flat_store = FlatFileBlockStore::open(root)?;
    let pos = flat_store.append(height, *block_hash.as_bytes(), &body_bytes)?;

    let mut batch = cs_store.new_batch();
    batch.put(
        ColumnFamily::BlockBodies,
        &block_body_key(height, block_hash_256),
        &pos.encode(),
    );

    let spent_lookup_map: HashMap<OutPoint, UtxoCoin> = block
        .txs
        .iter()
        .filter(|tx| !tx.is_coinbase())
        .flat_map(|tx| &tx.inputs)
        .filter_map(|input| {
            utxo_set
                .get_entry(&input.previous_output)
                .map(|coin| (input.previous_output, coin))
        })
        .collect();
    let block_txids_set: hashbrown::HashSet<Txid> = block.txs.iter().map(|tx| tx.txid()).collect();
    let same_block_spent: hashbrown::HashSet<OutPoint> = block
        .txs
        .iter()
        .filter(|tx| !tx.is_coinbase())
        .flat_map(|tx| &tx.inputs)
        .map(|input| input.previous_output)
        .filter(|prev| block_txids_set.contains(&prev.txid))
        .collect();
    let txids: Vec<Txid> = block.txs.iter().map(|tx| tx.txid()).collect();
    let image = BlockImage::from_local(block.clone());
    let change_inputs = BlockChangeInputs {
        block: &image,
        height,
        txids: &txids,
        same_block_spent: Some(&same_block_spent),
        add_capacity: block.txs.iter().map(|t| t.outputs.len()).sum(),
        remove_capacity: block.txs.iter().map(|t| t.inputs.len()).sum(),
        max_script_size: 10_000,
    };

    let (changes, undo, _totals) =
        build_block_changes(&change_inputs, &MapSpentLookup(&spent_lookup_map))
            .map_err(|e| TestError::Assertion(format!("build_block_changes failed: {e}")))?;

    for add in changes.adds() {
        let out = bitcoin_rs_storage::utxo::record::OwnedUtxoOut {
            vout: add.outpoint.vout,
            value: add.txout.value.to_sat(),
            script_pubkey: add.txout.script_pubkey.to_vec(),
            coinbase: add.coinbase,
            height: add.height,
        };
        let record = UtxoRecord::from_owned_outputs(add.outpoint.txid.into(), &[out])
            .map_err(|e| TestError::Assertion(e.to_string()))?;
        utxo_set.insert_parsed_record(record);
    }

    let undo_bytes = encode_undo_v1(&undo, block_hash_256);
    batch.put(
        ColumnFamily::UndoData,
        &block_undo_key(height, block_hash_256),
        &undo_bytes,
    );

    cs_store.write_durable(batch)?;
    Ok((block, block_hash_256))
}

#[test]
fn missing_block_data_reports_first_missing_height() -> TestResult<()> {
    let source_temp = tempdir()?;
    let dest_temp = tempdir()?;
    let from_path = source_temp.path();
    let to_path = dest_temp.path().join("converted");

    let anchor = stage_canonical_epoch3_source(from_path)?;
    let cs_store = RocksDbStore::open(from_path.join("chainstate"))?;
    let base_head = read_durable_head(&cs_store)?;
    let suffix_height = base_head
        .height
        .checked_add(1)
        .ok_or_else(|| TestError::Assertion("suffix height overflow".into()))?;

    let (_block, block_hash) = append_block_and_undo(
        from_path,
        &cs_store,
        suffix_height,
        anchor.tip,
        vec![coinbase_tx(0x65, 50_000)],
        &anchor.snapshot.set,
    )?;

    promote_durable_head(
        &cs_store,
        &base_head,
        suffix_height,
        block_hash,
        base_head.chain_tx_count.saturating_add(1),
    )?;

    let mut del_batch = cs_store.new_batch();
    del_batch.delete(
        ColumnFamily::UndoData,
        &block_undo_key(suffix_height, block_hash),
    );
    cs_store.write_durable(del_batch)?;
    drop(cs_store);

    let from_str = from_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("utf8".into()))?;
    let to_str = to_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("utf8".into()))?;
    let output = run_converter(&["--from", from_str, "--to", to_str])?;

    if output.status.success() {
        return Err(TestError::Assertion(
            "converter should fail when block data is missing".into(),
        ));
    }
    let expected = format!("height {suffix_height}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.contains(&expected) {
        return Err(TestError::Assertion(format!(
            "expected stderr to report missing {expected}, got: {stderr}"
        )));
    }

    Ok(())
}

#[test]
fn missing_checkpoint_refuses_before_writes() -> TestResult<()> {
    let source_temp = tempdir()?;
    let dest_temp = tempdir()?;
    let from_path = source_temp.path();
    let to_path = dest_temp.path().join("converted");

    write_schema_marker(from_path, 3)?;
    let cs_store = RocksDbStore::open(from_path.join("chainstate"))?;
    cs_store.put(ColumnFamily::UtxoMeta, b"key", b"val")?;
    drop(cs_store);

    let source_digest_before = recursive_dir_digest(from_path)?;

    let from_str = from_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("utf8".into()))?;
    let to_str = to_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("utf8".into()))?;
    let output = run_converter(&["--from", from_str, "--to", to_str])?;

    if output.status.success() {
        return Err(TestError::Assertion(
            "converter should fail without checkpoint".into(),
        ));
    }

    let source_digest_after = recursive_dir_digest(from_path)?;
    if source_digest_before != source_digest_after {
        return Err(TestError::Assertion("source tree modified".into()));
    }

    if to_path.exists() {
        let entries: Vec<_> = fs::read_dir(&to_path)?.collect();
        if !entries.is_empty() {
            return Err(TestError::Assertion(
                "destination must be empty after refusal".into(),
            ));
        }
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.contains("checkpoint") && !stderr.contains("resync") {
        return Err(TestError::Assertion(format!(
            "expected stderr to mention missing checkpoint and resync, got: {stderr}"
        )));
    }

    Ok(())
}

#[test]
fn replay_with_checkpoint_at_durable_head() -> TestResult<()> {
    let source_temp = tempdir()?;
    let dest_temp = tempdir()?;
    let from_path = source_temp.path();
    let to_path = dest_temp.path().join("converted");

    let anchor = stage_canonical_epoch3_source(from_path)?;
    let (txid1, _coin_out) = first_snapshot_coin(&anchor.snapshot)?;
    let from_str = from_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("utf8".into()))?;
    let to_str = to_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("utf8".into()))?;
    let output = run_converter(&["--from", from_str, "--to", to_str])?;
    let report = parse_report(&output)?;

    if report.source_epoch != 3 || report.target_epoch != 6 {
        return Err(TestError::Assertion("unexpected report epochs".into()));
    }
    let dest_schema = fs::read_to_string(to_path.join("CURRENT_SCHEMA"))?;
    if dest_schema != "6\n" {
        return Err(TestError::Assertion("expected 6\n".into()));
    }

    let dest_store = RocksDbStore::open(to_path.join("chainstate"))?;
    let r1 = dest_store.get(ColumnFamily::Coins, &txid1.to_le_bytes())?;
    if r1.is_none() {
        return Err(TestError::Assertion(
            "checkpoint coin txid1 must exist in coins CF".into(),
        ));
    }

    Ok(())
}

fn assert_engine_digest_matches_image(generation_dir: &Path) -> TestResult<()> {
    let manifest: CheckpointManifestV1 =
        sonic_rs::from_slice(&fs::read(generation_dir.join(MANIFEST_FILE))?)?;
    let Some(expected) = manifest.engine.as_ref() else {
        return Err(TestError::Assertion(
            "converted generation manifest lacks an engine digest".into(),
        ));
    };
    let chainstate = cap_std::fs::Dir::open_ambient_dir(
        generation_dir.join("chainstate"),
        cap_std::ambient_authority(),
    )?;
    let actual = bitcoin_rs_storage::checkpoint::digest_engine_dir(&chainstate)
        .map_err(|error| TestError::Assertion(error.to_string()))?;
    if actual != *expected {
        return Err(TestError::Assertion(
            "converted generation manifest digest does not match its image".into(),
        ));
    }
    Ok(())
}

#[test]
fn converted_datadir_drops_old_checkpoint_coin_image() -> TestResult<()> {
    let source_temp = tempdir()?;
    let dest_temp = tempdir()?;
    let from_path = source_temp.path();
    let to_path = dest_temp.path().join("converted");

    stage_canonical_epoch3_source(from_path)?;
    let cs_store = RocksDbStore::open(from_path.join("chainstate"))?;
    let durable_head = read_durable_head(&cs_store)?;
    drop(cs_store);

    let from_str = from_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("utf8".into()))?;
    let to_str = to_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("utf8".into()))?;
    let output = run_converter(&["--from", from_str, "--to", to_str])?;
    parse_report(&output)?;

    if let Some(stale) = find_file_named(&to_path, UTXO_FILE)? {
        return Err(TestError::Assertion(format!(
            "converted datadir carries an old checkpoint coin image at {}",
            stale.display()
        )));
    }

    let dest_store = RocksDbStore::open(to_path.join("chainstate"))?;
    let raw = dest_store
        .get(ColumnFamily::UtxoMeta, DURABLE_HEAD_KEY)?
        .ok_or_else(|| TestError::Assertion("converted durable head missing".into()))?;
    let converted = DurableHead::decode(&raw)
        .ok_or_else(|| TestError::Assertion("converted durable head undecodable".into()))?;
    if converted.height != durable_head.height || converted.tip != durable_head.tip {
        return Err(TestError::Assertion(format!(
            "converted durable head is at height {} tip {:?}, source at height {} tip {:?}",
            converted.height, converted.tip, durable_head.height, durable_head.tip
        )));
    }
    assert_engine_digest_matches_image(
        &to_path
            .join(bitcoin_rs_storage::checkpoint::CHECKPOINT_ROOT)
            .join("gen-00000000000000000001"),
    )?;
    Ok(())
}

#[test]
fn converted_historical_checkpoint_carries_engine_coins() -> TestResult<()> {
    let source_temp = tempdir()?;
    let dest_temp = tempdir()?;
    let from_path = source_temp.path();
    let to_path = dest_temp.path().join("converted");

    let anchor = stage_canonical_epoch3_source(from_path)?;
    let (txid1, coin_out) = first_snapshot_coin(&anchor.snapshot)?;

    let gen_name = "gen-00000000000000000001";
    let historical_source = from_path
        .join(bitcoin_rs_storage::checkpoint::HISTORICAL_CHECKPOINT_ROOT)
        .join(gen_name);
    fs::create_dir_all(&historical_source)?;
    for entry in fs::read_dir(from_path.join(CHECKPOINT_ROOT).join(gen_name))? {
        let entry = entry?;
        fs::copy(entry.path(), historical_source.join(entry.file_name()))?;
    }

    let from_str = from_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("utf8".into()))?;
    let to_str = to_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("utf8".into()))?;
    let output = run_converter(&["--from", from_str, "--to", to_str])?;
    parse_report(&output)?;

    let converted_gen = to_path
        .join(bitcoin_rs_storage::checkpoint::HISTORICAL_CHECKPOINT_ROOT)
        .join(gen_name);
    if converted_gen.join(UTXO_FILE).exists() {
        return Err(TestError::Assertion(
            "converted historical generation must not carry utxo-v4.dat".into(),
        ));
    }
    assert_engine_digest_matches_image(&converted_gen)?;
    let engine = RocksDbStore::open(converted_gen.join("chainstate"))?;
    let stored = engine
        .get(ColumnFamily::Coins, &txid1.to_le_bytes())?
        .ok_or_else(|| {
            TestError::Assertion(
                "historical checkpoint engine image lacks the checkpoint coin".into(),
            )
        })?;
    let stored_bytes: &[u8] = &stored;
    let expected = UtxoRecord::from_owned_outputs(txid1, &[coin_out])
        .map_err(|e| TestError::Assertion(e.to_string()))?;
    if stored_bytes != expected.bytes() {
        return Err(TestError::Assertion(
            "historical engine coin must hold the checkpoint's coin record".into(),
        ));
    }
    Ok(())
}

fn find_file_named(root: &Path, name: &str) -> TestResult<Option<std::path::PathBuf>> {
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        if path.is_dir() {
            if let Some(found) = find_file_named(&path, name)? {
                return Ok(Some(found));
            }
        } else if path.file_name().is_some_and(|file| file == name) {
            return Ok(Some(path));
        }
    }
    Ok(None)
}

fn coinbase_tx(tag: u8, value: u64) -> Tx {
    Tx {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: Script::from_bytes(vec![0x01, tag]),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: Script::from_bytes(vec![0x76, 0xa9, 0x14, tag, 0x88, 0xac]),
        }],
        lock_time: LockTime::ZERO,
    }
}

#[test]
fn replay_refuses_when_head_does_not_descend_from_checkpoint() -> TestResult<()> {
    let source_temp = tempdir()?;
    let dest_temp = tempdir()?;
    let from_path = source_temp.path();
    let to_path = dest_temp.path().join("converted");

    let anchor = stage_canonical_epoch3_source(from_path)?;
    let cs_store = RocksDbStore::open(from_path.join("chainstate"))?;
    let base_head = read_durable_head(&cs_store)?;
    let suffix_height = base_head
        .height
        .checked_add(1)
        .ok_or_else(|| TestError::Assertion("suffix height overflow".into()))?;

    let foreign_parent = Hash256::from_le_bytes(&[7u8; 32]);
    let (_block, block_hash) = append_block_and_undo(
        from_path,
        &cs_store,
        suffix_height,
        foreign_parent,
        vec![coinbase_tx(0xc3, 50_000)],
        &anchor.snapshot.set,
    )?;

    promote_durable_head(
        &cs_store,
        &base_head,
        suffix_height,
        block_hash,
        base_head.chain_tx_count.saturating_add(1),
    )?;
    drop(cs_store);

    let from_str = from_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("utf8".into()))?;
    let to_str = to_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("utf8".into()))?;
    let output = run_converter(&["--from", from_str, "--to", to_str])?;

    if output.status.success() {
        return Err(TestError::Assertion(
            "converter must refuse a durable head that does not descend from the checkpoint tip"
                .into(),
        ));
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.contains("ancestry") {
        return Err(TestError::Assertion(format!(
            "expected stderr to report the ancestry mismatch, got: {stderr}"
        )));
    }

    Ok(())
}

fn rewrite_manifest(root: &Path, mutate: impl FnOnce(&mut CheckpointManifestV1)) -> TestResult<()> {
    let root_dir = root.join(CHECKPOINT_ROOT);
    let current_path = root_dir.join(CURRENT_FILE);
    let current: CurrentV1 = sonic_rs::from_slice(&fs::read(&current_path)?)
        .map_err(|e| TestError::Assertion(format!("{e}")))?;
    let manifest_path = root_dir.join(&current.directory).join(MANIFEST_FILE);
    let mut manifest: CheckpointManifestV1 = sonic_rs::from_slice(&fs::read(&manifest_path)?)
        .map_err(|e| TestError::Assertion(format!("{e}")))?;
    mutate(&mut manifest);
    let manifest_bytes = sonic_rs::to_vec(&manifest)?;
    fs::write(&manifest_path, &manifest_bytes)?;
    let updated = CurrentV1 {
        manifest_sha256: hex_encode(&Sha256::digest(&manifest_bytes)),
        ..current
    };
    fs::write(&current_path, sonic_rs::to_vec(&updated)?)?;
    Ok(())
}

fn run_conversion_expecting_failure(from_path: &Path, to_path: &Path) -> TestResult<String> {
    let from_str = from_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("utf8".into()))?;
    let to_str = to_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("utf8".into()))?;
    let output = run_converter(&["--from", from_str, "--to", to_str])?;
    if output.status.success() {
        return Err(TestError::Assertion(
            "converter must refuse the inconsistent source".into(),
        ));
    }
    Ok(String::from_utf8_lossy(&output.stderr).into_owned())
}

#[test]
fn checkpoint_utxo_digest_mismatch_refuses() -> TestResult<()> {
    let source_temp = tempdir()?;
    let dest_temp = tempdir()?;
    let from_path = source_temp.path();
    let to_path = dest_temp.path().join("converted");

    stage_canonical_epoch3_source(from_path)?;
    rewrite_manifest(from_path, |manifest| {
        if let Some(utxo) = manifest.utxo.as_mut() {
            utxo.sha256 = hex_encode(&[0u8; 32]);
        }
    })?;

    let stderr = run_conversion_expecting_failure(from_path, &to_path)?;
    if !stderr.contains("utxo-v4.dat") {
        return Err(TestError::Assertion(format!(
            "expected stderr to name the utxo artifact digest, got: {stderr}"
        )));
    }
    Ok(())
}

#[test]
fn checkpoint_coinstats_mismatch_refuses() -> TestResult<()> {
    let source_temp = tempdir()?;
    let dest_temp = tempdir()?;
    let from_path = source_temp.path();
    let to_path = dest_temp.path().join("converted");

    stage_canonical_epoch3_source(from_path)?;
    rewrite_manifest(from_path, |manifest| {
        manifest.coinstats.total_amount = manifest.coinstats.total_amount.saturating_add(1);
    })?;

    let stderr = run_conversion_expecting_failure(from_path, &to_path)?;
    if !stderr.contains("coinstats.total_amount") {
        return Err(TestError::Assertion(format!(
            "expected stderr to report the coinstats mismatch, got: {stderr}"
        )));
    }
    Ok(())
}

#[test]
fn corrupt_headers_or_coinstats_artifact_refuses_publish() -> TestResult<()> {
    for artifact in [HEADERS_FILE, COINSTATS_FILE] {
        let source_temp = tempdir()?;
        let dest_temp = tempdir()?;
        let from_path = source_temp.path();
        let to_path = dest_temp.path().join("converted");
        stage_canonical_epoch3_source(from_path)?;

        let artifact_path = from_path
            .join(CHECKPOINT_ROOT)
            .join("gen-00000000000000000001")
            .join(artifact);
        let mut bytes = fs::read(&artifact_path)?;
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        fs::write(&artifact_path, &bytes)?;

        let stderr = run_conversion_expecting_failure(from_path, &to_path)?;
        if !stderr.contains(artifact) {
            return Err(TestError::Assertion(format!(
                "expected stderr to name the corrupt artifact {artifact}, got: {stderr}"
            )));
        }
        if to_path.exists() {
            let entries: Vec<_> = fs::read_dir(&to_path)?.collect();
            if !entries.is_empty() {
                return Err(TestError::Assertion(format!(
                    "destination was populated despite corrupt {artifact}"
                )));
            }
        }
    }
    Ok(())
}

#[test]
fn durable_head_tx_count_mismatch_refuses() -> TestResult<()> {
    let source_temp = tempdir()?;
    let dest_temp = tempdir()?;
    let from_path = source_temp.path();
    let to_path = dest_temp.path().join("converted");

    let anchor = stage_canonical_epoch3_source(from_path)?;
    let cs_store = RocksDbStore::open(from_path.join("chainstate"))?;
    let base_head = read_durable_head(&cs_store)?;
    let suffix_height = base_head
        .height
        .checked_add(1)
        .ok_or_else(|| TestError::Assertion("suffix height overflow".into()))?;
    let (_block, block_hash) = append_block_and_undo(
        from_path,
        &cs_store,
        suffix_height,
        anchor.tip,
        vec![coinbase_tx(0xd4, 50_000)],
        &anchor.snapshot.set,
    )?;
    promote_durable_head(
        &cs_store,
        &base_head,
        suffix_height,
        block_hash,
        base_head.chain_tx_count.saturating_add(2),
    )?;
    drop(cs_store);

    let stderr = run_conversion_expecting_failure(from_path, &to_path)?;
    if !stderr.contains("chain_tx_count") {
        return Err(TestError::Assertion(format!(
            "expected stderr to report the chain_tx_count mismatch, got: {stderr}"
        )));
    }
    Ok(())
}

#[test]
fn durable_head_tip_without_block_data_refuses() -> TestResult<()> {
    let source_temp = tempdir()?;
    let dest_temp = tempdir()?;
    let from_path = source_temp.path();
    let to_path = dest_temp.path().join("converted");

    let anchor = stage_canonical_epoch3_source(from_path)?;
    let cs_store = RocksDbStore::open(from_path.join("chainstate"))?;
    let base_head = read_durable_head(&cs_store)?;
    let suffix_height = base_head
        .height
        .checked_add(1)
        .ok_or_else(|| TestError::Assertion("suffix height overflow".into()))?;
    let (_block, block_hash) = append_block_and_undo(
        from_path,
        &cs_store,
        suffix_height,
        anchor.tip,
        vec![coinbase_tx(0xe5, 50_000)],
        &anchor.snapshot.set,
    )?;
    promote_durable_head(
        &cs_store,
        &base_head,
        suffix_height,
        block_hash,
        base_head.chain_tx_count.saturating_add(1),
    )?;
    let mut del_batch = cs_store.new_batch();
    del_batch.delete(
        ColumnFamily::BlockBodies,
        &block_body_key(suffix_height, block_hash),
    );
    cs_store.write_durable(del_batch)?;
    drop(cs_store);

    let stderr = run_conversion_expecting_failure(from_path, &to_path)?;
    let expected = format!("height {suffix_height}");
    if !stderr.contains(&expected) {
        return Err(TestError::Assertion(format!(
            "expected stderr to report the missing head block at {expected}, got: {stderr}"
        )));
    }
    Ok(())
}

#[test]
fn bip30_overwrite_row_without_block_data_refuses() -> TestResult<()> {
    let (height, exception_hash) = bitcoin_rs_consensus::bip30::BIP30_DUPLICATE_TXID_EXCEPTIONS[0];
    let source_temp = tempdir()?;
    let dest_temp = tempdir()?;
    let from_path = source_temp.path();
    let to_path = dest_temp.path().join("converted");

    stage_canonical_epoch3_source(from_path)?;
    let cs_store = RocksDbStore::open(from_path.join("chainstate"))?;

    let coinbase = coinbase_tx(0xf6, 50_000);
    let txids = vec![coinbase.txid()];
    let block = Block {
        header: Header {
            version: 1,
            prev_blockhash: bitcoin_rs_consensus::primitives::BlockHash(Hash256::default()),
            merkle_root: Hash256::default(),
            time: 1_300_000_000,
            bits: CompactTarget::from_consensus(0x1d00ffff),
            nonce: 1,
        },
        txs: vec![coinbase],
    };
    let image = bitcoin_rs_consensus::primitives::BlockImage::from_local(block);
    let changes_inputs = BlockChangeInputs {
        block: &image,
        height,
        txids: &txids,
        same_block_spent: None,
        add_capacity: 1,
        remove_capacity: 0,
        max_script_size: 10_000,
    };
    let spent_map: HashMap<OutPoint, UtxoCoin> = HashMap::new();
    let (_, undo, _) = build_block_changes(&changes_inputs, &MapSpentLookup(&spent_map))
        .map_err(|e| TestError::Assertion(format!("{e}")))?;
    cs_store.put(
        ColumnFamily::UndoData,
        &block_undo_key(height, exception_hash),
        &encode_undo_v1(&undo, exception_hash),
    )?;
    drop(cs_store);

    let stderr = run_conversion_expecting_failure(from_path, &to_path)?;
    if !stderr.contains("91842") {
        return Err(TestError::Assertion(format!(
            "expected stderr to report the missing exception block, got: {stderr}"
        )));
    }
    Ok(())
}
