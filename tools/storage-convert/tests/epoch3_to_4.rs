use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write as _;
use std::path::Path;
use tempfile::tempdir;

use bitcoin_rs_consensus::primitives::{
    Amount, Block, BlockImage, CompactTarget, ConsensusEncode, Hash256, Header, LockTime, OutPoint,
    Script, Sequence, Tx, TxIn, TxOut, Txid, Witness, hex::hex_encode,
};
use bitcoin_rs_storage::checkpoint::{
    CHECKPOINT_ROOT, COINSTATS_ARTIFACT_LEN, COINSTATS_FILE, COINSTATS_MAGIC, COINSTATS_VERSION,
    CURRENT_FILE, CheckpointManifestV1, CheckpointTipV1, CoinStatsArtifactV1, CurrentV1,
    HEADER_CODEC, HEADERS_FILE, HeadersArtifactV1, MANIFEST_FILE, MANIFEST_FORMAT,
    MANIFEST_VERSION, UTXO_CODEC, UTXO_VERSION, UtxoArtifactV1,
};
const UTXO_FILE: &str = "utxo-v4.dat";
use bitcoin_rs_storage::durable_head::{DURABLE_HEAD_KEY, DurableHead};
use bitcoin_rs_storage::pruning::{block_body_key, block_undo_key};
use bitcoin_rs_storage::utxo::contract::{
    BlockChangeInputs, SpentOutputLookup, build_block_changes, encode_undo_record,
};
use bitcoin_rs_storage::utxo::record::UtxoRecord;
use bitcoin_rs_storage::utxo::stats::CoinStatsAccumulator;
use bitcoin_rs_storage::utxo::{UtxoCoin, UtxoSet, write_snapshot_witnessed};
use bitcoin_rs_storage::{ColumnFamily, FlatFileBlockStore, KvStore, RocksDbStore};
use sha2::{Digest, Sha256};

use super::support::error::{TestError, TestResult};
use super::support::harness::{parse_report, recursive_dir_digest, run_converter};
use super::support::oracle::write_schema_marker;

const CURRENT_FORMAT: &str = "bitcoin-rs-chainstate-current";
const CURRENT_VERSION: u32 = 1;

struct MapSpentLookup<'a>(&'a HashMap<OutPoint, UtxoCoin>);

impl SpentOutputLookup for MapSpentLookup<'_> {
    fn entry(&self, outpoint: &OutPoint) -> Option<&UtxoCoin> {
        self.0.get(outpoint)
    }
}

pub(crate) fn create_checkpoint_fixture(
    root: &Path,
    tip_hash: Hash256,
    height: u32,
    txids: &[Hash256],
) -> TestResult<UtxoSet> {
    let set = UtxoSet::new();
    for (i, txid) in txids.iter().enumerate() {
        let vout = 0u32;
        let idx = u64::try_from(i).map_err(|e| TestError::Assertion(e.to_string()))?;
        let sat = 50_000u64.saturating_mul(idx.saturating_add(1));
        let tag = u8::try_from(i).map_err(|e| TestError::Assertion(e.to_string()))?;
        let out = bitcoin_rs_storage::utxo::record::OwnedUtxoOut {
            vout,
            value: sat,
            script_pubkey: vec![0x76, 0xa9, 0x14, tag, 0x88, 0xac],
            coinbase: true,
            height,
        };
        let record = UtxoRecord::from_owned_outputs(*txid, &[out])
            .map_err(|e| TestError::Assertion(e.to_string()))?;
        set.insert_parsed_record(record);
    }

    let gen_dir = root.join(CHECKPOINT_ROOT).join("gen-00000000000000000001");
    fs::create_dir_all(&gen_dir)?;

    let utxo_path = gen_dir.join(UTXO_FILE);
    let mut utxo_file = File::create(&utxo_path)?;
    let (trailer, _, witness) = write_snapshot_witnessed(
        &set,
        &tip_hash,
        height,
        &mut utxo_file,
        CoinStatsAccumulator::with_parallel_muhash(height),
    )
    .map_err(|e| TestError::Assertion(e.to_string()))?;
    let witness = witness.ok_or_else(|| TestError::Assertion("snapshot witness failed".into()))?;

    let headers_path = gen_dir.join(HEADERS_FILE);
    let mut headers_file = File::create(&headers_path)?;
    let dummy_headers = vec![0x42u8; 80];
    headers_file.write_all(&dummy_headers)?;
    let headers_sha256 = hex_encode(&Sha256::digest(&dummy_headers));

    let coinstats_path = gen_dir.join(COINSTATS_FILE);
    let mut coinstats_file = File::create(&coinstats_path)?;
    let coinstats_len =
        usize::try_from(COINSTATS_ARTIFACT_LEN).map_err(|e| TestError::Assertion(e.to_string()))?;
    let mut dummy_coinstats = vec![0u8; coinstats_len];
    dummy_coinstats[..8].copy_from_slice(&COINSTATS_MAGIC);
    dummy_coinstats[8..12].copy_from_slice(&COINSTATS_VERSION.to_le_bytes());
    coinstats_file.write_all(&dummy_coinstats)?;
    let coinstats_sha256 = hex_encode(&Sha256::digest(&dummy_coinstats));

    let trailer_sha256 = hex_encode(&Sha256::digest(trailer));

    let coin_count = u64::try_from(txids.len()).map_err(|e| TestError::Assertion(e.to_string()))?;
    let total_amount = (0..coin_count)
        .map(|idx| 50_000_u64.saturating_mul(idx.saturating_add(1)))
        .sum::<u64>();
    let bogo_size = coin_count.saturating_mul(56);
    let chain_tx_count = 100_u64;
    let headers_len =
        u64::try_from(dummy_headers.len()).map_err(|e| TestError::Assertion(e.to_string()))?;
    let zero_hash_bytes = [0u8; 32];
    let manifest = CheckpointManifestV1 {
        format: MANIFEST_FORMAT.to_string(),
        version: MANIFEST_VERSION,
        generation: 1,
        network: "regtest".to_string(),
        network_magic: "fabfb5da".to_string(),
        genesis_hash: hex_encode(&zero_hash_bytes),
        applied_tip: CheckpointTipV1 {
            height,
            hash: tip_hash.to_string_be(),
            chainwork: hex_encode(&zero_hash_bytes),
            chain_tx_count,
        },
        best_header_tip: CheckpointTipV1 {
            height,
            hash: tip_hash.to_string_be(),
            chainwork: hex_encode(&zero_hash_bytes),
            chain_tx_count,
        },
        headers: HeadersArtifactV1 {
            file: HEADERS_FILE.to_string(),
            codec: HEADER_CODEC.to_string(),
            version: 1,
            bytes: headers_len,
            sha256: headers_sha256,
            header_count: 1,
            best_chain_sha256: hex_encode(&zero_hash_bytes),
            applied_chain_sha256: hex_encode(&zero_hash_bytes),
        },
        utxo: Some(UtxoArtifactV1 {
            file: UTXO_FILE.to_string(),
            codec: UTXO_CODEC.to_string(),
            version: UTXO_VERSION,
            bytes: witness.byte_len(),
            sha256: hex_encode(&witness.sha256()),
            record_count: witness.record_count(),
            output_count: witness.output_count(),
            muhash_trailer_sha256: trailer_sha256,
        }),
        coinstats: CoinStatsArtifactV1 {
            file: COINSTATS_FILE.to_string(),
            codec: bitcoin_rs_storage::checkpoint::COINSTATS_CODEC.to_string(),
            version: COINSTATS_VERSION,
            bytes: COINSTATS_ARTIFACT_LEN,
            sha256: coinstats_sha256,
            height,
            total_amount,
            bogo_size,
            tx_count: chain_tx_count,
            utxo_count: coin_count,
            muhash: hex_encode(&trailer),
        },
    };

    let manifest_bytes = sonic_rs::to_vec(&manifest)?;
    let manifest_path = gen_dir.join(MANIFEST_FILE);
    fs::write(&manifest_path, &manifest_bytes)?;
    let manifest_digest_hex = hex_encode(&Sha256::digest(&manifest_bytes));

    let current = CurrentV1 {
        format: CURRENT_FORMAT.to_string(),
        version: CURRENT_VERSION,
        generation: 1,
        directory: "gen-00000000000000000001".to_string(),
        manifest_sha256: manifest_digest_hex,
    };
    let current_bytes = sonic_rs::to_vec(&current)?;
    let current_path = root.join(CHECKPOINT_ROOT).join(CURRENT_FILE);
    fs::write(current_path, current_bytes)?;

    Ok(set)
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

    let undo_bytes = encode_undo_record(&undo, block_hash_256);
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

    write_schema_marker(from_path, 3)?;

    let txid1 = Hash256::from_le_bytes(&[1u8; 32]);
    let checkpoint_tip = Hash256::from_le_bytes(&[100u8; 32]);
    let utxo_set = create_checkpoint_fixture(from_path, checkpoint_tip, 100, &[txid1])?;
    let cs_store = RocksDbStore::open(from_path.join("chainstate"))?;

    let cb_101 = Tx {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: Script::from_bytes(vec![0x01, 0x65]),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: Script::default(),
        }],
        lock_time: LockTime::ZERO,
    };
    let (_block_101, hash_101) = append_block_and_undo(
        from_path,
        &cs_store,
        101,
        checkpoint_tip,
        vec![cb_101],
        &utxo_set,
    )?;

    let durable_head = DurableHead {
        assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
        commit_id: 1,
        height: 101,
        tip: hash_101,
        chain_tx_count: 101,
        body_extent: None,
        undo_extent: None,
    };
    cs_store.put(
        ColumnFamily::UtxoMeta,
        DURABLE_HEAD_KEY,
        &durable_head.encode(),
    )?;

    let mut del_batch = cs_store.new_batch();
    del_batch.delete(ColumnFamily::UndoData, &block_undo_key(101, hash_101));
    cs_store.write_durable(del_batch)?;

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
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.contains("height 101") && !stderr.contains("101") {
        return Err(TestError::Assertion(format!(
            "expected stderr to report missing height 101, got: {stderr}"
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

    write_schema_marker(from_path, 3)?;

    let txid1 = Hash256::from_le_bytes(&[5u8; 32]);
    let checkpoint_tip = nonuniform_hash(0x31);
    create_checkpoint_fixture(from_path, checkpoint_tip, 100, &[txid1])?;

    let cs_store = RocksDbStore::open(from_path.join("chainstate"))?;
    let durable_head = DurableHead {
        assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
        commit_id: 1,
        height: 100,
        tip: checkpoint_tip,
        chain_tx_count: 100,
        body_extent: None,
        undo_extent: None,
    };
    cs_store.put(
        ColumnFamily::UtxoMeta,
        DURABLE_HEAD_KEY,
        &durable_head.encode(),
    )?;
    drop(cs_store);

    let from_str = from_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("utf8".into()))?;
    let to_str = to_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("utf8".into()))?;
    let output = run_converter(&["--from", from_str, "--to", to_str])?;
    let report = parse_report(&output)?;

    if report.source_epoch != 3 || report.target_epoch != 4 {
        return Err(TestError::Assertion("unexpected report epochs".into()));
    }

    let dest_schema = fs::read_to_string(to_path.join("CURRENT_SCHEMA"))?;
    if dest_schema != "4\n" {
        return Err(TestError::Assertion("expected 4\n".into()));
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

#[test]
fn converted_datadir_drops_old_checkpoint_coin_image() -> TestResult<()> {
    let source_temp = tempdir()?;
    let dest_temp = tempdir()?;
    let from_path = source_temp.path();
    let to_path = dest_temp.path().join("converted");

    write_schema_marker(from_path, 3)?;

    let txid1 = Hash256::from_le_bytes(&[7u8; 32]);
    let checkpoint_tip = nonuniform_hash(0x42);
    create_checkpoint_fixture(from_path, checkpoint_tip, 100, &[txid1])?;

    let cs_store = RocksDbStore::open(from_path.join("chainstate"))?;
    let durable_head = DurableHead {
        assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
        commit_id: 1,
        height: 100,
        tip: checkpoint_tip,
        chain_tx_count: 100,
        body_extent: None,
        undo_extent: None,
    };
    cs_store.put(
        ColumnFamily::UtxoMeta,
        DURABLE_HEAD_KEY,
        &durable_head.encode(),
    )?;
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
    Ok(())
}

#[test]
fn converted_historical_checkpoint_carries_engine_coins() -> TestResult<()> {
    let source_temp = tempdir()?;
    let dest_temp = tempdir()?;
    let from_path = source_temp.path();
    let to_path = dest_temp.path().join("converted");

    write_schema_marker(from_path, 3)?;

    let txid1 = Hash256::from_le_bytes(&[13u8; 32]);
    let checkpoint_tip = nonuniform_hash(0x64);
    create_checkpoint_fixture(from_path, checkpoint_tip, 100, &[txid1])?;

    let cs_store = RocksDbStore::open(from_path.join("chainstate"))?;
    let durable_head = DurableHead {
        assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
        commit_id: 1,
        height: 100,
        tip: checkpoint_tip,
        chain_tx_count: 100,
        body_extent: None,
        undo_extent: None,
    };
    cs_store.put(
        ColumnFamily::UtxoMeta,
        DURABLE_HEAD_KEY,
        &durable_head.encode(),
    )?;
    drop(cs_store);

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
    let engine = RocksDbStore::open(converted_gen.join("chainstate"))?;
    let stored = engine
        .get(ColumnFamily::Coins, &txid1.to_le_bytes())?
        .ok_or_else(|| {
            TestError::Assertion(
                "historical checkpoint engine image lacks the checkpoint coin".into(),
            )
        })?;
    let stored_bytes: &[u8] = &stored;
    let expected = UtxoRecord::from_owned_outputs(
        txid1,
        &[bitcoin_rs_storage::utxo::record::OwnedUtxoOut {
            vout: 0,
            value: 50_000,
            script_pubkey: vec![0x76, 0xa9, 0x14, 0, 0x88, 0xac],
            coinbase: true,
            height: 100,
        }],
    )
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

fn nonuniform_hash(seed: u8) -> Hash256 {
    let mut bytes = [0_u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = seed.wrapping_add(u8::try_from(index).unwrap_or(u8::MAX));
    }
    Hash256::from_le_bytes(&bytes)
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

    write_schema_marker(from_path, 3)?;

    let txid1 = Hash256::from_le_bytes(&[10u8; 32]);
    let checkpoint_tip = Hash256::from_le_bytes(&[100u8; 32]);
    let utxo_set = create_checkpoint_fixture(from_path, checkpoint_tip, 100, &[txid1])?;
    let cs_store = RocksDbStore::open(from_path.join("chainstate"))?;

    let foreign_parent = Hash256::from_le_bytes(&[7u8; 32]);
    let (_block, block_hash) = append_block_and_undo(
        from_path,
        &cs_store,
        101,
        foreign_parent,
        vec![coinbase_tx(0xc3, 50_000)],
        &utxo_set,
    )?;

    let durable_head = DurableHead {
        assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
        commit_id: 1,
        height: 101,
        tip: block_hash,
        chain_tx_count: 101,
        body_extent: None,
        undo_extent: None,
    };
    cs_store.put(
        ColumnFamily::UtxoMeta,
        DURABLE_HEAD_KEY,
        &durable_head.encode(),
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

    write_schema_marker(from_path, 3)?;
    let txid1 = Hash256::from_le_bytes(&[11u8; 32]);
    let checkpoint_tip = Hash256::from_le_bytes(&[100u8; 32]);
    create_checkpoint_fixture(from_path, checkpoint_tip, 100, &[txid1])?;
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

    write_schema_marker(from_path, 3)?;
    let txid1 = Hash256::from_le_bytes(&[12u8; 32]);
    let checkpoint_tip = Hash256::from_le_bytes(&[100u8; 32]);
    create_checkpoint_fixture(from_path, checkpoint_tip, 100, &[txid1])?;
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

        write_schema_marker(from_path, 3)?;
        let txid1 = Hash256::from_le_bytes(&[16u8; 32]);
        let checkpoint_tip = nonuniform_hash(0x41);
        create_checkpoint_fixture(from_path, checkpoint_tip, 100, &[txid1])?;
        let cs_store = RocksDbStore::open(from_path.join("chainstate"))?;
        let durable_head = DurableHead {
            assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
            commit_id: 1,
            height: 100,
            tip: checkpoint_tip,
            chain_tx_count: 100,
            body_extent: None,
            undo_extent: None,
        };
        cs_store.put(
            ColumnFamily::UtxoMeta,
            DURABLE_HEAD_KEY,
            &durable_head.encode(),
        )?;
        drop(cs_store);

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

    write_schema_marker(from_path, 3)?;
    let txid1 = Hash256::from_le_bytes(&[13u8; 32]);
    let checkpoint_tip = Hash256::from_le_bytes(&[100u8; 32]);
    let utxo_set = create_checkpoint_fixture(from_path, checkpoint_tip, 100, &[txid1])?;
    let cs_store = RocksDbStore::open(from_path.join("chainstate"))?;
    let (_block, block_hash) = append_block_and_undo(
        from_path,
        &cs_store,
        101,
        checkpoint_tip,
        vec![coinbase_tx(0xd4, 50_000)],
        &utxo_set,
    )?;
    let durable_head = DurableHead {
        assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
        commit_id: 1,
        height: 101,
        tip: block_hash,
        chain_tx_count: 102,
        body_extent: None,
        undo_extent: None,
    };
    cs_store.put(
        ColumnFamily::UtxoMeta,
        DURABLE_HEAD_KEY,
        &durable_head.encode(),
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

    write_schema_marker(from_path, 3)?;
    let txid1 = Hash256::from_le_bytes(&[14u8; 32]);
    let checkpoint_tip = Hash256::from_le_bytes(&[100u8; 32]);
    let utxo_set = create_checkpoint_fixture(from_path, checkpoint_tip, 100, &[txid1])?;
    let cs_store = RocksDbStore::open(from_path.join("chainstate"))?;
    let (_block, _block_hash) = append_block_and_undo(
        from_path,
        &cs_store,
        101,
        checkpoint_tip,
        vec![coinbase_tx(0xe5, 50_000)],
        &utxo_set,
    )?;
    let durable_head = DurableHead {
        assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
        commit_id: 1,
        height: 101,
        tip: Hash256::from_le_bytes(&[0xeeu8; 32]),
        chain_tx_count: 101,
        body_extent: None,
        undo_extent: None,
    };
    cs_store.put(
        ColumnFamily::UtxoMeta,
        DURABLE_HEAD_KEY,
        &durable_head.encode(),
    )?;
    drop(cs_store);

    let stderr = run_conversion_expecting_failure(from_path, &to_path)?;
    if !stderr.contains("height 101") && !stderr.contains("101") {
        return Err(TestError::Assertion(format!(
            "expected stderr to report the missing head block, got: {stderr}"
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

    write_schema_marker(from_path, 3)?;
    let txid1 = Hash256::from_le_bytes(&[15u8; 32]);
    let checkpoint_tip = Hash256::from_le_bytes(&[100u8; 32]);
    create_checkpoint_fixture(from_path, checkpoint_tip, 100, &[txid1])?;
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
        &encode_undo_record(&undo, exception_hash),
    )?;

    let durable_head = DurableHead {
        assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
        commit_id: 1,
        height: 100,
        tip: checkpoint_tip,
        chain_tx_count: 100,
        body_extent: None,
        undo_extent: None,
    };
    cs_store.put(
        ColumnFamily::UtxoMeta,
        DURABLE_HEAD_KEY,
        &durable_head.encode(),
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
