use bitcoin::absolute::LockTime;
use bitcoin::hashes::{Hash as _, sha256d};
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, BlockHash, CompactTarget, ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode, Witness,
};
use bitcoin_rs_consensus::primitives::BlockImage;
use bitcoin_rs_consensus::primitives::{Hash256, OutPoint, Txid};
use bitcoin_rs_projection::IndexCapabilities;
use bitcoin_rs_projection::runtime::{DEFAULT_BATCH_LIMITS, open_derived_index_store_with_scratch};
use bitcoin_rs_projection::segment::bulk_builder::BulkSegmentBuilder;
use bitcoin_rs_projection::segment::{
    Coverage, GenerationDescriptor, IndexGeneration, NoSealedTxOrdinals, TailDescriptor,
    TailWriterState, append_tail_block, meta_gen_key, seal_tail_generation,
};
use bitcoin_rs_projection::{IndexCapability, IndexWatermark, IndexWriter};
use bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus;
use bitcoin_rs_storage::committed_facts::{CommittedBlock, CreatedOutput, SpentPrevout, TxFacts};
use bitcoin_rs_storage::durable_head::{DURABLE_HEAD_KEY, DurableHead};
use bitcoin_rs_storage::utxo::contract::decode_undo_record;
use bitcoin_rs_storage::{ColumnFamily, KvStore, RocksDbStore, block_undo_key};
use bytes::Bytes;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::Arc;

use crate::support::error::{TestError, TestResult};
use crate::support::harness::run_converter;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
struct FamilyResetReport {
    family: String,
    rows_removed: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
struct RebuildIndexReport {
    datadir: String,
    engine: String,
    format_version: u32,
    budget_refusals: u64,
    families: Vec<FamilyResetReport>,
}

fn parse_rebuild_report(output: &Output) -> TestResult<RebuildIndexReport> {
    if !output.status.success() {
        return Err(TestError::Assertion(format!(
            "rebuild-index exited with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let report: RebuildIndexReport = sonic_rs::from_slice(&output.stdout)?;
    Ok(report)
}

fn seeded_datadir(root: &Path) -> TestResult<PathBuf> {
    let datadir = root.join("datadir");
    fs::create_dir_all(datadir.join("txindex"))?;
    fs::write(datadir.join("CURRENT_SCHEMA"), "6\n")?;
    let store = Arc::new(RocksDbStore::open(datadir.join("txindex"))?);
    let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
    let scripthash = bitcoin_rs_projection::ScriptHash::from_script_bytes(&[0x51, 0x01]);
    let coins = (0_u32..3)
        .map(|vout| {
            (
                OutPoint::new(Txid(Hash256::from_le_bytes(&[0x11_u8; 32])), vout),
                bitcoin_rs_projection::ScriptLiveCoin::new(scripthash, 1_000, 5, false),
            )
        })
        .collect::<Vec<_>>();
    writer.seed_script_live(
        coins,
        IndexWatermark {
            height: 5,
            hash: [0x05_u8; 32],
        },
    )?;
    let mut batch = store.new_batch();
    batch.put(ColumnFamily::Funding, &[0xAA; 10], &[0x01, 0x02]);
    batch.put(ColumnFamily::TxConfirmed, &[0xBB; 10], &[0x03]);
    store.write_durable(batch)?;
    drop(writer);
    drop(store);
    Ok(datadir)
}

fn count_rows(store: &RocksDbStore, cf: ColumnFamily) -> TestResult<u64> {
    let scan = store.scan_prefix_bounded(
        cf,
        &[],
        bitcoin_rs_storage::PrefixScanLimit {
            max_rows: 100_000,
            max_bytes: usize::MAX,
        },
    )?;
    Ok(u64::try_from(scan.rows.len())?)
}

fn family_removed(report: &RebuildIndexReport, family: &str) -> u64 {
    report
        .families
        .iter()
        .find(|entry| entry.family == family)
        .map_or(0, |entry| entry.rows_removed)
}

#[test]
fn rebuild_index_resets_derived_rows_and_stamps_the_current_format() -> TestResult {
    let root = tempfile::tempdir()?;
    let datadir = seeded_datadir(root.path())?;

    let output = run_converter(&[
        "rebuild-index",
        "--datadir",
        datadir.to_string_lossy().as_ref(),
    ])?;
    let report = parse_rebuild_report(&output)?;
    assert_eq!(report.engine, "rocksdb");
    assert_eq!(report.format_version, 9);
    assert_eq!(family_removed(&report, "script_live"), 3);
    assert_eq!(family_removed(&report, "funding"), 1);
    assert_eq!(family_removed(&report, "tx_confirmed"), 1);

    let store = RocksDbStore::open(datadir.join("txindex"))?;
    assert_eq!(count_rows(&store, ColumnFamily::ScriptLive)?, 0);
    assert_eq!(count_rows(&store, ColumnFamily::Funding)?, 0);
    assert_eq!(count_rows(&store, ColumnFamily::TxConfirmed)?, 0);
    let marker = store
        .get(ColumnFamily::UtxoMeta, &[0x00, b'V'])?
        .expect("reset stamps the format marker");
    assert_eq!(marker.as_slice(), &[0x09, 0x00, 0x00, 0x00]);
    drop(store);

    let store = Arc::new(RocksDbStore::open(datadir.join("txindex"))?);
    let writer = IndexWriter::open(Arc::clone(&store), 2)?;
    assert_eq!(writer.watermarks()?.script_live, None);
    Ok(())
}

#[test]
fn rebuild_index_is_idempotent_on_a_reset_datadir() -> TestResult {
    let root = tempfile::tempdir()?;
    let datadir = seeded_datadir(root.path())?;
    for _ in 0..2 {
        let output = run_converter(&[
            "rebuild-index",
            "--datadir",
            datadir.to_string_lossy().as_ref(),
        ])?;
        parse_rebuild_report(&output)?;
    }
    let store = RocksDbStore::open(datadir.join("txindex"))?;
    assert_eq!(count_rows(&store, ColumnFamily::ScriptLive)?, 0);
    Ok(())
}

#[test]
fn rebuild_index_refuses_an_unknown_epoch() -> TestResult {
    let root = tempfile::tempdir()?;
    let datadir = seeded_datadir(root.path())?;
    fs::write(datadir.join("CURRENT_SCHEMA"), "9\n")?;
    let output = run_converter(&[
        "rebuild-index",
        "--datadir",
        datadir.to_string_lossy().as_ref(),
    ])?;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("epoch"),
        "refusal must name the epoch problem: {stderr}"
    );
    Ok(())
}

#[test]
fn rebuild_index_refuses_a_datadir_without_txindex() -> TestResult {
    let root = tempfile::tempdir()?;
    let datadir = root.path().join("datadir");
    fs::create_dir_all(&datadir)?;
    fs::write(datadir.join("CURRENT_SCHEMA"), "6\n")?;
    let output = run_converter(&[
        "rebuild-index",
        "--datadir",
        datadir.to_string_lossy().as_ref(),
    ])?;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("txindex"),
        "refusal must name the missing namespace: {stderr}"
    );
    Ok(())
}

#[test]
fn rebuild_index_refuses_missing_current_schema() -> TestResult {
    let root = tempfile::tempdir()?;
    let datadir = seeded_datadir(root.path())?;
    fs::remove_file(datadir.join("CURRENT_SCHEMA"))?;
    let output = run_converter(&[
        "rebuild-index",
        "--datadir",
        datadir.to_string_lossy().as_ref(),
    ])?;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("epoch"),
        "missing CURRENT_SCHEMA must be refused with epoch error: {stderr}"
    );
    Ok(())
}

#[test]
fn rebuild_index_refuses_empty_txindex_when_chainstate_engine_undetectable() -> TestResult {
    let root = tempfile::tempdir()?;
    let datadir = root.path().join("datadir");
    fs::create_dir_all(datadir.join("txindex"))?;
    fs::write(datadir.join("CURRENT_SCHEMA"), "6\n")?;
    let output = run_converter(&[
        "rebuild-index",
        "--datadir",
        datadir.to_string_lossy().as_ref(),
    ])?;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot detect storage engine"),
        "empty txindex without chainstate engine must refuse: {stderr}"
    );
    Ok(())
}

#[test]
fn rebuild_index_empty_txindex_follows_detected_chainstate_engine() -> TestResult {
    let root = tempfile::tempdir()?;
    let datadir = root.path().join("datadir");
    fs::create_dir_all(datadir.join("txindex"))?;
    fs::create_dir_all(datadir.join("chainstate"))?;
    fs::write(datadir.join("CURRENT_SCHEMA"), "6\n")?;
    let cs_store = RocksDbStore::open(datadir.join("chainstate"))?;
    drop(cs_store);

    let output = run_converter(&[
        "rebuild-index",
        "--datadir",
        datadir.to_string_lossy().as_ref(),
    ])?;
    let report = parse_rebuild_report(&output)?;
    assert_eq!(report.engine, "rocksdb");
    assert_eq!(report.format_version, 9);

    let store = RocksDbStore::open(datadir.join("txindex"))?;
    let marker = store
        .get(ColumnFamily::UtxoMeta, &[0x00, b'V'])?
        .expect("format marker in UtxoMeta");
    assert_eq!(marker.as_slice(), &[0x09, 0x00, 0x00, 0x00]);
    let desc = store
        .get(
            ColumnFamily::IdxMeta,
            &bitcoin_rs_projection::segment::meta_gen_key(
                bitcoin_rs_projection::IndexCapability::TxLookup,
            ),
        )?
        .expect("generation descriptor in IdxMeta");
    assert!(!desc.is_empty());
    let idx_meta_marker = store.get(ColumnFamily::IdxMeta, &[0x00, b'V'])?;
    assert!(idx_meta_marker.is_none());
    Ok(())
}

const BULK_GEN_ID: u64 = 1;

type CoinLedger = HashMap<([u8; 32], u32), (u64, Vec<u8>, u32, bool)>;

type RestoreSpec = ([u8; 32], u32, u64, Vec<u8>, bool, u32);

type CreatedCoin = (u64, Bytes, u32, bool);

#[derive(Clone)]
struct FixtureBlock {
    height: u32,
    hash: [u8; 32],
    body: Vec<u8>,
    facts: CommittedBlock,
    undo: Vec<u8>,
}

fn push_compact_size(out: &mut Vec<u8>, value: usize) {
    let value = u64::try_from(value).expect("fixture size fits u64");
    assert!(value < 0xFD, "fixture count stays in one compact-size byte");
    out.push(u8::try_from(value).expect("fixture count fits u8"));
}

fn fixture_outputs(spec: &[(u64, Vec<u8>)]) -> Vec<bitcoin::TxOut> {
    spec.iter()
        .map(|(value, script)| bitcoin::TxOut {
            value: Amount::from_sat(*value),
            script_pubkey: ScriptBuf::from_bytes(script.clone()),
        })
        .collect()
}

fn coinbase_tx(tag: u8, outputs: &[(u64, Vec<u8>)]) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: bitcoin::OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![tag]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: fixture_outputs(outputs),
    }
}

fn spending_tx(prev: ([u8; 32], u32), witness: Witness, outputs: &[(u64, Vec<u8>)]) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: bitcoin::OutPoint {
                txid: bitcoin::Txid::from_byte_array(prev.0),
                vout: prev.1,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness,
        }],
        output: fixture_outputs(outputs),
    }
}

fn encode_undo(
    block_hash: [u8; 32],
    restores: &[RestoreSpec],
    _removes: &[([u8; 32], u32)],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(2);
    out.extend_from_slice(&block_hash);
    out.extend_from_slice(&u32::try_from(restores.len()).expect("fits").to_le_bytes());
    for (txid, vout, value, script, coinbase, height) in restores {
        out.extend_from_slice(txid);
        out.extend_from_slice(&vout.to_le_bytes());
        out.extend_from_slice(&value.to_le_bytes());
        push_compact_size(&mut out, script.len());
        out.extend_from_slice(script);
        out.push(u8::from(*coinbase));
        out.extend_from_slice(&height.to_le_bytes());
    }
    out
}

struct BlockSpec {
    height: u32,
    parent: [u8; 32],
    nonce: u32,
    txs: Vec<Transaction>,
}

// PRJ-09
fn assemble_block(spec: BlockSpec, ledger: &mut CoinLedger) -> FixtureBlock {
    let BlockSpec {
        height,
        parent,
        nonce,
        txs,
    } = spec;
    let merkle_root =
        bitcoin::merkle_tree::calculate_root(txs.iter().map(bitcoin::Transaction::compute_txid))
            .map_or_else(
                || TxMerkleNode::from_byte_array([0u8; 32]),
                |root| TxMerkleNode::from_byte_array(root.to_byte_array()),
            );
    let header = bitcoin::block::Header {
        version: bitcoin::block::Version::ONE,
        prev_blockhash: BlockHash::from_byte_array(parent),
        merkle_root,
        time: height,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce,
    };
    let header_bytes = bitcoin::consensus::serialize(&header);
    assert_eq!(header_bytes.len(), 80);
    let hash = sha256d::Hash::hash(&header_bytes).to_byte_array();

    let mut body = Vec::new();
    body.extend_from_slice(&header_bytes);
    push_compact_size(&mut body, txs.len());
    let mut spans = Vec::with_capacity(txs.len());
    for tx in &txs {
        let encoded = bitcoin::consensus::serialize(tx);
        let start = body.len();
        body.extend_from_slice(&encoded);
        spans.push((start, encoded.len()));
    }

    let image = BlockImage::from_raw(Bytes::copy_from_slice(&body)).expect("fixture block parses");
    assert_eq!(image.block_hash().0.to_le_bytes(), hash);
    assert_eq!(&image.header_bytes()[..], header_bytes.as_slice());
    assert_eq!(
        image.header().merkle_root.to_le_bytes(),
        merkle_root.to_byte_array()
    );
    assert_eq!(image.tx_count(), txs.len());

    let mut created: HashMap<([u8; 32], u32), CreatedCoin> = HashMap::new();
    let mut restores: Vec<RestoreSpec> = Vec::new();
    let mut removes: Vec<([u8; 32], u32)> = Vec::new();
    let mut facts_txs = Vec::with_capacity(txs.len());
    for (tx, (start, len)) in txs.iter().zip(spans.iter()) {
        let txid = tx.compute_txid().to_byte_array();
        let is_coinbase = tx.is_coinbase();
        let mut inputs = Vec::new();
        if !is_coinbase {
            for input in &tx.input {
                let prev_txid = input.previous_output.txid.to_byte_array();
                let prev_vout = input.previous_output.vout;
                let (value, script, coin_height, coinbase) =
                    if let Some((value, script, coin_height, coinbase)) =
                        created.get(&(prev_txid, prev_vout))
                    {
                        removes.push((prev_txid, prev_vout));
                        (*value, script.clone(), *coin_height, *coinbase)
                    } else {
                        let (value, script, coin_height, coinbase) = ledger
                            .get(&(prev_txid, prev_vout))
                            .expect("fixture spends a known coin")
                            .clone();
                        restores.push((
                            prev_txid,
                            prev_vout,
                            value,
                            script.clone(),
                            coinbase,
                            coin_height,
                        ));
                        (value, Bytes::from(script), coin_height, coinbase)
                    };
                inputs.push(SpentPrevout {
                    txid: prev_txid,
                    vout: prev_vout,
                    value,
                    script,
                    height: coin_height,
                    coinbase,
                });
            }
        }
        let mut outputs = Vec::new();
        for (vout, output) in tx.output.iter().enumerate() {
            let vout = u32::try_from(vout).expect("fixture vout fits u32");
            let script = output.script_pubkey.as_bytes().to_vec();
            let value = output.value.to_sat();
            let script_bytes = Bytes::copy_from_slice(&script);
            outputs.push(CreatedOutput {
                vout,
                value,
                script: script_bytes.clone(),
            });
            created.insert((txid, vout), (value, script_bytes, height, is_coinbase));
            ledger.insert((txid, vout), (value, script, height, is_coinbase));
        }
        facts_txs.push(TxFacts {
            txid,
            offset: u32::try_from(*start).expect("fixture offset fits u32"),
            len: u32::try_from(*len).expect("fixture length fits u32"),
            inputs,
            outputs,
        });
    }

    let undo = encode_undo(hash, &restores, &removes);
    let decoded = decode_undo_record(&undo, Hash256::from_le_bytes(&hash))
        .expect("fixture undo record decodes");
    assert_eq!(decoded.restores().len(), restores.len());
    assert!(decoded.removes().is_empty());
    for (add, (txid, vout, value, script, coinbase, coin_height)) in
        decoded.restores().iter().zip(restores.iter())
    {
        let decoded_txid = add.outpoint.txid;
        let decoded_vout = add.outpoint.vout;
        assert_eq!(decoded_txid.as_bytes(), txid);
        assert_eq!(decoded_vout, *vout);
        assert_eq!(add.txout.value.to_sat(), *value);
        assert_eq!(
            &Bytes::copy_from_slice(&add.txout.script_pubkey)[..],
            script
        );
        assert_eq!(add.coinbase, *coinbase);
        assert_eq!(add.height, *coin_height);
    }

    FixtureBlock {
        height,
        hash,
        body,
        facts: CommittedBlock {
            height,
            hash,
            parent_hash: parent,
            header: image.header_bytes(),
            txs: facts_txs,
        },
        undo,
    }
}

fn p2wpkh_script(tag: u8) -> Vec<u8> {
    let mut script = vec![0x00, 0x14];
    script.extend_from_slice(&[tag; 20]);
    script
}

fn p2pkh_script(tag: u8) -> Vec<u8> {
    let mut script = vec![0x76, 0xa9, 0x14];
    script.extend_from_slice(&[tag; 20]);
    script.push(0x88);
    script.push(0xac);
    script
}

fn creating_chain() -> Vec<FixtureBlock> {
    let mut ledger = CoinLedger::new();
    let mut blocks = Vec::new();
    let mut parent = [0u8; 32];

    let coinbase = coinbase_tx(1, &[(50_000, p2wpkh_script(0xA1))]);
    let block = assemble_block(
        BlockSpec {
            height: 0,
            parent,
            nonce: 0,
            txs: vec![coinbase],
        },
        &mut ledger,
    );
    parent = block.hash;
    blocks.push(block);

    let coinbase = coinbase_tx(2, &[(50_000, p2pkh_script(0xB1))]);
    let coinbase_txid = coinbase.compute_txid().to_byte_array();
    let spend = spending_tx(
        (coinbase_txid, 0),
        Witness::new(),
        &[(49_000, p2pkh_script(0xB2))],
    );
    let block = assemble_block(
        BlockSpec {
            height: 1,
            parent,
            nonce: 1,
            txs: vec![coinbase, spend],
        },
        &mut ledger,
    );
    parent = block.hash;
    blocks.push(block);

    let coinbase = coinbase_tx(3, &[(50_000, p2wpkh_script(0xC1))]);
    let block = assemble_block(
        BlockSpec {
            height: 2,
            parent,
            nonce: 2,
            txs: vec![coinbase],
        },
        &mut ledger,
    );
    parent = block.hash;
    blocks.push(block);

    let coinbase = coinbase_tx(4, &[(50_000, p2pkh_script(0xD1))]);
    let coinbase_txid = coinbase.compute_txid().to_byte_array();
    let spend = spending_tx(
        (coinbase_txid, 0),
        Witness::from_slice(&[vec![0x30; 71], vec![0x02; 33]]),
        &[(49_500, p2pkh_script(0xD2))],
    );
    let block = assemble_block(
        BlockSpec {
            height: 3,
            parent,
            nonce: 3,
            txs: vec![coinbase, spend],
        },
        &mut ledger,
    );
    blocks.push(block);
    blocks
}

fn crossing_chain() -> Vec<FixtureBlock> {
    let mut ledger = CoinLedger::new();
    let mut blocks = Vec::new();
    let mut parent = [0u8; 32];

    let coinbase = coinbase_tx(11, &[(50_000, p2wpkh_script(0xE1))]);
    let coinbase_txid = coinbase.compute_txid().to_byte_array();
    let block = assemble_block(
        BlockSpec {
            height: 0,
            parent,
            nonce: 0,
            txs: vec![coinbase],
        },
        &mut ledger,
    );
    parent = block.hash;
    blocks.push(block);

    let coinbase = coinbase_tx(12, &[(50_000, p2pkh_script(0xE2))]);
    let spend = spending_tx(
        (coinbase_txid, 0),
        Witness::from_slice(&[vec![0x30; 72], vec![0x02; 33]]),
        &[(30_000, p2pkh_script(0xE3)), (19_000, p2wpkh_script(0xE4))],
    );
    let spend_txid = spend.compute_txid().to_byte_array();
    let block = assemble_block(
        BlockSpec {
            height: 1,
            parent,
            nonce: 1,
            txs: vec![coinbase, spend],
        },
        &mut ledger,
    );
    parent = block.hash;
    blocks.push(block);

    let coinbase = coinbase_tx(13, &[(50_000, p2wpkh_script(0xF1))]);
    let coinbase_txid = coinbase.compute_txid().to_byte_array();
    let external = spending_tx(
        (spend_txid, 0),
        Witness::new(),
        &[(29_000, p2pkh_script(0xF2))],
    );
    let same_block = spending_tx(
        (coinbase_txid, 0),
        Witness::new(),
        &[(49_000, p2wpkh_script(0xF3))],
    );
    let block = assemble_block(
        BlockSpec {
            height: 2,
            parent,
            nonce: 2,
            txs: vec![coinbase, external, same_block],
        },
        &mut ledger,
    );
    parent = block.hash;
    blocks.push(block);

    let coinbase = coinbase_tx(14, &[(50_000, p2pkh_script(0xF4))]);
    let block = assemble_block(
        BlockSpec {
            height: 3,
            parent,
            nonce: 3,
            txs: vec![coinbase],
        },
        &mut ledger,
    );
    blocks.push(block);
    blocks
}

fn prepare_datadir(root: &Path) -> TestResult<PathBuf> {
    let datadir = root.join("datadir");
    fs::create_dir_all(datadir.join("txindex"))?;
    fs::create_dir_all(datadir.join("blocks"))?;
    fs::write(datadir.join("CURRENT_SCHEMA"), "6\n")?;
    let store = RocksDbStore::open(datadir.join("txindex"))?;
    drop(store);
    Ok(datadir)
}

fn write_chainstate(
    datadir: &Path,
    undo_blocks: &[&FixtureBlock],
    tip: Option<&FixtureBlock>,
    chain_blocks: &[&FixtureBlock],
) -> TestResult<()> {
    let store = RocksDbStore::open(datadir.join("chainstate"))?;
    let mut batch = store.new_batch();
    for block in undo_blocks {
        batch.put(
            ColumnFamily::UndoData,
            &block_undo_key(block.height, Hash256::from_le_bytes(&block.hash)),
            &block.undo,
        );
    }
    if let Some(tip) = tip {
        let chain_tx_count = chain_blocks
            .iter()
            .map(|block| u64::try_from(block.facts.txs.len()).expect("fits"))
            .sum();
        let head = DurableHead {
            assumeutxo: AssumeUtxoDiskStatus::Uninitialized,
            commit_id: 1,
            height: tip.height,
            tip: Hash256::from_le_bytes(&tip.hash),
            chain_tx_count,
            body_extent: None,
            undo_extent: Some((tip.height, Hash256::from_le_bytes(&tip.hash))),
        };
        batch.put(ColumnFamily::UtxoMeta, DURABLE_HEAD_KEY, &head.encode());
    }
    store.write_durable(batch)?;
    drop(store);
    Ok(())
}

fn write_block_records(datadir: &Path, records: &[&FixtureBlock]) -> TestResult<()> {
    let store = bitcoin_rs_storage::FlatFileBlockStore::open(datadir)?;
    for block in records {
        store.append(block.height, block.hash, &block.body)?;
    }
    drop(store);
    Ok(())
}

fn coverage_for(blocks: &[FixtureBlock]) -> Coverage {
    let first = blocks.first().expect("fixture chain is not empty");
    let last = blocks.last().expect("fixture chain is not empty");
    Coverage::new(first.height, last.height, last.hash)
}

fn hash_cf_entry(hasher: &mut Sha256, key: &[u8], value: &[u8]) {
    hasher.update(u32::try_from(key.len()).expect("fits").to_le_bytes());
    hasher.update(key);
    hasher.update(u32::try_from(value.len()).expect("fits").to_le_bytes());
    hasher.update(value);
}

fn family_digest(store: &RocksDbStore, cf: ColumnFamily, gen_id: u64) -> [u8; 32] {
    let start = gen_id.to_be_bytes();
    let end = gen_id.saturating_add(1).to_be_bytes();
    let mut hasher = Sha256::new();
    let snapshot = store.snapshot().expect("snapshot");
    let iter = snapshot.iter_prefix(cf, &start).expect("prefix scan");
    for item in iter {
        let (key, value) = item.expect("scan row");
        if key.as_slice() >= end.as_slice() {
            break;
        }
        hash_cf_entry(&mut hasher, &key, &value);
    }
    hasher.finalize().into()
}

struct Reference {
    store: RocksDbStore,
    _dir: tempfile::TempDir,
}

fn bulk_reference(blocks: &[FixtureBlock]) -> TestResult<Reference> {
    let dir = tempfile::tempdir()?;
    let scratch = tempfile::tempdir()?;
    let store = RocksDbStore::open(dir.path())?;
    let facts = blocks
        .iter()
        .map(|block| block.facts.clone())
        .collect::<Vec<_>>();
    let builder = BulkSegmentBuilder::new(
        std::sync::Arc::new(bitcoin_rs_storage::budget::UnboundedBudget),
        None,
        scratch.path().to_path_buf(),
    );
    builder
        .build_and_ingest(&store, BULK_GEN_ID, &facts)
        .map_err(|error| TestError::Assertion(error.to_string()))?;
    Ok(Reference { store, _dir: dir })
}

fn live_reference(blocks: &[FixtureBlock]) -> TestResult<Reference> {
    let dir = tempfile::tempdir()?;
    let scratch = tempfile::tempdir()?;
    let store = RocksDbStore::open(dir.path())?;
    let mut state = TailWriterState::new();
    for block in blocks {
        let mut batch = store.new_batch();
        append_tail_block(&mut batch, &block.facts, &mut state, &NoSealedTxOrdinals)?;
        store.write_durable(batch)?;
    }
    seal_tail_generation(
        &store,
        BULK_GEN_ID,
        coverage_for(blocks).last_height,
        IndexCapabilities::ALL,
        scratch.path(),
    )?;
    Ok(Reference { store, _dir: dir })
}

fn assert_generation_matches(converter: &RocksDbStore, reference: &RocksDbStore) {
    for cf in [
        ColumnFamily::TxDir,
        ColumnFamily::ScriptDict,
        ColumnFamily::ScriptPost,
        ColumnFamily::SpendDir,
        ColumnFamily::ScriptStats,
        ColumnFamily::Filters,
    ] {
        assert_eq!(
            family_digest(converter, cf, BULK_GEN_ID),
            family_digest(reference, cf, BULK_GEN_ID),
            "family {cf:?} differs between the converter rebuild and the reference build"
        );
    }
}

fn assert_descriptors(store: &RocksDbStore, blocks: &[FixtureBlock]) -> TestResult<()> {
    let coverage = coverage_for(blocks);
    let expected = IndexGeneration::encode_meta_value(&GenerationDescriptor {
        gen_id: BULK_GEN_ID,
        coverage,
        tail: TailDescriptor {
            tail_lo: coverage.last_height.saturating_add(1),
            tail_hi: coverage.last_height,
            tail_hash: coverage.last_hash,
        },
    });
    for capability in IndexCapability::ALL {
        let actual = store
            .get(ColumnFamily::IdxMeta, &meta_gen_key(capability))?
            .expect("generation descriptor");
        assert_eq!(actual, expected, "descriptor for {capability:?}");
    }
    Ok(())
}

fn rebuild(datadir: &Path) -> TestResult<Output> {
    Ok(run_converter(&[
        "rebuild-index",
        "--datadir",
        datadir.to_string_lossy().as_ref(),
    ])?)
}

// PRJ-09
#[test]
fn rebuild_index_refuses_a_block_without_its_undo_row() -> TestResult {
    let root = tempfile::tempdir()?;
    let datadir = prepare_datadir(root.path())?;
    let blocks = crossing_chain();
    let refs = blocks.iter().collect::<Vec<_>>();
    let undo_blocks = refs
        .iter()
        .copied()
        .enumerate()
        .filter(|(index, _)| *index != 1)
        .map(|(_, block)| block)
        .collect::<Vec<_>>();
    write_chainstate(&datadir, &undo_blocks, refs.last().copied(), &refs)?;
    write_block_records(&datadir, &refs)?;

    let output = rebuild(&datadir)?;
    assert!(
        !output.status.success(),
        "a missing undo row must abort the rebuild"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no undo row"),
        "refusal must name the missing undo row: {stderr}"
    );
    Ok(())
}

// PRJ-09
#[test]
fn rebuild_index_refuses_a_truncated_block_record() -> TestResult {
    let root = tempfile::tempdir()?;
    let datadir = prepare_datadir(root.path())?;
    let blocks = creating_chain();
    let refs = blocks.iter().collect::<Vec<_>>();
    write_chainstate(&datadir, &refs, refs.last().copied(), &refs)?;
    write_block_records(&datadir, &refs)?;

    let path = datadir.join("blocks").join("blk00000.dat");
    let mut bytes = fs::read(&path)?;
    let len = bytes.len();
    bytes.truncate(len - 3);
    fs::write(&path, bytes)?;

    let output = rebuild(&datadir)?;
    assert!(
        !output.status.success(),
        "a truncated block record must abort the rebuild"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("truncated"),
        "refusal must name the truncation: {stderr}"
    );
    Ok(())
}

// PRJ-09
#[test]
fn rebuild_index_refuses_a_record_with_bad_magic() -> TestResult {
    let root = tempfile::tempdir()?;
    let datadir = prepare_datadir(root.path())?;
    let blocks = creating_chain();
    let refs = blocks.iter().collect::<Vec<_>>();
    write_chainstate(&datadir, &refs, refs.last().copied(), &refs)?;
    write_block_records(&datadir, &refs)?;

    let path = datadir.join("blocks").join("blk00000.dat");
    let mut bytes = fs::read(&path)?;
    let second_record = 44 + blocks[0].body.len();
    bytes[second_record] = b'X';
    fs::write(&path, bytes)?;

    let output = rebuild(&datadir)?;
    assert!(
        !output.status.success(),
        "a record with bad magic must abort the rebuild"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("magic"),
        "refusal must name the bad magic: {stderr}"
    );
    Ok(())
}

// PRJ-09
#[test]
fn rebuild_index_refuses_an_oversize_block_record() -> TestResult {
    let root = tempfile::tempdir()?;
    let datadir = prepare_datadir(root.path())?;
    let blocks = creating_chain();
    let refs = blocks.iter().collect::<Vec<_>>();
    write_chainstate(&datadir, &refs, refs.last().copied(), &refs)?;
    write_block_records(&datadir, &refs)?;

    let path = datadir.join("blocks").join("blk00000.dat");
    let mut bytes = fs::read(&path)?;
    bytes[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
    fs::write(&path, bytes)?;

    let output = rebuild(&datadir)?;
    assert!(
        !output.status.success(),
        "an oversize block record must abort the rebuild"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("record limit"),
        "refusal must name the record limit: {stderr}"
    );
    Ok(())
}

// PRJ-05, PRJ-09
#[test]
fn rebuild_index_excludes_orphan_blocks() -> TestResult {
    let root = tempfile::tempdir()?;
    let datadir = prepare_datadir(root.path())?;
    let blocks = crossing_chain();
    let refs = blocks.iter().collect::<Vec<_>>();
    let mut orphan_ledger = CoinLedger::new();
    let orphan = assemble_block(
        BlockSpec {
            height: 1,
            parent: blocks[0].hash,
            nonce: 1000,
            txs: vec![coinbase_tx(99, &[(7_000, p2pkh_script(0x99))])],
        },
        &mut orphan_ledger,
    );
    write_chainstate(&datadir, &refs, refs.last().copied(), &refs)?;
    let records = vec![refs[0], refs[1], &orphan, refs[2], refs[3]];
    write_block_records(&datadir, &records)?;

    let output = rebuild(&datadir)?;
    parse_rebuild_report(&output)?;
    let store = RocksDbStore::open(datadir.join("txindex"))?;
    let reference = bulk_reference(&blocks)?;
    assert_generation_matches(&store, &reference.store);
    assert_descriptors(&store, &blocks)?;
    Ok(())
}

// PRJ-05, PRJ-09
#[test]
fn rebuild_index_matches_the_bulk_generation_for_the_same_chain() -> TestResult {
    let root = tempfile::tempdir()?;
    let datadir = prepare_datadir(root.path())?;
    let blocks = crossing_chain();
    let refs = blocks.iter().collect::<Vec<_>>();
    write_chainstate(&datadir, &refs, refs.last().copied(), &refs)?;
    write_block_records(&datadir, &refs)?;

    let output = rebuild(&datadir)?;
    parse_rebuild_report(&output)?;
    let store = RocksDbStore::open(datadir.join("txindex"))?;
    let reference = bulk_reference(&blocks)?;
    assert_generation_matches(&store, &reference.store);
    assert_descriptors(&store, &blocks)?;
    Ok(())
}

fn bulk_owned_row_counts(store: &RocksDbStore) -> TestResult<Vec<u64>> {
    let mut counts = Vec::new();
    for cf in [
        ColumnFamily::TxDir,
        ColumnFamily::ScriptDict,
        ColumnFamily::ScriptPost,
        ColumnFamily::SpendDir,
        ColumnFamily::ScriptStats,
        ColumnFamily::Filters,
        ColumnFamily::IdxMeta,
    ] {
        counts.push(count_rows(store, cf)?);
    }
    Ok(counts)
}

// PRJ-05, PRJ-09
#[test]
fn rebuild_index_generation_opens_on_the_node_path_without_writes() -> TestResult {
    let root = tempfile::tempdir()?;
    let datadir = prepare_datadir(root.path())?;
    let blocks = crossing_chain();
    let refs = blocks.iter().collect::<Vec<_>>();
    write_chainstate(&datadir, &refs, refs.last().copied(), &refs)?;
    write_block_records(&datadir, &refs)?;

    let output = rebuild(&datadir)?;
    parse_rebuild_report(&output)?;

    let store = Arc::new(RocksDbStore::open(datadir.join("txindex"))?);
    let before = bulk_owned_row_counts(&store)?;

    let scratch = tempfile::tempdir()?;
    let open = open_derived_index_store_with_scratch(
        Arc::clone(&store),
        DEFAULT_BATCH_LIMITS,
        BULK_GEN_ID,
        scratch.path().to_path_buf(),
    )
    .map_err(|error| TestError::Assertion(error.to_string()))?;
    let (_fence, marks) = open.writer().fenced_watermarks()?;

    let coverage = coverage_for(&blocks);
    let tip = IndexWatermark {
        height: coverage.last_height,
        hash: coverage.last_hash,
    };
    assert_eq!(
        marks.tx_lookup,
        Some(tip),
        "tx_lookup must sit at the rebuilt tip"
    );
    assert_eq!(
        marks.script_history,
        Some(tip),
        "script_history must sit at the rebuilt tip"
    );
    assert_eq!(
        marks.compact_filters,
        Some(tip),
        "compact_filters must sit at the rebuilt tip"
    );

    let after = bulk_owned_row_counts(&store)?;
    assert_eq!(
        after, before,
        "opening the rebuilt index must write no bulk-owned or IdxMeta rows"
    );
    Ok(())
}

// PRJ-09
#[test]
fn pruned_rebuild_withholds_unanchored_compact_filters() -> TestResult {
    let root = tempfile::tempdir()?;
    let datadir = prepare_datadir(root.path())?;
    let blocks = creating_chain();
    let retained = blocks[2..].iter().collect::<Vec<_>>();
    let all = blocks.iter().collect::<Vec<_>>();
    write_chainstate(&datadir, &retained, retained.last().copied(), &all)?;
    write_block_records(&datadir, &retained)?;

    parse_rebuild_report(&rebuild(&datadir)?)?;
    let store = Arc::new(RocksDbStore::open(datadir.join("txindex"))?);
    let mut writer = IndexWriter::open(Arc::clone(&store), BULK_GEN_ID)?;
    let (_, marks) = writer.fenced_watermarks()?;
    let tip = blocks.last().expect("fixture has a tip");
    let expected = Some(IndexWatermark {
        height: tip.height,
        hash: tip.hash,
    });
    assert_eq!(marks.tx_lookup, expected);
    assert_eq!(marks.script_history, expected);
    assert_eq!(marks.compact_filters, None);
    assert_eq!(
        store.get(
            ColumnFamily::IdxMeta,
            &meta_gen_key(IndexCapability::CompactFilters),
        )?,
        None
    );
    assert_eq!(count_rows(&store, ColumnFamily::Filters)?, 0);
    use bitcoin_rs_projection::IndexReader as _;

    let snapshot = writer.snapshot()?;
    assert!(!snapshot.capability_published(IndexCapability::CompactFilters)?);
    for block in retained {
        let txid = block.facts.txs[0].txid;
        let rows = snapshot.transaction_rows(
            &Txid::from(Hash256::from_le_bytes(&txid)),
            bitcoin_rs_storage::PrefixScanLimit {
                max_rows: 100,
                max_bytes: 1_000_000,
            },
        )?;
        assert!(rows.complete);
        let heights = rows
            .rows
            .iter()
            .map(|row| row.row.height())
            .collect::<Vec<_>>();
        assert_eq!(heights, vec![block.height]);
    }
    Ok(())
}

// PRJ-05
#[test]
fn rebuild_index_matches_the_live_tail_and_seal_generation() -> TestResult {
    let root = tempfile::tempdir()?;
    let datadir = prepare_datadir(root.path())?;
    let blocks = creating_chain();
    let refs = blocks.iter().collect::<Vec<_>>();
    write_chainstate(&datadir, &refs, refs.last().copied(), &refs)?;
    write_block_records(&datadir, &refs)?;

    let output = rebuild(&datadir)?;
    parse_rebuild_report(&output)?;
    let store = RocksDbStore::open(datadir.join("txindex"))?;
    let reference = live_reference(&blocks)?;
    assert_generation_matches(&store, &reference.store);
    Ok(())
}

// PRJ-05, PRJ-09
#[test]
fn rebuild_index_replaces_stale_generations_instead_of_overlaying() -> TestResult {
    let root = tempfile::tempdir()?;
    let datadir = prepare_datadir(root.path())?;
    let blocks = crossing_chain();
    let refs = blocks.iter().collect::<Vec<_>>();
    write_chainstate(&datadir, &refs, refs.last().copied(), &refs)?;
    write_block_records(&datadir, &refs)?;

    let stale_key = [BULK_GEN_ID.to_be_bytes().as_slice(), &[0xDE, 0xAD]].concat();
    {
        let store = RocksDbStore::open(datadir.join("txindex"))?;
        let mut batch = store.new_batch();
        batch.put(ColumnFamily::TxDir, &stale_key, b"stale");
        store.write_durable(batch)?;
    }

    for _ in 0..2 {
        let output = rebuild(&datadir)?;
        parse_rebuild_report(&output)?;
        let store = RocksDbStore::open(datadir.join("txindex"))?;
        assert!(
            store.get(ColumnFamily::TxDir, &stale_key)?.is_none(),
            "a stale generation row must be removed before the rebuild"
        );
        let reference = bulk_reference(&blocks)?;
        assert_generation_matches(&store, &reference.store);
        assert_descriptors(&store, &blocks)?;
    }
    Ok(())
}

const WIDE_OUTPUTS: u32 = 40_000;

fn wide_chain() -> Vec<FixtureBlock> {
    let mut ledger = CoinLedger::new();
    let genesis = assemble_block(
        BlockSpec {
            height: 0,
            parent: [0u8; 32],
            nonce: 0,
            txs: vec![coinbase_tx(6, &[(50_000, p2wpkh_script(0xE1))])],
        },
        &mut ledger,
    );
    let outputs = (0..WIDE_OUTPUTS)
        .map(|i| {
            (
                1_000 + u64::from(i),
                p2wpkh_script(u8::try_from(i % 256).expect("byte")),
            )
        })
        .collect::<Vec<_>>();
    let wide = assemble_block(
        BlockSpec {
            height: 1,
            parent: genesis.hash,
            nonce: 1,
            txs: vec![coinbase_tx(7, &outputs)],
        },
        &mut ledger,
    );
    vec![genesis, wide]
}

#[test]
fn rebuild_index_spills_under_a_one_mib_budget_and_matches_unbounded() -> TestResult {
    let tight_root = tempfile::tempdir()?;
    let tight = prepare_datadir(tight_root.path())?;
    let blocks = wide_chain();
    let refs = blocks.iter().collect::<Vec<_>>();
    write_chainstate(&tight, &refs, refs.last().copied(), &refs)?;
    write_block_records(&tight, &refs)?;
    let output = run_converter(&[
        "rebuild-index",
        "--datadir",
        tight.to_string_lossy().as_ref(),
        "--budget-mb",
        "1",
    ])?;
    let tight_report = parse_rebuild_report(&output)?;
    assert!(
        tight_report.budget_refusals > 0,
        "a 1 MiB budget over a >1 MiB row set must refuse reservations and spill runs: {tight_report:?}"
    );

    let wide_root = tempfile::tempdir()?;
    let wide = prepare_datadir(wide_root.path())?;
    write_chainstate(&wide, &refs, refs.last().copied(), &refs)?;
    write_block_records(&wide, &refs)?;
    let output = run_converter(&[
        "rebuild-index",
        "--datadir",
        wide.to_string_lossy().as_ref(),
        "--budget-mb",
        "1024",
    ])?;
    let wide_report = parse_rebuild_report(&output)?;
    assert_eq!(wide_report.budget_refusals, 0);

    let tight_store = RocksDbStore::open(tight.join("txindex"))?;
    let wide_store = RocksDbStore::open(wide.join("txindex"))?;
    assert_generation_matches(&tight_store, &wide_store);
    Ok(())
}

#[cfg(unix)]
#[test]
fn rebuild_index_refuses_symlinked_txindex_before_any_wipe() -> TestResult {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir()?;
    let victim = root.path().join("victim");
    fs::create_dir_all(&victim)?;
    let store = RocksDbStore::open(&victim)?;
    let mut batch = store.new_batch();
    batch.put(ColumnFamily::Funding, &[0xAA; 10], &[0x01, 0x02]);
    store.write_durable(batch)?;
    drop(store);
    let datadir = root.path().join("datadir");
    fs::create_dir_all(&datadir)?;
    fs::write(datadir.join("CURRENT_SCHEMA"), "6\n")?;
    symlink(&victim, datadir.join("txindex"))?;
    let output = run_converter(&[
        "rebuild-index",
        "--datadir",
        datadir.to_string_lossy().as_ref(),
    ])?;
    assert!(
        !output.status.success(),
        "a symlinked txindex namespace must abort the rebuild"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("symlink"),
        "refusal must name the symlinked namespace: {stderr}"
    );
    let store = RocksDbStore::open(&victim)?;
    let Some(value) = store.get(ColumnFamily::Funding, &[0xAA; 10])? else {
        return Err(TestError::Assertion(
            "refused rebuild wiped the symlink target".to_owned(),
        ));
    };
    assert_eq!(value.as_slice(), &[0x01, 0x02]);
    Ok(())
}

#[test]
fn rebuild_index_corrupt_source_leaves_existing_index_intact() -> TestResult {
    let root = tempfile::tempdir()?;
    let datadir = prepare_datadir(root.path())?;
    let store = RocksDbStore::open(datadir.join("txindex"))?;
    let mut batch = store.new_batch();
    batch.put(ColumnFamily::Funding, &[0xCC; 10], &[0x07, 0x08]);
    store.write_durable(batch)?;
    drop(store);
    let blocks = creating_chain();
    let refs = blocks.iter().collect::<Vec<_>>();
    write_chainstate(&datadir, &refs, refs.last().copied(), &refs)?;
    write_block_records(&datadir, &refs)?;
    let path = datadir.join("blocks").join("blk00000.dat");
    let mut bytes = fs::read(&path)?;
    let second_record = 44 + blocks[0].body.len();
    bytes[second_record] = b'X';
    fs::write(&path, bytes)?;
    let output = rebuild(&datadir)?;
    assert!(
        !output.status.success(),
        "a corrupt block record must abort the rebuild"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("magic"),
        "refusal must name the bad magic: {stderr}"
    );
    let store = RocksDbStore::open(datadir.join("txindex"))?;
    let Some(value) = store.get(ColumnFamily::Funding, &[0xCC; 10])? else {
        return Err(TestError::Assertion(
            "aborted rebuild wiped the live index".to_owned(),
        ));
    };
    assert_eq!(value.as_slice(), &[0x07, 0x08]);
    Ok(())
}

#[cfg(target_os = "linux")]
const LONG_CHAIN_BLOCKS: u32 = 100;

#[cfg(target_os = "linux")]
const SHORT_CHAIN_BLOCKS: u32 = 8;

#[cfg(target_os = "linux")]
const CHAIN_OUTPUTS_PER_BLOCK: u32 = 1_000;

#[cfg(target_os = "linux")]
const CHAIN_SCRIPT_LEN: usize = 512;

#[cfg(target_os = "linux")]
const CHAIN_PEAK_SLACK_KB: u64 = 24 * 1024;

#[cfg(target_os = "linux")]
fn chain_script() -> Vec<u8> {
    vec![0x42; CHAIN_SCRIPT_LEN]
}

#[cfg(target_os = "linux")]
fn uniform_chain(blocks: u32) -> TestResult<Vec<FixtureBlock>> {
    let mut ledger = CoinLedger::new();
    let mut out = Vec::new();
    let mut parent = [0u8; 32];
    for height in 0..blocks {
        let tag = u8::try_from(height % 256)?;
        let outputs = (0..CHAIN_OUTPUTS_PER_BLOCK)
            .map(|i| (1_000 + u64::from(i), chain_script()))
            .collect::<Vec<_>>();
        let block = assemble_block(
            BlockSpec {
                height,
                parent,
                nonce: height,
                txs: vec![coinbase_tx(tag, &outputs)],
            },
            &mut ledger,
        );
        parent = block.hash;
        out.push(block);
    }
    Ok(out)
}

#[cfg(target_os = "linux")]
fn timed_rebuild_peak(datadir: &Path) -> TestResult<(RebuildIndexReport, u64)> {
    let bin = env!("CARGO_BIN_EXE_bitcoin-rs-storage-convert");
    let output = std::process::Command::new("/usr/bin/time")
        .args([
            "-v",
            bin,
            "rebuild-index",
            "--datadir",
            datadir.to_string_lossy().as_ref(),
            "--budget-mb",
            "1",
        ])
        .output()?;
    if !output.status.success() {
        return Err(TestError::Assertion(format!(
            "rebuild-index failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let report: RebuildIndexReport = sonic_rs::from_slice(&output.stdout)?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    let mut peak = None;
    for line in stderr.lines() {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim() == "Maximum resident set size (kbytes)" {
                peak = value
                    .split_whitespace()
                    .next()
                    .and_then(|text| text.parse::<u64>().ok());
            }
        }
    }
    let Some(peak) = peak else {
        return Err(TestError::Assertion(
            "time reported no peak resident set size".to_owned(),
        ));
    };
    Ok((report, peak))
}

#[cfg(target_os = "linux")]
#[test]
fn rebuild_index_long_chain_peak_stays_near_short_chain_peak() -> TestResult {
    let short_root = tempfile::tempdir()?;
    let short_dir = prepare_datadir(short_root.path())?;
    let short_blocks = uniform_chain(SHORT_CHAIN_BLOCKS)?;
    let short_refs = short_blocks.iter().collect::<Vec<_>>();
    write_chainstate(
        &short_dir,
        &short_refs,
        short_refs.last().copied(),
        &short_refs,
    )?;
    write_block_records(&short_dir, &short_refs)?;
    let (_, short_peak) = timed_rebuild_peak(&short_dir)?;
    let long_root = tempfile::tempdir()?;
    let long_dir = prepare_datadir(long_root.path())?;
    let long_blocks = uniform_chain(LONG_CHAIN_BLOCKS)?;
    let long_refs = long_blocks.iter().collect::<Vec<_>>();
    write_chainstate(&long_dir, &long_refs, long_refs.last().copied(), &long_refs)?;
    write_block_records(&long_dir, &long_refs)?;
    let (long_report, long_peak) = timed_rebuild_peak(&long_dir)?;
    assert!(
        long_report.budget_refusals > 0,
        "a 1 MiB budget over a long chain must refuse and spill: {long_report:?}"
    );
    let bound = short_peak.saturating_add(CHAIN_PEAK_SLACK_KB);
    assert!(
        long_peak <= bound,
        "long-chain peak {long_peak} KiB exceeds short-chain peak {short_peak} KiB plus {CHAIN_PEAK_SLACK_KB} KiB"
    );
    Ok(())
}
