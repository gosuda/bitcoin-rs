use std::fs;
use std::path::{Path, PathBuf};

use bitcoin_rs_consensus::primitives::{BlockHash, CompactTarget, Hash256, Header, Network};
use bitcoin_rs_execution::recovery::{
    ConvertedCheckpoint, ConvertedCheckpointError, ResumeSource, prepare_initial_state_with_engine,
    publish_converted_checkpoint,
};
use bitcoin_rs_storage::durable_head::{DURABLE_HEAD_KEY, DurableHead};
use bitcoin_rs_storage::utxo::record::UtxoRecord;
use bitcoin_rs_storage::utxo::stats::CoinStatsAccumulator;
use bitcoin_rs_storage::{ColumnFamily, KvStore, RocksDbStore};
use tempfile::tempdir;

use super::support::error::{TestError, TestResult};
use super::support::harness::{ConversionReport, parse_report, run_converter};

const FLAT_RECORD_MAGIC: &[u8; 4] = b"BRSB";

#[derive(serde::Deserialize)]
struct SuffixExpected {
    height: u32,
    tip_hash: String,
    txouts: u64,
    funding_txid: String,
    spend_txid: String,
    untouched_txid: String,
    canonical_coinbase_txid: String,
    stale_coinbase_txid: String,
}

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/epoch3-regtest-suffix")
}

fn expected() -> TestResult<SuffixExpected> {
    let path = fixture_dir().with_extension("expected.json");
    Ok(sonic_rs::from_slice(&fs::read(path)?)?)
}

fn path_str(path: &Path) -> TestResult<&str> {
    path.to_str()
        .ok_or_else(|| TestError::Assertion("utf8 path".into()))
}

fn copy_tree(from: &Path, to: &Path) -> TestResult<()> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let destination = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &destination)?;
        } else {
            fs::copy(entry.path(), destination)?;
        }
    }
    Ok(())
}

fn coin_key(txid_be: &str) -> TestResult<Vec<u8>> {
    let txid = Hash256::from_str_be(txid_be)
        .map_err(|error| TestError::Assertion(format!("txid {txid_be}: {error}")))?;
    Ok(txid.to_le_bytes().to_vec())
}

fn coin_vouts(store: &dyn KvStore, txid_be: &str) -> TestResult<Option<Vec<u32>>> {
    let Some(raw) = store.get(ColumnFamily::Coins, &coin_key(txid_be)?)? else {
        return Ok(None);
    };
    let record = UtxoRecord::from_encoded(raw.into_boxed_slice())
        .map_err(|error| TestError::Assertion(format!("coin record: {error}")))?;
    Ok(Some(record.outputs().map(|out| out.vout).collect()))
}

fn converted_durable_head(to: &Path) -> TestResult<DurableHead> {
    let store = RocksDbStore::open(to.join("chainstate"))?;
    let raw = store
        .get(ColumnFamily::UtxoMeta, DURABLE_HEAD_KEY)?
        .ok_or_else(|| TestError::Assertion("converted durable head missing".into()))?;
    DurableHead::decode(&raw)
        .ok_or_else(|| TestError::Assertion("converted durable head undecodable".into()))
}

fn convert_fixture(from: &Path, to: &Path) -> TestResult<ConversionReport> {
    copy_tree(&fixture_dir(), from)?;
    let output = run_converter(&["--from", path_str(from)?, "--to", path_str(to)?])?;
    parse_report(&output)
}

#[test]
fn converted_suffix_datadir_resumes_from_checkpoint_at_durable_head() -> TestResult {
    let source = tempdir()?;
    let dest = tempdir()?;
    let from = source.path();
    let to = dest.path().join("converted");
    let report = convert_fixture(from, &to)?;
    if !report.published_checkpoint {
        return Err(TestError::Assertion(
            "a durable head above the source checkpoint must publish an epoch-4 checkpoint".into(),
        ));
    }

    let head = converted_durable_head(&to)?;
    let source_head = {
        let store = RocksDbStore::open(from.join("chainstate"))?;
        let raw = store
            .get(ColumnFamily::UtxoMeta, DURABLE_HEAD_KEY)?
            .ok_or_else(|| TestError::Assertion("source durable head missing".into()))?;
        DurableHead::decode(&raw)
            .ok_or_else(|| TestError::Assertion("source durable head undecodable".into()))?
    };
    if source_head.height != head.height
        || source_head.tip != head.tip
        || source_head.chain_tx_count != head.chain_tx_count
    {
        return Err(TestError::Assertion(format!(
            "converted durable head {} at {} with chain_tx_count {} must equal the source {} at {} with {}",
            head.tip.to_string_be(),
            head.height,
            head.chain_tx_count,
            source_head.tip.to_string_be(),
            source_head.height,
            source_head.chain_tx_count
        )));
    }
    let expected = expected()?;
    if head.height != expected.height || head.tip.to_string_be() != expected.tip_hash {
        return Err(TestError::Assertion(format!(
            "converted durable head {} at {} differs from the source head {} at {}",
            head.tip.to_string_be(),
            head.height,
            expected.tip_hash,
            expected.height
        )));
    }

    let restored = prepare_initial_state_with_engine(&to, Network::Regtest, Some(&head))
        .map_err(|error| TestError::Assertion(error.to_string()))?;
    if restored.initial.resume_source != ResumeSource::Checkpoint {
        return Err(TestError::Assertion(format!(
            "converted suffix datadir must resume from the checkpoint, found {:?}",
            restored.initial.resume_source
        )));
    }
    if restored.engine.is_none() {
        return Err(TestError::Assertion(
            "checkpoint resume must carry the converted engine coins".into(),
        ));
    }
    let tip = restored
        .initial
        .applied_tip
        .ok_or_else(|| TestError::Assertion("resumed state has no applied tip".into()))?;
    if tip.height != head.height || tip.hash != head.tip {
        return Err(TestError::Assertion(format!(
            "resumed tip {} at {} must equal the durable head {} at {}",
            tip.hash.to_string_be(),
            tip.height,
            head.tip.to_string_be(),
            head.height
        )));
    }
    if tip.chain_tx_count.to_wire() != head.chain_tx_count {
        return Err(TestError::Assertion(format!(
            "resumed chain_tx_count {} must equal the source {}",
            tip.chain_tx_count.to_wire(),
            head.chain_tx_count
        )));
    }
    Ok(())
}

#[test]
fn converted_suffix_applies_spends_and_excludes_the_stale_branch() -> TestResult {
    let source = tempdir()?;
    let dest = tempdir()?;
    let to = dest.path().join("converted");
    let report = convert_fixture(source.path(), &to)?;
    let expected = expected()?;

    let store = RocksDbStore::open(to.join("chainstate"))?;
    if coin_vouts(&store, &expected.funding_txid)?.is_some() {
        return Err(TestError::Assertion(
            "a checkpoint coin spent in the suffix must be deleted from the converted coins".into(),
        ));
    }
    if coin_vouts(&store, &expected.spend_txid)? != Some(vec![0]) {
        return Err(TestError::Assertion(
            "the suffix spend output must exist in the converted coins".into(),
        ));
    }
    if coin_vouts(&store, &expected.untouched_txid)? != Some(vec![0]) {
        return Err(TestError::Assertion(
            "an unspent checkpoint coin must be preserved in the converted coins".into(),
        ));
    }
    if coin_vouts(&store, &expected.canonical_coinbase_txid)? != Some(vec![0]) {
        return Err(TestError::Assertion(
            "the canonical branch coinbase must exist in the converted coin set".into(),
        ));
    }
    if coin_vouts(&store, &expected.stale_coinbase_txid)?.is_some() {
        return Err(TestError::Assertion(
            "the stale branch coinbase must not exist in the converted coin set".into(),
        ));
    }
    let final_stats = report
        .final_stats
        .ok_or_else(|| TestError::Assertion("report must carry final coin statistics".into()))?;
    if final_stats.utxo_count != expected.txouts {
        return Err(TestError::Assertion(format!(
            "converted coin count {} must equal the source txouts {}",
            final_stats.utxo_count, expected.txouts
        )));
    }
    Ok(())
}

#[test]
fn converted_suffix_with_corrupt_block_record_fails_closed() -> TestResult {
    let source = tempdir()?;
    let dest = tempdir()?;
    let from = source.path();
    let to = dest.path().join("converted");
    copy_tree(&fixture_dir(), from)?;

    let blocks = from.join("blocks/blk00000.dat");
    let mut bytes = fs::read(&blocks)?;
    let last_record = bytes
        .windows(FLAT_RECORD_MAGIC.len())
        .rposition(|window| window == FLAT_RECORD_MAGIC)
        .ok_or_else(|| TestError::Assertion("source block file has no record".into()))?;
    bytes[last_record] ^= 0xff;
    fs::write(&blocks, &bytes)?;

    let output = run_converter(&["--from", path_str(from)?, "--to", path_str(&to)?])?;
    if output.status.success() {
        return Err(TestError::Assertion(
            "a corrupt suffix block record must refuse conversion".into(),
        ));
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.contains("missing block or undo data at height 104") {
        return Err(TestError::Assertion(format!(
            "a corrupt suffix block must refuse at height 104 with missing block data, got: {stderr}"
        )));
    }
    if to.join("CURRENT_SCHEMA").exists() {
        return Err(TestError::Assertion(
            "a refused conversion must not publish the target schema".into(),
        ));
    }
    Ok(())
}

#[test]
fn converted_suffix_with_mismatched_chain_tx_count_fails_closed() -> TestResult {
    let source = tempdir()?;
    let dest = tempdir()?;
    let from = source.path();
    let to = dest.path().join("converted");
    copy_tree(&fixture_dir(), from)?;

    let source_store = RocksDbStore::open(from.join("chainstate"))?;
    let raw = source_store
        .get(ColumnFamily::UtxoMeta, DURABLE_HEAD_KEY)?
        .ok_or_else(|| TestError::Assertion("source durable head missing".into()))?;
    let mut head = DurableHead::decode(&raw)
        .ok_or_else(|| TestError::Assertion("source durable head undecodable".into()))?;
    head.chain_tx_count += 1;
    source_store.put(ColumnFamily::UtxoMeta, DURABLE_HEAD_KEY, &head.encode())?;
    drop(source_store);

    let output = run_converter(&["--from", path_str(from)?, "--to", path_str(&to)?])?;
    if output.status.success() {
        return Err(TestError::Assertion(
            "a durable head whose chain_tx_count differs from the replay must refuse conversion"
                .into(),
        ));
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.contains("chain_tx_count") {
        return Err(TestError::Assertion(format!(
            "refusal must name chain_tx_count, got: {stderr}"
        )));
    }
    if to.join("CURRENT_SCHEMA").exists() {
        return Err(TestError::Assertion(
            "a refused conversion must not publish the target schema".into(),
        ));
    }
    let source_current = fs::read(from.join("chainstate-checkpoints/CURRENT"))?;
    let target_current = to.join("chainstate-checkpoints/CURRENT");
    if target_current.exists() && fs::read(&target_current)? != source_current {
        return Err(TestError::Assertion(
            "a refused conversion must not publish a new checkpoint generation".into(),
        ));
    }
    Ok(())
}

#[derive(serde::Deserialize)]
struct ManifestTipHash {
    hash: String,
}

#[derive(serde::Deserialize)]
struct ManifestApplied {
    applied_tip: ManifestTipHash,
}

#[test]
fn converted_suffix_with_broken_prev_hash_fails_closed() -> TestResult {
    let source = tempdir()?;
    let dest = tempdir()?;
    let from = source.path();
    let to = dest.path().join("converted");
    copy_tree(&fixture_dir(), from)?;

    let blocks = from.join("blocks/blk00000.dat");
    let mut bytes = fs::read(&blocks)?;
    let records: Vec<usize> = bytes
        .windows(FLAT_RECORD_MAGIC.len())
        .enumerate()
        .filter(|(_, window)| *window == FLAT_RECORD_MAGIC)
        .map(|(offset, _)| offset)
        .collect();
    let record = *records.iter().rev().nth(1).ok_or_else(|| {
        TestError::Assertion("source block file needs a height-103 record".into())
    })?;
    let height_bytes: [u8; 4] = bytes[record + 8..record + 12]
        .try_into()
        .map_err(|_| TestError::Assertion("record height is short".into()))?;
    let height = u32::from_le_bytes(height_bytes);
    if height != 103 {
        return Err(TestError::Assertion(format!(
            "expected the height-103 record, found height {height}"
        )));
    }
    let body_start = record + 44;
    bytes[body_start + 4..body_start + 36].copy_from_slice(&[0xab; 32]);
    fs::write(&blocks, &bytes)?;

    let output = run_converter(&["--from", path_str(from)?, "--to", path_str(&to)?])?;
    if output.status.success() {
        return Err(TestError::Assertion(
            "a suffix block whose prev-hash does not link must refuse conversion".into(),
        ));
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.contains("block identity") {
        return Err(TestError::Assertion(format!(
            "refusal must come from the block identity (linkage) check, got: {stderr}"
        )));
    }
    if to.join("CURRENT_SCHEMA").exists() {
        return Err(TestError::Assertion(
            "a refused conversion must not publish the target schema".into(),
        ));
    }
    Ok(())
}

#[test]
fn publish_converted_checkpoint_refuses_a_header_that_fails_proof_of_work() -> TestResult {
    let source = tempdir()?;
    let dest = tempdir()?;
    let from = source.path();
    copy_tree(&fixture_dir(), from)?;

    let manifest: ManifestApplied = sonic_rs::from_slice(&fs::read(
        from.join("chainstate-checkpoints/gen-00000000000000000001/manifest-v1.json"),
    )?)?;
    let checkpoint_tip = Hash256::from_str_be(&manifest.applied_tip.hash)
        .map_err(|error| TestError::Assertion(format!("checkpoint tip: {error}")))?;
    let header = Header {
        version: 1,
        prev_blockhash: BlockHash(checkpoint_tip),
        merkle_root: Hash256::from_le_bytes(&[0_u8; 32]),
        time: 1_700_000_102,
        bits: CompactTarget::from_consensus(0x1c00_ffff),
        nonce: 0,
    };
    let header_hash = Hash256::from(header.compute_hash());

    let to = dest.path().join("converted");
    fs::create_dir_all(&to)?;
    let engine = RocksDbStore::open(dest.path().join("engine"))?;
    let source_dir = cap_std::fs::Dir::open_ambient_dir(from, cap_std::ambient_authority())?;
    let target_dir = cap_std::fs::Dir::open_ambient_dir(&to, cap_std::ambient_authority())?;
    let result = publish_converted_checkpoint(
        &source_dir,
        &target_dir,
        &to,
        Network::Regtest,
        ConvertedCheckpoint {
            headers: &[header],
            tip_height: 102,
            tip_hash: header_hash,
            chain_tx_count: 0,
            stats: CoinStatsAccumulator::with_parallel_muhash(102).into_stats(),
        },
        &engine,
    );
    match result {
        Err(ConvertedCheckpointError::Headers(_)) => {}
        Err(other) => {
            return Err(TestError::Assertion(format!(
                "a header that fails proof of work must fail in header validation, got: {other}"
            )));
        }
        Ok(()) => {
            return Err(TestError::Assertion(
                "a header that fails proof of work must not publish a checkpoint".into(),
            ));
        }
    }
    if to.join("chainstate-checkpoints").exists() {
        return Err(TestError::Assertion(
            "a refused publish must write no checkpoint root".into(),
        ));
    }
    Ok(())
}
