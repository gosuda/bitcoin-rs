use std::fs;
use std::path::{Path, PathBuf};

use bitcoin_rs_consensus::primitives::{Hash256, Network, OutPoint, Txid};
use bitcoin_rs_execution::recovery::{ResumeSource, prepare_initial_state_with_engine};
use bitcoin_rs_storage::checkpoint::{CHECKPOINT_ROOT, CheckpointManifestV1, MANIFEST_FILE};
use bitcoin_rs_storage::durable_head::{DURABLE_HEAD_KEY, DurableHead};
use bitcoin_rs_storage::utxo::record::UtxoRecord;
use bitcoin_rs_storage::utxo::snapshot::read_snapshot_strict_v4;
use bitcoin_rs_storage::{ColumnFamily, KvStore, RocksDbStore};
use tempfile::tempdir;

use super::support::error::{TestError, TestResult};
use super::support::harness::{
    ConversionReport, parse_report, recursive_dir_digest, run_converter,
};
use super::support::oracle::write_schema_marker;

const ANCHORED_BASE_HASH: &str = "06e5c2437917d314b424eb249ad2ae9d5408e530b7abf33b03cb0d0a084ca528";
const GENERATION: &str = "gen-00000000000000000001";
const UTXO_FILE: &str = "utxo-v4.dat";
const HEADERS_PAYLOAD: &[u8] = b"assumeutxo-headers-immutable-archive-bytes";
const COINS_PAYLOAD: &[u8] = b"assumeutxo-coins-immutable-archive-bytes";

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/epoch3-regtest")
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

fn str_path(path: &Path) -> TestResult<&str> {
    path.to_str()
        .ok_or_else(|| TestError::Assertion("utf8 path".into()))
}

fn write_snapshot_archive(source: &Path) -> TestResult<()> {
    let generation_dir = source.join("assumeutxo").join(ANCHORED_BASE_HASH);
    fs::create_dir_all(&generation_dir)?;
    fs::write(generation_dir.join("headers.dat"), HEADERS_PAYLOAD)?;
    fs::write(generation_dir.join("coins.dat"), COINS_PAYLOAD)?;
    Ok(())
}

fn read_manifest(generation: &Path) -> TestResult<CheckpointManifestV1> {
    let bytes = fs::read(generation.join(MANIFEST_FILE))?;
    sonic_rs::from_slice(&bytes).map_err(|error| TestError::Assertion(format!("manifest: {error}")))
}

fn convert(from: &Path, to: &Path) -> TestResult<ConversionReport> {
    let output = run_converter(&["--from", str_path(from)?, "--to", str_path(to)?])?;
    if !output.status.success() {
        return Err(TestError::Assertion(format!(
            "converter failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    parse_report(&output)
}

fn assert_archive_copied(
    dest_root: &Path,
    report: &ConversionReport,
    file_name: &str,
    payload: &[u8],
) -> TestResult<()> {
    let rel_path = format!("assumeutxo/{ANCHORED_BASE_HASH}/{file_name}");
    let path = dest_root.join(&rel_path);
    if !path.is_file() {
        return Err(TestError::Assertion(format!(
            "converted datadir is missing the immutable snapshot archive file {rel_path} that the epoch-3 target must preserve"
        )));
    }
    let bytes = fs::read(&path)?;
    if bytes != payload {
        return Err(TestError::Assertion(format!(
            "converted snapshot archive file {rel_path} is not byte-identical to the source archive"
        )));
    }
    let Some(entry) = report
        .copied_files
        .iter()
        .find(|copied| copied.path == rel_path)
    else {
        return Err(TestError::Assertion(format!(
            "verification report omits the copied snapshot archive file {rel_path}"
        )));
    };
    let expected_bytes = u64::try_from(payload.len()).map_err(|_| {
        TestError::Assertion(format!("payload length for {rel_path} overflows u64"))
    })?;
    if entry.bytes != expected_bytes {
        return Err(TestError::Assertion(format!(
            "verification report records the wrong size for {rel_path}"
        )));
    }
    Ok(())
}

#[test]
fn epoch2_source_copies_snapshot_archive_into_epoch3_target() -> TestResult<()> {
    let source = tempdir()?;
    let dest = tempdir()?;
    let from = source.path();
    let to = dest.path().join("converted");

    write_schema_marker(from, 2)?;
    write_snapshot_archive(from)?;

    let source_digest_before = recursive_dir_digest(from)?;
    let report = convert(from, &to)?;
    if report.source_epoch != 2 || report.target_epoch != 3 {
        return Err(TestError::Assertion(format!(
            "expected report 2 -> 3, got {} -> {}",
            report.source_epoch, report.target_epoch
        )));
    }
    if fs::read_to_string(to.join("CURRENT_SCHEMA"))? != "3\n" {
        return Err(TestError::Assertion(
            "epoch-2 conversion must publish the epoch-3 schema".into(),
        ));
    }
    let source_digest_after = recursive_dir_digest(from)?;
    if source_digest_before != source_digest_after {
        return Err(TestError::Assertion(
            "source directory recursive digest changed while converting the snapshot archive"
                .into(),
        ));
    }

    assert_archive_copied(&to, &report, "headers.dat", HEADERS_PAYLOAD)?;
    assert_archive_copied(&to, &report, "coins.dat", COINS_PAYLOAD)?;
    Ok(())
}

#[test]
fn epoch3_archive_source_retires_archive_and_reopens_published_checkpoint() -> TestResult<()> {
    let source = tempdir()?;
    let dest = tempdir()?;
    let from = source.path();
    let to = dest.path().join("converted");

    copy_tree(&fixture_dir(), from)?;
    write_snapshot_archive(from)?;

    let source_digest_before = recursive_dir_digest(from)?;
    let report = convert(from, &to)?;
    if report.source_epoch != 3 || report.target_epoch != 6 {
        return Err(TestError::Assertion(format!(
            "expected report 3 -> 6, got {} -> {}",
            report.source_epoch, report.target_epoch
        )));
    }
    if !report.published_checkpoint {
        return Err(TestError::Assertion(
            "an equal-head epoch-3 conversion must publish its checkpoint".into(),
        ));
    }
    if to.join("assumeutxo").exists() {
        return Err(TestError::Assertion(
            "the epoch-6 target retires the archive consumer and must not copy assumeutxo/".into(),
        ));
    }
    if fs::read_to_string(to.join("CURRENT_SCHEMA"))? != "6\n" {
        return Err(TestError::Assertion(
            "destination marker must be epoch 6".into(),
        ));
    }
    let source_digest_after = recursive_dir_digest(from)?;
    if source_digest_before != source_digest_after {
        return Err(TestError::Assertion(
            "source directory recursive digest changed while converting the epoch-3 archive source"
                .into(),
        ));
    }

    let generation = from.join(CHECKPOINT_ROOT).join(GENERATION);
    let manifest = read_manifest(&generation)?;
    let source_utxo = manifest
        .utxo
        .as_ref()
        .ok_or_else(|| TestError::Assertion("epoch-3 fixture manifest must carry utxo".into()))?;
    let mut snapshot_file = fs::File::open(generation.join(UTXO_FILE))?;
    let snapshot = read_snapshot_strict_v4(&mut snapshot_file)
        .map_err(|error| TestError::Assertion(format!("epoch-3 utxo-v4.dat: {error}")))?;

    let store = RocksDbStore::open(to.join("chainstate"))?;
    let raw = store
        .get(ColumnFamily::UtxoMeta, DURABLE_HEAD_KEY)?
        .ok_or_else(|| TestError::Assertion("converted durable head missing".into()))?;
    let head = DurableHead::decode(&raw)
        .ok_or_else(|| TestError::Assertion("converted durable head undecodable".into()))?;
    drop(store);
    if head.height != snapshot.height || head.tip != snapshot.tip_hash {
        return Err(TestError::Assertion(
            "converted durable head must equal the checkpoint applied tip".into(),
        ));
    }

    let state = prepare_initial_state_with_engine(&to, Network::Regtest, Some(&head), None)
        .map_err(|error| TestError::Assertion(error.to_string()))?;
    if state.initial.resume_source != ResumeSource::Checkpoint {
        return Err(TestError::Assertion(
            "the converted datadir must resume from the published checkpoint".into(),
        ));
    }
    let applied = state
        .initial
        .applied_tip
        .ok_or_else(|| TestError::Assertion("restored tip missing".into()))?;
    if applied.height != snapshot.height || applied.hash != snapshot.tip_hash {
        return Err(TestError::Assertion(
            "the converted datadir must resume at the checkpoint tip".into(),
        ));
    }
    if state.initial.coin_stats.tx_count != manifest.applied_tip.chain_tx_count {
        return Err(TestError::Assertion(
            "restored coin statistics must equal the checkpoint transaction count".into(),
        ));
    }

    let engine = state
        .engine
        .ok_or_else(|| TestError::Assertion("restored engine image missing".into()))?;
    let rows = engine
        .iter_prefix(ColumnFamily::Coins, &[])?
        .collect::<Result<Vec<_>, _>>()?;
    let mut outputs = 0_u64;
    for (key, value) in &rows {
        let txid_bytes: [u8; 32] = key
            .as_slice()
            .try_into()
            .map_err(|_| TestError::Assertion("coin key must be a 32-byte txid".into()))?;
        let txid = Txid(Hash256::from_le_bytes(&txid_bytes));
        let record = UtxoRecord::from_encoded(value.clone().into_boxed_slice())
            .map_err(|error| TestError::Assertion(format!("coin record: {error}")))?;
        for out in record.outputs() {
            outputs += 1;
            let coin = snapshot
                .set
                .get_entry(&OutPoint::new(txid, out.vout))
                .ok_or_else(|| {
                    TestError::Assertion("engine coin absent from utxo-v4.dat".into())
                })?;
            if coin.txout.value.to_sat() != out.value
                || coin.txout.script_pubkey.as_bytes() != out.script_pubkey
                || coin.coinbase != out.coinbase
                || coin.height != out.height
            {
                return Err(TestError::Assertion(
                    "engine coin differs from the checkpoint utxo-v4.dat coin".into(),
                ));
            }
        }
    }
    let record_count =
        u64::try_from(rows.len()).map_err(|error| TestError::Assertion(error.to_string()))?;
    if record_count != source_utxo.record_count {
        return Err(TestError::Assertion(format!(
            "engine holds {} coin records, epoch-3 utxo-v4.dat holds {}",
            rows.len(),
            source_utxo.record_count
        )));
    }
    if outputs != source_utxo.output_count {
        return Err(TestError::Assertion(format!(
            "engine holds {outputs} outputs, epoch-3 utxo-v4.dat holds {}",
            source_utxo.output_count
        )));
    }
    Ok(())
}
