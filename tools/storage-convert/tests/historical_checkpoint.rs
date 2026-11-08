use std::fs;
use std::path::{Path, PathBuf};

use bitcoin_rs_consensus::primitives::{Hash256, Network, OutPoint, Txid};
use bitcoin_rs_execution::{AssumeUtxoManager, HistoricalCheckpointRef};
use bitcoin_rs_storage::ColumnFamily;
use bitcoin_rs_storage::checkpoint::{
    CheckpointManifestV1, CheckpointReference, HISTORICAL_CHECKPOINT_ROOT, MANIFEST_FILE,
};
use bitcoin_rs_storage::utxo::record::UtxoRecord;
use bitcoin_rs_storage::utxo::snapshot::read_snapshot_strict_v4;
use sha2::{Digest, Sha256};
use tempfile::tempdir;

use super::support::error::{TestError, TestResult};
use super::support::harness::{parse_report, run_converter};

const GENERATION: &str = "gen-00000000000000000001";
const UTXO_FILE: &str = "utxo-v4.dat";

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

fn stage_historical_source(from: &Path) -> TestResult<()> {
    copy_tree(&fixture_dir(), from)?;
    let checkpoint = from.join("chainstate-checkpoints").join(GENERATION);
    let historical = from.join(HISTORICAL_CHECKPOINT_ROOT).join(GENERATION);
    copy_tree(&checkpoint, &historical)
}

fn str_path(path: &Path) -> TestResult<&str> {
    path.to_str()
        .ok_or_else(|| TestError::Assertion("utf8 path".into()))
}

fn converted_generation(to: &Path) -> PathBuf {
    to.join(HISTORICAL_CHECKPOINT_ROOT).join(GENERATION)
}

fn read_manifest(generation: &Path) -> TestResult<(Vec<u8>, CheckpointManifestV1)> {
    let bytes = fs::read(generation.join(MANIFEST_FILE))?;
    let manifest: CheckpointManifestV1 = sonic_rs::from_slice(&bytes)
        .map_err(|error| TestError::Assertion(format!("manifest: {error}")))?;
    Ok((bytes, manifest))
}

fn historical_reference(generation: &Path) -> TestResult<HistoricalCheckpointRef> {
    let (bytes, manifest) = read_manifest(generation)?;
    let manifest_sha256: [u8; 32] = Sha256::digest(&bytes).into();
    let hash = Hash256::from_str_be(&manifest.applied_tip.hash)
        .map_err(|error| TestError::Assertion(format!("tip hash: {error}")))?;
    Ok(HistoricalCheckpointRef {
        checkpoint: CheckpointReference {
            generation: 1,
            manifest_sha256,
        },
        height: manifest.applied_tip.height,
        hash,
    })
}

#[test]
fn converted_historical_generation_loads_epoch3_coins_through_assumeutxo() -> TestResult {
    let source = tempdir()?;
    let dest = tempdir()?;
    let from = source.path();
    let to = dest.path().join("converted");
    stage_historical_source(from)?;

    let output = run_converter(&["--from", str_path(from)?, "--to", str_path(&to)?])?;
    parse_report(&output)?;

    let generation = converted_generation(&to);
    let (_, manifest) = read_manifest(&generation)?;
    let utxo = manifest.utxo.as_ref().ok_or_else(|| {
        TestError::Assertion("historical manifest must keep its utxo artifact".into())
    })?;
    let reference = historical_reference(&generation)?;

    let engine =
        AssumeUtxoManager::historical_checkpoint_engine(Network::Regtest, to.clone(), &reference)
            .map_err(|error| TestError::Assertion(error.to_string()))?
            .ok_or_else(|| {
                TestError::Assertion("historical checkpoint must restore an engine".into())
            })?;

    let mut snapshot_file = fs::File::open(generation.join(UTXO_FILE))?;
    let snapshot = read_snapshot_strict_v4(&mut snapshot_file)
        .map_err(|error| TestError::Assertion(format!("epoch-3 utxo-v4.dat: {error}")))?;

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
                    "engine coin differs from the epoch-3 utxo-v4.dat coin".into(),
                ));
            }
        }
    }

    let record_count =
        u64::try_from(rows.len()).map_err(|error| TestError::Assertion(error.to_string()))?;
    if record_count != utxo.record_count {
        return Err(TestError::Assertion(format!(
            "engine holds {} coin records, epoch-3 utxo-v4.dat holds {}",
            rows.len(),
            utxo.record_count
        )));
    }
    if outputs != utxo.output_count {
        return Err(TestError::Assertion(format!(
            "engine holds {outputs} outputs, epoch-3 utxo-v4.dat holds {}",
            utxo.output_count
        )));
    }
    Ok(())
}
