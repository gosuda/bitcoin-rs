use std::fs;
use std::path::Path;

use bitcoin_rs_consensus::primitives::{Hash256, Network};
use bitcoin_rs_execution::recovery::{
    ResumeSource, prepare_initial_state_with_engine, requires_full_revalidation,
};
use bitcoin_rs_storage::durable_head::{DURABLE_HEAD_KEY, DurableHead};
use bitcoin_rs_storage::recovery_evidence::FULL_REVALIDATION_MARKER;
use bitcoin_rs_storage::{ColumnFamily, KvStore, RocksDbStore};
use tempfile::tempdir;

use super::epoch3_to_4::create_checkpoint_fixture;
use super::support::error::{TestError, TestResult};
use super::support::harness::{parse_report, run_converter};
use super::support::oracle::write_schema_marker;

const MARKER_TEXT: &[u8] = b"full revalidation required after the checkpoint base\n";

fn path_str(path: &Path) -> TestResult<&str> {
    path.to_str()
        .ok_or_else(|| TestError::Assertion("utf8 path".into()))
}

fn write_epoch3_base(from: &Path) -> TestResult<()> {
    write_schema_marker(from, 3)?;
    let txid = Hash256::from_le_bytes(&[21u8; 32]);
    let tip = Hash256::from_le_bytes(&[0x5a; 32]);
    create_checkpoint_fixture(from, tip, 100, &[txid])?;

    let store = RocksDbStore::open(from.join("chainstate"))?;
    let head = DurableHead {
        assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
        commit_id: 1,
        height: 100,
        tip,
        chain_tx_count: 100,
        body_extent: None,
        undo_extent: None,
    };
    store.put(ColumnFamily::UtxoMeta, DURABLE_HEAD_KEY, &head.encode())?;
    Ok(())
}

fn write_epoch3_source_with_marker(from: &Path) -> TestResult<()> {
    write_epoch3_base(from)?;
    let journal = from.join("chainstate-journal");
    fs::create_dir_all(&journal)?;
    fs::write(journal.join(FULL_REVALIDATION_MARKER), MARKER_TEXT)?;
    Ok(())
}

#[test]
fn converted_datadir_carries_epoch3_full_revalidation_marker() -> TestResult {
    let source = tempdir()?;
    let dest = tempdir()?;
    let from = source.path();
    let to = dest.path().join("converted");
    write_epoch3_source_with_marker(from)?;

    let output = run_converter(&["--from", path_str(from)?, "--to", path_str(&to)?])?;
    let report = parse_report(&output)?;

    if report.carried_markers != vec![FULL_REVALIDATION_MARKER] {
        return Err(TestError::Assertion(format!(
            "report must list the carried marker, found {:?}",
            report.carried_markers
        )));
    }
    let carried = fs::read(to.join(FULL_REVALIDATION_MARKER))?;
    if carried != MARKER_TEXT {
        return Err(TestError::Assertion(
            "converted full-revalidation marker must keep the source bytes".into(),
        ));
    }
    Ok(())
}

#[test]
fn converted_full_revalidation_marker_selects_cold_startup() -> TestResult {
    let source = tempdir()?;
    let dest = tempdir()?;
    let from = source.path();
    let to = dest.path().join("converted");
    write_epoch3_source_with_marker(from)?;
    run_converter(&["--from", path_str(from)?, "--to", path_str(&to)?])?;

    if !requires_full_revalidation(&to) {
        return Err(TestError::Assertion(
            "a converted datadir with the epoch-3 marker must require full revalidation".into(),
        ));
    }
    let store = RocksDbStore::open(to.join("chainstate"))?;
    let raw = store
        .get(ColumnFamily::UtxoMeta, DURABLE_HEAD_KEY)?
        .ok_or_else(|| TestError::Assertion("converted durable head missing".into()))?;
    let head = DurableHead::decode(&raw)
        .ok_or_else(|| TestError::Assertion("converted durable head undecodable".into()))?;
    drop(store);

    let state = prepare_initial_state_with_engine(&to, Network::Regtest, Some(&head))
        .map_err(|error| TestError::Assertion(error.to_string()))?;
    if state.initial.resume_source != ResumeSource::Cold || state.engine.is_some() {
        return Err(TestError::Assertion(
            "the marked datadir must take the cold full-revalidation startup route".into(),
        ));
    }
    Ok(())
}

#[test]
fn converted_datadir_without_marker_does_not_require_full_revalidation() -> TestResult {
    let source = tempdir()?;
    let dest = tempdir()?;
    let from = source.path();
    let to = dest.path().join("converted");
    write_epoch3_base(from)?;
    let output = run_converter(&["--from", path_str(from)?, "--to", path_str(&to)?])?;
    let report = parse_report(&output)?;

    if !report.carried_markers.is_empty() || requires_full_revalidation(&to) {
        return Err(TestError::Assertion(
            "a source without the marker must not produce one".into(),
        ));
    }
    Ok(())
}
