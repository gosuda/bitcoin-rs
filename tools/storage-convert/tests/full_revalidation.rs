use std::fs;
use std::path::Path;

use bitcoin_rs_consensus::primitives::Network;
use bitcoin_rs_execution::recovery::{
    ResumeSource, prepare_initial_state_with_engine, requires_full_revalidation,
};
use bitcoin_rs_storage::durable_head::{DURABLE_HEAD_KEY, DurableHead};
use bitcoin_rs_storage::recovery_evidence::FULL_REVALIDATION_MARKER;
use bitcoin_rs_storage::{ColumnFamily, KvStore, RocksDbStore};
use tempfile::tempdir;

use super::support::error::{TestError, TestResult};
use super::support::harness::{parse_report, run_converter};
use super::support::oracle::{write_rocksdb_namespace, write_schema_marker};

const MARKER_TEXT: &[u8] = b"required\n";

fn path_str(path: &Path) -> TestResult<&str> {
    path.to_str()
        .ok_or_else(|| TestError::Assertion("utf8 path".into()))
}

fn write_epoch3_base(from: &Path) -> TestResult<()> {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/epoch3-regtest");
    copy_fixture(&fixture, from)
}

fn copy_fixture(from: &Path, to: &Path) -> TestResult<()> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            copy_fixture(&entry.path(), &to.join(entry.file_name()))?;
        } else {
            fs::copy(entry.path(), to.join(entry.file_name()))?;
        }
    }
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

    let state = prepare_initial_state_with_engine(&to, Network::Regtest, Some(&head), None)
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

#[test]
fn epoch4_backend_copy_preserves_root_marker() -> TestResult {
    let source = tempdir()?;
    let dest = tempdir()?;
    let to = dest.path().join("converted");
    write_schema_marker(source.path(), 4)?;
    fs::write(source.path().join(FULL_REVALIDATION_MARKER), MARKER_TEXT)?;

    let height_key = b"head:height".to_vec();
    let height_value = 101_u64.to_le_bytes().to_vec();
    let tip_key = b"head:tip".to_vec();
    let tip_value = b"000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f".to_vec();
    let rows = vec![(
        ColumnFamily::UtxoMeta,
        vec![
            (height_key.clone(), height_value.clone()),
            (tip_key.clone(), tip_value.clone()),
        ],
    )];
    write_rocksdb_namespace(&source.path().join("chainstate"), &rows)?;

    let output = run_converter(&["--from", path_str(source.path())?, "--to", path_str(&to)?])?;
    let report = parse_report(&output)?;

    let chainstate = report
        .namespaces
        .iter()
        .find(|namespace| namespace.namespace == "chainstate")
        .ok_or_else(|| TestError::Assertion("chainstate namespace report missing".into()))?;
    if chainstate.engine != "rocksdb" {
        return Err(TestError::Assertion(format!(
            "the epoch-4 source chainstate must be converted from a real rocksdb backend, found engine {:?}",
            chainstate.engine
        )));
    }
    let meta = chainstate
        .families
        .iter()
        .find(|family| family.family == ColumnFamily::UtxoMeta.name())
        .ok_or_else(|| TestError::Assertion("utxo_meta family report missing".into()))?;
    if meta.row_count != 2 {
        return Err(TestError::Assertion(format!(
            "converted chainstate must carry both seeded rows, found {}",
            meta.row_count
        )));
    }

    assert_eq!(report.carried_markers, vec![FULL_REVALIDATION_MARKER]);
    assert_eq!(fs::read(to.join(FULL_REVALIDATION_MARKER))?, MARKER_TEXT);
    assert_eq!(
        fs::read(source.path().join(FULL_REVALIDATION_MARKER))?,
        MARKER_TEXT
    );

    let store = RocksDbStore::open(to.join("chainstate"))?;
    assert_eq!(
        store.get(ColumnFamily::UtxoMeta, &height_key)?,
        Some(height_value)
    );
    assert_eq!(
        store.get(ColumnFamily::UtxoMeta, &tip_key)?,
        Some(tip_value)
    );
    drop(store);

    let schema = fs::read_to_string(to.join("CURRENT_SCHEMA"))?;
    assert_eq!(schema, "6\n");
    Ok(())
}

#[test]
fn oversized_revalidation_markers_refuse_without_publication() -> TestResult {
    for epoch in [3, 4] {
        let source = tempdir()?;
        let dest = tempdir()?;
        let to = dest.path().join("converted");
        let marker_dir = if epoch == 3 {
            write_epoch3_base(source.path())?;
            let journal = source.path().join("chainstate-journal");
            fs::create_dir_all(&journal)?;
            journal
        } else {
            write_schema_marker(source.path(), 4)?;
            source.path().to_path_buf()
        };
        let bytes = b"required\nx";
        fs::write(marker_dir.join(FULL_REVALIDATION_MARKER), bytes)?;
        let output = run_converter(&["--from", path_str(source.path())?, "--to", path_str(&to)?])?;
        assert!(!output.status.success(), "oversized marker must refuse");
        assert!(!to.join("CURRENT_SCHEMA").exists());
        assert!(!to.join(FULL_REVALIDATION_MARKER).exists());
        assert_eq!(fs::read(marker_dir.join(FULL_REVALIDATION_MARKER))?, bytes);
    }
    Ok(())
}
