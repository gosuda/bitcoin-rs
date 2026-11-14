use bitcoin_rs_consensus::primitives::Hash256;
use bitcoin_rs_storage::durable_head::{DURABLE_HEAD_KEY, DurableHead};
use bitcoin_rs_storage::{ColumnFamily, KvStore, RocksDbStore};
use std::fs;
use tempfile::tempdir;

use super::epoch3_to_4::create_checkpoint_fixture;
use super::support::error::{TestError, TestResult};
use super::support::harness::{recursive_dir_digest, run_converter};
use super::support::oracle::{write_rocksdb_namespace, write_schema_marker};

/// Builds an epoch-3 source whose chainstate checkpoint, durable head, and
/// namespace rows satisfy the converter's fail-closed preconditions.
fn write_complete_epoch3_source(from_path: &std::path::Path) -> TestResult<()> {
    write_schema_marker(from_path, 3)?;
    let txid1 = Hash256::from_le_bytes(&[5u8; 32]);
    let checkpoint_tip = Hash256::from_le_bytes(&[100u8; 32]);
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
    Ok(())
}

#[test]
fn nonempty_destination_is_rejected_without_modifying_source_or_destination() -> TestResult<()> {
    let source_temp = tempdir()?;
    let dest_temp = tempdir()?;
    let from_path = source_temp.path();
    let to_path = dest_temp.path();

    write_schema_marker(from_path, 2)?;

    let pre_existing_file = to_path.join("existing_file.txt");
    fs::write(&pre_existing_file, b"pre-existing content")?;

    let source_digest_before = recursive_dir_digest(from_path)?;

    let output = run_converter(&[
        "--from",
        from_path.to_str().expect("valid utf8 path"),
        "--to",
        to_path.to_str().expect("valid utf8 path"),
    ])?;

    if output.status.success() {
        return Err(TestError::Assertion(
            "converter unexpectedly succeeded when destination was nonempty".into(),
        ));
    }

    let source_digest_after = recursive_dir_digest(from_path)?;
    if source_digest_before != source_digest_after {
        return Err(TestError::Assertion(
            "source directory was modified on nonempty destination rejection".into(),
        ));
    }

    let dest_content = fs::read(&pre_existing_file)?;
    if dest_content != b"pre-existing content" {
        return Err(TestError::Assertion(
            "pre-existing destination file was mutated on rejection".into(),
        ));
    }

    Ok(())
}

// RCV-09
#[test]
fn unknown_schema_epoch_is_rejected() -> TestResult<()> {
    let source_temp = tempdir()?;
    let dest_temp = tempdir()?;
    let from_path = source_temp.path();
    let to_path = dest_temp.path().join("converted");

    write_schema_marker(from_path, 9)?;

    let source_digest_before = recursive_dir_digest(from_path)?;

    let output = run_converter(&[
        "--from",
        from_path.to_str().expect("valid utf8 path"),
        "--to",
        to_path.to_str().expect("valid utf8 path"),
    ])?;

    if output.status.success() {
        return Err(TestError::Assertion(
            "converter unexpectedly succeeded on unknown epoch 9".into(),
        ));
    }

    let source_digest_after = recursive_dir_digest(from_path)?;
    if source_digest_before != source_digest_after {
        return Err(TestError::Assertion(
            "source directory was modified on unknown epoch rejection".into(),
        ));
    }

    if to_path.join("CURRENT_SCHEMA").exists() {
        return Err(TestError::Assertion(
            "destination CURRENT_SCHEMA was published on unknown epoch rejection".into(),
        ));
    }

    Ok(())
}

// RCV-09
#[test]
fn missing_schema_marker_is_rejected() -> TestResult<()> {
    let source_temp = tempdir()?;
    let dest_temp = tempdir()?;
    let from_path = source_temp.path();
    let to_path = dest_temp.path().join("converted");

    fs::write(from_path.join("unrelated_file.txt"), b"some data")?;

    let output = run_converter(&[
        "--from",
        from_path.to_str().expect("valid utf8 path"),
        "--to",
        to_path.to_str().expect("valid utf8 path"),
    ])?;

    if output.status.success() {
        return Err(TestError::Assertion(
            "converter unexpectedly succeeded on missing schema marker".into(),
        ));
    }

    if to_path.join("CURRENT_SCHEMA").exists() {
        return Err(TestError::Assertion(
            "destination CURRENT_SCHEMA was published on missing marker rejection".into(),
        ));
    }

    Ok(())
}

#[test]
fn identical_from_and_to_paths_rejected() -> TestResult<()> {
    let source_temp = tempdir()?;
    let path = source_temp.path();

    write_schema_marker(path, 2)?;

    let source_digest_before = recursive_dir_digest(path)?;

    let output = run_converter(&[
        "--from",
        path.to_str().expect("valid utf8 path"),
        "--to",
        path.to_str().expect("valid utf8 path"),
    ])?;

    if output.status.success() {
        return Err(TestError::Assertion(
            "converter unexpectedly succeeded when --from and --to are identical".into(),
        ));
    }

    let source_digest_after = recursive_dir_digest(path)?;
    if source_digest_before != source_digest_after {
        return Err(TestError::Assertion(
            "source directory was modified on identical paths rejection".into(),
        ));
    }

    Ok(())
}

#[test]
fn nested_destination_inside_source_rejected() -> TestResult<()> {
    let source_temp = tempdir()?;
    let from_path = source_temp.path();
    let nested_to = from_path.join("nested_dest");

    write_schema_marker(from_path, 2)?;

    let source_digest_before = recursive_dir_digest(from_path)?;

    let output = run_converter(&[
        "--from",
        from_path.to_str().expect("valid utf8 path"),
        "--to",
        nested_to.to_str().expect("valid utf8 path"),
    ])?;

    if output.status.success() {
        return Err(TestError::Assertion(
            "converter unexpectedly succeeded when --to was nested inside --from".into(),
        ));
    }

    let source_digest_after = recursive_dir_digest(from_path)?;
    if source_digest_before != source_digest_after {
        return Err(TestError::Assertion(
            "source directory was modified on nested destination rejection".into(),
        ));
    }

    Ok(())
}

#[test]
fn nested_source_inside_destination_rejected() -> TestResult<()> {
    let parent_temp = tempdir()?;
    let to_path = parent_temp.path();
    let nested_from = to_path.join("nested_from");

    write_schema_marker(&nested_from, 2)?;

    let source_digest_before = recursive_dir_digest(&nested_from)?;

    let output = run_converter(&[
        "--from",
        nested_from.to_str().expect("valid utf8 path"),
        "--to",
        to_path.to_str().expect("valid utf8 path"),
    ])?;

    if output.status.success() {
        return Err(TestError::Assertion(
            "converter unexpectedly succeeded when --from was nested inside --to".into(),
        ));
    }

    let source_digest_after = recursive_dir_digest(&nested_from)?;
    if source_digest_before != source_digest_after {
        return Err(TestError::Assertion(
            "source directory was modified on nested source rejection".into(),
        ));
    }

    Ok(())
}

#[test]
fn unpaired_pool_flags_rejected() -> TestResult<()> {
    let source_temp = tempdir()?;
    let dest_temp = tempdir()?;
    let pool_temp = tempdir()?;

    let from_path = source_temp.path();
    let to_path = dest_temp.path().join("converted");
    let pool_path = pool_temp.path();

    write_schema_marker(from_path, 2)?;

    let output_missing_to = run_converter(&[
        "--from",
        from_path.to_str().expect("valid utf8 path"),
        "--to",
        to_path.to_str().expect("valid utf8 path"),
        "--pool-from",
        pool_path.to_str().expect("valid utf8 path"),
    ])?;

    if output_missing_to.status.success() {
        return Err(TestError::Assertion(
            "converter unexpectedly succeeded with --pool-from but no --pool-to".into(),
        ));
    }

    let output_missing_from = run_converter(&[
        "--from",
        from_path.to_str().expect("valid utf8 path"),
        "--to",
        to_path.to_str().expect("valid utf8 path"),
        "--pool-to",
        pool_path.to_str().expect("valid utf8 path"),
    ])?;

    if output_missing_from.status.success() {
        return Err(TestError::Assertion(
            "converter unexpectedly succeeded with --pool-to but no --pool-from".into(),
        ));
    }

    Ok(())
}

#[test]
fn overlapping_pool_and_node_roots_rejected() -> TestResult<()> {
    let node_temp = tempdir()?;
    let dest_temp = tempdir()?;
    let from_path = node_temp.path();
    let to_path = dest_temp.path().join("converted");
    let pool_to = dest_temp.path().join("converted_pool");

    write_schema_marker(from_path, 2)?;

    let output = run_converter(&[
        "--from",
        from_path.to_str().expect("valid utf8 path"),
        "--to",
        to_path.to_str().expect("valid utf8 path"),
        "--pool-from",
        from_path.to_str().expect("valid utf8 path"),
        "--pool-to",
        pool_to.to_str().expect("valid utf8 path"),
    ])?;

    if output.status.success() {
        return Err(TestError::Assertion(
            "converter unexpectedly succeeded when --pool-from equaled --from".into(),
        ));
    }

    Ok(())
}

#[cfg(unix)]
#[test]
fn symlink_final_component_rejected() -> TestResult<()> {
    let source_temp = tempdir()?;
    let dest_temp = tempdir()?;
    let link_temp = tempdir()?;

    let from_path = source_temp.path();
    let to_path = dest_temp.path().join("converted");

    write_schema_marker(from_path, 2)?;

    let symlink_from = link_temp.path().join("symlink_from");
    std::os::unix::fs::symlink(from_path, &symlink_from)?;

    let output = run_converter(&[
        "--from",
        symlink_from.to_str().expect("valid utf8 path"),
        "--to",
        to_path.to_str().expect("valid utf8 path"),
    ])?;

    if output.status.success() {
        return Err(TestError::Assertion(
            "converter unexpectedly succeeded with symlink final component for --from".into(),
        ));
    }

    if to_path.join("CURRENT_SCHEMA").exists() {
        return Err(TestError::Assertion(
            "destination CURRENT_SCHEMA was published on symlink rejection".into(),
        ));
    }

    Ok(())
}

#[cfg(unix)]
#[test]
fn symlink_inside_independent_files_rejected() -> TestResult<()> {
    let source_temp = tempdir()?;
    let dest_temp = tempdir()?;
    let outside_temp = tempdir()?;

    let from_path = source_temp.path();
    let to_path = dest_temp.path().join("converted");

    write_schema_marker(from_path, 2)?;

    let blocks_dir = from_path.join("blocks");
    fs::create_dir_all(&blocks_dir)?;

    let outside_target = outside_temp.path().join("outside.dat");
    fs::write(&outside_target, b"secret_data")?;

    let symlink_in_blocks = blocks_dir.join("blk00000.dat");
    std::os::unix::fs::symlink(&outside_target, &symlink_in_blocks)?;

    let output = run_converter(&[
        "--from",
        from_path.to_str().expect("valid utf8 path"),
        "--to",
        to_path.to_str().expect("valid utf8 path"),
    ])?;

    if output.status.success() {
        return Err(TestError::Assertion(
            "converter unexpectedly succeeded when symlink was present inside blocks/".into(),
        ));
    }

    if to_path.join("CURRENT_SCHEMA").exists() {
        return Err(TestError::Assertion(
            "destination CURRENT_SCHEMA was published on internal symlink rejection".into(),
        ));
    }

    Ok(())
}

// RCV-09
#[test]
fn oversized_schema_marker_is_rejected() -> TestResult<()> {
    let source_temp = tempdir()?;
    let dest_temp = tempdir()?;
    let from_path = source_temp.path();
    let to_path = dest_temp.path().join("converted");

    fs::create_dir_all(from_path)?;
    fs::write(from_path.join("CURRENT_SCHEMA"), b"2\n               ")?;

    let source_digest_before = recursive_dir_digest(from_path)?;

    let output = run_converter(&[
        "--from",
        from_path.to_str().expect("valid utf8 path"),
        "--to",
        to_path.to_str().expect("valid utf8 path"),
    ])?;

    if output.status.success() {
        return Err(TestError::Assertion(
            "converter unexpectedly succeeded on oversized schema marker".into(),
        ));
    }

    let source_digest_after = recursive_dir_digest(from_path)?;
    if source_digest_before != source_digest_after {
        return Err(TestError::Assertion(
            "source directory was modified on oversized schema marker rejection".into(),
        ));
    }

    if to_path.join("CURRENT_SCHEMA").exists() {
        return Err(TestError::Assertion(
            "destination CURRENT_SCHEMA was published on oversized marker rejection".into(),
        ));
    }

    Ok(())
}

#[test]
fn unsupported_engine_string_rejected() -> TestResult<()> {
    let source_temp = tempdir()?;
    let dest_temp = tempdir()?;
    let from_path = source_temp.path();
    let to_path = dest_temp.path().join("converted");

    write_schema_marker(from_path, 3)?;

    let from_str = from_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("invalid utf-8 path".into()))?;
    let to_str = to_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("invalid utf-8 path".into()))?;

    let output = run_converter(&[
        "--from",
        from_str,
        "--to",
        to_str,
        "--to-engine",
        "unsupported_engine",
    ])?;

    if output.status.success() {
        return Err(TestError::Assertion(
            "converter unexpectedly succeeded with unsupported engine string".into(),
        ));
    }

    Ok(())
}

#[cfg(not(feature = "mdbx"))]
#[test]
fn uncompiled_mdbx_fails_with_missing_feature() -> TestResult<()> {
    let source_temp = tempdir()?;
    let dest_temp = tempdir()?;
    let from_path = source_temp.path();
    let to_path = dest_temp.path().join("converted");

    write_schema_marker(from_path, 3)?;

    let from_str = from_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("invalid utf-8 path".into()))?;
    let to_str = to_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("invalid utf-8 path".into()))?;

    let output = run_converter(&["--from", from_str, "--to", to_str, "--to-engine", "mdbx"])?;

    if output.status.success() {
        return Err(TestError::Assertion(
            "converter unexpectedly succeeded when mdbx feature was not compiled".into(),
        ));
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.contains("mdbx") {
        return Err(TestError::Assertion(format!(
            "stderr did not mention missing feature mdbx: {stderr}"
        )));
    }

    Ok(())
}

#[cfg(not(feature = "surrealkv"))]
#[test]
fn uncompiled_surrealkv_fails_with_missing_feature() -> TestResult<()> {
    let source_temp = tempdir()?;
    let dest_temp = tempdir()?;
    let from_path = source_temp.path();
    let to_path = dest_temp.path().join("converted");

    write_schema_marker(from_path, 3)?;

    let from_str = from_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("invalid utf-8 path".into()))?;
    let to_str = to_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("invalid utf-8 path".into()))?;

    let output = run_converter(&[
        "--from",
        from_str,
        "--to",
        to_str,
        "--to-engine",
        "surrealkv",
    ])?;

    if output.status.success() {
        return Err(TestError::Assertion(
            "converter unexpectedly succeeded when surrealkv feature was not compiled".into(),
        ));
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.contains("surrealkv") {
        return Err(TestError::Assertion(format!(
            "stderr did not mention missing feature surrealkv: {stderr}"
        )));
    }

    Ok(())
}

#[test]
fn overlaid_recognized_engines_in_epoch_3_namespace_is_rejected() -> TestResult<()> {
    let source_temp = tempdir()?;
    let dest_temp = tempdir()?;
    let from_path = source_temp.path();
    let to_path = dest_temp.path().join("converted");

    write_complete_epoch3_source(from_path)?;

    let chainstate_dir = from_path.join("chainstate");
    let rocks_data = vec![(
        bitcoin_rs_storage::ColumnFamily::UtxoMeta,
        vec![(b"meta:key".to_vec(), b"val".to_vec())],
    )];
    write_rocksdb_namespace(&chainstate_dir, &rocks_data)?;

    let standalone_mdbx_dir = tempdir()?;
    #[cfg(feature = "mdbx")]
    {
        let store = bitcoin_rs_storage::MdbxStore::open(standalone_mdbx_dir.path())?;
        store.put(bitcoin_rs_storage::ColumnFamily::UtxoMeta, b"k", b"v")?;
        fs::copy(
            standalone_mdbx_dir.path().join("mdbx.dat"),
            chainstate_dir.join("mdbx.dat"),
        )?;
    }
    #[cfg(not(feature = "mdbx"))]
    {
        fs::write(standalone_mdbx_dir.path().join("mdbx.dat"), b"fake_mdbx")?;
        fs::copy(
            standalone_mdbx_dir.path().join("mdbx.dat"),
            chainstate_dir.join("mdbx.dat"),
        )?;
    }

    let source_digest_before = recursive_dir_digest(from_path)?;

    let from_str = from_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("invalid utf-8 path".into()))?;
    let to_str = to_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("invalid utf-8 path".into()))?;

    let output = run_converter(&["--from", from_str, "--to", to_str])?;

    if output.status.success() {
        return Err(TestError::Assertion(
            "converter unexpectedly succeeded when multiple recognized engines were overlaid in epoch 3 namespace".into(),
        ));
    }

    let source_digest_after = recursive_dir_digest(from_path)?;
    if source_digest_before != source_digest_after {
        return Err(TestError::Assertion(
            "source directory was modified on overlaid engine rejection in epoch 3".into(),
        ));
    }

    if to_path.join("CURRENT_SCHEMA").exists() {
        return Err(TestError::Assertion(
            "CURRENT_SCHEMA was created on overlaid engine rejection in epoch 3".into(),
        ));
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.contains("multiple recognized storage engines detected") {
        return Err(TestError::Assertion(format!(
            "stderr did not mention multiple recognized storage engines: {stderr}"
        )));
    }

    Ok(())
}

#[test]
fn bare_relative_destination_path_succeeds() -> TestResult<()> {
    let source_temp = tempdir()?;
    let run_temp = tempdir()?;
    let from_path = source_temp.path();

    write_complete_epoch3_source(from_path)?;

    let from_str = from_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("invalid utf-8 path".into()))?;

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bitcoin-rs-storage-convert"))
        .args(["--from", from_str, "--to", "bare_converted_dest"])
        .current_dir(run_temp.path())
        .output()?;

    if !output.status.success() {
        return Err(TestError::Assertion(format!(
            "converter unexpectedly failed on bare relative destination path: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    let dest_schema = run_temp
        .path()
        .join("bare_converted_dest")
        .join("CURRENT_SCHEMA");
    if !dest_schema.exists() {
        return Err(TestError::Assertion(
            "destination CURRENT_SCHEMA was not created for bare relative destination path".into(),
        ));
    }

    Ok(())
}

#[cfg(unix)]
#[test]
fn symlink_final_component_trailing_slash_rejected() -> TestResult<()> {
    let source_temp = tempdir()?;
    let dest_temp = tempdir()?;
    let link_temp = tempdir()?;

    let from_path = source_temp.path();
    let to_path = dest_temp.path().join("converted");

    write_schema_marker(from_path, 3)?;

    let symlink_from = link_temp.path().join("symlink_from");
    std::os::unix::fs::symlink(from_path, &symlink_from)?;

    let symlink_from_trailing = format!("{}/", symlink_from.display());

    let output = run_converter(&[
        "--from",
        &symlink_from_trailing,
        "--to",
        to_path.to_str().expect("valid utf8 path"),
    ])?;

    if output.status.success() {
        return Err(TestError::Assertion(
            "converter unexpectedly succeeded with trailing slash on symlink final component for --from".into(),
        ));
    }

    if to_path.join("CURRENT_SCHEMA").exists() {
        return Err(TestError::Assertion(
            "destination CURRENT_SCHEMA was published on trailing slash symlink rejection".into(),
        ));
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.contains("symlink final component") {
        return Err(TestError::Assertion(format!(
            "stderr did not mention symlink final component: {stderr}"
        )));
    }

    Ok(())
}
