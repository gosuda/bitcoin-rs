use super::*;

use std::path::PathBuf;

fn publish_checkpoint_with_engine_image(data_dir: &Path) -> TestResult<PathBuf> {
    let (tree, _, applied) = chain_with_applied_height(0, 0)?;
    let applied_tip = tip_snapshot(&tree, applied)?;
    super::super::write_checkpoint(
        data_dir,
        config(),
        &RwLock::new(tree),
        &UtxoSet::new(),
        &CoinStatsListener::new(CoinStats::new()),
        Some(&applied_tip),
    )?;
    let root = data_dir.join(CHECKPOINT_ROOT);
    let current: CurrentV1 = sonic_rs::from_slice(&fs::read(root.join(CURRENT_FILE))?)?;
    Ok(root.join(current.directory).join("chainstate"))
}

fn replace_image_with_files(image: &Path, names: &[std::ffi::OsString]) -> TestResult {
    fs::remove_dir_all(image)?;
    fs::create_dir(image)?;
    for name in names {
        fs::write(image.join(name), b"foreign")?;
    }
    Ok(())
}

// RCV-10
#[test]
fn a_published_engine_image_restores_with_its_engine() -> TestResult {
    let dir = tempfile::tempdir()?;
    publish_checkpoint_with_engine_image(dir.path())?;
    let CheckpointLoad::Complete(restored) = load_checkpoint(dir.path(), config())? else {
        return Err(TestError::UnexpectedSuccess(
            "valid checkpoint did not load",
        ));
    };
    assert!(restored.engine.is_some());
    Ok(())
}

// RCV-10
#[test]
fn a_generation_without_an_engine_image_restores_without_an_engine() -> TestResult {
    let dir = tempfile::tempdir()?;
    let image = publish_checkpoint_with_engine_image(dir.path())?;
    fs::remove_dir_all(&image)?;
    let CheckpointLoad::Complete(restored) = load_checkpoint(dir.path(), config())? else {
        return Err(TestError::UnexpectedSuccess(
            "a generation without an engine image did not load",
        ));
    };
    assert!(restored.engine.is_none());
    Ok(())
}

// RCV-10
#[test]
fn an_engine_image_that_cannot_be_identified_fails_the_load_closed() -> TestResult {
    let shapes: [(&str, &[&str]); 3] = [
        ("empty directory", &[]),
        ("unknown files", &["junk"]),
        ("two engines", &["mdbx.dat", "CURRENT", "OPTIONS-000001"]),
    ];
    for (shape, names) in shapes {
        let dir = tempfile::tempdir()?;
        let image = publish_checkpoint_with_engine_image(dir.path())?;
        let names: Vec<std::ffi::OsString> = names.iter().map(Into::into).collect();
        replace_image_with_files(&image, &names)?;
        assert!(
            matches!(
                load_checkpoint(dir.path(), config()),
                Err(CheckpointLoadError::Corrupt(_))
            ),
            "{shape}: an engine image that cannot be identified must fail the load closed"
        );
    }
    Ok(())
}

// RCV-10
#[cfg(unix)]
#[test]
fn an_engine_image_with_a_non_utf8_file_name_fails_the_load_closed() -> TestResult {
    use std::os::unix::ffi::OsStringExt as _;

    let dir = tempfile::tempdir()?;
    let image = publish_checkpoint_with_engine_image(dir.path())?;
    let foreign = std::ffi::OsString::from_vec(b"\xff\xfenon-utf8".to_vec());
    replace_image_with_files(&image, &[foreign])?;
    assert!(
        matches!(
            load_checkpoint(dir.path(), config()),
            Err(CheckpointLoadError::Corrupt(_))
        ),
        "an engine image with a non-UTF-8 file name must fail the load closed"
    );
    Ok(())
}
