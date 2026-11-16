use super::*;

use sha2::Digest;

#[test]
fn checkpoint_transaction_counts_must_agree_when_known() -> TestResult {
    for chain_tx_count in [0, 1] {
        let dir = tempfile::tempdir()?;
        let (tree, _, applied) = chain_with_applied_height(0, 0)?;
        let applied_tip = tip_snapshot(&tree, applied)?;
        let tree = RwLock::new(tree);
        let applied_tip = crate::chain::TipSnapshot {
            chain_tx_count: crate::chain::ChainTxCount::from_wire(chain_tx_count),
            ..applied_tip
        };
        let mut stats = CoinStats::new();
        stats.finish_block(0, 1);
        super::super::write_checkpoint(
            dir.path(),
            config(),
            &tree,
            &UtxoSet::new(),
            &CoinStatsListener::new(stats),
            Some(&applied_tip),
        )?;
        let CheckpointLoad::Complete(restored) = load_checkpoint(dir.path(), config())? else {
            return Err(TestError::UnexpectedSuccess(
                "valid checkpoint did not load",
            ));
        };
        assert_eq!(
            restored.applied_tip.chain_tx_count.to_wire(),
            chain_tx_count
        );
        assert_eq!(restored.coin_stats.tx_count, 1);

        mutate_authenticated_manifest(dir.path(), |manifest| {
            manifest.applied_tip.chain_tx_count = 2;
        })?;
        let Err(CheckpointLoadError::Corrupt(_)) = load_checkpoint(dir.path(), config()) else {
            return Err(TestError::UnexpectedSuccess(
                "inconsistent authenticated transaction counts were restored",
            ));
        };
    }
    Ok(())
}

#[test]
fn checkpoint_writer_refuses_inconsistent_transaction_counts() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (tree, _, applied) = chain_with_applied_height(0, 0)?;
    let applied_tip = tip_snapshot(&tree, applied)?;
    let applied_tip = crate::chain::TipSnapshot {
        chain_tx_count: crate::chain::ChainTxCount::established(2),
        ..applied_tip
    };
    let result = super::super::write_checkpoint(
        dir.path(),
        config(),
        &RwLock::new(tree),
        &UtxoSet::new(),
        &CoinStatsListener::new(CoinStats::new()),
        Some(&applied_tip),
    );
    let Err(_) = result else {
        return Err(TestError::UnexpectedSuccess(
            "inconsistent transaction counts were published",
        ));
    };
    assert!(!dir.path().join(CHECKPOINT_ROOT).join(CURRENT_FILE).exists());
    Ok(())
}
#[test]
fn checkpoint_writer_refuses_height_mismatch() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (tree, _, applied) = chain_with_applied_height(0, 0)?;
    let applied_tip = tip_snapshot(&tree, applied)?;
    let mut stats = CoinStats::new();
    stats.finish_block(1, 0);
    let result = super::super::write_checkpoint(
        dir.path(),
        config(),
        &RwLock::new(tree),
        &UtxoSet::new(),
        &CoinStatsListener::new(stats),
        Some(&applied_tip),
    );
    let Err(_) = result else {
        return Err(TestError::UnexpectedSuccess(
            "stale CoinStats unexpectedly published",
        ));
    };
    assert!(!dir.path().join(CHECKPOINT_ROOT).join(CURRENT_FILE).exists());
    Ok(())
}

#[test]
fn authenticated_header_semantics_require_resync() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (tree, _, applied) = chain_with_applied_height(2, 0)?;
    let applied_tip = tip_snapshot(&tree, applied)?;
    let tree = RwLock::new(tree);
    super::super::write_checkpoint(
        dir.path(),
        config(),
        &tree,
        &UtxoSet::new(),
        &CoinStatsListener::new(CoinStats::new()),
        Some(&applied_tip),
    )?;
    mutate_authenticated_artifact(dir.path(), HEADERS_FILE, |bytes| {
        bytes[headers::HEADER_PREFIX_LEN + 80 + 4] ^= 1;
    })?;

    let Err(CheckpointLoadError::Corrupt(_)) = load_checkpoint(dir.path(), config()) else {
        return Err(TestError::UnexpectedSuccess(
            "corrupt header checkpoint unexpectedly loaded",
        ));
    };
    Ok(())
}

/// The offsets below are the checkpoint envelope (16 bytes) followed by the stable
/// `CoinStats::to_bytes` layout defined in `crates/storage/src/utxo/stats/coin_stats.rs`:
/// `MuHash` numerator/denominator, then height, total amount, bogo size, transaction
/// count, and UTXO count.
///
/// The `full resync` assertion is the checkpoint recovery contract documented in
/// `docs/policies/db-migration.md` and exercised by the loader.
#[test]
fn authenticated_coinstats_semantics_require_resync() -> TestResult {
    const COINSTATS_ENVELOPE_BYTES: usize = 16;
    const MUHASH_BYTES: usize = 384 + 384;
    const HEIGHT_BYTES: usize = 4;
    const U64_BYTES: usize = 8;
    const COINSTATS_FIELD_OFFSETS: [usize; 6] = [
        COINSTATS_ENVELOPE_BYTES,
        COINSTATS_ENVELOPE_BYTES + MUHASH_BYTES,
        COINSTATS_ENVELOPE_BYTES + MUHASH_BYTES + HEIGHT_BYTES,
        COINSTATS_ENVELOPE_BYTES + MUHASH_BYTES + HEIGHT_BYTES + U64_BYTES,
        COINSTATS_ENVELOPE_BYTES + MUHASH_BYTES + HEIGHT_BYTES + 2 * U64_BYTES,
        COINSTATS_ENVELOPE_BYTES + MUHASH_BYTES + HEIGHT_BYTES + 3 * U64_BYTES,
    ];

    for offset in COINSTATS_FIELD_OFFSETS {
        let dir = tempfile::tempdir()?;
        let (tree, _, applied) = chain_with_applied_height(0, 0)?;
        let applied_tip = tip_snapshot(&tree, applied)?;
        let tree = RwLock::new(tree);
        super::super::write_checkpoint(
            dir.path(),
            config(),
            &tree,
            &UtxoSet::new(),
            &CoinStatsListener::new(CoinStats::new()),
            Some(&applied_tip),
        )?;
        mutate_authenticated_artifact(dir.path(), COINSTATS_FILE, |bytes| {
            bytes[offset] ^= 1;
        })?;

        let Err(error) = load_checkpoint(dir.path(), config()) else {
            return Err(TestError::UnexpectedSuccess(
                "corrupt CoinStats checkpoint unexpectedly loaded",
            ));
        };
        assert!(
            matches!(error, CheckpointLoadError::Corrupt(_)),
            "unexpected checkpoint load error: {error}"
        );
    }
    Ok(())
}

#[test]
fn engine_image_tamper_requires_resync() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (tree, _, applied) = chain_with_applied_height(0, 0)?;
    let applied_tip = tip_snapshot(&tree, applied)?;
    let data_dir = super::super::open_data_dir(dir.path())?;
    let store = bitcoin_rs_storage::memory_kv::MemoryKvStore::new();
    let write = super::super::write_checkpoint_with_store(
        &data_dir,
        config(),
        &RwLock::new(tree),
        &CoinStatsListener::new(CoinStats::new()),
        Some(&applied_tip),
        super::super::CheckpointStoreTarget {
            store: &store,
            host_data_dir: dir.path(),
        },
    )?;
    assert!(matches!(write, CheckpointWrite::Published { .. }));
    let root = dir.path().join(CHECKPOINT_ROOT);
    let current: CurrentV1 = sonic_rs::from_slice(&fs::read(root.join(CURRENT_FILE))?)?;
    let image = root
        .join(&current.directory)
        .join("chainstate")
        .join(bitcoin_rs_storage::memory_kv::MEMORY_KV_FILE);
    let mut image_bytes = fs::read(&image)?;
    image_bytes.pop();
    fs::write(&image, &image_bytes)?;
    let Err(CheckpointLoadError::Corrupt(_)) = load_checkpoint(dir.path(), config()) else {
        return Err(TestError::UnexpectedSuccess(
            "truncated engine image unexpectedly loaded",
        ));
    };
    Ok(())
}

#[test]
fn engine_image_value_flip_requires_resync() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (tree, _, applied) = chain_with_applied_height(0, 0)?;
    let applied_tip = tip_snapshot(&tree, applied)?;
    let data_dir = super::super::open_data_dir(dir.path())?;
    let store = bitcoin_rs_storage::memory_kv::MemoryKvStore::new();
    let record = bitcoin_rs_storage::utxo::record::UtxoRecord::from_owned_outputs(
        Hash256::from_le_bytes(&[7u8; 32]),
        &[bitcoin_rs_storage::utxo::record::OwnedUtxoOut {
            vout: 0,
            value: 50_000,
            script_pubkey: vec![0x76, 0xa9, 0x14, 0, 0, 0x88, 0xac],
            coinbase: true,
            height: 0,
        }],
    )?;
    {
        use bitcoin_rs_storage::KvStore;
        let mut batch = store.new_batch();
        batch.put(
            bitcoin_rs_storage::ColumnFamily::Coins,
            bitcoin_rs_storage::CoinKey([7u8; 32]).as_bytes(),
            record.bytes(),
        );
        store.write(batch)?;
    }
    let write = super::super::write_checkpoint_with_store(
        &data_dir,
        config(),
        &RwLock::new(tree),
        &CoinStatsListener::new(CoinStats::new()),
        Some(&applied_tip),
        super::super::CheckpointStoreTarget {
            store: &store,
            host_data_dir: dir.path(),
        },
    )?;
    assert!(matches!(write, CheckpointWrite::Published { .. }));
    let root = dir.path().join(CHECKPOINT_ROOT);
    let current: CurrentV1 = sonic_rs::from_slice(&fs::read(root.join(CURRENT_FILE))?)?;
    let image = root
        .join(&current.directory)
        .join("chainstate")
        .join(bitcoin_rs_storage::memory_kv::MEMORY_KV_FILE);
    let mut image_bytes = fs::read(&image)?;
    let needle = record.bytes().to_vec();
    let Some(offset) = image_bytes
        .windows(needle.len())
        .position(|window| window == needle.as_slice())
    else {
        return Err(TestError::UnexpectedSuccess(
            "checkpoint image lacks the minted coin record",
        ));
    };
    image_bytes[offset + needle.len() / 2] ^= 0x01;
    fs::write(&image, &image_bytes)?;
    let Err(CheckpointLoadError::Corrupt(_)) = load_checkpoint(dir.path(), config()) else {
        return Err(TestError::UnexpectedSuccess(
            "flipped engine coin value unexpectedly loaded",
        ));
    };
    Ok(())
}

#[test]
fn publish_swap_between_commit_and_open_yields_integrity() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (tree, _, applied) = chain_with_applied_height(0, 0)?;
    let applied_tip = tip_snapshot(&tree, applied)?;
    let data_dir = super::super::open_data_dir(dir.path())?;
    let store = bitcoin_rs_storage::memory_kv::MemoryKvStore::new();
    let write = super::super::write_checkpoint_with_store(
        &data_dir,
        config(),
        &RwLock::new(tree),
        &CoinStatsListener::new(CoinStats::new()),
        Some(&applied_tip),
        super::super::CheckpointStoreTarget {
            store: &store,
            host_data_dir: dir.path(),
        },
    )?;
    assert!(matches!(write, CheckpointWrite::Published { .. }));
    let root = dir.path().join(CHECKPOINT_ROOT);
    let current: CurrentV1 = sonic_rs::from_slice(&fs::read(root.join(CURRENT_FILE))?)?;
    let manifest_path = root.join(&current.directory).join(MANIFEST_FILE);
    let mut manifest_bytes = fs::read(&manifest_path)?;
    manifest_bytes.push(b'\n');
    fs::write(&manifest_path, &manifest_bytes)?;
    let Err(CheckpointLoadError::Corrupt(_)) = load_checkpoint(dir.path(), config()) else {
        return Err(TestError::UnexpectedSuccess(
            "swapped manifest unexpectedly loaded",
        ));
    };
    Ok(())
}

fn write_engine_checkpoint(data_dir: &Path) -> TestResult<std::path::PathBuf> {
    let (tree, _, applied) = chain_with_applied_height(0, 0)?;
    let applied_tip = tip_snapshot(&tree, applied)?;
    let staged = super::super::open_data_dir(data_dir)?;
    let store = bitcoin_rs_storage::memory_kv::MemoryKvStore::new();
    let write = super::super::write_checkpoint_with_store(
        &staged,
        config(),
        &RwLock::new(tree),
        &CoinStatsListener::new(CoinStats::new()),
        Some(&applied_tip),
        super::super::CheckpointStoreTarget {
            store: &store,
            host_data_dir: data_dir,
        },
    )?;
    assert!(matches!(write, CheckpointWrite::Published { .. }));
    let root = data_dir.join(CHECKPOINT_ROOT);
    let current: CurrentV1 = sonic_rs::from_slice(&fs::read(root.join(CURRENT_FILE))?)?;
    Ok(root.join(current.directory))
}

#[test]
fn engine_manifest_parent_traversal_is_refused() -> TestResult {
    let dir = tempfile::tempdir()?;
    let generation = write_engine_checkpoint(dir.path())?;
    std::fs::remove_file(
        generation
            .join("chainstate")
            .join(bitcoin_rs_storage::memory_kv::MEMORY_KV_FILE),
    )?;
    const SENTINEL: &[u8] = b"checkpoint traversal sentinel";
    let sentinel = generation.join("outside");
    std::fs::write(&sentinel, SENTINEL)?;
    let sentinel_len = u64::try_from(SENTINEL.len())?;
    let sentinel_sha = super::super::hex_encode(&sha2::Sha256::digest(SENTINEL));
    let mut rewrote_engine = false;
    mutate_authenticated_manifest(dir.path(), |manifest| {
        let Some(engine) = manifest.engine.as_mut() else {
            return;
        };
        engine.files = vec![bitcoin_rs_storage::checkpoint::EngineFileV1 {
            file: "../outside".to_owned(),
            bytes: sentinel_len,
            sha256: sentinel_sha.clone(),
        }];
        rewrote_engine = true;
    })?;
    if !rewrote_engine {
        return Err(TestError::UnexpectedSuccess(
            "checkpoint lacks an engine image",
        ));
    }
    let Err(CheckpointLoadError::Corrupt(_)) = load_checkpoint(dir.path(), config()) else {
        return Err(TestError::UnexpectedSuccess(
            "parent-traversal engine record unexpectedly loaded",
        ));
    };
    assert_eq!(std::fs::read(&sentinel)?, SENTINEL);
    Ok(())
}

#[test]
fn engine_manifest_absolute_path_is_refused() -> TestResult {
    let dir = tempfile::tempdir()?;
    let generation = write_engine_checkpoint(dir.path())?;
    std::fs::remove_file(
        generation
            .join("chainstate")
            .join(bitcoin_rs_storage::memory_kv::MEMORY_KV_FILE),
    )?;
    const SENTINEL: &[u8] = b"checkpoint traversal sentinel";
    let sentinel = dir.path().join("abs-sentinel");
    std::fs::write(&sentinel, SENTINEL)?;
    let sentinel_len = u64::try_from(SENTINEL.len())?;
    let hostile = sentinel.to_string_lossy().into_owned();
    let sentinel_sha = super::super::hex_encode(&sha2::Sha256::digest(SENTINEL));
    let mut rewrote_engine = false;
    mutate_authenticated_manifest(dir.path(), |manifest| {
        let Some(engine) = manifest.engine.as_mut() else {
            return;
        };
        engine.files = vec![bitcoin_rs_storage::checkpoint::EngineFileV1 {
            file: hostile.clone(),
            bytes: sentinel_len,
            sha256: sentinel_sha.clone(),
        }];
        rewrote_engine = true;
    })?;
    if !rewrote_engine {
        return Err(TestError::UnexpectedSuccess(
            "checkpoint lacks an engine image",
        ));
    }
    let Err(CheckpointLoadError::Corrupt(_)) = load_checkpoint(dir.path(), config()) else {
        return Err(TestError::UnexpectedSuccess(
            "absolute-path engine record unexpectedly loaded",
        ));
    };
    assert_eq!(std::fs::read(&sentinel)?, SENTINEL);
    Ok(())
}

#[test]
fn engine_manifest_paths_are_refused_at_parse() -> TestResult {
    let dir = tempfile::tempdir()?;
    let generation = write_engine_checkpoint(dir.path())?;
    let generation_dir = super::super::open_data_dir(&generation)?;
    let identity = super::super::CheckpointIdentity {
        network: config().network,
        genesis: config().genesis,
    };
    let empty_sha = super::super::hex_encode(&Sha256::digest(b""));
    for (file, accepted) in [
        ("a/b", true),
        ("a//b", false),
        ("a/", false),
        ("a/.", false),
        ("./a", false),
        ("a/../b", false),
        ("", false),
    ] {
        let mut rewrote_engine = false;
        mutate_authenticated_manifest(dir.path(), |manifest| {
            let Some(engine) = manifest.engine.as_mut() else {
                return;
            };
            engine.files = vec![bitcoin_rs_storage::checkpoint::EngineFileV1 {
                file: file.to_owned(),
                bytes: 0,
                sha256: empty_sha.clone(),
            }];
            rewrote_engine = true;
        })?;
        if !rewrote_engine {
            return Err(TestError::UnexpectedSuccess(
                "checkpoint lacks an engine image",
            ));
        }
        let current: CurrentV1 = sonic_rs::from_slice(&fs::read(
            dir.path().join(CHECKPOINT_ROOT).join(CURRENT_FILE),
        )?)?;
        let manifest_bytes = fs::read(generation.join(MANIFEST_FILE))?;
        let reference = bitcoin_rs_storage::checkpoint::CheckpointReference {
            generation: current.generation,
            manifest_sha256: Sha256::digest(&manifest_bytes).into(),
        };
        let parsed = super::super::read_manifest(&generation_dir, &reference, identity);
        assert_eq!(parsed.is_ok(), accepted, "engine record {file:?}");
    }
    Ok(())
}
