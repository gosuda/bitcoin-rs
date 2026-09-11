use super::*;

/// The checkpoint manifest's codec identifiers are on-disk values.
///
/// Pinned as literals rather than through the constants, because comparing a
/// constant to itself proves nothing: the writer and the reader use the same
/// three names, so renaming one keeps a single binary perfectly
/// self-consistent while every checkpoint already on disk stops loading and
/// requires an explicit full resync (`docs/policies/db-migration.md`). That
/// failure is invisible to a round-trip test and expensive in production.
///
/// These identifiers are the current schema's on-disk codec names. Changing
/// one requires a schema epoch bump and an explicit resync.
#[test]
fn manifest_codec_identifiers_are_current_and_frozen() {
    assert_eq!(super::super::HEADER_CODEC, "bitcoin-rs-canonical-headers");
    assert_eq!(super::super::UTXO_CODEC, "bitcoin-rs-utxo-spendable-v1");
    assert_eq!(super::super::COINSTATS_CODEC, "bitcoin-rs-coinstats-v1");
    assert_eq!(
        super::super::CURRENT_FORMAT,
        "bitcoin-rs-chainstate-current"
    );
    assert_eq!(
        super::super::MANIFEST_FORMAT,
        "bitcoin-rs-chainstate-checkpoint"
    );
}

#[test]
fn round_trip_replays_consensus_validated_active_chain() -> Result<(), Box<dyn std::error::Error>> {
    let (tree, best_tip_id, applied) = chain_with_applied_height(3, 1)?;
    let written = write_checkpoint(&tree, best_tip_id, applied)?;
    let mut reader = Cursor::new(written.0);

    let restored = headers::read_headers(&mut reader, config(), written.1.metadata)?;

    assert_eq!(restored.tree.len(), 4);
    assert_eq!(
        restored.tree.tip().map(|tip| tip.hash),
        Some(tree.node(best_tip_id)?.hash),
        "the restored best tip identifies the same chain across distinct trees"
    );
    assert_eq!(
        restored.tree.node(restored.applied_tip_id)?.hash,
        applied.hash,
        "the applied checkpoint tip is reconstructed from the accepted prefix"
    );
    Ok(())
}

#[test]
fn reader_rejects_wrong_network_and_genesis() -> Result<(), Box<dyn std::error::Error>> {
    let (tree, best_tip_id, applied) = chain_with_applied_height(1, 0)?;
    let written = write_checkpoint(&tree, best_tip_id, applied)?;

    let wrong_network = headers::HeaderCheckpointConfig {
        network: Network::Testnet3,
        genesis: Network::Testnet3.genesis_block_hash(),
    };
    assert!(
        headers::read_headers(
            &mut Cursor::new(&written.0),
            wrong_network,
            written.1.metadata
        )
        .is_err()
    );
    let configured_genesis_mismatch = headers::HeaderCheckpointConfig {
        network: NETWORK,
        genesis: Hash256::from_le_bytes(&[0x22; 32]),
    };
    assert!(matches!(
        headers::read_headers(
            &mut Cursor::new(&written.0),
            configured_genesis_mismatch,
            written.1.metadata
        ),
        Err(headers::HeaderCheckpointError::ConfiguredGenesisMismatch { .. })
    ));
    let mut wrong_genesis = written.0;
    wrong_genesis[16] ^= 1;
    assert!(
        headers::read_headers(
            &mut Cursor::new(wrong_genesis),
            config(),
            written.1.metadata
        )
        .is_err()
    );
    Ok(())
}

/// Regression coverage for the headers-v1 wire contract in
/// `crates/node/src/checkpoint/headers.rs`: `prefix`/`parse_prefix` define the
/// magic at bytes 0..8, version at 8..12, and count at 48..56; `checkpoint_size`
/// and `read_headers` require the encoded length to contain exactly the prefix
/// plus 80-byte headers. Keep these offsets tied to that authoritative codec
/// contract rather than treating them as incidental test fixture details.
#[test]
fn reader_rejects_bad_prefix_count_and_trailing_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let (tree, best_tip_id, applied) = chain_with_applied_height(1, 0)?;
    let (bytes, written) = write_checkpoint(&tree, best_tip_id, applied)?;

    let mut bad_magic = bytes.clone();
    bad_magic[0] ^= 1;
    assert!(
        headers::read_headers(&mut Cursor::new(bad_magic), config(), written.metadata).is_err()
    );
    let mut bad_version = bytes.clone();
    bad_version[8] ^= 1;
    assert!(
        headers::read_headers(&mut Cursor::new(bad_version), config(), written.metadata).is_err()
    );
    let mut bad_count = bytes.clone();
    bad_count[48] ^= 1;
    assert!(
        headers::read_headers(&mut Cursor::new(bad_count), config(), written.metadata).is_err()
    );
    let mut trailing = bytes;
    trailing.push(0);
    assert!(headers::read_headers(&mut Cursor::new(trailing), config(), written.metadata).is_err());
    Ok(())
}

#[test]
fn reader_rejects_metadata_and_commitment_mutations() -> Result<(), Box<dyn std::error::Error>> {
    let (tree, best_tip_id, applied) = chain_with_applied_height(2, 1)?;
    let (bytes, written) = write_checkpoint(&tree, best_tip_id, applied)?;

    let mut wrong_best = written.metadata;
    wrong_best.best.hash = Hash256::from_le_bytes(&[0x11; 32]);
    assert!(headers::read_headers(&mut Cursor::new(&bytes), config(), wrong_best).is_err());

    let mut wrong_applied = written.metadata;
    wrong_applied.applied = headers::HeaderCheckpointTip {
        hash: written.metadata.best.hash,
        ..written.metadata.applied
    };
    assert!(headers::read_headers(&mut Cursor::new(&bytes), config(), wrong_applied).is_err());

    let mut wrong_applied_prefix_commitment = written.metadata;
    wrong_applied_prefix_commitment.applied_prefix_commitment[0] ^= 1;
    assert!(
        headers::read_headers(
            &mut Cursor::new(bytes.clone()),
            config(),
            wrong_applied_prefix_commitment
        )
        .is_err()
    );

    let mut wrong_commitment = written.metadata;
    wrong_commitment.best_chain_commitment[0] ^= 1;
    assert!(headers::read_headers(&mut Cursor::new(bytes), config(), wrong_commitment).is_err());
    Ok(())
}

#[test]
fn publication_selects_applied_ancestry_and_forgets_competing_fork()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let (mut tree, main_best_id, applied_point) = chain_with_applied_height(3, 1)?;
    let main_best_hash = tree.node(main_best_id)?.hash;

    let genesis_hash = tree.node(NodeId::new(0))?.hash;
    let mut prev = BlockHash(genesis_hash);
    let mut fork_best_id = NodeId::new(0);
    for height in 1..=4 {
        let mut header = next_header(prev, height);
        header.time = header.time.saturating_add(100);
        mine_header_to_declared_target(&mut header)?;
        fork_best_id = accept_headers(
            &mut tree,
            core::slice::from_ref(&header),
            NETWORK,
            bitcoin_rs_chain::current_unix_seconds(),
        )?[0];
        prev = BlockHash(tree.node(fork_best_id)?.hash);
    }
    let fork_best_hash = tree.node(fork_best_id)?.hash;
    assert_eq!(tree.tip().map(|tip| tip.tip_id), Some(fork_best_id));
    assert_ne!(
        tree.node_at_height_from(fork_best_id, applied_point.height),
        tree.lookup(applied_point.hash),
        "fixture must place the applied tip outside the live best ancestry"
    );

    let applied_tip = tip_snapshot(&tree, applied_point)?;
    let tree = RwLock::new(tree);
    let utxo = UtxoSet::new();
    let mut stats = CoinStats::new();
    stats.height = applied_point.height;
    let listener = CoinStatsListener::new(stats);

    assert!(matches!(
        super::super::write_checkpoint(
            dir.path(),
            config(),
            &tree,
            &utxo,
            &listener,
            Some(&applied_tip),
        )?,
        CheckpointWrite::Published { .. }
    ));

    let loaded = load_checkpoint(dir.path(), config())?;
    let CheckpointLoad::Complete(restored) = loaded else {
        return Err("checkpoint did not restore complete chainstate".into());
    };

    assert_eq!(
        restored.tree.tip().map(|tip| (tip.height, tip.hash)),
        Some((applied_point.height, applied_point.hash)),
        "checkpoint must publish the coherent applied ancestry"
    );
    assert!(
        restored.tree.lookup(fork_best_hash).is_none(),
        "the competing best-work fork must be rediscovered after restart"
    );
    assert!(
        restored.tree.lookup(main_best_hash).is_none(),
        "headers above the applied tip must be rediscovered after restart"
    );
    assert_eq!(restored.applied_tip.height, applied_point.height);
    assert_eq!(restored.applied_tip.hash, applied_point.hash);
    Ok(())
}

#[test]
fn every_publication_failpoint_leaves_old_or_fully_valid_current()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let (tree, _, applied) = chain_with_applied_height(0, 0)?;
    let applied_tip = tip_snapshot(&tree, applied)?;
    let tree = RwLock::new(tree);
    let utxo = UtxoSet::new();
    let listener = CoinStatsListener::new(CoinStats::new());
    super::super::write_checkpoint(
        dir.path(),
        config(),
        &tree,
        &utxo,
        &listener,
        Some(&applied_tip),
    )?;

    for failpoint in [
        CheckpointFailpoint::HeadersWrite,
        CheckpointFailpoint::HeadersSync,
        CheckpointFailpoint::UtxoWrite,
        CheckpointFailpoint::UtxoSync,
        CheckpointFailpoint::CoinStatsWrite,
        CheckpointFailpoint::CoinStatsSync,
        CheckpointFailpoint::ManifestWrite,
        CheckpointFailpoint::ManifestSync,
        CheckpointFailpoint::StageSync,
        CheckpointFailpoint::GenerationRename,
        CheckpointFailpoint::GenerationRootSync,
        CheckpointFailpoint::CurrentTempWrite,
        CheckpointFailpoint::CurrentTempSync,
        CheckpointFailpoint::CurrentRename,
    ] {
        let current_path = dir.path().join(CHECKPOINT_ROOT).join(CURRENT_FILE);
        let previous_current = fs::read(&current_path)?;
        assert!(
            write_checkpoint_with_failpoint(
                dir.path(),
                config(),
                &tree,
                &utxo,
                &listener,
                Some(&applied_tip),
                failpoint,
            )
            .is_err(),
            "{failpoint:?}"
        );
        assert_eq!(
            fs::read(&current_path)?,
            previous_current,
            "pre-CURRENT failure changed the authoritative pointer at {failpoint:?}"
        );
        assert!(matches!(
            load_checkpoint(dir.path(), config())?,
            CheckpointLoad::Complete(_)
        ));
    }
    assert!(
        write_checkpoint_with_failpoint(
            dir.path(),
            config(),
            &tree,
            &utxo,
            &listener,
            Some(&applied_tip),
            CheckpointFailpoint::CurrentRootSync,
        )
        .is_err()
    );
    assert!(matches!(
        load_checkpoint(dir.path(), config())?,
        CheckpointLoad::Complete(_)
    ));
    Ok(())
}

#[test]
fn unsupported_utxo_codec_requires_explicit_resync() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let (tree, _, applied) = chain_with_applied_height(0, 0)?;
    let applied_tip = tip_snapshot(&tree, applied)?;
    super::super::write_checkpoint(
        dir.path(),
        config(),
        &RwLock::new(tree),
        &UtxoSet::new(),
        &CoinStatsListener::new(CoinStats::new()),
        Some(&applied_tip),
    )?;
    mutate_authenticated_manifest(dir.path(), |manifest| {
        manifest.utxo.codec = "bitcoin-rs-utxo".to_owned();
    })?;

    let Err(error) = load_checkpoint(dir.path(), config()) else {
        return Err("unsupported UTXO codec unexpectedly loaded".into());
    };
    let message = error.to_string();
    assert!(message.contains("unexpected payload codecs"));
    assert!(message.contains("full resync"));
    Ok(())
}

#[test]
fn unsupported_utxo_snapshot_version_requires_explicit_resync()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let (tree, _, applied) = chain_with_applied_height(1, 0)?;
    let applied_tip = tip_snapshot(&tree, applied)?;
    super::super::write_checkpoint(
        dir.path(),
        config(),
        &RwLock::new(tree),
        &UtxoSet::new(),
        &CoinStatsListener::new(CoinStats::new()),
        Some(&applied_tip),
    )?;
    mutate_authenticated_manifest(dir.path(), |manifest| {
        manifest.utxo.version = 3;
    })?;

    let Err(CheckpointLoadError::Corrupt(CheckpointCorruption::Invalid { reason })) =
        load_checkpoint(dir.path(), config())
    else {
        return Err("unsupported UTXO snapshot unexpectedly loaded".into());
    };
    assert!(reason.contains("UTXO checkpoint version 3 is not current"));
    Ok(())
}

#[test]
fn semantic_utxo_trailing_byte_with_rebound_hashes_requires_resync()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let (tree, _, applied) = chain_with_applied_height(1, 0)?;
    let applied_tip = tip_snapshot(&tree, applied)?;
    let tree = RwLock::new(tree);
    let utxo = UtxoSet::new();
    let listener = CoinStatsListener::new(CoinStats::new());
    super::super::write_checkpoint(
        dir.path(),
        config(),
        &tree,
        &utxo,
        &listener,
        Some(&applied_tip),
    )?;

    let root = dir.path().join(CHECKPOINT_ROOT);
    let current_path = root.join(CURRENT_FILE);
    let mut current: CurrentV1 = serde_json::from_slice(&fs::read(&current_path)?)?;
    let generation = root.join(&current.directory);
    let manifest_path = generation.join(MANIFEST_FILE);
    let mut manifest: CheckpointManifestV1 = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    let utxo_path = generation.join(UTXO_FILE);
    let mut utxo_bytes = fs::read(&utxo_path)?;
    utxo_bytes.push(0x5a);
    fs::write(&utxo_path, &utxo_bytes)?;
    manifest.utxo.bytes = u64::try_from(utxo_bytes.len())?;
    manifest.utxo.sha256 = super::super::hex_encode(&Sha256::digest(&utxo_bytes));
    let manifest_bytes = serde_json::to_vec(&manifest)?;
    fs::write(&manifest_path, &manifest_bytes)?;
    current.manifest_sha256 = super::super::hex_encode(&Sha256::digest(&manifest_bytes));
    fs::write(&current_path, serde_json::to_vec(&current)?)?;

    let Err(error) = load_checkpoint(dir.path(), config()) else {
        return Err("semantic UTXO corruption unexpectedly loaded".into());
    };
    assert!(error.to_string().contains("full resync"));
    Ok(())
}

#[test]
fn configured_network_mismatch_is_fatal() -> Result<(), Box<dyn std::error::Error>> {
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
    let wrong = headers::HeaderCheckpointConfig {
        network: Network::Testnet3,
        genesis: Network::Testnet3.genesis_block_hash(),
    };
    assert!(load_checkpoint(dir.path(), wrong).is_err());
    Ok(())
}

#[test]
fn authenticated_inner_header_version_is_fatal() -> Result<(), Box<dyn std::error::Error>> {
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
    mutate_authenticated_artifact(dir.path(), HEADERS_FILE, |bytes| {
        bytes[8..12].copy_from_slice(&2_u32.to_le_bytes());
    })?;

    assert!(matches!(
        load_checkpoint(dir.path(), config()),
        Err(super::super::CheckpointLoadError::Corrupt(
            super::super::CheckpointCorruption::Invalid { .. }
        ))
    ));
    Ok(())
}
