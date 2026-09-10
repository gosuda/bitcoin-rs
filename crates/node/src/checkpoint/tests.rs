//! Checkpoint codec and immutable-publication regressions.

use super::headers;

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
    assert_eq!(super::HEADER_CODEC, "bitcoin-rs-canonical-headers");
    assert_eq!(super::UTXO_CODEC, "bitcoin-rs-utxo-spendable-v1");
    assert_eq!(super::COINSTATS_CODEC, "bitcoin-rs-coinstats-v1");
    assert_eq!(super::CURRENT_FORMAT, "bitcoin-rs-chainstate-current");
    assert_eq!(super::MANIFEST_FORMAT, "bitcoin-rs-chainstate-checkpoint");
}

use std::fs;
use std::io::Cursor;
use std::path::Path;

use bitcoin_rs_chain::{BlockTree, ChainWork, NodeId, TipSnapshot, accept_headers};
use bitcoin_rs_primitives::{
    BlockHash, Hash256, Header, Network, OutPoint, TxOut, Txid, deserialize,
};
use bitcoin_rs_utxo::stats::{CoinStats, CoinStatsListener, scan_coin_stats};
use bitcoin_rs_utxo::{BlockChanges, UtxoAdd, UtxoSet};
use parking_lot::RwLock;
use sha2::{Digest, Sha256};

use super::{
    CHECKPOINT_ROOT, COINSTATS_FILE, CURRENT_FILE, CheckpointCorruption, CheckpointFailpoint,
    CheckpointLoad, CheckpointLoadError, CheckpointManifestV1, CheckpointWrite, CurrentV1,
    HEADERS_FILE, MANIFEST_FILE, UTXO_FILE, load_checkpoint, write_checkpoint_with_failpoint,
};

const NETWORK: Network = Network::Regtest;

#[test]
fn transient_checkpoint_io_is_not_classified_as_incompatible() {
    let error = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "checkpoint locked");
    let classified = super::classify_checkpoint_error(super::CheckpointError::Io(error));
    let CheckpointLoadError::Io(error) = classified else {
        panic!("transient checkpoint I/O was classified as datadir incompatibility");
    };
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(error.to_string(), "checkpoint locked");

    let error = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "root locked");
    let classified = super::classify_open_error("open checkpoint root", error);
    let CheckpointLoadError::Io(error) = classified else {
        panic!("transient checkpoint-open I/O was classified as datadir incompatibility");
    };
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(error.to_string(), "root locked");
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
fn reader_rejects_mutated_linkage_and_invalid_pow_or_nbits()
-> Result<(), Box<dyn std::error::Error>> {
    let (tree, best_tip_id, applied) = chain_with_applied_height(2, 1)?;
    let (bytes, written) = write_checkpoint(&tree, best_tip_id, applied)?;

    let mut bad_prev = bytes.clone();
    bad_prev[headers::HEADER_PREFIX_LEN + 80 + 4] ^= 1;
    assert!(headers::read_headers(&mut Cursor::new(bad_prev), config(), written.metadata).is_err());

    let mut bad_pow = bytes.clone();
    let header_offset = headers::HEADER_PREFIX_LEN + 80;
    let mut invalid = header_from_row(&bad_pow[header_offset..header_offset + 80])?;
    while pow_meets_target(invalid.bits, invalid.compute_hash().0) {
        invalid.nonce = invalid.nonce.checked_add(1).ok_or("nonce exhausted")?;
    }
    bad_pow[header_offset..header_offset + 80].copy_from_slice(&headers::encode_header(&invalid)?);
    assert!(headers::read_headers(&mut Cursor::new(bad_pow), config(), written.metadata).is_err());

    let mut bad_nbits = bytes;
    let previous = header_from_row(&bad_nbits[header_offset..header_offset + 80])?;
    let mut nbits_mismatch = Header {
        bits: 0x207f_fffe,
        ..previous
    };
    mine_header_to_declared_target(&mut nbits_mismatch)?;
    bad_nbits[header_offset..header_offset + 80]
        .copy_from_slice(&headers::encode_header(&nbits_mismatch)?);
    assert!(
        headers::read_headers(&mut Cursor::new(bad_nbits), config(), written.metadata).is_err()
    );
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
fn writer_refuses_a_best_tip_that_is_not_active() -> Result<(), Box<dyn std::error::Error>> {
    let (tree, _, applied) = chain_with_applied_height(3, 1)?;

    assert!(matches!(
        headers::write_headers(&mut Vec::new(), &tree, config(), NodeId::new(0), applied),
        Err(headers::HeaderCheckpointError::BestTipNotActive)
    ));
    Ok(())
}

#[test]
fn writer_refuses_an_applied_tip_off_the_active_best_ancestry()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut tree, best_tip_id, _) = chain_with_applied_height(3, 1)?;
    let genesis_hash = tree.node(NodeId::new(0))?.hash;
    let mut fork = next_header(
        BlockHash(genesis_hash),
        u32::from(NETWORK.genesis_block_hash().to_le_bytes()[0]) + 1,
    );
    mine_header_to_declared_target(&mut fork)?;
    let fork_id = accept_headers(
        &mut tree,
        core::slice::from_ref(&fork),
        NETWORK,
        bitcoin_rs_chain::current_unix_seconds(),
    )?[0];
    let fork = tree.node(fork_id)?;
    let applied = headers::HeaderCheckpointPoint {
        height: fork.height,
        hash: fork.hash,
    };

    assert!(matches!(
        headers::write_headers(&mut Vec::new(), &tree, config(), best_tip_id, applied),
        Err(headers::HeaderCheckpointError::AppliedTipNotBestPrefix)
    ));
    Ok(())
}

#[test]
fn immutable_generation_resumes_best_ahead_of_applied() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let (tree, _, applied) = chain_with_applied_height(3, 1)?;
    let applied_tip = tip_snapshot(&tree, applied)?;
    let tree = RwLock::new(tree);
    let utxo = UtxoSet::new();
    let mut stats = CoinStats::new();
    stats.height = applied.height;
    let listener = CoinStatsListener::new(stats);

    assert!(matches!(
        super::write_checkpoint(
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
    assert_eq!(restored.tree.tip().map(|tip| tip.height), Some(3));
    assert_eq!(restored.applied_tip.height, 1);
    assert_eq!(restored.applied_tip.hash, applied.hash);
    assert_eq!(restored.utxo.record_count(), 0);
    assert_eq!(restored.coin_stats.height, 1);
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
        super::write_checkpoint(
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
    super::write_checkpoint(
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
fn first_publication_failures_leave_no_committed_checkpoint()
-> Result<(), Box<dyn std::error::Error>> {
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
        let dir = tempfile::tempdir()?;
        let (tree, _, applied) = chain_with_applied_height(0, 0)?;
        let applied_tip = tip_snapshot(&tree, applied)?;
        let tree = RwLock::new(tree);
        let utxo = UtxoSet::new();
        let listener = CoinStatsListener::new(CoinStats::new());

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
        assert!(
            !dir.path().join(CHECKPOINT_ROOT).join(CURRENT_FILE).exists(),
            "pre-publication failure exposed CURRENT at {failpoint:?}"
        );
        assert!(matches!(
            load_checkpoint(dir.path(), config()),
            Ok(CheckpointLoad::Cold)
        ));
    }
    Ok(())
}

#[test]
fn no_applied_tip_skips_without_changing_current() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let (tree, _, applied) = chain_with_applied_height(0, 0)?;
    let applied_tip = tip_snapshot(&tree, applied)?;
    let tree = RwLock::new(tree);
    let utxo = UtxoSet::new();
    let listener = CoinStatsListener::new(CoinStats::new());
    super::write_checkpoint(
        dir.path(),
        config(),
        &tree,
        &utxo,
        &listener,
        Some(&applied_tip),
    )?;
    let current_path = dir.path().join(CHECKPOINT_ROOT).join(CURRENT_FILE);
    let before = fs::read(&current_path)?;
    assert_eq!(
        super::write_checkpoint(dir.path(), config(), &tree, &utxo, &listener, None)?,
        CheckpointWrite::SkippedNoAppliedTip
    );
    assert_eq!(fs::read(current_path)?, before);
    Ok(())
}

#[test]
fn checkpoint_without_current_is_cold() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let (tree, _, applied) = chain_with_applied_height(0, 0)?;
    let applied_tip = tip_snapshot(&tree, applied)?;
    super::write_checkpoint(
        dir.path(),
        config(),
        &RwLock::new(tree),
        &UtxoSet::new(),
        &CoinStatsListener::new(CoinStats::new()),
        Some(&applied_tip),
    )?;
    fs::remove_file(dir.path().join(CHECKPOINT_ROOT).join(CURRENT_FILE))?;

    assert!(matches!(
        load_checkpoint(dir.path(), config()),
        Ok(CheckpointLoad::Cold)
    ));
    Ok(())
}

#[test]
fn unsupported_utxo_codec_requires_explicit_resync() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let (tree, _, applied) = chain_with_applied_height(0, 0)?;
    let applied_tip = tip_snapshot(&tree, applied)?;
    super::write_checkpoint(
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
    super::write_checkpoint(
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
fn unsupported_current_version_is_current_checkpoint_corruption()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let (tree, _, applied) = chain_with_applied_height(0, 0)?;
    let applied_tip = tip_snapshot(&tree, applied)?;
    let tree = RwLock::new(tree);
    super::write_checkpoint(
        dir.path(),
        config(),
        &tree,
        &UtxoSet::new(),
        &CoinStatsListener::new(CoinStats::new()),
        Some(&applied_tip),
    )?;
    let current_path = dir.path().join(CHECKPOINT_ROOT).join(CURRENT_FILE);
    let mut current: CurrentV1 = serde_json::from_slice(&fs::read(&current_path)?)?;
    current.version = current.version.saturating_add(1);
    fs::write(current_path, serde_json::to_vec(&current)?)?;
    let Err(CheckpointLoadError::Corrupt(CheckpointCorruption::Invalid { reason })) =
        load_checkpoint(dir.path(), config())
    else {
        return Err("unsupported CURRENT version was not reported as corruption".into());
    };
    assert!(reason.contains("CURRENT checkpoint version"));
    assert!(!reason.contains("incompatible bitcoin-rs datadir"));
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
    super::write_checkpoint(
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
    manifest.utxo.sha256 = super::hex_encode(&Sha256::digest(&utxo_bytes));
    let manifest_bytes = serde_json::to_vec(&manifest)?;
    fs::write(&manifest_path, &manifest_bytes)?;
    current.manifest_sha256 = super::hex_encode(&Sha256::digest(&manifest_bytes));
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
    super::write_checkpoint(
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
    super::write_checkpoint(
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
        Err(super::CheckpointLoadError::Corrupt(
            super::CheckpointCorruption::Invalid { .. }
        ))
    ));
    Ok(())
}

#[test]
fn authenticated_header_semantics_require_resync() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let (tree, _, applied) = chain_with_applied_height(2, 0)?;
    let applied_tip = tip_snapshot(&tree, applied)?;
    let tree = RwLock::new(tree);
    super::write_checkpoint(
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

    let Err(error) = load_checkpoint(dir.path(), config()) else {
        return Err("corrupt header checkpoint unexpectedly loaded".into());
    };
    assert!(error.to_string().contains("full resync"));
    Ok(())
}
#[test]
fn authenticated_header_tip_and_commitment_mutations_require_resync()
-> Result<(), Box<dyn std::error::Error>> {
    for case in 0..4 {
        let dir = tempfile::tempdir()?;
        let (tree, _, applied) = chain_with_applied_height(2, 0)?;
        let applied_tip = tip_snapshot(&tree, applied)?;
        let tree = RwLock::new(tree);
        super::write_checkpoint(
            dir.path(),
            config(),
            &tree,
            &UtxoSet::new(),
            &CoinStatsListener::new(CoinStats::new()),
            Some(&applied_tip),
        )?;
        mutate_authenticated_manifest(dir.path(), |manifest| match case {
            0 => manifest.best_header_tip.hash = "00".repeat(32),
            1 => manifest.applied_tip.hash = "00".repeat(32),
            2 => manifest.headers.best_chain_sha256 = "00".repeat(32),
            _ => manifest.headers.applied_chain_sha256 = "00".repeat(32),
        })?;
        let Err(error) = load_checkpoint(dir.path(), config()) else {
            return Err("corrupt checkpoint unexpectedly loaded".into());
        };
        assert!(error.to_string().contains("full resync"));
    }
    Ok(())
}

#[test]
fn authenticated_coinstats_semantics_require_resync() -> Result<(), Box<dyn std::error::Error>> {
    for offset in [16, 16 + 768, 16 + 772, 16 + 780, 16 + 788, 16 + 796] {
        let dir = tempfile::tempdir()?;
        let (tree, _, applied) = chain_with_applied_height(0, 0)?;
        let applied_tip = tip_snapshot(&tree, applied)?;
        let tree = RwLock::new(tree);
        super::write_checkpoint(
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
            return Err("corrupt CoinStats checkpoint unexpectedly loaded".into());
        };
        assert!(error.to_string().contains("full resync"));
    }
    Ok(())
}

#[test]
fn checkpoint_roundtrip_preserves_record_with_440_outputs() -> Result<(), Box<dyn std::error::Error>>
{
    const OUTPUT_COUNT: u32 = 440;
    let dir = tempfile::tempdir()?;
    let (tree, _, applied) = chain_with_applied_height(0, 0)?;
    let applied_tip = tip_snapshot(&tree, applied)?;
    let record_txid = Txid(Hash256::from_le_bytes(&[0x44; 32]));
    let mut changes = BlockChanges::default();
    for vout in 0..OUTPUT_COUNT {
        changes.add(UtxoAdd::new(
            OutPoint::new(record_txid, vout),
            TxOut {
                value: u64::from(vout) + 1,
                script_pubkey: vec![0x51],
            },
            false,
            0,
        ));
    }
    let utxo = UtxoSet::new();
    utxo.commit_block(&changes, &Hash256::default())?;

    super::write_checkpoint(
        dir.path(),
        config(),
        &RwLock::new(tree),
        &utxo,
        &CoinStatsListener::new(CoinStats::new()),
        Some(&applied_tip),
    )?;
    let CheckpointLoad::Complete(restored) = load_checkpoint(dir.path(), config())? else {
        return Err("multi-output checkpoint did not restore".into());
    };

    assert_eq!(restored.utxo.len(), usize::try_from(OUTPUT_COUNT)?);
    assert!(
        restored
            .utxo
            .get(&OutPoint::new(record_txid, OUTPUT_COUNT - 1))
            .is_some()
    );
    Ok(())
}

#[test]
fn scanned_trailer_restores_independently_scanned_stats() -> Result<(), Box<dyn std::error::Error>>
{
    let dir = tempfile::tempdir()?;
    let (tree, _, applied) = chain_with_applied_height(0, 0)?;
    let applied_tip = tip_snapshot(&tree, applied)?;
    let tree = RwLock::new(tree);
    let utxo = populated_utxo()?;
    let expected = utxo.with_stable_view(|view| scan_coin_stats(view, 0, true))?;
    super::write_checkpoint(
        dir.path(),
        config(),
        &tree,
        &utxo,
        &CoinStatsListener::new(CoinStats::new()),
        Some(&applied_tip),
    )?;

    let root = dir.path().join(CHECKPOINT_ROOT);
    let current: CurrentV1 = serde_json::from_slice(&fs::read(root.join(CURRENT_FILE))?)?;
    let generation = root.join(current.directory);
    let mut reader = std::io::BufReader::new(std::fs::File::open(generation.join(UTXO_FILE))?);
    let snapshot = bitcoin_rs_utxo::snapshot::read_snapshot_strict_v4(&mut reader)?;
    assert_ne!(snapshot.muhash_trailer, [0_u8; 384]);
    assert_eq!(snapshot.muhash_trailer, expected.muhash.finalize());

    let CheckpointLoad::Complete(mut restored) = load_checkpoint(dir.path(), config())? else {
        return Err(std::io::Error::other("scanned generation did not restore").into());
    };
    assert_eq!(restored.coin_stats, expected);

    let listener = CoinStatsListener::new(restored.coin_stats.clone());
    restored.utxo.set_listener(Box::new(listener.clone()));
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(
        OutPoint::new(Txid(Hash256::from_le_bytes(&[0x5a; 32])), 42),
        TxOut {
            value: 123_456,
            script_pubkey: vec![0x51, 0xac],
        },
        false,
        restored.applied_tip.height,
    ));
    restored
        .utxo
        .commit_block(&changes, &Hash256::from_le_bytes(&[0xa5; 32]))?;
    let continued = restored
        .utxo
        .with_stable_view(|view| scan_coin_stats(view, restored.applied_tip.height, true))?;
    assert_eq!(listener.snapshot().to_bytes(), continued.to_bytes());
    Ok(())
}

#[test]
fn authenticated_utxo_value_mutation_requires_resync() -> Result<(), Box<dyn std::error::Error>> {
    const FIRST_VALUE_OFFSET: usize = 52 + 45 + 4;

    let dir = tempfile::tempdir()?;
    let (tree, _, applied) = chain_with_applied_height(0, 0)?;
    let applied_tip = tip_snapshot(&tree, applied)?;
    super::write_checkpoint(
        dir.path(),
        config(),
        &RwLock::new(tree),
        &populated_utxo()?,
        &CoinStatsListener::new(CoinStats::new()),
        Some(&applied_tip),
    )?;

    mutate_authenticated_artifact(dir.path(), UTXO_FILE, |bytes| {
        bytes[FIRST_VALUE_OFFSET] ^= 1;
    })?;
    let Err(error) = load_checkpoint(dir.path(), config()) else {
        return Err("corrupt UTXO checkpoint unexpectedly loaded".into());
    };
    assert!(error.to_string().contains("full resync"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn unknown_entries_and_symlinks_are_never_deleted() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir()?;
    let (tree, _, applied) = chain_with_applied_height(0, 0)?;
    let applied_tip = tip_snapshot(&tree, applied)?;
    let tree = RwLock::new(tree);
    let utxo = UtxoSet::new();
    let listener = CoinStatsListener::new(CoinStats::new());
    super::write_checkpoint(
        dir.path(),
        config(),
        &tree,
        &utxo,
        &listener,
        Some(&applied_tip),
    )?;
    let root = dir.path().join(CHECKPOINT_ROOT);
    let unknown = root.join("operator-note");
    fs::write(&unknown, b"keep")?;
    let linked = root.join("gen-18446744073709551615");
    symlink(dir.path().join("outside"), &linked)?;
    let stale_generation = root.join("gen-00000000000000000088");
    let stale_staging = root.join(".gen-18446744073709551615.tmp");
    let stale_current = root.join(".CURRENT-00000000000000000066.tmp");
    fs::create_dir(&stale_generation)?;
    fs::create_dir(&stale_staging)?;
    fs::write(&stale_current, b"stale")?;

    assert_eq!(
        super::write_checkpoint(
            dir.path(),
            config(),
            &tree,
            &utxo,
            &listener,
            Some(&applied_tip),
        )?,
        CheckpointWrite::Published { generation: 2 }
    );
    assert!(unknown.exists());
    assert!(fs::symlink_metadata(linked)?.file_type().is_symlink());
    assert!(!stale_generation.exists());
    assert!(!stale_staging.exists());
    assert!(!stale_current.exists());
    let current: CurrentV1 = serde_json::from_slice(&fs::read(root.join(CURRENT_FILE))?)?;
    assert!(root.join(&current.directory).is_dir());
    Ok(())
}

fn mutate_authenticated_artifact(
    data_dir: &Path,
    artifact: &str,
    mutate: impl FnOnce(&mut Vec<u8>),
) -> Result<(), Box<dyn std::error::Error>> {
    let root = data_dir.join(CHECKPOINT_ROOT);
    let current_path = root.join(CURRENT_FILE);
    let mut current: CurrentV1 = serde_json::from_slice(&fs::read(&current_path)?)?;

    let generation = root.join(&current.directory);
    let manifest_path = generation.join(MANIFEST_FILE);
    let mut manifest: CheckpointManifestV1 = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    let artifact_path = generation.join(artifact);
    let mut bytes = fs::read(&artifact_path)?;
    mutate(&mut bytes);
    fs::write(&artifact_path, &bytes)?;
    let digest = super::hex_encode(&Sha256::digest(&bytes));
    let length = u64::try_from(bytes.len())?;
    match artifact {
        HEADERS_FILE => {
            manifest.headers.bytes = length;
            manifest.headers.sha256 = digest;
        }
        UTXO_FILE => {
            manifest.utxo.bytes = length;
            manifest.utxo.sha256 = digest;
        }
        COINSTATS_FILE => {
            manifest.coinstats.bytes = length;
            manifest.coinstats.sha256 = digest;
        }
        _ => return Err("unknown checkpoint artifact".into()),
    }
    let manifest_bytes = serde_json::to_vec(&manifest)?;
    fs::write(&manifest_path, &manifest_bytes)?;
    current.manifest_sha256 = super::hex_encode(&Sha256::digest(&manifest_bytes));
    fs::write(current_path, serde_json::to_vec(&current)?)?;
    Ok(())
}
fn mutate_authenticated_manifest(
    data_dir: &Path,
    mutate: impl FnOnce(&mut CheckpointManifestV1),
) -> Result<(), Box<dyn std::error::Error>> {
    let root = data_dir.join(CHECKPOINT_ROOT);
    let current_path = root.join(CURRENT_FILE);
    let mut current: CurrentV1 = serde_json::from_slice(&fs::read(&current_path)?)?;
    let manifest_path = root.join(&current.directory).join(MANIFEST_FILE);
    let mut manifest: CheckpointManifestV1 = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    mutate(&mut manifest);
    let manifest_bytes = serde_json::to_vec(&manifest)?;
    fs::write(&manifest_path, &manifest_bytes)?;
    current.manifest_sha256 = super::hex_encode(&Sha256::digest(&manifest_bytes));
    fs::write(current_path, serde_json::to_vec(&current)?)?;
    Ok(())
}

fn tip_snapshot(
    tree: &BlockTree,
    point: headers::HeaderCheckpointPoint,
) -> Result<TipSnapshot, headers::HeaderCheckpointError> {
    let id = tree
        .lookup(point.hash)
        .ok_or(headers::HeaderCheckpointError::AppliedTipNotBestPrefix)?;
    let node = tree.node(id)?;
    Ok(TipSnapshot {
        tip_id: id,
        height: node.height,
        chainwork: node.chainwork,
        hash: node.hash,
    })
}

fn config() -> headers::HeaderCheckpointConfig {
    headers::HeaderCheckpointConfig {
        network: NETWORK,
        genesis: NETWORK.genesis_block_hash(),
    }
}

fn write_checkpoint(
    tree: &BlockTree,
    best_tip_id: NodeId,
    applied: headers::HeaderCheckpointPoint,
) -> Result<(Vec<u8>, headers::HeaderCheckpointWrite), headers::HeaderCheckpointError> {
    let mut bytes = Vec::new();
    let written = headers::write_headers(&mut bytes, tree, config(), best_tip_id, applied)?;
    assert_eq!(u64::try_from(bytes.len()).ok(), Some(written.bytes_written));
    Ok((bytes, written))
}

fn chain_with_applied_height(
    best_height: u32,
    applied_height: u32,
) -> Result<(BlockTree, NodeId, headers::HeaderCheckpointPoint), headers::HeaderCheckpointError> {
    let genesis = NETWORK.genesis_block().header;
    let mut tree = BlockTree::new();
    let mut current = accept_headers(
        &mut tree,
        core::slice::from_ref(&genesis),
        NETWORK,
        bitcoin_rs_chain::current_unix_seconds(),
    )?[0];
    for height in 1..=best_height {
        let prev = BlockHash(tree.node(current)?.hash);
        let mut header = next_header(prev, height);
        mine_header_to_declared_target(&mut header)?;
        current = accept_headers(
            &mut tree,
            core::slice::from_ref(&header),
            NETWORK,
            bitcoin_rs_chain::current_unix_seconds(),
        )?[0];
    }
    let applied_id = tree
        .node_at_height_from(current, applied_height)
        .ok_or(headers::HeaderCheckpointError::AppliedTipNotBestPrefix)?;
    let applied = tree.node(applied_id)?;
    let height = applied.height;
    let hash = applied.hash;
    Ok((
        tree,
        current,
        headers::HeaderCheckpointPoint { height, hash },
    ))
}

fn next_header(prev_blockhash: BlockHash, height: u32) -> Header {
    Header {
        version: 1,
        prev_blockhash,
        merkle_root: Hash256::default(),
        time: 1_296_688_602_u32.saturating_add(height),
        bits: 0x207f_ffff,
        nonce: 0,
    }
}

fn mine_header_to_declared_target(
    header: &mut Header,
) -> Result<(), headers::HeaderCheckpointError> {
    while !pow_meets_target(header.bits, header.compute_hash().0) {
        header.nonce = header.nonce.checked_add(1).ok_or_else(|| {
            headers::HeaderCheckpointError::Codec("exhausted test nonce".to_owned())
        })?;
    }
    Ok(())
}

/// Decodes a compact target and checks whether `hash` meets it, mirroring
/// the chain crate's private `compact_is_met_by`.
fn pow_meets_target(bits: u32, hash: Hash256) -> bool {
    let exponent = usize::from(u8::try_from(bits >> 24).unwrap_or(0));
    let mantissa = u64::from(bits & 0x007f_ffff);
    let negative = mantissa != 0 && bits & 0x0080_0000 != 0;
    let overflow = mantissa != 0
        && (exponent > 34
            || (mantissa > 0xff && exponent > 33)
            || (mantissa > 0xffff && exponent > 32));
    if negative || overflow {
        return false;
    }
    let target = if exponent <= 3 {
        ChainWork::from(mantissa >> (8 * (3 - exponent)))
    } else {
        let shift = 8 * (exponent - 3);
        if shift < 256 {
            ChainWork::from(mantissa) << shift
        } else {
            return false;
        }
    };
    if target == ChainWork::ZERO {
        return false;
    }
    ChainWork::from_le_bytes(hash.to_le_bytes()) <= target
}

fn header_from_row(row: &[u8]) -> Result<Header, headers::HeaderCheckpointError> {
    deserialize(row).map_err(|error| headers::HeaderCheckpointError::Codec(error.to_string()))
}

fn populated_utxo() -> Result<UtxoSet, bitcoin_rs_utxo::UtxoError> {
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(
        OutPoint::new(Txid(Hash256::from_le_bytes(&[7_u8; 32])), 3),
        TxOut {
            value: 50_000,
            script_pubkey: vec![0x51, 0x21],
        },
        true,
        0,
    ));
    let utxo = UtxoSet::new();
    utxo.commit_block(&changes, &Hash256::default())?;
    Ok(utxo)
}
