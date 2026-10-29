use super::format::generation_name;
use super::fs::CheckpointRoot;
use super::load::read_current;
use super::*;
use bitcoin_rs_primitives::encode::hex_encode;

use cap_std::ambient_authority;
use sha2::{Digest, Sha256};
use std::fs;
use tempfile::tempdir;

fn publish_fixture(
    data_dir: &cap_std::fs::Dir,
    failpoint: Option<CheckpointFailpoint>,
) -> Result<u64, CheckpointError> {
    publish_fixture_at(
        data_dir,
        CHECKPOINT_ROOT,
        CheckpointRetention::Replace,
        failpoint,
    )
    .map(|reference| reference.generation)
}

fn publish_fixture_at(
    data_dir: &cap_std::fs::Dir,
    root_name: &str,
    retention: CheckpointRetention,
    failpoint: Option<CheckpointFailpoint>,
) -> Result<CheckpointReference, CheckpointError> {
    let stage = begin_publication_at_with_failpoint(data_dir, root_name, retention, failpoint)?;
    let headers = b"headers";
    let utxo = b"utxo";
    let coinstats = {
        let coinstats_len = 820_usize;
        let mut bytes = Vec::with_capacity(coinstats_len);
        bytes.extend_from_slice(&COINSTATS_MAGIC);
        bytes.extend_from_slice(&COINSTATS_VERSION.to_le_bytes());
        bytes.extend_from_slice(&COINSTATS_PAYLOAD_LEN.to_le_bytes());
        bytes.resize(coinstats_len, 0);
        bytes
    };
    let ((), headers_digest) = stage.write_artifact_with_failpoints(
        HEADERS_FILE,
        CheckpointFailpoint::HeadersWrite,
        CheckpointFailpoint::HeadersSync,
        |writer| {
            writer.write_all(headers)?;
            Ok::<_, CheckpointError>(())
        },
    )?;
    let ((), utxo_digest) = stage.write_artifact_with_failpoints(
        UTXO_FILE,
        CheckpointFailpoint::UtxoWrite,
        CheckpointFailpoint::UtxoSync,
        |writer| {
            writer.write_all(utxo)?;
            Ok::<_, CheckpointError>(())
        },
    )?;
    let ((), coinstats_digest) = stage.write_artifact_with_failpoints(
        COINSTATS_FILE,
        CheckpointFailpoint::CoinStatsWrite,
        CheckpointFailpoint::CoinStatsSync,
        |writer| {
            writer.write_all(&coinstats)?;
            Ok::<_, CheckpointError>(())
        },
    )?;
    let identity = CheckpointIdentity {
        network: bitcoin_rs_primitives::Network::Regtest,
        genesis: bitcoin_rs_primitives::Network::Regtest.genesis_block_hash(),
    };
    let manifest = CheckpointManifestV1 {
        format: MANIFEST_FORMAT.to_owned(),
        version: MANIFEST_VERSION,
        generation: stage.generation(),
        network: network_name(identity.network).to_owned(),
        network_magic: hex_encode(&identity.network.magic()),
        genesis_hash: identity.genesis.to_string_be(),
        applied_tip: CheckpointTipV1 {
            height: 0,
            hash: "00".repeat(32),
            chainwork: "00".repeat(32),
            chain_tx_count: 0,
        },
        best_header_tip: CheckpointTipV1 {
            height: 0,
            hash: "00".repeat(32),
            chainwork: "00".repeat(32),
            chain_tx_count: 0,
        },
        headers: HeadersArtifactV1 {
            file: HEADERS_FILE.to_owned(),
            codec: HEADER_CODEC.to_owned(),
            version: 1,
            bytes: headers_digest.bytes,
            sha256: hex_encode(&headers_digest.sha256),
            header_count: 0,
            best_chain_sha256: "00".repeat(32),
            applied_chain_sha256: "00".repeat(32),
        },
        utxo: UtxoArtifactV1 {
            file: UTXO_FILE.to_owned(),
            codec: UTXO_CODEC.to_owned(),
            version: UTXO_VERSION,
            bytes: utxo_digest.bytes,
            sha256: hex_encode(&utxo_digest.sha256),
            record_count: 0,
            output_count: 0,
            muhash_trailer_sha256: "00".repeat(32),
        },
        coinstats: CoinStatsArtifactV1 {
            file: COINSTATS_FILE.to_owned(),
            codec: COINSTATS_CODEC.to_owned(),
            version: COINSTATS_VERSION,
            bytes: coinstats_digest.bytes,
            sha256: hex_encode(&coinstats_digest.sha256),
            height: 0,
            total_amount: 0,
            bogo_size: 0,
            tx_count: 0,
            utxo_count: 0,
            muhash: "00".repeat(32),
        },
    };
    commit_publication(stage, &manifest)
}

fn open_root(path: &std::path::Path) -> Result<cap_std::fs::Dir, std::io::Error> {
    cap_std::fs::Dir::open_ambient_dir(path, ambient_authority())
}

#[test]
fn publication_replaces_current_and_cleans_previous_generation()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let data = open_root(dir.path())?;
    assert_eq!(publish_fixture(&data, None)?, 1);
    assert_eq!(publish_fixture(&data, None)?, 2);
    let root = dir.path().join(CHECKPOINT_ROOT);
    let current: CurrentV1 = serde_json::from_slice(&fs::read(root.join(CURRENT_FILE))?)?;
    assert_eq!(current.generation, 2);
    assert!(!root.join(generation_name(1)).exists());
    let entries = fs::read_dir(root)?.collect::<Result<Vec<_>, _>>()?;
    assert!(!entries.iter().any(|entry| {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        name.starts_with(".gen-") || name.starts_with(".CURRENT-")
    }));
    Ok(())
}

#[test]
fn publication_failpoints_preserve_the_previous_current() -> Result<(), Box<dyn std::error::Error>>
{
    let failpoints = [
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
        CheckpointFailpoint::CurrentRootSync,
    ];
    for failpoint in failpoints {
        let dir = tempdir()?;
        let data = open_root(dir.path())?;
        assert_eq!(publish_fixture(&data, None)?, 1);
        assert!(
            publish_fixture(&data, Some(failpoint)).is_err(),
            "{failpoint:?}"
        );
        let opened = open_current_checkpoint(&data)?;
        let CheckpointOpen::Selected {
            reference: current,
            generation_dir,
        } = opened
        else {
            panic!("failed publication lost CURRENT at {failpoint:?}");
        };
        assert!(current.generation == 1 || failpoint == CheckpointFailpoint::CurrentRootSync);
        let identity = CheckpointIdentity {
            network: bitcoin_rs_primitives::Network::Regtest,
            genesis: bitcoin_rs_primitives::Network::Regtest.genesis_block_hash(),
        };
        let manifest = read_manifest(&generation_dir, &current, identity)?;
        verify_artifact(
            &generation_dir,
            &manifest.headers.file,
            manifest.headers.bytes,
            &manifest.headers.sha256,
        )?;
        verify_artifact(
            &generation_dir,
            &manifest.utxo.file,
            manifest.utxo.bytes,
            &manifest.utxo.sha256,
        )?;
        verify_artifact(
            &generation_dir,
            &manifest.coinstats.file,
            manifest.coinstats.bytes,
            &manifest.coinstats.sha256,
        )?;
        assert!(publish_fixture(&data, None)? > 1);
        let entries =
            fs::read_dir(dir.path().join(CHECKPOINT_ROOT))?.collect::<Result<Vec<_>, _>>()?;
        assert!(!entries.iter().any(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            name.starts_with(".gen-") || name.starts_with(".CURRENT-")
        }));
    }
    Ok(())
}

#[test]
fn historical_publication_retains_head_generation_until_explicit_retirement()
-> Result<(), Box<dyn std::error::Error>> {
    for failpoint in [
        None,
        Some(CheckpointFailpoint::CurrentRename),
        Some(CheckpointFailpoint::CurrentRootSync),
    ] {
        let dir = tempdir()?;
        let data = open_root(dir.path())?;
        let accepted = publish_fixture_at(
            &data,
            HISTORICAL_CHECKPOINT_ROOT,
            CheckpointRetention::UntilReferenced,
            None,
        )?;
        let result = publish_fixture_at(
            &data,
            HISTORICAL_CHECKPOINT_ROOT,
            CheckpointRetention::UntilReferenced,
            failpoint,
        );
        assert_eq!(result.is_err(), failpoint.is_some());
        let CheckpointOpen::Selected {
            generation_dir,
            reference: current,
        } = open_checkpoint_generation_at(&data, HISTORICAL_CHECKPOINT_ROOT, accepted)?
        else {
            panic!("accepted generation missing");
        };
        let manifest = read_manifest(
            &generation_dir,
            &current,
            CheckpointIdentity {
                network: bitcoin_rs_primitives::Network::Regtest,
                genesis: bitcoin_rs_primitives::Network::Regtest.genesis_block_hash(),
            },
        )?;
        verify_artifact(
            &generation_dir,
            &manifest.utxo.file,
            manifest.utxo.bytes,
            &manifest.utxo.sha256,
        )?;
        drop(generation_dir);
        let replacement = publish_fixture_at(
            &data,
            HISTORICAL_CHECKPOINT_ROOT,
            CheckpointRetention::UntilReferenced,
            None,
        )?;
        assert!(
            dir.path()
                .join(HISTORICAL_CHECKPOINT_ROOT)
                .join(generation_name(accepted.generation))
                .exists()
        );
        retire_checkpoint_generations_at(
            &data,
            HISTORICAL_CHECKPOINT_ROOT,
            replacement.generation,
        )?;
        assert!(
            open_checkpoint_generation_at(&data, HISTORICAL_CHECKPOINT_ROOT, accepted).is_err()
        );
        assert!(
            open_checkpoint_generation_at(&data, HISTORICAL_CHECKPOINT_ROOT, replacement).is_ok()
        );
    }
    Ok(())
}

#[test]
fn clearing_checkpoint_namespace_preserves_unknown_entries_and_other_namespaces()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let data = open_root(dir.path())?;
    clear_checkpoint_generations_at(&data, HISTORICAL_CHECKPOINT_ROOT)?;
    publish_fixture(&data, None)?;
    for _ in 0..2 {
        publish_fixture_at(
            &data,
            HISTORICAL_CHECKPOINT_ROOT,
            CheckpointRetention::UntilReferenced,
            None,
        )?;
    }
    let root = dir.path().join(HISTORICAL_CHECKPOINT_ROOT);
    fs::create_dir(root.join(".gen-00000000000000000003.tmp"))?;
    fs::write(root.join(".CURRENT-00000000000000000003.tmp"), b"partial")?;
    fs::write(root.join("operator-notes"), b"keep")?;
    fs::create_dir(root.join("operator-backup"))?;
    for _ in 0..2 {
        clear_checkpoint_generations_at(&data, HISTORICAL_CHECKPOINT_ROOT)?;
        assert_eq!(fs::read_dir(&root)?.count(), 2);
        assert_eq!(fs::read(root.join("operator-notes"))?, b"keep");
        assert!(root.join("operator-backup").is_dir());
        assert!(matches!(
            open_current_checkpoint(&data)?,
            CheckpointOpen::Selected { .. }
        ));
    }
    Ok(())
}

#[test]
fn direct_and_current_selection_share_publication_digest_validation()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let data = open_root(dir.path())?;
    let reference = publish_fixture_at(&data, CHECKPOINT_ROOT, CheckpointRetention::Replace, None)?;
    let manifest_path = dir
        .path()
        .join(CHECKPOINT_ROOT)
        .join(generation_name(reference.generation))
        .join(MANIFEST_FILE);
    let mut bytes = fs::read(&manifest_path)?;
    bytes.push(b' '); // Still valid JSON with unchanged manifest semantics.
    fs::write(&manifest_path, bytes)?;
    for selection in [
        open_current_checkpoint(&data)?,
        open_checkpoint_generation_at(&data, CHECKPOINT_ROOT, reference)?,
    ] {
        let CheckpointOpen::Selected {
            generation_dir,
            reference,
        } = selection
        else {
            return Err("missing selection".into());
        };
        assert!(matches!(
            read_manifest(
                &generation_dir,
                &reference,
                CheckpointIdentity {
                    network: bitcoin_rs_primitives::Network::Regtest,
                    genesis: bitcoin_rs_primitives::Network::Regtest.genesis_block_hash(),
                }
            ),
            Err(CheckpointError::Invalid(_))
        ));
    }
    Ok(())
}

#[test]
fn current_and_manifest_validation_reject_tampering() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let data = open_root(dir.path())?;
    publish_fixture(&data, None)?;
    let root_path = dir.path().join(CHECKPOINT_ROOT);
    let root =
        CheckpointRoot::open_existing(&data, CHECKPOINT_ROOT)?.ok_or("missing checkpoint root")?;
    let current_path = root_path.join(CURRENT_FILE);
    let original_current = fs::read(&current_path)?;
    for mutation in 0..4 {
        fs::write(&current_path, &original_current)?;
        let mut current: CurrentV1 = serde_json::from_slice(&original_current)?;
        match mutation {
            0 => current.version += 1,
            1 => current.format.push_str("-wrong"),
            2 => current.directory.push_str("-wrong"),
            _ => current.manifest_sha256 = "zz".repeat(32),
        }
        fs::write(&current_path, serde_json::to_vec(&current)?)?;
        assert!(matches!(
            read_current(&root),
            Err(CheckpointError::Invalid(_))
        ));
    }
    fs::write(&current_path, &original_current)?;
    let current = read_current(&root)?.ok_or("missing CURRENT")?;
    let generation = root.open_dir(&current.directory)?;
    let manifest_path = root_path.join(&current.directory).join(MANIFEST_FILE);
    let original_manifest = fs::read(&manifest_path)?;
    for mutation in 0..6 {
        fs::write(&manifest_path, &original_manifest)?;
        let mut manifest: CheckpointManifestV1 = serde_json::from_slice(&original_manifest)?;
        match mutation {
            0 => {
                let stale = current.clone();
                fs::write(&manifest_path, b"stale")?;
                assert!(
                    read_manifest(
                        &generation,
                        &stale.reference()?,
                        CheckpointIdentity {
                            network: bitcoin_rs_primitives::Network::Regtest,
                            genesis: bitcoin_rs_primitives::Network::Regtest.genesis_block_hash(),
                        }
                    )
                    .is_err()
                );
                continue;
            }
            1 => manifest.version += 1,
            2 => manifest.format.push_str("-wrong"),
            3 => manifest.generation += 1,
            4 => manifest.network.push_str("-wrong"),
            _ => manifest.genesis_hash.push_str("-wrong"),
        }
        let bytes = serde_json::to_vec(&manifest)?;
        fs::write(&manifest_path, &bytes)?;
        let mut authenticated = current.clone();
        authenticated.manifest_sha256 = hex_encode(&Sha256::digest(&bytes));
        assert!(matches!(
            read_manifest(
                &generation,
                &authenticated.reference()?,
                CheckpointIdentity {
                    network: bitcoin_rs_primitives::Network::Regtest,
                    genesis: bitcoin_rs_primitives::Network::Regtest.genesis_block_hash(),
                }
            ),
            Err(CheckpointError::Invalid(_))
        ));
    }
    Ok(())
}

#[test]
fn artifact_and_coinstats_validation_preserves_protocol_bounds()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let data = open_root(dir.path())?;
    publish_fixture(&data, None)?;
    let root =
        CheckpointRoot::open_existing(&data, CHECKPOINT_ROOT)?.ok_or("missing checkpoint root")?;
    let current = read_current(&root)?.ok_or("missing CURRENT")?;
    let generation = root.open_dir(&current.directory)?;
    assert!(matches!(
        verify_artifact(&generation, HEADERS_FILE, 1, &"00".repeat(32)),
        Err(CheckpointError::Invalid(_))
    ));
    assert!(matches!(
        verify_artifact(&generation, HEADERS_FILE, 7, &"00".repeat(32)),
        Err(CheckpointError::Invalid(_))
    ));
    assert!(require_filename("nested/headers-v1.dat", HEADERS_FILE).is_err());
    let mut payload = vec![0; 820_usize];
    payload[..8].copy_from_slice(&COINSTATS_MAGIC);
    payload[8..12].copy_from_slice(&COINSTATS_VERSION.to_le_bytes());
    payload[12..16].copy_from_slice(&COINSTATS_PAYLOAD_LEN.to_le_bytes());
    assert_eq!(coinstats_artifact_payload(&payload)?.len(), 804);
    payload[12..16].copy_from_slice(&0_u32.to_le_bytes());
    assert!(coinstats_artifact_payload(&payload).is_err());
    payload[12..16].copy_from_slice(&COINSTATS_PAYLOAD_LEN.to_le_bytes());
    payload[8..12].copy_from_slice(&(COINSTATS_VERSION + 1).to_le_bytes());
    assert!(coinstats_artifact_payload(&payload).is_err());
    payload[8..12].copy_from_slice(&COINSTATS_VERSION.to_le_bytes());
    payload[..8].fill(0);
    assert!(coinstats_artifact_payload(&payload).is_err());
    assert!(coinstats_artifact_payload(&payload[..819]).is_err());
    Ok(())
}

#[test]
fn transient_checkpoint_io_is_not_classified_as_incompatible() {
    let error = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "checkpoint locked");
    let CheckpointLoadError::Io(error) = classify_checkpoint_io(error) else {
        panic!("transient checkpoint I/O was classified as corruption");
    };
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
}

#[cfg(unix)]
#[test]
fn unknown_entries_and_symlinks_are_never_deleted() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::symlink;

    let dir = tempdir()?;
    let data = open_root(dir.path())?;
    publish_fixture(&data, None)?;
    let root = dir.path().join(CHECKPOINT_ROOT);
    let unknown = root.join("operator-note");
    fs::write(&unknown, b"keep")?;
    let linked = root.join("gen-18446744073709551615");
    symlink(dir.path().join("outside"), &linked)?;
    fs::create_dir(root.join("gen-00000000000000000088"))?;
    fs::create_dir(root.join(".gen-18446744073709551615.tmp"))?;
    fs::write(root.join(".CURRENT-00000000000000000066.tmp"), b"stale")?;

    publish_fixture(&data, None)?;
    assert!(unknown.exists());
    assert!(fs::symlink_metadata(linked)?.file_type().is_symlink());
    assert!(!root.join("gen-00000000000000000088").exists());
    assert!(!root.join(".gen-18446744073709551615.tmp").exists());
    assert!(!root.join(".CURRENT-00000000000000000066.tmp").exists());
    Ok(())
}

#[test]
fn commit_rejects_manifest_for_wrong_generation() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let data = open_root(dir.path())?;
    let stage = begin_publication_with_failpoint(&data, None)?;
    let generation = stage.generation();
    let manifest: CheckpointManifestV1 = serde_json::from_value(serde_json::json!({
        "format": MANIFEST_FORMAT,
        "version": MANIFEST_VERSION,
        "generation": generation + 1,
        "network": "regtest",
        "network_magic": hex_encode(&bitcoin_rs_primitives::Network::Regtest.magic()),
        "genesis_hash": bitcoin_rs_primitives::Network::Regtest.genesis_block_hash().to_string_be(),
        "applied_tip": { "height": 0, "hash": "00".repeat(32), "chainwork": "00".repeat(32), "chain_tx_count": 0 },
        "best_header_tip": { "height": 0, "hash": "00".repeat(32), "chainwork": "00".repeat(32), "chain_tx_count": 0 },
        "headers": { "file": HEADERS_FILE, "codec": HEADER_CODEC, "version": 1, "bytes": 0, "sha256": "00".repeat(32), "header_count": 0, "best_chain_sha256": "00".repeat(32), "applied_chain_sha256": "00".repeat(32) },
        "utxo": { "file": UTXO_FILE, "codec": UTXO_CODEC, "version": UTXO_VERSION, "bytes": 0, "sha256": "00".repeat(32), "record_count": 0, "output_count": 0, "muhash_trailer_sha256": "00".repeat(32) },
        "coinstats": { "file": COINSTATS_FILE, "codec": COINSTATS_CODEC, "version": COINSTATS_VERSION, "bytes": COINSTATS_ARTIFACT_LEN, "sha256": "00".repeat(32), "height": 0, "total_amount": 0, "bogo_size": 0, "tx_count": 0, "utxo_count": 0, "muhash": "00".repeat(32) }
    }))?;
    assert!(matches!(
        commit_publication(stage, &manifest),
        Err(CheckpointError::Invalid(message)) if message.contains("does not match staged generation")
    ));
    assert!(matches!(
        open_current_checkpoint(&data)?,
        CheckpointOpen::Cold
    ));
    Ok(())
}

#[test]
fn format_and_schema_helpers_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(HEADER_CODEC, "bitcoin-rs-canonical-headers");
    assert_eq!(UTXO_CODEC, "bitcoin-rs-utxo-spendable-v1");
    assert_eq!(COINSTATS_CODEC, "bitcoin-rs-coinstats-v1");
    assert_eq!(CURRENT_FORMAT, "bitcoin-rs-chainstate-current");
    assert_eq!(MANIFEST_FORMAT, "bitcoin-rs-chainstate-checkpoint");
    assert_eq!(generation_name(7), "gen-00000000000000000007");
    let bytes = [0_u8, 1, 0xfe, 0xff];
    assert_eq!(decode_hex::<4>(&hex_encode(&bytes))?, bytes);
    assert_eq!(hex_encode(&bytes), "0001feff");
    for invalid in ["0001FEFF", "0001fe", "0001feffff", "0001fegf"] {
        assert!(decode_hex::<4>(invalid).is_err(), "accepted {invalid}");
    }
    let dir = tempdir()?;
    let data = open_root(dir.path())?;
    ensure_current_schema(&data)?;
    assert_eq!(read_file(&data, CURRENT_SCHEMA_FILE, 16)?, b"2\n");
    let mut oversized = data.create("oversized")?;
    oversized.write_all(&[0_u8; 17])?;
    oversized.sync_all()?;
    assert!(matches!(
        read_file(&data, "oversized", 16),
        Err(error) if error.kind() == std::io::ErrorKind::InvalidData
    ));
    data.remove_file(CURRENT_SCHEMA_FILE)?;
    for epoch in [b"0\n", b"1\n"] {
        let mut stale_schema = data.create(CURRENT_SCHEMA_FILE)?;
        stale_schema.write_all(epoch)?;
        stale_schema.sync_all()?;
        assert!(ensure_current_schema(&data).is_err());
        assert_eq!(read_file(&data, CURRENT_SCHEMA_FILE, 16)?, epoch);
    }
    Ok(())
}

#[test]
fn schema_init_exempts_only_a_regular_lock_file() -> Result<(), Box<dyn std::error::Error>> {
    // Only the lock file initializes.
    let dir = tempdir()?;
    let data = open_root(dir.path())?;
    {
        let mut lock = data.create(super::fs::DATA_DIR_LOCK_FILE)?;
        lock.write_all(b"locked")?;
        lock.sync_all()?;
    }
    ensure_current_schema(&data)?;
    // The lock plus any other entry still errors.
    {
        let mut other = data.create("other")?;
        other.write_all(b"data")?;
        other.sync_all()?;
    }
    data.remove_file(CURRENT_SCHEMA_FILE)?;
    assert!(ensure_current_schema(&data).is_err());
    // A lock directory does not exempt.
    let dir = tempdir()?;
    let data = open_root(dir.path())?;
    data.create_dir(super::fs::DATA_DIR_LOCK_FILE)?;
    assert!(ensure_current_schema(&data).is_err());
    Ok(())
}

#[cfg(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    target_os = "redox"
))]
#[test]
fn rename_noreplace_refuses_escape_but_keeps_same_dir_renames()
-> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write as _;

    let dir = tempdir()?;
    let data = open_root(dir.path())?;
    let root = CheckpointRoot::open_or_create(&data, CHECKPOINT_ROOT)?;

    // A valid same-directory rename retains its behavior.
    root.create_dir("stage-a")?;
    super::fs::rename_noreplace(root.dir(), "stage-a", "stage-b")?;
    assert!(root.entry_exists("stage-b")?);
    assert!(!root.entry_exists("stage-a")?);

    // Operator data that must survive the attack attempts.
    let mut operator = root.create_file("operator-notes")?;
    operator.write_all(b"keep")?;
    drop(operator);

    // Crafted destinations: parent traversal, absolute paths, nested paths
    // (including symlink-intermediate and replacement-path shapes), trailing
    // directory slashes, and non-entry structures. Each must fail with
    // `InvalidInput` before any syscall, leaving the source in place.
    root.create_dir("victim")?;
    let hostile_destinations = [
        "..",
        ".",
        "",
        "/",
        "/tmp/checkpoint-escape",
        "../escape",
        "a/b",
        "a/../b",
        "link/",
        "sub/CURRENT",
        ".hidden/../escape",
    ];
    for hostile in hostile_destinations {
        let error = match super::fs::rename_noreplace(root.dir(), "victim", hostile) {
            Ok(()) => panic!("destination {hostile:?} was accepted"),
            Err(error) => error,
        };
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::InvalidInput,
            "destination {hostile:?}"
        );
    }
    assert!(
        root.entry_exists("victim")?,
        "rejected destinations must not consume the source"
    );

    // Crafted sources are confined symmetrically: an outside path must not be
    // importable into the root.
    for hostile in ["../victim", "/tmp/victim", "a/b", "", ".", "..", "link/"] {
        let error = match super::fs::rename_noreplace(root.dir(), hostile, "fresh-dest") {
            Ok(()) => panic!("source {hostile:?} was accepted"),
            Err(error) => error,
        };
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::InvalidInput,
            "source {hostile:?}"
        );
    }
    assert!(!root.entry_exists("fresh-dest")?);

    // A planted symlink plus a trailing-slash destination must not resolve
    // outside the root: the raw `/` is rejected before component analysis.
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let outside = dir.path().join("outside-real");
        fs::create_dir(&outside)?;
        let root_path = dir.path().join(CHECKPOINT_ROOT);
        symlink(&outside, root_path.join("link"))?;
        let error = match super::fs::rename_noreplace(root.dir(), "victim", "link/escape") {
            Ok(()) => panic!("symlink-intermediate destination was accepted"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        let error = match super::fs::rename_noreplace(root.dir(), "link/escape", "fresh-dest") {
            Ok(()) => panic!("symlink-intermediate source was accepted"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            !outside.join("escape").exists(),
            "rename escaped through the symlink"
        );
        assert_eq!(
            fs::read(root_path.join("operator-notes"))?,
            b"keep",
            "operator data must survive"
        );
    }

    // An existing destination is preserved by NOREPLACE: the collision fails
    // without consuming the source or clobbering operator data.
    let collision = match super::fs::rename_noreplace(root.dir(), "victim", "operator-notes") {
        Ok(()) => panic!("rename onto operator data was accepted"),
        Err(collision) => collision,
    };
    assert_eq!(collision.kind(), std::io::ErrorKind::AlreadyExists);
    assert!(root.entry_exists("victim")?);
    assert!(root.entry_exists("operator-notes")?);
    assert_eq!(
        fs::read(dir.path().join(CHECKPOINT_ROOT).join("operator-notes"))?,
        b"keep",
        "operator data must survive collision"
    );

    // Nothing escaped the checkpoint root and the root still behaves.
    assert!(!dir.path().join("escape").exists());
    assert!(!dir.path().join("tmp").join("checkpoint-escape").exists());
    super::fs::rename_noreplace(root.dir(), "victim", "victim-promoted")?;
    assert!(root.entry_exists("victim-promoted")?);
    Ok(())
}

#[test]
fn open_file_reads_regular_file() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Read as _;

    let dir = tempdir()?;
    std::fs::write(dir.path().join("utxo-v4.dat"), b"checkpoint-bytes")?;
    let cap_dir = open_root(dir.path())?;

    let mut file = super::fs::open_file(&cap_dir, "utxo-v4.dat")?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    assert_eq!(bytes, b"checkpoint-bytes");
    // The public caller delegates to `open_file`, so it inherits the same
    // no-follow, regular-file-only posture.
    assert_eq!(
        read_file(&cap_dir, "utxo-v4.dat", 1024)?,
        b"checkpoint-bytes"
    );

    let missing = match super::fs::open_file(&cap_dir, "missing.dat") {
        Err(error) => error,
        Ok(_) => return Err("opening a missing checkpoint entry must fail".into()),
    };
    assert_eq!(missing.kind(), std::io::ErrorKind::NotFound);
    Ok(())
}

#[cfg(unix)]
#[test]
fn open_file_refuses_directory_entry() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    std::fs::create_dir(dir.path().join("gen-1"))?;
    let cap_dir = open_root(dir.path())?;

    let error = match super::fs::open_file(&cap_dir, "gen-1") {
        Err(error) => error,
        Ok(_) => return Err("opening a directory as a checkpoint entry must fail".into()),
    };
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    Ok(())
}

#[cfg(unix)]
#[test]
fn open_file_refuses_fifo_without_blocking() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::FileTypeExt as _;

    let dir = tempdir()?;
    let fifo_path = dir.path().join("utxo-v4.dat");
    let created = std::process::Command::new("mkfifo")
        .arg(&fifo_path)
        .status()?;
    assert!(created.success(), "create isolated Unix FIFO");

    let cap_dir = open_root(dir.path())?;
    let worker_dir = cap_dir.try_clone()?;
    // Bounded queue: the worker owns exactly one outcome and the test owns
    // the join, so a regressed reader cannot outlive this test.
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let result = super::fs::open_file(&worker_dir, "utxo-v4.dat").map(|_| ());
        let _ = sender.send(result.map_err(|error| error.kind()));
    });
    let observed = receiver.recv_timeout(std::time::Duration::from_secs(5));
    let rescue = if observed.is_err() {
        // Unblock a regressed reader before reporting failure. O_RDWR
        // plus NONBLOCK prevents this rescue from introducing another
        // FIFO wait.
        use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _};
        let mut options = cap_std::fs::OpenOptions::new();
        options
            .read(true)
            .write(true)
            .follow(FollowSymlinks::No)
            .nonblock(true);
        Some(cap_dir.open_with("utxo-v4.dat", &options)?)
    } else {
        None
    };
    worker
        .join()
        .map_err(|_| "checkpoint open worker panicked")?;
    // Keep queued rescue bytes alive even if the worker started late.
    drop(rescue);
    assert_eq!(
        observed.map_err(|_| "opening a substituted FIFO must not block")?,
        Err(std::io::ErrorKind::InvalidData)
    );
    assert!(
        std::fs::symlink_metadata(&fifo_path)?.file_type().is_fifo(),
        "substituted FIFO is preserved, not consumed"
    );
    Ok(())
}

#[cfg(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    target_os = "redox"
))]
#[test]
fn rename_noreplace_refuses_an_existing_destination_and_keeps_both_files()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let data = open_root(dir.path())?;
    fs::write(dir.path().join("staged"), b"new")?;
    fs::write(dir.path().join("taken"), b"operator")?;

    let error = super::fs::rename_noreplace(&data, "staged", "taken")
        .err()
        .ok_or("rename over an existing file must fail")?;
    assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(fs::read(dir.path().join("taken"))?, b"operator");
    assert_eq!(fs::read(dir.path().join("staged"))?, b"new");

    super::fs::rename_noreplace(&data, "staged", "free")?;
    assert_eq!(fs::read(dir.path().join("free"))?, b"new");
    assert!(!dir.path().join("staged").exists());
    Ok(())
}
