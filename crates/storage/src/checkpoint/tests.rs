use super::format::generation_name;
use super::fs::CheckpointRoot;
use super::load::read_current;
use super::*;

use bitcoin_rs_primitives::hex_encode;
use cap_std::ambient_authority;
use sha2::{Digest, Sha256};
use std::fs;
use tempfile::tempdir;

fn publish_fixture(
    data_dir: &cap_std::fs::Dir,
    failpoint: Option<CheckpointFailpoint>,
) -> Result<u64, CheckpointError> {
    let stage = begin_publication(data_dir, failpoint)?;
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
    let ((), headers_digest) = stage.write_artifact(
        HEADERS_FILE,
        CheckpointFailpoint::HeadersWrite,
        CheckpointFailpoint::HeadersSync,
        |writer| {
            writer.write_all(headers)?;
            Ok::<_, CheckpointError>(())
        },
    )?;
    let ((), utxo_digest) = stage.write_artifact(
        UTXO_FILE,
        CheckpointFailpoint::UtxoWrite,
        CheckpointFailpoint::UtxoSync,
        |writer| {
            writer.write_all(utxo)?;
            Ok::<_, CheckpointError>(())
        },
    )?;
    let ((), coinstats_digest) = stage.write_artifact(
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
        let CheckpointOpen::Current {
            current,
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
                        &stale,
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
                &authenticated,
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
    let stage = begin_publication(&data, None)?;
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
    let dir = tempdir()?;
    let data = open_root(dir.path())?;
    ensure_current_schema(&data)?;
    assert_eq!(read_file(&data, CURRENT_SCHEMA_FILE, 16)?, b"0\n");
    let mut oversized = data.create("oversized")?;
    oversized.write_all(&[0_u8; 17])?;
    oversized.sync_all()?;
    assert!(matches!(
        read_file(&data, "oversized", 16),
        Err(error) if error.kind() == std::io::ErrorKind::InvalidData
    ));
    data.remove_file(CURRENT_SCHEMA_FILE)?;
    let mut stale_schema = data.create(CURRENT_SCHEMA_FILE)?;
    stale_schema.write_all(b"1\n")?;
    stale_schema.sync_all()?;
    assert!(ensure_current_schema(&data).is_err());
    Ok(())
}
