//! Independent coverage for the witnessed v4 snapshot codec, the sealed
//! artifact raw traversal, and the worker-owned seed cell.
//!
//! Every test below exercises real bytes through the public codec: no mocks,
//! no source-text assertions.

use std::convert::Infallible;
use std::io::{Cursor, Seek, Write};

use bitcoin_rs_primitives::{Amount, Hash256, OutPoint, Script, TxOut};
use bitcoin_rs_storage::checkpoint::CheckpointReference;
use bitcoin_rs_utxo::contract::{BlockChanges, UtxoAdd, commit_block_changes};
use bitcoin_rs_utxo::{
    OfferOutcome, RawSeedError, SeedOfferCell, SeedProvenance, SeedSlot, SnapshotCoin,
    SnapshotCoinObserver, VerifiedSnapshotArtifact, read_snapshot_strict_v4,
    read_snapshot_strict_v4_witnessed, write_snapshot_observed, write_snapshot_witnessed,
};
use sha2::{Digest, Sha256};

fn txid(seed: u64) -> Hash256 {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    bytes[8..16].copy_from_slice(&seed.rotate_left(23).to_le_bytes());
    bytes[16..24].copy_from_slice(&seed.wrapping_mul(0x94d0_49bb_1331_11eb).to_le_bytes());
    bytes[24..32].copy_from_slice(&seed.wrapping_add(0x0123_4567_89ab_cdef).to_le_bytes());
    Hash256::from_le_bytes(&bytes)
}

fn txout(seed: u64) -> TxOut {
    TxOut {
        value: Amount::from_sat(2_000 + seed),
        script_pubkey: vec![0x51, u8::try_from(seed % 256).unwrap_or(0)].into(),
    }
}

fn fixture_set() -> Result<(bitcoin_rs_utxo::UtxoSet, Hash256, u32), Box<dyn std::error::Error>> {
    let set = bitcoin_rs_utxo::UtxoSet::new();
    let first = txid(7_001);
    let second = txid(7_002);
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(
        OutPoint::new(first.into(), 0),
        txout(7_010),
        false,
        100,
    ));
    changes.add(UtxoAdd::new(
        OutPoint::new(first.into(), 3),
        TxOut {
            value: Amount::from_sat(7_011),
            script_pubkey: Script::new(),
        },
        true,
        101,
    ));
    changes.add(UtxoAdd::new(
        OutPoint::new(second.into(), 1),
        txout(7_012),
        false,
        102,
    ));
    commit_block_changes(&set, &changes, &txid(7_003))?;
    Ok((set, txid(7_004), 103))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SeenCoin {
    txid: Hash256,
    vout: u32,
    value: u64,
    script_pubkey: Vec<u8>,
    height: u32,
    coinbase: bool,
}

#[derive(Default)]
struct RecordingObserver {
    coins: Vec<SeenCoin>,
}

impl SnapshotCoinObserver for RecordingObserver {
    fn observe_coin(&mut self, coin: SnapshotCoin<'_>) {
        self.coins.push(SeenCoin {
            txid: coin.txid,
            vout: coin.vout,
            value: coin.value,
            script_pubkey: coin.script_pubkey.to_vec(),
            height: coin.height,
            coinbase: coin.coinbase,
        });
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    digest.into()
}

fn encoded_witnessed() -> Result<(Vec<u8>, bitcoin_rs_utxo::V4Witness), Box<dyn std::error::Error>>
{
    let (set, tip, height) = fixture_set()?;
    let mut bytes = Vec::new();
    let (_, (), witness) = write_snapshot_witnessed(&set, &tip, height, &mut bytes, ())?;
    let witness = witness.ok_or("valid encode must mint a witness")?;
    Ok((bytes, witness))
}

fn file_with(bytes: &[u8]) -> Result<std::fs::File, Box<dyn std::error::Error>> {
    let mut file = tempfile::tempfile()?;
    file.write_all(bytes)?;
    file.rewind()?;
    Ok(file)
}

/// One raw seed coin as emitted by traversal: identity plus script bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RawCoin {
    txid: [u8; 32],
    vout: u32,
    script_pubkey: Vec<u8>,
}

fn raw_projection(
    artifact: &mut VerifiedSnapshotArtifact,
) -> Result<Vec<RawCoin>, RawSeedError<Infallible>> {
    let mut coins = Vec::new();
    artifact.for_each_coin_raw(
        &mut |outpoint: &OutPoint, script: &[u8]| {
            // `OutPoint` is packed: copy it onto the stack before touching fields.
            let outpoint = *outpoint;
            coins.push(RawCoin {
                txid: *outpoint.txid.as_bytes(),
                vout: outpoint.vout,
                script_pubkey: script.to_vec(),
            });
            Ok::<(), Infallible>(())
        },
        &|| false,
    )?;
    Ok(coins)
}

#[test]
fn witnessed_write_matches_plain_bytes_and_mints_exact_witness()
-> Result<(), Box<dyn std::error::Error>> {
    let (set, tip, height) = fixture_set()?;
    let mut plain = Vec::new();
    let (plain_trailer, ()) = write_snapshot_observed(&set, &tip, height, &mut plain, ())?;
    let mut witnessed = Vec::new();
    let (witness_trailer, (), witness) =
        write_snapshot_witnessed(&set, &tip, height, &mut witnessed, ())?;

    assert_eq!(plain, witnessed);
    assert_eq!(plain_trailer, witness_trailer);
    let witness = witness.ok_or("valid encode must mint a witness")?;
    assert_eq!(witness.byte_len(), u64::try_from(plain.len())?);
    assert_eq!(witness.sha256(), sha256(&plain));
    assert_eq!(witness.tip_hash(), tip);
    assert_eq!(witness.height(), height);
    assert_eq!(witness.record_count(), u64::try_from(set.record_count())?);
    assert_eq!(witness.output_count(), u64::try_from(set.len())?);
    assert_eq!(witness.record_count(), 2);
    assert_eq!(witness.output_count(), 3);
    assert!(!witness.is_decoded());
    Ok(())
}

#[test]
fn witnessed_read_accepts_exact_and_raw_traversal_replays_coins()
-> Result<(), Box<dyn std::error::Error>> {
    let (set, tip, height) = fixture_set()?;
    let mut bytes = Vec::new();
    let (_, writer_observer, witness) =
        write_snapshot_witnessed(&set, &tip, height, &mut bytes, RecordingObserver::default())?;
    let witness = witness.ok_or("valid encode must mint a witness")?;

    let mut file = file_with(&bytes)?;
    let (load, reader_observer, read_witness) =
        read_snapshot_strict_v4_witnessed(&mut file, RecordingObserver::default())?;
    assert_eq!(load.tip_hash, tip);
    assert_eq!(load.height, height);
    assert_eq!(reader_observer.coins, writer_observer.coins);
    assert!(read_witness.is_decoded());
    assert_eq!(read_witness.byte_len(), witness.byte_len());
    assert_eq!(read_witness.sha256(), witness.sha256());
    assert_eq!(read_witness.record_count(), 2);
    assert_eq!(read_witness.output_count(), 3);

    // Seal the SAME descriptor the strict load consumed (cursor sits at EOF);
    // traversal seeks it back internally.
    let mut artifact = VerifiedSnapshotArtifact::seal(
        file,
        read_witness,
        SeedProvenance::AssumeUtxoArchive {
            base: tip.to_le_bytes(),
        },
    );
    assert_eq!(artifact.tip(), (height, tip));

    // File order is encode order: compare without sorting.
    let expected: Vec<RawCoin> = writer_observer
        .coins
        .iter()
        .map(|coin| RawCoin {
            txid: coin.txid.to_le_bytes(),
            vout: coin.vout,
            script_pubkey: coin.script_pubkey.clone(),
        })
        .collect();
    assert_eq!(raw_projection(&mut artifact)?, expected);
    Ok(())
}

fn v4_header(tip_hash: Hash256, height: u32, record_count: u64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(52);
    bytes.extend_from_slice(&0x55_54_58_4f_u32.to_le_bytes());
    bytes.extend_from_slice(&4_u32.to_le_bytes());
    bytes.extend_from_slice(&tip_hash.to_le_bytes());
    bytes.extend_from_slice(&height.to_le_bytes());
    bytes.extend_from_slice(&record_count.to_le_bytes());
    bytes
}

fn v4_record_body(txid_bytes: &[u8; 32], output_count: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(txid_bytes[0]);
    bytes.extend_from_slice(&txid_bytes[..8]);
    bytes.extend_from_slice(txid_bytes);
    bytes.extend_from_slice(&output_count.to_le_bytes());
    bytes
}

fn append_snapshot_output(
    bytes: &mut Vec<u8>,
    vout: u32,
    value: u64,
    height: u32,
    coinbase: bool,
    script_pubkey: &[u8],
) {
    let script_len = u16::try_from(script_pubkey.len()).unwrap_or(u16::MAX);
    bytes.extend_from_slice(&vout.to_le_bytes());
    bytes.extend_from_slice(&value.to_le_bytes());
    bytes.extend_from_slice(&height.to_le_bytes());
    bytes.push(u8::from(coinbase));
    bytes.extend_from_slice(&script_len.to_le_bytes());
    bytes.extend_from_slice(script_pubkey);
}

#[test]
fn strict_loader_rejects_malformed_without_witness() -> Result<(), Box<dyn std::error::Error>> {
    let (good, _) = encoded_witnessed()?;
    assert!(
        read_snapshot_strict_v4_witnessed(&mut Cursor::new(good.clone()), ()).is_ok(),
        "fixture must load before it can anchor malformed variants"
    );

    let mut bad_magic = v4_header(txid(1), 100, 0);
    bad_magic[0] ^= 0xff;
    let mut bad_version = v4_header(txid(1), 100, 0);
    bad_version[4] = 9;

    let duplicate_vout = {
        let mut bytes = v4_header(txid(2), 200, 1);
        bytes.extend_from_slice(&v4_record_body(&txid(3).to_le_bytes(), 2));
        append_snapshot_output(&mut bytes, 5, 1_000, 200, false, &[0x51]);
        append_snapshot_output(&mut bytes, 5, 2_000, 200, false, &[0x51]);
        bytes.extend_from_slice(&[0_u8; 384]);
        bytes
    };
    let duplicate_txid = {
        let record_txid = txid(4);
        let mut bytes = v4_header(txid(5), 300, 2);
        for vout in [0_u32, 1] {
            bytes.extend_from_slice(&v4_record_body(&record_txid.to_le_bytes(), 1));
            append_snapshot_output(&mut bytes, vout, 1_000, 300, false, &[0x51]);
        }
        bytes.extend_from_slice(&[0_u8; 384]);
        bytes
    };
    let empty_record = {
        let mut bytes = v4_header(txid(6), 400, 1);
        bytes.extend_from_slice(&v4_record_body(&txid(7).to_le_bytes(), 0));
        bytes.extend_from_slice(&[0_u8; 384]);
        bytes
    };
    let mut trailing_byte = good.clone();
    trailing_byte.push(0xAA);

    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("bad magic", bad_magic),
        ("bad version", bad_version),
        ("duplicate vout", duplicate_vout),
        ("duplicate txid", duplicate_txid),
        ("empty record", empty_record),
        ("empty input", Vec::new()),
        ("truncated trailer", good[..good.len() - 1].to_vec()),
        ("trailing byte", trailing_byte),
    ];
    for (name, bytes) in &cases {
        assert!(
            read_snapshot_strict_v4(&mut Cursor::new(bytes.clone())).is_err(),
            "{name} was accepted by the plain loader"
        );
        assert!(
            read_snapshot_strict_v4_witnessed(&mut Cursor::new(bytes.clone()), ()).is_err(),
            "{name} minted a witness"
        );
    }
    Ok(())
}

#[test]
fn tampered_or_truncated_artifact_yields_integrity() -> Result<(), Box<dyn std::error::Error>> {
    let (bytes, witness) = encoded_witnessed()?;
    // Record layout: 52-byte header, 45-byte record header, 19-byte vout
    // header, then the first script byte.
    let first_script = 52 + 45 + 19;

    let mut header_tip = bytes.clone();
    header_tip[10] ^= 0x01;
    let mut script_byte = bytes.clone();
    script_byte[first_script] ^= 0x01;
    let mut trailer_byte = bytes.clone();
    let trailer_at = trailer_byte.len() - 10;
    trailer_byte[trailer_at] ^= 0x01;
    // The script flip still parses (script bytes are opaque), proving the
    // rejection below comes from the byte binding rather than the parser.
    assert!(
        read_snapshot_strict_v4(&mut Cursor::new(script_byte.clone())).is_ok(),
        "script-flip fixture must still parse so the binding does the work"
    );

    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("header tip flip", header_tip),
        ("script byte flip", script_byte),
        ("trailer byte flip", trailer_byte),
        ("one byte truncated", bytes[..bytes.len() - 1].to_vec()),
        ("half truncated", bytes[..bytes.len() / 2].to_vec()),
        ("trailing byte", {
            let mut extra = bytes.clone();
            extra.push(0x00);
            extra
        }),
    ];
    for (name, tampered) in &cases {
        let file = file_with(tampered)?;
        let mut artifact = VerifiedSnapshotArtifact::seal(
            file,
            witness,
            SeedProvenance::AssumeUtxoArchive { base: [7_u8; 32] },
        );
        assert!(
            matches!(raw_projection(&mut artifact), Err(RawSeedError::Integrity)),
            "{name} did not yield Integrity"
        );
    }
    Ok(())
}

#[test]
fn same_fd_pins_bytes_despite_path_replace() -> Result<(), Box<dyn std::error::Error>> {
    let (bytes, _) = encoded_witnessed()?;
    let (set, tip, height) = fixture_set()?;
    let mut canonical = Vec::new();
    let (_, writer_seen, _) = write_snapshot_witnessed(
        &set,
        &tip,
        height,
        &mut canonical,
        RecordingObserver::default(),
    )?;
    assert_eq!(canonical, bytes);
    let expected: Vec<RawCoin> = writer_seen
        .coins
        .iter()
        .map(|coin| RawCoin {
            txid: coin.txid.to_le_bytes(),
            vout: coin.vout,
            script_pubkey: coin.script_pubkey.clone(),
        })
        .collect();

    let dir = tempfile::tempdir()?;
    let path = dir.path().join("coins.dat");
    std::fs::write(&path, &bytes)?;
    let mut file = std::fs::File::open(&path)?;
    let (_, (), witness) = read_snapshot_strict_v4_witnessed(&mut file, ())?;
    let mut artifact = VerifiedSnapshotArtifact::seal(
        file,
        witness,
        SeedProvenance::AssumeUtxoArchive { base: [9_u8; 32] },
    );

    // Atomic replace (the publication-cleanup shape): the path now resolves to
    // a new inode, while the sealed descriptor keeps reading the old bytes.
    let garbage = vec![0x5A_u8; bytes.len()];
    assert!(
        read_snapshot_strict_v4(&mut Cursor::new(garbage.clone())).is_err(),
        "replacement bytes must not parse as a snapshot"
    );
    let swap_path = dir.path().join("coins.dat.swap");
    std::fs::write(&swap_path, &garbage)?;
    std::fs::rename(&swap_path, &path)?;

    assert_eq!(raw_projection(&mut artifact)?, expected);
    Ok(())
}

#[test]
fn grown_file_after_seal_yields_integrity() -> Result<(), Box<dyn std::error::Error>> {
    let (bytes, witness) = encoded_witnessed()?;
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("coins.dat");
    std::fs::write(&path, &bytes)?;
    let file = std::fs::File::open(&path)?;
    let mut artifact = VerifiedSnapshotArtifact::seal(
        file,
        witness,
        SeedProvenance::AssumeUtxoArchive { base: [13_u8; 32] },
    );

    // Concurrent growth through the path must neither extend the work nor
    // validate: the capped traversal rejects the artifact.
    let mut grown = std::fs::OpenOptions::new().append(true).open(&path)?;
    grown.write_all(&[0xAA_u8; 1024])?;
    drop(grown);

    assert!(matches!(
        raw_projection(&mut artifact),
        Err(RawSeedError::Integrity)
    ));
    Ok(())
}

#[test]
fn emit_failure_aborts_as_emit() -> Result<(), Box<dyn std::error::Error>> {
    #[derive(Debug)]
    struct Boom;

    impl std::fmt::Display for Boom {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("boom")
        }
    }

    let (bytes, witness) = encoded_witnessed()?;
    let file = file_with(&bytes)?;
    let mut artifact = VerifiedSnapshotArtifact::seal(
        file,
        witness,
        SeedProvenance::Checkpoint(CheckpointReference {
            generation: 11,
            manifest_sha256: [12_u8; 32],
        }),
    );
    let mut calls = 0_u64;
    let result = artifact.for_each_coin_raw(
        &mut |_: &OutPoint, _: &[u8]| {
            calls += 1;
            Err(Boom)
        },
        &|| false,
    );
    assert!(matches!(result, Err(RawSeedError::Emit(Boom))));
    assert_eq!(calls, 1);
    Ok(())
}

#[test]
fn empty_snapshot_mints_and_traverses_zero_coins() -> Result<(), Box<dyn std::error::Error>> {
    let set = bitcoin_rs_utxo::UtxoSet::new();
    let tip = txid(99);
    let mut bytes = Vec::new();
    let (_, (), witness) = write_snapshot_witnessed(&set, &tip, 0, &mut bytes, ())?;
    let witness = witness.ok_or("empty encode must mint a witness")?;
    assert_eq!(witness.record_count(), 0);
    assert_eq!(witness.output_count(), 0);
    assert_eq!(witness.byte_len(), u64::try_from(bytes.len())?);

    let (load, (), read_witness) = read_snapshot_strict_v4_witnessed(&mut Cursor::new(&bytes), ())?;
    assert_eq!(load.set.record_count(), 0);

    let file = file_with(&bytes)?;
    let mut artifact = VerifiedSnapshotArtifact::seal(
        file,
        read_witness,
        SeedProvenance::Checkpoint(CheckpointReference {
            generation: 3,
            manifest_sha256: [4_u8; 32],
        }),
    );
    let mut count = 0_u64;
    artifact.for_each_coin_raw(
        &mut |_: &OutPoint, _: &[u8]| {
            count += 1;
            Ok::<(), Infallible>(())
        },
        &|| false,
    )?;
    assert_eq!(count, 0);
    Ok(())
}

fn tiny_artifact(
    tip_seed: u64,
    base_byte: u8,
) -> Result<VerifiedSnapshotArtifact, Box<dyn std::error::Error>> {
    let set = bitcoin_rs_utxo::UtxoSet::new();
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(
        OutPoint::new(txid(tip_seed).into(), 0),
        txout(tip_seed + 1),
        false,
        10,
    ));
    commit_block_changes(&set, &changes, &txid(tip_seed + 2))?;
    let tip = txid(tip_seed + 3);
    let mut bytes = Vec::new();
    let (_, (), witness) = write_snapshot_witnessed(&set, &tip, 11, &mut bytes, ())?;
    let witness = witness.ok_or("tiny encode must mint a witness")?;
    let file = file_with(&bytes)?;
    Ok(VerifiedSnapshotArtifact::seal(
        file,
        witness,
        SeedProvenance::AssumeUtxoArchive {
            base: [base_byte; 32],
        },
    ))
}

#[test]
fn offer_without_demand_is_skipped_and_stores_nothing() -> Result<(), Box<dyn std::error::Error>> {
    let cell = SeedSlot::new();
    assert!(!cell.is_wanted());
    assert!(matches!(
        cell.offer(tiny_artifact(21, 21)?),
        OfferOutcome::Skipped
    ));
    assert!(cell.take().is_none());
    assert!(!cell.is_wanted());
    Ok(())
}

#[test]
fn first_offer_wins_take_clears_demand() -> Result<(), Box<dyn std::error::Error>> {
    let cell = SeedSlot::new();
    cell.want();
    assert!(cell.is_wanted());
    assert!(matches!(
        cell.offer(tiny_artifact(31, 31)?),
        OfferOutcome::Stored
    ));
    assert!(!cell.is_wanted());
    assert!(matches!(
        cell.offer(tiny_artifact(32, 32)?),
        OfferOutcome::Skipped
    ));

    let mut taken = cell.take().ok_or("queued artifact missing")?;
    assert_eq!(taken.tip(), (11, txid(34)));
    assert!(cell.take().is_none());
    assert!(!cell.is_wanted());
    assert!(matches!(
        cell.offer(tiny_artifact(33, 33)?),
        OfferOutcome::Skipped
    ));

    // The winner survived the loser's close: its bytes still traverse.
    let mut count = 0_u64;
    taken.for_each_coin_raw(
        &mut |_: &OutPoint, _: &[u8]| {
            count += 1;
            Ok::<(), Infallible>(())
        },
        &|| false,
    )?;
    assert_eq!(count, 1);
    Ok(())
}

#[test]
fn rest_drops_artifact_and_demand() -> Result<(), Box<dyn std::error::Error>> {
    let cell = SeedSlot::new();
    assert!(cell.take().is_none());
    cell.want();
    cell.want();
    assert!(cell.is_wanted());
    assert!(cell.take().is_none());
    assert!(cell.is_wanted());
    cell.rest();
    assert!(!cell.is_wanted());
    assert!(cell.take().is_none());

    cell.want();
    assert!(matches!(
        cell.offer(tiny_artifact(41, 41)?),
        OfferOutcome::Stored
    ));
    cell.rest();
    assert!(cell.take().is_none());
    assert!(!cell.is_wanted());
    Ok(())
}

#[test]
fn cell_handles_are_thread_shareable() {
    fn assert_send_sync<T: Send + Sync>() {}
    fn assert_send<T: Send>() {}
    assert_send_sync::<SeedSlot>();
    assert_send_sync::<SeedOfferCell>();
    assert_send::<VerifiedSnapshotArtifact>();
}

/// Cancellation is polled at entry and every 4,096 emitted coins; a trip
/// returns `Cancelled` with the bundle intact so the caller can retry.
#[test]
fn seed_traversal_polls_cancellation_every_4096_coins() -> Result<(), Box<dyn std::error::Error>> {
    let set = bitcoin_rs_utxo::UtxoSet::new();
    let mut changes = BlockChanges::default();
    for i in 0..9_000_u64 {
        changes.add(UtxoAdd::new(
            OutPoint::new(txid(200_000 + i).into(), 0),
            txout(i),
            false,
            1,
        ));
    }
    commit_block_changes(&set, &changes, &txid(199_999))?;
    let tip = txid(200_001);
    let mut bytes = Vec::new();
    let (_, (), witness) = write_snapshot_witnessed(&set, &tip, 7, &mut bytes, ())?;
    let witness = witness.ok_or("valid encode must mint a witness")?;
    let mut file = file_with(&bytes)?;
    let (_, (), read_witness) = read_snapshot_strict_v4_witnessed(&mut file, ())?;
    let mut artifact = VerifiedSnapshotArtifact::seal(
        file,
        read_witness,
        SeedProvenance::Checkpoint(CheckpointReference {
            generation: 3,
            manifest_sha256: [4_u8; 32],
        }),
    );
    assert_eq!(witness.sha256(), read_witness.sha256());

    // Immediate cancellation emits nothing.
    let mut count = 0_u64;
    let immediate = artifact.for_each_coin_raw(
        &mut |_: &OutPoint, _: &[u8]| {
            count += 1;
            Ok::<(), Infallible>(())
        },
        &|| true,
    );
    assert!(
        matches!(immediate, Err(RawSeedError::Cancelled)),
        "entry poll must stop before any emit: {immediate:?}"
    );
    assert_eq!(count, 0, "a cancelled entry must not traverse");

    // Mid-stream cancellation stops at the next 4,096 boundary with a
    // partial traversal and no integrity verdict.
    let seen = std::cell::Cell::new(0_u64);
    let mut emitted = 0_u64;
    let mid = artifact.for_each_coin_raw(
        &mut |_: &OutPoint, _: &[u8]| {
            seen.set(seen.get() + 1);
            emitted += 1;
            Ok::<(), Infallible>(())
        },
        &|| seen.get() >= 5_000,
    );
    assert!(
        matches!(mid, Err(RawSeedError::Cancelled)),
        "mid-stream stop must report cancellation: {mid:?}"
    );
    assert!(
        (4_096..9_000).contains(&emitted),
        "cancellation must stop at a poll boundary with partial work: {emitted}"
    );

    // Without cancellation the same descriptor traverses every coin.
    let mut all = 0_u64;
    artifact.for_each_coin_raw(
        &mut |_: &OutPoint, _: &[u8]| {
            all += 1;
            Ok::<(), Infallible>(())
        },
        &|| false,
    )?;
    assert_eq!(all, 9_000, "retry after cancellation must replay all coins");
    Ok(())
}
