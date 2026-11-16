use std::io::{Cursor, Seek, Write};

use crate::support::utxo::{TestError, TestResult};
use bitcoin_rs_consensus::primitives::{Amount, Hash256, TxOut};
use bitcoin_rs_storage::utxo::{
    SeedProvenance, SnapshotCoin, SnapshotCoinObserver, read_snapshot_strict_v4,
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

fn fixture_set() -> TestResult<(bitcoin_rs_storage::utxo::UtxoSet, Hash256, u32)> {
    let set = bitcoin_rs_storage::utxo::UtxoSet::new();
    let first = txid(7_001);
    let second = txid(7_002);
    let out1 = bitcoin_rs_storage::utxo::record::OwnedUtxoOut {
        vout: 0,
        value: txout(7_010).value.to_sat(),
        script_pubkey: txout(7_010).script_pubkey.to_vec(),
        coinbase: false,
        height: 100,
    };
    let out2 = bitcoin_rs_storage::utxo::record::OwnedUtxoOut {
        vout: 3,
        value: 7_011,
        script_pubkey: Vec::new(),
        coinbase: true,
        height: 101,
    };
    let out3 = bitcoin_rs_storage::utxo::record::OwnedUtxoOut {
        vout: 1,
        value: txout(7_012).value.to_sat(),
        script_pubkey: txout(7_012).script_pubkey.to_vec(),
        coinbase: false,
        height: 102,
    };
    let rec1 =
        bitcoin_rs_storage::utxo::record::UtxoRecord::from_owned_outputs(first, &[out1, out2])?;
    let rec2 = bitcoin_rs_storage::utxo::record::UtxoRecord::from_owned_outputs(second, &[out3])?;
    set.insert_parsed_record(rec1);
    set.insert_parsed_record(rec2);
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

fn encoded_witnessed() -> TestResult<(Vec<u8>, bitcoin_rs_storage::utxo::V4Witness)> {
    let (set, tip, height) = fixture_set()?;
    let mut bytes = Vec::new();
    let (_, (), witness) = write_snapshot_witnessed(&set, &tip, height, &mut bytes, ())?;
    let witness = witness.ok_or(TestError::Missing("valid encode must mint a witness"))?;
    Ok((bytes, witness))
}

fn file_with(bytes: &[u8]) -> TestResult<std::fs::File> {
    let mut file = tempfile::tempfile()?;
    file.write_all(bytes)?;
    file.rewind()?;
    Ok(file)
}

#[test]
fn witnessed_write_matches_plain_bytes_and_mints_exact_witness() -> TestResult {
    let (set, tip, height) = fixture_set()?;
    let mut plain = Vec::new();
    let (plain_trailer, ()) = write_snapshot_observed(&set, &tip, height, &mut plain, ())?;
    let mut witnessed = Vec::new();
    let (witness_trailer, (), witness) =
        write_snapshot_witnessed(&set, &tip, height, &mut witnessed, ())?;

    assert_eq!(plain, witnessed);
    assert_eq!(plain_trailer, witness_trailer);
    let witness = witness.ok_or(TestError::Missing("valid encode must mint a witness"))?;
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
fn witnessed_read_accepts_exact_bytes_and_replays_the_same_coins() -> TestResult {
    let (set, tip, height) = fixture_set()?;
    let mut bytes = Vec::new();
    let (_, writer_observer, witness) =
        write_snapshot_witnessed(&set, &tip, height, &mut bytes, RecordingObserver::default())?;
    let witness = witness.ok_or(TestError::Missing("valid encode must mint a witness"))?;

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

    let artifact = bitcoin_rs_storage::utxo::VerifiedSnapshotArtifact::seal(
        read_witness,
        SeedProvenance::AssumeUtxoArchive {
            base: tip.to_le_bytes(),
        },
    );
    assert_eq!(artifact.tip(), (height, tip));
    assert_eq!(
        artifact.provenance(),
        SeedProvenance::AssumeUtxoArchive {
            base: tip.to_le_bytes()
        }
    );
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
fn strict_loader_rejects_malformed_without_witness() -> TestResult {
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
fn empty_snapshot_mints_witness_and_decodes_zero_coins() -> TestResult {
    let set = bitcoin_rs_storage::utxo::UtxoSet::new();
    let tip = txid(99);
    let mut bytes = Vec::new();
    let (_, (), witness) = write_snapshot_witnessed(&set, &tip, 0, &mut bytes, ())?;
    let witness = witness.ok_or(TestError::Missing("empty encode must mint a witness"))?;
    assert_eq!(witness.record_count(), 0);
    assert_eq!(witness.output_count(), 0);
    assert_eq!(witness.byte_len(), u64::try_from(bytes.len())?);

    let (load, (), _) = read_snapshot_strict_v4_witnessed(&mut Cursor::new(&bytes), ())?;
    assert_eq!(load.set.record_count(), 0);
    Ok(())
}
