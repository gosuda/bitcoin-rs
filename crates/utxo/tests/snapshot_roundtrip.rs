//! Contract coverage for the native version-4 UTXO snapshot format.

use std::io::{Cursor, Seek};

use bitcoin_rs_primitives::{Amount, Hash256, OutPoint, Script, TxOut};
use bitcoin_rs_utxo::contract::{BlockChanges, UtxoAdd};
use bitcoin_rs_utxo::{
    SnapshotCoin, SnapshotCoinObserver, UtxoError, UtxoSet, read_snapshot_strict_v4,
    read_snapshot_strict_v4_observed, write_snapshot_observed,
};
use tempfile::tempfile;

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

#[test]
fn snapshot_roundtrip_preserves_vout_and_metadata_boundaries()
-> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let live_txid = txid(42_000);
    let low = OutPoint::new(live_txid.into(), 63);
    let high = OutPoint::new(live_txid.into(), 64);
    let max = OutPoint::new(live_txid.into(), u32::MAX);
    let low_txout = txout(42_001);
    let high_txout = txout(42_002);
    let max_txout = TxOut {
        value: Amount::from_sat(42_003),
        script_pubkey: Script::new(),
    };
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(low, low_txout.clone(), false, 400));
    changes.add(UtxoAdd::new(high, high_txout.clone(), true, 401));
    changes.add(UtxoAdd::new(max, max_txout.clone(), false, u32::MAX));
    bitcoin_rs_utxo::contract::commit_block_changes(&set, &changes, &txid(42_004))?;

    let expected_hash = set.lock_stable_view().hash_serialized_3()?;
    let mut file = tempfile()?;
    write_snapshot_observed(&set, &txid(42_005), u32::MAX, &mut file, ())?;
    file.rewind()?;
    let loaded = read_snapshot_strict_v4(&mut file)?;

    assert_eq!(loaded.tip_hash, txid(42_005));
    assert_eq!(loaded.height, u32::MAX);
    assert_eq!(loaded.set.get(&low), Some(low_txout));
    assert_eq!(loaded.set.get(&high), Some(high_txout));
    assert_eq!(loaded.set.get(&max), Some(max_txout));
    assert_eq!(
        loaded.set.lock_stable_view().hash_serialized_3()?,
        expected_hash
    );
    assert!(
        !loaded
            .set
            .get_entry(&low)
            .ok_or("missing low entry")?
            .coinbase
    );
    assert!(
        loaded
            .set
            .get_entry(&high)
            .ok_or("missing high entry")?
            .coinbase
    );
    assert_eq!(
        loaded
            .set
            .get_entry(&max)
            .ok_or("missing max entry")?
            .height,
        u32::MAX
    );
    Ok(())
}

#[test]
fn strict_v4_snapshot_requires_complete_exact_input() -> Result<(), Box<dyn std::error::Error>> {
    let mut snapshot = Vec::new();
    write_snapshot_observed(&UtxoSet::new(), &txid(64_100), 64, &mut snapshot, ())?;

    let loaded = read_snapshot_strict_v4(&mut Cursor::new(&snapshot))?;
    assert_eq!(loaded.tip_hash, txid(64_100));
    assert_eq!(loaded.height, 64);
    assert_eq!(loaded.muhash_trailer, [0_u8; 384]);

    assert!(read_snapshot_strict_v4(&mut Cursor::new(&snapshot[..snapshot.len() - 384])).is_err());
    assert!(read_snapshot_strict_v4(&mut Cursor::new(&snapshot[..snapshot.len() - 1])).is_err());

    let mut trailing = snapshot;
    trailing.push(0);
    assert!(read_snapshot_strict_v4(&mut Cursor::new(trailing)).is_err());
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SeenSnapshotCoin {
    txid: Hash256,
    vout: u32,
    value: u64,
    script_pubkey: Vec<u8>,
    height: u32,
    coinbase: bool,
}

#[derive(Default)]
struct RecordingSnapshotObserver {
    coins: Vec<SeenSnapshotCoin>,
    replacement_trailer: Option<[u8; 384]>,
    trailer_calls: usize,
}

impl SnapshotCoinObserver for RecordingSnapshotObserver {
    fn observe_coin(&mut self, coin: SnapshotCoin<'_>) {
        self.coins.push(SeenSnapshotCoin {
            txid: coin.txid,
            vout: coin.vout,
            value: coin.value,
            script_pubkey: coin.script_pubkey.to_vec(),
            height: coin.height,
            coinbase: coin.coinbase,
        });
    }

    fn select_trailer(&mut self, fallback: [u8; 384]) -> [u8; 384] {
        self.trailer_calls += 1;
        self.replacement_trailer.unwrap_or(fallback)
    }
}

#[test]
fn observed_snapshot_traversal_matches_the_current_reader() -> Result<(), Box<dyn std::error::Error>>
{
    let set = UtxoSet::new();
    let first_txid = txid(200_000);
    let second_txid = txid(200_001);
    let first = txout(200_010);
    let second = TxOut {
        value: Amount::from_sat(200_011),
        script_pubkey: Script::new(),
    };
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(
        OutPoint::new(first_txid.into(), 0),
        first,
        false,
        2000,
    ));
    changes.add(UtxoAdd::new(
        OutPoint::new(first_txid.into(), 9),
        second,
        true,
        2001,
    ));
    changes.add(UtxoAdd::new(
        OutPoint::new(second_txid.into(), 2),
        txout(200_012),
        false,
        2002,
    ));
    bitcoin_rs_utxo::contract::commit_block_changes(&set, &changes, &txid(200_002))?;

    let mut ordinary = Vec::new();
    let (ordinary_trailer, ()) =
        write_snapshot_observed(&set, &txid(200_003), 2002, &mut ordinary, ())?;
    let mut observed = Vec::new();
    let (observed_trailer, writer_observer) = write_snapshot_observed(
        &set,
        &txid(200_003),
        2002,
        &mut observed,
        RecordingSnapshotObserver::default(),
    )?;

    assert_eq!(observed, ordinary);
    assert_eq!(observed_trailer, ordinary_trailer);
    assert_eq!(writer_observer.trailer_calls, 1);
    assert_eq!(writer_observer.coins.len(), 3);

    let (_, reader_observer) = read_snapshot_strict_v4_observed(
        &mut Cursor::new(&observed),
        RecordingSnapshotObserver::default(),
    )?;
    assert_eq!(reader_observer.coins, writer_observer.coins);
    Ok(())
}

#[test]
fn snapshot_trailer_round_trips_without_a_listener() -> Result<(), Box<dyn std::error::Error>> {
    // With no coinstats attached, the writer falls back to the zero trailer
    // and the strict reader round-trips exactly those bytes.
    let set = UtxoSet::new();

    let op = OutPoint::new(txid(130_000).into(), 0);
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(op, txout(130_001), false, 900));
    bitcoin_rs_utxo::contract::commit_block_changes(&set, &changes, &txid(130_099))?;

    let mut file = tempfile()?;
    let (returned_trailer, ()) = write_snapshot_observed(&set, &txid(130_100), 900, &mut file, ())?;
    assert_eq!(returned_trailer, [0_u8; 384]);
    file.rewind()?;
    let loaded = read_snapshot_strict_v4(&mut file)?;
    assert_eq!(loaded.muhash_trailer, [0_u8; 384]);
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

/// Every way a v4 snapshot can be malformed, with the error each must name.
#[test]
fn snapshot_read_refuses_malformed_v4_bytes() {
    type Expected = fn(&UtxoError) -> bool;
    let duplicate_vouts = {
        let mut bytes = v4_header(txid(160_011), 1601, 1);
        bytes.extend_from_slice(&v4_record_body(&txid(160_010).to_le_bytes(), 4));
        for vout in [9, 1, 9, 1] {
            append_snapshot_output(&mut bytes, vout, 1_000, 1601, false, &[0x51]);
        }
        bytes.extend_from_slice(&[0_u8; 384]);
        bytes
    };
    let mut invalid_magic = v4_header(txid(1), 100, 0);
    invalid_magic[0..4].copy_from_slice(&0xDE_AD_BE_EF_u32.to_le_bytes());
    let mut count_mismatch = v4_header(txid(170_001), 1700, 1);
    count_mismatch.extend_from_slice(&v4_record_body(&txid(170_000).to_le_bytes(), 0));
    count_mismatch.extend_from_slice(&[0_u8; 384]);

    let cases: [(&str, Vec<u8>, Expected); 3] = [
        (
            "invalid magic",
            invalid_magic,
            |error| matches!(error, UtxoError::InvalidSnapshotMagic { actual } if *actual == 0xDE_AD_BE_EF),
        ),
        ("duplicate vout", duplicate_vouts, |error| {
            matches!(error, UtxoError::SnapshotDuplicateVout { vout: 9 })
        }),
        ("record count mismatch", count_mismatch, |error| {
            matches!(
                error,
                UtxoError::SnapshotRecordCountMismatch {
                    declared: 1,
                    actual: 0
                }
            )
        }),
    ];
    for version in [2_u32, 3, 99] {
        let mut bytes = v4_header(txid(1), 100, 0);
        bytes[4..8].copy_from_slice(&version.to_le_bytes());
        let Err(error) = read_snapshot_strict_v4(&mut Cursor::new(bytes)) else {
            panic!("unsupported version {version} was accepted");
        };
        assert!(
            matches!(error, UtxoError::UnsupportedSnapshotVersion { version: actual } if actual == version)
        );
    }
    for (name, bytes, expected) in cases {
        let Err(error) = read_snapshot_strict_v4(&mut Cursor::new(bytes)) else {
            panic!("{name} was accepted");
        };
        assert!(expected(&error), "{name} gave {error:?}");
    }
}

#[test]
fn strict_v4_observer_is_dropped_on_error() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    struct DropObserver {
        dropped: Arc<AtomicBool>,
    }

    impl SnapshotCoinObserver for DropObserver {
        fn observe_coin(&mut self, _: SnapshotCoin<'_>) {}
    }

    impl Drop for DropObserver {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    let record_txid = txid(180_000);
    let mut bytes = v4_header(txid(180_001), 1800, 2);
    for vout in 0..2 {
        bytes.extend_from_slice(&v4_record_body(&record_txid.to_le_bytes(), 1));
        append_snapshot_output(
            &mut bytes,
            vout,
            4_000 + u64::from(vout),
            1800,
            false,
            &[0x51],
        );
    }
    bytes.extend_from_slice(&[0_u8; 384]);

    let dropped = Arc::new(AtomicBool::new(false));
    let result = read_snapshot_strict_v4_observed(
        &mut Cursor::new(bytes),
        DropObserver {
            dropped: Arc::clone(&dropped),
        },
    );
    assert!(matches!(
        result,
        Err(UtxoError::SnapshotRecordCountMismatch { .. })
    ));
    assert!(dropped.load(Ordering::SeqCst));
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
