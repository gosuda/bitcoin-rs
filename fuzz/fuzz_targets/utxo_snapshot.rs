#![no_main]

use std::io::Cursor;

use bitcoin_rs_primitives::Network;
use bitcoin_rs_utxo::core_snapshot::{
    CoreV2Base, SnapshotLimits, read_and_verify, read_metadata, write_core_v2,
};
use libfuzzer_sys::fuzz_target;

const CORE_FIXTURE: &[u8] = include_bytes!("../../crates/utxo/tests/fixtures/core-v2/core200.dat");
const CORE_HEADER_BYTES: usize = 51;

fuzz_target!(|data: &[u8]| {
    let s1 = bitcoin_rs_utxo::read_snapshot_strict_v4_observed(&mut Cursor::new(data), ());
    let s2 = bitcoin_rs_utxo::read_snapshot_strict_v4_observed(&mut Cursor::new(data), ());
    assert_eq!(s1.is_ok(), s2.is_ok(), "read_snapshot_strict_v4 determinism status");
    if let (Ok((snap1, ())), Ok((snap2, ()))) = (&s1, &s2) {
        assert_eq!(snap1.tip_hash, snap2.tip_hash, "strict v4 tip_hash determinism");
        assert_eq!(snap1.height, snap2.height, "strict v4 height determinism");
        let accounted = snap1.set.with_stable_view(|view| view.memory_report().accounted_bytes());
        assert!(
            accounted <= data.len().saturating_mul(128) + 65536,
            "strict v4 memory amplification: {accounted} bytes for {len} bytes input",
            len = data.len()
        );

        let mut re_written = Vec::new();
        if bitcoin_rs_utxo::write_snapshot_witnessed(
            &snap1.set,
            &snap1.tip_hash,
            snap1.height,
            &mut re_written,
            (),
        ).is_ok() {
            let re_load = bitcoin_rs_utxo::read_snapshot_strict_v4(&mut Cursor::new(&re_written))
                .expect("re-encoded strict v4 snapshot must decode");
            assert_eq!(re_load.tip_hash, snap1.tip_hash, "strict v4 round-trip tip_hash");
            assert_eq!(re_load.height, snap1.height, "strict v4 round-trip height");
        }
    }

    let m1 = read_metadata(&mut Cursor::new(data));
    let m2 = read_metadata(&mut Cursor::new(data));
    assert_eq!(
        format!("{m1:?}"),
        format!("{m2:?}"),
        "read_metadata determinism"
    );

    let limits = SnapshotLimits {
        max_file_bytes: 1024 * 1024,
        max_coins: 1000,
        max_script_bytes: 100_000,
        max_coins_per_txid: 1000,
    };

    let v1 = read_and_verify(&mut Cursor::new(data), Network::Regtest, limits);
    let v2 = read_and_verify(&mut Cursor::new(data), Network::Regtest, limits);
    assert_eq!(v1.is_ok(), v2.is_ok(), "read_and_verify determinism status");
    if let (Ok(snap1), Ok(snap2)) = (&v1, &v2) {
        assert_eq!(snap1.hash_serialized, snap2.hash_serialized, "core v2 hash determinism");
        assert_eq!(snap1.metadata, snap2.metadata, "core v2 metadata determinism");
        assert_eq!(snap1.bytes_read, snap2.bytes_read, "core v2 bytes_read determinism");

        let accounted = snap1.set.with_stable_view(|view| view.memory_report().accounted_bytes());
        assert!(
            accounted <= data.len().saturating_mul(128) + 65536,
            "core v2 memory amplification: {accounted} bytes for {len} bytes input",
            len = data.len()
        );

        let base = CoreV2Base {
            network: Network::Regtest,
            base_hash: snap1.metadata.base_block_hash,
            base_height: snap1.anchor.height,
            coins_count: snap1.metadata.coins_count,
        };
        let mut re_written = Vec::new();
        if snap1.set.with_stable_view(|view| {
            write_core_v2(view, &base, &mut re_written, &|| false)
        }).is_ok() {
            let re_snap = read_and_verify(&mut Cursor::new(&re_written), Network::Regtest, limits)
                .expect("re-encoded core v2 snapshot must decode");
            assert_eq!(re_snap.hash_serialized, snap1.hash_serialized, "core v2 round-trip hash");
            assert_eq!(re_snap.metadata, snap1.metadata, "core v2 round-trip metadata");
        }
    }

    let mut mutated = CORE_FIXTURE.to_vec();
    for &[low, high, xor] in data.as_chunks::<3>().0.iter().take(256) {
        let offset =
            usize::from(u16::from_le_bytes([low, high])) % (mutated.len() - CORE_HEADER_BYTES);
        mutated[CORE_HEADER_BYTES + offset] ^= xor;
    }
    let m_r1 = read_and_verify(&mut Cursor::new(&mutated), Network::Regtest, limits);
    let m_r2 = read_and_verify(&mut Cursor::new(&mutated), Network::Regtest, limits);
    assert_eq!(m_r1.is_ok(), m_r2.is_ok(), "mutated fixture determinism");
});
