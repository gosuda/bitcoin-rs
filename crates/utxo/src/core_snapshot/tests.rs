//! Independent Core encodings and fail-closed resource contracts.
#![allow(clippy::expect_used)]

use std::io::{self, Cursor, Read};

use bitcoin_rs_primitives::{Hash256, Network, OutPoint, varint};

use super::{
    Decoder, SnapshotError, SnapshotLimits, read_and_verify, read_metadata, write_core_v2,
};
use crate::record::{OwnedUtxoOut, UtxoRecord};

const CORE: &[u8] = include_bytes!("../../tests/fixtures/core-v2/core200.dat");

fn hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = core::str::from_utf8(pair).expect("hex text");
            u8::from_str_radix(text, 16).expect("hex byte")
        })
        .collect()
}

// Used only to build corruption cases, never the independent positive fixtures.
fn core_varint(mut value: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        bytes.push(
            u8::try_from(value & 0x7f).expect("seven bits")
                | if bytes.is_empty() { 0 } else { 0x80 },
        );
        if value <= 0x7f {
            break;
        }
        value = (value >> 7) - 1;
    }
    bytes.reverse();
    bytes
}

fn script(bytes: &[u8]) -> Result<Vec<u8>, SnapshotError> {
    Decoder::new(&mut Cursor::new(bytes), 20_000).script(20_000)
}

fn body(bytes: &[u8], count: u64) -> Result<crate::UtxoSet, SnapshotError> {
    let (records, _) = Decoder::new(&mut Cursor::new(bytes), 1_000_000).coins(
        count,
        200,
        SnapshotLimits::default(),
    )?;
    let set = crate::UtxoSet::new();
    for record in records {
        set.insert_snapshot_record(record);
    }
    Ok(set)
}

fn group(txid: u8, indices: &[u64]) -> Vec<u8> {
    let mut bytes = vec![txid; 32];
    bytes.extend_from_slice(
        varint::encode(u64::try_from(indices.len()).expect("test index count")).as_slice(),
    );
    for index in indices {
        bytes.extend_from_slice(varint::encode(*index).as_slice());
        // Core Coin: height 1 + coinbase; compressed 50 BTC; raw OP_TRUE.
        bytes.extend_from_slice(&[3, 50, 7, 0x51]);
    }
    bytes
}

#[test]
fn genuine_core_dump_matches_compiled_anchor_and_full_state() {
    let loaded = read_and_verify(
        &mut Cursor::new(CORE),
        Network::Regtest,
        SnapshotLimits::default(),
    )
    .expect("Core-produced fixture");
    assert_eq!(loaded.metadata.coins_count, 200);
    assert_eq!(loaded.set.len(), 200);
    assert_eq!(loaded.anchor.height, 200);
    assert_eq!(loaded.anchor.chain_tx_count, 201);
    assert_eq!(loaded.hash_serialized, loaded.anchor.hash_serialized);
    assert_eq!(
        loaded
            .set
            .lock_stable_view()
            .hash_serialized_3()
            .expect("materialized commitment"),
        loaded.hash_serialized,
        "staging and stable-view traversals share the Core commitment",
    );
    assert_eq!(loaded.bytes_read, 14_439);
    assert_eq!(
        loaded.metadata.base_block_hash.to_string(),
        "385901ccbd69dff6bbd00065d01fb8a9e464dede7cfe0372443884f9b1dcf6b9"
    );
    assert_eq!(
        loaded.hash_serialized.to_string(),
        "17dcc016d188d16068907cdeb38b75691a118d43053b8cd6a25969419381d13a"
    );
    // Core reports 8725 BTC for the 149*50 + 51*25 regtest subsidy outputs.
    let total = loaded.set.with_stable_view(|view| {
        let mut total = 0_u64;
        view.for_each_all(|outpoint, _| {
            total += view
                .get_entry(outpoint)
                .expect("observed coin")
                .txout
                .value
                .to_sat();
        });
        total
    });
    assert_eq!(total, 872_500_000_000);
}

#[test]
fn inspection_reads_only_fixed_header_without_claiming_trust() {
    let mut input = Cursor::new(&CORE[..51]);
    let metadata = read_metadata(&mut input).expect("header without body");
    assert_eq!(input.position(), 51);
    assert_eq!(metadata.version, 2);
    assert_eq!(metadata.network_magic, Network::Regtest.magic());
    assert_eq!(metadata.coins_count, 200);
    let mut unpinned = CORE[..51].to_vec();
    unpinned[11..43].fill(0);
    assert_eq!(
        read_metadata(&mut Cursor::new(unpinned))
            .expect("untrusted header")
            .base_block_hash,
        Hash256::default()
    );
}

#[test]
fn core_varint_reference_boundaries_are_not_record_leb128() {
    // Core serialize.h's subtract-one MSB encoding, including its width transitions.
    for (bytes, expected) in [
        (vec![0], 0),
        (vec![0x7f], 127),
        (vec![0x80, 0], 128),
        (vec![0xff, 0x7f], 16_511),
        (vec![0x80, 0x80, 0], 16_512),
    ] {
        let actual = Decoder::new(&mut Cursor::new(&bytes), 10)
            .core_varint(u64::MAX)
            .expect("Core VARINT");
        assert_eq!(actual, expected);
    }
    assert!(matches!(
        Decoder::new(&mut Cursor::new([0xff; 10]), 10).core_varint(u64::MAX),
        Err(SnapshotError::VarIntOverflow)
    ));
    assert!(matches!(
        Decoder::new(&mut Cursor::new(core_varint(u64::from(u32::MAX) + 1)), 10)
            .core_varint(u64::from(u32::MAX)),
        Err(SnapshotError::VarIntOverflow)
    ));
}

#[test]
fn all_core_script_encodings_and_invalid_compressed_pubkeys_preserve_bytes() {
    // Core compressor.cpp / compress_tests.cpp: six special script encodings.
    let payload = vec![0x11; 20];
    for (code, prefix, suffix) in [
        (0, vec![0x76, 0xa9, 0x14], vec![0x88, 0xac]),
        (1, vec![0xa9, 0x14], vec![0x87]),
    ] {
        let mut encoded = vec![code];
        encoded.extend_from_slice(&payload);
        let mut expected = prefix;
        expected.extend_from_slice(&payload);
        expected.extend_from_slice(&suffix);
        assert_eq!(script(&encoded).expect("hash script"), expected);
    }
    for code in [2, 3] {
        let mut encoded = vec![code];
        encoded.extend_from_slice(&[0xff; 32]); // Not a curve point; Core preserves these bytes.
        let mut expected = vec![0x21, code];
        expected.extend_from_slice(&[0xff; 32]);
        expected.push(0xac);
        assert_eq!(
            script(&encoded).expect("opaque compressed pubkey"),
            expected
        );
    }
    // secp256k1 generator and its negation, fixed independent SEC encodings.
    let x = hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    for (code, y) in [
        (
            4,
            "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
        ),
        (
            5,
            "b7c52588d95c3b9aa25b0403f1eef75702e84bb7597aabe663b82f6f04ef2777",
        ),
    ] {
        let mut encoded = vec![code];
        encoded.extend_from_slice(&x);
        let mut expected = vec![0x41, 4];
        expected.extend_from_slice(&x);
        expected.extend_from_slice(&hex(y));
        expected.push(0xac);
        assert_eq!(
            script(&encoded).expect("uncompressed curve point"),
            expected
        );
        encoded[1..].fill(0xff);
        assert!(matches!(
            script(&encoded),
            Err(SnapshotError::InvalidPublicKey)
        ));
    }
    assert_eq!(script(&[6]).expect("empty script"), Vec::<u8>::new());
    assert_eq!(script(&[7, 0x51]).expect("raw script"), vec![0x51]);
    let mut maximum = core_varint(10_006);
    maximum.extend_from_slice(&vec![0x51; 10_000]);
    assert_eq!(script(&maximum).expect("maximum script").len(), 10_000);
    assert!(matches!(
        script(&core_varint(10_007)),
        Err(SnapshotError::InvalidScriptLength { length: 10_001 })
    ));
    for code in 0..=5 {
        assert!(matches!(
            script(&[code]),
            Err(SnapshotError::Truncated { .. })
        ));
    }
}

#[test]
fn coin_count_is_outputs_not_transaction_records() {
    let set = body(&group(1, &[0, 2]), 2).expect("two coins in one txid");
    assert_eq!(set.record_count(), 1);
    assert_eq!(set.len(), 2);
    let txid = Hash256::from_le_bytes(&[1; 32]);
    let coin = set
        .lock_stable_view()
        .get_entry(&OutPoint::new(txid.into(), 2))
        .expect("second output");
    assert_eq!(coin.txout.value.to_sat(), 5_000_000_000);
    assert_eq!(coin.height, 1);
    assert!(coin.coinbase);
}

#[test]
fn structure_and_record_semantics_fail_closed() {
    assert!(matches!(
        body(&group(1, &[]), 1),
        Err(SnapshotError::EmptyGroup)
    ));
    assert!(matches!(
        body(&group(1, &[0, 1]), 1),
        Err(SnapshotError::CoinCountMismatch { .. })
    ));
    assert!(matches!(
        body(&group(1, &[0, 0]), 2),
        Err(SnapshotError::DuplicateOutpoint { vout: 0 })
    ));
    for next in [0, 1] {
        let mut bytes = group(1, &[0]);
        bytes.extend(group(next, &[1]));
        assert!(matches!(
            body(&bytes, 2),
            Err(SnapshotError::TransactionOrder)
        ));
    }
    let mut too_high = group(1, &[0]);
    too_high.splice(34..35, core_varint(402));
    assert!(matches!(
        body(&too_high, 1),
        Err(SnapshotError::InvalidHeight { height: 201, .. })
    ));
    let mut bad_amount = group(1, &[0]);
    bad_amount.splice(35..36, core_varint(u64::MAX));
    assert!(matches!(
        body(&bad_amount, 1),
        Err(SnapshotError::InvalidAmount { .. })
    ));
    let mut noncanonical = vec![1; 32];
    noncanonical.extend_from_slice(&[0xfd, 1, 0]);
    assert!(matches!(
        body(&noncanonical, 1),
        Err(SnapshotError::NonCanonicalCompactSize)
    ));
    assert!(matches!(
        body(&group(1, &[u64::from(u32::MAX)]), 1),
        Err(SnapshotError::CompactSizeTooLarge { .. })
    ));
}

#[test]
fn all_limits_are_enforced_including_aggregate_scripts_and_header_bytes() {
    let defaults = SnapshotLimits::default();
    for (limits, resource) in [
        (
            SnapshotLimits {
                max_file_bytes: 50,
                ..defaults
            },
            "encoded bytes",
        ),
        (
            SnapshotLimits {
                max_file_bytes: 14_438,
                ..defaults
            },
            "encoded bytes",
        ),
        (
            SnapshotLimits {
                max_coins: 199,
                ..defaults
            },
            "coins",
        ),
        (
            SnapshotLimits {
                max_script_bytes: 6_799,
                ..defaults
            },
            "decoded script bytes",
        ),
        (
            SnapshotLimits {
                max_coins_per_txid: 0,
                ..defaults
            },
            "coins per txid",
        ),
    ] {
        assert!(
            matches!(read_and_verify(&mut Cursor::new(CORE), Network::Regtest, limits), Err(SnapshotError::LimitExceeded { resource: actual, .. }) if actual == resource)
        );
    }
    let exact = SnapshotLimits {
        max_file_bytes: 14_439,
        max_coins: 200,
        max_script_bytes: 6_800,
        max_coins_per_txid: 1,
    };
    assert!(read_and_verify(&mut Cursor::new(CORE), Network::Regtest, exact).is_ok());
    let mut reader = Cursor::new(group(1, &[0, 1]));
    let error = Decoder::new(&mut reader, 1000).coins(
        2,
        200,
        SnapshotLimits {
            max_coins_per_txid: 1,
            ..defaults
        },
    );
    assert!(matches!(
        error,
        Err(SnapshotError::LimitExceeded {
            resource: "coins per txid",
            ..
        })
    ));
    assert_eq!(
        reader.position(),
        33,
        "reject a group before allocating outputs"
    );
}

#[test]
fn corrupted_core_artifacts_and_untrusted_headers_are_rejected() {
    for offset in [0, 4, 5, 6, 10, 42, 50, 51, CORE.len() - 1] {
        assert!(matches!(
            read_and_verify(
                &mut Cursor::new(&CORE[..offset]),
                Network::Regtest,
                SnapshotLimits::default()
            ),
            Err(SnapshotError::Truncated { .. })
        ));
    }
    let mut bytes = CORE.to_vec();
    bytes[0] ^= 1;
    assert!(matches!(
        read_metadata(&mut Cursor::new(&bytes)),
        Err(SnapshotError::InvalidMagic)
    ));
    bytes = CORE.to_vec();
    bytes[5] = 3;
    assert!(matches!(
        read_metadata(&mut Cursor::new(&bytes)),
        Err(SnapshotError::UnsupportedVersion { version: 3 })
    ));
    assert!(matches!(
        read_and_verify(
            &mut Cursor::new(CORE),
            Network::Mainnet,
            SnapshotLimits::default()
        ),
        Err(SnapshotError::WrongNetwork { .. })
    ));
    bytes = CORE.to_vec();
    bytes[11..43].fill(0);
    assert!(matches!(
        read_and_verify(
            &mut Cursor::new(&bytes),
            Network::Regtest,
            SnapshotLimits::default()
        ),
        Err(SnapshotError::UnsupportedAnchor { .. })
    ));
    bytes = CORE.to_vec();
    bytes.push(0);
    assert!(matches!(
        read_and_verify(
            &mut Cursor::new(&bytes),
            Network::Regtest,
            SnapshotLimits::default()
        ),
        Err(SnapshotError::TrailingBytes)
    ));
    bytes = CORE.to_vec();
    bytes[43..51].copy_from_slice(&199_u64.to_le_bytes());
    assert!(matches!(
        read_and_verify(
            &mut Cursor::new(&bytes),
            Network::Regtest,
            SnapshotLimits::default()
        ),
        Err(SnapshotError::TrailingBytes)
    ));
    bytes[43..51].copy_from_slice(&201_u64.to_le_bytes());
    assert!(matches!(
        read_and_verify(
            &mut Cursor::new(&bytes),
            Network::Regtest,
            SnapshotLimits::default()
        ),
        Err(SnapshotError::Truncated { .. })
    ));
    bytes = CORE.to_vec();
    *bytes.last_mut().expect("fixture byte") ^= 1;
    assert!(matches!(
        read_and_verify(
            &mut Cursor::new(&bytes),
            Network::Regtest,
            SnapshotLimits::default()
        ),
        Err(SnapshotError::CommitmentMismatch { .. })
    ));
}

#[test]
fn short_reads_interrupts_and_io_failures_keep_their_meaning() {
    struct Short<'a> {
        input: &'a [u8],
        interrupted: bool,
    }
    impl Read for Short<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(io::ErrorKind::Interrupted.into());
            }
            let n = buf.len().min(1);
            self.input.read(&mut buf[..n])
        }
    }
    struct Failed;
    impl Read for Failed {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::ErrorKind::PermissionDenied.into())
        }
    }
    let mut short = Short {
        input: CORE,
        interrupted: false,
    };
    assert!(read_and_verify(&mut short, Network::Regtest, SnapshotLimits::default()).is_ok());
    assert!(
        matches!(read_metadata(&mut Failed), Err(SnapshotError::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied)
    );
}

/// Forged txids must not reach the identity-hashed UTXO table before the
/// compiled commitment matches. Exercise both identical full hashes and
/// distinct hashes sharing the low bucket and high tag bits.
#[test]
fn forged_collision_families_never_enter_the_utxo_hash_table() {
    const RECORDS: u32 = 4096;
    for same_full_hash in [true, false] {
        let mut bytes = CORE[..51].to_vec();
        bytes[43..51].copy_from_slice(&u64::from(RECORDS).to_le_bytes());
        for index in 0..RECORDS {
            let mut record = group(0, &[0]);
            if same_full_hash {
                record[8..12].copy_from_slice(&index.to_be_bytes());
            } else {
                // Distinct eight-byte keys, with low 32 and high 8 bits zero.
                record[4..7].copy_from_slice(&index.to_be_bytes()[1..]);
            }
            bytes.extend(record);
        }
        let before = crate::set::SNAPSHOT_INSERTIONS.with(std::cell::Cell::get);
        assert!(matches!(
            read_and_verify(
                &mut Cursor::new(&bytes),
                Network::Regtest,
                SnapshotLimits::default()
            ),
            Err(SnapshotError::CommitmentMismatch { .. })
        ));
        assert_eq!(
            crate::set::SNAPSHOT_INSERTIONS.with(std::cell::Cell::get),
            before
        );
    }
    // The instrumentation observes the real successful insertion boundary.
    let before = crate::set::SNAPSHOT_INSERTIONS.with(std::cell::Cell::get);
    assert!(
        read_and_verify(
            &mut Cursor::new(CORE),
            Network::Regtest,
            SnapshotLimits::default()
        )
        .is_ok()
    );
    assert_eq!(
        crate::set::SNAPSHOT_INSERTIONS.with(std::cell::Cell::get),
        before + 200
    );
}

#[test]
fn staged_records_sort_vouts_and_move_their_payloads_without_copying() {
    let bytes = group(1, &[9, 1, 3]);
    let (records, hash) = Decoder::new(&mut Cursor::new(bytes), 1000)
        .coins(3, 200, SnapshotLimits::default())
        .expect("bounded staged records");
    assert_eq!(
        records[0]
            .outputs()
            .map(|output| output.vout)
            .collect::<Vec<_>>(),
        vec![1, 3, 9]
    );
    let first_script = records[0]
        .outputs()
        .next()
        .expect("first coin")
        .script_pubkey
        .as_ptr();
    let set = crate::UtxoSet::new();
    for record in records {
        set.insert_snapshot_record(record);
    }
    set.with_stable_view(|view| {
        assert_eq!(view.hash_serialized_3().expect("stable-view hash"), hash);
        view.for_each_all(|outpoint, script| {
            if outpoint.vout == 1 {
                assert_eq!(script.as_ptr(), first_script, "record payload was moved");
            }
        });
    });
    assert!(matches!(
        body(&group(1, &[1, 9, 1]), 3),
        Err(SnapshotError::DuplicateOutpoint { vout: 1 })
    ));
}

#[test]
fn writer_emits_byte_identical_core200_snapshot_and_roundtrips_read_and_verify() {
    let loaded = read_and_verify(
        &mut Cursor::new(CORE),
        Network::Regtest,
        SnapshotLimits::default(),
    )
    .expect("load fixture snapshot");

    let mut written = Vec::new();
    let report = loaded
        .set
        .with_stable_view(|view| {
            write_core_v2(
                view,
                Network::Regtest,
                loaded.metadata.base_block_hash,
                loaded.anchor.height,
                loaded.metadata.coins_count,
                &mut written,
                &|| false,
            )
        })
        .expect("write_core_v2 succeeds");

    assert_eq!(report.bytes, u64::try_from(CORE.len()).expect("fit"));
    assert_eq!(report.coins, 200);
    assert_eq!(report.txoutset_hash, loaded.hash_serialized);
    assert_eq!(written.len(), CORE.len());
    assert_eq!(written, CORE);

    // Round-trip through read_and_verify
    let reloaded = read_and_verify(
        &mut Cursor::new(&written),
        Network::Regtest,
        SnapshotLimits::default(),
    )
    .expect("round-trip read_and_verify");
    assert_eq!(reloaded.hash_serialized, loaded.hash_serialized);
    assert_eq!(reloaded.metadata, loaded.metadata);
    assert_eq!(reloaded.bytes_read, report.bytes);
}

#[test]
fn writer_script_compression_encodes_odd_even_y_and_offcurve_fallback() {
    let set = crate::UtxoSet::new();

    let gx = hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    let even_y = hex("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
    let odd_y = hex("b7c52588d95c3b9aa25b0403f1eef75702e84bb7597aabe663b82f6f04ef2777");

    let mut p2pk_even = vec![0x41, 0x04];
    p2pk_even.extend_from_slice(&gx);
    p2pk_even.extend_from_slice(&even_y);
    p2pk_even.push(0xac);

    let mut p2pk_odd = vec![0x41, 0x04];
    p2pk_odd.extend_from_slice(&gx);
    p2pk_odd.extend_from_slice(&odd_y);
    p2pk_odd.push(0xac);

    let mut p2pk_offcurve = p2pk_even.clone();
    p2pk_offcurve[2..34].fill(0xff); // Not on curve

    let mut p2pk_comp = vec![0x21, 0x02];
    p2pk_comp.extend_from_slice(&gx);
    p2pk_comp.push(0xac);

    let mut p2pkh = vec![0x76, 0xa9, 0x14];
    p2pkh.extend_from_slice(&[0x22; 20]);
    p2pkh.extend_from_slice(&[0x88, 0xac]);

    let mut p2sh = vec![0xa9, 0x14];
    p2sh.extend_from_slice(&[0x33; 20]);
    p2sh.push(0x87);

    let scripts = [p2pk_even, p2pk_odd, p2pk_offcurve, p2pk_comp, p2pkh, p2sh];
    for (i, script) in scripts.iter().enumerate() {
        let mut txid_bytes = [0_u8; 32];
        txid_bytes[0] = u8::try_from(i).expect("fit");
        txid_bytes[1] = 0xaa;
        let txid = Hash256::from_le_bytes(&txid_bytes);
        let out = OwnedUtxoOut::new(0, 50_000_000, script.clone(), false, 1);
        let record = UtxoRecord::from_owned_outputs(txid, &[out]).expect("record");
        set.insert_snapshot_record(record);
    }

    let mut written = Vec::new();
    let base_hash = Hash256::from_le_bytes(&[0x42; 32]);
    let report = set
        .with_stable_view(|view| {
            write_core_v2(
                view,
                Network::Regtest,
                base_hash,
                100,
                6,
                &mut written,
                &|| false,
            )
        })
        .expect("write succeeds");
    assert_eq!(report.coins, 6);

    // Decode through Decoder and check each script matches original
    let mut cursor = Cursor::new(&written);
    let mut decoder = Decoder::new(&mut cursor, u64::try_from(written.len()).expect("fit"));
    let meta = decoder.metadata().expect("meta");
    assert_eq!(meta.coins_count, 6);
    let (records, hash) = decoder
        .coins(6, 100, SnapshotLimits::default())
        .expect("coins");
    assert_eq!(hash, report.txoutset_hash);
    assert_eq!(records.len(), 6);
    for (i, record) in records.iter().enumerate() {
        let out = record.outputs().next().expect("out");
        assert_eq!(out.script_pubkey, scripts[i].as_slice());
    }
}

#[test]
fn writer_cancellation_polls_every_5000_coins() {
    let loaded = read_and_verify(
        &mut Cursor::new(CORE),
        Network::Regtest,
        SnapshotLimits::default(),
    )
    .expect("fixture");

    // Immediate stop returns Interrupted before writing anything
    let mut written = Vec::new();
    let res = loaded.set.with_stable_view(|view| {
        write_core_v2(
            view,
            Network::Regtest,
            loaded.metadata.base_block_hash,
            loaded.anchor.height,
            loaded.metadata.coins_count,
            &mut written,
            &|| true,
        )
    });
    assert!(matches!(res, Err(SnapshotError::Interrupted)));

    // Set with > 5000 coins to verify 5000-coin polling
    let large_set = crate::UtxoSet::new();
    for i in 0..5_005_u32 {
        let mut txid_bytes = [0_u8; 32];
        txid_bytes[0] = u8::try_from(i & 0xff).expect("fit");
        txid_bytes[1..5].copy_from_slice(&i.to_le_bytes());
        let txid = Hash256::from_le_bytes(&txid_bytes);
        let out = OwnedUtxoOut::new(0, 1000, vec![0x51], false, 1);
        let record = UtxoRecord::from_owned_outputs(txid, &[out]).expect("record");
        large_set.insert_snapshot_record(record);
    }

    let poll_called = std::cell::Cell::new(false);
    let mut written_large = Vec::new();
    let res_large = large_set.with_stable_view(|view| {
        write_core_v2(
            view,
            Network::Regtest,
            loaded.metadata.base_block_hash,
            100,
            5005,
            &mut written_large,
            &|| {
                // Return false on first check (initial poll), true on subsequent check
                if poll_called.get() {
                    true
                } else {
                    poll_called.set(true);
                    false
                }
            },
        )
    });
    assert!(matches!(res_large, Err(SnapshotError::Interrupted)));
    assert!(poll_called.get());
}

#[test]
fn writer_declared_coin_count_mismatch_fails_closed() {
    let loaded = read_and_verify(
        &mut Cursor::new(CORE),
        Network::Regtest,
        SnapshotLimits::default(),
    )
    .expect("fixture");

    // Declaring fewer coins than actual (e.g. 100 declared, 200 actual)
    let mut written = Vec::new();
    let res_low = loaded.set.with_stable_view(|view| {
        write_core_v2(
            view,
            Network::Regtest,
            loaded.metadata.base_block_hash,
            loaded.anchor.height,
            100,
            &mut written,
            &|| false,
        )
    });
    assert!(matches!(
        res_low,
        Err(SnapshotError::DeclaredCoinCountMismatch {
            declared: 100,
            actual: 101
        })
    ));

    // Declaring more coins than actual (e.g. 300 declared, 200 actual)
    written.clear();
    let res_high = loaded.set.with_stable_view(|view| {
        write_core_v2(
            view,
            Network::Regtest,
            loaded.metadata.base_block_hash,
            loaded.anchor.height,
            300,
            &mut written,
            &|| false,
        )
    });
    assert!(matches!(
        res_high,
        Err(SnapshotError::DeclaredCoinCountMismatch {
            declared: 300,
            actual: 200
        })
    ));
}

#[test]
fn writer_io_failure_propagates_as_snapshot_error() {
    struct FailingWriter {
        fail_after: usize,
        written: usize,
    }
    impl std::io::Write for FailingWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.written + buf.len() > self.fail_after {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "simulated write failure",
                ))
            } else {
                self.written += buf.len();
                Ok(buf.len())
            }
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let loaded = read_and_verify(
        &mut Cursor::new(CORE),
        Network::Regtest,
        SnapshotLimits::default(),
    )
    .expect("fixture");

    // Fail during header
    let mut failing = FailingWriter {
        fail_after: 20,
        written: 0,
    };
    let res = loaded.set.with_stable_view(|view| {
        write_core_v2(
            view,
            Network::Regtest,
            loaded.metadata.base_block_hash,
            loaded.anchor.height,
            loaded.metadata.coins_count,
            &mut failing,
            &|| false,
        )
    });
    assert!(matches!(res, Err(SnapshotError::Io(_))));

    // Fail during coin streaming
    let mut failing_coins = FailingWriter {
        fail_after: 100,
        written: 0,
    };
    let res_coins = loaded.set.with_stable_view(|view| {
        write_core_v2(
            view,
            Network::Regtest,
            loaded.metadata.base_block_hash,
            loaded.anchor.height,
            loaded.metadata.coins_count,
            &mut failing_coins,
            &|| false,
        )
    });
    assert!(matches!(res_coins, Err(SnapshotError::Io(_))));
}

#[test]
fn writer_rejects_output_with_max_vout_as_invalid_outpoint() {
    let set = crate::UtxoSet::new();
    let txid = Hash256::from_le_bytes(&[0x5a; 32]);
    let out = OwnedUtxoOut::new(u32::MAX, 50_000_000, vec![0x51], false, 1);
    let record =
        UtxoRecord::from_owned_outputs(txid, &[out]).expect("UtxoRecord admits u32::MAX vout");
    set.insert_snapshot_record(record);

    let mut written = Vec::new();
    let base_hash = Hash256::from_le_bytes(&[0x42; 32]);
    let res = set.with_stable_view(|view| {
        write_core_v2(
            view,
            Network::Regtest,
            base_hash,
            100,
            1,
            &mut written,
            &|| false,
        )
    });

    let error = res.expect_err("write_core_v2 must reject output with vout u32::MAX");
    match error {
        SnapshotError::InvalidOutpoint { vout } => {
            assert_eq!(vout, u64::from(u32::MAX));
        }
        other => panic!("expected InvalidOutpoint error, got {other:?}"),
    }
}

#[test]
fn writer_encodes_highest_encodable_height_for_both_coinbase_variants() {
    // Packed height/coinbase limit: height <= 0x7fff_ffff allows code <= u32::MAX.
    // At height 0x7fff_ffff, coinbase=false yields 0xffff_fffe and coinbase=true yields 0xffff_ffff.
    let max_height: u32 = 0x7fff_ffff;
    let base_hash = Hash256::from_le_bytes(&[0x33; 32]);

    for coinbase in [false, true] {
        let set = crate::UtxoSet::new();
        let txid = Hash256::from_le_bytes(&[if coinbase { 0x11 } else { 0x22 }; 32]);
        let out = OwnedUtxoOut::new(0, 50_000_000, vec![0x51], coinbase, max_height);
        let record = UtxoRecord::from_owned_outputs(txid, &[out])
            .expect("UtxoRecord admits valid max height");
        set.insert_snapshot_record(record);

        let mut written = Vec::new();
        let report = set
            .with_stable_view(|view| {
                write_core_v2(
                    view,
                    Network::Regtest,
                    base_hash,
                    max_height,
                    1,
                    &mut written,
                    &|| false,
                )
            })
            .expect("write_core_v2 must accept max encodable height");

        assert_eq!(report.coins, 1);
        assert!(report.bytes > 51);

        // Verify that the written stream decodes successfully and roundtrips the height and coinbase.
        let (records, hash_serialized) = Decoder::new(&mut Cursor::new(&written[51..]), 1_000_000)
            .coins(1, max_height, SnapshotLimits::default())
            .expect("Decoder must accept snapshot written with max encodable height");

        assert_eq!(records.len(), 1);
        let outputs: Vec<_> = records[0].outputs().collect();
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].height, max_height);
        assert_eq!(outputs[0].coinbase, coinbase);
        assert_eq!(report.txoutset_hash, hash_serialized);
    }
}

#[test]
fn writer_rejects_next_height_as_varint_overflow_for_both_coinbase_variants() {
    // If bit 31 of height is set (height >= 0x8000_0000), (height << 1) exceeds u32::MAX
    // for both coinbase=false (0x1_0000_0000) and coinbase=true (0x1_0000_0001).
    // In Rust, the bit shift by 1 does not panic, but shifts out the high bit causing
    // high-bit loss during commitment hashing, and creates an incompatible 64-bit Core VARINT.
    // The writer must fail closed with VarIntOverflow.
    let overflow_height: u32 = 0x8000_0000;
    let base_hash = Hash256::from_le_bytes(&[0x44; 32]);

    for coinbase in [false, true] {
        let set = crate::UtxoSet::new();
        let txid = Hash256::from_le_bytes(&[if coinbase { 0xaa } else { 0xbb }; 32]);
        let out = OwnedUtxoOut::new(0, 50_000_000, vec![0x51], coinbase, overflow_height);
        let record = UtxoRecord::from_owned_outputs(txid, &[out])
            .expect("UtxoRecord admits height with bit 31 set");
        set.insert_snapshot_record(record);

        let mut written = Vec::new();
        let res = set.with_stable_view(|view| {
            write_core_v2(
                view,
                Network::Regtest,
                base_hash,
                overflow_height,
                1,
                &mut written,
                &|| false,
            )
        });

        match res {
            Err(SnapshotError::VarIntOverflow) => {}
            other => panic!(
                "expected VarIntOverflow for height 0x8000_0000 (coinbase={coinbase}), got {other:?}"
            ),
        }
    }
}

#[test]
fn writer_preserves_invalid_height_precedence_over_varint_overflow() {
    // When output height exceeds base_height, InvalidHeight must take precedence
    // over VarIntOverflow even when height >= 0x8000_0000.
    let overflow_height: u32 = 0x8000_0000;
    let base_height: u32 = 100;
    let base_hash = Hash256::from_le_bytes(&[0x55; 32]);

    let set = crate::UtxoSet::new();
    let txid = Hash256::from_le_bytes(&[0xcc; 32]);
    let out = OwnedUtxoOut::new(0, 50_000_000, vec![0x51], false, overflow_height);
    let record = UtxoRecord::from_owned_outputs(txid, &[out])
        .expect("UtxoRecord admits height with bit 31 set");
    set.insert_snapshot_record(record);

    let mut written = Vec::new();
    let res = set.with_stable_view(|view| {
        write_core_v2(
            view,
            Network::Regtest,
            base_hash,
            base_height,
            1,
            &mut written,
            &|| false,
        )
    });

    match res {
        Err(SnapshotError::InvalidHeight {
            height,
            base_height: base,
        }) => {
            assert_eq!(height, overflow_height);
            assert_eq!(base, base_height);
        }
        other => panic!("expected InvalidHeight error, got {other:?}"),
    }
}

#[test]
fn varint_key_order_spans_width_transition_at_16512() {
    use core::cmp::Ordering;

    use crate::compress::cmp_core_varint_key;
    use crate::snapshot::SerializedUtxoHasher;

    // Width boundaries of Core's subtract-one MSB VARINT.
    assert_eq!(core_varint(16_511), vec![0xFF, 0x7F]);
    assert_eq!(core_varint(16_512), vec![0x80, 0x80, 0x00]);
    // Bytewise cursor order inverts numeric order across the transition.
    assert_eq!(cmp_core_varint_key(16_512, 16_511), Ordering::Less);
    assert_eq!(cmp_core_varint_key(16_511, 16_512), Ordering::Greater);
    // Within one width numeric and key order agree.
    assert_eq!(cmp_core_varint_key(0, 127), Ordering::Less);
    assert_eq!(cmp_core_varint_key(128, 16_511), Ordering::Less);
    assert_eq!(cmp_core_varint_key(16_512, 16_513), Ordering::Less);
    assert_eq!(cmp_core_varint_key(5, 5), Ordering::Equal);

    // Decoder stages file-numeric order into cursor order and commits there.
    let bytes = group(7, &[16_511, 16_512]);
    let (records, hash) = Decoder::new(&mut Cursor::new(bytes), 100_000)
        .coins(2, 200, SnapshotLimits::default())
        .expect("staged records");
    assert_eq!(
        records[0]
            .outputs()
            .map(|output| output.vout)
            .collect::<Vec<_>>(),
        vec![16_512, 16_511]
    );
    let txid_bytes = Hash256::from_le_bytes(&[7; 32]).to_le_bytes();
    let staged: Vec<_> = records[0].outputs().collect();
    let mut varint_feed = SerializedUtxoHasher::new();
    for output in &staged {
        varint_feed
            .add(txid_bytes, *output, Some(200))
            .expect("varint feed");
    }
    assert_eq!(varint_feed.finish(), hash);
    let mut numeric_feed = SerializedUtxoHasher::new();
    for output in staged.iter().rev() {
        numeric_feed
            .add(txid_bytes, *output, Some(200))
            .expect("numeric feed");
    }
    assert_ne!(
        numeric_feed.finish(),
        hash,
        "the transition must distinguish cursor order from numeric order"
    );

    // Writer emits cursor order; the file, the report and a re-decode agree.
    let set = crate::UtxoSet::new();
    let txid = Hash256::from_le_bytes(&[7; 32]);
    let low = OwnedUtxoOut::new(16_511, 5_000_000_000, vec![0x51], true, 1);
    let high = OwnedUtxoOut::new(16_512, 5_000_000_000, vec![0x51], true, 1);
    let record = UtxoRecord::from_owned_outputs(txid, &[low, high]).expect("record");
    set.insert_snapshot_record(record);
    let base_hash = Hash256::from_le_bytes(&[0x77; 32]);
    let mut written = Vec::new();
    let report = set
        .with_stable_view(|view| {
            write_core_v2(
                view,
                Network::Regtest,
                base_hash,
                200,
                2,
                &mut written,
                &|| false,
            )
        })
        .expect("write succeeds");
    // First emitted vout is 16,512 in CompactSize (FD 80 40), not 16,511.
    assert_eq!(written[84..87], [0xFD, 0x80, 0x40]);
    let mut cursor = Cursor::new(&written);
    let mut decoder = Decoder::new(&mut cursor, u64::try_from(written.len()).expect("fit"));
    decoder.metadata().expect("header");
    let (emitted, emitted_hash) = decoder
        .coins(2, 200, SnapshotLimits::default())
        .expect("re-decode");
    assert_eq!(
        emitted[0]
            .outputs()
            .map(|output| output.vout)
            .collect::<Vec<_>>(),
        vec![16_512, 16_511]
    );
    assert_eq!(emitted_hash, report.txoutset_hash);
    assert_eq!(emitted_hash, hash);
    set.with_stable_view(|view| {
        assert_eq!(view.hash_serialized_3().expect("stable-view hash"), hash);
    });

    // Duplicate detection survives the new order in both duplicate positions.
    assert!(matches!(
        body(&group(7, &[16_511, 16_511]), 2),
        Err(SnapshotError::DuplicateOutpoint { vout: 16_511 })
    ));
    assert!(matches!(
        body(&group(7, &[16_512, 16_511, 16_512]), 3),
        Err(SnapshotError::DuplicateOutpoint { vout: 16_512 })
    ));
}
