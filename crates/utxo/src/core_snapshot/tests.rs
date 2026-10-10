//! Independent Core encodings and fail-closed resource contracts.
#![allow(clippy::expect_used)]

use std::io::{self, Cursor, Read};

use bitcoin_rs_primitives::{Hash256, Network, OutPoint, varint};

use super::{Decoder, SnapshotError, SnapshotLimits, read_and_verify, read_metadata};

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
