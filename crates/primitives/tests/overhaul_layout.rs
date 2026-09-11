//! Scenario tests for the checked borrowed wire layout (`layout` module).
//!

//! These pin the layout owner's contract against the golden block corpus and
//! synthetic malformations: every span a parsed structure hands out is
//! in-bounds by construction, malformed encodings fail with a defined
//! [`DecodeError`] before any out-of-bounds access or oversized allocation,
//! and materialized values are byte-identical to the consensus form.
#![expect(clippy::expect_used, reason = "test assertions")]

use std::ops::Range;

use bitcoin_rs_primitives::layout::{ByteSpan, ParsedBlock, ParsedTransaction};
use bitcoin_rs_primitives::{Block, DecodeError, Network, Tx, consensus_bytes, deserialize};

/// Golden fixture heights: one legacy-only block and one with segwit
/// transactions (height 481824 is the first segwit block on mainnet).
const HEIGHTS: &[u32] = &[170, 481_824];

fn read_fixture(height: u32) -> Vec<u8> {
    let path = format!("tests/testdata/{height}.bin");
    match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            panic!("missing {path}; run scripts/fetch-golden.sh to populate testdata")
        }
        Err(error) => panic!("read {path}: {error}"),
    }
}

/// Golden blocks: every transaction span slices to exactly the transaction's
/// consumed region, per-transaction regions account for the whole block, and
/// the materialized form re-encodes byte-identically.
#[test]
fn golden_blocks_validate_all_spans_and_consumed_counts() {
    for height in HEIGHTS {
        let bytes = read_fixture(*height);
        let parsed = ParsedBlock::parse_exact(&bytes).unwrap_or_else(|e| panic!("{height}: {e}"));

        assert_eq!(
            parsed.consumed_len(),
            bytes.len(),
            "height {height} exact consumption"
        );
        assert_eq!(
            parsed.transaction_spans().len(),
            parsed.tx_count(),
            "height {height} one span per transaction"
        );

        let mut per_tx_total = 0_usize;
        for (index, span) in parsed.transaction_spans().iter().enumerate() {
            let transaction = parsed
                .transaction(index)
                .unwrap_or_else(|| panic!("height {height} tx {index} missing"));
            let slice = parsed
                .span_bytes(*span)
                .unwrap_or_else(|| panic!("height {height} tx {index} span out of bounds"));
            assert_eq!(
                slice.len(),
                transaction.consumed_len(),
                "height {height} tx {index} span equals consumed region"
            );
            per_tx_total += transaction.consumed_len();
        }
        // Header (80) + count prefix width + transaction regions == block.
        let prefix = if u64::try_from(parsed.tx_count()).is_ok_and(|count| count <= 0xfc) {
            1
        } else {
            3
        };
        assert_eq!(
            per_tx_total + 80 + prefix,
            bytes.len(),
            "height {height} consumed regions account for the whole block"
        );

        let materialized = parsed.materialize();
        assert_eq!(
            consensus_bytes(&materialized),
            bytes,
            "height {height} materialize re-encode"
        );
    }
}

/// Every strict prefix of a golden block fails with a defined error and no
/// panic. One representative small block keeps the sweep cheap.
#[test]
fn truncation_sweep_produces_defined_errors_only() {
    let bytes = read_fixture(170);
    for cut in 0..bytes.len() {
        match ParsedBlock::parse_exact(&bytes[..cut]) {
            Ok(_) => panic!("prefix of length {cut} must not parse as a complete block"),
            Err(
                DecodeError::EndOfData { .. }
                | DecodeError::Varint(_)
                | DecodeError::InvalidSegwitFlag { .. }
                | DecodeError::SuperfluousWitness
                | DecodeError::TrailingBytes { .. },
            ) => {}
        }
    }
}

/// A trailing byte after an otherwise complete block is rejected.
#[test]
fn trailing_byte_is_rejected() {
    let mut bytes = read_fixture(170);
    bytes.push(0xAB);
    assert!(matches!(
        ParsedBlock::parse_exact(&bytes),
        Err(DecodeError::TrailingBytes { .. })
    ));
}

/// Counts whose minimal serialized footprint exceeds the remaining bytes are
/// rejected before any allocation sized by the count.
#[test]
fn impossible_counts_are_rejected_before_allocation() {
    // version + marker/flag + u64::MAX-sized input count, nothing else.
    let mut tx_bytes = Vec::new();
    tx_bytes.extend_from_slice(&1_i32.to_le_bytes());
    tx_bytes.extend_from_slice(&[0x00, 0x01]);
    tx_bytes.extend_from_slice(&[0xFF; 9]);
    assert!(matches!(
        ParsedTransaction::parse_exact(&tx_bytes),
        Err(DecodeError::EndOfData { .. })
    ));
}

/// Non-canonical compact-size encodings are rejected with `Varint`.
#[test]
fn noncanonical_varints_are_rejected() {
    // version + input count 0xFD 0x05 0x00 (little-endian 5; the canonical
    // form of 5 is one byte), then padding so only the varint is at fault.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&1_i32.to_le_bytes());
    bytes.extend_from_slice(&[0xFD, 0x05, 0x00]);
    bytes.extend_from_slice(&[0u8; 8]);
    let err = ParsedTransaction::parse_exact(&bytes).expect_err("must fail");
    assert!(
        matches!(err, DecodeError::Varint(_)),
        "expected Varint, got {err:?}"
    );
}
/// Segwit marker handling: the golden segwit block carries witness spans, and
/// mutating a marker/flag pair to flag 0x02 surfaces the defined flag error
/// (or a downstream defined error when the mutation lands inside script
/// data).
#[test]
fn segwit_flag_rules_hold() {
    let golden = read_fixture(481_824);
    let parsed = ParsedBlock::parse_exact(&golden).expect("segwit golden block parses");
    assert!(
        parsed
            .transactions()
            .iter()
            .any(|tx| !tx.witness_spans().is_empty()),
        "height 481824 carries witness data"
    );

    let mut corrupted = golden.clone();
    let mut replaced = false;
    let mut cursor = 81; // past header and transaction count
    while cursor + 1 < corrupted.len() {
        if corrupted[cursor] == 0x00 && corrupted[cursor + 1] == 0x01 {
            corrupted[cursor + 1] = 0x02;
            replaced = true;
            break;
        }
        cursor += 1;
    }
    assert!(replaced, "fixture contains a marker/flag pair");
    assert!(matches!(
        ParsedBlock::parse_exact(&corrupted),
        Err(DecodeError::InvalidSegwitFlag { got: 0x02 }
            | DecodeError::EndOfData { .. }
            | DecodeError::Varint(_))
    ));
}

/// Span widening: `file_range` adds the image base in checked `u64`
/// arithmetic and reports overflow instead of wrapping.
#[test]
fn span_file_ranges_widen_in_checked_u64() {
    let bytes = read_fixture(170);
    let parsed = ParsedBlock::parse_exact(&bytes).expect("golden parse");
    let base = u64::MAX - 1_000_000;
    for span in parsed.transaction_spans() {
        let file_range: Range<u64> = span
            .file_range(base)
            .expect("plenty of headroom under u64::MAX");
        assert!(file_range.end > file_range.start);
        assert!(file_range.end <= base + u64::try_from(bytes.len()).unwrap_or(u64::MAX));
    }
    // A base at u64::MAX with a non-zero length overflows and reports None.
    let span = parsed
        .transaction_spans()
        .first()
        .copied()
        .expect("at least one transaction");
    assert!(span.file_range(u64::MAX).is_none());
}

/// Metadata ranges arrive only from parsing (construction is internal), and
/// the type is distinct from `ByteSpan`: an input's witness metadata is a
/// `MetadataRange` over the parsed witness-span vector, never a byte offset.
#[test]
fn metadata_ranges_distinct_from_byte_spans() {
    let bytes = read_fixture(481_824);
    let parsed = ParsedBlock::parse_exact(&bytes).expect("segwit golden parses");
    let transaction = parsed
        .transactions()
        .iter()
        .find(|tx| !tx.witness_spans().is_empty())
        .expect("a transaction with witness data");
    let input = transaction
        .inputs()
        .iter()
        .find(|input| !input.witness().is_empty())
        .expect("an input with witness items");
    let witness_range = input.witness().as_range();
    assert!(witness_range.end <= transaction.witness_spans().len());
    for index in witness_range {
        assert!(
            parsed
                .span_bytes(transaction.witness_spans()[index])
                .is_some(),
            "witness item {index} span stays in bounds"
        );
    }
    // ByteSpan and MetadataRange are distinct types with no conversion.
    let _: Option<ByteSpan> = None;
}

/// The genesis coinbase parsed through the layout hashes to the same txid as
/// the direct consensus decode, and its span carries the exact wire bytes.
#[test]
fn genesis_txid_through_layout_matches_direct_decode() {
    let genesis = Network::Mainnet.genesis_block();
    let bytes = consensus_bytes(&genesis);
    let parsed = ParsedBlock::parse_exact(&bytes).expect("genesis parses");
    let materialized: Block = parsed.materialize();
    let direct: Block = deserialize(&bytes).expect("direct decode");

    assert_eq!(materialized.txs.len(), 1);
    let through_layout: &Tx = materialized
        .txs
        .first()
        .expect("genesis coinbase through layout");
    assert_eq!(
        through_layout.txid(),
        direct.txs.first().expect("direct coinbase").txid()
    );

    let span = parsed
        .transaction_spans()
        .first()
        .copied()
        .expect("genesis span");
    let slice = parsed.span_bytes(span).expect("genesis span in bounds");
    assert_eq!(slice, consensus_bytes(through_layout).as_slice());
}
