//! Scenario tests for the checked borrowed wire layout (`layout` module).

#![expect(clippy::expect_used, reason = "test assertions")]

use bitcoin_rs_primitives::layout::{ByteSpan, ParsedBlock, ParsedTransaction};
use bitcoin_rs_primitives::{Block, DecodeError, Network, Tx, consensus_bytes, deserialize};

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
                .transactions()
                .get(index)
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

#[test]
fn trailing_byte_is_rejected() {
    let mut bytes = read_fixture(170);
    bytes.push(0xAB);
    assert!(matches!(
        ParsedBlock::parse_exact(&bytes),
        Err(DecodeError::TrailingBytes { .. })
    ));
}

#[test]
fn impossible_counts_are_rejected_before_allocation() {
    let mut tx_bytes = Vec::new();
    tx_bytes.extend_from_slice(&1_i32.to_le_bytes());
    tx_bytes.extend_from_slice(&[0x00, 0x01]);
    tx_bytes.extend_from_slice(&[0xFF; 9]);
    assert!(matches!(
        ParsedTransaction::parse_exact(&tx_bytes),
        Err(DecodeError::EndOfData { .. })
    ));
}

#[test]
fn noncanonical_varints_are_rejected() {
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
    let mut cursor = 81;
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
    let _: Option<ByteSpan> = None;
}

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

#[test]
fn parsed_transaction_txid_and_base_size_match_materialized_form() {
    let mut compared = 0_usize;
    let mut segwit = 0_usize;
    for height in HEIGHTS {
        let bytes = read_fixture(*height);
        let parsed = ParsedBlock::parse_exact(&bytes).expect("golden block parses");
        for (index, tx) in parsed.transactions().iter().enumerate() {
            let materialized = tx.materialize();
            assert_eq!(
                tx.txid().as_bytes(),
                materialized.txid().as_bytes(),
                "height {height} tx {index} txid"
            );
            assert_eq!(
                tx.base_size(),
                materialized.base_size(),
                "height {height} tx {index} base size"
            );
            compared += 1;
            segwit += usize::from(tx.is_segwit());
        }
    }
    assert!(
        segwit > 0 && segwit < compared,
        "the fixtures must exercise both encodings, got {segwit} SegWit of {compared}"
    );
}
