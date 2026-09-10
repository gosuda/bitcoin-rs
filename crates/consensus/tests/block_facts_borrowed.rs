//! BIP141 base serialization parity over borrowed transaction ranges.
//! References: BIP141 Transaction ID / Block size; rust-bitcoin is the
//! independent decoder and hash/weight oracle, not the candidate serializer.
#![expect(clippy::expect_used, reason = "test assertions")]

#[path = "support/block_facts_fixture.rs"]
mod fixtures;

use bitcoin_rs_consensus::{BlockView, block_view::BlockFacts};
use bitcoin_rs_primitives::layout::ParsedBlock;
use bitcoin_rs_primitives::{Block, Tx, consensus_bytes};

fn facts(block: &Block) -> BlockFacts {
    let bytes = consensus_bytes(block);
    let parsed = ParsedBlock::parse_exact(&bytes).expect("fixture layout");
    let facts = BlockFacts::from_parsed(&parsed);
    fixtures::assert_oracle(&bytes, &facts);
    facts
}

#[test]
fn sha256_and_compact_size_script_boundaries_match_oracle() {
    // Include SHA256 padding/block boundaries and both representable
    // script-length CompactSize transitions without allocating huge scripts.
    for len in [0, 1, 55, 56, 63, 64, 65, 252, 253, 254, 65_535, 65_536] {
        for witness_modulus in [0, 1, 2] {
            let block = fixtures::fixture(3, 1, 1, len, witness_modulus);
            assert!(!facts(&block).merkle_mutated());
        }
    }
}

#[test]
fn count_prefixes_and_nonzero_transaction_origins_match_oracle() {
    for count in [1, 252, 253, 254] {
        for witness_modulus in [0, 1, 2] {
            // Vary input, output and block transaction counts independently.
            facts(&fixtures::fixture(3, count, 1, 0, witness_modulus));
            facts(&fixtures::fixture(3, 1, count, 0, witness_modulus));
            facts(&fixtures::fixture(count, 1, 1, 0, witness_modulus));
        }
    }
}

#[test]
fn zero_outputs_and_empty_last_script_preserve_base_body_end() {
    for witness_modulus in [0, 1, 2] {
        for outputs in [0, 1, 2] {
            let mut block = fixtures::fixture(3, 2, outputs, 17, witness_modulus);
            for tx in &mut block.txs {
                if let Some(output) = tx.outputs.last_mut() {
                    output.script_pubkey.clear();
                }
            }
            facts(&block);
        }
    }
}

#[test]
fn witness_only_mutations_leave_txids_and_merkle_root_unchanged() {
    let mut block = fixtures::fixture(3, 2, 2, 7, 2);
    let original = facts(&block);
    block.txs[1].inputs[0].witness = vec![Vec::new(), vec![0xab; 253]];
    let mutated = facts(&block);
    assert_eq!(original.txids(), mutated.txids());
    assert_eq!(original.merkle_root(), mutated.merkle_root());
    assert_ne!(original.wtxids(), mutated.wtxids());
    assert_ne!(original.weight(), mutated.weight());
}

#[test]
fn a_single_empty_witness_item_is_not_a_legacy_transaction() {
    let mut block = fixtures::fixture(3, 2, 0, 0, 0);
    block.txs[1].inputs[1].witness = vec![Vec::new()];
    let result = facts(&block);
    assert!(result.has_witness());
    let ids = result.wtxids().expect("one empty item still has witness data");
    assert_ne!(ids[1].0, result.txids()[1].0);
    assert_eq!(ids[0].0, result.txids()[0].0);
    assert_eq!(ids[2].0, result.txids()[2].0);
}

#[test]
fn parsing_a_prefix_never_hashes_the_following_message() {
    let block = fixtures::fixture(3, 2, 2, 253, 2);
    let original = consensus_bytes(&block);
    let mut bytes = original.clone();
    bytes.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    let mut reader = bytes.as_slice();
    let parsed = ParsedBlock::parse(&mut reader).expect("prefix parse");
    assert_eq!(reader, &[0xde, 0xad, 0xbe, 0xef]);
    let actual = BlockFacts::from_parsed(&parsed);
    fixtures::assert_oracle(&original, &actual);
    assert_eq!(actual, facts(&block));
    assert!(ParsedBlock::parse_exact(&bytes).is_err());
}

#[test]
fn legacy_and_mixed_lazy_witness_ids_match_oracle_and_reuse_cache() {
    for witness_modulus in [0, 1, 2, 3] {
        let block = fixtures::fixture(9, 3, 2, 253, witness_modulus);
        let bytes = consensus_bytes(&block);
        let oracle: bitcoin::Block = bitcoin::consensus::deserialize(&bytes).expect("oracle");
        let txids = block.txs.iter().map(Tx::txid).collect();
        let mut view = BlockView::new(&block.txs, txids);
        assert!(view.computed_witness_ids().is_none());
        let ids = view.witness_ids();
        assert_eq!(ids.len(), oracle.txdata.len());
        for (actual, expected) in ids.iter().zip(&oracle.txdata) {
            assert_eq!(actual.to_string(), expected.compute_wtxid().to_string());
        }
        let cached = ids.as_ptr();
        assert_eq!(cached, view.witness_ids().as_ptr());
    }
}

#[test]
fn empty_blocks_preserve_lazy_and_parsed_fact_shapes() {
    let block = fixtures::fixture(0, 1, 1, 0, 0);
    let actual = facts(&block);
    assert_eq!(actual.tx_count(), 0);
    assert_eq!(actual.weight(), 324);
    assert!(!actual.has_witness());
    assert!(actual.merkle_root().is_none());
    assert!(!actual.merkle_mutated());
    let mut view = BlockView::new(&block.txs, Vec::new());
    assert!(view.witness_ids().is_empty());
}

#[test]
fn mutation_flag_distinguishes_real_duplicate_tail_from_odd_padding() {
    // Core's [1..6] / [1..6,5,6] ambiguity: same root, only the latter
    // contains equal real siblings. Apply it to actual wire transactions.
    for witness_modulus in [0, 1, 2] {
        let mut block = fixtures::fixture(6, 1, 1, 0, witness_modulus);
        let original = facts(&block);
        let tail = block.txs[4..].to_vec();
        block.txs.extend(tail);
        let duplicated = facts(&block);
        assert_eq!(original.merkle_root(), duplicated.merkle_root());
        assert!(!original.merkle_mutated());
        assert!(duplicated.merkle_mutated());
    }
}

#[test]
fn noncanonical_script_lengths_still_fail_at_the_layout_boundary() {
    for witness_modulus in [0, 1] {
        let block = fixtures::fixture(1, 1, 1, 1, witness_modulus);
        let mut bytes = consensus_bytes(&block);
        let parsed = ParsedBlock::parse_exact(&bytes).expect("canonical layout");
        let script = parsed.transactions()[0].inputs()[0].script_sig();
        let prefix = usize::try_from(script.start()).expect("fixture offset") - 1;
        drop(parsed);
        drop(bytes.splice(prefix..prefix + 1, [0xfd, 1, 0]));
        assert!(ParsedBlock::parse_exact(&bytes).is_err());
        assert!(bitcoin::consensus::deserialize::<bitcoin::Block>(&bytes).is_err());
    }
}

#[test]
fn version_and_lock_time_bytes_remain_in_the_transaction_id() {
    let mut block = fixtures::fixture(3, 1, 1, 0, 2);
    let original = facts(&block);
    block.txs[1].version = -1;
    block.txs[1].lock_time = u32::MAX;
    let changed = facts(&block);
    assert_ne!(original.txids()[1], changed.txids()[1]);
    assert_eq!(original.txids()[0], changed.txids()[0]);
    assert_eq!(original.txids()[2], changed.txids()[2]);
    assert_eq!(original.weight(), changed.weight());
}
