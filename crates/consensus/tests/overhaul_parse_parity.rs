//! CONTRACT: docs/contracts/campaign-corpora.md#CORP-03; docs/contracts/architecture.md#ARCH-01.
//!
//! T06 parity: the one-pass derivation over the T05 borrowed layout must
//! agree with the independent `bitcoin`-crate oracle on txids, wtxids,
//! weight, byte positions, and Merkle mutation flags over the golden
//! fixtures, the BIP141 coinbase witness leaf must be zeroed for the witness
//! commitment without changing the coinbase's actual wtxid, and the native
//! single-pass shape must be observable (layout positions and pre-populated
//! witness IDs that a second-decode shape cannot produce).
//!
//! Fixtures come from `crates/primitives/tests/testdata` by path; a missing
//! fixture fails the lane, it is never skipped.
#![expect(clippy::expect_used, reason = "test assertions")]
use std::str::FromStr;

use bitcoin::merkle_tree::calculate_root;
use bitcoin_rs_consensus::block_view::BlockFacts;
use bitcoin_rs_consensus::verify_block::{
    BlockRuleContext, block_witness_commitment_matches, verify_block_rules,
    verify_block_rules_precomputed,
};
use bitcoin_rs_consensus::{ConsensusError, kernel::KernelBlock};
use bitcoin_rs_primitives::layout::ParsedBlock;
use bitcoin_rs_primitives::{Block, Tx, Txid, Wtxid, consensus_bytes};

/// Legacy (pre-segwit) golden fixture height; also the mutation-fixture base.
const LEGACY_HEIGHT: u32 = 170;
/// First segwit golden fixture height; carries a BIP141 witness commitment.
const SEGWIT_HEIGHT: u32 = 481_824;
const WITNESS_COMMITMENT_PREFIX: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];

fn fixture_bytes(height: u32) -> Vec<u8> {
    let path = format!(
        "{}/../primitives/tests/testdata/{}.bin",
        env!("CARGO_MANIFEST_DIR"),
        height
    );
    std::fs::read(&path).unwrap_or_else(|error| {
        panic!("missing fixture {path} (run scripts/fetch-golden.sh): {error}")
    })
}

fn fixture_txids(height: u32) -> Vec<Txid> {
    let path = format!(
        "{}/../primitives/tests/testdata/{}.txids.txt",
        env!("CARGO_MANIFEST_DIR"),
        height
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!("missing fixture {path} (run scripts/fetch-golden.sh): {error}")
    });
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            Txid::from_str(line.trim()).unwrap_or_else(|error| panic!("bad fixture txid: {error}"))
        })
        .collect()
}

/// Length in bytes of the canonical compact-size encoding of `value`.
const fn compact_size_len(value: u64) -> u32 {
    match value {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one contract across two fixtures: ids, weight, positions, merkle"
)]
fn golden_facts_match_oracle_on_ids_weight_positions_and_merkle() {
    for height in [LEGACY_HEIGHT, SEGWIT_HEIGHT] {
        let bytes = fixture_bytes(height);
        let oracle: bitcoin::Block = bitcoin::consensus::deserialize(&bytes)
            .unwrap_or_else(|error| panic!("height {height}: oracle decode failed: {error}"));
        let expected_txids = fixture_txids(height);
        let mut reader = bytes.as_slice();
        let parsed = ParsedBlock::parse(&mut reader)
            .unwrap_or_else(|error| panic!("height {height}: layout parse failed: {error:?}"));
        assert!(
            reader.is_empty(),
            "height {height}: layout left trailing bytes"
        );
        let facts = BlockFacts::from_parsed(&parsed);

        // Identities: one-pass txids match the fixture ledger and the oracle.
        assert_eq!(
            facts.tx_count(),
            oracle.txdata.len(),
            "height {height}: tx count"
        );
        assert_eq!(
            facts.tx_count(),
            expected_txids.len(),
            "height {height}: fixture tx count"
        );
        for (index, expected) in expected_txids.iter().enumerate() {
            let ours = facts.txids()[index].to_string();
            let oracle_id = oracle.txdata[index].compute_txid().to_string();
            let fixture_id = expected.to_string();
            assert_eq!(ours, oracle_id, "height {height}: txid mismatch at {index}");
            assert_eq!(
                ours, fixture_id,
                "height {height}: fixture txid mismatch at {index}"
            );
        }

        // Witness IDs: derived in the same pass whenever the block carries
        // witness data; a witness-free block never materializes them, and a
        // legacy transaction's wtxid is its txid (BIP141).
        let oracle_has_witness = oracle
            .txdata
            .iter()
            .any(|tx| tx.input.iter().any(|input| !input.witness.is_empty()));
        assert_eq!(
            facts.has_witness(),
            oracle_has_witness,
            "height {height}: witness presence"
        );
        match facts.wtxids() {
            Some(wtxids) => {
                assert!(
                    oracle_has_witness,
                    "height {height}: wtxids without witness data"
                );
                for (index, wtxid) in wtxids.iter().enumerate() {
                    assert_eq!(
                        wtxid.to_string(),
                        oracle.txdata[index].compute_wtxid().to_string(),
                        "height {height}: wtxid mismatch at {index}"
                    );
                }
            }
            None => assert!(
                !oracle_has_witness,
                "height {height}: witness data but no wtxids"
            ),
        }

        // Weight: stripped*3+total over span-derived sizes.
        assert_eq!(
            facts.weight(),
            oracle.weight().to_wu(),
            "height {height}: block weight"
        );

        // Byte positions: the count prefix sits after the header, the spans
        // tile the tree without gaps, and every span slices exactly the
        // oracle's serialization of the same transaction.
        let spans = facts.transaction_spans();
        assert_eq!(spans.len(), facts.tx_count(), "height {height}: span count");
        assert_eq!(
            parsed.tx_count_span().start(),
            80,
            "height {height}: count prefix not after header"
        );
        assert_eq!(
            u64::from(compact_size_len(
                u64::try_from(facts.tx_count()).unwrap_or(u64::MAX)
            )),
            u64::from(parsed.tx_count_span().len()),
            "height {height}: count prefix length"
        );
        let mut expected_start = parsed.tx_count_span().end();
        for (index, span) in spans.iter().enumerate() {
            assert_eq!(
                u64::from(span.start()),
                expected_start,
                "height {height}: tx {index} span start"
            );
            let span_bytes = parsed.transactions()[index]
                .span_bytes(*span)
                .unwrap_or_else(|| panic!("height {height}: tx {index} span outside image"));
            let oracle_bytes = bitcoin::consensus::serialize(&oracle.txdata[index]);
            assert_eq!(
                span_bytes, oracle_bytes,
                "height {height}: tx {index} span bytes"
            );
            expected_start = span.end();
        }
        assert_eq!(
            expected_start,
            u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            "height {height}: spans must tile the image"
        );
        assert_eq!(
            parsed.consumed_len(),
            bytes.len(),
            "height {height}: consumed length"
        );

        // Merkle: root matches the oracle reduction and the stored header;
        // a valid fixture is never flagged as mutated.
        let oracle_root = calculate_root(oracle.txdata.iter().map(|tx| {
            bitcoin::Txid::from_str(&tx.compute_txid().to_string()).expect("oracle txid")
        }))
        .expect("oracle merkle root")
        .to_string();
        let derived_root = facts
            .merkle_root()
            .unwrap_or_else(|| panic!("height {height}: empty tree over a fixture"))
            .to_string();
        assert_eq!(derived_root, oracle_root, "height {height}: merkle root");
        assert!(
            !facts.merkle_mutated(),
            "height {height}: valid tree flagged as mutated"
        );

        // The owned materialization agrees with the derived facts and
        // re-encodes to the exact fixture bytes.
        let materialized: Block = parsed.materialize();
        assert_eq!(
            BlockFacts::block_weight(&materialized.txs),
            oracle.weight().to_wu()
        );
        assert_eq!(
            BlockFacts::from_txids(&materialized.txs, expected_txids.clone()).weight(),
            oracle.weight().to_wu()
        );
        for (index, tx) in materialized.txs.iter().enumerate() {
            assert_eq!(
                &tx.txid(),
                &facts.txids()[index],
                "height {height}: materialized txid"
            );
        }
        assert_eq!(
            consensus_bytes(&materialized),
            bytes,
            "height {height}: re-encode"
        );
    }
}

/// Pins the single-decode property of the native production path.
///
/// The runtime observable is fact provenance: byte positions and in-pass
/// witness IDs exist only on the layout single-pass shape, and the
/// second-decode shape (`from_txids`) cannot produce them. The structural
/// half is pinned by `KernelBlock::parse` itself, whose entry performs
/// exactly one decoding call — the checked layout pass; a runtime decode
/// counter would need a harness hook inside the primitives crate, outside
/// this task's write set.
#[test]
fn single_pass_shape_is_observable_and_second_decode_shape_is_not() {
    let bytes = fixture_bytes(SEGWIT_HEIGHT);
    let mut reader = bytes.as_slice();
    let parsed = ParsedBlock::parse(&mut reader).expect("layout parse");
    let facts = BlockFacts::from_parsed(&parsed);

    // Layout positions exist only on the single-pass path.
    assert_eq!(
        facts.transaction_spans().len(),
        facts.tx_count(),
        "one-pass facts must carry byte positions"
    );
    // Witness IDs were computed inside the same pass; no lazy second hash
    // was needed to produce them.
    assert!(
        facts.wtxids().is_some(),
        "witness-carrying facts must arrive with witness IDs populated"
    );

    // The from_txids shape (identities handed in from elsewhere) carries no
    // positions and leaves witness IDs lazy: it is not the single-pass shape.
    let materialized: Block = parsed.materialize();
    let txids: Vec<Txid> = materialized.txs.iter().map(Tx::txid).collect();
    let handed_in = BlockFacts::from_txids(&materialized.txs, txids);
    assert!(handed_in.transaction_spans().is_empty());
    assert!(handed_in.wtxids().is_none());
    assert_eq!(handed_in.txids(), facts.txids());
    assert_eq!(handed_in.weight(), facts.weight());
    assert_eq!(handed_in.merkle_root(), facts.merkle_root());
    assert_eq!(handed_in.merkle_mutated(), facts.merkle_mutated());
}

#[test]
fn kernel_block_entry_matches_oracle_identities() {
    let bytes = fixture_bytes(SEGWIT_HEIGHT);
    let oracle: bitcoin::Block = bitcoin::consensus::deserialize(&bytes).expect("oracle decode");
    let parsed = KernelBlock::parse(&bytes).expect("one-pass block parse");
    // The kernel build surfaces identities as a Result; the native build
    // hands them over as an already-derived slice.
    #[cfg(not(feature = "kernel"))]
    let parsed_txids: Vec<Txid> = parsed.txids().to_vec();
    #[cfg(feature = "kernel")]
    let parsed_txids: Vec<Txid> = parsed
        .txids()
        .unwrap_or_else(|error| panic!("kernel txids failed: {error:?}"));

    assert_eq!(parsed.transaction_count(), oracle.txdata.len());
    assert_eq!(parsed_txids.len(), oracle.txdata.len());
    for (ours, oracle_tx) in parsed_txids.iter().zip(&oracle.txdata) {
        assert_eq!(ours.to_string(), oracle_tx.compute_txid().to_string());
    }

    // The derived facts agree with the independent reduction regardless of
    // which backend produced the identities.
    let mut reader = bytes.as_slice();
    let layout = ParsedBlock::parse(&mut reader).expect("layout parse");
    let materialized: Block = layout.materialize();
    let facts = parsed.derive_facts(&materialized.txs, &parsed_txids);
    assert_eq!(facts.tx_count(), oracle.txdata.len());
    assert_eq!(facts.weight(), oracle.weight().to_wu());
    assert_eq!(
        facts.merkle_root().expect("non-empty tree").to_string(),
        calculate_root(
            oracle
                .txdata
                .iter()
                .map(|tx| bitcoin::Txid::from_str(&tx.compute_txid().to_string()).expect("txid"))
                .collect::<Vec<_>>()
                .into_iter(),
        )
        .expect("oracle merkle root")
        .to_string(),
    );

    #[cfg(not(feature = "kernel"))]
    {
        // Native build: the parse entry IS the single layout pass, so it
        // carries positions and pre-populated witness IDs, and rejects
        // trailing bytes like the decoder it replaced.
        assert_eq!(facts.transaction_spans().len(), facts.tx_count());
        assert!(facts.wtxids().is_some());
        assert!(parsed.facts().transaction_spans().len() == parsed.transaction_count());
        let mut padded = bytes.clone();
        padded.push(0x00);
        assert!(
            KernelBlock::parse(&padded).is_err(),
            "trailing bytes must be rejected"
        );
    }
}

#[test]
fn coinbase_witness_leaf_is_zero_for_commitment_only() {
    use bitcoin::hashes::{Hash, sha256};
    let bytes = fixture_bytes(SEGWIT_HEIGHT);
    let oracle: bitcoin::Block = bitcoin::consensus::deserialize(&bytes).expect("oracle decode");
    let mut reader = bytes.as_slice();
    let parsed = ParsedBlock::parse(&mut reader).expect("layout parse");
    let facts = BlockFacts::from_parsed(&parsed);
    let materialized: Block = parsed.materialize();
    let wtxids: &[Wtxid] = facts.wtxids().expect("segwit fixture carries witness IDs");

    // The production commitment check accepts the real fixture with the
    // one-pass witness IDs.
    assert!(
        block_witness_commitment_matches(&materialized, wtxids),
        "production commitment check must accept the fixture"
    );

    // Independent oracle recomputation: the witness tree's coinbase leaf is
    // all zeros, the remaining leaves are the other transactions' wtxids,
    // and the commitment digests root || reserved with double SHA-256.
    let oracle_leaves = std::iter::once(
        bitcoin::Txid::from_str(&"0".repeat(64)).expect("zero leaf"),
    )
    .chain(oracle.txdata.iter().skip(1).map(|tx| {
        bitcoin::Txid::from_str(&tx.compute_wtxid().to_string()).expect("oracle wtxid leaf")
    }));
    let witness_root = calculate_root(oracle_leaves).expect("oracle witness root");
    let coinbase = &oracle.txdata[0];
    let reserved = coinbase.input[0]
        .witness
        .iter()
        .find(|item| item.len() == 32)
        .expect("coinbase witness reserved value");
    let mut preimage = Vec::with_capacity(64);
    preimage.extend_from_slice(&witness_root.to_byte_array());
    preimage.extend_from_slice(reserved);
    let commitment = sha256::Hash::hash(sha256::Hash::hash(&preimage).as_byte_array());

    // The fixture's stored commitment (OP_RETURN push after the 6-byte
    // prefix) matches the independent recomputation exactly.
    let stored = coinbase
        .output
        .iter()
        .find_map(|output| {
            let script = output.script_pubkey.as_bytes();
            if script.len() == 38 && script[..6] == WITNESS_COMMITMENT_PREFIX {
                Some(&script[6..38])
            } else {
                None
            }
        })
        .expect("fixture carries a witness commitment output");
    assert_eq!(
        stored,
        commitment.as_byte_array().as_slice(),
        "oracle witness commitment"
    );

    // The zeroed leaf is a Merkle-tree convention only: the facts keep the
    // coinbase's actual wtxid.
    assert_eq!(
        wtxids[0].to_string(),
        coinbase.compute_wtxid().to_string(),
        "coinbase actual wtxid must not be zeroed"
    );
}

#[test]
fn mutated_tree_flags_merkle_mutation_while_unmutated_passes() {
    // Synthetic tree [coinbase, X, X, X]: the two trailing X transactions
    // form an equal *real* sibling pair, so the mutation flag fires even
    // though the header root — computed with the odd-leaf duplication rule —
    // matches.
    let bytes = fixture_bytes(LEGACY_HEIGHT);
    let mut reader = bytes.as_slice();
    let parsed = ParsedBlock::parse(&mut reader).expect("layout parse");
    let base: Block = parsed.materialize();
    let coinbase = base.txs[0].clone();
    let spender = base.txs[1].clone();
    let coinbase_id = coinbase.txid();
    let spender_id = spender.txid();
    let oracle_root = calculate_root(
        [
            bitcoin::Txid::from_str(&coinbase_id.to_string()).expect("txid"),
            bitcoin::Txid::from_str(&spender_id.to_string()).expect("txid"),
            bitcoin::Txid::from_str(&spender_id.to_string()).expect("txid"),
            bitcoin::Txid::from_str(&spender_id.to_string()).expect("txid"),
        ]
        .into_iter(),
    )
    .expect("oracle merkle root over mutated tree");
    let mut mutated = base.clone();
    mutated.header.merkle_root = Txid::from_str(&oracle_root.to_string())
        .expect("oracle root")
        .0;
    let leaf = spender.clone();
    let leaf2 = spender;
    let leaf3 = leaf.clone();
    mutated.txs = vec![coinbase, leaf, leaf2, leaf3];
    let mutated_ids = vec![coinbase_id, spender_id, spender_id, spender_id];
    let facts = BlockFacts::from_txids(&mutated.txs, mutated_ids);
    assert!(
        facts.merkle_mutated(),
        "equal real siblings must flag mutation"
    );
    let error =
        verify_block_rules_precomputed(&mutated, BlockRuleContext::non_contextual(), &facts)
            .expect_err("mutated tree must be rejected");
    assert!(
        matches!(error, ConsensusError::MerkleMutation),
        "expected MerkleMutation, got {error:?}"
    );

    // Control: the untouched two-transaction fixture stays valid through the
    // same rules entry.
    let control_facts = BlockFacts::from_txids(&base.txs, base.txs.iter().map(Tx::txid).collect());
    verify_block_rules_precomputed(&base, BlockRuleContext::non_contextual(), &control_facts)
        .unwrap_or_else(|error| panic!("valid fixture must pass rules: {error:?}"));
}

#[test]
fn rules_entry_accepts_golden_fixtures_from_derived_facts() {
    for height in [LEGACY_HEIGHT, SEGWIT_HEIGHT] {
        let bytes = fixture_bytes(height);
        let mut reader = bytes.as_slice();
        let parsed = ParsedBlock::parse(&mut reader).expect("layout parse");
        let block: Block = parsed.materialize();
        verify_block_rules(&block).unwrap_or_else(|error| {
            panic!("height {height}: rules must accept the fixture: {error:?}")
        });
    }
}
