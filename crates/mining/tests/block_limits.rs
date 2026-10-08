//! Whole-block resource limits, checked against rust-bitcoin serialization.
//!
//! BIP141 / Core 31.1 `GetBlockWeight` counts both the fixed header and the
//! `CompactSize` transaction count. POL-05 keeps fee chunks indivisible and
//! configured capacity inclusive.

#[path = "common/fixtures.rs"]
mod common;

use std::error::Error;
use std::sync::Arc;

use bitcoin_rs_mempool::{MempoolMiningSnapshot, SnapshotEntry};
use bitcoin_rs_mining::{
    Candidate, CandidateContext, MiningError, assemble_candidate, assemble_ordered_candidate,
};
use bitcoin_rs_primitives::{
    Amount, Hash256, LockTime, Network, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
    encode::consensus_bytes,
};
use common::measured_entry;

type TestResult = Result<(), Box<dyn Error>>;
type Assemble =
    fn(&CandidateContext, &MempoolMiningSnapshot, &[u8]) -> Result<Candidate, MiningError>;

const ASSEMBLERS: [Assemble; 2] = [assemble_candidate, assemble_ordered_candidate];

/// Checks the 80-byte header and one-byte count against an independently parsed block.
#[test]
fn empty_candidate_limits_include_the_serialized_block_envelope() -> TestResult {
    let snapshot = snapshot(0, false)?;
    for segwit_active in [false, true] {
        for assemble in ASSEMBLERS {
            let mut context = context(segwit_active);
            let candidate = assemble(&context, &snapshot, &[0x51])?;
            assert_serialized_limits(&candidate)?;
            let size = u64::try_from(candidate.into_unsolved_block()?.total_size())?;
            assert_eq!(size - u64::try_from(candidate.coinbase.total_size())?, 81);
            assert_eq!(candidate.weight - candidate.coinbase.weight(), 324);
            context.max_weight = candidate.weight;
            context.max_size = size;
            assert_serialized_limits(&assemble(&context, &snapshot, &[0x51])?)?;
            for field in ["weight", "size"] {
                let mut limited = context.clone();
                lower_limit(&mut limited, field);
                assert!(matches!(
                    assemble(&limited, &snapshot, &[0x51]),
                    Err(MiningError::CapacityExhausted { field: actual }) if actual == field
                ));
            }
        }
    }
    Ok(())
}

/// Both assemblers accept exact limits and account for the 252-to-253 count growth.
#[test]
fn exact_block_limits_cover_both_sides_of_compact_size_boundary() -> TestResult {
    for segwit_active in [false, true] {
        for body_count in [251, 252] {
            let snapshot = snapshot(body_count, segwit_active)?;
            for assemble in ASSEMBLERS {
                let mut context = context(segwit_active);
                let candidate = assemble(&context, &snapshot, &[0x51])?;
                assert_eq!(candidate.transactions.len(), body_count);
                assert_serialized_limits(&candidate)?;
                context.max_weight = candidate.weight;
                context.max_size = u64::try_from(candidate.into_unsolved_block()?.total_size())?;
                let exact = assemble(&context, &snapshot, &[0x51])?;
                assert_eq!(exact.transactions.len(), body_count);
                assert_serialized_limits(&exact)?;

                for field in ["weight", "size"] {
                    // Isolate each dimension while leaving the other generous.
                    let mut limited = context.clone();
                    lower_limit(&mut limited, field);
                    assert!(matches!(
                        assemble_ordered_candidate(&limited, &snapshot, &[0x51]),
                        Err(MiningError::CapacityExhausted { field: actual }) if actual == field
                    ));
                    let selected = assemble_candidate(&limited, &snapshot, &[0x51])?;
                    assert_eq!(selected.transactions.len(), body_count - 1);
                    assert_serialized_limits(&selected)?;
                    assert_eq!(
                        selected.transactions.iter().map(|tx| tx.fee).sum::<u64>(),
                        u64::try_from(body_count - 1)? * 10_000
                    );
                }
            }
        }
    }
    Ok(())
}

/// Count growth must reject a complete fee chunk and leave its descendants unselected.
#[test]
fn count_encoding_growth_skips_a_whole_package_and_its_descendant() -> TestResult {
    for segwit_active in [false, true] {
        let mut snapshot = snapshot(250, segwit_active)?;
        let parent = entry(251, None, 100, segwit_active, vec![]);
        let child = entry(252, Some(parent.txid), 1_000, segwit_active, vec![250]);
        let descendant = entry(253, Some(child.txid), 1, segwit_active, vec![250, 251]);
        snapshot.entries.extend([parent, child]);
        // 250 independent transactions plus this two-member fee chunk produce
        // 253 total transactions including coinbase, growing CompactSize by 2.
        let mut context = context(segwit_active);
        let boundary = assemble_ordered_candidate(&context, &snapshot, &[0x51])?;
        assert_serialized_limits(&boundary)?;
        snapshot.entries.push(descendant);
        context.max_weight = boundary.weight;
        context.max_size = u64::try_from(boundary.into_unsolved_block()?.total_size())?;
        let exact = assemble_candidate(&context, &snapshot, &[0x51])?;
        assert_eq!(exact.transactions.len(), 252);
        assert_eq!(exact.transactions[250].txid, snapshot.entries[250].txid);
        assert_eq!(exact.transactions[251].depends, vec![251]);
        assert_eq!(
            exact.transactions.iter().map(|tx| tx.fee).sum::<u64>(),
            2_501_100
        );
        assert_serialized_limits(&exact)?;
        for field in ["weight", "size"] {
            let mut limited = context.clone();
            lower_limit(&mut limited, field);
            let selected = assemble_candidate(&limited, &snapshot, &[0x51])?;
            assert_eq!(selected.transactions.len(), 250);
            assert_eq!(
                selected.transactions.iter().map(|tx| tx.fee).sum::<u64>(),
                2_500_000
            );
            assert_serialized_limits(&selected)?;
        }
    }
    Ok(())
}

/// Makes one capacity dimension one unit too small while leaving the other unconstrained.
fn lower_limit(context: &mut CandidateContext, field: &str) {
    if field == "weight" {
        context.max_weight -= 1;
        context.max_size = 4_000_000;
    } else {
        context.max_size -= 1;
        context.max_weight = 4_000_000;
    }
}

/// Compares reported totals with rust-bitcoin wire parsing and enforces configured limits.
fn assert_serialized_limits(candidate: &Candidate) -> TestResult {
    let block = candidate.into_unsolved_block()?;
    let bytes = consensus_bytes(&block);
    let oracle: bitcoin::Block = bitcoin::consensus::deserialize(&bytes)?;
    assert_eq!(bitcoin::consensus::serialize(&oracle), bytes);
    assert_eq!(
        u64::try_from(block.total_size())?,
        u64::try_from(oracle.total_size())?
    );
    assert_eq!(candidate.weight, oracle.weight().to_wu());
    assert_eq!(candidate.weight, block.weight());
    assert!(candidate.weight <= candidate.max_weight);
    assert!(u64::try_from(block.total_size())? <= candidate.max_size);
    let subsidy = bitcoin_rs_consensus::block_subsidy(
        candidate.height,
        Network::Regtest.subsidy_halving_interval(),
    );
    let fees = candidate.transactions.iter().map(|tx| tx.fee).sum::<u64>();
    // Greedy assembly claims selected fees; ordered assembly claims none.
    assert!(
        candidate.coinbase_value == subsidy + fees || candidate.coinbase_value == subsidy,
        "coinbase value is neither subsidy plus claimed fees nor bare subsidy"
    );
    Ok(())
}

/// Supplies independent transactions with equal fees so count boundaries decide selection.
fn snapshot(count: usize, witness: bool) -> Result<MempoolMiningSnapshot, Box<dyn Error>> {
    let entries = (1..=count)
        .map(|label| Ok(entry(u16::try_from(label)?, None, 10_000, witness, vec![])))
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    Ok(MempoolMiningSnapshot {
        sequence: 1,
        entries,
    })
}

/// Creates a measured transaction with optional witness and an explicit dependency edge.
fn entry(
    label: u16,
    parent: Option<Txid>,
    fee: u64,
    witness: bool,
    ancestors: Vec<u32>,
) -> SnapshotEntry {
    let mut hash = [0; 32];
    hash[..2].copy_from_slice(&label.to_le_bytes());
    let tx = Arc::new(Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(
                parent.unwrap_or_else(|| Txid::from(Hash256::from_le_bytes(&hash))),
                0,
            ),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: if witness {
                vec![vec![0x11; 32]].into()
            } else {
                Witness::new()
            },
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: vec![0x51].into(),
        }],
        lock_time: LockTime::ZERO,
    });
    measured_entry(&tx, fee, 0, ancestors)
}

fn context(segwit_active: bool) -> CandidateContext {
    CandidateContext {
        segwit_active,
        ..common::context()
    }
}
