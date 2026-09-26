//! Whole-block resource limits, checked against rust-bitcoin serialization.
//!
//! BIP141 / Core 31.1 `GetBlockWeight` counts both the fixed header and the
//! `CompactSize` transaction count. POL-05 keeps fee chunks indivisible and
//! configured capacity inclusive.

use std::error::Error;
use std::sync::Arc;

use bitcoin_rs_mempool::{MempoolMiningSnapshot, SnapshotEntry};
use bitcoin_rs_mining::{
    Candidate, CandidateContext, MiningError, assemble_candidate, assemble_ordered_candidate,
};
use bitcoin_rs_primitives::{
    Amount, CompactTarget, Hash256, LockTime, Network, OutPoint, Script, Sequence, Tx, TxIn, TxOut,
    Txid, Witness, encode::consensus_bytes,
};

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
            assert_eq!(
                candidate.size - u64::try_from(candidate.coinbase.total_size())?,
                81
            );
            assert_eq!(candidate.weight - candidate.coinbase.weight(), 324);
            context.max_weight = candidate.weight;
            context.max_size = candidate.size;
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
                context.max_size = candidate.size;
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
                    assert_eq!(selected.fees, u64::try_from(body_count - 1)? * 10_000);
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
        let parent = entry(251, None, 100, segwit_active, vec![])?;
        let child = entry(252, Some(parent.txid), 1_000, segwit_active, vec![250])?;
        let descendant = entry(253, Some(child.txid), 1, segwit_active, vec![250, 251])?;
        snapshot.entries.extend([parent, child]);
        // 250 independent transactions plus this two-member fee chunk produce
        // 253 total transactions including coinbase, growing CompactSize by 2.
        let mut context = context(segwit_active);
        let boundary = assemble_ordered_candidate(&context, &snapshot, &[0x51])?;
        assert_serialized_limits(&boundary)?;
        snapshot.entries.push(descendant);
        context.max_weight = boundary.weight;
        context.max_size = boundary.size;
        let exact = assemble_candidate(&context, &snapshot, &[0x51])?;
        assert_eq!(exact.transactions.len(), 252);
        assert_eq!(exact.transactions[250].txid, snapshot.entries[250].txid);
        assert_eq!(exact.transactions[251].depends, vec![251]);
        assert_eq!(exact.fees, 2_501_100);
        assert_serialized_limits(&exact)?;
        for field in ["weight", "size"] {
            let mut limited = context.clone();
            lower_limit(&mut limited, field);
            let selected = assemble_candidate(&limited, &snapshot, &[0x51])?;
            assert_eq!(selected.transactions.len(), 250);
            assert_eq!(selected.fees, 2_500_000);
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
    let block = candidate.into_unsolved_block();
    let bytes = consensus_bytes(&block);
    let oracle: bitcoin::Block = bitcoin::consensus::deserialize(&bytes)?;
    assert_eq!(bitcoin::consensus::serialize(&oracle), bytes);
    assert_eq!(candidate.size, u64::try_from(oracle.total_size())?);
    assert_eq!(candidate.weight, oracle.weight().to_wu());
    assert_eq!(candidate.size, u64::try_from(block.total_size())?);
    assert_eq!(candidate.weight, block.weight());
    assert!(candidate.weight <= candidate.max_weight);
    assert!(candidate.size <= candidate.max_size);
    assert_eq!(
        candidate.coinbase_value,
        bitcoin_rs_consensus::block_subsidy(
            candidate.height,
            Network::Regtest.subsidy_halving_interval(),
        ) + candidate.fees,
    );
    Ok(())
}

/// Supplies independent transactions with equal fees so count boundaries decide selection.
fn snapshot(count: usize, witness: bool) -> Result<MempoolMiningSnapshot, Box<dyn Error>> {
    let entries = (1..=count)
        .map(|label| entry(u16::try_from(label)?, None, 10_000, witness, vec![]))
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
) -> Result<SnapshotEntry, Box<dyn Error>> {
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
    let size = u32::try_from(tx.total_size())?;
    let vsize = u32::try_from(tx.vsize())?;
    Ok(SnapshotEntry {
        txid: tx.txid(),
        wtxid: tx.wtxid(),
        size,
        weight: tx.weight(),
        vsize,
        bip141_vsize: vsize,
        sigop_cost: 0,
        fee,
        fee_delta: 0,
        time: 0,
        height: 0,
        ancestor_size: u64::from(vsize),
        ancestor_fee: fee,
        ancestor_fee_delta: 0,
        ancestors,
        tx,
    })
}

/// Uses generous regtest limits; each test narrows only the dimension under examination.
fn context(segwit_active: bool) -> CandidateContext {
    CandidateContext {
        previous_block_hash: Hash256::from_le_bytes(&[0x11; 32]),
        height: 100,
        version: 0x2000_0000,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        min_time: 1,
        current_time: 2,
        locktime_cutoff: 1,
        network: Network::Regtest,
        csv_active: true,
        segwit_active,
        max_weight: 4_000_000,
        max_size: 4_000_000,
        max_sigops: 80_000,
    }
}
