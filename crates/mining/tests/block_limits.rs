use crate::support::fixtures as common;

use std::error::Error;
use std::sync::Arc;

use bitcoin_rs_mempool::{Mempool, MempoolEntry};
use bitcoin_rs_mining::{
    Candidate, CandidateContext, MiningError, assemble_candidate, assemble_ordered_candidate,
};
use bitcoin_rs_primitives::{
    Amount, Hash256, LockTime, Network, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
    encode::consensus_bytes,
};
use common::zero_fee_pool;

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn empty_candidate_limits_include_the_serialized_block_envelope() -> TestResult {
    for segwit_active in [false, true] {
        let pool = zero_fee_pool();
        let snapshot = pool.mining_snapshot();
        {
            let mut context = context(segwit_active);
            let candidate = assemble_candidate(&context, &pool, &[0x51])?;
            assert_serialized_limits(&candidate)?;
            let size = u64::try_from(candidate.into_unsolved_block()?.total_size())?;
            assert_eq!(size - u64::try_from(candidate.coinbase.total_size())?, 81);
            assert_eq!(candidate.weight - candidate.coinbase.weight(), 324);
            context.max_weight = candidate.weight;
            context.max_size = size;
            assert_serialized_limits(&assemble_candidate(&context, &pool, &[0x51])?)?;
            for field in ["weight", "size"] {
                let mut limited = context.clone();
                lower_limit(&mut limited, field);
                assert!(matches!(
                    assemble_candidate(&limited, &pool, &[0x51]),
                    Err(MiningError::CapacityExhausted { field: actual }) if actual == field
                ));
            }
        }
        {
            let mut context = context(segwit_active);
            let candidate = assemble_ordered_candidate(&context, &snapshot, &[0x51])?;
            assert_serialized_limits(&candidate)?;
            let size = u64::try_from(candidate.into_unsolved_block()?.total_size())?;
            assert_eq!(size - u64::try_from(candidate.coinbase.total_size())?, 81);
            assert_eq!(candidate.weight - candidate.coinbase.weight(), 324);
            context.max_weight = candidate.weight;
            context.max_size = size;
            assert_serialized_limits(&assemble_ordered_candidate(&context, &snapshot, &[0x51])?)?;
            for field in ["weight", "size"] {
                let mut limited = context.clone();
                lower_limit(&mut limited, field);
                assert!(matches!(
                    assemble_ordered_candidate(&limited, &snapshot, &[0x51]),
                    Err(MiningError::CapacityExhausted { field: actual }) if actual == field
                ));
            }
        }
    }
    Ok(())
}

#[test]
fn exact_block_limits_cover_both_sides_of_compact_size_boundary() -> TestResult {
    for segwit_active in [false, true] {
        let witness: Witness = if segwit_active {
            vec![vec![0x11; 32]].into()
        } else {
            Witness::new()
        };
        for body_count in [251, 252] {
            let pool = build_pool(body_count, &witness)?;
            let snapshot = pool.mining_snapshot();
            {
                let mut context = context(segwit_active);
                let candidate = assemble_candidate(&context, &pool, &[0x51])?;
                assert_eq!(candidate.transactions.len(), body_count);
                assert_serialized_limits(&candidate)?;
                context.max_weight = candidate.weight;
                context.max_size = u64::try_from(candidate.into_unsolved_block()?.total_size())?;
                let exact = assemble_candidate(&context, &pool, &[0x51])?;
                assert_eq!(exact.transactions.len(), body_count);
                assert_serialized_limits(&exact)?;
            }
            {
                let mut context = context(segwit_active);
                let candidate = assemble_ordered_candidate(&context, &snapshot, &[0x51])?;
                assert_eq!(candidate.transactions.len(), body_count);
                assert_serialized_limits(&candidate)?;
                context.max_weight = candidate.weight;
                context.max_size = u64::try_from(candidate.into_unsolved_block()?.total_size())?;
                let exact = assemble_ordered_candidate(&context, &snapshot, &[0x51])?;
                assert_eq!(exact.transactions.len(), body_count);
                assert_serialized_limits(&exact)?;
                for field in ["weight", "size"] {
                    let mut limited = context.clone();
                    lower_limit(&mut limited, field);
                    assert!(matches!(
                        assemble_ordered_candidate(&limited, &snapshot, &[0x51]),
                        Err(MiningError::CapacityExhausted { field: actual }) if actual == field
                    ));
                    let selected = assemble_candidate(&limited, &pool, &[0x51])?;
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

#[test]
fn count_encoding_growth_fills_parent_prefix_and_skips_descendant() -> TestResult {
    for segwit_active in [false, true] {
        let witness: Witness = if segwit_active {
            vec![vec![0x11; 32]].into()
        } else {
            Witness::new()
        };
        let mut pool = build_pool(250, &witness)?;
        let parent_tx = make_tx(251, None, &witness);
        let parent_txid = parent_tx.txid();
        insert_measured(&mut pool, parent_tx, 100)?;
        let child_tx = make_tx(252, Some(parent_txid), &witness);
        let child_txid = child_tx.txid();
        insert_measured(&mut pool, child_tx, 1_000)?;
        let mut context = context(segwit_active);
        let boundary_snapshot = pool.mining_snapshot();
        let boundary = assemble_ordered_candidate(&context, &boundary_snapshot, &[0x51])?;
        assert_serialized_limits(&boundary)?;
        let descendant_tx = make_tx(253, Some(child_txid), &witness);
        let descendant_txid = descendant_tx.txid();
        insert_measured(&mut pool, descendant_tx, 1)?;
        context.max_weight = boundary.weight;
        context.max_size = u64::try_from(boundary.into_unsolved_block()?.total_size())?;
        let exact = assemble_candidate(&context, &pool, &[0x51])?;
        assert_eq!(exact.transactions.len(), 252);
        let expected_parent = pool.entry_by_txid(&parent_txid).ok_or("missing parent")?;
        assert_eq!(exact.transactions[250].txid, expected_parent.txid);
        assert_eq!(exact.transactions[250].depends, [0_u32; 0]);
        assert_eq!(exact.transactions[251].txid, child_txid);
        assert_eq!(exact.transactions[251].depends, vec![251]);
        assert!(
            !exact
                .transactions
                .iter()
                .any(|tx| tx.txid == descendant_txid)
        );
        assert_eq!(
            exact.transactions.iter().map(|tx| tx.fee).sum::<u64>(),
            2_501_100
        );
        assert_serialized_limits(&exact)?;
        for field in ["weight", "size"] {
            let mut limited = context.clone();
            lower_limit(&mut limited, field);
            let selected = assemble_candidate(&limited, &pool, &[0x51])?;
            assert_eq!(selected.transactions.len(), 251);
            assert_eq!(selected.transactions[250].txid, parent_txid);
            assert_eq!(selected.transactions[250].depends, [0_u32; 0]);
            assert!(!selected.transactions.iter().any(|tx| tx.txid == child_txid));
            assert!(
                !selected
                    .transactions
                    .iter()
                    .any(|tx| tx.txid == descendant_txid)
            );
            assert_eq!(
                selected.transactions.iter().map(|tx| tx.fee).sum::<u64>(),
                2_500_100
            );
            assert_serialized_limits(&selected)?;
        }
    }
    Ok(())
}

fn lower_limit(context: &mut CandidateContext, field: &str) {
    if field == "weight" {
        context.max_weight -= 1;
        context.max_size = 4_000_000;
    } else {
        context.max_size -= 1;
        context.max_weight = 4_000_000;
    }
}

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
    assert!(
        candidate.coinbase_value == subsidy + fees || candidate.coinbase_value == subsidy,
        "coinbase value is neither subsidy plus claimed fees nor bare subsidy"
    );
    Ok(())
}

fn build_pool(count: usize, witness: &Witness) -> Result<Mempool, Box<dyn Error>> {
    let mut pool = zero_fee_pool();
    for label in 1..=count {
        let tx = make_tx(u16::try_from(label)?, None, witness);
        insert_measured(&mut pool, tx, 10_000)?;
    }
    Ok(pool)
}

fn insert_measured(pool: &mut Mempool, tx: Tx, fee: u64) -> Result<Txid, Box<dyn Error>> {
    let txid = tx.txid();
    let vsize = u32::try_from(tx.vsize())?;
    pool.insert_entry(MempoolEntry::new(Arc::new(tx), vsize, fee, 0, 0, 0))?;
    Ok(txid)
}

fn make_tx(label: u16, parent: Option<Txid>, witness: &Witness) -> Tx {
    let mut hash = [0; 32];
    hash[..2].copy_from_slice(&label.to_le_bytes());
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(
                parent.unwrap_or_else(|| Txid::from(Hash256::from_le_bytes(&hash))),
                0,
            ),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: witness.clone(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: vec![0x51].into(),
        }],
        lock_time: LockTime::ZERO,
    }
}

fn context(segwit_active: bool) -> CandidateContext {
    CandidateContext {
        segwit_active,
        ..common::context()
    }
}
