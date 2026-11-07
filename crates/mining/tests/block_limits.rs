use crate::support::fixtures as common;

use crate::support::TestError;
use std::sync::Arc;

use bitcoin_rs_consensus::primitives::{
    Amount, Hash256, LockTime, Network, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
    encode::consensus_bytes,
};
use bitcoin_rs_mempool::{Mempool, MempoolEntry};
use bitcoin_rs_mining::{
    Candidate, CandidateContext, MiningError, assemble_candidate, assemble_ordered_candidate,
};
use common::zero_fee_pool;

type TestResult = Result<(), TestError>;

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

fn build_pool(count: usize, witness: &Witness) -> Result<Mempool, TestError> {
    let mut pool = zero_fee_pool();
    for label in 1..=count {
        let tx = make_tx(u16::try_from(label)?, None, witness);
        insert_measured(&mut pool, tx, 10_000)?;
    }
    Ok(pool)
}

fn insert_measured(pool: &mut Mempool, tx: Tx, fee: u64) -> Result<Txid, TestError> {
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

#[test]
fn exact_sigops_limits_cover_n_minus_one_n_and_n_plus_one() -> TestResult {
    for segwit_active in [false, true] {
        let mut pool = zero_fee_pool();
        let witness = if segwit_active {
            vec![vec![0x11; 32]].into()
        } else {
            Witness::new()
        };
        let tx = make_tx(1, None, &witness);
        let txid = tx.txid();
        let vsize = u32::try_from(tx.vsize())?;
        let sigop_cost = 400_u32;
        pool.insert_entry(MempoolEntry::new(
            Arc::new(tx),
            vsize,
            10_000,
            0,
            0,
            sigop_cost,
        ))?;

        let snapshot = pool.mining_snapshot();
        let mut ctx = context(segwit_active);
        let baseline = assemble_candidate(&ctx, &pool, &[0x51])?;
        assert_eq!(baseline.transactions.len(), 1);
        assert_eq!(baseline.transactions[0].txid, txid);

        let exact_sigops = u64::from(sigop_cost);
        ctx.max_sigops = exact_sigops;
        let at_n = assemble_candidate(&ctx, &pool, &[0x51])?;
        assert_eq!(at_n.transactions.len(), 1);
        let at_n_ordered = assemble_ordered_candidate(&ctx, &snapshot, &[0x51])?;
        assert_eq!(at_n_ordered.transactions.len(), 1);

        ctx.max_sigops = exact_sigops + 1;
        let at_n_plus_one = assemble_candidate(&ctx, &pool, &[0x51])?;
        assert_eq!(at_n_plus_one.transactions.len(), 1);
        let at_n_plus_one_ordered = assemble_ordered_candidate(&ctx, &snapshot, &[0x51])?;
        assert_eq!(at_n_plus_one_ordered.transactions.len(), 1);

        ctx.max_sigops = exact_sigops.saturating_sub(1);
        let at_n_minus_one = assemble_candidate(&ctx, &pool, &[0x51])?;
        assert_eq!(at_n_minus_one.transactions.len(), 0);
        assert!(matches!(
            assemble_ordered_candidate(&ctx, &snapshot, &[0x51]),
            Err(MiningError::CapacityExhausted { field: "sigops" })
        ));
    }
    Ok(())
}

#[test]
fn empty_template_builds_valid_envelope_and_merkle_root() -> TestResult {
    for segwit_active in [false, true] {
        let pool = zero_fee_pool();
        let ctx = context(segwit_active);
        let candidate = assemble_candidate(&ctx, &pool, &[0x51])?;

        assert!(candidate.transactions.is_empty());
        let subsidy = bitcoin_rs_consensus::block_subsidy(
            candidate.height,
            Network::Regtest.subsidy_halving_interval(),
        );
        assert_eq!(candidate.coinbase_value, subsidy);

        let block = candidate.into_unsolved_block()?;
        assert_eq!(block.txs.len(), 1);
        assert_eq!(
            block.header.prev_blockhash,
            candidate.previous_block_hash.into()
        );
        assert_eq!(
            block.header.merkle_root,
            Hash256::from(candidate.coinbase.txid())
        );

        if segwit_active {
            assert!(candidate.witness_commitment.is_some());
            assert_eq!(candidate.coinbase.outputs.len(), 2);
            assert_eq!(candidate.coinbase.inputs[0].witness.len(), 1);
            assert_eq!(
                candidate.coinbase.inputs[0].witness.first(),
                Some(&[0_u8; 32][..])
            );
        } else {
            assert!(candidate.witness_commitment.is_none());
            assert_eq!(candidate.coinbase.outputs.len(), 1);
            assert!(candidate.coinbase.inputs[0].witness.is_empty());
        }
    }
    Ok(())
}

#[test]
fn non_final_locktime_mempool_tx_is_excluded_from_template() -> TestResult {
    let mut pool = zero_fee_pool();
    let mut tx = make_tx(1, None, &Witness::new());
    tx.lock_time = LockTime::from_consensus(500_000_100);
    tx.inputs[0].sequence = Sequence::from_consensus(0);
    let txid = tx.txid();
    let vsize = u32::try_from(tx.vsize())?;
    pool.insert_entry(MempoolEntry::new(Arc::new(tx), vsize, 5_000, 0, 0, 0))?;

    let mut ctx = context(false);
    ctx.height = 100;
    ctx.locktime_cutoff = 500_000_100;
    let excluded = assemble_candidate(&ctx, &pool, &[0x51])?;
    assert!(excluded.transactions.is_empty());

    ctx.locktime_cutoff = 500_000_101;
    let included = assemble_candidate(&ctx, &pool, &[0x51])?;
    assert_eq!(included.transactions.len(), 1);
    assert_eq!(included.transactions[0].txid, txid);
    Ok(())
}

#[test]
fn coinbase_budget_admission_boundaries() -> TestResult {
    use bitcoin_rs_mining::CoinbaseBudget;

    let pool = zero_fee_pool();
    let ctx = context(true);
    let candidate = assemble_candidate(&ctx, &pool, &[0x51])?;

    assert!(
        candidate
            .admits(CoinbaseBudget {
                additional_size: 10,
                additional_sigops: 10
            })
            .is_ok()
    );
    assert!(matches!(
        candidate.admits(CoinbaseBudget {
            additional_size: u32::MAX,
            additional_sigops: 0
        }),
        Err(MiningError::CapacityExhausted { field: "weight" }
            | MiningError::CandidateScalarOverflow { .. })
    ));
    let mut limited_ctx = ctx;
    limited_ctx.max_sigops = 50_000;
    let limited = assemble_candidate(&limited_ctx, &pool, &[0x51])?;
    assert!(matches!(
        limited.admits(CoinbaseBudget {
            additional_size: 0,
            additional_sigops: u16::MAX
        }),
        Err(MiningError::CapacityExhausted { field: "sigops" })
    ));
    Ok(())
}
