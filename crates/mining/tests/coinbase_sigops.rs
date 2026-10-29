#[path = "support/fixtures.rs"]
mod common;

use std::error::Error;

use bitcoin_rs_consensus::transaction_sigop_cost;
use bitcoin_rs_mining::{
    Candidate, CandidateContext, MiningError, assemble_candidate, assemble_ordered_candidate,
};
use bitcoin_rs_primitives::{Hash256, OutPoint, Tx, Txid};
use bitcoin_rs_script::VerifyFlags;
use common::{context, insert_with_cost, oracle_sigop_cost, p2pkh, tx, zero_fee_pool};

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn budgeted_coinbase_input_growth_sigop_boundary() -> TestResult {
    use bitcoin_rs_mining::CoinbaseBudget;
    let pool = zero_fee_pool();
    let context = CandidateContext {
        segwit_active: false,
        ..context()
    };
    let budget = CoinbaseBudget {
        additional_size: 0,
        additional_sigops: 0,
    };
    let candidate = assemble_candidate(&context, &pool, &vec![0xac; 19_999])?;
    println!(
        "A declared_base_sigops=79996 budget_sigops=0 admits={:?} prefix_bytes={}",
        candidate.admits(budget),
        candidate.coinbase.inputs[0].script_sig.len()
    );
    assert!(matches!(
        candidate.admits(budget),
        Err(MiningError::CapacityExhausted { field: "sigops" })
    ));
    for (opcode, cost) in [(0xac, 80_000), (0xae, 80_076)] {
        let mut block = candidate.into_unsolved_block()?;
        let mut script = block.txs[0].inputs[0].script_sig.as_bytes().to_vec();
        script.push(opcode);
        block.txs[0].inputs[0].script_sig = script.into();
        block.header.merkle_root = Hash256::from_le_bytes(
            &bitcoin_rs_consensus::compute_merkle_root(&mut vec![*block.txs[0].txid().as_bytes()])
                .ok_or("merkle")?,
        );
        let native = bitcoin_rs_consensus::verify_block::verify_block_non_contextual(&block);
        println!(
            "A opcode={opcode:x} final_sigops={} weight={} bytes={} native={native:?}",
            oracle_sigop_cost(&block.txs[0])?,
            block.weight(),
            block.total_size()
        );
        assert_eq!(oracle_sigop_cost(&block.txs[0])?, cost);
        assert_eq!(native.is_ok(), opcode == 0xac);
    }
    let mut safe = assemble_candidate(&context, &pool, &vec![0xac; 18_040])?;
    assert!(safe.admits(budget).is_ok());
    safe.max_sigops -= 1;
    assert!(
        safe.admits(budget).is_err(),
        "the complete growth reservation is inclusive"
    );
    let mut block = safe.into_unsolved_block()?;
    let mut script = block.txs[0].inputs[0].script_sig.as_bytes().to_vec();
    script.resize(100, 0xae);
    block.txs[0].inputs[0].script_sig = script.into();
    assert_eq!(oracle_sigop_cost(&block.txs[0])?, 80_000);
    Ok(())
}

fn sigop_limited(segwit_active: bool, max_sigops: u64) -> CandidateContext {
    CandidateContext {
        segwit_active,
        max_sigops,
        ..context()
    }
}

#[test]
fn coinbase_sigops_match_consensus_cost_in_both_assembly_paths() -> TestResult {
    let pool = zero_fee_pool();
    let snapshot = pool.mining_snapshot();
    let cases = [(vec![0x51], 0), (p2pkh(), 4), (vec![0x51, 0xae], 80)];
    for segwit_active in [false, true] {
        for (payout, expected) in &cases {
            {
                let mut context = sigop_limited(segwit_active, *expected);
                let candidate = assemble_candidate(&context, &pool, payout)?;
                assert_costs(&candidate, payout, segwit_active, *expected)?;
                if *expected > 0 {
                    context.max_sigops -= 1;
                    assert!(matches!(
                        assemble_candidate(&context, &pool, payout),
                        Err(MiningError::CapacityExhausted { field: "sigops" })
                    ));
                }
            }
            {
                let mut context = sigop_limited(segwit_active, *expected);
                let candidate = assemble_ordered_candidate(&context, &snapshot, payout)?;
                assert_costs(&candidate, payout, segwit_active, *expected)?;
                if *expected > 0 {
                    context.max_sigops -= 1;
                    assert!(matches!(
                        assemble_ordered_candidate(&context, &snapshot, payout),
                        Err(MiningError::CapacityExhausted { field: "sigops" })
                    ));
                }
            }
        }
    }
    Ok(())
}

fn assert_costs(
    candidate: &Candidate,
    payout: &[u8],
    segwit_active: bool,
    expected: u64,
) -> TestResult {
    assert_eq!(oracle_sigop_cost(&candidate.coinbase)?, expected);
    assert_eq!(
        u64::from(transaction_sigop_cost(
            &candidate.coinbase,
            &[],
            VerifyFlags::NONE
        )),
        expected,
    );
    assert!(candidate.transactions.is_empty());
    assert_eq!(
        candidate.coinbase.outputs[0].script_pubkey.as_slice(),
        payout
    );
    assert_eq!(candidate.coinbase.has_witness(), segwit_active);
    assert_eq!(
        candidate.coinbase.outputs.len(),
        if segwit_active { 2 } else { 1 }
    );
    Ok(())
}

#[test]
fn coinbase_and_admitted_package_costs_share_one_inclusive_limit() -> TestResult {
    let payout = p2pkh();
    let mut pool = zero_fee_pool();
    let parent = transaction(None, 2_000);
    let child = transaction(Some(parent.txid()), 1_000);
    let parent_txid = parent.txid();
    let child_txid = child.txid();
    for (tx, fee) in [(parent, 100), (child, 1_000)] {
        assert_eq!(oracle_sigop_cost(&tx)?, 4);
        let cost = transaction_sigop_cost(&tx, &[], VerifyFlags::NONE);
        assert_eq!(cost, 4);
        let vsize = u32::try_from(tx.vsize())?;
        insert_with_cost(&mut pool, tx, vsize, fee, 1, 100, cost)?;
    }
    let snapshot = pool.mining_snapshot();
    for segwit_active in [false, true] {
        {
            let candidate = assemble_candidate(&sigop_limited(segwit_active, 12), &pool, &payout)?;
            assert_eq!(candidate.transactions.len(), 2);
            assert_eq!(block_sigop_cost(&candidate)?, 12);
        }
        {
            let candidate =
                assemble_ordered_candidate(&sigop_limited(segwit_active, 12), &snapshot, &payout)?;
            assert_eq!(candidate.transactions.len(), 2);
            assert_eq!(block_sigop_cost(&candidate)?, 12);
        }
        let limited = sigop_limited(segwit_active, 11);
        let selected = assemble_candidate(&limited, &pool, &payout)?;
        assert_eq!(selected.transactions.len(), 1);
        assert_eq!(selected.transactions[0].txid, parent_txid);
        assert_eq!(selected.transactions[0].fee, 100);
        assert_eq!(selected.transactions[0].depends, [0_u32; 0]);
        assert!(!selected.transactions.iter().any(|tx| tx.txid == child_txid));
        assert_eq!(block_sigop_cost(&selected)?, 8);
        assert_eq!(oracle_sigop_cost(&selected.coinbase)?, 4);
        assert!(matches!(
            assemble_ordered_candidate(&limited, &snapshot, &payout),
            Err(MiningError::CapacityExhausted { field: "sigops" })
        ));
    }
    Ok(())
}

fn block_sigop_cost(candidate: &Candidate) -> Result<u64, Box<dyn Error>> {
    Ok(candidate
        .into_unsolved_block()?
        .txs
        .iter()
        .map(oracle_sigop_cost)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .sum::<u64>())
}

fn transaction(parent: Option<Txid>, value: u64) -> Tx {
    let mut tx = tx(1, value, parent);
    tx.inputs[0].previous_output = OutPoint::new(
        parent.unwrap_or_else(|| Txid::from(Hash256::from_le_bytes(&[1; 32]))),
        0,
    );
    tx.outputs[0].script_pubkey = p2pkh().into();
    tx
}
