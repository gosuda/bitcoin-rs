//! Candidate scalar, dependency-index, and shape tests.

#[path = "common/fixtures.rs"]
mod common;

use std::error::Error;

// rust-bitcoin differential oracles: witness merkle root and sha256d commitment.
use bitcoin::Wtxid as OracleWtxid;
use bitcoin::hashes::{Hash as _, HashEngine as _, sha256d};
use bitcoin_rs_mining::{
    CandidateContext, TemplateId, WITNESS_RESERVED_VALUE, assemble_candidate,
    assemble_ordered_candidate, solve_block,
};
use bitcoin_rs_primitives::{CompactTarget, Hash256, Network, Txid};
use common::{PAYOUT, context, insert, selected_fees, tx, zero_fee_pool};

fn txids(transactions: &[bitcoin_rs_mining::CandidateTransaction]) -> Vec<Txid> {
    transactions.iter().map(|tx| tx.txid).collect()
}

/// Checks whole-block scalars and selected dependency indexes against wire and hash oracles.
#[test]
#[expect(clippy::too_many_lines)]
fn candidate_scalars_and_depends_match_selected_transactions() -> Result<(), Box<dyn Error>> {
    let mut mempool = zero_fee_pool();
    let parent = tx(1, 50_000, None);
    let parent_txid = parent.txid();
    insert(&mut mempool, parent, 150, 1_500, 1, 100)?;
    insert(
        &mut mempool,
        tx(2, 40_000, Some(parent_txid)),
        150,
        2_500,
        2,
        100,
    )?;
    for index in 3_u8..12 {
        insert(
            &mut mempool,
            tx(index, 1_000, None),
            120,
            1_000 + u64::from(index),
            u64::from(index),
            100,
        )?;
    }

    let snapshot = mempool.mining_snapshot();
    let context = CandidateContext {
        height: 250,
        version: 0x2000_0001,
        bits: CompactTarget::from_consensus(0x1d00_ffff),
        min_time: 10,
        current_time: 20,
        locktime_cutoff: 10,
        ..context()
    };
    let candidate = assemble_candidate(&context, &snapshot, PAYOUT)?;

    assert_eq!(
        candidate.template_id,
        TemplateId::new(&context.previous_block_hash, snapshot.sequence)
    );
    assert_eq!(
        candidate.template_id.as_str(),
        format!(
            "{}{}",
            context.previous_block_hash.to_string_be(),
            snapshot.sequence
        )
    );
    assert_eq!(candidate.previous_block_hash, context.previous_block_hash);
    assert_eq!(candidate.height, context.height);
    assert_eq!(candidate.version, context.version);
    assert_eq!(candidate.bits, context.bits);
    assert_eq!(candidate.mempool_sequence, snapshot.sequence);
    assert_eq!(candidate.csv_active, context.csv_active);
    assert_eq!(candidate.segwit_active, context.segwit_active);

    let mut fees = 0_u64;
    let mut positions = std::collections::BTreeMap::new();
    for (offset, tx) in candidate.transactions.iter().enumerate() {
        positions.insert(tx.txid, u32::try_from(offset + 1)?);
        fees = fees.checked_add(tx.fee).ok_or("fee")?;
        assert_eq!(tx.txid, tx.tx.txid());
        assert_eq!(tx.wtxid, tx.tx.wtxid());
    }
    for tx in &candidate.transactions {
        let mut expected = tx
            .tx
            .inputs
            .iter()
            .filter_map(|input| positions.get(&input.previous_output.txid).copied())
            .collect::<Vec<_>>();
        expected.sort_unstable();
        expected.dedup();
        assert_eq!(tx.depends, expected);
        for &depend in &tx.depends {
            assert!(depend >= 1);
            assert!(usize::try_from(depend)? <= candidate.transactions.len());
        }
    }
    let block = candidate.into_unsolved_block()?;
    let oracle: bitcoin::Block =
        bitcoin::consensus::deserialize(&bitcoin_rs_primitives::encode::consensus_bytes(&block))?;
    assert_eq!(candidate.weight, oracle.weight().to_wu());
    assert_eq!(
        candidate.coinbase_value,
        bitcoin_rs_consensus::block_subsidy(250, Network::Regtest.subsidy_halving_interval())
            + fees
    );

    // rust-bitcoin differential oracle for witness merkle and sha256d commitment.
    let mut leaves = vec![OracleWtxid::all_zeros()];
    leaves.extend(
        candidate
            .transactions
            .iter()
            .map(|tx| OracleWtxid::from_byte_array(*tx.wtxid.as_bytes())),
    );
    let root = bitcoin::merkle_tree::calculate_root(leaves.into_iter()).ok_or("root")?;
    let root = Hash256::from_le_bytes(root.as_byte_array());
    let mut engine = sha256d::Hash::engine();
    engine.input(root.as_byte_array());
    engine.input(&WITNESS_RESERVED_VALUE);
    assert_eq!(
        candidate.witness_commitment,
        Some(Hash256::from_le_bytes(
            sha256d::Hash::from_engine(engine).as_byte_array()
        ))
    );
    Ok(())
}

#[test]
fn equal_fee_ties_follow_snapshot_order_deterministically() -> Result<(), Box<dyn Error>> {
    let mut mempool = zero_fee_pool();
    for label in 1_u8..=5 {
        insert(
            &mut mempool,
            tx(label, 1_000, None),
            200,
            2_000,
            u64::from(label),
            100,
        )?;
    }
    let snapshot = mempool.mining_snapshot();
    let legacy = CandidateContext {
        previous_block_hash: Hash256::from_le_bytes(&[0x22; 32]),
        height: 10,
        version: 1,
        csv_active: false,
        segwit_active: false,
        ..context()
    };
    let first = assemble_candidate(&legacy, &snapshot, PAYOUT)?;
    let second = assemble_candidate(&legacy, &snapshot, PAYOUT)?;
    assert_eq!(txids(&first.transactions), txids(&second.transactions));
    assert_eq!(
        txids(&first.transactions),
        snapshot
            .entries
            .iter()
            .map(|entry| entry.txid)
            .collect::<Vec<_>>()
    );
    assert!(first.witness_commitment.is_none());
    Ok(())
}

#[test]
fn currentblocktx_counts_exclude_the_coinbase() -> Result<(), Box<dyn Error>> {
    let context = CandidateContext {
        previous_block_hash: Hash256::from_le_bytes(&[0x44; 32]),
        version: 1,
        ..context()
    };
    let zero = assemble_candidate(&context, &zero_fee_pool().mining_snapshot(), PAYOUT)?;
    assert_eq!(
        zero.transactions.len(),
        0,
        "coinbase-only candidate has zero non-coinbase txs"
    );

    let mut one_pool = zero_fee_pool();
    insert(&mut one_pool, tx(1, 1_000, None), 120, 1_000, 1, 100)?;
    let one = assemble_candidate(&context, &one_pool.mining_snapshot(), PAYOUT)?;
    assert_eq!(one.transactions.len(), 1);
    Ok(())
}

#[test]
fn assembly_copies_deployment_boundary_flags() -> Result<(), Box<dyn Error>> {
    let snapshot = zero_fee_pool().mining_snapshot();
    for (csv_active, segwit_active) in [(false, false), (true, false), (false, true), (true, true)]
    {
        let candidate = assemble_candidate(
            &CandidateContext {
                previous_block_hash: Hash256::from_le_bytes(&[0x55; 32]),
                height: 432,
                version: 1,
                csv_active,
                segwit_active,
                ..context()
            },
            &snapshot,
            PAYOUT,
        )?;
        assert_eq!(candidate.csv_active, csv_active);
        assert_eq!(candidate.segwit_active, segwit_active);
    }
    Ok(())
}

/// API-05: solving searches nonces until the compact target is met.
#[test]
fn candidate_solves_an_unsolved_regtest_header() -> Result<(), Box<dyn Error>> {
    let context = CandidateContext {
        height: 1,
        version: 1,
        ..context()
    };
    let candidate = assemble_candidate(&context, &zero_fee_pool().mining_snapshot(), PAYOUT)?;
    let unsolved = candidate.into_unsolved_block()?;
    assert_eq!(unsolved.txs.len(), 1);
    assert_eq!(unsolved.header.nonce, 0);
    assert_eq!(unsolved.header.bits, context.bits);
    let mut solved = candidate.into_unsolved_block()?;
    solve_block(&mut solved, 1_000_000)?;
    assert_eq!(solved.txs.len(), 1);
    assert_eq!(solved.header.prev_blockhash.0, context.previous_block_hash);
    assert!(
        bitcoin_rs_chain::compact_is_met_by(solved.header.bits, Hash256::from(solved.block_hash())),
        "solve_block must return a header whose hash meets its compact target"
    );
    Ok(())
}

/// API-05: generateblock keeps listed order and does not add those fees to the coinbase.
#[test]
fn ordered_assembly_keeps_snapshot_order() -> Result<(), Box<dyn Error>> {
    let mut mempool = zero_fee_pool();
    insert(&mut mempool, tx(1, 10_000, None), 150, 1_000, 1, 100)?;
    insert(&mut mempool, tx(2, 10_000, None), 150, 1_000, 1, 100)?;
    let snapshot = mempool.mining_snapshot();
    let context = CandidateContext {
        height: 1,
        version: 1,
        ..context()
    };
    let candidate = assemble_ordered_candidate(&context, &snapshot, PAYOUT)?;
    assert_eq!(selected_fees(&candidate), 2_000);
    assert_eq!(candidate.coinbase_value, 5_000_000_000);
    assert_eq!(
        txids(&candidate.transactions),
        snapshot
            .entries
            .iter()
            .map(|entry| entry.txid)
            .collect::<Vec<_>>()
    );
    Ok(())
}
