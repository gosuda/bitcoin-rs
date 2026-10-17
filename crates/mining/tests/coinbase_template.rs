//! Coinbase and witness-commitment candidate tests.

#[path = "support/fixtures.rs"]
mod common;

use std::error::Error;
use std::sync::Arc;

// rust-bitcoin differential oracles: witness merkle root and sha256d commitment.
use bitcoin::Wtxid as OracleWtxid;
use bitcoin::hashes::{Hash as _, HashEngine as _, sha256d};
use bitcoin_rs_consensus::ValidationEngine;
use bitcoin_rs_consensus::bip34::check_bip34;
use bitcoin_rs_mempool::{Mempool, MempoolGateway, MempoolLimits};
use bitcoin_rs_mining::{
    CandidateContext, MiningError, TemplateId, WITNESS_RESERVED_VALUE, assemble_candidate,
};
use bitcoin_rs_primitives::{
    Amount, Hash256, LockTime, Network, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
};
use common::{PAYOUT, insert, witnessed_tx, zero_fee_pool};

fn context(height: u32, segwit_active: bool) -> CandidateContext {
    CandidateContext {
        previous_block_hash: Hash256::from_le_bytes(&[0xab; 32]),
        height,
        segwit_active,
        min_time: 1_700_000_001,
        current_time: 1_700_000_600,
        locktime_cutoff: 1_700_000_000,
        ..common::context()
    }
}

/// An empty pool that has seen traffic: both generation counters have moved
/// and differ, so a dropped or transposed component changes the template
/// identity. `clear` retires both entries and, because a stored overlay
/// remains, advances the fee-delta sequence once more.
fn used_empty_pool() -> Result<Mempool, Box<dyn Error>> {
    let mut pool = zero_fee_pool();
    let first = witnessed_tx(1, 1_000, None);
    let first_txid = first.txid();
    for tx in [first, witnessed_tx(2, 1_000, None)] {
        let vsize = u32::try_from(tx.vsize())?;
        insert(&mut pool, tx, vsize, 1_000, 0, 0)?;
    }
    pool.prioritise(first_txid, 500)?;
    pool.clear();
    assert_eq!(pool.len(), 0, "the fixture pool is empty");
    assert_ne!(
        pool.fee_delta_sequence_number(),
        0,
        "prioritisation moved it"
    );
    assert_ne!(
        pool.sequence_number(),
        pool.fee_delta_sequence_number(),
        "distinct counters expose a transposed template identity"
    );
    Ok(pool)
}

#[test]
fn empty_candidate_encodes_bip34_and_exact_subsidy() -> Result<(), Box<dyn Error>> {
    let context = context(800_000, true);
    let pool = used_empty_pool()?;
    let candidate = assemble_candidate(&context, &pool, PAYOUT)?;

    check_bip34(800_000, &candidate.coinbase.inputs[0].script_sig)?;
    assert_eq!(
        &candidate.coinbase.inputs[0].script_sig[..4],
        &[3, 0x00, 0x35, 0x0c]
    );
    assert!(candidate.transactions.is_empty());
    assert_eq!(
        candidate.coinbase_value,
        bitcoin_rs_consensus::block_subsidy(800_000, Network::Regtest.subsidy_halving_interval())
    );
    assert_eq!(
        candidate.coinbase.outputs[0].script_pubkey.as_bytes(),
        PAYOUT
    );
    assert_eq!(
        candidate.template_id,
        TemplateId::with_fee_revision(
            &context.previous_block_hash,
            pool.sequence_number(),
            pool.fee_delta_sequence_number()
        )
    );
    assert_eq!(
        candidate.template_id.as_str(),
        format!(
            "{}{}:{}",
            context.previous_block_hash.to_string_be(),
            pool.sequence_number(),
            pool.fee_delta_sequence_number()
        )
    );
    Ok(())
}

#[test]
fn small_heights_use_bip34_opcodes_and_two_byte_script_sig() -> Result<(), Box<dyn Error>> {
    let pool = zero_fee_pool();
    for height in [1_u32, 16] {
        let candidate = assemble_candidate(&context(height, false), &pool, &[])?;
        check_bip34(height, &candidate.coinbase.inputs[0].script_sig)?;
        assert!(candidate.coinbase.inputs[0].script_sig.len() >= 2);
        assert!(candidate.witness_commitment.is_none());
        assert!(candidate.coinbase.inputs[0].witness.is_empty());
        assert_eq!(candidate.coinbase.outputs.len(), 1);
    }
    Ok(())
}

#[test]
fn segwit_candidate_commits_to_selected_wtxids_and_reserved_value() -> Result<(), Box<dyn Error>> {
    let parent = witnessed_tx(1, 50_000, None);
    let child = witnessed_tx(2, 40_000, Some(parent.txid()));
    let mut pool = zero_fee_pool();
    insert(
        &mut pool,
        parent.clone(),
        u32::try_from(parent.vsize())?,
        2_000,
        0,
        0,
    )?;
    insert(
        &mut pool,
        child.clone(),
        u32::try_from(child.vsize())?,
        3_000,
        0,
        0,
    )?;
    let candidate = assemble_candidate(&context(100, true), &pool, PAYOUT)?;

    assert_eq!(candidate.transactions.len(), 2);
    assert_eq!(
        candidate.transactions.iter().map(|tx| tx.fee).sum::<u64>(),
        5_000
    );
    assert_eq!(
        candidate.coinbase_value,
        bitcoin_rs_consensus::block_subsidy(100, Network::Regtest.subsidy_halving_interval())
            + 5_000
    );

    assert_eq!(
        candidate.coinbase.inputs[0].witness,
        vec![WITNESS_RESERVED_VALUE.to_vec()]
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
    let expected_root = Hash256::from_le_bytes(root.as_byte_array());
    let mut engine = sha256d::Hash::engine();
    engine.input(expected_root.as_byte_array());
    engine.input(&WITNESS_RESERVED_VALUE);
    let expected_commitment =
        Hash256::from_le_bytes(sha256d::Hash::from_engine(engine).as_byte_array());
    assert_eq!(candidate.witness_commitment, Some(expected_commitment));

    let commitment_output = candidate
        .coinbase
        .outputs
        .iter()
        .rev()
        .find(|output| output.script_pubkey.first() == Some(&0x6a))
        .ok_or("missing commitment output")?;
    let script = &commitment_output.script_pubkey;
    assert_eq!(script.len(), 38);
    assert_eq!(script[0], 0x6a);
    assert_eq!(script[1], 0x24);
    assert_eq!(&script[2..6], &[0xaa, 0x21, 0xa9, 0xed]);
    assert_eq!(&script[6..], expected_commitment.as_byte_array());
    Ok(())
}

#[test]
#[expect(clippy::expect_used)]
fn fee_overflow_is_reported_instead_of_wrapping() {
    let mut pool = zero_fee_pool();
    for tx in [witnessed_tx(1, 1_000, None), witnessed_tx(2, 1_000, None)] {
        let vsize = u32::try_from(tx.vsize()).expect("fixture vsize fits u32");
        insert(&mut pool, tx, vsize, u64::MAX, 0, 0).expect("max-fee fixture admits");
    }
    let err =
        assemble_candidate(&context(1, false), &pool, PAYOUT).expect_err("fee overflow must fail");
    assert_eq!(err, MiningError::FeeOverflow);
}

/// POL-05 and API-28 preserve the i128 modified-fee overlay. A priority boost
/// changes ordering; only the actual fee may increase the coinbase value.
#[test]
fn maximum_priority_delta_does_not_break_candidate_construction() -> Result<(), Box<dyn Error>> {
    let mut pool = Mempool::new(MempoolLimits::default());
    let tx = witnessed_tx(1, 1_000, None);
    let txid = tx.txid();
    let vsize = u32::try_from(tx.vsize())?;
    insert(&mut pool, tx, vsize, 1_000, 0, 1)?;
    pool.prioritise(txid, i64::MAX)?;
    let snapshot = pool.mining_snapshot();
    assert_eq!(snapshot.sequence, pool.sequence_number());
    assert_eq!(
        snapshot.fee_delta_sequence,
        pool.fee_delta_sequence_number(),
        "snapshot fee sequence comes from the same pool state"
    );
    assert_ne!(
        snapshot.fee_delta_sequence, 0,
        "prioritisation moves the fee sequence"
    );
    assert_eq!(
        snapshot.entries[0].fee_delta,
        i64::MAX,
        "the overlay saturates at the i64 boundary"
    );
    assert_eq!(
        snapshot.entries[0].fee, 1_000,
        "actual fees fund the coinbase, the delta only orders"
    );
    let chunks: Vec<_> = pool.chunks_by_feerate().collect();
    assert_eq!(chunks.len(), 1, "one entry, one chunk");
    assert_eq!(
        chunks[0].modified_fee,
        i128::from(i64::MAX) + 1_000,
        "the chunk keeps the full i128 modified fee"
    );
    let ctx = context(2, true);
    let candidate = assemble_candidate(&ctx, &pool, PAYOUT)?;
    assert_eq!(candidate.transactions.len(), 1);
    assert_eq!(candidate.transactions[0].txid, txid);
    assert_eq!(
        candidate.template_id,
        TemplateId::with_fee_revision(
            &ctx.previous_block_hash,
            snapshot.sequence,
            snapshot.fee_delta_sequence
        )
    );
    assert_eq!(
        candidate.transactions.iter().map(|tx| tx.fee).sum::<u64>(),
        1_000,
        "priority deltas are never coinbase income"
    );
    Ok(())
}

struct ReorgCoins {
    funding: OutPoint,
    confirmed: TxOut,
}

impl bitcoin_rs_mempool::AdmissionChain for ReorgCoins {
    fn snapshot(&self, tx: &Tx) -> Option<bitcoin_rs_mempool::ChainAdmissionSnapshot> {
        Some(bitcoin_rs_mempool::ChainAdmissionSnapshot {
            prevouts: tx
                .inputs
                .iter()
                .filter(|input| input.previous_output == self.funding)
                .map(|input| (input.previous_output, self.confirmed.clone()))
                .collect(),
            height: 100,
            ..bitcoin_rs_mempool::ChainAdmissionSnapshot::default()
        })
    }
}

fn reconsidered_sigop_fixture() -> Result<(Arc<MempoolGateway>, Tx, Tx), Box<dyn Error>> {
    use bitcoin::hashes::{hash160, sha256};

    // Both scripts succeed without signatures. Sigops in an unexecuted branch
    // are still counted: one legacy CHECKSIG costs 4, two-key witness multisig 2.
    let redeem = vec![0x00, 0x63, 0xac, 0x68, 0x51];
    let witness_script = vec![0x00, 0x63, 0x52, 0xae, 0x68, 0x51];
    let funding = OutPoint::new(Txid::from(Hash256::from_le_bytes(&[0x44; 32])), 0);
    let confirmed = TxOut {
        value: Amount::from_sat(10_000),
        script_pubkey: Script::from_bytes(
            [
                vec![0xa9, 0x14],
                hash160::Hash::hash(&redeem).to_byte_array().to_vec(),
                vec![0x87],
            ]
            .concat(),
        ),
    };
    let parent = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: funding,
            script_sig: Script::from_bytes(bitcoin_rs_script::push_data(&redeem)),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(9_000),
            script_pubkey: Script::from_bytes(
                [
                    vec![0x00, 0x20],
                    sha256::Hash::hash(&witness_script).to_byte_array().to_vec(),
                ]
                .concat(),
            ),
        }],
        lock_time: LockTime::ZERO,
    };
    let child = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(parent.txid(), 0),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_stack(vec![witness_script]),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(8_000),
            script_pubkey: Script::from_bytes([vec![0x00, 0x20], vec![0x22; 32]].concat()),
        }],
        lock_time: LockTime::ZERO,
    };
    let chain = ReorgCoins { funding, confirmed };
    let gateway = Arc::new(MempoolGateway::new(
        Arc::new(Mempool::new(MempoolLimits::default()).into()),
        None,
        ValidationEngine::Native,
        None,
    ));
    let transition = gateway.begin_chain_change()?;
    assert!(gateway.stable_generation().is_none());
    let changes = gateway.reconsider_disconnected(
        &transition,
        &chain,
        0,
        [Arc::new(parent.clone()), Arc::new(child.clone())],
    );
    assert_eq!(changes.len(), 2);
    transition.finish()?;

    Ok((gateway, parent, child))
}

/// The reserved reorg batch must store resolved BIP141 cost all the way
/// through the real gateway and pool; template selection consumes it.
#[test]
fn reconsidered_prevout_cost_reaches_the_mining_sigop_budget() -> Result<(), Box<dyn Error>> {
    let (gateway, parent, child) = reconsidered_sigop_fixture()?;
    let snapshot = gateway.read().mining_snapshot();
    assert_eq!(snapshot.entries.len(), 2);
    let entry_sigop_cost = |txid: Txid| -> Result<u32, Box<dyn Error>> {
        Ok(snapshot
            .entries
            .iter()
            .find(|entry| entry.txid == txid)
            .ok_or("missing entry")?
            .sigop_cost)
    };
    assert_eq!(entry_sigop_cost(parent.txid())?, 4);
    assert_eq!(entry_sigop_cost(child.txid())?, 2);

    let mut limited = context(101, true);
    limited.max_sigops = 5;
    let candidate = assemble_candidate(&limited, &gateway.read(), PAYOUT)?;
    // Whole chunk costs 6 over budget 5; parent prefix costs 4, meets the
    // rate floor, child omitted.
    assert_eq!(candidate.transactions.len(), 1);
    assert_eq!(candidate.transactions[0].txid, parent.txid());
    assert_eq!(candidate.transactions[0].fee, 1_000);
    assert_eq!(candidate.transactions[0].depends, [0_u32; 0]);
    assert_eq!(u64::from(candidate.transactions[0].sigop_cost), 4);
    assert!(
        !candidate
            .transactions
            .iter()
            .any(|tx| tx.txid == child.txid()),
        "the child stays omitted when only its parent prefix fits"
    );
    limited.max_sigops = 6;
    let candidate = assemble_candidate(&limited, &gateway.read(), PAYOUT)?;
    assert_eq!(candidate.transactions.len(), 2);
    assert_eq!(
        candidate
            .transactions
            .iter()
            .map(|tx| u64::from(tx.sigop_cost))
            .sum::<u64>(),
        6
    );
    Ok(())
}
