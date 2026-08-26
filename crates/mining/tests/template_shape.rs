//! Candidate scalar, dependency-index, and shape tests.

use std::error::Error;
use std::sync::Arc;

use bitcoin::hashes::{Hash as _, HashEngine as _, sha256d};
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, Wtxid,
    absolute, transaction,
};
use bitcoin_rs_mempool::{Mempool, MempoolEntry, MempoolLimits};
use bitcoin_rs_mining::{CandidateContext, TemplateId, WITNESS_RESERVED_VALUE, assemble_candidate};
use bitcoin_rs_primitives::{Hash256, Network};

#[test]
#[allow(clippy::too_many_lines)]
fn candidate_scalars_and_depends_match_selected_transactions() -> Result<(), Box<dyn Error>> {
    let mut mempool = Mempool::new(MempoolLimits {
        min_relay_fee_sat_per_kvb: 0,
        ..MempoolLimits::default()
    });
    let parent = tx(1, 50_000, None);
    let parent_txid = parent.compute_txid();
    mempool.insert_entry(MempoolEntry::new(Arc::new(parent), 150, 1_500, 1, 100))?;
    mempool.insert_entry(MempoolEntry::new(
        Arc::new(tx(2, 40_000, Some(parent_txid))),
        150,
        2_500,
        2,
        100,
    ))?;
    for index in 3_u8..12 {
        mempool.insert_entry(MempoolEntry::new(
            Arc::new(tx(index, 1_000, None)),
            120,
            1_000 + u64::from(index),
            u64::from(index),
            100,
        ))?;
    }

    let snapshot = mempool.mining_snapshot();
    let context = CandidateContext {
        previous_block_hash: Hash256::from_le_bytes(&[0x11; 32]),
        height: 250,
        version: 0x2000_0001,
        bits: 0x1d00_ffff,
        min_time: 10,
        current_time: 20,
        locktime_cutoff: 10,
        network: Network::Regtest,
        csv_active: true,
        segwit_active: true,
        max_weight: 4_000_000,
        max_size: 4_000_000,
        max_sigops: 80_000,
    };
    let candidate = assemble_candidate(&context, &snapshot, &ScriptBuf::from_bytes(vec![0x51]))?;

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
    let mut weight = candidate.coinbase.weight().to_wu();
    let mut size = u64::try_from(candidate.coinbase.total_size())?;
    let mut sigops = u64::try_from(candidate.coinbase.total_sigop_cost(|_| None))?;
    let mut positions = std::collections::BTreeMap::new();
    for (offset, tx) in candidate.transactions.iter().enumerate() {
        positions.insert(tx.txid, u32::try_from(offset + 1)?);
        fees = fees.checked_add(tx.fee).ok_or("fee")?;
        weight = weight.checked_add(tx.weight).ok_or("weight")?;
        size = size.checked_add(u64::from(tx.size)).ok_or("size")?;
        sigops = sigops
            .checked_add(u64::from(tx.sigop_cost))
            .ok_or("sigops")?;
        assert_eq!(tx.txid, tx.tx.compute_txid());
        assert_eq!(tx.wtxid, tx.tx.compute_wtxid());
        assert_eq!(
            tx.modified_fee,
            i128::from(tx.fee) + i128::from(tx.fee_delta)
        );
    }
    for tx in &candidate.transactions {
        let mut expected = tx
            .tx
            .input
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
    assert_eq!(candidate.fees, fees);
    assert_eq!(candidate.weight, weight);
    assert_eq!(candidate.size, size);
    assert_eq!(candidate.sigop_cost, sigops);
    assert_eq!(
        candidate.coinbase_value,
        bitcoin_rs_consensus::block_subsidy(250, Network::Regtest.subsidy_halving_interval())
            + fees
    );

    let mut leaves = vec![Wtxid::all_zeros()];
    leaves.extend(candidate.transactions.iter().map(|tx| tx.wtxid));
    let root = bitcoin::merkle_tree::calculate_root(leaves.into_iter()).ok_or("root")?;
    let root = Hash256::from_le_bytes(root.as_byte_array());
    assert_eq!(candidate.witness_merkle_root, Some(root));
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
    let mut mempool = Mempool::new(MempoolLimits {
        min_relay_fee_sat_per_kvb: 0,
        ..MempoolLimits::default()
    });
    for label in 1_u8..=5 {
        mempool.insert_entry(MempoolEntry::new(
            Arc::new(tx(label, 1_000, None)),
            200,
            2_000,
            u64::from(label),
            100,
        ))?;
    }
    let snapshot = mempool.mining_snapshot();
    let first = assemble_candidate(
        &CandidateContext {
            previous_block_hash: Hash256::from_le_bytes(&[0x22; 32]),
            height: 10,
            version: 1,
            bits: 0x207f_ffff,
            min_time: 1,
            current_time: 2,
            locktime_cutoff: 1,
            network: Network::Regtest,
            csv_active: false,
            segwit_active: false,
            max_weight: 4_000_000,
            max_size: 4_000_000,
            max_sigops: 80_000,
        },
        &snapshot,
        &ScriptBuf::from_bytes(vec![0x51]),
    )?;
    let second = assemble_candidate(
        &CandidateContext {
            previous_block_hash: Hash256::from_le_bytes(&[0x22; 32]),
            height: 10,
            version: 1,
            bits: 0x207f_ffff,
            min_time: 1,
            current_time: 2,
            locktime_cutoff: 1,
            network: Network::Regtest,
            csv_active: false,
            segwit_active: false,
            max_weight: 4_000_000,
            max_size: 4_000_000,
            max_sigops: 80_000,
        },
        &snapshot,
        &ScriptBuf::from_bytes(vec![0x51]),
    )?;
    assert_eq!(
        first
            .transactions
            .iter()
            .map(|tx| tx.txid)
            .collect::<Vec<_>>(),
        second
            .transactions
            .iter()
            .map(|tx| tx.txid)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        first
            .transactions
            .iter()
            .map(|tx| tx.txid)
            .collect::<Vec<_>>(),
        snapshot
            .entries
            .iter()
            .map(|entry| entry.txid)
            .collect::<Vec<_>>()
    );
    assert!(first.witness_commitment.is_none());
    Ok(())
}

fn tx(label: u8, value: u64, parent: Option<Txid>) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(
                parent.unwrap_or_else(|| {
                    let mut bytes = [0_u8; 32];
                    bytes[0] = label;
                    Txid::from_byte_array(bytes)
                }),
                0,
            ),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51, label]),
        }],
    }
}

#[test]
fn currentblocktx_counts_exclude_the_coinbase() -> Result<(), Box<dyn Error>> {
    let payout = ScriptBuf::from_bytes(vec![0x51]);
    let empty = Mempool::new(MempoolLimits {
        min_relay_fee_sat_per_kvb: 0,
        ..MempoolLimits::default()
    });
    let zero = assemble_candidate(
        &CandidateContext {
            previous_block_hash: Hash256::from_le_bytes(&[0x44; 32]),
            height: 100,
            version: 1,
            bits: 0x207f_ffff,
            min_time: 1,
            current_time: 2,
            locktime_cutoff: 1,
            network: Network::Regtest,
            csv_active: true,
            segwit_active: true,
            max_weight: 4_000_000,
            max_size: 4_000_000,
            max_sigops: 80_000,
        },
        &empty.mining_snapshot(),
        &payout,
    )?;
    assert_eq!(
        zero.transactions.len(),
        0,
        "coinbase-only candidate has zero non-coinbase txs"
    );

    let mut one_pool = Mempool::new(MempoolLimits {
        min_relay_fee_sat_per_kvb: 0,
        ..MempoolLimits::default()
    });
    one_pool.insert_entry(MempoolEntry::new(
        Arc::new(tx(1, 1_000, None)),
        120,
        1_000,
        1,
        100,
    ))?;
    let one = assemble_candidate(
        &CandidateContext {
            previous_block_hash: Hash256::from_le_bytes(&[0x44; 32]),
            height: 100,
            version: 1,
            bits: 0x207f_ffff,
            min_time: 1,
            current_time: 2,
            locktime_cutoff: 1,
            network: Network::Regtest,
            csv_active: true,
            segwit_active: true,
            max_weight: 4_000_000,
            max_size: 4_000_000,
            max_sigops: 80_000,
        },
        &one_pool.mining_snapshot(),
        &payout,
    )?;
    assert_eq!(one.transactions.len(), 1);
    Ok(())
}

#[test]
fn assembly_copies_deployment_boundary_flags() -> Result<(), Box<dyn Error>> {
    let snapshot = Mempool::new(MempoolLimits {
        min_relay_fee_sat_per_kvb: 0,
        ..MempoolLimits::default()
    })
    .mining_snapshot();
    let payout = ScriptBuf::from_bytes(vec![0x51]);
    for (csv_active, segwit_active) in [(false, false), (true, false), (false, true), (true, true)]
    {
        let candidate = assemble_candidate(
            &CandidateContext {
                previous_block_hash: Hash256::from_le_bytes(&[0x55; 32]),
                height: 432,
                version: 1,
                bits: 0x207f_ffff,
                min_time: 1,
                current_time: 2,
                locktime_cutoff: 1,
                network: Network::Regtest,
                csv_active,
                segwit_active,
                max_weight: 4_000_000,
                max_size: 4_000_000,
                max_sigops: 80_000,
            },
            &snapshot,
            &payout,
        )?;
        assert_eq!(candidate.csv_active, csv_active);
        assert_eq!(candidate.segwit_active, segwit_active);
    }
    Ok(())
}
