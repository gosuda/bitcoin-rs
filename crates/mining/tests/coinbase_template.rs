//! Coinbase and witness-commitment candidate tests.

use std::error::Error;
use std::sync::Arc;

use bitcoin::hashes::{Hash as _, HashEngine as _, sha256d};
use bitcoin::opcodes::all::{OP_PUSHBYTES_36, OP_RETURN};
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, Wtxid,
    absolute, transaction,
};
use bitcoin_rs_consensus::bip34::check_bip34;
use bitcoin_rs_mempool::{MempoolMiningSnapshot, SnapshotEntry};
use bitcoin_rs_mining::{
    CandidateContext, MiningError, TemplateId, WITNESS_RESERVED_VALUE, assemble_candidate,
};
use bitcoin_rs_primitives::{Hash256, Network};

#[test]
fn empty_candidate_encodes_bip34_and_exact_subsidy() -> Result<(), Box<dyn Error>> {
    let context = context(height(800_000), true);
    let snapshot = empty_snapshot(7);
    let payout = ScriptBuf::from_bytes(vec![0x51]);
    let candidate = assemble_candidate(&context, &snapshot, &payout)?;

    check_bip34(800_000, candidate.coinbase.input[0].script_sig.as_script())?;
    assert_eq!(
        &candidate.coinbase.input[0].script_sig.as_bytes()[..4],
        &[3, 0x00, 0x35, 0x0c]
    );
    assert_eq!(candidate.fees, 0);
    assert_eq!(
        candidate.coinbase_value,
        bitcoin_rs_consensus::block_subsidy(800_000, Network::Regtest.subsidy_halving_interval())
    );
    assert_eq!(
        candidate.coinbase.output[0].script_pubkey.as_bytes(),
        payout.as_bytes()
    );
    assert_eq!(
        candidate.template_id,
        TemplateId::new(&context.previous_block_hash, 7)
    );
    Ok(())
}

#[test]
fn small_heights_use_bip34_opcodes_and_two_byte_script_sig() -> Result<(), Box<dyn Error>> {
    for height in [1_u32, 16] {
        let candidate = assemble_candidate(
            &context(height, false),
            &empty_snapshot(1),
            &ScriptBuf::new(),
        )?;
        check_bip34(height, candidate.coinbase.input[0].script_sig.as_script())?;
        assert!(candidate.coinbase.input[0].script_sig.len() >= 2);
        assert!(candidate.witness_commitment.is_none());
        assert!(candidate.coinbase.input[0].witness.is_empty());
        assert_eq!(candidate.coinbase.output.len(), 1);
    }
    Ok(())
}

#[test]
fn segwit_candidate_commits_to_selected_wtxids_and_reserved_value() -> Result<(), Box<dyn Error>> {
    let parent = tx_with_witness(1, 50_000, None);
    let child = tx_with_witness(2, 40_000, Some(parent.compute_txid()));
    let snapshot = snapshot_from_chain(
        &[
            (Arc::new(parent), 2_000, 0, vec![]),
            (Arc::new(child), 3_000, 0, vec![0]),
        ],
        9,
    );
    let candidate = assemble_candidate(
        &context(100, true),
        &snapshot,
        &ScriptBuf::from_bytes(vec![0x51]),
    )?;

    assert_eq!(candidate.transactions.len(), 2);
    assert_eq!(candidate.fees, 5_000);
    assert_eq!(
        candidate.coinbase_value,
        bitcoin_rs_consensus::block_subsidy(100, Network::Regtest.subsidy_halving_interval())
            + 5_000
    );

    let reserved = candidate
        .witness_reserved_value
        .ok_or("missing reserved value")?;
    assert_eq!(reserved, WITNESS_RESERVED_VALUE);
    assert_eq!(
        candidate.coinbase.input[0].witness.to_vec(),
        vec![WITNESS_RESERVED_VALUE.to_vec()]
    );

    let mut leaves = vec![Wtxid::all_zeros()];
    for tx in &candidate.transactions {
        leaves.push(tx.wtxid);
    }
    let root = bitcoin::merkle_tree::calculate_root(leaves.into_iter()).ok_or("root")?;
    let expected_root = Hash256::from_le_bytes(root.as_byte_array());
    assert_eq!(candidate.witness_merkle_root, Some(expected_root));

    let mut engine = sha256d::Hash::engine();
    engine.input(expected_root.as_byte_array());
    engine.input(&WITNESS_RESERVED_VALUE);
    let expected_commitment =
        Hash256::from_le_bytes(sha256d::Hash::from_engine(engine).as_byte_array());
    assert_eq!(candidate.witness_commitment, Some(expected_commitment));

    let commitment_output = candidate
        .coinbase
        .output
        .iter()
        .rev()
        .find(|output| output.script_pubkey.is_op_return())
        .ok_or("missing commitment output")?;
    let script = commitment_output.script_pubkey.as_bytes();
    assert_eq!(script.len(), 38);
    assert_eq!(script[0], OP_RETURN.to_u8());
    assert_eq!(script[1], OP_PUSHBYTES_36.to_u8());
    assert_eq!(&script[2..6], &[0xaa, 0x21, 0xa9, 0xed]);
    assert_eq!(&script[6..], expected_commitment.as_byte_array());
    Ok(())
}

#[test]
#[allow(clippy::expect_used)]
fn fee_overflow_is_reported_instead_of_wrapping() {
    let entry = snapshot_entry(
        Arc::new(tx_with_witness(1, 1_000, None)),
        u64::MAX,
        0,
        vec![],
    );
    let snapshot = MempoolMiningSnapshot {
        sequence: 1,
        entries: vec![entry.clone(), {
            let mut second = entry;
            second.txid = Txid::from_byte_array([2; 32]);
            second.wtxid = Wtxid::from_byte_array([2; 32]);
            second.tx = Arc::new(tx_with_witness(2, 1_000, None));
            second
        }],
    };
    let err = assemble_candidate(
        &context(1, false),
        &snapshot,
        &ScriptBuf::from_bytes(vec![0x51]),
    )
    .expect_err("fee overflow must fail");
    assert_eq!(err, MiningError::FeeOverflow);
}

fn context(height: u32, segwit_active: bool) -> CandidateContext {
    CandidateContext {
        previous_block_hash: Hash256::from_le_bytes(&[0xab; 32]),
        height,
        version: 0x2000_0000,
        bits: 0x207f_ffff,
        min_time: 1_700_000_001,
        current_time: 1_700_000_600,
        locktime_cutoff: 1_700_000_000,
        network: Network::Regtest,
        csv_active: true,
        segwit_active,
        max_weight: 4_000_000,
        max_size: 4_000_000,
        max_sigops: 80_000,
    }
}

fn height(value: u32) -> u32 {
    value
}

fn empty_snapshot(sequence: u64) -> MempoolMiningSnapshot {
    MempoolMiningSnapshot {
        sequence,
        entries: Vec::new(),
    }
}

fn snapshot_from_chain(
    entries: &[(Arc<Transaction>, u64, i64, Vec<u32>)],
    sequence: u64,
) -> MempoolMiningSnapshot {
    MempoolMiningSnapshot {
        sequence,
        entries: entries
            .iter()
            .map(|(tx, fee, delta, ancestors)| {
                snapshot_entry(Arc::clone(tx), *fee, *delta, ancestors.clone())
            })
            .collect(),
    }
}

fn snapshot_entry(
    tx: Arc<Transaction>,
    fee: u64,
    fee_delta: i64,
    ancestors: Vec<u32>,
) -> SnapshotEntry {
    let weight = tx.weight().to_wu();
    let size = u32::try_from(tx.total_size()).unwrap_or(u32::MAX);
    let vsize = u32::try_from(tx.vsize()).unwrap_or(u32::MAX);
    SnapshotEntry {
        txid: tx.compute_txid(),
        wtxid: tx.compute_wtxid(),
        vsize,
        bip141_vsize: vsize,
        size,
        weight,
        sigop_cost: u32::try_from(tx.total_sigop_cost(|_| None)).unwrap_or(0),
        fee,
        fee_delta,
        time: 0,
        height: 0,
        ancestor_size: u64::from(vsize),
        ancestor_fee: fee,
        ancestor_fee_delta: i128::from(fee_delta),
        ancestors,
        tx,
    }
}

fn tx_with_witness(label: u8, value: u64, parent: Option<Txid>) -> Transaction {
    let mut witness = Witness::new();
    witness.push([label; 32]);
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
            witness,
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51, label]),
        }],
    }
}
