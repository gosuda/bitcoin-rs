//! Coinbase and witness-commitment candidate tests.

use std::error::Error;
use std::sync::Arc;

// rust-bitcoin differential oracle: sha256d engine for witness commitment.
use bitcoin::hashes::{Hash as _, HashEngine as _, sha256d};
// rust-bitcoin differential oracle: witness merkle root.
use bitcoin::Wtxid as OracleWtxid;
use bitcoin_rs_consensus::bip34::check_bip34;
use bitcoin_rs_mempool::{MempoolMiningSnapshot, SnapshotEntry};
use bitcoin_rs_mining::{
    CandidateContext, MiningError, TemplateId, WITNESS_RESERVED_VALUE, assemble_candidate,
};
use bitcoin_rs_primitives::{Amount, CompactTarget, Hash256, LockTime, Network, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness, Wtxid};

#[test]
fn empty_candidate_encodes_bip34_and_exact_subsidy() -> Result<(), Box<dyn Error>> {
    let context = context(height(800_000), true);
    let snapshot = empty_snapshot(7);
    let payout = vec![0x51];
    let candidate = assemble_candidate(&context, &snapshot, &payout)?;

    check_bip34(800_000, &candidate.coinbase.inputs[0].script_sig)?;
    assert_eq!(
        &candidate.coinbase.inputs[0].script_sig[..4],
        &[3, 0x00, 0x35, 0x0c]
    );
    assert_eq!(candidate.fees, 0);
    assert_eq!(
        candidate.coinbase_value,
        bitcoin_rs_consensus::block_subsidy(800_000, Network::Regtest.subsidy_halving_interval())
    );
    assert_eq!(candidate.coinbase.outputs[0].script_pubkey, payout);
    assert_eq!(
        candidate.template_id,
        TemplateId::new(&context.previous_block_hash, 7)
    );
    Ok(())
}

#[test]
fn small_heights_use_bip34_opcodes_and_two_byte_script_sig() -> Result<(), Box<dyn Error>> {
    for height in [1_u32, 16] {
        let candidate = assemble_candidate(&context(height, false), &empty_snapshot(1), &[])?;
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
    let parent = tx_with_witness(1, 50_000, None);
    let child = tx_with_witness(2, 40_000, Some(parent.txid()));
    let snapshot = snapshot_from_chain(
        &[
            (Arc::new(parent), 2_000, 0, vec![]),
            (Arc::new(child), 3_000, 0, vec![0]),
        ],
        9,
    );
    let candidate = assemble_candidate(&context(100, true), &snapshot, &[0x51])?;

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
    assert_eq!(candidate.witness_merkle_root, Some(expected_root));

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
            second.txid = Txid(Hash256::from_le_bytes(&[2; 32]));
            second.wtxid = Wtxid(Hash256::from_le_bytes(&[2; 32]));
            second.tx = Arc::new(tx_with_witness(2, 1_000, None));
            second
        }],
    };
    let err = assemble_candidate(&context(1, false), &snapshot, &[0x51])
        .expect_err("fee overflow must fail");
    assert_eq!(err, MiningError::FeeOverflow);
}

/// The reserved reorg batch must store resolved BIP141 cost all the way
/// through the real gateway and mining snapshot; template selection consumes it.
#[test]
fn reconsidered_prevout_cost_reaches_the_mining_sigop_budget() -> Result<(), Box<dyn Error>> {
    use bitcoin::hashes::{hash160, sha256};
    use bitcoin_rs_mempool::reconsider::DisconnectedCandidates;
    use bitcoin_rs_mempool::{AdmissionOrigin, Mempool, MempoolGateway, MempoolLimits};

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
            sequence: Sequence::from_consensus(u32::MAX),
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
        lock_time: LockTime::from_consensus(0),
    };
    let child = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(parent.txid(), 0),
            script_sig: Script::new(),
            sequence: Sequence::from_consensus(u32::MAX),
            witness: Witness::from_stack(vec![witness_script]),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(8_000),
            script_pubkey: Script::from_bytes(vec![0x51]),
        }],
        lock_time: LockTime::from_consensus(0),
    };
    let mut batch = DisconnectedCandidates::new(0, 100);
    assert!(batch.offer(&parent, |outpoint| {
        (*outpoint == funding).then(|| confirmed.clone())
    }));
    assert!(batch.offer(&child, |_| None));
    let gateway = MempoolGateway::shared(Arc::new(Mempool::new(MempoolLimits::default()).into()));
    let transition = gateway.begin_chain_change()?;
    assert!(gateway.stable_generation().is_none());
    let changes = gateway.reconsider_disconnected(AdmissionOrigin::Reorg, batch.into_entries());
    assert_eq!(changes.len(), 2);
    transition.finish()?;
    let snapshot = gateway.read().mining_snapshot();
    assert_eq!(snapshot.entries.len(), 2);
    assert_eq!(
        snapshot
            .entries
            .iter()
            .find(|entry| entry.txid == parent.txid())
            .ok_or("parent entry")?
            .sigop_cost,
        4
    );
    assert_eq!(
        snapshot
            .entries
            .iter()
            .find(|entry| entry.txid == child.txid())
            .ok_or("child entry")?
            .sigop_cost,
        2
    );

    let mut limited = context(101, true);
    limited.max_sigops = 5;
    let candidate = assemble_candidate(&limited, &snapshot, &[0x51])?;
    assert_eq!(candidate.transactions.len(), 1);
    assert_eq!(candidate.transactions[0].txid, parent.txid());
    assert_eq!(candidate.sigop_cost, 4);
    limited.max_sigops = 6;
    let candidate = assemble_candidate(&limited, &snapshot, &[0x51])?;
    assert_eq!(candidate.transactions.len(), 2);
    assert_eq!(candidate.sigop_cost, 6);
    Ok(())
}

fn context(height: u32, segwit_active: bool) -> CandidateContext {
    CandidateContext {
        previous_block_hash: Hash256::from_le_bytes(&[0xab; 32]),
        height,
        version: 0x2000_0000,
        bits: CompactTarget::from_consensus(0x207f_ffff),
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
    entries: &[(Arc<Tx>, u64, i64, Vec<u32>)],
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

fn snapshot_entry(tx: Arc<Tx>, fee: u64, fee_delta: i64, ancestors: Vec<u32>) -> SnapshotEntry {
    let weight = tx.weight();
    let size = u32::try_from(tx.total_size()).unwrap_or(u32::MAX);
    let vsize = u32::try_from(tx.vsize()).unwrap_or(u32::MAX);
    SnapshotEntry {
        txid: tx.txid(),
        wtxid: tx.wtxid(),
        vsize,
        bip141_vsize: vsize,
        size,
        weight,
        sigop_cost: 0,
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

fn tx_with_witness(label: u8, value: u64, parent: Option<Txid>) -> Tx {
    let mut bytes = [0_u8; 32];
    bytes[0] = label;
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(
                parent.unwrap_or_else(|| Txid(Hash256::from_le_bytes(&bytes))),
                0,
            ),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: vec![vec![label; 32]].into(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: vec![0x51, label].into(),
        }],
        lock_time: LockTime::ZERO,
    }
}
