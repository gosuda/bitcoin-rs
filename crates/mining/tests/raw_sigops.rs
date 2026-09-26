//! Ordered raw transactions use consensus costs with copied previous outputs.
//!
//! Core 31.1 `GetTransactionSigOpCost` owns the expected legacy/P2SH scaling
//! and witness activation. rust-bitcoin independently checks active costs;
//! these fixtures exercise accounting, not script validity or admission.

use std::error::Error;
use std::sync::Arc;

use bitcoin_rs_mempool::{Mempool, MempoolEntry, MempoolLimits};
use bitcoin_rs_mining::{
    CandidateContext, GenerateSelection, GenerateTx, MiningError, assemble_ordered_candidate,
    snapshot_for_selection,
};
use bitcoin_rs_primitives::{
    Amount, CompactTarget, Hash256, LockTime, Network, OutPoint, Sequence, Tx, TxIn, TxOut, Txid,
    consensus_bytes,
};
use bitcoin_rs_script::script::push_data;

type TestResult = Result<(), Box<dyn Error>>;

struct RawCase {
    previous_script: Vec<u8>,
    script_sig: Vec<u8>,
    witness: Vec<Vec<u8>>,
    active_cost: u32,
    inactive_cost: u32,
}

/// An exact sigop budget accepts the raw entry; one unit less refuses the block.
#[test]
fn raw_consensus_costs_obey_exact_ordered_limits() -> TestResult {
    let pool = Mempool::new(MempoolLimits::default());
    for case in cases() {
        let tx = raw_tx(&case);
        let prevout = previous_output(&case);
        assert_eq!(oracle_cost(&tx, &prevout)?, case.active_cost);
        for segwit_active in [false, true] {
            let expected = if segwit_active {
                case.active_cost
            } else {
                case.inactive_cost
            };
            let selection = GenerateSelection::Ordered(vec![GenerateTx::Raw(tx.clone())]);
            let snapshot = snapshot_for_selection(
                pool.mining_snapshot(),
                &selection,
                &[(tx.inputs[0].previous_output, prevout.clone())],
                segwit_active,
            )?;
            assert_eq!(snapshot.entries[0].sigop_cost, expected);
            // The P2PKH coinbase contributes four more cost units.
            let mut context = context(segwit_active, u64::from(expected) + 4);
            let candidate = assemble_ordered_candidate(&context, &snapshot, &p2pkh())?;
            assert_eq!(candidate.sigop_cost, u64::from(expected) + 4);
            context.max_sigops -= 1;
            assert!(matches!(
                assemble_ordered_candidate(&context, &snapshot, &p2pkh()),
                Err(MiningError::CapacityExhausted { field: "sigops" })
            ));
        }
    }
    Ok(())
}

/// Raw children can spend earlier raw, pool-id, or already-resolved pool entries.
#[test]
fn raw_children_resolve_only_earlier_selected_outputs() -> TestResult {
    for case in cases().into_iter().skip(1) {
        let mut parent = raw_tx(&cases()[0]);
        parent.outputs = vec![previous_output(&case)];
        let mut child = raw_tx(&case);
        child.inputs[0].previous_output = OutPoint::new(parent.txid(), 0);
        let mut pool = Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            ..MempoolLimits::default()
        });
        pool.insert_entry(MempoolEntry::new(
            Arc::new(parent.clone()),
            200,
            1_000,
            1,
            1,
        ))?;
        let admitted = pool.mining_snapshot().entries[0].clone();
        for parent_selection in [
            GenerateTx::Raw(parent.clone()),
            GenerateTx::Mempool(parent.txid()),
            GenerateTx::ResolvedMempool(admitted),
        ] {
            let selection =
                GenerateSelection::Ordered(vec![parent_selection, GenerateTx::Raw(child.clone())]);
            let snapshot = snapshot_for_selection(pool.mining_snapshot(), &selection, &[], true)?;
            assert_eq!(snapshot.entries[1].sigop_cost, case.active_cost);
        }
        // Neither an unselected pool entry nor a later listed parent resolves
        // the raw child's input. Missing-input rejection stays with validation.
        for items in [
            vec![GenerateTx::Raw(child.clone())],
            vec![GenerateTx::Raw(child.clone()), GenerateTx::Raw(parent)],
        ] {
            let snapshot = snapshot_for_selection(
                pool.mining_snapshot(),
                &GenerateSelection::Ordered(items),
                &[],
                true,
            )?;
            assert_eq!(snapshot.entries[0].sigop_cost, 4);
        }
    }
    Ok(())
}

/// Script-type fixtures distinguish legacy cost, accurate redeem cost and witness cost.
fn cases() -> Vec<RawCase> {
    let redeem = vec![0x51, 0xae];
    let witness_script = vec![0xac];
    let witness_program = bitcoin::ScriptBuf::from_bytes(witness_script.clone()).to_p2wsh();
    vec![
        RawCase {
            previous_script: vec![0x51],
            script_sig: vec![],
            witness: vec![],
            active_cost: 4,
            inactive_cost: 4,
        },
        RawCase {
            previous_script: bitcoin::ScriptBuf::from_bytes(redeem.clone())
                .to_p2sh()
                .into_bytes(),
            script_sig: push_data(&redeem),
            witness: vec![],
            active_cost: 8,
            inactive_cost: 8,
        },
        RawCase {
            previous_script: witness_program.clone().into_bytes(),
            script_sig: vec![],
            witness: vec![vec![], witness_script.clone()],
            active_cost: 5,
            inactive_cost: 4,
        },
        RawCase {
            previous_script: witness_program.to_p2sh().into_bytes(),
            script_sig: push_data(witness_program.as_bytes()),
            witness: vec![vec![], witness_script],
            active_cost: 5,
            inactive_cost: 4,
        },
    ]
}

/// Uses the independent rust-bitcoin consensus cost implementation with the same prevout.
fn oracle_cost(tx: &Tx, prevout: &TxOut) -> Result<u32, Box<dyn Error>> {
    let oracle: bitcoin::Transaction = bitcoin::consensus::deserialize(&consensus_bytes(tx))?;
    let prevout: bitcoin::TxOut = bitcoin::consensus::deserialize(&consensus_bytes(prevout))?;
    Ok(u32::try_from(
        oracle.total_sigop_cost(|_| Some(prevout.clone())),
    )?)
}

fn previous_output(case: &RawCase) -> TxOut {
    TxOut {
        value: Amount::from_sat(2_000),
        script_pubkey: case.previous_script.clone().into(),
    }
}

fn raw_tx(case: &RawCase) -> Tx {
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid::from(Hash256::from_le_bytes(&[1; 32])), 0),
            script_sig: case.script_sig.clone().into(),
            sequence: Sequence::MAX,
            witness: case.witness.clone().into(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: p2pkh().into(),
        }],
        lock_time: LockTime::ZERO,
    }
}

fn p2pkh() -> Vec<u8> {
    [vec![0x76, 0xa9, 0x14], vec![0x11; 20], vec![0x88, 0xac]].concat()
}

fn context(segwit_active: bool, max_sigops: u64) -> CandidateContext {
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
        max_sigops,
    }
}
