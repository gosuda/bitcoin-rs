use crate::support::fixtures as common;

use std::error::Error;
use std::sync::Arc;

use bitcoin_rs_mempool::{Mempool, MempoolEntry};
use bitcoin_rs_mining::{CandidateContext, select_template_body_after};
use bitcoin_rs_primitives::{
    Amount, Block, Hash256, Header, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid,
    Witness,
};
use common::{PAYOUT, context, zero_fee_pool};

const TIME_FLAG: u32 = 1 << 22;

fn lock_child(parent: Txid, vout: u32, version: u32, sequence: u32) -> Tx {
    Tx {
        version,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(parent, vout),
            script_sig: Script::new(),
            sequence: Sequence::from_consensus(sequence),
            witness: Witness::from(vec![vec![0x51; 10]]),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(900),
            script_pubkey: Script::from(vec![0x51]),
        }],
    }
}

fn insert_staged(pool: &mut Mempool, tx: Tx) -> Result<Txid, Box<dyn Error>> {
    let txid = tx.txid();
    let vsize = u32::try_from(tx.vsize())?;
    pool.insert_entry(MempoolEntry::new(Arc::new(tx), vsize, 10_000, 0, 0, 0))
        .map_err(|error| format!("fixture insert stages: {error:?}"))?;
    Ok(txid)
}

#[test]
fn projected_staged_parent_locks_evaluate_at_the_staged_height() -> Result<(), Box<dyn Error>> {
    let mut pool = zero_fee_pool();
    let parent = Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[0x77; 32])), 0),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::from(vec![vec![0x51; 10]]),
        }],
        outputs: (0..4)
            .map(|_| TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: Script::from(vec![0x51]),
            })
            .collect(),
    };
    let parent_txid = insert_staged(&mut pool, parent.clone())?;
    let height_met = insert_staged(&mut pool, lock_child(parent_txid, 0, 2, 1))?;
    let _height_unmet = insert_staged(&mut pool, lock_child(parent_txid, 1, 2, 2))?;
    let unsigned = insert_staged(&mut pool, lock_child(parent_txid, 2, 1, 2))?;
    let timed = insert_staged(&mut pool, lock_child(parent_txid, 3, 2, TIME_FLAG | 1))?;

    let block = Block {
        header: Header::default(),
        txs: vec![parent],
    };
    let plan = pool.plan_block_removals(&block);
    assert_eq!(plan.removals.len(), 1, "only the parent stages");

    let base = context();
    let selected = select_template_body_after(&pool, &plan, &base, PAYOUT)?;
    let body: Vec<Txid> = selected.transactions.iter().map(|tx| tx.txid).collect();
    assert_eq!(body.len(), 2, "only two children survive: {body:?}");
    assert!(body.contains(&height_met), "the met height lock selects");
    assert!(body.contains(&unsigned), "the unsigned child selects");

    let met_time = CandidateContext {
        locktime_cutoff: 1_512,
        staged_parent_mtp: 1_000,
        ..base
    };
    let selected = select_template_body_after(&pool, &plan, &met_time, PAYOUT)?;
    assert!(
        selected.transactions.iter().any(|tx| tx.txid == timed),
        "a time lock met by the staged predecessor MTP selects"
    );
    let unmet_time = CandidateContext {
        locktime_cutoff: 1_511,
        staged_parent_mtp: 1_000,
        ..base
    };
    let selected = select_template_body_after(&pool, &plan, &unmet_time, PAYOUT)?;
    assert!(
        selected.transactions.iter().all(|tx| tx.txid != timed),
        "a time lock unmet by the staged predecessor MTP refuses"
    );
    Ok(())
}
