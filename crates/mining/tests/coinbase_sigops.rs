//! BIP141 coinbase reservation and complete-block sigop-cost boundaries.
//!
//! Core 31.1 `GetTransactionSigOpCost` scales legacy operations by four,
//! then returns immediately for coinbase. rust-bitcoin supplies an independent
//! transaction-cost oracle; admitted snapshot costs are already scaled.

use std::error::Error;
use std::sync::Arc;

use bitcoin_rs_consensus::transaction_sigop_cost;
use bitcoin_rs_mempool::{Mempool, MempoolEntry, MempoolLimits, MempoolMiningSnapshot};
use bitcoin_rs_mining::{
    Candidate, CandidateContext, MiningError, assemble_candidate, assemble_ordered_candidate,
};
use bitcoin_rs_primitives::{
    Amount, CompactTarget, Hash256, LockTime, Network, OutPoint, Script, Sequence, Tx, TxIn, TxOut,
    Txid, Witness, encode::consensus_bytes,
};
use bitcoin_rs_script::VerifyFlags;

type TestResult = Result<(), Box<dyn Error>>;
type Assemble =
    fn(&CandidateContext, &MempoolMiningSnapshot, &[u8]) -> Result<Candidate, MiningError>;

const ASSEMBLERS: [Assemble; 2] = [assemble_candidate, assemble_ordered_candidate];

#[test]
fn coinbase_sigops_match_consensus_cost_in_both_assembly_paths() -> TestResult {
    let snapshot = MempoolMiningSnapshot {
        sequence: 1,
        entries: vec![],
    };
    let cases = [(vec![0x51], 0), (p2pkh(), 4), (vec![0x51, 0xae], 80)];
    for segwit_active in [false, true] {
        for (payout, expected) in &cases {
            for assemble in ASSEMBLERS {
                let mut context = context(segwit_active, *expected);
                let candidate = assemble(&context, &snapshot, payout)?;
                assert_eq!(oracle_sigop_cost(&candidate.coinbase)?, *expected);
                assert_eq!(
                    u64::from(transaction_sigop_cost(
                        &candidate.coinbase,
                        &[],
                        VerifyFlags::NONE
                    )),
                    *expected,
                );
                assert_eq!(candidate.sigop_cost, *expected);
                assert_eq!(
                    candidate.coinbase.outputs[0].script_pubkey.as_slice(),
                    payout
                );
                assert_eq!(candidate.coinbase.has_witness(), segwit_active);
                assert_eq!(
                    candidate.coinbase.outputs.len(),
                    if segwit_active { 2 } else { 1 }
                );
                if *expected > 0 {
                    context.max_sigops -= 1;
                    assert!(matches!(
                        assemble(&context, &snapshot, payout),
                        Err(MiningError::CapacityExhausted { field: "sigops" })
                    ));
                }
            }
        }
    }
    Ok(())
}

#[test]
fn coinbase_and_admitted_package_costs_share_one_inclusive_limit() -> TestResult {
    let payout = p2pkh();
    let mut pool = Mempool::new(MempoolLimits {
        min_relay_fee_sat_per_kvb: 0,
        ..MempoolLimits::default()
    });
    let parent = transaction(None, 2_000);
    let child = transaction(Some(parent.txid()), 1_000);
    for (tx, fee) in [(parent, 100), (child, 1_000)] {
        assert_eq!(oracle_sigop_cost(&tx)?, 4);
        let cost = transaction_sigop_cost(&tx, &[], VerifyFlags::NONE);
        assert_eq!(cost, 4);
        let vsize = u32::try_from(tx.vsize())?;
        pool.insert_entry(
            MempoolEntry::new(Arc::new(tx), vsize, fee, 1, 100).with_sigop_cost(cost),
        )?;
    }
    let snapshot = pool.mining_snapshot();
    for segwit_active in [false, true] {
        for assemble in ASSEMBLERS {
            let candidate = assemble(&context(segwit_active, 12), &snapshot, &payout)?;
            assert_eq!(candidate.transactions.len(), 2);
            assert_eq!(candidate.sigop_cost, 12);
            let actual_cost = candidate
                .into_unsolved_block()
                .txs
                .iter()
                .map(oracle_sigop_cost)
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .sum::<u64>();
            assert_eq!(actual_cost, candidate.sigop_cost);
        }
        // The fee owner joins this high-fee child with its low-fee parent.
        // One less unit must exclude both, while ordered assembly must refuse.
        let limited = context(segwit_active, 11);
        let selected = assemble_candidate(&limited, &snapshot, &payout)?;
        assert!(selected.transactions.is_empty());
        assert_eq!(selected.fees, 0);
        assert_eq!(selected.sigop_cost, 4);
        assert!(matches!(
            assemble_ordered_candidate(&limited, &snapshot, &payout),
            Err(MiningError::CapacityExhausted { field: "sigops" })
        ));
    }
    Ok(())
}

fn oracle_sigop_cost(tx: &Tx) -> Result<u64, Box<dyn Error>> {
    let oracle: bitcoin::Transaction = bitcoin::consensus::deserialize(&consensus_bytes(tx))?;
    Ok(u64::try_from(oracle.total_sigop_cost(|_| None))?)
}

fn p2pkh() -> Vec<u8> {
    [vec![0x76, 0xa9, 0x14], vec![0x11; 20], vec![0x88, 0xac]].concat()
}

fn transaction(parent: Option<Txid>, value: u64) -> Tx {
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(
                parent.unwrap_or_else(|| Txid::from(Hash256::from_le_bytes(&[1; 32]))),
                0,
            ),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: p2pkh().into(),
        }],
        lock_time: LockTime::ZERO,
    }
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
