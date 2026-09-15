//! Boundary vectors from pinned Core `policy/packages.cpp`, `truc_policy.cpp`,
//! and `ephemeral_policy.cpp`. Policy-only shape vectors do not claim script validity.

use super::*;
use crate::{
    AdmissionChain, AdmissionOrigin, ChainAdmissionSnapshot, MempoolGateway, MempoolLimits,
    RbfError, ReplacementCandidate, SubmitError, SubmitOutcome,
};
use alloc::sync::Arc;
use bitcoin::hashes::{Hash as _, sha256};
use bitcoin_rs_primitives::{
    Amount, Hash256, LockTime, Script, Sequence, TxIn, TxOut, Txid, Witness,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn coin(tag: u32) -> OutPoint {
    let mut bytes = [0_u8; 32];
    bytes[..4].copy_from_slice(&tag.to_le_bytes());
    OutPoint::new(Txid(Hash256::from_le_bytes(&bytes)), 0)
}

fn output(value: u64) -> TxOut {
    let hash = sha256::Hash::hash(&[0x51]);
    TxOut {
        value: Amount::from_sat(value),
        script_pubkey: Script::from_bytes([vec![0, 32], hash.to_byte_array().to_vec()].concat()),
    }
}

fn spend(inputs: &[OutPoint], outputs: &[u64], witness: bool) -> Tx {
    Tx {
        version: 3,
        lock_time: LockTime::ZERO,
        inputs: inputs
            .iter()
            .map(|outpoint| TxIn {
                previous_output: *outpoint,
                sequence: Sequence::MAX,
                script_sig: Script::new(),
                witness: if witness {
                    Witness::from_stack(vec![vec![0x51]])
                } else {
                    Witness::new()
                },
            })
            .collect(),
        outputs: outputs.iter().copied().map(output).collect(),
    }
}

struct Coins(Vec<(OutPoint, TxOut)>);
impl AdmissionChain for Coins {
    fn snapshot(&self, _: &Tx) -> Option<ChainAdmissionSnapshot> {
        Some(ChainAdmissionSnapshot {
            prevouts: self.0.clone(),
            height: 200,
            csv_active: true,
            ..ChainAdmissionSnapshot::default()
        })
    }
}

fn gateway() -> MempoolGateway {
    MempoolGateway::new(
        Arc::new(parking_lot::RwLock::new(Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            ..MempoolLimits::default()
        }))),
        None,
    )
}

#[test]
fn package_count_order_conflicts_and_weight_boundaries() -> TestResult {
    let txs: Vec<_> = (1..=26)
        .map(|tag| spend(&[coin(tag)], &[10_000], false))
        .collect();
    assert!(check_structure(&txs[..25]).is_ok());
    assert_eq!(
        check_structure(&txs),
        Err(AcceptanceRejectReason::PackageCount)
    );
    assert_eq!(
        check_structure(&[txs[0].clone(), txs[0].clone()]),
        Err(AcceptanceRejectReason::PackageDuplicates)
    );
    let child = spend(&[OutPoint::new(txs[0].txid(), 0)], &[9_000], true);
    assert!(check_structure(&[txs[0].clone(), child.clone()]).is_ok());
    assert_eq!(
        check_structure(&[child, txs[0].clone()]),
        Err(AcceptanceRejectReason::PackageOrder)
    );
    let conflict = spend(&[coin(1)], &[8_000], false);
    assert_eq!(
        check_structure(&[txs[0].clone(), conflict]),
        Err(AcceptanceRejectReason::PackageConflict)
    );
    let mut weighted = txs[..2].to_vec();
    for tx in &mut weighted {
        let padding = usize::try_from(202_000 - tx.weight() - 8)?;
        tx.inputs[0].witness = Witness::from_stack(vec![vec![0; padding]]);
        let oracle: bitcoin::Transaction =
            bitcoin::consensus::deserialize(&bitcoin_rs_primitives::consensus_bytes(tx))?;
        assert_eq!(oracle.weight().to_wu(), 202_000);
    }
    assert!(check_structure(&weighted).is_ok());
    let mut padding = weighted[1].inputs[0].witness[0].clone();
    padding.push(0);
    weighted[1].inputs[0].witness = Witness::from_stack(vec![padding]);
    assert_eq!(
        check_structure(&weighted),
        Err(AcceptanceRejectReason::PackageTooLarge)
    );
    Ok(())
}

#[test]
fn zero_fee_ephemeral_parent_requires_its_child_to_spend_dust() -> TestResult {
    let gateway = gateway();
    let chain = Coins(vec![(
        coin(1),
        TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: Script::from_bytes(vec![0x51]),
        },
    )]);
    let parent = spend(&[coin(1)], &[100_000, 0], false);
    assert!(matches!(
        gateway.submit_transaction(
            Arc::new(parent.clone()),
            AdmissionOrigin::Rpc,
            None,
            0,
            &chain
        )?,
        SubmitOutcome::Committed(_)
    ));
    let missing = spend(&[OutPoint::new(parent.txid(), 0)], &[98_000], true);
    let before = {
        let pool = gateway.read();
        (
            pool.mining_snapshot().entries,
            pool.estimator_history(),
            pool.prioritised_transactions(),
            pool.sequence_number(),
        )
    };
    let facts = gateway.preview_transactions(core::slice::from_ref(&missing), None, &chain)?;
    assert_eq!(
        facts.results[0].reject_reason,
        Some(AcceptanceRejectReason::MissingEphemeralSpends)
    );
    assert_eq!(
        gateway.submit_transaction(Arc::new(missing), AdmissionOrigin::Rpc, None, 0, &chain),
        Err(SubmitError::Policy(
            AcceptanceRejectReason::MissingEphemeralSpends
        ))
    );
    {
        let pool = gateway.read();
        assert_eq!(
            (
                pool.mining_snapshot().entries,
                pool.estimator_history(),
                pool.prioritised_transactions(),
                pool.sequence_number()
            ),
            before
        );
    }
    let child = spend(
        &[
            OutPoint::new(parent.txid(), 0),
            OutPoint::new(parent.txid(), 1),
        ],
        &[98_000],
        true,
    );
    let facts = gateway.preview_transactions(core::slice::from_ref(&child), None, &chain)?;
    assert_eq!(facts.results[0].allowed, Some(true), "{facts:?}");
    gateway.submit_transaction(Arc::new(child), AdmissionOrigin::Rpc, None, 0, &chain)?;
    assert_eq!(gateway.read().len(), 2);
    Ok(())
}

#[test]
fn ephemeral_fee_overlay_rejects_without_state_changes() -> TestResult {
    let gateway = gateway();
    let parent = spend(&[coin(1)], &[100_000, 0], false);
    let chain = Coins(vec![(
        coin(1),
        TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: Script::from_bytes(vec![0x51]),
        },
    )]);
    gateway.prioritise(parent.txid(), 1)?;
    let before = gateway.read().prioritised_transactions();
    let facts = gateway.preview_transactions(core::slice::from_ref(&parent), None, &chain)?;
    assert_eq!(
        facts.results[0].reject_reason,
        Some(AcceptanceRejectReason::NonStandard(
            crate::StandardnessError::DustOutput
        ))
    );
    assert!(
        gateway
            .submit_transaction(Arc::new(parent), AdmissionOrigin::Rpc, None, 0, &chain)
            .is_err()
    );
    assert_eq!(gateway.read().prioritised_transactions(), before);
    assert_eq!(gateway.read().sequence_number(), 0);
    Ok(())
}

#[test]
fn fee_only_change_invalidates_prepared_mutation() -> TestResult {
    let mut pool = Mempool::new(MempoolLimits::default());
    let tx = spend(&[coin(1)], &[98_000], false);
    let vsize = u32::try_from(tx.vsize())?;
    let candidate = ReplacementCandidate::new(Arc::new(tx.clone()), vsize, 2_000, 1_000);
    let plan = pool.capture_replacement(&candidate, 1, 1)?.verify()?;
    pool.prioritise(tx.txid(), -1_999)?;
    assert_eq!(
        pool.sequence_number(),
        0,
        "metadata changes do not publish membership events"
    );
    let before = (pool.prioritised_transactions(), pool.estimator_history());
    assert_eq!(
        pool.commit_pool_change(plan).err(),
        Some(RbfError::StalePlan)
    );
    assert_eq!(
        (pool.prioritised_transactions(), pool.estimator_history()),
        before
    );
    assert!(pool.is_empty());
    Ok(())
}

#[test]
fn package_children_cannot_jointly_cross_a_cluster_or_truc_limit() -> TestResult {
    let gateway = gateway();
    let chain = Coins(vec![(
        coin(1),
        TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: Script::from_bytes(vec![0x51]),
        },
    )]);
    let parent = spend(&[coin(1)], &[49_000, 49_000], false);
    let child = spend(&[OutPoint::new(parent.txid(), 0)], &[47_000], true);
    let sibling = spend(&[OutPoint::new(parent.txid(), 1)], &[47_000], true);
    let facts = gateway.preview_transactions(
        &[parent.clone(), child.clone(), sibling.clone()],
        None,
        &chain,
    )?;
    assert!(matches!(
        facts.package_error,
        Some(AcceptanceRejectReason::Truc(_))
    ));
    assert!(facts.results.iter().all(|fact| fact.allowed.is_none()));
    let mut txs = [parent, child, sibling];
    // Rebuild the spend links after changing each transaction's version.
    txs[0].version = 2;
    txs[1].version = 2;
    txs[1].inputs[0].previous_output.txid = txs[0].txid();
    txs[2].version = 2;
    txs[2].inputs[0].previous_output.txid = txs[0].txid();
    gateway.pool.write().limits.cluster_count = 2;
    let facts = gateway.preview_transactions(&txs, None, &chain)?;
    assert_eq!(
        facts.package_error,
        Some(AcceptanceRejectReason::PackageCluster)
    );
    assert!(facts.results.iter().all(|fact| fact.allowed.is_none()));
    assert!(gateway.read().is_empty());
    Ok(())
}
