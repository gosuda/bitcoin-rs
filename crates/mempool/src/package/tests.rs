//! Boundary vectors from pinned Core `policy/packages.cpp`, `truc_policy.cpp`,
//! and `ephemeral_policy.cpp`. Policy-only shape vectors do not claim script validity.

use super::*;
use crate::{
    AdmissionChain, AdmissionOrigin, ChainAdmissionSnapshot, MempoolGateway, MempoolLimits,
    RbfError, ReplacementCandidate, SubmitError, SubmitOutcome,
};
use alloc::sync::Arc;
use bitcoin::hashes::{Hash as _, sha256};
use bitcoin_rs_consensus::ValidationEngine;
use bitcoin_rs_primitives::{
    Amount, Hash256, LockTime, Script, Sequence, TxIn, TxOut, Txid, Witness, unix_time_secs,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Records every published envelope in order.
#[derive(Default)]
struct Seen(parking_lot::Mutex<Vec<crate::MutationEnvelope>>);

impl crate::MempoolObserver for Seen {
    fn on_mutation(&self, envelope: &crate::MutationEnvelope) {
        self.0.lock().push(envelope.clone());
    }
}

#[test]
fn native_package_aggregates_cpfp_atomically_and_ignores_input_order() -> TestResult {
    let seen = Arc::new(Seen::default());
    let gateway = MempoolGateway::new(
        Arc::new(parking_lot::RwLock::new(Mempool::new(
            MempoolLimits::default(),
        ))),
        Some((seen.clone(), crate::BodyInterest::Metadata)),
        ValidationEngine::Native,
        None,
    );
    gateway.pool.write().limits.min_relay_fee_sat_per_kvb = 1_000;
    let parent = spend(&[coin(801)], &[100_000], false);
    let child = spend(&[OutPoint::new(parent.txid(), 0)], &[98_000], true);
    let chain = Coins(vec![(
        coin(801),
        TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: Script::from_bytes(vec![0x51]),
        },
    )]);
    assert!(
        gateway
            .submit_local_transaction(
                Arc::new(parent.clone()),
                crate::LocalOrigin::Rpc,
                None,
                0,
                &chain
            )
            .is_err()
    );
    let history = gateway.read().estimator_history();
    let now = unix_time_secs();
    let result = gateway.submit_local_package(
        vec![child.clone(), parent.clone()],
        crate::LocalOrigin::Rpc,
        None,
        now,
        &chain,
    )?;
    assert!(
        gateway.read().estimator_history() == history,
        "successful CPFP admission must not register fee-estimation samples"
    );
    assert_eq!(
        result
            .changes
            .iter()
            .map(|change| change.txid)
            .collect::<Vec<_>>(),
        vec![Hash256::from(parent.txid()), Hash256::from(child.txid())]
    );
    assert_eq!(
        result.sequence_of(1),
        result.sequence_of(0).map(|value| value + 1)
    );
    assert_eq!(gateway.read().len(), 2);
    {
        let pool = gateway.read();
        let parent_entry = pool.entry_by_txid(&parent.txid()).ok_or("parent missing")?;
        let child_entry = pool.entry_by_txid(&child.txid()).ok_or("child missing")?;
        let total_size = u64::from(parent_entry.vsize) + u64::from(child_entry.vsize);
        assert_eq!(parent_entry.descendant_size, total_size);
        assert_eq!(child_entry.ancestor_size, total_size);
        assert_eq!(child_entry.ancestor_fee, 2_000);
    }
    assert_eq!(
        seen.0.lock().as_slice(),
        &[crate::MutationEnvelope {
            origin: AdmissionOrigin::Rpc,
            accepted_transactions: Vec::new(),
            result
        }]
    );
    assert!(
        gateway
            .submit_local_package(
                vec![child, parent],
                crate::LocalOrigin::Rpc,
                None,
                2,
                &chain
            )?
            .is_empty()
    );
    assert_eq!(gateway.read().estimator_history(), history);
    assert_eq!(seen.0.lock().len(), 1);
    Ok(())
}

#[test]
fn native_package_consensus_failures_match_single_submission() -> TestResult {
    for script_failure in [true, false] {
        let gateway = gateway();
        let parent = spend(&[coin(810)], &[98_000], false);
        let mut child = spend(&[OutPoint::new(parent.txid(), 0)], &[96_000], true);
        if script_failure {
            child.inputs[0].witness = Witness::from_stack(vec![vec![0x00]]);
        } else {
            child.outputs[0].value = Amount::from_sat(100_000);
        }
        let child_chain = Coins(vec![(
            OutPoint::new(parent.txid(), 0),
            parent.outputs[0].clone(),
        )]);
        let package_chain = Coins(vec![(
            coin(810),
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: Script::from_bytes(vec![0x51]),
            },
        )]);
        let before = (
            gateway.read().sequence_number(),
            gateway.read().estimator_history(),
        );
        assert_eq!(
            gateway.submit_local_transaction(
                Arc::new(child.clone()),
                crate::LocalOrigin::Rpc,
                None,
                0,
                &child_chain,
            ),
            Err(SubmitError::Consensus)
        );
        for (txs, chain) in [
            (vec![child.clone()], &child_chain),
            (vec![parent, child], &package_chain),
        ] {
            let preview = gateway.preview_transactions(&txs, None, chain)?;
            assert_eq!(preview.package_error, None);
            let failed = preview.results.last().ok_or("missing preview row")?;
            assert_eq!(failed.allowed, Some(false));
            assert_eq!(
                failed.reject_reason,
                Some(AcceptanceRejectReason::ScriptVerify)
            );
            assert_eq!(
                gateway.submit_local_package(txs.clone(), crate::LocalOrigin::Rpc, None, 0, chain),
                Err(SubmitError::Consensus)
            );
            assert_eq!(gateway.preview_transactions(&txs, None, chain)?, preview);
            assert!(gateway.read().is_empty());
            assert_eq!(
                (
                    gateway.read().sequence_number(),
                    gateway.read().estimator_history(),
                ),
                before
            );
        }
    }
    Ok(())
}

#[test]
fn native_package_revalidates_fee_metadata_and_bounds_unavailable_chain_retries() {
    struct Moving<'a> {
        gateway: &'a MempoolGateway,
        coins: Coins,
        txid: Txid,
        moved: std::sync::atomic::AtomicBool,
    }
    impl AdmissionChain for Moving<'_> {
        fn snapshot(&self, tx: &Tx) -> Option<ChainAdmissionSnapshot> {
            if !self.moved.swap(true, std::sync::atomic::Ordering::SeqCst) {
                self.gateway.prioritise(self.txid, -100_000).ok()?;
            }
            self.coins.snapshot(tx)
        }
    }
    struct Unavailable(std::sync::atomic::AtomicUsize);
    impl AdmissionChain for Unavailable {
        fn snapshot(&self, _: &Tx) -> Option<ChainAdmissionSnapshot> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            None
        }
    }
    let gateway = gateway();
    let parent = spend(&[coin(806)], &[100_000], false);
    let child = spend(&[OutPoint::new(parent.txid(), 0)], &[98_000], true);
    let moving = Moving {
        gateway: &gateway,
        coins: Coins(vec![(
            coin(806),
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: Script::from_bytes(vec![0x51]),
            },
        )]),
        txid: child.txid(),
        moved: std::sync::atomic::AtomicBool::new(false),
    };
    assert!(
        gateway
            .submit_local_package(
                vec![parent.clone(), child.clone()],
                crate::LocalOrigin::Rpc,
                None,
                0,
                &moving
            )
            .is_err()
    );
    assert_eq!(gateway.read().len(), 0);
    let unavailable = Unavailable(std::sync::atomic::AtomicUsize::new(0));
    assert_eq!(
        gateway.submit_local_package(
            vec![parent, child],
            crate::LocalOrigin::Rpc,
            None,
            0,
            &unavailable
        ),
        Err(SubmitError::RetryExhausted)
    );
    assert_eq!(
        unavailable.0.load(std::sync::atomic::Ordering::SeqCst),
        crate::admission::MAX_ADMISSION_RETRIES
    );
    assert_eq!(gateway.read().sequence_number(), 0);
}

#[test]
fn native_package_failure_keeps_membership_sequence_overlay_and_estimator() -> TestResult {
    let gateway = gateway();
    gateway.pool.write().limits.min_relay_fee_sat_per_kvb = 1_000;
    let parent = spend(&[coin(802)], &[100_000], false);
    let mut child = spend(&[OutPoint::new(parent.txid(), 0)], &[98_000], true);
    child.inputs[0].witness = Witness::from_stack(vec![vec![0x00]]);
    let chain = Coins(vec![(
        coin(802),
        TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: Script::from_bytes(vec![0x51]),
        },
    )]);
    gateway.prioritise(parent.txid(), 0)?;
    let before = (
        gateway.read().sequence_number(),
        gateway.read().estimator_history(),
        gateway.read().prioritised_transactions(),
    );
    assert!(
        gateway
            .submit_local_package(
                vec![child.clone(), parent.clone()],
                crate::LocalOrigin::Rpc,
                None,
                0,
                &chain
            )
            .is_err()
    );
    // Aggregate fee refusal precedes scripts, like the owner's single path.
    child.outputs[0].value = Amount::from_sat(100_000);
    assert!(matches!(
        gateway.submit_local_package(
            vec![child, parent],
            crate::LocalOrigin::Rpc,
            None,
            0,
            &chain
        ),
        Err(SubmitError::Policy(
            AcceptanceRejectReason::MinRelayFeeNotMet
        ))
    ));
    assert_eq!(gateway.read().len(), 0);
    assert_eq!(
        (
            gateway.read().sequence_number(),
            gateway.read().estimator_history(),
            gateway.read().prioritised_transactions()
        ),
        before
    );
    Ok(())
}

#[test]
fn native_package_resident_parent_fees_do_not_subsidize_child() -> TestResult {
    let gateway = gateway();
    gateway.pool.write().limits.min_relay_fee_sat_per_kvb = 1_000;
    let parent = spend(&[coin(803)], &[90_000], false);
    let child = spend(&[OutPoint::new(parent.txid(), 0)], &[90_000], true);
    let chain = Coins(vec![(
        coin(803),
        TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: Script::from_bytes(vec![0x51]),
        },
    )]);
    let now = unix_time_secs();
    gateway.submit_local_transaction(
        Arc::new(parent.clone()),
        crate::LocalOrigin::Rpc,
        None,
        now,
        &chain,
    )?;
    let before = gateway.read().sequence_number();
    assert!(
        gateway
            .submit_local_package(
                vec![parent, child],
                crate::LocalOrigin::Rpc,
                None,
                now,
                &chain
            )
            .is_err()
    );
    assert_eq!(gateway.read().len(), 1);
    assert_eq!(gateway.read().sequence_number(), before);
    Ok(())
}

#[test]
fn native_package_uses_confirmed_parent_coins_without_readmitting_parent() -> TestResult {
    struct ConfirmedParent {
        parent: Txid,
        coins: Coins,
    }
    impl AdmissionChain for ConfirmedParent {
        fn snapshot(&self, tx: &Tx) -> Option<ChainAdmissionSnapshot> {
            let mut snapshot = self.coins.snapshot(tx)?;
            snapshot.confirmed = tx.txid() == self.parent;
            Some(snapshot)
        }
    }
    let gateway = gateway();
    gateway.pool.write().limits.min_relay_fee_sat_per_kvb = 1_000;
    let parent = spend(&[coin(807)], &[100_000], false);
    let child = spend(&[OutPoint::new(parent.txid(), 0)], &[98_000], true);
    let chain = ConfirmedParent {
        parent: parent.txid(),
        coins: Coins(vec![(
            OutPoint::new(parent.txid(), 0),
            parent.outputs[0].clone(),
        )]),
    };
    let now = unix_time_secs();
    let result = gateway.submit_local_package(
        vec![child.clone(), parent.clone()],
        crate::LocalOrigin::Rpc,
        None,
        now,
        &chain,
    )?;
    assert_eq!(result.len(), 1);
    assert_eq!(result.changes[0].txid, Hash256::from(child.txid()));
    assert!(!gateway.read().contains_txid(&parent.txid()));
    assert!(gateway.read().contains_txid(&child.txid()));
    Ok(())
}

#[test]
fn native_package_capacity_and_topology_refuse_before_mutation() {
    let gateway = gateway();
    gateway.pool.write().limits.max_total_bytes = 1;
    let parent = spend(&[coin(804)], &[100_000], false);
    let child = spend(&[OutPoint::new(parent.txid(), 0)], &[98_000], true);
    let chain = Coins(vec![(
        coin(804),
        TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: Script::from_bytes(vec![0x51]),
        },
    )]);
    assert_eq!(
        gateway.submit_local_package(
            vec![parent.clone(), child],
            crate::LocalOrigin::Rpc,
            None,
            0,
            &chain
        ),
        Err(SubmitError::Policy(AcceptanceRejectReason::Mempool(
            crate::MempoolError::Full
        )))
    );
    let unrelated = spend(&[coin(805)], &[90_000], false);
    assert!(matches!(
        gateway.submit_local_package(
            vec![parent, unrelated],
            crate::LocalOrigin::Rpc,
            None,
            0,
            &chain
        ),
        Err(SubmitError::Policy(AcceptanceRejectReason::PackageTopology))
    ));
    assert_eq!(gateway.read().len(), 0);
    assert_eq!(gateway.read().sequence_number(), 0);
}

#[test]
fn native_package_combined_cluster_limit_is_checked_before_any_insert() -> TestResult {
    let gateway = gateway();
    gateway.pool.write().limits.cluster_count = 1;
    let parent = spend(&[coin(808)], &[100_000], false);
    let child = spend(&[OutPoint::new(parent.txid(), 0)], &[98_000], true);
    let chain = Coins(vec![(
        coin(808),
        TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: Script::from_bytes(vec![0x51]),
        },
    )]);
    let txs = vec![parent, child];
    assert_eq!(
        gateway
            .preview_transactions(&txs, None, &chain)?
            .package_error,
        Some(AcceptanceRejectReason::PackageCluster)
    );
    assert_eq!(
        gateway.submit_local_package(txs, crate::LocalOrigin::Rpc, None, 0, &chain),
        Err(SubmitError::Policy(AcceptanceRejectReason::PackageCluster))
    );
    assert!(gateway.read().is_empty());
    assert_eq!(gateway.read().sequence_number(), 0);
    Ok(())
}

#[test]
fn native_package_plan_reports_stale_pool_state_without_mutation() -> TestResult {
    let gateway = gateway();
    let tx = spend(&[coin(809)], &[98_000], false);
    let txid = tx.txid();
    let entry = crate::MempoolEntry::new(
        Arc::new(tx.clone()),
        u32::try_from(tx.vsize())?,
        2_000,
        0,
        200,
        0,
    );
    let plan = gateway.read().prepare_package(vec![entry], 0)?;
    let history = gateway.read().estimator_history();
    gateway.prioritise(txid, 1)?;
    assert_eq!(
        gateway.pool.write().commit_package(plan),
        Err(crate::MempoolError::StalePolicy)
    );
    assert!(gateway.read().is_empty());
    assert_eq!(gateway.read().sequence_number(), 0);
    assert_eq!(gateway.read().estimator_history(), history);
    Ok(())
}

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
    gateway_observed(None)
}

#[test]
fn rpc_cpfp_commits_one_ordered_batch_with_actual_fees_and_pure_preview() -> TestResult {
    use crate::PackageTxResult;
    let seen = Arc::new(Seen::default());
    let gateway = gateway_observed(Some(seen.clone()));
    gateway.pool.write().limits.min_relay_fee_sat_per_kvb = 1_000;
    let parent = spend(&[coin(830)], &[100_000], false);
    let child = spend(&[OutPoint::new(parent.txid(), 0)], &[98_000], true);
    let txs = [parent, child];
    let chain = Coins(vec![(
        coin(830),
        TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: Script::from_bytes(vec![0x51]),
        },
    )]);
    let preview = gateway.preview_transactions(&txs, None, &chain)?;
    assert_eq!(
        preview.results[0].reject_reason,
        Some(AcceptanceRejectReason::MinRelayFeeNotMet)
    );
    let history = gateway.read().estimator_history();
    let submitted = gateway.submit_rpc_package(&txs, None, unix_time_secs(), &chain)?;
    assert_eq!(submitted.package_error, None);
    let mut total_size = 0_u32;
    for (tx, row) in txs.iter().zip(&submitted.tx_results) {
        let PackageTxResult::Accepted {
            vsize,
            base_fee,
            effective_includes,
            ..
        } = row
        else {
            return Err("package was not accepted".into());
        };
        total_size += *vsize;
        assert_eq!(
            *base_fee,
            if tx.txid() == txs[0].txid() { 0 } else { 2_000 }
        );
        let expected_includes: Vec<_> = txs.iter().map(Tx::wtxid).collect();
        assert_eq!(effective_includes, &expected_includes);
    }
    for row in &submitted.tx_results {
        let PackageTxResult::Accepted {
            effective_fee_rate, ..
        } = row
        else {
            unreachable!()
        };
        // Every member committed by the atomic plan reports the package's
        // aggregate rate over the same full set.
        assert_eq!(*effective_fee_rate, Some(2_000_000 / u64::from(total_size)));
    }
    let batches = seen.0.lock();
    assert_eq!(batches.len(), 1);
    assert_eq!(
        batches[0]
            .result
            .changes
            .iter()
            .map(|change| change.txid)
            .collect::<Vec<_>>(),
        txs.iter()
            .map(|tx| Hash256::from(tx.txid()))
            .collect::<Vec<_>>()
    );
    assert_eq!(gateway.read().sequence_number(), 2);
    assert_eq!(gateway.read().estimator_history(), history);
    drop(batches);
    let resident = gateway.submit_rpc_package(&txs, None, unix_time_secs(), &chain)?;
    assert!(resident.tx_results.iter().all(|row| matches!(
        row,
        PackageTxResult::Accepted {
            effective_fee_rate: None,
            ..
        }
    )));
    assert_eq!(seen.0.lock().len(), 1);
    Ok(())
}

#[test]
fn rpc_package_keeps_independent_parent_but_never_uses_its_fees_twice() -> TestResult {
    use crate::PackageTxResult;
    for invalid_script in [false, true] {
        let gateway = gateway();
        gateway.pool.write().limits.min_relay_fee_sat_per_kvb = 1_000;
        let parent = spend(&[coin(831)], &[98_000], false);
        let mut child = spend(
            &[OutPoint::new(parent.txid(), 0)],
            &[if invalid_script { 96_000 } else { 98_000 }],
            true,
        );
        if invalid_script {
            child.inputs[0].witness = Witness::from_stack(vec![vec![0x00]]);
        }
        let chain = Coins(vec![(
            coin(831),
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: Script::from_bytes(vec![0x51]),
            },
        )]);
        let expected = if invalid_script {
            SubmitError::Consensus
        } else {
            AcceptanceRejectReason::MinRelayFeeNotMet.into()
        };
        let result =
            gateway.submit_rpc_package(&[parent.clone(), child], None, unix_time_secs(), &chain)?;
        assert!(matches!(
            result.tx_results[0],
            PackageTxResult::Accepted { .. }
        ));
        assert_eq!(result.tx_results[1], PackageTxResult::Rejected(expected));
        assert_eq!(gateway.read().len(), 1);
        assert!(gateway.read().contains_txid(&parent.txid()));
        assert_eq!(gateway.read().sequence_number(), 1);
    }
    Ok(())
}

#[test]
fn rpc_package_underpayment_priority_cap_and_unsupported_shapes_mutate_nothing() -> TestResult {
    let gateway = gateway();
    gateway.pool.write().limits.min_relay_fee_sat_per_kvb = 1_000;
    let parent = spend(&[coin(832)], &[100_000], false);
    let child = spend(&[OutPoint::new(parent.txid(), 0)], &[99_999], true);
    let chain = Coins(vec![(
        coin(832),
        TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: Script::from_bytes(vec![0x51]),
        },
    )]);
    let txs = [parent.clone(), child.clone()];
    let history = gateway.read().estimator_history();
    let result = gateway.submit_rpc_package(&txs, None, unix_time_secs(), &chain)?;
    assert!(
        result
            .tx_results
            .iter()
            .all(|row| matches!(row, crate::PackageTxResult::Rejected(_)))
    );
    assert!(gateway.read().is_empty());
    assert_eq!(gateway.read().sequence_number(), 0);
    assert_eq!(gateway.read().estimator_history(), history);
    assert_eq!(
        gateway.submit_rpc_package(&[child, parent.clone()], None, 0, &chain),
        Err(AcceptanceRejectReason::PackageTopology.into())
    );
    assert_eq!(
        gateway.submit_rpc_package(&[parent.clone(), parent.clone()], None, 0, &chain),
        Err(AcceptanceRejectReason::PackageTopology.into())
    );
    assert_eq!(
        gateway.submit_rpc_package(
            &[parent.clone(), parent.clone(), parent.clone()],
            None,
            0,
            &chain
        ),
        Err(AcceptanceRejectReason::PackageUnsupported.into())
    );
    assert_eq!(
        gateway.submit_rpc_package(
            &[parent.clone(), parent.clone(), parent.clone()],
            None,
            0,
            &chain
        ),
        Err(AcceptanceRejectReason::PackageUnsupported.into())
    );
    gateway.prioritise(parent.txid(), 10_000)?;
    let capped = gateway.submit_rpc_package(&[parent], Some(1_000), unix_time_secs(), &chain)?;
    assert_eq!(
        capped.tx_results,
        vec![crate::PackageTxResult::Rejected(
            AcceptanceRejectReason::MaxFeeExceeded.into()
        )]
    );
    assert!(gateway.read().is_empty());
    assert_eq!(gateway.read().sequence_number(), 0);
    Ok(())
}

#[test]
fn rpc_package_retries_fee_revision_and_chain_fences_without_membership_leaks() -> TestResult {
    struct MovingChain<'a> {
        gateway: &'a MempoolGateway,
        chain: Coins,
        marker: bitcoin_rs_primitives::Txid,
    }
    impl AdmissionChain for MovingChain<'_> {
        fn snapshot(&self, tx: &Tx) -> Option<ChainAdmissionSnapshot> {
            self.gateway.prioritise(self.marker, 1).ok()?;
            self.chain.snapshot(tx)
        }
    }
    let gateway = Arc::new(gateway());
    let parent = spend(&[coin(833)], &[100_000], false);
    let child = spend(&[OutPoint::new(parent.txid(), 0)], &[98_000], true);
    let chain = MovingChain {
        gateway: &gateway,
        chain: Coins(vec![(
            coin(833),
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: Script::from_bytes(vec![0x51]),
            },
        )]),
        marker: coin(900).txid,
    };
    let txs = [parent, child];
    let result = gateway.submit_rpc_package(&txs, None, unix_time_secs(), &chain)?;
    assert_eq!(
        result.tx_results,
        vec![crate::PackageTxResult::Rejected(SubmitError::RetryExhausted); 2]
    );
    assert_eq!(gateway.read().sequence_number(), 0);
    assert!(gateway.read().is_empty());
    let change = gateway.begin_chain_change()?;
    let result = gateway.submit_rpc_package(&txs, None, unix_time_secs(), &chain.chain)?;
    assert_eq!(
        result.tx_results,
        vec![crate::PackageTxResult::Rejected(SubmitError::RetryExhausted); 2]
    );
    assert!(gateway.read().is_empty());
    change.finish()?;
    Ok(())
}

#[test]
fn rpc_package_capacity_and_replacement_refusals_preserve_authoritative_state() -> TestResult {
    let gateway = gateway();
    gateway.pool.write().limits.min_relay_fee_sat_per_kvb = 1_000;
    let parent = spend(&[coin(834)], &[100_000], false);
    let child = spend(&[OutPoint::new(parent.txid(), 0)], &[98_000], true);
    let chain = Coins(vec![(
        coin(834),
        TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: Script::from_bytes(vec![0x51]),
        },
    )]);
    gateway.pool.write().limits.max_total_bytes = parent.vsize() + child.vsize() - 1;
    let result = gateway.submit_rpc_package(&[parent, child], None, unix_time_secs(), &chain)?;
    assert_eq!(
        result.package_error,
        Some(AcceptanceRejectReason::Mempool(crate::MempoolError::Full))
    );
    assert!(gateway.read().is_empty());
    assert_eq!(gateway.read().sequence_number(), 0);

    gateway.pool.write().limits.max_total_bytes = 0;
    let resident = spend(&[coin(834)], &[98_000], false);
    gateway.submit_local_transaction(
        Arc::new(resident.clone()),
        crate::LocalOrigin::Rpc,
        None,
        unix_time_secs(),
        &chain,
    )?;
    let history = gateway.read().estimator_history();
    let replacement = spend(&[coin(834)], &[97_000], false);
    let child = spend(&[OutPoint::new(replacement.txid(), 0)], &[95_000], true);
    let result =
        gateway.submit_rpc_package(&[replacement, child], None, unix_time_secs(), &chain)?;
    assert_eq!(
        result.tx_results[0],
        crate::PackageTxResult::Rejected(AcceptanceRejectReason::MempoolConflict.into())
    );
    assert!(gateway.read().contains_txid(&resident.txid()));
    assert_eq!(gateway.read().len(), 1);
    assert_eq!(gateway.read().sequence_number(), 1);
    assert_eq!(gateway.read().estimator_history(), history);
    Ok(())
}

fn gateway_observed(observer: Option<Arc<dyn crate::MempoolObserver>>) -> MempoolGateway {
    MempoolGateway::new(
        Arc::new(parking_lot::RwLock::new(Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            ..MempoolLimits::default()
        }))),
        observer.map(|leg| (leg, crate::BodyInterest::Metadata)),
        ValidationEngine::Native,
        None,
    )
}

/// A resident stamped with time zero: older than the mempool lifetime
/// against any wall clock, so the tests below never sleep.
fn stale_entry(tx: &Tx) -> Result<crate::MempoolEntry, std::num::TryFromIntError> {
    Ok(crate::MempoolEntry::new(
        Arc::new(tx.clone()),
        u32::try_from(tx.vsize())?,
        1_000,
        0,
        200,
        0,
    ))
}

fn expired(txid: Txid) -> crate::MutationChange {
    crate::mutation::change(
        &txid,
        crate::MutationOutcome::Removed(crate::RemovalReason::Expiry),
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
    let now = unix_time_secs();
    assert!(matches!(
        gateway.submit_transaction(
            Arc::new(parent.clone()),
            AdmissionOrigin::Rpc,
            None,
            now,
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
    gateway.submit_transaction(Arc::new(child), AdmissionOrigin::Rpc, None, now, &chain)?;
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
    let plan = pool
        .capture_replacement(&candidate, 1, 1, crate::rbf::FeeEstimation::Estimate)?
        .verify()?;
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
    // Changing the parent's version changes its txid; relink both children.
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

// Core expires stale entries after each accepted transaction: a committed
// package does too, inside the same atomic envelope as its acceptance.
#[test]
fn native_package_commit_expires_an_unrelated_stale_entry_in_its_own_envelope() -> TestResult {
    let seen = Arc::new(Seen::default());
    let gateway = gateway_observed(Some(seen.clone()));
    let stale = spend(&[coin(820)], &[100_000], false);
    gateway.insert_entry(AdmissionOrigin::Rpc, stale_entry(&stale)?)?;
    let parent = spend(&[coin(821)], &[100_000], false);
    let child = spend(&[OutPoint::new(parent.txid(), 0)], &[98_000], true);
    let chain = Coins(vec![(
        coin(821),
        TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: Script::from_bytes(vec![0x51]),
        },
    )]);

    let result = gateway.submit_local_package(
        vec![child.clone(), parent.clone()],
        crate::LocalOrigin::Rpc,
        None,
        unix_time_secs(),
        &chain,
    )?;

    assert_eq!(result.len(), 3);
    let pool = gateway.read();
    assert!(!pool.contains_txid(&stale.txid()));
    assert!(pool.contains_txid(&parent.txid()));
    assert!(pool.contains_txid(&child.txid()));
    let envelopes = seen.0.lock();
    assert_eq!(
        envelopes.len(),
        2,
        "stale insert, atomic package and expiry commit"
    );
    assert_eq!(envelopes[1].result, result);
    assert_eq!(envelopes[1].origin, AdmissionOrigin::Rpc);
    assert_eq!(
        envelopes[1].result.changes.last(),
        Some(&expired(stale.txid()))
    );
    Ok(())
}

// A package member that expires with its stale resident parent was admitted
// and published, then removed: the caller sees the ordinary full refusal.
#[test]
fn native_package_member_expires_with_its_stale_parent_and_is_refused_as_full() -> TestResult {
    let seen = Arc::new(Seen::default());
    let gateway = gateway_observed(Some(seen.clone()));
    let parent = spend(&[coin(822)], &[100_000], false);
    let child = spend(&[OutPoint::new(parent.txid(), 0)], &[98_000], true);
    gateway.insert_entry(AdmissionOrigin::Rpc, stale_entry(&parent)?)?;

    let refused = gateway.submit_local_package(
        vec![parent.clone(), child.clone()],
        crate::LocalOrigin::Rpc,
        None,
        unix_time_secs(),
        &Coins(vec![]),
    );

    assert_eq!(
        refused,
        Err(SubmitError::Policy(AcceptanceRejectReason::Mempool(
            crate::MempoolError::Full
        )))
    );
    assert!(gateway.read().is_empty());
    let envelopes = seen.0.lock();
    assert_eq!(
        envelopes.len(),
        2,
        "stale insert, atomic package and expiry commit"
    );
    assert_eq!(
        envelopes[1].result.changes.first(),
        Some(&crate::mutation::change(
            &child.txid(),
            crate::MutationOutcome::Accepted
        )),
        "the refused member's commit stays published"
    );
    let removed = &envelopes[1].result.changes[1..];
    assert_eq!(removed.len(), 2);
    assert!(removed.contains(&expired(parent.txid())));
    assert!(removed.contains(&expired(child.txid())));
    Ok(())
}

// A stale child carried in the package was never admitted here: only its
// two independent parents are. The expiry pass removes stale roots with
// their descendants but never ancestors, so the parents survive and the
// package still succeeds. Only a removed admitted member refuses as full.
#[test]
fn native_package_commit_survives_its_stale_resident_expiring() -> TestResult {
    let seen = Arc::new(Seen::default());
    let gateway = gateway_observed(Some(seen.clone()));
    let parent_a = spend(&[coin(824)], &[100_000], false);
    let parent_b = spend(&[coin(825)], &[100_000], false);
    let resident = spend(
        &[
            OutPoint::new(parent_a.txid(), 0),
            OutPoint::new(parent_b.txid(), 0),
        ],
        &[198_000],
        true,
    );
    let parent_a_txid = parent_a.txid();
    let parent_b_txid = parent_b.txid();
    let resident_txid = resident.txid();
    gateway.insert_entry(AdmissionOrigin::Rpc, stale_entry(&resident)?)?;
    let chain = Coins(vec![
        (
            coin(824),
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: Script::from_bytes(vec![0x51]),
            },
        ),
        (
            coin(825),
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: Script::from_bytes(vec![0x51]),
            },
        ),
    ]);

    let result = gateway.submit_local_package(
        vec![resident, parent_a, parent_b],
        crate::LocalOrigin::Rpc,
        None,
        unix_time_secs(),
        &chain,
    )?;

    assert_eq!(
        result.len(),
        3,
        "two new parents precede the resident's expiry"
    );
    let pool = gateway.read();
    assert!(!pool.contains_txid(&resident_txid));
    assert!(pool.contains_txid(&parent_a_txid));
    assert!(pool.contains_txid(&parent_b_txid));
    let envelopes = seen.0.lock();
    assert_eq!(
        envelopes.len(),
        2,
        "stale insert, atomic package and expiry commit"
    );
    assert_eq!(
        envelopes[1].result.changes.last(),
        Some(&expired(resident_txid))
    );
    Ok(())
}

/// Single-transaction `maxfeerate` gates on the actual base fee, never the
/// modified fee: a policy discount must not smuggle an over-cap fee in,
/// and a surcharge must not refuse an under-cap fee.
#[test]
fn single_tx_maxfeerate_gates_on_base_fee_not_modified_fee() -> TestResult {
    use crate::standardness::AcceptanceRejectReason;
    // Gauge the fixture shape once: one anyone-can-spend input and output.
    let gauge = gateway();
    gauge.pool.write().limits.min_relay_fee_sat_per_kvb = 1;
    let tx = spend(&[coin(840)], &[98_000], true);
    // The spent output is a witness program so the native single path
    // verifies the pushed witness instead of refusing a bare key.
    let chain = Coins(vec![(coin(840), output(100_000))]);
    gauge.submit_local_transaction(
        Arc::new(tx.clone()),
        crate::LocalOrigin::Rpc,
        None,
        0,
        &chain,
    )?;
    let vsize = gauge
        .read()
        .entry_by_txid(&tx.txid())
        .ok_or("fixture missing")?
        .vsize;
    let base_rate = 2_000_000 / u64::from(vsize);
    // Wide margins around both rates so integer rounding cannot matter:
    // the discount drops the modified fee to 100 sats, the surcharge lifts
    // it to 100_000 sats, while the base fee stays 2_000 sats.
    let below_base = base_rate / 2;
    let above_base = base_rate * 2 + 1_000;
    // Real margins, immune to integer-division equality: the discounted fee
    // (100 sats) sits below the cap's required fee, the surcharge-implied
    // fee (100_000 sats) sits above the higher cap's.
    assert!(crate::rbf::required_fee(below_base, vsize).is_ok_and(|limit| limit > 100));
    assert!(above_base < 100_000_000 / u64::from(vsize));

    // Discount: modified rate is under the cap, base rate is over it.
    let discounted = gateway();
    discounted.pool.write().limits.min_relay_fee_sat_per_kvb = 1;
    discounted.prioritise(tx.txid(), -1_900)?;
    let preview =
        discounted.preview_transactions(std::slice::from_ref(&tx), Some(below_base), &chain)?;
    assert_eq!(preview.results[0].allowed, Some(false));
    assert_eq!(
        preview.results[0].reject_reason,
        Some(AcceptanceRejectReason::MaxFeeExceeded),
        "preview must agree with submit on the base-fee cap"
    );
    assert_eq!(
        discounted.submit_local_transaction(
            Arc::new(tx.clone()),
            crate::LocalOrigin::Rpc,
            Some(below_base),
            0,
            &chain,
        ),
        Err(SubmitError::Policy(AcceptanceRejectReason::MaxFeeExceeded)),
        "a discount must not admit an over-cap base fee"
    );
    assert!(discounted.read().is_empty());

    // Surcharge: modified rate is over the cap, base rate is under it.
    let surcharged = gateway();
    surcharged.pool.write().limits.min_relay_fee_sat_per_kvb = 1;
    surcharged.prioritise(tx.txid(), 98_000)?;
    let preview =
        surcharged.preview_transactions(std::slice::from_ref(&tx), Some(above_base), &chain)?;
    assert_eq!(preview.results[0].allowed, Some(true));
    assert_eq!(preview.results[0].reject_reason, None);
    surcharged.submit_local_transaction(
        Arc::new(tx),
        crate::LocalOrigin::Rpc,
        Some(above_base),
        0,
        &chain,
    )?;
    assert_eq!(surcharged.read().len(), 1);
    Ok(())
}
