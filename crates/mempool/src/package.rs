use bitcoin_rs_primitives::{OutPoint, Tx};
use hashbrown::HashSet;

use crate::{
    Mempool,
    standardness::{
        AcceptanceRejectReason, MAX_PACKAGE_COUNT, MAX_PACKAGE_WEIGHT, TxAcceptanceFact,
    },
};

pub(crate) fn check_structure(txs: &[Tx]) -> Result<(), AcceptanceRejectReason> {
    if txs.is_empty() || txs.len() > MAX_PACKAGE_COUNT {
        return Err(AcceptanceRejectReason::PackageCount);
    }
    if txs.len() == 1 {
        return Ok(());
    }
    let weight = txs
        .iter()
        .try_fold(0_u64, |sum, tx| sum.checked_add(tx.weight()));
    if weight.is_none_or(|weight| weight > MAX_PACKAGE_WEIGHT) {
        return Err(AcceptanceRejectReason::PackageTooLarge);
    }
    let mut later: HashSet<_> = txs.iter().map(Tx::txid).collect();
    if later.len() != txs.len() {
        return Err(AcceptanceRejectReason::PackageDuplicates);
    }
    for tx in txs {
        if tx
            .inputs
            .iter()
            .any(|i| later.contains(&i.previous_output.txid))
        {
            return Err(AcceptanceRejectReason::PackageOrder);
        }
        later.remove(&tx.txid());
    }
    let mut spent = HashSet::new();
    for tx in txs {
        if tx.inputs.is_empty() || tx.inputs.iter().any(|i| spent.contains(&i.previous_output)) {
            return Err(AcceptanceRejectReason::PackageConflict);
        }
        spent.extend(tx.inputs.iter().map(|i| i.previous_output));
    }
    Ok(())
}

pub(crate) fn unfinished(tx: &Tx) -> TxAcceptanceFact {
    TxAcceptanceFact {
        txid: tx.txid(),
        wtxid: tx.wtxid(),
        allowed: None,
        vsize: 0,
        weight: tx.weight(),
        sigop_cost: 0,
        base_fee: None,
        modified_fee: None,
        effective_fee_rate: None,
        reject_reason: None,
    }
}

pub(crate) fn missing_ephemeral_spends(
    pool: &Mempool,
    txs: &[Tx],
    dust_rate: u64,
) -> Option<usize> {
    for (index, tx) in txs.iter().enumerate() {
        let spent: HashSet<_> = tx.inputs.iter().map(|i| i.previous_output).collect();
        let parents: HashSet<_> = tx.inputs.iter().map(|i| i.previous_output.txid).collect();
        for id in parents {
            let parent = txs
                .iter()
                .find(|candidate| candidate.txid() == id)
                .or_else(|| pool.entry_by_txid(&id).map(|entry| entry.tx.as_ref()));
            if let Some(parent) = parent {
                for (vout, output) in parent.outputs.iter().enumerate() {
                    if crate::standardness::is_dust(output, dust_rate) {
                        let Ok(vout) = u32::try_from(vout) else {
                            return Some(index);
                        };
                        if !spent.contains(&OutPoint::new(id, vout)) {
                            return Some(index);
                        }
                    }
                }
            }
        }
    }
    None
}

pub(crate) struct PackageChecks {
    graph: Result<crate::pool::fee_policy::PolicyGraph, crate::RbfError>,
    limits: crate::MempoolLimits,
    truc: Result<(), crate::TrucError>,
    dust_child: Option<usize>,
}

pub(crate) fn package_entries(
    requests: &[crate::AdmissionRequest],
    prepared: &[crate::gateway::PreparedAdmission],
) -> Vec<crate::MempoolEntry> {
    requests
        .iter()
        .zip(prepared)
        .map(|(request, job)| {
            crate::MempoolEntry::new(
                alloc::sync::Arc::clone(&request.tx),
                job.fact.vsize,
                job.fact.base_fee.unwrap_or(0),
                request.time,
                request.height,
                job.fact.sigop_cost,
            )
        })
        .collect()
}

pub(crate) fn capture_package_checks(
    pool: &Mempool,
    txs: &[Tx],
    entries: &[crate::MempoolEntry],
) -> PackageChecks {
    PackageChecks {
        graph: pool
            .projected_graphs(entries, &[], false)
            .map(|(_, after)| after),
        limits: pool.limits,
        truc: pool.check_package_truc(txs, &entries.iter().map(|e| e.vsize).collect::<Vec<_>>()),
        dust_child: missing_ephemeral_spends(
            pool,
            txs,
            pool.policy_snapshot().standardness.dust_relay_fee,
        ),
    }
}

pub(crate) fn finish_preview(
    txs: &[Tx],
    requests: &[crate::AdmissionRequest],
    prepared: &mut [crate::gateway::PreparedAdmission],
    checks: Option<PackageChecks>,
) -> crate::standardness::PackageAcceptanceFacts {
    use crate::standardness::PackageAcceptanceFacts;
    if txs.len() == 1 {
        prepared[0].verify(&requests[0], None);
        return PackageAcceptanceFacts {
            package_error: None,
            results: vec![prepared[0].fact.clone()],
        };
    }
    finish_package(
        txs,
        requests,
        prepared,
        checks,
        None,
        crate::gateway::AdmissionMode::PackageTest,
        None,
    )
}

pub(crate) fn finish_package(
    txs: &[Tx],
    requests: &[crate::AdmissionRequest],
    prepared: &mut [crate::gateway::PreparedAdmission],
    checks: Option<PackageChecks>,
    aggregate_error: Option<AcceptanceRejectReason>,
    mode: crate::gateway::AdmissionMode,
    script_cache: Option<&bitcoin_rs_consensus::ScriptExecutionCache>,
) -> crate::standardness::PackageAcceptanceFacts {
    use crate::standardness::PackageAcceptanceFacts;
    let mut facts = PackageAcceptanceFacts {
        package_error: None,
        results: txs.iter().map(unfinished).collect(),
    };
    for (index, (job, request)) in prepared.iter_mut().zip(requests).enumerate() {
        job.verify_policy(request);
        if let crate::gateway::AdmissionMode::PackageRpcSubmit(maximum) = mode
            && (txs.len() > 1 || aggregate_error != Some(AcceptanceRejectReason::MinRelayFeeNotMet))
        {
            job.check_package_max_feerate(maximum);
        }
        if job.fact.allowed == Some(false) {
            facts.results[index] = job.fact.clone();
            return facts;
        }
    }
    let Some(checks) = checks else {
        return facts;
    };
    if let Err(error) = checks.truc {
        facts.package_error = Some(error.into());
        return facts;
    }
    if matches!(mode, crate::gateway::AdmissionMode::PackageRpcSubmit(_))
        && aggregate_error == Some(AcceptanceRejectReason::MinRelayFeeNotMet)
    {
        facts.package_error = aggregate_error;
        return facts;
    }
    match checks
        .graph
        .and_then(|graph| graph.check_limits(checks.limits))
    {
        Ok(()) => {}
        Err(crate::RbfError::Mempool(crate::MempoolError::Policy(
            crate::PolicyError::ClusterCountLimit | crate::PolicyError::ClusterSizeLimit,
        ))) => {
            facts.package_error = Some(AcceptanceRejectReason::PackageCluster);
            return facts;
        }
        Err(error) => {
            facts.package_error = Some(
                if matches!(
                    mode,
                    crate::gateway::AdmissionMode::PackageSubmit
                        | crate::gateway::AdmissionMode::PackageRpcSubmit(_)
                ) {
                    AcceptanceRejectReason::Mempool(error.into_pool_error())
                } else {
                    AcceptanceRejectReason::Replacement(error)
                },
            );
            return facts;
        }
    }
    if let Some(index) = checks.dust_child {
        facts.results[index].allowed = Some(false);
        facts.results[index].reject_reason = Some(AcceptanceRejectReason::MissingEphemeralSpends);
        return facts;
    }
    if let Some(error) = aggregate_error {
        facts.package_error = Some(error);
        return facts;
    }
    for (index, (job, request)) in prepared.iter_mut().zip(requests).enumerate() {
        job.verify_scripts(request, script_cache);
        facts.results[index] = job.fact.clone();
        if job.fact.allowed == Some(false) {
            break;
        }
    }
    facts
}

#[cfg(test)]
mod tests;
