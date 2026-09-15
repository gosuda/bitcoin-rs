//! Core 31.1 package structure and ephemeral-spend policy.

use bitcoin_rs_primitives::{OutPoint, Tx};
use hashbrown::HashSet;

use crate::{
    Mempool,
    standardness::{AcceptanceRejectReason, MAX_PACKAGE_COUNT, TxAcceptanceFact},
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
    if weight.is_none_or(|weight| weight > 404_000) {
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
        effective_fee_rate: None,
        reject_reason: None,
    }
}

/// The child that spends any output of an unconfirmed parent must also
/// spend every dust output of that parent. Returns the offending child index.
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

pub(crate) struct PreviewChecks {
    graph: Result<crate::pool::fee_policy::PolicyGraph, crate::RbfError>,
    limits: crate::MempoolLimits,
    truc: Result<(), crate::TrucError>,
    dust_child: Option<usize>,
}

pub(crate) fn capture_preview_checks(
    pool: &Mempool,
    txs: &[Tx],
    requests: &[crate::AdmissionRequest],
    prepared: &[crate::gateway::PreparedAdmission],
) -> PreviewChecks {
    let entries: Vec<_> = requests
        .iter()
        .zip(prepared)
        .map(|(request, job)| {
            crate::MempoolEntry::new(
                alloc::sync::Arc::clone(&request.tx),
                job.fact.vsize,
                job.fact.base_fee.unwrap_or(0),
                request.time,
                request.height,
            )
            .with_sigop_cost(job.fact.sigop_cost)
        })
        .collect();
    PreviewChecks {
        graph: pool
            .projected_graphs(&entries, &[], false)
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

/// Work over copied facts only. Unfinished rows never imply acceptance, and
/// no candidate output or graph edge is installed in the live pool.
pub(crate) fn finish_preview(
    txs: &[Tx],
    requests: &[crate::AdmissionRequest],
    prepared: &mut [crate::gateway::PreparedAdmission],
    checks: Option<PreviewChecks>,
) -> crate::standardness::PackageAcceptanceFacts {
    use crate::standardness::PackageAcceptanceFacts;
    if txs.len() == 1 {
        prepared[0].verify(&requests[0]);
        return PackageAcceptanceFacts {
            package_error: None,
            results: vec![prepared[0].fact.clone()],
        };
    }
    let mut facts = PackageAcceptanceFacts {
        package_error: None,
        results: txs.iter().map(unfinished).collect(),
    };
    for (index, (job, request)) in prepared.iter_mut().zip(requests).enumerate() {
        job.verify_policy(request);
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
            facts.package_error = Some(AcceptanceRejectReason::Replacement(error));
            return facts;
        }
    }
    if let Some(index) = checks.dust_child {
        facts.results[index].allowed = Some(false);
        facts.results[index].reject_reason = Some(AcceptanceRejectReason::MissingEphemeralSpends);
        return facts;
    }
    for (index, (job, request)) in prepared.iter_mut().zip(requests).enumerate() {
        job.verify_scripts(request);
        facts.results[index] = job.fact.clone();
        if job.fact.allowed == Some(false) {
            break;
        }
    }
    facts
}

#[cfg(test)]
mod tests;
