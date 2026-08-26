use std::collections::BTreeMap;

use bitcoin_rs_mempool::{MempoolMiningSnapshot, SnapshotEntry};

use crate::MiningError;
use crate::template::CandidateContext;

/// One dependency-closed package selected for a candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SelectedPackage {
    /// Snapshot positions in topological order.
    pub indices: Vec<usize>,
    /// Sum of actual fees for the residual package.
    pub fee: u64,
    /// Sum of weights for the residual package.
    pub weight: u64,
    /// Sum of serialized sizes for the residual package.
    pub size: u64,
    /// Sum of sigop costs for the residual package.
    pub sigop_cost: u64,
}

/// Selects dependency-closed packages under the candidate's resource limits.
///
/// Packages are considered in the snapshot's modified-priority order. Each
/// package is the still-unselected ancestor closure of the considered entry.
/// A package that fails finality or would overflow weight, serialized size, or
/// sigop cost is skipped atomically; later packages may still fit.
pub(crate) fn select_packages(
    context: &CandidateContext,
    snapshot: &MempoolMiningSnapshot,
    reserved_weight: u64,
    reserved_size: u64,
    reserved_sigops: u64,
) -> Result<(Vec<usize>, u64, u64, u64, u64), MiningError> {
    if reserved_weight > context.max_weight {
        return Err(MiningError::CapacityExhausted { field: "weight" });
    }
    if reserved_size > context.max_size {
        return Err(MiningError::CapacityExhausted { field: "size" });
    }
    if reserved_sigops > context.max_sigops {
        return Err(MiningError::CapacityExhausted { field: "sigops" });
    }

    let mut selected = vec![false; snapshot.entries.len()];
    let mut ordered = Vec::new();
    let mut used_weight = reserved_weight;
    let mut used_size = reserved_size;
    let mut used_sigops = reserved_sigops;
    let mut fees = 0_u64;

    for index in 0..snapshot.entries.len() {
        if selected[index] {
            continue;
        }

        let package = residual_package(snapshot, index, &selected)?;
        if !package_is_final(context, snapshot, &package) {
            continue;
        }

        let Some(next_weight) = used_weight.checked_add(package.weight) else {
            continue;
        };
        let Some(next_size) = used_size.checked_add(package.size) else {
            continue;
        };
        let Some(next_sigops) = used_sigops.checked_add(package.sigop_cost) else {
            continue;
        };
        if next_weight > context.max_weight
            || next_size > context.max_size
            || next_sigops > context.max_sigops
        {
            continue;
        }
        let Some(next_fees) = fees.checked_add(package.fee) else {
            return Err(MiningError::FeeOverflow);
        };

        for &member in &package.indices {
            selected[member] = true;
            ordered.push(member);
        }
        used_weight = next_weight;
        used_size = next_size;
        used_sigops = next_sigops;
        fees = next_fees;
    }

    Ok((
        ordered,
        fees,
        used_weight.saturating_sub(reserved_weight),
        used_size.saturating_sub(reserved_size),
        used_sigops.saturating_sub(reserved_sigops),
    ))
}

fn residual_package(
    snapshot: &MempoolMiningSnapshot,
    tip: usize,
    selected: &[bool],
) -> Result<SelectedPackage, MiningError> {
    let tip_entry = &snapshot.entries[tip];
    let mut indices = Vec::with_capacity(tip_entry.ancestors.len().saturating_add(1));

    for &ancestor in &tip_entry.ancestors {
        let ancestor = usize::try_from(ancestor).map_err(|_| MiningError::MissingAncestor {
            entry: tip,
            ancestor,
        })?;
        if ancestor >= snapshot.entries.len() {
            return Err(MiningError::MissingAncestor {
                entry: tip,
                ancestor: u32::try_from(ancestor).unwrap_or(u32::MAX),
            });
        }
        if !selected[ancestor] {
            indices.push(ancestor);
        }
    }
    indices.push(tip);

    // Parents have strictly fewer in-pool ancestors than their descendants, so
    // sorting by ancestor count yields a deterministic topological order. Equal
    // counts break on snapshot position.
    indices.sort_by_key(|&index| (snapshot.entries[index].ancestors.len(), index));
    detect_cycles(snapshot, tip, &indices)?;

    let mut fee = 0_u64;
    let mut weight = 0_u64;
    let mut size = 0_u64;
    let mut sigop_cost = 0_u64;
    for &index in &indices {
        let entry = &snapshot.entries[index];
        fee = fee.checked_add(entry.fee).ok_or(MiningError::FeeOverflow)?;
        weight = weight
            .checked_add(entry.weight)
            .ok_or(MiningError::CandidateScalarOverflow { field: "weight" })?;
        size = size
            .checked_add(u64::from(entry.size))
            .ok_or(MiningError::CandidateScalarOverflow { field: "size" })?;
        sigop_cost = sigop_cost.checked_add(u64::from(entry.sigop_cost)).ok_or(
            MiningError::CandidateScalarOverflow {
                field: "sigop cost",
            },
        )?;
    }

    Ok(SelectedPackage {
        indices,
        fee,
        weight,
        size,
        sigop_cost,
    })
}

fn detect_cycles(
    snapshot: &MempoolMiningSnapshot,
    tip: usize,
    ordered: &[usize],
) -> Result<(), MiningError> {
    let positions: BTreeMap<usize, usize> = ordered
        .iter()
        .copied()
        .enumerate()
        .map(|(position, index)| (index, position))
        .collect();

    for &index in ordered {
        for &ancestor in &snapshot.entries[index].ancestors {
            let ancestor = usize::try_from(ancestor).map_err(|_| MiningError::MissingAncestor {
                entry: index,
                ancestor,
            })?;
            let Some(&ancestor_position) = positions.get(&ancestor) else {
                continue;
            };
            let self_position = positions[&index];
            if ancestor_position >= self_position {
                return Err(MiningError::DependencyCycle { entry: tip });
            }
        }
    }
    Ok(())
}

fn package_is_final(
    context: &CandidateContext,
    snapshot: &MempoolMiningSnapshot,
    package: &SelectedPackage,
) -> bool {
    package.indices.iter().all(|&index| {
        bitcoin_rs_consensus::is_final_tx(
            &snapshot.entries[index].tx,
            context.height,
            context.locktime_cutoff,
        )
    })
}

/// Modified fee used for ranking overlays: actual fee plus the signed delta.
#[must_use]
pub(crate) fn modified_fee(entry: &SnapshotEntry) -> i128 {
    i128::from(entry.fee).saturating_add(i128::from(entry.fee_delta))
}
