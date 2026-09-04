#[cfg(test)]
use std::cell::Cell;
use std::collections::HashSet;

use bitcoin_rs_consensus::is_final_tx;
use bitcoin_rs_mempool::{MempoolMiningSnapshot, SnapshotEntry};
use bitcoin_rs_primitives::{Tx, Txid};

use crate::MiningError;
use crate::template::CandidateContext;

#[cfg(test)]
thread_local! {
    static RESIDUAL_PACKAGE_CONSTRUCTIONS: Cell<usize> = const { Cell::new(0) };
}

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
    let pooled: HashSet<Txid> = snapshot.entries.iter().map(|entry| entry.txid).collect();

    for index in 0..snapshot.entries.len() {
        if (context.max_weight > 0 && used_weight >= context.max_weight)
            || (context.max_size > 0 && used_size >= context.max_size)
        {
            break;
        }
        if selected[index] {
            continue;
        }

        let package = residual_package(snapshot, index, &selected)?;
        if !package_is_final(context, snapshot, &pooled, &package) {
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
    #[cfg(test)]
    RESIDUAL_PACKAGE_CONSTRUCTIONS.with(|count| count.set(count.get() + 1));
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

    // Snapshot ancestor lists are a mempool invariant. Mining does not re-check
    // the DAG; parents have strictly fewer in-pool ancestors, so sorting by
    // that count is topological. Equal counts break on snapshot position.
    if indices.is_empty() {
        return Ok(single_entry_package(tip_entry, tip));
    }
    indices.push(tip);
    indices.sort_by_key(|&index| (snapshot.entries[index].ancestors.len(), index));

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

fn single_entry_package(entry: &SnapshotEntry, index: usize) -> SelectedPackage {
    SelectedPackage {
        indices: vec![index],
        fee: entry.fee,
        weight: entry.weight,
        size: u64::from(entry.size),
        sigop_cost: u64::from(entry.sigop_cost),
    }
}

fn package_is_final(
    context: &CandidateContext,
    snapshot: &MempoolMiningSnapshot,
    pooled: &HashSet<Txid>,
    package: &SelectedPackage,
) -> bool {
    package.indices.iter().all(|&index| {
        let entry = &snapshot.entries[index];
        is_final_tx(&entry.tx, context.height, context.locktime_cutoff)
            && next_block_sequence_locks_final(context, pooled, &entry.tx)
    })
}

fn next_block_sequence_locks_final(
    context: &CandidateContext,
    pooled: &HashSet<Txid>,
    tx: &Tx,
) -> bool {
    if !context.csv_active {
        return true;
    }
    if tx.version < 2 {
        return true;
    }
    tx.inputs.iter().all(|input| {
        if !pooled.contains(&input.previous_output.txid) {
            return true;
        }
        bitcoin_rs_consensus::bip68::sequence_lock_satisfied(
            tx.version,
            input.sequence,
            context.height,
            context.locktime_cutoff,
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

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::cell::Cell;
    use std::sync::Arc;

    use bitcoin_rs_mempool::{MempoolMiningSnapshot, SnapshotEntry};
    use bitcoin_rs_primitives::{Hash256, Network, OutPoint, Tx, TxIn, TxOut, Txid};

    use super::{RESIDUAL_PACKAGE_CONSTRUCTIONS, select_packages};
    use crate::template::CandidateContext;

    #[test]
    fn stops_before_residual_construction_once_a_positive_dimension_is_full() {
        let filler = snapshot_entry(independent_tx(1), 5_000, 1_000, 1_000, 0);
        let leftover = snapshot_entry(independent_tx(2), 4_000, 10, 10, 0);
        let snapshot = MempoolMiningSnapshot {
            sequence: 1,
            entries: vec![filler, leftover],
        };

        RESIDUAL_PACKAGE_CONSTRUCTIONS.with(|count| count.set(0));
        let weight_full = select_packages(&context(1_000, 4_000_000, 80_000), &snapshot, 0, 0, 0)
            .expect("weight-full selection");
        assert_eq!(weight_full.0, vec![0]);
        assert_eq!(RESIDUAL_PACKAGE_CONSTRUCTIONS.with(Cell::get), 1);

        RESIDUAL_PACKAGE_CONSTRUCTIONS.with(|count| count.set(0));
        let size_full = select_packages(&context(4_000_000, 1_000, 80_000), &snapshot, 0, 0, 0)
            .expect("size-full selection");
        assert_eq!(size_full.0, vec![0]);
        assert_eq!(RESIDUAL_PACKAGE_CONSTRUCTIONS.with(Cell::get), 1);
    }

    #[test]
    fn zero_capacity_limits_do_not_stop_before_residual_construction() {
        let zero_size = snapshot_entry(independent_tx(1), 1_000, 10, 0, 0);
        let snapshot = MempoolMiningSnapshot {
            sequence: 2,
            entries: vec![zero_size],
        };

        RESIDUAL_PACKAGE_CONSTRUCTIONS.with(|count| count.set(0));
        let selected = select_packages(&context(4_000_000, 0, 80_000), &snapshot, 0, 0, 0)
            .expect("zero serialized-size limit still considers packages");
        assert_eq!(selected.0, vec![0]);
        assert_eq!(RESIDUAL_PACKAGE_CONSTRUCTIONS.with(Cell::get), 1);
    }

    fn context(max_weight: u64, max_size: u64, max_sigops: u64) -> CandidateContext {
        CandidateContext {
            previous_block_hash: Hash256::from_le_bytes(&[0xcd; 32]),
            height: 100,
            version: 0x2000_0000,
            bits: 0x207f_ffff,
            min_time: 1,
            current_time: 2,
            locktime_cutoff: 1,
            network: Network::Regtest,
            csv_active: true,
            segwit_active: true,
            max_weight,
            max_size,
            max_sigops,
        }
    }

    fn snapshot_entry(tx: Tx, fee: u64, weight: u64, size: u32, sigop_cost: u32) -> SnapshotEntry {
        let tx = Arc::new(tx);
        SnapshotEntry {
            txid: tx.txid(),
            wtxid: tx.wtxid(),
            vsize: size.max(1),
            bip141_vsize: size.max(1),
            size,
            weight,
            sigop_cost,
            fee,
            fee_delta: 0,
            time: 0,
            height: 0,
            ancestor_size: u64::from(size.max(1)),
            ancestor_fee: fee,
            ancestor_fee_delta: 0,
            ancestors: vec![],
            tx,
        }
    }

    fn independent_tx(label: u8) -> Tx {
        let mut bytes = [0_u8; 32];
        bytes[0] = label;
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid::from(Hash256::from_le_bytes(&bytes)), 0),
                script_sig: vec![],
                sequence: u32::MAX,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: 1_000,
                script_pubkey: vec![0x51, label],
            }],
            lock_time: 0,
        }
    }
}
