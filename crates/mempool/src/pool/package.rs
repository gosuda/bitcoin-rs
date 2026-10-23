//! Prepared, all-or-nothing native package insertion over the existing pool.
use super::{Mempool, PreparedInsert, fee_policy};
use crate::rbf::LimitEnforcement;
use crate::standardness::AcceptanceRejectReason;
use crate::{MempoolEntry, MempoolError, MutationResult, PolicyError};
use alloc::vec::Vec;
use bitcoin_rs_primitives::Txid;
use hashbrown::HashSet;

pub(crate) struct PreparedPackage {
    stamp: fee_policy::PolicyStamp,
    inserts: Vec<PreparedInsert>,
    expiry_time: u64,
}

impl Mempool {
    /// Plans one all-or-nothing package insertion. `now` is the wall-clock
    /// second the rolling minimum fee is read at.
    pub(crate) fn prepare_package(
        &self,
        entries: Vec<MempoolEntry>,
        now: u64,
    ) -> Result<PreparedPackage, AcceptanceRejectReason> {
        let expiry_time = entries.iter().map(|entry| entry.time).max().unwrap_or(0);
        let size = entries.iter().try_fold(self.total_vsize(), |sum, entry| {
            sum.checked_add(u64::from(entry.vsize))
                .ok_or(PolicyError::FeeArithmetic)
        })?;
        let cutoff = expiry_time.saturating_sub(crate::policy::MEMPOOL_EXPIRY_SECS);
        let expired_ids = self.expired_entry_ids(expiry_time);
        let mut expired_txids: HashSet<Txid> = expired_ids
            .iter()
            .filter_map(|id| self.entry(*id).map(|e| e.txid))
            .collect();
        let mut expired_vsize = expired_ids
            .iter()
            .filter_map(|id| self.entry(*id))
            .map(|entry| u64::from(entry.vsize))
            .sum::<u64>();

        let mut expired_pending_indices = HashSet::new();
        let mut changed = true;
        while changed {
            changed = false;
            for (idx, entry) in entries.iter().enumerate() {
                if expired_pending_indices.contains(&idx) {
                    continue;
                }
                let is_expired_root = entry.time < cutoff;
                let spends_expired = entry
                    .tx
                    .inputs
                    .iter()
                    .any(|input| expired_txids.contains(&input.previous_output.txid));
                if is_expired_root || spends_expired {
                    expired_pending_indices.insert(idx);
                    expired_txids.insert(entry.txid);
                    expired_vsize = expired_vsize
                        .checked_add(u64::from(entry.vsize))
                        .ok_or(PolicyError::FeeArithmetic)?;
                    changed = true;
                }
            }
        }

        let size = size
            .checked_sub(expired_vsize)
            .ok_or(PolicyError::FeeArithmetic)?;
        if self.limits.max_total_bytes != 0 && size > self.limits.max_total_bytes {
            return Err(MempoolError::Full.into());
        }
        // Reused slots already have valid ids. Preflight the highest new slot,
        // not just live membership, before the infallible insertion phase.
        if self
            .entries
            .capacity()
            .checked_add(entries.len().saturating_sub(self.entries.free.len()))
            .and_then(|capacity| capacity.checked_sub(1))
            .and_then(|last| u32::try_from(last).ok())
            .is_none()
        {
            return Err(MempoolError::TooManyEntries.into());
        }
        let floor = self.min_fee_sat_per_kvb(now);
        let mut fee = 0_i128;
        let mut vsize = 0_u32;
        for entry in &entries {
            fee = fee
                .checked_add(
                    self.modified_fee_for(entry.txid, entry.fee)
                        .map_err(|_| PolicyError::FeeArithmetic)?,
                )
                .ok_or(PolicyError::FeeArithmetic)?;
            vsize = vsize
                .checked_add(entry.vsize)
                .ok_or(PolicyError::FeeArithmetic)?;
        }
        if fee < crate::rbf::required_fee(floor, vsize).map_err(|_| PolicyError::FeeArithmetic)? {
            return Err(AcceptanceRejectReason::MinRelayFeeNotMet);
        }
        let inserts = entries
            .into_iter()
            // The full package graph is verified once by finish_package.
            // Batch entry-id allocation was preflighted above.
            .map(|entry| self.prepare_insert(entry, &HashSet::new(), LimitEnforcement::Deferred))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(PreparedPackage {
            stamp: self.policy_stamp(),
            inserts,
            expiry_time,
        })
    }

    pub(crate) fn commit_package(
        &mut self,
        prepared: PreparedPackage,
    ) -> Result<MutationResult, MempoolError> {
        if !prepared.stamp.matches(self) {
            return Err(MempoolError::StalePolicy);
        }
        let mut changes = Vec::new();
        // All fallible checks finished against the captured stamp. No partial
        // package is ever visible outside this writer interval. Package fees
        // pay for the group, so member rates are not fee-estimation samples.
        for entry in prepared.inserts {
            changes.extend(self.commit_insert(entry).changes);
        }
        changes.extend(self.expire(prepared.expiry_time).changes);
        Ok(self.finish_mutation(changes))
    }
}
