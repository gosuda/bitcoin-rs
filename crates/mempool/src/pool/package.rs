//! Prepared, all-or-nothing native package insertion over the existing pool.
use super::{Mempool, PreparedInsert, fee_policy};
use crate::rbf::{LimitEnforcement, RbfError};
use crate::{MempoolEntry, MempoolError, MutationResult, PolicyError};
use alloc::vec::Vec;
use hashbrown::HashSet;

pub(crate) struct PreparedPackage {
    stamp: fee_policy::PolicyStamp,
    inserts: Vec<PreparedInsert>,
}

impl Mempool {
    pub(crate) fn prepare_package(
        &self,
        entries: Vec<MempoolEntry>,
    ) -> Result<PreparedPackage, RbfError> {
        let size = entries.iter().try_fold(self.total_vsize(), |sum, entry| {
            sum.checked_add(u64::from(entry.vsize))
                .ok_or(RbfError::ArithmeticOverflow)
        })?;
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
        let policy = self.policy_snapshot();
        let floor = crate::eviction::mempool_min_fee_sat_per_kvb(
            self,
            policy.incremental_relay_fee_sat_per_kvb,
        );
        let mut fee = 0_i128;
        let mut vsize = 0_u32;
        for entry in &entries {
            fee = fee
                .checked_add(self.modified_fee_for(entry.txid, entry.fee)?)
                .ok_or(RbfError::ArithmeticOverflow)?;
            vsize = vsize
                .checked_add(entry.vsize)
                .ok_or(RbfError::ArithmeticOverflow)?;
        }
        if fee < crate::rbf::required_fee(floor, vsize)? {
            return Err(PolicyError::BelowMinRelayFee {
                tx_rate: u64::try_from(fee * 1000 / i128::from(vsize.max(1))).unwrap_or(0),
                min_rate: floor,
            }
            .into());
        }
        let inserts = entries
            .into_iter()
            .map(|entry| self.validate_insert(entry, &HashSet::new(), LimitEnforcement::Deferred))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(PreparedPackage {
            stamp: self.policy_stamp(),
            inserts,
        })
    }

    pub(crate) fn commit_package(
        &mut self,
        prepared: PreparedPackage,
    ) -> Result<MutationResult, RbfError> {
        if !prepared.stamp.matches(self) {
            return Err(RbfError::StalePlan);
        }
        let mut changes = Vec::new();
        // All fallible checks finished against the captured stamp. No partial
        // package is ever visible outside this writer interval.
        for entry in prepared.inserts {
            let txid = entry.entry.txid;
            changes.extend(self.commit_insert(entry).changes);
            self.record_entry_arrival(txid);
        }
        Ok(self.finish_mutation(changes))
    }
}
