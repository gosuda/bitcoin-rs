use alloc::sync::Arc;
use alloc::vec::Vec;

use bitcoin::Transaction;
use thiserror::Error;

use crate::pool::tx_fee_rate;
use crate::{EntryId, Mempool, MempoolEntry, MempoolError};

/// Candidate transaction and feerate policy used for BIP125 validation.
#[derive(Clone, Debug)]
pub struct ReplacementCandidate {
    /// Replacement transaction.
    pub tx: Arc<Transaction>,
    /// Replacement virtual size in vbytes.
    pub vsize: u32,
    /// Replacement fee in satoshis.
    pub fee: u64,
    /// Incremental relay fee rate in sat/kvB.
    pub min_relay_fee_rate: u64,
}

impl ReplacementCandidate {
    /// Builds a replacement candidate.
    #[must_use]
    pub const fn new(tx: Arc<Transaction>, vsize: u32, fee: u64, min_relay_fee_rate: u64) -> Self {
        Self {
            tx,
            vsize,
            fee,
            min_relay_fee_rate,
        }
    }

    /// Candidate fee rate in sat/vB multiplied by 1000.
    #[must_use]
    pub fn fee_rate(&self) -> u64 {
        tx_fee_rate(self.fee, self.vsize)
    }
}

/// Successful replacement validation result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplacementPlan {
    /// Directly conflicting entries and their descendants to evict.
    pub evicted: Vec<EntryId>,
}

/// BIP125 replacement rejection reason.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RbfError {
    /// No directly conflicting transaction signals replaceability, directly or through ancestors.
    #[error("BIP125 rule 1: original transactions do not opt in")]
    Rule1NoOptIn,
    /// Replacement spends a new unconfirmed input not spent by the originals.
    #[error("BIP125 rule 2: replacement adds a new unconfirmed input")]
    Rule2NewUnconfirmedInput,
    /// Replacement absolute fee is below the conflicts it evicts.
    #[error("BIP125 rule 3: replacement fee does not pay evicted fees")]
    Rule3InsufficientAbsoluteFee,
    /// Replacement does not pay the configured incremental relay fee.
    #[error("BIP125 rule 4: replacement does not pay incremental relay fee")]
    Rule4InsufficientIncrementalFee,
    /// Replacement would evict more transactions than policy allows.
    #[error("BIP125 rule 5: replacement evicts too many transactions")]
    Rule5TooManyEvictions,
    /// Replacement fee rate does not improve on directly conflicting transactions.
    #[error("BIP125 rule 6: replacement fee rate is not higher than originals")]
    Rule6InsufficientFeeRate,
    /// A validated replacement failed insertion after evicting conflicts.
    #[error(transparent)]
    Mempool(#[from] MempoolError),
}

impl Mempool {
    /// Checks BIP125 replacement rules without mutating the mempool.
    pub fn check_replacement(
        &self,
        candidate: &ReplacementCandidate,
    ) -> Result<ReplacementPlan, RbfError> {
        let direct_conflicts = self.conflicts_for(&candidate.tx);
        if direct_conflicts.is_empty() {
            return Ok(ReplacementPlan {
                evicted: Vec::new(),
            });
        }

        if !direct_conflicts
            .iter()
            .any(|id| self.signals_rbf_including_ancestors(*id))
        {
            return Err(RbfError::Rule1NoOptIn);
        }

        let original_spends = direct_conflicts
            .iter()
            .filter_map(|id| self.entry(*id))
            .flat_map(|entry| entry.tx.input.iter().map(|input| input.previous_output))
            .collect::<Vec<_>>();
        for input in &candidate.tx.input {
            if self.is_unconfirmed_outpoint(input.previous_output)
                && !original_spends.contains(&input.previous_output)
            {
                return Err(RbfError::Rule2NewUnconfirmedInput);
            }
        }

        let evicted = self.conflicts_with_descendants(&candidate.tx);
        let evicted_fee = evicted.iter().fold(0_u64, |total, id| {
            total.saturating_add(self.entry(*id).map_or(0, |entry| entry.fee))
        });
        if candidate.fee < evicted_fee {
            return Err(RbfError::Rule3InsufficientAbsoluteFee);
        }

        let incremental_fee =
            u64::from(candidate.vsize).saturating_mul(candidate.min_relay_fee_rate) / 1_000;
        if candidate.fee.saturating_sub(evicted_fee) < incremental_fee {
            return Err(RbfError::Rule4InsufficientIncrementalFee);
        }

        let eviction_count = u32::try_from(evicted.len()).unwrap_or(u32::MAX);
        if eviction_count > self.limits.max_replacement_evictions {
            return Err(RbfError::Rule5TooManyEvictions);
        }

        let candidate_fee_rate = candidate.fee_rate();
        if direct_conflicts.iter().any(|id| {
            self.entry(*id)
                .is_some_and(|entry| candidate_fee_rate <= entry.fee_rate)
        }) {
            return Err(RbfError::Rule6InsufficientFeeRate);
        }

        Ok(ReplacementPlan { evicted })
    }

    /// Applies a BIP125 replacement after validation and returns the new entry id.
    pub fn replace_transaction(
        &mut self,
        candidate: ReplacementCandidate,
        time: u64,
        height: u32,
    ) -> Result<EntryId, RbfError> {
        let plan = self.check_replacement(&candidate)?;
        for id in plan.evicted {
            let _ = self.remove_entry_and_descendants(id);
        }
        let entry = MempoolEntry::new(candidate.tx, candidate.vsize, candidate.fee, time, height);
        self.insert_entry(entry).map_err(RbfError::from)
    }
}
