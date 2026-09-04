use alloc::sync::Arc;
use alloc::vec::Vec;

use bitcoin_rs_primitives::Tx;
use hashbrown::HashSet;
use thiserror::Error;

use crate::mutation::RemovalReason;
use crate::pool::tx_fee_rate;
use crate::{EntryId, Mempool, MempoolEntry, MempoolError};

/// Candidate transaction and feerate policy used for BIP125 validation.
#[derive(Clone, Debug)]
pub struct ReplacementCandidate {
    /// Replacement transaction.
    pub tx: Arc<Tx>,
    /// Replacement virtual size in vbytes.
    pub vsize: u32,
    /// Replacement fee in satoshis.
    pub fee: u64,
    /// Incremental relay fee rate in sat/kvB.
    pub min_relay_fee_rate: u64,
    /// BIP141 sigop cost against the resolved prevouts.
    ///
    /// Carried through so a replacement lands with the same accounting a plain
    /// acceptance would give it. Zero when the candidate was built without
    /// resolved prevouts, which means unknown rather than none.
    pub sigop_cost: u32,
}

impl ReplacementCandidate {
    /// Builds a replacement candidate.
    #[must_use]
    pub const fn new(tx: Arc<Tx>, vsize: u32, fee: u64, min_relay_fee_rate: u64) -> Self {
        Self {
            tx,
            vsize,
            fee,
            min_relay_fee_rate,
            sigop_cost: 0,
        }
    }

    /// Attaches a sigop cost counted against resolved prevouts.
    #[must_use]
    pub const fn with_sigop_cost(mut self, sigop_cost: u32) -> Self {
        self.sigop_cost = sigop_cost;
        self
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
    /// Some directly conflicting transaction does not signal replaceability,
    /// itself or through an ancestor.
    #[error("BIP125 rule 1: an original transaction does not opt in")]
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
    /// Rejected by pool insertion constraints before any eviction.
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

        // Rule 1 is a condition on *every* original the replacement would
        // evict, not on the set containing one willing member. A candidate
        // conflicting with an opt-in transaction and a final one would
        // otherwise evict both -- and the final one never agreed to that.
        if !direct_conflicts
            .iter()
            .all(|id| self.signals_rbf_including_ancestors(*id))
        {
            return Err(RbfError::Rule1NoOptIn);
        }

        let original_parent_txids = direct_conflicts
            .iter()
            .filter_map(|id| self.entry(*id))
            .flat_map(|entry| {
                entry
                    .tx
                    .inputs
                    .iter()
                    .map(|input| input.previous_output.txid)
            })
            .collect::<HashSet<_>>();
        for input in &candidate.tx.inputs {
            if self.is_unconfirmed_outpoint(input.previous_output)
                && !original_parent_txids.contains(&input.previous_output.txid)
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

    /// Applies a BIP125 replacement after validation and reports the
    /// committed mutation: each direct conflict commits as
    /// `Removed(Replaced)`, each descendant swept with a conflict as
    /// `Removed(Descendant)` (parents before descendants), then the
    /// replacement's `Accepted` and any post-insert policy evictions. The
    /// replacement's entry id resolves from the `Accepted` change via
    /// `entry_id_by_txid`.
    ///
    /// Re-runs conflict checks under the caller's exclusive access so a plan
    /// computed earlier cannot silently race with concurrent admissions.
    /// Non-conflicting candidates take the same path with an empty eviction
    /// set.
    ///
    /// When the post-insert trim sheds the replacement itself, the conflict
    /// removals and the insert have already committed; the outcome reports
    /// as [`InsertionOutcome::ShedAfterCommit`] carrying that record, and
    /// only an `Err` means nothing was committed.
    pub fn replace_transaction(
        &mut self,
        candidate: ReplacementCandidate,
        time: u64,
        height: u32,
        sigop_cost: u32,
    ) -> Result<crate::mutation::InsertionOutcome, RbfError> {
        let candidate_txid = candidate.tx.txid();
        let plan = self.check_replacement(&candidate)?;
        let direct: HashSet<EntryId> = self.conflicts_for(&candidate.tx).into_iter().collect();
        let entry = MempoolEntry::new(candidate.tx, candidate.vsize, candidate.fee, time, height)
            .with_sigop_cost(sigop_cost);
        let excluded: HashSet<EntryId> = plan.evicted.iter().copied().collect();
        let prepared = self.validate_insert(entry, &excluded)?;
        let mut changes = Vec::new();
        let removals = plan
            .evicted
            .into_iter()
            .map(|id| {
                let reason = if direct.contains(&id) {
                    RemovalReason::Replaced
                } else {
                    RemovalReason::Descendant
                };
                (id, reason)
            })
            .collect::<Vec<_>>();
        self.remove_entries_with_reasons(&removals, &mut changes);
        let replacement = self.commit_insert(prepared);
        changes.extend(replacement.changes);
        // The trim evicts the worst-paying entries, and the replacement can
        // be one of them. The conflict removals and the insert already
        // committed, so the outcome carries the whole record; reporting
        // plain success would hand the caller a receipt for a transaction
        // that is not in the pool. Same check as `insert_entry`.
        let result = self.finish_mutation(changes);
        Ok(if self.contains_txid(&candidate_txid) {
            crate::mutation::InsertionOutcome::Accepted(result)
        } else {
            crate::mutation::InsertionOutcome::ShedAfterCommit(result)
        })
    }
}
