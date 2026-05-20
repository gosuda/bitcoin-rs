use alloc::vec::Vec;
use core::ops::RangeInclusive;

use bitcoin::hashes::{Hash as _, sha256d};
use bitcoin::{OutPoint, ScriptBuf, Transaction, Txid};
use bitcoin_rs_primitives::Hash256;
use hashbrown::HashMap;
use slab::Slab;
use thiserror::Error;

use crate::entry::fee_rate;
use crate::{EntryId, MempoolEntry, MempoolLimits, ParetoFront, PolicyError};

/// Electrum-compatible script hash key for funding index range scans.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    bytemuck::Pod,
    bytemuck::Zeroable,
)]
#[repr(transparent)]
pub struct ScriptHash {
    /// Double-SHA256 of the script bytes in consensus byte order.
    pub hash: Hash256,
}

impl ScriptHash {
    /// Hashes a script into an index key.
    #[must_use]
    pub fn from_script(script: &ScriptBuf) -> Self {
        let hash = sha256d::Hash::hash(script.as_bytes());
        Self {
            hash: Hash256::from_le_bytes(hash.as_byte_array()),
        }
    }
}

/// Mempool insertion and mutation errors.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum MempoolError {
    /// The transaction id already exists in the pool.
    #[error("transaction already exists in mempool")]
    DuplicateTransaction,
    /// The slab index can no longer fit the public `u32` entry id.
    #[error("mempool entry id space exhausted")]
    TooManyEntries,
    /// The transaction violates mempool policy limits.
    #[error(transparent)]
    Policy(#[from] PolicyError),
}

/// In-memory transaction pool with txid, funding, spending, and fee-priority indexes.
#[derive(Debug)]
pub struct Mempool {
    /// Entry arena. Public ids are slab indices represented as `u32`.
    pub entries: Slab<MempoolEntry>,
    /// Transaction id to entry id lookup.
    pub by_txid: HashMap<Txid, EntryId>,
    /// Funding index keyed by script hash then entry id.
    pub funding: std::collections::BTreeSet<(ScriptHash, EntryId)>,
    /// Spending index keyed by spent outpoint then entry id.
    pub spending: std::collections::BTreeSet<(OutPoint, EntryId)>,
    /// Fee-priority index for mining and eviction consumers.
    pub pareto: ParetoFront,
    /// Active mempool policy limits.
    pub limits: MempoolLimits,
    sequence: core::sync::atomic::AtomicU64,
}
/// Aggregate mempool counters surfaced through the JSON-RPC `getmempoolinfo`
/// and Electrum `mempool.get_fee_histogram` surfaces.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MempoolStats {
    /// Number of transactions in the mempool.
    pub txs: u64,
    /// Sum of virtual sizes in vbytes.
    pub bytes: u64,
    /// Sum of base fees in satoshis.
    pub total_fee: u64,
}

impl Mempool {
    /// Creates an empty mempool with the supplied limits.
    #[must_use]
    pub fn new(limits: MempoolLimits) -> Self {
        Self {
            entries: Slab::new(),
            by_txid: HashMap::new(),
            funding: std::collections::BTreeSet::new(),
            spending: std::collections::BTreeSet::new(),
            pareto: ParetoFront::new(),
            limits,
            sequence: core::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Returns the current sequence number. Increments on every insert/remove.
    #[must_use]
    pub fn sequence_number(&self) -> u64 {
        self.sequence.load(core::sync::atomic::Ordering::Acquire)
    }

    fn bump_sequence(&self) {
        let _ = self
            .sequence
            .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
    }

    /// Inserts an entry after applying ancestor and descendant policy checks.
    pub fn insert_entry(&mut self, mut entry: MempoolEntry) -> Result<EntryId, MempoolError> {
        let txid = entry.tx.compute_txid();
        if self.by_txid.contains_key(&txid) {
            return Err(MempoolError::DuplicateTransaction);
        }

        let ancestors = self.ancestor_ids_for_tx(&entry.tx);
        self.check_ancestor_limits(&ancestors, &entry)?;
        self.check_descendant_limits(&ancestors)?;

        let ancestor_size = ancestors.iter().fold(u64::from(entry.vsize), |total, id| {
            total.saturating_add(
                self.entry(*id)
                    .map_or(0, |ancestor| u64::from(ancestor.vsize)),
            )
        });
        let ancestor_fee = ancestors.iter().fold(entry.fee, |total, id| {
            total.saturating_add(self.entry(*id).map_or(0, |ancestor| ancestor.fee))
        });
        entry.ancestor_size = ancestor_size;
        entry.ancestor_fee = ancestor_fee;
        entry.descendant_size = u64::from(entry.vsize);
        entry.descendant_fee = entry.fee;

        let index = self.entries.insert(entry);
        let id = EntryId::try_from(index).map_err(|_| MempoolError::TooManyEntries)?;
        self.by_txid.insert(txid, id);
        self.index_entry(id);
        self.recompute_all_metadata();
        self.bump_sequence();
        Ok(id)
    }

    /// Returns the number of transactions in the mempool.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the mempool is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the total virtual size of all entries.
    #[must_use]
    pub fn total_vsize(&self) -> u64 {
        self.entries.iter().fold(0, |total, (_, entry)| {
            total.saturating_add(u64::from(entry.vsize))
        })
    }

    /// Returns aggregate counters for the current pool.
    #[must_use]
    pub fn stats(&self) -> MempoolStats {
        let txs = u64::try_from(self.entries.len()).unwrap_or(u64::MAX);
        let bytes = self.total_vsize();
        let total_fee = self
            .entries
            .iter()
            .fold(0_u64, |acc, (_id, entry)| acc.saturating_add(entry.fee));
        MempoolStats {
            txs,
            bytes,
            total_fee,
        }
    }

    /// Returns an entry by public id.
    #[must_use]
    pub fn entry(&self, id: EntryId) -> Option<&MempoolEntry> {
        usize::try_from(id)
            .ok()
            .and_then(|index| self.entries.get(index))
    }

    /// Adjusts the effective fee of `txid` in the pool by `fee_delta` satoshis.
    ///
    /// The delta can be negative (saturating at 0). Bumps the entry's `fee`,
    /// recomputes `fee_rate` against the existing `vsize`, and propagates the
    /// realized delta into ancestor and descendant aggregate fees. Returns
    /// `true` when the txid was present and the adjustment was applied; `false`
    /// when the txid was not in the mempool.
    #[must_use]
    pub fn prioritise(&mut self, txid: Txid, fee_delta: i64) -> bool {
        let Some(&id) = self.by_txid.get(&txid) else {
            return false;
        };

        let actual_delta = {
            let Some(entry) = self.entry_mut(id) else {
                return false;
            };
            let new_fee = apply_fee_delta(entry.fee, fee_delta);
            let actual_delta = i128::from(new_fee).saturating_sub(i128::from(entry.fee));
            entry.fee = new_fee;
            let denom = u64::from(entry.vsize).max(1);
            entry.fee_rate = new_fee.saturating_mul(1_000) / denom;
            entry.ancestor_fee = apply_delta_u64(entry.ancestor_fee, actual_delta);
            actual_delta
        };

        let ancestor_ids = self.ancestor_ids_for_entry(id);
        let descendant_ids = self.descendant_ids_for_entry(id);
        for ancestor_id in ancestor_ids {
            if let Some(ancestor) = self.entry_mut(ancestor_id) {
                ancestor.descendant_fee = apply_delta_u64(ancestor.descendant_fee, actual_delta);
            }
        }
        for descendant_id in descendant_ids {
            if let Some(descendant) = self.entry_mut(descendant_id) {
                descendant.ancestor_fee = apply_delta_u64(descendant.ancestor_fee, actual_delta);
            }
        }

        let Some(entry) = self.entry(id).cloned() else {
            return false;
        };
        self.pareto.insert(id, &entry);
        self.bump_sequence();
        true
    }

    /// Removes an entry and all descendants that spend its outputs.
    pub fn remove_entry_and_descendants(&mut self, id: EntryId) -> Vec<EntryId> {
        let mut ids = Vec::new();
        self.collect_descendants_inclusive(id, &mut ids);
        ids.sort_unstable();
        ids.dedup();
        self.remove_entries(&ids);
        ids
    }

    /// Removes the entry for `txid` along with all descendants that spend
    /// its outputs. Returns the set of removed entry ids in stable order.
    ///
    /// Returns an empty vector when the txid is not present in the pool.
    pub fn remove_by_txid(&mut self, txid: &bitcoin::Txid) -> Vec<EntryId> {
        let Some(id) = self.by_txid.get(txid).copied() else {
            return Vec::new();
        };
        self.remove_entry_and_descendants(id)
    }

    pub(crate) fn conflicts_for(&self, tx: &Transaction) -> Vec<EntryId> {
        let mut conflicts = Vec::new();
        for input in &tx.input {
            for (_, id) in self.spending.range(outpoint_range(input.previous_output)) {
                conflicts.push(*id);
            }
        }
        conflicts.sort_unstable();
        conflicts.dedup();
        conflicts
    }

    pub(crate) fn conflicts_with_descendants(&self, tx: &Transaction) -> Vec<EntryId> {
        let mut conflicts = self.conflicts_for(tx);
        let direct = conflicts.clone();
        for id in direct {
            self.collect_descendants_exclusive(id, &mut conflicts);
        }
        conflicts.sort_unstable();
        conflicts.dedup();
        conflicts
    }

    /// Returns all ancestor entry ids for `id`, excluding `id` itself.
    #[must_use]
    pub fn ancestor_ids_for_entry(&self, id: EntryId) -> Vec<EntryId> {
        self.entry(id)
            .map_or_else(Vec::new, |entry| self.ancestor_ids_for_tx(&entry.tx))
    }

    /// Returns all descendant entry ids for `id`, EXCLUDING `id` itself.
    ///
    /// Walks the spend graph forward via output references. Empty Vec when the
    /// entry has no descendants or is unknown.
    #[must_use]
    pub fn descendant_ids_for_entry(&self, id: EntryId) -> Vec<EntryId> {
        let mut ids = Vec::new();
        self.collect_descendants_inclusive(id, &mut ids);
        ids.retain(|other| *other != id);
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    pub(crate) fn signals_rbf_including_ancestors(&self, id: EntryId) -> bool {
        self.entry_signals_rbf(id)
            || self
                .ancestor_ids_for_entry(id)
                .into_iter()
                .any(|ancestor| self.entry_signals_rbf(ancestor))
    }

    pub(crate) fn is_unconfirmed_outpoint(&self, outpoint: OutPoint) -> bool {
        self.by_txid.contains_key(&outpoint.txid)
    }

    fn remove_entries(&mut self, ids: &[EntryId]) {
        let mut removed_any = false;
        for id in ids {
            let Some(index) = usize::try_from(*id).ok() else {
                continue;
            };
            if !self.entries.contains(index) {
                continue;
            }
            let entry = self.entries.remove(index);
            removed_any = true;
            self.by_txid.remove(&entry.tx.compute_txid());
            self.pareto.remove(*id);
            for (vout, output) in entry.tx.output.iter().enumerate() {
                let Ok(_) = EntryId::try_from(vout) else {
                    continue;
                };
                let _ = self
                    .funding
                    .remove(&(ScriptHash::from_script(&output.script_pubkey), *id));
            }
            for input in &entry.tx.input {
                let _ = self.spending.remove(&(input.previous_output, *id));
            }
        }
        self.recompute_all_metadata();
        if removed_any {
            self.bump_sequence();
        }
    }

    fn index_entry(&mut self, id: EntryId) {
        let Some(entry) = self.entry(id) else {
            return;
        };
        let funding_keys = entry
            .tx
            .output
            .iter()
            .map(|output| (ScriptHash::from_script(&output.script_pubkey), id))
            .collect::<Vec<_>>();
        let spending_keys = entry
            .tx
            .input
            .iter()
            .map(|input| (input.previous_output, id))
            .collect::<Vec<_>>();
        for key in funding_keys {
            self.funding.insert(key);
        }
        for key in spending_keys {
            self.spending.insert(key);
        }
    }

    fn recompute_all_metadata(&mut self) {
        let ids = self
            .entries
            .iter()
            .filter_map(|(index, _)| EntryId::try_from(index).ok())
            .collect::<Vec<_>>();
        for id in &ids {
            let ancestors = self.ancestor_ids_for_entry(*id);
            let mut ancestor_size = self.entry(*id).map_or(0, |entry| u64::from(entry.vsize));
            let mut ancestor_fee = self.entry(*id).map_or(0, |entry| entry.fee);
            for ancestor in ancestors {
                if let Some(entry) = self.entry(ancestor) {
                    ancestor_size = ancestor_size.saturating_add(u64::from(entry.vsize));
                    ancestor_fee = ancestor_fee.saturating_add(entry.fee);
                }
            }
            if let Some(entry) = self.entry_mut(*id) {
                entry.ancestor_size = ancestor_size;
                entry.ancestor_fee = ancestor_fee;
                entry.descendant_size = u64::from(entry.vsize);
                entry.descendant_fee = entry.fee;
            }
        }

        for id in &ids {
            let Some(entry) = self.entry(*id) else {
                continue;
            };
            let size = u64::from(entry.vsize);
            let fee = entry.fee;
            for ancestor in self.ancestor_ids_for_entry(*id) {
                if let Some(ancestor_entry) = self.entry_mut(ancestor) {
                    ancestor_entry.descendant_size =
                        ancestor_entry.descendant_size.saturating_add(size);
                    ancestor_entry.descendant_fee =
                        ancestor_entry.descendant_fee.saturating_add(fee);
                }
            }
        }

        let pareto_entries = ids
            .into_iter()
            .filter_map(|id| self.entry(id).cloned().map(|entry| (id, entry)))
            .collect::<Vec<_>>();
        self.pareto = ParetoFront::new();
        for (id, entry) in pareto_entries {
            self.pareto.insert(id, &entry);
        }
    }

    fn check_ancestor_limits(
        &self,
        ancestors: &[EntryId],
        entry: &MempoolEntry,
    ) -> Result<(), PolicyError> {
        let ancestor_count = u32::try_from(ancestors.len())
            .unwrap_or(u32::MAX)
            .saturating_add(1);
        if ancestor_count > self.limits.max_ancestors {
            return Err(PolicyError::TooManyAncestors);
        }
        let ancestor_size = ancestors.iter().fold(u64::from(entry.vsize), |total, id| {
            total.saturating_add(
                self.entry(*id)
                    .map_or(0, |ancestor| u64::from(ancestor.vsize)),
            )
        });
        if ancestor_size > self.limits.max_ancestor_size {
            return Err(PolicyError::AncestorSizeLimit);
        }
        Ok(())
    }

    fn check_descendant_limits(&self, ancestors: &[EntryId]) -> Result<(), PolicyError> {
        for ancestor in ancestors {
            let descendant_count = self.descendant_count_inclusive(*ancestor).saturating_add(1);
            if descendant_count > self.limits.max_descendants {
                return Err(PolicyError::TooManyDescendants);
            }
        }
        Ok(())
    }

    fn ancestor_ids_for_tx(&self, tx: &Transaction) -> Vec<EntryId> {
        let mut ancestors = Vec::new();
        let mut stack = tx
            .input
            .iter()
            .filter_map(|input| self.by_txid.get(&input.previous_output.txid).copied())
            .collect::<Vec<_>>();
        while let Some(id) = stack.pop() {
            if ancestors.contains(&id) {
                continue;
            }
            ancestors.push(id);
            if let Some(entry) = self.entry(id) {
                for input in &entry.tx.input {
                    if let Some(parent) = self.by_txid.get(&input.previous_output.txid) {
                        stack.push(*parent);
                    }
                }
            }
        }
        ancestors.sort_unstable();
        ancestors
    }

    fn collect_descendants_inclusive(&self, id: EntryId, out: &mut Vec<EntryId>) {
        if out.contains(&id) {
            return;
        }
        out.push(id);
        self.collect_descendants_exclusive(id, out);
    }

    fn collect_descendants_exclusive(&self, id: EntryId, out: &mut Vec<EntryId>) {
        for child in self.child_ids(id) {
            if out.contains(&child) {
                continue;
            }
            out.push(child);
            self.collect_descendants_exclusive(child, out);
        }
    }

    fn child_ids(&self, id: EntryId) -> Vec<EntryId> {
        let Some(entry) = self.entry(id) else {
            return Vec::new();
        };
        let txid = entry.tx.compute_txid();
        let mut children = Vec::new();
        for (vout, _) in entry.tx.output.iter().enumerate() {
            let Ok(vout) = u32::try_from(vout) else {
                continue;
            };
            let outpoint = OutPoint::new(txid, vout);
            for (_, child) in self.spending.range(outpoint_range(outpoint)) {
                children.push(*child);
            }
        }
        children.sort_unstable();
        children.dedup();
        children
    }

    fn descendant_count_inclusive(&self, id: EntryId) -> u32 {
        let mut descendants = Vec::new();
        self.collect_descendants_inclusive(id, &mut descendants);
        u32::try_from(descendants.len()).unwrap_or(u32::MAX)
    }

    fn entry_mut(&mut self, id: EntryId) -> Option<&mut MempoolEntry> {
        usize::try_from(id)
            .ok()
            .and_then(|index| self.entries.get_mut(index))
    }

    fn entry_signals_rbf(&self, id: EntryId) -> bool {
        self.entry(id)
            .is_some_and(|entry| entry.tx.input.iter().any(|input| input.sequence.is_rbf()))
    }
}

pub(crate) fn tx_fee_rate(fee: u64, vsize: u32) -> u64 {
    fee_rate(fee, u64::from(vsize))
}

fn apply_fee_delta(fee: u64, delta: i64) -> u64 {
    if delta >= 0 {
        fee.saturating_add(delta.unsigned_abs())
    } else {
        fee.saturating_sub(delta.unsigned_abs())
    }
}

fn apply_delta_u64(value: u64, delta: i128) -> u64 {
    let magnitude = u64::try_from(delta.unsigned_abs()).unwrap_or(u64::MAX);
    if delta >= 0 {
        value.saturating_add(magnitude)
    } else {
        value.saturating_sub(magnitude)
    }
}

const fn outpoint_range(outpoint: OutPoint) -> RangeInclusive<(OutPoint, EntryId)> {
    (outpoint, EntryId::MIN)..=(outpoint, EntryId::MAX)
}
#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use alloc::vec::Vec;

    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

    use super::*;

    #[test]
    fn stats_reports_empty_and_inserted_entry_counters() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits::default());
        assert_eq!(pool.stats(), MempoolStats::default());

        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: Vec::new(),
            output: Vec::new(),
        };
        let entry = MempoolEntry::new(Arc::new(tx), 123, 4_567, 0, 0);
        let expected_vsize = u64::from(entry.vsize);
        let expected_fee = entry.fee;

        pool.insert_entry(entry)?;

        let stats = pool.stats();
        assert_eq!(stats.txs, 1);
        assert_eq!(stats.bytes, expected_vsize);
        assert_eq!(stats.total_fee, expected_fee);
        Ok(())
    }

    #[test]
    fn sequence_number_bumps_on_successful_insert() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits::default());
        let before = pool.sequence_number();
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: Vec::new(),
            output: Vec::new(),
        };
        let entry = MempoolEntry::new(Arc::new(tx), 100, 1_000, 1, 7);
        pool.insert_entry(entry)?;
        let after = pool.sequence_number();
        assert!(after > before, "expected sequence to bump");
        Ok(())
    }

    #[test]
    fn remove_by_txid_returns_empty_for_unknown_txid() {
        let mut pool = Mempool::new(MempoolLimits::default());

        let removed = pool.remove_by_txid(&bitcoin::Txid::all_zeros());

        assert!(removed.is_empty());
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn remove_by_txid_removes_entry_and_descendants_when_present() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits::default());
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: Vec::new(),
            output: Vec::new(),
        };
        let txid = tx.compute_txid();
        let entry = MempoolEntry::new(Arc::new(tx), 123, 4_567, 0, 0);
        let id = pool.insert_entry(entry)?;

        let removed = pool.remove_by_txid(&txid);

        assert_eq!(removed.len(), 1);
        assert_eq!(removed.first().copied(), Some(id));
        assert_eq!(pool.len(), 0);
        Ok(())
    }

    #[test]
    fn descendant_ids_for_entry_returns_descendants_excluding_origin() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits::default());
        let parent = tx(1, Vec::new());
        let parent_txid = parent.compute_txid();
        let parent_id = pool.insert_entry(MempoolEntry::new(Arc::new(parent), 100, 1_000, 0, 0))?;
        let child = tx(2, vec![OutPoint::new(parent_txid, 0)]);
        let child_id = pool.insert_entry(MempoolEntry::new(Arc::new(child), 100, 1_000, 0, 0))?;

        let descendants = pool.descendant_ids_for_entry(parent_id);

        assert_eq!(descendants, vec![child_id]);
        Ok(())
    }

    #[test]
    fn prioritise_bumps_fee_and_rate() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits::default());
        let tx = tx(1, Vec::new());
        let txid = tx.compute_txid();
        let entry = MempoolEntry::new(Arc::new(tx), 100, 1_000, 1, 7);
        let _id = pool.insert_entry(entry)?;

        assert!(pool.prioritise(txid, 500));

        let Some(&id) = pool.by_txid.get(&txid) else {
            panic!("tx missing after prioritise");
        };
        let Some(entry) = pool.entry(id) else {
            panic!("entry missing");
        };
        assert_eq!(entry.fee, 1_500);
        assert_eq!(entry.fee_rate, 15_000);
        Ok(())
    }

    #[test]
    fn prioritise_saturates_negative_delta_at_zero() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits::default());
        let tx = tx(2, Vec::new());
        let txid = tx.compute_txid();
        let entry = MempoolEntry::new(Arc::new(tx), 100, 1_000, 1, 7);
        let _id = pool.insert_entry(entry)?;

        assert!(pool.prioritise(txid, -2_000));

        let Some(&id) = pool.by_txid.get(&txid) else {
            panic!("tx missing after prioritise");
        };
        let Some(entry) = pool.entry(id) else {
            panic!("entry missing");
        };
        assert_eq!(entry.fee, 0);
        assert_eq!(entry.fee_rate, 0);
        Ok(())
    }

    #[test]
    fn prioritise_propagates_delta_to_ancestor_descendant_fees() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits::default());
        let parent = tx(5, Vec::new());
        let parent_txid = parent.compute_txid();
        let parent_id = pool.insert_entry(MempoolEntry::new(Arc::new(parent), 100, 1_000, 0, 0))?;
        let child = tx(6, vec![OutPoint::new(parent_txid, 0)]);
        let child_txid = child.compute_txid();
        let child_id = pool.insert_entry(MempoolEntry::new(Arc::new(child), 100, 2_000, 0, 0))?;
        let grandchild = tx(7, vec![OutPoint::new(child_txid, 0)]);
        let grandchild_id =
            pool.insert_entry(MempoolEntry::new(Arc::new(grandchild), 100, 3_000, 0, 0))?;

        let Some(parent_before) = pool.entry(parent_id) else {
            panic!("missing parent");
        };
        let parent_descendant_fee = parent_before.descendant_fee;
        let Some(child_before) = pool.entry(child_id) else {
            panic!("missing child");
        };
        let child_ancestor_fee = child_before.ancestor_fee;
        let Some(grandchild_before) = pool.entry(grandchild_id) else {
            panic!("missing grandchild");
        };
        let grandchild_ancestor_fee = grandchild_before.ancestor_fee;

        assert!(pool.prioritise(child_txid, 500));

        let Some(parent_after) = pool.entry(parent_id) else {
            panic!("missing parent");
        };
        assert_eq!(
            parent_after.descendant_fee,
            parent_descendant_fee.saturating_add(500)
        );
        let Some(child_after) = pool.entry(child_id) else {
            panic!("missing child");
        };
        assert_eq!(
            child_after.ancestor_fee,
            child_ancestor_fee.saturating_add(500)
        );
        let Some(grandchild_after) = pool.entry(grandchild_id) else {
            panic!("missing grandchild");
        };
        assert_eq!(
            grandchild_after.ancestor_fee,
            grandchild_ancestor_fee.saturating_add(500)
        );
        Ok(())
    }

    #[test]
    fn prioritise_returns_false_for_unknown_txid() {
        let mut pool = Mempool::new(MempoolLimits::default());

        assert!(!pool.prioritise(Txid::all_zeros(), 100));
    }

    #[test]
    fn prioritise_reorders_priority_index() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits::default());
        let lower_fee_tx = tx(3, Vec::new());
        let lower_fee_txid = lower_fee_tx.compute_txid();
        let lower_fee_id =
            pool.insert_entry(MempoolEntry::new(Arc::new(lower_fee_tx), 100, 1_000, 1, 7))?;
        let higher_fee_tx = tx(4, Vec::new());
        let higher_fee_id =
            pool.insert_entry(MempoolEntry::new(Arc::new(higher_fee_tx), 100, 2_000, 2, 7))?;

        assert_eq!(
            pool.pareto.top_n(1).collect::<Vec<_>>(),
            vec![higher_fee_id]
        );
        assert!(pool.prioritise(lower_fee_txid, 2_000));

        assert_eq!(pool.pareto.top_n(1).collect::<Vec<_>>(), vec![lower_fee_id]);
        Ok(())
    }

    fn tx(label: u8, previous_outputs: Vec<OutPoint>) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: previous_outputs
                .into_iter()
                .map(|previous_output| TxIn {
                    previous_output,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            output: vec![TxOut {
                value: Amount::from_sat(5_000 + u64::from(label)),
                script_pubkey: ScriptBuf::from_bytes(vec![label]),
            }],
        }
    }
}
