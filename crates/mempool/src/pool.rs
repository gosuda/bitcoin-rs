use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::{Bound, RangeInclusive};

use bitcoin_rs_primitives::{Hash256, OutPoint, Tx, TxIn, TxOut, Txid, Wtxid};
use hashbrown::{HashMap, HashSet};
use sha2::{Digest, Sha256};
use slab::Slab;
use thiserror::Error;

use crate::entry::fee_rate;
use crate::fee_estimator::{FeeEstimator, FeeRate};
use crate::mutation::{MutationChange, MutationOutcome, MutationResult, RemovalReason};
use crate::{
    EntryId, MempoolEntry, MempoolLimits, MempoolPolicySnapshot, ParetoFront, PolicyError,
};

/// Script-index key for funding index range scans.
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
    /// Single SHA256 of the script bytes in consensus byte order.
    pub hash: Hash256,
}

impl ScriptHash {
    /// Hashes a script into an index key.
    #[must_use]
    pub fn from_script(script: &[u8]) -> Self {
        Self {
            hash: Hash256::from_le_bytes(&Sha256::digest(script).into()),
        }
    }

    /// Creates a script hash from the standard SHA256 digest bytes.
    #[must_use]
    pub const fn from_byte_array(bytes: [u8; 32]) -> Self {
        Self {
            hash: Hash256::from_le_bytes(&bytes),
        }
    }
}

/// Mempool insertion, mutation, and query-consistency errors.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum MempoolError {
    /// The transaction id already exists in the pool.
    #[error("transaction already exists in mempool")]
    DuplicateTransaction,
    /// The slab index can no longer fit the public `u32` entry id.
    #[error("mempool entry id space exhausted")]
    TooManyEntries,
    /// The transaction spends an output created by an entry scheduled for eviction.
    #[error("transaction spends an output of an evicted mempool entry")]
    EvictedParent,
    /// The transaction violates mempool policy limits.
    #[error(transparent)]
    Policy(#[from] PolicyError),
    /// The pool was over its size limit and this transaction was what it shed.
    ///
    /// Bitcoin Core's `mempool full`: it adds the transaction, trims the pool,
    /// and then checks whether what it added is still there. A transaction that
    /// was trimmed away was never accepted, however briefly it was indexed.
    #[error("mempool full: the transaction was evicted by the size limit")]
    Full,
    /// The spending index names an entry that is missing from the pool, or an
    /// entry whose transaction does not spend the indexed outpoint.
    #[error("mempool spending index is inconsistent")]
    InconsistentSpendingIndex,
}

/// Prioritisation overlay rejection reason.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PrioritiseError {
    /// Adding the delta to the signed overlay stored for a txid would leave
    /// the satoshi range. The overlay is left exactly as it was.
    #[error("fee delta would overflow the persistent overlay")]
    FeeDeltaOverflow,
}

/// One `prioritisetransaction` overlay entry, including txs not currently pooled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrioritisedTransaction {
    /// Transaction id the overlay is stored against.
    pub txid: Txid,
    /// Accumulated signed satoshi overlay.
    pub fee_delta: i64,
    /// Whether `txid` is currently in the pool.
    pub in_mempool: bool,
    /// Actual fee plus the accumulated delta, when pooled.
    pub modified_fee: Option<i128>,
}

/// In-memory transaction pool with txid, funding, spending, and fee-priority indexes.
#[derive(Debug)]
pub struct Mempool {
    /// Entry arena. Public ids are slab indices represented as `u32`.
    pub(crate) entries: Slab<MempoolEntry>,
    /// Tx id to entry id lookup. Owned by this module; reach it
    /// through `contains_txid`, `entry_id_by_txid`, and `entry_by_txid`.
    by_txid: HashMap<Txid, EntryId>,
    /// Funding index keyed by script hash then entry id. Owned by this
    /// module; reach it through `entries_funding_script`.
    funding: std::collections::BTreeSet<(ScriptHash, EntryId)>,
    /// Spending index keyed by spent outpoint then entry id. Owned by this
    /// module; reach it through `is_outpoint_spent` and `outpoint_spender`.
    spending: std::collections::BTreeSet<(SpendingKey, EntryId)>,
    /// Fee-priority index for mining and eviction consumers.
    pub(crate) pareto: ParetoFront,
    /// Active mempool policy limits.
    pub limits: MempoolLimits,
    /// Running sum of `vsize` over `entries`.
    ///
    /// Maintained by the mutation methods below rather than folded on demand.
    /// `insert_entry` consults it on every accepted transaction to decide
    /// whether the pool is over its size limit, so folding it there cost `O(n)`
    /// per acceptance and made insertion quadratic in pool size on its own.
    ///
    /// `entries` is crate-visible so eviction can walk the arena, but every
    /// mutation still goes through `insert_entry`, `remove_entries`,
    /// `prioritise` or `clear` — and `debug_assert`s in `total_vsize` and
    /// `aggregate_fees` fail the moment a future in-crate caller forgets.
    total_vsize: u64,
    /// Exact running sum of `fee` over `entries`. A `u32` entry id bounds the
    /// successful-entry sum below `u128::MAX`.
    total_fee: u128,
    /// Ordered multiset of live `MempoolEntry.fee_rate` values keyed to their
    /// occurrence count. Mutation paths use it to advance `fee_rate_floor`
    /// when the last entry at the current floor leaves.
    fee_rate_counts: std::collections::BTreeMap<u64, u64>,
    /// Cached first key of `fee_rate_counts`. Reads are `O(1)`; inserts and
    /// removals maintain it together with the multiset.
    fee_rate_floor: Option<u64>,
    /// Signed additive mining-only fee overlay, keyed by txid. A delta may be
    /// stored before its transaction is admitted, accumulates across calls,
    /// survives ordinary removal and replacement, and is erased only when the
    /// transaction is mined (see [`Mempool::remove_for_block`]). It adjusts
    /// modified package ordering only — never an actual fee.
    fee_deltas: HashMap<Txid, i64>,
    /// Fee-rate history this pool owns and feeds from its own mutations:
    /// admissions record arrivals, non-mined removals record departures, and
    /// `remove_for_block` records confirmations.
    estimator: FeeEstimator,
    /// Mempool sequence: advanced once per emitted mutation change while the
    /// write lock is held. Reported by [`Mempool::sequence_number`], carried
    /// in ZMQ `A`/`R` event payloads, and used as the mining generation key's
    /// mempool component. Failed inserts, no-op removals, clear-on-empty, and
    /// in-pool prioritisation move nothing.
    mempool_sequence: u64,
}

pub(crate) struct PreparedInsert {
    entry: MempoolEntry,
}

/// The in-pool spender of one outpoint, resolved through the spending index.
#[derive(Clone, Copy, Debug)]
pub struct OutpointSpender<'a> {
    /// The entry whose transaction spends the outpoint.
    pub entry: &'a MempoolEntry,
    /// Index of the input within `entry.tx` that spends the outpoint.
    pub vin: u32,
}

/// Aggregate mempool counters surfaced through the JSON-RPC `getmempoolinfo`
/// and Esplora fee-estimate surfaces.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MempoolStats {
    /// Number of transactions in the mempool.
    pub txs: u64,
    /// Sum of virtual sizes in vbytes.
    pub bytes: u64,
    /// Sum of base fees in satoshis.
    pub total_fee: u64,
}

/// One mempool entry copied into a [`MempoolMiningSnapshot`].
///
/// A pure record of what selection consumed at capture time. `ancestors`
/// holds the snapshot positions of the entry's transitive unconfirmed
/// ancestors — its in-pool parents, their parents, and so on — so package
/// walks stay inside the snapshot; an entry with no in-pool parent chain
/// carries an empty vector.
#[derive(Clone, Debug)]
pub struct SnapshotEntry {
    /// Tx payload, shared with the pool entry by `Arc`.
    pub tx: Arc<Tx>,
    /// Tx id.
    pub txid: Txid,
    /// Witness transaction id.
    pub wtxid: Wtxid,
    /// Policy-adjusted virtual size in vbytes.
    pub vsize: u32,
    /// BIP141 virtual size in vbytes.
    pub bip141_vsize: u32,
    /// Consensus serialization size, including witness, in bytes.
    pub size: u32,
    /// Consensus transaction weight in weight units.
    pub weight: u64,
    /// Consensus sigop cost, prevout-aware when admission supplied it.
    pub sigop_cost: u32,
    /// Actual transaction fee in satoshis. Prioritisation never changes it.
    pub fee: u64,
    /// Signed additive mining-only overlay applied to `fee` for ordering.
    pub fee_delta: i64,
    /// Mempool acceptance time in seconds.
    pub time: u64,
    /// Chain height at acceptance.
    pub height: u32,
    /// Total virtual size of this entry and all its unconfirmed ancestors.
    pub ancestor_size: u64,
    /// Total actual fee of this entry and all its unconfirmed ancestors.
    pub ancestor_fee: u64,
    /// Total signed overlay of this entry and all its unconfirmed ancestors.
    pub ancestor_fee_delta: i128,
    /// Snapshot positions of the transitive unconfirmed ancestors.
    pub ancestors: Vec<u32>,
}

/// Immutable copy of everything block-template selection needs from the pool,
/// captured by [`Mempool::mining_snapshot`] under one read.
#[derive(Clone, Debug)]
pub struct MempoolMiningSnapshot {
    /// Pool mempool sequence at capture. Every admission and removal change
    /// moves it; in-pool prioritisation does not (it emits no mutation
    /// change). Template caches key on it.
    pub sequence: u64,
    /// Entries in modified-priority order. `ancestors` positions and the
    /// order itself both refer to this vector.
    pub entries: Vec<SnapshotEntry>,
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
            total_vsize: 0,
            total_fee: 0,
            fee_rate_counts: std::collections::BTreeMap::new(),
            fee_rate_floor: None,
            fee_deltas: HashMap::new(),
            estimator: FeeEstimator::new(),
            mempool_sequence: 0,
        }
    }

    /// Removes all entries from the pool, clears every index and the
    /// persistent prioritisation overlay, and resets the fee history. Every
    /// cleared entry commits as one `Removed(Clear)` change — in entry-id
    /// order — each taking the next mempool sequence value. A clear of an
    /// already-empty pool commits nothing and moves no sequence.
    pub fn clear(&mut self) -> MutationResult {
        let txids: Vec<Txid> = self.entries.iter().map(|(_id, entry)| entry.txid).collect();
        self.entries.clear();
        self.by_txid.clear();
        self.funding.clear();
        self.spending.clear();
        self.pareto = ParetoFront::new();
        self.total_vsize = 0;
        self.total_fee = 0;
        self.fee_rate_counts.clear();
        self.fee_rate_floor = None;
        self.fee_deltas.clear();
        self.estimator = FeeEstimator::new();
        let mut changes = Vec::with_capacity(txids.len());
        for txid in txids {
            self.push_change(
                &mut changes,
                txid,
                MutationOutcome::Removed(RemovalReason::Clear),
            );
        }
        self.finish_mutation(changes)
    }

    /// Returns the current mempool sequence: a counter advanced once per
    /// emitted mutation change. `getmempoolinfo`, `getrawmempool` sequence
    /// reporting, and the mining generation key all read this counter. Failed
    /// inserts, no-op removals, clear-on-empty, and in-pool prioritisation
    /// move nothing.
    #[must_use]
    pub const fn sequence_number(&self) -> u64 {
        self.mempool_sequence
    }

    /// Returns the configured min-relay-fee rate in sat/kvB.
    #[must_use]
    pub const fn min_relay_fee_sat_per_kvb(&self) -> u64 {
        self.limits.min_relay_fee_sat_per_kvb
    }

    /// Records one committed change and assigns it the next mempool sequence
    /// value. Callers hold the write lock for the whole mutation, so
    /// assignment is total, ordered, and gap-free within a batch.
    fn push_change(
        &mut self,
        changes: &mut Vec<MutationChange>,
        txid: Txid,
        outcome: MutationOutcome,
    ) {
        self.mempool_sequence = self.mempool_sequence.wrapping_add(1);
        changes.push(crate::mutation::change(&txid, outcome));
    }

    /// Wraps an ordered change list into a result, deriving the batch's
    /// sequence base from the counter the changes just advanced.
    pub(crate) fn finish_mutation(&self, changes: Vec<MutationChange>) -> MutationResult {
        let batch_len = u64::try_from(changes.len()).unwrap_or(u64::MAX);
        let sequence_base = changes.first().map_or(0, |_| {
            self.mempool_sequence
                .wrapping_sub(batch_len)
                .wrapping_add(1)
        });
        MutationResult {
            changes,
            sequence_base,
        }
    }

    /// Inserts an entry after applying ancestor and descendant policy checks.
    /// On success the outcome carries the `Accepted` change followed by any
    /// post-insert size-limit evictions as `Removed(PolicyEviction)`, in
    /// commit order. When the trim sheds the entry itself the mutation is
    /// still committed; it reports as
    /// [`InsertionOutcome::ShedAfterCommit`] carrying that record, and only
    /// an `Err` means nothing was committed.
    pub fn insert_entry(
        &mut self,
        entry: MempoolEntry,
    ) -> Result<crate::mutation::InsertionOutcome, MempoolError> {
        let prepared = self.validate_insert(entry, &HashSet::new())?;
        let txid = prepared.entry.txid;
        let result = self.commit_insert(prepared);
        // The trim evicts the worst-paying entries, and the arrival can be
        // one of them. The mutation already committed -- the sequence moved
        // and any eviction is durable -- so the outcome carries the record;
        // reporting plain success would hand the caller a receipt for a
        // transaction that is not in the pool, which `sendrawtransaction`
        // would turn into a success the sender acts on. Core makes the
        // same check for the same reason (`validation.cpp`:
        // `LimitMempoolSize`).
        Ok(if self.contains_txid(&txid) {
            crate::mutation::InsertionOutcome::Accepted(result)
        } else {
            crate::mutation::InsertionOutcome::ShedAfterCommit(result)
        })
    }

    pub(crate) fn validate_insert(
        &self,
        mut entry: MempoolEntry,
        excluded: &HashSet<EntryId>,
    ) -> Result<PreparedInsert, MempoolError> {
        let txid = entry.txid;
        let min_rate = self.limits.min_relay_fee_sat_per_kvb;
        if min_rate > 0 && entry.fee_rate < min_rate {
            return Err(PolicyError::BelowMinRelayFee {
                tx_rate: entry.fee_rate,
                min_rate,
            }
            .into());
        }

        if self.by_txid.contains_key(&txid) {
            return Err(MempoolError::DuplicateTransaction);
        }

        if entry.tx.inputs.iter().any(|input| {
            self.by_txid
                .get(&input.previous_output.txid)
                .is_some_and(|id| excluded.contains(id))
        }) {
            return Err(MempoolError::EvictedParent);
        }

        let ancestors = self.ancestor_ids_for_tx(&entry.tx);
        self.check_ancestor_limits(&ancestors, &entry)?;
        self.check_descendant_limits_excluding(&ancestors, excluded)?;
        self.check_cluster_limits(&entry.tx, entry.vsize, excluded)?;

        if excluded.is_empty() && u32::try_from(self.entries.vacant_key()).is_err() {
            return Err(MempoolError::TooManyEntries);
        }

        let ancestor_size = ancestors.iter().fold(u64::from(entry.vsize), |total, id| {
            total.saturating_add(
                self.entry(*id)
                    .map_or(0, |ancestor| u64::from(ancestor.vsize)),
            )
        });
        let ancestor_fee = ancestors.iter().fold(entry.fee, |total, id| {
            total.saturating_add(self.entry(*id).map_or(0, |ancestor| ancestor.fee))
        });
        // A delta stored before admission applies from the moment the
        // transaction arrives. It adjusts modified package ordering only;
        // the actual fee and fee rate that policy and accounting read are
        // exactly what the caller supplied.
        entry.fee_delta = self.fee_deltas.get(&txid).copied().unwrap_or(0);
        entry.ancestor_size = ancestor_size;
        entry.ancestor_fee = ancestor_fee;
        entry.ancestor_fee_delta = i128::from(entry.fee_delta);
        entry.descendant_size = u64::from(entry.vsize);
        entry.descendant_fee = entry.fee;
        entry.descendant_fee_delta = i128::from(entry.fee_delta);

        Ok(PreparedInsert { entry })
    }

    /// Commits a validated insert. The result carries the `Accepted` change
    /// first, then any post-insert size-limit evictions as
    /// `Removed(PolicyEviction)` in eviction order.
    pub(crate) fn commit_insert(&mut self, prepared: PreparedInsert) -> MutationResult {
        let entry = prepared.entry;
        let txid = entry.txid;
        let added_vsize = u64::from(entry.vsize);
        let added_fee = entry.fee;
        let added_fee_rate = entry.fee_rate;
        let index = self.entries.insert(entry);
        let Ok(id) = EntryId::try_from(index) else {
            panic!("validate_insert accepted an entry id that does not fit u32");
        };
        self.total_vsize = self.total_vsize.saturating_add(added_vsize);
        self.total_fee += u128::from(added_fee);
        *self.fee_rate_counts.entry(added_fee_rate).or_insert(0) += 1;
        self.fee_rate_floor = Some(
            self.fee_rate_floor
                .map_or(added_fee_rate, |floor| floor.min(added_fee_rate)),
        );
        self.by_txid.insert(txid, id);
        self.index_entry(id);
        // The closure is taken after `index_entry`, because a transaction can
        // arrive after something that already spends its outputs — an orphan
        // promotion, or plain out-of-order relay — and those descendants only
        // become reachable once this entry is in the spend indexes.
        let affected = self.metadata_closure(&[id]);
        self.refresh_metadata(&affected);
        let mut changes = Vec::new();
        self.push_change(&mut changes, txid, MutationOutcome::Accepted);
        if self.limits.max_total_bytes > 0 && self.total_vsize() > self.limits.max_total_bytes {
            changes.extend(crate::evict_lowest_fee_packages(
                self,
                self.limits.max_total_bytes,
            ));
        }
        // Fed last, after size-limit eviction: an acceptance that eviction
        // immediately removed must not linger in the estimator's pending set.
        // The scalars are copied out so the entry borrow ends before the
        // estimator is borrowed mutably.
        if let Some((fee_rate, height)) = self.entry(id).map(|entry| (entry.fee_rate, entry.height))
        {
            self.estimator.tx_entered(txid, fee_rate, height);
        }
        self.finish_mutation(changes)
    }

    /// Returns the number of transactions in the mempool.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` when `txid` is present in the pool.
    #[must_use]
    pub fn contains_txid(&self, txid: &Txid) -> bool {
        self.by_txid.contains_key(txid)
    }

    #[must_use]
    pub fn entry_by_txid(&self, txid: &Txid) -> Option<&MempoolEntry> {
        let id = *self.by_txid.get(txid)?;
        self.entry(id)
    }

    #[must_use]
    pub fn transaction_by_txid(&self, txid: &Txid) -> Option<Arc<Tx>> {
        self.entry_by_txid(txid).map(|entry| Arc::clone(&entry.tx))
    }

    #[must_use]
    pub fn entry_id_by_txid(&self, txid: &Txid) -> Option<EntryId> {
        self.by_txid.get(txid).copied()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub fn tx_count(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn iter_txids(&self) -> Vec<Txid> {
        self.entries.iter().map(|(_id, entry)| entry.txid).collect()
    }

    #[must_use]
    pub fn iter_replaceable_txids(&self) -> Vec<Txid> {
        self.entries
            .iter()
            .filter(|(_id, entry)| entry.is_replaceable())
            .map(|(_id, entry)| entry.txid)
            .collect()
    }

    #[must_use]
    pub fn policy_snapshot(&self) -> MempoolPolicySnapshot {
        MempoolPolicySnapshot::from_enforced(
            self.limits,
            crate::standardness::StandardnessPolicy::default(),
        )
    }

    #[must_use]
    pub fn total_vsize(&self) -> u64 {
        debug_assert_eq!(
            self.total_vsize,
            self.entries.iter().fold(0_u64, |total, (_, entry)| total
                .saturating_add(u64::from(entry.vsize))),
            "running vsize total drifted from the entries it summarizes"
        );
        self.total_vsize
    }

    pub fn enforce_size_limit(&mut self, max_bytes: u64) -> MutationResult {
        let changes = crate::evict_lowest_fee_packages(self, max_bytes);
        self.finish_mutation(changes)
    }

    #[must_use]
    pub fn aggregate_fees(&self) -> u64 {
        let total_fee = u64::try_from(self.total_fee).unwrap_or(u64::MAX);
        debug_assert_eq!(
            total_fee,
            self.entries
                .iter()
                .fold(0_u64, |acc, (_id, entry)| acc.saturating_add(entry.fee)),
            "running fee total drifted from the entries it summarizes"
        );
        total_fee
    }

    #[must_use]
    pub fn stats(&self) -> MempoolStats {
        let txs = u64::try_from(self.entries.len()).unwrap_or(u64::MAX);
        let bytes = self.total_vsize();
        let total_fee = self.aggregate_fees();
        MempoolStats {
            txs,
            bytes,
            total_fee,
        }
    }

    #[must_use]
    pub fn dynamic_memory_usage(&self) -> u64 {
        use core::mem::size_of;
        let arena = u64::try_from(self.entries.capacity())
            .unwrap_or(u64::MAX)
            .saturating_mul(u64::try_from(size_of::<MempoolEntry>()).unwrap_or(0));
        let transactions = self
            .entries
            .iter()
            .map(|(_index, entry)| transaction_heap_usage(&entry.tx))
            .fold(0_u64, u64::saturating_add);
        let by_txid = u64::try_from(self.by_txid.capacity())
            .unwrap_or(u64::MAX)
            .saturating_mul(u64::try_from(size_of::<(Txid, EntryId)>()).unwrap_or(0));
        let funding = u64::try_from(self.funding.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(u64::try_from(size_of::<(ScriptHash, EntryId)>()).unwrap_or(0));
        let spending = u64::try_from(self.spending.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(u64::try_from(size_of::<(SpendingKey, EntryId)>()).unwrap_or(0));
        let pareto = self.pareto.dynamic_memory_usage();
        arena
            .saturating_add(transactions)
            .saturating_add(by_txid)
            .saturating_add(funding)
            .saturating_add(spending)
            .saturating_add(pareto)
    }

    #[must_use]
    pub fn estimate_fee_rate(&self, conf_target_blocks: u32) -> Option<FeeRate> {
        self.estimator.estimate(conf_target_blocks)
    }

    pub fn estimator_last_decayed_height(&self) -> Option<u32> {
        self.estimator.last_decayed_height()
    }

    #[must_use]
    pub fn mining_snapshot(&self) -> MempoolMiningSnapshot {
        let order: Vec<EntryId> = self.pareto.top_n(self.pareto.len()).collect();
        debug_assert_eq!(
            order.len(),
            self.entries.len(),
            "priority index and entry arena disagree on the pool contents"
        );
        let position: HashMap<EntryId, u32> = order
            .iter()
            .enumerate()
            .filter_map(|(index, &id)| u32::try_from(index).ok().map(|slot| (id, slot)))
            .collect();
        let entries = order
            .iter()
            .map(|&id| {
                let Some(entry) = self.entry(id) else {
                    panic!("priority index names a missing entry");
                };
                let ancestors = self
                    .ancestor_ids_for_entry(id)
                    .into_iter()
                    .filter_map(|ancestor| position.get(&ancestor).copied())
                    .collect();
                SnapshotEntry {
                    tx: Arc::clone(&entry.tx),
                    txid: entry.txid,
                    wtxid: entry.wtxid,
                    vsize: entry.vsize,
                    bip141_vsize: entry.bip141_vsize,
                    size: entry.size,
                    weight: entry.weight,
                    sigop_cost: entry.sigop_cost,
                    fee: entry.fee,
                    fee_delta: entry.fee_delta,
                    time: entry.time,
                    height: entry.height,
                    ancestor_size: entry.ancestor_size,
                    ancestor_fee: entry.ancestor_fee,
                    ancestor_fee_delta: entry.ancestor_fee_delta,
                    ancestors,
                }
            })
            .collect();
        MempoolMiningSnapshot {
            sequence: self.sequence_number(),
            entries,
        }
    }

    #[must_use]
    pub fn entry(&self, id: EntryId) -> Option<&MempoolEntry> {
        usize::try_from(id)
            .ok()
            .and_then(|index| self.entries.get(index))
    }

    pub fn iter_entries(&self) -> impl Iterator<Item = &MempoolEntry> + '_ {
        self.entries.iter().map(|(_id, entry)| entry)
    }

    pub fn entries_funding_script(
        &self,
        script_hash: ScriptHash,
    ) -> impl Iterator<Item = &MempoolEntry> + '_ {
        let entries = &self.entries;
        self.funding
            .range((
                Bound::Included((script_hash, 0)),
                Bound::Included((script_hash, u32::MAX)),
            ))
            .filter_map(move |(_, id)| {
                usize::try_from(*id)
                    .ok()
                    .and_then(|index| entries.get(index))
            })
    }

    #[must_use]
    pub fn contains_wtxid(&self, wtxid: &Wtxid) -> bool {
        self.entries
            .iter()
            .any(|(_id, entry)| entry.wtxid == *wtxid)
    }

    #[must_use]
    pub fn entry_by_wtxid(&self, wtxid: &Wtxid) -> Option<&MempoolEntry> {
        self.entries
            .iter()
            .map(|(_id, entry)| entry)
            .find(|entry| entry.wtxid == *wtxid)
    }

    #[must_use]
    pub fn iter_by_fee_rate_desc(&self) -> Vec<EntryId> {
        let mut pairs: Vec<(u64, EntryId)> = self
            .entries
            .iter()
            .filter_map(|(index, entry)| {
                let id = EntryId::try_from(index).ok()?;
                Some((entry.fee_rate, id))
            })
            .collect();
        pairs.sort_by_key(|pair| core::cmp::Reverse(pair.0));
        pairs.into_iter().map(|(_, id)| id).collect()
    }

    #[must_use]
    pub fn lowest_fee_rate(&self) -> Option<u64> {
        debug_assert_eq!(
            self.fee_rate_floor,
            self.fee_rate_counts
                .first_key_value()
                .map(|(&rate, _count)| rate),
            "cached fee-rate floor drifted from its multiset"
        );
        debug_assert_eq!(
            self.fee_rate_floor,
            self.entries
                .iter()
                .map(|(_index, entry)| entry.fee_rate)
                .min(),
            "maintained fee-rate floor drifted from the entries it summarizes"
        );
        self.fee_rate_floor
    }

    #[must_use]
    pub fn iter_above_fee_rate(&self, threshold_sat_per_kvb: u64) -> Vec<EntryId> {
        self.entries
            .iter()
            .filter(|(_index, entry)| entry.fee_rate >= threshold_sat_per_kvb)
            .filter_map(|(index, _entry)| EntryId::try_from(index).ok())
            .collect()
    }

    #[must_use]
    pub fn is_outpoint_spent(&self, outpoint: &OutPoint) -> bool {
        self.spending
            .range(outpoint_range(*outpoint))
            .next()
            .is_some()
    }

    pub fn outpoint_spender(
        &self,
        outpoint: OutPoint,
    ) -> Result<Option<OutpointSpender<'_>>, MempoolError> {
        let Some(&(_, id)) = self.spending.range(outpoint_range(outpoint)).next() else {
            return Ok(None);
        };
        let entry = self
            .entry(id)
            .ok_or(MempoolError::InconsistentSpendingIndex)?;
        let vin = entry
            .tx
            .inputs
            .iter()
            .position(|input| input.previous_output == outpoint)
            .ok_or(MempoolError::InconsistentSpendingIndex)?;
        Ok(Some(OutpointSpender {
            entry,
            vin: u32::try_from(vin).unwrap_or(u32::MAX),
        }))
    }

    pub fn prioritise(&mut self, txid: Txid, fee_delta: i64) -> Result<(), PrioritiseError> {
        let accumulated = self
            .fee_deltas
            .get(&txid)
            .copied()
            .unwrap_or(0)
            .checked_add(fee_delta)
            .ok_or(PrioritiseError::FeeDeltaOverflow)?;
        if accumulated == 0 {
            self.fee_deltas.remove(&txid);
        } else {
            self.fee_deltas.insert(txid, accumulated);
        }
        let Some(&id) = self.by_txid.get(&txid) else {
            return Ok(());
        };
        if let Some(entry) = self.entry_mut(id) {
            entry.fee_delta = accumulated;
        }
        let affected = self.metadata_closure(&[id]);
        self.refresh_metadata(&affected);
        Ok(())
    }

    #[must_use]
    pub fn prioritised_transactions(&self) -> Vec<PrioritisedTransaction> {
        self.fee_deltas
            .iter()
            .map(|(&txid, &fee_delta)| PrioritisedTransaction {
                txid,
                fee_delta,
                in_mempool: self.by_txid.contains_key(&txid),
                modified_fee: self
                    .by_txid
                    .get(&txid)
                    .and_then(|&id| self.entry(id).map(MempoolEntry::modified_fee)),
            })
            .collect()
    }

    pub(crate) fn remove_entry_and_descendants_into(
        &mut self,
        id: EntryId,
        reason: RemovalReason,
        changes: &mut Vec<MutationChange>,
    ) {
        let mut ids = Vec::new();
        self.collect_descendants_inclusive(id, &mut ids);
        ids.sort_unstable();
        ids.dedup();
        let removals = ids.into_iter().map(|id| (id, reason)).collect::<Vec<_>>();
        self.remove_entries_with_reasons(&removals, changes);
    }

    fn remove_by_txid_into(
        &mut self,
        txid: &Txid,
        reason: RemovalReason,
        changes: &mut Vec<MutationChange>,
    ) {
        let Some(id) = self.by_txid.get(txid).copied() else {
            return;
        };
        self.remove_entry_and_descendants_into(id, reason, changes);
    }

    pub fn remove_for_block(
        &mut self,
        block_txs: &[&Tx],
        block_txids: &[Txid],
        height: u32,
    ) -> MutationResult {
        assert_eq!(
            block_txs.len(),
            block_txids.len(),
            "block transactions and validated txids must stay aligned"
        );
        self.estimator.block_connected(block_txids, height);
        let mut changes = Vec::new();
        for (tx, txid) in block_txs.iter().zip(block_txids) {
            if let Some(id) = self.by_txid.get(txid).copied() {
                self.remove_entries_with_reasons(
                    &[(id, RemovalReason::BlockInclusion)],
                    &mut changes,
                );
            }
            for conflict in self.conflicts_for(tx) {
                self.remove_entry_and_descendants_into(
                    conflict,
                    RemovalReason::Conflict,
                    &mut changes,
                );
            }
            self.fee_deltas.remove(txid);
        }
        self.finish_mutation(changes)
    }

    #[must_use]
    pub fn evict_below_fee_rate(&mut self, threshold_sat_per_kvb: u64) -> MutationResult {
        let mut to_evict: Vec<Txid> = Vec::new();
        for (_id, entry) in &self.entries {
            if entry.fee_rate < threshold_sat_per_kvb {
                to_evict.push(entry.txid);
            }
        }
        let mut changes = Vec::with_capacity(to_evict.len());
        for txid in to_evict {
            self.remove_by_txid_into(&txid, RemovalReason::PolicyEviction, &mut changes);
        }
        self.finish_mutation(changes)
    }

    pub(crate) fn conflicts_for(&self, tx: &Tx) -> Vec<EntryId> {
        let mut conflicts = Vec::new();
        for input in &tx.inputs {
            for (_, id) in self.spending.range(outpoint_range(input.previous_output)) {
                conflicts.push(*id);
            }
        }
        conflicts.sort_unstable();
        conflicts.dedup();
        conflicts
    }

    pub(crate) fn conflicts_with_descendants(&self, tx: &Tx) -> Vec<EntryId> {
        let mut conflicts = self.conflicts_for(tx);
        let direct = conflicts.clone();
        for id in direct {
            self.collect_descendants_exclusive(id, &mut conflicts);
        }
        conflicts.sort_unstable();
        conflicts.dedup();
        conflicts
    }

    #[must_use]
    pub fn ancestor_ids_for_entry(&self, id: EntryId) -> Vec<EntryId> {
        self.entry(id)
            .map_or_else(Vec::new, |entry| self.ancestor_ids_for_tx(&entry.tx))
    }

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

    pub(crate) fn remove_entries_with_reasons(
        &mut self,
        removals: &[(EntryId, RemovalReason)],
        changes: &mut Vec<MutationChange>,
    ) {
        let ids: Vec<EntryId> = removals.iter().map(|(id, _reason)| *id).collect();
        let affected = self.metadata_closure(&ids);
        for (id, reason) in removals {
            let Some(index) = usize::try_from(*id).ok() else {
                continue;
            };
            if !self.entries.contains(index) {
                continue;
            }
            let entry = self.entries.remove(index);
            self.total_vsize = self.total_vsize.saturating_sub(u64::from(entry.vsize));
            self.total_fee -= u128::from(entry.fee);
            let removed_floor = match self.fee_rate_counts.entry(entry.fee_rate) {
                std::collections::btree_map::Entry::Occupied(mut occupied) => {
                    let count = occupied.get_mut();
                    if *count > 1 {
                        *count -= 1;
                        false
                    } else {
                        let removed_floor = self.fee_rate_floor == Some(entry.fee_rate);
                        occupied.remove();
                        removed_floor
                    }
                }
                std::collections::btree_map::Entry::Vacant(_) => {
                    debug_assert!(false, "fee-rate multiset drifted");
                    false
                }
            };
            if removed_floor {
                self.fee_rate_floor = self
                    .fee_rate_counts
                    .first_key_value()
                    .map(|(&rate, _count)| rate);
            }
            self.by_txid.remove(&entry.txid);
            self.push_change(changes, entry.txid, MutationOutcome::Removed(*reason));
            self.estimator.tx_left(&entry.txid);
            self.pareto.remove(*id);
            for output in &entry.tx.outputs {
                let _ = self
                    .funding
                    .remove(&(ScriptHash::from_script(&output.script_pubkey), *id));
            }
            for input in &entry.tx.inputs {
                let _ = self
                    .spending
                    .remove(&(SpendingKey::from(input.previous_output), *id));
            }
        }
        self.refresh_metadata(&affected);
    }

    fn index_entry(&mut self, id: EntryId) {
        let Some(entry) = self.entry(id) else {
            return;
        };
        let funding_keys = entry
            .tx
            .outputs
            .iter()
            .map(|output| (ScriptHash::from_script(&output.script_pubkey), id))
            .collect::<Vec<_>>();
        let spending_keys = entry
            .tx
            .inputs
            .iter()
            .map(|input| (SpendingKey::from(input.previous_output), id))
            .collect::<Vec<_>>();
        for key in funding_keys {
            self.funding.insert(key);
        }
        for key in spending_keys {
            self.spending.insert(key);
        }
    }

    fn recompute_entry_totals(&mut self, id: EntryId) {
        let Some(entry) = self.entry(id) else {
            return;
        };
        let own_size = u64::from(entry.vsize);
        let own_fee = entry.fee;
        let own_delta = i128::from(entry.fee_delta);
        let (ancestor_size, ancestor_fee, ancestor_fee_delta) = self
            .ancestor_ids_for_entry(id)
            .into_iter()
            .filter_map(|ancestor| self.entry(ancestor))
            .fold((own_size, own_fee, own_delta), |(size, fee, delta), ancestor| {
                (
                    size.saturating_add(u64::from(ancestor.vsize)),
                    fee.saturating_add(ancestor.fee),
                    delta.saturating_add(i128::from(ancestor.fee_delta)),
                )
            });
        let (descendant_size, descendant_fee, descendant_fee_delta) = self
            .descendant_ids_for_entry(id)
            .into_iter()
            .filter_map(|descendant| self.entry(descendant))
            .fold((own_size, own_fee, own_delta), |(size, fee, delta), descendant| {
                (
                    size.saturating_add(u64::from(descendant.vsize)),
                    fee.saturating_add(descendant.fee),
                    delta.saturating_add(i128::from(descendant.fee_delta)),
                )
            });
        if let Some(entry) = self.entry_mut(id) {
            entry.ancestor_size = ancestor_size;
            entry.ancestor_fee = ancestor_fee;
            entry.ancestor_fee_delta = ancestor_fee_delta;
            entry.descendant_size = descendant_size;
            entry.descendant_fee = descendant_fee;
            entry.descendant_fee_delta = descendant_fee_delta;
        }
    }

    fn metadata_closure(&self, seeds: &[EntryId]) -> Vec<EntryId> {
        let mut affected = Vec::new();
        for seed in seeds {
            for id in self
                .ancestor_ids_for_entry(*seed)
                .into_iter()
                .chain(core::iter::once(*seed))
                .chain(self.descendant_ids_for_entry(*seed))
            {
                if !affected.contains(&id) {
                    affected.push(id);
                }
            }
        }
        affected
    }

    fn refresh_metadata(&mut self, affected: &[EntryId]) {
        for id in affected {
            self.recompute_entry_totals(*id);
        }
        for id in affected {
            match self.entry(*id).cloned() {
                Some(entry) => self.pareto.insert(*id, &entry),
                None => {
                    let _ = self.pareto.remove(*id);
                }
            }
        }
    }

    #[cfg(test)]
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
            let mut ancestor_fee_delta = self
                .entry(*id)
                .map_or(0, |entry| i128::from(entry.fee_delta));
            for ancestor in ancestors {
                if let Some(entry) = self.entry(ancestor) {
                    ancestor_size = ancestor_size.saturating_add(u64::from(entry.vsize));
                    ancestor_fee = ancestor_fee.saturating_add(entry.fee);
                    ancestor_fee_delta =
                        ancestor_fee_delta.saturating_add(i128::from(entry.fee_delta));
                }
            }
            if let Some(entry) = self.entry_mut(*id) {
                entry.ancestor_size = ancestor_size;
                entry.ancestor_fee = ancestor_fee;
                entry.ancestor_fee_delta = ancestor_fee_delta;
                entry.descendant_size = u64::from(entry.vsize);
                entry.descendant_fee = entry.fee;
                entry.descendant_fee_delta = i128::from(entry.fee_delta);
            }
        }
        for id in &ids {
            let Some(entry) = self.entry(*id) else {
                continue;
            };
            let size = u64::from(entry.vsize);
            let fee = entry.fee;
            let fee_delta = i128::from(entry.fee_delta);
            for ancestor in self.ancestor_ids_for_entry(*id) {
                if let Some(ancestor_entry) = self.entry_mut(ancestor) {
                    ancestor_entry.descendant_size =
                        ancestor_entry.descendant_size.saturating_add(size);
                    ancestor_entry.descendant_fee =
                        ancestor_entry.descendant_fee.saturating_add(fee);
                    ancestor_entry.descendant_fee_delta = ancestor_entry
                        .descendant_fee_delta
                        .saturating_add(fee_delta);
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

    fn check_ancestor_count_and_size(
        &self,
        ancestors: &[EntryId],
        candidate_vsize: u32,
    ) -> Result<(), PolicyError> {
        let ancestor_count = u32::try_from(ancestors.len())
            .unwrap_or(u32::MAX)
            .saturating_add(1);
        if ancestor_count > self.limits.max_ancestors {
            return Err(PolicyError::TooManyAncestors);
        }
        let ancestor_size = ancestors.iter().fold(u64::from(candidate_vsize), |total, id| {
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

    fn check_ancestor_limits(
        &self,
        ancestors: &[EntryId],
        entry: &MempoolEntry,
    ) -> Result<(), PolicyError> {
        self.check_ancestor_count_and_size(ancestors, entry.vsize)
    }

    fn check_descendant_limits_excluding(
        &self,
        ancestors: &[EntryId],
        excluded: &HashSet<EntryId>,
    ) -> Result<(), PolicyError> {
        for ancestor in ancestors {
            if excluded.contains(ancestor) {
                continue;
            }
            let mut descendants = Vec::new();
            self.collect_descendants_inclusive(*ancestor, &mut descendants);
            let remaining = descendants
                .iter()
                .filter(|id| !excluded.contains(*id))
                .count();
            let descendant_count = u32::try_from(remaining)
                .unwrap_or(u32::MAX)
                .saturating_add(1);
            if descendant_count > self.limits.max_descendants {
                return Err(PolicyError::TooManyDescendants);
            }
        }
        Ok(())
    }

    fn cluster_ids_seeded_by(
        &self,
        seeds: &[EntryId],
        excluded: &HashSet<EntryId>,
    ) -> Vec<EntryId> {
        let mut seen: Vec<EntryId> = Vec::new();
        let mut frontier: Vec<EntryId> = Vec::new();
        for seed in seeds {
            if !excluded.contains(seed) && !seen.contains(seed) {
                seen.push(*seed);
                frontier.push(*seed);
            }
        }
        while let Some(id) = frontier.pop() {
            let parents = self.entry(id).map_or_else(Vec::new, |entry| {
                entry
                    .tx
                    .inputs
                    .iter()
                    .filter_map(|input| self.by_txid.get(&input.previous_output.txid).copied())
                    .collect::<Vec<_>>()
            });
            for neighbour in parents.into_iter().chain(self.child_ids(id)) {
                if !excluded.contains(&neighbour) && !seen.contains(&neighbour) {
                    seen.push(neighbour);
                    frontier.push(neighbour);
                }
            }
        }
        seen.sort_unstable();
        seen
    }

    fn check_cluster_limits(
        &self,
        tx: &Tx,
        vsize: u32,
        excluded: &HashSet<EntryId>,
    ) -> Result<(), PolicyError> {
        let txid = tx.txid();
        let mut seeds = tx
            .inputs
            .iter()
            .filter_map(|input| self.by_txid.get(&input.previous_output.txid).copied())
            .collect::<Vec<_>>();
        seeds.extend(self.existing_spenders_of(txid, tx.outputs.len()));
        let cluster = self.cluster_ids_seeded_by(&seeds, excluded);
        if cluster.is_empty() {
            return cluster_within_limits(1, u64::from(vsize), &self.limits);
        }
        let count = u32::try_from(cluster.len())
            .unwrap_or(u32::MAX)
            .saturating_add(1);
        let cluster_vsize = cluster.iter().fold(u64::from(vsize), |total, id| {
            total.saturating_add(self.entry(*id).map_or(0, |member| u64::from(member.vsize)))
        });
        cluster_within_limits(count, cluster_vsize, &self.limits)
    }

    fn existing_spenders_of(&self, txid: Txid, output_count: usize) -> Vec<EntryId> {
        let mut spenders = Vec::new();
        for vout in 0..output_count {
            let Ok(vout) = u32::try_from(vout) else {
                continue;
            };
            for (_, spender) in self
                .spending
                .range(outpoint_range(OutPoint::new(txid, vout)))
            {
                if !spenders.contains(spender) {
                    spenders.push(*spender);
                }
            }
        }
        spenders
    }

    #[must_use]
    pub const fn cluster_limits(&self) -> (u32, u64) {
        (self.limits.cluster_count, self.limits.cluster_size_vbytes)
    }

    fn ancestor_ids_for_tx(&self, tx: &Tx) -> Vec<EntryId> {
        let mut ancestors = Vec::new();
        let mut stack = tx
            .inputs
            .iter()
            .filter_map(|input| self.by_txid.get(&input.previous_output.txid).copied())
            .collect::<Vec<_>>();
        while let Some(id) = stack.pop() {
            if ancestors.contains(&id) {
                continue;
            }
            ancestors.push(id);
            if let Some(entry) = self.entry(id) {
                for input in &entry.tx.inputs {
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
        let txid = entry.txid;
        let mut children = Vec::new();
        for (vout, _) in entry.tx.outputs.iter().enumerate() {
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

    #[must_use]
    pub fn spender_txids(&self, id: EntryId) -> Vec<Txid> {
        let Some(entry) = self.entry(id) else {
            return Vec::new();
        };
        let start = (
            SpendingKey::from(OutPoint::new(entry.txid, u32::MIN)),
            EntryId::MIN,
        );
        let end = (
            SpendingKey::from(OutPoint::new(entry.txid, u32::MAX)),
            EntryId::MAX,
        );
        let mut spenders: Vec<EntryId> = self
            .spending
            .range(start..=end)
            .map(|(_, child)| *child)
            .collect();
        spenders.sort_unstable();
        spenders.dedup();
        spenders
            .into_iter()
            .filter_map(|child| self.entry(child).map(|entry| entry.txid))
            .collect()
    }

    #[must_use]
    pub fn descendant_count_inclusive(&self, id: EntryId) -> u32 {
        let mut descendants = Vec::new();
        self.collect_descendants_inclusive(id, &mut descendants);
        u32::try_from(descendants.len()).unwrap_or(u32::MAX)
    }

    #[must_use]
    pub fn ancestor_count_inclusive(&self, id: EntryId) -> u32 {
        let ancestors = self.ancestor_ids_for_entry(id);
        u32::try_from(ancestors.len())
            .unwrap_or(u32::MAX)
            .saturating_add(1)
    }

    pub fn check_package_limits(
        &self,
        tx: &Tx,
        vsize: u32,
        excluded: &HashSet<EntryId>,
    ) -> Result<(), PolicyError> {
        let ancestors = self.ancestor_ids_for_tx(tx);
        self.check_ancestor_count_and_size(&ancestors, vsize)?;
        self.check_descendant_limits_excluding(&ancestors, excluded)?;
        self.check_cluster_limits(tx, vsize, excluded)?;
        Ok(())
    }

    fn entry_mut(&mut self, id: EntryId) -> Option<&mut MempoolEntry> {
        usize::try_from(id)
            .ok()
            .and_then(|index| self.entries.get_mut(index))
    }

    fn entry_signals_rbf(&self, id: EntryId) -> bool {
        self.entry(id).is_some_and(|entry| {
            entry
                .tx
                .inputs
                .iter()
                .any(|input| input.sequence < 0xFFFF_FFFE)
        })
    }
}

pub(crate) fn tx_fee_rate(fee: u64, vsize: u32) -> u64 {
    fee_rate(fee, u64::from(vsize))
}

#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SpendingKey([u8; 36]);

impl From<OutPoint> for SpendingKey {
    fn from(outpoint: OutPoint) -> Self {
        let mut key = [0_u8; 36];
        key[..32].copy_from_slice(outpoint.txid.as_bytes());
        key[32..].copy_from_slice(&outpoint.vout.to_le_bytes());
        Self(key)
    }
}

const fn cluster_within_limits(
    count: u32,
    vsize: u64,
    limits: &MempoolLimits,
) -> Result<(), PolicyError> {
    if count > limits.cluster_count {
        return Err(PolicyError::ClusterCountLimit);
    }
    if vsize > limits.cluster_size_vbytes {
        return Err(PolicyError::ClusterSizeLimit);
    }
    Ok(())
}

fn transaction_heap_usage(tx: &Tx) -> u64 {
    use core::mem::size_of;
    let mut total = u64::try_from(size_of::<Tx>()).unwrap_or(0);
    total = total.saturating_add(
        u64::try_from(tx.inputs.capacity().saturating_mul(size_of::<TxIn>())).unwrap_or(u64::MAX),
    );
    total = total.saturating_add(
        u64::try_from(tx.outputs.capacity().saturating_mul(size_of::<TxOut>())).unwrap_or(u64::MAX),
    );
    for input in &tx.inputs {
        total = total.saturating_add(u64::try_from(input.script_sig.len()).unwrap_or(u64::MAX));
        total = total.saturating_add(
            u64::try_from(input.witness.iter().map(std::vec::Vec::len).sum::<usize>())
                .unwrap_or(u64::MAX),
        );
    }
    for output in &tx.outputs {
        total = total.saturating_add(u64::try_from(output.script_pubkey.len()).unwrap_or(u64::MAX));
    }
    total
}

fn outpoint_range(outpoint: OutPoint) -> RangeInclusive<(SpendingKey, EntryId)> {
    let key = SpendingKey::from(outpoint);
    (key, EntryId::MIN)..=(key, EntryId::MAX)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use bitcoin_rs_primitives::{Hash256, OutPoint, Tx, TxIn, TxOut};
    use super::*;

    fn txid_of(bytes: [u8; 32]) -> Txid {
        Txid::from(Hash256::from_le_bytes(&bytes))
    }

    fn hash_of(txid: &Txid) -> Hash256 {
        Hash256::from_le_bytes(txid.as_bytes())
    }

    fn change_txids(result: &crate::mutation::MutationResult) -> Vec<Hash256> {
        result.changes.iter().map(|change| change.txid).collect()
    }

    #[test]
    fn sequence_number_bumps_on_successful_insert() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits::default());
        let before = pool.sequence_number();
        let tx = Tx {
            version: 2,
            lock_time: 0,
            inputs: Vec::new(),
            outputs: Vec::new(),
        };
        let entry = MempoolEntry::new(Arc::new(tx), 100, 1_000, 1, 7);
        pool.insert_entry(entry)?;
        let after = pool.sequence_number();
        assert!(after > before, "expected sequence to bump");
        Ok(())
    }

    #[test]
    fn finish_mutation_preserves_sequences_across_counter_wrap() {
        let mut pool = Mempool::new(MempoolLimits::default());
        pool.mempool_sequence = u64::MAX - 1;
        let mut changes = Vec::new();
        pool.push_change(
            &mut changes,
            txid_of([1; 32]),
            MutationOutcome::Accepted,
        );
        pool.push_change(
            &mut changes,
            txid_of([2; 32]),
            MutationOutcome::Accepted,
        );

        let result = pool.finish_mutation(changes);

        assert_eq!(pool.sequence_number(), 0);
        assert_eq!(result.sequence_base, u64::MAX);
        assert_eq!(result.sequence_of(0), Some(u64::MAX));
        assert_eq!(result.sequence_of(1), Some(0));
    }

    fn tx(label: u8, previous_outputs: Vec<OutPoint>) -> Tx {
        Tx {
            version: 2,
            lock_time: 0,
            inputs: previous_outputs
                .into_iter()
                .map(|previous_output| TxIn {
                    previous_output,
                    script_sig: Vec::new(),
                    sequence: 0xFF_FF_FF_FF,
                    witness: Vec::new(),
                })
                .collect(),
            outputs: vec![TxOut {
                value: 5_000 + u64::from(label),
                script_pubkey: vec![label],
            }],
        }
    }
}
