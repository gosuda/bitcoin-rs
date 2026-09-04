use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::RangeInclusive;

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

/// In-memory transaction pool with txid, funding, spending, and fee-priority indexes.
#[derive(Debug)]
pub struct Mempool {
    /// Entry arena. Public ids are slab indices represented as `u32`.
    pub entries: Slab<MempoolEntry>,
    /// Tx id to entry id lookup. Owned by this module; reach it
    /// through `contains_txid`, `entry_id_by_txid`, and `entry_by_txid`.
    by_txid: HashMap<Txid, EntryId>,
    /// Funding index keyed by script hash then entry id.
    pub funding: std::collections::BTreeSet<(ScriptHash, EntryId)>,
    /// Spending index keyed by spent outpoint then entry id. Owned by this
    /// module; reach it through `is_outpoint_spent` and `outpoint_spender`.
    spending: std::collections::BTreeSet<(SpendingKey, EntryId)>,
    /// Fee-priority index for mining and eviction consumers.
    pub pareto: ParetoFront,
    /// Active mempool policy limits.
    pub limits: MempoolLimits,
    /// Running sum of `vsize` over `entries`.
    ///
    /// Maintained by the mutation methods below rather than folded on demand.
    /// `insert_entry` consults it on every accepted transaction to decide
    /// whether the pool is over its size limit, so folding it there cost `O(n)`
    /// per acceptance and made insertion quadratic in pool size on its own.
    ///
    /// `entries` is a public field, so code outside this module *could*
    /// desynchronize this by mutating the slab directly. Nothing does — every
    /// mutation goes through `insert_entry`, `remove_entries`, `prioritise` or
    /// `clear` — and `debug_assert`s in `total_vsize` and `aggregate_fees` fail
    /// loudly in test and debug builds if that ever stops being true.
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
        let sequence_base = changes
            .first()
            .map_or(0, |_| self.mempool_sequence - batch_len + 1);
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

    /// Returns `true` when `txid` is present in the mempool.
    ///
    /// Constant-time wrapper over `by_txid.contains_key`. Cheaper than `entry()`
    /// for callers that only need a presence check.
    #[must_use]
    pub fn contains_txid(&self, txid: &Txid) -> bool {
        self.by_txid.contains_key(txid)
    }

    /// Returns a reference to the `MempoolEntry` for `txid`, or `None` if the
    /// transaction is not in the pool.
    ///
    /// Composite of `self.by_txid.get(txid)` and `self.entry(*id)`. Saves the
    /// 2-step lookup pattern at HTTP/RPC handler callsites.
    #[must_use]
    pub fn entry_by_txid(&self, txid: &Txid) -> Option<&MempoolEntry> {
        let id = *self.by_txid.get(txid)?;
        self.entry(id)
    }

    /// Returns a clone of the shared `Arc<Tx>` for `txid`, or `None`
    /// if the transaction is not in the pool.
    ///
    /// Cheaper than [`entry_by_txid`] when only the transaction body is needed
    /// — no `MempoolEntry` indirection, just an `Arc::clone`.
    #[must_use]
    pub fn transaction_by_txid(&self, txid: &Txid) -> Option<Arc<Tx>> {
        self.entry_by_txid(txid).map(|entry| Arc::clone(&entry.tx))
    }

    /// Returns the public entry id for `txid`, or `None` when the transaction
    /// is not in the pool.
    ///
    /// The id is a slab index, so it is valid only while the pool is not
    /// mutated: a removal can recycle the slot behind it. Re-resolve through
    /// this lookup after dropping and re-acquiring a pool lock.
    #[must_use]
    pub fn entry_id_by_txid(&self, txid: &Txid) -> Option<EntryId> {
        self.by_txid.get(txid).copied()
    }

    /// Returns whether the pool currently holds zero entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the count of in-pool transactions.
    #[must_use]
    pub fn tx_count(&self) -> usize {
        self.entries.len()
    }

    /// Returns the txids of every entry in the pool.
    ///
    /// Order is the underlying slab iteration order (i.e., NOT fee-rate sorted;
    /// use `iter_by_fee_rate_desc` for that).
    #[must_use]
    pub fn iter_txids(&self) -> Vec<Txid> {
        self.entries.iter().map(|(_id, entry)| entry.txid).collect()
    }

    /// Returns txids of mempool entries signalling BIP-125 RBF eligibility.
    ///
    /// An entry is replaceable when ANY of its inputs has `sequence < 0xFFFFFFFE`
    /// (the BIP-125 opt-in convention). Used by fee-bumping and replacement-eligibility
    /// queries.
    #[must_use]
    pub fn iter_replaceable_txids(&self) -> Vec<Txid> {
        self.entries
            .iter()
            .filter(|(_id, entry)| entry.is_replaceable())
            .map(|(_id, entry)| entry.txid)
            .collect()
    }

    /// Returns the relay-policy snapshot this pool enforces, for the RPC
    /// `getmempoolinfo` projection and the transaction-admission surface.
    ///
    /// Standardness reads [`crate::standardness::StandardnessPolicy::default`]:
    /// the pool holds no separate standardness knob, so the enforced default
    /// is the single source of those values.
    #[must_use]
    pub fn policy_snapshot(&self) -> MempoolPolicySnapshot {
        MempoolPolicySnapshot::from_enforced(
            self.limits,
            crate::standardness::StandardnessPolicy::default(),
        )
    }

    /// Returns the total virtual size of all entries.
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

    /// Evicts the lowest-fee packages until the pool's total vsize is at or
    /// below `max_bytes`. Each evicted entry — and each descendant swept with
    /// its package — commits as one `Removed(PolicyEviction)` change, in
    /// eviction commit order.
    ///
    /// Delegates to the free-function `evict_lowest_fee_packages`, which
    /// removes through `remove_entry_and_descendants_into`.
    pub fn enforce_size_limit(&mut self, max_bytes: u64) -> MutationResult {
        let changes = crate::evict_lowest_fee_packages(self, max_bytes);
        self.finish_mutation(changes)
    }

    /// Returns the sum of fees of all entries in the pool, in satoshis.
    ///
    /// Used by `getmempoolinfo.total_fee` (BTC = sats / 1e8). The exact internal
    /// sum preserves saturating `u64` semantics after removals and fee decreases.
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

    /// Returns aggregate counters for the current pool.
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

    /// Estimates the heap this pool occupies, in bytes.
    ///
    /// This is `getmempoolinfo`'s `usage`, and it is a different quantity from
    /// `bytes`: `bytes` is the sum of virtual sizes, a consensus-facing measure
    /// of the transactions, while this is how much memory holding them costs.
    /// The two differ by a large constant factor — per-entry accounting, four
    /// indexes, and the allocations inside each transaction.
    ///
    /// An estimate, as it is in Bitcoin Core, whose own `DynamicMemoryUsage`
    /// carries the comment "Estimate the overhead of mapTx to be 9 pointers …
    /// as no exact formula for `boost::multi_index_container` is implemented".
    /// The figure is Core's *shape*, not Core's number: it counts this node's
    /// structures, which are not Core's.
    ///
    /// Counted here: the entry arena and the txid map at their **allocated
    /// capacity**, each live transaction's own heap, and the indexes keyed off
    /// those entries -- with the priority index answering for itself, because
    /// it stores every entry twice.
    ///
    /// Capacity rather than length for the two that retain it. Neither the slab
    /// nor the hash map hands its allocation back on removal or on `clear`, so
    /// a pool that peaked and then drained is still holding the memory, and a
    /// figure read off `len()` answers "nothing" at exactly the moment someone
    /// is asking where it went.
    #[must_use]
    pub fn dynamic_memory_usage(&self) -> u64 {
        use core::mem::size_of;

        // The arena is charged at **capacity**, not at length. `slab::Slab`
        // keeps its backing allocation across removals and across `clear`, so a
        // pool that grew to a million entries and then emptied still holds the
        // arena -- and charging `len()` reported that retained memory as zero,
        // which is exactly the moment an operator looks at `usage` to find out
        // where it went. Core charges its own pool the same way: `mapTx`'s
        // allocator does not return nodes to the OS either.
        //
        // Everything below stays keyed to live entries. They are payload terms
        // -- the transactions and the index keys -- and a removed entry's
        // payload really is gone.
        let arena = u64::try_from(self.entries.capacity())
            .unwrap_or(u64::MAX)
            .saturating_mul(u64::try_from(size_of::<MempoolEntry>()).unwrap_or(0));

        let transactions = self
            .entries
            .iter()
            .map(|(_index, entry)| transaction_heap_usage(&entry.tx))
            .fold(0_u64, u64::saturating_add);

        // `by_txid` is a hash map, so it carries slack; the other three are
        // B-tree sets of fixed-size keys.
        let by_txid = u64::try_from(self.by_txid.capacity())
            .unwrap_or(u64::MAX)
            .saturating_mul(u64::try_from(size_of::<(Txid, EntryId)>()).unwrap_or(0));
        let funding = u64::try_from(self.funding.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(u64::try_from(size_of::<(ScriptHash, EntryId)>()).unwrap_or(0));
        let spending = u64::try_from(self.spending.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(u64::try_from(size_of::<(SpendingKey, EntryId)>()).unwrap_or(0));
        // The priority index stores every entry twice -- once ordered by
        // priority, once keyed by id so a removal need not search for what to
        // remove -- so it answers for itself rather than being charged one
        // `EntryId` per transaction here.
        let pareto = self.pareto.dynamic_memory_usage();

        arena
            .saturating_add(transactions)
            .saturating_add(by_txid)
            .saturating_add(funding)
            .saturating_add(spending)
            .saturating_add(pareto)
    }

    /// Estimates the fee rate that historically confirmed within
    /// `conf_target_blocks`, from the admission and confirmation history this
    /// pool feeds itself. Returns `None` when the history is too thin to
    /// answer — an honest refusal rather than a fabricated rate.
    #[must_use]
    pub fn estimate_fee_rate(&self, conf_target_blocks: u32) -> Option<FeeRate> {
        self.estimator.estimate(conf_target_blocks)
    }

    /// Returns the estimator's last decayed height, or `None` before the first
    /// connected block. A connected block ages the estimator even when the
    /// pool is empty, so this is the observable proof that `remove_for_block`
    /// fired `block_connected`.
    #[must_use]
    pub fn estimator_last_decayed_height(&self) -> Option<u32> {
        self.estimator.last_decayed_height()
    }

    /// Copies the pool's mining state into one immutable snapshot.
    ///
    /// Everything block-template selection needs is read in this single
    /// coherent pass — shared transaction payloads, per-entry fee, sigop,
    /// weight, and size metadata, the signed overlay, ancestor-package
    /// aggregates, ancestor topology, and the current sequence number — so
    /// the caller's read critical section ends when this returns and
    /// selection works on the owned copy with the lock released. Entries
    /// appear in modified-priority order (the order [`ParetoFront`] ranks
    /// them), and `ancestors` positions refer to this vector, so a consumer
    /// can walk packages without re-consulting the pool.
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

    /// Returns an entry by public id.
    #[must_use]
    pub fn entry(&self, id: EntryId) -> Option<&MempoolEntry> {
        usize::try_from(id)
            .ok()
            .and_then(|index| self.entries.get(index))
    }

    /// Returns mempool entry ids in order of descending `fee_rate` (sat/kvB).
    ///
    /// Walks `entries` and sorts; cost O(N log N) per call. Used by mining
    /// template builders and fee estimators that want actual-fee-ordered
    /// traversal without going through `ParetoFront` (which ranks on signed
    /// modified fees with ancestor-aware package scoring).
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

    /// Returns the minimum `fee_rate` (sat/kvB) among all entries, or `None`
    /// for an empty pool.
    ///
    /// Reads the cached first key of the maintained fee-rate multiset so
    /// admission tightening does not scan `entries` or descend the tree.
    /// The min is over `MempoolEntry.fee_rate`, which is pre-computed at insert
    /// time.
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

    /// Returns mempool entry ids whose `fee_rate` >= `threshold_sat_per_kvb`.
    ///
    /// Linear scan over `entries`. Used by mining template builders and eviction
    /// strategies that want a fee-rate cohort without sorting.
    #[must_use]
    pub fn iter_above_fee_rate(&self, threshold_sat_per_kvb: u64) -> Vec<EntryId> {
        self.entries
            .iter()
            .filter(|(_index, entry)| entry.fee_rate >= threshold_sat_per_kvb)
            .filter_map(|(index, _entry)| EntryId::try_from(index).ok())
            .collect()
    }

    /// Returns whether any in-pool transaction spends `outpoint`.
    ///
    /// A range probe over the spending index: the presence of any
    /// `(outpoint, entry)` row is the answer, and the entries themselves are
    /// never touched.
    #[must_use]
    pub fn is_outpoint_spent(&self, outpoint: &OutPoint) -> bool {
        self.spending
            .range(outpoint_range(*outpoint))
            .next()
            .is_some()
    }

    /// Returns the in-pool spender of `outpoint`: the spending entry and the
    /// exact input (`vin`) of its transaction that spends it, or `None` when
    /// nothing in the pool spends it.
    ///
    /// Resolved through the spending index, so callers never see index
    /// tuples. If an inconsistent pool indexed more than one spender for one
    /// outpoint, the first in `EntryId` order wins — the entry a first-match
    /// scan over `entries` would have settled on. A spending index row that
    /// names a missing entry, or an entry whose transaction does not spend
    /// `outpoint`, is [`MempoolError::InconsistentSpendingIndex`].
    ///
    /// The returned entry borrows the pool and is valid only while the pool
    /// is not mutated.
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

    /// Adds `fee_delta` satoshis to `txid`'s signed mining-only fee overlay.
    ///
    /// The overlay is additive and persistent, matching Bitcoin Core's
    /// `PrioritiseTransaction`: deltas accumulate across calls, may be stored
    /// before the transaction is ever admitted, apply on admission, survive
    /// ordinary removal and replacement, and are erased only when the
    /// transaction is mined (see [`Mempool::remove_for_block`]). The overlay
    /// changes modified package ordering only — the entry's actual fee, fee
    /// rate, and every aggregate over actual fees stay exactly as they were,
    /// so admission policy, RBF accounting, and fee reporting never observe
    /// it.
    ///
    /// Returns [`PrioritiseError::FeeDeltaOverflow`] and leaves the overlay
    /// untouched when the accumulated total would leave the signed satoshi
    /// range; the alternative — saturating — would silently break
    /// additivity, which is this operation's whole contract.
    ///
    /// The mempool sequence does not move: prioritisation emits no mutation
    /// change (only pool membership does), so template consumers are woken
    /// explicitly by the caller instead of through the sequence.
    pub fn prioritise(&mut self, txid: Txid, fee_delta: i64) -> Result<(), PrioritiseError> {
        let accumulated = self
            .fee_deltas
            .get(&txid)
            .copied()
            .unwrap_or(0)
            .checked_add(fee_delta)
            .ok_or(PrioritiseError::FeeDeltaOverflow)?;
        self.fee_deltas.insert(txid, accumulated);

        let Some(&id) = self.by_txid.get(&txid) else {
            return Ok(());
        };
        if let Some(entry) = self.entry_mut(id) {
            entry.fee_delta = accumulated;
        }

        // The entry's overlay is the only thing that moved, so the modified
        // package aggregates of its relatives follow from the graph — the
        // same refresh an insertion does, which also reindexes every
        // descendant whose modified ancestor fee rate the delta lifted.
        // Without that reindex a descendant kept the priority key it had
        // before its ancestor was bumped, and `prioritisetransaction` —
        // which exists to move transactions in the miner's template — was
        // defeated for exactly the packages it was aimed at.
        let affected = self.metadata_closure(&[id]);
        self.refresh_metadata(&affected);
        Ok(())
    }

    /// Removes an entry and all descendants that spend its outputs. The
    /// parent commits before its descendants; each removed entry emits one
    /// `Removed(Explicit)` change.
    pub fn remove_entry_and_descendants(&mut self, id: EntryId) -> MutationResult {
        let mut changes = Vec::new();
        self.remove_entry_and_descendants_into(id, RemovalReason::Explicit, &mut changes);
        self.finish_mutation(changes)
    }

    /// Reason-carrying core of [`Mempool::remove_entry_and_descendants`] for
    /// composite mutations that must tag the removal with their own reason.
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

    /// Removes the entry for `txid` along with all descendants that spend
    /// its outputs, each as one `Removed(Explicit)` change in parent-before-
    /// descendants order.
    ///
    /// Returns an empty result when the txid is not present in the pool.
    pub fn remove_by_txid(&mut self, txid: &Txid) -> MutationResult {
        let mut changes = Vec::new();
        self.remove_by_txid_into(txid, RemovalReason::Explicit, &mut changes);
        self.finish_mutation(changes)
    }

    /// Reason-carrying core of [`Mempool::remove_by_txid`].
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

    /// Removes the transactions a connected block confirmed, clears their
    /// prioritisation overlays, and records the confirmations in the fee
    /// history. Every removed entry commits as one `Removed(BlockInclusion)`
    /// change, in commit order: block-transaction order, each removal
    /// committing parent before descendants.
    ///
    /// For each block transaction, this mirrors Bitcoin Core's
    /// `removeForBlock`: the entry and its descendants leave the pool, other
    /// entries spending the same inputs — double spends the block just
    /// settled — leave with their descendants, and the overlay stored for the
    /// txid is erased whether or not the transaction was ever admitted (a
    /// pre-admission delta for a directly mined transaction must not survive
    /// into a later re-admission). Entries removed only because a parent or
    /// conflict was mined were not confirmed themselves: they keep their
    /// overlay and are recorded as departures, not confirmations.
    ///
    /// `block_txids` contains the validated txid for each transaction in
    /// `block_txs`, in the same order. `height` is the connected block's
    /// height; the fee history ages one height per call even when the block
    /// confirms nothing the pool tracked.
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
        // Confirmations are recorded before the removals take the entries
        // out: the removal path reports departures, and a confirmed txid must
        // not be demoted to a departure before the estimator sees it.
        self.estimator.block_connected(block_txids, height);

        let mut changes = Vec::new();
        for (tx, txid) in block_txs.iter().zip(block_txids) {
            self.remove_by_txid_into(txid, RemovalReason::BlockInclusion, &mut changes);
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

    /// Removes every entry whose `fee_rate` (sat/kvB) is strictly below
    /// `threshold_sat_per_kvb`. Every evicted entry — and each descendant
    /// swept with it — commits as one `Removed(PolicyEviction)` change.
    ///
    /// Use this for min-relay-fee tightening or size-bound eviction policies.
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

    pub(crate) fn remove_entries_with_reasons(
        &mut self,
        removals: &[(EntryId, RemovalReason)],
        changes: &mut Vec<MutationChange>,
    ) {
        // Collected first: once an entry is out of the slab its ancestors can no
        // longer be walked, and they are exactly the entries whose descendant
        // totals this removal invalidates. Surviving descendants are in the
        // closure too — `remove_entries` is reached from eviction paths that
        // remove arbitrary sets, not only from the one that takes descendants
        // along with their parent.
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
                    debug_assert!(
                        false,
                        "fee-rate multiset drifted: removed a rate with no tracked count"
                    );
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
            // A departure that is not a confirmation: eviction, replacement,
            // conflict, and reorg removal all free the estimator's pending
            // slot without saying anything about fee-rate success.
            self.estimator.tx_left(&entry.txid);
            self.pareto.remove(*id);
            for (vout, output) in entry.tx.outputs.iter().enumerate() {
                let Ok(_) = EntryId::try_from(vout) else {
                    continue;
                };
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

    /// Recomputes one entry's six package totals directly from the spend
    /// graph.
    ///
    /// This is the invariant written out: an entry's ancestor totals are its
    /// own plus every transitive in-mempool parent, and its descendant totals
    /// are its own plus every transitive in-mempool child — once for actual
    /// fees, and once for the signed overlay that modified ordering reads.
    /// `recompute_all_metadata` arrives at the same numbers by a
    /// reset-then-accumulate pass over the whole pool; this arrives at them
    /// for one entry.
    ///
    /// Cost is bounded by the ancestor and descendant *policy* limits — 25 each
    /// by default — not by the number of entries in the pool.
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
            .fold(
                (own_size, own_fee, own_delta),
                |(size, fee, delta), ancestor| {
                    (
                        size.saturating_add(u64::from(ancestor.vsize)),
                        fee.saturating_add(ancestor.fee),
                        delta.saturating_add(i128::from(ancestor.fee_delta)),
                    )
                },
            );
        let (descendant_size, descendant_fee, descendant_fee_delta) = self
            .descendant_ids_for_entry(id)
            .into_iter()
            .filter_map(|descendant| self.entry(descendant))
            .fold(
                (own_size, own_fee, own_delta),
                |(size, fee, delta), descendant| {
                    (
                        size.saturating_add(u64::from(descendant.vsize)),
                        fee.saturating_add(descendant.fee),
                        delta.saturating_add(i128::from(descendant.fee_delta)),
                    )
                },
            );

        if let Some(entry) = self.entry_mut(id) {
            entry.ancestor_size = ancestor_size;
            entry.ancestor_fee = ancestor_fee;
            entry.ancestor_fee_delta = ancestor_fee_delta;
            entry.descendant_size = descendant_size;
            entry.descendant_fee = descendant_fee;
            entry.descendant_fee_delta = descendant_fee_delta;
        }
    }

    /// Every entry whose totals a change at `seeds` can have altered.
    ///
    /// Linking one transaction into the spend graph changes package totals for
    /// its transitive ancestors, itself, and its transitive descendants — and
    /// for nothing else. An entry `x` outside that set gains no new ancestor,
    /// because `x` is not a descendant of the seed; and gains no new descendant,
    /// because every new path runs through the seed, which would put `x` among
    /// its ancestors. That argument is what makes the incremental update exact
    /// rather than approximate, and
    /// `incremental_metadata_matches_the_full_recompute` holds it to it.
    ///
    /// Collected before the mutation on a removal, because a removed entry's
    /// ancestors cannot be walked once it is gone.
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

    /// Recomputes package totals and priority keys for `affected` only.
    ///
    /// Entries that no longer exist are skipped rather than resurrected: a
    /// removal's closure is collected before the removal, so it names entries
    /// that are deliberately gone by the time this runs.
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

    /// Rebuilds every entry's package totals and the whole priority index.
    ///
    /// Nothing in the pool calls this any more, and that is the change: it is
    /// `n` walks of the spend graph, and doing it per accepted transaction is
    /// what made `insert_entry` quadratic in mempool size. It is kept, compiled
    /// only under `cfg(test)`, as the oracle that
    /// `incremental_metadata_matches_the_full_recompute` compares the
    /// incremental path against — an oracle nothing in production can drift
    /// away from, because production no longer has a path to it.
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
        let ancestor_size = ancestors
            .iter()
            .fold(u64::from(candidate_vsize), |total, id| {
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

    /// Returns the txids of in-pool transactions whose inputs reference `id`,
    /// in `EntryId` order and deduplicated.
    ///
    /// This is Bitcoin Core's `spentby` field. The answer comes from one
    /// contiguous range of the `spending` index — `O(log n + matching inputs)`
    /// — where asking the same question by scanning is
    /// `O(inputs in the whole pool)` per entry.
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

    /// Returns the descendant-package count for `id` (inclusive of `id` itself).
    ///
    /// Saturates at `u32::MAX` for pathological packages.
    #[must_use]
    pub fn descendant_count_inclusive(&self, id: EntryId) -> u32 {
        let mut descendants = Vec::new();
        self.collect_descendants_inclusive(id, &mut descendants);
        u32::try_from(descendants.len()).unwrap_or(u32::MAX)
    }

    /// Returns the ancestor-package count for `id` (inclusive of `id` itself).
    ///
    /// Saturates at `u32::MAX` for pathological packages. Composes
    /// `ancestor_ids_for_entry` + plus-one (caller is itself an ancestor of
    /// the inclusive count).
    #[must_use]
    pub fn ancestor_count_inclusive(&self, id: EntryId) -> u32 {
        let ancestors = self.ancestor_ids_for_entry(id);
        u32::try_from(ancestors.len())
            .unwrap_or(u32::MAX)
            .saturating_add(1)
    }

    /// Checks ancestor and descendant package limits for `tx` without
    /// inserting it, mirroring the gates `validate_insert` applies.
    ///
    /// `excluded` is the set of entry ids that a replacement will evict;
    /// those entries are skipped in the descendant-count check so a
    /// replacement that trims an over-large descendant package is not
    /// falsely rejected by the package it is about to clear. Pass an empty
    /// set for a plain (non-replacement) admission preview.
    ///
    /// `vsize` is the candidate's own virtual size; it is folded into the
    /// ancestor-size total exactly as `validate_insert` does.
    ///
    /// WHY: the acceptance preview (`testmempoolaccept`) and the admission
    /// gate (`sendrawtransaction` → `replace_transaction`) must quote the
    /// same verdict; without this check the preview reports `allowed` for a
    /// transaction the admission gate then rejects on package limits.
    pub fn check_package_limits(
        &self,
        tx: &Tx,
        vsize: u32,
        excluded: &HashSet<EntryId>,
    ) -> Result<(), PolicyError> {
        let ancestors = self.ancestor_ids_for_tx(tx);
        self.check_ancestor_count_and_size(&ancestors, vsize)?;
        self.check_descendant_limits_excluding(&ancestors, excluded)?;
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

/// Spending-index key over the raw 36-byte `OutPoint` consensus encoding.
///
/// `primitives::OutPoint` is a packed layout type without `Ord`; the index
/// needs only a total order that groups one outpoint's rows contiguously, so
/// it keys on the encoded bytes — little-endian txid then little-endian vout,
/// whose fixed-width byte order matches numeric vout order.
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

/// Heap a single transaction owns, beyond the `Tx` struct itself.
///
/// The input and output vectors, and the script and witness bytes inside them.
/// Counted from the structures rather than from the serialized length, because
/// a `Vec` costs its capacity and a serialized form costs neither the vector
/// headers nor the per-field overhead.
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

    /// Native txid for a raw 32-byte fixture id.
    fn txid_of(bytes: [u8; 32]) -> Txid {
        Txid::from(Hash256::from_le_bytes(&bytes))
    }

    /// Native consensus-byte txid for change-record comparisons.
    fn hash_of(txid: &Txid) -> Hash256 {
        Hash256::from_le_bytes(txid.as_bytes())
    }

    /// The txid of every change in a mutation result, in commit order.
    fn change_txids(result: &crate::mutation::MutationResult) -> Vec<Hash256> {
        result.changes.iter().map(|change| change.txid).collect()
    }

    #[test]
    fn default_min_relay_fee_is_1_sat_per_vbyte() {
        let pool = Mempool::new(MempoolLimits::default());
        assert_eq!(pool.min_relay_fee_sat_per_kvb(), 1_000);
    }

    #[test]
    fn custom_min_relay_fee_round_trips() {
        let limits = MempoolLimits {
            min_relay_fee_sat_per_kvb: 5_000,
            ..MempoolLimits::default()
        };
        let pool = Mempool::new(limits);
        assert_eq!(pool.min_relay_fee_sat_per_kvb(), 5_000);
    }

    #[test]
    fn insert_entry_rejects_below_min_relay_fee() {
        let limits = MempoolLimits {
            min_relay_fee_sat_per_kvb: 5_000,
            ..MempoolLimits::default()
        };
        let mut pool = Mempool::new(limits);
        let tx = Tx {
            version: 2,
            lock_time: 0,
            inputs: Vec::new(),
            outputs: vec![TxOut {
                value: 1_000,
                script_pubkey: vec![0x51],
            }],
        };
        let entry = MempoolEntry::new(Arc::new(tx), 100, 100, 1, 7);
        let result = pool.insert_entry(entry);

        assert!(
            matches!(
                result,
                Err(MempoolError::Policy(PolicyError::BelowMinRelayFee {
                    tx_rate: 1_000,
                    min_rate: 5_000
                }))
            ),
            "expected BelowMinRelayFee rejection, got {result:?}"
        );
    }

    #[test]
    fn stats_reports_empty_and_inserted_entry_counters() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits::default());
        assert_eq!(pool.stats(), MempoolStats::default());

        let tx = Tx {
            version: 2,
            lock_time: 0,
            inputs: Vec::new(),
            outputs: Vec::new(),
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
    fn is_empty_true_for_default_pool() {
        let pool = Mempool::new(MempoolLimits::default());
        assert!(pool.is_empty());
        assert_eq!(pool.tx_count(), 0);
    }

    #[test]
    fn tx_count_increments_with_insert() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            ..MempoolLimits::default()
        });
        let tx = Tx {
            version: 2,
            lock_time: 0,
            inputs: vec![],
            outputs: vec![],
        };
        pool.insert_entry(MempoolEntry::new(Arc::new(tx), 100, 10_000, 1, 7))?;
        assert!(!pool.is_empty());
        assert_eq!(pool.tx_count(), 1);
        Ok(())
    }

    #[test]
    fn aggregate_fees_sums_entry_fees() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits::default());
        assert_eq!(pool.aggregate_fees(), 0);

        let entry_a = MempoolEntry::new(Arc::new(tx(1, Vec::new())), 400, 500, 1, 7);
        let entry_b = MempoolEntry::new(Arc::new(tx(2, Vec::new())), 900, 1_000, 2, 7);
        pool.insert_entry(entry_a)?;
        pool.insert_entry(entry_b)?;

        assert_eq!(pool.aggregate_fees(), 1_500);
        Ok(())
    }

    #[test]
    fn aggregate_fees_stays_saturated_after_decrements() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            ..MempoolLimits::default()
        });
        let prioritised = tx(2, Vec::new());
        let prioritised_txid = prioritised.txid();
        let removed = tx(3, Vec::new());
        let removed_txid = removed.txid();

        pool.insert_entry(MempoolEntry::new(
            Arc::new(tx(1, Vec::new())),
            100,
            u64::MAX - 1,
            1,
            7,
        ))?;
        pool.insert_entry(MempoolEntry::new(Arc::new(prioritised), 100, 100, 2, 7))?;
        pool.insert_entry(MempoolEntry::new(Arc::new(removed), 100, 50, 3, 7))?;

        assert_eq!(pool.aggregate_fees(), u64::MAX);
        assert!(!pool.remove_by_txid(&removed_txid).is_empty());
        assert_eq!(pool.aggregate_fees(), u64::MAX);
        pool.prioritise(prioritised_txid, -100)
            .expect("overlay delta applies");
        // The overlay is mining-only: actual fees — and therefore the
        // aggregate — never move for it.
        assert_eq!(pool.aggregate_fees(), u64::MAX);
        Ok(())
    }

    #[test]
    fn contains_txid_returns_true_after_insert() {
        let mut pool = Mempool::new(MempoolLimits::default());
        let tx = Tx {
            version: 2,
            lock_time: 0,
            inputs: Vec::new(),
            outputs: vec![TxOut {
                value: 99_000,
                script_pubkey: vec![0x51],
            }],
        };
        let txid = tx.txid();
        let _ = pool.insert_entry(MempoolEntry::new(Arc::new(tx), 100, 10_000, 1, 7));
        assert!(pool.contains_txid(&txid));
        let other = txid_of([0xff; 32]);
        assert!(!pool.contains_txid(&other));
    }

    #[test]
    fn entry_by_txid_returns_some_for_inserted_tx() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            ..MempoolLimits::default()
        });
        let tx = Tx {
            version: 2,
            lock_time: 0,
            inputs: vec![],
            outputs: vec![],
        };
        let txid = tx.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(tx), 100, 10_000, 1, 7))?;
        let Some(entry) = pool.entry_by_txid(&txid) else {
            panic!("entry_by_txid returned None for inserted tx");
        };
        assert_eq!(entry.tx.txid(), txid);
        Ok(())
    }

    #[test]
    fn entry_by_txid_returns_none_for_absent_tx() {
        let pool = Mempool::new(MempoolLimits::default());
        let absent = txid_of([0xff; 32]);
        assert!(pool.entry_by_txid(&absent).is_none());
    }

    #[test]
    fn transaction_by_txid_returns_arc_for_inserted_tx() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            ..MempoolLimits::default()
        });
        let tx = Tx {
            version: 2,
            lock_time: 0,
            inputs: vec![],
            outputs: vec![],
        };
        let txid = tx.txid();
        let tx_arc = Arc::new(tx);
        pool.insert_entry(MempoolEntry::new(Arc::clone(&tx_arc), 500, 100, 1, 7))?;
        let Some(retrieved) = pool.transaction_by_txid(&txid) else {
            panic!("transaction_by_txid returned None");
        };
        assert_eq!(retrieved.txid(), txid);
        // The retrieved Arc should be the same allocation as the inserted one.
        assert!(Arc::ptr_eq(&tx_arc, &retrieved));
        Ok(())
    }

    #[test]
    fn transaction_by_txid_returns_none_for_absent_tx() {
        let pool = Mempool::new(MempoolLimits::default());
        let absent = txid_of([0xff; 32]);
        assert!(pool.transaction_by_txid(&absent).is_none());
    }

    #[test]
    fn iter_txids_returns_empty_for_empty_pool() {
        let pool = Mempool::new(MempoolLimits::default());
        assert!(pool.iter_txids().is_empty());
    }

    #[test]
    fn iter_txids_returns_all_inserted_txids() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            ..MempoolLimits::default()
        });
        let tx_a = Tx {
            version: 2,
            lock_time: 0,
            inputs: vec![],
            outputs: vec![TxOut {
                value: 100,
                script_pubkey: Vec::new(),
            }],
        };
        let txid_a = tx_a.txid();
        let tx_b = Tx {
            version: 2,
            lock_time: 0,
            inputs: vec![],
            outputs: vec![TxOut {
                value: 200,
                script_pubkey: Vec::new(),
            }],
        };
        let txid_b = tx_b.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(tx_a), 500, 100, 1, 7))?;
        pool.insert_entry(MempoolEntry::new(Arc::new(tx_b), 500, 100, 2, 7))?;
        let txids = pool.iter_txids();
        assert_eq!(txids.len(), 2);
        assert!(txids.contains(&txid_a));
        assert!(txids.contains(&txid_b));
        Ok(())
    }

    #[test]
    fn iter_by_fee_rate_desc_orders_highest_first() {
        let mut pool = Mempool::new(MempoolLimits::default());
        // Two distinct txs with different fee rates.
        let low_tx = Tx {
            version: 2,
            lock_time: 0,
            inputs: Vec::new(),
            outputs: vec![TxOut {
                value: 1_000,
                script_pubkey: vec![0x51],
            }],
        };
        let low_txid = low_tx.txid();
        let _ = pool.insert_entry(MempoolEntry::new(Arc::new(low_tx), 100, 1_000, 1, 7));
        let high_tx = Tx {
            version: 2,
            lock_time: 0,
            inputs: Vec::new(),
            outputs: vec![TxOut {
                value: 99_000,
                script_pubkey: vec![0x52],
            }],
        };
        let high_txid = high_tx.txid();
        let _ = pool.insert_entry(MempoolEntry::new(Arc::new(high_tx), 100, 10_000, 1, 7));
        let ordered = pool.iter_by_fee_rate_desc();
        assert_eq!(ordered.len(), 2);
        let Some(&first_id) = ordered.first() else {
            panic!("expected at least one entry");
        };
        let Some(first_entry) = pool.entry(first_id) else {
            panic!("first entry missing");
        };
        assert_eq!(first_entry.tx.txid(), high_txid);
        let Some(&second_id) = ordered.get(1) else {
            panic!("expected two entries");
        };
        let Some(second_entry) = pool.entry(second_id) else {
            panic!("second entry missing");
        };
        assert_eq!(second_entry.tx.txid(), low_txid);
    }

    #[test]
    fn lowest_fee_rate_returns_none_for_empty_pool() {
        let pool = Mempool::new(MempoolLimits::default());
        assert!(pool.lowest_fee_rate().is_none());
    }

    #[test]
    fn lowest_fee_rate_returns_minimum_across_entries() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            ..MempoolLimits::default()
        });

        let high = MempoolEntry::new(Arc::new(tx(1, Vec::new())), 1_000, 5_000, 1, 7);
        let low = MempoolEntry::new(Arc::new(tx(2, Vec::new())), 1_000, 1_500, 1, 7);
        pool.insert_entry(high)?;
        pool.insert_entry(low)?;

        assert_eq!(pool.lowest_fee_rate(), Some(1_500));
        Ok(())
    }

    fn independent_lowest_fee_rate(pool: &Mempool) -> Option<u64> {
        pool.entries
            .iter()
            .map(|(_index, entry)| entry.fee_rate)
            .min()
    }

    fn assert_floor(pool: &Mempool, expected: Option<u64>, stage: &str) {
        assert_eq!(
            pool.lowest_fee_rate(),
            expected,
            "maintained floor mismatched expected after {stage}"
        );
        assert_eq!(
            pool.lowest_fee_rate(),
            independent_lowest_fee_rate(pool),
            "maintained floor drifted from entries after {stage}"
        );
    }

    #[test]
    fn lowest_fee_rate_tracks_duplicate_rates_and_every_removal_path() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            max_total_bytes: 10_000,
            ..MempoolLimits::default()
        });
        assert_floor(&pool, None, "empty");

        let high = MempoolEntry::new(Arc::new(tx(1, Vec::new())), 1_000, 5_000, 1, 7);
        pool.insert_entry(high)?;
        assert_floor(&pool, Some(5_000), "insert high");

        let low_a_tx = tx(2, Vec::new());
        let low_a_txid = low_a_tx.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(low_a_tx), 1_000, 1_500, 1, 7))?;
        assert_floor(&pool, Some(1_500), "insert lower rate");

        let low_b_tx = tx(3, Vec::new());
        let low_b_txid = low_b_tx.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(low_b_tx), 1_000, 1_500, 1, 7))?;
        assert_floor(&pool, Some(1_500), "duplicate min rate");

        let removed = pool.remove_by_txid(&low_a_txid);
        assert_eq!(removed.len(), 1);
        assert_floor(&pool, Some(1_500), "explicit remove of one duplicate min");

        let evicted = pool.evict_below_fee_rate(2_000);
        assert_eq!(change_txids(&evicted), vec![hash_of(&low_b_txid)]);
        assert_floor(&pool, Some(5_000), "evict_below remaining min");

        let mined = tx(4, Vec::new());
        let mined_txid = mined.txid();
        pool.insert_entry(MempoolEntry::new(
            Arc::new(mined.clone()),
            1_000,
            2_000,
            1,
            7,
        ))?;
        assert_floor(&pool, Some(2_000), "insert new min before block");
        let removed = pool.remove_for_block(&[&mined], &[mined_txid], 8);
        assert_eq!(removed.len(), 1);
        assert_floor(&pool, Some(5_000), "remove_for_block of current min");

        let bulky_low = MempoolEntry::new(Arc::new(tx(5, Vec::new())), 5_000, 5_000, 1, 7);
        pool.insert_entry(bulky_low)?;
        assert_floor(&pool, Some(1_000), "insert eviction victim");
        let evicted = pool.enforce_size_limit(5_000);
        assert_eq!(evicted.len(), 1);
        assert_floor(&pool, Some(5_000), "size-limit eviction of min");

        pool.prioritise(
            pool.iter_txids()
                .into_iter()
                .next()
                .expect("survivor after eviction"),
            250_000,
        )
        .expect("prioritise must not touch actual fee_rate");
        assert_floor(&pool, Some(5_000), "prioritise overlay");

        pool.clear();
        assert_floor(&pool, None, "clear");
        Ok(())
    }

    #[test]
    fn lowest_fee_rate_tracks_bip125_replacement() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            ..MempoolLimits::default()
        });
        let prev = OutPoint {
            txid: txid_of([0x11; 32]),
            vout: 0,
        };
        let original = Tx {
            version: 2,
            lock_time: 0,
            inputs: vec![TxIn {
                previous_output: prev,
                script_sig: Vec::new(),
                sequence: 0xFFFF_FFFD,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 1_000,
                script_pubkey: vec![0x51],
            }],
        };
        pool.insert_entry(MempoolEntry::new(Arc::new(original), 1_000, 2_000, 1, 7))?;
        pool.insert_entry(MempoolEntry::new(
            Arc::new(tx(8, Vec::new())),
            1_000,
            1_500,
            1,
            7,
        ))?;
        assert_floor(&pool, Some(1_500), "before replacement");

        let replacement = Tx {
            version: 2,
            lock_time: 0,
            inputs: vec![TxIn {
                previous_output: prev,
                script_sig: Vec::new(),
                sequence: 0xFFFF_FFFD,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 900,
                script_pubkey: vec![0x52],
            }],
        };
        pool.replace_transaction(
            crate::ReplacementCandidate::new(Arc::new(replacement), 1_000, 4_000, 1),
            10,
            1,
            4,
        )
        .expect("replacement must apply");
        assert_floor(
            &pool,
            Some(1_500),
            "replacement must not drop the bystander min",
        );
        Ok(())
    }

    #[test]
    fn iter_above_fee_rate_filters_to_high_fee_only() {
        let mut pool = Mempool::new(MempoolLimits::default());
        let low_tx = Tx {
            version: 2,
            lock_time: 0,
            inputs: Vec::new(),
            outputs: vec![TxOut {
                value: 1_000,
                script_pubkey: vec![0x51],
            }],
        };
        let _ = pool.insert_entry(MempoolEntry::new(Arc::new(low_tx), 100, 1_000, 1, 7)); // fee_rate = 1000
        let high_tx = Tx {
            version: 2,
            lock_time: 0,
            inputs: Vec::new(),
            outputs: vec![TxOut {
                value: 99_000,
                script_pubkey: vec![0x52],
            }],
        };
        let _ = pool.insert_entry(MempoolEntry::new(Arc::new(high_tx), 100, 10_000, 1, 7)); // fee_rate = 100_000
        let high_only = pool.iter_above_fee_rate(50_000);
        assert_eq!(high_only.len(), 1);
        let both = pool.iter_above_fee_rate(500);
        assert_eq!(both.len(), 2);
        let none = pool.iter_above_fee_rate(200_000);
        assert_eq!(none.len(), 0);
    }

    #[test]
    fn iter_replaceable_txids_returns_only_rbf_signaled_txs() {
        let mut pool = Mempool::new(MempoolLimits::default());
        // RBF-signalled tx (sequence < 0xFFFFFFFE).
        let rbf_tx = Tx {
            version: 2,
            lock_time: 0,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: txid_of([0xaa; 32]),
                    vout: 0,
                },
                script_sig: Vec::new(),
                sequence: 0x0000_0001,
                witness: Vec::new(),
            }],
            outputs: Vec::new(),
        };
        let rbf_txid = rbf_tx.txid();
        let _ = pool.insert_entry(MempoolEntry::new(Arc::new(rbf_tx), 100, 10_000, 1, 7));
        // Non-RBF tx (sequence = MAX = 0xFFFFFFFF).
        let non_rbf_tx = Tx {
            version: 2,
            lock_time: 0,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: txid_of([0xbb; 32]),
                    vout: 0,
                },
                script_sig: Vec::new(),
                sequence: 0xFF_FF_FF_FF,
                witness: Vec::new(),
            }],
            outputs: Vec::new(),
        };
        let non_rbf_txid = non_rbf_tx.txid();
        let _ = pool.insert_entry(MempoolEntry::new(Arc::new(non_rbf_tx), 100, 10_000, 1, 7));
        let replaceable = pool.iter_replaceable_txids();
        assert!(replaceable.contains(&rbf_txid));
        assert!(!replaceable.contains(&non_rbf_txid));
        assert_eq!(replaceable.len(), 1);
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
    fn clear_removes_all_entries_and_bumps_sequence() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits::default());
        let tx = Tx {
            version: 2,
            lock_time: 0,
            inputs: Vec::new(),
            outputs: vec![TxOut {
                value: 99_000,
                script_pubkey: vec![0x51],
            }],
        };
        let _id = pool.insert_entry(MempoolEntry::new(Arc::new(tx), 100, 10_000, 1, 7))?;
        let seq_before_clear = pool.sequence_number();

        pool.clear();

        assert_eq!(pool.len(), 0);
        assert!(pool.by_txid.is_empty());
        assert!(pool.funding.is_empty());
        assert!(pool.spending.is_empty());
        assert!(pool.pareto.is_empty());
        assert!(pool.fee_deltas.is_empty(), "clear is a wholesale reset");
        assert!(pool.sequence_number() > seq_before_clear);
        Ok(())
    }

    #[test]
    fn outpoint_spender_returns_the_spending_entry_and_vin() {
        let mut pool = Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            ..MempoolLimits::default()
        });
        let outpoint = OutPoint {
            txid: txid_of([0xaa; 32]),
            vout: 7,
        };
        // A decoy input first, so the spending input sits at vin 1 rather
        // than the position every trivial fixture happens to use.
        let decoy = OutPoint {
            txid: txid_of([0xbb; 32]),
            vout: 3,
        };
        let spending = Tx {
            version: 2,
            lock_time: 0,
            inputs: vec![
                TxIn {
                    previous_output: decoy,
                    script_sig: Vec::new(),
                    sequence: 0xFF_FF_FF_FF,
                    witness: Vec::new(),
                },
                TxIn {
                    previous_output: outpoint,
                    script_sig: Vec::new(),
                    sequence: 0xFF_FF_FF_FF,
                    witness: Vec::new(),
                },
            ],
            outputs: vec![TxOut {
                value: 99_000,
                script_pubkey: vec![0x51],
            }],
        };
        let spending_txid = spending.txid();
        let _ = pool.insert_entry(MempoolEntry::new(Arc::new(spending), 100, 10_000, 1, 7));
        let spender = pool
            .outpoint_spender(outpoint)
            .expect("the index and the entries agree")
            .expect("the pool holds a spender");
        assert_eq!(spender.entry.txid, spending_txid);
        assert_eq!(spender.vin, 1);
    }

    #[test]
    fn outpoint_spender_returns_none_for_unspent_outpoint() {
        let pool = Mempool::new(MempoolLimits::default());
        let outpoint = OutPoint {
            txid: txid_of([0xff; 32]),
            vout: 0,
        };
        assert!(matches!(pool.outpoint_spender(outpoint), Ok(None)));
    }

    #[test]
    fn outpoint_spender_errors_when_the_index_names_a_missing_entry() {
        let mut pool = Mempool::new(MempoolLimits::default());
        let outpoint = OutPoint {
            txid: txid_of([0xee; 32]),
            vout: 0,
        };
        // No entry was ever inserted, so this row dangles.
        pool.spending.insert((SpendingKey::from(outpoint), 9_999));
        assert!(matches!(
            pool.outpoint_spender(outpoint),
            Err(MempoolError::InconsistentSpendingIndex)
        ));
    }

    #[test]
    fn outpoint_spender_errors_when_the_entry_does_not_spend_the_outpoint() {
        let mut pool = Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            ..MempoolLimits::default()
        });
        let unrelated = OutPoint {
            txid: txid_of([0xdd; 32]),
            vout: 0,
        };
        let indexed = OutPoint {
            txid: txid_of([0xcc; 32]),
            vout: 5,
        };
        let tx = Tx {
            version: 2,
            lock_time: 0,
            inputs: vec![TxIn {
                previous_output: unrelated,
                script_sig: Vec::new(),
                sequence: 0xFF_FF_FF_FF,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 99_000,
                script_pubkey: vec![0x51],
            }],
        };
        let entry_txid = tx.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(tx), 100, 10_000, 1, 7))
            .expect("insertion succeeds");
        let id = pool
            .entry_id_by_txid(&entry_txid)
            .expect("inserted entry id resolves");
        // A row the entry's inputs never earn.
        pool.spending.insert((SpendingKey::from(indexed), id));
        assert!(matches!(
            pool.outpoint_spender(indexed),
            Err(MempoolError::InconsistentSpendingIndex)
        ));
    }

    #[test]
    fn outpoint_spender_keeps_the_first_entry_when_two_spenders_are_indexed() {
        let mut pool = Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            ..MempoolLimits::default()
        });
        let outpoint = OutPoint {
            txid: txid_of([0x11; 32]),
            vout: 0,
        };
        let spender_tx = |fee: u64| Tx {
            version: 2,
            lock_time: 0,
            inputs: vec![TxIn {
                previous_output: outpoint,
                script_sig: Vec::new(),
                sequence: 0xFF_FF_FF_FF,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: fee,
                script_pubkey: vec![0x51],
            }],
        };
        let first = spender_tx(99_000);
        let first_txid = first.txid();
        let _ = pool.insert_entry(MempoolEntry::new(Arc::new(first), 100, 10_000, 1, 7));
        // A second spender of the same outpoint is a pool invariant violation
        // that insertion does not police; the query must still answer with
        // the first indexed entry, like the scan it replaces did.
        let _ = pool.insert_entry(MempoolEntry::new(
            Arc::new(spender_tx(98_000)),
            100,
            10_000,
            1,
            7,
        ));
        let spender = pool
            .outpoint_spender(outpoint)
            .expect("both rows are internally consistent")
            .expect("the pool holds spenders");
        assert_eq!(spender.entry.txid, first_txid);
    }

    #[test]
    fn is_outpoint_spent_returns_true_after_insert() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            ..MempoolLimits::default()
        });
        let prev_txid = txid_of([0xaa_u8; 32]);
        let outpoint = OutPoint {
            txid: prev_txid,
            vout: 1,
        };
        let spending = Tx {
            version: 2,
            lock_time: 0,
            inputs: vec![TxIn {
                previous_output: outpoint,
                script_sig: Vec::new(),
                sequence: 0xFFFF_FFFF,
                witness: Vec::new(),
            }],
            outputs: vec![],
        };
        pool.insert_entry(MempoolEntry::new(Arc::new(spending), 100, 10_000, 1, 7))?;
        assert!(pool.is_outpoint_spent(&outpoint));
        Ok(())
    }

    #[test]
    fn is_outpoint_spent_returns_false_for_unspent_outpoint() {
        let pool = Mempool::new(MempoolLimits::default());
        let outpoint = OutPoint {
            txid: txid_of([0xff_u8; 32]),
            vout: 0,
        };
        assert!(!pool.is_outpoint_spent(&outpoint));
    }

    #[test]
    fn remove_by_txid_returns_empty_for_unknown_txid() {
        let mut pool = Mempool::new(MempoolLimits::default());

        let removed = pool.remove_by_txid(&txid_of([0_u8; 32]));

        assert!(removed.is_empty());
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn remove_by_txid_removes_entry_and_descendants_when_present() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits::default());
        let tx = Tx {
            version: 2,
            lock_time: 0,
            inputs: Vec::new(),
            outputs: Vec::new(),
        };
        let txid = tx.txid();
        let entry = MempoolEntry::new(Arc::new(tx), 123, 4_567, 0, 0);
        pool.insert_entry(entry)?;

        let removed = pool.remove_by_txid(&txid);

        assert_eq!(removed.len(), 1);
        assert_eq!(
            removed.changes.first().map(|change| change.txid),
            Some(hash_of(&txid))
        );
        assert_eq!(pool.len(), 0);
        Ok(())
    }

    #[test]
    fn descendant_ids_for_entry_returns_descendants_excluding_origin() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits::default());
        let parent = tx(1, Vec::new());
        let parent_txid = parent.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(parent), 100, 1_000, 0, 0))?;
        let parent_id = pool
            .entry_id_by_txid(&parent_txid)
            .expect("parent id resolves");
        let child = tx(2, vec![OutPoint::new(parent_txid, 0)]);
        let child_txid = child.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(child), 100, 1_000, 0, 0))?;
        let child_id = pool
            .entry_id_by_txid(&child_txid)
            .expect("child id resolves");

        let descendants = pool.descendant_ids_for_entry(parent_id);

        assert_eq!(descendants, vec![child_id]);
        Ok(())
    }

    #[test]
    fn descendant_count_inclusive_returns_one_for_lone_tx() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits::default());
        let lone = tx(1, Vec::new());
        let lone_txid = lone.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(lone), 500, 1_000, 1, 7))?;
        let Some(id) = pool.entry_id_by_txid(&lone_txid) else {
            panic!("insert failed");
        };
        assert_eq!(pool.descendant_count_inclusive(id), 1);
        assert_eq!(pool.ancestor_count_inclusive(id), 1);
        Ok(())
    }

    #[test]
    fn prioritise_moves_modified_fee_without_touching_actual_fees() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits::default());
        let tx = tx(1, Vec::new());
        let txid = tx.txid();
        let _id = pool.insert_entry(MempoolEntry::new(Arc::new(tx), 100, 1_000, 1, 7))?;

        pool.prioritise(txid, 500).expect("overlay delta applies");

        let Some(entry) = pool.entry_by_txid(&txid) else {
            panic!("tx missing after prioritise");
        };
        assert_eq!(
            entry.fee, 1_000,
            "the actual fee is what the transaction pays"
        );
        assert_eq!(
            entry.fee_rate, 10_000,
            "the actual fee rate is policy input"
        );
        assert_eq!(entry.fee_delta, 500);
        assert_eq!(entry.modified_fee(), 1_500);
        assert_eq!(entry.modified_fee_rate(), 15_000);
        assert_eq!(
            pool.aggregate_fees(),
            1_000,
            "aggregates read actual fees only"
        );
        Ok(())
    }

    #[test]
    fn prioritise_keeps_the_actual_fee_when_modified_fee_goes_negative() -> Result<(), MempoolError>
    {
        let mut pool = Mempool::new(MempoolLimits::default());
        let tx = tx(2, Vec::new());
        let txid = tx.txid();
        let _id = pool.insert_entry(MempoolEntry::new(Arc::new(tx), 100, 1_000, 1, 7))?;

        pool.prioritise(txid, -2_000)
            .expect("negative overlay applies");

        let Some(entry) = pool.entry_by_txid(&txid) else {
            panic!("tx missing after prioritise");
        };
        assert_eq!(entry.fee, 1_000);
        assert_eq!(entry.fee_rate, 10_000);
        assert_eq!(entry.modified_fee(), -1_000);
        // A negative modified fee ranks below every actual fee, including
        // zero — that is the signed order the priority index keeps.
        assert_eq!(
            pool.pareto.len(),
            1,
            "a negative overlay still indexes the entry"
        );
        Ok(())
    }

    #[test]
    fn prioritise_accumulates_additively_and_rejects_overflow() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits::default());
        let entry_tx = tx(3, Vec::new());
        let txid = entry_tx.txid();
        let _id = pool.insert_entry(MempoolEntry::new(Arc::new(entry_tx), 100, 1_000, 1, 7))?;

        pool.prioritise(txid, 2_000).expect("first delta applies");
        pool.prioritise(txid, 3_000)
            .expect("second delta accumulates");
        pool.prioritise(txid, -1_200)
            .expect("a negative delta subtracts");
        assert_eq!(
            pool.entry_by_txid(&txid).map(|entry| entry.fee_delta),
            Some(3_800),
            "deltas are additive, not replacements"
        );

        let other = tx(4, Vec::new());
        let other_txid = other.txid();
        let _other_id = pool.insert_entry(MempoolEntry::new(Arc::new(other), 100, 1_000, 1, 7))?;
        pool.prioritise(other_txid, i64::MAX)
            .expect("the signed range edge itself is storable");
        assert_eq!(
            pool.prioritise(other_txid, 1),
            Err(PrioritiseError::FeeDeltaOverflow)
        );
        assert_eq!(
            pool.entry_by_txid(&other_txid).map(|entry| entry.fee_delta),
            Some(i64::MAX),
            "a rejected delta leaves the overlay exactly as it was"
        );
        pool.prioritise(other_txid, -1)
            .expect("recovery from the edge works");
        Ok(())
    }

    #[test]
    fn prioritise_propagates_the_overlay_through_package_deltas() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits::default());
        let parent = tx(5, Vec::new());
        let parent_txid = parent.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(parent), 100, 1_000, 0, 0))?;
        let parent_id = pool
            .entry_id_by_txid(&parent_txid)
            .expect("parent id resolves");
        let child = tx(6, vec![OutPoint::new(parent_txid, 0)]);
        let child_txid = child.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(child), 100, 2_000, 0, 0))?;
        let child_id = pool
            .entry_id_by_txid(&child_txid)
            .expect("child id resolves");
        let grandchild = tx(7, vec![OutPoint::new(child_txid, 0)]);
        let grandchild_txid = grandchild.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(grandchild), 100, 3_000, 0, 0))?;
        let grandchild_id = pool
            .entry_id_by_txid(&grandchild_txid)
            .expect("grandchild id resolves");

        pool.prioritise(child_txid, 500)
            .expect("overlay delta applies");

        let Some(parent_after) = pool.entry(parent_id) else {
            panic!("missing parent");
        };
        assert_eq!(
            parent_after.descendant_fee, 6_000,
            "actual fees do not move"
        );
        assert_eq!(parent_after.descendant_fee_delta, 500);
        let Some(child_after) = pool.entry(child_id) else {
            panic!("missing child");
        };
        assert_eq!(child_after.ancestor_fee, 3_000, "actual fees do not move");
        assert_eq!(child_after.ancestor_fee_delta, 500);
        assert_eq!(child_after.modified_ancestor_fee_rate(), 17_500);
        let Some(grandchild_after) = pool.entry(grandchild_id) else {
            panic!("missing grandchild");
        };
        assert_eq!(
            grandchild_after.ancestor_fee, 6_000,
            "actual fees do not move"
        );
        assert_eq!(grandchild_after.ancestor_fee_delta, 500);
        Ok(())
    }

    #[test]
    fn a_delta_may_predate_admission() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits::default());
        let tx = tx(8, Vec::new());
        let txid = tx.txid();
        let before = pool.sequence_number();

        pool.prioritise(txid, 1_500)
            .expect("an absent txid stores its delta");
        // Nothing a template or long-poll waiter can observe changed yet, so
        // the sequence — the invalidation key they ride on — must not move.
        assert!(!pool.contains_txid(&txid));
        assert_eq!(pool.sequence_number(), before);

        pool.insert_entry(MempoolEntry::new(Arc::new(tx), 100, 1_000, 1, 7))?;

        let Some(entry) = pool.entry_by_txid(&txid) else {
            panic!("insert failed");
        };
        assert_eq!(entry.fee_delta, 1_500);
        assert_eq!(
            entry.fee, 1_000,
            "a pre-admission delta adjusts ordering only"
        );
        assert_eq!(entry.modified_fee(), 2_500);
        Ok(())
    }

    #[test]
    fn ordinary_removal_keeps_the_overlay_for_readmission() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits::default());
        let tx = tx(9, Vec::new());
        let txid = tx.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(tx.clone()), 100, 1_000, 1, 7))?;
        pool.prioritise(txid, 700).expect("delta applies");

        assert!(!pool.remove_by_txid(&txid).is_empty());

        pool.insert_entry(MempoolEntry::new(Arc::new(tx), 100, 1_000, 1, 7))?;
        let Some(entry) = pool.entry_by_txid(&txid) else {
            panic!("readmission failed");
        };
        assert_eq!(entry.fee_delta, 700, "ordinary removal keeps the overlay");
        assert_eq!(entry.fee, 1_000);
        Ok(())
    }

    #[test]
    fn mined_removal_clears_only_the_overlays_of_block_transactions() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits::default());
        let parent = tx(10, Vec::new());
        let parent_txid = parent.txid();
        pool.insert_entry(MempoolEntry::new(
            Arc::new(parent.clone()),
            100,
            1_000,
            1,
            7,
        ))?;
        let child = tx(11, vec![OutPoint::new(parent_txid, 0)]);
        let child_txid = child.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(child.clone()), 100, 1_000, 1, 7))?;
        // A delta stored for a transaction that never reached the pool.
        let stranger = tx(12, Vec::new());
        let stranger_txid = stranger.txid();

        pool.prioritise(parent_txid, 100)
            .expect("parent delta applies");
        pool.prioritise(child_txid, 200)
            .expect("child delta applies");
        pool.prioritise(stranger_txid, 50)
            .expect("stranger delta applies");

        let removed =
            pool.remove_for_block(&[&parent, &stranger], &[parent_txid, stranger_txid], 8);

        assert_eq!(removed.len(), 2, "the parent leaves with its descendant");
        assert!(!pool.fee_deltas.contains_key(&parent_txid));
        assert!(!pool.fee_deltas.contains_key(&stranger_txid));
        assert_eq!(
            pool.fee_deltas.get(&child_txid).copied(),
            Some(200),
            "a descendant removed for a mined parent was not confirmed itself"
        );

        // Readmission answers from the surviving state alone.
        pool.insert_entry(MempoolEntry::new(Arc::new(child), 100, 1_000, 1, 7))?;
        assert_eq!(
            pool.entry_by_txid(&child_txid).map(|entry| entry.fee_delta),
            Some(200)
        );
        pool.insert_entry(MempoolEntry::new(Arc::new(parent), 100, 1_000, 1, 7))?;
        assert_eq!(
            pool.entry_by_txid(&parent_txid)
                .map(|entry| entry.fee_delta),
            Some(0),
            "a mined transaction's overlay is erased"
        );
        Ok(())
    }

    #[test]
    fn prioritise_reorders_priority_index() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits::default());
        let lower_fee_tx = tx(13, Vec::new());
        let lower_fee_txid = lower_fee_tx.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(lower_fee_tx), 100, 1_000, 1, 7))?;
        let lower_fee_id = pool
            .entry_id_by_txid(&lower_fee_txid)
            .expect("lower id resolves");
        let higher_fee_tx = tx(14, Vec::new());
        let higher_fee_txid = higher_fee_tx.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(higher_fee_tx), 100, 2_000, 2, 7))?;
        let higher_fee_id = pool
            .entry_id_by_txid(&higher_fee_txid)
            .expect("higher id resolves");

        assert_eq!(
            pool.pareto.top_n(1).collect::<Vec<_>>(),
            vec![higher_fee_id]
        );
        pool.prioritise(lower_fee_txid, 2_000)
            .expect("delta applies");

        assert_eq!(pool.pareto.top_n(1).collect::<Vec<_>>(), vec![lower_fee_id]);
        Ok(())
    }

    #[test]
    fn mining_snapshot_copies_metadata_topology_and_sequence() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits::default());
        let parent = Arc::new(tx(15, Vec::new()));
        let parent_txid = parent.txid();
        let _parent_id =
            pool.insert_entry(MempoolEntry::new(Arc::clone(&parent), 100, 1_000, 1, 7))?;
        let child = Arc::new(tx(16, vec![OutPoint::new(parent_txid, 0)]));
        let child_txid = child.txid();
        let _child_id =
            pool.insert_entry(MempoolEntry::new(Arc::clone(&child), 100, 2_000, 2, 7))?;

        let snapshot = pool.mining_snapshot();
        assert_eq!(snapshot.sequence, pool.sequence_number());
        assert_eq!(snapshot.entries.len(), 2);
        // The child pays the higher actual fee rate, so it ranks first.
        let [child_entry, parent_entry] = &snapshot.entries[..] else {
            panic!("snapshot must hold both entries");
        };
        assert_eq!(child_entry.txid, child_txid);
        assert_eq!(parent_entry.txid, parent_txid);
        assert_eq!(child_entry.ancestors, vec![1], "positions are in-snapshot");
        assert!(parent_entry.ancestors.is_empty());
        // Metadata fidelity: copied scalars are the ones derived from the
        // transaction itself, not policy reconstructions of them.
        assert_eq!(child_entry.fee, 2_000);
        assert_eq!(child_entry.fee_delta, 0);
        assert_eq!(child_entry.vsize, 100);
        assert_eq!(
            child_entry.bip141_vsize,
            u32::try_from(child.vsize()).unwrap_or(u32::MAX)
        );
        assert_eq!(
            child_entry.size,
            u32::try_from(child.total_size()).unwrap_or(u32::MAX)
        );
        assert_eq!(child_entry.weight, child.weight());
        assert_eq!(
            child_entry.sigop_cost,
            bitcoin_rs_script::count_tx_legacy(&child)
        );
        assert_eq!(child_entry.wtxid, child.wtxid());
        assert_eq!(child_entry.ancestor_size, 200);
        assert_eq!(child_entry.ancestor_fee, 3_000);
        assert_eq!(child_entry.ancestor_fee_delta, 0);

        pool.prioritise(parent_txid, 2_000).expect("delta applies");
        let bumped = pool.mining_snapshot();
        assert_eq!(
            bumped.sequence, snapshot.sequence,
            "prioritisation emits no mutation change and moves no sequence"
        );
        let [bumped_parent, bumped_child] = &bumped.entries[..] else {
            panic!("bumped snapshot must hold both entries");
        };
        assert_eq!(
            bumped_parent.txid, parent_txid,
            "the overlay lifted the parent"
        );
        assert_eq!(bumped_child.ancestors, vec![0]);
        assert_eq!(
            bumped_child.ancestor_fee, 3_000,
            "actual package fees hold still"
        );
        assert_eq!(bumped_child.ancestor_fee_delta, 2_000);
        Ok(())
    }

    #[test]
    fn a_snapshot_outlives_pool_mutation() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits::default());
        let tx = tx(17, Vec::new());
        let txid = tx.txid();
        let shared = Arc::new(tx);
        pool.insert_entry(MempoolEntry::new(Arc::clone(&shared), 100, 1_000, 1, 7))?;

        let snapshot = pool.mining_snapshot();
        pool.clear();
        pool.prioritise(txid, 5_000)
            .expect("delta applies after the clear");

        let Some(entry) = snapshot.entries.first() else {
            panic!("the snapshot holds what it captured");
        };
        assert_eq!(entry.txid, txid);
        assert_eq!(entry.fee, 1_000);
        assert_eq!(entry.fee_delta, 0);
        assert!(
            Arc::ptr_eq(&entry.tx, &shared),
            "payloads are shared, not copied"
        );
        Ok(())
    }

    #[test]
    fn admissions_and_mined_confirmations_feed_the_pool_owned_estimator() -> Result<(), MempoolError>
    {
        let mut pool = Mempool::new(MempoolLimits::default());
        assert_eq!(pool.estimate_fee_rate(2), None, "no history yet");

        let first = tx(18, Vec::new());
        let first_txid = first.txid();
        let second = tx(19, Vec::new());
        let second_txid = second.txid();
        pool.insert_entry(MempoolEntry::new(
            Arc::new(first.clone()),
            100,
            10_000,
            1,
            7,
        ))?;
        pool.insert_entry(MempoolEntry::new(
            Arc::new(second.clone()),
            100,
            10_000,
            1,
            7,
        ))?;
        assert_eq!(
            pool.estimate_fee_rate(2),
            None,
            "arrivals alone are not confirmation evidence"
        );

        // Two confirmations, not one: every sample is stored post-decay, so a
        // single confirmation decays to 0.998 within its own block — under
        // the estimator's one-decayed-observation minimum. The test feeds
        // that gate rather than weakening it.
        pool.remove_for_block(&[&first, &second], &[first_txid, second_txid], 8);
        assert!(
            pool.estimate_fee_rate(2).is_some(),
            "the confirmations this pool observed itself answer the estimate"
        );
        assert!(!pool.contains_txid(&first_txid));
        assert!(
            !pool.contains_txid(&second_txid),
            "the mined transactions left the pool"
        );
        Ok(())
    }

    #[test]
    fn evict_below_fee_rate_removes_low_fee_entries_only() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            ..MempoolLimits::default()
        });
        let low = Tx {
            version: 2,
            lock_time: 0,
            inputs: Vec::new(),
            outputs: vec![TxOut {
                value: 1_000,
                script_pubkey: vec![0x51],
            }],
        };
        let low_txid = low.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(low), 100, 100, 1, 7))?;

        let high = Tx {
            version: 2,
            lock_time: 0,
            inputs: Vec::new(),
            outputs: vec![TxOut {
                value: 99_000,
                script_pubkey: vec![0x52],
            }],
        };
        let high_txid = high.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(high), 100, 10_000, 1, 7))?;

        let evicted = pool.evict_below_fee_rate(5_000);

        assert_eq!(change_txids(&evicted), vec![hash_of(&low_txid)]);
        assert!(!pool.contains_txid(&low_txid));
        assert!(pool.contains_txid(&high_txid));
        Ok(())
    }

    #[test]
    fn enforce_size_limit_evicts_lowest_fee_until_below_target() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            ..MempoolLimits::default()
        });

        let low = Tx {
            version: 2,
            lock_time: 0,
            inputs: Vec::new(),
            outputs: vec![TxOut {
                value: 1_000,
                script_pubkey: vec![0x51],
            }],
        };
        let low_txid = low.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(low), 500, 100, 1, 7))?;

        let high = Tx {
            version: 2,
            lock_time: 0,
            inputs: Vec::new(),
            outputs: vec![TxOut {
                value: 99_000,
                script_pubkey: vec![0x52],
            }],
        };
        let high_txid = high.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(high), 500, 10_000, 1, 7))?;

        let evicted = pool.enforce_size_limit(600);

        assert_eq!(evicted.len(), 1);
        assert!(!pool.contains_txid(&low_txid));
        assert!(pool.contains_txid(&high_txid));
        assert!(pool.total_vsize() <= 600);
        Ok(())
    }

    #[test]
    fn insert_entry_triggers_size_limit_eviction_when_overflow() {
        let limits = MempoolLimits {
            max_total_bytes: 1_000,
            min_relay_fee_sat_per_kvb: 0,
            ..MempoolLimits::default()
        };
        let mut pool = Mempool::new(limits);

        for nonce in 0..2_u32 {
            let tx = Tx {
                version: 2,
                lock_time: 0,
                inputs: Vec::new(),
                outputs: vec![TxOut {
                    value: 1_000 + u64::from(nonce),
                    script_pubkey: vec![0x51, u8::try_from(nonce).unwrap_or(0)],
                }],
            };
            let fee = 100_u64.saturating_add(u64::from(nonce).saturating_mul(50));

            let _ = pool.insert_entry(MempoolEntry::new(Arc::new(tx), 600, fee, 1, 7));
        }

        assert!(
            pool.total_vsize() <= 1_000,
            "size limit must hold after inserts: {}",
            pool.total_vsize()
        );
    }

    /// A transaction the size limit sheds is never accepted.
    ///
    /// `insert_entry` indexes the arrival and only then trims the pool, so the
    /// arrival can be what the trim takes. The mutation did commit — the
    /// sequence moved and the trim eviction is durable — so the outcome
    /// reports `ShedAfterCommit` carrying that record, not `Ok(Accepted)`;
    /// a caller deriving success from `Accepted` would act on a transaction
    /// that is not in the pool. The paired accept is the point: the same
    /// pool, one better-paying transaction, must still be admitted.
    #[test]
    fn a_transaction_the_size_limit_sheds_is_not_accepted() {
        fn tx_paying(nonce: u8) -> Arc<Tx> {
            Arc::new(Tx {
                version: 2,
                lock_time: 0,
                inputs: Vec::new(),
                outputs: vec![TxOut {
                    value: 1_000 + u64::from(nonce),
                    script_pubkey: vec![0x51, nonce],
                }],
            })
        }

        let limits = MempoolLimits {
            max_total_bytes: 1_000,
            min_relay_fee_sat_per_kvb: 0,
            ..MempoolLimits::default()
        };
        let mut pool = Mempool::new(limits);

        // Fills the pool at a rate the arrivals below are measured against.
        let seated = pool.insert_entry(MempoolEntry::new(tx_paying(1), 900, 90_000, 1, 7));
        assert!(seated.is_ok(), "the first transaction fits: {seated:?}");

        // Pays far less per byte than what is seated, so the trim takes it.
        let shed = pool.insert_entry(MempoolEntry::new(tx_paying(2), 900, 10, 2, 7));
        let Ok(shed) = shed else {
            panic!("the shed insert committed; Err means nothing did: {shed:?}");
        };
        assert!(
            shed.is_shed(),
            "a transaction evicted by the trim must not report Accepted: {shed:?}"
        );
        assert_eq!(
            shed.mutation().changes,
            vec![
                crate::mutation::change(&tx_paying(2).txid(), MutationOutcome::Accepted),
                crate::mutation::change(
                    &tx_paying(2).txid(),
                    MutationOutcome::Removed(RemovalReason::PolicyEviction),
                ),
            ],
            "the shed insert's record carries its own acceptance and removal"
        );
        assert_eq!(pool.len(), 1, "the seated transaction stays");

        // The paired accept: pays more, so the trim takes the other one.
        let admitted = pool.insert_entry(MempoolEntry::new(tx_paying(3), 900, 900_000, 3, 7));
        let Ok(_result) = admitted else {
            panic!("a better-paying transaction must be admitted: {admitted:?}");
        };
        assert_eq!(pool.len(), 1, "the accepted transaction is the only entry");
        assert!(
            pool.entries.iter().any(|(_, entry)| entry.vsize == 900),
            "an accepted entry must resolve"
        );
    }

    /// A replacement the size limit sheds must not report plain success.
    ///
    /// `replace_transaction` evicts conflicting entries, inserts the
    /// replacement, and then trims. If the replacement itself is the
    /// worst-paying entry, the trim takes it — but the mutation already
    /// committed, so the outcome reports `ShedAfterCommit` carrying the
    /// committed record instead of `Ok(Accepted)`. A caller treating a
    /// shed replacement as accepted would act on a transaction that is
    /// no longer in the pool.
    #[test]
    fn a_replacement_the_size_limit_sheds_is_not_accepted() {
        let limits = MempoolLimits {
            max_total_bytes: 1_000,
            min_relay_fee_sat_per_kvb: 0,
            ..MempoolLimits::default()
        };
        let mut pool = Mempool::new(limits);

        // Shared prevout so the replacement directly conflicts with the
        // original — both spend the same outpoint.
        let prev = OutPoint {
            txid: txid_of([0x11; 32]),
            vout: 0,
        };

        // Original: 100 vbytes, low fee rate (100 sat/vbyte).
        let original = Tx {
            version: 2,
            lock_time: 0,
            inputs: vec![TxIn {
                previous_output: prev,
                script_sig: Vec::new(),
                sequence: 0xFFFF_FFFD,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 1_000,
                script_pubkey: vec![0x51],
            }],
        };
        let original_txid = original.txid();
        let seated = pool.insert_entry(MempoolEntry::new(Arc::new(original), 100, 10_000, 1, 7));
        assert!(seated.is_ok(), "original must fit: {seated:?}");

        // Bystander: 850 vbytes, high fee rate (10_000 sat/vbyte), fills pool.
        let bystander = tx(8, Vec::new());
        let seated_by =
            pool.insert_entry(MempoolEntry::new(Arc::new(bystander), 850, 8_500_000, 1, 7));
        assert!(seated_by.is_ok(), "bystander must fit: {seated_by:?}");
        assert_eq!(pool.len(), 2);

        // Replacement: conflicts with the original (same prevout), higher
        // absolute fee (BIP125 rule 3: 15_000 > 10_000), higher fee rate
        // than the original (BIP125 rule 6: 150 > 100 sat/vbyte), but
        // 900 vbytes at a far lower fee rate than the bystander
        // (166 vs 10_000). After evicting the original (100 vbytes freed),
        // the pool has 850 + 900 = 1750 > 1000, so the trim evicts the
        // lowest-fee-rate entry — the replacement itself.
        let replacement = Tx {
            version: 2,
            lock_time: 0,
            inputs: vec![TxIn {
                previous_output: prev,
                script_sig: Vec::new(),
                sequence: 0xFFFF_FFFD,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 100,
                script_pubkey: vec![0x52],
            }],
        };
        let replacement_txid = replacement.txid();
        let result = pool.replace_transaction(
            crate::ReplacementCandidate::new(Arc::new(replacement), 900, 100_000, 1),
            2,
            7,
            4,
        );
        let Ok(result) = result else {
            panic!("the shed replacement committed; Err means nothing did: {result:?}");
        };
        assert!(
            result.is_shed(),
            "a replacement evicted by the trim must not report Accepted: {result:?}"
        );
        assert_eq!(
            result.mutation().removed_txids(),
            vec![original_txid, replacement_txid],
            "the record carries the conflict removal then the shed replacement"
        );
    }

    /// Every entry's four package totals, in entry-id order.
    fn totals(pool: &Mempool) -> Vec<(usize, u64, u64, u64, u64)> {
        let mut all = pool
            .entries
            .iter()
            .map(|(index, entry)| {
                (
                    index,
                    entry.ancestor_size,
                    entry.ancestor_fee,
                    entry.descendant_size,
                    entry.descendant_fee,
                )
            })
            .collect::<Vec<_>>();
        all.sort_unstable();
        all
    }

    /// Builds a pool whose spend graph has every shape the closure argument
    /// rests on: a chain, a fan-out, a fan-in, and an isolated entry.
    ///
    /// Returns the pool and the outpoint of each inserted transaction's first
    /// output so a caller can extend the graph further.
    fn graph_pool() -> Result<(Mempool, Vec<OutPoint>), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits::default());
        let mut outs = Vec::new();

        let add = |pool: &mut Mempool,
                   label: u8,
                   parents: Vec<OutPoint>|
         -> Result<OutPoint, MempoolError> {
            let transaction = tx(label, parents);
            let txid = transaction.txid();
            let vsize = 100 + u32::from(label);
            pool.insert_entry(MempoolEntry::new(
                Arc::new(transaction),
                vsize,
                u64::from(vsize) * 10,
                u64::from(label),
                1,
            ))?;
            Ok(OutPoint::new(txid, 0))
        };

        // root -> mid -> leaf: a chain.
        let root = add(&mut pool, 1, vec![OutPoint::default()])?;
        let mid = add(&mut pool, 2, vec![root])?;
        let leaf = add(&mut pool, 3, vec![mid])?;
        // root also funds a second child: a fan-out.
        let sibling = add(&mut pool, 4, vec![root])?;
        // one transaction spending two unrelated parents: a fan-in.
        let joined = add(&mut pool, 5, vec![leaf, sibling])?;
        // an entry connected to nothing.
        let lonely = add(&mut pool, 6, vec![OutPoint::default()])?;

        outs.extend([root, mid, leaf, sibling, joined, lonely]);
        Ok((pool, outs))
    }

    /// The incremental update must land on exactly what a full recompute would.
    ///
    /// `insert_entry` and `remove_entries` now refresh only the entries a change
    /// can have touched. That is an argument about the spend graph, so this
    /// checks it against the implementation that made no argument and simply
    /// recomputed everything: run the incremental path, then run the full
    /// recompute, and assert nothing moved.
    #[test]
    fn incremental_metadata_matches_the_full_recompute() -> Result<(), MempoolError> {
        let (mut pool, _outs) = graph_pool()?;

        let incremental = totals(&pool);
        pool.recompute_all_metadata();
        assert_eq!(
            incremental,
            totals(&pool),
            "incremental insert metadata diverged from the full recompute"
        );
        Ok(())
    }

    /// The same, after a removal that leaves surviving relatives behind.
    ///
    /// Every entry in the fixture is removed in turn, from a fresh pool each
    /// time, rather than one chosen entry. Each victim exercises a different
    /// shape: removing the middle of the chain leaves a parent that must forget
    /// descendants and a child that must forget an ancestor, and removing
    /// `leaf` takes the fan-in `joined` with it while `sibling` — `joined`'s
    /// *other* parent — survives and has to drop it from its descendant totals.
    /// That last one is not reachable by removing any single entry the closure
    /// names directly, and is the case a chosen victim is most likely to miss.
    ///
    /// The victim is addressed by entry id, which is the slab index and so
    /// follows insertion order. An earlier revision picked it out of
    /// `pool.by_txid`, a `HashMap` whose iteration order is randomized per
    /// process: the test removed a different entry on every run, and under a
    /// mutation that took the closure after the removal instead of before it,
    /// it went red in only 36 of 60 runs.
    #[test]
    fn incremental_metadata_matches_the_full_recompute_after_removals() -> Result<(), MempoolError>
    {
        for victim in 0..6_u32 {
            let (mut pool, _outs) = graph_pool()?;
            let removed = pool.remove_entry_and_descendants(victim);
            assert!(
                !removed.is_empty(),
                "entry {victim} must be present in the fixture"
            );

            let incremental = totals(&pool);
            pool.recompute_all_metadata();
            assert_eq!(
                incremental,
                totals(&pool),
                "incremental removal metadata diverged from the full recompute \
                 after removing entry {victim}"
            );
        }
        Ok(())
    }

    /// The eviction path is a `remove_entries` caller nothing else drives.
    ///
    /// `insert_entry` calls `enforce_size_limit` when an acceptance puts the
    /// pool over `max_total_bytes`, and that removes packages the caller never
    /// named. The refresh has to leave both the package totals and the priority
    /// index in the state a full rebuild would, from inside the insertion that
    /// triggered it.
    #[test]
    fn eviction_during_insertion_leaves_metadata_a_rebuild_agrees_with() -> Result<(), MempoolError>
    {
        let limits = MempoolLimits {
            max_total_bytes: 400,
            ..MempoolLimits::default()
        };
        let mut pool = Mempool::new(limits);

        let root = tx(31, vec![OutPoint::default()]);
        let root_out = OutPoint::new(root.txid(), 0);
        pool.insert_entry(MempoolEntry::new(Arc::new(root), 100, 500, 0, 1))?;
        let child = tx(32, vec![root_out]);
        let child_out = OutPoint::new(child.txid(), 0);
        pool.insert_entry(MempoolEntry::new(Arc::new(child), 100, 9_000, 1, 1))?;
        pool.insert_entry(MempoolEntry::new(
            Arc::new(tx(33, vec![child_out])),
            100,
            100_000,
            2,
            1,
        ))?;
        pool.insert_entry(MempoolEntry::new(
            Arc::new(tx(34, vec![OutPoint::default()])),
            100,
            200,
            3,
            1,
        ))?;
        pool.insert_entry(MempoolEntry::new(
            Arc::new(tx(35, vec![OutPoint::default()])),
            100,
            300,
            4,
            1,
        ))?;
        assert!(
            pool.len() < 5,
            "the fixture must actually cross the size limit"
        );

        let incremental = totals(&pool);
        let index = pool.pareto.top_n(pool.pareto.len()).collect::<Vec<_>>();
        pool.recompute_all_metadata();
        assert_eq!(
            incremental,
            totals(&pool),
            "eviction left package totals a full recompute disagrees with"
        );
        assert_eq!(
            index,
            pool.pareto.top_n(pool.pareto.len()).collect::<Vec<_>>(),
            "eviction left a stale priority index behind"
        );
        Ok(())
    }

    /// The running totals must survive every mutation, not just insertion.
    ///
    /// `total_vsize` and `aggregate_fees` each guard themselves with a
    /// `debug_assert` against a fold of `entries`, but a guard only fires when
    /// something calls it. `total_vsize` is called by `insert_entry` on every
    /// acceptance, so its bookkeeping was covered by accident; `aggregate_fees`
    /// is only reached through `stats`, and deleting the fee bookkeeping in
    /// *both* the removal path and `prioritise` turned nothing red. This calls
    /// both accessors after each kind of mutation, and compares against an
    /// independent fold so the check survives a release build where the
    /// `debug_assert`s are compiled out.
    #[test]
    fn running_totals_track_inserts_removals_and_prioritise() -> Result<(), MempoolError> {
        fn folded(pool: &Mempool) -> (u64, u64) {
            pool.entries
                .iter()
                .fold((0_u64, 0_u64), |(size, fee), (_, entry)| {
                    (
                        size.saturating_add(u64::from(entry.vsize)),
                        fee.saturating_add(entry.fee),
                    )
                })
        }
        fn check(pool: &Mempool, stage: &str) {
            let (size, fee) = folded(pool);
            assert_eq!(pool.total_vsize(), size, "vsize total wrong after {stage}");
            assert_eq!(pool.aggregate_fees(), fee, "fee total wrong after {stage}");
            let stats = pool.stats();
            assert_eq!(stats.bytes, size, "stats.bytes wrong after {stage}");
            assert_eq!(stats.total_fee, fee, "stats.total_fee wrong after {stage}");
        }

        let (mut pool, outs) = graph_pool()?;
        check(&pool, "inserts");

        // Addressed through the fixture's own handles, in insertion order.
        // `pool.by_txid` is a `HashMap`, so picking from it would choose a
        // different subject on every run — see
        // `incremental_metadata_matches_the_full_recompute_after_removals`.
        let Some(root) = outs.first().map(|out| out.txid) else {
            panic!("fixture must hold entries");
        };
        pool.prioritise(root, 250_000)
            .expect("prioritise up must apply");
        check(&pool, "a positive fee delta");

        pool.prioritise(root, -100_000)
            .expect("prioritise down must apply");
        check(&pool, "a negative fee delta");

        // `mid`: removing it takes the rest of the chain with it and leaves
        // both a surviving parent and an unrelated entry behind.
        let Some(victim_txid) = outs.get(1).map(|out| out.txid) else {
            panic!("fixture must hold a second entry");
        };
        let removed = pool.remove_by_txid(&victim_txid);
        assert!(!removed.is_empty(), "the victim must actually be removed");
        check(&pool, "a removal");

        pool.clear();
        check(&pool, "clear");
        Ok(())
    }

    /// Bumping a transaction's fee must reindex the transactions it drags with it.
    ///
    /// Before the refresh replaced the hand-applied delta loops, `prioritise`
    /// updated each descendant's `ancestor_fee` and then never reindexed it, so
    /// the descendant kept the priority key it had before its ancestor was
    /// bumped. Comparing the index against a full rebuild is what catches that:
    /// the totals were already right, only the keys derived from them were
    /// stale.
    #[test]
    fn prioritise_reindexes_the_descendants_it_lifts() -> Result<(), MempoolError> {
        let (mut pool, outs) = graph_pool()?;

        // Lift the chain root, which every entry in the chain descends from.
        let Some(txid) = outs.first().map(|out| out.txid) else {
            panic!("fixture must hold entries");
        };
        pool.prioritise(txid, 5_000_000)
            .expect("prioritise must apply");

        let after_prioritise = pool.pareto.top_n(pool.pareto.len()).collect::<Vec<_>>();
        let totals_after = totals(&pool);
        pool.recompute_all_metadata();
        assert_eq!(
            totals_after,
            totals(&pool),
            "prioritise left package totals a full recompute disagrees with"
        );
        assert_eq!(
            after_prioritise,
            pool.pareto.top_n(pool.pareto.len()).collect::<Vec<_>>(),
            "prioritise left stale priority keys behind"
        );
        Ok(())
    }

    /// A transaction can arrive after something that already spends its outputs.
    ///
    /// The closure is taken after the entry is put in the spend indexes for
    /// exactly this reason: taken before, the pre-existing child would not be
    /// reachable and would keep ancestor totals that no longer count its new
    /// parent.
    #[test]
    fn inserting_a_parent_after_its_child_refreshes_the_child() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits::default());

        let parent = tx(11, vec![OutPoint::default()]);
        let parent_out = OutPoint::new(parent.txid(), 0);
        let child = tx(12, vec![parent_out]);

        // Child first: at this point it has no in-mempool ancestor.
        pool.insert_entry(MempoolEntry::new(Arc::new(child), 100, 1_000, 0, 1))?;
        // Then the parent it spends from.
        pool.insert_entry(MempoolEntry::new(Arc::new(parent), 200, 4_000, 1, 1))?;

        let incremental = totals(&pool);
        pool.recompute_all_metadata();
        assert_eq!(
            incremental,
            totals(&pool),
            "a child inserted before its parent kept stale ancestor totals"
        );
        Ok(())
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

#[cfg(test)]
#[allow(clippy::expect_used)]
mod spend_index_tests {
    use alloc::sync::Arc;
    use alloc::vec::Vec;

    use bitcoin_rs_primitives::{Hash256, OutPoint, Tx, TxIn, TxOut};

    use super::*;

    /// Native txid for a raw 32-byte fixture id.
    fn txid_of(bytes: [u8; 32]) -> Txid {
        Txid::from(Hash256::from_le_bytes(&bytes))
    }

    fn tx_with(inputs: &[OutPoint], outputs: u32, tag: u64) -> Tx {
        Tx {
            version: 2,
            lock_time: 0,
            inputs: inputs
                .iter()
                .map(|previous_output| TxIn {
                    previous_output: *previous_output,
                    script_sig: Vec::new(),
                    sequence: 0xFF_FF_FF_FF,
                    witness: Vec::new(),
                })
                .collect(),
            outputs: (0..outputs)
                .map(|vout| TxOut {
                    value: 10_000_u64
                        .saturating_add(u64::from(vout))
                        .saturating_add(tag.saturating_mul(1_000)),
                    script_pubkey: alloc::vec![0x51],
                })
                .collect(),
        }
    }

    /// ```text
    ///   root ──vout 0──> child_a ──vout 0──> child_c
    ///        ──vout 1──> child_b
    ///        ──vout 2──> child_b
    /// ```
    ///
    /// `child_b` spends **two of the root's outputs**, so walking the index
    /// reaches it twice and a missing dedup shows up as a repeat. Nothing in a
    /// fixture where each child spends one output can catch that.
    fn graph_pool() -> (Mempool, Txid) {
        let confirmed = OutPoint::new(txid_of([7_u8; 32]), 0);
        let root = tx_with(&[confirmed], 3, 1);
        let root_txid = root.txid();
        let child_a = tx_with(&[OutPoint::new(root_txid, 0)], 1, 2);
        let child_a_txid = child_a.txid();
        let child_b = tx_with(
            &[OutPoint::new(root_txid, 1), OutPoint::new(root_txid, 2)],
            1,
            3,
        );
        let child_c = tx_with(&[OutPoint::new(child_a_txid, 0)], 1, 4);

        let mut pool = Mempool::new(MempoolLimits::default());
        for tx in [root, child_a, child_b, child_c] {
            let entry = MempoolEntry::new(Arc::new(tx), 100, 10_000, 1, 7);
            let Ok(_id) = pool.insert_entry(entry) else {
                panic!("mempool insert failed while building the fixture");
            };
        }
        (pool, root_txid)
    }

    #[test]
    fn the_cached_txid_matches_a_recomputation() {
        let (pool, _root_txid) = graph_pool();
        for (_id, entry) in &pool.entries {
            assert_eq!(
                entry.txid,
                entry.tx.txid(),
                "the entry's cached txid drifted from its transaction"
            );
        }
    }

    #[test]
    fn spender_txids_matches_a_scan_of_every_entrys_inputs() {
        let (pool, _root_txid) = graph_pool();

        let mut spenders_seen = 0_usize;
        for (index, entry) in &pool.entries {
            let Ok(id) = EntryId::try_from(index) else {
                panic!("entry index {index} does not fit an EntryId");
            };

            // The scan the index replaces, written out rather than reused.
            let mut expected: Vec<Txid> = Vec::new();
            for (_other_index, candidate) in &pool.entries {
                if candidate
                    .tx
                    .inputs
                    .iter()
                    .any(|input| input.previous_output.txid == entry.txid)
                {
                    expected.push(candidate.tx.txid());
                }
            }
            expected.sort_unstable();
            spenders_seen = spenders_seen.saturating_add(expected.len());

            let mut actual = pool.spender_txids(id);
            actual.sort_unstable();
            assert_eq!(
                actual, expected,
                "spender_txids diverged from the scan for {}",
                entry.txid
            );
        }

        assert_eq!(
            spenders_seen, 3,
            "the fixture must exercise spenders: root has 2, child_a has 1"
        );
    }

    #[test]
    fn spender_txids_includes_an_out_of_range_prevout_inserted_before_its_parent() {
        let confirmed = OutPoint::new(txid_of([8_u8; 32]), 0);
        let parent = tx_with(&[confirmed], 1, 10);
        let parent_txid = parent.txid();
        let child = tx_with(&[OutPoint::new(parent_txid, u32::MAX)], 1, 11);
        let child_txid = child.txid();
        let mut pool = Mempool::new(MempoolLimits::default());

        let child_entry = MempoolEntry::new(Arc::new(child), 100, 10_000, 1, 7);
        assert!(
            pool.insert_entry(child_entry).is_ok(),
            "child insertion failed"
        );
        let parent_entry = MempoolEntry::new(Arc::new(parent), 100, 10_000, 1, 7);
        assert!(
            pool.insert_entry(parent_entry).is_ok(),
            "parent insertion failed"
        );
        let parent_id = pool
            .entry_id_by_txid(&parent_txid)
            .expect("parent id resolves");

        assert_eq!(pool.spender_txids(parent_id), vec![child_txid]);
    }

    #[test]
    fn a_transaction_reached_through_two_outputs_is_reported_once() {
        let (pool, root_txid) = graph_pool();
        let Some(root_id) = pool.entry_id_by_txid(&root_txid) else {
            panic!("root missing from the fixture pool");
        };
        let spenders = pool.spender_txids(root_id);
        let mut deduped = spenders.clone();
        deduped.sort_unstable();
        deduped.dedup();
        assert_eq!(
            spenders.len(),
            deduped.len(),
            "child_b spends two of the root's outputs and must still appear once"
        );
        assert_eq!(spenders.len(), 2, "the root has two distinct spenders");
    }

    #[test]
    fn spender_txids_is_empty_once_the_spenders_are_gone() {
        let (mut pool, root_txid) = graph_pool();
        let Some(root_id) = pool.entry_id_by_txid(&root_txid) else {
            panic!("root missing from the fixture pool");
        };
        let removed = pool.remove_entry_and_descendants(root_id);
        assert!(!removed.is_empty());
        // The root left with its descendants, so nothing is left to spend it.
        assert!(pool.entry_id_by_txid(&root_txid).is_none());
        assert!(pool.is_empty(), "the fixture is a single connected package");
    }
}

#[cfg(test)]
mod dynamic_memory_usage_tests {
    use alloc::sync::Arc;

    use bitcoin_rs_primitives::{Hash256, OutPoint, Tx, TxIn, TxOut};

    use super::*;

    fn tx_with(script_len: usize, tag: u8) -> Tx {
        Tx {
            version: 2,
            lock_time: 0,
            inputs: alloc::vec![TxIn {
                previous_output: OutPoint::new(Txid::from(Hash256::from_le_bytes(&[tag; 32])), 0,),
                script_sig: Vec::new(),
                sequence: u32::MAX,
                witness: Vec::new(),
            }],
            outputs: alloc::vec![TxOut {
                value: 10_000,
                script_pubkey: alloc::vec![0x51; script_len],
            }],
        }
    }

    fn pool_with(count: u8, script_len: usize) -> Mempool {
        let mut pool = Mempool::new(MempoolLimits {
            max_total_bytes: 0,
            ..MempoolLimits::default()
        });
        for tag in 0..count {
            let entry = MempoolEntry::new(Arc::new(tx_with(script_len, tag)), 100, 10_000, 1, 7);
            let Ok(_id) = pool.insert_entry(entry) else {
                panic!("fixture insert failed");
            };
        }
        pool
    }

    #[test]
    fn an_empty_pool_reports_no_transaction_memory() {
        let pool = Mempool::new(MempoolLimits::default());
        // Only whatever the empty containers hold, which for unallocated ones is
        // nothing. The point is that it does not report a phantom footprint.
        assert_eq!(pool.dynamic_memory_usage(), 0);
    }

    #[test]
    fn usage_is_a_different_quantity_from_the_vsize_sum() {
        let pool = pool_with(4, 64);
        let stats = pool.stats();
        let usage = pool.dynamic_memory_usage();

        assert!(usage > 0);
        assert_ne!(
            usage, stats.bytes,
            "reporting `usage` as the vsize sum is the defect this replaces"
        );
        assert!(
            usage > stats.bytes,
            "holding a transaction costs more than its virtual size: {usage} vs {}",
            stats.bytes
        );
    }

    #[test]
    fn usage_grows_with_the_transactions_it_holds() {
        let small = pool_with(4, 64).dynamic_memory_usage();
        let more_entries = pool_with(8, 64).dynamic_memory_usage();
        let bigger_scripts = pool_with(4, 4_096).dynamic_memory_usage();

        assert!(more_entries > small, "{more_entries} vs {small}");
        assert!(
            bigger_scripts > small,
            "script bytes are held too: {bigger_scripts} vs {small}"
        );
    }

    /// Clearing releases the payload. It does not release the arena.
    #[test]
    fn usage_falls_when_the_pool_is_cleared() {
        let mut pool = pool_with(4, 64);
        let before = pool.dynamic_memory_usage();
        pool.clear();
        let after = pool.dynamic_memory_usage();
        assert!(after < before, "{after} vs {before}");
    }

    /// A grown-then-emptied pool still holds its arena, and still says so.
    ///
    /// `slab::Slab` keeps its backing allocation across removals and across
    /// `clear`; nothing here hands it back. Charging the arena from `len()`
    /// therefore reported that retained memory as **zero** at exactly the
    /// moment an operator reads `usage` to find out where the memory went --
    /// a pool that peaked at a million transactions and then drained answers
    /// "nothing", while the process RSS says otherwise.
    ///
    /// The bound below is the arena alone: after `clear` there are no live
    /// entries, so every other term is zero and what remains is the arena or
    /// nothing.
    #[test]
    fn the_arena_is_charged_after_the_pool_is_cleared() {
        use core::mem::size_of;

        let mut pool = pool_with(64, 64);
        pool.clear();

        let capacity = u64::try_from(pool.entries.capacity()).unwrap_or(0);
        assert!(
            capacity > 0,
            "the fixture must leave a grown arena behind, or this proves nothing"
        );
        let arena = capacity.saturating_mul(u64::try_from(size_of::<MempoolEntry>()).unwrap_or(0));

        let cleared = pool.dynamic_memory_usage();
        // Strictly above the arena, not merely at it: the txid map is a hash
        // map and keeps its capacity across `clear` for the same reason the
        // slab does, so both retentions have to be counted or this fails.
        assert!(
            cleared > arena,
            "the retained arena and txid map must both be counted: {cleared} vs {arena}"
        );

        // Against a pool that never grew, which is the difference the old
        // accounting erased: both have no live entries, and only one of them is
        // holding memory.
        let fresh = Mempool::new(MempoolLimits {
            max_total_bytes: 0,
            ..MempoolLimits::default()
        })
        .dynamic_memory_usage();
        assert_eq!(fresh, 0, "a pool that never grew holds nothing");
        assert!(
            cleared > fresh,
            "a drained pool and a fresh one must not report the same footprint"
        );
    }

    /// The priority index is charged for both copies of every entry.
    ///
    /// `ParetoFront` stores each entry in an ordered set *and* in a map from
    /// id, because a removal is given an id and the set is keyed by priority.
    /// Charging one `EntryId` per transaction, as this did, counted four bytes
    /// where the index holds two whole keys -- an under-report on every
    /// non-empty pool, growing with the pool.
    ///
    /// A lower bound, not a measurement: a B-tree leaves its nodes partly
    /// filled, so the real footprint is above this and depends on insertion
    /// order. The bound is what a test can state; that it scales with what is
    /// stored is what the old term did not do.
    #[test]
    fn the_priority_index_is_charged_for_both_of_its_key_collections() {
        use core::mem::size_of;

        const COUNT: u64 = 32;

        let mut pool = pool_with(u8::try_from(COUNT).unwrap_or(0), 64);
        let index = pool.pareto.dynamic_memory_usage();

        // The floor on what two key collections cost lives in `pareto.rs`,
        // beside the private key type it is stated in terms of. This is the
        // half that belongs here: that the pool charges what the index says.
        let one_id_each = COUNT.saturating_mul(u64::try_from(size_of::<EntryId>()).unwrap_or(0));
        assert!(
            index > one_id_each.saturating_mul(4),
            "the index holds two keys per entry, not one id: {index} vs {one_id_each}"
        );

        // What the pool's total actually attributes to the index: empty the
        // index and leave everything else standing. Asserting only that the
        // total is *at least* the index term would pass while the total was
        // still computing its own figure from the entry count and ignoring the
        // index entirely, which is the term this replaces.
        let with_index = pool.dynamic_memory_usage();
        pool.pareto = ParetoFront::new();
        let without_index = pool.dynamic_memory_usage();
        assert_eq!(
            with_index.saturating_sub(without_index),
            index,
            "the pool must charge the index what the index says it costs"
        );
    }
}

#[cfg(test)]
mod entry_overhead_tests {
    use alloc::sync::Arc;

    use bitcoin_rs_primitives::Tx;

    use super::*;

    /// A transaction that owns no heap of its own: no inputs, no outputs, so
    /// `transaction_heap_usage` is just the struct. What is left in the estimate
    /// for a pool of these is the per-entry accounting, which is what this pins.
    fn empty_tx(tag: u32) -> Tx {
        Tx {
            version: 2,
            // The only thing distinguishing them, so they get distinct txids.
            lock_time: tag,
            inputs: alloc::vec::Vec::new(),
            outputs: alloc::vec::Vec::new(),
        }
    }

    #[test]
    fn usage_counts_the_entry_itself_not_only_the_transaction() {
        use core::mem::size_of;

        let mut pool = Mempool::new(MempoolLimits {
            max_total_bytes: 0,
            ..MempoolLimits::default()
        });
        let count = 8_u32;
        for tag in 0..count {
            let entry = MempoolEntry::new(Arc::new(empty_tx(tag)), 100, 10_000, 1, 7);
            let Ok(_id) = pool.insert_entry(entry) else {
                panic!("fixture insert failed");
            };
        }

        let live = u64::from(count);
        let entry_bytes = u64::try_from(size_of::<MempoolEntry>()).unwrap_or(0);
        let tx_bytes = u64::try_from(size_of::<Tx>()).unwrap_or(0);

        // These transactions have no inputs, so the funding and spending indexes
        // are empty and cannot make up the difference. Dropping the per-entry
        // term leaves the estimate below this bound.
        assert!(
            pool.dynamic_memory_usage()
                >= live.saturating_mul(entry_bytes.saturating_add(tx_bytes)),
            "usage {} is below {live} entries of {entry_bytes} plus their transactions",
            pool.dynamic_memory_usage()
        );
    }
}
