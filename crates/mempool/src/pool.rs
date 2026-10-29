use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::{Bound, RangeInclusive};

use bitcoin_rs_primitives::{Block, Hash256, OutPoint, Tx, TxIn, TxOut, Txid, Wtxid};

#[cfg(test)]
use bitcoin_rs_primitives::{Amount, LockTime, Script, Sequence, Witness};
use hashbrown::{HashMap, HashSet};
use sha2::{Digest, Sha256};
use smallvec::SmallVec;
use thiserror::Error;

use crate::chunk_index::{ChunkIndex, ComponentState, MemberFacts, ProjectedChunks};
use crate::fee_estimator::{FeeEstimator, FeeRate};
use crate::mutation::{
    MutationChange, MutationOutcome, MutationResult, MutationSequence, RemovalReason,
};
use crate::policy::MEMPOOL_EXPIRY_SECS;
use crate::{EntryId, MempoolEntry, MempoolLimits, MempoolPolicySnapshot, PolicyError};
use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(test)]
mod chunk_order_tests;
pub(crate) mod fee_policy;
pub(crate) mod package;

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
    pub hash: Hash256,
}

impl ScriptHash {
    #[must_use]
    pub fn from_script(script: &[u8]) -> Self {
        Self {
            hash: Hash256::from_le_bytes(&Sha256::digest(script).into()),
        }
    }

    #[must_use]
    pub const fn from_byte_array(bytes: [u8; 32]) -> Self {
        Self {
            hash: Hash256::from_le_bytes(&bytes),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum MempoolError {
    #[error(transparent)]
    FeeDiagram(#[from] crate::FeeDiagramError),
    #[error("mempool changed during policy preparation")]
    StalePolicy,
    #[error("transaction already exists in mempool")]
    DuplicateTransaction,
    #[error("mempool entry id space exhausted")]
    TooManyEntries,
    #[error("bad-txns-spends-conflicting-tx")]
    EvictedParent,
    #[error(transparent)]
    Policy(#[from] PolicyError),
    #[error("mempool full")]
    Full,
    #[error("mempool spending index is inconsistent")]
    InconsistentSpendingIndex,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PrioritiseError {
    #[error("fee delta would overflow the persistent overlay")]
    FeeDeltaOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrioritisedTransaction {
    pub txid: Txid,
    pub fee_delta: i64,
    pub in_mempool: bool,
    pub modified_fee: Option<i128>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockRemovalPlan {
    pub removals: Vec<(EntryId, RemovalReason)>,
    pub fee_deltas_cleared: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct FeeRateAggregate {
    count: u64,
    vsize: u64,
}

#[derive(Debug)]
pub struct Mempool {
    entries: EntryArena,
    derived: Derived,
    graph_steps: AtomicU64,
    pub limits: MempoolLimits,

    fee_deltas: HashMap<Txid, i64>,
    fee_delta_sequence: u64,
    estimator: FeeEstimator,
    mempool_sequence: u64,
    pub(crate) accepted_capture: Option<Vec<(Txid, Arc<Tx>)>>,
    rolling_min_fee: parking_lot::Mutex<crate::rolling_min_fee::RollingMinFee>,
    rolling_epoch: u64,
}

#[derive(Debug, Default)]
struct Derived {
    by_txid: HashMap<Txid, IndexedEntry>,
    funding: std::collections::BTreeSet<(ScriptHash, EntryId)>,
    spending: std::collections::BTreeSet<(SpendingKey, EntryId)>,
    by_time: std::collections::BTreeSet<(u64, EntryId)>,
    by_wtxid: HashMap<Wtxid, EntryId>,
    unbroadcast: std::collections::BTreeSet<Wtxid>,
    components: Vec<ComponentSummary>,
    free_components: Vec<u32>,
    chunks: ChunkIndex,
    total_vsize: u64,
    total_fee: u128,
    fee_rate_aggregates: std::collections::BTreeMap<u64, FeeRateAggregate>,
}

impl Derived {
    fn account_remove(&mut self, id: EntryId, entry: &MempoolEntry) {
        self.total_vsize = self.total_vsize.saturating_sub(u64::from(entry.vsize));
        self.total_fee -= u128::from(entry.fee);
        match self.fee_rate_aggregates.entry(entry.fee_rate) {
            std::collections::btree_map::Entry::Occupied(mut occupied) => {
                let aggregate = occupied.get_mut();
                if aggregate.count > 1 {
                    debug_assert!(aggregate.vsize >= u64::from(entry.vsize));
                    aggregate.count -= 1;
                    aggregate.vsize -= u64::from(entry.vsize);
                } else {
                    debug_assert_eq!(aggregate.vsize, u64::from(entry.vsize));
                    occupied.remove();
                }
            }
            std::collections::btree_map::Entry::Vacant(_) => {
                debug_assert!(
                    false,
                    "fee-rate multiset drifted: removed a rate with no tracked count"
                );
            }
        }
        self.by_txid.remove(&entry.txid);
        self.by_wtxid.remove(&entry.wtxid);
        let _ = self.by_time.remove(&(entry.time, id));
        self.unbroadcast.remove(&entry.wtxid);
        for output in &entry.tx.outputs {
            let _ = self
                .funding
                .remove(&(ScriptHash::from_script(&output.script_pubkey), id));
        }
        for input in &entry.tx.inputs {
            let _ = self
                .spending
                .remove(&(SpendingKey::from(input.previous_output), id));
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct IndexedEntry {
    id: EntryId,
    admitted_sequence: u64,
}
#[derive(Debug)]
struct LiveEntry {
    component: u32,
    links: GraphLinks,
    entry: MempoolEntry,
}
#[derive(Debug, Default)]
struct GraphLinks {
    parents: Vec<EntryId>,
    children: Vec<EntryId>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ComponentSummary {
    member_count: u32,
    weight: u64,
}

#[derive(Debug)]
struct EntryArena {
    slots: Vec<Option<LiveEntry>>,
    free: Vec<usize>,
    live: usize,
}

fn slot_index(id: EntryId) -> Option<usize> {
    usize::try_from(id).ok()
}

impl EntryArena {
    fn new() -> Self {
        Self {
            slots: Vec::new(),
            free: Vec::new(),
            live: 0,
        }
    }

    fn insert(&mut self, entry: MempoolEntry, component: u32, links: GraphLinks) -> usize {
        self.live += 1;
        let live = LiveEntry {
            component,
            links,
            entry,
        };
        if let Some(index) = self.free.pop() {
            let Some(slot) = self.slots.get_mut(index) else {
                panic!("vacancy stack names a live slot");
            };
            *slot = Some(live);
            return index;
        }
        self.slots.push(Some(live));
        self.slots.len() - 1
    }

    fn remove(&mut self, id: EntryId) -> Option<LiveEntry> {
        let index = slot_index(id)?;
        let slot = self.slots.get_mut(index)?;
        let live = slot.take()?;
        self.live -= 1;
        self.free.push(index);
        Some(live)
    }

    fn get(&self, id: EntryId) -> Option<&MempoolEntry> {
        self.slot(id).map(|live| &live.entry)
    }

    fn get_mut(&mut self, id: EntryId) -> Option<&mut MempoolEntry> {
        self.slot_mut(id).map(|live| &mut live.entry)
    }

    fn slot(&self, id: EntryId) -> Option<&LiveEntry> {
        self.slots.get(slot_index(id)?)?.as_ref()
    }

    fn slot_mut(&mut self, id: EntryId) -> Option<&mut LiveEntry> {
        self.slots.get_mut(slot_index(id)?)?.as_mut()
    }

    fn contains(&self, id: EntryId) -> bool {
        self.slot(id).is_some()
    }

    fn len(&self) -> usize {
        self.live
    }

    fn is_empty(&self) -> bool {
        self.live == 0
    }

    fn capacity(&self) -> usize {
        self.slots.len()
    }

    fn vacant_key(&self) -> usize {
        self.free.last().map_or(self.slots.len(), |&index| index)
    }

    fn clear(&mut self) {
        for slot in &mut self.slots {
            *slot = None;
        }
        self.free.clear();
        self.free.extend((0..self.slots.len()).rev());
        self.live = 0;
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (usize, &MempoolEntry)> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| slot.as_ref().map(|live| (index, &live.entry)))
    }

    fn iter_links(&self) -> impl Iterator<Item = &GraphLinks> {
        self.slots
            .iter()
            .filter_map(|slot| slot.as_ref().map(|live| &live.links))
    }
}

#[derive(Debug, Default)]
struct VisitSet {
    words: Vec<u64>,
    members: Vec<EntryId>,
}

impl VisitSet {
    fn new() -> Self {
        Self::default()
    }

    fn test(&self, id: EntryId) -> bool {
        let Some(index) = slot_index(id) else {
            return false;
        };
        let Some(&word) = self.words.get(index / 64) else {
            return false;
        };
        word & (1_u64 << (index % 64)) != 0
    }

    fn insert(&mut self, id: EntryId) -> bool {
        let Some(index) = slot_index(id) else {
            return false;
        };
        if index / 64 >= self.words.len() {
            self.words.resize(index / 64 + 1, 0);
        }
        let bit = 1_u64 << (index % 64);
        if self.words[index / 64] & bit != 0 {
            return false;
        }
        self.words[index / 64] |= bit;
        self.members.push(id);
        true
    }

    fn members(&self) -> &[EntryId] {
        &self.members
    }
}

trait VisitMarks {
    fn insert(&mut self, id: EntryId) -> bool;
}

impl VisitMarks for VisitSet {
    fn insert(&mut self, id: EntryId) -> bool {
        Self::insert(self, id)
    }
}

impl VisitMarks for HashSet<EntryId> {
    fn insert(&mut self, id: EntryId) -> bool {
        Self::insert(self, id)
    }
}

#[derive(Debug, Default)]
struct WalkSet {
    seen: SmallVec<[EntryId; 25]>,
}

impl WalkSet {
    fn new() -> Self {
        Self::default()
    }

    fn test(&self, id: EntryId) -> bool {
        self.seen.contains(&id)
    }

    fn len(&self) -> usize {
        self.seen.len()
    }
}

impl VisitMarks for WalkSet {
    fn insert(&mut self, id: EntryId) -> bool {
        if self.test(id) {
            return false;
        }
        self.seen.push(id);
        true
    }
}

pub(crate) struct PreparedInsert {
    pub(crate) entry: MempoolEntry,
}

#[derive(Clone, Copy, Debug)]
pub struct OutpointSpender<'a> {
    pub entry: &'a MempoolEntry,
    pub vin: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MempoolStats {
    pub txs: u64,
    pub bytes: u64,
    pub total_fee: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotEntry {
    pub tx: Arc<Tx>,
    pub txid: Txid,
    pub wtxid: Wtxid,
    pub vsize: u32,
    pub bip141_vsize: u32,
    pub size: u32,
    pub weight: u64,
    pub sigop_cost: u32,
    pub fee: u64,
    pub fee_delta: i64,
    pub time: u64,
    pub height: u32,
    pub ancestor_size: u64,
    pub ancestor_fee: u64,
    pub ancestor_fee_delta: i128,
    pub ancestors: Vec<u32>,
}

#[derive(Clone, Debug)]
pub struct MempoolMiningSnapshot {
    pub sequence: u64,
    pub fee_delta_sequence: u64,
    pub entries: Vec<SnapshotEntry>,
}

impl Mempool {
    #[must_use]
    pub fn new(limits: MempoolLimits) -> Self {
        Self {
            entries: EntryArena::new(),
            derived: Derived::default(),
            graph_steps: AtomicU64::new(0),
            limits,

            fee_deltas: HashMap::new(),
            fee_delta_sequence: 0,
            estimator: FeeEstimator::new(),
            mempool_sequence: 0,
            accepted_capture: None,
            rolling_min_fee: parking_lot::Mutex::new(
                crate::rolling_min_fee::RollingMinFee::default(),
            ),
            rolling_epoch: 0,
        }
    }

    pub fn clear(&mut self) -> MutationResult {
        let mut txids = Vec::with_capacity(self.entries.len());
        for (_id, entry) in self.entries.iter() {
            bitcoin_rs_consensus::trace::removed(|| {
                (
                    entry.txid.as_bytes().as_ptr(),
                    "unknown",
                    i32::try_from(entry.vsize).unwrap_or(i32::MAX),
                    i64::try_from(entry.fee).unwrap_or(i64::MAX),
                    entry.time,
                )
            });
            txids.push(entry.txid);
        }
        self.entries.clear();
        self.derived = Derived::default();
        self.graph_steps.store(0, Ordering::Relaxed);

        if !self.fee_deltas.is_empty() {
            self.fee_delta_sequence = MutationSequence::advance(self.fee_delta_sequence);
            self.fee_deltas.clear();
        }
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

    #[must_use]
    pub const fn sequence_number(&self) -> u64 {
        self.mempool_sequence
    }

    #[must_use]
    pub const fn fee_delta_sequence_number(&self) -> u64 {
        self.fee_delta_sequence
    }

    #[must_use]
    pub const fn min_relay_fee_sat_per_kvb(&self) -> u64 {
        self.limits.min_relay_fee_sat_per_kvb
    }

    #[must_use]
    pub fn min_fee_sat_per_kvb(&self, now: u64) -> u64 {
        let incremental = crate::policy::DEFAULT_INCREMENTAL_RELAY_FEE_SAT_PER_KVB;
        let rate = {
            let mut rolling = self.rolling_min_fee.lock();
            rolling.current(
                now,
                self.total_vsize(),
                self.limits.max_total_bytes,
                incremental,
            )
        };
        rate.max(self.limits.min_relay_fee_sat_per_kvb)
    }

    pub(crate) fn track_package_removed(&mut self, removed: u64) {
        if self.rolling_min_fee.lock().track_package_removed(removed) {
            self.rolling_epoch = MutationSequence::advance(self.rolling_epoch);
        }
    }

    const fn core_removal_reason(reason: RemovalReason) -> &'static str {
        match reason {
            RemovalReason::BlockInclusion => "block",
            RemovalReason::Conflict => "conflict",
            RemovalReason::Replaced | RemovalReason::Descendant => "replaced",
            RemovalReason::PolicyEviction => "sizelimit",
            RemovalReason::Expiry => "expiry",
            RemovalReason::Reorg => "reorg",
            RemovalReason::Clear => "unknown",
        }
    }

    fn push_change(
        &mut self,
        changes: &mut Vec<MutationChange>,
        txid: Txid,
        outcome: MutationOutcome,
    ) {
        self.mempool_sequence = MutationSequence::advance(self.mempool_sequence);
        changes.push(crate::mutation::change(&txid, outcome));
    }

    pub(crate) fn finish_mutation(&self, changes: Vec<MutationChange>) -> MutationResult {
        let sequence_base = MutationSequence::base(self.mempool_sequence, changes.len());
        MutationResult {
            changes,
            sequence_base,
        }
    }

    #[cfg(any(test, feature = "test-seam"))]
    pub fn insert_entry(
        &mut self,
        entry: MempoolEntry,
    ) -> Result<crate::mutation::MutationResult, MempoolError> {
        let inputs = self
            .capture_insertion(
                entry,
                crate::rbf::FeeEstimation::Estimate,
                crate::rbf::LimitEnforcement::Full,
            )
            .map_err(crate::RbfError::into_pool_error)?;
        let plan = match inputs.verify() {
            Ok(plan) => plan,
            Err(refusal) => {
                let (error, bump) = refusal.into_parts();
                if matches!(bump, Some(bump) if self.track_refused_trim(bump).is_err()) {
                    return Err(MempoolError::StalePolicy);
                }
                return Err(error.into_pool_error());
            }
        };
        self.commit_pool_change(plan)
            .map_err(crate::RbfError::into_pool_error)
    }

    pub(crate) fn validate_insert(
        &self,
        entry: MempoolEntry,
        excluded: &HashSet<EntryId>,
        enforcement: crate::rbf::LimitEnforcement,
    ) -> Result<PreparedInsert, MempoolError> {
        let prepared = self.prepare_insert(entry, excluded, enforcement)?;
        self.check_cluster_limits(&prepared.entry.tx, prepared.entry.policy_weight(), excluded)?;
        if excluded.is_empty() && u32::try_from(self.entries.vacant_key()).is_err() {
            return Err(MempoolError::TooManyEntries);
        }
        Ok(prepared)
    }

    fn prepare_insert(
        &self,
        mut entry: MempoolEntry,
        excluded: &HashSet<EntryId>,
        enforcement: crate::rbf::LimitEnforcement,
    ) -> Result<PreparedInsert, MempoolError> {
        let txid = entry.txid;
        let min_rate = self.limits.min_relay_fee_sat_per_kvb;
        entry.fee_delta = self.fee_deltas.get(&txid).copied().unwrap_or(0);
        if entry.vsize == 0 {
            return Err(PolicyError::InvalidVirtualSize.into());
        }
        let required = crate::rbf::required_fee(min_rate, entry.vsize)
            .map_err(|_| PolicyError::FeeArithmetic)?;
        if enforcement != crate::rbf::LimitEnforcement::Deferred && entry.modified_fee() < required
        {
            let modified_rate = entry.modified_fee() * 1_000 / i128::from(entry.vsize);
            return Err(PolicyError::BelowMinRelayFee {
                tx_rate: u64::try_from(modified_rate).unwrap_or(0),
                min_rate,
            }
            .into());
        }

        if self.derived.by_txid.contains_key(&txid) {
            return Err(MempoolError::DuplicateTransaction);
        }

        if entry.tx.inputs.iter().any(|input| {
            self.derived
                .by_txid
                .get(&input.previous_output.txid)
                .is_some_and(|indexed| excluded.contains(&indexed.id))
        }) {
            return Err(MempoolError::EvictedParent);
        }

        let ancestors = self.ancestor_ids_for_tx(&entry.tx);
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
        entry.ancestor_fee_delta = i128::from(entry.fee_delta);
        entry.descendant_size = u64::from(entry.vsize);
        entry.descendant_fee = entry.fee;
        entry.descendant_fee_delta = i128::from(entry.fee_delta);

        Ok(PreparedInsert { entry })
    }

    pub(crate) fn commit_insert(&mut self, prepared: PreparedInsert) -> MutationResult {
        let entry = prepared.entry;
        let txid = entry.txid;
        if let Some(capture) = &mut self.accepted_capture {
            capture.push((txid, Arc::clone(&entry.tx)));
        }
        let added_vsize = u64::from(entry.vsize);
        let added_fee = entry.fee;
        let parents = self.in_pool_parents(&entry.tx);
        let children = self.in_pool_children(txid);
        let component = self.merge_neighbour_components(&parents, &children, &entry);
        let index = self.entries.insert(entry, component, GraphLinks::default());
        let Ok(id) = EntryId::try_from(index) else {
            panic!("validate_insert accepted an entry id that does not fit u32");
        };
        for parent in &parents {
            if let Some(slot) = self.entries.slot_mut(*parent) {
                let position = slot
                    .links
                    .children
                    .binary_search(&id)
                    .unwrap_or_else(|position| position);
                slot.links.children.insert(position, id);
            }
        }
        for child in &children {
            if let Some(slot) = self.entries.slot_mut(*child) {
                let position = slot
                    .links
                    .parents
                    .binary_search(&id)
                    .unwrap_or_else(|position| position);
                slot.links.parents.insert(position, id);
            }
        }
        if let Some(slot) = self.entries.slot_mut(id) {
            slot.links = GraphLinks { parents, children };
        }

        let mut changes = Vec::new();
        self.push_change(&mut changes, txid, MutationOutcome::Accepted);
        let admitted_sequence = self.mempool_sequence;
        self.account_insert(id, admitted_sequence);
        let affected = self.metadata_closure(&[id]);
        self.refresh_metadata(&affected);
        self.relinearize_from_seed(component, id);
        bitcoin_rs_consensus::trace::added(|| {
            (
                txid.as_bytes().as_ptr(),
                i32::try_from(added_vsize).unwrap_or(i32::MAX),
                i64::try_from(added_fee).unwrap_or(i64::MAX),
            )
        });
        self.finish_mutation(changes)
    }

    fn account_insert(&mut self, id: EntryId, admitted_sequence: u64) {
        let Some(entry) = self.entry(id) else {
            debug_assert!(false, "account_insert called for a missing entry");
            return;
        };
        let tx = Arc::clone(&entry.tx);
        let txid = entry.txid;
        let wtxid = entry.wtxid;
        let time = entry.time;
        let unbroadcast = entry.unbroadcast;
        let added_vsize = u64::from(entry.vsize);
        let added_fee = entry.fee;
        let added_fee_rate = entry.fee_rate;
        self.derived.total_vsize = self.derived.total_vsize.saturating_add(added_vsize);
        self.derived.total_fee += u128::from(added_fee);
        let aggregate = self
            .derived
            .fee_rate_aggregates
            .entry(added_fee_rate)
            .or_default();
        aggregate.count += 1;
        aggregate.vsize += added_vsize;
        self.derived.by_txid.insert(
            txid,
            IndexedEntry {
                id,
                admitted_sequence,
            },
        );
        self.derived.by_wtxid.insert(wtxid, id);
        self.derived.by_time.insert((time, id));
        if unbroadcast {
            self.derived.unbroadcast.insert(wtxid);
        }
        for output in &tx.outputs {
            self.derived
                .funding
                .insert((ScriptHash::from_script(&output.script_pubkey), id));
        }
        for input in &tx.inputs {
            self.derived
                .spending
                .insert((SpendingKey::from(input.previous_output), id));
        }
    }

    pub(crate) fn record_entry_arrival(&mut self, txid: Txid) {
        if let Some((fee_rate, height)) = self
            .entry_by_txid(&txid)
            .map(|entry| (entry.fee_rate, entry.height))
        {
            self.estimator.tx_entered(txid, fee_rate, height);
        }
    }

    fn in_pool_children(&self, txid: Txid) -> Vec<EntryId> {
        let start = (
            SpendingKey::from(OutPoint::new(txid, u32::MIN)),
            EntryId::MIN,
        );
        let end = (
            SpendingKey::from(OutPoint::new(txid, u32::MAX)),
            EntryId::MAX,
        );
        let mut children: Vec<EntryId> = self
            .derived
            .spending
            .range(start..=end)
            .map(|(_, child)| *child)
            .collect();
        children.sort_unstable();
        children.dedup();
        children
    }
    fn in_pool_parents(&self, tx: &Tx) -> Vec<EntryId> {
        let mut parents: Vec<EntryId> = tx
            .inputs
            .iter()
            .filter_map(|input| self.entry_id_by_txid(&input.previous_output.txid))
            .collect();
        parents.sort_unstable();
        parents.dedup();
        parents
    }

    fn merge_neighbour_components(
        &mut self,
        parents: &[EntryId],
        children: &[EntryId],
        entry: &MempoolEntry,
    ) -> u32 {
        let mut summary = ComponentSummary {
            member_count: 1,
            weight: entry.policy_weight(),
        };
        let mut base: Option<u32> = None;
        let mut merged: Vec<u32> = Vec::new();
        for neighbour in parents.iter().chain(children.iter()).copied() {
            let Some(neighbour_component) = self.component_id(neighbour) else {
                continue;
            };
            if merged.contains(&neighbour_component) {
                continue;
            }
            merged.push(neighbour_component);
            let absorbed = self
                .component_summary(neighbour_component)
                .copied()
                .unwrap_or_default();
            summary.member_count = summary.member_count.saturating_add(absorbed.member_count);
            summary.weight = summary.weight.saturating_add(absorbed.weight);
            let Some(base_component) = base else {
                base = Some(neighbour_component);
                continue;
            };
            let mut visited = WalkSet::new();
            let mut members = Vec::new();
            self.collect_component_members(neighbour, &mut visited, &mut members);
            for member in &members {
                if let Some(slot) = self.entries.slot_mut(*member) {
                    slot.component = base_component;
                }
            }
            if let Some(vacated) = self.component_summary_mut(neighbour_component) {
                *vacated = ComponentSummary::default();
            }
            self.free_component(neighbour_component);
        }
        let component = base.unwrap_or_else(|| self.alloc_component());
        if let Some(slot) = self.component_summary_mut(component) {
            *slot = summary;
        }
        component
    }

    fn component_id(&self, id: EntryId) -> Option<u32> {
        Some(self.entries.slot(id)?.component)
    }

    fn component_summary(&self, component: u32) -> Option<&ComponentSummary> {
        self.derived
            .components
            .get(usize::try_from(component).ok()?)
    }

    fn component_summary_mut(&mut self, component: u32) -> Option<&mut ComponentSummary> {
        self.derived
            .components
            .get_mut(usize::try_from(component).ok()?)
    }

    fn alloc_component(&mut self) -> u32 {
        self.derived.free_components.pop().unwrap_or_else(|| {
            self.derived.components.push(ComponentSummary::default());
            let id = u32::try_from(self.derived.components.len() - 1);
            match id {
                Ok(id) => id,
                Err(error) => panic!("component count exceeds the u32 entry-id space: {error}"),
            }
        })
    }

    fn free_component(&mut self, component: u32) {
        debug_assert!(
            self.component_summary(component)
                .is_some_and(|summary| *summary == ComponentSummary::default()),
            "freed a component that still reports members"
        );
        self.derived.chunks.forget(component);
        self.derived.free_components.push(component);
    }

    fn collect_component_members<M: VisitMarks>(
        &self,
        seed: EntryId,
        visited: &mut M,
        members: &mut Vec<EntryId>,
    ) {
        if !visited.insert(seed) {
            return;
        }
        members.push(seed);
        let mut frontier = vec![seed];
        while let Some(id) = frontier.pop() {
            self.graph_steps.fetch_add(1, Ordering::Relaxed);
            let Some(links) = self.links(id) else {
                continue;
            };
            for neighbour in links.parents.iter().chain(links.children.iter()).copied() {
                if visited.insert(neighbour) {
                    members.push(neighbour);
                    frontier.push(neighbour);
                }
            }
        }
    }

    fn links(&self, id: EntryId) -> Option<&GraphLinks> {
        Some(&self.entries.slot(id)?.links)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn contains_txid(&self, txid: &Txid) -> bool {
        self.derived.by_txid.contains_key(txid)
    }

    #[must_use]
    pub fn entry_by_txid(&self, txid: &Txid) -> Option<&MempoolEntry> {
        self.entry(self.entry_id_by_txid(txid)?)
    }

    pub(crate) fn set_unbroadcast(&mut self, wtxid: bitcoin_rs_primitives::Wtxid, pending: bool) {
        if let Some(&id) = self.derived.by_wtxid.get(&wtxid)
            && let Some(entry) = self.entry_mut(id)
        {
            entry.unbroadcast = pending;
            if pending {
                self.derived.unbroadcast.insert(wtxid);
            } else {
                self.derived.unbroadcast.remove(&wtxid);
            }
        }
    }

    #[must_use]
    pub fn transaction_by_txid(&self, txid: &Txid) -> Option<Arc<Tx>> {
        self.entry_by_txid(txid).map(|entry| Arc::clone(&entry.tx))
    }

    #[must_use]
    pub fn entry_id_by_txid(&self, txid: &Txid) -> Option<EntryId> {
        self.derived.by_txid.get(txid).map(|indexed| indexed.id)
    }

    #[must_use]
    pub fn entry_by_txid_at_sequence(&self, txid: &Txid, sequence: u64) -> Option<&MempoolEntry> {
        let indexed = self.derived.by_txid.get(txid)?;
        if indexed.admitted_sequence != sequence {
            return None;
        }
        self.entry(indexed.id)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub fn iter_txids(&self) -> Vec<Txid> {
        self.entries.iter().map(|(_id, entry)| entry.txid).collect()
    }

    #[cfg(test)]
    #[must_use]
    fn iter_replaceable_txids(&self) -> Vec<Txid> {
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
        self.derived.total_vsize
    }

    pub fn enforce_size_limit(&mut self, max_bytes: u64) -> Result<MutationResult, MempoolError> {
        let changes = crate::evict_lowest_fee_packages(self, max_bytes)?;
        Ok(self.finish_mutation(changes))
    }

    #[must_use]
    fn aggregate_fees(&self) -> u64 {
        u64::try_from(self.derived.total_fee).unwrap_or(u64::MAX)
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
            .saturating_mul(u64::try_from(size_of::<Option<LiveEntry>>()).unwrap_or(0));

        let transactions = self
            .entries
            .iter()
            .map(|(_index, entry)| transaction_heap_usage(&entry.tx))
            .fold(0_u64, u64::saturating_add);

        let by_txid = u64::try_from(self.derived.by_txid.capacity())
            .unwrap_or(u64::MAX)
            .saturating_mul(u64::try_from(size_of::<(Txid, IndexedEntry)>()).unwrap_or(0));
        let funding = u64::try_from(self.derived.funding.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(u64::try_from(size_of::<(ScriptHash, EntryId)>()).unwrap_or(0));
        let spending = u64::try_from(self.derived.spending.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(u64::try_from(size_of::<(SpendingKey, EntryId)>()).unwrap_or(0));
        let by_wtxid = u64::try_from(self.derived.by_wtxid.capacity())
            .unwrap_or(u64::MAX)
            .saturating_mul(u64::try_from(size_of::<(Wtxid, EntryId)>()).unwrap_or(0));
        let by_time = u64::try_from(self.derived.by_time.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(u64::try_from(size_of::<(u64, EntryId)>()).unwrap_or(0));
        let unbroadcast = u64::try_from(self.derived.unbroadcast.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(u64::try_from(size_of::<Wtxid>()).unwrap_or(0));
        let links = self.entries.iter_links().fold(0_u64, |total, link| {
            let payload = link
                .parents
                .capacity()
                .saturating_add(link.children.capacity());
            total.saturating_add(
                u64::try_from(payload)
                    .unwrap_or(u64::MAX)
                    .saturating_mul(u64::try_from(size_of::<EntryId>()).unwrap_or(0)),
            )
        });
        let components = u64::try_from(self.derived.components.capacity())
            .unwrap_or(u64::MAX)
            .saturating_mul(u64::try_from(size_of::<ComponentSummary>()).unwrap_or(0));
        let chunks = self.derived.chunks.dynamic_memory_usage();

        arena
            .saturating_add(transactions)
            .saturating_add(by_txid)
            .saturating_add(by_wtxid)
            .saturating_add(by_time)
            .saturating_add(unbroadcast)
            .saturating_add(funding)
            .saturating_add(spending)
            .saturating_add(links)
            .saturating_add(components)
            .saturating_add(chunks)
    }
    #[must_use]
    pub fn estimate_fee_rate(&self, conf_target_blocks: u32) -> Option<FeeRate> {
        self.estimator.estimate(conf_target_blocks)
    }

    #[cfg(any(test, feature = "test-seam"))]
    #[must_use]
    pub fn estimator_last_decayed_height(&self) -> Option<u32> {
        self.estimator.last_decayed_height()
    }

    #[must_use]
    pub fn estimator_history(&self) -> Vec<u8> {
        self.estimator.to_history_bytes()
    }

    pub(crate) fn adopt_estimator_history(&mut self, history: FeeEstimator) {
        self.estimator = history;
    }

    #[must_use]
    pub fn mining_snapshot(&self) -> MempoolMiningSnapshot {
        let order: Vec<EntryId> = self
            .derived
            .chunks
            .chunks_descending(self)
            .flat_map(|chunk| chunk.members.iter().copied())
            .collect();
        debug_assert_eq!(
            order.len(),
            self.entries.len(),
            "chunk index and entry arena disagree on the pool contents"
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
                    panic!("chunk index names a missing entry");
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
            fee_delta_sequence: self.fee_delta_sequence,
            entries,
        }
    }

    pub fn chunks_by_feerate(&self) -> impl DoubleEndedIterator<Item = crate::ChunkView<'_>> + '_ {
        self.derived.chunks.chunks_descending(self)
    }

    pub(crate) fn chunk_index(&self) -> &ChunkIndex {
        &self.derived.chunks
    }

    #[must_use]
    pub fn entry(&self, id: EntryId) -> Option<&MempoolEntry> {
        self.entries.get(id)
    }

    pub fn chunk_member(&self, id: EntryId) -> &MempoolEntry {
        self.entry(id).unwrap_or_else(|| {
            panic!("chunk index names entry {id} that left the pool");
        })
    }

    pub fn parents_of(&self, id: EntryId) -> &[EntryId] {
        self.links(id).map_or(&[], |links| links.parents.as_slice())
    }

    pub fn iter_entries(&self) -> impl Iterator<Item = &MempoolEntry> + '_ {
        self.entries.iter().map(|(_id, entry)| entry)
    }

    pub fn unbroadcast_transactions(&self) -> impl Iterator<Item = (Txid, Wtxid, u64)> + '_ {
        self.unbroadcast_transactions_after(None)
    }

    pub fn unbroadcast_transactions_after(
        &self,
        after: Option<Wtxid>,
    ) -> impl Iterator<Item = (Txid, Wtxid, u64)> + '_ {
        self.derived
            .unbroadcast
            .range((
                after.map_or(Bound::Unbounded, Bound::Excluded),
                Bound::Unbounded,
            ))
            .filter_map(|wtxid| {
                let entry = self.entry_by_wtxid(wtxid)?;
                let indexed = self.derived.by_txid.get(&entry.txid)?;
                Some((entry.txid, entry.wtxid, indexed.admitted_sequence))
            })
    }

    pub(crate) fn iter_clusters(&self) -> impl Iterator<Item = Vec<&MempoolEntry>> + '_ {
        let mut visited = VisitSet::new();
        self.entries.iter().filter_map(move |(id, _)| {
            let id = EntryId::try_from(id).ok()?;
            if visited.test(id) {
                return None;
            }
            let mut members = Vec::new();
            self.collect_component_members(id, &mut visited, &mut members);
            Some(
                members
                    .into_iter()
                    .filter_map(|id| self.entry(id))
                    .collect(),
            )
        })
    }

    pub fn fee_rate_histogram(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.derived
            .fee_rate_aggregates
            .iter()
            .map(|(&rate, aggregate)| (rate, aggregate.vsize))
    }

    pub fn entries_funding_script(
        &self,
        script_hash: ScriptHash,
    ) -> impl Iterator<Item = &MempoolEntry> + '_ {
        let entries = &self.entries;
        self.derived
            .funding
            .range((
                Bound::Included((script_hash, 0)),
                Bound::Included((script_hash, u32::MAX)),
            ))
            .filter_map(move |(_, id)| entries.get(*id))
    }

    #[must_use]
    pub(crate) fn contains_wtxid(&self, wtxid: &Wtxid) -> bool {
        self.derived.by_wtxid.contains_key(wtxid)
    }

    #[must_use]
    pub(crate) fn entry_by_wtxid(&self, wtxid: &Wtxid) -> Option<&MempoolEntry> {
        let id = *self.derived.by_wtxid.get(wtxid)?;
        self.entry(id)
    }

    #[cfg(test)]
    #[must_use]
    fn iter_by_fee_rate_desc(&self) -> Vec<EntryId> {
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

    #[cfg(test)]
    #[must_use]
    fn iter_above_fee_rate(&self, threshold_sat_per_kvb: u64) -> Vec<EntryId> {
        self.entries
            .iter()
            .filter(|(_index, entry)| entry.fee_rate >= threshold_sat_per_kvb)
            .filter_map(|(index, _entry)| EntryId::try_from(index).ok())
            .collect()
    }

    #[must_use]
    pub fn is_outpoint_spent(&self, outpoint: &OutPoint) -> bool {
        self.derived
            .spending
            .range(outpoint_range(*outpoint))
            .next()
            .is_some()
    }

    pub fn outpoint_spender(
        &self,
        outpoint: OutPoint,
    ) -> Result<Option<OutpointSpender<'_>>, MempoolError> {
        let Some(&(_, id)) = self.derived.spending.range(outpoint_range(outpoint)).next() else {
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
        if fee_delta == 0 {
            return Ok(());
        }
        let accumulated = self
            .fee_deltas
            .get(&txid)
            .copied()
            .unwrap_or(0)
            .checked_add(fee_delta)
            .ok_or(PrioritiseError::FeeDeltaOverflow)?;
        self.fee_delta_sequence = MutationSequence::advance(self.fee_delta_sequence);
        if accumulated == 0 {
            self.fee_deltas.remove(&txid);
        } else {
            self.fee_deltas.insert(txid, accumulated);
        }

        let Some(id) = self.entry_id_by_txid(&txid) else {
            return Ok(());
        };
        if let Some(entry) = self.entry_mut(id) {
            entry.fee_delta = accumulated;
        }

        let affected = self.metadata_closure(&[id]);
        self.refresh_metadata(&affected);
        if let Some(component) = self.component_id(id) {
            self.relinearize_from_seed(component, id);
        }
        Ok(())
    }

    #[must_use]
    pub fn prioritised_transactions(&self) -> Vec<PrioritisedTransaction> {
        self.fee_deltas()
            .map(|(txid, fee_delta)| PrioritisedTransaction {
                txid,
                fee_delta,
                in_mempool: self.derived.by_txid.contains_key(&txid),
                modified_fee: self.entry_by_txid(&txid).map(MempoolEntry::modified_fee),
            })
            .collect()
    }

    pub(crate) fn fee_deltas(&self) -> impl ExactSizeIterator<Item = (Txid, i64)> + '_ {
        self.fee_deltas.iter().map(|(&txid, &delta)| (txid, delta))
    }

    fn remove_entry_and_descendants_into(
        &mut self,
        id: EntryId,
        reason: RemovalReason,
        changes: &mut Vec<MutationChange>,
    ) {
        let mut ids = Vec::new();
        self.collect_descendants(id, &mut ids, true);
        ids.sort_unstable();
        ids.dedup();
        let removals = ids.into_iter().map(|id| (id, reason)).collect::<Vec<_>>();
        self.remove_entries_with_reasons(&removals, changes);
    }

    #[cfg(any(test, feature = "test-seam"))]
    fn remove_by_txid_into(
        &mut self,
        txid: &Txid,
        reason: RemovalReason,
        changes: &mut Vec<MutationChange>,
    ) {
        let Some(id) = self.entry_id_by_txid(txid) else {
            return;
        };
        self.remove_entry_and_descendants_into(id, reason, changes);
    }

    #[must_use]
    pub fn plan_block_removals(&self, block: &Block) -> BlockRemovalPlan {
        let txids = block.txids();
        let txs: Vec<&Tx> = block.txs.iter().collect();
        self.plan_block_removals_from_txs(&txs, &txids)
    }

    fn plan_block_removals_from_txs(
        &self,
        block_txs: &[&Tx],
        block_txids: &[Txid],
    ) -> BlockRemovalPlan {
        assert_eq!(
            block_txs.len(),
            block_txids.len(),
            "block transactions and validated txids must stay aligned"
        );
        let mut planned: HashSet<EntryId> = HashSet::new();
        let mut removals: Vec<(EntryId, RemovalReason)> = Vec::new();
        for (tx, txid) in block_txs.iter().zip(block_txids) {
            if let Some(id) = self.entry_id_by_txid(txid) {
                if planned.insert(id) {
                    removals.push((id, RemovalReason::BlockInclusion));
                }
            }
            for root in self.conflicts_for(tx) {
                if planned.contains(&root) {
                    continue;
                }
                let mut subtree = Vec::new();
                self.collect_unplanned_descendants(root, &planned, &mut subtree);
                subtree.sort_unstable();
                for id in subtree {
                    if planned.insert(id) {
                        removals.push((id, RemovalReason::Conflict));
                    }
                }
            }
        }
        let mut seen_txids: HashSet<Txid> = HashSet::new();
        let mut fee_deltas_cleared = 0_u64;
        for txid in block_txids {
            if seen_txids.insert(*txid) && self.fee_deltas.contains_key(txid) {
                fee_deltas_cleared += 1;
            }
        }
        BlockRemovalPlan {
            removals,
            fee_deltas_cleared,
        }
    }

    fn collect_unplanned_descendants(
        &self,
        root: EntryId,
        planned: &HashSet<EntryId>,
        out: &mut Vec<EntryId>,
    ) {
        if planned.contains(&root) {
            return;
        }
        let mut seen: HashSet<EntryId> = HashSet::new();
        seen.insert(root);
        out.push(root);
        let mut stack = alloc::vec![root];
        while let Some(current) = stack.pop() {
            let Some(links) = self.links(current) else {
                continue;
            };
            for &child in &links.children {
                if planned.contains(&child) {
                    continue;
                }
                if seen.insert(child) {
                    out.push(child);
                    stack.push(child);
                }
            }
        }
    }

    #[must_use]
    pub fn chunks_after(&self, plan: &BlockRemovalPlan) -> ProjectedChunks<'_> {
        let mut planned: HashSet<EntryId> = HashSet::new();
        for (id, _) in &plan.removals {
            planned.insert(*id);
        }
        let mut confirmed: HashSet<EntryId> = HashSet::new();
        for (id, reason) in &plan.removals {
            if *reason == RemovalReason::BlockInclusion {
                confirmed.insert(*id);
            }
        }
        let mut touched: HashSet<u32> = HashSet::new();
        for (id, _) in &plan.removals {
            if let Some(component) = self.component_id(*id) {
                touched.insert(component);
            }
        }
        let mut pieces: Vec<ComponentState> = Vec::new();
        let mut synthetic = u32::MAX;
        let mut touched_ordered: Vec<u32> = touched.iter().copied().collect();
        touched_ordered.sort_unstable();
        for component in touched_ordered {
            let Some(members) = self.derived.chunks.members_of(component) else {
                continue;
            };
            let surviving: Vec<EntryId> = members
                .iter()
                .copied()
                .filter(|id| !planned.contains(id))
                .collect();
            if surviving.is_empty() {
                continue;
            }
            for piece in self.connected_pieces(&surviving, &planned) {
                let facts: Vec<MemberFacts<'_>> = piece
                    .iter()
                    .filter_map(|&id| {
                        let live = self.entries.slot(id)?;
                        Some(MemberFacts {
                            id,
                            entry: &live.entry,
                            parents: live.links.parents.as_slice(),
                        })
                    })
                    .collect();
                if facts.is_empty() {
                    continue;
                }
                let state = match facts.as_slice() {
                    [only] => ComponentState::singleton(synthetic, only),
                    _ => ComponentState::linearized(synthetic, &facts),
                };
                pieces.push(state);
                synthetic = synthetic.wrapping_sub(1);
            }
        }
        ProjectedChunks::new(self, confirmed, touched, pieces)
    }

    fn connected_pieces(
        &self,
        surviving: &[EntryId],
        planned: &HashSet<EntryId>,
    ) -> Vec<Vec<EntryId>> {
        let present: HashSet<EntryId> = surviving.iter().copied().collect();
        let mut visited: HashSet<EntryId> = HashSet::new();
        let mut pieces = Vec::new();
        for &seed in surviving {
            if !visited.insert(seed) {
                continue;
            }
            let mut piece = alloc::vec![seed];
            let mut stack = alloc::vec![seed];
            while let Some(current) = stack.pop() {
                let Some(links) = self.links(current) else {
                    continue;
                };
                for &neighbour in links.parents.iter().chain(links.children.iter()) {
                    if planned.contains(&neighbour) {
                        continue;
                    }
                    if !present.contains(&neighbour) {
                        continue;
                    }
                    if visited.insert(neighbour) {
                        piece.push(neighbour);
                        stack.push(neighbour);
                    }
                }
            }
            pieces.push(piece);
        }
        pieces
    }

    pub fn remove_for_block(
        &mut self,
        block_txs: &[&Tx],
        block_txids: &[Txid],
        height: u32,
        now: u64,
    ) -> MutationResult {
        assert_eq!(
            block_txs.len(),
            block_txids.len(),
            "block transactions and validated txids must stay aligned"
        );
        self.estimator.block_connected(block_txids, height);

        let plan = self.plan_block_removals_from_txs(block_txs, block_txids);
        let mut changes = Vec::with_capacity(plan.removals.len());
        self.remove_entries_with_reasons(&plan.removals, &mut changes);
        for txid in block_txids {
            if self.fee_deltas.remove(txid).is_some() {
                self.fee_delta_sequence = MutationSequence::advance(self.fee_delta_sequence);
            }
        }
        self.rolling_min_fee.lock().note_block(now);
        self.finish_mutation(changes)
    }

    #[must_use]
    pub fn has_expired_entries(&self, now: u64) -> bool {
        let cutoff = now.saturating_sub(MEMPOOL_EXPIRY_SECS);
        self.derived
            .by_time
            .first()
            .is_some_and(|&(time, _)| time < cutoff)
    }

    pub fn expire(&mut self, now: u64) -> MutationResult {
        let removals: Vec<_> = self
            .expired_entry_ids(now)
            .into_iter()
            .map(|id| (id, RemovalReason::Expiry))
            .collect();
        let mut changes = Vec::with_capacity(removals.len());
        self.remove_entries_with_reasons(&removals, &mut changes);
        self.finish_mutation(changes)
    }

    pub(crate) fn expired_entry_ids(&self, now: u64) -> Vec<EntryId> {
        let cutoff = now.saturating_sub(MEMPOOL_EXPIRY_SECS);
        let mut visited: HashSet<EntryId> = HashSet::new();
        let mut stage = Vec::new();
        for &(_, root) in self.derived.by_time.range(..(cutoff, EntryId::MIN)) {
            self.stage_with_descendants(root, &mut visited, &mut stage);
        }
        stage.sort_unstable();
        stage
    }

    fn stage_with_descendants(
        &self,
        root: EntryId,
        visited: &mut impl VisitMarks,
        stage: &mut Vec<EntryId>,
    ) {
        if !visited.insert(root) {
            return;
        }
        stage.push(root);
        let mut stack = vec![root];
        while let Some(current) = stack.pop() {
            let Some(links) = self.links(current) else {
                continue;
            };
            for &child in &links.children {
                if visited.insert(child) {
                    stage.push(child);
                    stack.push(child);
                }
            }
        }
    }

    pub fn remove_for_reorg(&mut self, txids: &[Txid]) -> MutationResult {
        let mut changes = Vec::new();
        for txid in txids {
            if let Some(id) = self.entry_id_by_txid(txid) {
                self.remove_entry_and_descendants_into(id, RemovalReason::Reorg, &mut changes);
            }
        }
        self.finish_mutation(changes)
    }

    #[cfg(any(test, feature = "test-seam"))]
    #[must_use]
    pub fn evict_below_fee_rate(&mut self, threshold_sat_per_kvb: u64) -> MutationResult {
        let mut to_evict: Vec<Txid> = Vec::new();
        for (_id, entry) in self.entries.iter() {
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
            for (_, id) in self
                .derived
                .spending
                .range(outpoint_range(input.previous_output))
            {
                conflicts.push(*id);
            }
        }
        conflicts.sort_unstable();
        conflicts.dedup();
        conflicts
    }

    pub(crate) fn descendants_of_conflicts(&self, direct: &[EntryId]) -> Vec<EntryId> {
        let mut conflicts = direct.to_vec();
        for &id in direct {
            self.collect_descendants(id, &mut conflicts, false);
        }
        conflicts.sort_unstable();
        conflicts.dedup();
        conflicts
    }

    #[must_use]
    pub fn ancestor_ids_for_entry(&self, id: EntryId) -> Vec<EntryId> {
        self.collect_ancestors(
            self.links(id)
                .map(|links| links.parents.clone())
                .unwrap_or_default(),
        )
    }

    #[must_use]
    pub(crate) fn ancestor_package_wtxids(&self, tip: &Wtxid) -> Option<Vec<Wtxid>> {
        let tip_id = *self.derived.by_wtxid.get(tip)?;
        let mut seen = WalkSet::new();
        seen.insert(tip_id);
        let mut order = Vec::new();
        let mut stack = vec![(tip_id, 0_usize)];
        while let Some(&(id, next)) = stack.last() {
            if let Some(&parent) = self.parents_of(id).get(next) {
                if let Some(frame) = stack.last_mut() {
                    frame.1 += 1;
                }
                if seen.insert(parent) {
                    if seen.len() > crate::standardness::MAX_PACKAGE_COUNT {
                        return None;
                    }
                    stack.push((parent, 0));
                }
            } else {
                order.push(id);
                stack.pop();
            }
        }
        order
            .into_iter()
            .map(|id| self.entry(id).map(|entry| entry.wtxid))
            .collect()
    }

    #[must_use]
    pub fn descendant_ids_for_entry(&self, id: EntryId) -> Vec<EntryId> {
        let mut ids = Vec::new();
        self.collect_descendants(id, &mut ids, false);
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    pub(crate) fn remove_entries_with_reasons(
        &mut self,
        removals: &[(EntryId, RemovalReason)],
        changes: &mut Vec<MutationChange>,
    ) {
        let ids: Vec<EntryId> = removals.iter().map(|(id, _reason)| *id).collect();
        let affected = self.metadata_closure(&ids);
        let mut dirty_components: Vec<u32> = Vec::new();
        let mut dirty_seen: HashSet<u32> = HashSet::new();
        let mut survivor_seeds: Vec<EntryId> = Vec::new();
        let mut seen_seeds = VisitSet::new();
        for (id, reason) in removals {
            if !self.entries.contains(*id) {
                continue;
            }
            let Some(retired) = self.entries.remove(*id) else {
                continue;
            };
            let entry = retired.entry;
            bitcoin_rs_consensus::trace::removed(|| {
                (
                    entry.txid.as_bytes().as_ptr(),
                    Self::core_removal_reason(*reason),
                    i32::try_from(entry.vsize).unwrap_or(i32::MAX),
                    i64::try_from(entry.fee).unwrap_or(i64::MAX),
                    entry.time,
                )
            });
            if let Some(summary) = self.component_summary_mut(retired.component) {
                summary.member_count = summary.member_count.saturating_sub(1);
                summary.weight = summary.weight.saturating_sub(entry.policy_weight());
                if dirty_seen.insert(retired.component) {
                    dirty_components.push(retired.component);
                }
            }
            for parent in &retired.links.parents {
                if let Some(slot) = self.entries.slot_mut(*parent) {
                    slot.links.children.retain(|child| child != id);
                }
                if seen_seeds.insert(*parent) {
                    survivor_seeds.push(*parent);
                }
            }
            for child in &retired.links.children {
                if let Some(slot) = self.entries.slot_mut(*child) {
                    slot.links.parents.retain(|parent| parent != id);
                }
                if seen_seeds.insert(*child) {
                    survivor_seeds.push(*child);
                }
            }
            self.derived.account_remove(*id, &entry);
            self.push_change(changes, entry.txid, MutationOutcome::Removed(*reason));
            self.estimator.tx_left(&entry.txid);
        }
        self.recompute_dirty_components(&survivor_seeds, &dirty_components);
        self.refresh_metadata(&affected);
    }

    fn recompute_dirty_components(&mut self, seeds: &[EntryId], dirty: &[u32]) {
        for &component in dirty {
            let Some(summary) = self.component_summary_mut(component) else {
                continue;
            };
            if summary.member_count == 0 {
                self.free_component(component);
                continue;
            }
            *summary = ComponentSummary::default();
            let mut visited = WalkSet::new();
            let mut pieces = Vec::new();
            for &seed in seeds {
                if !self.seed_starts_piece(component, seed, &visited) {
                    continue;
                }
                let mut members = Vec::new();
                self.collect_component_members(seed, &mut visited, &mut members);
                pieces.push(members);
            }
            let mut pieces = pieces.into_iter();
            if let Some(first) = pieces.next() {
                self.relabel_piece(&first, component);
                self.relinearize_members(component, &first);
            }
            for rest in pieces {
                let target = self.alloc_component();
                self.relabel_piece(&rest, target);
                self.relinearize_members(target, &rest);
            }
        }
    }

    fn seed_starts_piece(&self, component: u32, seed: EntryId, visited: &WalkSet) -> bool {
        self.entries.contains(seed)
            && self.component_id(seed) == Some(component)
            && !visited.test(seed)
    }

    fn relabel_piece(&mut self, members: &[EntryId], target: u32) {
        for member in members {
            if let Some(slot) = self.entries.slot_mut(*member) {
                slot.component = target;
            }
        }
        let rebuilt = ComponentSummary {
            member_count: u32::try_from(members.len()).unwrap_or(u32::MAX),
            weight: members.iter().fold(0_u64, |total, member| {
                total.saturating_add(self.entry(*member).map_or(0, MempoolEntry::policy_weight))
            }),
        };
        if let Some(slot) = self.component_summary_mut(target) {
            *slot = rebuilt;
        }
    }
    fn recompute_entry_totals(&mut self, id: EntryId) {
        let Some(entry) = self.entry(id) else {
            return;
        };
        let own_size = u64::from(entry.vsize);
        let own_fee = entry.fee;
        let own_delta = i128::from(entry.fee_delta);

        let own = (own_size, own_fee, own_delta);
        let (ancestor_size, ancestor_fee, ancestor_fee_delta) =
            self.package_totals(self.ancestor_ids_for_entry(id), own);
        let (descendant_size, descendant_fee, descendant_fee_delta) =
            self.package_totals(self.descendant_ids_for_entry(id), own);

        if let Some(entry) = self.entry_mut(id) {
            entry.ancestor_size = ancestor_size;
            entry.ancestor_fee = ancestor_fee;
            entry.ancestor_fee_delta = ancestor_fee_delta;
            entry.descendant_size = descendant_size;
            entry.descendant_fee = descendant_fee;
            entry.descendant_fee_delta = descendant_fee_delta;
        }
    }

    fn package_totals(&self, ids: Vec<EntryId>, own: (u64, u64, i128)) -> (u64, u64, i128) {
        ids.into_iter()
            .filter_map(|id| self.entry(id))
            .fold(own, |(size, fee, delta), entry| {
                (
                    size.saturating_add(u64::from(entry.vsize)),
                    fee.saturating_add(entry.fee),
                    delta.saturating_add(i128::from(entry.fee_delta)),
                )
            })
    }

    fn metadata_closure(&self, seeds: &[EntryId]) -> Vec<EntryId> {
        let mut affected = Vec::new();
        let mut seen: HashSet<EntryId> = HashSet::new();
        for seed in seeds {
            for id in self
                .ancestor_ids_for_entry(*seed)
                .into_iter()
                .chain(core::iter::once(*seed))
                .chain(self.descendant_ids_for_entry(*seed))
            {
                if seen.insert(id) {
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
    }

    fn relinearize_from_seed(&mut self, component: u32, seed: EntryId) {
        if self
            .component_summary(component)
            .is_some_and(|summary| summary.member_count == 1)
        {
            let entries = &self.entries;
            let Some(live) = entries.slot(seed) else {
                self.derived.chunks.forget(component);
                return;
            };
            let fact = MemberFacts {
                id: seed,
                entry: &live.entry,
                parents: &live.links.parents,
            };
            self.derived
                .chunks
                .relinearize(component, core::slice::from_ref(&fact));
            return;
        }
        let mut members = Vec::new();
        self.collect_component_members(seed, &mut WalkSet::new(), &mut members);
        self.relinearize_members(component, &members);
    }

    fn relinearize_members(&mut self, component: u32, members: &[EntryId]) {
        let entries = &self.entries;
        let facts = members
            .iter()
            .filter_map(|&id| {
                let live = entries.slot(id)?;
                Some(MemberFacts {
                    id,
                    entry: &live.entry,
                    parents: &live.links.parents,
                })
            })
            .collect::<Vec<_>>();
        self.derived.chunks.relinearize(component, &facts);
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

        self.derived.chunks = ChunkIndex::default();
        let mut components = Vec::new();
        let mut seen = VisitSet::new();
        for (index, _live) in self.entries.iter() {
            let Ok(id) = EntryId::try_from(index) else {
                continue;
            };
            let mut members = Vec::new();
            self.collect_component_members(id, &mut seen, &mut members);
            if members.is_empty() {
                continue;
            }
            if let Some(component) = self.component_id(id) {
                components.push((component, members));
            }
        }
        for (component, members) in components {
            self.relinearize_members(component, &members);
        }
    }

    fn cluster_ids_seeded_by(
        &self,
        seeds: &[EntryId],
        excluded: &HashSet<EntryId>,
    ) -> Vec<EntryId> {
        let mut seen = VisitSet::new();
        let mut frontier: Vec<EntryId> = Vec::new();
        for seed in seeds {
            if !excluded.contains(seed) && seen.insert(*seed) {
                frontier.push(*seed);
            }
        }
        while let Some(id) = frontier.pop() {
            self.graph_steps.fetch_add(1, Ordering::Relaxed);
            let Some(links) = self.links(id) else {
                continue;
            };
            for neighbour in links.parents.iter().chain(links.children.iter()).copied() {
                if !excluded.contains(&neighbour) && seen.insert(neighbour) {
                    frontier.push(neighbour);
                }
            }
        }
        let mut cluster = seen.members().to_vec();
        cluster.sort_unstable();
        cluster
    }

    fn check_cluster_limits(
        &self,
        tx: &Tx,
        weight: u64,
        excluded: &HashSet<EntryId>,
    ) -> Result<(), PolicyError> {
        if excluded.is_empty() {
            let cached = self.check_cluster_limits_cached(tx, weight);
            debug_assert_eq!(
                self.check_cluster_limits_by_walk(tx, weight, excluded),
                cached
            );
            cached
        } else {
            self.check_cluster_limits_by_walk(tx, weight, excluded)
        }
    }

    fn check_cluster_limits_cached(&self, tx: &Tx, weight: u64) -> Result<(), PolicyError> {
        let txid = tx.txid();
        let parents = self.in_pool_parents(tx);
        let neighbours = parents.iter().copied().chain(self.in_pool_children(txid));
        let mut count = 1_u32;
        let mut total = weight;
        let mut merged: Vec<u32> = Vec::new();
        for neighbour in neighbours {
            let Some(component) = self.component_id(neighbour) else {
                continue;
            };
            if merged.contains(&component) {
                continue;
            }
            merged.push(component);
            let summary = self
                .component_summary(component)
                .copied()
                .unwrap_or_default();
            count = count.saturating_add(summary.member_count);
            total = total.saturating_add(summary.weight);
        }
        cluster_within_limits(count, total, &self.limits)
    }

    fn check_cluster_limits_by_walk(
        &self,
        tx: &Tx,
        weight: u64,
        excluded: &HashSet<EntryId>,
    ) -> Result<(), PolicyError> {
        let txid = tx.txid();
        let mut seeds = tx
            .inputs
            .iter()
            .filter_map(|input| self.entry_id_by_txid(&input.previous_output.txid))
            .collect::<Vec<_>>();
        seeds.extend(self.in_pool_children(txid));
        let cluster = self.cluster_ids_seeded_by(&seeds, excluded);
        if cluster.is_empty() {
            return cluster_within_limits(1, weight, &self.limits);
        }
        let count = u32::try_from(cluster.len())
            .unwrap_or(u32::MAX)
            .saturating_add(1);
        let cluster_weight = cluster.iter().fold(weight, |total, id| {
            total.saturating_add(self.entry(*id).map_or(0, MempoolEntry::policy_weight))
        });
        cluster_within_limits(count, cluster_weight, &self.limits)
    }

    #[cfg(test)]
    #[must_use]
    const fn cluster_limits(&self) -> (u32, u64) {
        (self.limits.cluster_count, self.limits.cluster_size_vbytes)
    }

    fn ancestor_ids_for_tx(&self, tx: &Tx) -> Vec<EntryId> {
        self.collect_ancestors(self.in_pool_parents(tx))
    }

    fn collect_ancestors(&self, seeds: Vec<EntryId>) -> Vec<EntryId> {
        let mut seen = VisitSet::new();
        let mut stack = seeds;
        while let Some(id) = stack.pop() {
            if !seen.insert(id) {
                continue;
            }
            if let Some(links) = self.links(id) {
                stack.extend_from_slice(&links.parents);
            }
        }
        let mut ancestors = seen.members().to_vec();
        ancestors.sort_unstable();
        ancestors
    }

    fn collect_descendants(&self, id: EntryId, out: &mut Vec<EntryId>, include_root: bool) {
        let mut seen = VisitSet::new();
        for existing in out.iter() {
            seen.insert(*existing);
        }
        let fresh = seen.insert(id);
        if include_root && fresh {
            out.push(id);
        }
        let mut stack = vec![id];
        while let Some(current) = stack.pop() {
            let Some(links) = self.links(current) else {
                continue;
            };
            for child in links.children.iter().copied() {
                if seen.insert(child) {
                    out.push(child);
                    stack.push(child);
                }
            }
        }
    }

    #[must_use]
    pub fn spender_txids(&self, id: EntryId) -> Vec<Txid> {
        let Some(links) = self.links(id) else {
            return Vec::new();
        };
        links
            .children
            .iter()
            .filter_map(|child| self.entry(*child).map(|entry| entry.txid))
            .collect()
    }

    #[must_use]
    pub fn descendant_count_inclusive(&self, id: EntryId) -> u32 {
        let mut descendants = Vec::new();
        self.collect_descendants(id, &mut descendants, true);
        u32::try_from(descendants.len()).unwrap_or(u32::MAX)
    }

    #[must_use]
    pub fn ancestor_count_inclusive(&self, id: EntryId) -> u32 {
        let ancestors = self.ancestor_ids_for_entry(id);
        u32::try_from(ancestors.len())
            .unwrap_or(u32::MAX)
            .saturating_add(1)
    }

    fn entry_mut(&mut self, id: EntryId) -> Option<&mut MempoolEntry> {
        self.entries.get_mut(id)
    }
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
    weight: u64,
    limits: &MempoolLimits,
) -> Result<(), PolicyError> {
    if count > limits.cluster_count {
        return Err(PolicyError::ClusterCountLimit);
    }
    let Some(limit_weight) = limits.cluster_size_vbytes.checked_mul(4) else {
        return Err(PolicyError::ClusterSizeLimit);
    };
    if weight > limit_weight {
        return Err(PolicyError::ClusterSizeLimit);
    }
    Ok(())
}

pub(crate) fn transaction_heap_usage(tx: &Tx) -> u64 {
    use core::mem::size_of;

    let mut total = u64::try_from(size_of::<Tx>()).unwrap_or(0);
    total = total.saturating_add(
        u64::try_from(tx.inputs.capacity().saturating_mul(size_of::<TxIn>())).unwrap_or(u64::MAX),
    );
    total = total.saturating_add(
        u64::try_from(tx.outputs.capacity().saturating_mul(size_of::<TxOut>())).unwrap_or(u64::MAX),
    );
    for input in &tx.inputs {
        total =
            total.saturating_add(u64::try_from(input.script_sig.capacity()).unwrap_or(u64::MAX));
        total = total.saturating_add(
            u64::try_from(
                input
                    .witness
                    .capacity()
                    .saturating_mul(size_of::<Vec<u8>>())
                    .saturating_add(
                        input
                            .witness
                            .iter()
                            .map(std::vec::Vec::capacity)
                            .sum::<usize>(),
                    ),
            )
            .unwrap_or(u64::MAX),
        );
    }
    for output in &tx.outputs {
        total = total
            .saturating_add(u64::try_from(output.script_pubkey.capacity()).unwrap_or(u64::MAX));
    }
    total
}

#[must_use]
pub fn package_heap_usage(txs: &[Tx], spare_slots: usize) -> u64 {
    let spare =
        u64::try_from(spare_slots.saturating_mul(core::mem::size_of::<Tx>())).unwrap_or(u64::MAX);
    txs.iter().fold(spare, |total, tx| {
        total.saturating_add(transaction_heap_usage(tx))
    })
}

fn outpoint_range(outpoint: OutPoint) -> RangeInclusive<(SpendingKey, EntryId)> {
    let key = SpendingKey::from(outpoint);
    (key, EntryId::MIN)..=(key, EntryId::MAX)
}

#[cfg(test)]
fn txid_of(bytes: [u8; 32]) -> Txid {
    Txid::from(bitcoin_rs_primitives::Hash256::from_le_bytes(&bytes))
}
#[cfg(test)]
mod package_tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn linked(inputs: &[OutPoint], outputs: u32, tag: u64) -> Tx {
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: inputs
                .iter()
                .map(|previous_output| TxIn {
                    previous_output: *previous_output,
                    script_sig: Script::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            outputs: (0..outputs)
                .map(|vout| TxOut {
                    value: Amount::from_sat(10_000 + u64::from(vout) + tag * 1_000),
                    script_pubkey: vec![0x51].into(),
                })
                .collect(),
        }
    }

    fn resident(pool: &mut Mempool, tx: &Tx) -> Result<(), MempoolError> {
        let entry = MempoolEntry::new(Arc::new(tx.clone()), 100, 10_000, 1, 7, 0);
        pool.insert_entry(entry).map(|_id| ())
    }

    #[test]
    fn ancestor_package_is_topological_ends_at_the_tip_and_holds_only_residents() -> TestResult {
        let confirmed = OutPoint::new(txid_of([3; 32]), 0);
        let root = linked(&[confirmed], 2, 1);
        let left = linked(&[OutPoint::new(root.txid(), 0)], 1, 2);
        let right = linked(&[OutPoint::new(root.txid(), 1)], 1, 3);
        let tip = linked(
            &[
                OutPoint::new(left.txid(), 0),
                OutPoint::new(right.txid(), 0),
            ],
            1,
            4,
        );
        let unrelated = linked(&[OutPoint::new(txid_of([4; 32]), 0)], 1, 5);
        let mut pool = Mempool::new(MempoolLimits::default());
        for tx in [&root, &left, &right, &tip, &unrelated] {
            resident(&mut pool, tx)?;
        }

        let package = pool
            .ancestor_package_wtxids(&tip.wtxid())
            .ok_or("the tip is resident")?;
        assert_eq!(package.len(), 4);
        assert_eq!(package.first(), Some(&root.wtxid()));
        assert_eq!(package.last(), Some(&tip.wtxid()));
        assert!(package.contains(&left.wtxid()) && package.contains(&right.wtxid()));
        assert_eq!(
            pool.ancestor_package_wtxids(&left.wtxid()),
            Some(vec![root.wtxid(), left.wtxid()])
        );
        assert_eq!(
            pool.ancestor_package_wtxids(&root.wtxid()),
            Some(vec![root.wtxid()])
        );
        assert_eq!(
            pool.ancestor_package_wtxids(&unrelated.wtxid()),
            Some(vec![unrelated.wtxid()])
        );
        let absent = linked(&[confirmed], 1, 9);
        assert_eq!(pool.ancestor_package_wtxids(&absent.wtxid()), None);
        Ok(())
    }

    #[test]
    fn ancestor_package_stops_at_the_package_count_bound() -> TestResult {
        let count = crate::standardness::MAX_PACKAGE_COUNT;
        let mut pool = Mempool::new(MempoolLimits::default());
        let mut chain: Vec<Tx> = Vec::new();
        for tag in 0..=count {
            let input = chain.last().map_or_else(
                || OutPoint::new(txid_of([5; 32]), 0),
                |previous| OutPoint::new(previous.txid(), 0),
            );
            let tx = linked(&[input], 1, u64::try_from(tag)?);
            resident(&mut pool, &tx)?;
            chain.push(tx);
        }
        assert_eq!(chain.len(), count + 1);
        let at_bound = chain.get(count - 1).ok_or("chain reaches the bound")?;
        let past_bound = chain.get(count).ok_or("chain exceeds the bound")?;
        assert_eq!(
            pool.ancestor_package_wtxids(&at_bound.wtxid())
                .map(|served| served.len()),
            Some(count)
        );
        assert_eq!(pool.ancestor_package_wtxids(&past_bound.wtxid()), None);
        Ok(())
    }

    #[test]
    fn package_walk_stays_bounded_by_visited_entries() -> TestResult {
        let mut seen = WalkSet::new();
        for tag in 0..crate::standardness::MAX_PACKAGE_COUNT {
            let id = EntryId::try_from(u32::try_from(tag)?)?;
            assert!(seen.insert(id), "distinct ids insert once");
            assert!(!seen.insert(id), "reinserting is a no-op");
        }
        assert_eq!(seen.len(), crate::standardness::MAX_PACKAGE_COUNT);
        Ok(())
    }

    #[test]
    fn package_heap_usage_is_member_usage_plus_spare_outer_slots() -> TestResult {
        let first = linked(&[OutPoint::new(txid_of([6; 32]), 0)], 1, 1);
        let second = linked(&[OutPoint::new(txid_of([7; 32]), 0)], 3, 2);
        let mut txs: Vec<Tx> = Vec::with_capacity(5);
        txs.push(first);
        txs.push(second);
        let members = transaction_heap_usage(&txs[0]) + transaction_heap_usage(&txs[1]);
        let slot = u64::try_from(core::mem::size_of::<Tx>())?;
        let spare = txs.capacity() - txs.len();

        assert_eq!(package_heap_usage(&txs, 0), members);
        assert_eq!(
            package_heap_usage(&txs, spare),
            members + slot * u64::try_from(spare)?
        );
        assert_eq!(package_heap_usage(&[], 0), 0);
        assert_eq!(
            package_heap_usage(&[], usize::MAX),
            u64::try_from(usize::MAX)?
        );
        Ok(())
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests;

#[cfg(test)]
#[expect(clippy::expect_used)]
mod spend_index_tests;

#[cfg(test)]
mod dynamic_memory_usage_tests {
    use alloc::sync::Arc;

    use bitcoin_rs_primitives::{Hash256, OutPoint, Tx, TxIn, TxOut};

    use super::*;

    fn tx_with(script_len: usize, tag: u8) -> Tx {
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: alloc::vec![TxIn {
                previous_output: OutPoint::new(Txid::from(Hash256::from_le_bytes(&[tag; 32])), 0,),
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: alloc::vec![TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: alloc::vec![0x51; script_len].into(),
            }],
        }
    }

    fn pool_with(count: u8, script_len: usize) -> Mempool {
        let mut pool = Mempool::new(MempoolLimits {
            max_total_bytes: 0,
            ..MempoolLimits::default()
        });
        for tag in 0..count {
            let entry = MempoolEntry::new(Arc::new(tx_with(script_len, tag)), 100, 10_000, 1, 7, 0);
            let Ok(_id) = pool.insert_entry(entry) else {
                panic!("fixture insert failed");
            };
        }
        pool
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

    #[test]
    fn usage_falls_when_the_pool_is_cleared() {
        let mut pool = pool_with(4, 64);
        let before = pool.dynamic_memory_usage();
        pool.clear();
        let after = pool.dynamic_memory_usage();
        assert!(after < before, "{after} vs {before}");
    }

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
        let arena =
            capacity.saturating_mul(u64::try_from(size_of::<Option<LiveEntry>>()).unwrap_or(0));
        let cleared = pool.dynamic_memory_usage();
        assert_eq!(
            cleared, arena,
            "a cleared pool must report its arena and nothing else: {cleared} vs {arena}"
        );

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

    #[test]
    fn the_chunk_index_is_charged_for_what_it_holds() {
        const COUNT: u64 = 32;

        let mut pool = pool_with(u8::try_from(COUNT).unwrap_or(0), 64);
        let index = pool.derived.chunks.dynamic_memory_usage();
        assert!(index > 0, "a populated index must report a nonzero cost");

        let with_index = pool.dynamic_memory_usage();
        pool.derived.chunks = ChunkIndex::default();
        let without_index = pool.dynamic_memory_usage();
        assert_eq!(
            with_index.saturating_sub(without_index),
            index,
            "the pool must charge the index what the index says it costs"
        );
    }

    #[test]
    fn usage_accounts_the_acceptance_time_index() {
        use core::mem::size_of;

        let mut pool = pool_with(4, 64);
        let with_index = pool.dynamic_memory_usage();
        pool.derived.by_time.clear();
        let without_index = pool.dynamic_memory_usage();
        assert_eq!(
            with_index.saturating_sub(without_index),
            4_u64.saturating_mul(u64::try_from(size_of::<(u64, EntryId)>()).unwrap_or(0)),
            "the pool must charge one acceptance-time entry per pooled transaction"
        );
    }
}

#[cfg(test)]
mod entry_overhead_tests {
    use alloc::sync::Arc;

    use bitcoin_rs_primitives::Tx;

    use super::*;

    fn empty_tx(tag: u32) -> Tx {
        Tx {
            version: 2,
            lock_time: LockTime::from_consensus(tag),
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
            let entry = MempoolEntry::new(Arc::new(empty_tx(tag)), 100, 10_000, 1, 7, 0);
            let Ok(_id) = pool.insert_entry(entry) else {
                panic!("fixture insert failed");
            };
        }

        let live = u64::from(count);
        let entry_bytes = u64::try_from(size_of::<MempoolEntry>()).unwrap_or(0);
        let tx_bytes = u64::try_from(size_of::<Tx>()).unwrap_or(0);

        assert!(
            pool.dynamic_memory_usage()
                >= live.saturating_mul(entry_bytes.saturating_add(tx_bytes)),
            "usage {} is below {live} entries of {entry_bytes} plus their transactions",
            pool.dynamic_memory_usage()
        );
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod graph_tests;
