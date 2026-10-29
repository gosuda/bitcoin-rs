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
mod tests {
    use alloc::sync::Arc;
    use alloc::vec::Vec;

    use bitcoin_rs_primitives::{Hash256, OutPoint, Tx, TxIn, TxOut};

    use super::*;

    fn change_txids(result: &crate::mutation::MutationResult) -> Vec<Hash256> {
        result.changes.iter().map(|change| change.txid).collect()
    }

    #[test]
    fn mutation_batch_crossing_sequence_rollover_keeps_base_and_lookups() {
        let mut pool = Mempool::new(MempoolLimits::default());
        pool.mempool_sequence = u64::MAX - 1;

        let mut changes = Vec::new();
        pool.push_change(&mut changes, txid_of([0xAA; 32]), MutationOutcome::Accepted);
        pool.push_change(&mut changes, txid_of([0xBB; 32]), MutationOutcome::Accepted);
        assert_eq!(pool.sequence_number(), 0, "assignment wraps modulo 2^64");

        let result = pool.finish_mutation(changes);
        assert_eq!(result.sequence_base, u64::MAX);
        assert_eq!(result.sequence_of(0), Some(u64::MAX));
        assert_eq!(result.sequence_of(1), Some(0));
        assert_eq!(result.sequence_of(2), None);
    }

    #[test]
    fn pending_broadcast_index_tracks_flags_across_entry_lifecycle() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits::default());
        let first = Arc::new(tx(1, Vec::new()));
        let second = Arc::new(tx(2, Vec::new()));
        let assert_index = |pool: &Mempool| {
            let flags: std::collections::BTreeSet<_> = pool
                .iter_entries()
                .filter(|entry| entry.unbroadcast)
                .map(|entry| entry.wtxid)
                .collect();
            assert_eq!(pool.derived.unbroadcast, flags);
        };
        let mut entry = MempoolEntry::new(Arc::clone(&first), 100, 10_000, 1, 0, 0);
        entry.unbroadcast = true;
        pool.insert_entry(entry)?;
        pool.insert_entry(MempoolEntry::new(Arc::clone(&second), 100, 10_000, 1, 0, 0))?;
        assert_index(&pool);
        pool.set_unbroadcast(second.wtxid(), true);
        pool.set_unbroadcast(second.wtxid(), true);
        pool.set_unbroadcast(first.wtxid(), false);
        assert_index(&pool);
        pool.remove_for_block(&[second.as_ref()], &[second.txid()], 2, 1);
        assert_index(&pool);
        assert!(
            pool.derived.unbroadcast.is_empty(),
            "removal must retire the index key, not leave a tombstone"
        );
        pool.insert_entry(MempoolEntry::new(second, 100, 10_000, 1, 0, 0))?;
        assert_index(&pool);
        pool.set_unbroadcast(first.wtxid(), true);
        assert_index(&pool);
        pool.clear();
        assert_index(&pool);
        Ok(())
    }

    #[test]
    fn default_min_relay_fee_is_1_sat_per_vbyte() {
        let pool = Mempool::new(MempoolLimits::default());
        assert_eq!(pool.min_relay_fee_sat_per_kvb(), 1_000);
    }
    #[test]
    fn min_fee_floors_at_min_relay_while_the_rolling_rate_is_zero() {
        let pool = Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 1_000,
            ..MempoolLimits::default()
        });
        assert_eq!(pool.min_fee_sat_per_kvb(0), 1_000);
        assert_eq!(pool.min_fee_sat_per_kvb(u64::MAX), 1_000);
    }

    #[test]
    fn insert_entry_rejects_below_min_relay_fee() {
        let limits = MempoolLimits {
            min_relay_fee_sat_per_kvb: 5_000,
            ..MempoolLimits::default()
        };
        let mut pool = Mempool::new(limits);
        let tx = single_output_tx(&[], Sequence::MAX, 1_000, vec![0x51].into());
        let entry = MempoolEntry::new(Arc::new(tx), 100, 100, 1, 7, 0);
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
            lock_time: LockTime::ZERO,
            inputs: Vec::new(),
            outputs: Vec::new(),
        };
        let entry = MempoolEntry::new(Arc::new(tx), 123, 4_567, 0, 0, 0);
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
    fn aggregate_fees_sums_entry_fees() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits::default());
        assert_eq!(pool.aggregate_fees(), 0);

        let entry_a = MempoolEntry::new(Arc::new(tx(1, Vec::new())), 400, 500, 1, 7, 0);
        let entry_b = MempoolEntry::new(Arc::new(tx(2, Vec::new())), 900, 1_000, 2, 7, 0);
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
            0,
        ))?;
        pool.insert_entry(MempoolEntry::new(Arc::new(prioritised), 100, 100, 2, 7, 0))?;
        pool.insert_entry(MempoolEntry::new(
            Arc::new(removed.clone()),
            100,
            50,
            3,
            7,
            0,
        ))?;

        assert_eq!(pool.aggregate_fees(), u64::MAX);
        assert!(
            !pool
                .remove_for_block(&[&removed], &[removed_txid], 8, 1)
                .is_empty()
        );
        assert_eq!(pool.aggregate_fees(), u64::MAX);
        pool.prioritise(prioritised_txid, -100)
            .expect("overlay delta applies");
        assert_eq!(pool.aggregate_fees(), u64::MAX);
        Ok(())
    }

    #[test]
    fn iter_by_fee_rate_desc_orders_highest_first() {
        let mut pool = Mempool::new(MempoolLimits::default());
        let low_tx = single_output_tx(&[], Sequence::MAX, 1_000, vec![0x51].into());
        let low_txid = low_tx.txid();
        let _ = pool.insert_entry(MempoolEntry::new(Arc::new(low_tx), 100, 1_000, 1, 7, 0));
        let high_tx = single_output_tx(&[], Sequence::MAX, 99_000, vec![0x52].into());
        let high_txid = high_tx.txid();
        let _ = pool.insert_entry(MempoolEntry::new(Arc::new(high_tx), 100, 10_000, 1, 7, 0));
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
    fn fee_rate_aggregate_tracks_duplicate_rates_and_removals() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            ..MempoolLimits::default()
        });
        let first = Arc::new(tx(10, Vec::new()));
        let second = Arc::new(tx(11, Vec::new()));
        let other_rate = Arc::new(tx(12, Vec::new()));
        let first_txid = first.txid();
        let second_txid = second.txid();

        pool.insert_entry(MempoolEntry::new(Arc::clone(&first), 100, 1_000, 1, 7, 0))?;
        pool.insert_entry(MempoolEntry::new(Arc::clone(&second), 200, 2_000, 2, 7, 0))?;
        pool.insert_entry(MempoolEntry::new(
            Arc::clone(&other_rate),
            100,
            3_000,
            3,
            7,
            0,
        ))?;

        let ten_k = pool
            .derived
            .fee_rate_aggregates
            .get(&10_000)
            .expect("duplicate rate aggregate");
        assert_eq!((ten_k.count, ten_k.vsize), (2, 300));
        assert_eq!(
            pool.fee_rate_histogram().collect::<Vec<_>>(),
            vec![(10_000, 300), (30_000, 100)]
        );

        assert_eq!(
            pool.remove_for_block(&[first.as_ref()], &[first_txid], 4, 1)
                .len(),
            1
        );
        let ten_k = pool
            .derived
            .fee_rate_aggregates
            .get(&10_000)
            .expect("remaining duplicate rate aggregate");
        assert_eq!((ten_k.count, ten_k.vsize), (1, 200));
        assert_eq!(
            pool.fee_rate_histogram().collect::<Vec<_>>(),
            vec![(10_000, 200), (30_000, 100)]
        );

        assert_eq!(
            pool.remove_for_block(&[second.as_ref()], &[second_txid], 5, 1)
                .len(),
            1
        );
        assert!(!pool.derived.fee_rate_aggregates.contains_key(&10_000));
        assert_eq!(
            pool.fee_rate_histogram().collect::<Vec<_>>(),
            vec![(30_000, 100)]
        );
        Ok(())
    }

    #[test]
    fn iter_above_fee_rate_filters_to_high_fee_only() {
        let mut pool = Mempool::new(MempoolLimits::default());
        let low_tx = single_output_tx(&[], Sequence::MAX, 1_000, vec![0x51].into());
        let _ = pool.insert_entry(MempoolEntry::new(Arc::new(low_tx), 100, 1_000, 1, 7, 0));
        let high_tx = single_output_tx(&[], Sequence::MAX, 99_000, vec![0x52].into());
        let _ = pool.insert_entry(MempoolEntry::new(Arc::new(high_tx), 100, 10_000, 1, 7, 0));
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
        let rbf_tx = Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: txid_of([0xaa; 32]),
                    vout: 0,
                },
                script_sig: Script::new(),
                sequence: Sequence::from_consensus(0x0000_0001),
                witness: Witness::new(),
            }],
            outputs: Vec::new(),
        };
        let rbf_txid = rbf_tx.txid();
        let _ = pool.insert_entry(MempoolEntry::new(Arc::new(rbf_tx), 100, 10_000, 1, 7, 0));
        let non_rbf_tx = Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: txid_of([0xbb; 32]),
                    vout: 0,
                },
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: Vec::new(),
        };
        let non_rbf_txid = non_rbf_tx.txid();
        let _ = pool.insert_entry(MempoolEntry::new(
            Arc::new(non_rbf_tx),
            100,
            10_000,
            1,
            7,
            0,
        ));
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
            lock_time: LockTime::ZERO,
            inputs: Vec::new(),
            outputs: Vec::new(),
        };
        let entry = MempoolEntry::new(Arc::new(tx), 100, 1_000, 1, 7, 0);
        pool.insert_entry(entry)?;
        let after = pool.sequence_number();
        assert!(after > before, "expected sequence to bump");
        Ok(())
    }

    #[test]
    fn clear_removes_all_entries_and_bumps_sequence() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits::default());
        let tx = single_output_tx(&[], Sequence::MAX, 99_000, vec![0x51].into());
        let _id = pool.insert_entry(MempoolEntry::new(Arc::new(tx), 100, 10_000, 1, 7, 0))?;
        let seq_before_clear = pool.sequence_number();

        pool.clear();

        assert_eq!(pool.len(), 0);
        assert!(pool.derived.by_txid.is_empty());
        assert!(pool.derived.funding.is_empty());
        assert!(pool.derived.spending.is_empty());
        assert!(pool.derived.chunks.is_empty());
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
        let decoy = OutPoint {
            txid: txid_of([0xbb; 32]),
            vout: 3,
        };
        let spending = Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![
                TxIn {
                    previous_output: decoy,
                    script_sig: Script::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                },
                TxIn {
                    previous_output: outpoint,
                    script_sig: Script::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                },
            ],
            outputs: vec![TxOut {
                value: Amount::from_sat(99_000),
                script_pubkey: vec![0x51].into(),
            }],
        };
        let spending_txid = spending.txid();
        let _ = pool.insert_entry(MempoolEntry::new(Arc::new(spending), 100, 10_000, 1, 7, 0));
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
    fn entries_funding_script_selects_only_matching_funders() {
        let mut pool = Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            ..MempoolLimits::default()
        });
        let matching = vec![0x51];
        let other = vec![0x52];
        let funder = |script: Vec<u8>, tag: u8| {
            single_output_tx(
                &[OutPoint {
                    txid: txid_of([tag; 32]),
                    vout: 0,
                }],
                Sequence::MAX,
                50_000,
                script.into(),
            )
        };
        let matching_tx = funder(matching.clone(), 0xaa);
        let matching_txid = matching_tx.txid();
        let matching_wtxid = matching_tx.wtxid();
        pool.insert_entry(MempoolEntry::new(
            Arc::new(matching_tx),
            100,
            10_000,
            1,
            7,
            0,
        ))
        .expect("matching insert");
        pool.insert_entry(MempoolEntry::new(
            Arc::new(funder(other, 0xbb)),
            100,
            10_000,
            1,
            7,
            0,
        ))
        .expect("other insert");

        let funded: Vec<_> = pool
            .entries_funding_script(ScriptHash::from_script(&matching))
            .map(|entry| entry.txid)
            .collect();
        assert_eq!(funded, vec![matching_txid]);
        assert!(pool.contains_wtxid(&matching_wtxid));
        assert_eq!(
            pool.entry_by_wtxid(&matching_wtxid).map(|entry| entry.txid),
            Some(matching_txid)
        );
        assert_eq!(pool.iter_entries().count(), 2);
    }

    #[test]
    fn outpoint_spender_errors_when_the_index_names_a_missing_entry() {
        let mut pool = Mempool::new(MempoolLimits::default());
        let outpoint = OutPoint {
            txid: txid_of([0xee; 32]),
            vout: 0,
        };
        pool.derived
            .spending
            .insert((SpendingKey::from(outpoint), 9_999));
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
        let tx = single_output_tx(&[unrelated], Sequence::MAX, 99_000, vec![0x51].into());
        let entry_txid = tx.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(tx), 100, 10_000, 1, 7, 0))
            .expect("insertion succeeds");
        let id = pool
            .entry_id_by_txid(&entry_txid)
            .expect("inserted entry id resolves");
        pool.derived
            .spending
            .insert((SpendingKey::from(indexed), id));
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
        let spender_tx =
            |fee: u64| single_output_tx(&[outpoint], Sequence::MAX, fee, vec![0x51].into());
        let first = spender_tx(99_000);
        let first_txid = first.txid();
        let _ = pool.insert_entry(MempoolEntry::new(Arc::new(first), 100, 10_000, 1, 7, 0));
        let _ = pool.insert_entry(MempoolEntry::new(
            Arc::new(spender_tx(98_000)),
            100,
            10_000,
            1,
            7,
            0,
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
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: outpoint,
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![],
        };
        pool.insert_entry(MempoolEntry::new(Arc::new(spending), 100, 10_000, 1, 7, 0))?;
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
    fn block_inclusion_keeps_unmined_descendants() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits::default());
        let parent = tx(13, Vec::new());
        let parent_txid = parent.txid();
        let child = tx(14, vec![OutPoint::new(parent_txid, 0)]);
        let child_txid = child.txid();
        pool.insert_entry(MempoolEntry::new(
            Arc::new(parent.clone()),
            100,
            1_000,
            1,
            7,
            0,
        ))?;
        pool.insert_entry(MempoolEntry::new(Arc::new(child), 100, 1_000, 2, 7, 0))?;
        let child_id = pool
            .entry_id_by_txid(&child_txid)
            .expect("child id resolves");

        let removed = pool.remove_for_block(&[&parent], &[parent_txid], 8, 1);

        assert_eq!(
            removed.changes,
            vec![MutationChange {
                txid: Hash256::from(parent_txid),
                outcome: MutationOutcome::Removed(RemovalReason::BlockInclusion),
            }]
        );
        assert!(pool.contains_txid(&child_txid));
        assert_eq!(pool.ancestor_ids_for_entry(child_id), Vec::<u32>::new());
        let incremental = totals(&pool);
        pool.recompute_all_metadata();
        assert_eq!(incremental, totals(&pool));
        Ok(())
    }

    #[test]
    fn descendant_ids_for_entry_returns_descendants_excluding_origin() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits::default());
        let parent = tx(1, Vec::new());
        let parent_txid = parent.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(parent), 100, 1_000, 0, 0, 0))?;
        let parent_id = pool
            .entry_id_by_txid(&parent_txid)
            .expect("parent id resolves");
        let child = tx(2, vec![OutPoint::new(parent_txid, 0)]);
        let child_txid = child.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(child), 100, 1_000, 0, 0, 0))?;
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
        pool.insert_entry(MempoolEntry::new(Arc::new(lone), 500, 1_000, 1, 7, 0))?;
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
        let _id = pool.insert_entry(MempoolEntry::new(Arc::new(tx), 100, 1_000, 1, 7, 0))?;

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
        let _id = pool.insert_entry(MempoolEntry::new(Arc::new(tx), 100, 1_000, 1, 7, 0))?;

        pool.prioritise(txid, -2_000)
            .expect("negative overlay applies");

        let Some(entry) = pool.entry_by_txid(&txid) else {
            panic!("tx missing after prioritise");
        };
        assert_eq!(entry.fee, 1_000);
        assert_eq!(entry.fee_rate, 10_000);
        assert_eq!(entry.modified_fee(), -1_000);
        assert_eq!(
            pool.derived.chunks.len(),
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
        let _id = pool.insert_entry(MempoolEntry::new(Arc::new(entry_tx), 100, 1_000, 1, 7, 0))?;

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
        let _other_id =
            pool.insert_entry(MempoolEntry::new(Arc::new(other), 100, 1_000, 1, 7, 0))?;
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
    fn prioritised_transactions_includes_absent_txids() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits::default());
        let pooled = tx(30, Vec::new());
        let pooled_txid = pooled.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(pooled), 100, 1_000, 1, 7, 0))?;
        pool.prioritise(pooled_txid, 500)
            .expect("pooled overlay applies");

        let absent_txid = tx(31, Vec::new()).txid();
        pool.prioritise(absent_txid, -25)
            .expect("absent overlay is stored");

        let overlay = pool.prioritised_transactions();
        assert_eq!(overlay.len(), 2);
        let pooled_row = overlay
            .iter()
            .find(|entry| entry.txid == pooled_txid)
            .expect("pooled overlay is listed");
        assert_eq!(pooled_row.fee_delta, 500);
        assert!(pooled_row.in_mempool);
        assert_eq!(pooled_row.modified_fee, Some(1_500));
        let absent_row = overlay
            .iter()
            .find(|entry| entry.txid == absent_txid)
            .expect("absent overlay is listed");
        assert_eq!(absent_row.fee_delta, -25);
        assert!(!absent_row.in_mempool);
        assert_eq!(absent_row.modified_fee, None);
        Ok(())
    }

    #[test]
    fn prioritise_removes_a_zeroed_overlay() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits::default());
        let pooled = tx(32, Vec::new());
        let pooled_txid = pooled.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(pooled), 100, 1_000, 1, 7, 0))?;
        pool.prioritise(pooled_txid, 500)
            .expect("pooled overlay applies");
        pool.prioritise(pooled_txid, -500)
            .expect("reversing the overlay clears it");
        assert!(
            pool.prioritised_transactions().is_empty(),
            "a zero accumulated delta must leave the overlay map"
        );
        assert_eq!(
            pool.entry_by_txid(&pooled_txid)
                .map(|entry| entry.fee_delta),
            Some(0)
        );
        Ok(())
    }

    #[test]
    fn prioritise_propagates_the_overlay_through_package_deltas() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits::default());
        let parent = tx(5, Vec::new());
        let parent_txid = parent.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(parent), 100, 1_000, 0, 0, 0))?;
        let parent_id = pool
            .entry_id_by_txid(&parent_txid)
            .expect("parent id resolves");
        let child = tx(6, vec![OutPoint::new(parent_txid, 0)]);
        let child_txid = child.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(child), 100, 2_000, 0, 0, 0))?;
        let child_id = pool
            .entry_id_by_txid(&child_txid)
            .expect("child id resolves");
        let grandchild = tx(7, vec![OutPoint::new(child_txid, 0)]);
        let grandchild_txid = grandchild.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(grandchild), 100, 3_000, 0, 0, 0))?;
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
        assert_eq!(
            i128::from(child_after.ancestor_fee) + child_after.ancestor_fee_delta,
            3_500,
            "the modified ancestor package fee carries the overlay"
        );
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
        assert!(!pool.contains_txid(&txid));
        assert_eq!(pool.sequence_number(), before);

        pool.insert_entry(MempoolEntry::new(Arc::new(tx), 100, 1_000, 1, 7, 0))?;

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
        pool.insert_entry(MempoolEntry::new(Arc::new(tx.clone()), 100, 1_000, 1, 7, 0))?;
        pool.prioritise(txid, 700).expect("delta applies");

        assert!(!pool.evict_below_fee_rate(10_001).is_empty());

        pool.insert_entry(MempoolEntry::new(Arc::new(tx), 100, 1_000, 1, 7, 0))?;
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
            0,
        ))?;
        let child = tx(11, vec![OutPoint::new(parent_txid, 0)]);
        let child_txid = child.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(child), 100, 1_000, 1, 7, 0))?;
        let stranger = tx(12, Vec::new());
        let stranger_txid = stranger.txid();

        pool.prioritise(parent_txid, 100)
            .expect("parent delta applies");
        pool.prioritise(child_txid, 200)
            .expect("child delta applies");
        pool.prioritise(stranger_txid, 50)
            .expect("stranger delta applies");

        let removed =
            pool.remove_for_block(&[&parent, &stranger], &[parent_txid, stranger_txid], 8, 1);

        assert_eq!(removed.len(), 1, "only the mined parent leaves");
        assert_eq!(
            removed.changes,
            vec![MutationChange {
                txid: Hash256::from(parent_txid),
                outcome: MutationOutcome::Removed(RemovalReason::BlockInclusion),
            }]
        );
        assert!(!pool.fee_deltas.contains_key(&parent_txid));
        assert!(!pool.fee_deltas.contains_key(&stranger_txid));
        assert_eq!(
            pool.fee_deltas.get(&child_txid).copied(),
            Some(200),
            "the unmined child keeps its overlay"
        );
        assert!(pool.contains_txid(&child_txid));

        pool.insert_entry(MempoolEntry::new(Arc::new(parent), 100, 1_000, 1, 7, 0))?;
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
        pool.insert_entry(MempoolEntry::new(
            Arc::new(lower_fee_tx),
            100,
            1_000,
            1,
            7,
            0,
        ))?;
        let lower_fee_id = pool
            .entry_id_by_txid(&lower_fee_txid)
            .expect("lower id resolves");
        let higher_fee_tx = tx(14, Vec::new());
        let higher_fee_txid = higher_fee_tx.txid();
        pool.insert_entry(MempoolEntry::new(
            Arc::new(higher_fee_tx),
            100,
            2_000,
            2,
            7,
            0,
        ))?;
        let higher_fee_id = pool
            .entry_id_by_txid(&higher_fee_txid)
            .expect("higher id resolves");

        assert_eq!(
            pool.chunks_by_feerate()
                .flat_map(|chunk| chunk.members.iter().copied())
                .next(),
            Some(higher_fee_id)
        );
        pool.prioritise(lower_fee_txid, 2_000)
            .expect("delta applies");

        assert_eq!(
            pool.chunks_by_feerate()
                .flat_map(|chunk| chunk.members.iter().copied())
                .next(),
            Some(lower_fee_id)
        );
        Ok(())
    }

    #[test]
    fn a_snapshot_outlives_pool_mutation() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits::default());
        let tx = tx(17, Vec::new());
        let txid = tx.txid();
        let shared = Arc::new(tx);
        pool.insert_entry(MempoolEntry::new(Arc::clone(&shared), 100, 1_000, 1, 7, 0))?;

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
            0,
        ))?;
        pool.insert_entry(MempoolEntry::new(
            Arc::new(second.clone()),
            100,
            10_000,
            1,
            7,
            0,
        ))?;
        assert_eq!(
            pool.estimate_fee_rate(2),
            None,
            "arrivals alone are not confirmation evidence"
        );

        pool.remove_for_block(&[&first, &second], &[first_txid, second_txid], 8, 1);
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
        let low = single_output_tx(&[], Sequence::MAX, 1_000, vec![0x51].into());
        let low_txid = low.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(low), 100, 100, 1, 7, 0))?;

        let high = single_output_tx(&[], Sequence::MAX, 99_000, vec![0x52].into());
        let high_txid = high.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(high), 100, 10_000, 1, 7, 0))?;

        let evicted = pool.evict_below_fee_rate(5_000);

        assert_eq!(change_txids(&evicted), vec![Hash256::from(low_txid)]);
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

        let low = single_output_tx(&[], Sequence::MAX, 1_000, vec![0x51].into());
        let low_txid = low.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(low), 500, 100, 1, 7, 0))?;

        let high = single_output_tx(&[], Sequence::MAX, 99_000, vec![0x52].into());
        let high_txid = high.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(high), 500, 10_000, 1, 7, 0))?;

        let evicted = pool.enforce_size_limit(600)?;

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
            let tx = single_output_tx(
                &[],
                Sequence::MAX,
                1_000 + u64::from(nonce),
                vec![0x51, u8::try_from(nonce).unwrap_or(0)].into(),
            );
            let fee = 100_u64.saturating_add(u64::from(nonce).saturating_mul(50));

            let _ = pool.insert_entry(MempoolEntry::new(Arc::new(tx), 600, fee, 1, 7, 0));
        }

        assert!(
            pool.total_vsize() <= 1_000,
            "size limit must hold after inserts: {}",
            pool.total_vsize()
        );
    }

    #[test]
    fn capacity_rejection_is_atomic_and_a_better_arrival_can_enter() {
        fn tx_paying(nonce: u8) -> Arc<Tx> {
            Arc::new(single_output_tx(
                &[],
                Sequence::MAX,
                1_000 + u64::from(nonce),
                vec![0x51, nonce].into(),
            ))
        }

        let limits = MempoolLimits {
            max_total_bytes: 1_000,
            min_relay_fee_sat_per_kvb: 0,
            ..MempoolLimits::default()
        };
        let mut pool = Mempool::new(limits);

        let seated = pool.insert_entry(MempoolEntry::new(tx_paying(1), 900, 90_000, 1, 7, 0));
        assert!(seated.is_ok(), "the first transaction fits: {seated:?}");

        let before = (pool.sequence_number(), pool.estimator_history());
        let refused = pool.insert_entry(MempoolEntry::new(tx_paying(2), 900, 10, 2, 7, 0));
        assert!(matches!(refused, Err(MempoolError::Full)));
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.sequence_number(), before.0);
        assert_eq!(pool.estimator_history(), before.1);

        let admitted = pool.insert_entry(MempoolEntry::new(tx_paying(3), 900, 900_000, 3, 7, 0));
        let Ok(_result) = admitted else {
            panic!("a better-paying transaction must be admitted: {admitted:?}");
        };
        assert_eq!(pool.len(), 1, "the accepted transaction is the only entry");
        assert!(
            pool.entries.iter().any(|(_, entry)| entry.vsize == 900),
            "an accepted entry must resolve"
        );
    }

    #[test]
    fn a_replacement_that_would_be_shed_leaves_the_pool_unchanged() {
        let limits = MempoolLimits {
            max_total_bytes: 1_000,
            min_relay_fee_sat_per_kvb: 0,
            ..MempoolLimits::default()
        };
        let mut pool = Mempool::new(limits);

        let prev = OutPoint {
            txid: txid_of([0x11; 32]),
            vout: 0,
        };

        let original = single_output_tx(
            &[prev],
            Sequence::ENABLE_RBF_NO_LOCKTIME,
            1_000,
            vec![0x51].into(),
        );
        let original_txid = original.txid();
        let seated = pool.insert_entry(MempoolEntry::new(Arc::new(original), 100, 10_000, 1, 7, 0));
        assert!(seated.is_ok(), "original must fit: {seated:?}");

        let bystander = tx(8, Vec::new());
        let seated_by = pool.insert_entry(MempoolEntry::new(
            Arc::new(bystander),
            850,
            8_500_000,
            1,
            7,
            0,
        ));
        assert!(seated_by.is_ok(), "bystander must fit: {seated_by:?}");
        assert_eq!(pool.len(), 2);

        let replacement = single_output_tx(
            &[prev],
            Sequence::ENABLE_RBF_NO_LOCKTIME,
            100,
            vec![0x52].into(),
        );
        let replacement_txid = replacement.txid();
        let before = (
            pool.mining_snapshot().entries,
            pool.estimator_history(),
            pool.policy_stamp(),
        );
        let result = pool.replace_transaction(
            &crate::ReplacementCandidate::new(Arc::new(replacement), 900, 100_000, 1)
                .with_sigop_cost(4),
            2,
            7,
        );
        assert!(matches!(
            result,
            Err(crate::RbfError::Mempool(MempoolError::Full))
        ));
        assert!(pool.contains_txid(&original_txid));
        assert!(!pool.contains_txid(&replacement_txid));
        assert_eq!(pool.mining_snapshot().entries, before.0);
        assert_eq!(pool.estimator_history(), before.1);
        assert_ne!(pool.policy_stamp(), before.2);
        assert!(pool.min_fee_sat_per_kvb(9) > 0);
    }

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
                0,
            ))?;
            Ok(OutPoint::new(txid, 0))
        };

        let root = add(&mut pool, 1, vec![OutPoint::default()])?;
        let mid = add(&mut pool, 2, vec![root])?;
        let leaf = add(&mut pool, 3, vec![mid])?;
        let sibling = add(&mut pool, 4, vec![root])?;
        let joined = add(&mut pool, 5, vec![leaf, sibling])?;
        let lonely = add(&mut pool, 6, vec![OutPoint::default()])?;

        outs.extend([root, mid, leaf, sibling, joined, lonely]);
        Ok((pool, outs))
    }

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

    #[test]
    fn incremental_metadata_matches_the_full_recompute_after_removals() -> Result<(), MempoolError>
    {
        for victim in 0..6_u32 {
            let (mut pool, _outs) = graph_pool()?;
            let Some(entry) = pool.entry(victim) else {
                panic!("entry {victim} must be present in the fixture");
            };
            let tx = entry.tx.clone();
            let txid = entry.txid;
            let removed = pool.remove_for_block(&[&tx], &[txid], 8, 1);
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
        pool.insert_entry(MempoolEntry::new(Arc::new(root), 100, 500, 0, 1, 0))?;
        let child = tx(32, vec![root_out]);
        let child_out = OutPoint::new(child.txid(), 0);
        pool.insert_entry(MempoolEntry::new(Arc::new(child), 100, 9_000, 1, 1, 0))?;
        pool.insert_entry(MempoolEntry::new(
            Arc::new(tx(33, vec![child_out])),
            100,
            100_000,
            2,
            1,
            0,
        ))?;
        pool.insert_entry(MempoolEntry::new(
            Arc::new(tx(34, vec![OutPoint::default()])),
            100,
            200,
            3,
            1,
            0,
        ))?;
        pool.insert_entry(MempoolEntry::new(
            Arc::new(tx(35, vec![OutPoint::default()])),
            100,
            300,
            4,
            1,
            0,
        ))?;
        assert!(
            pool.len() < 5,
            "the fixture must actually cross the size limit"
        );

        let incremental = totals(&pool);
        let index = pool.chunk_order();
        pool.recompute_all_metadata();
        assert_eq!(
            incremental,
            totals(&pool),
            "eviction left package totals a full recompute disagrees with"
        );
        assert_eq!(
            index,
            pool.chunk_order(),
            "eviction left a stale chunk index behind"
        );
        Ok(())
    }

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

        let Some(root) = outs.first().map(|out| out.txid) else {
            panic!("fixture must hold entries");
        };
        pool.prioritise(root, 250_000)
            .expect("prioritise up must apply");
        check(&pool, "a positive fee delta");

        pool.prioritise(root, -100_000)
            .expect("prioritise down must apply");
        check(&pool, "a negative fee delta");

        let Some(victim_txid) = outs.get(1).map(|out| out.txid) else {
            panic!("fixture must hold a second entry");
        };
        let Some(victim) = pool.entry_by_txid(&victim_txid) else {
            panic!("fixture must hold the victim entry");
        };
        let victim_tx = victim.tx.clone();
        let removed = pool.remove_for_block(&[&victim_tx], &[victim_txid], 8, 1);
        assert!(!removed.is_empty(), "the victim must actually be removed");
        assert!(
            outs.get(2).is_some_and(|out| pool.contains_txid(&out.txid)),
            "the chain below the victim remains in the pool"
        );
        check(&pool, "a removal");

        pool.clear();
        check(&pool, "clear");
        Ok(())
    }

    #[test]
    fn prioritise_reindexes_the_descendants_it_lifts() -> Result<(), MempoolError> {
        let (mut pool, outs) = graph_pool()?;

        let Some(txid) = outs.first().map(|out| out.txid) else {
            panic!("fixture must hold entries");
        };
        pool.prioritise(txid, 5_000_000)
            .expect("prioritise must apply");

        let after_prioritise = pool.chunk_order();
        let totals_after = totals(&pool);
        pool.recompute_all_metadata();
        assert_eq!(
            totals_after,
            totals(&pool),
            "prioritise left package totals a full recompute disagrees with"
        );
        assert_eq!(
            after_prioritise,
            pool.chunk_order(),
            "prioritise left stale chunk keys behind"
        );
        Ok(())
    }

    #[test]
    fn inserting_a_parent_after_its_child_refreshes_the_child() -> Result<(), MempoolError> {
        let mut pool = Mempool::new(MempoolLimits::default());

        let parent = tx(11, vec![OutPoint::default()]);
        let parent_out = OutPoint::new(parent.txid(), 0);
        let child = tx(12, vec![parent_out]);

        pool.insert_entry(MempoolEntry::new(Arc::new(child), 100, 1_000, 0, 1, 0))?;
        pool.insert_entry(MempoolEntry::new(Arc::new(parent), 200, 4_000, 1, 1, 0))?;

        let incremental = totals(&pool);
        pool.recompute_all_metadata();
        assert_eq!(
            incremental,
            totals(&pool),
            "a child inserted before its parent kept stale ancestor totals"
        );
        Ok(())
    }

    #[test]
    fn full_refusal_raises_the_floor_to_the_candidate_chunk_rate() {
        let mut pool = Mempool::new(MempoolLimits {
            max_total_bytes: 1_000,
            min_relay_fee_sat_per_kvb: 0,
            ..MempoolLimits::default()
        });
        let seated = single_output_tx(&[], Sequence::MAX, 1_001, vec![0x51, 1].into());
        pool.insert_entry(MempoolEntry::new(Arc::new(seated), 900, 90_000, 1, 7, 0))
            .expect("first fits");
        assert_eq!(pool.min_fee_sat_per_kvb(2), 0);
        let candidate = single_output_tx(&[], Sequence::MAX, 1_002, vec![0x51, 2].into());
        let refused = pool.insert_entry(MempoolEntry::new(Arc::new(candidate), 900, 10, 2, 7, 0));
        assert!(matches!(refused, Err(MempoolError::Full)));
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.min_fee_sat_per_kvb(2), 1_011);
    }

    #[test]
    fn remove_for_block_stamps_the_floor_for_decay_even_when_empty() {
        let mut pool = Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 1_000,
            max_total_bytes: 400,
            ..MempoolLimits::default()
        });
        pool.insert_entry(MempoolEntry::new(
            Arc::new(tx(1, Vec::new())),
            200,
            400,
            1,
            1,
            0,
        ))
        .expect("low");
        pool.insert_entry(MempoolEntry::new(
            Arc::new(tx(2, Vec::new())),
            200,
            800,
            1,
            1,
            0,
        ))
        .expect("high");
        crate::eviction::evict_lowest_fee_packages(&mut pool, 200).expect("eviction");
        assert_eq!(pool.min_fee_sat_per_kvb(1_000), 3_000);
        pool.remove_for_block(&[], &[], 8, 1_000);
        assert_eq!(pool.min_fee_sat_per_kvb(1_000 + 12 * 60 * 60), 1_500);
    }

    #[test]
    fn expire_removes_stale_root_with_descendants() {
        let mut pool = Mempool::new(MempoolLimits::default());
        let parent = tx(41, Vec::new());
        let parent_txid = parent.txid();
        let child = tx(42, vec![OutPoint::new(parent_txid, 0)]);
        pool.insert_entry(MempoolEntry::new(Arc::new(parent), 100, 1_000, 0, 1, 0))
            .expect("parent");
        pool.insert_entry(MempoolEntry::new(
            Arc::new(child),
            100,
            1_000,
            crate::policy::MEMPOOL_EXPIRY_SECS,
            1,
            0,
        ))
        .expect("child");
        let now = crate::policy::MEMPOOL_EXPIRY_SECS + 1;
        assert!(pool.has_expired_entries(now));
        let expired = pool.expire(now);
        assert_eq!(expired.len(), 2);
        assert!(
            expired.changes.iter().all(|change| matches!(
                change.outcome,
                crate::mutation::MutationOutcome::Removed(crate::RemovalReason::Expiry)
            )),
            "every expiry change is tagged Expiry: {expired:?}"
        );
        assert!(pool.is_empty());
        let sequence = pool.sequence_number();
        assert!(pool.expire(now).is_empty());
        assert_eq!(pool.sequence_number(), sequence);
    }

    #[test]
    fn expire_keeps_entry_at_cutoff() {
        let mut pool = Mempool::new(MempoolLimits::default());
        let now = crate::policy::MEMPOOL_EXPIRY_SECS + 1;
        pool.insert_entry(MempoolEntry::new(
            Arc::new(tx(43, Vec::new())),
            100,
            1_000,
            1,
            1,
            0,
        ))
        .expect("at cutoff");
        assert!(!pool.has_expired_entries(now));
        assert!(pool.expire(now).is_empty());
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn expire_keeps_a_recycled_slot_with_a_fresh_timestamp() {
        let mut pool = Mempool::new(MempoolLimits::default());
        let old = Arc::new(tx(51, Vec::new()));
        let old_txid = old.txid();
        pool.insert_entry(MempoolEntry::new(Arc::clone(&old), 100, 1_000, 0, 1, 0))
            .expect("old");
        let recycled = pool.entry_id_by_txid(&old_txid).expect("old id resolves");
        pool.remove_for_block(&[old.as_ref()], &[old_txid], 1, 1);
        let now = crate::policy::MEMPOOL_EXPIRY_SECS + 1;
        let fresh = Arc::new(tx(52, Vec::new()));
        let fresh_txid = fresh.txid();
        pool.insert_entry(MempoolEntry::new(Arc::clone(&fresh), 100, 1_000, now, 1, 0))
            .expect("fresh");
        assert_eq!(
            pool.entry_id_by_txid(&fresh_txid),
            Some(recycled),
            "the vacated slot is reused"
        );
        assert!(!pool.has_expired_entries(now));
        assert!(pool.expire(now).is_empty());
        assert!(pool.contains_txid(&fresh_txid));
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn has_expired_entries_false_when_empty_or_cleared() {
        let mut pool = Mempool::new(MempoolLimits::default());
        assert!(!pool.has_expired_entries(crate::policy::MEMPOOL_EXPIRY_SECS + 1));
        pool.insert_entry(MempoolEntry::new(
            Arc::new(tx(44, Vec::new())),
            100,
            1_000,
            0,
            1,
            0,
        ))
        .expect("stale");
        assert!(pool.has_expired_entries(crate::policy::MEMPOOL_EXPIRY_SECS + 1));
        pool.clear();
        assert!(!pool.has_expired_entries(crate::policy::MEMPOOL_EXPIRY_SECS + 1));
    }

    fn single_output_tx(
        previous_outputs: &[OutPoint],
        sequence: Sequence,
        value: u64,
        script_pubkey: Script,
    ) -> Tx {
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: previous_outputs
                .iter()
                .map(|previous_output| TxIn {
                    previous_output: *previous_output,
                    script_sig: Script::new(),
                    sequence,
                    witness: Witness::new(),
                })
                .collect(),
            outputs: vec![TxOut {
                value: Amount::from_sat(value),
                script_pubkey,
            }],
        }
    }

    fn tx(label: u8, previous_outputs: Vec<OutPoint>) -> Tx {
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: previous_outputs
                .into_iter()
                .map(|previous_output| TxIn {
                    previous_output,
                    script_sig: Script::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            outputs: vec![TxOut {
                value: Amount::from_sat(5_000 + u64::from(label)),
                script_pubkey: vec![label].into(),
            }],
        }
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod spend_index_tests {
    use alloc::sync::Arc;
    use alloc::vec::Vec;

    use bitcoin_rs_primitives::{OutPoint, Tx, TxIn, TxOut};

    use super::*;

    fn tx_with(inputs: &[OutPoint], outputs: u32, tag: u64) -> Tx {
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
                    value: Amount::from_sat(
                        10_000_u64
                            .saturating_add(u64::from(vout))
                            .saturating_add(tag.saturating_mul(1_000)),
                    ),
                    script_pubkey: alloc::vec![0x51].into(),
                })
                .collect(),
        }
    }

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
            let entry = MempoolEntry::new(Arc::new(tx), 100, 10_000, 1, 7, 0);
            let Ok(_id) = pool.insert_entry(entry) else {
                panic!("mempool insert failed while building the fixture");
            };
        }
        (pool, root_txid)
    }

    #[test]
    fn a_cluster_holds_siblings_that_no_ancestor_walk_reaches() {
        let (pool, root_txid) = graph_pool();
        let child_a_txid = child_a_txid_of(&pool, root_txid);
        let Some(child_a_id) = pool.entry_id_by_txid(&child_a_txid) else {
            panic!("fixture child_a is missing");
        };

        let cluster = pool.cluster_ids_seeded_by(&[child_a_id], &HashSet::new());
        let chain = pool.metadata_closure(&[child_a_id]);

        assert_eq!(
            cluster.len(),
            pool.len(),
            "the cluster must span the whole connected component"
        );
        assert!(
            chain.len() < cluster.len(),
            "this fixture must distinguish the two walks or it proves nothing: chain={} cluster={}",
            chain.len(),
            cluster.len()
        );
    }

    fn child_a_txid_of(pool: &Mempool, root_txid: Txid) -> Txid {
        let Some(root_id) = pool.entry_id_by_txid(&root_txid) else {
            panic!("fixture root is missing");
        };
        for child in pool.links(root_id).expect("pooled").children.clone() {
            if !pool.links(child).expect("pooled").children.is_empty()
                && let Some(entry) = pool.entry(child)
            {
                return entry.txid;
            }
        }
        panic!("fixture has no grandchild-bearing child");
    }

    #[test]
    fn admission_refuses_a_transaction_over_the_cluster_count_limit() {
        let confirmed = OutPoint::new(txid_of([9_u8; 32]), 0);
        let root = tx_with(&[confirmed], 4, 1);
        let root_txid = root.txid();

        let build = |limit: u32| {
            let limits = MempoolLimits {
                cluster_count: limit,
                ..MempoolLimits::default()
            };
            let mut pool = Mempool::new(limits);
            let root_entry = MempoolEntry::new(Arc::new(root.clone()), 100, 10_000, 1, 7, 0);
            let Ok(_id) = pool.insert_entry(root_entry) else {
                panic!("root must be admitted");
            };
            let mut outcomes = Vec::new();
            for vout in 0..2_u32 {
                let child = tx_with(
                    &[OutPoint::new(root_txid, vout)],
                    1,
                    u64::from(vout).saturating_add(2),
                );
                let entry = MempoolEntry::new(Arc::new(child), 100, 10_000, 1, 7, 0);
                outcomes.push(pool.insert_entry(entry));
            }
            outcomes
        };

        let refused = build(2);
        assert!(refused[0].is_ok(), "the first sibling fits: {refused:?}");
        assert!(
            matches!(
                refused[1],
                Err(MempoolError::Policy(PolicyError::ClusterCountLimit))
            ),
            "the second sibling must be refused on cluster count: {refused:?}"
        );

        let accepted = build(3);
        assert!(
            accepted.iter().all(Result::is_ok),
            "a limit of three admits the whole cluster: {accepted:?}"
        );
    }

    #[test]
    fn admission_counts_a_cousin_that_no_chain_through_the_parent_reaches() {
        let confirmed = OutPoint::new(txid_of([17_u8; 32]), 0);
        let a = tx_with(&[confirmed], 2, 1);
        let a_txid = a.txid();
        let b = tx_with(&[OutPoint::new(a_txid, 0)], 1, 2);
        let b_txid = b.txid();
        let c = tx_with(&[OutPoint::new(a_txid, 1)], 1, 3);
        let d = tx_with(&[OutPoint::new(b_txid, 0)], 1, 4);

        let limits = MempoolLimits {
            cluster_count: 3,
            ..MempoolLimits::default()
        };
        let mut pool = Mempool::new(limits);
        for tx in [a, b, c] {
            let Ok(_id) = pool.insert_entry(MempoolEntry::new(Arc::new(tx), 100, 10_000, 1, 7, 0))
            else {
                panic!("the three-member cluster must be admitted under a limit of three");
            };
        }

        let outcome = pool.insert_entry(MempoolEntry::new(Arc::new(d), 100, 10_000, 1, 7, 0));
        assert!(
            matches!(
                outcome,
                Err(MempoolError::Policy(PolicyError::ClusterCountLimit))
            ),
            "C is in D's cluster although no chain through B reaches it: {outcome:?}"
        );
    }

    #[test]
    fn admission_refuses_a_transaction_over_the_cluster_size_limit() {
        let confirmed = OutPoint::new(txid_of([11_u8; 32]), 0);
        let root = tx_with(&[confirmed], 2, 1);
        let root_txid = root.txid();

        let limits = MempoolLimits {
            cluster_count: 100,
            cluster_size_vbytes: 250,
            ..MempoolLimits::default()
        };
        let mut pool = Mempool::new(limits);

        let Ok(_id) = pool.insert_entry(MempoolEntry::new(Arc::new(root), 200, 10_000, 1, 7, 0))
        else {
            panic!("root must be admitted");
        };
        let child = tx_with(&[OutPoint::new(root_txid, 0)], 1, 2);
        let outcome = pool.insert_entry(MempoolEntry::new(Arc::new(child), 100, 10_000, 1, 7, 0));
        assert!(
            matches!(
                outcome,
                Err(MempoolError::Policy(PolicyError::ClusterSizeLimit))
            ),
            "200 + 100 vbytes exceeds a 250-vbyte cluster: {outcome:?}"
        );
    }

    #[test]
    fn a_cluster_includes_transactions_that_already_spend_the_candidate() {
        let confirmed = OutPoint::new(txid_of([13_u8; 32]), 0);
        let parent = tx_with(&[confirmed], 1, 1);
        let parent_txid = parent.txid();
        let child = tx_with(&[OutPoint::new(parent_txid, 0)], 1, 2);

        let limits = MempoolLimits {
            cluster_count: 1,
            ..MempoolLimits::default()
        };
        let mut pool = Mempool::new(limits);

        let Ok(_id) = pool.insert_entry(MempoolEntry::new(Arc::new(child), 100, 10_000, 1, 7, 0))
        else {
            panic!("the child must be admitted into an empty pool");
        };
        let outcome = pool.insert_entry(MempoolEntry::new(Arc::new(parent), 100, 10_000, 1, 7, 0));
        assert!(
            matches!(
                outcome,
                Err(MempoolError::Policy(PolicyError::ClusterCountLimit))
            ),
            "the pre-existing spender must count toward the cluster: {outcome:?}"
        );
    }

    #[test]
    fn cluster_limits_default_to_cores_values_and_follow_configuration() {
        let pool = Mempool::new(MempoolLimits::default());
        assert_eq!(pool.cluster_limits(), (64, 101_000));

        let limits = MempoolLimits {
            cluster_count: 7,
            cluster_size_vbytes: 4_242,
            ..MempoolLimits::default()
        };
        let configured = Mempool::new(limits);
        assert_eq!(
            configured.cluster_limits(),
            (7, 4_242),
            "the reader must follow configuration, or the RPC reports a constant"
        );
    }

    #[test]
    fn a_replacement_that_evicts_from_a_full_cluster_is_admitted() {
        let confirmed = OutPoint::new(txid_of([21_u8; 32]), 0);
        let root = tx_with(&[confirmed], 2, 1);
        let root_txid = root.txid();
        let mut a = tx_with(&[OutPoint::new(root_txid, 0)], 1, 2);
        a.inputs[0].sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;
        let a_txid = a.txid();
        let b = tx_with(&[OutPoint::new(root_txid, 1)], 1, 3);

        let limits = MempoolLimits {
            cluster_count: 3,
            ..MempoolLimits::default()
        };
        let mut pool = Mempool::new(limits);
        for tx in [root, a, b] {
            let Ok(_id) = pool.insert_entry(MempoolEntry::new(Arc::new(tx), 100, 10_000, 1, 7, 0))
            else {
                panic!("the three-member cluster must be admitted under a limit of three");
            };
        }

        let replacement = tx_with(&[OutPoint::new(root_txid, 0)], 1, 4);
        let result = pool.replace_transaction(
            &crate::ReplacementCandidate::new(Arc::new(replacement), 100, 12_000, 1)
                .with_sigop_cost(4),
            4,
            7,
        );
        assert!(
            result.is_ok(),
            "a replacement that evicts from a full cluster must be admitted, \
             not rejected by the entries it removes: {result:?}"
        );
        assert!(
            pool.entry_id_by_txid(&a_txid).is_none(),
            "the replaced original must leave the pool"
        );
    }

    #[test]
    fn replacement_preview_rejects_a_cluster_only_violation() {
        let confirmed = OutPoint::new(txid_of([23_u8; 32]), 0);
        let root = tx_with(&[confirmed], 3, 1);
        let root_txid = root.txid();
        let child_a = tx_with(&[OutPoint::new(root_txid, 0)], 1, 2);
        let child_b = tx_with(&[OutPoint::new(root_txid, 1)], 1, 3);

        let limits = MempoolLimits {
            cluster_count: 3,
            ..MempoolLimits::default()
        };
        let mut pool = Mempool::new(limits);
        for tx in [root, child_a, child_b] {
            let Ok(_id) = pool.insert_entry(MempoolEntry::new(Arc::new(tx), 100, 10_000, 1, 7, 0))
            else {
                panic!("the three-member cluster must be admitted under a limit of three");
            };
        }

        let child_c = tx_with(&[OutPoint::new(root_txid, 2)], 1, 4);
        let preview = pool.check_replacement(&crate::ReplacementCandidate::new(
            Arc::new(child_c.clone()),
            100,
            10_000,
            1_000,
        ));
        assert!(
            matches!(
                preview,
                Err(crate::RbfError::Mempool(MempoolError::Policy(
                    PolicyError::ClusterCountLimit
                )))
            ),
            "the preview must reject a cluster-only violation: {preview:?}"
        );

        let admission =
            pool.insert_entry(MempoolEntry::new(Arc::new(child_c), 100, 10_000, 4, 7, 0));
        assert!(
            matches!(
                admission,
                Err(MempoolError::Policy(PolicyError::ClusterCountLimit))
            ),
            "admission must reject on cluster count: {admission:?}"
        );
        assert_eq!(
            preview.map_err(crate::RbfError::into_pool_error).err(),
            admission.err(),
            "preview and admission must reject on the same error"
        );
    }

    #[test]
    fn replacement_preview_excludes_planned_evictions() {
        let confirmed = OutPoint::new(txid_of([27_u8; 32]), 0);
        let root = tx_with(&[confirmed], 2, 1);
        let root_txid = root.txid();
        let mut a = tx_with(&[OutPoint::new(root_txid, 0)], 1, 2);
        a.inputs[0].sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;
        let a_txid = a.txid();
        let b = tx_with(&[OutPoint::new(root_txid, 1)], 1, 3);

        let limits = MempoolLimits {
            cluster_count: 3,
            ..MempoolLimits::default()
        };
        let mut pool = Mempool::new(limits);
        for tx in [root, a, b] {
            let Ok(_id) = pool.insert_entry(MempoolEntry::new(Arc::new(tx), 100, 10_000, 1, 7, 0))
            else {
                panic!("the three-member cluster must be admitted under a limit of three");
            };
        }

        let Some(a_id) = pool.entry_id_by_txid(&a_txid) else {
            panic!("A must be in the pool");
        };
        let replacement = tx_with(&[OutPoint::new(root_txid, 0)], 1, 4);
        let preview = pool
            .check_replacement(&crate::ReplacementCandidate::new(
                Arc::new(replacement.clone()),
                100,
                20_000,
                1_000,
            ))
            .expect("replacement preview excludes its victim");
        assert_eq!(preview.evicted, vec![a_id]);
        assert_eq!(pool.len(), 3, "preview does not mutate");
        assert_eq!(
            pool.insert_entry(MempoolEntry::new(
                Arc::new(replacement),
                100,
                20_000,
                1,
                7,
                0
            ))
            .err(),
            Some(MempoolError::Policy(PolicyError::ClusterCountLimit)),
            "ordinary insertion cannot grow this full cluster"
        );
    }

    #[test]
    fn the_cached_txid_matches_a_recomputation() {
        let (pool, _root_txid) = graph_pool();
        for (_id, entry) in pool.entries.iter() {
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
        for (index, entry) in pool.entries.iter() {
            let Ok(id) = EntryId::try_from(index) else {
                panic!("entry index {index} does not fit an EntryId");
            };

            let mut expected: Vec<Txid> = Vec::new();
            for (_other_index, candidate) in pool.entries.iter() {
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

        let child_entry = MempoolEntry::new(Arc::new(child), 100, 10_000, 1, 7, 0);
        assert!(
            pool.insert_entry(child_entry).is_ok(),
            "child insertion failed"
        );
        let parent_entry = MempoolEntry::new(Arc::new(parent), 100, 10_000, 1, 7, 0);
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
    fn block_inclusion_removes_root_but_leaves_descendants() {
        let (mut pool, root_txid) = graph_pool();
        let Some(root) = pool.entry_by_txid(&root_txid) else {
            panic!("root missing from the fixture pool");
        };
        let root_tx = root.tx.clone();
        let before = pool.len();
        let removed = pool.remove_for_block(&[&root_tx], &[root_txid], 8, 1);
        assert_ne!(removed.len(), 0);
        assert!(pool.entry_id_by_txid(&root_txid).is_none());
        assert_eq!(pool.len(), before - 1);
        assert_ne!(pool.len(), 0);
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
mod graph_tests {
    use super::*;

    const TIME: u64 = 1_700_000_000;
    const HEIGHT: u32 = 900;

    struct XorShift(u64);

    impl XorShift {
        fn new(seed: u64) -> Self {
            Self(seed.max(1))
        }

        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }

        fn below(&mut self, bound: usize) -> usize {
            let bound = u64::try_from(bound).unwrap_or(u64::MAX);
            usize::try_from(self.next() % bound).unwrap_or(0)
        }
    }

    fn graph_tx(nonce: u32, inputs: &[OutPoint], rbf: bool) -> Tx {
        Tx {
            version: 2,
            lock_time: LockTime::from_consensus(nonce),
            inputs: inputs
                .iter()
                .map(|previous_output| TxIn {
                    previous_output: *previous_output,
                    script_sig: Script::new(),
                    sequence: if rbf {
                        Sequence::from_consensus(0xFFFF_FFFD)
                    } else {
                        Sequence::MAX
                    },
                    witness: Witness::new(),
                })
                .collect(),
            outputs: alloc::vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: alloc::vec![0x51; 8].into(),
            }],
        }
    }

    fn fuzzer_pool() -> Mempool {
        Mempool::new(MempoolLimits {
            max_total_bytes: 0,
            min_relay_fee_sat_per_kvb: 0,
            cluster_count: 64,
            ..MempoolLimits::default()
        })
    }

    fn insert_ok(pool: &mut Mempool, nonce: u32, inputs: &[OutPoint], vsize: u32) -> Txid {
        let tx = graph_tx(nonce, inputs, false);
        let txid = tx.txid();
        pool.insert_entry(MempoolEntry::new(
            Arc::new(tx),
            vsize,
            1_000,
            TIME,
            HEIGHT,
            0,
        ))
        .expect("fixture insert must pass validation");
        txid
    }

    #[test]
    fn batched_removal_of_two_thousand_independent_entries_settles() {
        const COUNT: u32 = 2000;
        let count = usize::try_from(COUNT).expect("test count fits");
        let mut pool = Mempool::new(MempoolLimits {
            max_total_bytes: 0,
            ..MempoolLimits::default()
        });
        let mut txids = Vec::with_capacity(count);
        for nonce in 0..COUNT {
            let mut seed = [0xD1_u8; 32];
            seed[..4].copy_from_slice(&nonce.to_le_bytes());
            let funding = OutPoint::new(Txid::from(Hash256::from_le_bytes(&seed)), 0);
            txids.push(insert_ok(&mut pool, nonce, &[funding], 100));
        }
        assert_eq!(pool.len(), count);
        let mut removals = Vec::with_capacity(count);
        for txid in &txids {
            removals.push((
                pool.entry_id_by_txid(txid).expect("inserted id resolves"),
                RemovalReason::BlockInclusion,
            ));
        }
        let mut changes = Vec::new();
        pool.remove_entries_with_reasons(&removals, &mut changes);
        assert_eq!(pool.len(), 0, "every independent entry leaves");
        assert_eq!(changes.len(), count);
        for (change, txid) in changes.iter().zip(txids.iter()) {
            assert_eq!(change.txid, Hash256::from(*txid));
            assert!(
                matches!(
                    change.outcome,
                    MutationOutcome::Removed(RemovalReason::BlockInclusion)
                ),
                "unexpected outcome for {txid}: {:?}",
                change.outcome
            );
        }
        assert!(
            pool.chunks_by_feerate().next().is_none(),
            "no component linearization survives the batch"
        );
    }

    fn reference_components(pool: &Mempool) -> Vec<Vec<EntryId>> {
        let mut seen: HashSet<EntryId> = HashSet::new();
        let mut components = Vec::new();
        let live: Vec<EntryId> = pool
            .derived
            .by_txid
            .values()
            .map(|indexed| indexed.id)
            .collect();
        for seed in live {
            if !seen.insert(seed) {
                continue;
            }
            let mut part = vec![seed];
            let mut queue = vec![seed];
            while let Some(id) = queue.pop() {
                let entry = pool.entry(id).expect("entry must exist in pool");
                let parents = entry
                    .tx
                    .inputs
                    .iter()
                    .filter_map(|input| pool.entry_id_by_txid(&input.previous_output.txid));
                let start = (
                    SpendingKey::from(OutPoint::new(entry.txid, u32::MIN)),
                    EntryId::MIN,
                );
                let end = (
                    SpendingKey::from(OutPoint::new(entry.txid, u32::MAX)),
                    EntryId::MAX,
                );
                let children = pool
                    .derived
                    .spending
                    .range(start..=end)
                    .map(|(_, child)| *child)
                    .collect::<Vec<_>>();
                for neighbour in parents.chain(children) {
                    if seen.insert(neighbour) {
                        part.push(neighbour);
                        queue.push(neighbour);
                    }
                }
            }
            part.sort_unstable();
            components.push(part);
        }
        components.sort();
        components
    }

    fn assert_graph_exact(pool: &Mempool) {
        let mut cached: Vec<Vec<EntryId>> = Vec::new();
        let mut by_component: HashMap<u32, Vec<EntryId>> = HashMap::new();
        for (index, _entry) in pool.entries.iter() {
            let id = EntryId::try_from(index).expect("slot index fits u32");
            let component = pool.component_id(id).expect("live entry has a component");
            by_component.entry(component).or_default().push(id);
        }
        for members in by_component.values_mut() {
            members.sort_unstable();
            cached.push(members.clone());
        }
        cached.sort();
        assert_eq!(cached, reference_components(pool), "component partition");

        for (component, members) in &by_component {
            let summary = pool
                .component_summary(*component)
                .expect("component id names a live summary");
            let vsize = members.iter().fold(0_u64, |total, member| {
                total.saturating_add(
                    pool.entry(*member)
                        .map_or(0, |entry| u64::from(entry.vsize)),
                )
            });
            assert_eq!(
                summary.member_count,
                u32::try_from(members.len()).unwrap_or(u32::MAX)
            );
            assert_eq!(
                summary.weight,
                vsize * 4,
                "summary vsize for component {component}"
            );
        }

        for (index, _entry) in pool.entries.iter() {
            let id = EntryId::try_from(index).expect("slot index fits u32");
            let links = pool.links(id).expect("live entry has links");
            let mut sorted_parents = links.parents.clone();
            sorted_parents.sort_unstable();
            sorted_parents.dedup();
            assert_eq!(
                sorted_parents, links.parents,
                "parents of {id} sorted+dedup"
            );
            let mut sorted_children = links.children.clone();
            sorted_children.sort_unstable();
            sorted_children.dedup();
            assert_eq!(
                sorted_children, links.children,
                "children of {id} sorted+dedup"
            );
            for parent in &links.parents {
                let back = pool.links(*parent).expect("parent link names a live entry");
                assert!(back.children.contains(&id), "link symmetry for {id}");
            }
            for child in &links.children {
                let back = pool.links(*child).expect("child link names a live entry");
                assert!(back.parents.contains(&id), "link symmetry for {id}");
            }
        }
    }

    fn graph_steps(pool: &Mempool) -> u64 {
        pool.graph_steps.load(Ordering::Relaxed)
    }

    #[test]
    fn component_merges_and_splits_track_the_reference() {
        let mut pool = fuzzer_pool();
        let a1 = insert_ok(&mut pool, 1, &[], 100);
        let a2 = insert_ok(&mut pool, 2, &[OutPoint::new(a1, 0)], 100);
        let a3 = insert_ok(&mut pool, 3, &[OutPoint::new(a2, 0)], 100);
        let b1 = insert_ok(&mut pool, 4, &[], 110);
        let b2 = insert_ok(&mut pool, 5, &[OutPoint::new(b1, 0)], 110);
        assert_graph_exact(&pool);
        assert_eq!(reference_components(&pool).len(), 2, "two disjoint chains");

        let bridge = insert_ok(
            &mut pool,
            6,
            &[OutPoint::new(a3, 0), OutPoint::new(b2, 0)],
            120,
        );
        assert_graph_exact(&pool);
        let merged = reference_components(&pool);
        assert_eq!(merged.len(), 1, "bridge joins the chains: {merged:?}");
        assert_eq!(merged[0].len(), 6);

        let bridge_id = pool.entry_id_by_txid(&bridge).expect("bridge is pooled");
        let mut changes = Vec::new();
        pool.remove_entries_with_reasons(
            &[(bridge_id, RemovalReason::PolicyEviction)],
            &mut changes,
        );
        assert_graph_exact(&pool);
        assert_eq!(
            reference_components(&pool).len(),
            2,
            "bridge removal splits"
        );
    }

    #[test]
    fn recycled_slots_do_not_inherit_links_or_transaction_indexes() {
        let mut pool = fuzzer_pool();
        let parent = insert_ok(&mut pool, 1, &[], 100);
        let child = insert_ok(&mut pool, 2, &[OutPoint::new(parent, 0)], 100);
        let leaf = insert_ok(&mut pool, 3, &[OutPoint::new(child, 0)], 100);
        let child_id = pool.entry_id_by_txid(&child).expect("pooled child");
        let child_wtxid = pool.entry(child_id).expect("pooled child").wtxid;
        pool.remove_entries_with_reasons(
            &[(child_id, RemovalReason::PolicyEviction)],
            &mut Vec::new(),
        );

        let replacement = insert_ok(&mut pool, 4, &[], 100);
        assert_eq!(pool.entry_id_by_txid(&replacement), Some(child_id));
        assert!(pool.entry_by_txid(&child).is_none());
        assert!(pool.entry_by_wtxid(&child_wtxid).is_none());
        let links = pool.links(child_id).expect("reused slot");
        assert_eq!(links.parents, Vec::<u32>::new());
        assert_eq!(links.children, Vec::<u32>::new());
        let parent_id = pool.entry_id_by_txid(&parent).expect("pooled parent");
        let leaf_id = pool.entry_id_by_txid(&leaf).expect("pooled leaf");
        assert_eq!(
            pool.links(parent_id).expect("parent links").children,
            Vec::<u32>::new()
        );
        assert_eq!(
            pool.links(leaf_id).expect("leaf links").parents,
            Vec::<u32>::new()
        );
        assert_graph_exact(&pool);

        let retained_slots = pool.entries.capacity();
        let _ = pool.clear();
        assert_eq!(pool.entries.capacity(), retained_slots);
        let fresh = insert_ok(&mut pool, 5, &[], 100);
        assert_eq!(pool.entry_id_by_txid(&fresh), Some(0));
        assert_eq!(pool.len(), 1);
        for retired in [parent, leaf, replacement] {
            assert!(pool.entry_by_txid(&retired).is_none());
        }
        assert_graph_exact(&pool);
    }

    #[test]
    fn wtxid_lookups_track_mutations() {
        let mut pool = fuzzer_pool();
        let first = insert_ok(&mut pool, 1, &[], 100);
        let wtxid = pool.entry_by_txid(&first).map(|entry| entry.wtxid);
        assert!(pool.contains_wtxid(&wtxid.expect("pooled")));
        assert_eq!(
            pool.entry_by_wtxid(&wtxid.expect("pooled"))
                .map(|entry| entry.txid),
            Some(first)
        );

        let first_id = pool.entry_id_by_txid(&first).expect("pooled");
        let mut changes = Vec::new();
        pool.remove_entries_with_reasons(
            &[(first_id, RemovalReason::PolicyEviction)],
            &mut changes,
        );
        assert!(!pool.contains_wtxid(&wtxid.expect("pooled")));
        assert!(pool.entry_by_wtxid(&wtxid.expect("pooled")).is_none());

        let second = insert_ok(&mut pool, 2, &[], 100);
        let second_wtxid = pool.entry_by_txid(&second).map(|entry| entry.wtxid);
        assert_ne!(wtxid, second_wtxid);
        assert!(pool.contains_wtxid(&second_wtxid.expect("pooled")));
    }

    #[test]
    fn plain_admission_enforces_cluster_limits_through_the_cache() {
        let mut pool = Mempool::new(MempoolLimits {
            max_total_bytes: 0,
            min_relay_fee_sat_per_kvb: 0,
            cluster_count: 4,
            cluster_size_vbytes: 1_000_000,
            ..MempoolLimits::default()
        });
        let a = insert_ok(&mut pool, 1, &[], 100);
        let b = insert_ok(&mut pool, 2, &[OutPoint::new(a, 0)], 100);
        let c = insert_ok(&mut pool, 3, &[], 100);
        let d = insert_ok(&mut pool, 4, &[OutPoint::new(c, 0)], 100);

        let joiner = graph_tx(5, &[OutPoint::new(b, 0), OutPoint::new(d, 0)], false);
        let entry = MempoolEntry::new(Arc::new(joiner.clone()), 100, 1_000, TIME, HEIGHT, 0);
        let error = pool
            .insert_entry(entry)
            .expect_err("cluster of five is over the limit");
        assert!(matches!(
            error,
            MempoolError::Policy(PolicyError::ClusterCountLimit)
        ));
        assert_eq!(pool.len(), 4, "rejection commits nothing");
        assert!(!pool.contains_txid(&joiner.txid()));

        assert!(matches!(
            pool.check_replacement(&crate::ReplacementCandidate::new(
                Arc::new(joiner),
                100,
                1_000,
                1_000
            )),
            Err(crate::RbfError::Mempool(MempoolError::Policy(
                PolicyError::ClusterCountLimit
            )))
        ));

        let _e = insert_ok(&mut pool, 6, &[OutPoint::new(a, 0)], 100);
        assert_graph_exact(&pool);
    }

    #[test]
    fn check_cluster_limits_cached_matches_walk_across_graph_shapes() {
        fn agrees(pool: &Mempool, tx: &Tx, weight: u64, expected: Result<(), PolicyError>) {
            let excluded: HashSet<EntryId> = HashSet::new();
            assert_eq!(
                pool.check_cluster_limits_cached(tx, weight),
                expected,
                "cached verdict must match the pinned outcome"
            );
            assert_eq!(
                pool.check_cluster_limits_by_walk(tx, weight, &excluded),
                expected,
                "walk verdict must match the pinned outcome"
            );
        }

        fn shape_pool(count: u32) -> Mempool {
            Mempool::new(MempoolLimits {
                max_total_bytes: 0,
                min_relay_fee_sat_per_kvb: 0,
                cluster_count: count,
                cluster_size_vbytes: 1_000_000,
                ..MempoolLimits::default()
            })
        }

        let mut pool = shape_pool(4);
        let parent_one = insert_ok(&mut pool, 1, &[], 100);
        let child_one = insert_ok(&mut pool, 2, &[OutPoint::new(parent_one, 0)], 100);
        let parent_two = insert_ok(&mut pool, 3, &[], 100);
        let child_two = insert_ok(&mut pool, 4, &[OutPoint::new(parent_two, 0)], 100);
        let joiner = graph_tx(
            5,
            &[OutPoint::new(child_one, 0), OutPoint::new(child_two, 0)],
            false,
        );
        agrees(&pool, &joiner, 400, Err(PolicyError::ClusterCountLimit));

        let mut pool = shape_pool(4);
        let probe = insert_ok(&mut pool, 1, &[], 100);
        let c1 = insert_ok(&mut pool, 2, &[OutPoint::new(probe, 0)], 100);
        let _c2 = insert_ok(&mut pool, 3, &[OutPoint::new(probe, 0)], 100);
        let sibling_spender = graph_tx(4, &[OutPoint::new(c1, 0)], false);
        agrees(&pool, &sibling_spender, 400, Ok(()));

        let mut pool = shape_pool(3);
        let split_root = insert_ok(&mut pool, 1, &[], 100);
        let split_mid = insert_ok(&mut pool, 2, &[OutPoint::new(split_root, 0)], 100);
        let _split_tail = insert_ok(&mut pool, 3, &[OutPoint::new(split_mid, 0)], 100);
        let split_mid_id = pool
            .entry_id_by_txid(&split_mid)
            .expect("middle entry resolves");
        pool.remove_entries_with_reasons(
            &[(split_mid_id, RemovalReason::Conflict)],
            &mut Vec::new(),
        );
        let rejoiner = graph_tx(4, &[OutPoint::new(split_root, 0)], false);
        agrees(&pool, &rejoiner, 400, Ok(()));

        let mut pool = Mempool::new(MempoolLimits {
            max_total_bytes: 0,
            min_relay_fee_sat_per_kvb: 0,
            cluster_count: 8,
            cluster_size_vbytes: 200,
            ..MempoolLimits::default()
        });
        let oversize_root = insert_ok(&mut pool, 1, &[], 100);
        let oversize_mid = insert_ok(&mut pool, 2, &[OutPoint::new(oversize_root, 0)], 100);
        let overweight = graph_tx(3, &[OutPoint::new(oversize_mid, 0)], false);
        agrees(&pool, &overweight, 400, Err(PolicyError::ClusterSizeLimit));

        let mut pool = shape_pool(4);
        let parent_tx = graph_tx(1, &[], false);
        let parent_txid = parent_tx.txid();
        let _child = insert_ok(&mut pool, 2, &[OutPoint::new(parent_txid, 0)], 100);
        agrees(&pool, &parent_tx, 400, Ok(()));
        assert_eq!(pool.len(), 1, "the fixture pools the child only");
    }

    #[test]
    fn removal_splits_repartition_by_bounded_walk() {
        let mut pool = Mempool::new(MempoolLimits {
            max_total_bytes: 0,
            min_relay_fee_sat_per_kvb: 0,
            cluster_count: 8,
            cluster_size_vbytes: 1_000_000,
            ..MempoolLimits::default()
        });
        let root = insert_ok(&mut pool, 1, &[], 100);
        let left = insert_ok(&mut pool, 2, &[OutPoint::new(root, 0)], 100);
        let right = insert_ok(&mut pool, 3, &[OutPoint::new(root, 0)], 100);
        let sink = insert_ok(
            &mut pool,
            4,
            &[OutPoint::new(left, 0), OutPoint::new(right, 0)],
            100,
        );
        let tail = insert_ok(&mut pool, 5, &[OutPoint::new(sink, 0)], 100);
        let end = insert_ok(&mut pool, 6, &[OutPoint::new(tail, 0)], 100);
        assert_graph_exact(&pool);
        assert_eq!(reference_components(&pool)[0].len(), 6);

        let sink_id = pool.entry_id_by_txid(&sink).expect("pooled");
        let mut changes = Vec::new();
        pool.remove_entries_with_reasons(&[(sink_id, RemovalReason::PolicyEviction)], &mut changes);
        assert_graph_exact(&pool);
        let parts = reference_components(&pool);
        assert_eq!(parts.len(), 2, "the sink held the two halves: {parts:?}");
        assert_eq!(parts[0].len() + parts[1].len(), 5);

        let root_id = pool.entry_id_by_txid(&root).expect("pooled");
        assert_eq!(pool.links(root_id).expect("pooled").children.len(), 2);
        let _ = end;
    }

    #[test]
    fn graph_work_stays_local_on_worst_case_shapes() {
        let mut pool = Mempool::new(MempoolLimits {
            max_total_bytes: 0,
            min_relay_fee_sat_per_kvb: 0,
            cluster_count: 64,
            cluster_size_vbytes: 1_000_000,
            ..MempoolLimits::default()
        });
        let mut nonce = 0_u32;
        for _chain in 0..40 {
            let mut parent = insert_ok(&mut pool, nonce, &[], 100);
            nonce += 1;
            for _depth in 0..9 {
                parent = insert_ok(&mut pool, nonce, &[OutPoint::new(parent, 0)], 100);
                nonce += 1;
            }
        }
        assert_eq!(pool.len(), 400);

        pool.graph_steps.store(0, Ordering::Relaxed);
        let _ = insert_ok(&mut pool, nonce, &[], 100);
        nonce += 1;
        assert!(graph_steps(&pool) < 8, "isolated insert walked the pool");

        let live = pool.iter_txids();
        let anchor = live[live.len() / 2];
        pool.graph_steps.store(0, Ordering::Relaxed);
        let _ = insert_ok(&mut pool, nonce, &[OutPoint::new(anchor, 0)], 100);
        assert!(
            graph_steps(&pool) < 4 * 10 + 48,
            "leaf insert walked beyond its cluster: {}",
            graph_steps(&pool)
        );

        let middle = live[live.len() / 4];
        let middle_id = pool.entry_id_by_txid(&middle).expect("pooled");
        pool.graph_steps.store(0, Ordering::Relaxed);
        let mut changes = Vec::new();
        pool.remove_entries_with_reasons(
            &[(middle_id, RemovalReason::PolicyEviction)],
            &mut changes,
        );
        assert!(
            graph_steps(&pool) < 4 * 10 + 64,
            "split recompute walked beyond the broken cluster: {}",
            graph_steps(&pool)
        );
        assert_graph_exact(&pool);
    }

    fn try_insert_tracked(
        pool: &mut Mempool,
        txs: &mut Vec<Tx>,
        history: &mut Vec<(EntryId, Txid)>,
        nonce: u32,
        inputs: &[OutPoint],
        vsize: u32,
    ) -> Option<Txid> {
        let tx = graph_tx(nonce, inputs, false);
        let txid = tx.txid();
        let outcome = pool.insert_entry(MempoolEntry::new(
            Arc::new(tx.clone()),
            vsize,
            1_000,
            TIME,
            HEIGHT,
            0,
        ));
        outcome.ok()?;
        txs.push(tx);
        let id = pool.entry_id_by_txid(&txid)?;
        history.push((id, txid));
        Some(txid)
    }

    #[test]
    #[expect(clippy::too_many_lines)]
    fn random_mutations_leave_graph_semantics_exact() {
        for seed in [0x5EED_u64, 0xC0_FFEE, 0xB1_05] {
            let mut pool = fuzzer_pool();
            let mut rng = XorShift::new(seed);
            let mut nonce = 0_u32;
            let mut txs: Vec<Tx> = Vec::new();
            let mut history: Vec<(EntryId, Txid)> = Vec::new();

            for _round in 0..350 {
                let live = pool.iter_txids();
                pool.graph_steps.store(0, Ordering::Relaxed);
                match rng.below(10) {
                    0..=4 => {
                        if live.is_empty() {
                            continue;
                        }
                        let count = 1 + rng.below(3.min(live.len()));
                        let mut picked_parents: HashSet<Txid> = HashSet::new();
                        for _ in 0..count {
                            picked_parents.insert(live[rng.below(live.len())]);
                        }
                        let picked: Vec<OutPoint> = picked_parents
                            .iter()
                            .map(|txid| OutPoint::new(*txid, 0))
                            .collect();
                        let vsize = 100 + u32::try_from(rng.below(5) * 10).unwrap_or(100);
                        try_insert_tracked(
                            &mut pool,
                            &mut txs,
                            &mut history,
                            nonce,
                            &picked,
                            vsize,
                        );
                        nonce += 1;
                    }
                    5 => {
                        try_insert_tracked(&mut pool, &mut txs, &mut history, nonce, &[], 100);
                        nonce += 1;
                    }
                    6 if !live.is_empty() => {
                        let victim = live[rng.below(live.len())];
                        if let Some(id) = pool.entry_id_by_txid(&victim) {
                            let mut changes = Vec::new();
                            pool.remove_entries_with_reasons(
                                &[(id, RemovalReason::PolicyEviction)],
                                &mut changes,
                            );
                        }
                    }
                    7 if !txs.is_empty() => {
                        let count = 1 + rng.below(3.min(txs.len()));
                        let confirmed = (0..count)
                            .map(|_| txs[rng.below(txs.len())].clone())
                            .collect::<Vec<_>>();
                        let confirmed_refs: Vec<&Tx> = confirmed.iter().collect();
                        let confirmed_ids: Vec<Txid> = confirmed.iter().map(Tx::txid).collect();
                        let _ =
                            pool.remove_for_block(&confirmed_refs, &confirmed_ids, HEIGHT + 1, 1);
                    }
                    8 if !live.is_empty() => {
                        let victim = live[rng.below(live.len())];
                        let Some(victim_entry) = pool.entry_by_txid(&victim) else {
                            continue;
                        };
                        let Some(input) = victim_entry.tx.inputs.first() else {
                            continue;
                        };
                        let candidate = graph_tx(nonce, &[input.previous_output], true);
                        nonce += 1;
                        let evicted =
                            pool.descendants_of_conflicts(&pool.conflicts_for(&candidate));
                        if evicted.is_empty() {
                            continue;
                        }
                        let excluded: HashSet<EntryId> = evicted.iter().copied().collect();
                        let fee = 2_000 + u64::try_from(rng.below(1_000)).unwrap_or(0);
                        let entry = MempoolEntry::new(
                            Arc::new(candidate.clone()),
                            100,
                            fee,
                            TIME,
                            HEIGHT,
                            0,
                        );
                        let Ok(prepared) = pool.validate_insert(
                            entry,
                            &excluded,
                            crate::rbf::LimitEnforcement::Full,
                        ) else {
                            continue;
                        };
                        let removals = evicted
                            .iter()
                            .map(|id| (*id, RemovalReason::Replaced))
                            .collect::<Vec<_>>();
                        let mut changes = Vec::new();
                        pool.remove_entries_with_reasons(&removals, &mut changes);
                        let _committed = pool.commit_insert(prepared);
                        if let Some(id) = pool.entry_id_by_txid(&candidate.txid()) {
                            history.push((id, candidate.txid()));
                        }
                    }
                    9 if pool.len() > 8 => {
                        let target = u64::try_from(rng.below(200) * 100).unwrap_or(0);
                        crate::evict_lowest_fee_packages(&mut pool, target)
                            .expect("valid graph eviction");
                    }
                    _ => {}
                }

                assert!(
                    graph_steps(&pool) < 64 * 8 + 128,
                    "walk budget exceeded: {}",
                    graph_steps(&pool)
                );
                for (id, txid) in &history {
                    let live_now = pool.contains_txid(txid);
                    assert_eq!(
                        pool.entry(*id).is_some_and(|entry| entry.txid == *txid),
                        live_now,
                        "slot identity for {txid:?} must track liveness exactly"
                    );
                }
                assert_graph_exact(&pool);
            }
        }
    }
}
