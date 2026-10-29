use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::fmt;

use bitcoin_rs_primitives::Txid;
use hashbrown::HashSet;
use smallvec::SmallVec;

use crate::fee_diagram::{self, FeeWeight};
use crate::{EntryId, Mempool, MempoolEntry};

type ComponentId = u32;

const MAX_CHUNK_WEIGHT: u32 = 0x7fff_ffff;

const MAX_CHUNK_FEE: i128 = 1 << 94;

#[derive(Clone, Copy, Debug)]
pub(crate) struct MemberFacts<'a> {
    pub(crate) id: EntryId,
    pub(crate) entry: &'a MempoolEntry,
    pub(crate) parents: &'a [EntryId],
}

impl MemberFacts<'_> {
    fn fee_weight(&self) -> FeeWeight {
        FeeWeight {
            fee: self.entry.modified_fee(),
            weight: u32::try_from(self.entry.policy_weight()).unwrap_or(u32::MAX),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ChunkKey {
    pub(crate) modified_fee: i128,
    pub(crate) charged_weight: u64,
    pub(crate) prefix_weight: u64,
    pub(crate) max_txid: Txid,
    pub(crate) component: ComponentId,
    pub(crate) ordinal: u32,
}

impl Ord for ChunkKey {
    fn cmp(&self, other: &Self) -> Ordering {
        let ours = self.modified_fee * i128::from(other.charged_weight);
        let theirs = other.modified_fee * i128::from(self.charged_weight);
        theirs
            .cmp(&ours)
            .then_with(|| self.prefix_weight.cmp(&other.prefix_weight))
            .then_with(|| self.max_txid.cmp(&other.max_txid))
            .then_with(|| self.component.cmp(&other.component))
            .then_with(|| self.ordinal.cmp(&other.ordinal))
    }
}

impl PartialOrd for ChunkKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Default)]
struct PrefixRun {
    rate: Option<FeeWeight>,
    weight: u64,
}

impl PrefixRun {
    fn extend(&mut self, total: FeeWeight) -> u64 {
        let weight = u64::from(total.weight);
        self.weight = match self.rate {
            Some(rate) if rate.rate_cmp(total) == Ordering::Equal => {
                self.weight.saturating_add(weight)
            }
            _ => weight,
        };
        self.rate = Some(total);
        self.weight
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ChunkSlot {
    pub(crate) end: usize,
    pub(crate) key: ChunkKey,
}

#[derive(Debug, Default)]
pub(crate) struct ComponentState {
    pub(crate) members: SmallVec<[EntryId; 1]>,
    pub(crate) txids: SmallVec<[Txid; 1]>,
    pub(crate) chunks: SmallVec<[ChunkSlot; 1]>,
}

impl ComponentState {
    pub(crate) fn singleton(component: ComponentId, member: &MemberFacts<'_>) -> Self {
        let mut state = Self::default();
        state.push_member(member);
        let total = FeeWeight::default().checked_add(member.fee_weight());
        match total {
            Ok(total) if total.weight > 0 => {
                state.close_chunk(component, total, &mut PrefixRun::default());
            }
            _ => state.close_fallback_chunk(component, core::slice::from_ref(member)),
        }
        state
    }

    pub(crate) fn linearized(component: ComponentId, members: &[MemberFacts<'_>]) -> Self {
        let mut sorted = members.to_vec();
        sorted.sort_unstable_by_key(|member| member.entry.txid);
        let mut by_id: Vec<(EntryId, usize)> = sorted
            .iter()
            .enumerate()
            .map(|(position, member)| (member.id, position))
            .collect();
        by_id.sort_unstable();
        let fees: Vec<FeeWeight> = sorted.iter().map(MemberFacts::fee_weight).collect();
        let parents: Vec<Vec<usize>> = sorted
            .iter()
            .map(|member| {
                member
                    .parents
                    .iter()
                    .filter_map(|parent| {
                        by_id
                            .binary_search_by_key(parent, |&(id, _)| id)
                            .ok()
                            .map(|found| by_id[found].1)
                    })
                    .collect()
            })
            .collect();
        let chunks = match fee_diagram::linearize(&fees, &parents) {
            Ok(chunks) => chunks,
            Err(error) => {
                tracing::error!(%error, component, "chunk index solver refused a cluster");
                return Self::dependency_ordered(component, &sorted, &parents);
            }
        };
        let mut state = Self::default();
        let mut run = PrefixRun::default();
        for chunk in chunks {
            for &position in &chunk.members {
                state.push_member(&sorted[position]);
            }
            state.close_chunk(component, chunk.total, &mut run);
        }
        state
    }

    fn dependency_ordered(
        component: ComponentId,
        sorted: &[MemberFacts<'_>],
        parents: &[Vec<usize>],
    ) -> Self {
        let all: Vec<usize> = (0..sorted.len()).collect();
        let order = fee_diagram::topological(parents, &all).unwrap_or(all);
        let ordered: Vec<MemberFacts<'_>> =
            order.into_iter().map(|position| sorted[position]).collect();
        let mut state = Self::default();
        for member in &ordered {
            state.push_member(member);
        }
        state.close_fallback_chunk(component, &ordered);
        state
    }

    fn push_member(&mut self, member: &MemberFacts<'_>) {
        self.members.push(member.id);
        self.txids.push(member.entry.txid);
    }

    fn close_chunk(&mut self, component: ComponentId, total: FeeWeight, run: &mut PrefixRun) {
        let start = self.chunks.last().map_or(0, |slot| slot.end);
        let max_txid = self.txids[start..]
            .iter()
            .copied()
            .max()
            .unwrap_or_default();
        let key = ChunkKey {
            modified_fee: total.fee,
            charged_weight: u64::from(total.weight),
            prefix_weight: run.extend(total),
            max_txid,
            component,
            ordinal: u32::try_from(self.chunks.len()).unwrap_or(u32::MAX),
        };
        self.chunks.push(ChunkSlot {
            end: self.members.len(),
            key,
        });
    }

    fn close_fallback_chunk(&mut self, component: ComponentId, members: &[MemberFacts<'_>]) {
        let total = members.iter().fold(FeeWeight::default(), |total, member| {
            let next = member.fee_weight();
            FeeWeight {
                fee: total
                    .fee
                    .saturating_add(next.fee)
                    .clamp(-MAX_CHUNK_FEE, MAX_CHUNK_FEE),
                weight: total
                    .weight
                    .saturating_add(next.weight)
                    .clamp(1, MAX_CHUNK_WEIGHT),
            }
        });
        self.close_chunk(component, total, &mut PrefixRun::default());
    }

    fn chunk_range(&self, ordinal: usize) -> core::ops::Range<usize> {
        let start = ordinal
            .checked_sub(1)
            .map_or(0, |previous| self.chunks[previous].end);
        start..self.chunks[ordinal].end
    }
}

#[derive(Clone, Copy)]
pub struct ChunkView<'a> {
    pool: &'a Mempool,
    pub members: &'a [EntryId],
    pub txids: &'a [Txid],
    /// Modified fee of the whole chunk: actual fees plus signed overlays.
    pub modified_fee: i128,
    /// Charged weight of the whole chunk, the feerate denominator.
    pub charged_weight: u64,
    confirmed: Option<&'a HashSet<EntryId>>,
}

impl fmt::Debug for ChunkView<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChunkView")
            .field("members", &self.members)
            .field("modified_fee", &self.modified_fee)
            .field("charged_weight", &self.charged_weight)
            .finish_non_exhaustive()
    }
}

impl<'a> ChunkView<'a> {
    #[must_use]
    pub const fn len(&self) -> usize {
        self.members.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    pub fn entries(&self) -> impl ExactSizeIterator<Item = (EntryId, &'a MempoolEntry)> + use<'a> {
        let pool = self.pool;
        self.members
            .iter()
            .map(move |&member| (member, pool.chunk_member(member)))
    }

    pub fn is_staged_confirmed(&self, id: EntryId) -> bool {
        self.confirmed.is_some_and(|set| set.contains(&id))
    }

    pub fn parents_of(&self, member: EntryId) -> impl Iterator<Item = EntryId> + use<'a> {
        let pool = self.pool;
        let confirmed = self.confirmed;
        pool.parents_of(member)
            .iter()
            .copied()
            .filter(move |&parent| confirmed.is_none_or(|set| !set.contains(&parent)))
    }
}

#[derive(Debug, Default)]
pub(crate) struct ChunkIndex {
    components: Vec<ComponentState>,
    order: BTreeSet<ChunkKey>,
}

impl ChunkIndex {
    pub(crate) fn relinearize(&mut self, component: ComponentId, members: &[MemberFacts<'_>]) {
        self.forget(component);
        let state = match members {
            [] => return,
            [only] => ComponentState::singleton(component, only),
            _ => ComponentState::linearized(component, members),
        };
        self.order.extend(state.chunks.iter().map(|slot| slot.key));
        let index = component_index(component);
        if index >= self.components.len() {
            self.components
                .resize_with(index + 1, ComponentState::default);
        }
        self.components[index] = state;
    }

    pub(crate) fn forget(&mut self, component: ComponentId) {
        let Some(state) = self.components.get_mut(component_index(component)) else {
            return;
        };
        for slot in &state.chunks {
            self.order.remove(&slot.key);
        }
        *state = ComponentState::default();
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.components
            .iter()
            .filter(|state| !state.chunks.is_empty())
            .count()
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    pub(crate) fn members_of(&self, component: ComponentId) -> Option<&[EntryId]> {
        let state = self.components.get(component_index(component))?;
        if state.chunks.is_empty() {
            return None;
        }
        Some(state.members.as_slice())
    }

    fn view<'a>(&'a self, pool: &'a Mempool, key: &ChunkKey) -> ChunkView<'a> {
        self.view_with(pool, key, None)
    }

    fn view_with<'a>(
        &'a self,
        pool: &'a Mempool,
        key: &ChunkKey,
        confirmed: Option<&'a HashSet<EntryId>>,
    ) -> ChunkView<'a> {
        let Some(state) = self.components.get(component_index(key.component)) else {
            panic!("chunk keys always name a live component");
        };
        let range = state.chunk_range(usize::try_from(key.ordinal).unwrap_or(usize::MAX));
        ChunkView {
            pool,
            members: &state.members[range.clone()],
            txids: &state.txids[range],
            modified_fee: key.modified_fee,
            charged_weight: key.charged_weight,
            confirmed,
        }
    }

    pub(crate) fn chunks_descending<'a>(
        &'a self,
        pool: &'a Mempool,
    ) -> impl DoubleEndedIterator<Item = ChunkView<'a>> + 'a {
        self.order.iter().map(move |key| self.view(pool, key))
    }

    #[must_use]
    pub(crate) fn dynamic_memory_usage(&self) -> u64 {
        use core::mem::size_of;

        let bytes = |count: usize, each: usize| {
            u64::try_from(count)
                .unwrap_or(u64::MAX)
                .saturating_mul(u64::try_from(each).unwrap_or(0))
        };
        let keys = bytes(self.order.len(), size_of::<ChunkKey>());
        let slots = bytes(self.components.capacity(), size_of::<ComponentState>());
        self.components
            .iter()
            .fold(keys.saturating_add(slots), |total, state| {
                let spilled = |spilt: bool, capacity: usize, each: usize| {
                    if spilt { bytes(capacity, each) } else { 0 }
                };
                total
                    .saturating_add(spilled(
                        state.members.spilled(),
                        state.members.capacity(),
                        size_of::<EntryId>(),
                    ))
                    .saturating_add(spilled(
                        state.txids.spilled(),
                        state.txids.capacity(),
                        size_of::<Txid>(),
                    ))
                    .saturating_add(spilled(
                        state.chunks.spilled(),
                        state.chunks.capacity(),
                        size_of::<ChunkSlot>(),
                    ))
            })
    }
}

#[derive(Debug)]
pub struct ProjectedChunks<'a> {
    pool: &'a Mempool,
    confirmed: HashSet<EntryId>,
    touched: HashSet<u32>,
    pieces: Vec<ComponentState>,
    order: Vec<(ChunkKey, usize, usize)>,
}

impl<'a> ProjectedChunks<'a> {
    pub(crate) fn new(
        pool: &'a Mempool,
        confirmed: HashSet<EntryId>,
        touched: HashSet<u32>,
        pieces: Vec<ComponentState>,
    ) -> Self {
        let mut order = Vec::new();
        for (piece, state) in pieces.iter().enumerate() {
            for (ordinal, slot) in state.chunks.iter().enumerate() {
                order.push((slot.key, piece, ordinal));
            }
        }
        order.sort_by_key(|item| item.0);
        Self {
            pool,
            confirmed,
            touched,
            pieces,
            order,
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = ChunkView<'_>> + '_ {
        ProjectedChunksIter {
            pool: self.pool,
            confirmed: &self.confirmed,
            touched: &self.touched,
            index: self.pool.chunk_index(),
            live: self.pool.chunk_index().order.iter(),
            staged_live: StagedLive::Unread,
            pieces: self.pieces.as_slice(),
            order: self.order.as_slice(),
            front: 0,
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.order.is_empty() && {
            let index = self.pool.chunk_index();
            index
                .order
                .iter()
                .all(|key| self.touched.contains(&key.component))
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        let index = self.pool.chunk_index();
        let untouched = index
            .order
            .iter()
            .filter(|key| !self.touched.contains(&key.component))
            .count();
        untouched + self.order.len()
    }
}

#[derive(Clone, Copy, Debug)]
enum StagedLive<'s> {
    Unread,
    Ready(&'s ChunkKey),
    Exhausted,
}

struct ProjectedChunksIter<'s> {
    pool: &'s Mempool,
    confirmed: &'s HashSet<EntryId>,
    touched: &'s HashSet<u32>,
    index: &'s ChunkIndex,
    live: alloc::collections::btree_set::Iter<'s, ChunkKey>,
    staged_live: StagedLive<'s>,
    pieces: &'s [ComponentState],
    order: &'s [(ChunkKey, usize, usize)],
    front: usize,
}

impl<'s> ProjectedChunksIter<'s> {
    fn prime_live(&mut self) -> Option<&'s ChunkKey> {
        if matches!(self.staged_live, StagedLive::Unread) {
            match self
                .live
                .by_ref()
                .find(|key| !self.touched.contains(&key.component))
            {
                Some(key) => self.staged_live = StagedLive::Ready(key),
                None => self.staged_live = StagedLive::Exhausted,
            }
        }
        match self.staged_live {
            StagedLive::Ready(key) => Some(key),
            StagedLive::Unread | StagedLive::Exhausted => None,
        }
    }

    fn take_live(&mut self) -> Option<&'s ChunkKey> {
        match self.staged_live {
            StagedLive::Ready(key) => {
                self.staged_live = StagedLive::Unread;
                Some(key)
            }
            StagedLive::Unread | StagedLive::Exhausted => None,
        }
    }

    fn peek_projected(&self) -> Option<&'s (ChunkKey, usize, usize)> {
        self.order.get(self.front)
    }

    fn live_view(&self, key: &'s ChunkKey) -> ChunkView<'s> {
        self.index.view_with(self.pool, key, Some(self.confirmed))
    }

    fn projected_view(&self, entry: &'s (ChunkKey, usize, usize)) -> Option<ChunkView<'s>> {
        let (key, piece, ordinal) = entry;
        let state = self.pieces.get(*piece)?;
        let range = state.chunk_range(*ordinal);
        Some(ChunkView {
            pool: self.pool,
            members: &state.members[range.clone()],
            txids: &state.txids[range],
            modified_fee: key.modified_fee,
            charged_weight: key.charged_weight,
            confirmed: Some(self.confirmed),
        })
    }
}

impl<'s> Iterator for ProjectedChunksIter<'s> {
    type Item = ChunkView<'s>;

    fn next(&mut self) -> Option<Self::Item> {
        let live_key = self.prime_live();
        let projected = self.peek_projected();
        if live_key.is_none() && projected.is_none() {
            return None;
        }
        if projected.is_none() {
            return self.take_live().map(|key| self.live_view(key));
        }
        if live_key.is_none() {
            let entry = self.order.get(self.front)?;
            self.front += 1;
            return self.projected_view(entry);
        }
        let live = live_key?;
        let entry = projected?;
        if entry.0 < *live {
            self.front += 1;
            return self.projected_view(entry);
        }
        self.take_live().map(|key| self.live_view(key))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, None)
    }
}

fn component_index(component: ComponentId) -> usize {
    usize::try_from(component).unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests;
