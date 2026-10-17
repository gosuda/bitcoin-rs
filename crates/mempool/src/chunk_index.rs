//! Maintained chunk order over the live pool.
//!
//! One owner of every cluster's exact linearization. `ChunkIndex` keeps, per
//! component, the members in linearization order and the chunk boundaries,
//! plus one global `BTreeSet` of [`ChunkKey`]s that orders every chunk of
//! every component the way Core's block builder walks them. The exact min-cut
//! solver in `fee_diagram` stays the only linearization engine; this module
//! stores its output and orders it. The pool calls [`ChunkIndex::relinearize`]
//! once per changed component and [`ChunkIndex::forget`] for every component
//! id it frees, so the index never holds a stale or absorbed component.
//!
//! # Order of chunks
//!
//! Chunks sort by, in this order:
//!
//! 1. higher feerate first, compared exactly by cross-multiplication;
//! 2. the equal-feerate chunk prefix weight, ascending;
//! 3. the greatest member txid of the chunk, ascending;
//! 4. component id, then ordinal inside the component.
//!
//! The prefix weight is Core's `m_main_equal_feerate_chunk_prefix_size`
//! (`txgraph.cpp:502-519,1075-1128`): the summed charged weight of the
//! component's chunks that share this chunk's feerate, from the first of
//! them up to and including this chunk, in linearization order. Weighing the
//! chunk alone is not enough. A linearization may emit a parent chunk and its
//! child chunk at exactly the same feerate (parent 2000 sat over 800 WU, child
//! 1000 sat over 400 WU); the lighter child would then sort before its parent
//! and break dependency order for every consumer that walks the index. The
//! prefix grows strictly along such a run, so within one component the key
//! order is the linearization order, whatever the weights are. Chunks of
//! different components that tie on feerate and prefix fall to the txid rule,
//! Core's fallback order (`txmempool.cpp:183-186` orders by txid and
//! `m_main_max_chunk_fallback` is the maximal member).
//!
//! The order is a total order: every comparison is lexicographic over exact
//! orders (a total preorder on rationals, then `u64`, then txid, then ids),
//! so it is transitive, and no two live chunks compare equal because the last
//! two fields name the chunk.
//!
//! Equal-feerate chunks stay separate. Merging a run into one chunk would
//! change what fits: selection and eviction keep skipping or taking whole
//! chunks, as Core's builder does.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::fmt;

use bitcoin_rs_primitives::Txid;
use hashbrown::HashSet;
use smallvec::SmallVec;

use crate::fee_diagram::{self, FeeWeight};
use crate::{EntryId, Mempool, MempoolEntry};

/// Component id local to the index; mirrors the pool's component arena ids.
type ComponentId = u32;

/// Heaviest chunk the solver represents: `FeeWeight` caps totals at `i32::MAX`.
const MAX_CHUNK_WEIGHT: u32 = 0x7fff_ffff;

/// Largest chunk fee the fallback chunk keeps, so key cross-products stay
/// inside `i128`: `2^94 * 2^31 < 2^127`.
const MAX_CHUNK_FEE: i128 = 1 << 94;

/// One live member of a component as the pool hands it to the index, borrowed
/// straight out of the entry arena.
#[derive(Clone, Copy, Debug)]
pub(crate) struct MemberFacts<'a> {
    pub(crate) id: EntryId,
    pub(crate) entry: &'a MempoolEntry,
    /// Direct in-pool parents of the entry.
    pub(crate) parents: &'a [EntryId],
}

impl MemberFacts<'_> {
    /// Fee and weight the solver ranks this member by.
    fn fee_weight(&self) -> FeeWeight {
        FeeWeight {
            fee: self.entry.modified_fee(),
            weight: u32::try_from(self.entry.policy_weight()).unwrap_or(u32::MAX),
        }
    }
}

/// Sort key of one chunk in the global order. See the module documentation
/// for the fields' roles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ChunkKey {
    /// Modified fee of the whole chunk.
    pub(crate) modified_fee: i128,
    /// Charged weight of the whole chunk; at least 1.
    pub(crate) charged_weight: u64,
    /// Charged weight of the equal-feerate run of this component up to and
    /// including this chunk.
    pub(crate) prefix_weight: u64,
    /// Greatest txid among the chunk's members.
    pub(crate) max_txid: Txid,
    pub(crate) component: ComponentId,
    pub(crate) ordinal: u32,
}

impl Ord for ChunkKey {
    fn cmp(&self, other: &Self) -> Ordering {
        // Chunk totals are bounded by the solver (`FeeWeight::checked_add`
        // keeps `fee * i32::MAX` inside `i128`) or by `MAX_CHUNK_FEE`, and a
        // weight never exceeds `i32::MAX`, so both products fit.
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

/// Tracks Core's equal-feerate prefix while chunks append in linearization
/// order. Linearizations emit non-increasing feerates, so equal-feerate
/// chunks are adjacent.
#[derive(Default)]
struct PrefixRun {
    rate: Option<FeeWeight>,
    weight: u64,
}

impl PrefixRun {
    /// Returns the prefix weight of a chunk with `total` appended next.
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

/// One chunk of a component: where it ends in the member list and its key.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ChunkSlot {
    /// Exclusive end of the chunk inside `members`.
    pub(crate) end: usize,
    pub(crate) key: ChunkKey,
}

/// Everything the index stores for one live component.
#[derive(Debug, Default)]
pub(crate) struct ComponentState {
    /// Members in linearization order, chunk by chunk, concatenated.
    pub(crate) members: SmallVec<[EntryId; 1]>,
    /// Member txids in the same order.
    pub(crate) txids: SmallVec<[Txid; 1]>,
    /// Chunks in linearization order; empty when the component is not live.
    pub(crate) chunks: SmallVec<[ChunkSlot; 1]>,
}

impl ComponentState {
    /// A component of one transaction: one chunk, no solver run.
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

    /// Linearizes a component of two or more transactions with the exact
    /// solver. The solver's local order is txid order, so the result is a
    /// function of the cluster's content, not of arena slot reuse.
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

    /// The whole cluster as one chunk in dependency order, for a cluster the
    /// solver refused. Admission bounds weights, fees, and cluster size well
    /// inside what the solver accepts, so this is unreachable for pooled
    /// entries; the component must still stay visible to selection and
    /// eviction.
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

    /// Closes the chunk made of the members pushed since the last close.
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

    /// Closes one chunk over `members` with saturated totals, for entries the
    /// solver cannot rank.
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

    /// The member range of chunk `ordinal`.
    fn chunk_range(&self, ordinal: usize) -> core::ops::Range<usize> {
        let start = ordinal
            .checked_sub(1)
            .map_or(0, |previous| self.chunks[previous].end);
        start..self.chunks[ordinal].end
    }
}

/// Read view of one indexed chunk, handed to selection and eviction while the
/// caller holds the pool guard. Everything borrows the pool: nothing copies.
///
/// During block-template projection `confirmed` holds the entries the staged
/// block confirms, and [`ChunkView::parents_of`] omits them so a surviving
/// child does not require a confirmed parent in the candidate's selected set.
#[derive(Clone, Copy)]
pub struct ChunkView<'a> {
    pool: &'a Mempool,
    /// Member entry ids in linearization order.
    pub members: &'a [EntryId],
    /// Member txids in the same order.
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
    /// Number of transactions in the chunk.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.members.len()
    }

    /// Returns whether the chunk holds no transaction. Indexed chunks never do.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// The chunk's entries in linearization order: each member's pool id
    /// paired with its borrowed entry.
    pub fn entries(&self) -> impl ExactSizeIterator<Item = (EntryId, &'a MempoolEntry)> + use<'a> {
        let pool = self.pool;
        self.members
            .iter()
            .map(move |&member| (member, pool.chunk_member(member)))
    }

    /// The direct in-pool parents of `member` that require in-block
    /// selection, which may sit in this chunk or in an earlier chunk of the
    /// same component. During projection parents the staged block confirms
    /// are omitted, so surviving children do not require confirmed parents
    /// in the candidate's selected set. Returns an iterator by value: no
    /// filtered-slice allocation.
    pub fn parents_of(&self, member: EntryId) -> impl Iterator<Item = EntryId> + use<'a> {
        let pool = self.pool;
        let confirmed = self.confirmed;
        pool.parents_of(member)
            .iter()
            .copied()
            .filter(move |&parent| confirmed.is_none_or(|set| !set.contains(&parent)))
    }
}

/// Maintained chunk index over the pool's live components.
#[derive(Debug, Default)]
pub(crate) struct ChunkIndex {
    /// Per-component state, indexed by component id; a component without
    /// chunks is not live.
    components: Vec<ComponentState>,
    order: BTreeSet<ChunkKey>,
}

impl ChunkIndex {
    /// Stores the freshly linearized order of one component, replacing its
    /// previous chunks. `members` lists every live member of the component
    /// in any order, borrowed from the entry arena; an empty list forgets the
    /// component. The exact solver runs on the component only, so the work is
    /// bounded by the cluster limits.
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

    /// Drops every chunk of a component id the pool freed or absorbed.
    pub(crate) fn forget(&mut self, component: ComponentId) {
        let Some(state) = self.components.get_mut(component_index(component)) else {
            return;
        };
        for slot in &state.chunks {
            self.order.remove(&slot.key);
        }
        *state = ComponentState::default();
    }

    /// Returns the number of live components.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.components
            .iter()
            .filter(|state| !state.chunks.is_empty())
            .count()
    }

    /// Returns whether the index holds no live component.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    /// Live members of one component in linearization order, or `None` when
    /// the id names no live component. Projection partitions these survivors
    /// without walking the whole arena: work stays bounded by the cluster.
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

    /// Chunks from the highest feerate to the lowest: Core's builder order.
    pub(crate) fn chunks_descending<'a>(
        &'a self,
        pool: &'a Mempool,
    ) -> impl DoubleEndedIterator<Item = ChunkView<'a>> + 'a {
        self.order.iter().map(move |key| self.view(pool, key))
    }

    /// Estimates the heap this index occupies, in bytes.
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

/// Owned projection of the chunk order after applying a removal plan.
///
/// Borrows the pool and stores only the relinearized affected components:
/// untouched components are read from the maintained index at iteration
/// time, so the work is the solver over the touched clusters plus one merge
/// walk. The pool is borrowed, never cloned. `iter` merges both sources in
/// [`ChunkKey`] order; this owner never implements `Iterator` itself because
/// an iterator yielding borrows of its own owned storage is not expressible
/// safely.
#[derive(Debug)]
pub struct ProjectedChunks<'a> {
    pool: &'a Mempool,
    /// Entries the staged block confirms; surviving views omit them from
    /// [`ChunkView::parents_of`].
    confirmed: HashSet<EntryId>,
    /// Original component ids replaced by the side-linearized pieces.
    touched: HashSet<u32>,
    /// Side-linearized surviving pieces of the touched components, each
    /// solved exactly with its own fresh equal-feerate prefix run.
    pieces: Vec<ComponentState>,
    /// Every projected chunk sorted by its key: highest feerate first.
    order: Vec<(ChunkKey, usize, usize)>,
}

impl<'a> ProjectedChunks<'a> {
    /// Assembles the projection from already side-linearized pieces. The
    /// caller partitioned every touched component into its surviving
    /// connected pieces and solved each with the exact solver; this sorts
    /// the resulting chunk keys once.
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

    /// Chunks in descending feerate order as if the plan had applied: the
    /// untouched maintained chunks merged with the sorted projected chunks
    /// by [`ChunkKey`]. Every view borrows this owner and the pool.
    pub fn iter(&self) -> impl Iterator<Item = ChunkView<'_>> + '_ {
        ProjectedChunksIter {
            pool: self.pool,
            confirmed: &self.confirmed,
            touched: &self.touched,
            index: self.pool.chunk_index(),
            live: self.pool.chunk_index().order.iter(),
            pieces: self.pieces.as_slice(),
            order: self.order.as_slice(),
            front: 0,
        }
    }

    /// Returns whether the projected order holds no chunk.
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

    /// Returns the number of projected chunks: untouched plus relinearized.
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

/// Merge iterator over the untouched maintained chunks and the sorted
/// projected chunks. Holds a forward cursor into each source and yields the
/// smaller [`ChunkKey`] first, so the walk matches the maintained order.
struct ProjectedChunksIter<'s> {
    pool: &'s Mempool,
    confirmed: &'s HashSet<EntryId>,
    touched: &'s HashSet<u32>,
    index: &'s ChunkIndex,
    live: alloc::collections::btree_set::Iter<'s, ChunkKey>,
    pieces: &'s [ComponentState],
    order: &'s [(ChunkKey, usize, usize)],
    front: usize,
}

impl<'s> ProjectedChunksIter<'s> {
    fn next_live(&mut self) -> Option<&'s ChunkKey> {
        self.live
            .by_ref()
            .find(|key| !self.touched.contains(&key.component))
    }

    fn peek_live(&self) -> Option<&'s ChunkKey> {
        let mut cursor = self.live.clone();
        cursor.find(|key| !self.touched.contains(&key.component))
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
        let live_key = self.peek_live();
        let projected = self.peek_projected();
        if live_key.is_none() && projected.is_none() {
            return None;
        }
        if projected.is_none() {
            return self.next_live().map(|key| self.live_view(key));
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
        self.next_live().map(|key| self.live_view(key))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, None)
    }
}

/// Slot of a component id in the per-component table.
fn component_index(component: ComponentId) -> usize {
    usize::try_from(component).unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests;
