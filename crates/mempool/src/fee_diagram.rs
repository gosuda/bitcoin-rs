//! Fee curves over the mempool owner's graph projection.
//!
//! A maximum-weight closure chooses a dependency-closed set at a given fee
//! rate. Parametric min-cuts find the highest-rate set without enumerating
//! subsets. This module owns no transactions or mutable mempool state.

use core::cmp::{Ordering, Reverse};
use std::collections::{BinaryHeap, VecDeque};

use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
/// Failure to construct or compare a checked dependency fee diagram.
pub enum FeeDiagramError {
    /// The fee or accumulated weight exceeds the checked representation.
    #[error("fee diagram arithmetic overflow")]
    Arithmetic,
    /// A chunk has no positive representable weight.
    #[error("invalid fee diagram weight")]
    Weight,
    /// Dependency references are inconsistent or cyclic.
    #[error("inconsistent fee diagram dependencies")]
    Dependencies,
}

/// Fee over sigop-adjusted weight. Core's graph uses weight before rounding
/// to virtual bytes; using rounded vsize changes comparisons for witnesses.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct FeeWeight {
    pub fee: i128,
    pub weight: u32,
}

impl FeeWeight {
    pub(crate) fn checked_add(self, other: Self) -> Result<Self, FeeDiagramError> {
        let weight = self
            .weight
            .checked_add(other.weight)
            .ok_or(FeeDiagramError::Arithmetic)?;
        if i32::try_from(weight).is_err() {
            return Err(FeeDiagramError::Weight);
        }
        let fee = self
            .fee
            .checked_add(other.fee)
            .ok_or(FeeDiagramError::Arithmetic)?;
        // All later rate comparisons multiply by a positive i32-sized weight.
        // This covers every u64 base fee plus i64 overlay in a representable
        // graph, and rejects synthetic wider facts before an infallible sort.
        fee.checked_mul(i128::from(i32::MAX))
            .ok_or(FeeDiagramError::Arithmetic)?;
        Ok(Self { fee, weight })
    }

    pub(crate) fn rate_cmp(self, other: Self) -> Ordering {
        // validate/checked_add establish the product bound before sorting.
        (self.fee * i128::from(other.weight)).cmp(&(other.fee * i128::from(self.weight)))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Chunk {
    /// Positions in the supplied graph, in dependency order.
    pub members: Vec<usize>,
    pub total: FeeWeight,
}

pub(crate) fn components(parents: &[Vec<usize>]) -> Result<Vec<Vec<usize>>, FeeDiagramError> {
    let mut neighbours = vec![Vec::new(); parents.len()];
    for (child, entries) in parents.iter().enumerate() {
        for &parent in entries {
            if parent >= parents.len() || child == parent {
                return Err(FeeDiagramError::Dependencies);
            }
            neighbours[child].push(parent);
            neighbours[parent].push(child);
        }
    }
    let mut seen = vec![false; parents.len()];
    let mut groups = Vec::new();
    for seed in 0..parents.len() {
        if seen[seed] {
            continue;
        }
        seen[seed] = true;
        let mut members = Vec::new();
        let mut todo = vec![seed];
        while let Some(node) = todo.pop() {
            members.push(node);
            for &next in &neighbours[node] {
                if !seen[next] {
                    seen[next] = true;
                    todo.push(next);
                }
            }
        }
        members.sort_unstable();
        groups.push(members);
    }
    Ok(groups)
}

pub(crate) fn ordered_chunks(
    fees: &[FeeWeight],
    parents: &[Vec<usize>],
) -> Result<Vec<Chunk>, FeeDiagramError> {
    if fees.len() != parents.len() {
        return Err(FeeDiagramError::Dependencies);
    }
    let mut chunks = Vec::new();
    for members in components(parents)? {
        let local_fees: Vec<_> = members.iter().map(|&i| fees[i]).collect();
        let local_parents = members
            .iter()
            .map(|&i| {
                parents[i]
                    .iter()
                    .map(|parent| {
                        members
                            .binary_search(parent)
                            .map_err(|_| FeeDiagramError::Dependencies)
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?;
        for chunk in linearize(&local_fees, &local_parents)? {
            chunks.push(Chunk {
                members: chunk.members.into_iter().map(|i| members[i]).collect(),
                total: chunk.total,
            });
        }
    }
    // Stable sorting keeps the dependency order of equal-rate chunks within
    // a component. Chunks from different components have no dependencies.
    chunks.sort_by(|left, right| right.total.rate_cmp(left.total));
    Ok(chunks)
}

fn sum_members(fees: &[FeeWeight], members: &[usize]) -> Result<FeeWeight, FeeDiagramError> {
    members
        .iter()
        .try_fold(FeeWeight::default(), |total, &index| {
            total.checked_add(fees[index])
        })
}

fn validate(fees: &[FeeWeight], parents: &[Vec<usize>]) -> Result<(), FeeDiagramError> {
    if fees.len() != parents.len() {
        return Err(FeeDiagramError::Dependencies);
    }
    for (index, (fee, ancestors)) in fees.iter().zip(parents).enumerate() {
        if fee.weight == 0 || i32::try_from(fee.weight).is_err() {
            return Err(FeeDiagramError::Weight);
        }
        FeeWeight::default().checked_add(*fee)?;
        if ancestors
            .iter()
            .any(|&parent| parent >= fees.len() || parent == index)
        {
            return Err(FeeDiagramError::Dependencies);
        }
    }
    let members: Vec<_> = (0..fees.len()).collect();
    let _ = sum_members(fees, &members)?;
    let _ = topological(parents, &members)?;
    Ok(())
}

/// Stable topological order, preferring the supplied order among ready nodes.
/// Shared by linearization and mutation publication; no quadratic rescanning.
pub(crate) fn topological(
    parents: &[Vec<usize>],
    members: &[usize],
) -> Result<Vec<usize>, FeeDiagramError> {
    let mut rank = vec![usize::MAX; parents.len()];
    for (index, &member) in members.iter().enumerate() {
        let slot = rank.get_mut(member).ok_or(FeeDiagramError::Dependencies)?;
        if *slot != usize::MAX {
            return Err(FeeDiagramError::Dependencies);
        }
        *slot = index;
    }
    let mut children = vec![Vec::new(); parents.len()];
    let mut incoming = vec![0_usize; parents.len()];
    let mut ready = BinaryHeap::new();
    for &member in members {
        for &parent in &parents[member] {
            let parent_rank = *rank.get(parent).ok_or(FeeDiagramError::Dependencies)?;
            if parent_rank != usize::MAX {
                incoming[member] += 1;
                children[parent].push(member);
            }
        }
        if incoming[member] == 0 {
            ready.push(Reverse(rank[member]));
        }
    }
    let mut ordered = Vec::with_capacity(members.len());
    while let Some(Reverse(index)) = ready.pop() {
        let member = members[index];
        ordered.push(member);
        for &child in &children[member] {
            incoming[child] -= 1;
            if incoming[child] == 0 {
                ready.push(Reverse(rank[child]));
            }
        }
    }
    if ordered.len() != members.len() {
        return Err(FeeDiagramError::Dependencies);
    }
    Ok(ordered)
}

/// Compute decreasing-rate, dependency-closed chunks. All graph indices are
/// local to this immutable input. Work is bounded by its node and edge counts.
pub(crate) fn linearize(
    fees: &[FeeWeight],
    parents: &[Vec<usize>],
) -> Result<Vec<Chunk>, FeeDiagramError> {
    validate(fees, parents)?;
    let mut remaining = vec![true; fees.len()];
    let mut chunks = Vec::new();
    while remaining.iter().any(|&live| live) {
        let members: Vec<_> = (0..fees.len()).filter(|&i| remaining[i]).collect();
        let mut rate = sum_members(fees, &members)?;
        let mut optimal = None;
        // As the tested rate increases, minimum source-side optimal closures
        // shrink. A positive-gain step removes at least one node from the
        // previous closure; at most n such steps precede the zero-gain cut.
        for _ in 0..=members.len() {
            let (flow, gain) = closure(fees, parents, &remaining, rate)?;
            if gain == 0 {
                optimal = Some(flow);
                break;
            }
            let reached = flow.reachable(fees.len(), false);
            let next: Vec<_> = members.iter().copied().filter(|&i| reached[i]).collect();
            if next.is_empty() {
                return Err(FeeDiagramError::Dependencies);
            }
            let next_rate = sum_members(fees, &next)?;
            if next_rate.rate_cmp(rate) != Ordering::Greater {
                return Err(FeeDiagramError::Dependencies);
            }
            rate = next_rate;
        }
        let flow = optimal.ok_or(FeeDiagramError::Dependencies)?;
        let reaches_sink = flow.reachable(fees.len() + 1, true);
        let mut minimal: Option<Vec<usize>> = None;
        for &member in &members {
            if reaches_sink[member] {
                continue;
            }
            let reached = flow.reachable(member, false);
            let closed: Vec<_> = members.iter().copied().filter(|&i| reached[i]).collect();
            if minimal
                .as_ref()
                .is_none_or(|best| (closed.len(), &closed) < (best.len(), best))
            {
                minimal = Some(closed);
            }
        }
        // A smallest nonempty residual closure is one sink SCC: it is a
        // minimal maximum-rate chunk, rather than a union of equal-rate chunks.
        let members = minimal.ok_or(FeeDiagramError::Dependencies)?;
        let total = sum_members(fees, &members)?;
        if total.rate_cmp(rate) != Ordering::Equal {
            return Err(FeeDiagramError::Dependencies);
        }
        let members = topological(parents, &members)?;
        for &member in &members {
            remaining[member] = false;
        }
        chunks.push(Chunk { members, total });
    }
    Ok(chunks)
}

#[derive(Clone, Copy)]
struct Edge {
    to: usize,
    reverse: usize,
    capacity: u128,
}

struct Flow {
    edges: Vec<Vec<Edge>>,
}

impl Flow {
    fn new(nodes: usize) -> Self {
        Self {
            edges: vec![Vec::new(); nodes],
        }
    }

    fn add(&mut self, from: usize, to: usize, capacity: u128) {
        let forward = self.edges[from].len();
        let reverse = self.edges[to].len();
        self.edges[from].push(Edge {
            to,
            reverse,
            capacity,
        });
        self.edges[to].push(Edge {
            to: from,
            reverse: forward,
            capacity: 0,
        });
    }

    fn reachable(&self, start: usize, reverse: bool) -> Vec<bool> {
        let mut reached = vec![false; self.edges.len()];
        let mut queue = VecDeque::from([start]);
        reached[start] = true;
        while let Some(node) = queue.pop_front() {
            for edge in &self.edges[node] {
                let capacity = if reverse {
                    self.edges[edge.to][edge.reverse].capacity
                } else {
                    edge.capacity
                };
                if capacity > 0 && !reached[edge.to] {
                    reached[edge.to] = true;
                    queue.push_back(edge.to);
                }
            }
        }
        reached
    }

    fn send(
        &mut self,
        node: usize,
        sink: usize,
        amount: u128,
        levels: &[usize],
        next: &mut [usize],
    ) -> u128 {
        if node == sink {
            return amount;
        }
        while next[node] < self.edges[node].len() {
            let index = next[node];
            let edge = self.edges[node][index];
            if edge.capacity > 0 && levels[edge.to] == levels[node] + 1 {
                let sent = self.send(edge.to, sink, amount.min(edge.capacity), levels, next);
                if sent > 0 {
                    self.edges[node][index].capacity -= sent;
                    self.edges[edge.to][edge.reverse].capacity += sent;
                    return sent;
                }
            }
            next[node] += 1;
        }
        0
    }

    fn maximum(&mut self, source: usize, sink: usize, bound: u128) -> u128 {
        let mut total = 0;
        while total < bound {
            let mut levels = vec![usize::MAX; self.edges.len()];
            let mut queue = VecDeque::from([source]);
            levels[source] = 0;
            while let Some(node) = queue.pop_front() {
                for edge in &self.edges[node] {
                    if edge.capacity > 0 && levels[edge.to] == usize::MAX {
                        levels[edge.to] = levels[node] + 1;
                        queue.push_back(edge.to);
                    }
                }
            }
            if levels[sink] == usize::MAX {
                break;
            }
            let mut next = vec![0; self.edges.len()];
            loop {
                let sent = self.send(source, sink, bound - total, &levels, &mut next);
                if sent == 0 {
                    break;
                }
                total += sent;
            }
        }
        total
    }
}

fn closure(
    fees: &[FeeWeight],
    parents: &[Vec<usize>],
    remaining: &[bool],
    rate: FeeWeight,
) -> Result<(Flow, u128), FeeDiagramError> {
    let source = fees.len();
    let sink = source + 1;
    let mut flow = Flow::new(sink + 1);
    let mut positive = 0_u128;
    for (index, fee) in fees.iter().enumerate() {
        if !remaining[index] {
            continue;
        }
        let candidate_value = fee
            .fee
            .checked_mul(i128::from(rate.weight))
            .ok_or(FeeDiagramError::Arithmetic)?;
        let threshold = rate
            .fee
            .checked_mul(i128::from(fee.weight))
            .ok_or(FeeDiagramError::Arithmetic)?;
        let gain = candidate_value
            .checked_sub(threshold)
            .ok_or(FeeDiagramError::Arithmetic)?;
        if gain > 0 {
            let gain = gain.unsigned_abs();
            positive = positive
                .checked_add(gain)
                .ok_or(FeeDiagramError::Arithmetic)?;
            flow.add(source, index, gain);
        } else if gain < 0 {
            flow.add(index, sink, gain.unsigned_abs());
        }
    }
    let infinite = positive.checked_add(1).ok_or(FeeDiagramError::Arithmetic)?;
    for (child, ancestors) in parents.iter().enumerate() {
        if remaining[child] {
            for &parent in ancestors {
                if remaining[parent] {
                    flow.add(child, parent, infinite);
                }
            }
        }
    }
    let sent = flow.maximum(source, sink, positive);
    Ok((flow, positive - sent))
}

fn points(chunks: &[FeeWeight]) -> Result<Vec<FeeWeight>, FeeDiagramError> {
    let mut result = vec![FeeWeight::default()];
    for &chunk in chunks {
        if chunk.weight == 0 {
            return Err(FeeDiagramError::Weight);
        }
        let last = *result.last().ok_or(FeeDiagramError::Weight)?;
        result.push(last.checked_add(chunk)?);
    }
    Ok(result)
}

fn value_at(points: &[FeeWeight], at: u32) -> Result<(i128, i128), FeeDiagramError> {
    let end = points.partition_point(|point| point.weight <= at);
    if end == points.len() {
        return Ok((points[end - 1].fee, 1));
    }
    let start = points[end - 1];
    let stop = points[end];
    let span = i128::from(stop.weight - start.weight);
    let base = start
        .fee
        .checked_mul(span)
        .ok_or(FeeDiagramError::Arithmetic)?;
    let rise = stop
        .fee
        .checked_sub(start.fee)
        .and_then(|delta| delta.checked_mul(i128::from(at - start.weight)))
        .ok_or(FeeDiagramError::Arithmetic)?;
    let fee = base.checked_add(rise).ok_or(FeeDiagramError::Arithmetic)?;
    Ok((fee, span))
}

/// Pointwise comparison, including horizontal tails. Crossing curves are
/// incomparable; equal total fees alone never establish an improvement.
pub(crate) fn compare(
    left: &[FeeWeight],
    right: &[FeeWeight],
) -> Result<Option<Ordering>, FeeDiagramError> {
    let left = points(left)?;
    let right = points(right)?;
    let mut higher = false;
    let mut lower = false;
    for point in left.iter().chain(&right).skip(1) {
        let (left_fee, left_span) = value_at(&left, point.weight)?;
        let (right_fee, right_span) = value_at(&right, point.weight)?;
        let left_scaled = left_fee
            .checked_mul(right_span)
            .ok_or(FeeDiagramError::Arithmetic)?;
        let right_scaled = right_fee
            .checked_mul(left_span)
            .ok_or(FeeDiagramError::Arithmetic)?;
        match left_scaled.cmp(&right_scaled) {
            Ordering::Greater => higher = true,
            Ordering::Less => lower = true,
            Ordering::Equal => {}
        }
        if higher && lower {
            return Ok(None);
        }
    }
    Ok(Some(higher.cmp(&lower)))
}

#[cfg(test)]
mod tests;
