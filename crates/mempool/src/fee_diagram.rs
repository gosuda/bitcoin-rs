use core::cmp::{Ordering, Reverse};
use std::collections::{BinaryHeap, VecDeque};

use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FeeDiagramError {
    #[error("fee diagram arithmetic overflow")]
    Arithmetic,
    #[error("invalid fee diagram weight")]
    Weight,
    #[error("inconsistent fee diagram dependencies")]
    Dependencies,
}

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
        fee.checked_mul(i128::from(i32::MAX))
            .ok_or(FeeDiagramError::Arithmetic)?;
        Ok(Self { fee, weight })
    }

    pub(crate) fn rate_cmp(self, other: Self) -> Ordering {
        (self.fee * i128::from(other.weight)).cmp(&(other.fee * i128::from(self.weight)))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Chunk {
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
        for _ in 0..=members.len() {
            let (flow, gain) = closure(fees, parents, &remaining, rate)?;
            if gain == 0 {
                optimal = Some(flow);
                break;
            }
            let reached = flow.reachable(fees.len());
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
        let reaches_sink = flow.reverse_reachable(fees.len() + 1);
        let mut minimal: Option<Vec<usize>> = None;
        for &member in &members {
            if reaches_sink[member] {
                continue;
            }
            let reached = flow.reachable(member);
            let closed: Vec<_> = members.iter().copied().filter(|&i| reached[i]).collect();
            if minimal
                .as_ref()
                .is_none_or(|best| (closed.len(), &closed) < (best.len(), best))
            {
                minimal = Some(closed);
            }
        }
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

    fn reachable(&self, start: usize) -> Vec<bool> {
        let mut reached = vec![false; self.edges.len()];
        let mut queue = VecDeque::from([start]);
        reached[start] = true;
        while let Some(node) = queue.pop_front() {
            for edge in &self.edges[node] {
                if edge.capacity > 0 && !reached[edge.to] {
                    reached[edge.to] = true;
                    queue.push_back(edge.to);
                }
            }
        }
        reached
    }

    fn reverse_reachable(&self, start: usize) -> Vec<bool> {
        let mut reached = vec![false; self.edges.len()];
        let mut queue = VecDeque::from([start]);
        reached[start] = true;
        while let Some(node) = queue.pop_front() {
            for edge in &self.edges[node] {
                let capacity = self.edges[edge.to][edge.reverse].capacity;
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
mod tests {
    use super::*;

    fn values(rows: &[(i128, u32)]) -> Vec<FeeWeight> {
        rows.iter()
            .map(|&(fee, weight)| FeeWeight { fee, weight })
            .collect()
    }

    // POL-05
    #[test]
    fn core_311_diagram_vectors() -> Result<(), FeeDiagramError> {
        let old = values(&[(950, 300), (100, 100)]);
        for (new, expected) in [
            (values(&[(1000, 300), (50, 100)]), Some(Ordering::Greater)),
            (values(&[(1000, 300), (0, 100)]), None),
            (values(&[(1100, 300)]), Some(Ordering::Greater)),
            (values(&[(1100, 100), (0, 100)]), Some(Ordering::Greater)),
            (values(&[(750, 100), (249, 250), (151, 650)]), None),
            (
                values(&[(750, 100), (250, 250), (150, 150)]),
                Some(Ordering::Greater),
            ),
            (old.clone(), Some(Ordering::Equal)),
        ] {
            assert_eq!(compare(&new, &old)?, expected, "{new:?}");
            assert_eq!(compare(&old, &new)?, expected.map(Ordering::reverse));
        }
        let smaller = values(&[(950, 300), (100, 99)]);
        assert_eq!(compare(&smaller, &old)?, Some(Ordering::Greater));
        assert_eq!(
            compare(&smaller, &values(&[(950, 300), (100, 100), (0, 1), (0, 1)]))?,
            Some(Ordering::Greater)
        );
        assert_eq!(
            compare(
                &smaller,
                &values(&[(950, 300), (100, 100), (0, 1), (0, 1), (1, 1)])
            )?,
            None
        );
        Ok(())
    }

    #[test]
    fn exact_weights_negative_fees_and_horizontal_tails() -> Result<(), FeeDiagramError> {
        assert_eq!(
            compare(&values(&[(1000, 401)]), &values(&[(1000, 404)]))?,
            Some(Ordering::Greater)
        );
        assert_eq!(compare(&[], &values(&[(-1, 10)]))?, Some(Ordering::Greater));
        assert_eq!(compare(&values(&[(0, 10)]), &[])?, Some(Ordering::Equal));
        assert_eq!(
            compare(&values(&[(100, 10)]), &values(&[(200, 100)]))?,
            None
        );
        Ok(())
    }

    #[test]
    fn shared_parent_requires_a_joint_chunk() -> Result<(), FeeDiagramError> {
        let fees = values(&[(0, 100), (90, 100), (90, 100)]);
        let chunks = linearize(&fees, &[vec![], vec![0], vec![0]])?;
        assert_eq!(
            chunks,
            vec![Chunk {
                members: vec![0, 1, 2],
                total: FeeWeight {
                    fee: 180,
                    weight: 300
                }
            }]
        );
        Ok(())
    }

    #[test]
    fn equal_rates_have_minimal_topological_chunks() -> Result<(), FeeDiagramError> {
        let fees = values(&[(100, 100), (100, 100), (100, 100)]);
        let chunks = linearize(&fees, &[vec![], vec![0], vec![0]])?;
        assert_eq!(
            chunks
                .iter()
                .map(|chunk| chunk.members.clone())
                .collect::<Vec<_>>(),
            vec![vec![0], vec![1], vec![2]]
        );
        Ok(())
    }

    #[test]
    fn negative_parent_and_independent_competitor() -> Result<(), FeeDiagramError> {
        let fees = values(&[(-100, 100), (300, 100), (110, 100)]);
        let chunks = linearize(&fees, &[vec![], vec![0], vec![]])?;
        assert_eq!(
            chunks
                .iter()
                .map(|chunk| chunk.members.clone())
                .collect::<Vec<_>>(),
            vec![vec![2], vec![0, 1]]
        );
        assert_eq!(
            chunks[1].total,
            FeeWeight {
                fee: 200,
                weight: 200
            }
        );
        Ok(())
    }

    #[test]
    fn signed_priority_extremes_preserve_one_satoshi_and_parent_cancellation()
    -> Result<(), FeeDiagramError> {
        let maximum = i128::from(i64::MAX);
        let before = values(&[(maximum + 1_000, 400)]);
        let after = values(&[(maximum + 1_001, 400)]);
        assert_eq!(compare(&after, &before)?, Some(Ordering::Greater));
        let fees = values(&[(i128::from(i64::MIN) + 1_000, 400), (maximum + 2_000, 400)]);
        let chunks = linearize(&fees, &[vec![], vec![0]])?;
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].members, vec![0, 1]);
        assert_eq!(chunks[0].total.fee, 2_999);
        Ok(())
    }

    #[test]
    fn invalid_graphs_and_arithmetic_fail_explicitly() {
        assert_eq!(
            linearize(&values(&[(1, 0)]), &[vec![]]),
            Err(FeeDiagramError::Weight)
        );
        assert_eq!(
            linearize(&values(&[(1, 1)]), &[vec![1]]),
            Err(FeeDiagramError::Dependencies)
        );
        assert_eq!(
            linearize(&values(&[(1, 1), (1, 1)]), &[vec![1], vec![0]]),
            Err(FeeDiagramError::Dependencies)
        );
        assert_eq!(
            linearize(&values(&[(i128::MAX, 1), (1, 1)]), &[vec![], vec![]]),
            Err(FeeDiagramError::Arithmetic)
        );
        assert_eq!(
            compare(&values(&[(1, 0)]), &[]),
            Err(FeeDiagramError::Weight)
        );
        assert_eq!(
            compare(&values(&[(i128::MAX, 1), (1, 1)]), &[]),
            Err(FeeDiagramError::Arithmetic)
        );
    }

    #[test]
    fn maximum_default_cluster_shared_parent() -> Result<(), FeeDiagramError> {
        let mut fees = vec![
            FeeWeight {
                fee: 100,
                weight: 100
            };
            64
        ];
        fees[0].fee = 0;
        let mut parents = vec![vec![0]; 64];
        parents[0].clear();
        let chunks = linearize(&fees, &parents)?;
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].members, (0..64).collect::<Vec<_>>());
        assert_eq!(
            chunks[0].total,
            FeeWeight {
                fee: 6300,
                weight: 6400
            }
        );
        Ok(())
    }

    fn next(seed: &mut u64) -> u64 {
        *seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        *seed >> 32
    }

    #[test]
    fn chunks_match_exhaustive_closed_subsets() -> Result<(), FeeDiagramError> {
        let mut seed = 639_u64;
        for nodes in 1..=8 {
            for _ in 0..80 {
                let fees: Vec<_> = (0..nodes)
                    .map(|_| FeeWeight {
                        fee: i128::from(next(&mut seed) % 301) - 100,
                        weight: u32::try_from(next(&mut seed) % 31 + 1).unwrap_or(1),
                    })
                    .collect();
                let parents: Vec<Vec<usize>> = (0..nodes)
                    .map(|child| {
                        (0..child)
                            .filter(|_| next(&mut seed).is_multiple_of(3))
                            .collect()
                    })
                    .collect();
                let chunks = linearize(&fees, &parents)?;
                let mut done = 0_usize;
                for chunk in chunks {
                    let mut selected = 0_usize;
                    for &member in &chunk.members {
                        assert_eq!((done | selected) & (1 << member), 0);
                        assert!(
                            parents[member]
                                .iter()
                                .all(|&parent| (done | selected) & (1 << parent) != 0)
                        );
                        selected |= 1 << member;
                    }
                    assert_eq!(sum_members(&fees, &chunk.members)?, chunk.total);
                    for subset in 1..(1 << nodes) {
                        if subset & done != 0 {
                            continue;
                        }
                        let members: Vec<_> =
                            (0..nodes).filter(|&i| subset & (1 << i) != 0).collect();
                        if members
                            .iter()
                            .any(|&i| parents[i].iter().any(|&p| (subset | done) & (1 << p) == 0))
                        {
                            continue;
                        }
                        let fee: i128 = members.iter().map(|&i| fees[i].fee).sum();
                        let weight: i128 =
                            members.iter().map(|&i| i128::from(fees[i].weight)).sum();
                        assert!(
                            fee * i128::from(chunk.total.weight) <= chunk.total.fee * weight,
                            "nonoptimal chunk {chunk:?}; subset {subset:b}; fees {fees:?}; parents {parents:?}"
                        );
                    }
                    done |= selected;
                }
                assert_eq!(done, (1 << nodes) - 1);
            }
        }
        Ok(())
    }
}
