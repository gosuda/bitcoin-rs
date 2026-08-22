use std::collections::HashSet;

use bitcoin_rs_mempool::{EntryId as MempoolEntryId, Mempool};

/// Weight Bitcoin Core holds back for the coinbase transaction.
///
/// `DEFAULT_BLOCK_RESERVED_WEIGHT` in `policy/policy.h`. Selection runs against
/// `max_weight - reserved`, while the template still advertises the full
/// `weightlimit`: the miner is told what a block may weigh, and the space its
/// own coinbase will need is kept out of what we hand it. Filling the whole
/// four million and then adding a coinbase produces an oversize block.
pub const DEFAULT_BLOCK_RESERVED_WEIGHT: u32 = 8_000;

/// Transaction selection policy for candidate block assembly.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MiningPolicy;

impl MiningPolicy {
    /// Selects mempool transactions for a candidate block.
    ///
    /// Ancestor-package selection, as in Bitcoin Core's `addPackageTxs`:
    /// candidates are considered in descending **ancestor** fee-rate order,
    /// and a candidate is taken together with every unconfirmed ancestor it
    /// still needs. Two properties follow, and neither held before:
    ///
    /// - **The result is topologically ordered.** A parent always precedes its
    ///   child, so a miner can serialize the list as-is.
    /// - **No child is taken without its parents.** A package that does not
    ///   fit is skipped whole rather than truncated mid-way.
    ///
    /// Fee-rate order alone gave neither: a high-fee child sorted ahead of the
    /// low-fee parent it depends on, and the weight cut-off could land between
    /// them. Both produce a template that cannot be mined.
    ///
    /// Ordering by ancestor fee rate is also what makes child-pays-for-parent
    /// work — a child's fee lifts its parent into the block instead of being
    /// discarded with it.
    ///
    /// `max_weight` is the selection budget, which the caller is expected to
    /// have already reduced by [`DEFAULT_BLOCK_RESERVED_WEIGHT`]. `max_sigops`
    /// bounds the block's total sigop cost.
    #[must_use]
    pub fn select_transactions(
        &self,
        mempool: &Mempool,
        max_weight: u32,
        max_sigops: u32,
    ) -> Vec<MempoolEntryId> {
        let candidates = candidates_by_ancestor_fee_rate(mempool);
        let mut selected = Vec::with_capacity(candidates.len());
        let mut included = HashSet::with_capacity(candidates.len());
        let mut weight = 0_u64;
        let mut sigops = 0_u64;
        let weight_budget = u64::from(max_weight);
        let sigop_budget = u64::from(max_sigops);

        for id in candidates {
            if included.contains(&id) {
                continue;
            }
            let Some(package) = ancestor_package(mempool, id, &included) else {
                continue;
            };
            let Some((package_weight, package_sigops)) = package_cost(mempool, &package) else {
                continue;
            };
            let next_weight = weight.saturating_add(package_weight);
            let next_sigops = sigops.saturating_add(package_sigops);
            if next_weight > weight_budget || next_sigops > sigop_budget {
                // Skip rather than stop: a later, smaller package can still
                // fit in what is left. Core's assembler does the same.
                continue;
            }
            weight = next_weight;
            sigops = next_sigops;
            for member in package {
                included.insert(member);
                selected.push(member);
            }
        }

        selected
    }
}

/// Every entry id, ordered by the priority Core assembles blocks in.
///
/// Descending ancestor fee rate, then descending own fee rate, then oldest
/// first, then by id so the order is total and reproducible.
fn candidates_by_ancestor_fee_rate(mempool: &Mempool) -> Vec<MempoolEntryId> {
    let mut keys = mempool
        .entries
        .iter()
        .filter_map(|(index, entry)| {
            let id = MempoolEntryId::try_from(index).ok()?;
            Some((id, entry.ancestor_fee_rate(), entry.fee_rate, entry.time))
        })
        .collect::<Vec<_>>();
    keys.sort_unstable_by(|left, right| {
        right
            .1
            .cmp(&left.1)
            .then_with(|| right.2.cmp(&left.2))
            .then_with(|| left.3.cmp(&right.3))
            .then_with(|| left.0.cmp(&right.0))
    });
    keys.into_iter().map(|(id, _, _, _)| id).collect()
}

/// `id` and every unconfirmed ancestor not already included, parents first.
///
/// Returns `None` if any member has vanished from the pool, which drops the
/// whole package rather than emitting a partial one.
fn ancestor_package(
    mempool: &Mempool,
    id: MempoolEntryId,
    included: &HashSet<MempoolEntryId>,
) -> Option<Vec<MempoolEntryId>> {
    let mut ordered = Vec::new();
    let mut visited = HashSet::new();
    visit_ancestors(mempool, id, included, &mut visited, &mut ordered)?;
    Some(ordered)
}

/// Post-order depth-first walk over the parents, which is a topological sort.
///
/// Depth is bounded by the mempool's ancestor limit (25 by default), so this
/// cannot run away. Entry ids are deliberately not used as a stand-in for
/// dependency order: the pool's arena reuses freed slots, so a parent accepted
/// after a slab slot was released can hold a **higher** id than its own child.
fn visit_ancestors(
    mempool: &Mempool,
    id: MempoolEntryId,
    included: &HashSet<MempoolEntryId>,
    visited: &mut HashSet<MempoolEntryId>,
    ordered: &mut Vec<MempoolEntryId>,
) -> Option<()> {
    if included.contains(&id) || !visited.insert(id) {
        return Some(());
    }
    let entry = mempool.entry(id)?;
    for input in &entry.tx.input {
        if let Some(parent) = mempool.by_txid.get(&input.previous_output.txid) {
            visit_ancestors(mempool, *parent, included, visited, ordered)?;
        }
    }
    ordered.push(id);
    Some(())
}

/// Total weight and sigop cost of a package.
fn package_cost(mempool: &Mempool, package: &[MempoolEntryId]) -> Option<(u64, u64)> {
    let mut weight = 0_u64;
    let mut sigops = 0_u64;
    for id in package {
        let entry = mempool.entry(*id)?;
        weight = weight.saturating_add(entry.tx.weight().to_wu());
        sigops = sigops.saturating_add(u64::from(entry.sigop_cost));
    }
    Some((weight, sigops))
}
