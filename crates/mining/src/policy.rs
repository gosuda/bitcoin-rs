use bitcoin_rs_mempool::{EntryId as MempoolEntryId, Mempool};

/// Transaction selection policy for candidate block assembly.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MiningPolicy;

impl MiningPolicy {
    /// Selects mempool transactions in Pareto-front priority order until the weight limit is full.
    #[must_use]
    pub fn select_transactions(&self, mempool: &Mempool, max_weight: u32) -> Vec<MempoolEntryId> {
        let mut selected = Vec::new();
        let mut selected_weight = 0_u32;

        for id in mempool.pareto.top_n(mempool.pareto.len()) {
            let Some(entry) = mempool.entry(id) else {
                continue;
            };
            let weight = entry.vsize.saturating_mul(4);
            let Some(next_weight) = selected_weight.checked_add(weight) else {
                break;
            };
            if next_weight > max_weight {
                break;
            }
            selected_weight = next_weight;
            selected.push(id);
        }

        selected
    }
}
