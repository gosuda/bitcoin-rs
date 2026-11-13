pub const CHAINSTATE_CACHE_SHARE_PCT: u64 = 80;
pub const TXINDEX_CACHE_SHARE_PCT: u64 = 20;
pub const MIN_DBCACHE_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_DBCACHE_BYTES: u64 = 1 << 40;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheBudgetShare {
    pub namespace: &'static str,
    pub bytes: u64,
}

/// Allocation of the chainstate cache allowance between the backend engine
/// and the coin cache.
///
/// The shares sum to `chainstate_bytes` exactly: the engine share floors and
/// the coin share takes the remainder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChainstateCacheBudget {
    pub engine_bytes: u64,
    pub coin_bytes: u64,
}

/// Splits a chainstate cache allowance in half between engine and coins.
///
/// The engine share floors to whole bytes and the coin share takes the
/// remainder, so `engine_bytes + coin_bytes` always equals
/// `chainstate_bytes`.
#[must_use]
pub fn split_chainstate_cache_budget(chainstate_bytes: u64) -> ChainstateCacheBudget {
    let engine_bytes = chainstate_bytes / 2;
    ChainstateCacheBudget {
        engine_bytes,
        coin_bytes: chainstate_bytes - engine_bytes,
    }
}

/// Clamps a requested cache budget to the documented bounds.
///
/// A zero, a minimum, or an overflow input all produce a usable budget.
#[must_use]
pub fn clamp_dbcache_bytes(dbcache_mb: u64) -> u64 {
    let bytes = dbcache_mb.saturating_mul(1024 * 1024);
    bytes.clamp(MIN_DBCACHE_BYTES, MAX_DBCACHE_BYTES)
}

/// Divides a clamped cache budget across chainstate and the transaction index.
///
/// Shares floor to whole bytes, and the rounding remainder goes to chainstate.
/// The returned shares therefore always sum to at most `total_bytes`.
#[must_use]
pub fn split_cache_budget_with_txindex(total_bytes: u64) -> Vec<CacheBudgetShare> {
    let txindex_bytes = total_bytes / 100 * TXINDEX_CACHE_SHARE_PCT
        + total_bytes % 100 * TXINDEX_CACHE_SHARE_PCT / 100;
    cache_shares(total_bytes, txindex_bytes)
}

#[must_use]
pub fn split_cache_budget_without_txindex(total_bytes: u64) -> Vec<CacheBudgetShare> {
    cache_shares(total_bytes, 0)
}

fn cache_shares(total_bytes: u64, txindex_bytes: u64) -> Vec<CacheBudgetShare> {
    let chainstate_bytes = total_bytes.saturating_sub(txindex_bytes);
    vec![
        CacheBudgetShare {
            namespace: "chainstate",
            bytes: chainstate_bytes,
        },
        CacheBudgetShare {
            namespace: "txindex",
            bytes: txindex_bytes,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::{
        split_cache_budget_with_txindex, split_cache_budget_without_txindex,
        split_chainstate_cache_budget,
    };

    #[test]
    fn a_maximal_budget_keeps_the_floored_txindex_share() {
        let shares = split_cache_budget_with_txindex(u64::MAX);
        assert_eq!(shares[1].namespace, "txindex");
        assert_eq!(shares[1].bytes, 3_689_348_814_741_910_323);
        assert_eq!(shares[0].bytes + shares[1].bytes, u64::MAX);
    }

    #[test]
    fn the_same_budget_without_txindex_gives_chainstate_every_byte() {
        let shares = split_cache_budget_without_txindex(7_654_321);
        assert_eq!(shares[0].namespace, "chainstate");
        assert_eq!(shares[0].bytes, 7_654_321);
        assert_eq!(shares[1].bytes, 0);
    }

    #[test]
    fn an_odd_chainstate_allowance_gives_the_remainder_to_coins() {
        let budget = split_chainstate_cache_budget(7_654_321);
        assert_eq!(budget.engine_bytes, 3_827_160);
        assert_eq!(budget.coin_bytes, 3_827_161);
        assert_eq!(budget.engine_bytes + budget.coin_bytes, 7_654_321);
    }
}
