pub const CHAINSTATE_CACHE_SHARE_PCT: u64 = 80;
pub const TXINDEX_CACHE_SHARE_PCT: u64 = 20;
pub const MIN_DBCACHE_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_DBCACHE_BYTES: u64 = 1 << 40;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheBudgetShare {
    pub namespace: &'static str,
    pub bytes: u64,
}

#[must_use]
pub fn clamp_dbcache_bytes(dbcache_mb: u64) -> u64 {
    let bytes = dbcache_mb.saturating_mul(1024 * 1024);
    bytes.clamp(MIN_DBCACHE_BYTES, MAX_DBCACHE_BYTES)
}

#[must_use]
pub fn split_cache_budget_with_txindex(total_bytes: u64) -> Vec<CacheBudgetShare> {
    cache_shares(total_bytes, total_bytes * TXINDEX_CACHE_SHARE_PCT / 100)
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
