//! Process cache-budget division shared by every storage backend.

/// Chainstate share of the process cache budget, in percent.
pub const CHAINSTATE_CACHE_SHARE_PCT: u64 = 80;
/// Transaction-index share of the process cache budget, in percent.
pub const TXINDEX_CACHE_SHARE_PCT: u64 = 20;
/// Smallest cache budget the node accepts, in bytes.
pub const MIN_DBCACHE_BYTES: u64 = 16 * 1024 * 1024;
/// Largest cache budget the node accepts, in bytes.
pub const MAX_DBCACHE_BYTES: u64 = 1 << 40;

/// One namespace's slice of the process cache budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheBudgetShare {
    pub namespace: &'static str,
    pub bytes: u64,
}

/// Clamps a requested cache budget to the documented bounds.
///
/// `dbcache_mb` arrives as a `u64` in MiB.
///
/// The conversion saturates instead of overflowing, then clamps to `[MIN_DBCACHE_BYTES,
/// MAX_DBCACHE_BYTES]` so a zero, a minimum, or an overflow input all produce a usable
/// budget.
#[must_use]
pub fn clamp_dbcache_bytes(dbcache_mb: u64) -> u64 {
    let bytes = dbcache_mb.saturating_mul(1024 * 1024);
    bytes.clamp(MIN_DBCACHE_BYTES, MAX_DBCACHE_BYTES)
}

/// Divides a clamped cache budget across the enabled persistent namespaces.
///
/// Shares floor to whole bytes; the rounding remainder (and every disabled
/// namespace's share) is redistributed to chainstate. The returned shares
/// therefore always sum to at most `total_bytes`.
#[must_use]
pub fn split_cache_budget(total_bytes: u64, txindex_enabled: bool) -> Vec<CacheBudgetShare> {
    let txindex_bytes = if txindex_enabled {
        total_bytes * TXINDEX_CACHE_SHARE_PCT / 100
    } else {
        0
    };
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
