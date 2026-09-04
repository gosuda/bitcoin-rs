//! Process cache-budget division shared by every storage backend.
//!
//! `dbcache` is one process-wide budget, not a per-database knob. The node
//! divides it across the persistent namespaces that exist in a deployment —
//! chainstate and transaction index — and every backend receives
//! its namespace's share in bytes through `open_with_cache`, which configures
//! exactly those bytes. Division floors each share and hands the rounding
//! remainder to chainstate, so the shares always sum to at most the budget.
//!
//! The percentages are fixed at 80/20 and are not configuration. A namespace
//! that is disabled in a deployment
//! contributes nothing: its share is redistributed to chainstate, which keeps
//! the sum within budget while giving the only live namespace the full headroom.

/// Chainstate share of the process cache budget, in percent.
pub const CHAINSTATE_CACHE_SHARE_PCT: u64 = 80;
/// Transaction-index share of the process cache budget, in percent.
pub const TXINDEX_CACHE_SHARE_PCT: u64 = 20;
/// Smallest cache budget the node accepts, in bytes.
///
/// Below this the split would hand chainstate a sliver too small for the
/// engines to work with. Values the operator sets under this bound clamp up
/// to it; each enabled namespace's share is then configured exactly by its
/// backend, so the effective capacities still sum to at most the budget.
pub const MIN_DBCACHE_BYTES: u64 = 16 * 1024 * 1024;
/// Largest cache budget the node accepts, in bytes.
///
/// The bound keeps the byte arithmetic (shares, MiB-to-byte conversion)
/// overflow-free in `u64` and stops absurd `--dbcache` values from turning
/// into absurd per-engine capacities. Values above it clamp down.
pub const MAX_DBCACHE_BYTES: u64 = 1 << 40;

/// One namespace's slice of the process cache budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheBudgetShare {
    /// Namespace the share feeds (`chainstate` or `txindex`).
    pub namespace: &'static str,
    /// Share size in bytes.
    pub bytes: u64,
}

/// Clamps a requested cache budget to the documented bounds.
///
/// `dbcache_mb` arrives as a `u64` in MiB. The conversion saturates instead of
/// overflowing, then clamps to `[MIN_DBCACHE_BYTES, MAX_DBCACHE_BYTES]` so a
/// zero, a minimum, or an overflow input all produce a usable budget.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_split_at_default_budget() {
        let total = clamp_dbcache_bytes(450);
        let shares = split_cache_budget(total, true);
        assert_eq!(shares[0].namespace, "chainstate");
        assert_eq!(shares[1].namespace, "txindex");
        // 450 MiB divides cleanly: 360/90 MiB.
        assert_eq!(shares[0].bytes, 360 * 1024 * 1024);
        assert_eq!(shares[1].bytes, 90 * 1024 * 1024);
    }

    #[test]
    fn disabled_namespaces_redistribute_to_chainstate() {
        let total = clamp_dbcache_bytes(450);
        let shares = split_cache_budget(total, false);
        assert_eq!(shares[0].bytes, total);
        assert_eq!(shares[1].bytes, 0);
    }

    #[test]
    fn odd_budgets_never_exceed_the_budget() {
        for mb in [1_u64, 16, 17, 333, 999, 1 << 20] {
            let total = clamp_dbcache_bytes(mb);
            for txindex in [true, false] {
                let shares = split_cache_budget(total, txindex);
                let sum = shares.iter().map(|share| share.bytes).sum::<u64>();
                assert!(sum <= total, "shares exceed budget at {mb} MiB");
            }
        }
    }

    #[test]
    fn clamps_zero_underflow_and_overflow() {
        assert_eq!(clamp_dbcache_bytes(0), MIN_DBCACHE_BYTES);
        assert_eq!(clamp_dbcache_bytes(1), MIN_DBCACHE_BYTES);
        assert_eq!(clamp_dbcache_bytes(450), 450 * 1024 * 1024);
        assert_eq!(clamp_dbcache_bytes(u64::MAX), MAX_DBCACHE_BYTES);
    }
}
