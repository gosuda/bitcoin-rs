//! Contract tests for the process cache-budget split.

use bitcoin_rs_storage::cache_budget::{
    CHAINSTATE_CACHE_SHARE_PCT, MAX_DBCACHE_BYTES, MIN_DBCACHE_BYTES, TXINDEX_CACHE_SHARE_PCT,
    clamp_dbcache_bytes, split_cache_budget,
};

#[test]
fn shares_sum_within_budget_for_every_enabled_combination() {
    for mb in [0_u64, 1, 16, 17, 333, 450, 999, 1 << 20, u64::MAX] {
        let total = clamp_dbcache_bytes(mb);
        assert!(
            (MIN_DBCACHE_BYTES..=MAX_DBCACHE_BYTES).contains(&total),
            "clamped budget {total} escaped the documented bounds for input {mb}"
        );
        for txindex in [true, false] {
            let shares = split_cache_budget(total, txindex);
            let sum = shares.iter().map(|share| share.bytes).sum::<u64>();
            assert!(
                sum <= total,
                "shares ({sum}) exceed budget ({total}) at input {mb}"
            );
        }
    }
}

#[test]
fn disabled_namespaces_redistribute_to_chainstate() {
    let total = clamp_dbcache_bytes(450);
    let shares = split_cache_budget(total, false);
    assert_eq!(shares[0].bytes, total, "chainstate takes the full budget");
    assert_eq!(shares[1].bytes, 0);

    // With txindex enabled, chainstate gets the remainder and txindex keeps
    // exactly 20%.
    let shares = split_cache_budget(total, true);
    assert_eq!(
        shares[1].bytes,
        total * TXINDEX_CACHE_SHARE_PCT / 100,
        "txindex keeps its fixed share"
    );
    assert_eq!(
        shares[0].bytes + shares[1].bytes,
        total,
        "redistributed remainder lands on chainstate"
    );
}

#[test]
fn exact_percentages_at_a_clean_budget() {
    // 1000 MiB divides cleanly into 800/200.
    let total = clamp_dbcache_bytes(1000);
    let shares = split_cache_budget(total, true);
    assert_eq!(shares[0].bytes, total * CHAINSTATE_CACHE_SHARE_PCT / 100);
    assert_eq!(shares[1].bytes, total * TXINDEX_CACHE_SHARE_PCT / 100);
}

#[test]
fn minimum_budget_split_with_all_namespaces_enabled() {
    // The documented floor with txindex enabled: both shares are nonzero,
    // flooring loses nothing to rounding, and the whole budget is distributed.
    let total = clamp_dbcache_bytes(16);
    assert_eq!(total, MIN_DBCACHE_BYTES);
    let shares = split_cache_budget(total, true);
    assert_eq!(
        shares[0].bytes, 13_421_773,
        "chainstate keeps the remainder"
    );
    assert_eq!(shares[1].bytes, 3_355_443, "txindex keeps a floored 20%");
    assert_eq!(
        shares.iter().map(|share| share.bytes).sum::<u64>(),
        total,
        "the 16 MiB budget is fully distributed"
    );
}
