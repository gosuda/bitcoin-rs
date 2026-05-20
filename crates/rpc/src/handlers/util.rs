use alloc::sync::Arc;
use alloc::vec::Vec;

use sonic_rs::{Value, json};

use crate::context::Context;
use crate::error::RpcError;
use crate::handlers::required_u64;

const BLOCK_VSIZE_TARGET: u64 = 1_000_000;
const DEFAULT_MIN_FEERATE_SAT_PER_KVB: u64 = 1_000; // 1 sat/vB

fn estimate_feerate_sat_per_kvb(ctx: &Context, conf_target: u64) -> u64 {
    let mempool = ctx.mempool.read();
    if mempool.entries.is_empty() {
        return DEFAULT_MIN_FEERATE_SAT_PER_KVB;
    }

    let mut buckets: Vec<(u64, u64)> = Vec::new();
    for (_id, entry) in &mempool.entries {
        let Some((_, bucket_vsize)) = buckets
            .iter_mut()
            .find(|(bucket_rate, _)| *bucket_rate == entry.fee_rate)
        else {
            buckets.push((entry.fee_rate, u64::from(entry.vsize)));
            continue;
        };
        *bucket_vsize = bucket_vsize.saturating_add(u64::from(entry.vsize));
    }

    buckets.sort_unstable_by(|a, b| b.0.cmp(&a.0));

    let target_vsize = BLOCK_VSIZE_TARGET.saturating_mul(conf_target.max(1));
    let mut cumulative: u64 = 0;
    let mut threshold = DEFAULT_MIN_FEERATE_SAT_PER_KVB;
    for (rate, vsize) in &buckets {
        cumulative = cumulative.saturating_add(*vsize);
        threshold = *rate;
        if cumulative >= target_vsize {
            break;
        }
    }

    threshold.max(DEFAULT_MIN_FEERATE_SAT_PER_KVB)
}

fn sat_per_kvb_to_btc_per_kvb(sat: u64) -> f64 {
    f64::from(u32::try_from(sat).unwrap_or(u32::MAX)) / 100_000_000.0_f64
}

pub(crate) fn estimatesmartfee(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let conf_target = required_u64(params, 0, "conf_target is required")?;
    let rate_sat_per_kvb = estimate_feerate_sat_per_kvb(ctx, conf_target);
    let feerate = sat_per_kvb_to_btc_per_kvb(rate_sat_per_kvb);
    Ok(json!({
        "feerate": feerate,
        "blocks": conf_target
    }))
}

pub(crate) fn estimaterawfee(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let conf_target = required_u64(params, 0, "conf_target is required")?;
    let rate_sat_per_kvb = estimate_feerate_sat_per_kvb(ctx, conf_target);
    let feerate = sat_per_kvb_to_btc_per_kvb(rate_sat_per_kvb);
    Ok(json!({
        "short": {"feerate": feerate, "decay": 0.962, "scale": 1},
        "medium": {"feerate": feerate, "decay": 0.962, "scale": 1},
        "long": {"feerate": feerate, "decay": 0.962, "scale": 1}
    }))
}
#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use sonic_rs::JsonValueTrait;

    #[test]
    fn estimate_returns_default_when_mempool_empty() {
        let ctx = Arc::new(Context::new());
        let result = estimatesmartfee(&ctx, &json!([3]))
            .unwrap_or_else(|err| panic!("estimatesmartfee failed: {err}"));
        let Some(feerate) = result.get("feerate").and_then(JsonValueTrait::as_f64) else {
            panic!("feerate missing: {result:?}");
        };
        // Default min: 1000 sat/kvB / 100_000_000 = 0.00001
        assert!(
            feerate > 0.0,
            "empty mempool should still return a min feerate: {result:?}"
        );
    }
}
