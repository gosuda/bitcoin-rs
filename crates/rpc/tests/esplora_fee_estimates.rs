use std::collections::BTreeMap;
use std::sync::Arc;

use bitcoin_rs_mempool::{Mempool, MempoolEntry, MempoolLimits};
use bitcoin_rs_primitives::{
    Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
};
use bitcoin_rs_rpc::Handler;
use bitcoin_rs_rpc::context::Context;
use bitcoin_rs_rpc::esplora::{Surface, route};
use sonic_rs::JsonValueTrait as _;

const VSIZE: u32 = 100;
const HIGH_FEE_SATS: u64 = 10_000;
const LOW_FEE_SATS: u64 = 5_000;
const ENTRY_HEIGHT: u32 = 100;

fn spend(output_sats: u64) -> Tx {
    let mut prevout = [0_u8; 32];
    prevout[31] = u8::try_from(output_sats & 0xff).unwrap_or(0);
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&prevout)), 0),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(output_sats),
            script_pubkey: vec![0x51].into(),
        }],
    }
}

fn admit_batch(ctx: &Context, fee_sats: u64, entry_height: u32) -> Vec<Tx> {
    let pool = ctx.mempool.gateway.pool();
    let mut guard = pool.write();
    let mut txs = Vec::new();
    for index in 0_u64..2 {
        let tx = spend(1_000 + u64::from(entry_height) * 16 + index);
        txs.push(tx.clone());
        if guard
            .insert_entry(MempoolEntry::new(
                Arc::new(tx),
                VSIZE,
                fee_sats,
                1,
                entry_height,
                0,
            ))
            .is_err()
        {
            panic!("seeded entries must be admissible");
        }
    }
    txs
}

fn connect_block(ctx: &Context, confirmed: &[&Tx], confirmed_txids: &[Txid], height: u32) {
    let pool = ctx.mempool.gateway.pool();
    let mut guard = pool.write();
    let _ = guard.remove_for_block(confirmed, confirmed_txids, height, u64::from(height) * 600);
}

fn fee_estimates(ctx: &Arc<Context>) -> BTreeMap<String, f64> {
    let handler = Handler::new(Arc::clone(ctx));
    let response = route(&handler, Surface::Public, "fee-estimates", "");
    assert_eq!(response.status, 200, "fee-estimates must answer 200");
    let Ok(parsed) = sonic_rs::from_slice(&response.body) else {
        panic!("fee-estimates body must parse as JSON");
    };
    parsed
}

fn rpc_estimates(ctx: &Arc<Context>) -> BTreeMap<String, f64> {
    let handler = Handler::new(Arc::clone(ctx));
    (1_u32..=25)
        .chain([144, 504, 1008])
        .filter_map(|target| {
            let value = handler
                .dispatch("estimatesmartfee", &sonic_rs::json!([target]))
                .unwrap_or_else(|error| panic!("valid target {target}: {error}"));
            value
                .get("feerate")
                .and_then(sonic_rs::JsonValueTrait::as_f64)
                .map(|rate| (target.to_string(), rate * 100_000.0))
        })
        .collect()
}

fn confirmed_history(fee: u64, delay: u32) -> Arc<Context> {
    let ctx = Arc::new(Context::new());
    admit_batch(&ctx, fee / 2, ENTRY_HEIGHT);
    connect_block(&ctx, &[], &[], ENTRY_HEIGHT + delay);
    let txs = admit_batch(&ctx, fee, ENTRY_HEIGHT + delay);
    let txids: Vec<_> = txs.iter().map(Tx::txid).collect();
    let refs: Vec<_> = txs.iter().collect();
    connect_block(&ctx, &refs, &txids, ENTRY_HEIGHT + 2 * delay);
    ctx
}

#[test]
fn fee_estimates_omits_every_target_without_history() {
    let ctx = Arc::new(Context::new());
    let parsed = fee_estimates(&ctx);
    assert!(
        parsed.is_empty(),
        "without history no target may appear: {parsed:?}"
    );
    assert_eq!(parsed, rpc_estimates(&ctx));
}

#[test]
fn fee_estimates_projects_confirmed_history_to_sat_per_vbyte() {
    let ctx = confirmed_history(HIGH_FEE_SATS, 1);

    let parsed = fee_estimates(&ctx);
    assert_eq!(
        parsed.len(),
        28,
        "all declared targets carry the confirmed history: {parsed:?}"
    );

    let Some(estimate) = ctx.mempool.gateway.read().estimate_fee_rate(1) else {
        panic!("two confirmations against two sampled misses must qualify target 1");
    };
    let sat_per_kvb = estimate.as_sat_per_kvb();
    let projected =
        f64::from(u32::try_from(sat_per_kvb).unwrap_or(u32::MAX)) / 100_000_000.0 * 100_000.0;
    assert!(
        projected > 1.0,
        "the seeded history must estimate above the old 1 sat/vB floor"
    );
    assert_eq!(
        parsed.get("1"),
        Some(&projected),
        "Esplora target 1 must be the RPC estimate projected to sat/vB"
    );
    for target in ["2", "6", "25", "144", "504", "1008"] {
        assert!(
            parsed.contains_key(target),
            "target {target} must be present, not omitted"
        );
    }
    assert_eq!(parsed, rpc_estimates(&ctx));
}

#[test]
fn fee_estimates_preserves_partial_history_and_rpc_rounding() {
    let ctx = confirmed_history(LOW_FEE_SATS, 6);
    let parsed = fee_estimates(&ctx);
    assert_eq!(parsed, rpc_estimates(&ctx));
    assert_eq!(parsed.len(), 23);
    for target in 1..6 {
        assert!(!parsed.contains_key(&target.to_string()));
    }
    assert!(parsed.get("6").is_some_and(|rate| *rate > 1.0));
    for target in ["144", "504", "1008"] {
        assert_eq!(parsed.get(target), parsed.get("25"));
    }
}

#[test]
fn fee_estimates_is_coherent_during_concurrent_pool_changes() {
    use std::sync::{Barrier, mpsc};

    let ctx = confirmed_history(HIGH_FEE_SATS, 1);
    let other = confirmed_history(LOW_FEE_SATS, 6);
    let first = fee_estimates(&ctx);
    let second = fee_estimates(&other);
    assert_ne!(first, second);
    let mut alternate = Mempool::new(MempoolLimits::default());
    std::mem::swap(&mut *other.mempool.gateway.pool().write(), &mut alternate);
    let start = Barrier::new(2);
    std::thread::scope(|scope| {
        let (stop, stopped) = mpsc::channel::<()>();
        let ctx = &ctx;
        let start = &start;
        scope.spawn(move || {
            start.wait();
            while matches!(stopped.try_recv(), Err(mpsc::TryRecvError::Empty)) {
                std::mem::swap(&mut *ctx.mempool.gateway.pool().write(), &mut alternate);
                std::thread::yield_now();
            }
        });
        start.wait();
        for _ in 0..256 {
            let response = fee_estimates(ctx);
            assert!(
                response == first || response == second,
                "mixed estimator states: {response:?}"
            );
        }
        drop(stop);
    });
}
