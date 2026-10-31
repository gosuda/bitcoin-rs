//! Bounded CPU/projection probe. This synthetic index is not disk/sync evidence.

use super::super::*;
use std::sync::Barrier;
use std::time::Instant;

struct LoadTxIndex {
    transactions: std::collections::HashMap<Txid, Tx>,
    calls: AtomicUsize,
}

impl crate::context::DerivedIndexQuery for LoadTxIndex {
    fn transaction(&self, txid: &Txid) -> Result<Option<Tx>, TxQueryError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(self.transactions.get(txid).cloned())
    }

    fn transaction_height(&self, txid: &Txid) -> Result<Option<u32>, TxQueryError> {
        Ok(self.transactions.contains_key(txid).then_some(0))
    }

    fn outpoint_value(&self, _: &OutPoint) -> Result<Option<u64>, TxQueryError> {
        Ok(None)
    }

    fn index_info(&self) -> Result<crate::context::DerivedIndexInfo, TxQueryError> {
        Ok(crate::context::DerivedIndexInfo {
            synced: true,
            best_block_height: 0,
        })
    }
}

#[test]
#[ignore = "bounded load probe; run explicitly with --ignored --nocapture"]
#[expect(
    clippy::too_many_lines,
    reason = "keep bounded load setup and measurement together"
)]
fn large_script_projection_load() {
    let limit = std::env::var("ESPLORA_LOAD_LIMIT")
        .expect("set candidate limit")
        .parse::<std::num::NonZeroUsize>()
        .expect("positive limit");
    let target = vec![0x51];
    let transactions = (1..=20_000)
        .map(|value| {
            transaction(
                None,
                TxOut {
                    value: Amount::from_sat(value),
                    script_pubkey: target.clone().into(),
                },
            )
        })
        .collect::<Vec<_>>();
    let history = transactions
        .iter()
        .map(|tx| ScriptHistoryRecord {
            txid: tx.txid(),
            height: 0,
        })
        .collect();
    let funding = transactions
        .iter()
        .map(|tx| ScriptIndexRecord {
            txid: tx.txid(),
            height: 0,
            value: tx.outputs[0].value.to_sat(),
            vout: 0,
        })
        .collect::<Vec<_>>();
    let mut ctx = Context::new().with_esplora_query_limit(limit);
    ctx.chain
        .add_block(bitcoin_rs_index::block_log::BlockRecord::synthetic(
            0,
            BlockHash::default(),
        ));
    ctx.indexes.script_index = Some(Arc::new(StaticScriptIndex {
        history,
        funding: funding.clone(),
        unspent: funding,
    }));
    let tx_index = Arc::new(LoadTxIndex {
        transactions: transactions.into_iter().map(|tx| (tx.txid(), tx)).collect(),
        calls: AtomicUsize::new(0),
    });
    ctx.indexes.esplora_tx_index = Some(tx_index.clone());
    let handler = Arc::new(Handler::new(Arc::new(ctx)));
    let hash = ScriptHash::new(&target)
        .to_byte_array()
        .to_lower_hex_string();
    let paths = ["", "/utxo", "/txs", "/txs/summary", "/txs/chain"]
        .map(|suffix| format!("/scripthash/{hash}{suffix}"));
    // Validate all successful results and warm the same fixture before sampling.
    for path in &paths {
        assert_eq!(route(&handler, path, "").status, 200);
    }
    let start = Instant::now();
    let barrier = Arc::new(Barrier::new(8));
    let results = std::thread::scope(|scope| {
        let mut workers = Vec::with_capacity(8);
        for _ in 0..8 {
            let paths = &paths;
            let handler = &handler;
            let barrier = &barrier;
            workers.push(scope.spawn(move || {
                let mut results = Vec::new();
                for round in 0..20 {
                    barrier.wait();
                    let started = Instant::now();
                    let response = route(handler, &paths[round % paths.len()], "");
                    assert!(matches!(response.status, 200 | 503));
                    results.push((response.status, started.elapsed().as_secs_f64() * 1000.0));
                }
                results
            }));
        }
        workers
            .into_iter()
            .flat_map(|worker| worker.join().expect("load worker"))
            .collect::<Vec<_>>()
    });
    let mut accepted = results
        .iter()
        .filter(|(status, _)| *status == 200)
        .map(|(_, ms)| *ms)
        .collect::<Vec<_>>();
    let mut rejected = results
        .iter()
        .filter(|(status, _)| *status == 503)
        .map(|(_, ms)| *ms)
        .collect::<Vec<_>>();
    accepted.sort_by(f64::total_cmp);
    rejected.sort_by(f64::total_cmp);
    assert_ne!(accepted.len(), 0);
    assert_ne!(rejected.len(), 0);
    println!(
        "limit={} requests=160 accepted={} rejected={} accepted_p50_ms={:.3} accepted_p95_ms={:.3} rejected_p95_ms={:.3} wall_s={:.3} tx_lookups={} body_reads=0 sync_progress=not_attached",
        limit,
        accepted.len(),
        rejected.len(),
        accepted[accepted.len() / 2],
        accepted[(accepted.len() - 1) * 95 / 100],
        rejected[(rejected.len() - 1) * 95 / 100],
        start.elapsed().as_secs_f64(),
        tx_index.calls.load(Ordering::Relaxed)
    );
    assert_eq!(
        route(&handler, &paths[0], "").status,
        200,
        "permits recover after successful load"
    );
}
