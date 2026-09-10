//! Mempool-backend electrs extensions: `/internal/*` and `/block-template`.
//!
//! These are not wallet-facing. They exist so `mempool/backend` can set
//! `ESPLORA_REST_API_URL` to the `/esplora` directory on this listener.

use alloc::sync::Arc;
use core::str::FromStr as _;

use bitcoin_rs_mempool::{Mempool, MempoolEntry};
use bitcoin_rs_primitives::{OutPoint, Tx, Txid};

use super::http::{bad, dispatch_error, json_response, query_limit};
use super::model::{Outspend, TransactionValue};
use super::projection::Projection;
use super::public::{block_transaction_values, outspend, outspends_for_transaction};
use crate::context::Context;
use crate::handlers::Handler;
use crate::rest::Response;
use sonic_rs::json as sonic_json;

pub(super) fn get(handler: &Handler, ctx: &Context, path: &str, query: &str) -> Option<Response> {
    let parts: Vec<_> = path.trim_matches('/').split('/').collect();
    Some(match parts.as_slice() {
        ["internal", "mempool", "txs"] => internal_mempool_txs(ctx, None, query),
        ["internal", "mempool", "txs", last] => internal_mempool_txs(ctx, Some(last), query),
        ["internal", "block", hash, "txs"] => internal_block_txs(ctx, hash),
        ["block-template"] => block_template(handler),
        _ => return None,
    })
}

pub(super) fn post(handler: &Handler, path: &str, body: &[u8]) -> Option<Response> {
    let ctx = handler.context();
    match path {
        "/internal/txs" => Some(internal_transactions(ctx.as_ref(), body, false)),
        "/internal/mempool/txs" => Some(internal_transactions(ctx.as_ref(), body, true)),
        "/internal/txs/outspends/by-txid" => Some(internal_outspends_by_txid(ctx.as_ref(), body)),
        "/internal/txs/outspends/by-outpoint" => {
            Some(internal_outspends_by_outpoint(ctx.as_ref(), body))
        }
        _ => None,
    }
}

fn internal_block_txs(ctx: &Context, hash: &str) -> Response {
    let (record, block) = match Projection::new(ctx).required_block(hash) {
        Ok(value) => value,
        Err(response) => return response,
    };
    block_transaction_values(ctx, &record, block.txs.iter()).map_or_else(|r| r, json_response)
}

fn internal_mempool_txs(ctx: &Context, last: Option<&str>, query: &str) -> Response {
    let max_txs = query_limit(query, "max_txs").unwrap_or(usize::MAX);
    if max_txs == 0 {
        return json_response(Vec::<TransactionValue>::new());
    }
    // A cursor previously matched the exact lowercase Display text. Parse
    // once, but keep malformed, noncanonical, and absent cursors restarting
    // at the beginning instead of silently broadening the accepted syntax.
    let last = last.and_then(|text| {
        let txid = Txid::from_str(text).ok()?;
        (!text.bytes().any(|byte| byte.is_ascii_uppercase())).then_some(txid)
    });
    let transactions = {
        let pool = ctx.mempool.read();
        let mut ordered = snapshot_mempool_page(&pool, last, max_txs);
        drop(pool);
        // Only owned page entries reach sorting and projection. No entry
        // reference or pool guard escapes the snapshot.
        ordered.sort_unstable_by(|left, right| {
            left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1))
        });
        ordered
            .into_iter()
            .map(|(_, _, transaction)| transaction)
            .collect::<Vec<_>>()
    };
    let projection = Projection::new(ctx);
    transactions
        .into_iter()
        .map(|transaction| projection.transaction_value(&transaction, None))
        .collect::<Result<Vec<_>, _>>()
        .map_or_else(|r| r, json_response)
}

/// Selects one page from a single pool read, cloning only the selected payloads.
///
/// The scratch vector holds at most min(pool.len(), 2 * limit) borrowed entries.
/// Each full batch keeps its smallest `limit` keys: discarded keys cannot enter
/// that prefix after more entries arrive. Repeated full batches discard
/// `limit` entries; a pool smaller than two pages needs at most one partition.
/// Total selection work is therefore linear in the pool scan.
/// Selection happens under the caller's read guard; final sorting does not.
fn snapshot_mempool_page(
    pool: &Mempool,
    last: Option<Txid>,
    max_txs: usize,
) -> Vec<(u64, Txid, Arc<Tx>)> {
    let limit = max_txs.min(pool.len());
    if limit == 0 {
        return Vec::new();
    }
    let after = last
        .and_then(|txid| pool.entry_by_txid(&txid))
        .map(|entry| (entry.time, entry.txid));
    let mut entries = pool
        .iter_entries()
        .filter(|entry| after.is_none_or(|key| (entry.time, entry.txid) > key));
    // A full-pool request needs no selector or temporary borrowed vector.
    if limit == pool.len() {
        return entries
            .map(|entry| (entry.time, entry.txid, Arc::clone(&entry.tx)))
            .collect();
    }
    // Do not allocate the page scratch at all for an empty cursor suffix.
    let Some(first) = entries.next() else {
        return Vec::new();
    };
    let batch_len = limit.saturating_mul(2).min(pool.len());
    let mut selected = Vec::with_capacity(batch_len);
    selected.push(first);
    let mut cutoff = None;
    for entry in entries {
        if cutoff.is_some_and(|key| (entry.time, entry.txid) >= key) {
            continue;
        }
        selected.push(entry);
        if selected.len() == batch_len {
            cutoff = Some(trim_page_entries(&mut selected, limit));
        }
    }
    if selected.len() > limit {
        let _ = trim_page_entries(&mut selected, limit);
    }
    selected
        .into_iter()
        .map(|entry| (entry.time, entry.txid, Arc::clone(&entry.tx)))
        .collect()
}

/// Keeps the smallest `limit` keys and returns the first excluded key.
/// Callers establish `0 < limit < entries.len()` before partitioning.
fn trim_page_entries(entries: &mut Vec<&MempoolEntry>, limit: usize) -> (u64, Txid) {
    let (_, excluded, _) = entries.select_nth_unstable_by(limit, |left, right| {
        left.time
            .cmp(&right.time)
            .then_with(|| left.txid.cmp(&right.txid))
    });
    let cutoff = (excluded.time, excluded.txid);
    entries.truncate(limit);
    cutoff
}

fn internal_transactions(ctx: &Context, body: &[u8], mempool_only: bool) -> Response {
    let Ok(text_ids) = serde_json::from_slice::<Vec<String>>(body) else {
        return bad("transaction request body must be a JSON array of txids");
    };
    let ids = match text_ids
        .into_iter()
        .map(|id| Txid::from_str(&id).map_err(|_| bad("txid must be 64 hex characters")))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(ids) => ids,
        Err(response) => return response,
    };
    let projection = Projection::new(ctx);
    ids.into_iter()
        .filter_map(|id| {
            let transaction = if mempool_only {
                ctx.mempool
                    .read()
                    .transaction_by_txid(&id)
                    .map(|transaction| ((*transaction).clone(), None))
            } else {
                match projection.transaction(&id) {
                    Ok(transaction) => transaction,
                    Err(response) => return Some(Err(response)),
                }
            };
            transaction
                .map(|(transaction, status)| projection.transaction_value(&transaction, status))
        })
        .collect::<Result<Vec<_>, _>>()
        .map_or_else(|r| r, json_response)
}

fn internal_outspends_by_txid(ctx: &Context, body: &[u8]) -> Response {
    let Ok(text_ids) = serde_json::from_slice::<Vec<String>>(body) else {
        return bad("outspend request body must be a JSON array of txids");
    };
    let projection = Projection::new(ctx);
    text_ids
        .into_iter()
        .map(|id| {
            Txid::from_str(&id).ok().map_or(Ok(Vec::new()), |id| {
                projection
                    .transaction(&id)?
                    .map_or(Ok(Vec::new()), |(transaction, _)| {
                        outspends_for_transaction(&projection, &transaction)
                    })
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map_or_else(|r| r, json_response)
}

fn internal_outspends_by_outpoint(ctx: &Context, body: &[u8]) -> Response {
    let Ok(outpoints) = serde_json::from_slice::<Vec<String>>(body) else {
        return bad("outspend request body must be a JSON array of outpoints");
    };
    let projection = Projection::new(ctx);
    outpoints
        .into_iter()
        .map(|outpoint| internal_outspend(&projection, &outpoint))
        .collect::<Result<Vec<_>, _>>()
        .map_or_else(|r| r, json_response)
}

fn internal_outspend(
    projection: &Projection<'_>,
    text_outpoint: &str,
) -> Result<Outspend, Response> {
    let Some((text_txid, text_vout)) = text_outpoint.split_once(':') else {
        return Ok(Outspend::unspent());
    };
    let Ok(txid) = Txid::from_str(text_txid) else {
        return Ok(Outspend::unspent());
    };
    let Ok(vout) = text_vout.parse::<u32>() else {
        return Ok(Outspend::unspent());
    };
    let Some((transaction, _)) = projection.transaction(&txid)? else {
        return Ok(Outspend::unspent());
    };
    let Some(_) = transaction
        .outputs
        .get(usize::try_from(vout).unwrap_or(usize::MAX))
    else {
        return Ok(Outspend::unspent());
    };
    outspend(projection, OutPoint::new(txid, vout))
}

fn block_template(handler: &Handler) -> Response {
    handler
        .dispatch("getblocktemplate", &sonic_json!([]))
        .map_or_else(dispatch_error, json_response)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod pagination_tests {
    use alloc::sync::Arc;

    use bitcoin_rs_mempool::MempoolEntry;
    use bitcoin_rs_primitives::{Hash256, OutPoint, Tx, TxIn, TxOut, Txid};
    use serde_json::Value;

    use super::{internal_mempool_txs, snapshot_mempool_page};
    use crate::context::Context;

    fn fixture(times: &[u64]) -> (Context, Vec<(u64, Txid)>) {
        let ctx = Context::new();
        let mut expected = Vec::new();
        for (index, &time) in times.iter().enumerate() {
            // No-input fixtures isolate the projection/pagination owner;
            // they do not claim to exercise consensus or admission validity.
            let tx = Tx {
                version: 2,
                inputs: Vec::new(),
                outputs: vec![TxOut {
                    value: 1_000,
                    script_pubkey: vec![0x51],
                }],
                lock_time: u32::try_from(index).expect("small fixture index"),
            };
            let entry = MempoolEntry::new(Arc::new(tx), 100, 1_000, time, 0);
            expected.push((time, entry.txid));
            ctx.mempool
                .pool()
                .write()
                .insert_entry(entry)
                .expect("insert independent fixture entry");
        }
        // Independent reference: fully order all admission keys, then slice.
        expected.sort_unstable();
        (ctx, expected)
    }

    fn page(ctx: &Context, cursor: Option<&str>, query: &str) -> Vec<Txid> {
        let response = internal_mempool_txs(ctx, cursor, query);
        assert_eq!(
            response.status,
            200,
            "{}",
            String::from_utf8_lossy(&response.body)
        );
        let values: Value = serde_json::from_slice(&response.body).expect("response JSON");
        values
            .as_array()
            .expect("transaction array")
            .iter()
            .map(|value| {
                value["txid"]
                    .as_str()
                    .expect("text txid")
                    .parse()
                    .expect("valid txid")
            })
            .collect()
    }

    #[test]
    fn bounded_pages_match_full_sort_for_every_cursor() {
        for times in [
            Vec::new(),
            vec![0],
            vec![u64::MAX],
            vec![7; 18],
            vec![8, 0, u64::MAX, 8, 1, 8, 1, 0, 9, 8, 1, 0, 9, 4, 4, 8, 2, 9],
        ] {
            let (ctx, expected) = fixture(&times);
            let cursors = std::iter::once(None)
                .chain(expected.iter().map(|(_, txid)| Some(txid.to_string())));
            for (start, cursor) in cursors.enumerate() {
                for limit in [0, 1, 2, 3, 8, 17, 18, 19, usize::MAX] {
                    let want: Vec<_> = expected
                        .iter()
                        .skip(start)
                        .take(limit)
                        .map(|(_, txid)| *txid)
                        .collect();
                    assert_eq!(
                        page(&ctx, cursor.as_deref(), &format!("max_txs={limit}")),
                        want,
                        "cursor {cursor:?}, limit {limit}"
                    );
                }
            }
        }
    }

    // Contract: docs/contracts/external-api.md, API-09 (Esplora dialects),
    // which defines exact lowercase txid cursors and restart behavior for
    // malformed, noncanonical, unknown, and missing values.
    #[test]
    fn noncanonical_and_missing_cursors_keep_restart_behavior() {
        let (ctx, expected) = fixture(&[4, 1, 4, 2, 4, 3]);
        let lower = expected[2].1.to_string();
        let upper = lower.to_ascii_uppercase();
        assert_ne!(lower, upper, "fixture must exercise alphabetic hex");
        let unknown = Txid(Hash256::from_le_bytes(&[0xff; 32]));
        assert!(expected.iter().all(|(_, txid)| *txid != unknown));
        let want: Vec<_> = expected.iter().take(3).map(|(_, txid)| *txid).collect();
        for cursor in [
            String::new(),
            "00".to_owned(),
            "g".repeat(64),
            "é".repeat(32),
            format!(" {lower}"),
            format!("0x{lower}"),
            upper,
            unknown.to_string(),
        ] {
            assert_eq!(page(&ctx, Some(&cursor), "max_txs=3"), want);
        }
    }

    #[test]
    fn absent_invalid_and_duplicate_limits_keep_query_semantics() {
        let (ctx, expected) = fixture(&[2, 0, 1, 2]);
        let all: Vec<_> = expected.iter().map(|(_, txid)| *txid).collect();
        for query in [
            "",
            "max_txs=invalid",
            "max_txs=-1",
            "max_txs=184467440737095516160",
            "other=1",
        ] {
            assert_eq!(page(&ctx, None, query), all);
        }
        assert_eq!(page(&ctx, None, "max_txs=invalid&max_txs=2"), all[..2]);
        assert_eq!(page(&ctx, None, "max_txs=1&max_txs=2"), all[..1]);
        assert!(page(&ctx, None, "max_txs=0&max_txs=2").is_empty());
    }

    #[test]
    fn unselected_transactions_are_not_projected() {
        let (ctx, expected) = fixture(&[2, 3]);
        let tx = Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[0xaa; 32])), 0),
                script_sig: Vec::new(),
                sequence: u32::MAX,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 1,
                script_pubkey: vec![0x51],
            }],
            lock_time: 99,
        };
        let entry = MempoolEntry::new(Arc::new(tx), 100, 1_000, 1, 0);
        let cursor = entry.txid.to_string();
        ctx.mempool
            .pool()
            .write()
            .insert_entry(entry)
            .expect("insert unresolved-prevout fixture");
        assert_eq!(internal_mempool_txs(&ctx, None, "max_txs=1").status, 503);
        assert_eq!(page(&ctx, Some(&cursor), "max_txs=1"), vec![expected[0].1]);
        assert!(page(&ctx, None, "max_txs=0").is_empty());
    }

    #[test]
    fn streaming_pages_match_full_sort_across_many_batches() {
        for times in [
            (0..1_025).collect::<Vec<u64>>(),
            (0..1_025).rev().collect(),
            vec![7; 1_025],
            (0..1_025).map(|n| (n * 73) % 97).collect(),
        ] {
            let (ctx, expected) = fixture(&times);
            for start in [0_usize, 1, 513, 1_024, 1_025] {
                let cursor = start.checked_sub(1).map(|index| expected[index].1);
                for limit in [0, 1, 2, 3, 17, 257, 512, 513, 1_024, 1_025, usize::MAX] {
                    let mut got = snapshot_mempool_page(&ctx.mempool.read(), cursor, limit);
                    got.sort_unstable_by_key(|entry| (entry.0, entry.1));
                    let keys: Vec<_> = got.iter().map(|entry| (entry.0, entry.1)).collect();
                    let want: Vec<_> = expected.iter().skip(start).take(limit).copied().collect();
                    assert_eq!(keys, want, "start {start}, limit {limit}");
                    assert!(got.iter().all(|(_, _, tx)| Arc::strong_count(tx) >= 2));
                }
            }
        }
    }

    // Exact pre-streaming selector from commit 7571d49, restricted to tests.
    // The comparison excludes JSON projection and cursor text parsing in both
    // arms, and includes the read guard, Arc operations, selection, and sort.
    fn measured_snapshot(
        ctx: &Context,
        cursor: Option<Txid>,
        limit: usize,
        streaming: bool,
    ) -> (std::time::Duration, Vec<(u64, Txid, Arc<Tx>)>) {
        let pool = ctx.mempool.read();
        let locked_at = std::time::Instant::now();
        let mut page = if streaming {
            snapshot_mempool_page(&pool, cursor, limit)
        } else {
            let after = cursor
                .and_then(|txid| pool.entry_by_txid(&txid))
                .map(|entry| (entry.time, entry.txid));
            pool.iter_entries()
                .filter(|entry| after.is_none_or(|key| (entry.time, entry.txid) > key))
                .map(|entry| (entry.time, entry.txid, Arc::clone(&entry.tx)))
                .collect::<Vec<_>>()
        };
        drop(pool);
        let held = locked_at.elapsed();
        if !streaming && limit < page.len() {
            page.select_nth_unstable_by(limit, |left, right| {
                left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1))
            });
            page.truncate(limit);
        }
        page.sort_unstable_by(|left, right| {
            left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1))
        });
        (held, page)
    }

    #[test]
    #[ignore = "manual release benchmark; reports samples, not a performance acceptance gate"]
    fn benchmark_streaming_mempool_pages() {
        use std::hint::black_box;
        use std::time::Instant;

        assert!(!cfg!(debug_assertions), "run this benchmark with --release");
        for count in [256_usize, 4_096, 65_536] {
            let times: Vec<_> = (0..count)
                .map(|n| u64::try_from((n * 73) % 97).expect("small timestamp"))
                .collect();
            let (ctx, expected) = fixture(&times);
            for cursor in [None, Some(expected[count / 2].1)] {
                for limit in [1, 25, 256, count - 1, usize::MAX] {
                    let before = measured_snapshot(&ctx, cursor, limit, false).1;
                    let after = measured_snapshot(&ctx, cursor, limit, true).1;
                    assert_eq!(before, after);
                    drop((before, after));
                    let iterations = (65_536 / count).max(4);
                    // Warm both arms, then alternate order across seven pairs.
                    for streaming in [false, true] {
                        black_box(measured_snapshot(&ctx, cursor, limit, streaming));
                    }
                    for sample in 0..7 {
                        for streaming in [sample % 2 != 0, sample % 2 == 0] {
                            let mut held_ns = 0_u128;
                            let started = Instant::now();
                            for _ in 0..iterations {
                                let (held, page) = measured_snapshot(
                                    black_box(&ctx),
                                    black_box(cursor),
                                    black_box(limit),
                                    streaming,
                                );
                                held_ns += held.as_nanos();
                                black_box(page);
                            }
                            let elapsed_ns = started.elapsed().as_nanos();
                            println!(
                                "page_sample,count={count},cursor={},limit={limit},streaming={streaming},sample={sample},iterations={iterations},elapsed_ns={elapsed_ns},read_guard_ns={held_ns}",
                                cursor.is_some()
                            );
                        }
                    }
                }
            }
        }
    }
}
