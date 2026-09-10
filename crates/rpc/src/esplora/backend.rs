//! Mempool-backend electrs extensions: `/internal/*` and `/block-template`.
//!
//! These are not wallet-facing. They exist so `mempool/backend` can set
//! `ESPLORA_REST_API_URL` to the `/esplora` directory on this listener.

use alloc::sync::Arc;
use core::str::FromStr as _;

use bitcoin_rs_mempool::MempoolEntry;
use bitcoin_rs_primitives::{OutPoint, Txid};

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
        (txid.to_string() == text).then_some(txid)
    });
    let transactions = {
        let pool = ctx.mempool.read();
        // Cursor lookup, selection, and Arc capture share one read guard.
        // Only the selected page escapes the guard; no second lookup can
        // observe a removal or replacement between selection and capture.
        let after = last
            .and_then(|txid| pool.entry_by_txid(&txid))
            .map(|entry| (entry.time, entry.txid));
        let mut ordered = select_mempool_page(pool.iter_entries(), after, max_txs)
            .into_iter()
            .map(|entry| (entry.time, entry.txid, Arc::clone(&entry.tx)))
            .collect::<Vec<_>>();
        drop(pool);
        // Final ordering and transaction projection stay outside the guard.
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

/// Selects the API-09 page without retaining the entire eligible suffix.
///
/// At most 2K borrowed entries are live for a positive limit K. Every full
/// batch discards K entries in linear time; only the final page is cloned by
/// the caller. `Vec` capacity grows with observed entries, not an untrusted
/// requested limit. Selection holds the caller's read guard; it trades that
/// work for bounded scratch space and avoids `Arc` churn on rejected entries.
fn select_mempool_page<'a>(
    entries: impl Iterator<Item = &'a MempoolEntry>,
    after: Option<(u64, Txid)>,
    max_txs: usize,
) -> Vec<&'a MempoolEntry> {
    let mut selected = Vec::new();
    if max_txs == 0 {
        return selected;
    }
    let mut cutoff = None;
    for entry in entries {
        let key = (entry.time, entry.txid);
        if after.is_some_and(|after| key <= after) || cutoff.is_some_and(|cutoff| key >= cutoff) {
            continue;
        }
        selected.push(entry);
        // This is len >= 2K without multiplying the caller's usize limit.
        // K > 0 also proves the nth index is strictly below the length.
        if selected.len() / 2 >= max_txs {
            let (_, excluded, _) =
                selected.select_nth_unstable_by_key(max_txs, |entry| (entry.time, entry.txid));
            // Txids are unique in a pool snapshot. Everything retained is
            // strictly before this first excluded key; later keys cannot win.
            cutoff = Some((excluded.time, excluded.txid));
            selected.truncate(max_txs);
        }
    }
    if max_txs < selected.len() {
        selected.select_nth_unstable_by_key(max_txs, |entry| (entry.time, entry.txid));
        selected.truncate(max_txs);
    }
    selected
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

    use super::{internal_mempool_txs, select_mempool_page};
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

    // API-09 in docs/contracts/external-api.md owns order and strict cursor
    // exclusion. Full sorting is the independent selection reference.
    #[test]
    fn batched_selection_matches_full_sort_across_flush_boundaries() {
        let entries: Vec<_> = (0_u32..257)
            .map(|index| {
                let tx = Tx {
                    lock_time: index,
                    ..Tx::default()
                };
                MempoolEntry::new(Arc::new(tx), 100, 1_000, u64::from(index % 7), 0)
            })
            .collect();
        let mut ordered: Vec<_> = entries.iter().collect();
        ordered.sort_unstable_by_key(|entry| (entry.time, entry.txid));
        for reverse in [false, true] {
            let mut traversal = ordered.clone();
            if reverse {
                traversal.reverse();
            }
            for after in [None, Some((ordered[128].time, ordered[128].txid))] {
                for limit in [0, 1, 2, 3, 25, 127, 128, 129, 256, 257, usize::MAX] {
                    let mut actual = select_mempool_page(traversal.iter().copied(), after, limit);
                    actual.sort_unstable_by_key(|entry| (entry.time, entry.txid));
                    let actual: Vec<_> = actual.iter().map(|entry| entry.txid).collect();
                    let expected: Vec<_> = ordered
                        .iter()
                        .filter(|entry| after.is_none_or(|key| (entry.time, entry.txid) > key))
                        .take(limit)
                        .map(|entry| entry.txid)
                        .collect();
                    assert_eq!(actual, expected, "reverse={reverse}, limit={limit}");
                }
            }
        }
    }

    // Contract: CONSTRAINTS.md, "Mempool page-selection contracts (v1)", SEL-01.
    #[test]
    fn selection_borrows_payloads_and_only_the_final_page_is_cloned() {
        let entries: Vec<_> = (0_u32..129)
            .map(|index| {
                MempoolEntry::new(
                    Arc::new(Tx {
                        lock_time: index,
                        ..Tx::default()
                    }),
                    100,
                    1_000,
                    u64::from(129 - index),
                    0,
                )
            })
            .collect();
        let selected = select_mempool_page(
            entries.iter().inspect(|_| {
                assert!(
                    entries
                        .iter()
                        .all(|entry| Arc::strong_count(&entry.tx) == 1)
                );
            }),
            None,
            3,
        );
        assert_eq!(selected.len(), 3);
        assert!(
            entries
                .iter()
                .all(|entry| Arc::strong_count(&entry.tx) == 1)
        );
        let captured: Vec<_> = selected.iter().map(|entry| Arc::clone(&entry.tx)).collect();
        assert_eq!(
            entries
                .iter()
                .filter(|entry| Arc::strong_count(&entry.tx) == 2)
                .count(),
            3
        );
        drop(captured);
        assert!(
            entries
                .iter()
                .all(|entry| Arc::strong_count(&entry.tx) == 1)
        );
    }

    // Contract: CONSTRAINTS.md, "Mempool page-selection contracts (v1)", SEL-02.
    #[test]
    fn zero_selection_does_not_poll_the_pool_iterator() {
        let entries = std::iter::from_fn(|| -> Option<&MempoolEntry> {
            panic!("zero-sized pages must not traverse entries")
        });
        assert!(select_mempool_page(entries, None, 0).is_empty());
    }

    /// Paired page-selection microbenchmark, not an HTTP or lock benchmark.
    /// Run with --release --ignored --nocapture; fixture setup is untimed.
    #[test]
    #[ignore = "manual paired release benchmark; no timing threshold in unit tests"]
    fn benchmark_bounded_page_selection() {
        use std::hint::black_box;
        use std::time::Instant;

        fn snapshot(
            entries: &[MempoolEntry],
            after: Option<(u64, Txid)>,
            limit: usize,
            bounded: bool,
        ) -> Vec<(u64, Txid, Arc<Tx>)> {
            let mut page: Vec<_> = if bounded {
                select_mempool_page(entries.iter(), after, limit)
                    .into_iter()
                    .map(|entry| (entry.time, entry.txid, Arc::clone(&entry.tx)))
                    .collect()
            } else {
                // PR #796 at 9c6a3904: capture the entire suffix, partition,
                // then sort only the retained page. Keep this baseline local.
                let mut all: Vec<_> = entries
                    .iter()
                    .filter(|entry| after.is_none_or(|key| (entry.time, entry.txid) > key))
                    .map(|entry| (entry.time, entry.txid, Arc::clone(&entry.tx)))
                    .collect();
                if limit < all.len() {
                    all.select_nth_unstable_by_key(limit, |entry| (entry.0, entry.1));
                    all.truncate(limit);
                }
                all
            };
            page.sort_unstable_by_key(|entry| (entry.0, entry.1));
            page
        }

        let entries: Vec<_> = (0_u32..10_000)
            .map(|index| {
                MempoolEntry::new(
                    Arc::new(Tx {
                        lock_time: index,
                        ..Tx::default()
                    }),
                    100,
                    1_000,
                    u64::from(index.wrapping_mul(2_654_435_761) % 10_000),
                    0,
                )
            })
            .collect();
        for after in [None, Some((entries[5_000].time, entries[5_000].txid))] {
            for limit in [1, 25, 1_000, 9_999, usize::MAX] {
                let expected = snapshot(&entries, after, limit, false);
                assert_eq!(snapshot(&entries, after, limit, true), expected);
                drop(expected);
                for trial in 0..6 {
                    // Alternate order to reduce one-sided warm-cache bias.
                    for bounded in [trial % 2 == 0, trial % 2 != 0] {
                        let start = Instant::now();
                        for _ in 0..100 {
                            drop(black_box(snapshot(
                                black_box(&entries),
                                after,
                                limit,
                                bounded,
                            )));
                        }
                        eprintln!(
                            "page_selection n={} after={after:?} k={limit} trial={trial} bounded={bounded} iterations=100 elapsed_ns={}",
                            entries.len(),
                            start.elapsed().as_nanos()
                        );
                    }
                }
            }
        }
    }
}
