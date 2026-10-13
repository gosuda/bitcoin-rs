//! Mempool-backend electrs extensions: `/internal/*` and `/block-template`.
//!
//! These are not wallet-facing. They exist so `mempool/backend` can set
//! `ESPLORA_REST_API_URL` to the `/esplora` directory on this listener.

use alloc::sync::Arc;
use core::str::FromStr as _;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write as _};

use serde::Serialize;

use bitcoin_rs_mempool::MempoolEntry;
use bitcoin_rs_primitives::{OutPoint, Txid};

use super::http::{dispatch_error, query_limit};
use super::model::{Outspend, TransactionValue};
use super::projection::Projection;
use super::public::{block_transaction_rows, outspend, outspends_for_transaction};
use crate::context::Context;
use crate::handlers::Handler;
use crate::handlers::mining::required_gbt_rules;
use crate::rest::Response;
use crate::rest::{bad_request, internal_error, json_ok, service_unavailable, text_response};
use sonic_rs::json as sonic_json;


const DEFAULT_MEMPOOL_PAGE: usize = 25;
const MAX_MEMPOOL_PAGE: usize = 100;
const MAX_BULK_ITEMS: usize = 64;
const MAX_BACKEND_RESPONSE_BYTES: usize = 4 * 1_024 * 1_024;

struct LimitedJson(Vec<u8>);

impl io::Write for LimitedJson {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_BACKEND_RESPONSE_BYTES - self.0.len() {
            return Err(io::Error::other("backend response budget exceeded"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Serializes a bounded response incrementally, stopping projection as soon as
/// the byte budget is exhausted rather than collecting every transaction first.
fn bounded_json_array<T: Serialize>(
    items: impl IntoIterator<Item = Result<T, Response>>,
) -> Response {
    let mut body = LimitedJson(vec![b'[']);
    for (index, item) in items.into_iter().enumerate() {
        let value = match item {
            Ok(value) => value,
            Err(response) => return response,
        };
        if index != 0 && body.write_all(b",").is_err() {
            return service_unavailable("backend response budget exceeded");
        }
        if let Err(error) = serde_json::to_writer(&mut body, &value) {
            return if error.is_io() {
                service_unavailable("backend response budget exceeded")
            } else {
                internal_error("failed to serialize backend response")
            };
        }
    }
    if body.write_all(b"]").is_err() {
        return service_unavailable("backend response budget exceeded");
    }
    text_response("application/json", body.0)
}

fn bulk_strings(body: &[u8], invalid_message: &'static str) -> Result<Vec<String>, Response> {
    let values = serde_json::from_slice::<Vec<String>>(body)
        .map_err(|_| bad_request(invalid_message))?;
    if values.len() > MAX_BULK_ITEMS {
        return Err(bad_request("backend bulk request exceeds 64 items"));
    }
    Ok(values)
}

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
    bounded_json_array(block_transaction_rows(ctx, &record, block.txs.iter()))
}

fn internal_mempool_txs(ctx: &Context, last: Option<&str>, query: &str) -> Response {
    let max_txs = query_limit(query, "max_txs")
        .unwrap_or(DEFAULT_MEMPOOL_PAGE)
        .min(MAX_MEMPOOL_PAGE);
    if max_txs == 0 {
        return json_ok(Vec::<TransactionValue>::new());
    }
    // A cursor previously matched the exact lowercase Display text. Parse
    // once, but keep malformed, noncanonical, and absent cursors restarting
    // at the beginning instead of silently broadening the accepted syntax.
    let last = last.and_then(|text| {
        let txid = Txid::from_str(text).ok()?;
        (txid.to_string() == text).then_some(txid)
    });
    let transactions = {
        let pool = ctx.mempool.gateway.read();
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
    bounded_json_array(
        transactions
            .into_iter()
            .map(|transaction| projection.transaction_value(&transaction, None)),
    )
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
    let text_ids = match bulk_strings(body, "transaction request body must be a JSON array of txids") {
        Ok(ids) => ids,
        Err(response) => return response,
    };
    let ids = match text_ids
        .into_iter()
        .map(|id| Txid::from_str(&id).map_err(|_| bad_request("txid must be 64 hex characters")))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(ids) => ids,
        Err(response) => return response,
    };
    // Unlike positional outspends, this endpoint returns transaction objects.
    // Repeated IDs must not repeat expensive projection or inflate the reply.
    let mut seen = BTreeSet::new();
    let projection = Projection::new(ctx);
    bounded_json_array(ids.into_iter().filter(|id| seen.insert(*id)).filter_map(|id| {
        let transaction = if mempool_only {
            ctx.mempool
                .gateway
                .read()
                .transaction_by_txid(&id)
                .map(|transaction| ((*transaction).clone(), None))
        } else {
            match projection.transaction(&id) {
                Ok(transaction) => transaction,
                Err(response) => return Some(Err(response)),
            }
        };
        transaction.map(|(transaction, status)| projection.transaction_value(&transaction, status))
    }))
}

fn internal_outspends_by_txid(ctx: &Context, body: &[u8]) -> Response {
    let text_ids = match bulk_strings(body, "outspend request body must be a JSON array of txids") {
        Ok(ids) => ids,
        Err(response) => return response,
    };
    let projection = Projection::new(ctx);
    let mut cached = BTreeMap::<String, Vec<Outspend>>::new();
    bounded_json_array(text_ids.into_iter().map(|text| {
        if let Some(value) = cached.get(&text) {
            return Ok(value.clone());
        }
        let value = Txid::from_str(&text).ok().map_or(Ok(Vec::new()), |id| {
            projection
                .transaction(&id)?
                .map_or(Ok(Vec::new()), |(transaction, _)| {
                    outspends_for_transaction(&projection, &transaction)
                })
        })?;
        cached.insert(text, value.clone());
        Ok(value)
    }))
}

fn internal_outspends_by_outpoint(ctx: &Context, body: &[u8]) -> Response {
    let outpoints =
        match bulk_strings(body, "outspend request body must be a JSON array of outpoints") {
            Ok(outpoints) => outpoints,
            Err(response) => return response,
        };
    let projection = Projection::new(ctx);
    let mut cached = BTreeMap::<String, Outspend>::new();
    bounded_json_array(outpoints.into_iter().map(|text| {
        if let Some(value) = cached.get(&text) {
            return Ok(value.clone());
        }
        let value = internal_outspend(&projection, &text)?;
        cached.insert(text, value.clone());
        Ok(value)
    }))
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
    let rules = required_gbt_rules(handler.context().chain.chain_network);
    let request = sonic_json!([{"rules": rules}]);
    handler
        .dispatch("getblocktemplate", &request)
        .map_or_else(dispatch_error, json_ok)
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod pagination_tests {
    use alloc::sync::Arc;

    use bitcoin_rs_mempool::MempoolEntry;
    use bitcoin_rs_primitives::{
        Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
    };
    use serde_json::Value;

    use super::{
        DEFAULT_MEMPOOL_PAGE, MAX_BACKEND_RESPONSE_BYTES, MAX_BULK_ITEMS, MAX_MEMPOOL_PAGE,
        bounded_json_array, internal_mempool_txs, internal_outspends_by_outpoint,
        internal_outspends_by_txid, internal_transactions, select_mempool_page,
    };
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
                    value: Amount::from_sat(1_000),
                    script_pubkey: Script::from_bytes(vec![0x51]),
                }],
                lock_time: LockTime::from_consensus(
                    u32::try_from(index).expect("small fixture index"),
                ),
            };
            let entry = MempoolEntry::new(Arc::new(tx), 100, 1_000, time, 0, 0);
            expected.push((time, entry.txid));
            ctx.mempool
                .gateway
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
        assert_eq!(page(&ctx, None, "max_txs=0&max_txs=2"), []);
    }

    #[test]
    fn mempool_endpoint_defaults_and_hard_caps_page_size() {
        let times: Vec<_> = (0_u64..120).collect();
        let (ctx, _) = fixture(&times);
        assert_eq!(page(&ctx, None, "").len(), DEFAULT_MEMPOOL_PAGE);
        assert_eq!(page(&ctx, None, "max_txs=invalid").len(), DEFAULT_MEMPOOL_PAGE);
        assert_eq!(page(&ctx, None, "max_txs=999999").len(), MAX_MEMPOOL_PAGE);
        assert_eq!(page(&ctx, None, "max_txs=0"), []);
    }

    #[test]
    fn bulk_routes_reject_oversized_lists_and_deduplicate_expensive_work() {
        let (ctx, expected) = fixture(&[1, 2]);
        let text_id = expected[0].1.to_string();
        let duplicates = serde_json::to_vec(&vec![text_id.clone(), text_id])
            .expect("serialize duplicate IDs");
        let response = internal_transactions(&ctx, &duplicates, true);
        assert_eq!(response.status, 200);
        let values: Value = serde_json::from_slice(&response.body).expect("transaction array");
        assert_eq!(values.as_array().expect("array").len(), 1);

        // Positional outspend replies keep their original cardinality.
        let response = internal_outspends_by_txid(&ctx, &duplicates);
        assert_eq!(response.status, 200);
        let values: Value = serde_json::from_slice(&response.body).expect("outspend array");
        assert_eq!(values.as_array().expect("array").len(), 2);

        let outpoints = serde_json::to_vec(&vec!["invalid", "invalid"])
            .expect("serialize outpoints");
        let response = internal_outspends_by_outpoint(&ctx, &outpoints);
        assert_eq!(response.status, 200);
        let values: Value = serde_json::from_slice(&response.body).expect("outpoints array");
        assert_eq!(values.as_array().expect("array").len(), 2);

        let oversized = serde_json::to_vec(&vec!["invalid"; MAX_BULK_ITEMS + 1])
            .expect("serialize oversized list");
        for response in [
            internal_transactions(&ctx, &oversized, true),
            internal_outspends_by_txid(&ctx, &oversized),
            internal_outspends_by_outpoint(&ctx, &oversized),
        ] {
            assert_eq!(response.status, 400);
        }
    }

    #[test]
    fn backend_serialization_stops_at_the_response_budget() {
        let response = bounded_json_array(std::iter::once(Ok("x".repeat(MAX_BACKEND_RESPONSE_BYTES))));
        assert_eq!(response.status, 503);
        assert!(response.body.len() < 128);
    }

    #[test]
    fn unselected_transactions_are_not_projected() {
        let (ctx, expected) = fixture(&[2, 3]);
        let tx = Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[0xaa; 32])), 0),
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: Script::from_bytes(vec![0x51]),
            }],
            lock_time: LockTime::from_consensus(99),
        };
        let entry = MempoolEntry::new(Arc::new(tx), 100, 1_000, 1, 0, 0);
        let cursor = entry.txid.to_string();
        ctx.mempool
            .gateway
            .pool()
            .write()
            .insert_entry(entry)
            .expect("insert unresolved-prevout fixture");
        assert_eq!(internal_mempool_txs(&ctx, None, "max_txs=1").status, 503);
        assert_eq!(page(&ctx, Some(&cursor), "max_txs=1"), vec![expected[0].1]);
        assert_eq!(page(&ctx, None, "max_txs=0"), []);
    }

    // API-09 in docs/contracts/external-api.md owns order and strict cursor
    // exclusion. Full sorting is the independent selection reference.
    #[test]
    fn batched_selection_matches_full_sort_across_flush_boundaries() {
        let entries: Vec<_> = (0_u32..257)
            .map(|index| {
                let tx = Tx {
                    lock_time: LockTime::from_consensus(index),
                    ..Tx::default()
                };
                MempoolEntry::new(Arc::new(tx), 100, 1_000, u64::from(index % 7), 0, 0)
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

    // Regression: selection borrows candidates and clones only the returned page.
    #[test]
    fn selection_borrows_payloads_and_only_the_final_page_is_cloned() {
        let entries: Vec<_> = (0_u32..129)
            .map(|index| {
                MempoolEntry::new(
                    Arc::new(Tx {
                        lock_time: LockTime::from_consensus(index),
                        ..Tx::default()
                    }),
                    100,
                    1_000,
                    u64::from(129 - index),
                    0,
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

    // Regression: a zero-sized page must not traverse the pool.
    #[test]
    fn zero_selection_does_not_poll_the_pool_iterator() {
        let entries = std::iter::from_fn(|| -> Option<&MempoolEntry> {
            panic!("zero-sized pages must not traverse entries")
        });
        assert!(select_mempool_page(entries, None, 0).is_empty());
    }
}
