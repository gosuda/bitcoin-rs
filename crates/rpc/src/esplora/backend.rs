//! Mempool-backend electrs extensions: `/internal/*` and `/block-template`.
//!
//! These are not wallet-facing. They exist so `mempool/backend` can set
//! `ESPLORA_REST_API_URL` to the `/esplora` directory on this listener.

use alloc::sync::Arc;
use core::str::FromStr as _;

use bitcoin_rs_primitives::{OutPoint, Txid};

use super::http::{bad, dispatch_error, json_response, query_limit};
use super::model::Outspend;
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
    // Ordering needs every entry, the answer needs `max_txs` of them. The pool
    // payload stays behind its `Arc` until the page is cut, so a one-transaction
    // request no longer copies the whole mempool under the read lock.
    let transactions = {
        let pool = ctx.mempool.read();
        let mut ordered = pool
            .iter_entries()
            .map(|entry| (entry.time, entry.txid, Arc::clone(&entry.tx)))
            .collect::<Vec<_>>();
        drop(pool);
        ordered.sort_unstable_by(|left, right| {
            left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1))
        });
        let start = last
            .and_then(|last| {
                ordered
                    .iter()
                    .position(|(_, txid, _)| txid.to_string() == last)
            })
            .map_or(0, |position| position.saturating_add(1));
        ordered
            .into_iter()
            .skip(start)
            .take(max_txs)
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
