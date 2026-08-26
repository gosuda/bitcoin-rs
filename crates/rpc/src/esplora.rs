//! Esplora HTTP projections over confirmed indexes and the live mempool.
#![allow(
    clippy::as_conversions,
    clippy::cast_precision_loss,
    clippy::map_unwrap_or,
    clippy::needless_borrow,
    clippy::needless_pass_by_value,
    clippy::redundant_closure_for_method_calls,
    clippy::semicolon_if_nothing_returned,
    clippy::significant_drop_in_scrutinee,
    clippy::unnecessary_semicolon
)]

mod model;
mod projection;

use alloc::sync::Arc;

use core::str::FromStr as _;

use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::{Hash as _, sha256d};
use bitcoin::hex::{DisplayHex as _, FromHex as _};
use bitcoin::merkle_tree::MerkleBlock;
use bitcoin::{Block, OutPoint, Transaction, Txid};
use bitcoin_rs_index::ScriptHash;
#[cfg(test)]
use bitcoin_rs_primitives::Hash256;
use serde_json::json;
use sonic_rs::{JsonValueTrait as _, json as sonic_json};

use crate::context::{Context, ScriptHistoryRecord, ScriptIndexRecord, TxQueryError};
use crate::handlers::Handler;
use crate::rest::Response;

use self::model::{
    AddressTransactionSummary, BlockStatus, MempoolSummary, MerkleProof, Outspend,
    RecentTransaction, ScriptSummary, TransactionValue,
};
use self::projection::{Confirmation, Projection};

const CHAIN_PAGE: usize = 25;
const MEMPOOL_PAGE: usize = 50;

/// Routes a read-only Esplora request from the node HTTP listener.
#[must_use]
pub fn route(handler: &Handler, path: &str, query: &str) -> Response {
    let ctx = handler.context();
    let projection = Projection::new(&ctx);
    let chain_view = projection.capture_chain_view();
    let parts: Vec<_> = path.trim_matches('/').split('/').collect();
    let response = match parts.as_slice() {
        ["blocks", "tip", "height"] => text(ctx.applied_height().to_string()),
        ["blocks", "tip", "hash"] => text(ctx.applied_hash().to_string_be()),
        ["internal", "mempool", "txs"] => internal_mempool_txs(&ctx, None, query),
        ["internal", "mempool", "txs", last] => internal_mempool_txs(&ctx, Some(last), query),
        ["internal", "block", hash, "txs"] => internal_block_txs(&ctx, hash),
        ["tx", id, "hex"] => tx_hex(&ctx, id),
        ["tx", id, "raw"] => tx_raw(&ctx, id),
        ["tx", id, "status"] => tx_status(&ctx, id),
        ["tx", id, "merkleblock-proof"] => tx_merkleblock_proof(&ctx, id),
        ["tx", id, "merkle-proof"] => tx_merkle_proof(&ctx, id),
        ["tx", id, "outspend", vout] => tx_outspend(&ctx, id, vout),
        ["tx", id, "outspends"] => tx_outspends(&ctx, id),
        ["tx", id] => tx(&ctx, id),
        ["block", hash, "header"] => block_header(&ctx, hash),
        ["block", hash, "status"] => block_status(&ctx, hash),
        ["block", hash, "raw"] => block_raw(&ctx, hash),
        ["block", hash, "txs"] => block_txs(&ctx, hash, 0),
        ["block", hash, "txs", start] => match start.parse::<usize>() {
            Ok(n) if n % CHAIN_PAGE == 0 => block_txs(&ctx, hash, n),
            _ => bad("transaction start index must be a multiple of 25"),
        },
        ["block", hash, "txids"] => block_txids(&ctx, hash),
        ["block", hash, "txid", index] => block_txid(&ctx, hash, index),
        ["block", hash] => block(&ctx, hash),
        ["block-height", height] => height.parse::<u32>().map_or_else(
            |_| bad("height must be an unsigned integer"),
            |height| {
                ctx.block_hash_at_height(height)
                    .map_or_else(not_found, |hash| text(hash.to_string_be()))
            },
        ),
        ["blocks"] => blocks(&ctx, None),
        ["blocks", height] => height.parse::<u32>().map_or_else(
            |_| bad("start height must be an unsigned integer"),
            |h| blocks(&ctx, Some(h)),
        ),
        ["mempool"] => mempool(&ctx),
        ["mempool", "txids"] => json_response(
            ctx.mempool
                .read()
                .iter_txids()
                .into_iter()
                .map(|id| id.to_string())
                .collect::<Vec<_>>(),
        ),
        ["mempool", "recent"] => mempool_recent(&ctx),
        ["fee-estimates"] => fee_estimates(handler),
        ["block-template"] => block_template(handler),
        ["scripthash", hash] => summary(&ctx, hash, None),
        ["address", address] => {
            address_hash(&ctx, address).map_or_else(|r| r, |h| summary_for(&ctx, h, Some(address)))
        }
        ["scripthash", hash, "utxo"] => parse_script(hash).map_or_else(|r| r, |h| utxos(&ctx, h)),
        ["address", address, "utxo"] => {
            address_hash(&ctx, address).map_or_else(|r| r, |h| utxos(&ctx, h))
        }
        ["scripthash", hash, "txs"] => {
            parse_script(hash).map_or_else(|r| r, |h| history(&ctx, h, None, true))
        }
        ["address", address, "txs"] => {
            address_hash(&ctx, address).map_or_else(|r| r, |h| history(&ctx, h, None, true))
        }
        ["scripthash", hash, "txs", "summary"] => {
            parse_script(hash).map_or_else(|r| r, |h| address_transaction_summary(&ctx, h))
        }
        ["address", address, "txs", "summary"] => {
            address_hash(&ctx, address).map_or_else(|r| r, |h| address_transaction_summary(&ctx, h))
        }
        ["scripthash", hash, "txs", "mempool"] => {
            parse_script(hash).map_or_else(|r| r, |h| history(&ctx, h, Some(""), true))
        }
        ["address", address, "txs", "mempool"] => {
            address_hash(&ctx, address).map_or_else(|r| r, |h| history(&ctx, h, Some(""), true))
        }
        ["scripthash", hash, "txs", "chain"] => {
            parse_script(hash).map_or_else(|r| r, |h| history(&ctx, h, None, false))
        }
        ["address", address, "txs", "chain"] => {
            address_hash(&ctx, address).map_or_else(|r| r, |h| history(&ctx, h, None, false))
        }
        ["scripthash", hash, "txs", "chain", last] => {
            parse_script(hash).map_or_else(|r| r, |h| history(&ctx, h, Some(last), false))
        }
        ["address", address, "txs", "chain", last] => {
            address_hash(&ctx, address).map_or_else(|r| r, |h| history(&ctx, h, Some(last), false))
        }
        ["address-prefix", _] => unavailable("address prefix search requires an address index"),
        _ => not_found(),
    };
    match projection.ensure_chain_view(chain_view.as_ref()) {
        Ok(()) => response,
        Err(response) => response,
    }
}

/// Routes Esplora raw-transaction broadcast.
#[must_use]
pub fn route_post(handler: &Handler, path: &str, body: &[u8]) -> Option<Response> {
    match path {
        "/tx" => {
            let Ok(hex) = core::str::from_utf8(body) else {
                return Some(bad("transaction body must be UTF-8 hex"));
            };
            Some(
                match handler.dispatch("sendrawtransaction", &sonic_json!([hex.trim()])) {
                    Ok(value) => match value.as_str() {
                        Some(id) => text(id.to_owned()),
                        None => json_response(value),
                    },
                    Err(error) => dispatch_error(error),
                },
            )
        }
        "/internal/txs" => Some(internal_transactions(
            handler.context().as_ref(),
            body,
            false,
        )),
        "/internal/mempool/txs" => Some(internal_transactions(
            handler.context().as_ref(),
            body,
            true,
        )),
        "/internal/txs/outspends/by-txid" => {
            Some(internal_outspends_by_txid(handler.context().as_ref(), body))
        }
        "/internal/txs/outspends/by-outpoint" => Some(internal_outspends_by_outpoint(
            handler.context().as_ref(),
            body,
        )),
        // API.md makes package relay conditional on a package-admission
        // backend. Returning 404 is preferable to pretending that sequential
        // sendrawtransaction calls are atomic package evaluation.
        "/txs/package" => Some(not_found()),
        _ => None,
    }
}

fn tx(ctx: &Context, id: &str) -> Response {
    let projection = Projection::new(ctx);
    projection.required_transaction(id).map_or_else(
        |r| r,
        |(tx, status)| {
            projection
                .transaction_value(&tx, status)
                .map_or_else(|r| r, json_response)
        },
    )
}
fn tx_hex(ctx: &Context, id: &str) -> Response {
    Projection::new(ctx)
        .required_transaction(id)
        .map_or_else(|r| r, |(tx, _)| text(serialize(&tx).to_lower_hex_string()))
}
fn tx_raw(ctx: &Context, id: &str) -> Response {
    Projection::new(ctx).required_transaction(id).map_or_else(
        |r| r,
        |(tx, _)| Response {
            status: 200,
            reason: "OK",
            content_type: "application/octet-stream",
            body: serialize(&tx),
        },
    )
}
fn tx_status(ctx: &Context, id: &str) -> Response {
    Projection::new(ctx).required_transaction(id).map_or_else(
        |r| r,
        |(_, status)| json_response(Projection::status_value(status)),
    )
}

fn tx_merkleblock_proof(ctx: &Context, id: &str) -> Response {
    confirmed_block(ctx, id).map_or_else(
        |r| r,
        |(_, block, txid)| {
            let proof =
                MerkleBlock::from_block_with_predicate(&block, |candidate| *candidate == txid);
            text(serialize(&proof).to_lower_hex_string())
        },
    )
}

fn tx_merkle_proof(ctx: &Context, id: &str) -> Response {
    confirmed_block(ctx, id).map_or_else(
        |r| r,
        |(record, block, txid)| {
            let txids = block
                .txdata
                .iter()
                .map(Transaction::compute_txid)
                .collect::<Vec<_>>();
            let Some(position) = txids.iter().position(|candidate| *candidate == txid) else {
                return internal("confirmed transaction is absent from its block");
            };
            let proof = merkle_proof(txids, position);
            json_response(MerkleProof {
                block_height: record.height,
                merkle: proof,
                pos: position,
            })
        },
    )
}

fn confirmed_block(
    ctx: &Context,
    id: &str,
) -> Result<(crate::context::BlockRecord, Block, Txid), Response> {
    let (transaction, Some(status)) = Projection::new(ctx).required_transaction(id)? else {
        return Err(not_found());
    };
    let txid = transaction.compute_txid();
    let record = ctx
        .block_by_height(status.height)
        .ok_or_else(|| unavailable("confirming block unavailable"))?;
    let bytes = ctx
        .block_body_bytes(&record)
        .ok_or_else(|| unavailable("confirming block body unavailable"))?;
    let block = deserialize(&bytes).map_err(|_| internal("stored block body is corrupt"))?;
    Ok((record, block, txid))
}

fn merkle_proof(mut level: Vec<Txid>, mut position: usize) -> Vec<String> {
    let mut proof = Vec::new();
    while level.len() > 1 {
        let sibling = if position.is_multiple_of(2) {
            level.get(position + 1).unwrap_or(&level[position])
        } else {
            &level[position - 1]
        };
        proof.push(sibling.to_string());
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let right = pair.get(1).unwrap_or(&pair[0]);
            let mut bytes = [0_u8; 64];
            bytes[..32].copy_from_slice(&pair[0].to_byte_array());
            bytes[32..].copy_from_slice(&right.to_byte_array());
            next.push(Txid::from_raw_hash(sha256d::Hash::hash(&bytes)));
        }
        level = next;
        position /= 2;
    }
    proof
}

fn tx_outspend(ctx: &Context, id: &str, vout: &str) -> Response {
    let Ok(vout) = vout.parse::<u32>() else {
        return bad("vout must be an unsigned integer");
    };
    let projection = Projection::new(ctx);
    projection.required_transaction(id).map_or_else(
        |r| r,
        |(transaction, _)| {
            let Some(_) = transaction
                .output
                .get(usize::try_from(vout).unwrap_or(usize::MAX))
            else {
                return not_found();
            };
            outspend(&projection, OutPoint::new(transaction.compute_txid(), vout))
                .map_or_else(|r| r, json_response)
        },
    )
}

fn tx_outspends(ctx: &Context, id: &str) -> Response {
    let projection = Projection::new(ctx);
    projection.required_transaction(id).map_or_else(
        |r| r,
        |(transaction, _)| {
            outspends_for_transaction(&projection, &transaction).map_or_else(|r| r, json_response)
        },
    )
}

fn outspends_for_transaction(
    projection: &Projection<'_>,
    transaction: &Transaction,
) -> Result<Vec<Outspend>, Response> {
    transaction
        .output
        .iter()
        .enumerate()
        .map(|(vout, _)| {
            let vout = u32::try_from(vout).map_err(|_| internal("output index is too large"))?;
            outspend(projection, OutPoint::new(transaction.compute_txid(), vout))
        })
        .collect()
}

fn outspend(projection: &Projection<'_>, outpoint: OutPoint) -> Result<Outspend, Response> {
    let ctx = projection.ctx;
    let pool = ctx.mempool.read();
    if let Some(spender) = pool
        .outpoint_spender(outpoint)
        .map_err(|_| internal("mempool spending index is inconsistent"))?
    {
        return Ok(Outspend {
            spent: true,
            txid: Some(spender.entry.txid.to_string()),
            vin: Some(spender.vin),
            status: Some(Projection::status_value(None)),
        });
    }
    drop(pool);

    let index = ctx
        .script_index
        .as_ref()
        .ok_or_else(|| unavailable("script index is disabled"))?;
    let Some(spender) = index.spender(outpoint).map_err(query_error)? else {
        return Ok(Outspend::unspent());
    };
    let confirmation = projection
        .confirmation_at_height(spender.height)
        .ok_or_else(|| unavailable("spending block unavailable"))?;
    Ok(Outspend {
        spent: true,
        txid: Some(spender.txid.to_string()),
        vin: Some(spender.vin),
        status: Some(Projection::status_value(Some(confirmation))),
    })
}

fn block(ctx: &Context, text_hash: &str) -> Response {
    let projection = Projection::new(ctx);
    let record = match projection.required_block_record(text_hash) {
        Ok(record) => record,
        Err(response) => return response,
    };
    projection
        .block_value(&record)
        .map_or_else(|r| r, json_response)
}
fn block_header(ctx: &Context, h: &str) -> Response {
    let record = match Projection::new(ctx).required_block_record(h) {
        Ok(record) => record,
        Err(response) => return response,
    };
    record.header_bytes().map_or_else(
        || unavailable("block header unavailable"),
        |bytes| text(bytes.to_lower_hex_string()),
    )
}
fn block_status(ctx: &Context, text_hash: &str) -> Response {
    let record = match Projection::new(ctx).required_block_record(text_hash) {
        Ok(record) => record,
        Err(response) => return response,
    };
    let in_best_chain = ctx.active_hash_at_height(record.height) == Some(record.hash);
    json_response(BlockStatus {
        in_best_chain,
        height: record.height,
        next_best: in_best_chain
            .then(|| ctx.block_hash_at_height(record.height.saturating_add(1)))
            .flatten()
            .map(|hash| hash.to_string_be()),
    })
}
fn block_raw(ctx: &Context, text_hash: &str) -> Response {
    let record = match Projection::new(ctx).required_block_record(text_hash) {
        Ok(record) => record,
        Err(response) => return response,
    };
    let Some(bytes) = ctx.block_body_bytes(&record) else {
        return unavailable("block body unavailable");
    };
    Response {
        status: 200,
        reason: "OK",
        content_type: "application/octet-stream",
        body: bytes,
    }
}
fn block_txs(ctx: &Context, h: &str, start: usize) -> Response {
    let (record, block) = match Projection::new(ctx).required_block(h) {
        Ok(value) => value,
        Err(response) => return response,
    };
    block_transaction_values(
        ctx,
        &record,
        block.txdata.iter().skip(start).take(CHAIN_PAGE),
    )
    .map_or_else(|r| r, json_response)
}

fn block_transaction_values<'a>(
    ctx: &Context,
    record: &crate::context::BlockRecord,
    transactions: impl IntoIterator<Item = &'a Transaction>,
) -> Result<Vec<TransactionValue>, Response> {
    // A record fetched by hash can be from a losing branch. Do not reuse the
    // active block at the same height for its transactions' confirmation data.
    let block_status =
        (ctx.active_hash_at_height(record.height) == Some(record.hash)).then_some(Confirmation {
            height: record.height,
            hash: record.hash,
            time: record.time,
        });
    let projection = Projection::new(ctx);
    transactions
        .into_iter()
        .map(|tx| {
            let state = match block_status {
                Some(state) => Some(state),
                None => projection.confirmation(&tx.compute_txid())?,
            };
            projection.transaction_value(tx, state)
        })
        .collect::<Result<Vec<_>, _>>()
}
fn block_txids(ctx: &Context, h: &str) -> Response {
    let (_, block) = match Projection::new(ctx).required_block(h) {
        Ok(value) => value,
        Err(response) => return response,
    };
    json_response(
        block
            .txdata
            .iter()
            .map(|tx| tx.compute_txid().to_string())
            .collect::<Vec<_>>(),
    )
}
fn block_txid(ctx: &Context, h: &str, index: &str) -> Response {
    let Ok(index) = index.parse::<usize>() else {
        return bad("transaction index must be an unsigned integer");
    };
    let (_, block) = match Projection::new(ctx).required_block(h) {
        Ok(value) => value,
        Err(response) => return response,
    };
    block
        .txdata
        .get(index)
        .map_or_else(not_found, |tx| text(tx.compute_txid().to_string()))
}
fn blocks(ctx: &Context, start_height: Option<u32>) -> Response {
    let start = start_height.unwrap_or_else(|| ctx.applied_height());
    if ctx.block_by_height(start).is_none() {
        return not_found();
    }
    let mut values = Vec::with_capacity(10);
    let projection = Projection::new(ctx);
    for height in (0..=start).rev().take(10) {
        let Some(record) = ctx.block_by_height(height) else {
            continue;
        };
        let value = match projection.block_value(&record) {
            Ok(value) => value,
            Err(response) => return response,
        };
        values.push(value);
    }
    json_response(values)
}
fn internal_block_txs(ctx: &Context, hash: &str) -> Response {
    let (record, block) = match Projection::new(ctx).required_block(hash) {
        Ok(value) => value,
        Err(response) => return response,
    };
    block_transaction_values(ctx, &record, block.txdata.iter()).map_or_else(|r| r, json_response)
}

fn internal_mempool_txs(ctx: &Context, last: Option<&str>, query: &str) -> Response {
    let max_txs = query_limit(query, "max_txs").unwrap_or(usize::MAX);
    // Ordering needs every entry, the answer needs `max_txs` of them. The pool
    // payload stays behind its `Arc` until the page is cut, so a one-transaction
    // request no longer copies the whole mempool under the read lock.
    let transactions = {
        let pool = ctx.mempool.read();
        let mut ordered = pool
            .entries
            .iter()
            .map(|(_, entry)| (entry.time, entry.txid, Arc::clone(&entry.tx)))
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
        .output
        .get(usize::try_from(vout).unwrap_or(usize::MAX))
    else {
        return Ok(Outspend::unspent());
    };
    outspend(projection, OutPoint::new(txid, vout))
}

fn query_limit(query: &str, name: &str) -> Option<usize> {
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key == name).then(|| value.parse().ok()).flatten()
    })
}

fn mempool(ctx: &Context) -> Response {
    let pool = ctx.mempool.read();
    let stats = pool.stats();
    let mut bins = std::collections::BTreeMap::new();
    for (_, entry) in &pool.entries {
        *bins.entry(entry.fee_rate).or_insert(0_u64) += u64::from(entry.vsize);
    }
    json_response(MempoolSummary {
        count: stats.txs,
        vsize: stats.bytes,
        total_fee: stats.total_fee,
        fee_histogram: bins
            .into_iter()
            .rev()
            .map(|(rate, size)| (rate as f64 / 1000.0, size))
            .collect(),
    })
}
fn mempool_recent(ctx: &Context) -> Response {
    let pool = ctx.mempool.read();
    let mut entries = pool.entries.iter().map(|(_, e)| e).collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        right
            .time
            .cmp(&left.time)
            .then_with(|| right.txid.cmp(&left.txid))
    });
    json_response(
        entries
            .into_iter()
            .take(10)
            .map(|entry| RecentTransaction {
                txid: entry.txid.to_string(),
                fee: entry.fee,
                vsize: entry.vsize,
                value: entry.tx.output.iter().fold(0_u64, |sum, output| {
                    sum.saturating_add(output.value.to_sat())
                }),
            })
            .collect::<Vec<_>>(),
    )
}
fn fee_estimates(handler: &Handler) -> Response {
    let mut values = serde_json::Map::new();
    for target in (1_u32..=25).chain([144, 504, 1008]) {
        let fee = handler
            .dispatch("estimatesmartfee", &sonic_json!([target]))
            .ok()
            .and_then(|v| v.get("feerate").and_then(sonic_rs::JsonValueTrait::as_f64))
            .map(|v| v * 100_000_000.0 / 1000.0)
            .unwrap_or(1.0);
        values.insert(target.to_string(), json!(fee));
    }
    json_response(values)
}
fn block_template(handler: &Handler) -> Response {
    handler
        .dispatch("getblocktemplate", &sonic_json!([]))
        .map_or_else(dispatch_error, json_response)
}

fn summary(ctx: &Context, text: &str, address: Option<&str>) -> Response {
    parse_script(text).map_or_else(|r| r, |h| summary_for(ctx, h, address))
}
fn summary_for(ctx: &Context, h: ScriptHash, address: Option<&str>) -> Response {
    let projection = Projection::new(ctx);
    let activity = match projection.script_activity(h) {
        Ok(activity) => activity,
        Err(response) => return response,
    };
    let chain_stats = activity.chain_stats();
    json_response(ScriptSummary {
        address: address.map(str::to_owned),
        scripthash: address
            .is_none()
            .then(|| h.to_byte_array().to_lower_hex_string()),
        chain_stats,
        mempool_stats: activity.mempool_stats(h),
    })
}
fn utxos(ctx: &Context, h: ScriptHash) -> Response {
    Projection::new(ctx)
        .script_utxos(h)
        .map_or_else(|response| response, json_response)
}
fn history(ctx: &Context, h: ScriptHash, last: Option<&str>, include_mempool: bool) -> Response {
    let projection = Projection::new(ctx);
    let activity = match projection.script_activity(h) {
        Ok(activity) => activity,
        Err(response) => return response,
    };
    if last == Some("") {
        return activity
            .mempool
            .into_iter()
            .take(MEMPOOL_PAGE)
            .map(|t| projection.transaction_value(&t, None))
            .collect::<Result<Vec<_>, _>>()
            .map_or_else(|r| r, json_response);
    };
    let start = last.and_then(|x| {
        activity
            .confirmed
            .iter()
            .position(|entry| entry.record.txid.to_string() == x)
            .map(|n| n + 1)
    });
    if last.is_some() && start.is_none() {
        return not_found();
    }
    let out = if include_mempool {
        activity
            .mempool
            .iter()
            .take(MEMPOOL_PAGE)
            .map(|t| projection.transaction_value(t, None))
            .collect::<Result<Vec<_>, _>>()
    } else {
        Ok(Vec::new())
    };
    let mut out = match out {
        Ok(out) => out,
        Err(r) => return r,
    };
    let chain = match activity
        .confirmed
        .into_iter()
        .skip(start.unwrap_or(0))
        .take(CHAIN_PAGE)
        .map(|entry| {
            projection
                .confirmed_transaction(&entry.record.txid)
                .and_then(|transaction| {
                    projection.transaction_value(&transaction, Some(entry.confirmation))
                })
        })
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(chain) => chain,
        Err(r) => return r,
    };
    out.extend(chain);
    json_response(out)
}

fn address_transaction_summary(ctx: &Context, h: ScriptHash) -> Response {
    let activity = match Projection::new(ctx).script_activity(h) {
        Ok(activity) => activity,
        Err(response) => return response,
    };
    let mut funded = std::collections::BTreeMap::<bitcoin::Txid, u64>::new();
    for row in &activity.confirmed_funding {
        let total = funded.entry(row.txid).or_default();
        *total = total.saturating_add(row.value);
    }
    json_response(
        activity
            .confirmed
            .into_iter()
            .map(|entry| AddressTransactionSummary {
                txid: entry.record.txid.to_string(),
                value: funded.get(&entry.record.txid).copied().unwrap_or_default(),
                height: entry.confirmation.height,
                time: entry.confirmation.time,
            })
            .collect::<Vec<_>>(),
    )
}
fn address_hash(ctx: &Context, a: &str) -> Result<ScriptHash, Response> {
    let n = Projection::new(ctx).bitcoin_network();
    let a = bitcoin::Address::from_str(a)
        .map_err(|_| bad("invalid address"))?
        .require_network(n)
        .map_err(|_| bad("address network does not match node"))?;
    Ok(ScriptHash::from_script_bytes(a.script_pubkey().as_bytes()))
}
fn parse_script(s: &str) -> Result<ScriptHash, Response> {
    Ok(ScriptHash::from_byte_array(
        <[u8; 32]>::from_hex(s).map_err(|_| bad("scripthash must be 64 hex characters"))?,
    ))
}
fn query_error(e: TxQueryError) -> Response {
    match e {
        TxQueryError::Retry | TxQueryError::Unavailable(_) => unavailable(&e.to_string()),
        TxQueryError::Storage(_) => internal(&e.to_string()),
    }
}
fn dispatch_error(e: crate::RpcError) -> Response {
    match e {
        crate::RpcError::NotFound(_) => not_found(),
        crate::RpcError::InvalidParams(_) | crate::RpcError::InvalidType(_) => bad(&e.to_string()),
        _ => unavailable(&e.to_string()),
    }
}
fn json_response(v: impl serde::Serialize) -> Response {
    sonic_rs::to_string(&v).map_or_else(
        |_| internal("failed to serialize response"),
        |b| Response {
            status: 200,
            reason: "OK",
            content_type: "application/json",
            body: b.into_bytes(),
        },
    )
}
fn text(b: String) -> Response {
    Response {
        status: 200,
        reason: "OK",
        content_type: "text/plain",
        body: b.into_bytes(),
    }
}
fn bad(m: &str) -> Response {
    Response {
        status: 400,
        reason: "Bad Request",
        content_type: "text/plain",
        body: m.as_bytes().to_vec(),
    }
}
fn not_found() -> Response {
    Response {
        status: 404,
        reason: "Not Found",
        content_type: "text/plain",
        body: b"not found".to_vec(),
    }
}
fn unavailable(m: &str) -> Response {
    Response {
        status: 503,
        reason: "Service Unavailable",
        content_type: "text/plain",
        body: m.as_bytes().to_vec(),
    }
}
fn internal(m: &str) -> Response {
    Response {
        status: 500,
        reason: "Internal Server Error",
        content_type: "text/plain",
        body: m.as_bytes().to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};

    use bitcoin::{
        Amount, Block, BlockHash, CompactTarget, ScriptBuf, TxIn, TxMerkleNode, TxOut, Witness,
        absolute, block::Version, hashes::Hash as _, transaction,
    };
    use bitcoin_rs_chain::NodeStatus;
    use bitcoin_rs_mempool::MempoolEntry;
    use bitcoin_rs_mining::{Candidate, TemplateId};
    use bitcoin_rs_utxo::{BlockChanges, UtxoAdd, UtxoError};
    use serde_json::Value;

    use crate::context::{
        BlockTemplate, BlockTemplateRequest, BlockTemplateResult, BlockValidationResult,
        LastCandidateInfo, MiningCapability, MiningControl, MiningControlError, MiningInfo,
        MiningRule, TemplateMutation,
    };

    use super::*;

    struct SingleBlockSource {
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
        body: Vec<u8>,
    }

    impl crate::context::BlockBodySource for SingleBlockSource {
        fn block_body(&self, height: u32, hash: bitcoin_rs_primitives::Hash256) -> Option<Vec<u8>> {
            (height == self.height && hash == self.hash).then(|| self.body.clone())
        }
    }

    fn transaction(input: Option<OutPoint>, output: TxOut) -> Transaction {
        Transaction {
            version: transaction::Version(2),
            lock_time: absolute::LockTime::ZERO,
            input: input
                .into_iter()
                .map(|previous_output| TxIn {
                    previous_output,
                    script_sig: ScriptBuf::new(),
                    sequence: bitcoin::Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            output: vec![output],
        }
    }

    struct StaticTxIndex {
        transaction: Transaction,
        height: Option<u32>,
    }

    impl StaticTxIndex {
        fn new(transaction: Transaction) -> Self {
            Self {
                transaction,
                height: None,
            }
        }
    }

    impl crate::context::TxIndexQuery for StaticTxIndex {
        fn transaction(&self, txid: &Txid) -> Result<Option<Transaction>, TxQueryError> {
            Ok((self.transaction.compute_txid() == *txid).then(|| self.transaction.clone()))
        }

        fn outpoint_value(&self, outpoint: &OutPoint) -> Result<Option<u64>, TxQueryError> {
            Ok((self.transaction.compute_txid() == outpoint.txid)
                .then(|| {
                    self.transaction
                        .output
                        .get(usize::try_from(outpoint.vout).unwrap_or(usize::MAX))
                })
                .flatten()
                .map(|output| output.value.to_sat()))
        }

        fn transaction_height(&self, txid: &Txid) -> Result<Option<u32>, TxQueryError> {
            Ok((self.transaction.compute_txid() == *txid)
                .then_some(self.height)
                .flatten())
        }

        fn index_info(&self) -> Result<crate::context::TxIndexInfo, TxQueryError> {
            Ok(crate::context::TxIndexInfo {
                synced: true,
                best_block_height: 0,
            })
        }
    }

    struct CountingTxIndex {
        transactions: Vec<Transaction>,
        calls: Arc<AtomicUsize>,
    }

    impl crate::context::TxIndexQuery for CountingTxIndex {
        fn transaction(&self, txid: &Txid) -> Result<Option<Transaction>, TxQueryError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(self
                .transactions
                .iter()
                .find(|transaction| transaction.compute_txid() == *txid)
                .cloned())
        }

        fn outpoint_value(&self, _outpoint: &OutPoint) -> Result<Option<u64>, TxQueryError> {
            Ok(None)
        }

        fn index_info(&self) -> Result<crate::context::TxIndexInfo, TxQueryError> {
            Ok(crate::context::TxIndexInfo {
                synced: true,
                best_block_height: 0,
            })
        }
    }

    struct FixtureTxIndex(Vec<(Transaction, u32)>);

    impl crate::context::TxIndexQuery for FixtureTxIndex {
        fn transaction(&self, txid: &Txid) -> Result<Option<Transaction>, TxQueryError> {
            Ok(self
                .0
                .iter()
                .find(|(transaction, _)| transaction.compute_txid() == *txid)
                .map(|(transaction, _)| transaction.clone()))
        }

        fn outpoint_value(&self, outpoint: &OutPoint) -> Result<Option<u64>, TxQueryError> {
            Ok(self
                .0
                .iter()
                .find(|(transaction, _)| transaction.compute_txid() == outpoint.txid)
                .and_then(|(transaction, _)| {
                    transaction
                        .output
                        .get(usize::try_from(outpoint.vout).unwrap_or(usize::MAX))
                })
                .map(|output| output.value.to_sat()))
        }

        fn transaction_height(&self, txid: &Txid) -> Result<Option<u32>, TxQueryError> {
            Ok(self
                .0
                .iter()
                .find(|(transaction, _)| transaction.compute_txid() == *txid)
                .map(|(_, height)| *height))
        }

        fn index_info(&self) -> Result<crate::context::TxIndexInfo, TxQueryError> {
            Ok(crate::context::TxIndexInfo {
                synced: true,
                best_block_height: self.0.iter().map(|(_, height)| *height).max().unwrap_or(0),
            })
        }
    }

    struct StaticScriptIndex {
        history: Vec<ScriptHistoryRecord>,
        funding: Vec<ScriptIndexRecord>,
        unspent: Vec<ScriptIndexRecord>,
    }

    struct CountingScriptIndex {
        history_calls: Arc<AtomicUsize>,
        unspent_calls: Arc<AtomicUsize>,
        spender_calls: Arc<AtomicUsize>,
    }

    impl crate::context::ScriptIndexQuery for CountingScriptIndex {
        fn unspent_outputs(
            &self,
            _script_hash: ScriptHash,
        ) -> Result<Vec<ScriptIndexRecord>, TxQueryError> {
            self.unspent_calls.fetch_add(1, Ordering::Relaxed);
            Ok(Vec::new())
        }

        fn history_snapshot(
            &self,
            _script_hash: ScriptHash,
        ) -> Result<crate::context::ScriptIndexSnapshot, TxQueryError> {
            self.history_calls.fetch_add(1, Ordering::Relaxed);
            Ok(crate::context::ScriptIndexSnapshot::default())
        }

        fn spender(
            &self,
            _outpoint: OutPoint,
        ) -> Result<Option<crate::context::SpendingRecord>, TxQueryError> {
            self.spender_calls.fetch_add(1, Ordering::Relaxed);
            Ok(None)
        }
    }

    struct RepublishTipScriptIndex {
        applied_tip: Arc<arc_swap::ArcSwapOption<bitcoin_rs_chain::TipSnapshot>>,
    }

    impl crate::context::ScriptIndexQuery for RepublishTipScriptIndex {
        fn unspent_outputs(
            &self,
            _script_hash: ScriptHash,
        ) -> Result<Vec<ScriptIndexRecord>, TxQueryError> {
            Ok(Vec::new())
        }

        fn history_snapshot(
            &self,
            _script_hash: ScriptHash,
        ) -> Result<crate::context::ScriptIndexSnapshot, TxQueryError> {
            if let Some(tip) = self.applied_tip.load_full() {
                self.applied_tip.store(Some(Arc::new((*tip).clone())));
            }
            Ok(crate::context::ScriptIndexSnapshot::default())
        }

        fn spender(
            &self,
            _outpoint: OutPoint,
        ) -> Result<Option<crate::context::SpendingRecord>, TxQueryError> {
            Ok(None)
        }
    }

    impl crate::context::ScriptIndexQuery for StaticScriptIndex {
        fn unspent_outputs(
            &self,
            _script_hash: ScriptHash,
        ) -> Result<Vec<ScriptIndexRecord>, TxQueryError> {
            Ok(self.unspent.clone())
        }

        fn history_snapshot(
            &self,
            _script_hash: ScriptHash,
        ) -> Result<crate::context::ScriptIndexSnapshot, TxQueryError> {
            Ok(crate::context::ScriptIndexSnapshot {
                history: self.history.clone(),
                funding: self.funding.clone(),
            })
        }

        fn spender(
            &self,
            _outpoint: OutPoint,
        ) -> Result<Option<crate::context::SpendingRecord>, TxQueryError> {
            Ok(None)
        }
    }

    /// Commits one confirmed unspent output into the authoritative UTXO set so
    /// mempool admission resolves a real prevout instead of rejecting a
    /// spender for missing inputs.
    fn commit_unspent(
        ctx: &Context,
        txid: &Txid,
        vout: u32,
        output: &TxOut,
        height: u32,
    ) -> Result<(), UtxoError> {
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(
            bitcoin_rs_primitives::OutPoint::new(
                Hash256::from_le_bytes(txid.as_byte_array()),
                vout,
            ),
            bitcoin_rs_primitives::TxOut {
                value: output.value,
                script_pubkey: output.script_pubkey.clone(),
            },
            false,
            height,
        ));
        ctx.utxo
            .commit_block(&changes, &Hash256::from_le_bytes(&[9_u8; 32]))
    }

    /// Deterministic local [`MiningControl`] fixture.
    ///
    /// Serves one fixed semantic candidate, a coherent mining-info snapshot,
    /// and an accepting submit result. The template carries no mandatory
    /// rules, so the unparametrized `/block-template` request needs no caller
    /// capability negotiation to project it.
    struct FixtureMiningControl;

    impl FixtureMiningControl {
        fn template() -> BlockTemplate {
            let previous = Hash256::from_le_bytes(&[0x11; 32]);
            BlockTemplate {
                candidate: Arc::new(Candidate {
                    template_id: TemplateId::new(&previous, 9),
                    previous_block_hash: previous,
                    height: 101,
                    version: 0x2000_0000,
                    bits: 0x207f_ffff,
                    min_time: 1_700_000_001,
                    current_time: 1_700_000_010,
                    max_weight: 4_000_000,
                    max_size: 4_000_000,
                    max_sigops: 80_000,
                    mempool_sequence: 9,
                    coinbase: Transaction {
                        version: transaction::Version(2),
                        lock_time: absolute::LockTime::ZERO,
                        input: Vec::new(),
                        output: Vec::new(),
                    },
                    coinbase_value: 5_000_000_000,
                    fees: 0,
                    weight: 1_000,
                    size: 250,
                    sigop_cost: 0,
                    transactions: Vec::new(),
                    witness_merkle_root: None,
                    witness_reserved_value: None,
                    witness_commitment: None,
                }),
                rules: vec![MiningRule::new("csv")],
                version_bits_available: Vec::new(),
                version_bits_required: 0,
                capabilities: vec![MiningCapability::new("proposal")],
                mutable: vec![TemplateMutation::Time, TemplateMutation::Transactions],
                submit_old: None,
                work_id: None,
            }
        }
    }

    impl MiningControl for FixtureMiningControl {
        fn get_block_template(
            &self,
            _request: BlockTemplateRequest,
        ) -> Result<BlockTemplateResult, MiningControlError> {
            Ok(BlockTemplateResult::Template(Self::template()))
        }

        fn mining_info(&self) -> Result<MiningInfo, MiningControlError> {
            Ok(MiningInfo {
                blocks: 100,
                last_candidate: Some(LastCandidateInfo {
                    weight: 1_000,
                    transactions: 1,
                }),
                difficulty: 1.0,
                network_hashes_per_second: 0.0,
                pooled_transactions: 0,
                network: bitcoin_rs_primitives::Network::Regtest,
                next_bits: 0x207f_ffff,
                next_difficulty: 1.0,
                minimum_fee_rate: 1_000,
                signet: None,
                warnings: Vec::new(),
            })
        }

        fn submit_block(&self, _block: Block) -> Result<BlockValidationResult, MiningControlError> {
            Ok(BlockValidationResult::Accepted)
        }

        fn publish_generation(&self) {}
    }

    fn contract_fixture()
    -> Result<(Handler, Transaction, Block, String), Box<dyn std::error::Error>> {
        let target = ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([2; 20]));
        let address =
            bitcoin::Address::from_script(&target, bitcoin::Network::Regtest)?.to_string();
        let mut transaction = transaction(
            None,
            TxOut {
                value: Amount::from_sat(5_000_000_000),
                script_pubkey: target,
            },
        );
        transaction.output.push(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        });
        transaction.input.push(TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![1, 1]),
            sequence: bitcoin::Sequence::MAX,
            witness: Witness::new(),
        });
        let mut block = Block {
            header: bitcoin::block::Header {
                version: Version::ONE,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 1_700_000_000,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 1,
            },
            txdata: vec![transaction.clone()],
        };
        block.header.merkle_root = block
            .compute_merkle_root()
            .ok_or_else(|| std::io::Error::other("fixture merkle root missing"))?;
        let record = crate::context::BlockRecord::from_block(0, &block);
        let txid = transaction.compute_txid();
        let mut context = Context::new();
        context.chain_network = bitcoin_rs_primitives::Network::Regtest;
        context.block_body_source = Some(Arc::new(SingleBlockSource {
            height: 0,
            hash: record.hash,
            body: serialize(&block),
        }));
        context.add_block(record);
        let tip = {
            let mut tree = context.block_tree.write();
            tree.insert_node(None, block.header, NodeStatus::Active)?;
            tree.tip()
                .ok_or_else(|| std::io::Error::other("fixture tip missing"))?
                .as_ref()
                .clone()
        };
        context.set_applied_tip(tip);
        context.esplora_tx_index = Some(Arc::new(FixtureTxIndex(vec![(transaction.clone(), 0)])));
        let funding = vec![ScriptIndexRecord {
            txid,
            height: 0,
            value: 5_000_000_000,
            vout: 0,
        }];
        context.script_index = Some(Arc::new(StaticScriptIndex {
            history: vec![ScriptHistoryRecord { txid, height: 0 }],
            funding: funding.clone(),
            unspent: funding,
        }));
        // Output zero drives the address routes. Output one is a portable
        // consensus-valid OP_TRUE coin for the broadcast route.
        commit_unspent(&context, &txid, 0, &transaction.output[0], 0)?;
        commit_unspent(&context, &txid, 1, &transaction.output[1], 0)?;
        let context = context.with_mining_control(Arc::new(FixtureMiningControl));
        Ok((Handler::new(Arc::new(context)), transaction, block, address))
    }

    #[test]
    fn tip_routes_remain_available_without_script_index() {
        let handler = Handler::new(Arc::new(Context::new()));
        assert_eq!(route(&handler, "/blocks/tip/height", "").status, 200);
        assert_eq!(
            route(
                &handler,
                "/scripthash/0000000000000000000000000000000000000000000000000000000000000000/utxo",
                ""
            )
            .status,
            503
        );
    }

    #[test]
    #[allow(clippy::expect_used, clippy::too_many_lines)]
    fn bitcoin_esplora_surface_matches_documented_routes_and_content_types()
    -> Result<(), Box<dyn std::error::Error>> {
        let (handler, confirmed_tx, block, address) = contract_fixture()?;
        let txid = confirmed_tx.compute_txid().to_string();
        let block_hash = block.block_hash().to_string();
        let script_hash = ScriptHash::new(&confirmed_tx.output[0].script_pubkey)
            .to_byte_array()
            .to_lower_hex_string();
        let routes = [
            (format!("/tx/{txid}"), 200, "application/json"),
            (format!("/tx/{txid}/status"), 200, "application/json"),
            (format!("/tx/{txid}/hex"), 200, "text/plain"),
            (format!("/tx/{txid}/raw"), 200, "application/octet-stream"),
            (format!("/tx/{txid}/merkleblock-proof"), 200, "text/plain"),
            (format!("/tx/{txid}/merkle-proof"), 200, "application/json"),
            (format!("/tx/{txid}/outspend/0"), 200, "application/json"),
            (format!("/tx/{txid}/outspends"), 200, "application/json"),
            (format!("/address/{address}"), 200, "application/json"),
            (format!("/address/{address}/txs"), 200, "application/json"),
            (
                format!("/address/{address}/txs/chain"),
                200,
                "application/json",
            ),
            (
                format!("/address/{address}/txs/chain/{txid}"),
                200,
                "application/json",
            ),
            (
                format!("/address/{address}/txs/mempool"),
                200,
                "application/json",
            ),
            (format!("/address/{address}/utxo"), 200, "application/json"),
            (
                format!("/scripthash/{script_hash}"),
                200,
                "application/json",
            ),
            (
                format!("/scripthash/{script_hash}/txs"),
                200,
                "application/json",
            ),
            (
                format!("/scripthash/{script_hash}/txs/chain"),
                200,
                "application/json",
            ),
            (
                format!("/scripthash/{script_hash}/txs/chain/{txid}"),
                200,
                "application/json",
            ),
            (
                format!("/scripthash/{script_hash}/txs/mempool"),
                200,
                "application/json",
            ),
            (
                format!("/scripthash/{script_hash}/utxo"),
                200,
                "application/json",
            ),
            (format!("/block/{block_hash}"), 200, "application/json"),
            (format!("/block/{block_hash}/header"), 200, "text/plain"),
            (
                format!("/block/{block_hash}/status"),
                200,
                "application/json",
            ),
            (format!("/block/{block_hash}/txs"), 200, "application/json"),
            (
                format!("/block/{block_hash}/txs/0"),
                200,
                "application/json",
            ),
            (
                format!("/block/{block_hash}/txids"),
                200,
                "application/json",
            ),
            (format!("/block/{block_hash}/txid/0"), 200, "text/plain"),
            (
                format!("/block/{block_hash}/raw"),
                200,
                "application/octet-stream",
            ),
            ("/block-height/0".to_owned(), 200, "text/plain"),
            ("/blocks".to_owned(), 200, "application/json"),
            ("/blocks/0".to_owned(), 200, "application/json"),
            ("/blocks/tip/height".to_owned(), 200, "text/plain"),
            ("/blocks/tip/hash".to_owned(), 200, "text/plain"),
            ("/mempool".to_owned(), 200, "application/json"),
            ("/mempool/txids".to_owned(), 200, "application/json"),
            ("/mempool/recent".to_owned(), 200, "application/json"),
            ("/fee-estimates".to_owned(), 200, "application/json"),
            ("/block-template".to_owned(), 200, "application/json"),
            ("/address-prefix/bcrt1".to_owned(), 503, "text/plain"),
        ];
        for (path, expected_status, expected_content_type) in routes {
            let response = route(&handler, &path, "");
            assert_eq!(response.status, expected_status, "status for {path}");
            assert_eq!(
                response.content_type, expected_content_type,
                "content type for {path}"
            );
        }

        // Broadcast must clear real admission: spend the fixture's confirmed
        // unspent output — also committed to the UTXO set — rather than
        // replaying the coinbase-shaped null-input fixture transaction.
        let spend = transaction(
            Some(OutPoint {
                txid: confirmed_tx.compute_txid(),
                vout: 1,
            }),
            TxOut {
                value: Amount::from_sat(90_000),
                script_pubkey: confirmed_tx.output[0].script_pubkey.clone(),
            },
        );
        let raw = serialize(&spend).to_lower_hex_string();
        let broadcast = route_post(&handler, "/tx", raw.as_bytes()).expect("POST /tx is routed");
        assert_eq!(
            broadcast.status,
            200,
            "{}",
            String::from_utf8_lossy(&broadcast.body)
        );
        assert_eq!(broadcast.content_type, "text/plain");

        // Package relay is conditional in API.md (Bitcoin Core 28+). This node
        // has no atomic package-admission capability, so it must not advertise
        // sequential sendrawtransaction calls as that endpoint.
        let package = route_post(&handler, "/txs/package", b"[]")
            .expect("package path must not fall through to JSON-RPC");
        assert_eq!(package.status, 404);
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn bitcoin_esplora_representations_match_the_documented_schemas()
    -> Result<(), Box<dyn std::error::Error>> {
        fn keys(value: &Value) -> std::collections::BTreeSet<&str> {
            value
                .as_object()
                .map(|object| object.keys().map(String::as_str).collect())
                .unwrap_or_default()
        }

        let (handler, transaction, block, address) = contract_fixture()?;
        let txid = transaction.compute_txid().to_string();
        let block_hash = block.block_hash().to_string();
        let transaction_value: Value =
            serde_json::from_slice(&route(&handler, &format!("/tx/{txid}"), "").body)?;
        assert_eq!(
            keys(&transaction_value),
            [
                "fee", "locktime", "size", "status", "txid", "version", "vin", "vout", "weight",
            ]
            .into_iter()
            .collect()
        );
        assert_eq!(
            keys(&transaction_value["vin"][0]),
            [
                "is_coinbase",
                "prevout",
                "scriptsig",
                "scriptsig_asm",
                "sequence",
                "txid",
                "vout",
            ]
            .into_iter()
            .collect()
        );
        assert_eq!(
            transaction_value["vin"][0]["txid"],
            json!(Txid::all_zeros().to_string())
        );
        assert_eq!(transaction_value["vin"][0]["vout"], json!(u32::MAX));
        assert!(transaction_value["vin"][0]["prevout"].is_null());
        assert_eq!(transaction_value["fee"], json!(0));
        assert_eq!(
            keys(&transaction_value["vout"][0]),
            [
                "scriptpubkey",
                "scriptpubkey_address",
                "scriptpubkey_asm",
                "scriptpubkey_type",
                "value",
            ]
            .into_iter()
            .collect()
        );
        assert_eq!(
            keys(&transaction_value["status"]),
            ["block_hash", "block_height", "block_time", "confirmed"]
                .into_iter()
                .collect()
        );

        let block_value: Value =
            serde_json::from_slice(&route(&handler, &format!("/block/{block_hash}"), "").body)?;
        assert_eq!(
            keys(&block_value),
            [
                "bits",
                "difficulty",
                "height",
                "id",
                "mediantime",
                "merkle_root",
                "nonce",
                "previousblockhash",
                "size",
                "timestamp",
                "tx_count",
                "version",
                "weight",
            ]
            .into_iter()
            .collect()
        );
        assert!(block_value["previousblockhash"].is_null());

        let summary: Value =
            serde_json::from_slice(&route(&handler, &format!("/address/{address}"), "").body)?;
        assert_eq!(
            keys(&summary),
            ["address", "chain_stats", "mempool_stats"]
                .into_iter()
                .collect()
        );
        let stat_keys = [
            "funded_txo_count",
            "funded_txo_sum",
            "spent_txo_count",
            "spent_txo_sum",
            "tx_count",
        ]
        .into_iter()
        .collect();
        assert_eq!(keys(&summary["chain_stats"]), stat_keys);
        assert_eq!(summary["chain_stats"]["funded_txo_count"], json!(1));
        assert_eq!(summary["chain_stats"]["spent_txo_count"], json!(0));

        let utxos: Value =
            serde_json::from_slice(&route(&handler, &format!("/address/{address}/utxo"), "").body)?;
        assert_eq!(utxos[0]["status"]["confirmed"], json!(true));
        assert_eq!(utxos[0]["status"]["block_height"], json!(0));

        let outspend: Value =
            serde_json::from_slice(&route(&handler, &format!("/tx/{txid}/outspend/0"), "").body)?;
        assert_eq!(outspend, json!({"spent":false}));

        let mempool: Value = serde_json::from_slice(&route(&handler, "/mempool", "").body)?;
        assert_eq!(
            keys(&mempool),
            ["count", "fee_histogram", "total_fee", "vsize"]
                .into_iter()
                .collect()
        );
        Ok(())
    }

    #[test]
    fn bitcoin_esplora_errors_distinguish_bad_missing_and_unavailable() {
        let handler = Handler::new(Arc::new(Context::new()));
        assert_eq!(route(&handler, "/tx/not-a-txid", "").status, 400);
        assert_eq!(route(&handler, "/block/not-a-hash", "").status, 400);
        assert_eq!(
            route(&handler, "/block-height/not-a-height", "").status,
            400
        );
        assert_eq!(
            route(
                &handler,
                "/block/0000000000000000000000000000000000000000000000000000000000000000",
                ""
            )
            .status,
            404
        );
        assert_eq!(
            route(
                &handler,
                "/tx/0000000000000000000000000000000000000000000000000000000000000000",
                ""
            )
            .status,
            503
        );
        assert_eq!(
            route(
                &handler,
                "/block/0000000000000000000000000000000000000000000000000000000000000000/txs/1",
                ""
            )
            .status,
            400
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn composed_response_retries_when_the_applied_tip_identity_changes() {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let mut context = Context::new();
        context.add_block(crate::context::BlockRecord::from_block(0, &block));
        let tip = {
            let mut tree = context.block_tree.write();
            tree.insert_node(None, block.header, NodeStatus::Active)
                .expect("insert applied tip");
            tree.tip().expect("applied tip")
        };
        context.applied_tip.store(Some(tip));
        context.script_index = Some(Arc::new(RepublishTipScriptIndex {
            applied_tip: Arc::clone(&context.applied_tip),
        }));
        let handler = Handler::new(Arc::new(context));

        let response = route(
            &handler,
            "/scripthash/0000000000000000000000000000000000000000000000000000000000000000",
            "",
        );
        assert_eq!(response.status, 503);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn internal_mempool_routes_return_live_transactions() {
        let transaction = transaction(
            None,
            TxOut {
                value: Amount::from_sat(125),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            },
        );
        let txid = transaction.compute_txid();
        let ctx = Arc::new(Context::new());
        ctx.mempool
            .write()
            .insert_entry(MempoolEntry::new(Arc::new(transaction), 100, 1_000, 0, 0))
            .expect("mempool entry accepted");
        let handler = Handler::new(Arc::clone(&ctx));
        let body = serde_json::to_vec(&vec![txid.to_string()]).expect("txids serialize");

        let post = route_post(&handler, "/internal/mempool/txs", &body)
            .expect("internal route is handled");
        assert_eq!(post.status, 200);
        let paged = route(&handler, "/internal/mempool/txs", "max_txs=1");
        assert_eq!(paged.status, 200);
        let values: Value = serde_json::from_slice(&paged.body).expect("mempool response json");
        assert_eq!(values[0]["txid"], json!(txid.to_string()));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn mempool_backend_extension_surface_uses_the_same_projections()
    -> Result<(), Box<dyn std::error::Error>> {
        let (handler, transaction, block, address) = contract_fixture()?;
        let txid = transaction.compute_txid().to_string();
        let ids = serde_json::to_vec(&vec![txid.clone()])?;
        let outpoints = serde_json::to_vec(&vec![format!("{txid}:0")])?;

        for (path, body) in [
            ("/internal/txs", ids.as_slice()),
            ("/internal/mempool/txs", ids.as_slice()),
            ("/internal/txs/outspends/by-txid", ids.as_slice()),
            ("/internal/txs/outspends/by-outpoint", outpoints.as_slice()),
        ] {
            let response = route_post(&handler, path, body).expect("internal POST route exists");
            assert_eq!(response.status, 200, "status for {path}");
            assert_eq!(response.content_type, "application/json");
        }

        let block_response = route(
            &handler,
            &format!("/internal/block/{}/txs", block.block_hash()),
            "",
        );
        assert_eq!(block_response.status, 200);
        let summary = route(&handler, &format!("/address/{address}/txs/summary"), "");
        assert_eq!(summary.status, 200);
        Ok(())
    }

    #[test]
    fn package_broadcast_is_not_exposed_without_package_admission() {
        let handler = Handler::new(Arc::new(Context::new()));
        assert_eq!(
            route_post(&handler, "/txs/package", b"[]").map(|response| response.status),
            Some(404)
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn broadcast_transaction_is_immediately_visible_as_unconfirmed() {
        let target = ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([2; 20]));
        let funding = transaction(
            None,
            TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            },
        );
        let spend = transaction(
            Some(OutPoint {
                txid: funding.compute_txid(),
                vout: 0,
            }),
            TxOut {
                value: Amount::from_sat(30_000),
                script_pubkey: target,
            },
        );
        let txid = spend.compute_txid();
        let context = Context::new();
        // Admission resolves the prevout from the authoritative UTXO set: the
        // funding output is committed as a confirmed height-0 coin, so the
        // spend is a genuinely funded transaction. The funding transaction is
        // staged in the broadcast cache the way an earlier accepted
        // submission would be, so the follow-up GET can render the prevout.
        commit_unspent(&context, &funding.compute_txid(), 0, &funding.output[0], 0)
            .expect("fixture utxo commit succeeds");
        context.add_transaction(funding.clone());
        let handler = Handler::new(Arc::new(context));
        let raw = serialize(&spend).to_lower_hex_string();
        let broadcast = route_post(&handler, "/tx", raw.as_bytes()).expect("broadcast route");
        assert_eq!(
            broadcast.status,
            200,
            "{}",
            String::from_utf8_lossy(&broadcast.body)
        );
        assert_eq!(
            String::from_utf8(broadcast.body).expect("txid body is UTF-8"),
            txid.to_string()
        );

        let response = route(&handler, &format!("/tx/{txid}"), "");
        assert_eq!(response.status, 200);
        let value: Value = serde_json::from_slice(&response.body).expect("transaction json");
        assert_eq!(value["status"], json!({"confirmed":false}));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn history_hydrates_only_the_requested_chain_page() {
        let target = ScriptBuf::from_bytes(vec![0x51]);
        let transactions = (1_u64..=30)
            .map(|value| {
                transaction(
                    None,
                    TxOut {
                        value: Amount::from_sat(value),
                        script_pubkey: target.clone(),
                    },
                )
            })
            .collect::<Vec<_>>();
        let records = transactions
            .iter()
            .enumerate()
            .map(|(index, transaction)| ScriptHistoryRecord {
                txid: transaction.compute_txid(),
                height: u32::try_from(index + 1).expect("fixture height fits u32"),
            })
            .collect::<Vec<_>>();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut ctx = Context::new();
        for record in &records {
            ctx.add_block(crate::context::BlockRecord::synthetic(
                record.height,
                Hash256::from_le_bytes(&[0; 32]),
            ));
        }
        ctx.script_index = Some(Arc::new(StaticScriptIndex {
            history: records,
            funding: Vec::new(),
            unspent: Vec::new(),
        }));
        ctx.esplora_tx_index = Some(Arc::new(CountingTxIndex {
            transactions,
            calls: Arc::clone(&calls),
        }));

        let response = history(&ctx, ScriptHash::new(&target), None, false);
        assert_eq!(response.status, 200);
        let values: Value = serde_json::from_slice(&response.body).expect("history response json");
        assert_eq!(values.as_array().map(Vec::len), Some(CHAIN_PAGE));
        assert_eq!(calls.load(Ordering::Relaxed), CHAIN_PAGE);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn address_statistics_read_no_transactions_beyond_the_script_index() {
        let target = ScriptBuf::from_bytes(vec![0x51]);
        let script_hash = ScriptHash::new(&target);
        let transactions = (1_u64..=30)
            .map(|value| {
                transaction(
                    None,
                    TxOut {
                        value: Amount::from_sat(value),
                        script_pubkey: target.clone(),
                    },
                )
            })
            .collect::<Vec<_>>();
        let history = transactions
            .iter()
            .enumerate()
            .map(|(index, transaction)| ScriptHistoryRecord {
                txid: transaction.compute_txid(),
                height: u32::try_from(index + 1).expect("fixture height fits u32"),
            })
            .collect::<Vec<_>>();
        let funding = transactions
            .iter()
            .enumerate()
            .map(|(index, transaction)| ScriptIndexRecord {
                txid: transaction.compute_txid(),
                height: u32::try_from(index + 1).expect("fixture height fits u32"),
                value: u64::try_from(index + 1).expect("fixture value fits u64"),
                vout: 0,
            })
            .collect::<Vec<_>>();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut ctx = Context::new();
        for record in &history {
            ctx.add_block(crate::context::BlockRecord::synthetic(
                record.height,
                Hash256::from_le_bytes(&[0; 32]),
            ));
        }
        ctx.script_index = Some(Arc::new(StaticScriptIndex {
            history,
            funding: funding.clone(),
            unspent: vec![funding[0]],
        }));
        ctx.esplora_tx_index = Some(Arc::new(CountingTxIndex {
            transactions,
            calls: Arc::clone(&calls),
        }));

        let summary = summary(
            &ctx,
            &script_hash.to_byte_array().to_lower_hex_string(),
            None,
        );
        assert_eq!(summary.status, 200);
        let value: Value = serde_json::from_slice(&summary.body).expect("summary json");
        assert_eq!(value["chain_stats"]["funded_txo_count"], json!(30));
        assert_eq!(value["chain_stats"]["funded_txo_sum"], json!(465));
        assert_eq!(value["chain_stats"]["spent_txo_count"], json!(29));
        assert_eq!(value["chain_stats"]["spent_txo_sum"], json!(464));

        let per_transaction = address_transaction_summary(&ctx, script_hash);
        assert_eq!(per_transaction.status, 200);
        let rows: Value = serde_json::from_slice(&per_transaction.body).expect("summary rows json");
        assert_eq!(rows.as_array().map(Vec::len), Some(30));

        // Both endpoints answer from index rows alone. Reading one transaction
        // per history entry escapes the script index's per-query budget, so a
        // long-history address turns one request into unbounded storage I/O.
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn mempool_spender_of_a_confirmed_target_output_remains_in_activity_and_stats() {
        let target = ScriptBuf::from_bytes(vec![0x51]);
        let confirmed = ScriptIndexRecord {
            txid: Txid::from_byte_array([3; 32]),
            height: 42,
            value: 125,
            vout: 0,
        };
        let spending = transaction(
            Some(OutPoint::new(confirmed.txid, confirmed.vout)),
            TxOut {
                value: Amount::from_sat(100),
                script_pubkey: ScriptBuf::from_bytes(vec![0x52]),
            },
        );
        let mut ctx = Context::new();
        ctx.script_index = Some(Arc::new(StaticScriptIndex {
            history: Vec::new(),
            funding: vec![confirmed],
            unspent: vec![confirmed],
        }));
        ctx.mempool
            .write()
            .insert_entry(MempoolEntry::new(
                Arc::new(spending.clone()),
                100,
                1_000,
                0,
                0,
            ))
            .expect("mempool entry accepted");

        let script_hash = ScriptHash::new(&target);
        let projection = Projection::new(&ctx);
        let activity = projection
            .script_activity(script_hash)
            .expect("script activity resolves");
        assert_eq!(
            activity
                .mempool
                .iter()
                .map(AsRef::as_ref)
                .collect::<Vec<_>>(),
            vec![&spending]
        );
        assert!(
            projection
                .script_utxos(script_hash)
                .expect("UTXO overlay resolves")
                .is_empty()
        );
        let stats = activity.mempool_stats(script_hash);
        assert_eq!(stats.spent_txo_count, 1);
        assert_eq!(stats.spent_txo_sum, 125);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn utxo_and_outspend_use_their_dedicated_index_queries() {
        let history_calls = Arc::new(AtomicUsize::new(0));
        let unspent_calls = Arc::new(AtomicUsize::new(0));
        let spender_calls = Arc::new(AtomicUsize::new(0));
        let mut ctx = Context::new();
        ctx.script_index = Some(Arc::new(CountingScriptIndex {
            history_calls: Arc::clone(&history_calls),
            unspent_calls: Arc::clone(&unspent_calls),
            spender_calls: Arc::clone(&spender_calls),
        }));
        let projection = Projection::new(&ctx);
        let script_hash = ScriptHash::from_script_bytes(&[]);

        assert!(
            projection
                .script_utxos(script_hash)
                .expect("UTXO query")
                .is_empty()
        );
        assert!(
            !outspend(&projection, OutPoint::null())
                .expect("outspend query")
                .spent
        );
        assert_eq!(unspent_calls.load(Ordering::Relaxed), 1);
        assert_eq!(spender_calls.load(Ordering::Relaxed), 1);
        assert_eq!(history_calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn transaction_projection_uses_internal_lookup_for_prevout_and_fee() {
        let parent = transaction(
            None,
            TxOut {
                value: Amount::from_sat(125),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            },
        );
        let child = transaction(
            Some(OutPoint::new(parent.compute_txid(), 0)),
            TxOut {
                value: Amount::from_sat(100),
                script_pubkey: ScriptBuf::from_bytes(vec![0x52]),
            },
        );
        let mut ctx = Context::new();
        ctx.esplora_tx_index = Some(Arc::new(StaticTxIndex::new(parent)));

        let rendered = Projection::new(&ctx)
            .transaction_value(&child, None)
            .expect("prevout indexed");
        assert_eq!(rendered.fee, 25);
        assert_eq!(
            rendered.vin[0]
                .prevout
                .as_ref()
                .expect("rendered prevout")
                .value,
            125
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn stale_block_transactions_do_not_inherit_active_chain_status()
    -> Result<(), Box<dyn std::error::Error>> {
        let transaction = transaction(
            None,
            TxOut {
                value: Amount::from_sat(125),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            },
        );
        let genesis = bitcoin::block::Header {
            version: Version::ONE,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 1_000,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        };
        let stale_block = Block {
            header: bitcoin::block::Header {
                version: Version::ONE,
                prev_blockhash: genesis.block_hash(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 2_000,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 2,
            },
            txdata: vec![transaction.clone()],
        };
        let stale_record = crate::context::BlockRecord::from_block(1, &stale_block);
        let mut ctx = Context::new();
        ctx.block_body_source = Some(Arc::new(SingleBlockSource {
            height: 1,
            hash: stale_record.hash,
            body: serialize(&stale_block),
        }));
        ctx.add_block(stale_record.clone());
        {
            let mut tree = ctx.block_tree.write();
            let genesis_id = tree.insert_node(None, genesis, NodeStatus::Active)?;
            tree.insert_node(
                Some(genesis_id),
                stale_block.header,
                NodeStatus::HeaderValid,
            )?;
            // BlockTree::insert_node now publishes the best-work header on
            // insert and only reorgs on strictly greater chainwork. The stale
            // block had equal work and was inserted first, so it became the
            // active tip. Give the active chain a lower target so it wins.
            let active = bitcoin::block::Header {
                version: Version::ONE,
                prev_blockhash: genesis.block_hash(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 1_500,
                bits: CompactTarget::from_consensus(0x1d00_ffff),
                nonce: 1,
            };
            tree.insert_node(Some(genesis_id), active, NodeStatus::Active)?;
            let tip = tree
                .tip()
                .ok_or_else(|| std::io::Error::other("missing active tip"))?;
            ctx.set_applied_tip((*tip).clone());
        }
        ctx.esplora_tx_index = Some(Arc::new(StaticTxIndex::new(transaction)));

        let response = block_txs(&ctx, &stale_record.hash.to_string_be(), 0);
        assert_eq!(response.status, 200);
        let rendered: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(rendered[0]["status"], json!({"confirmed":false}));
        Ok(())
    }
}
