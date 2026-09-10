//! Wallet-facing electrs/Esplora routes.

use core::str::FromStr as _;

// WHY rust-bitcoin: `/tx/:id/merkleblock-proof` returns the serialized
// rust-bitcoin `MerkleBlock`; no native merkle-proof builder exists in-tree
// (sanctioned compat seam).
use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::Hash as _;
use bitcoin::hex::{DisplayHex as _, FromHex as _};
use bitcoin::merkle_tree::MerkleBlock;
use bitcoin_rs_index::ScriptHash;
use bitcoin_rs_primitives::encode::double_sha256;
use bitcoin_rs_primitives::{Block, Hash256, OutPoint, Tx, Txid, consensus_bytes, deserialize};
use serde_json::json;
use sonic_rs::{JsonValueTrait as _, json as sonic_json};

use crate::context::Context;
use crate::handlers::Handler;
use crate::rest::Response;

use super::http::{
    bad, dispatch_error, internal, json_response, not_found, query_error, text, unavailable,
};
use super::model::{
    AddressTransactionSummary, BlockStatus, MempoolSummary, MerkleProof, Outspend,
    RecentTransaction, ScriptSummary, TransactionValue,
};
use super::projection::{Confirmation, Projection};

pub(super) const CHAIN_PAGE: usize = 25;
const MEMPOOL_PAGE: usize = 50;

pub(super) fn get(handler: &Handler, ctx: &Context, path: &str, _query: &str) -> Response {
    let parts: Vec<_> = path.trim_matches('/').split('/').collect();
    match parts.as_slice() {
        ["blocks", "tip", "height"] => text(ctx.applied_height().to_string()),
        ["blocks", "tip", "hash"] => text(ctx.applied_hash().to_string_be()),
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
    }
}

pub(super) fn post(handler: &Handler, path: &str, body: &[u8]) -> Response {
    match path {
        "/tx" => {
            let Ok(hex) = core::str::from_utf8(body) else {
                return bad("transaction body must be UTF-8 hex");
            };
            match handler.dispatch("sendrawtransaction", &sonic_json!([hex.trim()])) {
                Ok(value) => match value.as_str() {
                    Some(id) => text(id.to_owned()),
                    None => json_response(value),
                },
                Err(error) => dispatch_error(error),
            }
        }
        // `/txs/package` is in this namespace so it cannot fall through to
        // JSON-RPC. API.md makes package relay conditional on a
        // package-admission backend; 404 is preferable to sequential
        // sendrawtransaction calls pretending to be atomic.
        _ => not_found(),
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
    Projection::new(ctx).required_transaction(id).map_or_else(
        |r| r,
        |(tx, _)| text(consensus_bytes(&tx).to_lower_hex_string()),
    )
}
fn tx_raw(ctx: &Context, id: &str) -> Response {
    Projection::new(ctx).required_transaction(id).map_or_else(
        |r| r,
        |(tx, _)| Response {
            status: 200,
            reason: "OK",
            content_type: "application/octet-stream",
            body: consensus_bytes(&tx),
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
        |(record, bytes, txid)| {
            // MerkleBlock construction requires bitcoin::Block (sanctioned seam).
            let Ok(block) = bitcoin::consensus::encode::deserialize::<bitcoin::Block>(&bytes)
            else {
                return internal("stored block body is corrupt");
            };
            let proof = MerkleBlock::from_block_with_predicate(&block, |candidate| {
                candidate.as_byte_array() == txid.as_bytes()
            });
            let _ = record;
            text(serialize(&proof).to_lower_hex_string())
        },
    )
}

fn tx_merkle_proof(ctx: &Context, id: &str) -> Response {
    confirmed_block(ctx, id).map_or_else(
        |r| r,
        |(record, bytes, txid)| {
            let Ok(block) = deserialize::<Block>(&bytes) else {
                return internal("stored block body is corrupt");
            };
            let txids = block.txs.iter().map(Tx::txid).collect::<Vec<_>>();
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
) -> Result<(crate::context::BlockRecord, Vec<u8>, Txid), Response> {
    let (transaction, Some(status)) = Projection::new(ctx).required_transaction(id)? else {
        return Err(not_found());
    };
    let txid = transaction.txid();
    let record = ctx
        .block_by_height(status.height)
        .ok_or_else(|| unavailable("confirming block unavailable"))?;
    let bytes = ctx
        .block_body_bytes(&record)
        .ok_or_else(|| unavailable("confirming block body unavailable"))?;
    Ok((record, bytes, txid))
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
            bytes[..32].copy_from_slice(pair[0].as_bytes());
            bytes[32..].copy_from_slice(right.as_bytes());
            next.push(Txid(double_sha256(&bytes)));
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
                .outputs
                .get(usize::try_from(vout).unwrap_or(usize::MAX))
            else {
                return not_found();
            };
            outspend(&projection, OutPoint::new(transaction.txid(), vout))
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

pub(super) fn outspends_for_transaction(
    projection: &Projection<'_>,
    transaction: &Tx,
) -> Result<Vec<Outspend>, Response> {
    transaction
        .outputs
        .iter()
        .enumerate()
        .map(|(vout, _)| {
            let vout = u32::try_from(vout).map_err(|_| internal("output index is too large"))?;
            outspend(projection, OutPoint::new(transaction.txid(), vout))
        })
        .collect()
}

pub(super) fn outspend(
    projection: &Projection<'_>,
    outpoint: OutPoint,
) -> Result<Outspend, Response> {
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
    let in_best_chain =
        ctx.active_hash_at_height(record.height) == Some(Hash256::from(record.hash));
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
pub(super) fn block_txs(ctx: &Context, h: &str, start: usize) -> Response {
    let (record, block) = match Projection::new(ctx).required_block(h) {
        Ok(value) => value,
        Err(response) => return response,
    };
    block_transaction_values(ctx, &record, block.txs.iter().skip(start).take(CHAIN_PAGE))
        .map_or_else(|r| r, json_response)
}

pub(super) fn block_transaction_values<'a>(
    ctx: &Context,
    record: &crate::context::BlockRecord,
    transactions: impl IntoIterator<Item = &'a Tx>,
) -> Result<Vec<TransactionValue>, Response> {
    // A record fetched by hash can be from a losing branch. Do not reuse the
    // active block at the same height for its transactions' confirmation data.
    let block_status = (ctx.active_hash_at_height(record.height)
        == Some(Hash256::from(record.hash)))
    .then_some(Confirmation {
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
                None => projection.confirmation(&tx.txid())?,
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
            .txs
            .iter()
            .map(|tx| tx.txid().to_string())
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
        .txs
        .get(index)
        .map_or_else(not_found, |tx| text(tx.txid().to_string()))
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
fn mempool(ctx: &Context) -> Response {
    let pool = ctx.mempool.read();
    let stats = pool.stats();
    let mut bins = std::collections::BTreeMap::new();
    for entry in pool.iter_entries() {
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
    let mut entries = pool.iter_entries().collect::<Vec<_>>();
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
                value: entry.tx.outputs.iter().fold(0_u64, |sum, output| {
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
pub(super) fn summary(ctx: &Context, text: &str, address: Option<&str>) -> Response {
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
pub(super) fn history(
    ctx: &Context,
    h: ScriptHash,
    last: Option<&str>,
    include_mempool: bool,
) -> Response {
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

pub(super) fn address_transaction_summary(ctx: &Context, h: ScriptHash) -> Response {
    let activity = match Projection::new(ctx).script_activity(h) {
        Ok(activity) => activity,
        Err(response) => return response,
    };
    let mut funded = std::collections::BTreeMap::<Txid, u64>::new();
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
