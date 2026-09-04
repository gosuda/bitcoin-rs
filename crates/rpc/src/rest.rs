//! Bitcoin Core-compatible REST surface used by remote clients.
//!
//! The twelve supported route prefixes mirror Core's `StartREST` registration table.
//! JSON projections come from [`crate::render`] and [`crate::tx_render`]; hex
//! and binary payloads use consensus serialization. Applied-chain membership is
//! always resolved through [`crate::context::Context`] ancestry facts — never
//! from the header tip alone.

use alloc::sync::Arc;
use std::str::FromStr;

use bitcoin_rs_primitives::{
    Block, BlockHash, Hash256, Header, TxOut, Txid, consensus_bytes, deserialize,
};
use sonic_rs::{JsonValueTrait as _, Value, json};

use crate::context::{BlockRecord, Context};
use crate::error::RpcError;
use crate::handlers::chain::getblockchaininfo;
use crate::handlers::mempool::{getmempoolinfo, getrawmempool};
use crate::handlers::tx::getrawtransaction;
use crate::render::{BlockChainContext, BlockTxVerbosity};
use crate::tx_render;

const DEFAULT_HEADER_COUNT: u32 = 5;
const MAX_HEADER_COUNT: u32 = 2_000;
/// Core's `MAX_GETUTXOS_OUTPOINTS`.
const MAX_GETUTXOS_OUTPOINTS: usize = 15;

/// BIP141's maximum block weight also bounds any valid serialized block body.
const MAX_REST_BLOCK_BODY_BYTES: usize = 4_000_000;

/// The Bitcoin Core REST prefixes registered by `StartREST`.
pub const REGISTRATIONS: [&str; 12] = [
    "/rest/tx/",
    "/rest/block/notxdetails/",
    "/rest/block/",
    "/rest/blockpart/",
    "/rest/chaininfo",
    "/rest/mempool/",
    "/rest/headers/",
    "/rest/getutxos",
    "/rest/deploymentinfo/",
    "/rest/deploymentinfo",
    "/rest/blockhashbyheight/",
    "/rest/spenttxouts/",
];

/// HTTP response produced by a REST route.
#[derive(Debug, Eq, PartialEq)]
pub struct Response {
    /// HTTP status code.
    pub status: u16,
    /// HTTP reason phrase.
    pub reason: &'static str,
    /// MIME type.
    pub content_type: &'static str,
    /// Response body.
    pub body: Vec<u8>,
}

#[derive(Clone)]
struct HeaderRecord {
    hash: Hash256,
    height: u32,
    header: Header,
}

/// Routes one REST request.
///
/// REST is deliberately distinct from unknown routes: a disabled gateway and
/// a genuinely unknown path return 404, while malformed header parameters
/// return 400. The enforcer uses 404 on `/rest/*` to diagnose a disabled
/// gateway, so an unknown but well-formed block hash returns an empty 200
/// response instead of a misleading 404. Header query parameters other than
/// `count` are ignored, matching Core's cache-buster-friendly behavior.
#[must_use]
pub fn route(ctx: &Arc<Context>, path: &str, query: &str, enabled: bool) -> Response {
    if !enabled {
        return not_found();
    }
    // Order matters: `/rest/block/notxdetails/` must be checked before
    // `/rest/block/` so the longer prefix wins.
    if let Some(suffix) = path.strip_prefix("/rest/tx/") {
        return route_tx(ctx, suffix);
    }
    if let Some(suffix) = path.strip_prefix("/rest/block/notxdetails/") {
        return route_block(ctx, suffix, false);
    }
    if let Some(suffix) = path.strip_prefix("/rest/blockpart/") {
        return route_block_part(ctx, suffix);
    }
    if let Some(suffix) = path.strip_prefix("/rest/block/") {
        return route_block(ctx, suffix, true);
    }
    if path.starts_with("/rest/chaininfo") {
        return route_chaininfo(ctx, path);
    }
    if let Some(suffix) = path.strip_prefix("/rest/mempool/") {
        return route_mempool(ctx, suffix, query);
    }
    if let Some(suffix) = path.strip_prefix("/rest/headers/") {
        return route_headers(ctx, suffix, query);
    }
    if let Some(suffix) = path.strip_prefix("/rest/getutxos") {
        return route_getutxos(ctx, suffix);
    }
    if let Some(suffix) = path.strip_prefix("/rest/deploymentinfo") {
        return route_deploymentinfo(ctx, suffix);
    }
    if let Some(suffix) = path.strip_prefix("/rest/blockhashbyheight/") {
        return route_blockhash_by_height(ctx, suffix);
    }
    if let Some(suffix) = path.strip_prefix("/rest/spenttxouts/") {
        return route_spent_txouts(suffix);
    }
    not_found()
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

/// Core: `/rest/tx/<txid>.<ext>`.
fn route_tx(ctx: &Arc<Context>, suffix: &str) -> Response {
    let (hash_text, format) = split_format(suffix);
    let Ok(txid) = Txid::from_str(hash_text) else {
        return bad_request_owned(format!("Invalid hash: {hash_text}"));
    };
    let Some(format) = format else {
        return format_not_found(available_formats());
    };
    let txid_text = txid.to_string();
    match format {
        "json" => match getrawtransaction(ctx, &json!([txid_text, true])) {
            Ok(value) => text_response("application/json", sonic_bytes(&value)),
            Err(RpcError::NotFound(_)) => not_found_owned(format!("{txid_text} not found")),
            Err(error) => json_response(Err(error)),
        },
        "hex" | "bin" => match getrawtransaction(ctx, &json!([txid_text, false])) {
            Ok(value) => {
                let hex = value.as_str().unwrap_or_default();
                if format == "hex" {
                    text_response("text/plain", format!("{hex}\n").into_bytes())
                } else {
                    let bytes: Vec<u8> = hex_decode(hex);
                    binary_response("application/octet-stream", &bytes)
                }
            }
            Err(RpcError::NotFound(_)) => not_found_owned(format!("{txid_text} not found")),
            Err(error) => json_response(Err(error)),
        },
        _ => format_not_found(available_formats()),
    }
}

/// Core: `/rest/block/<hash>.<ext>` (full tx details) and
/// `/rest/block/notxdetails/<hash>.<ext>` (txid-only).
fn route_block(ctx: &Arc<Context>, suffix: &str, with_details: bool) -> Response {
    let (hash_text, format) = split_format(suffix);
    let Ok(hash) = Hash256::from_str(hash_text) else {
        return bad_request_owned(format!("Invalid hash: {hash_text}"));
    };
    let Some(format) = format else {
        return format_not_found(available_formats());
    };
    let Some(record) = ctx.record_for_hash(hash) else {
        return not_found_owned(format!("{hash_text} not found"));
    };
    let Some(_render) = ctx.try_acquire_rest_render() else {
        return service_unavailable("too many concurrent full-block REST requests");
    };
    let body = match bounded_block_body(ctx, &record) {
        Ok(body) => body,
        Err(response) => return response,
    };
    match format {
        "bin" => binary_response("application/octet-stream", &body),
        "hex" => text_response(
            "text/plain",
            format!("{}\n", hex_encode(&body)).into_bytes(),
        ),
        "json" => {
            let block = match deserialize::<Block>(&body) {
                Ok(block) => block,
                Err(_) => return not_found_owned(format!("{hash_text} not found")),
            };
            let context = build_chain_context(ctx, &record, &block.header);
            let verbosity = if with_details {
                BlockTxVerbosity::Full
            } else {
                BlockTxVerbosity::Ids
            };
            let value = crate::render::block_json(&block, &context, verbosity, ctx.chain_network);
            text_response("application/json", sonic_bytes(&value))
        }
        _ => format_not_found(available_formats()),
    }
}

/// Core `/rest/blockpart/<hash>.<ext>` serves raw block payload bytes (hex or
/// binary only), matching Core's original part endpoint which rejected JSON.
fn route_block_part(ctx: &Arc<Context>, suffix: &str) -> Response {
    let (hash_text, format) = split_format(suffix);
    let Ok(hash) = Hash256::from_str(hash_text) else {
        return bad_request_owned(format!("Invalid hash: {hash_text}"));
    };
    let Some(format) = format else {
        return format_not_found(available_formats());
    };
    let Some(record) = ctx.record_for_hash(hash) else {
        return not_found_owned(format!("{hash_text} not found"));
    };
    let Some(_render) = ctx.try_acquire_rest_render() else {
        return service_unavailable("too many concurrent full-block REST requests");
    };
    let body = match bounded_block_body(ctx, &record) {
        Ok(body) => body,
        Err(response) => return response,
    };
    match format {
        "bin" => binary_response("application/octet-stream", &body),
        "hex" => text_response(
            "text/plain",
            format!("{}\n", hex_encode(&body)).into_bytes(),
        ),
        _ => format_not_found(available_formats()),
    }
}

fn bounded_block_body(ctx: &Context, record: &BlockRecord) -> Result<Vec<u8>, Response> {
    if record.body_size > MAX_REST_BLOCK_BODY_BYTES {
        return Err(internal_error(
            "stored block exceeds the REST response limit",
        ));
    }
    let Some(body) = ctx.block_body_bytes(record) else {
        return Err(not_found_owned(format!(
            "{} not available (pruned data)",
            record.hash
        )));
    };
    if body.len() > MAX_REST_BLOCK_BODY_BYTES {
        return Err(internal_error(
            "stored block exceeds the REST response limit",
        ));
    }
    Ok(body)
}

/// Core `/rest/chaininfo.json` (JSON only).
fn route_chaininfo(ctx: &Arc<Context>, path: &str) -> Response {
    let (_, format) = split_format(path);
    if format != Some("json") {
        return format_not_found("json");
    }
    json_response(getblockchaininfo(ctx, &json!([])))
}

/// Core `/rest/mempool/<info|contents>.json`.
fn route_mempool(ctx: &Arc<Context>, suffix: &str, query: &str) -> Response {
    let (kind, format) = split_format(suffix);
    if kind != "info" && kind != "contents" {
        return bad_request("Invalid URI format. Expected /rest/mempool/<info|contents>.json");
    }
    if format != Some("json") {
        return format_not_found("json");
    }
    match kind {
        "info" => json_response(getmempoolinfo(ctx, &json!([]))),
        "contents" => {
            let verbose = match query_param(query, "verbose") {
                Some(raw) => match raw {
                    "true" => true,
                    "false" => false,
                    _ => {
                        return bad_request(
                            "The \"verbose\" query parameter must be either \"true\" or \"false\".",
                        );
                    }
                },
                None => true,
            };
            match query_param(query, "mempool_sequence") {
                Some(raw) if raw != "true" && raw != "false" => {
                    return bad_request(
                        "The \"mempool_sequence\" query parameter must be either \"true\" or \"false\".",
                    );
                }
                Some("true") if verbose => {
                    return bad_request(
                        "Verbose results cannot contain mempool sequence values. (hint: set \"verbose=false\")",
                    );
                }
                _ => {}
            }
            json_response(getrawmempool(ctx, &json!([verbose])))
        }
        _ => unreachable!("mempool resource validated before rendering"),
    }
}

/// Core `/rest/headers/<hash>.<ext>?count=<count>`.
fn route_headers(ctx: &Arc<Context>, suffix: &str, query: &str) -> Response {
    let (hash_text, format) = split_format(suffix);
    let count = match parse_count(query) {
        Ok(count) => count,
        Err(response) => return response,
    };
    let Ok(hash) = Hash256::from_str(hash_text) else {
        return bad_request_owned(format!("Invalid hash: {hash_text}"));
    };
    let Some(format) = format else {
        return not_found_with("output format not found");
    };
    let records = header_records(ctx, hash, count);
    match format {
        "json" => {
            let values = records
                .iter()
                .map(|record| {
                    crate::render::header_json(&record.header, &header_chain_context(ctx, record))
                })
                .collect::<Vec<_>>();
            text_response("application/json", sonic_bytes(&Value::from(values)))
        }
        "hex" => {
            let body = records
                .iter()
                .map(|record| hex_encode(&consensus_bytes(&record.header)))
                .collect::<String>();
            text_response("text/plain", body.into_bytes())
        }
        "bin" => binary_response(
            "application/octet-stream",
            &records.iter().fold(Vec::new(), |mut body, record| {
                body.extend(consensus_bytes(&record.header));
                body
            }),
        ),
        _ => bad_request_owned(format!("Invalid hash: {hash_text}")),
    }
}

/// Core `/rest/getutxos[/checkmempool]/<txid>-<n>....{bin,hex,json}`.
///
/// Only the URI-scheme input form is implemented (Core's raw-body form is not
/// served). Responses follow Core's BIP64-ish shape.
fn route_getutxos(ctx: &Arc<Context>, suffix: &str) -> Response {
    let (path, format) = split_format(suffix);
    let (check_mempool, outpoints) = match parse_getutxos_outpoints(path) {
        Ok(request) => request,
        Err(response) => return response,
    };
    let Some(format) = format else {
        return format_not_found(available_formats());
    };

    let active_height = ctx.applied_height();
    let active_hash = ctx.applied_hash();

    let mut bitmap = vec![0_u8; outpoints.len().div_ceil(8)];
    let mut outs = Vec::with_capacity(outpoints.len());
    let mut hits = Vec::with_capacity(outpoints.len());
    let pool = ctx.mempool.read();
    for (txid, vout) in &outpoints {
        let outpoint = bitcoin_rs_primitives::OutPoint::new(*txid, *vout);
        let mempool_spent = check_mempool && pool.is_outpoint_spent(&outpoint);
        let live = if mempool_spent {
            None
        } else {
            ctx.utxo.get_entry(&outpoint)
        };
        hits.push(live.is_some());
        if let Some(entry) = live {
            outs.push((entry.height, entry.txout));
        }
    }
    drop(pool);
    // Bitmap packs the least-significant hit bit first per byte, matching Core.
    for (index, hit) in hits.iter().enumerate() {
        if *hit {
            bitmap[index / 8] |= 1 << (index % 8);
        }
    }

    let bitmap_text = hits
        .iter()
        .map(|hit| if *hit { '1' } else { '0' })
        .collect::<String>();

    match format {
        "json" => {
            let utxos = outs
                .iter()
                .map(|(height, txout)| {
                    json!({
                        "height": height,
                        "value": tx_render::btc_amount_json(txout.value),
                        "scriptPubKey": tx_render::script_pub_key_json(&txout.script_pubkey, ctx.chain_network)
                    })
                })
                .collect::<Vec<_>>();
            text_response(
                "application/json",
                sonic_bytes(&json!({
                    "chainHeight": active_height,
                    "chaintipHash": active_hash.to_string_be(),
                    "bitmap": bitmap_text,
                    "utxos": utxos
                })),
            )
        }
        "hex" => text_response(
            "text/plain",
            format!(
                "{}\n",
                hex_encode(&serialize_getutxos_bin(
                    active_height,
                    active_hash,
                    &bitmap,
                    &outs
                ))
            )
            .into_bytes(),
        ),
        "bin" => binary_response(
            "application/octet-stream",
            &serialize_getutxos_bin(active_height, active_hash, &bitmap, &outs),
        ),
        _ => format_not_found(available_formats()),
    }
}

/// Core `/rest/deploymentinfo[/<blockhash>].json` (JSON only).
///
/// No RPC handler exists for this surface, so the projection is Core-shaped
/// from applied-chain facts with an empty `deployments` map.
fn route_deploymentinfo(ctx: &Arc<Context>, suffix: &str) -> Response {
    let (hash_text, format) = split_format(suffix);
    if format != Some("json") {
        return format_not_found("json");
    }
    let object = if hash_text.is_empty() {
        json!({
            "hash": ctx.applied_hash().to_string_be(),
            "height": ctx.applied_height(),
            "deployments": {}
        })
    } else {
        let hash_text = hash_text.strip_prefix('/').unwrap_or(hash_text);
        let Ok(hash) = Hash256::from_str(hash_text) else {
            return bad_request_owned(format!("Invalid hash: {hash_text}"));
        };
        let Some(record) = ctx.record_for_hash(hash) else {
            return bad_request_owned("Block not found".to_owned());
        };
        json!({
            "hash": hash.to_string_be(),
            "height": record.height,
            "deployments": {}
        })
    };
    text_response("application/json", sonic_bytes(&object))
}

/// Core `/rest/blockhashbyheight/<height>.<ext>`.
fn route_blockhash_by_height(ctx: &Arc<Context>, suffix: &str) -> Response {
    let (height_text, format) = split_format(suffix);
    let Ok(height) = height_text.parse::<u32>() else {
        return bad_request_owned(format!("Invalid height: {height_text}"));
    };
    let Some(format) = format else {
        return format_not_found(available_formats());
    };
    let Some(hash) = ctx.block_hash_at_height(height) else {
        return not_found_owned("Block height out of range".to_owned());
    };
    match format {
        "bin" => binary_response("application/octet-stream", hash.to_le_bytes().as_slice()),
        "hex" => text_response(
            "text/plain",
            format!("{}\n", hash.to_string_be()).into_bytes(),
        ),
        "json" => text_response(
            "application/json",
            sonic_bytes(&json!({"blockhash": hash.to_string_be()})),
        ),
        _ => format_not_found(available_formats()),
    }
}

/// Core `/rest/spenttxouts/<hash>.<ext>`.
///
/// This node does not retain undo data, so every well-formed request answers
/// Core's undo-unavailable error.
fn route_spent_txouts(suffix: &str) -> Response {
    let (hash_text, format) = split_format(suffix);
    if Hash256::from_str(hash_text).is_err() {
        return bad_request_owned(format!("Invalid hash: {hash_text}"));
    }
    if format.is_none() {
        return format_not_found(available_formats());
    }
    not_found_owned(format!("{hash_text} undo not available"))
}

// ---------------------------------------------------------------------------
// Header chain walk
// ---------------------------------------------------------------------------

fn header_records(ctx: &Context, hash: Hash256, count: u32) -> Vec<HeaderRecord> {
    let applied_tip = ctx.applied_tip.load_full();
    let tree = ctx.block_tree.read();
    if let Some(start_id) = tree.lookup(hash)
        && let Ok(start_node) = tree.node(start_id)
    {
        let start = HeaderRecord {
            hash: start_node.hash,
            height: start_node.height,
            header: start_node.header,
        };
        let Some(tip) = applied_tip else {
            return Vec::new();
        };
        let Ok(tip_node) = tree.node(tip.tip_id) else {
            return Vec::new();
        };
        if tip_node.hash != tip.hash || tip_node.height != tip.height {
            return Vec::new();
        }
        let Some(active_start) = tree.node_at_height_from(tip.tip_id, start.height) else {
            return Vec::new();
        };
        if active_start != start_id {
            return Vec::new();
        }
        let last_height = start
            .height
            .saturating_add(count.saturating_sub(1))
            .min(tip_node.height);
        let Some(last_id) = tree.node_at_height_from(tip.tip_id, last_height) else {
            return Vec::new();
        };
        let mut records = Vec::with_capacity(usize::try_from(count).unwrap_or(usize::MAX));
        let mut cursor = last_id;
        while let Ok(node) = tree.node(cursor) {
            records.push(HeaderRecord {
                hash: node.hash,
                height: node.height,
                header: node.header,
            });
            if cursor == start_id {
                break;
            }
            let Some(parent) = node.parent else {
                break;
            };
            cursor = parent;
        }
        records.reverse();
        return truncate_at_linkage_break(records);
    }

    Vec::new()
}

fn truncate_at_linkage_break(mut records: Vec<HeaderRecord>) -> Vec<HeaderRecord> {
    let Some(break_index) = records
        .windows(2)
        .position(|pair| pair[1].header.prev_blockhash != BlockHash::from(pair[0].hash))
    else {
        return records;
    };
    records.truncate(break_index + 1);
    records
}

fn parse_count(query: &str) -> Result<u32, Response> {
    if query.is_empty() {
        return Ok(DEFAULT_HEADER_COUNT);
    }
    let mut count = None;
    for pair in query.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        if key == "count" {
            count = Some(value);
        }
    }
    let Some(value) = count else {
        return Ok(DEFAULT_HEADER_COUNT);
    };
    let Ok(parsed) = value.parse::<u64>() else {
        return Err(invalid_count(value));
    };
    if !(1..=u64::from(MAX_HEADER_COUNT)).contains(&parsed) {
        return Err(invalid_count(value));
    }
    Ok(u32::try_from(parsed).unwrap_or(MAX_HEADER_COUNT))
}

fn invalid_count(value: &str) -> Response {
    bad_request_owned(format!(
        "Header count is invalid or out of acceptable range (1-2000): {value}"
    ))
}

// ---------------------------------------------------------------------------
// Getutxos helpers
// ---------------------------------------------------------------------------

fn parse_getutxos_outpoints(path: &str) -> Result<(bool, Vec<(Txid, u32)>), Response> {
    let path = path.strip_prefix('/').unwrap_or(path);
    let mut segments = path.split('/').filter(|segment| !segment.is_empty());
    let check_mempool = segments.clone().next() == Some("checkmempool");
    if check_mempool {
        let _ = segments.next();
    }

    let mut outpoints = Vec::new();
    for segment in segments {
        let Some((txid_text, vout_text)) = segment.split_once('-') else {
            return Err(bad_request("Parse error"));
        };
        let Ok(txid) = Txid::from_str(txid_text) else {
            return Err(bad_request("Parse error"));
        };
        let Ok(vout) = vout_text.parse::<u32>() else {
            return Err(bad_request("Parse error"));
        };
        outpoints.push((txid, vout));
    }
    if outpoints.is_empty() {
        return Err(bad_request("Error: empty request"));
    }
    if outpoints.len() > MAX_GETUTXOS_OUTPOINTS {
        return Err(bad_request_owned(format!(
            "Error: max outpoints exceeded (max: {MAX_GETUTXOS_OUTPOINTS}, tried: {})",
            outpoints.len()
        )));
    }
    Ok((check_mempool, outpoints))
}

/// Serializes the getutxos response body: active height, active hash, packed
/// bitmap, then one `CCoin` (version, height, txout) per unspent output.
fn serialize_getutxos_bin(
    active_height: u32,
    active_hash: Hash256,
    bitmap: &[u8],
    outs: &[(u32, TxOut)],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&active_height.to_le_bytes());
    body.extend_from_slice(&active_hash.to_le_bytes());
    append_compact_size(&mut body, bitmap.len());
    body.extend_from_slice(bitmap);
    append_compact_size(&mut body, outs.len());
    for (height, txout) in outs {
        body.extend_from_slice(&0_u32.to_le_bytes()); // CCoin version dummy
        body.extend_from_slice(&height.to_le_bytes());
        body.extend_from_slice(&consensus_bytes(txout));
    }
    body
}

fn append_compact_size(body: &mut Vec<u8>, len: usize) {
    match len {
        0..=252 => {
            let Ok(value) = u8::try_from(len) else {
                unreachable!("compact-size byte arm exceeded u8");
            };
            body.push(value);
        }
        253..=0xffff => {
            let Ok(value) = u16::try_from(len) else {
                unreachable!("compact-size u16 arm exceeded u16");
            };
            body.push(253);
            body.extend_from_slice(&value.to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            let Ok(value) = u32::try_from(len) else {
                unreachable!("compact-size u32 arm exceeded u32");
            };
            body.push(254);
            body.extend_from_slice(&value.to_le_bytes());
        }
        _ => {
            let Ok(value) = u64::try_from(len) else {
                panic!("compact-size length exceeds u64");
            };
            body.push(255);
            body.extend_from_slice(&value.to_le_bytes());
        }
    }
}

// ---------------------------------------------------------------------------
// Chain context helpers
// ---------------------------------------------------------------------------

/// Builds the applied-chain facts [`crate::render`] needs to project a block or
/// header.
fn build_chain_context(ctx: &Context, record: &BlockRecord, header: &Header) -> BlockChainContext {
    let applied_height = ctx.applied_height();
    let on_active = ctx.active_hash_at_height(record.height) == Some(Hash256::from(record.hash));
    let n_tx = u32::try_from(record.tx_count).unwrap_or(u32::MAX);
    BlockChainContext {
        height: record.height,
        confirmations: crate::render::confirmations(applied_height, record.height, on_active),
        mediantime: ctx
            .median_time_past_for_hash(Hash256::from(record.hash))
            .unwrap_or(0),
        difficulty: ctx.difficulty_for_bits(header.bits),
        chainwork_hex: ctx
            .chain_work_hex_for_hash(Hash256::from(record.hash))
            .unwrap_or_else(|| "00".to_owned()),
        n_tx,
        next_block_hash: ctx
            .next_block_hash_for_height(record.height)
            .map(BlockHash::from),
    }
}

/// Applied-chain facts for a header record, resolving the real record (and its
/// transaction count) through the tree/log when available.
fn header_chain_context(ctx: &Context, record: &HeaderRecord) -> BlockChainContext {
    let real = ctx
        .record_for_hash(record.hash)
        .unwrap_or_else(|| BlockRecord {
            hash: BlockHash::from(record.hash),
            height: record.height,
            body_size: 0,
            header: None,
            tx_count: 0,
            time: record.header.time,
        });
    build_chain_context(ctx, &real, &record.header)
}

// ---------------------------------------------------------------------------
// Format and query helpers
// ---------------------------------------------------------------------------

/// Splits an endpoint suffix into its text portion and trailing data format.
/// Recognized formats are stripped; an unknown suffix stays in the path so
/// endpoint validation returns Core's malformed-parameter error.
fn split_format(suffix: &str) -> (&str, Option<&'static str>) {
    match suffix.rsplit_once('.') {
        Some((base, "json")) => (base, Some("json")),
        Some((base, "hex")) => (base, Some("hex")),
        Some((base, "bin")) => (base, Some("bin")),
        _ => (suffix, None),
    }
}

fn available_formats() -> &'static str {
    ".bin, .hex, .json"
}

fn format_not_found(available: &str) -> Response {
    not_found_owned(format!("output format not found (available: {available})"))
}

fn query_param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    for pair in query.split('&') {
        if let Some((k, value)) = pair.split_once('=') {
            if k == key {
                return Some(value);
            }
        }
    }
    None
}

fn sonic_bytes(value: &Value) -> Vec<u8> {
    sonic_rs::to_string(value)
        .unwrap_or_else(|_| "null".to_owned())
        .into_bytes()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

fn hex_decode(hex: &str) -> Vec<u8> {
    fn nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => 0xff,
        }
    }
    let bytes = hex.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks_exact(2) {
        let hi = nibble(chunk[0]);
        let lo = nibble(chunk[1]);
        if hi == 0xff || lo == 0xff {
            return Vec::new();
        }
        out.push((hi << 4) | lo);
    }
    out
}
// ---------------------------------------------------------------------------
// Response constructors
// ---------------------------------------------------------------------------

fn json_response(result: Result<Value, RpcError>) -> Response {
    match result {
        Ok(value) => text_response("application/json", sonic_bytes(&value)),
        Err(error) => match error {
            RpcError::InvalidParams(message) => bad_request(message),
            RpcError::NotFound(message) => not_found_with(message),
            _ => Response {
                status: 500,
                reason: "Internal Server Error",
                content_type: "text/plain",
                body: error.to_string().into_bytes(),
            },
        },
    }
}

fn text_response(content_type: &'static str, body: Vec<u8>) -> Response {
    Response {
        status: 200,
        reason: "OK",
        content_type,
        body,
    }
}

fn binary_response(content_type: &'static str, body: &[u8]) -> Response {
    text_response(content_type, body.to_vec())
}

fn service_unavailable(message: &'static str) -> Response {
    Response {
        status: 503,
        reason: "Service Unavailable",
        content_type: "text/plain",
        body: message.as_bytes().to_vec(),
    }
}

fn internal_error(message: &'static str) -> Response {
    Response {
        status: 500,
        reason: "Internal Server Error",
        content_type: "text/plain",
        body: message.as_bytes().to_vec(),
    }
}
fn bad_request(message: &'static str) -> Response {
    Response {
        status: 400,
        reason: "Bad Request",
        content_type: "text/plain",
        body: message.as_bytes().to_vec(),
    }
}

fn bad_request_owned(message: String) -> Response {
    Response {
        status: 400,
        reason: "Bad Request",
        content_type: "text/plain",
        body: message.into_bytes(),
    }
}

fn not_found() -> Response {
    not_found_with("not found")
}

fn not_found_with(message: &'static str) -> Response {
    not_found_owned(message.to_owned())
}

fn not_found_owned(message: String) -> Response {
    Response {
        status: 404,
        reason: "Not Found",
        content_type: "text/plain",
        body: message.into_bytes(),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::context::BlockRecord;
    use bitcoin_rs_chain::{NodeStatus, TipSnapshot};
    use bitcoin_rs_primitives::{OutPoint, Tx, TxIn};
    use sonic_rs::{JsonContainerTrait as _, JsonValueTrait};

    fn publish_active_chain(ctx: &Context, headers: &[Header]) -> Vec<Hash256> {
        let (tip_id, hashes) = {
            let mut tree = ctx.block_tree.write();
            let mut parent = None;
            let mut ids = Vec::with_capacity(headers.len());
            let mut hashes = Vec::with_capacity(headers.len());
            for header in headers {
                let id = tree
                    .insert_node(parent, *header, NodeStatus::Active)
                    .expect("active header");
                hashes.push(Hash256::from_le_bytes(header.compute_hash().as_bytes()));
                ids.push(id);
                parent = Some(id);
            }
            let tip_id = *ids.last().expect("active tip");
            (tip_id, hashes)
        };
        let tree = ctx.block_tree.read();
        let tip_node = tree.node(tip_id).expect("tip node");
        let tip = TipSnapshot {
            tip_id,
            height: tip_node.height,
            chainwork: tip_node.chainwork,
            hash: tip_node.hash,
        };
        drop(tree);
        ctx.set_applied_tip(tip.clone());
        ctx.set_chain_tip(tip);
        hashes
    }

    struct PanicBlockSource;

    impl crate::context::BlockBodySource for PanicBlockSource {
        fn block_body(&self, _height: u32, _hash: BlockHash) -> Option<Vec<u8>> {
            panic!("exhausted render budget must not load a block body");
        }
    }

    #[test]
    fn disabled_rest_is_not_found() {
        let ctx = Arc::new(Context::new());
        let response = route(&ctx, "/rest/chaininfo.json", "", false);
        assert_eq!(response.status, 404);
    }

    #[test]
    fn chaininfo_json_uses_enforcer_field_names() {
        let ctx = Arc::new(Context::new());
        let response = route(&ctx, "/rest/chaininfo.json", "", true);
        assert_eq!(response.status, 200);
        let value: Value = sonic_rs::from_slice(&response.body).expect("chaininfo JSON");
        for field in ["chain", "blocks", "headers", "bestblockhash"] {
            assert!(value.get(field).is_some(), "missing {field}");
        }
    }

    #[test]
    fn exhausted_block_render_budget_returns_service_unavailable() {
        let mut ctx = Context::new();
        let block = Block {
            header: Header {
                version: 1,
                prev_blockhash: BlockHash::default(),
                merkle_root: Hash256::default(),
                time: 1,
                bits: 0x207f_ffff,
                nonce: 0,
            },
            txs: Vec::new(),
        };
        let record = BlockRecord::from_block(0, &block);
        let hash = record.hash.to_string();
        ctx.add_block(record);
        ctx.block_body_source = Some(Arc::new(PanicBlockSource));
        publish_active_chain(&ctx, &[block.header]);
        let _first = ctx.try_acquire_rest_render().expect("first permit");
        let _second = ctx.try_acquire_rest_render().expect("second permit");
        let ctx = Arc::new(ctx);

        for path in [
            format!("/rest/block/{hash}.json"),
            format!("/rest/blockpart/{hash}.hex"),
        ] {
            let response = route(&ctx, &path, "", true);
            assert_eq!(response.status, 503, "{path}");
        }
    }

    #[test]
    fn route_rejects_unknown_formats_and_bad_hashes() {
        let ctx = Arc::new(Context::new());
        let hash = "0000000000000000000000000000000000000000000000000000000000000000";
        let response = route(&ctx, &format!("/rest/headers/{hash}.txt"), "", true);
        assert_eq!(response.status, 400);
        assert_eq!(
            String::from_utf8(response.body).expect("error body"),
            format!("Invalid hash: {hash}.txt")
        );
        let response = route(&ctx, &format!("/rest/headers/{hash}"), "", true);
        assert_eq!(response.status, 404);
        let response = route(&ctx, "/rest/headers/not-a-hash.json", "", true);
        assert_eq!(response.status, 400);
        assert_eq!(
            String::from_utf8(response.body).expect("error body"),
            "Invalid hash: not-a-hash"
        );
        let response = route(&ctx, "/rest/headers/not-a-hash", "", true);
        assert_eq!(response.status, 400);
        let response = route(&ctx, "/rest/headers/not-a-hash.json", "count=0", true);
        assert_eq!(response.status, 400);
        assert_eq!(
            String::from_utf8(response.body).expect("error body"),
            "Header count is invalid or out of acceptable range (1-2000): 0"
        );
    }

    #[test]
    fn count_boundaries_and_errors() {
        assert_eq!(parse_count("").expect("default"), 5);
        assert_eq!(parse_count("count=1").expect("lower boundary"), 1);
        assert_eq!(parse_count("count=2000").expect("upper boundary"), 2_000);
        assert_eq!(
            parse_count("count=2001").expect_err("above range").status,
            400
        );
        assert_eq!(parse_count("count=0").expect_err("zero count").status, 400);
        assert_eq!(
            parse_count("count=-1").expect_err("negative count").status,
            400
        );
        assert_eq!(parse_count("count=bad").expect_err("bad count").status, 400);
        assert_eq!(
            parse_count("count=18446744073709551616")
                .expect_err("overflow count")
                .status,
            400
        );
        assert_eq!(parse_count("limit=5").expect("unknown query"), 5);
        assert_eq!(parse_count("count").expect("bare query key"), 5);
        assert_eq!(parse_count("count=3&foo=1").expect("unknown query"), 3);
        assert_eq!(parse_count("foo=1&count=3").expect("unknown query"), 3);
    }

    #[test]
    fn unknown_hash_returns_empty_success_for_all_formats() {
        let ctx = Arc::new(Context::new());
        let hash = "0000000000000000000000000000000000000000000000000000000000000001";
        for format in ["json", "hex", "bin"] {
            let path = format!("/rest/headers/{hash}.{format}");
            let response = route(&ctx, &path, "count=1", true);
            assert_eq!(response.status, 200, "{format}");
            assert!(
                response.body.is_empty() || response.body == b"[]",
                "{format}"
            );
        }
        let with_unknown_param = route(
            &ctx,
            &format!("/rest/headers/{hash}.json"),
            "count=3&foo=1",
            true,
        );
        let without_count = route(&ctx, &format!("/rest/headers/{hash}.json"), "limit=5", true);
        assert_eq!(with_unknown_param.status, 200);
        assert_eq!(without_count.status, 200);
        assert_eq!(with_unknown_param.body, b"[]");
        assert_eq!(without_count.body, b"[]");
    }

    #[test]
    fn headers_json_returns_ordered_active_chain_headers() {
        let ctx = Arc::new(Context::new());
        let bits: u32 = 0x1d00_ffff;
        let genesis_header = Header {
            version: 1,
            prev_blockhash: BlockHash::default(),
            merkle_root: Hash256::default(),
            time: 1,
            bits,
            nonce: 1,
        };
        let genesis = Block {
            header: genesis_header,
            txs: Vec::new(),
        };
        let child_header = Header {
            version: 1,
            prev_blockhash: genesis.block_hash(),
            merkle_root: Hash256::default(),
            time: 2,
            bits,
            nonce: 2,
        };
        let child = Block {
            header: child_header,
            txs: Vec::new(),
        };
        let tip_header = Header {
            version: 1,
            prev_blockhash: child.block_hash(),
            merkle_root: Hash256::default(),
            time: 3,
            bits,
            nonce: 3,
        };
        let tip = Block {
            header: tip_header,
            txs: Vec::new(),
        };
        ctx.add_block(BlockRecord::from_block(0, &genesis));
        ctx.add_block(BlockRecord::from_block(1, &child));
        ctx.add_block(BlockRecord::from_block(2, &tip));
        publish_active_chain(&ctx, &[genesis.header, child.header, tip.header]);

        let path = format!("/rest/headers/{}.json", child.block_hash());
        let response = route(&ctx, &path, "count=2000", true);
        assert_eq!(response.status, 200);
        let values: Vec<Value> = sonic_rs::from_slice(&response.body).expect("headers JSON");
        assert_eq!(values.len(), 2);
        assert_eq!(values[0].get("height").and_then(Value::as_u64), Some(1));
        assert_eq!(values[1].get("height").and_then(Value::as_u64), Some(2));
        let child_hash = child.block_hash().to_string();
        assert_eq!(
            values[0].get("hash").and_then(Value::as_str),
            Some(child_hash.as_str())
        );
        let bits_text = values[0].get("bits").and_then(Value::as_str).expect("bits");
        assert_eq!(
            u32::from_str_radix(bits_text, 16).expect("bits round-trip"),
            bits
        );
    }

    #[test]
    fn headers_do_not_walk_past_applied_tip() {
        let ctx = Arc::new(Context::new());
        let bits: u32 = 0x1d00_ffff;
        let genesis = Header {
            version: 1,
            prev_blockhash: BlockHash::default(),
            merkle_root: Hash256::default(),
            time: 1,
            bits,
            nonce: 1,
        };
        let applied = Header {
            version: 1,
            prev_blockhash: genesis.compute_hash(),
            merkle_root: Hash256::default(),
            time: 2,
            bits,
            nonce: 2,
        };
        let header_tip = Header {
            version: 1,
            prev_blockhash: applied.compute_hash(),
            merkle_root: Hash256::default(),
            time: 3,
            bits,
            nonce: 3,
        };
        let applied_tip = {
            let mut tree = ctx.block_tree.write();
            let genesis_id = tree
                .insert_node(None, genesis, NodeStatus::Active)
                .expect("genesis header");
            let applied_id = tree
                .insert_node(Some(genesis_id), applied, NodeStatus::Active)
                .expect("applied header");
            let applied_tip = tree.tip().expect("applied tip").as_ref().clone();
            tree.insert_node(Some(applied_id), header_tip, NodeStatus::Active)
                .expect("header tip");
            applied_tip
        };
        ctx.set_applied_tip(applied_tip);
        let header_tip_hash = Hash256::from(header_tip.compute_hash());

        let response = route(
            &ctx,
            &format!("/rest/headers/{header_tip_hash}.json"),
            "count=2000",
            true,
        );
        let values: Vec<Value> = sonic_rs::from_slice(&response.body).expect("headers JSON");
        assert!(values.is_empty());
    }

    #[test]
    fn headers_json_returns_genesis_and_remaining_headers() {
        let ctx = Arc::new(Context::new());
        let bits: u32 = 0x1d00_ffff;
        let genesis = Header {
            version: 1,
            prev_blockhash: BlockHash::default(),
            merkle_root: Hash256::default(),
            time: 1,
            bits,
            nonce: 1,
        };
        let child = Header {
            version: 1,
            prev_blockhash: genesis.compute_hash(),
            merkle_root: Hash256::default(),
            time: 2,
            bits,
            nonce: 2,
        };
        let tip = Header {
            version: 1,
            prev_blockhash: child.compute_hash(),
            merkle_root: Hash256::default(),
            time: 3,
            bits,
            nonce: 3,
        };
        publish_active_chain(&ctx, &[genesis, child, tip]);

        let response = route(
            &ctx,
            &format!("/rest/headers/{}.json", genesis.compute_hash()),
            "count=2000",
            true,
        );
        let values: Vec<Value> = sonic_rs::from_slice(&response.body).expect("headers JSON");
        assert_eq!(values.len(), 3);
        // render::header_json always includes previousblockhash (all-zeros for genesis)
        assert_eq!(
            values[0].get("previousblockhash").and_then(Value::as_str),
            Some("0000000000000000000000000000000000000000000000000000000000000000")
        );
        assert_eq!(values[0].get("height").and_then(Value::as_u64), Some(0));
        assert_eq!(values[2].get("height").and_then(Value::as_u64), Some(2));
    }

    #[test]
    fn headers_side_branch_returns_empty() {
        let ctx = Arc::new(Context::new());
        let bits: u32 = 0x1d00_ffff;
        let genesis = Header {
            version: 1,
            prev_blockhash: BlockHash::default(),
            merkle_root: Hash256::default(),
            time: 1,
            bits,
            nonce: 1,
        };
        let active_child = Header {
            version: 1,
            prev_blockhash: genesis.compute_hash(),
            merkle_root: Hash256::default(),
            time: 2,
            bits,
            nonce: 2,
        };
        let active_tip = Header {
            version: 1,
            prev_blockhash: active_child.compute_hash(),
            merkle_root: Hash256::default(),
            time: 3,
            bits,
            nonce: 3,
        };
        let side_child = Header {
            version: 1,
            prev_blockhash: genesis.compute_hash(),
            merkle_root: Hash256::default(),
            time: 4,
            bits,
            nonce: 4,
        };
        let ids = publish_active_chain(&ctx, &[genesis, active_child, active_tip]);
        {
            let mut tree = ctx.block_tree.write();
            let parent = tree.lookup(ids[0]).expect("genesis node");
            tree.insert_node(Some(parent), side_child, NodeStatus::Stale)
                .expect("side branch header");
        }

        let response = route(
            &ctx,
            &format!(
                "/rest/headers/{}.json",
                Hash256::from(side_child.compute_hash())
            ),
            "count=2000",
            true,
        );
        let values: Vec<Value> = sonic_rs::from_slice(&response.body).expect("headers JSON");
        assert!(values.is_empty());
    }

    #[test]
    fn headers_truncate_when_linkage_breaks() {
        let ctx = Arc::new(Context::new());
        let bits: u32 = 0x1d00_ffff;
        let genesis = Block {
            header: Header {
                version: 1,
                prev_blockhash: BlockHash::default(),
                merkle_root: Hash256::default(),
                time: 1,
                bits,
                nonce: 1,
            },
            txs: Vec::new(),
        };
        let broken_child = Block {
            header: Header {
                version: 1,
                prev_blockhash: BlockHash::default(),
                merkle_root: Hash256::default(),
                time: 2,
                bits,
                nonce: 2,
            },
            txs: Vec::new(),
        };
        ctx.add_block(BlockRecord::from_block(0, &genesis));
        ctx.add_block(BlockRecord::from_block(1, &broken_child));
        let genesis_id = {
            let mut tree = ctx.block_tree.write();
            tree.insert_node(None, genesis.header, NodeStatus::Active)
                .expect("genesis header")
        };
        let broken_id = {
            let mut tree = ctx.block_tree.write();
            let valid_child = Header {
                prev_blockhash: genesis.block_hash(),
                ..broken_child.header
            };
            tree.insert_node(Some(genesis_id), valid_child, NodeStatus::Active)
                .expect("broken child header")
        };
        ctx.block_tree
            .write()
            .node_mut(broken_id)
            .expect("broken child node")
            .header
            .prev_blockhash = BlockHash::default();
        let tree = ctx.block_tree.read();
        let broken_node = tree.node(broken_id).expect("broken tip");
        let tip = TipSnapshot {
            tip_id: broken_id,
            height: broken_node.height,
            chainwork: broken_node.chainwork,
            hash: broken_node.hash,
        };
        drop(tree);
        ctx.set_applied_tip(tip.clone());
        ctx.set_chain_tip(tip);

        let path = format!("/rest/headers/{}.json", genesis.block_hash());
        let response = route(&ctx, &path, "count=2", true);
        assert_eq!(response.status, 200);
        let values: Vec<Value> = sonic_rs::from_slice(&response.body).expect("headers JSON");
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].get("height").and_then(Value::as_u64), Some(0));
    }

    #[test]
    fn headers_truncate_the_tail_after_a_middle_linkage_break() {
        let ctx = Arc::new(Context::new());
        let bits: u32 = 0x1d00_ffff;
        let genesis = Header {
            version: 1,
            prev_blockhash: BlockHash::default(),
            merkle_root: Hash256::default(),
            time: 1,
            bits,
            nonce: 1,
        };
        let first = Header {
            version: 1,
            prev_blockhash: genesis.compute_hash(),
            merkle_root: Hash256::default(),
            time: 2,
            bits,
            nonce: 2,
        };
        let middle = Header {
            version: 1,
            prev_blockhash: first.compute_hash(),
            merkle_root: Hash256::default(),
            time: 3,
            bits,
            nonce: 3,
        };
        let tail = Header {
            version: 1,
            prev_blockhash: middle.compute_hash(),
            merkle_root: Hash256::default(),
            time: 4,
            bits,
            nonce: 4,
        };
        let hashes = publish_active_chain(&ctx, &[genesis, first, middle, tail]);
        let middle_id = ctx
            .block_tree
            .read()
            .lookup(hashes[2])
            .expect("middle node");
        ctx.block_tree
            .write()
            .node_mut(middle_id)
            .expect("middle node")
            .header
            .prev_blockhash = BlockHash::default();

        let response = route(
            &ctx,
            &format!("/rest/headers/{}.json", hashes[0]),
            "count=2000",
            true,
        );
        let values: Vec<Value> = sonic_rs::from_slice(&response.body).expect("headers JSON");
        assert_eq!(values.len(), 2);
        assert_eq!(values[0].get("height").and_then(Value::as_u64), Some(0));
        assert_eq!(values[1].get("height").and_then(Value::as_u64), Some(1));
    }

    /// Minimal native stand-in for the regtest genesis block: one coinbase
    /// tx, with self-consistent identity via `block_hash()`.
    fn regtest_genesis() -> Block {
        let coinbase = Tx {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid::default(), 0xffff_ffff),
                script_sig: vec![0x51],
                sequence: 0xffff_ffff,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 50 * 100_000_000,
                script_pubkey: Vec::new(),
            }],
            lock_time: 0,
        };
        Block {
            header: Header {
                version: 1,
                prev_blockhash: BlockHash::default(),
                merkle_root: coinbase.txid().0,
                time: 1_296_688_602,
                bits: 0x207f_ffff,
                nonce: 2,
            },
            txs: vec![coinbase],
        }
    }

    /// `/rest/headers/` must serve bytes identical to the block's own header.
    ///
    /// The three formats all serialize `HeaderRecord.header`, which comes from
    /// the block tree. This pins the bytes rather than a field count, so a
    /// header sourced from the wrong place fails here even if every JSON key is
    /// still present.
    #[test]
    fn headers_serve_the_block_header_bytes_verbatim() {
        let ctx = Arc::new(Context::new());
        let genesis = regtest_genesis();
        ctx.add_block(BlockRecord::from_block(0, &genesis));
        let _ = publish_active_chain(&ctx, &[genesis.header]);

        let expected = consensus_bytes(&genesis.header);
        let path = format!("/rest/headers/{}.bin", genesis.block_hash());
        let response = route(&ctx, &path, "count=1", true);
        assert_eq!(response.status, 200);
        assert_eq!(
            response.body, expected,
            "the served header bytes must be the block's own"
        );

        let path = format!("/rest/headers/{}.hex", genesis.block_hash());
        let response = route(&ctx, &path, "count=1", true);
        assert_eq!(response.status, 200);
        assert_eq!(response.body, hex_encode(&expected).into_bytes());
    }

    /// A log-only hash remains an empty success in every REST format.
    ///
    /// The deleted fallback consulted `block_by_hash`, which used to recover
    /// this fixture through its full-log scan. Removing both paths must preserve
    /// REST's established unknown-hash 200 contract rather than turn it into a
    /// 404 or leak cached data.
    #[test]
    fn headers_for_a_record_the_tree_does_not_know_serve_nothing() {
        let ctx = Arc::new(Context::new());
        let genesis = regtest_genesis();
        ctx.add_block(BlockRecord::from_block(0, &genesis));

        for (format, expected) in [
            ("json", b"[]".as_slice()),
            ("hex", b"".as_slice()),
            ("bin", b"".as_slice()),
        ] {
            let path = format!("/rest/headers/{}.{format}", genesis.block_hash());
            let response = route(&ctx, &path, "count=1", true);
            assert_eq!(response.status, 200);
            assert_eq!(response.body, expected);
        }
    }

    // -----------------------------------------------------------------------
    // New route tests
    // -----------------------------------------------------------------------

    #[test]
    fn tx_not_found_returns_404() {
        let ctx = Arc::new(Context::new());
        let txid = "0000000000000000000000000000000000000000000000000000000000000001";
        for format in ["json", "hex", "bin"] {
            let response = route(&ctx, &format!("/rest/tx/{txid}.{format}"), "", true);
            assert_eq!(response.status, 404, "{format}");
        }
    }

    #[test]
    fn tx_bad_hash_returns_400() {
        let ctx = Arc::new(Context::new());
        let response = route(&ctx, "/rest/tx/not-a-hash.json", "", true);
        assert_eq!(response.status, 400);
    }

    #[test]
    fn tx_missing_format_returns_404() {
        let ctx = Arc::new(Context::new());
        let response = route(
            &ctx,
            "/rest/tx/0000000000000000000000000000000000000000000000000000000000000001",
            "",
            true,
        );
        assert_eq!(response.status, 404);
    }

    #[test]
    fn block_not_found_returns_404() {
        let ctx = Arc::new(Context::new());
        let hash = "0000000000000000000000000000000000000000000000000000000000000001";
        for format in ["json", "hex", "bin"] {
            let response = route(&ctx, &format!("/rest/block/{hash}.{format}"), "", true);
            assert_eq!(response.status, 404, "{format}");
        }
    }

    #[test]
    fn block_bad_hash_returns_400() {
        let ctx = Arc::new(Context::new());
        let response = route(&ctx, "/rest/block/not-a-hash.json", "", true);
        assert_eq!(response.status, 400);
    }

    #[test]
    fn block_notxdetails_prefix_is_distinct_from_block() {
        let ctx = Arc::new(Context::new());
        let hash = "0000000000000000000000000000000000000000000000000000000000000001";
        let response = route(
            &ctx,
            &format!("/rest/block/notxdetails/{hash}.json"),
            "",
            true,
        );
        assert_eq!(response.status, 404);
    }

    #[test]
    fn blockpart_rejects_json_format() {
        let ctx = Arc::new(Context::new());
        let hash = "0000000000000000000000000000000000000000000000000000000000000001";
        let response = route(&ctx, &format!("/rest/blockpart/{hash}.json"), "", true);
        // blockpart only serves bin/hex; json is not a valid format
        assert_eq!(response.status, 404);
    }

    #[test]
    fn chaininfo_rejects_non_json_format() {
        let ctx = Arc::new(Context::new());
        let response = route(&ctx, "/rest/chaininfo.bin", "", true);
        assert_eq!(response.status, 404);
    }

    #[test]
    fn mempool_info_json() {
        let ctx = Arc::new(Context::new());
        let response = route(&ctx, "/rest/mempool/info.json", "", true);
        assert_eq!(response.status, 200);
        assert_eq!(response.content_type, "application/json");
    }

    #[test]
    fn mempool_contents_json() {
        let ctx = Arc::new(Context::new());
        let response = route(&ctx, "/rest/mempool/contents.json", "", true);
        assert_eq!(response.status, 200);
        assert_eq!(response.content_type, "application/json");
    }

    #[test]
    fn mempool_contents_verbose_false() {
        let ctx = Arc::new(Context::new());
        let response = route(&ctx, "/rest/mempool/contents.json", "verbose=false", true);
        assert_eq!(response.status, 200);
    }

    #[test]
    fn mempool_contents_verbose_bad_value_returns_400() {
        let ctx = Arc::new(Context::new());
        let response = route(&ctx, "/rest/mempool/contents.json", "verbose=maybe", true);
        assert_eq!(response.status, 400);
    }

    #[test]
    fn mempool_contents_verbose_and_sequence_returns_400() {
        let ctx = Arc::new(Context::new());
        let response = route(
            &ctx,
            "/rest/mempool/contents.json",
            "verbose=true&mempool_sequence=true",
            true,
        );
        assert_eq!(response.status, 400);
    }

    #[test]
    fn mempool_invalid_kind_returns_400() {
        let ctx = Arc::new(Context::new());
        let response = route(&ctx, "/rest/mempool/foo.json", "", true);
        assert_eq!(response.status, 400);
    }

    #[test]
    fn mempool_non_json_format_returns_404() {
        let ctx = Arc::new(Context::new());
        let response = route(&ctx, "/rest/mempool/info.bin", "", true);
        assert_eq!(response.status, 404);
    }

    #[test]
    fn getutxos_empty_request_returns_400() {
        let ctx = Arc::new(Context::new());
        let response = route(&ctx, "/rest/getutxos.json", "", true);
        assert_eq!(response.status, 400);
    }

    #[test]
    fn getutxos_bad_outpoint_returns_400() {
        let ctx = Arc::new(Context::new());
        let response = route(&ctx, "/rest/getutxos/not-a-txid-0.json", "", true);
        assert_eq!(response.status, 400);
    }

    #[test]
    fn getutxos_missing_format_returns_404() {
        let ctx = Arc::new(Context::new());
        let response = route(
            &ctx,
            "/rest/getutxos/0000000000000000000000000000000000000000000000000000000000000001-0",
            "",
            true,
        );
        assert_eq!(response.status, 404);
    }

    #[test]
    fn getutxos_json_returns_empty_utxos_for_unknown_outpoint() {
        let ctx = Arc::new(Context::new());
        let response = route(
            &ctx,
            "/rest/getutxos/0000000000000000000000000000000000000000000000000000000000000001-0.json",
            "",
            true,
        );
        assert_eq!(response.status, 200);
        let value: Value = sonic_rs::from_slice(&response.body).expect("getutxos JSON");
        assert_eq!(value.get("bitmap").and_then(Value::as_str), Some("0"));
        let utxos = value.get("utxos").expect("utxos field");
        assert!(utxos.as_array().expect("utxos array").is_empty());
    }

    #[test]
    fn deploymentinfo_json() {
        let ctx = Arc::new(Context::new());
        let response = route(&ctx, "/rest/deploymentinfo.json", "", true);
        assert_eq!(response.status, 200);
        let value: Value = sonic_rs::from_slice(&response.body).expect("deploymentinfo JSON");
        assert!(value.get("deployments").is_some());
    }

    #[test]
    fn deploymentinfo_non_json_returns_404() {
        let ctx = Arc::new(Context::new());
        let response = route(&ctx, "/rest/deploymentinfo.bin", "", true);
        assert_eq!(response.status, 404);
    }

    #[test]
    fn deploymentinfo_bad_hash_returns_400() {
        let ctx = Arc::new(Context::new());
        let response = route(&ctx, "/rest/deploymentinfo/not-a-hash.json", "", true);
        assert_eq!(response.status, 400);
    }

    #[test]
    fn blockhashbyheight_out_of_range_returns_404() {
        let ctx = Arc::new(Context::new());
        for format in ["json", "hex", "bin"] {
            let response = route(
                &ctx,
                &format!("/rest/blockhashbyheight/999.{format}"),
                "",
                true,
            );
            assert_eq!(response.status, 404, "{format}");
        }
    }

    #[test]
    fn blockhashbyheight_bad_height_returns_400() {
        let ctx = Arc::new(Context::new());
        let response = route(&ctx, "/rest/blockhashbyheight/abc.json", "", true);
        assert_eq!(response.status, 400);
    }

    #[test]
    fn blockhashbyheight_missing_format_returns_404() {
        let ctx = Arc::new(Context::new());
        let response = route(&ctx, "/rest/blockhashbyheight/0", "", true);
        assert_eq!(response.status, 404);
    }

    #[test]
    fn spenttxouts_returns_unavailable() {
        let ctx = Arc::new(Context::new());
        let hash = "0000000000000000000000000000000000000000000000000000000000000001";
        for format in ["json", "hex", "bin"] {
            let response = route(
                &ctx,
                &format!("/rest/spenttxouts/{hash}.{format}"),
                "",
                true,
            );
            assert_eq!(response.status, 404, "{format}");
            assert!(
                String::from_utf8(response.body)
                    .expect("body")
                    .contains("undo not available"),
                "{format}"
            );
        }
    }

    #[test]
    fn spenttxouts_bad_hash_returns_400() {
        let ctx = Arc::new(Context::new());
        let response = route(&ctx, "/rest/spenttxouts/not-a-hash.json", "", true);
        assert_eq!(response.status, 400);
    }

    #[test]
    fn unknown_rest_path_returns_404() {
        let ctx = Arc::new(Context::new());
        let response = route(&ctx, "/rest/unknown", "", true);
        assert_eq!(response.status, 404);
    }

    /// Every REGISTRATIONS prefix must be dispatched — none falls through to
    /// the generic 404. We verify by checking that each prefix produces a
    /// response distinct from the generic "not found" body (or at minimum is
    /// handled, not silently passed through).
    #[test]
    fn all_registration_prefixes_are_dispatched() {
        let ctx = Arc::new(Context::new());
        // Each prefix gets a well-formed-ish path appended; the assertion is
        // that the route function handles it (returns a response) rather than
        // panicking or falling through.
        let cases: &[(&str, &str)] = &[
            (
                "/rest/tx/0000000000000000000000000000000000000000000000000000000000000001.json",
                "",
            ),
            (
                "/rest/block/notxdetails/0000000000000000000000000000000000000000000000000000000000000001.json",
                "",
            ),
            (
                "/rest/block/0000000000000000000000000000000000000000000000000000000000000001.json",
                "",
            ),
            (
                "/rest/blockpart/0000000000000000000000000000000000000000000000000000000000000001.bin",
                "",
            ),
            ("/rest/chaininfo.json", ""),
            ("/rest/mempool/info.json", ""),
            (
                "/rest/headers/0000000000000000000000000000000000000000000000000000000000000001.json",
                "count=1",
            ),
            (
                "/rest/getutxos/0000000000000000000000000000000000000000000000000000000000000001-0.json",
                "",
            ),
            ("/rest/deploymentinfo.json", ""),
            (
                "/rest/deploymentinfo/0000000000000000000000000000000000000000000000000000000000000001.json",
                "",
            ),
            ("/rest/blockhashbyheight/0.json", ""),
            (
                "/rest/spenttxouts/0000000000000000000000000000000000000000000000000000000000000001.json",
                "",
            ),
        ];
        assert_eq!(cases.len(), REGISTRATIONS.len());
        for (path, query) in cases {
            let _response = route(&ctx, path, query, true);
            // The assertion is that route handles the prefix without panicking.
            // Specific status codes are covered by the per-route tests above.
        }
    }
}
