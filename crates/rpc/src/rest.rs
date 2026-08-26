//! Bitcoin Core-compatible REST surface used by remote clients.
//!
//! The fourteen route prefixes mirror Core's `StartREST` registration table.
//! JSON projections come from [`crate::render`] and [`crate::tx_render`]; hex
//! and binary payloads use consensus serialization. Applied-chain membership is
//! always resolved through [`crate::context::Context`] ancestry facts — never
//! from the header tip alone.

use alloc::sync::Arc;
use core::ops::Deref;
use std::str::FromStr;

use bitcoin::block::Header;
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::Hash as _;
use bitcoin::hex::DisplayHex as _;
use bitcoin::{Block, Network, Txid};
use bitcoin_rs_primitives::Hash256;
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

/// The Bitcoin Core REST prefixes registered by `StartREST`.
pub const REGISTRATIONS: [&str; 14] = [
    "/rest/tx/",
    "/rest/block/notxdetails/",
    "/rest/block/",
    "/rest/blockpart/",
    "/rest/blockfilter/",
    "/rest/blockfilterheaders/",
    "/rest/chaininfo",
    "/rest/mempool/",
    "/rest/headers/",
    "/rest/getutxos",
    "/rest/deploymentinfo/",
    "/rest/deploymentinfo",
    "/rest/blockhashbyheight/",
    "/rest/spenttxouts/",
];

const CACHE_IMMUTABLE: &str = "public, immutable, max-age=86400";
const CACHE_NO_STORE: &str = "no-store";

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

/// REST-specific transport metadata layered over the shared HTTP response.
#[derive(Debug, Eq, PartialEq)]
pub struct RestResponse {
    response: Response,
    /// Cache policy emitted as `Cache-Control`.
    pub cache_control: &'static str,
    /// Length of the corresponding GET body (also used for HEAD).
    pub content_length: usize,
}

impl Deref for RestResponse {
    type Target = Response;

    fn deref(&self) -> &Self::Target {
        &self.response
    }
}

impl RestResponse {
    fn new(mut response: Response, cache_control: &'static str, head: bool) -> Self {
        let content_length = response.body.len();
        if head {
            response.body.clear();
        }
        Self {
            response,
            cache_control,
            content_length,
        }
    }
}

#[derive(Clone)]
struct HeaderRecord {
    hash: Hash256,
    height: u32,
    header: Header,
}

/// Routes one REST GET request.
#[must_use]
pub fn route(ctx: &Arc<Context>, path: &str, query: &str, enabled: bool) -> RestResponse {
    route_method(ctx, path, query, enabled, "GET")
}

/// Routes one REST request, preserving GET metadata for HEAD.
#[must_use]
pub fn route_method(
    ctx: &Arc<Context>,
    path: &str,
    query: &str,
    enabled: bool,
    method: &str,
) -> RestResponse {
    let head = method == "HEAD";
    if !enabled {
        return RestResponse::new(not_found(), CACHE_NO_STORE, head);
    }
    if !matches!(method, "GET" | "HEAD") {
        return RestResponse::new(method_not_allowed(), CACHE_NO_STORE, head);
    }

    let (response, cache) = dispatch(ctx, path, query);
    let cache = if response.status == 200 {
        cache
    } else {
        CACHE_NO_STORE
    };
    RestResponse::new(response, cache, head)
}

fn dispatch(ctx: &Arc<Context>, path: &str, query: &str) -> (Response, &'static str) {
    if let Some(suffix) = path.strip_prefix("/rest/tx/") {
        return (route_tx(ctx, suffix), CACHE_NO_STORE);
    }
    if let Some(suffix) = path.strip_prefix("/rest/block/notxdetails/") {
        return (
            route_block(ctx, suffix, false),
            cache_for_block_format(suffix),
        );
    }
    if let Some(suffix) = path.strip_prefix("/rest/blockpart/") {
        return (
            route_block_part(ctx, suffix),
            cache_for_block_format(suffix),
        );
    }
    if let Some(suffix) = path.strip_prefix("/rest/blockfilterheaders/") {
        return (route_filter_headers(ctx, suffix, query), CACHE_NO_STORE);
    }
    if let Some(suffix) = path.strip_prefix("/rest/blockfilter/") {
        return (route_block_filter(ctx, suffix), CACHE_IMMUTABLE);
    }
    if let Some(suffix) = path.strip_prefix("/rest/block/") {
        return (
            route_block(ctx, suffix, true),
            cache_for_block_format(suffix),
        );
    }
    if path.starts_with("/rest/chaininfo") {
        return (route_chaininfo(ctx, path), CACHE_NO_STORE);
    }
    if let Some(suffix) = path.strip_prefix("/rest/mempool/") {
        return (route_mempool(ctx, suffix, query), CACHE_NO_STORE);
    }
    if let Some(suffix) = path.strip_prefix("/rest/headers/") {
        return (route_headers(ctx, suffix, query), CACHE_NO_STORE);
    }
    if let Some(suffix) = path.strip_prefix("/rest/getutxos") {
        return (route_getutxos(ctx, suffix), CACHE_NO_STORE);
    }
    if let Some(suffix) = path.strip_prefix("/rest/deploymentinfo") {
        return (route_deploymentinfo(ctx, suffix), CACHE_NO_STORE);
    }
    if let Some(suffix) = path.strip_prefix("/rest/blockhashbyheight/") {
        return (route_blockhash_by_height(ctx, suffix), CACHE_NO_STORE);
    }
    if let Some(suffix) = path.strip_prefix("/rest/spenttxouts/") {
        return (route_spent_txouts(suffix), CACHE_IMMUTABLE);
    }
    (not_found(), CACHE_NO_STORE)
}

fn cache_for_block_format(suffix: &str) -> &'static str {
    if ends_with_format(suffix, "bin") || ends_with_format(suffix, "hex") {
        CACHE_IMMUTABLE
    } else {
        CACHE_NO_STORE
    }
}

fn ends_with_format(suffix: &str, format: &str) -> bool {
    match suffix.rsplit_once('.') {
        Some((_, ext)) => ext == format,
        None => false,
    }
}

/// Splits an endpoint suffix into its text portion and trailing data format.
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

/// Core: `/rest/tx/<txid>.<ext>`.
fn route_tx(ctx: &Arc<Context>, suffix: &str) -> Response {
    let (hash_text, format) = split_format(suffix);
    let Some(format) = format else {
        return format_not_found(available_formats());
    };
    let Ok(txid) = Txid::from_str(hash_text) else {
        return bad_request_owned(format!("Invalid hash: {hash_text}"));
    };
    let txid_text = txid.to_string();
    // Verbose RPC projection reuses the canonical tx renderer, so REST and RPC
    // agree on field names and units; hex/bin reuse its consensus hex.
    let value = match getrawtransaction(ctx, &json!([txid_text, true])) {
        Ok(value) => value,
        Err(RpcError::NotFound(_)) => return not_found_owned(format!("{txid_text} not found")),
        Err(error) => return json_response(Err(error)),
    };
    let hex = value.get("hex").and_then(Value::as_str).unwrap_or_default();
    match format {
        "json" => text_response("application/json", sonic_bytes(&value)),
        "hex" => text_response("text/plain", format!("{hex}\n").into_bytes()),
        "bin" => {
            let bytes: Vec<u8> = bitcoin::hex::FromHex::from_hex(hex).unwrap_or_default();
            binary_response("application/octet-stream", &bytes)
        }
        _ => format_not_found(available_formats()),
    }
}

/// Core: `/rest/block/<hash>.<ext>` (full tx details) and
/// `/rest/block/notxdetails/<hash>.<ext>` (txid-only).
fn route_block(ctx: &Arc<Context>, suffix: &str, with_details: bool) -> Response {
    let (hash_text, format) = split_format(suffix);
    let Some(format) = format else {
        return format_not_found(available_formats());
    };
    let Ok(hash) = Hash256::from_str(hash_text) else {
        return bad_request_owned(format!("Invalid hash: {hash_text}"));
    };
    let Some(record) = ctx.record_for_hash(hash) else {
        return not_found_owned(format!("{hash_text} not found"));
    };
    let Some(body) = ctx.block_body_bytes(&record) else {
        return not_found_owned(format!("{hash_text} not available (pruned data)"));
    };
    match format {
        "bin" => binary_response("application/octet-stream", &body),
        "hex" => text_response(
            "text/plain",
            format!("{}\n", body.to_lower_hex_string()).into_bytes(),
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
            let value = crate::render::block_json(
                &block,
                &context,
                verbosity,
                bitcoin_network(ctx.chain_network),
            );
            text_response("application/json", sonic_bytes(&value))
        }
        _ => format_not_found(available_formats()),
    }
}

/// Core `/rest/blockpart/<hash>.<ext>` serves raw block payload bytes (hex or
/// binary only), matching Core's original part endpoint which rejected JSON.
fn route_block_part(ctx: &Arc<Context>, suffix: &str) -> Response {
    let (hash_text, format) = split_format(suffix);
    let Some(format) = format else {
        return format_not_found(available_formats());
    };
    let Ok(hash) = Hash256::from_str(hash_text) else {
        return bad_request_owned(format!("Invalid hash: {hash_text}"));
    };
    let Some(record) = ctx.record_for_hash(hash) else {
        return not_found_owned(format!("{hash_text} not found"));
    };
    let Some(body) = ctx.block_body_bytes(&record) else {
        return not_found_owned(format!("{hash_text} not available (pruned data)"));
    };
    match format {
        "bin" => binary_response("application/octet-stream", &body),
        "hex" => text_response(
            "text/plain",
            format!("{}\n", body.to_lower_hex_string()).into_bytes(),
        ),
        _ => format_not_found(available_formats()),
    }
}

/// Core `/rest/blockfilter/<filtertype>/<hash>.<ext>`.
fn route_block_filter(ctx: &Arc<Context>, suffix: &str) -> Response {
    let (rest, format) = split_format(suffix);
    let Some(format) = format else {
        return format_not_found(available_formats());
    };
    let mut parts = rest.split('/');
    let filter_type = parts.next().unwrap_or_default();
    let hash_text = parts.next().unwrap_or_default();
    if parts.next().is_some() || hash_text.is_empty() {
        return bad_request(
            "Invalid URI format. Expected /rest/blockfilter/<filtertype>/<blockhash>",
        );
    }
    if filter_type != "basic" {
        return bad_request_owned(format!("Unknown filtertype {filter_type}"));
    }
    let Ok(hash) = Hash256::from_str(hash_text) else {
        return bad_request_owned(format!("Invalid hash: {hash_text}"));
    };
    if !ctx.filter_index.wants_filters() {
        return bad_request_owned(format!("Index is not enabled for filtertype {filter_type}"));
    }
    if ctx.record_for_hash(hash).is_none() {
        return not_found_owned(format!("{hash_text} not found"));
    }
    let filter = match ctx.filter_index.filter(hash) {
        Ok(Some(filter)) => filter,
        Ok(None) | Err(_) => return not_found_owned("Filter not found.".to_owned()),
    };
    match format {
        "bin" => binary_response("application/octet-stream", &filter),
        "hex" => text_response(
            "text/plain",
            format!("{}\n", filter.to_lower_hex_string()).into_bytes(),
        ),
        "json" => text_response(
            "application/json",
            sonic_bytes(&json!({"filter": filter.to_lower_hex_string()})),
        ),
        _ => format_not_found(available_formats()),
    }
}

/// Core `/rest/blockfilterheaders/<filtertype>/<hash>.<ext>?count=<count>`.
fn route_filter_headers(ctx: &Arc<Context>, suffix: &str, query: &str) -> Response {
    let (rest, format) = split_format(suffix);
    let Some(format) = format else {
        return format_not_found(available_formats());
    };
    let mut parts = rest.split('/');
    let filter_type = parts.next().unwrap_or_default();
    let hash_text = parts.next().unwrap_or_default();
    if parts.next().is_some() || hash_text.is_empty() {
        return bad_request(
            "Invalid URI format. Expected /rest/blockfilterheaders/<filtertype>/<blockhash>",
        );
    }
    if filter_type != "basic" {
        return bad_request_owned(format!("Unknown filtertype {filter_type}"));
    }
    let count = match parse_count(query) {
        Ok(count) => count,
        Err(response) => return response,
    };
    let Ok(hash) = Hash256::from_str(hash_text) else {
        return bad_request_owned(format!("Invalid hash: {hash_text}"));
    };
    let headers = header_records(ctx, hash, count);
    let mut filter_headers = Vec::with_capacity(headers.len());
    for record in &headers {
        match ctx.filter_index.filter_header(record.hash) {
            Ok(Some(header)) => filter_headers.push(header),
            Ok(None) | Err(_) => {
                return not_found_owned(
                    "Filter not found. Block filters are still in the process of being indexed."
                        .to_owned(),
                );
            }
        }
    }
    let body = filter_headers.iter().fold(
        Vec::with_capacity(filter_headers.len() * 32),
        |mut body, header| {
            body.extend_from_slice(&header.to_le_bytes());
            body
        },
    );
    match format {
        "bin" => binary_response("application/octet-stream", &body),
        "hex" => text_response(
            "text/plain",
            format!("{}\n", body.to_lower_hex_string()).into_bytes(),
        ),
        "json" => {
            let values = filter_headers
                .iter()
                .map(|header| json!(header.to_string_be()))
                .collect::<Vec<_>>();
            text_response("application/json", sonic_bytes(&Value::from(values)))
        }
        _ => format_not_found(available_formats()),
    }
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
        _ => bad_request("Invalid URI format. Expected /rest/mempool/<info|contents>.json"),
    }
}

/// Core `/rest/headers/<hash>.<ext>?count=<count>`.
fn route_headers(ctx: &Arc<Context>, suffix: &str, query: &str) -> Response {
    let (hash_text, format) = split_format(suffix);
    let Some(format) = format else {
        return format_not_found(available_formats());
    };
    if !matches!(format, "json" | "hex" | "bin") {
        return bad_request_owned(format!("Invalid hash: {hash_text}"));
    }
    let count = match parse_count(query) {
        Ok(count) => count,
        Err(response) => return response,
    };
    let Ok(hash) = Hash256::from_str(hash_text) else {
        return bad_request_owned(format!("Invalid hash: {hash_text}"));
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
                .map(|record| serialize(&record.header).to_lower_hex_string())
                .collect::<String>();
            text_response("text/plain", body.into_bytes())
        }
        "bin" => binary_response(
            "application/octet-stream",
            &records.iter().fold(Vec::new(), |mut body, record| {
                body.extend(serialize(&record.header));
                body
            }),
        ),
        _ => bad_request_owned(format!("Invalid hash: {hash_text}")),
    }
}

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
    let Some(break_index) = records.windows(2).position(|pair| {
        Hash256::from_le_bytes(pair[1].header.prev_blockhash.as_byte_array()) != pair[0].hash
    }) else {
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

/// Core `/rest/getutxos[/checkmempool]/<txid>-<n>....{bin,hex,json}`.
///
/// Only the URI-scheme input form is implemented (Core's raw-body form is not
/// served). Responses follow Core's BIP64-ish shape.
fn parse_getutxos_outpoints(path: &str) -> Result<(bool, Vec<(Hash256, u32)>), Response> {
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
        let Ok(txid) = Hash256::from_str(txid_text) else {
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

fn route_getutxos(ctx: &Arc<Context>, suffix: &str) -> Response {
    let (path, format) = split_format(suffix);
    let Some(format) = format else {
        return format_not_found(available_formats());
    };
    let (check_mempool, outpoints) = match parse_getutxos_outpoints(path) {
        Ok(request) => request,
        Err(response) => return response,
    };

    let active_height = ctx.applied_height();
    let active_hash = ctx.applied_hash();

    let mut bitmap = vec![0_u8; outpoints.len().div_ceil(8)];
    let mut outs = Vec::with_capacity(outpoints.len());
    let mut hits = Vec::with_capacity(outpoints.len());
    let pool = ctx.mempool.read();
    for (txid, vout) in &outpoints {
        let outpoint = bitcoin_rs_primitives::OutPoint::new(*txid, *vout);
        let bitcoin_outpoint = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array(txid.to_le_bytes()),
            vout: *vout,
        };
        let mempool_spent = check_mempool && pool.is_outpoint_spent(&bitcoin_outpoint);
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
                        "scriptPubKey": tx_render::script_pub_key_json(&txout.script_pubkey, bitcoin_network(ctx.chain_network))
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
                serialize_getutxos_bin(active_height, active_hash, &bitmap, &outs)
                    .to_lower_hex_string()
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

/// Serializes the getutxos response body: active height, active hash, packed
/// bitmap, then one `CCoin` (version, height, txout) per unspent output.
fn serialize_getutxos_bin(
    active_height: u32,
    active_hash: Hash256,
    bitmap: &[u8],
    outs: &[(u32, bitcoin::TxOut)],
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
        body.extend_from_slice(&serialize(txout));
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
    let Some(format) = format else {
        return format_not_found(available_formats());
    };
    let Ok(height) = height_text.parse::<u32>() else {
        return bad_request_owned(format!("Invalid height: {height_text}"));
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
    if format.is_none() {
        return format_not_found(available_formats());
    }
    if Hash256::from_str(hash_text).is_err() {
        return bad_request_owned(format!("Invalid hash: {hash_text}"));
    }
    not_found_owned(format!("{hash_text} undo not available"))
}

/// Builds the applied-chain facts [`crate::render`] needs to project a block or
/// header.
fn build_chain_context(ctx: &Context, record: &BlockRecord, header: &Header) -> BlockChainContext {
    let applied_height = ctx.applied_height();
    let on_active = ctx.active_hash_at_height(record.height) == Some(record.hash);
    let n_tx = u32::try_from(record.tx_count).unwrap_or(u32::MAX);
    BlockChainContext {
        height: record.height,
        confirmations: crate::render::confirmations(applied_height, record.height, on_active),
        mediantime: ctx.median_time_past_for_hash(record.hash).unwrap_or(0),
        difficulty: ctx.difficulty_for_bits(header.bits),
        chainwork_hex: ctx
            .chain_work_hex_for_hash(record.hash)
            .unwrap_or_else(|| "00".to_owned()),
        n_tx,
        next_block_hash: ctx
            .next_block_hash_for_height(record.height)
            .map(|hash| bitcoin::BlockHash::from_byte_array(hash.to_le_bytes())),
    }
}

/// Applied-chain facts for a header record, resolving the real record (and its
/// transaction count) through the tree/log when available.
fn header_chain_context(ctx: &Context, record: &HeaderRecord) -> BlockChainContext {
    let real = ctx.record_for_hash(record.hash).unwrap_or(BlockRecord {
        hash: record.hash,
        height: record.height,
        body_size: 0,
        header: None,
        tx_count: 0,
        time: record.header.time,
    });
    build_chain_context(ctx, &real, &record.header)
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

fn bitcoin_network(network: bitcoin_rs_primitives::Network) -> Network {
    crate::bitcoin_network(network)
}

fn sonic_bytes(value: &Value) -> Vec<u8> {
    sonic_rs::to_string(value)
        .unwrap_or_else(|_| "null".to_owned())
        .into_bytes()
}

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

fn method_not_allowed() -> Response {
    Response {
        status: 405,
        reason: "Method Not Allowed",
        content_type: "text/plain",
        body: b"method not allowed".to_vec(),
    }
}
