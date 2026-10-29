use alloc::sync::Arc;
use std::str::FromStr;

use bitcoin::hex::{DisplayHex as _, FromHex as _};
use bitcoin_rs_primitives::{
    Block, BlockHash, Hash256, Header, TxOut, Txid, consensus_bytes, deserialize,
};

#[cfg(test)]
use bitcoin_rs_primitives::{Amount, CompactTarget, LockTime, Script, Sequence, Witness};
use sonic_rs::{JsonValueTrait as _, Value, json};

use crate::context::{AppliedView, Context};
use crate::error::RpcError;
use crate::handlers::chain::getblockchaininfo;
use crate::handlers::mempool::{getmempoolinfo, getrawmempool};
use crate::handlers::tx::getrawtransaction;
use crate::render::{BlockChainContext, BlockTxVerbosity};
use crate::tx_render;
use bitcoin_rs_index::block_log::BlockRecord;

const DEFAULT_HEADER_COUNT: u32 = 5;
const MAX_HEADER_COUNT: u32 = 2_000;
const MAX_GETUTXOS_OUTPOINTS: u8 = 15;
pub(crate) const MAX_GETUTXOS_BODY_BYTES: usize = 2_048;
const MEMPOOL_HEIGHT: u32 = 0x7fff_ffff;

const MAX_REST_BLOCK_BODY_BYTES: usize = 4_000_000;

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

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub reason: &'static str,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

struct HeaderRecord {
    hash: Hash256,
    height: u32,
    header: Header,
}

#[must_use]
pub fn route(ctx: &Arc<Context>, path: &str, query: &str, enabled: bool) -> Response {
    if !enabled {
        return not_found();
    }
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
        return route_getutxos(ctx, suffix, &[]);
    }
    if let Some(suffix) = path.strip_prefix("/rest/deploymentinfo") {
        return route_deploymentinfo(ctx, suffix);
    }
    if let Some(suffix) = path.strip_prefix("/rest/blockhashbyheight/") {
        return route_blockhash_by_height(ctx, suffix);
    }
    if let Some(suffix) = path.strip_prefix("/rest/spenttxouts/") {
        return route_spent_txouts(ctx, suffix);
    }
    not_found()
}

pub(crate) fn getutxos_suffix(path: &str) -> Option<&str> {
    path.strip_prefix("/rest/getutxos")
        .filter(|suffix| suffix.is_empty() || suffix.starts_with(['/', '.']))
}

#[must_use]
pub fn route_post(ctx: &Arc<Context>, path: &str, body: &[u8], enabled: bool) -> Response {
    if !enabled {
        return not_found();
    }
    let Some(suffix) = getutxos_suffix(path) else {
        return not_found();
    };
    if body.len() > MAX_GETUTXOS_BODY_BYTES {
        return getutxos_body_too_large();
    }
    route_getutxos(ctx, suffix, body)
}

pub(crate) fn getutxos_body_too_large() -> Response {
    bad_request(format!(
        "getutxos request body exceeds {MAX_GETUTXOS_BODY_BYTES} bytes"
    ))
}

fn route_tx(ctx: &Arc<Context>, suffix: &str) -> Response {
    let (hash_text, format) = split_format(suffix);
    let Ok(txid) = Txid::from_str(hash_text) else {
        return bad_request(format!("Invalid hash: {hash_text}"));
    };
    let Some(format) = format else {
        return format_not_found(available_formats());
    };
    let txid_text = txid.to_string();
    match format {
        "json" => match getrawtransaction(ctx, &json!([txid_text, true])) {
            Ok(value) => text_response("application/json", sonic_bytes(&value)),
            Err(RpcError::NotFound(_)) => not_found_with(format!("{txid_text} not found")),
            Err(error) => json_response(Err(error)),
        },
        "hex" | "bin" => match getrawtransaction(ctx, &json!([txid_text, false])) {
            Ok(value) => {
                let hex = value.as_str().unwrap_or_default();
                if format == "hex" {
                    text_response("text/plain", format!("{hex}\n").into_bytes())
                } else {
                    let bytes = Vec::<u8>::from_hex(hex).unwrap_or_default();
                    binary_response("application/octet-stream", &bytes)
                }
            }
            Err(RpcError::NotFound(_)) => not_found_with(format!("{txid_text} not found")),
            Err(error) => json_response(Err(error)),
        },
        _ => format_not_found(available_formats()),
    }
}

fn route_block(ctx: &Arc<Context>, suffix: &str, with_details: bool) -> Response {
    let (hash_text, format) = split_format(suffix);
    let Ok(hash) = Hash256::from_str(hash_text) else {
        return bad_request(format!("Invalid hash: {hash_text}"));
    };
    let Some(format) = format else {
        return format_not_found(available_formats());
    };
    let Some(record) = ctx.chain.block_by_hash(hash) else {
        return not_found_with(format!("{hash_text} not found"));
    };
    let Some(_render) = ctx.try_acquire_block_render() else {
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
            format!("{}\n", body.to_lower_hex_string()).into_bytes(),
        ),
        "json" => {
            let block = match deserialize::<Block>(&body) {
                Ok(block) => block,
                Err(_) => return not_found_with(format!("{hash_text} not found")),
            };
            let view = ctx.chain.applied_view();
            let context = build_chain_context(ctx, &view, &record, &block.header);
            let verbosity = if with_details {
                BlockTxVerbosity::Full
            } else {
                BlockTxVerbosity::Ids
            };
            let value =
                crate::render::block_json(&block, &context, verbosity, ctx.chain.chain_network);
            text_response("application/json", sonic_bytes(&value))
        }
        _ => format_not_found(available_formats()),
    }
}

fn route_block_part(ctx: &Arc<Context>, suffix: &str) -> Response {
    let (hash_text, format) = split_format(suffix);
    let Ok(hash) = Hash256::from_str(hash_text) else {
        return bad_request(format!("Invalid hash: {hash_text}"));
    };
    let Some(format) = format else {
        return format_not_found(available_formats());
    };
    let Some(record) = ctx.chain.block_by_hash(hash) else {
        return not_found_with(format!("{hash_text} not found"));
    };
    let Some(_render) = ctx.try_acquire_block_render() else {
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
            format!("{}\n", body.to_lower_hex_string()).into_bytes(),
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
    let Some(body) = ctx.chain.block_body_bytes(record) else {
        return Err(not_found_with(format!(
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

fn route_chaininfo(ctx: &Arc<Context>, path: &str) -> Response {
    let (_, format) = split_format(path);
    if format != Some("json") {
        return format_not_found("json");
    }
    json_response(getblockchaininfo(ctx, &json!([])))
}

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

fn route_headers(ctx: &Arc<Context>, suffix: &str, query: &str) -> Response {
    let (hash_text, format) = split_format(suffix);
    let count = match parse_count(query) {
        Ok(count) => count,
        Err(response) => return response,
    };
    let Ok(hash) = Hash256::from_str(hash_text) else {
        return bad_request(format!("Invalid hash: {hash_text}"));
    };
    let Some(format) = format else {
        return not_found_with("output format not found");
    };
    let view = ctx.chain.applied_view();
    release_applied_capture();
    let records = header_records(ctx, &view, hash, count);
    match format {
        "json" => {
            let values = records
                .iter()
                .map(|record| {
                    crate::render::header_json(
                        &record.header,
                        &header_chain_context(ctx, &view, record),
                    )
                })
                .collect::<Vec<_>>();
            text_response("application/json", sonic_bytes(&Value::from(values)))
        }
        "hex" => {
            let body = records
                .iter()
                .map(|record| consensus_bytes(&record.header).to_lower_hex_string())
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
        _ => bad_request(format!("Invalid hash: {hash_text}")),
    }
}

#[cfg(test)]
std::thread_local! {
    static AFTER_APPLIED_CAPTURE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

fn release_applied_capture() {
    #[cfg(test)]
    AFTER_APPLIED_CAPTURE.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(test)]
fn arm_capture_hook(hook: impl FnOnce() + 'static) {
    AFTER_APPLIED_CAPTURE.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

fn route_getutxos(ctx: &Arc<Context>, suffix: &str, body: &[u8]) -> Response {
    let (path, format) = split_format(suffix);
    let request = if body.is_empty() {
        parse_getutxos_outpoints(path)
    } else if !path.is_empty() {
        Err(bad_request(
            "Combination of URI scheme inputs and raw post data is not allowed",
        ))
    } else {
        parse_getutxos_body(format, body)
    };
    let (check_mempool, outpoints) = match request {
        Ok(request) => request,
        Err(response) => return response,
    };
    let Some(format) = format else {
        return format_not_found(available_formats());
    };
    let entry_generation = if check_mempool {
        match ctx.mempool.gateway.stable_generation() {
            Some(generation) => Some(generation),
            None => return service_unavailable("chain generation is odd; retry"),
        }
    } else {
        None
    };
    let transition = (!check_mempool).then(|| ctx.chain.chain_transition.lock());
    let pool = check_mempool.then(|| ctx.mempool.gateway.read());
    let view = ctx.chain.applied_view();
    release_applied_capture();

    let mut outs = Vec::with_capacity(outpoints.len());
    let mut hits = Vec::with_capacity(outpoints.len());
    for (txid, vout) in &outpoints {
        let outpoint = bitcoin_rs_primitives::OutPoint::new(*txid, *vout);
        let mempool_spent = pool
            .as_ref()
            .is_some_and(|pool| pool.is_outpoint_spent(&outpoint));
        let coin = if mempool_spent {
            None
        } else if let Some(entry) = pool.as_ref().and_then(|pool| pool.entry_by_txid(txid)) {
            usize::try_from(*vout)
                .ok()
                .and_then(|index| entry.tx.outputs.get(index))
                .map(|output| (MEMPOOL_HEIGHT, output.clone()))
        } else {
            ctx.chain
                .utxo
                .get_entry(&outpoint)
                .map(|entry| (entry.height, entry.txout))
        };
        hits.push(coin.is_some());
        if let Some(coin) = coin {
            outs.push(coin);
        }
    }
    drop(pool);
    drop(transition);
    if entry_generation.is_some_and(|entry| ctx.mempool.gateway.stable_generation() != Some(entry))
    {
        return service_unavailable("chain generation is odd; retry");
    }
    getutxos_response(ctx.chain.chain_network, &view, format, &hits, &outs)
}

fn getutxos_response(
    network: bitcoin_rs_primitives::Network,
    view: &AppliedView,
    format: &str,
    hits: &[bool],
    outs: &[(u32, TxOut)],
) -> Response {
    let active_height = view.height();
    let active_hash = view.hash(network);
    let mut bitmap = vec![0_u8; hits.len().div_ceil(8)];
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
                        "value": tx_render::btc_amount_json(txout.value.to_sat()),
                        "scriptPubKey": tx_render::script_pub_key_json(&txout.script_pubkey, network)
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
                serialize_getutxos_bin(active_height, active_hash, &bitmap, outs)
                    .to_lower_hex_string()
            )
            .into_bytes(),
        ),
        "bin" => binary_response(
            "application/octet-stream",
            &serialize_getutxos_bin(active_height, active_hash, &bitmap, outs),
        ),
        _ => format_not_found(available_formats()),
    }
}

fn route_deploymentinfo(ctx: &Arc<Context>, suffix: &str) -> Response {
    let (hash_text, format) = split_format(suffix);
    if format != Some("json") {
        return format_not_found("json");
    }
    let hash = if hash_text.is_empty() {
        let view = ctx.chain.applied_view();
        release_applied_capture();
        view.hash(ctx.chain.chain_network)
    } else {
        let hash_text = hash_text.strip_prefix('/').unwrap_or(hash_text);
        let Ok(hash) = Hash256::from_str(hash_text) else {
            return bad_request(format!("Invalid hash: {hash_text}"));
        };
        hash
    };
    match crate::handlers::deployment::at_hash(ctx, hash) {
        Ok(object) => text_response("application/json", sonic_bytes(&object)),
        Err(RpcError::InvalidAddressOrKey(_)) => bad_request("Block not found"),
        Err(error) => service_unavailable(error.to_string()),
    }
}

fn route_blockhash_by_height(ctx: &Arc<Context>, suffix: &str) -> Response {
    let (height_text, format) = split_format(suffix);
    let Ok(height) = height_text.parse::<u32>() else {
        return bad_request(format!("Invalid height: {height_text}"));
    };
    let Some(format) = format else {
        return format_not_found(available_formats());
    };
    let Some(hash) = ctx.chain.block_hash_at_height(height) else {
        return not_found_with("Block height out of range");
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

fn route_spent_txouts(ctx: &Context, suffix: &str) -> Response {
    use bitcoin_rs_utxo::contract::{BlockSpendsError as E, BoundedReadError, HistoryUnavailable};
    let (hash_text, format) = split_format(suffix);
    if hash_text.contains('/') {
        return bad_request("Invalid URI format. Expected /rest/spenttxouts/<hash>.<ext>");
    }
    let Ok(hash) = Hash256::from_str(hash_text) else {
        return bad_request(format!("Invalid hash: {hash_text}"));
    };
    let format = format.unwrap_or("");
    let Some(_render) = ctx.try_acquire_block_render() else {
        return service_unavailable("too many concurrent full-block reads; retry");
    };
    let view = ctx.chain.applied_view();
    let rows = if hash == ctx.chain.chain_network.genesis_block_hash() {
        vec![Vec::new()]
    } else {
        let Some(source) = &ctx.chain.block_undo_source else {
            return if ctx.chain.height_for_hash(hash).is_some() {
                not_found_with(format!("{hash_text} undo not available"))
            } else {
                not_found_with(format!("{hash_text} not found"))
            };
        };
        match source.block_spends(hash, view.hash(ctx.chain.chain_network)) {
            Ok(result) => match result.spent {
                Ok(spent) => spent,
                Err(
                    reason @ (HistoryUnavailable::Reserved { .. } | HistoryUnavailable::Shutdown),
                ) => return service_unavailable(reason.to_string()),
                Err(HistoryUnavailable::Missing | HistoryUnavailable::Pruned { .. }) => {
                    return not_found_with(format!("{hash_text} undo not available"));
                }
            },
            Err(E::UnknownBlock) => return not_found_with(format!("{hash_text} not found")),
            Err(
                error @ (E::Retry
                | E::Closed
                | E::ResourceLimit
                | E::BodyRead(_)
                | E::BoundedRead(
                    BoundedReadError::Unsupported | BoundedReadError::Limit { .. },
                )
                | E::History(
                    HistoryUnavailable::Reserved { .. }
                    | HistoryUnavailable::Missing
                    | HistoryUnavailable::Shutdown,
                )),
            ) => {
                return service_unavailable(error.to_string());
            }
            Err(_) => return not_found_with(format!("{hash_text} undo not available")),
        }
    };
    match format {
        "json" => {
            let rows = rows.iter().map(|coins| coins.iter().map(|coin| json!({
                "value": tx_render::btc_amount_json(coin.txout.value.to_sat()),
                "scriptPubKey": tx_render::script_pub_key_json(&coin.txout.script_pubkey, ctx.chain.chain_network)
            })).collect::<Vec<_>>()).collect::<Vec<_>>();
            let mut body = sonic_bytes(&json!(rows));
            body.push(b'\n');
            text_response("application/json", body)
        }
        "hex" | "bin" => {
            let mut bytes = Vec::new();
            append_compact_size(&mut bytes, rows.len());
            for coins in rows {
                append_compact_size(&mut bytes, coins.len());
                for coin in coins {
                    bytes.extend_from_slice(&consensus_bytes(&coin.txout));
                }
            }
            if format == "hex" {
                text_response(
                    "text/plain",
                    format!("{}\n", bytes.to_lower_hex_string()).into_bytes(),
                )
            } else {
                binary_response("application/octet-stream", &bytes)
            }
        }
        _ => format_not_found(available_formats()),
    }
}

fn header_records(
    ctx: &Context,
    view: &AppliedView,
    hash: Hash256,
    count: u32,
) -> Vec<HeaderRecord> {
    let tree = ctx.chain.block_tree.read();
    if let Some(start_id) = tree.lookup(hash)
        && let Ok(start_node) = tree.node(start_id)
    {
        let start = HeaderRecord {
            hash: start_node.hash,
            height: start_node.height,
            header: start_node.header,
        };
        let Some(tip) = view.tip() else {
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
    bad_request(format!(
        "Header count is invalid or out of acceptable range (1-2000): {value}"
    ))
}

fn parse_getutxos_body(
    format: Option<&str>,
    body: &[u8],
) -> Result<(bool, Vec<(Txid, u32)>), Response> {
    use bitcoin::consensus::Decodable as _;
    use bitcoin::hashes::Hash as _;

    let decoded;
    let bytes = match format {
        Some("bin") => body,
        Some("hex") => {
            let text = core::str::from_utf8(body).map_err(|_| bad_request("Parse error"))?;
            let mut bytes = Vec::with_capacity(body.len() / 2);
            for part in text.split_ascii_whitespace() {
                bytes.extend(Vec::<u8>::from_hex(part).map_err(|_| bad_request("Parse error"))?);
            }
            decoded = bytes;
            decoded.as_slice()
        }
        Some("json") => return Err(bad_request("JSON request bodies are not supported")),
        _ => return Err(format_not_found(available_formats())),
    };
    let Some((&flag, mut remaining)) = bytes.split_first() else {
        return Err(bad_request("Parse error"));
    };
    let count = bitcoin::VarInt::consensus_decode(&mut remaining)
        .map_err(|_| bad_request("Parse error"))?
        .0;
    if count > u64::from(MAX_GETUTXOS_OUTPOINTS) {
        return Err(bad_request(format!(
            "Error: max outpoints exceeded (max: {MAX_GETUTXOS_OUTPOINTS}, tried: {count})"
        )));
    }
    let mut points = Vec::new();
    for _ in 0..count {
        let point = bitcoin::OutPoint::consensus_decode(&mut remaining)
            .map_err(|_| bad_request("Parse error"))?;
        points.push((
            Txid::from(Hash256::from_le_bytes(point.txid.as_byte_array())),
            point.vout,
        ));
    }
    if !remaining.is_empty() {
        return Err(bad_request("Parse error"));
    }
    Ok((flag != 0, points))
}

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
    if outpoints.len() > usize::from(MAX_GETUTXOS_OUTPOINTS) {
        return Err(bad_request(format!(
            "Error: max outpoints exceeded (max: {MAX_GETUTXOS_OUTPOINTS}, tried: {})",
            outpoints.len()
        )));
    }
    Ok((check_mempool, outpoints))
}

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
        body.extend_from_slice(&0_u32.to_le_bytes());
        body.extend_from_slice(&height.to_le_bytes());
        body.extend_from_slice(&consensus_bytes(txout));
    }
    body
}

fn append_compact_size(body: &mut Vec<u8>, len: usize) {
    let Ok(value) = u64::try_from(len) else {
        panic!("compact-size length exceeds u64");
    };
    body.extend_from_slice(bitcoin_rs_primitives::varint::encode(value).as_slice());
}

fn build_chain_context(
    ctx: &Context,
    view: &AppliedView,
    record: &BlockRecord,
    header: &Header,
) -> BlockChainContext {
    let on_active =
        ctx.chain.active_hash_in_view(view, record.height) == Some(Hash256::from(record.hash));
    let n_tx = u32::try_from(record.tx_count).unwrap_or(u32::MAX);
    BlockChainContext {
        height: record.height,
        confirmations: crate::render::confirmations(view.height(), record.height, on_active),
        mediantime: ctx
            .chain
            .median_time_past_for_hash(Hash256::from(record.hash))
            .unwrap_or(0),
        difficulty: ctx.chain.difficulty_for_bits(header.bits),
        chainwork_hex: ctx
            .chain
            .chain_work_hex_for_hash(Hash256::from(record.hash))
            .unwrap_or_else(|| "00".to_owned()),
        n_tx,
        next_block_hash: if on_active {
            record
                .height
                .checked_add(1)
                .and_then(|next| ctx.chain.active_hash_in_view(view, next))
                .map(BlockHash::from)
        } else {
            None
        },
    }
}

fn header_chain_context(
    ctx: &Context,
    view: &AppliedView,
    record: &HeaderRecord,
) -> BlockChainContext {
    let real = ctx
        .chain
        .block_by_hash(record.hash)
        .unwrap_or_else(|| BlockRecord {
            hash: BlockHash::from(record.hash),
            height: record.height,
            body_size: 0,
            header: None,
            tx_count: 0,
            time: record.header.time,
        });
    build_chain_context(ctx, view, &real, &record.header)
}

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
    not_found_with(format!("output format not found (available: {available})"))
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

pub(crate) fn json_ok<T: serde::Serialize>(value: T) -> Response {
    match sonic_rs::to_string(&value) {
        Ok(body) => text_response("application/json", body.into_bytes()),
        Err(_) => internal_error("failed to serialize response"),
    }
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

pub(crate) fn text_response(content_type: &'static str, body: Vec<u8>) -> Response {
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

pub(crate) fn service_unavailable(message: impl Into<String>) -> Response {
    Response {
        status: 503,
        reason: "Service Unavailable",
        content_type: "text/plain",
        body: message.into().into_bytes(),
    }
}

pub(crate) fn internal_error(message: impl Into<String>) -> Response {
    Response {
        status: 500,
        reason: "Internal Server Error",
        content_type: "text/plain",
        body: message.into().into_bytes(),
    }
}

pub(crate) fn bad_request(message: impl Into<String>) -> Response {
    Response {
        status: 400,
        reason: "Bad Request",
        content_type: "text/plain",
        body: message.into().into_bytes(),
    }
}

pub(crate) fn not_found() -> Response {
    not_found_with("not found")
}

fn not_found_with(message: impl Into<String>) -> Response {
    Response {
        status: 404,
        reason: "Not Found",
        content_type: "text/plain",
        body: message.into().into_bytes(),
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests;
