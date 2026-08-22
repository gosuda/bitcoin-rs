//! Small Bitcoin Core-compatible REST surface used by remote clients.

use alloc::sync::Arc;
use std::str::FromStr;

use bitcoin::block::Header;
use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::Hash as _;
use bitcoin::hex::DisplayHex as _;
use bitcoin_rs_primitives::Hash256;
use sonic_rs::{Value, json};

use crate::context::{BlockRecord, Context};
use crate::error::RpcError;

const DEFAULT_HEADER_COUNT: u32 = 5;
const MAX_HEADER_COUNT: u32 = 2_000;

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
    if path == "/rest/chaininfo.json" {
        return json_response(crate::handlers::chain::getblockchaininfo(ctx, &json!([])));
    }
    if let Some(rest) = path.strip_prefix("/rest/headers/") {
        return route_headers(ctx, rest, query);
    }
    not_found()
}

fn route_headers(ctx: &Arc<Context>, suffix: &str, query: &str) -> Response {
    let Some((hash_text, format)) = suffix.rsplit_once('.') else {
        return not_found_with("output format not found");
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
            let values = records.iter().map(header_json).collect::<Vec<_>>();
            json_response(Ok(Value::from(values)))
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

    // Cache-only records predate tree publication, so their active-chain
    // membership cannot be established here; preserve the singleton fallback
    // for those records rather than turning a usable header into a 404.
    let Some(record) = ctx.block_by_hash(hash) else {
        return Vec::new();
    };
    let Some(header) = decode_header(&record) else {
        return Vec::new();
    };
    vec![HeaderRecord {
        hash: record.hash,
        height: record.height,
        header,
    }]
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

fn decode_header(record: &BlockRecord) -> Option<Header> {
    bitcoin::consensus::encode::deserialize(record.header_bytes()?.as_slice()).ok()
}

fn header_json(record: &HeaderRecord) -> Value {
    json!({
        "hash": record.hash.to_string_be(),
        "height": record.height,
        "version": record.header.version.to_consensus(),
        "previousblockhash": if record.height == 0 { None::<String> } else { Some(record.header.prev_blockhash.to_string()) },
        "merkleroot": record.header.merkle_root.to_string(),
        "time": record.header.time,
        "bits": format!("{:08x}", record.header.bits.to_consensus()),
        "nonce": record.header.nonce,
    })
}

fn json_response(result: Result<Value, RpcError>) -> Response {
    match result {
        Ok(value) => {
            let body = sonic_rs::to_string(&value).unwrap_or_else(|_| "null".to_owned());
            text_response("application/json", body.into_bytes())
        }
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

/// Constructs the Core-style response for an unsupported HTTP path.
#[must_use]
pub(crate) fn not_found_response() -> Response {
    not_found()
}

fn not_found_with(message: &'static str) -> Response {
    Response {
        status: 404,
        reason: "Not Found",
        content_type: "text/plain",
        body: message.as_bytes().to_vec(),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use bitcoin::{BlockHash, CompactTarget, TxMerkleNode, block::Version};
    use bitcoin_rs_chain::{NodeStatus, TipSnapshot};
    use sonic_rs::JsonValueTrait;

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
                hashes.push(Hash256::from_le_bytes(header.block_hash().as_byte_array()));
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
    fn route_rejects_unknown_formats_and_bad_hashes() {
        let ctx = Arc::new(Context::new());
        let response = route(
            &ctx,
            "/rest/headers/0000000000000000000000000000000000000000000000000000000000000000.txt",
            "",
            true,
        );
        assert_eq!(response.status, 400);
        assert_eq!(
            String::from_utf8(response.body).expect("error body"),
            "Invalid hash: 0000000000000000000000000000000000000000000000000000000000000000"
        );
        let response = route(&ctx, "/rest/headers/not-a-hash.json", "", true);
        assert_eq!(response.status, 400);
        assert_eq!(
            String::from_utf8(response.body).expect("error body"),
            "Invalid hash: not-a-hash"
        );
        let response = route(&ctx, "/rest/headers/not-a-hash", "", true);
        assert_eq!(response.status, 404);
        assert_eq!(
            String::from_utf8(response.body).expect("error body"),
            "output format not found"
        );
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
        use bitcoin::hashes::Hash as _;
        use bitcoin::{Block, BlockHash, CompactTarget, TxMerkleNode, block::Version};

        let ctx = Arc::new(Context::new());
        let bits = CompactTarget::from_consensus(0x1d00_ffff);
        let genesis_header = Header {
            version: Version::ONE,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 1,
            bits,
            nonce: 1,
        };
        let genesis = Block {
            header: genesis_header,
            txdata: Vec::new(),
        };
        let child_header = Header {
            version: Version::ONE,
            prev_blockhash: genesis.block_hash(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 2,
            bits,
            nonce: 2,
        };
        let child = Block {
            header: child_header,
            txdata: Vec::new(),
        };
        let tip_header = Header {
            version: Version::ONE,
            prev_blockhash: child.block_hash(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 3,
            bits,
            nonce: 3,
        };
        let tip = Block {
            header: tip_header,
            txdata: Vec::new(),
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
            CompactTarget::from_unprefixed_hex(bits_text).expect("bits round-trip"),
            bits
        );
    }

    #[test]
    fn headers_do_not_walk_past_applied_tip() {
        let ctx = Arc::new(Context::new());
        let bits = CompactTarget::from_consensus(0x1d00_ffff);
        let genesis = Header {
            version: Version::ONE,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 1,
            bits,
            nonce: 1,
        };
        let applied = Header {
            version: Version::ONE,
            prev_blockhash: genesis.block_hash(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 2,
            bits,
            nonce: 2,
        };
        let header_tip = Header {
            version: Version::ONE,
            prev_blockhash: applied.block_hash(),
            merkle_root: TxMerkleNode::all_zeros(),
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
        let header_tip_hash = Hash256::from_le_bytes(header_tip.block_hash().as_byte_array());

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
        let bits = CompactTarget::from_consensus(0x1d00_ffff);
        let genesis = Header {
            version: Version::ONE,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 1,
            bits,
            nonce: 1,
        };
        let child = Header {
            version: Version::ONE,
            prev_blockhash: genesis.block_hash(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 2,
            bits,
            nonce: 2,
        };
        let tip = Header {
            version: Version::ONE,
            prev_blockhash: child.block_hash(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 3,
            bits,
            nonce: 3,
        };
        publish_active_chain(&ctx, &[genesis, child, tip]);

        let response = route(
            &ctx,
            &format!("/rest/headers/{}.json", genesis.block_hash()),
            "count=2000",
            true,
        );
        let values: Vec<Value> = sonic_rs::from_slice(&response.body).expect("headers JSON");
        assert_eq!(values.len(), 3);
        assert!(
            values[0]
                .get("previousblockhash")
                .is_some_and(Value::is_null)
        );
        assert_eq!(values[0].get("height").and_then(Value::as_u64), Some(0));
        assert_eq!(values[2].get("height").and_then(Value::as_u64), Some(2));
    }

    #[test]
    fn headers_side_branch_returns_empty() {
        let ctx = Arc::new(Context::new());
        let bits = CompactTarget::from_consensus(0x1d00_ffff);
        let genesis = Header {
            version: Version::ONE,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 1,
            bits,
            nonce: 1,
        };
        let active_child = Header {
            version: Version::ONE,
            prev_blockhash: genesis.block_hash(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 2,
            bits,
            nonce: 2,
        };
        let active_tip = Header {
            version: Version::ONE,
            prev_blockhash: active_child.block_hash(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 3,
            bits,
            nonce: 3,
        };
        let side_child = Header {
            version: Version::ONE,
            prev_blockhash: genesis.block_hash(),
            merkle_root: TxMerkleNode::all_zeros(),
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
                Hash256::from_le_bytes(side_child.block_hash().as_byte_array())
            ),
            "count=2000",
            true,
        );
        let values: Vec<Value> = sonic_rs::from_slice(&response.body).expect("headers JSON");
        assert!(values.is_empty());
    }

    #[test]
    fn headers_truncate_when_linkage_breaks() {
        use bitcoin::{Block, BlockHash, CompactTarget, TxMerkleNode, block::Version};

        let ctx = Arc::new(Context::new());
        let bits = CompactTarget::from_consensus(0x1d00_ffff);
        let genesis = Block {
            header: Header {
                version: Version::ONE,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 1,
                bits,
                nonce: 1,
            },
            txdata: Vec::new(),
        };
        let broken_child = Block {
            header: Header {
                version: Version::ONE,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 2,
                bits,
                nonce: 2,
            },
            txdata: Vec::new(),
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
            .prev_blockhash = BlockHash::all_zeros();
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
        let bits = CompactTarget::from_consensus(0x1d00_ffff);
        let genesis = Header {
            version: Version::ONE,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 1,
            bits,
            nonce: 1,
        };
        let first = Header {
            version: Version::ONE,
            prev_blockhash: genesis.block_hash(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 2,
            bits,
            nonce: 2,
        };
        let middle = Header {
            version: Version::ONE,
            prev_blockhash: first.block_hash(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 3,
            bits,
            nonce: 3,
        };
        let tail = Header {
            version: Version::ONE,
            prev_blockhash: middle.block_hash(),
            merkle_root: TxMerkleNode::all_zeros(),
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
            .prev_blockhash = BlockHash::all_zeros();

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

    #[test]
    fn header_json_uses_enforcer_field_names() {
        let record = BlockRecord {
            hash: Hash256::from_str(
                "0000000000000000000000000000000000000000000000000000000000000001",
            )
            .expect("hash"),
            height: 1,
            block_hex: String::new(),
            body_size: 0,
            header: None,
            tx_count: 0,
            time: 123,
        };
        let header = Header {
            version: Version::from_consensus(1),
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 123,
            bits: CompactTarget::from_consensus(0x1d00_ffff),
            nonce: 7,
        };
        let value = header_json(&HeaderRecord {
            hash: record.hash,
            height: record.height,
            header,
        });
        for field in [
            "hash",
            "height",
            "version",
            "previousblockhash",
            "merkleroot",
            "time",
            "bits",
            "nonce",
        ] {
            assert!(value.get(field).is_some(), "missing {field}");
        }
        assert_eq!(value.get("bits").and_then(Value::as_str), Some("1d00ffff"));
    }
}
