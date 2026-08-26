#![allow(clippy::expect_used, clippy::unwrap_used)]
//! Focused REST route coverage for X1.
//!
//! Enumerates the fourteen Core registrations and exercises formats, errors,
//! cache/HEAD policy, and REST/RPC projection parity.

use std::sync::Arc;

use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::Hash as _;
use bitcoin::hex::DisplayHex as _;
use bitcoin::{Block, CompactTarget, TxMerkleNode, block::Version};
use bitcoin_rs_chain::{NodeStatus, TipSnapshot};
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_rpc::context::{BlockBodySource, BlockRecord, Context};
use bitcoin_rs_rpc::handlers::Handler;
use bitcoin_rs_rpc::rest::Response as HttpResponse;
use bitcoin_rs_rpc::rest::{REGISTRATIONS, route, route_method};
use sonic_rs::{JsonValueTrait, Value, json};

const CACHE_IMMUTABLE: &str = "public, immutable, max-age=86400";
const CACHE_NO_STORE: &str = "no-store";

fn publish_active_chain(ctx: &Context, headers: &[bitcoin::block::Header]) -> Vec<Hash256> {
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
        (*ids.last().expect("tip"), hashes)
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

fn genesis_fixture() -> (Arc<Context>, Block, Hash256) {
    struct Source {
        height: u32,
        hash: Hash256,
        body: Vec<u8>,
    }
    impl BlockBodySource for Source {
        fn block_body(&self, height: u32, hash: Hash256) -> Option<Vec<u8>> {
            (height == self.height && hash == self.hash).then(|| self.body.clone())
        }
    }
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let hash = Hash256::from_le_bytes(genesis.block_hash().as_byte_array());
    let body = serialize(&genesis);
    let ctx = Arc::new(Context::new().with_block_body_source(Arc::new(Source {
        height: 0,
        hash,
        body,
    })));
    ctx.add_block(BlockRecord::from_block(0, &genesis));
    let _ = publish_active_chain(&ctx, &[genesis.header]);
    (ctx, genesis, hash)
}

#[test]
fn registrations_are_exactly_the_twelve_core_prefixes() {
    assert_eq!(REGISTRATIONS.len(), 12);
    assert_eq!(
        REGISTRATIONS,
        [
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
        ]
    );
}

#[test]
fn every_registration_is_reachable_without_falling_through_to_generic_404() {
    let (ctx, genesis, hash) = genesis_fixture();
    let hash_hex = hash.to_string_be();
    let zero_txid = "0".repeat(64);
    let probes = [
        format!("/rest/tx/{zero_txid}.json"),
        format!("/rest/block/notxdetails/{hash_hex}.json"),
        format!("/rest/block/{hash_hex}.json"),
        format!("/rest/blockpart/{hash_hex}.bin"),
        "/rest/chaininfo.json".to_owned(),
        "/rest/mempool/info.json".to_owned(),
        format!("/rest/headers/{hash_hex}.json"),
        format!("/rest/getutxos/{zero_txid}-0.json"),
        "/rest/deploymentinfo.json".to_owned(),
        format!("/rest/deploymentinfo/{hash_hex}.json"),
        "/rest/blockhashbyheight/0.json".to_owned(),
        format!("/rest/spenttxouts/{hash_hex}.json"),
    ];
    assert_eq!(probes.len(), REGISTRATIONS.len());
    for path in probes {
        let response = route(&ctx, &path, "", true);
        assert_ne!(
            String::from_utf8_lossy(&response.body),
            "not found",
            "registration fall-through for {path}"
        );
        assert!(
            response.status == 200 || response.status == 400 || response.status == 404,
            "{path} -> {}",
            response.status
        );
        let _ = genesis;
    }
}

#[test]
fn headers_support_json_hex_and_bin_formats() {
    let (ctx, genesis, hash) = genesis_fixture();
    let hash_hex = hash.to_string_be();
    for format in ["json", "hex", "bin"] {
        let response = route(
            &ctx,
            &format!("/rest/headers/{hash_hex}.{format}"),
            "count=1",
            true,
        );
        assert_eq!(response.status, 200, "{format}");
        assert_eq!(response.cache_control, CACHE_NO_STORE);
        match format {
            "json" => {
                let values: Vec<Value> =
                    sonic_rs::from_slice(&response.body).expect("headers json");
                assert_eq!(values.len(), 1);
                assert!(values[0].get("hash").is_some());
                assert!(values[0].get("confirmations").is_some());
            }
            "hex" => {
                let expected = serialize(&genesis.header).to_lower_hex_string();
                assert_eq!(String::from_utf8_lossy(&response.body), expected);
            }
            "bin" => assert_eq!(
                response.body.as_slice(),
                serialize(&genesis.header).as_slice()
            ),
            _ => unreachable!(),
        }
    }
}

#[test]
fn block_formats_and_pruned_error() {
    let (ctx, genesis, hash) = genesis_fixture();
    let hash_hex = hash.to_string_be();
    let json = route(&ctx, &format!("/rest/block/{hash_hex}.json"), "", true);
    assert_eq!(json.status, 200);
    assert_eq!(json.cache_control, CACHE_NO_STORE);
    let value: Value = sonic_rs::from_slice(&json.body).expect("block json");
    assert!(value.get("tx").is_some());

    let hex = route(&ctx, &format!("/rest/block/{hash_hex}.hex"), "", true);
    assert_eq!(hex.status, 200);
    assert_eq!(hex.cache_control, CACHE_IMMUTABLE);
    assert!(
        String::from_utf8_lossy(&hex.body)
            .starts_with(&serialize(&genesis).to_lower_hex_string()[..16])
    );

    let bin = route(&ctx, &format!("/rest/block/{hash_hex}.bin"), "", true);
    assert_eq!(bin.status, 200);
    assert_eq!(bin.cache_control, CACHE_IMMUTABLE);
    assert_eq!(bin.body, serialize(&genesis));

    let missing = route(
        &ctx,
        "/rest/block/0000000000000000000000000000000000000000000000000000000000000001.json",
        "",
        true,
    );
    assert_eq!(missing.status, 404);
    assert_eq!(missing.cache_control, CACHE_NO_STORE);

    // Header-known but body-less block behaves as pruned.
    let bits = CompactTarget::from_consensus(0x207f_ffff);
    let orphan_header = bitcoin::block::Header {
        version: Version::ONE,
        prev_blockhash: genesis.block_hash(),
        merkle_root: TxMerkleNode::all_zeros(),
        time: 2,
        bits,
        nonce: 1,
    };
    {
        let mut tree = ctx.block_tree.write();
        let parent = tree.lookup(hash).expect("genesis id");
        let _ = tree
            .insert_node(Some(parent), orphan_header, NodeStatus::HeaderValid)
            .expect("header-only child");
    }
    let orphan_hash = Hash256::from_le_bytes(orphan_header.block_hash().as_byte_array());
    let pruned = route(
        &ctx,
        &format!("/rest/block/{}.bin", orphan_hash.to_string_be()),
        "",
        true,
    );
    assert_eq!(pruned.status, 404);
    assert!(
        String::from_utf8_lossy(&pruned.body).contains("not available (pruned data)"),
        "{}",
        String::from_utf8_lossy(&pruned.body)
    );
}

#[test]
fn chaininfo_mempool_deployment_and_blockhash_routes() {
    let (ctx, _genesis, hash) = genesis_fixture();
    let chaininfo = route(&ctx, "/rest/chaininfo.json", "", true);
    assert_eq!(chaininfo.status, 200);
    assert_eq!(chaininfo.cache_control, CACHE_NO_STORE);
    let info: Value = sonic_rs::from_slice(&chaininfo.body).expect("chaininfo");
    for field in ["chain", "blocks", "headers", "bestblockhash"] {
        assert!(info.get(field).is_some(), "missing {field}");
    }

    let mempool_info = route(&ctx, "/rest/mempool/info.json", "", true);
    assert_eq!(mempool_info.status, 200);
    assert_eq!(mempool_info.cache_control, CACHE_NO_STORE);

    let mempool_contents = route(&ctx, "/rest/mempool/contents.json", "verbose=false", true);
    assert_eq!(mempool_contents.status, 200);

    let deployment = route(&ctx, "/rest/deploymentinfo.json", "", true);
    assert_eq!(deployment.status, 200);
    assert_eq!(deployment.cache_control, CACHE_NO_STORE);

    for format in ["json", "hex", "bin"] {
        let response = route(
            &ctx,
            &format!("/rest/blockhashbyheight/0.{format}"),
            "",
            true,
        );
        assert_eq!(response.status, 200, "{format}");
        assert_eq!(response.cache_control, CACHE_NO_STORE);
    }
    let out_of_range = route(&ctx, "/rest/blockhashbyheight/99.json", "", true);
    assert_eq!(out_of_range.status, 404);

    let spent = route(
        &ctx,
        &format!("/rest/spenttxouts/{}.json", hash.to_string_be()),
        "",
        true,
    );
    assert_eq!(spent.status, 404);
    assert!(String::from_utf8_lossy(&spent.body).contains("undo not available"));
}

#[test]
fn malformed_and_disabled_errors() {
    let ctx = Arc::new(Context::new());
    let disabled = route(&ctx, "/rest/chaininfo.json", "", false);
    assert_eq!(disabled.status, 404);
    assert_eq!(disabled.cache_control, CACHE_NO_STORE);

    let bad_format = route(
        &ctx,
        "/rest/headers/0000000000000000000000000000000000000000000000000000000000000000.txt",
        "",
        true,
    );
    assert_eq!(bad_format.status, 404);
    assert!(
        String::from_utf8_lossy(&bad_format.body).contains("output format not found"),
        "{}",
        String::from_utf8_lossy(&bad_format.body)
    );

    let missing_format = route(&ctx, "/rest/headers/not-a-hash", "", true);
    assert_eq!(missing_format.status, 404);
    assert!(String::from_utf8_lossy(&missing_format.body).contains("output format not found"));

    let bad_count = route(
        &ctx,
        "/rest/headers/0000000000000000000000000000000000000000000000000000000000000001.json",
        "count=0",
        true,
    );
    assert_eq!(bad_count.status, 400);
}

#[test]
fn head_preserves_status_headers_and_empties_body() {
    let (ctx, _genesis, hash) = genesis_fixture();
    let path = format!("/rest/block/{}.bin", hash.to_string_be());
    let get = route_method(&ctx, &path, "", true, "GET");
    let head = route_method(&ctx, &path, "", true, "HEAD");
    assert_eq!(head.status, get.status);
    assert_eq!(head.reason, get.reason);
    assert_eq!(head.content_type, get.content_type);
    assert_eq!(head.cache_control, get.cache_control);
    assert_eq!(head.content_length, get.body.len());
    assert!(head.body.is_empty());
    assert!(!get.body.is_empty());
}

#[test]
fn rest_chaininfo_and_header_json_match_rpc_projections() {
    let (ctx, _genesis, hash) = genesis_fixture();
    let handler = Handler::new(Arc::clone(&ctx));

    let rest_info = route(&ctx, "/rest/chaininfo.json", "", true);
    let rpc_info = handler
        .dispatch("getblockchaininfo", &json!([]))
        .expect("rpc chaininfo");
    let rest_value: Value = sonic_rs::from_slice(&rest_info.body).expect("rest chaininfo");
    assert_eq!(
        rest_value.get("bestblockhash"),
        rpc_info.get("bestblockhash")
    );
    assert_eq!(rest_value.get("blocks"), rpc_info.get("blocks"));

    let rest_headers = route(
        &ctx,
        &format!("/rest/headers/{}.json", hash.to_string_be()),
        "count=1",
        true,
    );
    let rpc_header = handler
        .dispatch("getblockheader", &json!([hash.to_string_be(), true]))
        .expect("rpc header");
    let rest_headers: Vec<Value> = sonic_rs::from_slice(&rest_headers.body).expect("rest headers");
    assert_eq!(rest_headers.len(), 1);
    assert_eq!(rest_headers[0].get("hash"), rpc_header.get("hash"));
    assert_eq!(
        rest_headers[0].get("confirmations"),
        rpc_header.get("confirmations")
    );
    assert_eq!(rest_headers[0].get("height"), rpc_header.get("height"));
}

#[test]
fn unknown_rest_path_is_not_found() {
    let ctx = Arc::new(Context::new());
    let response = route(&ctx, "/rest/nope.json", "", true);
    assert_eq!(response.status, 404);
    assert_eq!(response.cache_control, CACHE_NO_STORE);
}

// Silence unused import warnings if HttpResponse alias is reserved for future
// transport assertions.

#[test]
fn deploymentinfo_with_block_hash_succeeds() {
    // /rest/deploymentinfo/<blockhash>.json must parse the hash after the
    // prefix strip leaves a leading slash. The old code passed "/<hash>" to
    // Hash256::from_str, which always failed with 400.
    let (ctx, _genesis, hash) = genesis_fixture();
    let hash_hex = hash.to_string_be();
    let response = route(
        &ctx,
        &format!("/rest/deploymentinfo/{hash_hex}.json"),
        "",
        true,
    );
    assert_eq!(
        response.status, 200,
        "deploymentinfo with hash must succeed"
    );
    let body: Value = sonic_rs::from_slice(&response.body).expect("deploymentinfo json");
    assert_eq!(
        body.get("hash").and_then(JsonValueTrait::as_str),
        Some(hash_hex.as_str())
    );
    assert_eq!(body.get("height").and_then(JsonValueTrait::as_u64), Some(0));
}
#[allow(dead_code)]
fn _http_response_ty(_: &HttpResponse) {}
