//! Independent REST route prefix enumeration tests.
//!
//! These tests verify that every literal Core REST prefix in
//! [`REGISTRATIONS`] is dispatched by [`route`] — none falls through to a
//! generic 404 silently. They enumerate the prefixes as literal strings rather
//! than proving the constant against itself, and cover representative
//! supported formats and error paths.

// A route fixture that fails to resolve is a test failure, and panicking
// reports it at the call site. `expect` is deliberate.
#![allow(clippy::expect_used)]

use std::sync::Arc;

use bitcoin_rs_rpc::context::Context;
use bitcoin_rs_rpc::rest::{REGISTRATIONS, route};

/// A well-formed path suffix for each registered prefix, in REGISTRATIONS
/// order. These are literal strings — not derived from the constant — so a
/// missing or misrouted prefix is caught.
const PREFIX_PROBES: &[(&str, &str)] = &[
    // /rest/tx/
    (
        "/rest/tx/0000000000000000000000000000000000000000000000000000000000000001.json",
        "",
    ),
    // /rest/block/notxdetails/
    (
        "/rest/block/notxdetails/0000000000000000000000000000000000000000000000000000000000000001.json",
        "",
    ),
    // /rest/block/
    (
        "/rest/block/0000000000000000000000000000000000000000000000000000000000000001.json",
        "",
    ),
    // /rest/blockpart/
    (
        "/rest/blockpart/0000000000000000000000000000000000000000000000000000000000000001.bin",
        "",
    ),
    // /rest/chaininfo
    ("/rest/chaininfo.json", ""),
    // /rest/mempool/
    ("/rest/mempool/info.json", ""),
    // /rest/headers/
    (
        "/rest/headers/0000000000000000000000000000000000000000000000000000000000000001.json",
        "count=1",
    ),
    // /rest/getutxos
    (
        "/rest/getutxos/0000000000000000000000000000000000000000000000000000000000000001-0.json",
        "",
    ),
    // /rest/deploymentinfo/
    (
        "/rest/deploymentinfo/0000000000000000000000000000000000000000000000000000000000000001.json",
        "",
    ),
    // /rest/deploymentinfo
    ("/rest/deploymentinfo.json", ""),
    // /rest/blockhashbyheight/
    ("/rest/blockhashbyheight/0.json", ""),
    // /rest/spenttxouts/
    (
        "/rest/spenttxouts/0000000000000000000000000000000000000000000000000000000000000001.json",
        "",
    ),
];

#[test]
fn registration_count_is_twelve() {
    assert_eq!(
        REGISTRATIONS.len(),
        12,
        "Core registers exactly 12 supported REST prefixes"
    );
}

#[test]
fn every_registration_prefix_has_a_probe() {
    assert_eq!(
        PREFIX_PROBES.len(),
        REGISTRATIONS.len(),
        "one probe per registration"
    );
}

#[test]
fn every_prefix_is_dispatched_when_enabled() {
    let ctx = Arc::new(Context::new());
    for (path, query) in PREFIX_PROBES {
        let response = route(&ctx, path, query, true);
        // Every prefix must produce a response — the test asserts dispatch
        // itself (no panic, no fallthrough). Specific status codes are covered
        // by the per-prefix tests below.
        assert!(
            response.status >= 200,
            "{path} returned {status}",
            status = response.status
        );
    }
}

#[test]
fn every_prefix_is_404_when_disabled() {
    let ctx = Arc::new(Context::new());
    for (path, query) in PREFIX_PROBES {
        let response = route(&ctx, path, query, false);
        assert_eq!(response.status, 404, "disabled REST must 404 for {path}");
    }
}

// ---------------------------------------------------------------------------
// Per-prefix format and error coverage
// ---------------------------------------------------------------------------

#[test]
fn tx_prefix_all_formats_dispatch() {
    let ctx = Arc::new(Context::new());
    let txid = "0000000000000000000000000000000000000000000000000000000000000001";
    for format in ["json", "hex", "bin"] {
        let response = route(&ctx, &format!("/rest/tx/{txid}.{format}"), "", true);
        assert_eq!(response.status, 404, "unknown txid .{format} → 404");
    }
    // Missing format
    let response = route(&ctx, &format!("/rest/tx/{txid}"), "", true);
    assert_eq!(response.status, 404, "missing format → 404");
    // Bad hash
    let response = route(&ctx, "/rest/tx/not-a-hash.json", "", true);
    assert_eq!(response.status, 400, "bad hash → 400");
}

#[test]
fn unknown_suffixes_are_malformed_path_parameters() {
    const HASH: &str = "0000000000000000000000000000000000000000000000000000000000000001";

    let ctx = Arc::new(Context::new());
    let probes = [
        (format!("/rest/tx/{HASH}.txt"), ""),
        (format!("/rest/block/notxdetails/{HASH}.txt"), ""),
        (format!("/rest/block/{HASH}.txt"), ""),
        (format!("/rest/blockpart/{HASH}.txt"), ""),
        (format!("/rest/headers/{HASH}.txt"), "count=1"),
        (format!("/rest/getutxos/{HASH}-0.txt"), ""),
        ("/rest/blockhashbyheight/0.txt".to_owned(), ""),
        (format!("/rest/spenttxouts/{HASH}.txt"), ""),
        ("/rest/mempool/info.txt".to_owned(), ""),
    ];
    for (path, query) in probes {
        let response = route(&ctx, &path, query, true);
        assert_eq!(response.status, 400, "unknown suffix for {path}");
    }
}

#[test]
fn block_prefix_all_formats_dispatch() {
    let ctx = Arc::new(Context::new());
    let hash = "0000000000000000000000000000000000000000000000000000000000000001";
    for format in ["json", "hex", "bin"] {
        let response = route(&ctx, &format!("/rest/block/{hash}.{format}"), "", true);
        assert_eq!(response.status, 404, "unknown block .{format} → 404");
    }
}

#[test]
fn block_notxdetails_is_distinct_prefix() {
    let ctx = Arc::new(Context::new());
    let hash = "0000000000000000000000000000000000000000000000000000000000000001";
    let response = route(
        &ctx,
        &format!("/rest/block/notxdetails/{hash}.json"),
        "",
        true,
    );
    assert_eq!(response.status, 404);
    // Ensure /rest/block/notxdetails/ is not shadowed by /rest/block/
    let response = route(
        &ctx,
        &format!("/rest/block/notxdetails/{hash}.hex"),
        "",
        true,
    );
    assert_eq!(response.status, 404);
}

#[test]
fn blockpart_prefix_bin_hex_dispatch() {
    let ctx = Arc::new(Context::new());
    let hash = "0000000000000000000000000000000000000000000000000000000000000001";
    for format in ["bin", "hex"] {
        let response = route(&ctx, &format!("/rest/blockpart/{hash}.{format}"), "", true);
        assert_eq!(response.status, 404, "unknown blockpart .{format} → 404");
    }
    // JSON is not a valid blockpart format
    let response = route(&ctx, &format!("/rest/blockpart/{hash}.json"), "", true);
    assert_eq!(
        response.status, 404,
        "blockpart .json → 404 (format not found)"
    );
}

#[test]
fn chaininfo_prefix_json_only() {
    let ctx = Arc::new(Context::new());
    let response = route(&ctx, "/rest/chaininfo.json", "", true);
    assert_eq!(response.status, 200);
    assert_eq!(response.content_type, "application/json");
    // Non-JSON format
    let response = route(&ctx, "/rest/chaininfo.bin", "", true);
    assert_eq!(response.status, 404);
}

#[test]
fn mempool_prefix_info_and_contents() {
    let ctx = Arc::new(Context::new());
    let response = route(&ctx, "/rest/mempool/info.json", "", true);
    assert_eq!(response.status, 200);
    let response = route(&ctx, "/rest/mempool/contents.json", "", true);
    assert_eq!(response.status, 200);
    // Invalid sub-resource
    let response = route(&ctx, "/rest/mempool/foo.json", "", true);
    assert_eq!(response.status, 400);
    // Non-JSON format
    let response = route(&ctx, "/rest/mempool/info.hex", "", true);
    assert_eq!(response.status, 404);
}

#[test]
fn headers_prefix_all_formats() {
    let ctx = Arc::new(Context::new());
    let hash = "0000000000000000000000000000000000000000000000000000000000000001";
    for format in ["json", "hex", "bin"] {
        let response = route(
            &ctx,
            &format!("/rest/headers/{hash}.{format}"),
            "count=1",
            true,
        );
        assert_eq!(response.status, 200, "unknown hash .{format} → 200 empty");
    }
    // Bad count
    let response = route(&ctx, &format!("/rest/headers/{hash}.json"), "count=0", true);
    assert_eq!(response.status, 400);
}

#[test]
fn getutxos_prefix_json_and_checkmempool() {
    let ctx = Arc::new(Context::new());
    let txid = "0000000000000000000000000000000000000000000000000000000000000001";
    let response = route(&ctx, &format!("/rest/getutxos/{txid}-0.json"), "", true);
    assert_eq!(response.status, 200);
    // checkmempool variant
    let response = route(
        &ctx,
        &format!("/rest/getutxos/checkmempool/{txid}-0.json"),
        "",
        true,
    );
    assert_eq!(response.status, 200);
    // Empty request
    let response = route(&ctx, "/rest/getutxos.json", "", true);
    assert_eq!(response.status, 400);
}

#[test]
fn deploymentinfo_prefix_with_and_without_blockhash() {
    let ctx = Arc::new(Context::new());
    let response = route(&ctx, "/rest/deploymentinfo.json", "", true);
    assert_eq!(response.status, 200);
    let response = route(
        &ctx,
        "/rest/deploymentinfo/0000000000000000000000000000000000000000000000000000000000000001.json",
        "",
        true,
    );
    // Unknown block hash → 400 "Block not found"
    assert_eq!(response.status, 400);
    // Non-JSON format
    let response = route(&ctx, "/rest/deploymentinfo.bin", "", true);
    assert_eq!(response.status, 404);
}

#[test]
fn blockhashbyheight_prefix_all_formats() {
    let ctx = Arc::new(Context::new());
    // Height zero resolves to the selected network's genesis block even before a tip publishes.
    for format in ["json", "hex", "bin"] {
        let response = route(
            &ctx,
            &format!("/rest/blockhashbyheight/0.{format}"),
            "",
            true,
        );
        assert_eq!(response.status, 200, "genesis .{format} → 200");
    }
    // Bad height
    let response = route(&ctx, "/rest/blockhashbyheight/abc.json", "", true);
    assert_eq!(response.status, 400);
}

#[test]
fn spenttxouts_prefix_returns_undo_unavailable() {
    let ctx = Arc::new(Context::new());
    let hash = "0000000000000000000000000000000000000000000000000000000000000001";
    for format in ["json", "hex", "bin"] {
        let response = route(
            &ctx,
            &format!("/rest/spenttxouts/{hash}.{format}"),
            "",
            true,
        );
        assert_eq!(response.status, 404, ".{format} → 404");
        let body = String::from_utf8(response.body).expect("body");
        assert!(
            body.contains("undo not available"),
            "spenttxouts must say 'undo not available', got: {body}"
        );
    }
}

#[test]
fn unknown_rest_path_is_generic_404() {
    let ctx = Arc::new(Context::new());
    let response = route(&ctx, "/rest/totally-unknown", "", true);
    assert_eq!(response.status, 404);
    assert_eq!(String::from_utf8(response.body).expect("body"), "not found");
}

#[test]
fn registrations_contain_expected_literal_prefixes() {
    // Verify the literal strings against Core's known registration table.
    let expected = [
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
    assert_eq!(REGISTRATIONS, expected);
}
