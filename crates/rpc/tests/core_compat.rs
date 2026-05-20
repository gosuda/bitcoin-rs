//! Bitcoin Core schema compatibility tests for the RPC crate.
extern crate alloc;

use alloc::sync::Arc;
use std::collections::BTreeSet;

use bitcoin_rs_chain::{ChainWork, NodeId, TipSnapshot};
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_rpc::{Context, Handler};
use sonic_rs::{JsonValueTrait as _, json};

#[test]
fn selected_methods_match_core_documented_key_sets() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());
    ctx.set_chain_tip(TipSnapshot {
        tip_id: NodeId::new(0),
        height: 42,
        chainwork: ChainWork::ZERO,
        hash: Hash256::from_le_bytes(&[42_u8; 32]),
    });
    let handler = Handler::new(ctx);

    assert_keys(
        &handler.dispatch("getblockchaininfo", &json!([]))?,
        &[
            "chain",
            "blocks",
            "headers",
            "bestblockhash",
            "difficulty",
            "time",
            "mediantime",
            "verificationprogress",
            "initialblockdownload",
            "chainwork",
            "size_on_disk",
            "pruned",
            "warnings",
        ],
    )?;
    assert!(handler.dispatch("getblockcount", &json!([]))?.is_u64());
    assert!(handler.dispatch("getbestblockhash", &json!([]))?.is_str());
    assert_keys(
        &handler.dispatch("getmempoolinfo", &json!([]))?,
        &[
            "loaded",
            "size",
            "bytes",
            "usage",
            "total_fee",
            "maxmempool",
            "mempoolminfee",
            "minrelaytxfee",
            "incrementalrelayfee",
            "unbroadcastcount",
            "fullrbf",
            "mempool_sequence",
        ],
    )?;
    assert_keys(
        &handler.dispatch("getnetworkinfo", &json!([]))?,
        &[
            "version",
            "subversion",
            "protocolversion",
            "localservices",
            "localservicesnames",
            "localrelay",
            "timeoffset",
            "networkactive",
            "connections",
            "connections_in",
            "connections_out",
            "networks",
            "relayfee",
            "incrementalfee",
            "localaddresses",
            "warnings",
        ],
    )?;
    Ok(())
}

fn assert_keys(
    value: &sonic_rs::Value,
    expected: &[&str],
) -> Result<(), Box<dyn std::error::Error>> {
    let text = sonic_rs::to_string(value)?;
    let value: serde_json::Value = serde_json::from_str(&text)?;
    let Some(object) = value.as_object() else {
        panic!("response must be an object");
    };
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    assert_eq!(actual, expected);
    Ok(())
}
