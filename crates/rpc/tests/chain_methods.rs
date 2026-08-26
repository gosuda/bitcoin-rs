//! Focused behavioral coverage for R1 chain RPC methods via `Handler::dispatch`.

use std::sync::Arc;

use bitcoin::hashes::Hash as _;
use bitcoin_rs_chain::{ChainWork, NodeId, NodeStatus, TipSnapshot};
use bitcoin_rs_filters::FilterIndexLike;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_rpc::context::{BlockRecord, Context};
use bitcoin_rs_rpc::error::RpcError;
use bitcoin_rs_rpc::handlers::Handler;
use sonic_rs::{JsonValueTrait, json};

fn publish_tip(ctx: &Context, tip: TipSnapshot) {
    ctx.set_chain_tip(tip.clone());
    ctx.set_applied_tip(tip);
}

fn seed_genesis(ctx: &Arc<Context>) -> (Hash256, bitcoin::Block) {
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let hash = Hash256::from_le_bytes(genesis.block_hash().as_byte_array());
    let tip_id = {
        let mut tree = ctx.block_tree.write();
        tree.insert_node(None, genesis.header, NodeStatus::Active)
            .expect("genesis insert")
    };
    ctx.add_block(BlockRecord::from_block(0, &genesis));
    publish_tip(
        ctx,
        TipSnapshot {
            tip_id,
            height: 0,
            chainwork: ChainWork::ZERO,
            hash,
        },
    );
    (hash, genesis)
}

fn dispatch(ctx: &Arc<Context>, method: &str, params: sonic_rs::Value) -> sonic_rs::Value {
    let handler = Handler::new(Arc::clone(ctx));
    handler
        .dispatch(method, &params)
        .unwrap_or_else(|err| panic!("{method} failed: {err}"))
}

#[test]
fn tip_methods_use_applied_not_header_only_state() {
    let ctx = Arc::new(Context::new());
    let (applied_hash, _) = seed_genesis(&ctx);
    let applied_hex = applied_hash.to_string_be();
    {
        let mut tree = ctx.block_tree.write();
        let genesis = tree
            .node_by_hash(applied_hash)
            .expect("genesis")
            .header
            .clone();
        let child = bitcoin::block::Header {
            version: bitcoin::block::Version::ONE,
            prev_blockhash: genesis.block_hash(),
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: genesis.time.saturating_add(600),
            bits: genesis.bits,
            nonce: 1,
        };
        let id = tree
            .insert_node(Some(NodeId::new(0)), child, NodeStatus::HeaderValid)
            .expect("header insert");
        let hash = Hash256::from_le_bytes(child.block_hash().as_byte_array());
        ctx.set_chain_tip(TipSnapshot {
            tip_id: id,
            height: 1,
            chainwork: ChainWork::ZERO,
            hash,
        });
    }

    assert_eq!(dispatch(&ctx, "getblockcount", json!([])).as_u64(), Some(0));
    assert_eq!(
        dispatch(&ctx, "getbestblockhash", json!([])).as_str(),
        Some(applied_hex.as_str())
    );
    let info = dispatch(&ctx, "getblockchaininfo", json!([]));
    assert_eq!(info.get("blocks").and_then(JsonValueTrait::as_u64), Some(0));
    assert_eq!(
        info.get("bestblockhash").and_then(JsonValueTrait::as_str),
        Some(applied_hex.as_str())
    );
}

#[test]
fn getblockheader_omits_nextblockhash_at_applied_tip() {
    let ctx = Arc::new(Context::new());
    let (hash, _) = seed_genesis(&ctx);
    let header = dispatch(&ctx, "getblockheader", json!([hash.to_string_be(), true]));
    assert!(
        header.get("nextblockhash").is_none(),
        "tip header must omit nextblockhash: {header:?}"
    );
    assert_eq!(
        header.get("confirmations").and_then(JsonValueTrait::as_i64),
        Some(1)
    );
}

#[test]
fn getchaintxstats_rejects_window_covering_full_height() {
    let ctx = Arc::new(Context::new());
    let (hash, _) = seed_genesis(&ctx);
    let tip = ctx.applied_tip.load_full().expect("tip");
    ctx.set_applied_tip(TipSnapshot {
        tip_id: tip.tip_id,
        height: 2,
        chainwork: ChainWork::ZERO,
        hash,
    });
    let handler = Handler::new(Arc::clone(&ctx));
    let err = handler
        .dispatch("getchaintxstats", &json!([2]))
        .expect_err("nblocks == tip height must fail");
    assert!(matches!(
        err,
        RpcError::InvalidParams(
            "Invalid block count: should be between 0 and the block's height - 1"
        )
    ));
}

#[test]
fn gettxoutsetinfo_reports_accounted_disk_size() {
    let ctx = Arc::new(Context::new());
    let _ = seed_genesis(&ctx);
    let info = dispatch(&ctx, "gettxoutsetinfo", json!([]));
    assert!(
        info.get("disk_size")
            .and_then(JsonValueTrait::as_u64)
            .is_some(),
        "disk_size must be present: {info:?}"
    );
}

struct LaggingFilterIndex {
    best: Option<Hash256>,
}

impl FilterIndexLike for LaggingFilterIndex {
    fn put_filter(
        &self,
        _block_hash: Hash256,
        _prev_header: Hash256,
        _filter_bytes: &[u8],
    ) -> Result<Hash256, bitcoin_rs_filters::FilterIndexError> {
        Ok(Hash256::default())
    }

    fn filter_header(
        &self,
        _block_hash: Hash256,
    ) -> Result<Option<Hash256>, bitcoin_rs_filters::FilterIndexError> {
        Ok(None)
    }

    fn filter(
        &self,
        _block_hash: Hash256,
    ) -> Result<Option<Vec<u8>>, bitcoin_rs_filters::FilterIndexError> {
        Ok(None)
    }

    fn best_indexed_block(&self) -> Result<Option<Hash256>, bitcoin_rs_filters::FilterIndexError> {
        Ok(self.best)
    }
}

#[test]
fn getindexinfo_basic_filter_uses_best_indexed_block() {
    let mut ctx = Context::new();
    let (applied_hash, _) = {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let hash = Hash256::from_le_bytes(genesis.block_hash().as_byte_array());
        let tip_id = {
            let mut tree = ctx.block_tree.write();
            tree.insert_node(None, genesis.header, NodeStatus::Active)
                .expect("genesis")
        };
        ctx.add_block(BlockRecord::from_block(0, &genesis));
        publish_tip(
            &ctx,
            TipSnapshot {
                tip_id,
                height: 0,
                chainwork: ChainWork::ZERO,
                hash,
            },
        );
        (hash, genesis)
    };
    let lagging = Hash256::from_le_bytes(&[1; 32]);
    ctx.filter_index = Arc::new(Box::new(LaggingFilterIndex {
        best: Some(lagging),
    }));
    let ctx = Arc::new(ctx);

    let info = dispatch(&ctx, "getindexinfo", json!(["basicblockfilterindex"]));
    let entry = info
        .get("basicblockfilterindex")
        .expect("basicblockfilterindex entry");
    assert_eq!(
        entry.get("synced").and_then(JsonValueTrait::as_bool),
        Some(false),
        "lagging filter index must not report synced against applied tip {applied_hash}"
    );
}

#[test]
fn getblockfilter_rejects_unknown_filtertype() {
    let ctx = Arc::new(Context::new());
    let handler = Handler::new(ctx);
    let hash = "0".repeat(64);
    let err = handler
        .dispatch("getblockfilter", &json!([hash.as_str(), "invalid"]))
        .expect_err("unknown filtertype");
    assert!(matches!(err, RpcError::InvalidParams("Unknown filtertype")));
}

#[test]
fn getdifficulty_is_registered() {
    let ctx = Arc::new(Context::new());
    let value = dispatch(&ctx, "getdifficulty", json!([]));
    assert!(value.as_f64().is_some());
}
