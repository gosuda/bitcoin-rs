use super::*;
use bitcoin_rs_chain::{NodeStatus, TipSnapshot};
use bitcoin_rs_index::block_log::BlockRecord;
use bitcoin_rs_primitives::{OutPoint, Tx, TxIn};
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait};

fn publish_active_chain(ctx: &Context, headers: &[Header]) -> Vec<Hash256> {
    let (tip_id, hashes) = {
        let mut tree = ctx.chain.block_tree.write();
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
    let tree = ctx.chain.block_tree.read();
    let tip_node = tree.node(tip_id).expect("tip node");
    let tip = TipSnapshot {
        tip_id,
        height: tip_node.height,
        chainwork: tip_node.chainwork,
        hash: tip_node.hash,
        chain_tx_count: tip_node.chain_tx_count,
    };
    drop(tree);
    ctx.chain.applied_tip.store(Some(Arc::new(tip.clone())));
    ctx.chain.chain_tip.store(Some(Arc::new(tip)));
    hashes
}

struct PanicBlockSource;

impl bitcoin_rs_chain::BlockBodySource for PanicBlockSource {
    fn block_body(
        &self,
        _height: u32,
        _hash: BlockHash,
    ) -> Result<Option<Vec<u8>>, bitcoin_rs_chain::BlockBodyReadError> {
        panic!("exhausted render budget must not load a block body");
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
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txs: Vec::new(),
    };
    let record = BlockRecord::from_block(0, &block);
    let hash = record.hash.to_string();
    ctx.chain.add_block(record);
    ctx.chain.block_body_source = Some(Arc::new(PanicBlockSource));
    publish_active_chain(&ctx, &[block.header]);
    let _first = ctx.try_acquire_block_render().expect("first permit");
    let _second = ctx.try_acquire_block_render().expect("second permit");
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
        bits: CompactTarget::from_consensus(bits),
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
        bits: CompactTarget::from_consensus(bits),
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
        bits: CompactTarget::from_consensus(bits),
        nonce: 3,
    };
    let tip = Block {
        header: tip_header,
        txs: Vec::new(),
    };
    ctx.chain.add_block(BlockRecord::from_block(0, &genesis));
    ctx.chain.add_block(BlockRecord::from_block(1, &child));
    ctx.chain.add_block(BlockRecord::from_block(2, &tip));
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
        bits: CompactTarget::from_consensus(bits),
        nonce: 1,
    };
    let applied = Header {
        version: 1,
        prev_blockhash: genesis.compute_hash(),
        merkle_root: Hash256::default(),
        time: 2,
        bits: CompactTarget::from_consensus(bits),
        nonce: 2,
    };
    let header_tip = Header {
        version: 1,
        prev_blockhash: applied.compute_hash(),
        merkle_root: Hash256::default(),
        time: 3,
        bits: CompactTarget::from_consensus(bits),
        nonce: 3,
    };
    let applied_tip = {
        let mut tree = ctx.chain.block_tree.write();
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
    ctx.chain.applied_tip.store(Some(Arc::new(applied_tip)));
    let header_tip_hash = Hash256::from(header_tip.compute_hash());

    let response = route(
        &ctx,
        &format!("/rest/headers/{header_tip_hash}.json"),
        "count=2000",
        true,
    );
    let values: Vec<Value> = sonic_rs::from_slice(&response.body).expect("headers JSON");
    assert_eq!(values, Vec::<sonic_rs::Value>::new());
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
        bits: CompactTarget::from_consensus(bits),
        nonce: 1,
    };
    let child = Header {
        version: 1,
        prev_blockhash: genesis.compute_hash(),
        merkle_root: Hash256::default(),
        time: 2,
        bits: CompactTarget::from_consensus(bits),
        nonce: 2,
    };
    let tip = Header {
        version: 1,
        prev_blockhash: child.compute_hash(),
        merkle_root: Hash256::default(),
        time: 3,
        bits: CompactTarget::from_consensus(bits),
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
        bits: CompactTarget::from_consensus(bits),
        nonce: 1,
    };
    let active_child = Header {
        version: 1,
        prev_blockhash: genesis.compute_hash(),
        merkle_root: Hash256::default(),
        time: 2,
        bits: CompactTarget::from_consensus(bits),
        nonce: 2,
    };
    let active_tip = Header {
        version: 1,
        prev_blockhash: active_child.compute_hash(),
        merkle_root: Hash256::default(),
        time: 3,
        bits: CompactTarget::from_consensus(bits),
        nonce: 3,
    };
    let side_child = Header {
        version: 1,
        prev_blockhash: genesis.compute_hash(),
        merkle_root: Hash256::default(),
        time: 4,
        bits: CompactTarget::from_consensus(bits),
        nonce: 4,
    };
    let ids = publish_active_chain(&ctx, &[genesis, active_child, active_tip]);
    {
        let mut tree = ctx.chain.block_tree.write();
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
    assert_eq!(values, Vec::<sonic_rs::Value>::new());
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
            bits: CompactTarget::from_consensus(bits),
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
            bits: CompactTarget::from_consensus(bits),
            nonce: 2,
        },
        txs: Vec::new(),
    };
    ctx.chain.add_block(BlockRecord::from_block(0, &genesis));
    ctx.chain
        .add_block(BlockRecord::from_block(1, &broken_child));
    let genesis_id = {
        let mut tree = ctx.chain.block_tree.write();
        tree.insert_node(None, genesis.header, NodeStatus::Active)
            .expect("genesis header")
    };
    let broken_id = {
        let mut tree = ctx.chain.block_tree.write();
        let valid_child = Header {
            prev_blockhash: genesis.block_hash(),
            ..broken_child.header
        };
        tree.insert_node(Some(genesis_id), valid_child, NodeStatus::Active)
            .expect("broken child header")
    };
    ctx.chain
        .block_tree
        .write()
        .node_mut(broken_id)
        .expect("broken child node")
        .header
        .prev_blockhash = BlockHash::default();
    let tree = ctx.chain.block_tree.read();
    let broken_node = tree.node(broken_id).expect("broken tip");
    let tip = TipSnapshot {
        tip_id: broken_id,
        height: broken_node.height,
        chainwork: broken_node.chainwork,
        hash: broken_node.hash,
        chain_tx_count: broken_node.chain_tx_count,
    };
    drop(tree);
    ctx.chain.applied_tip.store(Some(Arc::new(tip.clone())));
    ctx.chain.chain_tip.store(Some(Arc::new(tip)));

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
        bits: CompactTarget::from_consensus(bits),
        nonce: 1,
    };
    let first = Header {
        version: 1,
        prev_blockhash: genesis.compute_hash(),
        merkle_root: Hash256::default(),
        time: 2,
        bits: CompactTarget::from_consensus(bits),
        nonce: 2,
    };
    let middle = Header {
        version: 1,
        prev_blockhash: first.compute_hash(),
        merkle_root: Hash256::default(),
        time: 3,
        bits: CompactTarget::from_consensus(bits),
        nonce: 3,
    };
    let tail = Header {
        version: 1,
        prev_blockhash: middle.compute_hash(),
        merkle_root: Hash256::default(),
        time: 4,
        bits: CompactTarget::from_consensus(bits),
        nonce: 4,
    };
    let hashes = publish_active_chain(&ctx, &[genesis, first, middle, tail]);
    let middle_id = ctx
        .chain
        .block_tree
        .read()
        .lookup(hashes[2])
        .expect("middle node");
    ctx.chain
        .block_tree
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

fn regtest_genesis() -> Block {
    let coinbase = Tx {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: vec![0x51].into(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(50 * 100_000_000),
            script_pubkey: Script::new(),
        }],
        lock_time: LockTime::ZERO,
    };
    Block {
        header: Header {
            version: 1,
            prev_blockhash: BlockHash::default(),
            merkle_root: coinbase.txid().0,
            time: 1_296_688_602,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 2,
        },
        txs: vec![coinbase],
    }
}

#[test]
fn headers_serve_the_block_header_bytes_verbatim() {
    let ctx = Arc::new(Context::new());
    let genesis = regtest_genesis();
    ctx.chain.add_block(BlockRecord::from_block(0, &genesis));
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
    assert_eq!(response.body, expected.to_lower_hex_string().into_bytes());
}

#[test]
fn headers_for_a_record_the_tree_does_not_know_serve_nothing() {
    let ctx = Arc::new(Context::new());
    let genesis = regtest_genesis();
    ctx.chain.add_block(BlockRecord::from_block(0, &genesis));

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

#[test]
fn route_status_table() {
    const HASH: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    let ctx = Arc::new(Context::new());
    let cases: Vec<(String, &str, u16)> = vec![
        (format!("/rest/tx/{HASH}.json"), "", 404),
        (format!("/rest/tx/{HASH}.hex"), "", 404),
        (format!("/rest/tx/{HASH}.bin"), "", 404),
        (format!("/rest/tx/{HASH}"), "", 404),
        (format!("/rest/tx/{HASH}.txt"), "", 400),
        ("/rest/tx/not-a-hash.json".into(), "", 400),
        (format!("/rest/block/notxdetails/{HASH}.json"), "", 404),
        (format!("/rest/block/{HASH}.json"), "", 404),
        (format!("/rest/block/{HASH}.hex"), "", 404),
        (format!("/rest/block/{HASH}.bin"), "", 404),
        ("/rest/block/not-a-hash.json".into(), "", 400),
        (format!("/rest/blockpart/{HASH}.bin"), "", 404),
        (format!("/rest/blockpart/{HASH}.hex"), "", 404),
        (format!("/rest/blockpart/{HASH}.json"), "", 404),
        ("/rest/chaininfo.json".into(), "", 200),
        ("/rest/chaininfo.bin".into(), "", 404),
        ("/rest/mempool/info.json".into(), "", 200),
        ("/rest/mempool/contents.json".into(), "", 200),
        ("/rest/mempool/contents.json".into(), "verbose=false", 200),
        ("/rest/mempool/contents.json".into(), "verbose=maybe", 400),
        (
            "/rest/mempool/contents.json".into(),
            "verbose=true&mempool_sequence=true",
            400,
        ),
        ("/rest/mempool/foo.json".into(), "", 400),
        ("/rest/mempool/info.bin".into(), "", 404),
        (format!("/rest/headers/{HASH}.json"), "count=1", 200),
        (format!("/rest/headers/{HASH}.txt"), "count=1", 400),
        ("/rest/getutxos.json".into(), "", 400),
        ("/rest/getutxos/not-a-txid-0.json".into(), "", 400),
        (format!("/rest/getutxos/{HASH}-0"), "", 404),
        (format!("/rest/getutxos/{HASH}-0.json"), "", 200),
        ("/rest/deploymentinfo.json".into(), "", 200),
        ("/rest/deploymentinfo.bin".into(), "", 404),
        ("/rest/deploymentinfo/not-a-hash.json".into(), "", 400),
        (format!("/rest/deploymentinfo/{HASH}.json"), "", 400),
        ("/rest/blockhashbyheight/0.json".into(), "", 200),
        ("/rest/blockhashbyheight/0.hex".into(), "", 200),
        ("/rest/blockhashbyheight/0.bin".into(), "", 200),
        ("/rest/blockhashbyheight/999.json".into(), "", 404),
        ("/rest/blockhashbyheight/999.hex".into(), "", 404),
        ("/rest/blockhashbyheight/999.bin".into(), "", 404),
        ("/rest/blockhashbyheight/abc.json".into(), "", 400),
        ("/rest/blockhashbyheight/0".into(), "", 404),
        ("/rest/blockhashbyheight/0.txt".into(), "", 400),
        (format!("/rest/spenttxouts/{HASH}.json"), "", 404),
        ("/rest/spenttxouts/not-a-hash.json".into(), "", 400),
        (format!("/rest/block/notxdetails/{HASH}.hex"), "", 404),
        (format!("/rest/block/notxdetails/{HASH}.txt"), "", 400),
        (format!("/rest/block/{HASH}.txt"), "", 400),
        (format!("/rest/blockpart/{HASH}.txt"), "", 400),
        (format!("/rest/headers/{HASH}.hex"), "count=1", 200),
        (format!("/rest/headers/{HASH}.bin"), "count=1", 200),
        (format!("/rest/headers/{HASH}.json"), "count=0", 400),
        (format!("/rest/getutxos/{HASH}-0.txt"), "", 400),
        (
            format!("/rest/getutxos/checkmempool/{HASH}-0.json"),
            "",
            200,
        ),
        ("/rest/mempool/info.hex".into(), "", 404),
        ("/rest/mempool/info.txt".into(), "", 400),
        (format!("/rest/spenttxouts/{HASH}.hex"), "", 404),
        (format!("/rest/spenttxouts/{HASH}.bin"), "", 404),
        (format!("/rest/spenttxouts/{HASH}.txt"), "", 400),
        ("/rest/unknown".into(), "", 404),
    ];

    for (path, query, status) in &cases {
        let response = route(&ctx, path, query, true);
        assert_eq!(response.status, *status, "{path}?{query}");
        if *status == 200 {
            let content_type = match path.rsplit_once('.') {
                Some((_, "json")) => "application/json",
                Some((_, "hex")) => "text/plain",
                _ => "application/octet-stream",
            };
            assert_eq!(response.content_type, content_type, "{path}?{query}");
        }
        assert_eq!(
            route(&ctx, path, query, false).status,
            404,
            "disabled REST must 404 for {path}?{query}"
        );
    }
    for prefix in REGISTRATIONS {
        assert!(
            cases.iter().any(|(path, _, _)| path.starts_with(prefix)),
            "no row probes {prefix}"
        );
    }
    let unknown = route(&ctx, "/rest/unknown", "", true);
    assert_eq!(
        String::from_utf8(unknown.body).expect("not-found body"),
        "not found"
    );
}

#[test]
fn chaininfo_json_uses_core_field_names_and_omits_absent_options() {
    let ctx = Arc::new(Context::new());
    let response = route(&ctx, "/rest/chaininfo.json", "", true);
    let value: Value = sonic_rs::from_slice(&response.body).expect("chaininfo JSON");
    for field in ["chain", "blocks", "headers", "bestblockhash"] {
        assert!(value.get(field).is_some(), "{field}: {value:?}");
    }
    for field in [
        "automatic_pruning",
        "prune_target_size",
        "pruneheight",
        "signet_challenge",
    ] {
        assert!(value.get(field).is_none(), "{field}: {value:?}");
    }
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
fn getutxos_post_canonical_wire_and_input_boundaries() {
    let ctx = Arc::new(Context::new());
    let mut wire = vec![2, 1, 1];
    wire.resize(38, 0);
    let get = route(&ctx, &GETUTXOS_JSON.replace(".json", ".bin"), "", true);
    for (format, body) in [
        ("bin", wire.clone()),
        ("hex", wire.to_lower_hex_string().into_bytes()),
    ] {
        let post = route_post(&ctx, &format!("/rest/getutxos.{format}"), &body, true);
        assert_eq!(post.status, 200);
        let bytes = if format == "hex" {
            Vec::<u8>::from_hex(core::str::from_utf8(&post.body).expect("hex").trim())
                .expect("response bytes")
        } else {
            post.body
        };
        assert_eq!(bytes, get.body);
        assert_eq!(
            &bytes[36..],
            &[1, 0, 0],
            "bitmap length, missing bit, zero coins"
        );
    }
    let uri = GETUTXOS_JSON.replace(".json", ".bin");
    assert_eq!(route_post(&ctx, &uri, &[], true).body, get.body);
    assert_eq!(route_post(&ctx, &uri, &[0, 0], true).status, 400);
    assert_eq!(
        route_post(&ctx, "/rest/getutxos.bin", b"0000", true).status,
        400
    );
    assert_eq!(
        route_post(&ctx, "/rest/getutxos.hex", &[0, 0], true).status,
        400
    );
    let mut fifteen = vec![0, 15];
    for _ in 0..15 {
        fifteen.extend_from_slice(&wire[2..]);
    }
    let response = route_post(&ctx, "/rest/getutxos.bin", &fifteen, true);
    assert_eq!(response.status, 200);
    assert_eq!(&response.body[36..], &[2, 0, 0, 0]);
    for flag in [0, 1] {
        let response = route_post(&ctx, "/rest/getutxos.bin", &[flag, 0], true);
        assert_eq!(response.status, 200);
        assert_eq!(&response.body[36..], &[0, 0]);
    }
}

#[test]
fn getutxos_post_rejects_malformed_and_oversized_inputs() {
    let ctx = Arc::new(Context::new());
    let mut wire = vec![1, 1, 1];
    wire.resize(38, 0);
    let malformed: &[&[u8]] = &[
        &[0],
        &[0, 1],
        &[0, 0, 0],
        &[0, 16],
        &[0, 253, 1, 0],
        &[0, 254, 0, 0, 0, 0],
        &[0, 255, 255, 255, 255, 255, 255, 255, 255, 255],
        &wire[..37],
    ];
    for body in malformed {
        assert_eq!(
            route_post(&ctx, "/rest/getutxos.bin", body, true).status,
            400,
            "{body:?}"
        );
    }
    for body in [b"0".as_slice(), b"gg", b"0 0", b"  ", &[255]] {
        assert_eq!(
            route_post(&ctx, "/rest/getutxos.hex", body, true).status,
            400
        );
    }
    for suffix in ["/checkmempool.bin", "/00-0.bin", "/checkmempool.json"] {
        assert_eq!(
            route_post(&ctx, &format!("/rest/getutxos{suffix}"), &[0, 0], true).status,
            400
        );
    }
    assert_eq!(
        route_post(&ctx, "/rest/getutxos.json", b"{}", true).status,
        400
    );
    assert_eq!(
        route_post(&ctx, "/rest/getutxos", &[0, 0], true).status,
        404
    );
    assert_eq!(
        route_post(&ctx, "/rest/getutxos.bin", &[], true).status,
        400
    );
    let mut at_limit = b"00 00".to_vec();
    at_limit.resize(MAX_GETUTXOS_BODY_BYTES, b' ');
    assert_eq!(
        route_post(&ctx, "/rest/getutxos.hex", &at_limit, true).status,
        200
    );
    at_limit.push(b' ');
    assert_eq!(
        route_post(&ctx, "/rest/getutxos.hex", &at_limit, true).status,
        400
    );
    assert_eq!(
        route_post(&ctx, "/rest/getutxos.hex", &at_limit, false).status,
        404
    );
}

#[test]
fn getutxos_post_uses_the_existing_applied_view_and_generation_fence() {
    let ctx = Arc::new(Context::new());
    let a = tip_snapshot(10, 0xaa, 100);
    ctx.chain.applied_tip.store(Some(Arc::clone(&a)));
    let publisher = Arc::clone(&ctx);
    arm_capture_hook(move || {
        publisher
            .chain
            .applied_tip
            .store(Some(tip_snapshot(20, 0xbb, 200)));
    });
    let response = route_post(&ctx, "/rest/getutxos.bin", &[0, 0], true);
    assert_eq!(response.status, 200);
    assert_eq!(&response.body[..4], &10_u32.to_le_bytes());
    assert_eq!(&response.body[4..36], &a.hash.to_le_bytes());
    ctx.mempool.gateway.force_chain_generation(3);
    assert_eq!(
        route_post(&ctx, "/rest/getutxos.bin", &[1, 0], true).status,
        503
    );
    ctx.mempool.gateway.force_chain_generation(4);
    let publisher = Arc::clone(&ctx);
    arm_capture_hook(move || publisher.mempool.gateway.force_chain_generation(6));
    assert_eq!(
        route_post(&ctx, "/rest/getutxos.bin", &[1, 0], true).status,
        503
    );
}

#[test]
fn getutxos_plain_read_waits_for_the_chain_transition() {
    let ctx = Arc::new(Context::new());
    ctx.chain
        .applied_tip
        .store(Some(tip_snapshot(10, 0xaa, 100)));
    let transition = ctx.chain.chain_transition.lock();
    let worker = Arc::clone(&ctx);
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (tx, rx) = std::sync::mpsc::channel();
    let join = std::thread::spawn(move || {
        started_tx.send(()).expect("started");
        tx.send(route_post(&worker, "/rest/getutxos.bin", &[0, 0], true))
            .expect("response");
    });
    started_rx.recv().expect("worker started");
    assert!(
        rx.recv_timeout(std::time::Duration::from_millis(50))
            .is_err()
    );
    let committed = tip_snapshot(20, 0xbb, 200);
    ctx.chain.applied_tip.store(Some(Arc::clone(&committed)));
    drop(transition);
    let response = rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .expect("settled response");
    join.join().expect("worker");
    assert_eq!(&response.body[..4], &20_u32.to_le_bytes());
    assert_eq!(&response.body[4..36], &committed.hash.to_le_bytes());
}

fn tip_snapshot(height: u32, byte: u8, count: u64) -> Arc<TipSnapshot> {
    Arc::new(TipSnapshot {
        tip_id: bitcoin_rs_chain::NodeId::new(height),
        height,
        chainwork: bitcoin_rs_chain::ChainWork::from(u128::from(count)),
        hash: Hash256::from_le_bytes(&[byte; 32]),
        chain_tx_count: bitcoin_rs_chain::ChainTxCount::established(count),
    })
}

const GETUTXOS_JSON: &str = "/rest/getutxos/\
        0000000000000000000000000000000000000000000000000000000000000001-0.json";

#[test]
fn getutxos_reports_one_coherent_tip_pair_under_concurrent_swap() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let ctx = Arc::new(Context::new());
    let a = tip_snapshot(10, 0xaa, 100);
    let b = tip_snapshot(20, 0xbb, 200);
    ctx.chain.applied_tip.store(Some(Arc::clone(&a)));

    let stop = Arc::new(AtomicBool::new(false));
    let (cell, swap_a, swap_b, flag) = (
        ctx.chain.applied_tip.clone(),
        Arc::clone(&a),
        Arc::clone(&b),
        Arc::clone(&stop),
    );
    let swapper = std::thread::spawn(move || {
        let mut flip = false;
        while !flag.load(Ordering::Relaxed) {
            flip = !flip;
            let tip = if flip { &swap_b } else { &swap_a };
            cell.store(Some(Arc::clone(tip)));
        }
    });

    let mut seen_a = false;
    let mut seen_b = false;
    for iteration in 0..100_000 {
        let response = route(&ctx, GETUTXOS_JSON, "", true);
        assert_eq!(response.status, 200);
        let value: Value = sonic_rs::from_slice(&response.body).expect("getutxos JSON");
        let height = u32::try_from(
            value
                .get("chainHeight")
                .and_then(Value::as_u64)
                .expect("chainHeight"),
        )
        .expect("height fits u32");
        let hash = value
            .get("chaintipHash")
            .and_then(Value::as_str)
            .expect("chaintipHash");
        if height == 20 {
            assert_eq!(hash, b.hash.to_string_be(), "a foreign hash rode height 20");
            seen_b = true;
        } else {
            assert_eq!(height, 10, "the route reported an unpublished height");
            assert_eq!(hash, a.hash.to_string_be(), "a foreign hash rode height 10");
            seen_a = true;
        }
        if iteration >= 199 && seen_a && seen_b {
            break;
        }
        std::thread::yield_now();
    }
    stop.store(true, Ordering::Relaxed);
    swapper.join().expect("swapper thread panicked");
    assert!(
        seen_a && seen_b,
        "a publication was never observed, so coherence proved nothing"
    );
}

#[test]
fn getutxos_keeps_captured_tip_after_publication() {
    let ctx = Arc::new(Context::new());
    let a = tip_snapshot(10, 0xaa, 100);
    ctx.chain.applied_tip.store(Some(Arc::clone(&a)));

    let publisher = Arc::clone(&ctx);
    arm_capture_hook(move || {
        publisher
            .chain
            .applied_tip
            .store(Some(tip_snapshot(20, 0xbb, 200)));
    });
    let response = route(&ctx, GETUTXOS_JSON, "", true);

    assert_eq!(response.status, 200);
    let value: Value = sonic_rs::from_slice(&response.body).expect("getutxos JSON");
    assert_eq!(
        value.get("chainHeight").and_then(Value::as_u64),
        Some(10),
        "the answer must describe the captured tip"
    );
    assert_eq!(
        value.get("chaintipHash").and_then(Value::as_str),
        Some(a.hash.to_string_be().as_str())
    );
    assert_eq!(
        ctx.chain.applied_tip.load_full().map(|tip| tip.height),
        Some(20),
        "the hook must really have published mid-response"
    );
}

#[test]
fn deploymentinfo_keeps_captured_tip_after_publication() {
    let genesis = bitcoin_rs_primitives::Network::Regtest.genesis_block();
    let ctx = Arc::new(Context::new());
    publish_active_chain(&ctx, &[genesis.header]);
    let applied_height = ctx
        .chain
        .applied_tip
        .load_full()
        .expect("published applied tip")
        .height;

    let arm_rival = |ctx: &Arc<Context>| {
        let publisher = Arc::clone(ctx);
        let height = applied_height + 40;
        arm_capture_hook(move || {
            publisher
                .chain
                .applied_tip
                .store(Some(tip_snapshot(height, 0xee, 9_000)));
        });
    };

    arm_rival(&ctx);
    let response = route(&ctx, "/rest/deploymentinfo.json", "", true);
    let value: Value = sonic_rs::from_slice(&response.body).expect("deploymentinfo JSON");
    assert!(
        value
            .get("deployments")
            .and_then(Value::as_object)
            .is_some_and(|deployments| !deployments.is_empty())
    );
    assert_eq!(
        value.get("height").and_then(Value::as_u64),
        Some(u64::from(applied_height)),
        "deploymentinfo must report the captured height"
    );
    assert_eq!(
        ctx.chain
            .applied_tip
            .load_full()
            .map(|published| published.height),
        Some(applied_height + 40),
        "the hook must really have published mid-response"
    );
}

const CHECKMEMPOOL_JSON: &str = "/rest/getutxos/checkmempool/\
        0000000000000000000000000000000000000000000000000000000000000001-0.json";

#[test]
fn getutxos_checkmempool_returns_503_on_unstable_generation() {
    let ctx = Arc::new(Context::new());
    ctx.mempool.gateway.force_chain_generation(3);
    let response = route(&ctx, CHECKMEMPOOL_JSON, "", true);
    assert_eq!(response.status, 503);
    assert_eq!(response.reason, "Service Unavailable");
    assert_eq!(response.content_type, "text/plain");
    assert_eq!(response.body, b"chain generation is odd; retry".to_vec());
}

#[test]
fn getutxos_checkmempool_rejects_moved_generation() {
    let ctx = Arc::new(Context::new());
    ctx.mempool.gateway.force_chain_generation(4);
    let mover = Arc::clone(&ctx);
    arm_capture_hook(move || mover.mempool.gateway.force_chain_generation(6));
    let response = route(&ctx, CHECKMEMPOOL_JSON, "", true);
    assert_eq!(response.status, 503);
    assert_eq!(response.body, b"chain generation is odd; retry".to_vec());
}

#[test]
fn plain_tip_routes_ignore_mempool_generation() {
    let ctx = Arc::new(Context::new());
    ctx.mempool.gateway.force_chain_generation(3);
    assert_eq!(route(&ctx, GETUTXOS_JSON, "", true).status, 200);
    assert_eq!(
        route(&ctx, "/rest/deploymentinfo.json", "", true).status,
        200
    );
}

#[test]
fn spenttxouts_genesis_json_ends_with_core_newline() {
    let ctx = Arc::new(Context::new());
    let hash = ctx.chain.chain_network.genesis_block_hash();
    let response = route(&ctx, &format!("/rest/spenttxouts/{hash}.json"), "", true);
    assert_eq!(response.status, 200);
    assert_eq!(response.content_type, "application/json");
    assert_eq!(response.body, b"[[]]\n");
}

#[test]
fn spenttxouts_unknown_block_is_not_found() {
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
                .contains("not found"),
            "{format}"
        );
    }
}
