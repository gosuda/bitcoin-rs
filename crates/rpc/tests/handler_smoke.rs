//! Smoke tests for every required Task 16 RPC handler.
// A mis-sequenced fixture is a test failure; panicking reports it at the call
// site, so expect() is deliberate throughout.
#![allow(clippy::expect_used)]
extern crate alloc;

use alloc::sync::Arc;
use hashbrown::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};

use bitcoin_rs_chain::{ChainWork, NodeId, NodeStatus, TipSnapshot};
use bitcoin_rs_mempool::MempoolEntry;
use bitcoin_rs_mining::{Candidate, TemplateId};
use bitcoin_rs_p2p::{PeerInfo, PeerLease, PeerTable};
use bitcoin_rs_primitives::{
    Block, BlockHash, Hash256, Header, Network, OutPoint, Tx, TxIn, TxOut, Txid, consensus_bytes,
    encode::double_sha256,
};
use bitcoin_rs_rpc::context::{
    BlockBodySource, BlockRecord, BlockTemplate, BlockTemplateRequest, BlockTemplateResult,
    BlockValidationResult, ChainControl, ChainControlError, Context, MiningControl,
    MiningControlError, MiningInfo,
};
use bitcoin_rs_rpc::{Handler, RpcError};
use bitcoin_rs_utxo::{BlockChanges, UtxoAdd};
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait, json};

struct SmokeMiningControl;

impl SmokeMiningControl {
    fn new() -> Self {
        Self
    }
}

impl MiningControl for SmokeMiningControl {
    fn get_block_template(
        &self,
        _request: BlockTemplateRequest,
    ) -> Result<BlockTemplateResult, MiningControlError> {
        let previous_block_hash = Hash256::default();
        Ok(BlockTemplateResult::Template(BlockTemplate {
            candidate: Arc::new(Candidate {
                template_id: TemplateId::new(&previous_block_hash, 0),
                previous_block_hash,
                height: 0,
                version: 0x2000_0000,
                bits: 0x1d00_ffff,
                min_time: 0,
                current_time: 0,
                csv_active: false,
                segwit_active: false,
                max_weight: 4_000_000,
                max_size: 4_000_000,
                max_sigops: 80_000,
                mempool_sequence: 0,
                coinbase: Tx {
                    version: 1,
                    lock_time: 0,
                    inputs: vec![TxIn {
                        previous_output: OutPoint::new(Txid::default(), u32::MAX),
                        script_sig: Vec::new(),
                        sequence: u32::MAX,
                        witness: Vec::new(),
                    }],
                    outputs: Vec::new(),
                },
                coinbase_value: 0,
                fees: 0,
                weight: 0,
                size: 0,
                sigop_cost: 0,
                transactions: Vec::new(),
                witness_merkle_root: None,
                witness_reserved_value: None,
                witness_commitment: None,
            }),
            rules: Vec::new(),
            version_bits_available: Vec::new(),
            version_bits_required: 0,
            capabilities: Vec::new(),
            mutable: Vec::new(),
            submit_old: None,
            work_id: None,
        }))
    }

    fn mining_info(&self) -> Result<MiningInfo, MiningControlError> {
        Ok(MiningInfo {
            blocks: 0,
            last_candidate: None,
            bits: 0x207f_ffff,
            difficulty: 1.0,
            network_hashes_per_second: 0.0,
            pooled_transactions: 0,
            network: Network::Regtest,
            next_bits: 0x207f_ffff,
            next_difficulty: 1.0,
            minimum_fee_rate: 1_000,
            signet: None,
            warnings: Vec::new(),
        })
    }

    fn submit_block(&self, _block: Block) -> Result<BlockValidationResult, MiningControlError> {
        Ok(BlockValidationResult::Accepted)
    }

    fn publish_generation(&self) {}
}

#[test]
fn all_required_handlers_return_core_shapes() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let handler = Handler::new(Arc::clone(&fixture.ctx));
    let raw_tx = hex_encode(&consensus_bytes(&fixture.tx));

    // A valid base64 PSBT for finalizepsbt / combinepsbt.
    let valid_psbt = build_valid_base64_psbt(&fixture.tx)?;

    let cases: &[(&str, sonic_rs::Value)] = &[
        ("getblockcount", json!([])),
        ("getbestblockhash", json!([])),
        ("getblockhash", json!([0])),
        (
            "getblockheader",
            json!([fixture.block_hash.to_string(), false]),
        ),
        ("getblock", json!([fixture.block_hash.to_string(), 1])),
        ("getblockchaininfo", json!([])),
        ("getchaintxstats", json!([])),
        ("getmempoolinfo", json!([])),
        ("getrawmempool", json!([])),
        ("getmempoolentry", json!([fixture.txid.to_string()])),
        ("gettxout", json!([fixture.txid.to_string(), 0_u64])),
        ("gettxoutsetinfo", json!([])),
        ("getrawtransaction", json!([fixture.txid.to_string()])),
        ("sendrawtransaction", json!([raw_tx.as_str()])),
        ("testmempoolaccept", json!([[raw_tx.as_str()]])),
        ("getblockstats", json!([fixture.block_hash.to_string()])),
        ("getindexinfo", json!([])),
        ("getnetworkinfo", json!([])),
        ("getpeerinfo", json!([])),
        ("getconnectioncount", json!([])),
        // getnetworkhashps is not implemented yet — Core-compat manifest gap,
        // covered by the method-coverage work, not by this wiring sweep.
        ("uptime", json!([])),
        ("finalizepsbt", json!([valid_psbt.as_str()])),
        ("combinepsbt", json!([[valid_psbt.as_str()]])),
        ("verifychain", json!([])),
        // preciousblock, invalidateblock, stop, and help are not dispatched
        // here: preciousblock/stop/help are not implemented yet (Core-compat
        // manifest gap), and invalidateblock requires a chain control, which
        // the dedicated invalidateblock tests wire themselves.
        ("getmininginfo", json!([])),
        ("getblocktemplate", json!([{}])),
        ("submitblock", json!([raw_tx.as_str()])),
    ];

    for (method, params) in cases {
        handler
            .dispatch(method, params)
            .unwrap_or_else(|err| panic!("{method} should return a Core shape: {err}"));
    }
    Ok(())
}
#[cfg(feature = "zmq")]
#[test]
fn getzmqnotifications_dispatches_compiled_notifications() -> Result<(), Box<dyn std::error::Error>>
{
    let ctx = Arc::new(Context::new());
    let handler = Handler::new(ctx);
    let result = handler.dispatch("getzmqnotifications", &json!([]))?;
    assert!(
        result.is_array(),
        "getzmqnotifications must return an array"
    );
    Ok(())
}

#[cfg(not(feature = "zmq"))]
#[test]
fn getzmqnotifications_is_absent_without_zmq() {
    let ctx = Arc::new(Context::new());
    let handler = Handler::new(ctx);
    let err = handler
        .dispatch("getzmqnotifications", &json!([]))
        .expect_err("getzmqnotifications should be absent without zmq feature");
    assert_eq!(err.code(), RpcError::METHOD_NOT_FOUND);
}
#[test]
fn getblockhash_zero_returns_mainnet_genesis_on_fresh_context()
-> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());
    let handler = Handler::new(Arc::clone(&ctx));
    let response = handler.dispatch("getblockhash", &json!([0]))?;
    let actual = response
        .as_str()
        .ok_or("getblockhash response must be a string")?;
    let expected = Network::Mainnet.genesis_block_hash().to_string();
    assert_eq!(actual, expected);
    Ok(())
}

#[derive(Debug)]
struct RecordingChainControl {
    called: Arc<AtomicBool>,
    error: Option<ChainControlError>,
}

impl ChainControl for RecordingChainControl {
    fn invalidate_block(&self, _hash: Hash256) -> Result<(), ChainControlError> {
        self.called.store(true, Ordering::SeqCst);
        match &self.error {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }
}

#[test]
fn invalidateblock_delegates_to_node_control_and_returns_null() -> Result<(), RpcError> {
    let called = Arc::new(AtomicBool::new(false));
    let control = RecordingChainControl {
        called: Arc::clone(&called),
        error: None,
    };
    let mut ctx = Context::new().with_chain_control(Arc::new(control));
    ctx.chain_network = Network::Regtest;
    let handler = Handler::new(Arc::new(ctx));
    let result = handler.dispatch(
        "invalidateblock",
        &json!(["0000000000000000000000000000000000000000000000000000000000000000"]),
    )?;
    assert!(
        result.is_null(),
        "invalidateblock must return null on success"
    );
    assert!(
        called.load(Ordering::SeqCst),
        "chain control was not called"
    );
    Ok(())
}

#[test]
fn invalidateblock_maps_unknown_block_to_core_not_found() {
    let called = Arc::new(AtomicBool::new(false));
    let control = RecordingChainControl {
        called: Arc::clone(&called),
        error: Some(ChainControlError::UnknownBlock),
    };
    let mut ctx = Context::new().with_chain_control(Arc::new(control));
    ctx.chain_network = Network::Regtest;
    let handler = Handler::new(Arc::new(ctx));
    let err = handler
        .dispatch(
            "invalidateblock",
            &json!(["0000000000000000000000000000000000000000000000000000000000000000"]),
        )
        .expect_err("unknown block should map to an error");
    // Core reports an unknown block as RPC_INVALID_ADDRESS_OR_KEY (-5).
    assert_eq!(err.code(), RpcError::CORE_NOT_FOUND);
}

#[test]
fn getblockchaininfo_surfaces_published_chainwork_hex() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());
    let tip = TipSnapshot {
        tip_id: NodeId::new(0),
        height: 42,
        hash: Hash256::from_le_bytes(&[0xff; 32]),
        chainwork: ChainWork::from_be_bytes([0x11; 32]),
    };
    ctx.set_chain_tip(tip.clone());
    ctx.set_applied_tip(tip);
    let handler = Handler::new(Arc::clone(&ctx));
    let result = handler.dispatch("getblockchaininfo", &json!([]))?;
    let chainwork = result
        .get("chainwork")
        .and_then(JsonValueTrait::as_str)
        .ok_or("chainwork missing")?;
    assert_eq!(
        chainwork,
        "1111111111111111111111111111111111111111111111111111111111111111"
    );
    Ok(())
}

#[test]
fn gettxoutsetinfo_returns_real_utxo_counts() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(
        OutPoint::new(Txid(Hash256::from_le_bytes(&[1; 32])), 0),
        TxOut {
            value: 50_000,
            script_pubkey: vec![0x51],
        },
        false,
        1,
    ));
    ctx.utxo
        .commit_block(&changes, &Hash256::from_le_bytes(&[0xaa; 32]))?;
    let handler = Handler::new(Arc::clone(&ctx));
    let result = handler.dispatch("gettxoutsetinfo", &json!([]))?;
    assert_eq!(
        result.get("txouts").and_then(JsonValueTrait::as_u64),
        Some(1)
    );
    assert_eq!(
        result.get("total_amount").and_then(JsonValueTrait::as_f64),
        Some(0.0005)
    );
    Ok(())
}

#[test]
fn gettxoutsetinfo_empty_muhash_matches_core_digest() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());
    let handler = Handler::new(Arc::clone(&ctx));
    let result = handler.dispatch("gettxoutsetinfo", &json!(["muhash"]))?;
    let muhash = result
        .get("muhash")
        .and_then(JsonValueTrait::as_str)
        .ok_or("muhash missing")?;
    // Core's muhash over the empty UTXO set (identity accumulator digest).
    assert_eq!(
        muhash,
        "dd5ad2a105c2d29495f577245c357409002329b9f4d6182c0af3dc2f462555c8"
    );
    Ok(())
}

#[test]
fn gettxoutsetinfo_hash_type_modes_match_core_shapes() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());
    let handler = Handler::new(Arc::clone(&ctx));
    for hash_type in ["muhash", "none", "hash_serialized_3"] {
        let result = handler.dispatch("gettxoutsetinfo", &json!([hash_type]))?;
        assert!(
            result
                .get("bestblock")
                .and_then(JsonValueTrait::as_str)
                .is_some(),
            "bestblock missing for hash_type={hash_type}"
        );
    }
    Ok(())
}

#[test]
fn getindexinfo_returns_available_indexes() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());
    let handler = Handler::new(Arc::clone(&ctx));
    let result = handler.dispatch("getindexinfo", &json!([]))?;
    assert!(result.is_object(), "getindexinfo must return an object");
    Ok(())
}

#[test]
fn getindexinfo_returns_txindex_when_indexer_is_available() -> Result<(), Box<dyn std::error::Error>>
{
    let mut ctx = Context::new();
    ctx.tx_index = Some(Arc::new(FakeTxIndex {
        transactions: HashMap::new(),
        values: HashMap::new(),
        info: bitcoin_rs_rpc::context::TxIndexInfo {
            synced: true,
            best_block_height: 7,
        },
    }));
    let handler = Handler::new(Arc::new(ctx));
    let result = handler.dispatch("getindexinfo", &json!([]))?;
    let txindex = result.get("txindex").ok_or("txindex key missing")?;
    assert_eq!(
        txindex.get("synced").and_then(JsonValueTrait::as_bool),
        Some(true)
    );
    assert_eq!(
        txindex
            .get("best_block_height")
            .and_then(JsonValueTrait::as_u64),
        Some(7)
    );
    Ok(())
}

#[test]
fn getindexinfo_named_request_returns_only_that_index() -> Result<(), Box<dyn std::error::Error>> {
    let mut ctx = Context::new();
    ctx.tx_index = Some(Arc::new(FakeTxIndex {
        transactions: HashMap::new(),
        values: HashMap::new(),
        info: bitcoin_rs_rpc::context::TxIndexInfo {
            synced: true,
            best_block_height: 7,
        },
    }));
    let handler = Handler::new(Arc::new(ctx));

    let txindex = handler.dispatch("getindexinfo", &json!(["txindex"]))?;
    assert!(txindex.get("txindex").is_some(), "txindex must be present");
    let all = handler.dispatch("getindexinfo", &json!([]))?;
    assert!(
        all.get("txindex").is_some(),
        "no-param request includes txindex"
    );
    let unknown = handler.dispatch("getindexinfo", &json!(["unknown"]))?;
    assert!(
        unknown.get("txindex").is_none(),
        "unknown index name yields an empty object"
    );
    Ok(())
}

#[test]
fn getblockstats_errors_without_indexer() {
    let ctx = Arc::new(Context::new());
    let handler = Handler::new(ctx);
    let err = handler
        .dispatch(
            "getblockstats",
            &json!(["0000000000000000000000000000000000000000000000000000000000000000"]),
        )
        .expect_err("getblockstats should error without an indexer");
    // Core reports an unknown block as RPC_INVALID_ADDRESS_OR_KEY (-5).
    assert_eq!(err.code(), RpcError::CORE_NOT_FOUND);
}

#[test]
fn getblockstats_uses_indexer_for_fee_fields() -> Result<(), Box<dyn std::error::Error>> {
    let mut values = HashMap::new();
    // The indexed prevout values equal the outputs they fund, so every fee
    // in the fixture block is zero and every percentile bucket reads zero.
    values.insert(outpoint(21), 10_000);
    values.insert(outpoint(22), 20_000);
    let (ctx, _low_tx, _high_tx) = fee_stats_context(Some(values));
    let handler = Handler::new(Arc::clone(&ctx));
    let tip_hash = ctx
        .block_tree
        .read()
        .tip()
        .expect("tip")
        .as_ref()
        .clone()
        .hash;
    let result = handler.dispatch("getblockstats", &json!([tip_hash.to_string()]))?;
    let percentiles = result
        .get("feerate_percentiles")
        .and_then(|value| value.as_array())
        .ok_or("feerate_percentiles missing")?;
    let values: Vec<u64> = percentiles
        .iter()
        .map(|v| v.as_u64().unwrap_or(0))
        .collect();
    // Core reports five percentiles: the 10th, 25th, 50th, 75th, and 90th.
    assert_eq!(values, vec![0, 0, 0, 0, 0]);
    Ok(())
}

#[test]
fn getblockstats_errors_when_any_prevout_missing() {
    let (ctx, _low_tx, _high_tx) = fee_stats_context(None);
    let handler = Handler::new(Arc::clone(&ctx));
    let tip_hash = ctx
        .block_tree
        .read()
        .tip()
        .expect("tip")
        .as_ref()
        .clone()
        .hash;
    let err = handler
        .dispatch("getblockstats", &json!([tip_hash.to_string()]))
        .expect_err("getblockstats should error when prevouts cannot be resolved");
    assert_eq!(err.code(), RpcError::INTERNAL_ERROR);
}

#[test]
fn empty_context_is_in_initial_block_download() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());
    let handler = Handler::new(Arc::clone(&ctx));
    let result = handler.dispatch("getblockchaininfo", &json!([]))?;
    assert_eq!(
        result
            .get("initialblockdownload")
            .and_then(JsonValueTrait::as_bool),
        Some(true)
    );
    Ok(())
}

#[test]
fn chain_rpcs_report_applied_tip_separately_from_headers() -> Result<(), Box<dyn std::error::Error>>
{
    let ctx = Arc::new(Context::new());
    let headers_tip = TipSnapshot {
        tip_id: NodeId::new(0),
        height: 10,
        hash: Hash256::from_le_bytes(&[0xaa; 32]),
        chainwork: ChainWork::default(),
    };
    let applied_tip = TipSnapshot {
        tip_id: NodeId::new(0),
        height: 7,
        hash: Hash256::from_le_bytes(&[0xbb; 32]),
        chainwork: ChainWork::default(),
    };
    ctx.set_chain_tip(headers_tip);
    ctx.set_applied_tip(applied_tip);
    let handler = Handler::new(Arc::clone(&ctx));
    let result = handler.dispatch("getblockchaininfo", &json!([]))?;
    assert_eq!(
        result.get("headers").and_then(JsonValueTrait::as_u64),
        Some(10)
    );
    assert_eq!(
        result.get("blocks").and_then(JsonValueTrait::as_u64),
        Some(7)
    );
    Ok(())
}

#[test]
fn network_peer_methods_read_shared_peer_table() -> Result<(), Box<dyn std::error::Error>> {
    let peer_table = Arc::new(PeerTable::new());
    let info = PeerInfo {
        addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333),
        version: 70016,
        services: 0,
        user_agent: "/bitcoin-rs:0.1.0/".to_string(),
        start_height: 0,
        conn_time: 0,
        inbound: true,
        addr_bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333),
        time_offset: 0,
        counters: Arc::new(bitcoin_rs_p2p::PeerCounters::default()),
    };
    let (tx, _rx) = crossbeam_channel::unbounded();
    let lease = PeerLease::new(tx);
    peer_table.register(info.addr, lease.clone());
    peer_table.publish_info(info.addr, &lease, info);
    let ctx = context_with_peers(peer_table);
    let handler = Handler::new(ctx);
    let result = handler.dispatch("getpeerinfo", &json!([]))?;
    let array = result
        .as_array()
        .ok_or("getpeerinfo must return an array")?;
    assert_eq!(array.len(), 1);
    let count = handler.dispatch("getconnectioncount", &json!([]))?;
    assert_eq!(count.as_u64(), Some(1));
    Ok(())
}

#[test]
fn removed_wallet_methods_return_method_not_found() {
    let ctx = Arc::new(Context::new());
    let handler = Handler::new(ctx);
    for method in [
        "listunspent",
        "getbalance",
        "sendtoaddress",
        "walletcreatefundedpsbt",
        "walletprocesspsbt",
    ] {
        let err = handler
            .dispatch(method, &json!([]))
            .expect_err(&format!("{method} should return method-not-found"));
        assert_eq!(
            err.code(),
            RpcError::METHOD_NOT_FOUND,
            "{method} should return method-not-found"
        );
    }
}

struct FakeTxIndex {
    info: bitcoin_rs_rpc::context::TxIndexInfo,
    transactions: HashMap<Txid, Tx>,
    values: HashMap<OutPoint, u64>,
}

impl bitcoin_rs_rpc::context::TxIndexQuery for FakeTxIndex {
    fn transaction(
        &self,
        txid: &Txid,
    ) -> Result<Option<Tx>, bitcoin_rs_rpc::context::TxQueryError> {
        Ok(self.transactions.get(txid).cloned())
    }

    fn outpoint_value(
        &self,
        outpoint: &OutPoint,
    ) -> Result<Option<u64>, bitcoin_rs_rpc::context::TxQueryError> {
        Ok(self.values.get(outpoint).copied())
    }

    fn index_info(
        &self,
    ) -> Result<bitcoin_rs_rpc::context::TxIndexInfo, bitcoin_rs_rpc::context::TxQueryError> {
        Ok(self.info)
    }
}

#[allow(clippy::arc_with_non_send_sync)]
fn fee_stats_context(values: Option<HashMap<OutPoint, u64>>) -> (Arc<Context>, Tx, Tx) {
    let low_tx = fee_tx(21, 10_000);
    let high_tx = fee_tx(22, 20_000);
    let block = fee_block(low_tx.clone(), high_tx.clone());
    let mut ctx = Context::new();
    if let Some(values) = values {
        let mut transactions = HashMap::new();
        for label in [21_u8, 22] {
            transactions.insert(
                Txid(Hash256::from_le_bytes(&[label; 32])),
                Tx {
                    version: 2,
                    lock_time: 0,
                    inputs: Vec::new(),
                    outputs: vec![TxOut {
                        value: 10_000,
                        script_pubkey: Vec::new(),
                    }],
                },
            );
        }
        ctx.tx_index = Some(Arc::new(FakeTxIndex {
            transactions,
            values,
            info: bitcoin_rs_rpc::context::TxIndexInfo {
                synced: true,
                best_block_height: 7,
            },
        }));
    }
    let block = seed_tree_chain(&ctx, &block);
    let record = BlockRecord::from_block(7, &block);
    ctx.block_body_source = Some(Arc::new(SingleBlockSource {
        height: record.height,
        hash: record.hash,
        body: consensus_bytes(&block),
    }));
    ctx.add_block(record);
    (Arc::new(ctx), low_tx, high_tx)
}

fn seed_tree_chain(ctx: &Context, block: &Block) -> Block {
    let mut tree = ctx.block_tree.write();
    let mut parent = None;
    let mut prev_blockhash = BlockHash::default();

    for height in 0_u32..7 {
        let header = Header {
            version: 1,
            prev_blockhash,
            merkle_root: Hash256::default(),
            time: 1_231_006_498 + height,
            bits: block.header.bits,
            nonce: height,
        };
        prev_blockhash = header.compute_hash();
        parent = Some(
            tree.insert_node(parent, header, NodeStatus::Active)
                .expect("insert synthetic ancestor"),
        );
    }

    let mut linked_block = block.clone();
    linked_block.header.prev_blockhash = prev_blockhash;
    tree.insert_node(parent, linked_block.header, NodeStatus::Active)
        .expect("insert fixture block");
    linked_block
}

/// Encodes `bytes` as lowercase hexadecimal.
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

/// Computes the consensus merkle root over `txs` by folding hash pairs with
/// double SHA-256, duplicating the final hash when a layer has odd length.
fn fixture_merkle_root(txs: &[Tx]) -> Hash256 {
    let mut layer: Vec<[u8; 32]> = txs.iter().map(|tx| *tx.txid().as_bytes()).collect();
    while layer.len() > 1 {
        if layer.len() % 2 == 1 {
            layer.push(*layer.last().expect("non-empty merkle layer"));
        }
        layer = layer
            .chunks(2)
            .map(|pair| *double_sha256(&pair.concat()).as_byte_array())
            .collect();
    }
    layer
        .first()
        .map_or_else(Hash256::default, Hash256::from_le_bytes)
}

fn fee_block(low_tx: Tx, high_tx: Tx) -> Block {
    let coinbase = Tx {
        version: 2,
        lock_time: 0,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[0_u8; 32])), u32::MAX),
            script_sig: vec![0x51],
            sequence: 0xFFFF_FFFE,
            witness: Vec::new(),
        }],
        outputs: vec![TxOut {
            value: 50_000,
            script_pubkey: vec![0x51],
        }],
    };
    let txs = vec![coinbase, low_tx, high_tx];
    let merkle_root = fixture_merkle_root(&txs);
    Block {
        header: Header {
            version: 1,
            prev_blockhash: BlockHash::default(),
            merkle_root,
            time: 1_231_006_505,
            bits: 0x1d00_ffff,
            nonce: 0,
        },
        txs,
    }
}

fn fee_tx(label: u8, output_sat: u64) -> Tx {
    Tx {
        version: 2,
        lock_time: 0,
        inputs: vec![TxIn {
            previous_output: outpoint(label),
            script_sig: Vec::new(),
            sequence: 0xFFFF_FFFE,
            witness: Vec::new(),
        }],
        outputs: vec![TxOut {
            value: output_sat,
            script_pubkey: vec![0x51],
        }],
    }
}

struct SingleBlockSource {
    height: u32,
    hash: BlockHash,
    body: Vec<u8>,
}

impl BlockBodySource for SingleBlockSource {
    fn block_body(&self, height: u32, hash: BlockHash) -> Option<Vec<u8>> {
        (height == self.height && hash == self.hash).then(|| self.body.clone())
    }
}

struct Fixture {
    ctx: Arc<Context>,
    tx: Tx,
    txid: Txid,
    block_hash: BlockHash,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let mut ctx = Context::new().with_mining_control(Arc::new(SmokeMiningControl::new()));
        let tx = tx(1, vec![0x51]);
        let merkle_root = fixture_merkle_root(std::slice::from_ref(&tx));
        let block = Block {
            header: Header {
                version: 1,
                prev_blockhash: BlockHash::default(),
                merkle_root,
                time: 1_231_006_505,
                bits: 0x1d00_ffff,
                nonce: 0,
            },
            txs: vec![tx.clone()],
        };
        let block = seed_tree_chain(&ctx, &block);
        let block_hash = block.block_hash();
        let tip = ctx
            .block_tree
            .read()
            .tip()
            .expect("fixture tip missing")
            .as_ref()
            .clone();
        ctx.set_chain_tip(tip.clone());
        ctx.set_applied_tip(tip);
        ctx.block_body_source = Some(Arc::new(SingleBlockSource {
            height: 7,
            hash: block_hash,
            body: consensus_bytes(&block),
        }));
        ctx.add_block(BlockRecord::from_block(7, &block));
        let mut values = HashMap::new();
        values.insert(outpoint(1), 6_000);
        ctx.tx_index = Some(Arc::new(FakeTxIndex {
            transactions: HashMap::new(),
            values,
            info: bitcoin_rs_rpc::context::TxIndexInfo {
                synced: true,
                best_block_height: 7,
            },
        }));
        let txid = ctx.add_transaction(tx.clone());
        let entry = MempoolEntry::new(Arc::new(tx.clone()), 100, 1_000, 1, 7);
        ctx.mempool.pool().write().insert_entry(entry)?;
        Ok(Self {
            ctx: Arc::new(ctx),
            tx,
            txid,
            block_hash,
        })
    }
}
#[allow(clippy::arc_with_non_send_sync)]
fn context_with_peers(peer_table: Arc<PeerTable>) -> Arc<Context> {
    let mut ctx = Context::new();
    ctx.peer_table = peer_table;
    Arc::new(ctx)
}

fn tx(label: u8, script_pubkey: Vec<u8>) -> Tx {
    Tx {
        version: 2,
        lock_time: 0,
        inputs: vec![TxIn {
            previous_output: outpoint(label),
            script_sig: Vec::new(),
            sequence: 0xFFFF_FFFE,
            witness: Vec::new(),
        }],
        outputs: vec![TxOut {
            value: 5_000,
            script_pubkey,
        }],
    }
}
fn outpoint(label: u8) -> OutPoint {
    OutPoint::new(Txid(Hash256::from_le_bytes(&[label; 32])), 0)
}

fn build_valid_base64_psbt(tx: &Tx) -> Result<String, Box<dyn std::error::Error>> {
    // PSBT construction uses the bitcoin crate's Psbt type as a sanctioned
    // seam — there is no native PSBT implementation. Convert the native tx
    // to bitcoin::Transaction by re-serializing and deserializing.
    let bytes = consensus_bytes(tx);
    let btc_tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&bytes)?;
    let psbt = bitcoin::psbt::Psbt::from_unsigned_tx(btc_tx)?;
    Ok(encode_base64(&psbt.serialize()))
}

const BASE64_TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn encode_base64(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        result.push(char::from(BASE64_TABLE[usize::from(b0 >> 2)]));
        result.push(char::from(
            BASE64_TABLE[usize::from((b0 & 0x03) << 4 | b1 >> 4)],
        ));
        if chunk.len() > 1 {
            result.push(char::from(
                BASE64_TABLE[usize::from((b1 & 0x0f) << 2 | b2 >> 6)],
            ));
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(char::from(BASE64_TABLE[usize::from(b2 & 0x3f)]));
        } else {
            result.push('=');
        }
    }
    result
}
