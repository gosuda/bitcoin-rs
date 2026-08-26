//! Smoke tests for every required Task 16 RPC handler.
extern crate alloc;

use alloc::sync::Arc;
use hashbrown::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};

use bitcoin::consensus::encode::serialize;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::Hash as _;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use bitcoin_rs_chain::{ChainWork, NodeId, NodeStatus, TipSnapshot};
use bitcoin_rs_mempool::MempoolEntry;
use bitcoin_rs_p2p::PeerInfo;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_rpc::context::{
    BlockBodySource, BlockRecord, ChainControl, ChainControlError, Context,
};
use bitcoin_rs_rpc::{Handler, RpcError};
use bitcoin_rs_utxo::{BlockChanges, UtxoAdd};
use parking_lot::RwLock;
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, json};

#[test]
fn all_required_handlers_return_core_shapes() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let handler = Handler::new(Arc::clone(&fixture.ctx));
    let raw_tx = serialize_hex(&fixture.tx);
    let valid_psbt = build_valid_base64_psbt(&fixture.tx)?;
    let txid = fixture.txid.to_string();
    let block_hash = fixture.block_hash.to_string_be();
    let descriptor = "addr(1111111111111111111114oLvT2)";
    let descriptor_info = handler.dispatch("getdescriptorinfo", &json!([descriptor]))?;
    let checksummed_descriptor = descriptor_info
        .get("descriptor")
        .as_str()
        .ok_or("getdescriptorinfo omitted descriptor")?
        .to_owned();

    let calls = [
        ("getblockchaininfo", json!([])),
        ("getblockcount", json!([])),
        ("getblockhash", json!([7])),
        ("getbestblockhash", json!([])),
        ("getblock", json!([block_hash.as_str(), 1])),
        ("getblockheader", json!([block_hash.as_str(), true])),
        ("getblockstats", json!([7])),
        ("gettxoutsetinfo", json!([])),
        ("getrawtransaction", json!([txid.as_str(), true])),
        ("gettxout", json!([txid.as_str(), 0])),
        ("gettxoutproof", json!([[txid.as_str()]])),
        ("verifytxoutproof", json!([""])),
        ("sendrawtransaction", json!([raw_tx.as_str()])),
        ("testmempoolaccept", json!([[raw_tx.as_str()]])),
        ("decoderawtransaction", json!([raw_tx.as_str()])),
        ("getmempoolinfo", json!([])),
        ("getmempoolentry", json!([txid.as_str()])),
        ("getrawmempool", json!([])),
        ("getmempoolancestors", json!([txid.as_str()])),
        ("getmempooldescendants", json!([txid.as_str()])),
        ("estimatesmartfee", json!([6])),
        ("estimaterawfee", json!([6])),
        ("getnetworkinfo", json!([])),
        ("getpeerinfo", json!([])),
        ("addnode", json!(["127.0.0.1:8333", "onetry"])),
        ("disconnectnode", json!(["127.0.0.1:8333"])),
        ("getconnectioncount", json!([])),
        ("getnettotals", json!([])),
        ("getblocktemplate", json!([{}])),
        ("submitblock", json!([""])),
        ("prioritisetransaction", json!([txid.as_str(), 0, 0])),
        ("getdescriptorinfo", json!([descriptor])),
        ("deriveaddresses", json!([checksummed_descriptor.as_str()])),
        (
            "scantxoutset",
            json!(["start", ["addr(1111111111111111111114oLvT2)"]]),
        ),
        ("finalizepsbt", json!([valid_psbt.as_str()])),
        ("combinepsbt", json!([[valid_psbt.as_str()]])),
    ];

    for (method, params) in calls {
        let response = handler.dispatch(method, &params);
        assert!(response.is_ok(), "{method} failed: {response:?}");
    }

    assert!(
        handler
            .dispatch("getblockchaininfo", &json!([]))?
            .get("blocks")
            .is_u64()
    );
    assert!(
        handler
            .dispatch("getmempoolinfo", &json!([]))?
            .get("size")
            .is_u64()
    );
    assert!(
        handler
            .dispatch("getnetworkinfo", &json!([]))?
            .get("networks")
            .as_array()
            .is_some()
    );
    assert!(
        handler
            .dispatch("getblocktemplate", &json!([{}]))?
            .get("longpollid")
            .is_str()
    );
    Ok(())
}

#[test]
fn getblockhash_zero_returns_mainnet_genesis_on_fresh_context()
-> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());
    let handler = Handler::new(ctx);
    let response = handler.dispatch("getblockhash", &json!([0]))?;
    let actual = response
        .as_str()
        .ok_or("getblockhash response must be a string")?;
    let expected = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Bitcoin)
        .block_hash()
        .to_string();
    assert_eq!(actual, expected);
    Ok(())
}

#[derive(Debug)]
struct RecordingChainControl {
    called: Arc<AtomicBool>,
    result: Result<(), ChainControlError>,
}

impl ChainControl for RecordingChainControl {
    fn invalidate_block(&self, _hash: Hash256) -> Result<(), ChainControlError> {
        self.called.store(true, Ordering::Release);
        self.result.clone()
    }
}

#[test]
fn invalidateblock_delegates_to_node_control_and_returns_null() -> Result<(), RpcError> {
    let called = Arc::new(AtomicBool::new(false));
    let ctx = Context::new().with_chain_control(Arc::new(RecordingChainControl {
        called: Arc::clone(&called),
        result: Ok(()),
    }));
    let handler = Handler::new(Arc::new(ctx));
    let hash = Hash256::from_le_bytes(&[7_u8; 32]).to_string_be();

    assert!(
        handler
            .dispatch("invalidateblock", &json!([hash]))?
            .is_null()
    );
    assert!(called.load(Ordering::Acquire));
    Ok(())
}

#[test]
fn invalidateblock_maps_unknown_block_to_core_not_found() -> Result<(), Box<dyn std::error::Error>>
{
    let ctx = Context::new().with_chain_control(Arc::new(RecordingChainControl {
        called: Arc::new(AtomicBool::new(false)),
        result: Err(ChainControlError::UnknownBlock),
    }));
    let handler = Handler::new(Arc::new(ctx));
    let hash = Hash256::from_le_bytes(&[8_u8; 32]).to_string_be();

    let error = handler
        .dispatch("invalidateblock", &json!([hash]))
        .err()
        .ok_or_else(|| std::io::Error::other("unknown block unexpectedly succeeded"))?;
    assert_eq!(error.code(), RpcError::CORE_NOT_FOUND);
    Ok(())
}

#[test]
fn getblockchaininfo_surfaces_published_chainwork_hex() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());
    let mut chainwork = [0_u8; 32];
    chainwork[30] = 0xab;
    chainwork[31] = 0xcd;
    ctx.set_chain_tip(TipSnapshot {
        tip_id: NodeId::new(1),
        height: 1,
        chainwork: ChainWork::from_be_bytes(chainwork),
        hash: Hash256::from_le_bytes(&[1_u8; 32]),
    });
    let handler = Handler::new(ctx);

    let result = handler.dispatch("getblockchaininfo", &json!([]))?;
    let chainwork_value = result.get("chainwork");
    let chainwork = chainwork_value
        .as_str()
        .ok_or("chainwork must be a string")?;

    assert_eq!(chainwork.len(), 64);
    assert!(
        chainwork
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "chainwork must be lowercase hex"
    );
    assert_eq!(
        chainwork,
        "000000000000000000000000000000000000000000000000000000000000abcd"
    );
    Ok(())
}

#[test]
fn gettxoutsetinfo_returns_real_utxo_counts() -> Result<(), Box<dyn std::error::Error>> {
    let handler = Handler::new(Arc::new(Context::new()));
    let result = handler.dispatch("gettxoutsetinfo", &json!([]))?;

    assert_eq!(result.get("txouts").as_u64(), Some(0));
    assert_eq!(result.get("transactions").as_u64(), Some(0));
    assert_eq!(result.get("bogosize").as_u64(), Some(0));
    assert_eq!(result.get("total_amount").as_f64(), Some(0.0));
    let hash_serialized_value = result.get("hash_serialized_3");
    let hash_serialized = hash_serialized_value
        .as_str()
        .ok_or("hash_serialized_3 must be a string")?;
    assert_eq!(hash_serialized.len(), 64);
    assert!(
        hash_serialized
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "hash_serialized_3 must be lowercase hex"
    );
    Ok(())
}

#[test]
fn gettxoutsetinfo_empty_muhash_matches_core_digest() -> Result<(), Box<dyn std::error::Error>> {
    const EMPTY_MUHASH_CORE_DIGEST: &str =
        "dd5ad2a105c2d29495f577245c357409002329b9f4d6182c0af3dc2f462555c8";

    let handler = Handler::new(Arc::new(Context::new()));
    let result = handler.dispatch("gettxoutsetinfo", &json!(["muhash"]))?;

    assert_eq!(result.get("txouts").as_u64(), Some(0));
    assert_eq!(result.get("transactions").as_u64(), Some(0));
    assert_eq!(
        result.get("muhash").as_str(),
        Some(EMPTY_MUHASH_CORE_DIGEST)
    );
    assert!(result.get("hash_serialized_3").is_none());
    Ok(())
}

#[test]
fn gettxoutsetinfo_hash_type_modes_match_core_shapes() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());
    let txid = Hash256::from_le_bytes(&[0x42; 32]);
    let outpoint = bitcoin_rs_primitives::OutPoint::new(txid, 0);
    let txout = TxOut {
        value: Amount::from_sat(12_345),
        script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
    };
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(outpoint, txout, true, 9));
    ctx.utxo
        .commit_block(&changes, &Hash256::from_le_bytes(&[0x24; 32]))?;
    let expected_hash = bitcoin_rs_utxo::hash_serialized_3(&ctx.utxo)?.to_string_be();
    let expected_muhash = ctx
        .coin_stats
        .snapshot()
        .muhash
        .finalize_hash()
        .to_string_be();
    let handler = Handler::new(ctx);

    let default_result = handler.dispatch("gettxoutsetinfo", &json!([]))?;
    assert_eq!(
        default_result.get("hash_serialized_3").as_str(),
        Some(expected_hash.as_str())
    );
    assert!(default_result.get("muhash").is_none());

    let explicit_result = handler.dispatch("gettxoutsetinfo", &json!(["hash_serialized_3"]))?;
    assert_eq!(
        explicit_result.get("hash_serialized_3").as_str(),
        Some(expected_hash.as_str())
    );
    assert!(explicit_result.get("muhash").is_none());

    let muhash_result = handler.dispatch("gettxoutsetinfo", &json!(["muhash"]))?;
    let muhash_value = muhash_result.get("muhash");
    let muhash = muhash_value.as_str().ok_or("muhash must be a string")?;
    assert_eq!(muhash.len(), 64);
    assert_eq!(muhash, expected_muhash.as_str());
    assert!(
        muhash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "muhash must be lowercase hex"
    );
    assert!(muhash_result.get("hash_serialized_3").is_none());

    let none_result = handler.dispatch("gettxoutsetinfo", &json!(["none"]))?;
    assert!(none_result.get("hash_serialized_3").is_none());
    assert!(none_result.get("muhash").is_none());

    assert!(matches!(
        handler.dispatch("gettxoutsetinfo", &json!(["sha3"])),
        Err(RpcError::InvalidParams(
            "hash_type must be one of: hash_serialized_3, muhash, none"
        ))
    ));
    Ok(())
}

#[test]
fn getindexinfo_returns_available_indexes() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());
    let handler = Handler::new(Arc::clone(&ctx));

    let result = handler.dispatch("getindexinfo", &json!([]))?;

    let txindex = result.get("txindex");
    assert!(
        txindex.is_none(),
        "txindex entry unexpectedly present: {result:?}"
    );

    let filter_index = result.get("basicblockfilterindex");
    assert!(
        filter_index.is_none(),
        "basicblockfilterindex entry unexpectedly present: {result:?}"
    );

    Ok(())
}

#[test]
fn getindexinfo_returns_txindex_when_indexer_is_available() -> Result<(), Box<dyn std::error::Error>>
{
    let mut ctx = Context::new();
    ctx.tx_index = Some(Arc::new(FakeTxIndex {
        values: HashMap::new(),
        info: bitcoin_rs_rpc::context::TxIndexInfo {
            synced: false,
            best_block_height: 0,
        },
    }));
    let handler = Handler::new(Arc::new(ctx));

    let result = handler.dispatch("getindexinfo", &json!(["txindex"]))?;
    let txindex = result.get("txindex");

    assert!(txindex.is_some(), "txindex entry missing: {result:?}");
    assert_eq!(txindex.get("synced").as_bool(), Some(false));
    assert_eq!(txindex.get("best_block_height").as_u64(), Some(0));
    Ok(())
}

#[test]
fn getblockstats_errors_without_indexer() {
    let (ctx, _low_tx, _high_tx) = fee_stats_context(None);
    let handler = Handler::new(ctx);

    let result = handler.dispatch("getblockstats", &json!([7]));
    assert!(
        matches!(result, Err(RpcError::Internal(_))),
        "expected unavailable index to be an explicit error, got {result:?}"
    );
}

#[test]
fn getblockstats_uses_indexer_for_fee_fields() -> Result<(), Box<dyn std::error::Error>> {
    let mut values = HashMap::new();
    values.insert(outpoint(21), 10_000);
    values.insert(outpoint(22), 10_000);
    let (ctx, low_tx, high_tx) = fee_stats_context(Some(values));
    let handler = Handler::new(ctx);

    let result = handler.dispatch("getblockstats", &json!([7]))?;
    let low_rate = 1_000_u64.saturating_mul(4) / low_tx.weight().to_wu();
    let high_rate = 3_000_u64.saturating_mul(4) / high_tx.weight().to_wu();
    let total_weight = low_tx
        .weight()
        .to_wu()
        .saturating_add(high_tx.weight().to_wu());
    let avg_rate = 4_000_u64.saturating_mul(4) / total_weight;

    assert_eq!(result.get("totalfee").as_u64(), Some(4_000));
    assert_eq!(result.get("avgfee").as_u64(), Some(2_000));
    assert_eq!(result.get("avgfeerate").as_u64(), Some(avg_rate));
    assert_eq!(result.get("medianfee").as_u64(), Some(2_000));
    assert_eq!(result.get("minfee").as_u64(), Some(1_000));
    assert_eq!(result.get("maxfee").as_u64(), Some(3_000));
    assert_eq!(result.get("minfeerate").as_u64(), Some(low_rate));
    assert_eq!(result.get("maxfeerate").as_u64(), Some(high_rate));
    assert_percentiles(
        &result,
        &[low_rate, low_rate, low_rate, high_rate, high_rate],
    )?;
    Ok(())
}

#[test]
fn getblockstats_errors_when_any_prevout_missing() {
    let mut values = HashMap::new();
    values.insert(outpoint(21), 10_000);
    let (ctx, _low_tx, _high_tx) = fee_stats_context(Some(values));
    let handler = Handler::new(ctx);

    let result = handler.dispatch("getblockstats", &json!([7]));
    assert!(
        matches!(result, Err(RpcError::Internal(_))),
        "expected incomplete fee inputs to be an explicit error, got {result:?}"
    );
}

#[test]
fn empty_context_is_in_initial_block_download() -> Result<(), Box<dyn std::error::Error>> {
    let handler = Handler::new(Arc::new(Context::new()));

    let result = handler.dispatch("getblockchaininfo", &json!([]))?;

    assert_eq!(result.get("blocks").as_u64(), Some(0));
    assert_eq!(result.get("headers").as_u64(), Some(0));
    // A node that has applied no blocks is in initial block download by
    // definition, and Bitcoin Core says so. This asserted `false` while the
    // field was `applied < headers`, which on an empty node is `0 < 0`.
    assert_eq!(result.get("initialblockdownload").as_bool(), Some(true));
    Ok(())
}

#[test]
fn chain_rpcs_report_applied_tip_separately_from_headers() -> Result<(), Box<dyn std::error::Error>>
{
    let ctx = Arc::new(Context::new());
    let applied_hash = Hash256::from_le_bytes(&[1_u8; 32]);
    let header_hash = Hash256::from_le_bytes(&[2_u8; 32]);
    ctx.set_applied_tip(TipSnapshot {
        tip_id: NodeId::new(1),
        height: 3,
        chainwork: ChainWork::ZERO,
        hash: applied_hash,
    });
    ctx.set_chain_tip(TipSnapshot {
        tip_id: NodeId::new(2),
        height: 7,
        chainwork: ChainWork::ZERO,
        hash: header_hash,
    });
    let handler = Handler::new(ctx);

    let info = handler.dispatch("getblockchaininfo", &json!([]))?;
    assert_eq!(info.get("blocks").as_u64(), Some(3));
    assert_eq!(info.get("headers").as_u64(), Some(7));
    assert_eq!(
        info.get("bestblockhash").as_str(),
        Some(applied_hash.to_string_be().as_str())
    );
    assert_eq!(info.get("initialblockdownload").as_bool(), Some(true));
    assert_eq!(
        handler.dispatch("getblockcount", &json!([]))?.as_u64(),
        Some(3)
    );
    assert_eq!(
        handler.dispatch("getbestblockhash", &json!([]))?.as_str(),
        Some(applied_hash.to_string_be().as_str())
    );
    Ok(())
}

#[test]
fn network_peer_methods_read_shared_peer_registry() -> Result<(), Box<dyn std::error::Error>> {
    let peers = Arc::new(RwLock::new(vec![PeerInfo {
        addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333),
        version: 70_016,
        services: 0,
        user_agent: "/test/".into(),
        start_height: 0,
        conn_time: 0,
        inbound: true,
    }]));
    let handler = Handler::new(context_with_peers(peers));

    let count = handler.dispatch("getconnectioncount", &json!([]))?;
    assert_eq!(count.as_u64(), Some(1));

    let peer_info = handler.dispatch("getpeerinfo", &json!([]))?;
    let peer_info = peer_info
        .as_array()
        .ok_or("getpeerinfo must return array")?;
    let peer = peer_info
        .first()
        .ok_or("getpeerinfo must return one peer")?;
    assert_eq!(peer_info.len(), 1);
    assert_eq!(peer.get("version").as_u64(), Some(70_016));
    Ok(())
}

#[test]
fn removed_wallet_methods_return_method_not_found() {
    let handler = Handler::new(Arc::new(Context::new()));
    for method in [
        "walletcreatefundedpsbt",
        "walletprocesspsbt",
        "bumpfee",
        "signrawtransactionwithkey",
        "signrawtransactionwithwallet",
        "dumpprivkey",
        "dumpwallet",
        "importprivkey",
        "importwallet",
        "importmulti",
        "importdescriptors",
        "sethdseed",
        "walletpassphrase",
        "walletpassphrasechange",
        "encryptwallet",
    ] {
        let error = handler
            .dispatch(method, &json!([]))
            .err()
            .unwrap_or_else(|| panic!("{method} unexpectedly succeeded"));
        assert_eq!(error.code(), RpcError::METHOD_NOT_FOUND);
        assert!(
            matches!(&error, RpcError::MethodNotFound(name) if name == method),
            "{method} must map to MethodNotFound, got {error:?}"
        );
    }
}

struct FakeTxIndex {
    values: HashMap<OutPoint, u64>,
    info: bitcoin_rs_rpc::context::TxIndexInfo,
}

impl bitcoin_rs_rpc::context::TxIndexQuery for FakeTxIndex {
    fn transaction(
        &self,
        _txid: &Txid,
    ) -> Result<Option<Transaction>, bitcoin_rs_rpc::context::TxQueryError> {
        Ok(None)
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
fn fee_stats_context(
    values: Option<HashMap<OutPoint, u64>>,
) -> (Arc<Context>, Transaction, Transaction) {
    let low_tx = fee_tx(21, 9_000);
    let high_tx = fee_tx(22, 7_000);
    let block = fee_block(low_tx.clone(), high_tx.clone());
    let mut ctx = Context::new();
    if let Some(values) = values {
        ctx.tx_index = Some(Arc::new(FakeTxIndex {
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
        body: serialize(&block),
    }));
    ctx.add_block(record);
    (Arc::new(ctx), low_tx, high_tx)
}

fn seed_tree_chain(ctx: &Context, block: &bitcoin::Block) -> bitcoin::Block {
    let mut tree = ctx.block_tree.write();
    let mut parent = None;
    let mut prev_blockhash = bitcoin::BlockHash::all_zeros();

    for height in 0_u32..7 {
        let header = bitcoin::block::Header {
            version: bitcoin::block::Version::ONE,
            prev_blockhash,
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 1_231_006_498 + height,
            bits: block.header.bits,
            nonce: height,
        };
        prev_blockhash = header.block_hash();
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

fn fee_block(low_tx: Transaction, high_tx: Transaction) -> bitcoin::Block {
    let coinbase = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([0_u8; 32]),
                vout: u32::MAX,
            },
            script_sig: ScriptBuf::from_bytes(vec![0x51]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let txdata = vec![coinbase, low_tx, high_tx];
    let merkle_root = bitcoin::merkle_tree::calculate_root(
        txdata.iter().map(|tx| tx.compute_txid().to_raw_hash()),
    )
    .map_or_else(
        bitcoin::TxMerkleNode::all_zeros,
        bitcoin::TxMerkleNode::from_raw_hash,
    );
    bitcoin::Block {
        header: bitcoin::block::Header {
            version: bitcoin::block::Version::ONE,
            prev_blockhash: bitcoin::BlockHash::all_zeros(),
            merkle_root,
            time: 1_231_006_505,
            bits: bitcoin::CompactTarget::from_consensus(0x1d00_ffff),
            nonce: 0,
        },
        txdata,
    }
}

fn fee_tx(label: u8, output_sat: u64) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint(label),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(output_sat),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

fn assert_percentiles(
    value: &sonic_rs::Value,
    expected: &[u64],
) -> Result<(), Box<dyn std::error::Error>> {
    let percentile_value = value.get("feerate_percentiles");
    let percentiles = percentile_value
        .as_array()
        .ok_or("feerate_percentiles must be an array")?;
    let observed = percentiles
        .iter()
        .map(|value| {
            value
                .as_u64()
                .ok_or_else(|| std::io::Error::other("percentile must be u64"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(observed.as_slice(), expected);
    Ok(())
}

struct SingleBlockSource {
    height: u32,
    hash: Hash256,
    body: Vec<u8>,
}

impl BlockBodySource for SingleBlockSource {
    fn block_body(&self, height: u32, hash: Hash256) -> Option<Vec<u8>> {
        (height == self.height && hash == self.hash).then(|| self.body.clone())
    }
}

struct Fixture {
    ctx: Arc<Context>,
    tx: Transaction,
    txid: Txid,
    block_hash: Hash256,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let mut ctx = Context::new();
        let tx = tx(1, ScriptBuf::from_bytes(vec![0x51]));
        let block = bitcoin::Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::ONE,
                prev_blockhash: bitcoin::BlockHash::all_zeros(),
                merkle_root: bitcoin::merkle_tree::calculate_root(std::iter::once(
                    tx.compute_txid().to_raw_hash(),
                ))
                .map_or_else(
                    bitcoin::TxMerkleNode::all_zeros,
                    bitcoin::TxMerkleNode::from_raw_hash,
                ),
                time: 1_231_006_505,
                bits: bitcoin::CompactTarget::from_consensus(0x1d00_ffff),
                nonce: 0,
            },
            txdata: vec![tx.clone()],
        };
        let block = seed_tree_chain(&ctx, &block);
        let block_hash_bytes = block.block_hash();
        let block_hash = Hash256::from_le_bytes(block_hash_bytes.as_byte_array());
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
            body: serialize(&block),
        }));
        ctx.add_block(BlockRecord::from_block(7, &block));
        let mut values = HashMap::new();
        values.insert(outpoint(1), 6_000);
        ctx.tx_index = Some(Arc::new(FakeTxIndex {
            values,
            info: bitcoin_rs_rpc::context::TxIndexInfo {
                synced: true,
                best_block_height: 7,
            },
        }));
        let txid = ctx.add_transaction(tx.clone());
        let entry = MempoolEntry::new(Arc::new(tx.clone()), 100, 1_000, 1, 7);
        ctx.mempool.write().insert_entry(entry)?;
        Ok(Self {
            ctx: Arc::new(ctx),
            tx,
            txid,
            block_hash,
        })
    }
}

#[allow(clippy::arc_with_non_send_sync)]
fn context_with_peers(peers: Arc<RwLock<Vec<PeerInfo>>>) -> Arc<Context> {
    let mut ctx = Context::new();
    ctx.peers = peers;
    Arc::new(ctx)
}

fn tx(label: u8, script_pubkey: ScriptBuf) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint(label),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(5_000),
            script_pubkey,
        }],
    }
}

fn outpoint(label: u8) -> OutPoint {
    OutPoint {
        txid: Txid::from_byte_array([label; 32]),
        vout: 0,
    }
}

fn build_valid_base64_psbt(tx: &Transaction) -> Result<String, Box<dyn std::error::Error>> {
    let psbt = bitcoin::psbt::Psbt::from_unsigned_tx(tx.clone())?;
    Ok(encode_base64(&psbt.serialize()))
}

const BASE64_TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn encode_base64(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(char::from(BASE64_TABLE[usize::from(b0 >> 2)]));
        out.push(char::from(
            BASE64_TABLE[usize::from(((b0 & 0x03) << 4) | (b1 >> 4))],
        ));
        out.push(if chunk.len() > 1 {
            char::from(BASE64_TABLE[usize::from(((b1 & 0x0f) << 2) | (b2 >> 6))])
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            char::from(BASE64_TABLE[usize::from(b2 & 0x3f)])
        } else {
            '='
        });
    }
    out
}
