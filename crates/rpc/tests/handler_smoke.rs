//! Smoke tests for every required Task 16 RPC handler.
extern crate alloc;

use alloc::sync::Arc;
use hashbrown::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::Hash as _;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use bitcoin_rs_chain::{ChainWork, NodeId, NodeStatus, TipSnapshot};
use bitcoin_rs_filters::{FilterIndexError, FilterIndexLike};
use bitcoin_rs_index::{BlockSource, IndexError, IndexRowCounts, IndexerLike};
use bitcoin_rs_mempool::MempoolEntry;
use bitcoin_rs_p2p::PeerInfo;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_rpc::{BlockRecord, Context, Handler, RpcError};
use bitcoin_rs_utxo::{BlockChanges, UtxoAdd};
use parking_lot::{Mutex, RwLock};
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, json};

#[test]
fn all_required_handlers_return_core_shapes() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let handler = Handler::new(Arc::clone(&fixture.ctx));
    let raw_tx = serialize_hex(&fixture.tx);
    let valid_psbt = build_valid_base64_psbt(&fixture.tx)?;
    let txid = fixture.txid.to_string();
    let block_hash = fixture.block_hash.to_string_be();

    let calls = [
        ("getblockchaininfo", json!([])),
        ("getblockcount", json!([])),
        ("getblockhash", json!([7])),
        ("getbestblockhash", json!([])),
        ("getblock", json!([block_hash.as_str(), 1])),
        ("getblockheader", json!([block_hash.as_str(), true])),
        ("getblockstats", json!([7])),
        ("gettxoutsetinfo", json!([])),
        ("getblockfilter", json!([block_hash.as_str()])),
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
        (
            "getdescriptorinfo",
            json!(["addr(1111111111111111111114oLvT2)"]),
        ),
        (
            "deriveaddresses",
            json!(["addr(1111111111111111111114oLvT2)"]),
        ),
        (
            "scantxoutset",
            json!(["start", ["addr(1111111111111111111114oLvT2)"]]),
        ),
        ("walletcreatefundedpsbt", json!([[], []])),
        ("walletprocesspsbt", json!([valid_psbt.as_str()])),
        ("finalizepsbt", json!([valid_psbt.as_str()])),
        ("combinepsbt", json!([[valid_psbt.as_str()]])),
        ("bumpfee", json!([txid.as_str()])),
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
fn getblockhash_reads_historical_active_header_without_block_record()
-> Result<(), Box<dyn std::error::Error>> {
    let ctx = active_regtest_header_context()?;
    let genesis_hash = bitcoin_rs_primitives::Network::Regtest.genesis_block_hash();
    assert!(ctx.blocks.read().is_empty());
    let handler = Handler::new(Arc::new(ctx));

    let result = handler.dispatch("getblockhash", &json!([0]))?;

    assert_eq!(result.as_str(), Some(genesis_hash.to_string_be().as_str()));
    Ok(())
}

#[test]
fn getblockhash_prefers_active_header_over_stale_block_record()
-> Result<(), Box<dyn std::error::Error>> {
    let ctx = active_regtest_header_context()?;
    let genesis_hash = bitcoin_rs_primitives::Network::Regtest.genesis_block_hash();
    ctx.add_block(BlockRecord::synthetic(
        0,
        Hash256::from_le_bytes(&[0x99; 32]),
    ));
    let handler = Handler::new(Arc::new(ctx));

    let result = handler.dispatch("getblockhash", &json!([0]))?;

    assert_eq!(result.as_str(), Some(genesis_hash.to_string_be().as_str()));
    Ok(())
}

#[test]
fn getblockhash_rejects_stale_block_record_above_active_tip()
-> Result<(), Box<dyn std::error::Error>> {
    let ctx = active_regtest_header_context()?;
    ctx.add_block(BlockRecord::synthetic(
        2,
        Hash256::from_le_bytes(&[0x77; 32]),
    ));
    let handler = Handler::new(Arc::new(ctx));

    let error = handler
        .dispatch("getblockhash", &json!([2]))
        .expect_err("stale block record above active tip unexpectedly resolved");

    assert_eq!(error.code(), RpcError::CORE_NOT_FOUND);
    Ok(())
}

#[test]
fn getblockfilter_reads_filter_index() -> Result<(), Box<dyn std::error::Error>> {
    let block_hash = Hash256::from_le_bytes(&[9_u8; 32]);
    let header = Hash256::from_le_bytes(&[8_u8; 32]);
    let mut ctx = Context::new();
    let filter_index: Box<dyn FilterIndexLike> = Box::new(StaticFilterIndex {
        block_hash,
        filter: vec![0xab, 0xcd],
        header,
    });
    ctx.filter_index = Some(Arc::new(filter_index));
    let handler = Handler::new(Arc::new(ctx));
    let block_hash_hex = block_hash.to_string_be();

    let result = handler.dispatch("getblockfilter", &json!([block_hash_hex.as_str()]))?;

    assert_eq!(result.get("filter").as_str(), Some("abcd"));
    assert_eq!(
        result.get("header").as_str(),
        Some(header.to_string_be().as_str())
    );
    Ok(())
}

#[test]
fn getblockfilter_reports_disabled_basic_filter_index() {
    let handler = Handler::new(Arc::new(Context::new()));
    let block_hash = Hash256::from_le_bytes(&[9_u8; 32]);
    let block_hash_hex = block_hash.to_string_be();

    let error = handler
        .dispatch("getblockfilter", &json!([block_hash_hex.as_str()]))
        .expect_err("disabled block filter index unexpectedly succeeded");

    assert_eq!(error.code(), -1);
    assert_eq!(
        error.to_string(),
        "Index is not enabled for filtertype basic"
    );
}

#[test]
fn getblockfilter_returns_not_found_for_missing_filter_row()
-> Result<(), Box<dyn std::error::Error>> {
    let block_hash = Hash256::from_le_bytes(&[9_u8; 32]);
    let header = Hash256::from_le_bytes(&[8_u8; 32]);
    let mut ctx = Context::new();
    let filter_index: Box<dyn FilterIndexLike> = Box::new(StaticFilterIndex {
        block_hash,
        filter: vec![0xab, 0xcd],
        header,
    });
    ctx.filter_index = Some(Arc::new(filter_index));
    let handler = Handler::new(Arc::new(ctx));
    let missing_hash = Hash256::from_le_bytes(&[7_u8; 32]);
    let missing_hash_hex = missing_hash.to_string_be();

    let error = handler
        .dispatch("getblockfilter", &json!([missing_hash_hex.as_str()]))
        .err()
        .ok_or("missing filter unexpectedly succeeded")?;

    assert_eq!(error.code(), RpcError::CORE_NOT_FOUND);
    assert_eq!(error.to_string(), "not found: block filter not found");
    Ok(())
}

#[test]
fn getindexinfo_omits_disabled_indexes() -> Result<(), Box<dyn std::error::Error>> {
    let handler = Handler::new(Arc::new(Context::new()));

    let result = handler.dispatch("getindexinfo", &json!([]))?;

    assert_eq!(result.as_object().map(sonic_rs::Object::len), Some(0));
    Ok(())
}

#[test]
fn getindexinfo_returns_enabled_core_index_names() -> Result<(), Box<dyn std::error::Error>> {
    let mut ctx = Context::new();
    ctx.indexer = Some(Arc::new(Mutex::new(Box::new(FakeIndexer {
        values: HashMap::new(),
    }))));
    ctx.filter_index = Some(Arc::new(Box::new(StaticFilterIndex {
        block_hash: Hash256::from_le_bytes(&[9_u8; 32]),
        filter: vec![0xab, 0xcd],
        header: Hash256::from_le_bytes(&[8_u8; 32]),
    })));
    let handler = Handler::new(Arc::new(ctx));

    let result = handler.dispatch("getindexinfo", &json!([]))?;

    let txindex = result.get("txindex");
    assert!(txindex.is_some(), "txindex entry missing: {result:?}");
    assert_eq!(txindex.get("synced").as_bool(), Some(false));
    assert_eq!(txindex.get("best_block_height").as_u64(), Some(0));

    let filter_index = result.get("basic block filter index");
    assert!(
        filter_index.is_some(),
        "basic block filter index entry missing: {result:?}"
    );
    assert_eq!(filter_index.get("synced").as_bool(), Some(false));
    assert_eq!(filter_index.get("best_block_height").as_u64(), Some(0));
    assert!(result.get("basicblockfilterindex").is_none());

    Ok(())
}

#[test]
fn getrawtransaction_does_not_use_confirmed_map_when_txindex_disabled()
-> Result<(), Box<dyn std::error::Error>> {
    let ctx = Context::new();
    let tx = tx(42, ScriptBuf::from_bytes(vec![0x51]));
    let txid = ctx.add_transaction(tx);
    let handler = Handler::new(Arc::new(ctx));

    let error = handler
        .dispatch("getrawtransaction", &json!([txid.to_string()]))
        .expect_err("confirmed map lookup unexpectedly succeeded with txindex disabled");

    assert_eq!(error.code(), RpcError::CORE_NOT_FOUND);
    Ok(())
}

#[test]
fn getrawtransaction_uses_confirmed_map_when_txindex_enabled()
-> Result<(), Box<dyn std::error::Error>> {
    let mut ctx = Context::new();
    ctx.indexer = Some(Arc::new(Mutex::new(Box::new(FakeIndexer {
        values: HashMap::new(),
    }))));
    let tx = tx(43, ScriptBuf::from_bytes(vec![0x51]));
    let txid = ctx.add_transaction(tx);
    let handler = Handler::new(Arc::new(ctx));

    let result = handler.dispatch("getrawtransaction", &json!([txid.to_string()]))?;

    assert!(result.as_str().is_some());
    Ok(())
}

#[test]
fn getblockstats_fee_fields_are_zero_without_indexer() -> Result<(), Box<dyn std::error::Error>> {
    let (ctx, _low_tx, _high_tx) = fee_stats_context(None);
    let handler = Handler::new(ctx);

    let result = handler.dispatch("getblockstats", &json!([7]))?;

    assert_fee_fields_zero(&result)?;
    Ok(())
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
fn getblockstats_fee_fields_are_all_zero_when_any_prevout_missing()
-> Result<(), Box<dyn std::error::Error>> {
    let mut values = HashMap::new();
    values.insert(outpoint(21), 10_000);
    let (ctx, _low_tx, _high_tx) = fee_stats_context(Some(values));
    let handler = Handler::new(ctx);

    let result = handler.dispatch("getblockstats", &json!([7]))?;

    assert_fee_fields_zero(&result)?;
    Ok(())
}

#[test]
fn empty_context_is_not_initial_block_download() -> Result<(), Box<dyn std::error::Error>> {
    let handler = Handler::new(Arc::new(Context::new()));

    let result = handler.dispatch("getblockchaininfo", &json!([]))?;

    assert_eq!(result.get("blocks").as_u64(), Some(0));
    assert_eq!(result.get("headers").as_u64(), Some(0));
    assert_eq!(result.get("initialblockdownload").as_bool(), Some(false));
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
fn signing_methods_are_disabled() -> Result<(), Box<dyn std::error::Error>> {
    let handler = Handler::new(Arc::new(Context::new()));
    let error = handler
        .dispatch("signrawtransactionwithwallet", &json!([]))
        .err()
        .ok_or("signing method unexpectedly succeeded")?;
    assert_eq!(error.code(), RpcError::INTERNAL_ERROR);
    assert_eq!(
        error.to_string(),
        "wallet has no private keys; use external signer"
    );
    Ok(())
}

#[derive(Debug)]
struct StaticFilterIndex {
    block_hash: Hash256,
    filter: Vec<u8>,
    header: Hash256,
}

impl FilterIndexLike for StaticFilterIndex {
    fn put_filter(
        &self,
        _block_hash: bitcoin_rs_primitives::Hash256,
        _prev_header: bitcoin_rs_primitives::Hash256,
        _filter_bytes: &[u8],
    ) -> Result<bitcoin_rs_primitives::Hash256, FilterIndexError> {
        Ok(self.header)
    }

    fn filter_header(
        &self,
        block_hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<Option<bitcoin_rs_primitives::Hash256>, FilterIndexError> {
        Ok((block_hash == self.block_hash).then_some(self.header))
    }

    fn filter(
        &self,
        block_hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<Option<Vec<u8>>, FilterIndexError> {
        Ok((block_hash == self.block_hash).then(|| self.filter.clone()))
    }
}

struct FakeIndexer {
    values: HashMap<OutPoint, u64>,
}

impl IndexerLike for FakeIndexer {
    fn ingest_block(&mut self, _block: &[u8], _height: u32) -> Result<IndexRowCounts, IndexError> {
        Ok(IndexRowCounts::default())
    }

    fn resolve_outpoint_value(
        &self,
        outpoint: OutPoint,
        _source: &dyn BlockSource,
    ) -> Result<Option<u64>, IndexError> {
        Ok(self.values.get(&outpoint).copied())
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
        let indexer: Box<dyn IndexerLike> = Box::new(FakeIndexer { values });
        ctx.indexer = Some(Arc::new(Mutex::new(indexer)));
    }
    ctx.add_block(BlockRecord::from_block(7, &block));
    (Arc::new(ctx), low_tx, high_tx)
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

fn assert_fee_fields_zero(value: &sonic_rs::Value) -> Result<(), Box<dyn std::error::Error>> {
    for field in [
        "avgfee",
        "avgfeerate",
        "maxfee",
        "maxfeerate",
        "medianfee",
        "minfee",
        "minfeerate",
        "totalfee",
    ] {
        assert_eq!(value.get(field).as_u64(), Some(0), "{field} must be zero");
    }
    assert_percentiles(value, &[0, 0, 0, 0, 0])
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
        let block_hash_bytes = block.block_hash();
        let block_hash = Hash256::from_le_bytes(block_hash_bytes.as_byte_array());
        ctx.filter_index = Some(Arc::new(Box::new(StaticFilterIndex {
            block_hash,
            filter: vec![0x00],
            header: Hash256::from_le_bytes(&[0x08; 32]),
        })));
        ctx.set_chain_tip(TipSnapshot {
            tip_id: NodeId::new(0),
            height: 7,
            chainwork: ChainWork::ZERO,
            hash: block_hash,
        });
        ctx.set_applied_tip(TipSnapshot {
            tip_id: NodeId::new(0),
            height: 7,
            chainwork: ChainWork::ZERO,
            hash: block_hash,
        });
        ctx.add_block(BlockRecord::from_block(7, &block));
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

fn active_regtest_header_context() -> Result<Context, Box<dyn std::error::Error>> {
    let ctx = Context::new();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let child_header = bitcoin::block::Header {
        version: bitcoin::block::Version::ONE,
        prev_blockhash: genesis.block_hash(),
        merkle_root: bitcoin::TxMerkleNode::all_zeros(),
        time: genesis.header.time.saturating_add(1),
        bits: genesis.header.bits,
        nonce: genesis.header.nonce.saturating_add(1),
    };
    let child_hash = Hash256::from_le_bytes(child_header.block_hash().as_byte_array());
    let child_id = {
        let mut tree = ctx.block_tree.write();
        tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
        tree.insert_header(child_header, NodeStatus::HeaderValid)?
    };
    ctx.set_chain_tip(TipSnapshot {
        tip_id: child_id,
        height: 1,
        chainwork: ChainWork::ZERO,
        hash: child_hash,
    });
    Ok(ctx)
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
