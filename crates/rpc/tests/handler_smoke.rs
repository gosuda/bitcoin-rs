//! Smoke tests for every required Task 16 RPC handler.
extern crate alloc;

use alloc::sync::Arc;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::Hash as _;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use bitcoin_rs_chain::{ChainWork, NodeId, TipSnapshot};
use bitcoin_rs_filters::{FilterIndexError, FilterIndexLike};
use bitcoin_rs_mempool::MempoolEntry;
use bitcoin_rs_p2p::PeerInfo;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_rpc::{BlockRecord, Context, Handler, RpcError};
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
        ("addnode", json!(["127.0.0.1", "onetry"])),
        ("disconnectnode", json!(["127.0.0.1"])),
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
        ("scantxoutset", json!(["start", []])),
        ("walletcreatefundedpsbt", json!([[], []])),
        ("walletprocesspsbt", json!([""])),
        ("finalizepsbt", json!([""])),
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
    let hash_serialized_value = result.get("hash_serialized_2");
    let hash_serialized = hash_serialized_value
        .as_str()
        .ok_or("hash_serialized_2 must be a string")?;
    assert_eq!(hash_serialized.len(), 768);
    assert!(hash_serialized.ends_with("01"));
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
    ctx.filter_index = Arc::new(filter_index);
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
fn getindexinfo_returns_both_indexes() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());
    let handler = Handler::new(Arc::clone(&ctx));

    let result = handler.dispatch("getindexinfo", &json!([]))?;

    let txindex = result.get("txindex");
    assert!(txindex.is_some(), "txindex entry missing: {result:?}");
    assert_eq!(txindex.get("synced").as_bool(), Some(false));
    assert_eq!(txindex.get("best_block_height").as_u64(), Some(0));

    let filter_index = result.get("basicblockfilterindex");
    assert!(
        filter_index.is_some(),
        "basicblockfilterindex entry missing: {result:?}"
    );
    assert_eq!(filter_index.get("synced").as_bool(), Some(false));
    assert_eq!(filter_index.get("best_block_height").as_u64(), Some(0));

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

struct Fixture {
    ctx: Arc<Context>,
    tx: Transaction,
    txid: Txid,
    block_hash: Hash256,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let ctx = Arc::new(Context::new());
        let block_hash = Hash256::from_le_bytes(&[7_u8; 32]);
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
        ctx.add_block(BlockRecord::synthetic(7, block_hash));
        let tx = tx(1, ScriptBuf::from_bytes(vec![0x51]));
        let txid = ctx.add_transaction(tx.clone());
        let entry = MempoolEntry::new(Arc::new(tx.clone()), 100, 1_000, 1, 7);
        ctx.mempool.write().insert_entry(entry)?;
        Ok(Self {
            ctx,
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
