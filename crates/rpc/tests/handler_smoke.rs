#![allow(clippy::expect_used)]
extern crate alloc;

use alloc::sync::Arc;
use hashbrown::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};

use bitcoin::hex::DisplayHex;
use bitcoin_rs_chain::{BlockBodySource, ChainWork, NodeId, NodeStatus, TipSnapshot};
use bitcoin_rs_index::block_log::BlockRecord;
use bitcoin_rs_mempool::MempoolEntry;
use bitcoin_rs_mining::FakeMiningControl;
use bitcoin_rs_p2p::{PeerInfo, PeerLease, PeerTable, wire::PROTOCOL_VERSION};
use bitcoin_rs_primitives::{
    Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, Network, OutPoint, Script,
    Sequence, Tx, TxIn, TxOut, Txid, Witness, consensus_bytes,
};
use bitcoin_rs_rpc::context::{ChainControl, ChainControlError, Context};
use bitcoin_rs_rpc::{Handler, RpcError};
use bitcoin_rs_utxo::contract::{BlockChanges, UtxoAdd};
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait, json};

mod mining_fixture;

#[test]
fn required_handlers_report_the_fixture_chain_mempool_and_network_facts()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let handler = Handler::new(Arc::clone(&fixture.ctx));

    for (method, params, expected) in chain_and_mempool_expectations(&fixture)
        .into_iter()
        .chain(network_and_wallet_expectations(&fixture)?)
    {
        let actual = handler
            .dispatch(method, &params)
            .unwrap_or_else(|err| panic!("{method} must answer: {err}"));
        assert_contains(method, method, &actual, &expected);
    }

    let uptime = handler.dispatch("uptime", &json!([]))?;
    assert!(uptime.as_u64().is_some(), "uptime must be a second count");
    Ok(())
}

type Expectation = (&'static str, sonic_rs::Value, sonic_rs::Value);

#[test]
fn compact_filter_rpc_exposes_only_enabled_ready_data() -> Result<(), Box<dyn std::error::Error>> {
    use bitcoin_rs_index::{BasicFilter, CompactFilterQuery, DerivedIndexInfo, TxQueryError};
    struct Filters(AtomicBool);
    impl CompactFilterQuery for Filters {
        fn block_filter(&self, _: Hash256) -> Result<Option<BasicFilter>, TxQueryError> {
            if !self.0.load(Ordering::Acquire) {
                return Err(TxQueryError::Retry);
            }
            let mut header = [0; 32];
            header[0] = 1;
            Ok(Some(BasicFilter {
                filter: vec![0],
                hash: [2; 32],
                header,
            }))
        }
        fn for_each_filter(
            &self,
            _: u32,
            _: Hash256,
            _: u32,
            _: &mut dyn FnMut(Hash256, BasicFilter) -> bool,
        ) -> Result<Option<[u8; 32]>, TxQueryError> {
            unreachable!("single-block RPC only")
        }
        fn filter_index_info(&self) -> Result<DerivedIndexInfo, TxQueryError> {
            Ok(DerivedIndexInfo {
                synced: self.0.load(Ordering::Acquire),
                best_block_height: 0,
            })
        }
    }
    let mut fixture = Fixture::new()?;
    let hash = fixture.block_hash.to_string();
    {
        let handler = Handler::new(Arc::clone(&fixture.ctx));
        assert_eq!(
            handler
                .dispatch("getblockfilter", &json!([hash]))
                .expect_err("disabled")
                .code(),
            -1
        );
        for (params, code) in [
            (json!([hash, "unknown"]), -5),
            (json!([hash, 1]), -3),
            (json!(["00".repeat(32)]), -5),
            (json!(["00"]), -8),
            (json!(["zz".repeat(32)]), -8),
        ] {
            let error = handler
                .dispatch("getblockfilter", &params)
                .expect_err("invalid request");
            assert_eq!(error.code(), code);
            if code == -8 {
                assert_eq!(error.to_string(), "hash must be 64 hex characters");
            }
        }
    }
    let index = Arc::new(Filters(AtomicBool::new(false)));
    let context = Arc::get_mut(&mut fixture.ctx).ok_or("fixture context still shared")?;
    context.indexes.derived_index = None;
    context.indexes.compact_filters = Some(index.clone());
    context.network.local_services |= 64;
    let handler = Handler::new(Arc::clone(&fixture.ctx));
    assert_eq!(
        handler
            .dispatch("getblockfilter", &json!([hash]))
            .expect_err("catching up")
            .code(),
        -1
    );
    let services = handler.dispatch("getnetworkinfo", &json!([]))?;
    assert_eq!(
        u64::from_str_radix(services["localservices"].as_str().ok_or("services")?, 16)? & 64,
        0
    );
    index.0.store(true, Ordering::Release);
    for params in [
        json!([hash]),
        json!([hash, null]),
        json!({"blockhash": hash, "filtertype": "basic"}),
    ] {
        assert_eq!(
            handler.dispatch("getblockfilter", &params)?,
            json!({"filter": "00", "header": format!("{}01", "00".repeat(31))})
        );
    }
    assert_eq!(
        handler.dispatch("getindexinfo", &json!([]))?,
        json!({"basic block filter index": {"synced": true, "best_block_height": 0}})
    );
    let services = handler.dispatch("getnetworkinfo", &json!([]))?;
    assert_ne!(
        u64::from_str_radix(services["localservices"].as_str().ok_or("services")?, 16)? & 64,
        0
    );
    Ok(())
}

fn chain_and_mempool_expectations(fixture: &Fixture) -> Vec<Expectation> {
    let tip = fixture.block_hash.to_string();
    let txid = fixture.txid.to_string();
    let raw_tx = consensus_bytes(&fixture.tx).to_lower_hex_string();
    let header_hex = &fixture.block_hex[..160];

    vec![
        ("getblockcount", json!([]), json!(FIXTURE_HEIGHT)),
        ("getbestblockhash", json!([]), json!(tip)),
        ("getblockhash", json!([FIXTURE_HEIGHT]), json!(tip)),
        ("getblockheader", json!([tip, false]), json!(header_hex)),
        (
            "getblock",
            json!([tip, 1]),
            json!({
                "hash": tip,
                "height": FIXTURE_HEIGHT,
                "nTx": 1,
                "confirmations": 1,
                "tx": [txid],
            }),
        ),
        (
            "getblockchaininfo",
            json!([]),
            json!({
                "chain": "regtest",
                "blocks": FIXTURE_HEIGHT,
                "headers": FIXTURE_HEIGHT,
                "bestblockhash": tip,
            }),
        ),
        (
            "getchaintxstats",
            json!([]),
            json!({
                "window_final_block_hash": tip,
                "window_final_block_height": FIXTURE_HEIGHT,
            }),
        ),
        (
            "getblockstats",
            json!([tip]),
            json!({"blockhash": tip, "height": FIXTURE_HEIGHT, "txs": 1, "outs": 1}),
        ),
        (
            "getmempoolinfo",
            json!([]),
            json!({"size": 1, "bytes": 100}),
        ),
        ("getrawmempool", json!([]), json!([txid])),
        (
            "getmempoolentry",
            json!([txid]),
            json!({
                "vsize": 100,
                "height": FIXTURE_HEIGHT,
                "ancestorcount": 1,
                "descendantcount": 1,
            }),
        ),
        (
            "gettxout",
            json!([txid, 0_u64]),
            json!({"value": 0.00005, "bestblock": tip, "coinbase": false}),
        ),
        (
            "gettxoutsetinfo",
            json!([]),
            json!({"height": FIXTURE_HEIGHT, "bestblock": tip}),
        ),
        ("getrawtransaction", json!([txid]), json!(raw_tx)),
        ("sendrawtransaction", json!([raw_tx]), json!(txid)),
        (
            "testmempoolaccept",
            json!([[raw_tx]]),
            json!([{
                "txid": txid,
                "allowed": false,
                "reject-reason": "txn-already-in-mempool",
            }]),
        ),
    ]
}

fn network_and_wallet_expectations(
    fixture: &Fixture,
) -> Result<Vec<Expectation>, Box<dyn std::error::Error>> {
    let psbt = build_valid_base64_psbt(&fixture.tx)?;

    Ok(vec![
        (
            "getindexinfo",
            json!([]),
            json!({"txindex": {"synced": true, "best_block_height": FIXTURE_HEIGHT}}),
        ),
        (
            "getnetworkinfo",
            json!([]),
            json!({"protocolversion": PROTOCOL_VERSION, "connections": 0, "networkactive": true}),
        ),
        ("getpeerinfo", json!([]), json!([])),
        ("getconnectioncount", json!([]), json!(0)),
        ("getnetworkhashps", json!([]), json!(0.0)),
        ("getprioritisedtransactions", json!([]), json!({})),
        (
            "finalizepsbt",
            json!([psbt]),
            json!({"complete": false, "psbt": psbt, "hex": null}),
        ),
        ("combinepsbt", json!([[psbt]]), json!(psbt)),
        ("verifychain", json!([]), json!(false)),
        ("getmininginfo", json!([]), json!({"chain": "regtest"})),
        (
            "getblocktemplate",
            json!([{"rules": ["segwit"]}]),
            json!({"weightlimit": 4_000_000, "sizelimit": 4_000_000}),
        ),
        ("submitblock", json!([fixture.block_hex]), json!(null)),
    ])
}

const FIXTURE_HEIGHT: u64 = 7;

fn assert_contains(method: &str, path: &str, actual: &sonic_rs::Value, expected: &sonic_rs::Value) {
    if let Some(fields) = expected.as_object() {
        let found = actual
            .as_object()
            .unwrap_or_else(|| panic!("{method}: {path} must be an object, got {actual}"));
        if fields.is_empty() {
            assert_eq!(
                found.len(),
                0,
                "{method}: {path} must be empty, got {actual}"
            );
            return;
        }
        for (key, value) in fields {
            let found = actual
                .get(key)
                .unwrap_or_else(|| panic!("{method}: {path}.{key} missing from {actual}"));
            assert_contains(method, &format!("{path}.{key}"), found, value);
        }
        return;
    }
    if let Some(items) = expected.as_array() {
        let found = actual
            .as_array()
            .unwrap_or_else(|| panic!("{method}: {path} must be an array, got {actual}"));
        assert_eq!(found.len(), items.len(), "{method}: {path} length");
        for (index, item) in items.iter().enumerate() {
            assert_contains(method, &format!("{path}[{index}]"), &found[index], item);
        }
        return;
    }
    assert_eq!(actual, expected, "{method}: {path}");
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

#[test]
fn getblockchaininfo_reports_the_closed_for_recovery_fact() -> Result<(), Box<dyn std::error::Error>>
{
    let ctx = Arc::new(Context::new());
    let handler = Handler::new(Arc::clone(&ctx));
    let open = handler.dispatch("getblockchaininfo", &json!([]))?;
    assert_eq!(open["is_closed_for_recovery"], json!(false));
    ctx.chain.closed_for_recovery.store(true);
    let closed = handler.dispatch("getblockchaininfo", &json!([]))?;
    assert_eq!(closed["is_closed_for_recovery"], json!(true));
    Ok(())
}

#[derive(Debug)]
struct RecordingChainControl {
    called: Arc<AtomicBool>,
    error: Option<ChainControlError>,
    verify_error: Option<ChainControlError>,
}

impl ChainControl for RecordingChainControl {
    fn invalidate_block(&self, _hash: Hash256) -> Result<(), ChainControlError> {
        self.called.store(true, Ordering::SeqCst);
        match &self.error {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }

    fn dump_txoutset(
        &self,
        _path: &std::path::Path,
        _cancellation: &bitcoin_rs_chain::LatchReader,
    ) -> Result<
        bitcoin_rs_rpc::context::SnapshotExport,
        bitcoin_rs_rpc::context::SnapshotControlError,
    > {
        Err(bitcoin_rs_rpc::context::SnapshotControlError::Unavailable(
            "snapshot export is not attached to this fixture".to_owned(),
        ))
    }

    fn verify_chain(
        &self,
        _check_level: u8,
        _nblocks: u32,
        _cancellation: &bitcoin_rs_chain::LatchReader,
    ) -> Result<bool, ChainControlError> {
        match &self.verify_error {
            Some(error) => Err(error.clone()),
            None => Ok(false),
        }
    }
}

#[test]
fn invalidateblock_delegates_to_node_control_and_returns_null() -> Result<(), RpcError> {
    let called = Arc::new(AtomicBool::new(false));
    let control = RecordingChainControl {
        called: Arc::clone(&called),
        error: None,
        verify_error: None,
    };
    let mut ctx = Context::new().with_chain_control(Arc::new(control));
    ctx.chain.chain_network = Network::Regtest;
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
        verify_error: None,
    };
    let mut ctx = Context::new().with_chain_control(Arc::new(control));
    ctx.chain.chain_network = Network::Regtest;
    let handler = Handler::new(Arc::new(ctx));
    let err = handler
        .dispatch(
            "invalidateblock",
            &json!(["0000000000000000000000000000000000000000000000000000000000000000"]),
        )
        .expect_err("unknown block should map to an error");
    assert_eq!(err.code(), RpcError::CORE_NOT_FOUND);
}

#[test]
fn verifychain_maps_control_interruptions_to_core_errors() {
    for (error, message) in [
        (
            ChainControlError::Interrupted,
            "Block verification interrupted",
        ),
        (
            ChainControlError::Unavailable,
            "Chainstate is unavailable for verification",
        ),
    ] {
        let control = RecordingChainControl {
            called: Arc::new(AtomicBool::new(false)),
            error: None,
            verify_error: Some(error),
        };
        let mut ctx = Context::new().with_chain_control(Arc::new(control));
        ctx.chain.chain_network = Network::Regtest;
        let tip = TipSnapshot {
            tip_id: NodeId::new(0),
            height: 42,
            hash: Hash256::from_le_bytes(&[0xff; 32]),
            chainwork: ChainWork::default(),
            chain_tx_count: bitcoin_rs_chain::ChainTxCount::UNKNOWN,
        };
        ctx.chain.applied_tip.store(Some(Arc::new(tip)));
        let handler = Handler::new(Arc::new(ctx));
        let err = handler
            .dispatch("verifychain", &json!([3, 6]))
            .expect_err("control interruption must map to an error");
        assert_eq!(err.code(), -1);
        assert_eq!(err.to_string(), message);
    }
}

#[test]
fn getblockchaininfo_surfaces_published_chainwork_hex() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());
    let tip = TipSnapshot {
        tip_id: NodeId::new(0),
        height: 42,
        hash: Hash256::from_le_bytes(&[0xff; 32]),
        chainwork: ChainWork::from_be_bytes([0x11; 32]),
        chain_tx_count: bitcoin_rs_chain::ChainTxCount::UNKNOWN,
    };
    ctx.chain.chain_tip.store(Some(Arc::new(tip.clone())));
    ctx.chain.applied_tip.store(Some(Arc::new(tip)));
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
            value: Amount::from_sat(50_000),
            script_pubkey: vec![0x51].into(),
        },
        false,
        1,
    ));
    bitcoin_rs_utxo::contract::commit_block_changes(
        &ctx.chain.utxo.fixture_set(),
        &changes,
        &Hash256::from_le_bytes(&[0xaa; 32]),
    )?;
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
    assert_eq!(
        muhash,
        "dd5ad2a105c2d29495f577245c357409002329b9f4d6182c0af3dc2f462555c8"
    );
    Ok(())
}

#[test]
fn gettxoutsetinfo_production_triplet_matches_core_digest() -> Result<(), Box<dyn std::error::Error>>
{
    let ctx = Arc::new(Context::new());
    let handler = Handler::new(Arc::clone(&ctx));
    let result = handler.dispatch("gettxoutsetinfo", &json!(["muhash", null, false]))?;
    let muhash = result
        .get("muhash")
        .and_then(JsonValueTrait::as_str)
        .ok_or("muhash missing")?;
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
    ctx.indexes.derived_index = Some(Arc::new(FakeTxIndex {
        transactions: HashMap::new(),
        values: HashMap::new(),
        info: bitcoin_rs_rpc::context::DerivedIndexInfo {
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
    struct UnavailableFilters;
    impl bitcoin_rs_index::CompactFilterQuery for UnavailableFilters {
        fn block_filter(
            &self,
            _: Hash256,
        ) -> Result<Option<bitcoin_rs_index::BasicFilter>, bitcoin_rs_index::TxQueryError> {
            unreachable!("status only")
        }
        fn for_each_filter(
            &self,
            _: u32,
            _: Hash256,
            _: u32,
            _: &mut dyn FnMut(Hash256, bitcoin_rs_index::BasicFilter) -> bool,
        ) -> Result<Option<[u8; 32]>, bitcoin_rs_index::TxQueryError> {
            unreachable!("status only")
        }
        fn filter_index_info(
            &self,
        ) -> Result<bitcoin_rs_index::DerivedIndexInfo, bitcoin_rs_index::TxQueryError> {
            Err(bitcoin_rs_index::TxQueryError::Unavailable(
                bitcoin_rs_index::TxUnavailableCause::Other("history unavailable".into()),
            ))
        }
    }
    let mut ctx = Context::new();
    ctx.indexes.compact_filters = Some(Arc::new(UnavailableFilters));
    ctx.indexes.derived_index = Some(Arc::new(FakeTxIndex {
        transactions: HashMap::new(),
        values: HashMap::new(),
        info: bitcoin_rs_rpc::context::DerivedIndexInfo {
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
    assert_eq!(err.code(), RpcError::CORE_NOT_FOUND);
}

#[test]
fn getblockstats_uses_indexer_for_fee_fields() -> Result<(), Box<dyn std::error::Error>> {
    let mut values = HashMap::new();
    values.insert(outpoint(21), 10_000);
    values.insert(outpoint(22), 20_000);
    let (ctx, _low_tx, _high_tx) = fee_stats_context(Some(values));
    let handler = Handler::new(Arc::clone(&ctx));
    let tip_hash = ctx
        .chain
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
    assert_eq!(values, vec![0, 0, 0, 0, 0]);
    Ok(())
}

#[test]
fn getblockstats_errors_when_any_prevout_missing() {
    let (ctx, _low_tx, _high_tx) = fee_stats_context(None);
    let handler = Handler::new(Arc::clone(&ctx));
    let tip_hash = ctx
        .chain
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
        chain_tx_count: bitcoin_rs_chain::ChainTxCount::UNKNOWN,
    };
    let applied_tip = TipSnapshot {
        tip_id: NodeId::new(0),
        height: 7,
        hash: Hash256::from_le_bytes(&[0xbb; 32]),
        chainwork: ChainWork::default(),
        chain_tx_count: bitcoin_rs_chain::ChainTxCount::UNKNOWN,
    };
    ctx.chain.chain_tip.store(Some(Arc::new(headers_tip)));
    ctx.chain.applied_tip.store(Some(Arc::new(applied_tip)));
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
        wtxid_relay: false,
        relay_transactions: true,
        compact_block_relay: false,
        send_headers: false,
        endpoint: Some(bitcoin_rs_p2p::PeerEndpoint::Ip(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            8333,
        ))),
        network: bitcoin_rs_p2p::NetworkLabel::Ipv4,
        addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333).into(),
        version: 70016,
        services: 0,
        user_agent: "/bitcoin-rs:0.1.0/".to_string(),
        start_height: 0,
        best_known_height: 0,
        conn_time: 0,
        inbound: true,
        addr_bind: bitcoin_rs_p2p::TransportRemote::new(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            8333,
        )),
        time_offset: 0,
        counters: Arc::new(bitcoin_rs_p2p::PeerCounters::default()),
        transport: bitcoin_rs_p2p::TransportProtocol::V1,
    };
    let (tx, _rx) = crossbeam_channel::unbounded();
    let lease = PeerLease::new(tx);
    peer_table.register(info.endpoint.expect("identified test peer"), lease.clone());
    peer_table.publish_info(info.endpoint.expect("identified test peer"), &lease, info);
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
    info: bitcoin_rs_rpc::context::DerivedIndexInfo,
    transactions: HashMap<Txid, Tx>,
    values: HashMap<OutPoint, u64>,
}

impl bitcoin_rs_rpc::context::DerivedIndexQuery for FakeTxIndex {
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
    ) -> Result<bitcoin_rs_rpc::context::DerivedIndexInfo, bitcoin_rs_rpc::context::TxQueryError>
    {
        Ok(self.info)
    }
}

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
                    lock_time: LockTime::ZERO,
                    inputs: Vec::new(),
                    outputs: vec![TxOut {
                        value: Amount::from_sat(10_000),
                        script_pubkey: Script::new(),
                    }],
                },
            );
        }
        ctx.indexes.derived_index = Some(Arc::new(FakeTxIndex {
            transactions,
            values,
            info: bitcoin_rs_rpc::context::DerivedIndexInfo {
                synced: true,
                best_block_height: 7,
            },
        }));
    }
    let block = seed_tree_chain(&ctx, &block);
    let record = BlockRecord::from_block(7, &block);
    ctx.chain.block_body_source = Some(Arc::new(SingleBlockSource {
        height: record.height,
        hash: record.hash,
        body: consensus_bytes(&block),
    }));
    ctx.chain.add_block(record);
    (Arc::new(ctx), low_tx, high_tx)
}

fn seed_tree_chain(ctx: &Context, block: &Block) -> Block {
    let mut tree = ctx.chain.block_tree.write();
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

fn fee_block(low_tx: Tx, high_tx: Tx) -> Block {
    let coinbase = Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[0_u8; 32])), u32::MAX),
            script_sig: vec![0x51].into(),
            sequence: Sequence::from_consensus(0xFFFF_FFFE),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: vec![0x51].into(),
        }],
    };
    let txs = vec![coinbase, low_tx, high_tx];
    let merkle_root = bitcoin_rs_chain::regtest_fixture::merkle_root(&txs).unwrap_or_default();
    Block {
        header: Header {
            version: 1,
            prev_blockhash: BlockHash::default(),
            merkle_root,
            time: 1_231_006_505,
            bits: CompactTarget::from_consensus(0x1d00_ffff),
            nonce: 0,
        },
        txs,
    }
}

fn fee_tx(label: u8, output_sat: u64) -> Tx {
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: outpoint(label),
            script_sig: Script::new(),
            sequence: Sequence::from_consensus(0xFFFF_FFFE),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(output_sat),
            script_pubkey: vec![0x51].into(),
        }],
    }
}

struct SingleBlockSource {
    height: u32,
    hash: BlockHash,
    body: Vec<u8>,
}

impl BlockBodySource for SingleBlockSource {
    fn block_body(
        &self,
        height: u32,
        hash: BlockHash,
    ) -> Result<Option<Vec<u8>>, bitcoin_rs_chain::BlockBodyReadError> {
        Ok((height == self.height && hash == self.hash).then(|| self.body.clone()))
    }
}

struct Fixture {
    ctx: Arc<Context>,
    tx: Tx,
    txid: Txid,
    block_hash: BlockHash,
    block_hex: String,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let mut ctx = Context::new().with_mining_control(FakeMiningControl::with_template(
            mining_fixture::canned_template(Vec::new(), Vec::new()),
            mining_fixture::canned_info(),
        ));

        ctx.chain.chain_network = Network::Regtest;
        let tx = tx(1, vec![0x51]);
        let merkle_root = bitcoin_rs_chain::regtest_fixture::merkle_root(std::slice::from_ref(&tx))
            .unwrap_or_default();
        let block = Block {
            header: Header {
                version: 1,
                prev_blockhash: BlockHash::default(),
                merkle_root,
                time: 1_231_006_505,
                bits: CompactTarget::from_consensus(0x1d00_ffff),
                nonce: 0,
            },
            txs: vec![tx.clone()],
        };
        let block = seed_tree_chain(&ctx, &block);
        let block_hash = block.block_hash();
        let tip = ctx
            .chain
            .block_tree
            .read()
            .tip()
            .expect("fixture tip missing")
            .as_ref()
            .clone();
        ctx.chain.chain_tip.store(Some(Arc::new(tip.clone())));
        ctx.chain.applied_tip.store(Some(Arc::new(tip)));
        ctx.chain.block_body_source = Some(Arc::new(SingleBlockSource {
            height: 7,
            hash: block_hash,
            body: consensus_bytes(&block),
        }));
        ctx.chain.add_block(BlockRecord::from_block(7, &block));
        let mut values = HashMap::new();
        values.insert(outpoint(1), 6_000);
        ctx.indexes.derived_index = Some(Arc::new(FakeTxIndex {
            transactions: HashMap::new(),
            values,
            info: bitcoin_rs_rpc::context::DerivedIndexInfo {
                synced: true,
                best_block_height: 7,
            },
        }));
        let block_hex = consensus_bytes(&block).to_lower_hex_string();
        let txid = tx.txid();
        let entry = MempoolEntry::new(Arc::new(tx.clone()), 100, 1_000, 1, 7, 0);
        ctx.mempool.gateway.pool().write().insert_entry(entry)?;
        Ok(Self {
            ctx: Arc::new(ctx),
            tx,
            txid,
            block_hash,
            block_hex,
        })
    }
}
fn context_with_peers(peer_table: Arc<PeerTable>) -> Arc<Context> {
    let mut ctx = Context::new();
    ctx.network.peer_table = peer_table;
    Arc::new(ctx)
}

fn tx(label: u8, script_pubkey: Vec<u8>) -> Tx {
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: outpoint(label),
            script_sig: Script::new(),
            sequence: Sequence::from_consensus(0xFFFF_FFFE),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(5_000),
            script_pubkey: script_pubkey.into(),
        }],
    }
}
fn outpoint(label: u8) -> OutPoint {
    OutPoint::new(Txid(Hash256::from_le_bytes(&[label; 32])), 0)
}

fn build_valid_base64_psbt(tx: &Tx) -> Result<String, Box<dyn std::error::Error>> {
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
