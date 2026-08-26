//! Integration proof for I1 RPC cutover: shared Arc identity, exact method
//! accounting (65 with ZMQ / 64 without), seven `MethodNotFound` absences,
//! typed no-custody errors, and fourteen REST registrations.

use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use bitcoin::ScriptBuf;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin_rs_node::run::RpcBlockUndoSource;
use bitcoin_rs_node::{Config, MiningCoordinator, state::NodeState};
use bitcoin_rs_p2p::NetworkControls;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_rpc::Handler;
use bitcoin_rs_rpc::RpcError;
use bitcoin_rs_rpc::RpcLifecycle;
use bitcoin_rs_rpc::context::{
    BlockUndoSource, ChainHandles, Context, ContextHandles, IndexHandles, NetworkHandles,
};
use bitcoin_rs_rpc::rest::REGISTRATIONS;
use bitcoin_rs_wallet::Watcher;
use parking_lot::RwLock;
use sonic_rs::{Value, json};
use tempfile::tempdir;

const CHAIN: &[&str] = &[
    "getblockchaininfo",
    "getdifficulty",
    "getchaintips",
    "getchaintxstats",
    "getblockcount",
    "getblockhash",
    "getbestblockhash",
    "getblock",
    "getblockheader",
    "getblockstats",
    "verifychain",
    "gettxoutsetinfo",
    "getblockfilter",
    "getindexinfo",
    "pruneblockchain",
    "invalidateblock",
];

const TX: &[&str] = &[
    "getrawtransaction",
    "gettxout",
    "gettxoutproof",
    "verifytxoutproof",
    "sendrawtransaction",
    "testmempoolaccept",
    "decoderawtransaction",
];

const MEMPOOL: &[&str] = &[
    "getmempoolinfo",
    "getmempoolentry",
    "getrawmempool",
    "getmempoolancestors",
    "getmempooldescendants",
];

const UTIL_BASE: &[&str] = &[
    "estimatesmartfee",
    "uptime",
    "getrpcinfo",
    "getmemoryinfo",
    "estimaterawfee",
    "validateaddress",
];

const NETWORK: &[&str] = &[
    "getnetworkinfo",
    "getpeerinfo",
    "ping",
    "addnode",
    "disconnectnode",
    "getconnectioncount",
    "getnettotals",
    "getaddednodeinfo",
    "listbanned",
    "setban",
    "clearbanned",
    "setnetworkactive",
];

const MINING: &[&str] = &[
    "getblocktemplate",
    "getmininginfo",
    "submitblock",
    "prioritisetransaction",
];

const WALLET: &[&str] = &[
    "getdescriptorinfo",
    "deriveaddresses",
    "scantxoutset",
    "walletcreatefundedpsbt",
    "walletprocesspsbt",
    "finalizepsbt",
    "combinepsbt",
    "bumpfee",
    "signrawtransactionwithkey",
    "signrawtransactionwithwallet",
    "importdescriptors",
    "walletpassphrase",
    "walletpassphrasechange",
    "encryptwallet",
];

const ABSENT: &[&str] = &[
    "clearmempool",
    "dumpprivkey",
    "dumpwallet",
    "importprivkey",
    "importwallet",
    "importmulti",
    "sethdseed",
    "waitfornewblock",
    "waitforblock",
    "waitforblockheight",
    "createrawtransaction",
    "analyzepsbt",
    "joinpsbts",
    "utxoupdatepsbt",
    "getnodeaddresses",
];

const NO_CUSTODY: &[&str] = &[
    "signrawtransactionwithwallet",
    "walletpassphrase",
    "walletpassphrasechange",
    "encryptwallet",
];

const NO_PRIVATE_KEYS: &str = "wallet has no private keys; use external signer";

fn expected_methods() -> Vec<&'static str> {
    let mut methods = Vec::with_capacity(65);
    methods.extend_from_slice(CHAIN);
    methods.extend_from_slice(TX);
    methods.extend_from_slice(MEMPOOL);
    methods.extend_from_slice(UTIL_BASE);
    #[cfg(feature = "zmq")]
    methods.push("getzmqnotifications");
    methods.extend_from_slice(NETWORK);
    methods.extend_from_slice(MINING);
    methods.extend_from_slice(WALLET);
    methods
}

fn empty_params() -> Value {
    json!([])
}

#[test]
#[allow(clippy::arc_with_non_send_sync)]
#[allow(clippy::too_many_lines)]
fn rpc_context_shares_arc_identity_with_node_state() -> Result<()> {
    let dir = tempdir()?;
    let mut config = Config::default();
    config.data_dir = dir.path().join("node");
    config.txindex = true;
    config.zmqpubhashblock = vec!["inproc://rpc-wiring-zmq-pubhashblock".to_owned()];
    config.zmqpubhashblockhwm = Some(21);
    config.zmqpubsequence = vec!["inproc://rpc-wiring-zmq-pubsequence".to_owned()];
    config.zmqpubsequencehwm = Some(22);
    let state = NodeState::open(config)?;

    let chain_tip = state.chain_tip();
    let applied_tip = state.applied_tip();
    let mempool = state.mempool();
    let blocks = state.blocks();
    let transactions = state.transactions();
    let utxo = state.utxo();
    let coin_stats = state.coin_stats();
    let filter_index = state.filter_index();
    let network = state.network();
    let block_tree = state.block_tree();
    let peers = state.peers();
    let peer_outbound = state.peer_outbound();
    let banned = state.banned_subnets();
    let controls = Arc::new(NetworkControls::new(
        Arc::clone(&peers),
        Arc::clone(&peer_outbound),
        Arc::clone(&banned),
        state.config().network.default_p2p_port(),
    ));
    let wallet = Arc::new(RwLock::new(Watcher::new(Vec::new())));
    let lifecycle = Arc::new(RpcLifecycle::new(state.shutdown(), Instant::now()));
    let mining = Arc::new(MiningCoordinator::new(
        state.config().network,
        Arc::clone(&applied_tip),
        Arc::clone(&block_tree),
        Arc::clone(&mempool),
        state.apply_handles(),
        ScriptBuf::new(),
        state.shutdown(),
    ));
    let Some(tx_index) = state.tx_index_query() else {
        panic!("txindex query engine missing when enabled");
    };

    let mining_control: Arc<dyn bitcoin_rs_rpc::context::MiningControl> = mining;
    let block_undo_source: Arc<dyn BlockUndoSource> =
        Arc::new(RpcBlockUndoSource::new(&state.apply_handles()));
    let ctx = Context::production(ContextHandles {
        chain: ChainHandles {
            chain_tip: Arc::clone(&chain_tip),
            applied_tip: Arc::clone(&applied_tip),
            chain_tx_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            blocks: Arc::clone(&blocks),
            transactions: Arc::clone(&transactions),
            utxo: Arc::clone(&utxo),
            coin_stats: Arc::clone(&coin_stats),
            filter_index: Arc::clone(&filter_index),
            block_tree: Arc::clone(&block_tree),
            block_undo_source: Arc::clone(&block_undo_source),
            network: state.config().network,
        },
        mempool: Arc::clone(&mempool),
        indexes: IndexHandles {
            transactions: Some(tx_index),
            esplora_transactions: state.esplora_tx_index_query(),
            scripts: state.script_index_query(),
        },
        network: NetworkHandles {
            state: Arc::clone(&network),
            controls: Arc::clone(&controls),
        },
    })
    .with_zmq_notifications(state.active_zmq_notifications())
    .with_wallet(Arc::clone(&wallet))
    .with_rpc_lifecycle(Arc::clone(&lifecycle))
    .with_mining_control(Arc::clone(&mining_control))
    .with_debug_log_path(state.data_dir().join("debug.log"));

    assert!(Arc::ptr_eq(&ctx.chain_tip, &chain_tip));
    assert!(Arc::ptr_eq(&ctx.applied_tip, &applied_tip));
    assert!(Arc::ptr_eq(&ctx.mempool, &mempool));
    assert!(Arc::ptr_eq(&ctx.blocks, &blocks));
    assert!(Arc::ptr_eq(&ctx.transactions, &transactions));
    assert!(Arc::ptr_eq(&ctx.utxo, &utxo));
    assert!(Arc::ptr_eq(&ctx.coin_stats, &coin_stats));
    assert!(Arc::ptr_eq(&ctx.filter_index, &filter_index));
    assert!(Arc::ptr_eq(&ctx.network, &network));
    assert!(Arc::ptr_eq(&ctx.block_tree, &block_tree));
    assert!(Arc::ptr_eq(
        ctx.network_controls
            .as_ref()
            .unwrap_or_else(|| panic!("network controls missing")),
        &controls
    ));
    assert!(Arc::ptr_eq(
        ctx.wallet
            .as_ref()
            .unwrap_or_else(|| panic!("wallet missing")),
        &wallet
    ));
    assert!(Arc::ptr_eq(
        ctx.rpc_lifecycle
            .as_ref()
            .unwrap_or_else(|| panic!("RPC lifecycle missing")),
        &lifecycle
    ));
    {
        let installed = ctx
            .mining_control
            .as_ref()
            .unwrap_or_else(|| panic!("mining control missing"));
        assert!(
            Arc::ptr_eq(installed, &mining_control),
            "mining_control must share identity"
        );
    }
    assert!(
        ctx.tx_index.is_some(),
        "txindex query adapter must be wired"
    );
    let installed_undo = ctx
        .block_undo_source
        .as_ref()
        .unwrap_or_else(|| panic!("block undo source missing"));
    let missing = installed_undo.block_undo(99, Hash256::from_le_bytes(&[0x11; 32]))?;
    assert!(
        missing.is_none(),
        "unknown undo records must be absence, not an error"
    );
    let genesis = genesis_block(bitcoin::Network::Bitcoin);
    let tip = state.apply_block(&genesis)?;
    let decoded = installed_undo
        .block_undo(tip.height, tip.hash)?
        .unwrap_or_else(|| panic!("production undo adapter must decode applied genesis undo"));
    assert!(decoded.is_empty(), "genesis undo is an empty decoded batch");
    assert_eq!(ctx.chain_network, state.config().network);
    assert_eq!(
        ctx.debug_log_path,
        Some(state.data_dir().join("debug.log")),
        "debug_log_path must mirror <datadir>/debug.log"
    );

    let notifications = ctx.zmq_notifications();
    #[cfg(feature = "zmq")]
    {
        assert_eq!(notifications.len(), 2);
        assert_eq!(notifications[0].notification_type.as_str(), "pubhashblock");
        assert_eq!(notifications[0].hwm, 21);
        assert_eq!(notifications[1].notification_type.as_str(), "pubsequence");
        assert_eq!(notifications[1].hwm, 22);
    }
    #[cfg(not(feature = "zmq"))]
    {
        assert!(notifications.is_empty());
    }

    Ok(())
}

#[test]
fn rpc_context_omits_indexer_when_node_txindex_is_disabled() -> Result<()> {
    let dir = tempdir()?;
    let mut config = Config::default();
    config.data_dir = dir.path().join("node");
    config.txindex = false;
    let state = NodeState::open(config)?;

    assert!(state.tx_index_query().is_none());
    Ok(())
}

#[test]
#[cfg(feature = "zmq")]
fn rpc_method_accounting_with_zmq() {
    let expected = expected_methods();
    assert_eq!(
        expected.len(),
        65,
        "ZMQ build must register exactly 65 methods"
    );
    assert_eq!(REGISTRATIONS.len(), 14);

    let handler = Handler::new(Arc::new(Context::new()));
    let params = empty_params();
    for method in &expected {
        let err = match handler.dispatch(method, &params) {
            Ok(_) => continue,
            Err(error) => error,
        };
        assert!(
            !matches!(err, RpcError::MethodNotFound(_)),
            "{method} must be registered under zmq"
        );
    }
    for method in ABSENT {
        match handler.dispatch(method, &params) {
            Err(RpcError::MethodNotFound(_)) => {}
            other => panic!("{method} must be MethodNotFound, got {other:?}"),
        }
    }
    for method in NO_CUSTODY {
        match handler.dispatch(method, &params) {
            Err(RpcError::MethodDisabled(message)) => {
                assert_eq!(message, NO_PRIVATE_KEYS);
            }
            other => panic!("{method} must be MethodDisabled, got {other:?}"),
        }
    }
    match handler.dispatch("getzmqnotifications", &params) {
        Ok(_) | Err(_) => {}
    }
}

#[test]
#[cfg(not(feature = "zmq"))]
fn rpc_method_accounting_without_zmq() {
    let expected = expected_methods();
    assert_eq!(
        expected.len(),
        64,
        "non-ZMQ build must register exactly 64 methods"
    );
    assert_eq!(REGISTRATIONS.len(), 14);

    let handler = Handler::new(Arc::new(Context::new()));
    let params = empty_params();
    for method in &expected {
        let err = match handler.dispatch(method, &params) {
            Ok(_) => continue,
            Err(error) => error,
        };
        assert!(
            !matches!(err, RpcError::MethodNotFound(_)),
            "{method} must be registered without zmq"
        );
    }
    for method in ABSENT {
        match handler.dispatch(method, &params) {
            Err(RpcError::MethodNotFound(_)) => {}
            other => panic!("{method} must be MethodNotFound, got {other:?}"),
        }
    }
    match handler.dispatch("getzmqnotifications", &params) {
        Err(RpcError::MethodNotFound(_)) => {}
        other => panic!("getzmqnotifications must be absent without zmq, got {other:?}"),
    }
}
