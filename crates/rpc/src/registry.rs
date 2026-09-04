//! Unified RPC registry: one row owns compat metadata plus dispatch arm.
//!
//! [`REGISTRY`] is the single source of truth for every external surface.
//! Each row declares the compat metadata (the [`Entry`] projection) and
//! binds the dispatch arm (`handler`) in one literal. `dispatch` routes
//! through this table; manifest views project from the same rows.

use alloc::sync::Arc;

use sonic_rs::Value;

use crate::context::Context;
use crate::error::RpcError;
use crate::handlers::{chain, mempool, mining, network, tx, util};
use crate::manifest::{CORE_VERSION, Entry, NO_WALLET, Status, SurfaceKind};

/// Signature of one dispatch arm.
pub(crate) type HandlerFn = fn(&Arc<Context>, &Value) -> Result<Value, RpcError>;

/// One unified registry row: compat metadata plus the dispatch arm.
///
/// `handler` is `None` for surfaces not dispatched through this table
/// (REST, ZMQ, `Unimplemented`, `pending`).
pub(crate) struct Row {
    pub entry: Entry,
    pub handler: Option<HandlerFn>,
}

/// Handler for `getzmqnotifications`, compiled only under the `zmq` feature.
#[cfg(feature = "zmq")]
const ZMQ_NOTIFS_HANDLER: Option<HandlerFn> = Some(util::getzmqnotifications);

#[cfg(not(feature = "zmq"))]
const ZMQ_NOTIFS_HANDLER: Option<HandlerFn> = None;

/// Declares both [`REGISTRY`] and [`MANIFEST`] from one set of row literals
/// so a method is declared and bound in a single source location.
macro_rules! declare_rows {
    (
        $(
            $name:literal,
            $kind:expr,
            $status:expr,
            $feature:literal,
            $core_version:expr,
            $notes:expr,
            $since:literal,
            $handler:expr;
        )*
    ) => {
        pub(crate) const REGISTRY: &[Row] = &[
            $(Row {
                entry: Entry {
                    name: $name,
                    kind: $kind,
                    status: $status,
                    feature: $feature,
                    core_version: $core_version,
                    notes: $notes,
                    since: $since,
                },
                handler: $handler,
            }),*
        ];

        /// Every external surface, declared against Core 31.x. Projection of
        /// [`REGISTRY`] without the dispatch arms; re-exported as
        /// `manifest::MANIFEST` for consumers that take `&[Entry]`.
        pub const MANIFEST: &[Entry] = &[
            $(Entry {
                name: $name,
                kind: $kind,
                status: $status,
                feature: $feature,
                core_version: $core_version,
                notes: $notes,
                since: $since,
            }),*
        ];
    };
}

declare_rows! {
    // -- JSON-RPC: shipped methods (registration order) --------------
    "getblockchaininfo", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "", "0.4.0", Some(chain::getblockchaininfo);
    "getdifficulty", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "", "0.4.0", Some(chain::getdifficulty);
    "getchaintips", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "", "0.4.0", Some(chain::getchaintips);
    "getchaintxstats", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "", "0.4.0", Some(chain::getchaintxstats);
    "getblockcount", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "", "0.4.0", Some(chain::getblockcount);
    "getblockhash", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "", "0.4.0", Some(chain::getblockhash);
    "getbestblockhash", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "", "0.4.0", Some(chain::getbestblockhash);
    "getblock", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "Response is the pinned corepc v31 verbose contract; verbosity 3 serves the verbosity-2 shape (no prevout source).", "0.4.0", Some(chain::getblock);
    "getblockheader", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "", "0.4.0", Some(chain::getblockheader);
    "getblockstats", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "", "0.4.0", Some(chain::getblockstats);
    "verifychain", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "", "0.4.0", Some(chain::verifychain);
    "gettxoutsetinfo", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "", "0.4.0", Some(chain::gettxoutsetinfo);
    "getindexinfo", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "", "0.4.0", Some(chain::getindexinfo);
    "pruneblockchain", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "", "0.4.0", Some(chain::pruneblockchain);
    "invalidateblock", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "", "0.4.0", Some(chain::invalidateblock);
    "scantxoutset", SurfaceKind::Rpc, Status::Deviation, "", CORE_VERSION, "Accepts only addr() scan descriptors; Core supports the full descriptor set (crates/rpc/src/handlers/chain.rs). Response uses the v28 scan contract; the status action answers null.", "0.4.0", Some(chain::scantxoutset);
    "getrawtransaction", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "", "0.4.0", Some(tx::getrawtransaction);
    "gettxout", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "", "0.4.0", Some(tx::gettxout);
    "gettxoutproof", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "", "0.4.0", Some(tx::gettxoutproof);
    "verifytxoutproof", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "", "0.4.0", Some(tx::verifytxoutproof);
    "sendrawtransaction", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "", "0.4.0", Some(tx::sendrawtransaction);
    "testmempoolaccept", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "", "0.4.0", Some(tx::testmempoolaccept);
    "decoderawtransaction", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "", "0.4.0", Some(tx::decoderawtransaction);
    "createrawtransaction", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "", "0.4.0", Some(tx::createrawtransaction);
    "combinepsbt", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "", "0.4.0", Some(tx::combinepsbt);
    "finalizepsbt", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "", "0.4.0", Some(tx::finalizepsbt);
    "getmempoolinfo", SurfaceKind::Rpc, Status::Deviation, "", CORE_VERSION, "Policy fields project the enforced MempoolPolicySnapshot (crates/mempool/src/policy.rs): fullrbf always reports the enforced BIP125 signaling requirement (false) where Core 31.1 emits the field only under -deprecatedrpc=fullrbf; limitclustercount and limitclustersize project the cluster limits admission enforces; optimal is always true because the fee-rate index is rewritten under the pool write lock (crates/rpc/src/handlers/mempool.rs).", "0.4.0", Some(mempool::getmempoolinfo);
    "getmempoolentry", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "", "0.4.0", Some(mempool::getmempoolentry);
    "getrawmempool", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "", "0.4.0", Some(mempool::getrawmempool);
    "getmempoolancestors", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "", "0.4.0", Some(mempool::getmempoolancestors);
    "getmempooldescendants", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "", "0.4.0", Some(mempool::getmempooldescendants);
    "estimatesmartfee", SurfaceKind::Rpc, Status::Deviation, "", CORE_VERSION, "No estimate_mode handling: Core parses the mode string and rejects unknown values with -8; conf_target is not range-checked against Core's 1-1008 (crates/rpc/src/handlers/util.rs).", "0.4.0", Some(util::estimatesmartfee);
    "uptime", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "", "0.4.0", Some(util::uptime);
    "getrpcinfo", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "", "0.4.0", Some(util::getrpcinfo);
    "getmemoryinfo", SurfaceKind::Rpc, Status::Deviation, "", CORE_VERSION, "mode=mallocinfo is rejected with an invalid-parameter error instead of returning allocator XML (crates/rpc/src/handlers/util.rs).", "0.4.0", Some(util::getmemoryinfo);
    "estimaterawfee", SurfaceKind::Rpc, Status::Deviation, "", CORE_VERSION, "local_shape: the fee estimator does not expose Core decay/scale/pass/fail internals, so horizon objects carry feerate only and the no-estimate branch stays {} (crates/rpc/src/handlers/util.rs).", "0.4.0", Some(util::estimaterawfee);
    "getzmqnotifications", SurfaceKind::Rpc, Status::Implemented, "zmq", CORE_VERSION, "Requires the zmq feature and --enablezmq* startup flags.", "0.4.0", ZMQ_NOTIFS_HANDLER;
    "validateaddress", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "local_shape (invalid branch): a malformed or wrong-network address is hand-built as Core's sparse {isvalid:false} object because corepc-types models the valid-only fields (address, scriptPubKey, isscript, iswitness) as required and cannot represent that wire shape; valid addresses round-trip the typed v31 contract (crates/rpc/src/handlers/util.rs).", "0.4.0", Some(util::validateaddress);
    "getdescriptorinfo", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "", "0.4.0", Some(util::getdescriptorinfo);
    "deriveaddresses", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "", "0.4.0", Some(util::deriveaddresses);
    "getnetworkinfo", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "", "0.4.0", Some(network::getnetworkinfo);
    "getpeerinfo", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "Pinned v31 shape; telemetry this node does not measure (byte counters, pingwait, addr relay stats) reports Core's zero-value defaults.", "0.4.0", Some(network::getpeerinfo);
    "ping", SurfaceKind::Rpc, Status::Deviation, "", CORE_VERSION, "Answers immediately; Core schedules a P2P ping and reports the seen pong (crates/rpc/src/handlers/network.rs).", "0.4.0", Some(network::ping);
    "addnode", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "", "0.4.0", Some(network::addnode);
    "disconnectnode", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "", "0.4.0", Some(network::disconnectnode);
    "getconnectioncount", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "", "0.4.0", Some(network::getconnectioncount);
    "getnettotals", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "", "0.4.0", Some(network::getnettotals);
    "getaddednodeinfo", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "", "0.4.0", Some(network::getaddednodeinfo);
    "listbanned", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "Pinned v22 shape; the pre-v22 ban_reason field is replaced by ban_duration and time_remaining.", "0.4.0", Some(network::listbanned);
    "setban", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "", "0.4.0", Some(network::setban);
    "clearbanned", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "", "0.4.0", Some(network::clearbanned);
    "setnetworkactive", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "", "0.4.0", Some(network::setnetworkactive);
    "getnodeaddresses", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "", "0.4.0", Some(network::getnodeaddresses);
    "getblocktemplate", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "Pinned v17 template contract; BIP23 submitold/workid extras are not emitted.", "0.4.0", Some(mining::getblocktemplate);
    "getmininginfo", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "Pinned v30 shape including bits/target and next-block facts derived from the mining coordinator.", "0.4.0", Some(mining::getmininginfo);
    "submitblock", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "", "0.4.0", Some(mining::submitblock);
    "prioritisetransaction", SurfaceKind::Rpc, Status::Implemented, "", CORE_VERSION, "", "0.4.0", Some(mining::prioritisetransaction);

    // -- JSON-RPC: bitcoin-rs extension ------------------------------
    "getcapabilities", SurfaceKind::Rpc, Status::Extension, "", CORE_VERSION, "bitcoin-rs reporting of compiled/enabled concrete service capabilities and index lifecycle state (crates/rpc/src/handlers/chain.rs, crates/node/src/capabilities.rs).", "0.4.0", Some(chain::getcapabilities);

    // -- JSON-RPC: Core surface not exposed (blockchain/control) -----
    "dumptxoutset", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "UTXO snapshot dump not implemented.", "n/a", None;
    "getblockfrompeer", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "No on-demand block fetch from peers.", "n/a", None;
    "getchainstates", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "Not implemented.", "n/a", None;
    "getdeploymentinfo", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "Not implemented over JSON-RPC (the REST /rest/deploymentinfo route exists).", "n/a", None;
    "getdescriptoractivity", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "No wallet/scan index to serve it.", "n/a", None;
    "getmempoolcluster", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "Cluster mempool tracking not implemented.", "n/a", None;
    "gettxspendingprevout", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "Not implemented.", "n/a", None;
    "importmempool", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "Mempool import not implemented.", "n/a", None;
    "loadtxoutset", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "UTXO snapshot load (assumeutxo) not implemented.", "n/a", None;
    "preciousblock", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "No manual block-preference surface.", "n/a", None;
    "reconsiderblock", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "No manual reorg-control surface.", "n/a", None;
    "savemempool", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "Mempool dump/reload persistence not implemented.", "n/a", None;
    "scanblocks", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "No BIP157/158 filter index to scan.", "n/a", None;
    "waitforblock", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "No long-poll wait surface.", "n/a", None;
    "waitforblockheight", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "No long-poll wait surface.", "n/a", None;
    "waitfornewblock", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "No long-poll wait surface.", "n/a", None;
    "help", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "No per-method help text renderer.", "n/a", None;
    "logging", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "Log-category controls not exposed over RPC.", "n/a", None;
    "stop", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "Lifecycle control not exposed over RPC.", "n/a", None;

    // -- JSON-RPC: Core surface not exposed (mining/network/util/signer)
    "getnetworkhashps", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "Network hash-rate estimate not implemented.", "n/a", None;
    "getprioritisedtransactions", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "Prioritisation map not queryable yet.", "n/a", None;
    "submitheader", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "Header-only submission not implemented.", "n/a", None;
    "getaddrmaninfo", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "Addrman table stats not exposed.", "n/a", None;
    "abortprivatebroadcast", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "Private-broadcast store not implemented.", "n/a", None;
    "analyzepsbt", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "PSBT analysis not implemented (combine/finalize only).", "n/a", None;
    "combinerawtransaction", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "Raw-transaction combination not implemented.", "n/a", None;
    "converttopsbt", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "PSBT creation not implemented.", "n/a", None;
    "createpsbt", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "PSBT creation not implemented.", "n/a", None;
    "decodepsbt", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "PSBT analysis not implemented (combine/finalize only).", "n/a", None;
    "decodescript", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "Script decode helper not implemented.", "n/a", None;
    "descriptorprocesspsbt", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "fundrawtransaction", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "getprivatebroadcastinfo", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "Private-broadcast store not implemented.", "n/a", None;
    "joinpsbts", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "PSBT merge not implemented (combine/finalize only).", "n/a", None;
    "signrawtransactionwithkey", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "Signing requires key material this process never holds.", "n/a", None;
    "submitpackage", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "Package acceptance not implemented.", "n/a", None;
    "utxoupdatepsbt", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "PSBT update from the UTXO set not implemented.", "n/a", None;
    "enumeratesigners", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "No external signer support.", "n/a", None;
    "createmultisig", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "No key material (policy).", "n/a", None;
    "signmessagewithprivkey", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "Signing requires key material this process never holds.", "n/a", None;
    "verifymessage", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "Message-signature verification not implemented.", "n/a", None;

    // -- JSON-RPC: Core wallet surface, excluded by the no-wallet policy
    "abandontransaction", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "abortrescan", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "backupwallet", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "bumpfee", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "createwallet", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "createwalletdescriptor", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "encryptwallet", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "getaddressesbylabel", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "getaddressinfo", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "getbalance", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "getbalances", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "gethdkeys", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "getnewaddress", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "getrawchangeaddress", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "getreceivedbyaddress", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "getreceivedbylabel", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "gettransaction", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "getwalletinfo", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "importdescriptors", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "importprunedfunds", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "keypoolrefill", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "listaddressgroupings", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "listdescriptors", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "listlabels", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "listlockunspent", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "listreceivedbyaddress", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "listreceivedbylabel", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "listsinceblock", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "listtransactions", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "listunspent", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "listwalletdir", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "listwallets", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "loadwallet", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "lockunspent", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "migratewallet", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "psbtbumpfee", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "removeprunedfunds", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "rescanblockchain", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "restorewallet", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "send", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "sendall", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "sendmany", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "sendtoaddress", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "setlabel", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "setwalletflag", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "signmessage", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "signrawtransactionwithwallet", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "simulaterawtransaction", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "unloadwallet", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "walletcreatefundedpsbt", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "walletdisplayaddress", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "walletlock", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "walletpassphrase", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "walletpassphrasechange", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;
    "walletprocesspsbt", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, NO_WALLET, "n/a", None;

    // -- REST (Core StartREST registration order) --------------------
    "/rest/tx/", SurfaceKind::Rest, Status::Implemented, "", CORE_VERSION, "", "0.4.0", None;
    "/rest/block/notxdetails/", SurfaceKind::Rest, Status::Implemented, "", CORE_VERSION, "", "0.4.0", None;
    "/rest/block/", SurfaceKind::Rest, Status::Implemented, "", CORE_VERSION, "", "0.4.0", None;
    "/rest/blockpart/", SurfaceKind::Rest, Status::Implemented, "", CORE_VERSION, "bin/hex only; JSON rejected as in Core's original part endpoint.", "0.4.0", None;
    "/rest/chaininfo", SurfaceKind::Rest, Status::Implemented, "", CORE_VERSION, "", "0.4.0", None;
    "/rest/mempool/", SurfaceKind::Rest, Status::Implemented, "", CORE_VERSION, "", "0.4.0", None;
    "/rest/headers/", SurfaceKind::Rest, Status::Implemented, "", CORE_VERSION, "", "0.4.0", None;
    "/rest/getutxos", SurfaceKind::Rest, Status::Deviation, "", CORE_VERSION, "URI-scheme input only; Core also accepts a POST raw-transaction body (crates/rpc/src/rest.rs).", "0.4.0", None;
    "/rest/deploymentinfo/", SurfaceKind::Rest, Status::Implemented, "", CORE_VERSION, "", "0.4.0", None;
    "/rest/deploymentinfo", SurfaceKind::Rest, Status::Implemented, "", CORE_VERSION, "", "0.4.0", None;
    "/rest/blockhashbyheight/", SurfaceKind::Rest, Status::Implemented, "", CORE_VERSION, "", "0.4.0", None;
    "/rest/spenttxouts/", SurfaceKind::Rest, Status::Deviation, "", CORE_VERSION, "Always answers undo-unavailable: undo data is not persisted (crates/rpc/src/rest.rs).", "0.4.0", None;
    "esplora/*", SurfaceKind::Rest, Status::Extension, "", CORE_VERSION, "Esplora-compatible indexer HTTP surface, a separate non-Core contract (crates/rpc/src/esplora.rs, docs/rest-interface.md).", "0.4.0", None;

    // -- ZMQ topics --------------------------------------------------
    "hashblock", SurfaceKind::Zmq, Status::Implemented, "zmq", CORE_VERSION, "Requires the zmq feature and a --zmqpubhashblock endpoint.", "0.4.0", None;
    "hashtx", SurfaceKind::Zmq, Status::Implemented, "zmq", CORE_VERSION, "Requires the zmq feature and a --zmqpubhashtx endpoint.", "0.4.0", None;
    "rawblock", SurfaceKind::Zmq, Status::Implemented, "zmq", CORE_VERSION, "Requires the zmq feature and a --zmqpubrawblock endpoint.", "0.4.0", None;
    "rawtx", SurfaceKind::Zmq, Status::Implemented, "zmq", CORE_VERSION, "Requires the zmq feature and a --zmqpubrawtx endpoint.", "0.4.0", None;
    "sequence", SurfaceKind::Zmq, Status::Implemented, "zmq", CORE_VERSION, "Requires the zmq feature and a --zmqpubsequence endpoint. Publishes C/D block events and A/R mempool events; A/R carry reversed txid, the label byte, and the mempool sequence as u64 LE (crates/node/src/zmq_publisher.rs).", "0.4.0", None;
}
