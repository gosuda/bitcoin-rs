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
use crate::handlers::{chain, deployment, mempool, mining, network, tx, util};
use crate::manifest::{CORE_VERSION, Entry, NO_WALLET, Status, SurfaceKind};

/// Signature of one dispatch arm.
type HandlerFn = fn(&Arc<Context>, &Value) -> Result<Value, RpcError>;

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
    "getblockchaininfo", SurfaceKind::Rpc, Status::Deviation, "", CORE_VERSION, "Unavailable optional fields are omitted. Pruning mode/target and signet challenge are not reported (automatic_pruning, prune_target_size, signet_challenge); pruneheight reflects the backing prune service (crates/rpc/src/handlers/chain.rs).", "0.4.0", Some(chain::getblockchaininfo);
    "getdifficulty", SurfaceKind::Rpc, Status::ImplementedUnverified, "", CORE_VERSION, "", "0.4.0", Some(chain::getdifficulty);
    "getchaintips", SurfaceKind::Rpc, Status::ImplementedUnverified, "", CORE_VERSION, "", "0.4.0", Some(chain::getchaintips);
    "getchaintxstats", SurfaceKind::Rpc, Status::ImplementedUnverified, "", CORE_VERSION, "", "0.4.0", Some(chain::getchaintxstats);
    "getblockcount", SurfaceKind::Rpc, Status::ImplementedUnverified, "", CORE_VERSION, "", "0.4.0", Some(chain::getblockcount);
    "getblockhash", SurfaceKind::Rpc, Status::ImplementedUnverified, "", CORE_VERSION, "", "0.4.0", Some(chain::getblockhash);
    "getbestblockhash", SurfaceKind::Rpc, Status::ImplementedUnverified, "", CORE_VERSION, "", "0.4.0", Some(chain::getbestblockhash);
    "getblock", SurfaceKind::Rpc, Status::Deviation, "", CORE_VERSION, "Response is the pinned corepc v31 verbose contract; verbosity 3 serves the verbosity-2 shape because no prevout source exists — Core returns prevouts at verbosity 3 (crates/rpc/src/handlers/chain.rs).", "0.4.0", Some(chain::getblock);
    "getblockheader", SurfaceKind::Rpc, Status::ImplementedUnverified, "", CORE_VERSION, "", "0.4.0", Some(chain::getblockheader);
    "getblockstats", SurfaceKind::Rpc, Status::ImplementedUnverified, "", CORE_VERSION, "", "0.4.0", Some(chain::getblockstats);
    "verifychain", SurfaceKind::Rpc, Status::Deviation, "", CORE_VERSION, "Levels 3 and 4 omit Core's block disconnect and reconnect checks; level 3 behaves as level 2 and level 4 does not replay the UTXO set (crates/rpc/src/handlers/chain.rs).", "0.4.0", Some(chain::verifychain);
    "gettxoutsetinfo", SurfaceKind::Rpc, Status::ImplementedUnverified, "", CORE_VERSION, "", "0.4.0", Some(chain::gettxoutsetinfo);
    "getindexinfo", SurfaceKind::Rpc, Status::ImplementedUnverified, "", CORE_VERSION, "", "0.4.0", Some(chain::getindexinfo);
    "pruneblockchain", SurfaceKind::Rpc, Status::ImplementedUnverified, "", CORE_VERSION, "", "0.4.0", Some(chain::pruneblockchain);
    "invalidateblock", SurfaceKind::Rpc, Status::ImplementedUnverified, "", CORE_VERSION, "", "0.4.0", Some(chain::invalidateblock);
    "scantxoutset", SurfaceKind::Rpc, Status::Deviation, "", CORE_VERSION, "Accepts only addr() scan descriptors; Core supports the full descriptor set (crates/rpc/src/handlers/chain.rs). Response uses the v28 scan contract; the status action answers null.", "0.4.0", Some(chain::scantxoutset);
    "getrawtransaction", SurfaceKind::Rpc, Status::ImplementedUnverified, "", CORE_VERSION, "", "0.4.0", Some(tx::getrawtransaction);
    "gettxout", SurfaceKind::Rpc, Status::ImplementedUnverified, "", CORE_VERSION, "", "0.4.0", Some(tx::gettxout);
    "gettxoutproof", SurfaceKind::Rpc, Status::ImplementedUnverified, "", CORE_VERSION, "", "0.4.0", Some(tx::gettxoutproof);
    "verifytxoutproof", SurfaceKind::Rpc, Status::ImplementedUnverified, "", CORE_VERSION, "", "0.4.0", Some(tx::verifytxoutproof);
    "sendrawtransaction", SurfaceKind::Rpc, Status::Deviation, "", CORE_VERSION, "Core 31.1 replacement, modified-fee, cluster and TRUC cases are process-verified in overhaul_process_harness::policy_cases. Exact optimal graph ordering does not emulate Core transient SFL work-budget states. Capacity/floor accounting and generic consensus error details retain the differences in docs/policies/mempool-policy.md; aggregate package submission is unsupported.", "0.4.0", Some(tx::sendrawtransaction);
    "testmempoolaccept", SurfaceKind::Rpc, Status::Deviation, "", CORE_VERSION, "Single preview shares committed admission verification. Core 31.1 package shape, dependency, fail-fast and replacement-disallowed cases are process-verified in overhaul_process_harness::policy_cases. Exact graph ordering, capacity/floor behavior and generic error details retain the differences in docs/policies/mempool-policy.md. Aggregate package submission is unsupported.", "0.4.0", Some(tx::testmempoolaccept);
    "decoderawtransaction", SurfaceKind::Rpc, Status::ImplementedUnverified, "", CORE_VERSION, "", "0.4.0", Some(tx::decoderawtransaction);
    "createrawtransaction", SurfaceKind::Rpc, Status::Deviation, "", CORE_VERSION, "Accepts inputs, outputs, locktime and replaceable only. Version is fixed at 2 and replaceable defaults to false. Named version is rejected with -8; a fifth positional or args-prefix entry is rejected with -32602 after named binding. See docs/contracts/external-api.md#api-02-json-rpc-mechanics-and-the-wallet-free-surface.", "0.4.0", Some(tx::createrawtransaction);
    "combinepsbt", SurfaceKind::Rpc, Status::ImplementedUnverified, "", CORE_VERSION, "", "0.4.0", Some(tx::combinepsbt);
    "finalizepsbt", SurfaceKind::Rpc, Status::ImplementedUnverified, "", CORE_VERSION, "", "0.4.0", Some(tx::finalizepsbt);
    "getmempoolinfo", SurfaceKind::Rpc, Status::Deviation, "", CORE_VERSION, "Policy fields project the enforced MempoolPolicySnapshot: fullrbf is true and cluster bounds are enforced. optimal is always true for exact graph ordering rather than Core background SFL state. usage estimates local structures; maxmempool bounds virtual size rather than allocator usage. The pressure floor is a local heuristic, not Core rolling decay. See docs/policies/mempool-policy.md.", "0.4.0", Some(mempool::getmempoolinfo);
    "getmempoolentry", SurfaceKind::Rpc, Status::ImplementedUnverified, "", CORE_VERSION, "", "0.4.0", Some(mempool::getmempoolentry);
    "gettxspendingprevout", SurfaceKind::Rpc, Status::Deviation, "", CORE_VERSION, "Mempool lookup and options follow Core 31.1 without txospenderindex. After named binding, missing outputs and excess positional arguments use local -32602 shape errors. Core uses -1 help for no arguments/excess arity but -3 for an outputs hole created by named options; explicit null matches Core -3. Name and collision errors retain Core precedence. See docs/contracts/external-api.md#api-32-gettxspendingprevout-mempool-snapshot.", "0.11.0", Some(mempool::gettxspendingprevout);
    "getrawmempool", SurfaceKind::Rpc, Status::ImplementedUnverified, "", CORE_VERSION, "", "0.4.0", Some(mempool::getrawmempool);
    "getmempoolancestors", SurfaceKind::Rpc, Status::ImplementedUnverified, "", CORE_VERSION, "", "0.4.0", Some(mempool::getmempoolancestors);
    "getmempooldescendants", SurfaceKind::Rpc, Status::ImplementedUnverified, "", CORE_VERSION, "", "0.4.0", Some(mempool::getmempooldescendants);
    "estimatesmartfee", SurfaceKind::Rpc, Status::Deviation, "", CORE_VERSION, "See docs/contracts/external-api.md#API-26 for conf_target and estimate_mode validation. The estimate comes from this node's mempool confirmation-history estimator with a 25-block horizon; estimate_mode is accepted and ignored (no ECONOMICAL/CONSERVATIVE split), and insufficient history returns an `errors` array (crates/rpc/src/handlers/util.rs).", "0.4.0", Some(util::estimatesmartfee);
    "uptime", SurfaceKind::Rpc, Status::ImplementedUnverified, "", CORE_VERSION, "", "0.4.0", Some(util::uptime);
    "getrpcinfo", SurfaceKind::Rpc, Status::Deviation, "", CORE_VERSION, "active_commands is always an empty array; this node does not track in-flight RPC calls. logpath reports the configured debug log path (crates/rpc/src/handlers/util.rs).", "0.4.0", Some(util::getrpcinfo);
    "getmemoryinfo", SurfaceKind::Rpc, Status::Deviation, "", CORE_VERSION, "mode=mallocinfo is rejected with an invalid-parameter error instead of returning allocator XML (crates/rpc/src/handlers/util.rs). The figures are resident set size read from the OS, not Core's locked-pool allocator accounting.", "0.4.0", Some(util::getmemoryinfo);
    "estimaterawfee", SurfaceKind::Rpc, Status::Deviation, "", CORE_VERSION, "local_shape: the fee estimator does not expose Core decay/scale/pass/fail internals, so horizon objects carry feerate only and the no-estimate branch stays {} (crates/rpc/src/handlers/util.rs). All three horizons carry the same feerate where Core computes three independent estimates.", "0.4.0", Some(util::estimaterawfee);
    "getzmqnotifications", SurfaceKind::Rpc, Status::ImplementedUnverified, "zmq", CORE_VERSION, "Requires the zmq feature and --enablezmq* startup flags.", "0.4.0", ZMQ_NOTIFS_HANDLER;
    "validateaddress", SurfaceKind::Rpc, Status::Deviation, "", CORE_VERSION, "local_shape (invalid branch): a malformed or wrong-network address is hand-built as Core's sparse {isvalid:false} object because corepc-types models the valid-only fields (address, scriptPubKey, isscript, iswitness) as required and cannot represent that wire shape; valid addresses round-trip the typed v31 contract (crates/rpc/src/handlers/util.rs).", "0.4.0", Some(util::validateaddress);
    "getdescriptorinfo", SurfaceKind::Rpc, Status::ImplementedUnverified, "", CORE_VERSION, "", "0.4.0", Some(util::getdescriptorinfo);
    "deriveaddresses", SurfaceKind::Rpc, Status::ImplementedUnverified, "", CORE_VERSION, "", "0.4.0", Some(util::deriveaddresses);
    "getnetworkinfo", SurfaceKind::Rpc, Status::ImplementedUnverified, "", CORE_VERSION, "", "0.4.0", Some(network::getnetworkinfo);
    "getpeerinfo", SurfaceKind::Rpc, Status::Deviation, "", CORE_VERSION, "Pinned v31 shape; aggregate byte totals, negotiated transaction-relay preference, and received minimum_fee_filter are measured, while per-message byte breakdowns report empty maps and last_transaction/last_block/last_inv_sequence report Core's zero-value defaults; unmeasured telemetry (ping times, addr relay stats, starting_height, address_local, mapped_as) is null-omitted (crates/rpc/src/handlers/network.rs).", "0.4.0", Some(network::getpeerinfo);
    "ping", SurfaceKind::Rpc, Status::Deviation, "", CORE_VERSION, "Answers immediately; Core schedules a P2P ping and reports the seen pong (crates/rpc/src/handlers/network.rs).", "0.4.0", Some(network::ping);
    "addnode", SurfaceKind::Rpc, Status::ImplementedUnverified, "", CORE_VERSION, "", "0.4.0", Some(network::addnode);
    "disconnectnode", SurfaceKind::Rpc, Status::ImplementedUnverified, "", CORE_VERSION, "", "0.4.0", Some(network::disconnectnode);
    "getconnectioncount", SurfaceKind::Rpc, Status::ImplementedUnverified, "", CORE_VERSION, "", "0.4.0", Some(network::getconnectioncount);
    "getnettotals", SurfaceKind::Rpc, Status::ImplementedUnverified, "", CORE_VERSION, "", "0.4.0", Some(network::getnettotals);
    "getaddednodeinfo", SurfaceKind::Rpc, Status::ImplementedUnverified, "", CORE_VERSION, "", "0.4.0", Some(network::getaddednodeinfo);
    "listbanned", SurfaceKind::Rpc, Status::ImplementedUnverified, "", CORE_VERSION, "Pinned v22 shape; the pre-v22 ban_reason field is replaced by ban_duration and time_remaining.", "0.4.0", Some(network::listbanned);
    "setban", SurfaceKind::Rpc, Status::ImplementedUnverified, "", CORE_VERSION, "", "0.4.0", Some(network::setban);
    "clearbanned", SurfaceKind::Rpc, Status::ImplementedUnverified, "", CORE_VERSION, "", "0.4.0", Some(network::clearbanned);
    "setnetworkactive", SurfaceKind::Rpc, Status::ImplementedUnverified, "", CORE_VERSION, "", "0.4.0", Some(network::setnetworkactive);
    "getnodeaddresses", SurfaceKind::Rpc, Status::ImplementedUnverified, "", CORE_VERSION, "", "0.4.0", Some(network::getnodeaddresses);
    "getblocktemplate", SurfaceKind::Rpc, Status::ImplementedUnverified, "", CORE_VERSION, "BIP22/BIP23 template: client must advertise segwit (and signet on signet); signet_challenge on signet, capabilities proposal+longpoll, coinbaseaux.flags empty hex.", "0.4.0", Some(mining::getblocktemplate);
    "getmininginfo", SurfaceKind::Rpc, Status::Deviation, "", CORE_VERSION, "Pinned v30 shape including bits/target and next-block facts. Unset currentblocktx, currentblockweight, and signet_challenge are omitted like Core.", "0.4.0", Some(mining::getmininginfo);
    "submitblock", SurfaceKind::Rpc, Status::ImplementedUnverified, "", CORE_VERSION, "Decode failures are -22 (Block decode failed). Extra bytes after a complete block and BIP22's dummy second argument are ignored. A header already admitted by submitheader still accepts the body; a previously connected body (scripts-valid), including after a later reorg, is duplicate.", "0.4.0", Some(mining::submitblock);
    "submitheader", SurfaceKind::Rpc, Status::ImplementedUnverified, "", CORE_VERSION, "See API-13 in docs/contracts/external-api.md for submitheader behavior.", "0.4.0", Some(mining::submitheader);
    "prioritisetransaction", SurfaceKind::Rpc, Status::ImplementedUnverified, "", CORE_VERSION, "Dummy (params[1]) must be 0 or null; fee_delta is params[2]. Non-zero dummy is Core -8. Pooled dust outputs are -8 except on regtest. See API-23 in docs/contracts/external-api.md for dummy and fee_delta compatibility.", "0.4.0", Some(mining::prioritisetransaction);
    "generatetoaddress", SurfaceKind::Rpc, Status::ImplementedUnverified, "", CORE_VERSION, "Assembles, solves, and submits n blocks paying the given address through the mining coordinator. Invalid-output behavior is defined in docs/contracts/external-api.md#API-29.", "0.4.0", Some(mining::generatetoaddress);
    "generateblock", SurfaceKind::Rpc, Status::ImplementedUnverified, "", CORE_VERSION, "Assembles and solves one block paying an address or descriptor from the listed mempool txids or raw txs in that order. See the canonical contract: docs/contracts/external-api.md#API-31.", "0.4.0", Some(mining::generateblock);
    "getnetworkhashps", SurfaceKind::Rpc, Status::ImplementedUnverified, "", CORE_VERSION, "Estimated hashes/s over a caller-chosen lookback ending at a caller-chosen height; default lookback 120, height the applied tip.", "0.4.0", Some(mining::getnetworkhashps);
    "getprioritisedtransactions", SurfaceKind::Rpc, Status::ImplementedUnverified, "", CORE_VERSION, "Projects the mempool's signed fee-delta overlay, including txids not currently pooled. See docs/contracts/external-api.md#API-28 for modified_fee units.", "0.4.0", Some(mining::getprioritisedtransactions);

    // -- JSON-RPC: bitcoin-rs extension ------------------------------
    "getcapabilities", SurfaceKind::Rpc, Status::Extension, "", CORE_VERSION, "bitcoin-rs reporting of compiled/enabled concrete service capabilities and index lifecycle state (crates/rpc/src/handlers/chain.rs, crates/index/src/capabilities.rs).", "0.4.0", Some(chain::getcapabilities);

    // -- JSON-RPC: additional Core blockchain/control surfaces ------
    "dumptxoutset", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "UTXO snapshot dump not implemented.", "n/a", None;
    "getblockfilter", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "BIP157/158 compact block filters and the filter index are not implemented.", "n/a", None;
    "getblockfrompeer", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "No on-demand block fetch from peers.", "n/a", None;
    "getchainstates", SurfaceKind::Rpc, Status::Deviation, "", CORE_VERSION, "Reports coherent active/historical lifecycle with transaction-based progress; omits Core cache/difficulty fields and unavailable progress. Returns -32603 instead of waiting when lifecycle work is busy; ordinary chain-transition reads may still wait. Historical role precedes active. See API-33, crates/node/src/snapshot.rs and crates/rpc/src/handlers/chain.rs.", "0.12.0", Some(chain::getchainstates);
    "getdeploymentinfo", SurfaceKind::Rpc, Status::Deviation, "", CORE_VERSION, "Reports actual native activation: CSV/Segwit use historical BIP9 on mainnet/testnet3; Taproot is height-based and testdummy is absent. Native regtest heights and historical script flags differ from Core 31.1; off-header-chain queries have a 2,000,000-ancestor budget. See docs/contracts/external-api.md#native-deployment-reporting.", "0.12.0", Some(deployment::getdeploymentinfo);
    "getdescriptoractivity", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "No wallet/scan index to serve it.", "n/a", None;
    "getmempoolcluster", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "Cluster mempool tracking not implemented.", "n/a", None;
    "importmempool", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "Mempool import not implemented.", "n/a", None;
    "loadtxoutset", SurfaceKind::Rpc, Status::Deviation, "", CORE_VERSION, "Imports bounded Core v2 files against compiled network pins through node-owned fenced activation; refuses a nonempty mempool or an invalid/off-best-chain base. Malformed input returns -22. See API-33, crates/node/src/snapshot.rs and crates/rpc/src/handlers/chain.rs. dumptxoutset export remains unimplemented.", "0.12.0", Some(chain::loadtxoutset);
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
    "submitpackage", SurfaceKind::Rpc, Status::Unimplemented, "", CORE_VERSION, "Aggregate CPFP and package RBF submission are intentionally unsupported; multi-row testmempoolaccept implements Core PackageTestAccept. See docs/policies/mempool-policy.md.", "n/a", None;
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
    "/rest/tx/", SurfaceKind::Rest, Status::ImplementedUnverified, "", CORE_VERSION, "", "0.4.0", None;
    "/rest/block/notxdetails/", SurfaceKind::Rest, Status::ImplementedUnverified, "", CORE_VERSION, "", "0.4.0", None;
    "/rest/block/", SurfaceKind::Rest, Status::ImplementedUnverified, "", CORE_VERSION, "", "0.4.0", None;
    "/rest/blockpart/", SurfaceKind::Rest, Status::ImplementedUnverified, "", CORE_VERSION, "bin/hex only; JSON rejected, matching Core's /rest/blockpart (bitcoin-core/src/rest.cpp rest_block_part).", "0.4.0", None;
    "/rest/chaininfo", SurfaceKind::Rest, Status::ImplementedUnverified, "", CORE_VERSION, "", "0.4.0", None;
    "/rest/mempool/", SurfaceKind::Rest, Status::ImplementedUnverified, "", CORE_VERSION, "", "0.4.0", None;
    "/rest/headers/", SurfaceKind::Rest, Status::Deviation, "", CORE_VERSION, "Unknown but well-formed block hashes answer an empty 200 rather than 404; query parameters other than count are ignored (crates/rpc/src/rest.rs).", "0.4.0", None;
    "/rest/getutxos", SurfaceKind::Rest, Status::Deviation, "", CORE_VERSION, "GET and bounded canonical binary/hex POST share UTXO and mempool lookup. Intentionally corrects Core 31.1 POST string-length-prefix decoding; rejects mixed inputs, JSON bodies and trailing data. POST limit: 2048 bytes, 15 outpoints.", "0.4.0", None;
    "/rest/deploymentinfo/", SurfaceKind::Rest, Status::Deviation, "", CORE_VERSION, "Reports actual native activation: CSV/Segwit use historical BIP9 on mainnet/testnet3; Taproot is height-based and testdummy is absent. Native regtest heights and historical script flags differ from Core 31.1; off-header-chain queries have a 2,000,000-ancestor budget. See docs/contracts/external-api.md#native-deployment-reporting.", "0.4.0", None;
    "/rest/deploymentinfo", SurfaceKind::Rest, Status::Deviation, "", CORE_VERSION, "Reports actual native activation: CSV/Segwit use historical BIP9 on mainnet/testnet3; Taproot is height-based and testdummy is absent. Native regtest heights and historical script flags differ from Core 31.1; off-header-chain queries have a 2,000,000-ancestor budget. See docs/contracts/external-api.md#native-deployment-reporting.", "0.4.0", None;
    "/rest/blockhashbyheight/", SurfaceKind::Rest, Status::ImplementedUnverified, "", CORE_VERSION, "", "0.4.0", None;
    "/rest/spenttxouts/", SurfaceKind::Rest, Status::Deviation, "", CORE_VERSION, "Always answers undo-unavailable: undo data is not persisted (crates/rpc/src/rest.rs).", "0.4.0", None;
    "esplora/*", SurfaceKind::Rest, Status::Extension, "", CORE_VERSION, "Esplora-compatible indexer HTTP surface at /api on the JSON-RPC listener (crates/rpc/src/esplora.rs, docs/contracts/wallet-facing.md).", "0.4.0", None;

    // -- ZMQ topics --------------------------------------------------
    "hashblock", SurfaceKind::Zmq, Status::ImplementedUnverified, "zmq", CORE_VERSION, "Requires the zmq feature and a --zmqpubhashblock endpoint.", "0.4.0", None;
    "hashtx", SurfaceKind::Zmq, Status::ImplementedUnverified, "zmq", CORE_VERSION, "Requires the zmq feature and a --zmqpubhashtx endpoint.", "0.4.0", None;
    "rawblock", SurfaceKind::Zmq, Status::ImplementedUnverified, "zmq", CORE_VERSION, "Requires the zmq feature and a --zmqpubrawblock endpoint.", "0.4.0", None;
    "rawtx", SurfaceKind::Zmq, Status::ImplementedUnverified, "zmq", CORE_VERSION, "Requires the zmq feature and a --zmqpubrawtx endpoint.", "0.4.0", None;
    "sequence", SurfaceKind::Zmq, Status::ImplementedUnverified, "zmq", CORE_VERSION, "Requires the zmq feature and a --zmqpubsequence endpoint. Publishes C/D block events and A/R mempool events; A/R carry reversed txid, the label byte, and the mempool sequence as u64 LE (crates/rpc/src/zmq.rs).", "0.4.0", None;
}
