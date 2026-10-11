# External API Compatibility Reference

<!-- GENERATED FILE - do not edit by hand.
     Source of truth: REGISTRY in crates/rpc/src/registry.rs.
     Regenerate: REGEN_RPC_REFERENCE=1 cargo test -p bitcoin-rs-rpc --test manifest_coverage -- --ignored regenerate_reference
     The generated_reference_matches_checked_in test fails when this file drifts. -->

Surface contract of bitcoin-rs against Bitcoin Core 31.x.

- **Supported** - differentially verified against the pinned Bitcoin Core reference; requires `reference.differential_harness` in `crates/rpc/core-compat.toml`.
- **Deviation** - shipped with a recorded difference from Core; notes cite the source file.
- **Implemented (unverified)** - shipped; not compared against the pinned reference.
- **Extension** - bitcoin-rs-specific surface with no Core counterpart.
- **Disabled** - reserved for parameter-level refusal with a stable error.
- **Unimplemented** - Core surface this node does not expose: JSON-RPC answers `method not found`, REST answers 404.

`since` is the bitcoin-rs version whose surface a row describes; `pending` marks a row whose implementation lands in a later change. Rows naming a cargo feature exist only when that feature is compiled.

Unimplemented-set derivation: audited against the Bitcoin Core v31.0 source command tables (src/rpc/*.cpp, src/wallet/rpc/*.cpp, src/rest.cpp StartREST, src/zmq/zmqpublishnotifier.cpp) - the same registrations Core's `help` output prints. Hidden test/administration commands are intentionally absent.

## JSON-RPC methods

### Deviation

| surface | since | notes |
|---|---|---|
| `getblockchaininfo` | 0.4.0 | Unavailable optional fields are omitted. Pruning mode/target and signet challenge are not reported (automatic_pruning, prune_target_size, signet_challenge); pruneheight reflects the backing prune service (crates/rpc/src/handlers/chain.rs). |
| `getblock` | 0.4.0 | Response is the pinned corepc v31 verbose contract; verbosity 3 serves the verbosity-2 shape because no prevout source exists — Core returns prevouts at verbosity 3 (crates/rpc/src/handlers/chain.rs). |
| `verifychain` | 0.4.0 | Levels 3 and 4 omit Core's block disconnect and reconnect checks; level 3 behaves as level 2 and level 4 does not replay the UTXO set (crates/rpc/src/handlers/chain.rs). |
| `scantxoutset` | 0.4.0 | Accepts only addr() scan descriptors; Core supports the full descriptor set (crates/rpc/src/handlers/chain.rs). Response uses the v28 scan contract; the status action answers null. |
| `sendrawtransaction` | 0.4.0 | Core 31.1 replacement, modified-fee, cluster and TRUC cases are process-verified in overhaul_process_harness::policy_cases. Exact optimal graph ordering does not emulate Core transient SFL work-budget states. Capacity/floor accounting and generic consensus error details retain the differences in docs/policies/mempool-policy.md; aggregate package submission is unsupported. |
| `testmempoolaccept` | 0.4.0 | Single preview shares committed admission verification. Core 31.1 package shape, dependency, fail-fast and replacement-disallowed cases are process-verified in overhaul_process_harness::policy_cases. Exact graph ordering, capacity/floor behavior and generic error details retain the differences in docs/policies/mempool-policy.md. Aggregate package submission is unsupported. |
| `createrawtransaction` | 0.4.0 | Accepts inputs, outputs, locktime and replaceable only. Version is fixed at 2 and replaceable defaults to false. Named version is rejected with -8; a fifth positional or args-prefix entry is rejected with -32602 after named binding. See docs/contracts/external-api.md#api-02-json-rpc-mechanics-and-the-wallet-free-surface. |
| `getmempoolinfo` | 0.4.0 | Policy fields project the enforced MempoolPolicySnapshot: fullrbf is true and cluster bounds are enforced. optimal is always true for exact graph ordering rather than Core background SFL state. usage estimates local structures; maxmempool bounds virtual size rather than allocator usage. The pressure floor is a local heuristic, not Core rolling decay. See docs/policies/mempool-policy.md. |
| `gettxspendingprevout` | 0.11.0 | Mempool lookup and options follow Core 31.1 without txospenderindex. After named binding, missing outputs and excess positional arguments use local -32602 shape errors. Core uses -1 help for no arguments/excess arity but -3 for an outputs hole created by named options; explicit null matches Core -3. Name and collision errors retain Core precedence. See docs/contracts/external-api.md#api-32-gettxspendingprevout-mempool-snapshot. |
| `estimatesmartfee` | 0.4.0 | See docs/contracts/external-api.md#API-26 for conf_target and estimate_mode validation. The estimate comes from this node's mempool confirmation-history estimator with a 25-block horizon; estimate_mode is accepted and ignored (no ECONOMICAL/CONSERVATIVE split), and insufficient history returns an `errors` array (crates/rpc/src/handlers/util.rs). |
| `getrpcinfo` | 0.4.0 | active_commands is always an empty array; this node does not track in-flight RPC calls. logpath reports the configured debug log path (crates/rpc/src/handlers/util.rs). |
| `getmemoryinfo` | 0.4.0 | mode=mallocinfo is rejected with an invalid-parameter error instead of returning allocator XML (crates/rpc/src/handlers/util.rs). The figures are resident set size read from the OS, not Core's locked-pool allocator accounting. |
| `estimaterawfee` | 0.4.0 | local_shape: the fee estimator does not expose Core decay/scale/pass/fail internals, so horizon objects carry feerate only and the no-estimate branch stays {} (crates/rpc/src/handlers/util.rs). All three horizons carry the same feerate where Core computes three independent estimates. |
| `validateaddress` | 0.4.0 | local_shape (invalid branch): a malformed or wrong-network address is hand-built as Core's sparse {isvalid:false} object because corepc-types models the valid-only fields (address, scriptPubKey, isscript, iswitness) as required and cannot represent that wire shape; valid addresses round-trip the typed v31 contract (crates/rpc/src/handlers/util.rs). |
| `getpeerinfo` | 0.4.0 | Pinned v31 shape; aggregate byte totals, negotiated transaction-relay preference, and received minimum_fee_filter are measured, while per-message byte breakdowns report empty maps and last_transaction/last_block/last_inv_sequence report Core's zero-value defaults; unmeasured telemetry (ping times, addr relay stats, starting_height, address_local, mapped_as) is null-omitted (crates/rpc/src/handlers/network.rs). |
| `ping` | 0.4.0 | Answers immediately; Core schedules a P2P ping and reports the seen pong (crates/rpc/src/handlers/network.rs). |
| `getmininginfo` | 0.4.0 | Pinned v30 shape including bits/target and next-block facts. Unset currentblocktx, currentblockweight, and signet_challenge are omitted like Core. |
| `getchainstates` | 0.12.0 | Reports coherent active/historical lifecycle with transaction-based progress; omits Core cache/difficulty fields and unavailable progress. Returns -32603 instead of waiting when lifecycle work is busy; ordinary chain-transition reads may still wait. Historical role precedes active. See API-33, crates/node/src/snapshot.rs and crates/rpc/src/handlers/chain.rs. |
| `getdeploymentinfo` | 0.12.0 | Reports actual native activation: CSV/Segwit use historical BIP9 on mainnet/testnet3; Taproot is height-based and testdummy is absent. Native regtest heights and historical script flags differ from Core 31.1; off-header-chain queries have a 2,000,000-ancestor budget. See docs/contracts/external-api.md#native-deployment-reporting. |
| `loadtxoutset` | 0.12.0 | Imports bounded Core v2 files against compiled network pins through node-owned fenced activation; refuses a nonempty mempool or an invalid/off-best-chain base. Malformed input returns -22. See API-33, crates/node/src/snapshot.rs and crates/rpc/src/handlers/chain.rs. dumptxoutset export remains unimplemented. |

### Implemented (unverified)

| surface | since | notes |
|---|---|---|
| `getdifficulty` | 0.4.0 |  |
| `getchaintips` | 0.4.0 |  |
| `getchaintxstats` | 0.4.0 |  |
| `getblockcount` | 0.4.0 |  |
| `getblockhash` | 0.4.0 |  |
| `getbestblockhash` | 0.4.0 |  |
| `getblockheader` | 0.4.0 |  |
| `getblockstats` | 0.4.0 |  |
| `gettxoutsetinfo` | 0.4.0 |  |
| `getindexinfo` | 0.4.0 |  |
| `pruneblockchain` | 0.4.0 |  |
| `invalidateblock` | 0.4.0 |  |
| `getrawtransaction` | 0.4.0 |  |
| `gettxout` | 0.4.0 |  |
| `gettxoutproof` | 0.4.0 |  |
| `verifytxoutproof` | 0.4.0 |  |
| `decoderawtransaction` | 0.4.0 |  |
| `combinepsbt` | 0.4.0 |  |
| `finalizepsbt` | 0.4.0 |  |
| `getmempoolentry` | 0.4.0 |  |
| `getrawmempool` | 0.4.0 |  |
| `getmempoolancestors` | 0.4.0 |  |
| `getmempooldescendants` | 0.4.0 |  |
| `uptime` | 0.4.0 |  |
| `getzmqnotifications` | 0.4.0 | Requires the zmq feature and --enablezmq* startup flags. |
| `getdescriptorinfo` | 0.4.0 |  |
| `deriveaddresses` | 0.4.0 |  |
| `getnetworkinfo` | 0.4.0 |  |
| `addnode` | 0.4.0 |  |
| `disconnectnode` | 0.4.0 |  |
| `getconnectioncount` | 0.4.0 |  |
| `getnettotals` | 0.4.0 |  |
| `getaddednodeinfo` | 0.4.0 |  |
| `listbanned` | 0.4.0 | Pinned v22 shape; the pre-v22 ban_reason field is replaced by ban_duration and time_remaining. |
| `setban` | 0.4.0 |  |
| `clearbanned` | 0.4.0 |  |
| `setnetworkactive` | 0.4.0 |  |
| `getnodeaddresses` | 0.4.0 |  |
| `getblocktemplate` | 0.4.0 | BIP22/BIP23 template: client must advertise segwit (and signet on signet); signet_challenge on signet, capabilities proposal+longpoll, coinbaseaux.flags empty hex. |
| `submitblock` | 0.4.0 | Decode failures are -22 (Block decode failed). Extra bytes after a complete block and BIP22's dummy second argument are ignored. A header already admitted by submitheader still accepts the body; a previously connected body (scripts-valid), including after a later reorg, is duplicate. |
| `submitheader` | 0.4.0 | See API-13 in docs/contracts/external-api.md for submitheader behavior. |
| `prioritisetransaction` | 0.4.0 | Dummy (params[1]) must be 0 or null; fee_delta is params[2]. Non-zero dummy is Core -8. Pooled dust outputs are -8 except on regtest. See API-23 in docs/contracts/external-api.md for dummy and fee_delta compatibility. |
| `generatetoaddress` | 0.4.0 | Assembles, solves, and submits n blocks paying the given address through the mining coordinator. Invalid-output behavior is defined in docs/contracts/external-api.md#API-29. |
| `generateblock` | 0.4.0 | Assembles and solves one block paying an address or descriptor from the listed mempool txids or raw txs in that order. See the canonical contract: docs/contracts/external-api.md#API-31. |
| `getnetworkhashps` | 0.4.0 | Estimated hashes/s over a caller-chosen lookback ending at a caller-chosen height; default lookback 120, height the applied tip. |
| `getprioritisedtransactions` | 0.4.0 | Projects the mempool's signed fee-delta overlay, including txids not currently pooled. See docs/contracts/external-api.md#API-28 for modified_fee units. |

### Extension

| surface | since | notes |
|---|---|---|
| `getcapabilities` | 0.4.0 | bitcoin-rs reporting of compiled/enabled concrete service capabilities and index lifecycle state (crates/rpc/src/handlers/chain.rs, crates/index/src/capabilities.rs). |

### Unimplemented

| surface | since | notes |
|---|---|---|
| `dumptxoutset` | n/a | UTXO snapshot dump not implemented. |
| `getblockfilter` | n/a | BIP157/158 compact block filters and the filter index are not implemented. |
| `getblockfrompeer` | n/a | No on-demand block fetch from peers. |
| `getdescriptoractivity` | n/a | No wallet/scan index to serve it. |
| `getmempoolcluster` | n/a | Cluster mempool tracking not implemented. |
| `importmempool` | n/a | Mempool import not implemented. |
| `preciousblock` | n/a | No manual block-preference surface. |
| `reconsiderblock` | n/a | No manual reorg-control surface. |
| `savemempool` | n/a | Mempool dump/reload persistence not implemented. |
| `scanblocks` | n/a | No BIP157/158 filter index to scan. |
| `waitforblock` | n/a | No long-poll wait surface. |
| `waitforblockheight` | n/a | No long-poll wait surface. |
| `waitfornewblock` | n/a | No long-poll wait surface. |
| `help` | n/a | No per-method help text renderer. |
| `logging` | n/a | Log-category controls not exposed over RPC. |
| `stop` | n/a | Lifecycle control not exposed over RPC. |
| `getaddrmaninfo` | n/a | Addrman table stats not exposed. |
| `abortprivatebroadcast` | n/a | Private-broadcast store not implemented. |
| `analyzepsbt` | n/a | PSBT analysis not implemented (combine/finalize only). |
| `combinerawtransaction` | n/a | Raw-transaction combination not implemented. |
| `converttopsbt` | n/a | PSBT creation not implemented. |
| `createpsbt` | n/a | PSBT creation not implemented. |
| `decodepsbt` | n/a | PSBT analysis not implemented (combine/finalize only). |
| `decodescript` | n/a | Script decode helper not implemented. |
| `descriptorprocesspsbt` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `fundrawtransaction` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `getprivatebroadcastinfo` | n/a | Private-broadcast store not implemented. |
| `joinpsbts` | n/a | PSBT merge not implemented (combine/finalize only). |
| `signrawtransactionwithkey` | n/a | Signing requires key material this process never holds. |
| `submitpackage` | n/a | Aggregate CPFP and package RBF submission are intentionally unsupported; multi-row testmempoolaccept implements Core PackageTestAccept. See docs/policies/mempool-policy.md. |
| `utxoupdatepsbt` | n/a | PSBT update from the UTXO set not implemented. |
| `enumeratesigners` | n/a | No external signer support. |
| `createmultisig` | n/a | No key material (policy). |
| `signmessagewithprivkey` | n/a | Signing requires key material this process never holds. |
| `verifymessage` | n/a | Message-signature verification not implemented. |
| `abandontransaction` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `abortrescan` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `backupwallet` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `bumpfee` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `createwallet` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `createwalletdescriptor` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `encryptwallet` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `getaddressesbylabel` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `getaddressinfo` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `getbalance` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `getbalances` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `gethdkeys` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `getnewaddress` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `getrawchangeaddress` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `getreceivedbyaddress` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `getreceivedbylabel` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `gettransaction` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `getwalletinfo` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `importdescriptors` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `importprunedfunds` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `keypoolrefill` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `listaddressgroupings` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `listdescriptors` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `listlabels` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `listlockunspent` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `listreceivedbyaddress` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `listreceivedbylabel` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `listsinceblock` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `listtransactions` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `listunspent` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `listwalletdir` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `listwallets` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `loadwallet` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `lockunspent` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `migratewallet` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `psbtbumpfee` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `removeprunedfunds` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `rescanblockchain` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `restorewallet` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `send` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `sendall` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `sendmany` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `sendtoaddress` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `setlabel` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `setwalletflag` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `signmessage` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `signrawtransactionwithwallet` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `simulaterawtransaction` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `unloadwallet` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `walletcreatefundedpsbt` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `walletdisplayaddress` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `walletlock` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `walletpassphrase` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `walletpassphrasechange` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |
| `walletprocesspsbt` | n/a | No wallet: this process holds no private-key material (crates/rpc/src/lib.rs). |

## REST endpoints

### Deviation

| surface | since | notes |
|---|---|---|
| `/rest/headers/` | 0.4.0 | Unknown but well-formed block hashes answer an empty 200 rather than 404; query parameters other than count are ignored (crates/rpc/src/rest.rs). |
| `/rest/getutxos` | 0.4.0 | GET and bounded canonical binary/hex POST share UTXO and mempool lookup. Intentionally corrects Core 31.1 POST string-length-prefix decoding; rejects mixed inputs, JSON bodies and trailing data. POST limit: 2048 bytes, 15 outpoints. |
| `/rest/deploymentinfo/` | 0.4.0 | Reports actual native activation: CSV/Segwit use historical BIP9 on mainnet/testnet3; Taproot is height-based and testdummy is absent. Native regtest heights and historical script flags differ from Core 31.1; off-header-chain queries have a 2,000,000-ancestor budget. See docs/contracts/external-api.md#native-deployment-reporting. |
| `/rest/deploymentinfo` | 0.4.0 | Reports actual native activation: CSV/Segwit use historical BIP9 on mainnet/testnet3; Taproot is height-based and testdummy is absent. Native regtest heights and historical script flags differ from Core 31.1; off-header-chain queries have a 2,000,000-ancestor budget. See docs/contracts/external-api.md#native-deployment-reporting. |
| `/rest/spenttxouts/` | 0.4.0 | Always answers undo-unavailable: undo data is not persisted (crates/rpc/src/rest.rs). |

### Implemented (unverified)

| surface | since | notes |
|---|---|---|
| `/rest/tx/` | 0.4.0 |  |
| `/rest/block/notxdetails/` | 0.4.0 |  |
| `/rest/block/` | 0.4.0 |  |
| `/rest/blockpart/` | 0.4.0 | bin/hex only; JSON rejected, matching Core's /rest/blockpart (bitcoin-core/src/rest.cpp rest_block_part). |
| `/rest/chaininfo` | 0.4.0 |  |
| `/rest/mempool/` | 0.4.0 |  |
| `/rest/blockhashbyheight/` | 0.4.0 |  |

### Extension

| surface | since | notes |
|---|---|---|
| `esplora/*` | 0.4.0 | Esplora-compatible indexer HTTP surface at /api on the JSON-RPC listener (crates/rpc/src/esplora.rs, docs/contracts/wallet-facing.md). |

## ZMQ topics

### Implemented (unverified)

| surface | since | notes |
|---|---|---|
| `hashblock` | 0.4.0 | Requires the zmq feature and a --zmqpubhashblock endpoint. |
| `hashtx` | 0.4.0 | Requires the zmq feature and a --zmqpubhashtx endpoint. |
| `rawblock` | 0.4.0 | Requires the zmq feature and a --zmqpubrawblock endpoint. |
| `rawtx` | 0.4.0 | Requires the zmq feature and a --zmqpubrawtx endpoint. |
| `sequence` | 0.4.0 | Requires the zmq feature and a --zmqpubsequence endpoint. Publishes C/D block events and A/R mempool events; A/R carry reversed txid, the label byte, and the mempool sequence as u64 LE (crates/rpc/src/zmq.rs). |

Row counts: Supported 0, Deviation 25, Implemented (unverified) 58, Extension 2, Disabled 0, Unimplemented 90 - total 175.
