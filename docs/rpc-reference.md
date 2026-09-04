# External API Compatibility Reference

<!-- GENERATED FILE - do not edit by hand.
     Source of truth: MANIFEST in crates/rpc/src/manifest.rs.
     Regenerate: REGEN_RPC_REFERENCE=1 cargo test -p bitcoin-rs-rpc --test manifest_coverage -- --ignored regenerate_reference
     The generated_reference_matches_checked_in test fails when this file drifts. -->

Surface contract of bitcoin-rs against Bitcoin Core 31.x.

- **Implemented** - shipped and shape-compatible with the Core contract.
- **Deviation** - shipped with a recorded difference from Core; notes cite the source file.
- **Extension** - bitcoin-rs-specific surface with no Core counterpart.
- **Unimplemented** - Core surface this node does not expose: JSON-RPC answers `method not found`, REST answers 404.

`since` is the bitcoin-rs version whose surface a row describes; `pending` marks a row whose implementation lands in a later change. Rows naming a cargo feature exist only when that feature is compiled.

Unimplemented-set derivation: audited against the Bitcoin Core v31.0 source command tables (src/rpc/*.cpp, src/wallet/rpc/*.cpp, src/rest.cpp StartREST, src/zmq/zmqpublishnotifier.cpp) - the same registrations Core's `help` output prints. Hidden test/administration commands are intentionally absent.

## JSON-RPC methods

### Implemented

| surface | since | notes |
|---|---|---|
| `getblockchaininfo` | 0.4.0 |  |
| `getdifficulty` | 0.4.0 |  |
| `getchaintips` | 0.4.0 |  |
| `getchaintxstats` | 0.4.0 |  |
| `getblockcount` | 0.4.0 |  |
| `getblockhash` | 0.4.0 |  |
| `getbestblockhash` | 0.4.0 |  |
| `getblock` | 0.4.0 | Response is the pinned corepc v31 verbose contract; verbosity 3 serves the verbosity-2 shape (no prevout source). |
| `getblockheader` | 0.4.0 |  |
| `getblockstats` | 0.4.0 |  |
| `verifychain` | 0.4.0 |  |
| `gettxoutsetinfo` | 0.4.0 |  |
| `getindexinfo` | 0.4.0 |  |
| `pruneblockchain` | 0.4.0 |  |
| `invalidateblock` | 0.4.0 |  |
| `getrawtransaction` | 0.4.0 |  |
| `gettxout` | 0.4.0 |  |
| `gettxoutproof` | 0.4.0 |  |
| `verifytxoutproof` | 0.4.0 |  |
| `sendrawtransaction` | 0.4.0 |  |
| `testmempoolaccept` | 0.4.0 |  |
| `decoderawtransaction` | 0.4.0 |  |
| `createrawtransaction` | 0.4.0 |  |
| `combinepsbt` | 0.4.0 |  |
| `finalizepsbt` | 0.4.0 |  |
| `getmempoolentry` | 0.4.0 |  |
| `getrawmempool` | 0.4.0 |  |
| `getmempoolancestors` | 0.4.0 |  |
| `getmempooldescendants` | 0.4.0 |  |
| `uptime` | 0.4.0 |  |
| `getrpcinfo` | 0.4.0 |  |
| `getzmqnotifications` | 0.4.0 | Requires the zmq feature and --enablezmq* startup flags. |
| `validateaddress` | 0.4.0 | local_shape (invalid branch): a malformed or wrong-network address is hand-built as Core's sparse {isvalid:false} object because corepc-types models the valid-only fields (address, scriptPubKey, isscript, iswitness) as required and cannot represent that wire shape; valid addresses round-trip the typed v31 contract (crates/rpc/src/handlers/util.rs). |
| `getdescriptorinfo` | 0.4.0 |  |
| `deriveaddresses` | 0.4.0 |  |
| `getnetworkinfo` | 0.4.0 |  |
| `getpeerinfo` | 0.4.0 | Pinned v31 shape; telemetry this node does not measure (byte counters, pingwait, addr relay stats) reports Core's zero-value defaults. |
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
| `getblocktemplate` | 0.4.0 | Pinned v17 template contract; BIP23 submitold/workid extras are not emitted. |
| `getmininginfo` | 0.4.0 | Pinned v30 shape including bits/target and next-block facts derived from the mining coordinator. |
| `submitblock` | 0.4.0 |  |
| `prioritisetransaction` | 0.4.0 |  |

### Deviation

| surface | since | notes |
|---|---|---|
| `scantxoutset` | 0.4.0 | Accepts only addr() scan descriptors; Core supports the full descriptor set (crates/rpc/src/handlers/chain.rs). Response uses the v28 scan contract; the status action answers null. |
| `getmempoolinfo` | 0.4.0 | Policy fields project the enforced MempoolPolicySnapshot (crates/mempool/src/policy.rs): fullrbf always reports the enforced BIP125 signaling requirement (false) where Core 31.1 emits the field only under -deprecatedrpc=fullrbf; limitclustercount and limitclustersize project the enforced ancestor-package bounds because cluster tracking is not implemented (see getmempoolcluster); optimal is always true because the fee-rate index is rewritten under the pool write lock (crates/rpc/src/handlers/mempool.rs). |
| `estimatesmartfee` | 0.4.0 | No estimate_mode handling: Core parses the mode string and rejects unknown values with -8; conf_target is not range-checked against Core's 1-1008 (crates/rpc/src/handlers/util.rs). |
| `getmemoryinfo` | 0.4.0 | mode=mallocinfo is rejected with an invalid-parameter error instead of returning allocator XML (crates/rpc/src/handlers/util.rs). |
| `estimaterawfee` | 0.4.0 | local_shape: the fee estimator does not expose Core decay/scale/pass/fail internals, so horizon objects carry feerate only and the no-estimate branch stays {} (crates/rpc/src/handlers/util.rs). |
| `ping` | 0.4.0 | Answers immediately; Core schedules a P2P ping and reports the seen pong (crates/rpc/src/handlers/network.rs). |

### Extension

| surface | since | notes |
|---|---|---|
| `getcapabilities` | 0.4.0 | bitcoin-rs reporting of compiled/enabled concrete service capabilities and index lifecycle state (crates/rpc/src/handlers/chain.rs, crates/node/src/capabilities.rs). |

### Unimplemented

| surface | since | notes |
|---|---|---|
| `dumptxoutset` | n/a | UTXO snapshot dump not implemented. |
| `getblockfrompeer` | n/a | No on-demand block fetch from peers. |
| `getchainstates` | n/a | Not implemented. |
| `getdeploymentinfo` | n/a | Not implemented over JSON-RPC (the REST /rest/deploymentinfo route exists). |
| `getdescriptoractivity` | n/a | No wallet/scan index to serve it. |
| `getmempoolcluster` | n/a | Cluster mempool tracking not implemented. |
| `gettxspendingprevout` | n/a | Not implemented. |
| `importmempool` | n/a | Mempool import not implemented. |
| `loadtxoutset` | n/a | UTXO snapshot load (assumeutxo) not implemented. |
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
| `getnetworkhashps` | n/a | Network hash-rate estimate not implemented. |
| `getprioritisedtransactions` | n/a | Prioritisation map not queryable yet. |
| `submitheader` | n/a | Header-only submission not implemented. |
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
| `submitpackage` | n/a | Package acceptance not implemented. |
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

### Implemented

| surface | since | notes |
|---|---|---|
| `/rest/tx/` | 0.4.0 |  |
| `/rest/block/notxdetails/` | 0.4.0 |  |
| `/rest/block/` | 0.4.0 |  |
| `/rest/blockpart/` | 0.4.0 | bin/hex only; JSON rejected as in Core's original part endpoint. |
| `/rest/chaininfo` | 0.4.0 |  |
| `/rest/mempool/` | 0.4.0 |  |
| `/rest/headers/` | 0.4.0 |  |
| `/rest/deploymentinfo/` | 0.4.0 |  |
| `/rest/deploymentinfo` | 0.4.0 |  |
| `/rest/blockhashbyheight/` | 0.4.0 |  |

### Deviation

| surface | since | notes |
|---|---|---|
| `/rest/getutxos` | 0.4.0 | URI-scheme input only; Core also accepts a POST raw-transaction body (crates/rpc/src/rest.rs). |
| `/rest/spenttxouts/` | 0.4.0 | Always answers undo-unavailable: undo data is not persisted (crates/rpc/src/rest.rs). |

### Extension

| surface | since | notes |
|---|---|---|
| `esplora/*` | 0.4.0 | Esplora-compatible indexer HTTP surface, a separate non-Core contract (crates/rpc/src/esplora.rs, docs/rest-interface.md). |

## ZMQ topics

### Implemented

| surface | since | notes |
|---|---|---|
| `hashblock` | 0.4.0 | Requires the zmq feature and a --zmqpubhashblock endpoint. |
| `hashtx` | 0.4.0 | Requires the zmq feature and a --zmqpubhashtx endpoint. |
| `rawblock` | 0.4.0 | Requires the zmq feature and a --zmqpubrawblock endpoint. |
| `rawtx` | 0.4.0 | Requires the zmq feature and a --zmqpubrawtx endpoint. |
| `sequence` | 0.4.0 | Requires the zmq feature and a --zmqpubsequence endpoint. Publishes C/D block events and A/R mempool events; A/R carry reversed txid, the label byte, and the mempool sequence as u64 LE (crates/node/src/zmq_publisher.rs). |

Row counts: Implemented 66, Deviation 8, Extension 2, Unimplemented 96 - total 172.
