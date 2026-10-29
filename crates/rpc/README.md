# bitcoin-rs-rpc

The synchronous, Bitcoin Core-compatible JSON-RPC and REST surface: method dispatch, HTTP Basic and cookie authentication, and a wallet-free method surface. Every RPC that would require private key material is absent.

`RpcServer::bind` binds a TCP listener and `serve_with_shutdown` runs the blocking accept loop under a shared shutdown flag, handing each connection to a bounded worker thread with a per-connection idle timeout. Sockets go through `prepare_http_socket` (`TCP_NODELAY`); JSON and REST responses emit headers plus bodies through one vectored write. Each request is authenticated by `Auth`, then matched by `Handler::dispatch`, which reads shared node state through the injected `Context`: `ChainControl` consensus operations, `PruneService`, `DerivedIndexQuery`, `NetworkHandles` (peer table, P2P service control, local services), and the live `ZmqPublisher`. Failures map to JSON-RPC codes through `RpcError`. Core-compatible REST endpoints (`rest`) are served on the same listener when enabled. RPCs that would reveal, import, create, or use private keys are unimplemented and answer `method not found`; PSBT combination and finalization stay available because external signers drive them without this process holding key material.

## Capability boundary

`ContextHandles` groups node-owned handles by capability (`chain`, `mempool`, `indexes`, `network`, `mining`); `Context::from_handles` is the single composition point. RPC consumes capabilities through these groups, never names a storage backend or engine type, and the crate exposes no backend cargo feature (`g17_dependency_direction` proves both from `cargo metadata`).

## Interface architecture and implementation guidance

### 1. Protocol demuxing and authentication

- Private free function `classify` (`crates/rpc/src/server.rs`) is the listener directory table. `serve_connection` dispatches that table before authentication. The wallet-facing Esplora routing contract is [`WF-02`](../../docs/contracts/wallet-facing.md#wf-02-operations-a-wallet-actually-issues). The parser preserves HTTP framing while letting valid unsupported methods reach the demux for a 404:
  - `GET /rest/*` goes to Core REST (`rest::route`).
  - `GET` or `POST` under `/api` or `/esplora` goes to Esplora. `classify` strips the directory prefix and passes `Surface` plus the rest; `esplora::route` / `route_post` dispatch only inside that directory. Unknown paths 404 and never become JSON-RPC. `/api` is public electrs; `/esplora` is the mempool-backend superset. Wallet broadcast is `POST /api/tx`.
  - Other `POST` goes to JSON-RPC. `Auth::validate_header` (`crates/rpc/src/auth.rs`) guards this path only.
  - Any other method, or GET outside `/rest/`, `/api`, `/esplora`, 404s at the demux. Unprefixed electrs paths and `HEAD`/`PUT`/`DELETE` enter neither Esplora nor JSON-RPC. The parser accepts those methods so `classify` can 404 them instead of answering JSON-RPC 400.
- `JsonRpcVersion` (`crates/rpc/src/server.rs`) governs wire framing:
  - `"jsonrpc": "2.0"` requests use JSON-RPC 2.0 (`JsonRpcVersion::V2`): success emits `{"jsonrpc":"2.0","result":...,"id":...}` (HTTP 200), dispatch errors emit `{"jsonrpc":"2.0","error":...,"id":...}` (HTTP 200), and requests omitting `id` are notifications returning HTTP 204. An envelope refusal (`-32600` while validating the envelope itself) answers HTTP 400 in either dialect; only the reply envelope follows how far parsing got.
  - Other requests use JSON-RPC 1.1 / legacy (`JsonRpcVersion::Legacy`): success emits `{"result":...,"error":null,"id":...}` (HTTP 200); errors emit `{"result":null,"error":...,"id":...}` with Core's status mapping (`-32600` to 400, `-32601` to 404, every other code to 500); missing `id` defaults to `null`. A top-level JSON scalar is `-32700` at HTTP 500 with null id. A batch with at least one reply answers 200; an empty batch answers 200 with `[]`; an all-notification batch answers 204 with no body.
- The node ships no wallet. Methods needing private keys (funding, signing, key import/export) are unimplemented and return `RpcError::MethodNotFound`. PSBT combination and finalization, descriptor utilities, and `scantxoutset` stay available because external signers drive them.

### 2. Deep module separation and system owners

- Handlers, REST routes, and Esplora projections sit at the transport seam as pure wire adapters translating payloads into deep module interfaces (`Context`, `BlockTree`, `DerivedIndexQuery`, `applied_tip`), using domain-local concurrency and storage without leaking locks, indexing, or consensus logic into serialization.
- System owners:
  - Routing and demux: `classify` in `crates/rpc/src/server.rs` owns the listener directory table; routing rules are under [protocol demuxing and authentication](#1-protocol-demuxing-and-authentication).
  - Authentication: `Auth::validate_header` in `crates/rpc/src/auth.rs` guards JSON-RPC; `serve_connection` in `crates/rpc/src/server.rs` is the routing callsite. REST and Esplora stay unauthenticated.
  - Error codes: failures map through `RpcError` in `crates/rpc/src/error.rs`. Current mappings cover standard codes (`-32700`, `-32600` to `-32603`) and Core codes `-3` (invalid type), `-5` (not found), `-8` (invalid parameter). Handlers also emit `-1` (misc), `-22` (deserialization), `-25` (verify), and `-26` (verify-rejected) where implemented; `-27` stays a method-specific obligation when its behavior is implemented.
  - Read consistency and tip fencing: multi-record chain queries must use two-phase optimistic fencing (`capture_chain_view` / `ensure_chain_view` in `crates/rpc/src/esplora.rs`) or active-tip ancestry verification against `BlockTree` (`crates/rpc/src/rest.rs`). On a mid-execution reorg, return `503 Service Unavailable`.
  - Status reads versus live scans: published-status reads (`getblockchaininfo`, `getchaintxstats`, typed `Context::sync_progress`) project from one `AppliedView` capture of the last complete applied publication and never take the node's `StableRead` transition role, so a mid-transition block cannot stall an explorer or monitoring client. Reads needing a mutable chainstate as one piece (`scantxoutset` tip-plus-UTXO scan, `gettxoutsetinfo`, REST `getutxos`) run inside `Context::with_stable_chainstate`, which holds that exclusion across the whole read. Mempool admission is not one of them: `sendrawtransaction` and Esplora broadcasts submit through `MempoolGateway::submit_local_transaction` under the mempool's optimistic `AdmissionFence::Stable` version fence, retrying on a mid-check transition instead of excluding one. That exclusion is mutable-chainstate exclusion, not status synchronization.
  - Index query budgets: statistical and script index queries must be bounded by `QueryBudget` (`crates/index/src/runtime/query.rs`) against memory exhaustion and disk query starvation.
  - Multi-format rendering: multi-representation REST routes (such as `/rest/headers/...` in `crates/rpc/src/rest.rs`) implement `.json`, `.hex`, and `.bin` with explicit `Content-Type` headers (`application/json`, `text/plain`, `application/octet-stream`); single-representation routes (such as `/rest/chaininfo.json`) stay JSON-only.

### 3. Caching and pagination rules

- HTTP caching (RFC 9111):
  - Confirmed blocks, headers, immutable transactions: `Cache-Control: public, immutable, max-age=86400`.
  - Volatile tips, mempool, unconfirmed transactions: `Cache-Control: no-store`.
  - REST endpoints must ignore unrecognized query parameters to preserve downstream cache efficiency.
- Cursor pagination: use immutable hash cursors (`last_seen_txid`, block hashes), never integer offsets, for volatile datasets.

### 4. Non-blocking event notifications

- ZMQ framing: notifications (`ZmqPublisher` in `crates/rpc/src/zmq.rs`) emit 3-part multipart frames of topic, body, and 4-byte LE sequence.
- Non-blocking delivery: socket writes must use non-blocking sends (`zmq::DONTWAIT`). Buffer saturation at the high-water mark drops messages instead of stalling block validation or consensus.
- Reorg sequencing and order: rollback and admission orchestration in `crates/node/src/chain_effects.rs` guarantees disconnect events (`D`, published during rollback) emit before connect events (`C`, published by `on_connect`).

### 5. Architectural guardrails

- No generic middleware: no heavy async web framework stacks (Axum, Actix, Tower) in `RpcServer`.
- No speculative traits: no universal query abstractions across distinct wire protocols.
- No URL versioning: no `/v1/` or `/v2/` prefixes on Core-compatible endpoints.

## Features

- `silent-payments`: experimental `getblocktweaks` extension, separately enabled at runtime with `--silent-payments`. See [usage and limits](../../docs/silent-payments.md).
- `zmq`: gates ZMQ notification methods in the JSON-RPC registry. The crate defines and forwards no storage-backend features (`ARCH-04`).

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the project vocabulary.
