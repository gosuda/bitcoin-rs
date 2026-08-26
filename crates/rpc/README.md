# bitcoin-rs-rpc

The synchronous, Bitcoin Core-compatible JSON-RPC and REST surface of the node: method dispatch, HTTP Basic and cookie authentication, and a wallet-free method surface — every RPC that would require private key material is simply absent.

`RpcServer::bind` binds a TCP listener and `serve` (or `serve_with_shutdown` for controlled shutdown) runs the blocking accept loop, handing each connection to a bounded worker thread under a per-connection idle timeout. Each request is authenticated by `Auth`, then matched to a Core-compatible handler by `Handler::dispatch`, which reads shared node state through the dependency-injected `Context` — the boundary carrying `ChainControl` consensus-affecting operations, `PruneService`, `TxIndexQuery`, `NetworkState`, and `ZmqNotification`. Failures map to JSON-RPC error codes through `RpcError`, and Bitcoin Core-compatible REST endpoints (`rest`) are served on the same listener when enabled. RPCs that would reveal, import, create, or use private keys are not implemented and answer `method not found`, while PSBT combination and finalization remain available because they are driven by external signers without this process holding private key material.

## Interface architecture and implementation guidance

### 1. Protocol demuxing and authentication
- **Transport Demuxing**: Private free function `serve_connection` (`crates/rpc/src/server.rs`) demuxes incoming HTTP requests before authentication:
  - `GET`: If path starts with `/rest/*`, routed to unauthenticated `rest::route`; all other `GET` paths are routed to unauthenticated `esplora::route`.
  - `POST` (Esplora): Recognized paths (`/tx`, `/internal/*`) route to unauthenticated `esplora::route_post`.
  - `POST` (JSON-RPC): Unhandled POST paths (such as `/`) fall through to JSON-RPC authentication. `serve_connection` in `crates/rpc/src/server.rs` calls `Auth::validate_header`, which is owned by `crates/rpc/src/auth.rs` (HTTP Basic / Cookie).
- **JSON-RPC Framing & Protocol Versioning**: `JsonRpcVersion` (`crates/rpc/src/server.rs`) governs wire framing:
  - Requests with `"jsonrpc": "2.0"` use JSON-RPC 2.0 (`JsonRpcVersion::V2`): success responses emit `{"jsonrpc":"2.0","result":...,"id":...}` (HTTP 200), error responses emit `{"jsonrpc":"2.0","error":...,"id":...}` (HTTP 200), and requests omitting `id` are treated as notifications returning HTTP 204 No Content.
  - Other requests use JSON-RPC 1.1 / legacy (`JsonRpcVersion::Legacy`): success responses emit `{"result":...,"error":null,"id":...}` (HTTP 200), error responses emit `{"result":null,"error":...,"id":...}` with HTTP 500 status, and missing `id` values default to `null`.
- **Wallet-Free Surface**: The node ships no wallet. Methods requiring private keys (funding, signing, key import/export) are not implemented and return `RpcError::MethodNotFound`. PSBT combination and finalization, descriptor utilities, and `scantxoutset` remain available because they are driven by external signers without this process holding private key material.

### 2. Deep module separation and system owners
- **Adapters vs Modules**: RPC handlers, REST routes, and Esplora projections sit at the transport Seam as pure wire Adapters translating network payloads into deep Module Interfaces (`Context`, `BlockTree`, `TxIndexQuery`, `applied_tip`). They leverage domain-local concurrency and storage mechanisms without leaking database locks, indexing details, or consensus logic into protocol serialization.
- **System Owners**:
  - **Routing & Demux**: `serve_connection` in `crates/rpc/src/server.rs` demuxes path prefixes and HTTP methods before authentication.
  - **Authentication**: `Auth::validate_header` in `crates/rpc/src/auth.rs` guards JSON-RPC requests; `serve_connection` in `crates/rpc/src/server.rs` is the routing callsite. REST and Esplora remain unauthenticated.
  - **Error Codes**: JSON-RPC failures map through `RpcError` in `crates/rpc/src/error.rs`. Current mappings cover standard JSON-RPC codes (`-32700`, `-32600`..=`-32603`) and Bitcoin Core codes `-3` (invalid type) and `-5` (not found). The code reserves `-8` (invalid parameter), but no current variant emits it. Other Core codes (`-1`, `-22`, `-25`, `-26`, `-27`) remain method-specific obligations when their behavior is implemented.
  - **Read Consistency & Tip Fencing**: Multi-record queries against chain state must use two-phase optimistic fencing (`capture_chain_view` / `ensure_chain_view` in `crates/rpc/src/esplora.rs`) or active-tip ancestry verification against `BlockTree` (`crates/rpc/src/rest.rs`). If a reorg occurs during execution, return `503 Service Unavailable`.
  - **Index Query Budgets**: Statistical and script index queries must be bounded by `QueryBudget` (`crates/node/src/txindex_worker.rs`, `crates/rpc/src/esplora.rs`) to prevent memory exhaustion and disk query starvation.
  - **Multi-Format Rendering**: REST routes supporting multiple representations (such as `/rest/headers/...` in `crates/rpc/src/rest.rs`) implement `.json`, `.hex`, and `.bin` formats with explicit `Content-Type` headers (`application/json`, `text/plain`, `application/octet-stream`), while single-representation routes (e.g. `/rest/chaininfo.json`) remain JSON-only.

### 3. Caching and pagination rules
- **HTTP Caching (RFC 9111)**:
  - Confirmed blocks, headers, and immutable transactions: `Cache-Control: public, immutable, max-age=86400`.
  - Volatile tips, mempool, and unconfirmed transactions: `Cache-Control: no-store`.
  - REST endpoints must ignore unrecognized query parameters to maintain downstream cache efficiency.
- **Cursor Pagination**: Use immutable hash cursors (`last_seen_txid`, block hashes) rather than integer offsets for volatile datasets.

### 4. Non-blocking event notifications
- **ZMQ Framing**: ZeroMQ notifications (`ZmqPublisher` in `crates/node/src/zmq_publisher.rs`) emit 3-part multipart frames `[topic, body, 4-byte LE sequence]`.
- **Non-Blocking Delivery**: Socket writes must use non-blocking sends (`zmq::DONTWAIT`). Notification buffer saturation must drop messages at the high-water mark rather than stalling block validation or consensus execution.
- **Reorg Sequencing & Notification Order**: Chain-transition rollback and admission orchestration in `crates/node/src/apply.rs` guarantees block disconnect events (`D`, published during rollback) are emitted before block connect events (`C`, published in `apply_block_admitted`).

### 5. Architectural guardrails
- **No Generic Middleware**: Do not introduce heavy async web framework stacks (Axum, Actix, Tower) into `RpcServer`.
- **No Speculative Traits**: Reject universal query abstractions across distinct wire protocols.
- **No URL Versioning**: Reject `/v1/`, `/v2/` URL prefixes for Bitcoin Core-compatible endpoints.

## Features

- `rocksdb`, `fjall`, `redb`: forward the storage-backend selection into the `utxo`, `storage`, and `p2p` crates.
- `mdbx`: forwards the MDBX storage-backend selection into the `storage` crate.

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
