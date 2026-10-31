# Wallet-facing public surface

Target contract for the surface an external wallet consumes.
The node exposes public transports only.
Wallet keys, coin selection, and signing stay in the external process.

## Clauses

### `WF-01`: Public transports only

- An external wallet talks to a running node through native Esplora HTTP at `/api`.
- It also uses the wallet-free JSON-RPC methods declared in `MANIFEST` (`crates/rpc/src/manifest.rs`).
- The embeddable `Node` API (`crates/node/src/embed.rs`) is the in-process equivalent of the same facts, not a second surface.
- The consumer gets no datadir access.
- The consumer imports no `NodeState`, `UtxoSet`, index types, or other crate-internal handles.
- Key-free helpers stay node RPCs because they need no key custody:
  - `getdescriptorinfo`
  - `deriveaddresses`
  - `decodescript`
  - `scantxoutset`
  - `combinepsbt`
  - `finalizepsbt`
  - `sendrawtransaction`
- Privileged access MUST fail by design.
- Import, datadir, and internal-state probes have no endpoint.
- These probes MUST return the declared unsupported or not-found response of their dialect.
- A successful privileged probe is a contract violation, not a feature.
- Key material never crosses to the node.
- Signing MUST happen inside the consumer process.
- Owners:
  - Esplora router `crates/rpc/src/esplora.rs`
  - JSON-RPC dispatch `crates/rpc/src/handlers.rs`
  - Embedding `crates/node/src/embed.rs`

### `WF-02`: Operations a wallet actually issues

- By default Esplora lives at `/api` on the JSON-RPC listener.
- This path is the electrs and mempool.space base URL; relative routes append to it.
- With opt-in `public_bind`, REST (if enabled), `/api`, and `/esplora` move to that separate public listener.
- `rpc_bind` serves authenticated JSON-RPC only.
- The public listener refuses JSON-RPC, including the legacy unknown-POST fallback, with 404 response codes.
- It closes before authentication or body upload.
- Both bindings share the same Context and authoritative services.
- Routing, capability gates, broadcast origins, and CORS inside the public namespaces stay unchanged.
- Each binding owns its connection budget, dispatcher cancellation latch, and blocking quota (`API-34`).
- Proof:
  - `rpc::server::tests::listeners::split_listener_routes_are_closed_before_authentication_and_body_upload`
  - `rpc::server::tests::listeners::public_saturation_preserves_management_and_recovers`
  - `split_rpc_listeners_start_and_join_through_node_services`
  - `public_bind_failure_rolls_back_management_binding_and_node_state`
- Every read captures the applied-tip publication and answers from one coherent view.
- A moved chain generation MUST return the declared unavailable response, never a mixed-tip page.
- Transaction rendering resolves a distinct parent at most once per response or bounded backend batch.
- It retains only referenced outputs until that batch finishes.
- Backend mempool GETs render at most 25 selected transactions at a time without limiting the response count.
- The ordered selection and its borrowed parent lookup retain the captured transaction Arcs across batches.
- Only the prevout working set is bounded by one batch's inputs.
- Backend POST transaction requests render at most 25 requested IDs at a time.
- They share duplicate bodies within each batch.
- Completed batches retain only response rows.
- Request size, row ordering, duplicates, and omitted missing IDs keep existing semantics.
- Transactions already selected through the mempool or verified index queries may supply those outputs.
- A decoded block may supply those outputs only when all conditions hold:
  - Its header identity matches the requested record.
  - Its transactions pass merkle-root, mutation, and witness-commitment checks using activation at that block's ancestry.
  - It belongs to the applied chain.
  - The transaction index is healthy and caught up.
- The readiness snapshot is consulted once only when the batch can reuse an in-block parent.
- Ordinary parent queries enforce their own readiness checks.
- Losing branch bodies MUST never substitute for authoritative parent history.
- Missing, pruned, unavailable, and corrupt required data keep their explicit errors.
- Read-only backend POST batches use the same applied-tip publication fence as GET responses.
- Proof:
  - `esplora::tests::backend_mempool_get_bounds_prevouts_without_limiting_rows`
  - `backend_mempool_get_keeps_captured_parents_across_batches`
  - `crates/rpc/src/esplora.rs` tests:
    - `history_resolves_shared_parents_once_per_page`
    - `batch_reuses_selected_transactions_and_mempool_parents`
    - `block_page_reuses_parent_outside_the_selected_page`
    - `block_transactions_reject_corrupt_witness_commitments`
    - `block_witness_binding_observes_activation`
    - `block_parent_reuse_checks_readiness_only_when_needed`
    - `backend_transaction_batches_share_duplicate_bodies_and_preserve_rows`
    - `parent_query_errors_and_republication_never_yield_a_cached_success`
- Routes:
  - Chain tip: `GET /blocks/tip/height`, `GET /blocks/tip/hash`.
  - Checkpoint hashes: `GET /block-height/{h}` (BDK walks this while building its chain).
  - Headers: `GET /block/{hash}/header` (80-byte header as hex).
  - Scan by scripthash: `GET /scripthash/{hash}`, `/utxo`, `/txs`, and the `/address/{addr}` twins.
  - BDK syncs through scripthash, not address.
  - These routes follow `--scriptindex` and return HTTP 503 until that index covers the applied tip.
  - UTXO and history lookup with pagination: the `.../txs/chain[/{last}]` cursors keep public Esplora cursor semantics.
  - Fee estimates: `GET /fee-estimates` plus `estimatesmartfee` and `estimaterawfee` over JSON-RPC.
  - Insufficient data returns the declared insufficient-data shape, never a fabricated rate.
  - Build and sign outside the node: `combinepsbt`, `finalizepsbt`, descriptor helpers are key-free; the consumer signs.
  - Broadcast: `POST /tx` (hex body) reaching the shared `MempoolGateway` with `AdmissionOrigin::Esplora`.
  - Broadcast uses its own fixed 10,000,000 sat/kvB request ceiling (`API-10`).
  - Rejections return HTTP 400 with the reason.
  - Success returns the transaction id as plain text.
  - Confirmation tracking, replacement observation, disconnect and reorg observation, and rescan operate over the same public reads.
- Public `/api` responses, including errors, allow cross-origin reads with `Access-Control-Allow-Origin: *` and expose `X-Total-Results`.
- `OPTIONS` under `/api` returns a 204 preflight permitting `GET`, `POST`, and the `Content-Type` request header.
- The mempool backend `/esplora` namespace, JSON-RPC, and Core REST do not inherit this policy.
- `/api` is a closed electrs namespace: a request in it never falls through to JSON-RPC.
- Unprefixed electrs paths on this listener return 404 status, so JSON-RPC keeps `/`.
- `/api/v1` is Mempool's API on the explorer port, not an Esplora alias here.
- `/api` serves no mempool-backend helpers.
- `/internal/*` and `/block-template` live under `/esplora`, the electrs superset `mempool/backend` uses as `ESPLORA_REST_API_URL`.
- Only GET and POST exist on `/api` and `/esplora`.
- Other methods, and GET outside `/rest/`, `/api/`, and `/esplora`, return 404 at listener demux and never become JSON-RPC.

### Acceptance criteria and execution evidence

- `WF-02` routing: `HEAD /api/tx` and `PUT /` return 404 status while `POST /api/tx` stays the broadcast route.
- Neither unsupported request reaches JSON-RPC.
- Evidence: running-node assertions in `external_wallet_can_scan_estimate_and_broadcast` (the `HEAD /api/tx` and `PUT /` exchanges) and the CI test log.
- Closed namespaces: `/api` and `/esplora` accept only documented GET and POST routes, and unprefixed explorer paths stay 404.
- Evidence: the same integration test plus `listener_directory_table_is_closed_over_http`.
- Run with `cargo test -p bitcoin-rs --test suite wallet_facing::`.
- Consumer boundary: proof uses only HTTP against a spawned node.
- Evidence: the imports of that test target.

### `WF-03`: Proof is a public-process consumer

- `bin/bitcoin-rs/tests/wallet_facing.rs` lives in binary package so it can spawn `CARGO_BIN_EXE_bitcoin-rs`.
- The package is a pure binary crate and its `bitcoin.conf` process-input adapters are binary modules.
- The test depends on rust-bitcoin and speaks only HTTP.
- It funds a regtest chain through `getblocktemplate` and `submitblock`.
- It issues BDK and esplora-client dialect against `/api` (tip, block height, headers, scripthash UTXOs and history, fee estimates, `POST /api/tx`).
- Named out-of-repo consumer: `btcw -n regtest -u http://<rpc-bind>/api` against a node started with `--network regtest --scriptindex`.
- Failures of that run are public-interface defects, not reasons to patch a wallet into this repository.

## Verification boundaries

RPC/HTTP consumers and pinned Core comparisons own wallet-facing query, admission, confirmation, and error behavior. Context fixtures remain distinct from real node/process evidence; no external wallet deployment or independent consumer result is inferred.

## Vocabulary

[Wallet-free RPC boundary](../../CONCEPTS.md),
[Chain snapshot](../../CONCEPTS.md),
[embedded node](../../CONCEPTS.md).
