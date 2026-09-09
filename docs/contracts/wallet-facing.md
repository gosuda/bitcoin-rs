# Wallet-facing public surface

Target contract for the surface an external wallet consumes. The node
exposes public transports only. Wallet keys, coin selection, and signing
stay in the external process.

## Clauses

### `WF-01`: Public transports only

- An external wallet talks to a running node through native Esplora HTTP
  at `/api` and the wallet-free JSON-RPC methods declared in `MANIFEST`
  (`crates/rpc/src/manifest.rs`). The embeddable `Node` API
  (`crates/node/src/embed.rs`) is the in-process equivalent of the same
  facts, not a second surface.
- The consumer does not import `NodeState`, `UtxoSet`, index types, or
  other crate-internal handles, and it gets no datadir access. The
  key-free helpers `getdescriptorinfo`, `deriveaddresses`, `scantxoutset`,
  `combinepsbt`, `finalizepsbt`, and `sendrawtransaction` remain node
  RPCs because they need no key custody.
- Privileged access fails by design. Import, datadir, and internal-state
  probes have no endpoint and return the declared unsupported or
  not-found response of their dialect. A successful privileged probe is a
  contract violation, not a feature.
- Key material never crosses to the node. Signing happens inside the
  consumer process.
- Owners: Esplora router `crates/rpc/src/esplora.rs`; JSON-RPC dispatch
  `crates/rpc/src/handlers.rs`; embedding `crates/node/src/embed.rs`.

### `WF-02`: Operations a wallet actually issues

Esplora lives at `/api` on the JSON-RPC listener. That directory is the
electrs/mempool.space base URL. Relative routes below are appended to it.
Every read captures a `ReadStamp` and answers from one coherent view. A
moved chain generation returns the declared unavailable response, never a
mixed-tip page.

- Chain tip: `GET /blocks/tip/height`, `GET /blocks/tip/hash`.
- Checkpoint hashes: `GET /block-height/{h}` (BDK walks this while
  building its chain).
- Headers: `GET /block/{hash}/header` (80-byte header as hex).
- Scan by scripthash: `GET /scripthash/{hash}`, `/utxo`, `/txs`, and the
  `/address/{addr}` twins. BDK syncs through scripthash, not address.
  These routes follow `--scriptindex`; they return HTTP 503 until that
  index covers the applied tip.
- UTXO and history lookup with pagination: the `.../txs/chain[/{last}]`
  cursors keep public Esplora cursor semantics.
- Fee estimates: `GET /fee-estimates`, plus `estimatesmartfee` and
  `estimaterawfee` over JSON-RPC. Insufficient data returns the declared
  insufficient-data shape, never a fabricated rate.
- Build and sign outside the node: `combinepsbt`, `finalizepsbt`, and the
  descriptor helpers are key-free. The consumer signs.
- Broadcast: `POST /tx` (hex body) reaches the shared `MempoolGateway`
  with the Esplora origin and its own request fee limits.
- Confirmation tracking, replacement observation, disconnect and reorg
  observation, and rescan all run over the same public reads.
- Public `/api` responses, including errors, allow cross-origin reads with
  `Access-Control-Allow-Origin: *` and expose `X-Total-Results`. `OPTIONS`
  requests under `/api` return a 204 preflight response permitting `GET`,
  `POST`, and the `Content-Type` request header. The mempool backend
  `/esplora` namespace, JSON-RPC, and Core REST do not inherit this policy.
- Public `/api` responses, including errors, allow cross-origin reads with
  `Access-Control-Allow-Origin: *` and expose `X-Total-Results`. `OPTIONS`
  requests under `/api` return a 204 preflight response permitting `GET`,
  `POST`, and the `Content-Type` request header. The mempool backend
  `/esplora` namespace, JSON-RPC, and Core REST do not inherit this policy.
- `/api` is a closed electrs namespace: a request in it never falls
  through to JSON-RPC. Unprefixed electrs paths on this listener 404 so
  JSON-RPC keeps `/`. `/api/v1` is Mempool's API on the explorer port,
  not an Esplora alias here.
- `/api` does not serve mempool-backend helpers. `/internal/*` and
  `/block-template` live under `/esplora`, the electrs superset
  `mempool/backend` uses as `ESPLORA_REST_API_URL`.

### `WF-03`: Proof is a public-process consumer

- `bin/bitcoin-rs/tests/wallet_facing.rs` (existing) lives in the binary
  package so it can spawn `CARGO_BIN_EXE_bitcoin-rs`. The package `[lib]`
  is process-input adapters (`bitcoin.conf`). The test depends on
  rust-bitcoin and speaks only HTTP. It funds a regtest chain through
  `getblocktemplate` and `submitblock`, then issues the
  BDK/esplora-client dialect against `/api`: tip, block height, headers,
  scripthash UTXOs and history, fee estimates, and `POST /api/tx`.
  `source_does_not_import_node_internals` enforces `WF-01` on uncommented
  proof source, including aliases and fully qualified paths.
- Named out-of-repo consumer: `btcw -n regtest -u http://<rpc-bind>/api`
  against a node started with `--network regtest --scriptindex`. Failures
  of that run are public-interface defects, not reasons to patch a wallet
  into this repository.

## Proven by

- `bin/bitcoin-rs/tests/wallet_facing.rs::external_wallet_can_scan_estimate_and_broadcast`
  (existing)
- `bin/bitcoin-rs/tests/wallet_facing.rs::source_does_not_import_node_internals`
  (existing)
- `crates/rpc/src/esplora.rs` tests
  `esplora_lives_only_under_the_api_prefix`,
  `api_is_the_public_electrs_directory`, and
  `esplora_is_the_mempool_backend_superset` (existing)

## Vocabulary

[Wallet-free RPC boundary](../../CONCEPTS.md),
[ReadStamp](../../CONCEPTS.md),
[embedded node](../../CONCEPTS.md).
