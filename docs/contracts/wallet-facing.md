# Wallet-facing public surface

The repository stops at the interface an external wallet consumes. This
page names that surface, its owners, and the proof that a process outside
the node crates can use it. Wallet keys, coin selection, and signing stay
out of tree.

## Clauses

### `WF-01`: Public transports only

- An external wallet talks to a running node through native Esplora HTTP
  and/or the wallet-free JSON-RPC methods declared in `MANIFEST`
  (`crates/rpc/src/manifest.rs`). The embeddable `Node` API
  (`crates/node/src/embed.rs`) is the in-process equivalent of the same
  facts, not a second surface.
- The consumer does not import `NodeState`, `UtxoSet`, index types, or
  other crate-internal handles. Descriptor helpers, `scantxoutset`,
  `combinepsbt`, `finalizepsbt`, and `sendrawtransaction` remain node
  RPCs because they do not require key custody.
- Owner: Esplora router `crates/rpc/src/esplora.rs`; JSON-RPC dispatch
  `crates/rpc/src/handlers.rs`; embedding `crates/node/src/embed.rs`.

### `WF-02`: Operations a wallet actually issues

Esplora lives at `/api` on the JSON-RPC listener. That directory is the
electrs/mempool.space base URL. Relative routes below are appended to it.

- Chain tip: `GET /blocks/tip/height`, `GET /blocks/tip/hash`.
- Checkpoint hashes: `GET /block-height/{h}` (BDK walks this while
  building its chain).
- Headers: `GET /block/{hash}/header` (80-byte header as hex).
- Fee estimates: `GET /fee-estimates`.
- Address or script activity: `GET /address/{addr}`, `/utxo`, `/txs` and
  the `scripthash` twins. BDK syncs through scripthash, not address.
  These routes follow `--scriptindex`; they return HTTP 503 until that
  index covers the applied tip.
- Broadcast: `POST /tx` (hex body), which dispatches `sendrawtransaction`
  through the same admission owner as JSON-RPC.
- `/api` is a closed electrs namespace: a request in it never falls
  through to JSON-RPC. Unprefixed electrs paths on this listener 404 so
  JSON-RPC keeps `/`. `/api/v1` is Mempool's API on the explorer port,
  not an Esplora alias here.
- `/api` does not serve mempool-backend helpers. `/internal/*` and
  `/block-template` live under `/esplora`, the electrs superset
  `mempool/backend` uses as `ESPLORA_REST_API_URL`.
- Only GET and POST exist on `/api` and `/esplora`. Other methods, and
  GET outside `/rest/`, `/api`, and `/esplora`, 404 at the listener demux
  and never become JSON-RPC.

### `WF-03`: Proof is a public-HTTP consumer

- In-tree fixtures that violate `WF-01` do not prove this contract.
- Proof: `bin/bitcoin-rs/tests/wallet_facing.rs` lives in the binary
  package so it can spawn `CARGO_BIN_EXE_bitcoin-rs`. The package `[lib]`
  is process-input adapters (`bitcoin.conf`). The binary package still
  compiles node and storage so the daemon can start;
  `source_does_not_import_node_internals` enforces `WF-01` on uncommented
  proof source, including aliases and fully qualified paths. The test
  depends on rust-bitcoin and speaks only HTTP. It funds a regtest chain
  through `getblocktemplate` / `submitblock` (this node has no `generate*`
  RPC), then issues the BDK/esplora-client dialect against `/api` — tip,
  block height, headers, scripthash UTXOs/history, fee estimates, and
  `POST /api/tx` — the same operations
  [bitcoin-wallet](https://github.com/gosuda/bitcoin-wallet) (`btcw -u`)
  sends against any Esplora URL.
- Named out-of-repo consumer: `btcw -n regtest -u http://<rpc-bind>/api`
  against a node started with `--network regtest --scriptindex`. Failures
  of that run are public-interface defects, not reasons to patch a wallet
  into this repository.

## Proven by

- `bin/bitcoin-rs/tests/wallet_facing.rs::external_wallet_can_scan_estimate_and_broadcast`
- `crates/rpc/src/server.rs` test `classify_splits_rest_esplora_and_json_rpc`
- `crates/rpc/src/esplora.rs` tests `esplora_lives_only_under_the_api_prefix`, `api_is_the_public_electrs_directory`, and `esplora_is_the_mempool_backend_superset`
- `bin/bitcoin-rs/tests/wallet_facing.rs::source_does_not_import_node_internals`

## Vocabulary

[Wallet-free RPC boundary](../../CONCEPTS.md),
[Esplora request chain view](../../CONCEPTS.md),
[embedded node](../../CONCEPTS.md).
