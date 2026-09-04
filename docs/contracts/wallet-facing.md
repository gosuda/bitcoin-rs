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

- Chain tip: `GET /blocks/tip/height`, `GET /blocks/tip/hash`.
- Checkpoint hashes: `GET /block-height/{h}` (BDK walks this while
  building its chain).
- Fee estimates: `GET /fee-estimates`.
- Address or script activity: `GET /address/{addr}`, `/utxo`, `/txs` and
  the `scripthash` twins. These routes follow `--scriptindex`; they
  return HTTP 503 until that index covers the applied tip.
- Broadcast: `POST /tx` (hex body), which dispatches `sendrawtransaction`
  through the same admission owner as JSON-RPC.

### `WF-03`: Proof is a public-HTTP consumer

- In-tree fixtures that import node internals do not prove this contract.
- Proof: `bin/bitcoin-rs/tests/wallet_facing.rs` spawns the `bitcoin-rs`
  binary and speaks only HTTP. It submits genesis and mined blocks through
  `submitblock`, then scans, fee-estimates, and broadcasts the way
  [bitcoin-wallet](https://github.com/gosuda/bitcoin-wallet) (`btcw -u`)
  does against any Esplora URL.
- Named out-of-repo consumer: `btcw -n regtest -u http://<rpc-bind>`
  against a node started with `--network regtest --scriptindex`. Failures
  of that run are public-interface defects, not reasons to patch a wallet
  into this repository.

## Proven by

- `bin/bitcoin-rs/tests/wallet_facing.rs::external_wallet_can_scan_estimate_and_broadcast`

## Vocabulary

[Wallet-free RPC boundary](../../CONCEPTS.md),
[Esplora request chain view](../../CONCEPTS.md),
[embedded node](../../CONCEPTS.md).
