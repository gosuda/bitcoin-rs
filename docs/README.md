# Documentation

This tree is organised by where documents came from, not by who reads them.
This page maps it to what you might want.

## Start here

- [getting-started.md](getting-started.md) walks from a clone to a syncing
  node.
- [rest-interface.md](rest-interface.md) documents the optional Core-compatible
  REST gateway and enforcer integration.
- [chainstate-recovery.md](chainstate-recovery.md) documents checkpoint/journal
  crash recovery, fallback behavior, metrics, and operator actions.
- [../CONCEPTS.md](../CONCEPTS.md) is the project glossary. Read a term here
  before assuming it means what it means elsewhere in Bitcoin.
- [../README.md](../README.md) covers the defaults and the measured benchmark.

## Contracts

[docs/contracts/](contracts/) holds the normative behavior docs. Each one
states what the code must keep, then names the files and tests that prove
it. When documents disagree, the contract wins and the drift is a bug. The
precedence rule and the index of contract pages live in
[docs/contracts/README.md](contracts/README.md).

## Reference

- [policies/](policies/) holds the rules a change has to satisfy.
  [source-compatibility.md](policies/source-compatibility.md) covers the
  toolchain and dependency rules;
  [db-migration.md](policies/db-migration.md) covers on-disk schema changes;
  [mempool-policy.md](policies/mempool-policy.md) pins transaction
  acceptance against Bitcoin Core;
  [p2p-compatibility.md](policies/p2p-compatibility.md) pins the peer wire
  surface against Bitcoin Core.
- [rpc-reference.md](rpc-reference.md) is the generated JSON-RPC, REST, and
  ZMQ surface table. Do not edit it by hand; its source of truth is
  `MANIFEST` in `crates/rpc/src/manifest.rs`, and the file header gives the
  regeneration command.
- [api/](api/) holds machine-readable compatibility inputs embedded into the
  `bitcoin-rs-rpc` build: `core-compat.toml` (the Core compatibility manifest,
  checked by `crates/rpc/src/compat_manifest.rs`) and `core-rpc-schema.json`
  (Core result schemas extracted by `tools/core-rpc-schema/extract.py`).
  Treat both as code, not prose.
- [benchmarks/](benchmarks/) holds the retained benchmark notes:
  [end-to-end-sync.md](benchmarks/end-to-end-sync.md),
  [offline-full-validation.md](benchmarks/offline-full-validation.md),
  [p2p-loopback.md](benchmarks/p2p-loopback.md),
  [muhash-rpc.md](benchmarks/muhash-rpc.md),
  [index-read-path.md](benchmarks/index-read-path.md),
  [index-rollback-rebuild-cutover.md](benchmarks/index-rollback-rebuild-cutover.md),
  [utxo-memory.md](benchmarks/utxo-memory.md),
  [storage-footprint.md](benchmarks/storage-footprint.md),
  [scriptindex-format.md](benchmarks/scriptindex-format.md),
  [simd-allocator-decision.md](benchmarks/simd-allocator-decision.md), the
  product hot-path [ledger](benchmarks/hot-path-ledger.toml) with its
  [reading guide](benchmarks/hot-path-attribution.md), owned by
  [contracts/hot-path-attribution.md](contracts/hot-path-attribution.md), and
  the #213 decision
  [native-validation-default.md](benchmarks/native-validation-default.md).
  Read the methodology before quoting any number: the results depend on CPU
  pinning and on whether the harness competes with the node. Raw run
  evidence lives in the corresponding PR discussions, not in the tree.

## Explanation

[solutions/](solutions/) is the durable knowledge base: a problem that cost
real time, and what was concluded. It is informative, not normative; each note
records the code and measurements at its date. Five areas:
`architecture-patterns`, `best-practices`, `logic-errors`, `performance`, and
`performance-issues`.

Search it before debugging a recurring problem or designing in an area someone
has already touched.

## Known gaps

**Do not run this on mainnet as your only node.** Sync calls
`switch_to_branch` when a higher-work header branch wins. It preloads the
divergent bodies, revalidates the plan under one chain-transition guard,
restores UTXO state and coinstats, re-admits disconnected non-coinbase
transactions to the mempool in dependency order, and wakes index consumers to
reconcile asynchronously. A fatal partial transition stops the process.

The ZMQ `pubsequence` stream publishes block connect (`C`) and disconnect
(`D`) events and mempool `A`/`R` events, each carrying the mempool sequence
assigned to the change. A transaction removed because a connected block
included it emits no `R`; the block's `C` event covers it, as in Core.

Still incomplete: proactive block announcements to peers (the node relays
accepted transactions as `inv(tx)` but does not announce new blocks), address
gossip and peer discovery beyond configured `--connect`/`--addnode` peers
([p2p-compatibility.md](policies/p2p-compatibility.md) §7), broader metrics
coverage, and parts of the CLI and RPC surface.

On documentation itself: there is no tutorial series. JSON-RPC uses Bitcoin
Core's method names, so Core's API documentation applies to the shared surface.
The authoritative list of what this node implements is `MANIFEST` in
`crates/rpc/src/manifest.rs`, rendered as [rpc-reference.md](rpc-reference.md);
`crates/rpc/src/handlers.rs` dispatches through that registry.
