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
  [db-migration.md](policies/db-migration.md) covers on-disk schema changes.
- [benchmarks/](benchmarks/) holds the retained benchmark notes:
  [end-to-end-sync.md](benchmarks/end-to-end-sync.md),
  [index-read-path.md](benchmarks/index-read-path.md), and
  [utxo-memory.md](benchmarks/utxo-memory.md). Read the methodology before
  quoting any number: the results depend on CPU pinning and on whether the
  harness competes with the node. Raw run evidence lives in the corresponding
  PR discussions, not in the tree.

## Explanation

[solutions/](solutions/) is the durable knowledge base: a problem that cost
real time, and what was concluded. Five areas, `architecture-patterns`,
`best-practices`, `logic-errors`, `performance`, and `performance-issues`.

Search it before debugging a recurring problem or designing in an area someone
has already touched.



## Known gaps

**Do not run this on mainnet as your only node.** Sync calls
`switch_to_branch` when a higher-work header branch wins. It preloads the
divergent bodies, revalidates the plan under one chain-transition guard,
restores UTXO state and coinstats, re-admits disconnected non-coinbase
transactions to the mempool in dependency order, and wakes index consumers to
reconcile asynchronously. A fatal partial transition stops the process.

The ZMQ `pubsequence` stream publishes block connect/disconnect events and
mempool `A`/`R` events with per-change sequence assignment and explicit removal
reasons.

Still incomplete: production P2P transaction relay, broader metrics coverage,
and parts of the CLI and RPC surface.

On documentation itself: there is no tutorial series. JSON-RPC uses Bitcoin
Core's method names, so Core's API documentation applies to the shared surface;
the authoritative list of what this node implements is the manifest and dispatch
table in `crates/rpc/src/handlers.rs`.
