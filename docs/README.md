# Documentation

## Start here

- [getting-started.md](getting-started.md): build, configuration, startup, RPC, indexes, and consumers
- [contracts/README.md](contracts/README.md): normative contract index and precedence
- [../CONCEPTS.md](../CONCEPTS.md): project vocabulary
- [../CONSTRAINTS.md](../CONSTRAINTS.md): gate and evidence register
- [../AGENTS.md](../AGENTS.md): repository-change rules

[chainstate-recovery.md](chainstate-recovery.md) and [rest-interface.md](rest-interface.md) are operator summaries. Their linked contract pages remain authoritative.

## Authority

Use this order when documents disagree:

1. [contracts/](contracts/)
2. source comments for local invariants
3. [policies/](policies/) for detailed domain matrices
4. benchmarks, solutions, concepts, and consumer guides

A code/contract disagreement is drift to fix, not a reason to silently rewrite one side.

## Contracts

The complete clause/proof map is in [contracts/README.md](contracts/README.md). Major owners include:

- [architecture.md](contracts/architecture.md): crate layering and mutation ownership
- [validation-default.md](contracts/validation-default.md): current kernel/native default decision
- [recovery.md](contracts/recovery.md): durable-root target, crash outcomes, reorg, schema policy
- [mempool-policy.md](contracts/mempool-policy.md) and [mempool-mutations.md](contracts/mempool-mutations.md): admission and lifecycle
- [indexing.md](contracts/indexing.md): capability readiness and reconciliation
- [p2p-wire.md](contracts/p2p-wire.md): current peer-wire contract
- [external-api.md](contracts/external-api.md), [wallet-facing.md](contracts/wallet-facing.md), [embedding.md](contracts/embedding.md): public surfaces
- [storage-footprint.md](contracts/storage-footprint.md), [hot-path-attribution.md](contracts/hot-path-attribution.md), [campaign-corpora.md](contracts/campaign-corpora.md): measurement contracts
- [reference-set.md](contracts/reference-set.md): pinned external identities

## Policies and machine-readable inputs

- [policies/source-compatibility.md](policies/source-compatibility.md): toolchain, dependencies, TLS, versioning
- [policies/db-migration.md](policies/db-migration.md): authoritative and owner-local format changes
- [policies/mempool-policy.md](policies/mempool-policy.md): detailed Core 31.1 admission matrix
- [policies/p2p-compatibility.md](policies/p2p-compatibility.md): detailed peer compatibility matrix
- [api/core-compat.toml](api/core-compat.toml) and `api/core-rpc-schema.json`: machine-consumed compatibility data; treat as code
- [rpc-reference.md](rpc-reference.md): generated from `crates/rpc/src/manifest.rs`; do not edit by hand
- [models/](models/): TLA+ models and Apalache configurations; `CONSTRAINTS.md` records gate status

## Evidence

[benchmarks/](benchmarks/) contains methods, retained measurements, and decision records. A row marked `UNMEASURED`, `planned`, or `BLOCKED` is not a result. The machine ledger is [benchmarks/hot-path-ledger.toml](benchmarks/hot-path-ledger.toml); [contracts/hot-path-attribution.md](contracts/hot-path-attribution.md) owns its interpretation.

[solutions/](solutions/) is historical engineering context. It is informative and may describe code or designs that have since been replaced.

## Current build status

The default `bitcoin-rs` binary is kernel-free; `--features kernel` builds the optional kernel lane. Library default behavior is governed separately by [contracts/validation-default.md](contracts/validation-default.md), which currently keeps `kernel` in the consensus/node library defaults until the recorded promotion gate changes.

BIP324 is target work only in this checkout. There is no `bip324` Cargo feature or dependency, so documentation must not advertise `--features bip324` as a usable lane.

## Release status

Do not duplicate gate tables here. [../CONSTRAINTS.md](../CONSTRAINTS.md) owns current gate state and [contracts/](contracts/) owns required behavior. A build is not evidence merely because it compiles, and a target design is not implemented merely because a contract describes it.
