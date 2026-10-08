# Benchmark evidence rules

Each page under `docs/benchmarks/` owns its measurement cells. This page owns
the rules every cell shares, so a cell page states only what is specific to it.

## Required identities per sample

Every sample in a cell records six identities. The T02 collector rejects a sample that lacks any of them; a rejected sample is not evidence.

| Identity | Content |
|---|---|
| Artifact | SHA-256 of the exact binary, library or image measured; source commit |
| Configuration | Resolved `NodeConfig`, feature set, allocator, validation mode |
| Corpus | Corpus digest, height range, stop height and stop hash |
| Durability | Backend, batch mode (`write`, `write_deferred`, `write_durable`), flush and sync posture |
| Toolchain | `rustc 1.95.0`, edition 2024, profile, enabled features |
| Hardware | CPU model, pinned core set, memory, storage device, OS kernel |

## Acceptance rule

- Promotion of a candidate over its control requires a median gain of at least 1.05x over at least three alternating candidate/control runs. Each arm stays within 5% of its own median. The improvement must exceed the observed host noise.
- Non-target cells guard at no more than 3% median regression and no more than 5% p99 regression, measured with repeated runs and reported uncertainty. Average-only reporting never passes.
- Report p50, p95, p99 and max with the sample count. Never sum nested intervals. Never sum concurrent intervals. Parallel worker walls and inclusive stage histograms are reported beside the process wall, not added to it.
- Retain raw samples beside every summary. A Criterion adaptive elapsed total is not a median source.
- A missing binary, corpus, hardware target or digest marks the cell `BLOCKED` with the missing identity named. `BLOCKED` is never a pass and never a skip.

## Status vocabulary

A page marked `planned_not_executed` has run no end-state cell: every value in
its end-state tables is a required contract value, not a measurement, and its
`Prior candidate evidence` section is historical and proves no end-state cell.

## Pages

| Page | Cell or record |
| --- | --- |
| [end-to-end-sync.md](end-to-end-sync.md) | End-to-end sync performance cells |
| [muhash-rpc.md](muhash-rpc.md) | MuHash/gettxoutsetinfo RPC cells |
| [native-validation-default.md](native-validation-default.md) | Native-validation promotion record (verdict historical since #1117) |
| [offline-full-validation.md](offline-full-validation.md) | Offline full-validation campaign |
| [p2p-loopback.md](p2p-loopback.md) | P2P loopback measurement |
| [scriptindex-format.md](scriptindex-format.md) | Generic index on-disk format and its cells |
| [storage-footprint.md](storage-footprint.md) | Storage-footprint budget cells |
| [utxo-memory.md](utxo-memory.md) | UTXO memory cells |
| [index-rollback-rebuild-cutover.md](index-rollback-rebuild-cutover.md) | Rollback-versus-rebuild cutover decision |
| [data/](data/) | Retained evidence records: `overhaul-kernel-baseline-20260829`, `overhaul-native-apply-20260902`, `overhaul-signed-spend-20260904`, `comparator-lanes-20260913` |