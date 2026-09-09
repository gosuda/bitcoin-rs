# Solutions

Non-normative: historical decisions, evidence, and failed approaches. Informative, not normative. For current contracts see `docs/contracts/`.

Each note records the state of the code and the measurements at its date. Where a note quotes constants, paths, or benchmark numbers, read them as evidence from that time and check the cited source before relying on them.

## Architecture patterns

- [Node-level reorg execution](architecture-patterns/node-reorg-execution-design.md) (2026-08-08) — where the disconnect commit point sits, why undo records are not idempotent, and how derived TxIndex watermarks stay outside the authoritative rollback.
- [P2P owns the peer lifecycle](architecture-patterns/p2p-owns-peer-lifecycle.md) — one `PeerTable` as the connection authority; `PeerSource` identity so a stale predecessor cannot publish, send, or cancel a same-address replacement.
- [Multi-peer block download requires Core-style stalling-disconnect](architecture-patterns/multi-peer-block-download-requires-core-stalling-disconnect.md) (2026-06-08) — why the naive parallel download collapsed, the Core-faithful window design that replaced it, and why simulations cannot sign off a scheduler.

## Best practices

- [Criterion bench trust](best-practices/criterion-bench-trust-rebuild-drift-baselines-allocator.md) (2026-06-10) — rebuild codegen drift, `--baseline`/`--save-baseline` exclusivity, allocator parity.
- [Small-window benchmarks do not predict at-scale throughput](best-practices/small-window-benchmarks-do-not-predict-at-scale-throughput.md) (2026-06-10) — the 0–150,000 matched-validation replay that disproved the "beats Core" premise drawn from blocks 0–1000.
- [Benchmark the operation the workload performs](best-practices/benchmark-the-operation-the-workload-performs-not-the-one-the-api-exposes.md) (2026-08-17) — a codec that won on encode/decode lost 4.9x on `find_output`; call sites are the benchmark specification.

## Logic errors

- [Exclude provably unspendable outputs from the UTXO set](logic-errors/exclude-provably-unspendable-utxos.md) (2026-07-29) — `OP_RETURN` and over-`MAX_SCRIPT_SIZE` outputs never enter chainstate; the checkpoint codec name binds the admission rule.

## Performance

- [Defer redb block-body index durability to checkpoints](performance-issues/defer-redb-block-body-index-durability.md) (2026-08-03) — a scoped `write_deferred` for the index batch; 405 s to 134 s on the 150k replay.
- [Allocator parity changes wall time, not CPU time](performance/allocator-parity-changes-wall-not-cpu.md) — the mimalloc-versus-system panel that falsified the earlier CPU-deficit premise.
- [Cross-block script batching: reverted once, then shipped](performance/script-batching-needs-a-split-apply-path.md) — the first attempt cost what it saved; the prepare/commit split, its invariants, and the checkpoint-tail follow-ups.
