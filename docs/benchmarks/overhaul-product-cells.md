# Product cells: T02 evidence catalogue

This document is the T02 product cell catalogue: the cells the collector in `crates/node/src/metrics.rs` emits, the identities every sample carries, and the reuse rule that binds T14 and T39 to this one collector. The hot-path ledger `hot-path-ledger.toml` (36 frozen cells, gate `g18_hot_path_ledger`) remains the wall denominator; this catalogue extends it for the live lanes BLUEPRINT §14.1 names: admission, block propagation, API queries, index backfill and mining. Method: [`docs/contracts/hot-path-attribution.md`](../contracts/hot-path-attribution.md).

## Schema

Schema version string: `bitcoin-rs-product-cells-v1`. The T02 gate `bin/bitcoin-rs/tests/overhaul_evidence.rs` rejects a record that lacks a required identity, sums nested or concurrent intervals, or collapses repeated samples. Schema validity never establishes a product result; only an executed scenario with observable state transition does.

## Identity fields

Every sample record carries: `artifact_sha256`, `source_commit`, `configuration_id` (resolved `NodeConfig` digest, features, allocator, validation mode), `corpus_id` (digest, height range, stop height, stop hash), `durability_id` (backend, batch mode, flush and sync posture), `toolchain_id` (`rustc 1.95.0`, edition 2024, profile, features), `hardware_id` (CPU model, pinned cores, memory, storage device, kernel), `cell`, `interval_parent`, `concurrency_group`, `sample_index`, and the raw observation (`elapsed_ns`, `cpu_ns`, `rss_peak_bytes`, `io_bytes`, `storage_owner_bytes` where the cell defines them).

## Cell catalogue

Input count and bytes are recorded per run from the actual corpus or request stream; the column below states what is counted. Resource budgets name the owner limit that bounds the cell; the resolved value is recorded from configuration, never typed into this table.

| Cell | Owner crate | Input count / bytes | Interval parent | Concurrency group | Resource budget | Evidence |
|---|---|---|---|---|---|---|
| `replay.offline_full_validation` | `chainstate` (target), `consensus` | blocks and serialized block bytes of the pinned corpus | process wall from spawn to durable clean exit | validation workers (T08 bounded window) | window bytes, inputs, retained coin bytes, CPU jobs, age; RSS guard | `UNMEASURED` |
| `replay.live_ibd_loopback` | `p2p`, `chainstate` | blocks and bytes delivered by the loopback peer set | process wall from start to pinned stop | download window plus validation workers | `DownloadWindow` byte and height budget; RSS guard | `UNMEASURED` |
| `admission.live` | `mempool` | transactions and serialized bytes admitted through `MempoolGateway` | request wall from ingress accept to typed verdict | admission workers; writer held once per attempt | `MempoolLimits` (cluster count 64, cluster size 101_000 vB, max ancestors 25); four attempts then `Busy`; `MAX_STANDARD_TX_SIGOPS_COST` 16_000 | `UNMEASURED` |
| `propagation.block` | `p2p` | blocks and bytes announced, including compact-block reconstruction and full-block fallback | announce at source to validated body publication on the receiving node | one `P2pService` session per peer | per-command and global payload bounds in `wire.rs`; `TX_RELAY_QUEUE_CAPACITY` for tx relay | `UNMEASURED` |
| `api.query` | `rpc` | requests and response bytes per manifest row (RPC, REST, Esplora public, backend dialect) | request wall from parsed request to response flush | handler pool; coherent read fence per request | request body, batch size, response assembly, scan rows, in-flight work bounds | `UNMEASURED` |
| `mining.template` | `mining` | admitted-pool snapshot entry count and bytes | GBT request wall from coherent capture to rendered template | one template job per generation key | coinbase reservation; bounded oversize-chunk subset work budget; bounded long-poll clients | `UNMEASURED` |
| `storage.commit` | `storage`, `chainstate` | batch bytes per durable commit (body append, undo append, coins and head batch) | durable commit from append to `write_durable_if` completion | single ordered writer | physical high-water `<= 1_000_000_000_000` bytes at pinned stop (default lane); logical ledger separate | `UNMEASURED` |
| `index.backfill` | `index` | blocks and body bytes parsed once per aligned capability set | capability watermark advance from prepared batch to atomic row plus watermark commit | one index worker per capability set | `PreparedBatchLimits` rows and bytes; retained-body bound | `UNMEASURED` |

Each cell's interval has exactly one parent. Child intervals inside a parent are reported as inclusive histograms beside it and are never summed to reconstruct the parent. Concurrent intervals in one concurrency group are never summed; the group wall is measured directly.

## Append-only history

Histories are append-only. Each appended record carries the schema version and every identity field. Repeated samples are retained individually; empty or missing cells are retained as `UNMEASURED`, never dropped or averaged away. A record is never edited; a correction is a new record naming the record it supersedes.

## Reuse rule

The only artifacts reused across the T14 authority cutover and the T39 final campaign are this collector, this schema and the matched workload inputs (frozen corpus and order, stop identity, configuration, validation mode and backend, hardware identity, sample protocol). Measurements themselves are regenerated: T14 measures its isolated candidate against the T02 baseline before the cut; T39 measures the final integrated binary against the same frozen T02 baseline. T39 output is never a baseline and never retroactive proof for T14. T14 never depends on T39.

## Baseline capture

Before any production change T02 captures the original existing candidate on every cell above that has an existing I/O surface, using an external harness on those surfaces. A cell with no existing counterpart records `absent counterpart` with a stated reason; that is neither a zero baseline nor a false Boolean. The original candidate's physical high-water on the matched full-tip workload must be captured before T14; if it cannot be, the authority cut stays blocked.

## Gate

```bash
cargo test --locked -p bitcoin-rs --no-default-features --features fjall --test overhaul_evidence -- --nocapture
```

Scenario: reject evidence missing binary, corpus, configuration or durability identity; reject summed nested or concurrent intervals; retain every repeated sample and every empty cell.

## Required identities per sample

Every sample in this cell records six identities. The T02 collector rejects a sample that lacks any of them; a rejected sample is not evidence.

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

## Status

`planned_not_executed`. No end-state cell in this document has run. Every value in the end-state tables is a required contract value, not a measurement. The section `Prior candidate evidence` below is historical and unchanged; it does not prove any end-state cell.
