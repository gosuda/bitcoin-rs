# Product hot-path attribution

Reading guide for the product hot-path ledger. The method is [`docs/contracts/hot-path-attribution.md`](../contracts/hot-path-attribution.md). The inventory is [`hot-path-ledger.toml`](hot-path-ledger.toml), parsed by `bin/bitcoin-rs/tests/gates/g18_hot_path_ledger.rs`. This page copies neither and publishes no measured seconds.

Prove the ledger:

```bash
cargo test --locked -p bitcoin-rs --no-default-features --features fjall --test g18_hot_path_ledger
```

## The frozen 36-cell denominator

The ledger matrix is three domains (`offline`, `p2p`, `muhash`) by two corpora (`c150`, `cmodern`) by two architectures (`x86_64`, `arm64`) by three backends (`fjall`, `rocksdb`, `redb`): 36 cells. Each cell's residual is `unmeasured` until it has seven valid bitcoin-rs walls and an overlap-aware exclusive union. The 48 `[[paths]]` rows name owners, parents, concurrency groups and dispositions inside those cells. This denominator is frozen: T02 does not renumber or delete a cell.

## T02 extension

T02 extends the ledger, in the same TOML and the same schema discipline, with the live lanes BLUEPRINT §14.1 requires: live admission, block propagation, API queries, index backfill and mining. The cell definitions, identities and reuse rule live in [`overhaul-product-cells.md`](overhaul-product-cells.md) under schema `bitcoin-rs-product-cells-v1`. Each new entry names an owner, input count and bytes, interval parent, concurrency group, resource budget and evidence status, exactly as the existing entries do. Every new cell starts `unmeasured`. The TOML change is T02's; this page describes it and does not perform it.

## What the ledger will not do

It will not close a residual from nested `metrics::histogram!` names, from Criterion microbenchmarks, or from historical campaign JSON retired by #224. An unobserved noise floor cannot classify a leftover as small. Parallel worker walls are never added to obtain the process wall; inclusive stage histograms are never added to nested children. Amdahl's bound `speedup <= 1 / ((1-f) + f/s)` is a sanity check on the maximum benefit of accelerating a measured fraction `f` by `s`; `f` is measured, never assumed.

## How to add a path

1. Add a row to `hot-path-ledger.toml` with parent, concurrency group, domains, seams that exist in this tree, and one of the four dispositions.
2. If the row is a disable experiment, it must preserve the product posture in `HPA-06`. Otherwise leave `disable_delta` unset so it stays `blocked_pending_safe_probe`.
3. A measured wall contribution needs a custody digest in the same row carrying the six sample identities (artifact, configuration, corpus, durability, toolchain, hardware).
4. Run `g18_hot_path_ledger`. Do not add a parallel markdown table.

## Status

`planned_not_executed` for every T02 extension cell. Existing ledger cells keep their recorded `unmeasured` residuals.
