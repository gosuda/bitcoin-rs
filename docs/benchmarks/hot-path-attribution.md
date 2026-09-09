# Product hot-path attribution

Reading guide for the ledger that issue #39 asked for. The method is
[docs/contracts/hot-path-attribution.md](../contracts/hot-path-attribution.md).
The inventory is [hot-path-ledger.toml](hot-path-ledger.toml). This page
does not copy either, and it does not publish measured seconds.

Prove the ledger:

```
cargo test -p bitcoin-rs --test g18_hot_path_ledger
```

## What the ledger will not do

It will not close a 36-cell residual account from nested
`metrics::histogram!` names, from Criterion microbenchmarks, or from
historical campaign JSON retired by #224. A cell residual is
`unmeasured` until that cell has seven valid bitcoin-rs walls and an
overlap-aware exclusive union. An unobserved noise floor cannot classify
a leftover as small.

## How to add a path

1. Add a row to `hot-path-ledger.toml` with parent, concurrency group,
   domains, seams that exist in this tree, and one of the four
   dispositions.
2. If the row is a disable experiment, it must preserve the product
   posture in `HPA-06`. Otherwise leave `disable_delta` unset so it
   stays `blocked_pending_safe_probe`.
3. A measured wall contribution needs a custody digest in the same row.
4. Run `g18_hot_path_ledger`. Do not add a parallel markdown table.
