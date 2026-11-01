# Benchmarks

No benchmark number in this book is a result. At this commit every product performance cell is unmeasured, and every Cmodern cell is blocked on a missing corpus. The benchmark pages own the evidence rules.

## Three evidence tiers

The benchmark work classifies each harness and claim page as end-to-end, partial, or verified. The evidence rules for a sample are in [`docs/benchmarks/README.md`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/benchmarks/README.md).

End-to-end means a whole-node lane over a real corpus or live peers. The offline replay lane builds chainstate from a pinned archive. The live IBD lane runs over loopback peers. The MuHash lane serves a production UTXO query.

Partial means one subsystem or one comparator harness. Fixture runs that prove the harness mechanics belong here even when they execute the production code path.

Verified means a cell whose sample met every identity requirement and passed the acceptance rule. The tier labels a page's scope. It never substitutes for a result.

## Six identities per sample

A sample records six identities. The collector rejects a sample that lacks any of them:

1. The artifact SHA-256 and the source commit.
2. The resolved `NodeConfig`, feature set, allocator, and validation mode.
3. The corpus digest, height range, stop height, and stop hash.
4. The backend, batch mode (`write`, `write_deferred`, or `write_durable`), and flush and sync posture.
5. The toolchain: `rustc 1.99.0`, edition 2024, profile, and features.
6. The hardware: CPU model, pinned cores, memory, storage device, and OS kernel.

The collector is [`crates/node/benches/evidence.rs`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/node/benches/evidence.rs) and [`tools/benchmark-campaign/evidence.py`](https://github.com/gosuda/bitcoin-rs/blob/main/tools/benchmark-campaign/evidence.py). A rejected sample is not evidence.

## The acceptance rule

To promote a candidate over its control, the median gain must be at least 1.05x over at least three alternating candidate and control runs. Each arm must stay within 5 percent of its own median. The improvement must exceed the observed host noise.

Non-target cells guard at no more than 3 percent median regression and 5 percent p99 regression. Reports carry p50, p95, p99, and max with the sample count. Average-only reporting never passes. Nested or concurrent intervals are never summed. Parallel worker walls and inclusive stage histograms sit beside the process wall. Never add them to the process wall. Raw samples stay beside every summary. A Criterion adaptive elapsed total is not a median source.

A fixture ratio near 1.0 is a plumbing check, not a product result. Both arms can be the same program, so the ratio measures harness noise.

## Status vocabulary

`planned_not_executed` means the page ran no end-state cell. Every value in its end-state tables is a required contract value, not a measurement. Its prior candidate evidence is historical and proves no current cell.

`BLOCKED` means a binary, corpus, hardware target, or digest is missing. The cell names the missing identity. `BLOCKED` is never a pass and never a skip.

`Observed once, not evidence` marks a number kept for context. It has no six-identity sample, supports no acceptance verdict, and supports no promotion.

The product ledger has 36 cells, one per domain, corpus, native architecture, and backend. At this commit all 36 cells have `residual = "unmeasured"`, `custody = "none"`, and `noise_floor = "unobserved"`. Every Cmodern cell is `BLOCKED` on the missing archive and manifest. C150 custody is staged, but no Core-versus-bitcoin-rs campaign has run against it. The live IBD arm still has no stop-at-height flag.

The historical C150 ratio in the offline comparator page is not carried forward. A new ratio exists only after a gated result file against a frozen corpus.

## Comparator custody

The shared evidence owner is [`tools/benchmark-campaign/evidence.py`](https://github.com/gosuda/bitcoin-rs/blob/main/tools/benchmark-campaign/evidence.py). Every comparator imports it. A comparator must not restate or replace its guarantees.

The owner defines one canonical byte encoding per value, nearest-rank percentiles with no mean, no-follow file hashing, and a pinned copy that checks the digest before and after. It also defines process start-time identity and atomic publication with a single commit point. A crash before the link leaves the destination unchanged. A retry after the link gets `EEXIST` and never overwrites the committed document.

Read the [comparator custody section](https://github.com/gosuda/bitcoin-rs/blob/main/docs/benchmarks/README.md#comparator-custody) before you quote a comparator result. The properties are the contract, not a suggestion for new controllers.

## Validate or plan without launching a workload

The measured campaign runner separates validation from execution:

```
python3 tools/benchmark-campaign/measured_runner.py validate --registration /abs/path/to/registration.json
python3 tools/benchmark-campaign/measured_runner.py plan --registration /abs/path/to/registration.json
```

`validate` checks the schema, file hashes, CPU affinity, and CPU model without launching anything. `plan` prints the execution schedule after live validation, also without launching a workload. Only `run` launches benchmark child processes, and it refuses unless the registration status is `registered`, the campaign root does not exist, and every static and live check passes.

The offline comparator has its own entry point:

```
python3 tools/benchmark-campaign/offline_full_validation.py --config <config.json> --output <result.json>
```

It refuses to publish a result when the archive, manifest, binary, or certified-state gates fail. A refusal exits 2 and emits no result document.

## What the pages say at this commit

On the end-to-end synchronization page, every cell is `planned_not_executed` or `BLOCKED`. Its Cmodern offline row is `BLOCKED` on the missing corpus. Its live IBD loopback rows have not run.

The offline full-validation page says CI proves the harness with fixture nodes only. It does not claim a live C150 or Cmodern campaign.

The measured campaign page is `planned_not_executed`. Packaging the harness and passing the synthetic probe is not a baseline or an acceptance.

Fixture stability and capability audits fill the product-cell comparator page. It states that no Core-versus-bitcoin-rs campaign ran and that the fixture figures fill no ledger cell.

Quote a benchmark number only with its identity row and its evidence page link. When a page says `BLOCKED`, write `BLOCKED`. When a page says `planned_not_executed`, do not turn a contract value into a measurement.

Owner: [`docs/benchmarks/README.md`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/benchmarks/README.md). Next: [Verification](verification.md) covers the test and proof layers, and [Build and test](../contribute/build-and-test.md) covers the gates that compile a benchmark target.
