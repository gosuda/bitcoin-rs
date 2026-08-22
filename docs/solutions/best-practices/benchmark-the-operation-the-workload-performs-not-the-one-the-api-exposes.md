---
title: Benchmark the operation the workload performs, not the one the API exposes — a codec that won on encode/decode lost 4.9x on the call the node actually makes
date: 2026-08-17
category: docs/solutions/best-practices
module: performance measurement / UTXO record codec (crates/utxo)
problem_type: best_practice
component: tooling
severity: high
applies_when:
  - "Benchmarking a data-structure or codec change behind an accessor API"
  - "Choosing between a fixed-width and a variable-length in-memory layout"
  - "Quoting a speedup ratio measured on one fixture size"
related_components:
  - development_workflow
  - testing_framework
tags:
  - benchmark
  - paired-arm
  - codec
  - measurement-discipline
---

## What happened

The UTXO record payload was re-encoded to save memory. The refactor set required
a paired benchmark, and it had one: `encode` and `decode` of a whole record, v4
against v5, both arms in one Criterion group over one fixture. v5 was slower on
both, by 1.9-3.2x, and two rounds of optimization went into closing that gap.

Both the benchmark and the optimization were aimed at the wrong thing.

The operation the node performs is **`find_output(vout)`** — every spent input
resolves one output by index through `Shard::get`, `get_entry` or `get_meta`,
and all three land there. Whole-record decode is the snapshot and rescan path,
which is rare by comparison. Reshaped around `find_output`, the same v5 codec
measured **4.4-4.9x slower**, not 1.9x. The change was far worse than the
harness had been reporting, and no amount of tuning the encode path would have
found it.

## Why the wrong benchmark looked reasonable

`encode` and `decode` are what the codec module exposes. They are the natural
unit to benchmark if you are looking at the codec. `find_output` lives one layer
up, in the record type, and reads like a convenience wrapper over the decoder —
which is exactly what it was, and exactly why it was slow: it decoded every
output it rejected.

The tell was available and was not read: the codec is `pub(crate)`, and the only
callers outside its own tests were three `Shard` methods, all doing the same
by-index lookup. **The call sites were the benchmark specification.**

## The second-order finding

Once `find_output` was benchmarked, the cause was not what it appeared:

> Every v4 field sits at a constant offset, so when only `vout` is read the
> optimizer deletes the loads for the rest. v4 got lazy field skipping for free
> from LLVM, without anyone designing it. A variable-length layout cannot be
> given the same treatment, because each field's length is what locates the
> next, so the reads are a serial dependency chain no optimizer can remove.

The fixed-width arm was not merely faster — it was benefiting from an
optimization the variable-length arm is structurally unable to receive. That is
a property of the layout choice, not of the implementation, and it is invisible
in a benchmark that consumes every field.

The fix was a layout change (fixed-width directories in front of the payloads),
not a tuning pass.

## One fixture size hides a crossover in both directions

The corrected harness ran 1, 4 and 16 outputs per record. The real-workload
benchmark, `utxo_commit`, used a fixture with **256**. They disagreed, and both
were quoted as if general:

| outputs | `find_output/miss` v4 | v5 | ratio |
|---:|---:|---:|---:|
| 1 | 2.6 ns | 7.6 ns | 0.35x |
| 3.626 (measured mainnet average) | 3.9 ns | 6.9 ns | 0.57x |
| 16 | 16.6 ns | 20.7 ns | 0.80x |
| 64 | 108.4 ns | 78.7 ns | **1.38x** |
| 256 | 462.1 ns | 294.1 ns | **1.57x** |

Benchmarking only small sizes hid the crossover one way; quoting only the large
fixture hid it the other. The claim shipped as "makes lookups faster than v4",
which was **true of the fixture and false of the workload** — the measured
mainnet average is 3.626 outputs per record, where v5 is slower.

## Rules

1. **Enumerate the call sites before writing the harness.** For a `pub(crate)`
   API that is a grep, and it is the specification. Benchmark what calls it, not
   what it exports.
2. **Bracket the workload's real parameter, and put the workload's own value in
   the table.** One fixture size cannot show a crossover, and a crossover is the
   normal outcome when a change trades fixed cost for per-item cost.
3. **Suspect the arm that looks impossibly fast.** v4's best case measured 2.1 ns
   and did not move with record size; that was the optimizer eliminating work,
   which is real but tells you the arms are not doing comparable work.
4. **When two harnesses disagree, publish the conservative one and say why.**
   `utxo_commit` reported 2.35x and the microbenchmark 1.58x on the same shape,
   because the microbenchmark reimplements the `before` arm as a direct loop the
   optimizer handles better — so its v4 arm is *faster than the shipped v4*. The
   smaller number is the one that survives scrutiny.

## Related

- `docs/solutions/best-practices/small-window-benchmarks-do-not-predict-at-scale-throughput.md`
  — the same failure in the size dimension rather than the operation dimension.
- `docs/solutions/best-practices/criterion-bench-trust-rebuild-drift-baselines-allocator.md`
  — why both arms belong in one group in one run.
- `docs/benchmarks/utxo-memory.md` — the campaign this came from, including the
  correction notice.
- The *Directory-layout record* and *Work-count assertion* entries in
  `CONCEPTS.md`.
