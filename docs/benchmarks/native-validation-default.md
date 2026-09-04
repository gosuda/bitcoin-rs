# Native validation default

This page owns the #213 decision: whether the native Rust interpreter becomes
the default script engine in `bitcoin-rs-consensus` and `bitcoin-rs-node`.
Numbers from a named run live in `docs/benchmarks/data/`; this page records
the disposition those numbers license.

A **measured observation** copies a field or result from a cited artifact or
from an in-tree test pin. An **inference** interprets those observations.

## Decision rule (issue #213)

The native path becomes the library default only after:

1. Identities for both arms are pinned (source, compiler, features, corpus,
   machine, binary).
2. Every verdict on the available consensus corpus matches Bitcoin Core.
3. The signed-spend harness reports p50 / p95 / p99 / max, with at least
   three independent-run medians, and both arms stay within five percent of
   their own median.
4. The native median is faster than the pinned kernel median.
5. Changed validation boundaries pass the in-tree test and clippy gates.

Full-mainnet replay remains blocked on #34 and #42 (no frozen C150/Cmodern
corpus and no in-tree `bitcoind` comparator run). A missing replay does not
weaken the signed-spend or vector gates. A failed signed-spend measurement
does not flip the default.

## Current ownership of the default

| Surface | Script engine |
|---|---|
| `bin/bitcoin-rs` default features (`fjall,redb,zmq`) | Native interpreter |
| `bitcoin-rs-consensus` / `bitcoin-rs-node` crate defaults | `kernel` (`libbitcoinkernel`) |
| Compose image (`Dockerfile --features fjall,kernel`) | `kernel` |

One owner is the point of #213. Until the gates pass, the library crates and
the image keep `kernel`. The binary already builds native so a default
`cargo build -p bitcoin-rs` needs no C++ toolchain.

## Measured observations

### Correctness (in-tree Core vectors)

`crates/script/tests/core_vectors.rs` pins:

| Corpus | Native mismatch pin |
|---|---:|
| `script_tests.json` | 0 |
| `tx_valid.json` | 0 |
| `tx_invalid.json` | 0 |

The native interpreter executes legacy, P2SH, SegWit v0, and Taproot
key-path and script-path spends. The earlier stub that accepted only
`OP_TRUE` is gone.

### Performance, signed-spend proxy (2026-09-04)

Artifact: [`data/overhaul-signed-spend-20260904.md`](data/overhaul-signed-spend-20260904.md).
Commit `0299e677`, rustc 1.95.0, 4-CPU Xeon, Linux 6.12.94+. Corpus: same
117-block signed-spend proxy as the 2026-09-02 pre-change baseline. Three
independent runs per arm after the `secp256k1::SECP256K1` reuse.

| Arm | Median of apply p50s | Run-median spread |
|---|---:|---:|
| Native (`fjall`) | 50.014 ms | 0.58% |
| Kernel (`fjall,kernel`) | 45.784 ms | 1.82% |

Both arms stay within five percent of their own median. Native / kernel =
1.092. Native does not win.

The 2026-09-02 artifact was a different host (80-core Xeon Gold 6138) and
is not a paired control for these numbers. On that host native apply p50
was 486–639 ms; the context reuse is why this host sits near 50 ms, not a
claim that the two hosts are comparable.

### Attributed lever

Production CHECKSIG, Schnorr, and Taproot tweak checks constructed
`Secp256k1::verification_only()` per signature. That rebuilds secp256k1's
verification tables on every input. Those paths now share
`secp256k1::SECP256K1`, which `batch.rs` and `taproot::verify_taproot_keypath`
already used.

### Peak RSS

Profile-time child rusage: native 14.3 MiB, kernel 15.6 MiB. Allocation
count is not reported by this harness.

## Disposition

| Gate | Status |
|---|---|
| Core vector parity (available corpus) | Pass (zero pinned native mismatches) |
| Signed-spend native faster, stable medians | Fail (stable; native 9.2% slower on apply p50) |
| Full-mainnet replay | Blocked on #34 / #42 |
| Library / image default | Keep `kernel` |
