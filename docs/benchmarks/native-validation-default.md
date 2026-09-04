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

### Performance, signed-spend proxy (pre-change baseline, 2026-09-02)

Artifact: [`data/overhaul-signed-spend-20260902.md`](data/overhaul-signed-spend-20260902.md).
This is the two-run pre-change baseline only; it is not the required post-change
three-run decision measurement. Host: Intel Xeon Gold 6138. Corpus: 117-block
regtest skeleton, 16 spend blocks, P2PKH / P2WPKH / P2WSH 2-of-3.

| Arm | Run 1 Criterion median | Run 2 Criterion median |
|---|---:|---:|
| Native (`fjall`) | 588.24 ms | 819.31 ms |
| Kernel (`fjall,kernel`) | 532.21 ms | 616.60 ms |

Native was slower on both runs. Neither arm stayed within five percent of
its own independent-run median, so the comparison did not count under the
#213 stability rule.

### Attributed lever

Production CHECKSIG / Schnorr / Taproot tweak checks constructed
`Secp256k1::verification_only()` per signature. That rebuilds secp256k1's
verification tables on every input. `crates/script/src/batch.rs` and
`taproot::verify_taproot_keypath` already used the process-wide
`secp256k1::SECP256K1` context. This change makes the remaining production
paths use that same context.

## Disposition

| Gate | Status |
|---|---|
| Core vector parity (available corpus) | Pass (zero pinned native mismatches) |
| Signed-spend native faster, stable medians | Insufficient evidence: the 2026-09-02 artifact is a two-run pre-change baseline; three post-change runs per arm are pending |
| Full-mainnet replay | Blocked on #34 / #42 |
| Library / image default | Keep `kernel` until signed-spend passes |

Do not flip `crates/consensus` or `crates/node` defaults on this page's
current evidence. Re-run:

```sh
cargo bench -p bitcoin-rs-node --bench sync_pipeline \
  --no-default-features --features fjall -- signed_spend
cargo bench -p bitcoin-rs-node --bench sync_pipeline \
  --no-default-features --features fjall,kernel -- signed_spend
```

Three independent runs per arm. Record p50 / p95 / p99 / max under
`docs/benchmarks/data/` and update the disposition table here. Flip the
library defaults only when that artifact shows a stable native win.
