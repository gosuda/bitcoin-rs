# Native validation default (issue #213)

This note records the #213 measurements. The owner of the default is
[`docs/contracts/validation-default.md`](../contracts/validation-default.md),
proven by `g19_validation_default`. Numbers from a named run live in
`docs/benchmarks/data/`.

A **measured observation** copies a field from a cited artifact or an
in-tree test pin. An **inference** interprets those observations. Promotion
requires every gate in the issue, not a subset.

## Decision

Keep `kernel` as the `bitcoin-rs-consensus` and `bitcoin-rs-node` default,
and in the Compose image. Leave `bin/bitcoin-rs` kernel-free. The native
interpreter is a complete consensus script engine; it is not yet the
measured winner. Recorded verdict: `KeepKernel`.

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

The signed-spend Criterion target times `NodeState::apply_block`. Keep it
for engine diagnostics. It is not a daemon, P2P, or CLI wall. The named
end-to-end wall is the offline full-validation corpus and full-mainnet
replay versus Bitcoin Core. That cell remains blocked on #34 (no in-tree
`bitcoind` comparator run). #42 froze the C150/Cmodern corpus contracts;
that freeze does not run the comparator. A missing replay does not weaken
the signed-spend or vector gates. A failed signed-spend measurement does
not flip the default.

## Current ownership of the default

| Surface | Script engine |
|---|---|
| `bin/bitcoin-rs` default features (`fjall,redb,zmq`) | Native interpreter |
| `bitcoin-rs-consensus` / `bitcoin-rs-node` crate defaults | `kernel` (`libbitcoinkernel`) |
| Compose image (`Dockerfile --features fjall,kernel`) | `kernel` |

Until the gates pass, the library crates and the image keep `kernel`. The
binary already builds native so a default `cargo build -p bitcoin-rs` needs
no C++ toolchain. Promoting native is one coordinated change: flip
`RECORDED_VERDICT` in `g19_validation_default` and drop `kernel` from the
two library defaults in the same commit.

## Measured observations

### Correctness (in-tree Core vectors)

`crates/script/tests/core_vectors.rs` pins

```text
NATIVE_SCRIPT_TESTS_FAILURES = 0
NATIVE_TX_VALID_FAILURES = 0
NATIVE_TX_INVALID_FAILURES = 0
```

Those columns feed Core's `script_tests.json`, `tx_valid.json`, and
`tx_invalid.json` through `Interpreter`. The recorded gate is zero
mismatches on runnable rows, a pinned skip count per corpus, **and** a
skip-reason allow-list: `script_tests` may skip only one-string
prose/section headers (55), `tx_valid` skips nothing, and `tx_invalid` may
skip only `BADTX` parse-stage rows (9). A new skip category cannot shrink
coverage while staying green.

Kernel-vs-interpreter fixture parity lives in
`crates/consensus/tests/kernel_block_parity.rs`: the committed differential
is currently Taproot key-path, script-path has a separate non-vacuity
check, and legacy, P2SH, bare multisig, and `SegWit` v0 fixtures are
kernel-only in that harness. Native coverage for every class is
established by the Core-vector lane.

The earlier stub (`verify_non_taproot_portable`, bare `OP_TRUE` only) is
gone.

### Performance, signed-spend apply-path (2026-09-04)

This is the in-tree apply-path comparison: `NodeState::apply_block` over a
generated signed-spend corpus (P2PKH, P2WPKH, P2WSH 2-of-3, real ECDSA).

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

The 2026-09-02 artifact
([`data/overhaul-signed-spend-20260902.md`](data/overhaul-signed-spend-20260902.md))
was a different host (80-core Xeon Gold 6138) and is not a paired control
for these numbers. On that host native apply p50 was 486–639 ms; the
context reuse is why this host sits near 50 ms, not a claim that the two
hosts are comparable. The vacuous `OP_TRUE` apply-path numbers do not
license promotion: that corpus verifies no signatures.

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
| Core vector parity (available corpus) | Pass (zero pinned native mismatches; skip counts and reasons pinned) |
| Signed-spend native faster, stable medians | Fail (stable; native 9.2% slower on apply p50) |
| Full-mainnet replay | Blocked on #34 (#42 corpus freeze is done) |
| Recorded verdict | `KeepKernel` |
