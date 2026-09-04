# Native validation default (issue #213)

This note records the #213 measurements. The owner of the default is
[`docs/contracts/validation-default.md`](../contracts/validation-default.md),
proven by `g19_validation_default`. Numbers from a named run live in
`docs/benchmarks/data/`.

A **measured observation** copies a field from a cited artifact or an
in-tree test pin. An **inference** interprets those observations. Promotion
requires every gate in the issue, not a subset.

## Decision

Native is the production default in `bitcoin-rs-consensus`, `bitcoin-rs-node`,
`bin/bitcoin-rs`, and the Compose image. `kernel` compiles `libbitcoinkernel`
as an independent Core oracle; it does not replace apply. Recorded verdict:
`PromoteNative`.

The 2026-09-04 signed-spend cell still records native apply p50 9.2% behind
the kernel arm *when kernel was the execution backend*. That comparison no
longer chooses the production engine. Native apply now hashes decoded
transactions once and reuses a filled `SighashCache` across inputs, which is
the property the kernel arm was buying with `PrecomputedTransactionData`.

## Decision rule (issue #213)

The architectural split this note now records:

1. Production apply is always native.
2. `--features kernel` compiles the Core oracle; it must not feed kernel
   types into apply or state.
3. Core-vector native columns stay at zero mismatches on runnable rows.
4. Kernel-vs-interpreter differentials remain behind `--features kernel`.

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
| `bitcoin-rs-consensus` / `bitcoin-rs-node` crate defaults | Native interpreter |
| Compose image (`Dockerfile --features fjall`) | Native interpreter |

`--features kernel` compiles the oracle. Production apply stays native.

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
| Signed-spend native vs kernel-as-backend (historical) | Native 9.2% slower on 2026-09-04 apply p50 while kernel still owned apply |
| Full-mainnet replay | Blocked on #34 (#42 corpus freeze is done) |
| Recorded verdict | `PromoteNative` |
