# Native validation default: promotion record

This page records the pending gates for a strict-Rust production validation
engine. The current default is owned by the
[validation-default contract](../contracts/validation-default.md). Current
native verification uses `secp256k1` for ECDSA, Schnorr and Taproot tweaks
(`crates/script/src/checker.rs` and `taproot.rs`); it is not the proposed
strict-Rust cryptography implementation. The historical `KeepKernel` verdict
below does not describe today's manifest defaults or qualify the pending gates.

Implementation and command availability below describe the #1703 checkout,
not every unmerged branch. The strict-Rust qualification gaps are separate
from the window attribution spans and harness implemented in
[#1701](https://github.com/gosuda/bitcoin-rs/pull/1701); see
[their branch-specific status](window-pipeline-attribution.md).

> **Policy superseded (issue #1117).** The manifest policy this page's recorded
> verdict (`KeepKernel`) answered — "`kernel` is a library default" — no longer
> exists: #1117 moved engine selection to the runtime `validation.engine`
> setting (default `native`) and made `kernel` an opt-in capability feature in
> every manifest. The verdict below is historical (it records which engine the
> 2026-09-04 measurements preferred) and does not describe today's defaults.
> The end-state cells now govern promotion of a **documented production default
> engine** under `VAL-01`'s measured-decision clause, not a manifest edit.

## Decision it owns

Whether the documented production default engine is strict-Rust validation.
Every crate manifest is already kernel-free and `validation.engine` already
defaults to `native`; the shipped image selects `kernel` through
`/etc/bitcoin-rs/default.toml`. Promotion below means changing that documented
production selection, not manifest defaults. `bitcoinkernel` remains an explicit
opt-in oracle only. It is never a silent fallback and it is never the default
after promotion.

## Ordering

1. Implement and independently qualify the strict-Rust cryptography path before
   measuring it. No `k256` verifier or dedicated strict-Rust crypto test target
   exists in the current tree. Qualification must cover valid and invalid ECDSA,
   Schnorr and tweak inputs, integer and point boundaries, historical encoding
   rules and the dependency closure. The current regression suites below do not
   establish that missing implementation or its qualification.
2. Measure the final qualified artifact. Earlier candidate measurements,
   including every number in the prior-evidence section, are not promotion proof.
3. Promotion happens in one changeset: complete the measured end-state cells
   below, change the shipped engine selection (`/etc/bitcoin-rs/default.toml`,
   `Dockerfile`), and prove kernel-free transitive closure with the explicit
   `cargo tree` lane below plus the native profiles in `scripts/ci-pr.sh`.

## End-state cells

| Cell | Required evidence | Command | Status |
|---|---|---|---|
| Core vector parity | Zero mismatches on runnable rows; pinned skip counts and skip reasons per corpus | `cargo test --locked -p bitcoin-rs-script --test core_vectors` | `planned_not_executed` |
| Contextual and script qualification | Active/inactive boundaries and mandatory/policy flags; zero unexplained mismatches; exclusions counted and classified | No consolidated promotion matrix exists. Current regression commands are listed below; they do not establish complete qualification coverage. | `BLOCKED`: missing qualification matrix and coverage accounting |
| Strict-Rust crypto qualification | Valid/invalid signatures and tweaks, integer/point boundaries, independent oracle agreement and audited dependency closure | No strict-Rust implementation or dedicated qualification target exists. | `BLOCKED`: missing implementation and qualification suite |
| Signed-spend apply | Native median beats the pinned kernel median by the acceptance rule below, measured on the final strict artifact. Each arm selects its engine explicitly. | Diagnostic commands below exercise the current engines. | `BLOCKED`: final strict-Rust artifact unavailable |
| Full mainnet replay | Genesis to the pinned stop identity with sampled and exact coin comparison against Core `v31.1` | offline comparator, see [`offline-full-validation.md`](offline-full-validation.md) | `planned_not_executed` |
| Invalid and contextual corpora | Rejection parity on invalid local corpora; a passing valid chain alone does not prove rejection | Core vectors exercise runnable rejection rows; promotion still needs the qualification matrix and exclusion accounting. | `BLOCKED`: missing qualification matrix |
| Kernel-free closure | `cargo tree --locked -p bitcoin-rs --no-default-features --features fjall -e features` shows no `bitcoinkernel` on any transitive path; native and oracle lanes built under separate `CARGO_TARGET_DIR` | `cargo tree --locked -p bitcoin-rs --no-default-features --features fjall -e features` plus the native and kernel `sync_pipeline` commands below, each under its own `CARGO_TARGET_DIR` | `planned_not_executed` |

Reference identity for the comparison arm: Bitcoin Core release `v31.1`, commit `9be056a8a72b624dae9623b2f7bded92c2a21c91`, x86_64 linux archive SHA-256 `b80d9c3e04da78fb6f0569685673418cf686fadba9042d926d13fb87ff503f9e`, `bitcoind` SHA-256 `986e63b3c8770f08d0059820ad3dd085d1ab9e1bea23946c243f858a06888a08`. The kernel oracle is the `31.99.0` development tree through `bitcoinkernel 0.3.0` with `differential_harness = false`; it is oracle evidence only and never a policy pin.

## Current regression and diagnostic commands

These targets exercise the existing `secp256k1`-backed native engine. A pass is
evidence for their covered behavior, not strict-Rust promotion or full-mainnet
qualification. The validation contract owns the detailed proof map.

```sh
# Native Core-vector verdicts, including invalid rows and skip accounting
cargo test --locked -p bitcoin-rs-script --test core_vectors
# Signed witness/input boundaries and signature encoding/error order
cargo test --locked -p bitcoin-rs-script --test verifier_boundaries --test taproot_spend_rules --test ecdsa_encoding_order --test segwit_v0_sighash_edges
# Missing/duplicate inputs, block facts, witness activation and commitments
cargo test --locked -p bitcoin-rs-consensus --no-default-features --test overhaul_prepared_inputs --test overhaul_parse_parity --test witness_sigop_activation --test witness_commitment_rules
```

The existing signed-spend diagnostic compares current engines. Build each arm
separately and retain the identities and raw samples required by
[the benchmark rules](README.md). The `kernel` feature compiles capability;
`BITCOIN_RS_VALIDATION_ENGINE` selects the measured engine.

```sh
BITCOIN_RS_VALIDATION_ENGINE=native CARGO_TARGET_DIR=target/signed-spend-native cargo bench --locked -p bitcoin-rs-node --bench sync_pipeline --no-default-features --features fjall -- signed_spend --sample-size 30 --warm-up-time 1 --measurement-time 8
BITCOIN_RS_VALIDATION_ENGINE=kernel CARGO_TARGET_DIR=target/signed-spend-kernel cargo bench --locked -p bitcoin-rs-node --bench sync_pipeline --no-default-features --features fjall,kernel -- signed_spend --sample-size 30 --warm-up-time 1 --measurement-time 8
```

These commands measure the current artifact; rerun against a qualified final
strict-Rust artifact before using them for the pending promotion decision.

## Refusal conditions

Promotion is refused when any cell above is `BLOCKED`, when signed-spend evidence is not measured on the final strict artifacts, when either arm exceeds the 5% stability rule, or when a feature-unified workspace build supplied the closure claim. On refusal the last-green `secp256k1` product is retained and the documented production selection is unchanged.

## Required identities per sample

The six identities of [`README.md`](README.md), enforced by the T02 collector.

## Acceptance rule

The promotion, regression, reporting, retention and `BLOCKED` rules of [`README.md`](README.md).


## Status

No end-state campaign has run under this protocol. Cells without an available
implementation or qualification suite are `BLOCKED`; the remaining unexecuted
cells stay `planned_not_executed`, as defined in [`README.md`](README.md).

PR #1124's chainstate extraction is a structural ownership change, not a
performance-promotion campaign. It carries no baseline-linked before/after
samples for the extracted apply/reorg paths, so the applicable `HPA-13`
promotion and regression cells remain **UNMEASURED**. No latency, RSS, retained-byte,
storage, p99, or throughput non-regression verdict is inferred from functional
tests or from the historical September 4 signed-spend run.

## Prior candidate evidence (2026-09-04 signed-spend run and earlier)

Retained verbatim from the pre-rewrite document. Headings are demoted one level. Nothing below is end-state proof.

This note records the #213 measurements. The owner of the default is
[`docs/contracts/validation-default.md`](../contracts/validation-default.md),
proven by `g19_validation_default`. Numbers from a named run live in
`docs/benchmarks/data/`.

A **measured observation** copies a field from a cited artifact or an
in-tree test pin. An **inference** interprets those observations. Promotion
requires every gate in the issue, not a subset.

### Historical decision (superseded)

Keep `kernel` as the `bitcoin-rs-consensus` and `bitcoin-rs-node` default,
and in the Compose image. Leave `bin/bitcoin-rs` kernel-free. The native
interpreter is a complete consensus script engine; it is not yet the
measured winner. Recorded verdict: `KeepKernel`.

### Decision rule (issue #213)

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

### Historical ownership of the default (superseded)

| Surface | Script engine |
|---|---|
| `bin/bitcoin-rs` default features (`fjall,redb,zmq`) | Native interpreter |
| `bitcoin-rs-consensus` / `bitcoin-rs-node` crate defaults | `kernel` (`libbitcoinkernel`) |
| Compose image (`Dockerfile --features fjall,kernel`) | `kernel` |

> Historical 2026-09-04 plan (superseded): coordinated manifest cut described here; current promotion changes the shipped image selection, not manifest defaults.

### Measured observations

#### Correctness (in-tree Core vectors)

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

#### Performance, signed-spend apply-path (2026-09-04)

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

#### Attributed lever

Production CHECKSIG, Schnorr, and Taproot tweak checks constructed
`Secp256k1::verification_only()` per signature. That rebuilds secp256k1's
verification tables on every input. Those paths now share
`secp256k1::SECP256K1`, which `batch.rs` and `taproot::verify_taproot_keypath`
already used.

#### Peak RSS

Profile-time child rusage: native 14.3 MiB, kernel 15.6 MiB. Allocation
count is not reported by this harness.

### Disposition

| Gate | Status |
|---|---|
| Core vector parity (available corpus) | Pass (zero pinned native mismatches; skip counts and reasons pinned) |
| Signed-spend native faster, stable medians | Fail (stable; native 9.2% slower on apply p50) |
| Full-mainnet replay | Blocked on #34 (#42 corpus freeze is done) |
| Recorded verdict | `KeepKernel` |
