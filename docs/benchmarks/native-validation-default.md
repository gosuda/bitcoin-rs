# Native validation default: promotion record

This document is the promotion record for the native strict-Rust validation default. The owner of the default is [`docs/contracts/validation-default.md`](../contracts/validation-default.md), proven by feature-matrix builds, Core vectors, and measured promotion evidence. The end-state decision is recorded here after T16 and T17 run; until then the recorded verdict stays `KeepKernel` and this page states the contract only.

> **Policy superseded (issue #1117).** The manifest policy the recorded
> verdict (`KeepKernel`) answered — "`kernel` is a library default" — no longer
> exists: #1117 moved engine selection to the runtime `validation.engine`
> setting (default `native`) and made `kernel` an opt-in capability feature in
> every manifest. The end-state cells now govern promotion of a **documented
> production default engine** under `VAL-01`'s measured-decision clause, not a
> manifest edit.

## Decision it owns

Whether `bitcoin-rs-consensus`, `bitcoin-rs-chainstate`, `bitcoin-rs-node`,
`bin/bitcoin-rs` and the container image ship strict-Rust validation as their
default. The decision is one coordinated cut across binary, library and image
with matching manifests and packaging. `bitcoinkernel` remains an explicit
opt-in oracle only. It is never a silent fallback and it is never the default
after promotion.

The promotion target moved with #1263: every crate manifest is kernel-free and
`validation.engine` defaults to `native`, while the shipped image selects
`kernel` through `/etc/bitcoin-rs/default.toml`. Promotion below means changing
that documented production selection, not manifest defaults.

## Ordering

1. T16 (strict-Rust cryptography lane) must pass first. The verifier is one general BIP340 operation composed over maintained `k256 0.14.0` arithmetic and ECDSA primitives. The `k256` high-level Schnorr signature type is withdrawn because its `Signature` stores a `NonZeroScalar` and cannot represent the whole BIP340 input domain. No custom field or group arithmetic. Overflowing TapTweak is canonically rejected, never reduced. Hybrid-key parity and historical DER and high-S rules are preserved.
2. T17 then measures the actual final strict artifact. Earlier candidate measurements are not promotion proof.
3. Promotion happens in one changeset: complete the measured end-state cells
   below, change the shipped engine selection (`/etc/bitcoin-rs/default.toml`,
   `Dockerfile`), and prove kernel-free transitive closure with the explicit
   `cargo tree` lane below plus the native profiles in `scripts/ci-pr.sh`.

## End-state cells

| Cell | Required evidence | Command | Status |
|---|---|---|---|
| Core vector parity | Zero mismatches on runnable rows; pinned skip counts and skip reasons per corpus | `cargo test --locked -p bitcoin-rs-script --test core_vectors` | `planned_not_executed` |
| Contextual and script matrix (T15) | Every §5.1 family, active and inactive boundaries, mandatory versus policy flags; zero unexplained mismatches; every exclusion counted and classified | `cargo test --locked -p bitcoin-rs-consensus --test overhaul_consensus_matrix -- --nocapture` | `planned_not_executed` |
| Strict-Rust crypto lane (T16) | Valid and invalid ECDSA, Schnorr and tweak vectors; integer and point boundary cases; independent oracle agreement; audited dependency closure | `cargo test --locked -p bitcoin-rs-script --test overhaul_native_crypto -- --nocapture` | `planned_not_executed` |
| Signed-spend apply (T16, T17) | Native median beats the pinned kernel median by the acceptance rule below, measured on the final strict artifact. Each arm selects its engine explicitly — capability features compile the arm, `BITCOIN_RS_VALIDATION_ENGINE` selects it | Native: `BITCOIN_RS_VALIDATION_ENGINE=native CARGO_TARGET_DIR=target/signed-spend-native cargo bench --locked -p bitcoin-rs-node --bench sync_pipeline --no-default-features --features fjall -- signed_spend --sample-size 30 --warm-up-time 1 --measurement-time 8`<br>Kernel: `BITCOIN_RS_VALIDATION_ENGINE=kernel CARGO_TARGET_DIR=target/signed-spend-kernel cargo bench --locked -p bitcoin-rs-node --bench sync_pipeline --no-default-features --features fjall,kernel -- signed_spend --sample-size 30 --warm-up-time 1 --measurement-time 8` | `planned_not_executed` |
| Full mainnet replay | Genesis to the pinned stop identity with sampled and exact coin comparison against Core `v31.1` | offline comparator, see [`offline-full-validation.md`](offline-full-validation.md) | `planned_not_executed` |
| Invalid and contextual corpora | Rejection parity on invalid local corpora; a passing valid chain alone does not prove rejection | T15 matrix | `planned_not_executed` |
| Kernel-free closure | `cargo tree --locked -p bitcoin-rs --no-default-features --features fjall -e features` shows no `bitcoinkernel` on any transitive path; native and oracle lanes built under separate `CARGO_TARGET_DIR` | `cargo tree --locked -p bitcoin-rs --no-default-features --features fjall -e features` plus the native and kernel `sync_pipeline` lanes above, each under its own `CARGO_TARGET_DIR` | `planned_not_executed` |

Reference identity for the comparison arm: Bitcoin Core release `v31.1`, commit `9be056a8a72b624dae9623b2f7bded92c2a21c91`, x86_64 linux archive SHA-256 `b80d9c3e04da78fb6f0569685673418cf686fadba9042d926d13fb87ff503f9e`, `bitcoind` SHA-256 `986e63b3c8770f08d0059820ad3dd085d1ab9e1bea23946c243f858a06888a08`. The kernel oracle is the `31.99.0` development tree through `bitcoinkernel 0.3.0` with `differential_harness = false`; it is oracle evidence only and never a policy pin.

## Refusal conditions

Promotion is refused when any cell above is `BLOCKED`, when signed-spend evidence is not measured on the final strict artifacts, when either arm exceeds the 5% stability rule, or when a feature-unified workspace build supplied the closure claim. On refusal the last-green `secp256k1` product is retained and the verdict stays `KeepKernel`.

## Required identities per sample

See [`measurement-rules.md`](measurement-rules.md). A sample missing any of the six identities is not evidence.

## Acceptance rule

See [`measurement-rules.md`](measurement-rules.md).

## Status

`planned_not_executed`. No end-state cell in this document has run. Every value in the end-state tables is a required contract value, not a measurement.

PR #1124's chainstate extraction is a structural ownership change, not a
performance-promotion campaign. It carries no baseline-linked before/after
samples for the extracted apply/reorg paths, so the applicable `HPA-13`
promotion and regression cells remain **UNMEASURED**. No latency, RSS, retained-byte,
storage, p99, or throughput non-regression verdict is inferred from functional
tests.
