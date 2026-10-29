# Native validation default: promotion record

This page records the pending gates for a strict-Rust production validation engine. The current default is owned by the [validation-default contract](../contracts/validation-default.md). Current native verification uses `secp256k1` for ECDSA, Schnorr and Taproot tweaks (`crates/script/src/checker.rs`, `taproot.rs`); it is not the proposed strict-Rust implementation. The historical `KeepKernel` verdict below does not describe today's defaults or qualify the pending gates. Command availability below describes the #1703 checkout; strict-Rust gaps are separate from the window spans of [#1701](https://github.com/gosuda/bitcoin-rs/pull/1701) ([branch status](window-pipeline-attribution.md)).

> Policy superseded (issue #1117): the manifest policy this page's recorded verdict answered is gone; #1117 moved engine selection to runtime `validation.engine` (default `native`) and made `kernel` an opt-in capability feature in every manifest. The verdict below is historical (2026-09-04 preferred engine), not today's default. End-state cells now govern promotion of a documented production default engine under `VAL-01`'s measured-decision clause.

## Decision it owns

Whether the documented production default engine is strict-Rust validation. Every manifest is already kernel-free and `validation.engine` already defaults to `native`; the shipped image selects `kernel` via `/etc/bitcoin-rs/default.toml`. Promotion below changes that documented production selection, not manifest defaults. `bitcoinkernel` remains an explicit opt-in oracle only; it is NEVER a silent fallback and NEVER the default after promotion.

## Ordering

1. Implement and independently qualify the strict-Rust cryptography path (valid/invalid ECDSA, Schnorr, tweaks; integer/point boundaries; encoding rules; dependency closure) before measuring it (no `k256` verifier or dedicated target exists yet; current regressions do not establish it). 2. Measure the final qualified artifact; earlier numbers are not promotion proof. 3. Promote in one changeset: complete the cells below, change the shipped selection (`/etc/bitcoin-rs/default.toml`, `Dockerfile`), prove kernel-free closure with the `cargo tree` lane below plus native profiles in `scripts/ci-pr.sh`.

## End-state cells

| Cell | Required evidence | Command | Status |
|---|---|---|---|
| Core vector parity | zero mismatches on runnable rows; pinned skip counts + reasons | `cargo test --locked -p bitcoin-rs-script --test core_vectors` | `planned_not_executed` |
| Contextual/script qualification | active/inactive boundaries, mandatory/policy flags; zero unexplained mismatches; exclusions counted/classified | regression commands below (no consolidated matrix) | `BLOCKED` |
| Strict-Rust crypto qualification | valid/invalid signatures/tweaks, boundaries, oracle agreement, audited closure | none exists | `BLOCKED` |
| Signed-spend apply | native median beats pinned kernel median per acceptance rule, on final strict artifact, engines explicit | diagnostic commands below | `BLOCKED` |
| Full mainnet replay | genesis to pinned stop vs Core `v31.1`, sampled + exact coin comparison | offline comparator ([`offline-full-validation.md`](offline-full-validation.md)) | `planned_not_executed` |
| Invalid/contextual corpora | rejection parity on invalid local corpora | Core vectors + qualification matrix | `BLOCKED` |
| Kernel-free closure | `cargo tree -e features` shows no `bitcoinkernel` transitively; lanes under separate `CARGO_TARGET_DIR` | `cargo tree --locked -p bitcoin-rs --no-default-features --features fjall -e features` + native/kernel `sync_pipeline` below | `planned_not_executed` |

Reference arm: Bitcoin Core `v31.1`, commit `9be056a8a72b624dae9623b2f7bded92c2a21c91`, x86_64 linux archive SHA-256 `b80d9c3e04da78fb6f0569685673418cf686fadba9042d926d13fb87ff503f9e`, `bitcoind` SHA-256 `986e63b3c8770f08d0059820ad3dd085d1ab9e1bea23946c243f858a06888a08`. Kernel oracle: `31.99.0` tree via `bitcoinkernel 0.3.0`, `differential_harness = false`; oracle evidence only, never a policy pin.
```sh
cargo test --locked -p bitcoin-rs-script --test core_vectors
BITCOIN_RS_VALIDATION_ENGINE=native CARGO_TARGET_DIR=target/signed-spend-native cargo bench --locked -p bitcoin-rs-node --bench sync_pipeline --no-default-features --features fjall -- signed_spend --sample-size 30 --warm-up-time 1 --measurement-time 8
BITCOIN_RS_VALIDATION_ENGINE=kernel CARGO_TARGET_DIR=target/signed-spend-kernel cargo bench --locked -p bitcoin-rs-node --bench sync_pipeline --no-default-features --features fjall,kernel -- signed_spend --sample-size 30 --warm-up-time 1 --measurement-time 8
```
Regression targets above exercise the existing `secp256k1`-backed native engine per [`README.md`](README.md); a pass is evidence for covered behavior only, NOT strict-Rust promotion or full-mainnet qualification. The `kernel` feature compiles capability; `BITCOIN_RS_VALIDATION_ENGINE` selects the measured engine; rerun on the qualified final strict artifact before any promotion decision.

Promotion is REFUSED when any cell is `BLOCKED`, signed-spend evidence is not on the final strict artifacts, either arm exceeds the 5% stability rule, or a feature-unified workspace build supplied the closure claim; on refusal the last-green `secp256k1` product is retained and the documented production selection is unchanged. Identities: six of [`README.md`](README.md) via T02 collector. Acceptance: promotion/regression/reporting/retention/`BLOCKED` rules of [`README.md`](README.md). Status: no end-state campaign run; missing-implementation cells `BLOCKED`, rest `planned_not_executed`. PR #1124 chainstate extraction is structural, carries no baseline-linked samples, leaves `HPA-13` cells UNMEASURED.

## Prior candidate evidence (2026-09-04 signed-spend run and earlier)

Prior text, not end-state proof. Records #213; default owner [`docs/contracts/validation-default.md`](../contracts/validation-default.md) via `g19_validation_default`; named-run numbers in `docs/benchmarks/data/`. A measured observation copies a cited artifact/pin; an inference interprets it. Promotion requires every gate in the issue.

| Arm | Median of apply p50s | Run-median spread |
|---|---|---:|
| Native (`fjall`) | 50.014 ms | 0.58% |
| Kernel (`fjall,kernel`) | 45.784 ms | 1.82% |

Artifact [`data/overhaul-signed-spend-20260904.md`](data/overhaul-signed-spend-20260904.md): commit `0299e677`, rustc 1.95.0, 4-CPU Xeon, Linux 6.12.94+, same 117-block signed-spend proxy as 2026-09-02 baseline, 3 runs/arm after `secp256k1::SECP256K1` reuse; `NodeState::apply_block` over P2PKH/P2WPKH/P2WSH-2-of-3 real ECDSA; both arms within 5% of own median; native/kernel = 1.092, native does not win. Core vectors pin `NATIVE_SCRIPT_TESTS_FAILURES = 0`, `NATIVE_TX_VALID_FAILURES = 0`, `NATIVE_TX_INVALID_FAILURES = 0` (`script_tests` skips only 55 one-string prose headers, `tx_valid` skips none, `tx_invalid` skips only 9 `BADTX` parse-stage rows); kernel-vs-interpreter parity in `crates/consensus/tests/kernel_block_parity.rs` is a Taproot key-path differential (legacy/P2SH/multisig/SegWit-v0 kernel-only there; native coverage via Core vectors). Peak RSS: native 14.3 MiB, kernel 15.6 MiB.

Conclusion: verdict `KeepKernel` (native 9.2% slower on apply p50; full-mainnet replay blocked on #34; #42 froze the C150/Cmodern corpus contracts but runs no comparator); the signed-spend target is engine diagnostics, not daemon/P2P/CLI wall.
