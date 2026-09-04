# Native validation default (issue #213)

This note records the #213 decision. It does not change crate defaults.
The owner of the default is
[`docs/contracts/validation-default.md`](../contracts/validation-default.md),
proven by `g18_validation_default`.

A **measured observation** copies a field from a cited artifact. An
**inference** interprets those observations or names evidence that is
missing. Promotion requires every gate in the issue, not a subset.

## Decision

Keep `kernel` as the `bitcoin-rs-consensus` and `bitcoin-rs-node` default.
Leave `bin/bitcoin-rs` kernel-free. The native interpreter is a complete
consensus script engine; it is not yet the measured winner.

| Gate | Result |
|---|---|
| Native Core-vector parity (`script_tests`, `tx_valid`, `tx_invalid`) | **Pass** — pinned mismatch counts are 0 |
| Signed-spend apply median faster than kernel, both arms within 5% of their own three-run median | **Fail** — native slower; both arms noisier than 5% |
| Offline full-validation corpus and full-mainnet replay vs Bitcoin Core | **Not run** — blocked on #34 and #42 |
| Recorded verdict | `KeepKernel` |

## Native capability (measured)

`crates/script/tests/core_vectors.rs` pins

```text
NATIVE_SCRIPT_TESTS_FAILURES = 0
NATIVE_TX_VALID_FAILURES = 0
NATIVE_TX_INVALID_FAILURES = 0
```

Those columns feed Core's `script_tests.json`, `tx_valid.json`, and
`tx_invalid.json` through `Interpreter`. A growth of any count fails the
lane. Kernel-vs-interpreter fixture parity lives in
`crates/consensus/tests/kernel_block_parity.rs` (legacy, P2SH, bare
multisig, SegWit v0, Taproot key-path and script-path).

The earlier stub (`verify_non_taproot_portable`, bare `OP_TRUE` only) is
gone. `CONCEPTS.md` and the crate rustdocs that still described it were
wrong against this tree.

## Signed-spend performance (measured)

Source:
[`data/overhaul-signed-spend-20260902.md`](data/overhaul-signed-spend-20260902.md).

- Host: Intel Xeon Gold 6138, Linux x86-64.
- Command (native): `cargo bench -p bitcoin-rs-node --bench sync_pipeline --no-default-features --features fjall -- signed_spend`
- Command (kernel): same with `--features fjall,kernel`
- Corpus: `signed_spend_proxy_blocks()` — P2PKH, P2WPKH, and P2WSH 2-of-3
  spends with real ECDSA signatures. Not the vacuous `OP_TRUE` corpus in
  [`data/overhaul-native-apply-20260902.md`](data/overhaul-native-apply-20260902.md).

| Arm | Run 1 Criterion median | Run 2 Criterion median |
|---|---:|---:|
| Native | 588.24 ms | 819.31 ms |
| Kernel | 532.21 ms | 616.60 ms |

Native is slower on both runs. Run-to-run spread on each arm exceeds five
percent of that arm's median, so the comparison would not count even if
native were faster. Two runs is also short of the required three.

The `OP_TRUE` apply-path numbers (native 15.747 ms vs kernel 36.136 ms)
do not license promotion: that corpus verifies no signatures.

## Full-mainnet / offline corpus (missing)

Issue #213 requires every verdict and accepted state transition on the
held offline corpus and a full-mainnet replay to match Bitcoin Core.
[#34](https://github.com/gosuda/bitcoin-rs/issues/34) (offline comparator)
and [#42](https://github.com/gosuda/bitcoin-rs/issues/42) (C150 / modern
corpus) are still open. No receipt for those cells is in the tree.

## Inference

Vector parity is necessary and not sufficient. The signed-spend proxy is
the in-tree performance gate that actually runs the script engine, and
native loses it. Full-chain parity has not been executed. Changing the
library default would replace Core's engine with a slower path whose
replay evidence is still missing.

The default binary already uses the native path (`default = ["fjall",
"redb", "zmq"]`). Dockerfile / Compose still build `fjall,kernel`. That
split stays: C++-free quickstart on the binary, kernel on the library
default and the production image, until a later measurement moves
`RECORDED_VERDICT` and the two library manifests together.
