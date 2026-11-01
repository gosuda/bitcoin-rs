# Verification: tests, fuzzing, proofs

No layer proves the node correct. Each layer names a property it covers and a property it cannot cover. Run the smallest layer that covers your change, then read its result at the scope it claims.

## The layers

| Layer | What it proves | What it does not prove |
| :--- | :--- | :--- |
| Unit and property tests | A named behavior or invariant holds for the cases and generators the test owns | End-to-end node behavior, external compatibility, or absence of untested cases |
| Fuzzing | The targets did not crash, hang, or disagree with the stated oracle during the campaign | Semantic correctness, coverage completeness, or that every input class was reached |
| Kani, Lean, and Charon | Bounded properties or named theorems hold for the modeled code | Whole-node behavior, or that an unextracted path matches its model |
| TLA+ models | Safety and conditional progress hold on the model at the stated bounds | That the Rust implementation refines the model |
| Differential oracle | Native and `libbitcoinkernel` agree on named fixtures and boundaries | Parity over all scripts and transactions |
| Live Core lane | Named observable outcomes match a pinned Core 31.1 process | Full rule-family equivalence or mainnet behavior |

The contracts own the thresholds and the evidence records.

## Unit and property tests

[`scripts/ci-pr.sh`](https://github.com/gosuda/bitcoin-rs/blob/main/scripts/ci-pr.sh) composes the test lanes. `test-crates` runs the library suites, `test-binary` runs the node binary suite, and `test-workspace` runs the workspace level. `./scripts/ci-pr.sh test` runs all three in that order. The script uses `cargo nextest` when it is installed and falls back to `cargo test --no-fail-fast` otherwise.

A test that carries a contract clause id above it appears in the generated [evidence index](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/evidence-index.md). The tag is the link between a rule and its proof. [Contracts and evidence](../contribute/contracts.md) explains the tag format.

Property tests live beside their owners. They prove an invariant over generated inputs, such as a compressed amount round trip or a fee-rate comparison that must be a total preorder. A property test does not prove that the generator reaches every production input shape. Where the claim is about elapsed work, the assertion belongs in a paired-arm benchmark, not in a unit test.

```
./scripts/ci-pr.sh test
```

The full run is long. Use the narrowest cargo package for a local change.

## Fuzzing

The repository has 23 libFuzzer targets under [`fuzz/fuzz_targets`](https://github.com/gosuda/bitcoin-rs/blob/main/fuzz/fuzz_targets). They cover P2P wire framing, BIP324 transport, block and transaction validation, script execution, snapshot and storage decoding, RPC and REST parsing, header sync, and reorg state. One target is a cross-implementation differential: `tx_differential` compares the native transaction decoder with `rust-bitcoin`. `script_differential` re-runs the native interpreter and checks determinism, flag monotonicity, and commitment-mismatch rejection.

Run one target from the repository root:

```
cargo +nightly fuzz run p2p_message
```

Seeds live in the companion repository [`gosuda/bitcoin-rs-fuzz-corpus`](https://github.com/gosuda/bitcoin-rs-fuzz-corpus) under `corpus/<target>/`. A local `fuzz/corpus/<target>/` overlay works for ad hoc runs and stays untracked.

Campaign automation uses [`scripts/run-fuzz-campaign.sh`](https://github.com/gosuda/bitcoin-rs/blob/main/scripts/run-fuzz-campaign.sh):

```
scripts/run-fuzz-campaign.sh all 60
```

`all` discovers every target from `fuzz/Cargo.toml` and runs each for 60 seconds. A single target uses `scripts/run-fuzz-campaign.sh p2p_message 60`. The script exits nonzero when `fuzz/artifacts/<target>/` or `campaign-output/artifacts/` contains a crash, OOM, or timeout.

Fuzz builds enable AddressSanitizer, value profiling, debug assertions, and integer overflow checks. Campaigns enforce an RSS ceiling, a malloc ceiling, and a per-input timeout. The smoke gate on `fuzz/**` pull requests compiles every target and runs each for 30 seconds. The daily campaign minimizes seeds and publishes non-empty corpora.

The corpus verdict gate is separate from a live campaign:

```
BITCOIN_RS_FUZZ_CORPUS=../bitcoin-rs-fuzz-corpus/corpus cargo test --locked -p bitcoin-rs-primitives --test suite differential::
```

When the corpus directory is absent the gate skips with a notice. When `verdicts.json` is absent it degrades to the verdict-shape check and reports the downgrade. A seed that decodes to neither `accepted` nor `rejected:<kind>` fails the gate.

Fuzzing proves that the target survived the input distribution it saw. It does not prove that the target reaches every production parser state, and it does not prove a semantic rule. The bitcoinfuzz module integration is in progress and is not completed verification.

## Kani, Lean, and Charon

Run the proof stage when you change a module that owns a `proofs.rs` file, a `*_model.rs` model, or a Lean file:

```
./scripts/ci-pr.sh proofs
```

CI does not run this stage because the runners carry no Kani, Lean, or Aeneas toolchain. The stage does four things. It runs `cargo kani --tests` for every crate that contains a `proofs.rs`. It runs `./scripts/extract_lean.sh --check` and `env -C docs/lean lake build`. It scans `docs/lean` for `sorry`, `admit`, `axiom`, and `native_decide`, excluding the extracted tree. It runs `python3 scripts/check_models.py` unless `PROOFS_MODELS=0` is set.

The Kani table in [`docs/contracts/formal-verification.md`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/formal-verification.md) records four primitives harnesses under one second each and one mempool chunk-index antisymmetry harness at 489 seconds. Four properties exceeded the 1,800-second Kani budget and moved to Lean: chunk-index transitivity, fee-diagram rate-comparison totality, the compressed-amount round trip inside the money supply, and the storage lease refusal line.

The Lean build covers every module except `docs/lean/Extracted/`. Building the extracted tree needs the Aeneas Lean library as a lake dependency, and the contract pins the Aeneas tool asset but not that library wiring. `scripts/extract_lean.sh --check` writes to a temporary directory and fails when the output differs from the checked-in extraction. It exits 67 on a crate whose status is not `extracted`, except for crates named in `EXTRACT_UNEXTRACTED_ALLOW`, which is unset by default.

These tools prove bounded properties and named theorems. They do not prove that an unextracted Rust path matches its Lean model, and they do not prove node behavior that no harness covers.

## TLA+ models

Six TLA+ modules model chain admission, peer leases, and mining projections: `ChainAdmission/Commit`, `ChainAdmission/Frontier`, `PeerLeases/Lease`, `PeerLeases/Session`, `ProjectionMining/Mining`, and `ProjectionMining/Projection`.

```
python3 scripts/check_models.py
```

The checker runs one safety lane (`TypeOK,Safety`) and one temporal lane (`ConditionalProgress`) per module. Every lane starts at K = 128 or the module's K floor, whichever is larger. Resource exhaustion halves K down to the floor, never below it. `--check-only` verifies the tool and model identities; it does not evaluate a property.

Read the evidence codes, not only the exit status. A counterexample is code 13. Code 14 means timeout, out-of-memory, or incomplete output. Code 16 means no run at or above the module's K floor. Codes 14 and 16 are unavailable evidence, not passes.

The recorded table has no Apalache result. Every module says TLC 1.8.0 found no safety error at depth 16 with reduced constants, and every module adds "Apalache run pending". Do not read the TLC line as an Apalache pass.

The runner defaults to 3,600 seconds per solver invocation. The temporal lane at K = 128 is the long pole, and on this class of host it does not finish inside that budget. A run that reaches the budget records code 14, which is a failed-to-complete run. Treat a temporal run as an overnight operator job, not a pull-request gate.

The tool pins are Apalache 0.62.4, its release archive, and the JAR digest. The contract records Java 26.0.2.1 as the observed runtime; provision that runtime before you treat a run as the pinned lane.

## Differential oracle

The in-process oracle compares the native interpreter with Bitcoin Core's C++ engine on named fixtures:

```
cargo test --locked -p bitcoin-rs-consensus --features kernel --test suite -- kernel_block_parity:: kernel_boundary_parity:: kernel_vector_parity:: --nocapture
```

[`docs/validation-tooling.md`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/validation-tooling.md) owns the lane and its prerequisites. It needs `cmake`, `libboost-dev`, and a C++ toolchain. The comparison covers six mainnet fixtures and synthetic consensus limits. It does not run the full Core corpus, and the vector test excludes `BADTX` rows that fail before script verification.

The live Core lane is a process comparison, not an in-process oracle. Its evidence test is:

```
P2P_CORE_INTEROP_EVIDENCE=target/core-differential/evidence.json cargo test --locked -p bitcoin-rs-p2p --test suite core_interop_live:: -- --ignored
```

That test reads the evidence document produced by `scripts/run-p2p-core-interop.sh`. It does not run Core by itself. [Compatibility with Bitcoin Core](core-compatibility.md) owns the lane scopes and the main-only limits.

## The contract evidence index

```
cargo run --locked -p contract-index -- --check
```

The check exits 0 in this checkout. The generated index records 204 clauses, 157 with tagged proof artifacts, and 47 gap clauses. `./scripts/ci-pr.sh contracts` runs the same check and also verifies the contract list in `docs/contracts/README.md`.

A gap clause has no tagged artifact. It is not a waiver and not a pass. Closing one means adding the artifact and its tag, then regenerating the index in the same change-set. The count moves only when the tree moves.

## What no layer proves

There is no formal proof of the whole node. There is no recorded external JSON-RPC, REST, or ZMQ consumer run. There is no product benchmark cell at the acceptance threshold. The `CORE-05` and `CORE-06` live lanes are main-only, and `CORE-07` needs a local Core checkout. The TLA+ Apalache rows are pending.

Use those limits when you describe a result. "Tested" names the layer and the scope. "Verified" without a scope names nothing.

Next: [Contracts and evidence](../contribute/contracts.md) explains how a test earns a clause tag. [Benchmarks](benchmarks.md) explains why no performance number in this book is a result.
