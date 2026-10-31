# Formal verification contract

This file owns the formal toolchain pins, the run rules, and the per-module Apalache table. Machine-readable hashes live in `crates/rpc/core-compat.toml`.

## Toolchain pins

| Tool | Pin |
| --- | --- |
| Apalache | `apalache-mc` 0.62.4, release `https://github.com/apalache-mc/apalache/releases/tag/v0.62.4` |
| Archive | `apalache-0.62.4.zip`, SHA256 `3b6b7ebf24e778535bf47e0cb3f0799c9ab9048df41119c7d3091c6ca1760bc1` (matches the release `sha256sum.txt` and the GitHub asset digest) |
| Jar | `lib/apalache.jar`, SHA256 `e5223915507b65cc5f1638bd037ede60f8a4fc1644aff46355779f9b05df9262` |
| Apalache home | `${APALACHE_HOME}`, default `target/tools/apalache-0.62.4` (untracked) |
| Java | `java -version` observed line: Java 26.0.2.1 |
| Solver | `SMT_SOLVER=z3`, `JVM_ARGS` default `-Xmx4096m` |
| SMT encoding | `funArrays` (`--smt-encoding=funArrays`) |
| Lean | `leanprover/lean4:v4.35.0` (`docs/lean/lean-toolchain`) |
| Aeneas | nightly `2026.10.30-de16f3c`, asset `aeneas-linux-x86_64.tar.gz`, SHA256 `0963dc77cab890de16b213b903091721961afca6303b9b0ea05ff8d76013f624` |
| Charon | 0.1.301 at commit `373d84044d80f6eb44285c2c349bae1453f5b6ca` (the Aeneas revision's `charon-pin`) |
| Aeneas Lean library | `backends/lean/lean-toolchain` of the Aeneas revision: `leanprover/lean4:v4.35.0` |

The moving `ghcr.io/apalache-mc/apalache:main` image is not accepted evidence. A run begins only after the pinned archive and JAR digests match.

## Run rules

`python3 scripts/check_models.py` checks one safety lane and one temporal lane for every module:

```text
apalache-mc check --config=docs/models/<Owner>/<Machine>.cfg --inv=TypeOK --length=<K> --smt-encoding=funArrays --out-dir=target/apalache/<Owner>/<Machine>/safety/k<K> docs/models/<Owner>/<Machine>.tla
apalache-mc check --config=docs/models/<Owner>/<Machine>.cfg --temporal=ConditionalProgress --length=<K> --smt-encoding=funArrays --out-dir=target/apalache/<Owner>/<Machine>/temporal/k<K> docs/models/<Owner>/<Machine>.tla
```

- Every lane starts at K = 128.
- Resource exhaustion (evidence return code 14) halves K until the lane completes or K reaches 1.
- The run records the last K attempted and its return codes.
- `--check-only` verifies the tool and module identities.
- It does not evaluate a property.
- `target/apalache/summary.json` records the bound and both return codes of every lane.
- Native return codes map to evidence codes:
  - Success maps `0 -> 0`.
  - Parse maps `150 -> 12`.
  - Typecheck maps `120 -> 12`.
  - A counterexample maps `12 -> 13`.
  - Spec evaluation maps `75 -> 14`.
  - System error maps `255 -> 14`.
  - Timeout or incomplete output maps `-> 14`.
  - A model identity mismatch maps `-> 15`.
  - A tool identity mismatch maps `-> 11`.
- The solver run belongs to the operator-invoked `model-check-manual` workflow and to the `proofs` stage.
- Normal Cargo suites do not run the external checker.

`env -C docs/lean lake build` builds every Lean module.
`scripts/extract_lean.sh` runs Charon and Aeneas for the listed functions and writes `docs/lean/Extracted/`.
With `--check` it writes to a temporary directory and fails when the output differs from `docs/lean/Extracted/`.
The chainstate admission model step implements the state machine verified in `docs/lean/ChainAdmission/Safety.lean`.

## Per-module Apalache table

| module | .tla sha256 | .cfg sha256 | CONSTANT values | K | last recorded outcome | native rc | evidence rc |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ChainAdmission/Commit | 4949df3cc2a2c1d65911028dbcff1e22ed254d4cb61a21a2b14d582be442a922 | 139dfe3312a4363c2b0a8f48fb41fd60b97f3e06dda010e03dfbbcdb17bd471a | MaxAttempts=4, CounterBound=1024, FrameBound=72 | 128 | safety K=32 rc 0; temporal K=8 rc 0; recorded under a 180 s per-invocation cap | 0 | 0 |
| ChainAdmission/Frontier | 01aa7f482475b25f069f7fd26ddec98e8c8ba83609cebdcf5799e931adf37b43 | 1495f0d4223a7c40ba955736066a59689a4e018998f6fd36f00804102e6662ce | JobSlots=12, ReqSlots=12, EventBudget=12 | 128 | safety K=32 rc 0; temporal K=8 rc 0; recorded under a 180 s per-invocation cap | 0 | 0 |
| PeerLeases/Lease | d192ce554e7e23897c770a03071a5edad797d386430fd32bfc0bf3f85055ccf6 | 4adabd58221c2ce894e092d198d3cfd6f5df26c402c97b01053a4e80a817284c | R0="R0", R1="R1", F0="F0", F1="F1" | 128 | safety K=4 rc 0; temporal K=4 rc 0; recorded under a 180 s per-invocation cap | 0 | 0 |
| PeerLeases/Session | 5a9bf4ab04e3e58067660d88021fa38e3665afc03c7aed4510134cd678a1e537 | 1d5e4c42b59427a1f80984449fec537e8f6bc6bae2beb0c3cf177b2f8d2d6c76 | S0="S0", S1="S1", ExternalBudget=12 | 128 | safety K=16 rc 0; temporal K=8 rc 0; recorded under a 180 s per-invocation cap | 0 | 0 |
| ProjectionMining/Mining | 8b9490ea691280eae2752bece5e0e2c24d235ee7b36d1e97476f0cd7a8d14737 | 10194af480821b515b499250bf76b117481632637589d50460b0d704bc848dc0 | TipGen=4, ShareCap=2 | 128 | safety K=64 rc 0; temporal K=8 rc 0; recorded under a 180 s per-invocation cap | 0 | 0 |
| ProjectionMining/Projection | f93bc2e9c172eba434a61c6e86ee8a5d2094487075e5fcd47f88a4c84098e4a1 | 43768a52de0a9e1032ab534d3ffc4c916c288b5f9b2b849fde92a2d265f0e31a | AppliedHeight=12, CounterBound=1024 | 128 | safety K=32 rc 0; temporal K=16 rc 0; recorded under a 180 s per-invocation cap | 0 | 0 |

A row with evidence return code 14 is unavailable evidence. It is not a counterexample and not a verified pass.

## Per-module Kani and Lean table

This table shows the status of each Kani harness and each property that moved to Lean.

| Module | Property | Status | Lean theorem path |
| --- | --- | --- | --- |
| primitives | 4 harnesses | Verified (under 1 s each) | None |
| mempool chunk_index | `chunk_key_cmp_is_antisymmetric` | Verified (489 s) | None |
| mempool chunk_index | `chunk_key_cmp_is_transitive` | Moved to Lean (>1800 s) | `docs/lean/Mempool/ChunkIndex.lean::chunkKey_strict_total_order` |
| mempool fee_diagram | `fee_weight_rate_cmp_is_transitive` | Moved to Lean (>1800 s) | `docs/lean/Mempool/FeeDiagram.lean::rateCmp_total_preorder` |
| utxo compress | `compressed_amounts_round_trip_inside_the_money_supply` | Moved to Lean (>1800 s) | `docs/lean/Utxo/Compress.lean::dec_enc` |
| storage lease | `refusal_line_never_passes_a_mandatory_floor` | Moved to Lean (>1800 s) | `docs/lean/Storage/Lease.lean::refusal_line_never_passes_floor` |
