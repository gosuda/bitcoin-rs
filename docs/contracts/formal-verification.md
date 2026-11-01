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
apalache-mc check --config=docs/models/<Owner>/<Machine>.cfg --inv=TypeOK,Safety --length=<K> --smt-encoding=funArrays --out-dir=target/apalache/<Owner>/<Machine>/safety/k<K> docs/models/<Owner>/<Machine>.tla
apalache-mc check --config=docs/models/<Owner>/<Machine>.cfg --temporal=ConditionalProgress --length=<K> --smt-encoding=funArrays --out-dir=target/apalache/<Owner>/<Machine>/temporal/k<K> docs/models/<Owner>/<Machine>.tla
```

- Every lane starts at K = 128 or the row's K floor, whichever is larger.
- The row's K column is the evidence floor for the module.
- A pass below the floor is evidence return code 16, not a pass.
- Resource exhaustion (evidence return code 14 from a timeout, an out-of-memory kill, or incomplete output) halves K down to the floor, never below it.
- A native return code 75 (spec evaluation) or 255 (system error) never halves K.
- The run records the last K attempted and its return codes.
- `--check-only` verifies the tool and module identities.
- It does not evaluate a property.
- `target/apalache/summary.json` records the bound and both return codes of every lane.
- Native return codes map to evidence codes:
  - Success maps `0 -> 0`.
  - Parse maps `150 -> 12`.
  - Typecheck maps `120 -> 12`.
  - A counterexample maps `12 -> 13`.
  - Spec evaluation maps `75 -> 14` and does not halve K.
  - System error maps `255 -> 14` and does not halve K.
  - Timeout or incomplete output maps `-> 14` and halves K down to the floor.
  - A bound below the row's K floor maps `-> 16`.
  - A model identity mismatch maps `-> 15`.
  - A tool identity mismatch maps `-> 11`.
- The solver run belongs to the operator-invoked `model-check-manual` workflow and to the `proofs` stage.
- Normal Cargo suites do not run the external checker.

`env -C docs/lean lake build` builds every Lean module except `docs/lean/Extracted/`.
Compiling the extracted tree needs the Aeneas Lean library as a lake dependency, and the contract pins only the Aeneas tool asset, so that wiring remains a recorded gap.
`scripts/extract_lean.sh` runs Charon and Aeneas for the listed functions and writes `docs/lean/Extracted/`.
With `--check` it writes to a temporary directory and fails when the output differs from `docs/lean/Extracted/`.
It also fails with exit 67 on any crate whose status is not `extracted`, except the crates named in `EXTRACT_UNEXTRACTED_ALLOW` (unset by default), and it prints each allowed failure.
The chainstate admission model step implements the state machine verified in `docs/lean/ChainAdmission/Safety.lean`.

## Per-module Apalache table

| module | .tla sha256 | .cfg sha256 | CONSTANT values | K | last recorded outcome | native rc | evidence rc |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ChainAdmission/Commit | f7507483e986095ecc1b4314dd60b8bdf1062ce27b7d31edba6758e029197669 | 139dfe3312a4363c2b0a8f48fb41fd60b97f3e06dda010e03dfbbcdb17bd471a | MaxAttempts=4, CounterBound=1024, FrameBound=72 | 128 | TLC 1.8.0 Safety at depth 16 with CounterBound=8 and FrameBound=3 found no error; Apalache run pending | - | - |
| ChainAdmission/Frontier | 711d4d86314f2098eccc235e726f10dd84a5d6423e5a45388cbc8d4243157db3 | 1495f0d4223a7c40ba955736066a59689a4e018998f6fd36f00804102e6662ce | JobSlots=12, ReqSlots=12, EventBudget=12 | 128 | TLC 1.8.0 Safety at depth 16 with 3 slots found no error; Apalache run pending | - | - |
| PeerLeases/Lease | de734ebefb70a8532c4103eb519170e171cf8d405c59b36c9d95c43dc03ce2de | 4adabd58221c2ce894e092d198d3cfd6f5df26c402c97b01053a4e80a817284c | R0="R0", R1="R1", F0="F0", F1="F1" | 128 | TLC 1.8.0 Safety at depth 16 found no error; Apalache run pending | - | - |
| PeerLeases/Session | 84952eb83bfe66978ba54afcbbeba7dbe41620674241fb627fb8bfd1425d1c4c | 1d5e4c42b59427a1f80984449fec537e8f6bc6bae2beb0c3cf177b2f8d2d6c76 | S0="S0", S1="S1", ExternalBudget=12 | 128 | TLC 1.8.0 Safety at depth 16 with ExternalBudget=3 found no error; Apalache run pending | - | - |
| ProjectionMining/Mining | cb8c2e36bf5cc89027c195c157e1925bcee06040b5b597e3f4817afe5f75521a | 10194af480821b515b499250bf76b117481632637589d50460b0d704bc848dc0 | TipGen=4, ShareCap=2 | 128 | TLC 1.8.0 Safety at depth 16 with TipGen=3 found no error; Apalache run pending | - | - |
| ProjectionMining/Projection | 0f741a9d9c2d1951896ba0bfb85884165b978f7ccc2c1f658054283135f7c22a | 43768a52de0a9e1032ab534d3ffc4c916c288b5f9b2b849fde92a2d265f0e31a | AppliedHeight=12, CounterBound=1024 | 128 | TLC 1.8.0 Safety at depth 16 with AppliedHeight=4 found no error; Apalache run pending | - | - |

A row with evidence return code 14 is unavailable evidence. It is not a counterexample and not a verified pass.
A row with evidence return code 16 has no run at or above its K floor.
Evidence return code 13 (a counterexample) takes priority over 14 and 16 in the process exit status.

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
