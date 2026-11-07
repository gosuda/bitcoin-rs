# Formal verification contract

This file owns the formal toolchain pins, the run rules, and the per-module checker table. Apalache archive and JAR hashes are also recorded in `crates/rpc/core-compat.toml`.

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

`python3 scripts/check_models.py` checks safety and temporal evidence for every module in the inventory.
The checker engine is configured per module in the `checker` column below (`tlc` or `apalache`), and can be selected via `--checker {configured,apalache,tlc}` (default `configured`).

When a module runs under `tlc`:

```text
java -Xmx4096m -cp <apalache.jar> tlc2.TLC -workers 1 -fp 1 -metadir <out>/states -noGenerateSpecTE -teSpecOutDir <out>/te -config <generated_cfg> docs/models/<Owner>/<Machine>.tla
```

- A per-run `.cfg` copies the pinned `.cfg` verbatim and appends `INVARIANT TypeOK`, `INVARIANT Safety`, and `PROPERTY ConditionalProgress`.
- The pinned `.cfg` must define `INIT` and `NEXT` (exact sections, not `SPECIFICATION`), and must not define state or action constraints (`CONSTRAINT`/`CONSTRAINTS`, `ACTION_CONSTRAINT`/`ACTION_CONSTRAINTS`), state abstraction (`VIEW`), symmetry, fairness, simulation limits, or deadlock disabling (`CHECK_DEADLOCK`).
- One exhaustive breadth-first exploration covers both safety and temporal verification and projects results into `safety` and `temporal` lanes with `k = null` and exact state counts.
- Complete graph evidence required for success (evidence code 0): native return code 0, complete graph marker (`Model checking completed. No error has been found.`), 0 states left on queue, positive distinct state count, and a per-run configuration specifying `PROPERTY ConditionalProgress`.
- Native return codes for TLC map to evidence codes:
  - Exit 0 with verified complete graph, zero queue, positive count, and configured temporal property maps `0 -> 0` on both lanes.
  - Deadlock maps `11 -> 13` (safety counterexample; temporal unavailable 14).
  - Invariant violation maps `12 -> 13` (safety counterexample; temporal unavailable 14).
  - Assumption or assertion violation maps `10` or `14 -> 13` (safety counterexample; temporal unavailable 14).
  - Temporal property violation maps `13 -> 13` (temporal counterexample; safety unavailable 14).
  - Syntax or configuration error maps `150` or `151 -> 12`.
  - Resource exhaustion, timeout, or incomplete output maps `-> 14`.
  - A non-zero exit or uncompleted graph never claims evidence code 0 on any lane.

When a module runs under `apalache`:

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

General rules:
- `--check-only` verifies the tool and module identities and the registered checker column without evaluating properties.
- `target/apalache/summary.json` records the bound and return codes of every lane.
- The solver run belongs to the operator-invoked `model-check-manual` workflow and to the `proofs` stage.
- Normal Cargo suites do not run the external checker.

`env -C docs/lean lake build` builds every Lean module except `docs/lean/Extracted/`.
Compiling the extracted tree needs the Aeneas Lean library as a lake dependency, and the contract pins only the Aeneas tool asset, so that wiring remains a recorded gap.
`scripts/extract_lean.sh` runs Charon and Aeneas for the listed functions and writes `docs/lean/Extracted/`.
With `--check` it writes to a temporary directory and fails when the output differs from `docs/lean/Extracted/`.
It also fails with exit 67 on any crate whose status is not `extracted`, except the crates named in `EXTRACT_UNEXTRACTED_ALLOW` (unset by default), and it prints each allowed failure.
The chainstate admission model step implements the state machine verified in `docs/lean/ChainAdmission/Safety.lean`.

## Per-module checker table

| module | .tla sha256 | .cfg sha256 | CONSTANT values | K | last recorded outcome | native rc | evidence rc | checker |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ChainAdmission/Commit | f7507483e986095ecc1b4314dd60b8bdf1062ce27b7d31edba6758e029197669 | 139dfe3312a4363c2b0a8f48fb41fd60b97f3e06dda010e03dfbbcdb17bd471a | MaxAttempts=4, CounterBound=1024, FrameBound=72 | 128 | Full TLC exhausted heap during liveness checking after 68237659 distinct states; no complete result. A separate original-Next witness violated TypeOK at state 4618, epoch=513, generation=1026 (native 12, evidence 13). Both Apalache lanes timed out | 1 | 14 | tlc |
| ChainAdmission/Frontier | 711d4d86314f2098eccc235e726f10dd84a5d6423e5a45388cbc8d4243157db3 | 1495f0d4223a7c40ba955736066a59689a4e018998f6fd36f00804102e6662ce | JobSlots=12, ReqSlots=12, EventBudget=12 | 128 | TLC exhaustive TypeOK, Safety, and ConditionalProgress passed: 3302 distinct states. Both Apalache lanes timed out | 0 | 0 | tlc |
| DatadirSchema/Marker | 441097ec432b5cd506b4f7d46bf8e7f424ca3fb59dbb0fed26e1ec87ecf36c11 | 0c79f0462da0d1e70ed7b24594478108ae80de8aa32dc87485fdd2c96c5863ab | CellBound=4, ContentBound=2 | 128 | TLC exhaustive checks passed: 120852 distinct states. Both Apalache K128 lanes passed. ConditionalProgress is TRUE; no liveness claim. Bypassed verification and premature success each produced a counterexample. Design model only | 0 | 0 | tlc |
| IndexOpen/Open | 7a0cf7893d75bbafc3793786d65194afc674fbf0c7519bf14f26d098a88288b0 | c68b2aadd0e582fc50e8f291c75f34444fc64dd8f646faaabdcc0bbb1e963006 | none | 128 | TLC exhaustive TypeOK, Safety, and ConditionalProgress passed: 134 distinct states, depth 11. Premature worker completion produced a counterexample. Both Apalache lanes timed out. Design model only | 0 | 0 | tlc |
| PeerLeases/Lease | de734ebefb70a8532c4103eb519170e171cf8d405c59b36c9d95c43dc03ce2de | 4adabd58221c2ce894e092d198d3cfd6f5df26c402c97b01053a4e80a817284c | R0="R0", R1="R1", F0="F0", F1="F1" | 128 | TLC exhaustive TypeOK, Safety, and ConditionalProgress passed: 881 distinct states. Both Apalache lanes timed out | 0 | 0 | tlc |
| PeerLeases/Session | 84952eb83bfe66978ba54afcbbeba7dbe41620674241fb627fb8bfd1425d1c4c | 1d5e4c42b59427a1f80984449fec537e8f6bc6bae2beb0c3cf177b2f8d2d6c76 | S0="S0", S1="S1", ExternalBudget=12 | 128 | TLC exhaustive TypeOK, Safety, and ConditionalProgress passed: 21 distinct states. Both Apalache lanes timed out | 0 | 0 | tlc |
| ProjectionMining/Mining | cb8c2e36bf5cc89027c195c157e1925bcee06040b5b597e3f4817afe5f75521a | 10194af480821b515b499250bf76b117481632637589d50460b0d704bc848dc0 | TipGen=4, ShareCap=2 | 128 | TLC exhaustive TypeOK, Safety, and ConditionalProgress passed: 8 distinct states. Apalache K128 safety passed; its temporal lane timed out | 0 | 0 | tlc |
| ProjectionMining/Projection | 0f741a9d9c2d1951896ba0bfb85884165b978f7ccc2c1f658054283135f7c22a | 43768a52de0a9e1032ab534d3ffc4c916c288b5f9b2b849fde92a2d265f0e31a | AppliedHeight=12, CounterBound=1024 | 128 | TLC exhaustive TypeOK, Safety, and ConditionalProgress passed: 26 distinct states. Both Apalache lanes timed out | 0 | 0 | tlc |

These outcomes use the pinned Apalache JAR and unchanged registered constants. The full runs used a 3500 s limit per invocation and a 4096 MiB JVM heap. Each completed TLC graph had an empty queue. An Apalache timeout has evidence code 14.
The Commit witness uses `Next /\ CycleAction` to select successive successful commits. Its source, initial state, constants, and invariants are unchanged. A violation on this subset is a counterexample to the original model; a passing subset would not prove the original model.

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
| storage schema | 7 lifecycle harnesses (`RCV-09`) | Kani verified; independent Lean model compiled | `docs/lean/Storage/Schema.lean::invariant_step` |
| index startup | 8 lifecycle harnesses (`EMB-01`) | Kani verified; independent Lean model compiled | `docs/lean/IndexOpen/Safety.lean::safety_inductive` |

The storage schema models specify the Epoch 3 admission and offline conversion design. The node uses Epoch 3 and `tools/storage-convert` provides offline conversion from Epoch 2 to Epoch 3. These design models MUST NOT be reported as implementation refinement proofs. Lean phase constructors encode required-file and scratch ordering. Source contents and final directory sync observations are independent state fields; they do not establish physical durability.

The index startup models specify helper thread ownership, joined cancellation, startup timeout abandonment, host teardown deadlines, and checkpoint gating under EMB-01. These design models MUST NOT be reported as implementation refinement proofs or OS durability proofs. Lean phase definitions specify the sequential transition system; they do not establish physical thread execution guarantees.

The index startup TLC check MUST use `INIT Init`, `NEXT Next`, `INVARIANT TypeOK`, `INVARIANT Safety`, and `PROPERTY ConditionalProgress`. The checker is `tlc2.TLC` in the pinned Apalache JAR. The check MUST use exhaustive breadth-first search without a depth limit, state constraints, or fairness assumptions. `ConditionalProgress` specifies sticky failure safety, not liveness.
