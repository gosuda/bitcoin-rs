# Formal verification contract

This file owns the formal toolchain pins, the run rules, and the per-module checker table. Apalache archive and JAR hashes are also recorded in `crates/serving/core-compat.toml`.

## Toolchain pins

| Tool | Pin |
| --- | --- |
| Apalache | `apalache-mc` 0.62.4, release `https://github.com/apalache-mc/apalache/releases/tag/v0.62.4` |
| Archive | `apalache-0.62.4.zip`, SHA256 `3b6b7ebf24e778535bf47e0cb3f0799c9ab9048df41119c7d3091c6ca1760bc1` (matches the release `sha256sum.txt` and the GitHub asset digest) |
| Jar | `lib/apalache.jar`, SHA256 `e5223915507b65cc5f1638bd037ede60f8a4fc1644aff46355779f9b05df9262` |
| Apalache home | `${APALACHE_HOME}`, default `target/tools/apalache-0.62.4` (untracked) |
| Java | `java -version` observed line: Java 25.0.5 |
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
| ChainAdmission/Commit | bc7827ed1d8f53a129815999c0b7c1002858416be198d7908ccee6cb605a786b | 139dfe3312a4363c2b0a8f48fb41fd60b97f3e06dda010e03dfbbcdb17bd471a | MaxAttempts=4, CounterBound=1024, FrameBound=72 | 128 | TLC exhaustive TypeOK, Safety, and ConditionalProgress passed: 275788 distinct states, depth 5642. TypeOK overflow repaired; WindowDelta and PublishPrefix verified. Cache install before commit, publish without commit, create-spend leakage, and prefix overcommit negative controls each produced counterexamples. Design model only | 0 | 0 | tlc |
| ChainAdmission/Frontier | 711d4d86314f2098eccc235e726f10dd84a5d6423e5a45388cbc8d4243157db3 | 1495f0d4223a7c40ba955736066a59689a4e018998f6fd36f00804102e6662ce | JobSlots=12, ReqSlots=12, EventBudget=12 | 128 | TLC exhaustive TypeOK, Safety, and ConditionalProgress passed: 3302 distinct states. Both Apalache lanes timed out | 0 | 0 | tlc |
| DatadirSchema/Marker | 441097ec432b5cd506b4f7d46bf8e7f424ca3fb59dbb0fed26e1ec87ecf36c11 | 0c79f0462da0d1e70ed7b24594478108ae80de8aa32dc87485fdd2c96c5863ab | CellBound=4, ContentBound=2 | 128 | TLC exhaustive checks passed: 120852 distinct states. Both Apalache K128 lanes passed. ConditionalProgress is TRUE; no liveness claim. Bypassed verification and premature success each produced a counterexample. Design model only | 0 | 0 | tlc |
| DatadirSchema/MarkerEpoch4 | c2df23c07934a62d6b23a24eb338f2f6d65c7b516e31993b09224b6f14b9a873 | 299520a4099bd596cbdcb082e884c5316bc6382969b3b1969b02f2d6c05a6a06 | CellBound=4, ContentBound=1, HeightBound=1, CoinCellBound=1 | 128 | TLC exhaustive TypeOK, Safety, and ConditionalProgress passed: 217216 distinct states, depth 17. ConditionalProgress is TRUE; no liveness claim. Guard-removal mutants for TypeOK, source immutability, marker soundness, refusal cleanliness, sync-before-success, oracle-derived coins, and journal absence each produced a counterexample. Design model only | 0 | 0 | tlc |
| IndexOpen/Open | 7a0cf7893d75bbafc3793786d65194afc674fbf0c7519bf14f26d098a88288b0 | c68b2aadd0e582fc50e8f291c75f34444fc64dd8f646faaabdcc0bbb1e963006 | none | 128 | TLC exhaustive TypeOK, Safety, and ConditionalProgress passed: 134 distinct states, depth 11. Premature worker completion produced a counterexample. Both Apalache lanes timed out. Design model only | 0 | 0 | tlc |
| PeerLeases/Lease | de734ebefb70a8532c4103eb519170e171cf8d405c59b36c9d95c43dc03ce2de | 4adabd58221c2ce894e092d198d3cfd6f5df26c402c97b01053a4e80a817284c | R0="R0", R1="R1", F0="F0", F1="F1" | 128 | TLC exhaustive TypeOK, Safety, and ConditionalProgress passed: 881 distinct states. Both Apalache lanes timed out | 0 | 0 | tlc |
| PeerLeases/Session | 84952eb83bfe66978ba54afcbbeba7dbe41620674241fb627fb8bfd1425d1c4c | 1d5e4c42b59427a1f80984449fec537e8f6bc6bae2beb0c3cf177b2f8d2d6c76 | S0="S0", S1="S1", ExternalBudget=12 | 128 | TLC exhaustive TypeOK, Safety, and ConditionalProgress passed: 21 distinct states. Both Apalache lanes timed out | 0 | 0 | tlc |
| ProjectionMining/Mining | cb8c2e36bf5cc89027c195c157e1925bcee06040b5b597e3f4817afe5f75521a | 10194af480821b515b499250bf76b117481632637589d50460b0d704bc848dc0 | TipGen=4, ShareCap=2 | 128 | TLC exhaustive TypeOK, Safety, and ConditionalProgress passed: 8 distinct states. Apalache K128 safety passed; its temporal lane timed out | 0 | 0 | tlc |
| ProjectionMining/Projection | 6af2dd2741d21528475ccc46e090d45ef1b3b9dc56f3341d61b8ad8e81224e1b | 43768a52de0a9e1032ab534d3ffc4c916c288b5f9b2b849fde92a2d265f0e31a | AppliedHeight=12, CounterBound=1024 | 128 | TLC exhaustive TypeOK, Safety, and ConditionalProgress passed: 26 distinct states. Both Apalache lanes timed out | 0 | 0 | tlc |
| ProjectionIndex/CommittedFactsHandoff | b0ebaeab2b42cc261acbd8e53b3ad4f878079466f6bdd5222df992747ec19c66 | 7fc43e3ee8b97325480f706fce9599add97e393224c3778e042a9d5f65298897 | MaxHeight=3, QueueBudget=2, MaxVerified=2 | 128 | TLC exhaustive TypeOK, Safety, and ConditionalProgress passed: 195 distinct states, depth 14. Unbounded queue push produced a counterexample (queueBytes > QueueBudget). ConditionalProgress is TRUE; no liveness claim. Design model only | 0 | 0 | tlc |
| ProjectionIndex/IndexGenerations | 1f49e232fa2983a92e655a0d9a91cf5e6deed841b5e11ce491055ccf49c95d61 | e91878c9b6cd95019848a85ded351850b742e69b8fc231f480a81bff3dbdf933 | MaxTip=4, TailBound=2, MaxReorgs=1 | 128 | TLC exhaustive TypeOK, Safety, and ConditionalProgress passed: 5964 distinct states, depth 20. Omission of deep reorg retirement guard produced a counterexample (active generation covers blocks above fork tip). ConditionalProgress is TRUE; no liveness claim. Design model only | 0 | 0 | tlc |
| ServingView/ServingView | 15ea96a33c72b5dafdaef11b0b8b5dbff2e5ea9b46824de70bcad0fb0a4b56fa | f02ba8df40b403b8a24771f9c1c906c8184b47e58c2459c6094a1cecc3cf98c6 | MaxHeight=2, MaxViews=2, MaxGenerations=2 | 128 | TLC exhaustive TypeOK, Safety, and ConditionalProgress passed: 61368 distinct states, depth 15. Negative controls for ScriptLive transition lock acquisition (depth 2) and serialization under lock (depth 4) each produced a counterexample. Removed coverage guard produced counterexample at step 3. Design model only | 0 | 0 | tlc |
| SnapshotBootstrap/SnapshotBootstrap | 7ae962e757e5ef84a06cae5f6dae2145ac9c9b8b792ae4d0c5222754fef5fde3 | 76f9cf177628533b65c201fa6bddd60c50e2265a6899b53e9979c8ce5c97c899 | HasHistoricalBodies=FALSE, BaseHeight=2, MaxHeight=4 | 128 | TLC exhaustive TypeOK, Safety, and ConditionalProgress passed: 170 distinct states, depth 11. Removed UTXO verification guard produced counterexample at step 4. Design model only | 0 | 0 | tlc |
| MempoolSettlement/MempoolSettlement | 0d8d7e367717889473cefd13546729e0c2f77a8b06445e616676a935183c28cf | cf0fc7ca6874b72571cb4c3dc7475c28c5b823d1861283babe1546b7eefcf4cc | TxIds={"tx1", "tx2"}, MaxEpoch=3, MaxBlockId=2 | 128 | TLC exhaustive TypeOK, Safety, and ConditionalProgress passed: 6306 distinct states, depth 13. Negative control produced a counterexample at depth 2 (native rc 12, evidence rc 13). Design model only | 0 | 0 | tlc |
| NodeBudget/NodeBudget | f7baf09cd1c1d71f92d67cf6aebc2693e73c2049a6a0d552d0fb2dff43257b91 | e562d9aa25afc208031cc387a3ea462a43abeb8e7557fa2ac6366e1dc320db85 | TotalBudget=4, ForegroundReserve=1, MaxBlockId=2, IsMdbx=FALSE | 128 | TLC exhaustive TypeOK, Safety, and ConditionalProgress passed: 38240 distinct states, depth 17. Negative control produced a counterexample at depth 4 (native rc 12, evidence rc 13). Design model only | 0 | 0 | tlc |

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
| primitives sighash | `tapleaf_hash_input_stream_matches_concatenation_and_spec` (`SCR-03`) | Kani bound MAX_SCRIPT_LEN = 253; SHA-256 stubbed with a recording model, so the harness proves the input stream, not the digest; BIP341 leaf digests pinned by `tapleaf_hash_matches_bip341_wallet_vectors` | None |
| mempool chunk_index | `chunk_key_cmp_is_antisymmetric` | Verified (489 s) | None |
| mempool chunk_index | `chunk_key_cmp_is_transitive` | Moved to Lean (>1800 s) | `docs/lean/Mempool/ChunkIndex.lean::chunkKey_strict_total_order` |
| mempool fee_diagram | `fee_weight_rate_cmp_is_transitive` | Moved to Lean (>1800 s) | `docs/lean/Mempool/FeeDiagram.lean::rateCmp_total_preorder` |
| utxo compress | `compressed_amounts_round_trip_inside_the_money_supply` | Moved to Lean (>1800 s) | `docs/lean/Utxo/Compress.lean::dec_enc` |
| storage lease | `refusal_line_never_passes_a_mandatory_floor` | Moved to Lean (>1800 s) | `docs/lean/Storage/Lease.lean::refusal_line_never_passes_floor` |
| storage schema | 7 lifecycle harnesses (`RCV-09`) | Kani verified; independent Lean model compiled | `docs/lean/Storage/Schema.lean::invariant_step` |
| storage schema epoch 4 | 11 lifecycle harnesses (`RCV-09`, `RCV-10`) | Kani verified; independent Lean model compiled | `docs/lean/Storage/SchemaEpoch4.lean::invariant_step` |
| index startup | 8 lifecycle harnesses (`EMB-01`) | Kani verified; independent Lean model compiled | `docs/lean/IndexOpen/Safety.lean::safety_inductive` |
| projection handoff | 8 lifecycle harnesses (PRJ-01, PRJ-02, PRJ-04, PRJ-13, IDX-08) | Kani verified; independent Lean model compiled | docs/lean/ProjectionIndex/HandoffSafety.lean::safety_inductive |
| projection generations | 7 lifecycle harnesses (PRJ-05, PRJ-07, PRJ-09, REO-04, REO-05) | Kani verified; independent Lean model compiled | docs/lean/ProjectionIndex/GenerationsSafety.lean::safety_inductive |
| serving view | 7 lifecycle harnesses (`QRY-01..08`, `PRJ-11`) | Kani verified; independent Lean model compiled | `docs/lean/ServingView/Safety.lean::safety_inductive` |
| snapshot bootstrap | 8 lifecycle harnesses (`SNP-01..11`) | Kani verified; independent Lean model compiled | `docs/lean/SnapshotBootstrap/Safety.lean::safety_inductive` |
| node budget | 8 lifecycle harnesses (`BUD-01..07`) | Kani verified; independent Lean model compiled | `docs/lean/NodeBudget/Safety.lean::safety_inductive` |
| mempool settlement | 8 lifecycle harnesses (`MPS-01`, `MPS-03`) | Kani verified; independent Lean model compiled | `docs/lean/MempoolSettlement/Safety.lean::safety_inductive` |

The storage schema models specify the Epoch 4 admission and offline conversion design. The node uses Epoch 4 and `tools/storage-convert` provides offline conversion from Epoch 3 to Epoch 4; Epoch 2 converts to Epoch 3 first. `Storage/SchemaEpoch4` and `DatadirSchema/MarkerEpoch4` are design models for the implemented Epoch 4 schema: coins in the engine `coins` keyspace, no chainstate journal, no utxo v4 checkpoint coin image as an authority, and converter step `3 -> 4`. These design models MUST NOT be reported as implementation refinement proofs. Lean phase constructors encode required-file and scratch ordering. Source contents and final directory sync observations are independent state fields; they do not establish physical durability.

The index startup models specify helper thread ownership, joined cancellation, startup timeout abandonment, host teardown deadlines, and checkpoint gating under EMB-01. These design models MUST NOT be reported as implementation refinement proofs or OS durability proofs. Lean phase definitions specify the sequential transition system; they do not establish physical thread execution guarantees.

The serving view query lifecycle model in `crates/projection/src/runtime/query/proofs.rs` specifies view capture, extension immunity, explicit coverage and unavailable status, retired view expiration, lock-free self-contained ScriptLive, and post-access serialization without locks under QRY-01..08 and PRJ-11. This design model MUST NOT be reported as an implementation refinement proof.

The snapshot bootstrap model in `crates/execution/src/assumeutxo/proofs.rs` specifies unified single-pass streaming decode of coins and ScriptLive base, publication gating on UTXO verification, direct attachment of verified index generations, index failure domain isolation, independence of the three reported positions, and explicit historical body availability under SNP-01..11. This design model MUST NOT be reported as an implementation refinement proof.

The index startup TLC check MUST use `INIT Init`, `NEXT Next`, `INVARIANT TypeOK`, `INVARIANT Safety`, and `PROPERTY ConditionalProgress`. The checker is `tlc2.TLC` in the pinned Apalache JAR. The check MUST use exhaustive breadth-first search without a depth limit, state constraints, or fairness assumptions. `ConditionalProgress` specifies sticky failure safety, not liveness.
