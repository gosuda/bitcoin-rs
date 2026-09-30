# Formal verification contract

This document owns the formal-model inventory, runner identity, and evidence
semantics used by `scripts/check_models.py`. Machine-readable tool hashes are
owned by `crates/rpc/core-compat.toml`; the workflow is owned by
`.github/workflows/model-check-manual.yml`.

## Tool identity

| Field | Value |
| --- | --- |
| Tool | `apalache-mc` 0.62.2 |
| Release | `https://github.com/apalache-mc/apalache/releases/tag/v0.62.2` |
| Archive | `apalache-0.62.2.zip`, SHA256 `7cfadf6e8c04c63f05ac907ec9541c66297005c8cb5efb1731f6a838dfc3fad2` |
| Jar | `lib/apalache.jar`, SHA256 `079b6c2320252469dcf79afec6886b8255d3dd1b34a9484433c88986752efaa8` |
| Sums file | `apalache.sha256sums.txt`; API `https://api.github.com/repos/apalache-mc/apalache/releases/tags/v0.62.2` (`assets[].digest`) |
| Java | `java -version` observed line: Java 26.0.2.1 |
| Install root | `${APALACHE_HOME}`, default `target/tools/apalache-0.62.2` (untracked) |
| Version check | `apalache-mc version` must print `0.62.2`; mismatch is evidence rc 11 |
| Solver | `SMT_SOLVER=z3`; `JVM_ARGS` default `-Xmx4096m` |
| SMT encoding | `funArrays` (`--smt-encoding=funArrays`) |
| Step bound | K = 128 (`--length=128`); a verification bound, not a production limit |

The moving `ghcr.io/apalache-mc/apalache:main` image is not accepted evidence.
The pinned archive and JAR hashes must match before a run begins.

## Proof inventory

Each model in `docs/models/` exports `Init`, `Next`, `TypeOK`, `Safety`,
`TransitionSafety`, and `ConditionalProgress`. Each configuration carries only
constants, `INIT`, and `NEXT`. Fairness is explicit in `ConditionalProgress`,
not embedded in `Next`.

| model | .tla sha256 | .cfg sha256 | CONSTANT values | K | last recorded outcome | native rc | evidence rc |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ChainAdmission | 3cf14873929ffab5bc8c7d68f4e7fe6b00a8c470c5af3f2474cef2d030d305e2 | d9019ce0f244bde70e6fea34c99aff76c3f383bf9268630cab80e3f87506ce67 | EventBudget=12, JobSlots=12, MaxAttempts=4, CounterBound=1024, FrameBound=72, FactBound=36, ReqSlots=12 | 128 | Temporal (ConditionalProgress): 16g and 64g runs exhausted heap during rewriting; a 96g run was stopped by an obsolete local guard before its comparison point. No completed safety proof is recorded. | 255 | 14 |
| PeerLeases | 1b9780fd95e9813545bc992958825569b6ab2b62fc175cf4b18989b676c1b437 | 3b23777fb2dcdcee61ac81f29c06b99a33d140cef01fc5be8e1d5c71104aa7ea | Peer=P, S0, S1, G0, G1, R0, R1, F0, F1, D0, D1, CtrlCap=1, DataCap=1, InCap=1, OutCap=1, ExternalBudget=12 | 128 | Temporal (ConditionalProgress) exhausted a 16 GiB heap at step 5; the last safety run reached state 7 without completing. | 255 | 14 |
| ProjectionMining | 2c6f502b53bf91026a01f3d09597b060643da8a9479f19a12207e71c83082fe7 | f4d7dacc59d1d9c7bd87328bb0114a74d4b133f3a7a2bfa2b519aa127e1939c4 | O, A, B, TxLookup, ScriptLive, ScriptHistory, J0, J1, Rw0..Rw2, X0, X1, ExternalBudget=12 | 128 | Temporal (ConditionalProgress) exhausted a 32 GiB heap during step-1 search; 16g and 32g resource rungs failed, higher rungs remain untested. No completed safety proof is recorded. | 255 | 14 |

The recorded failures are unavailable evidence, not counterexamples and not
verified passes. Inventory rows remain blocked until all six pinned checks
finish successfully.

## Runner and evidence semantics

`python3 scripts/check_models.py` runs one safety and one temporal invocation
for each model:

```text
apalache-mc check --config=docs/models/<M>.cfg --inv=TypeOK,Safety,TransitionSafety --length=128 --out-dir=target/apalache/<M> docs/models/<M>.tla
apalache-mc check --config=docs/models/<M>.cfg --temporal=ConditionalProgress --length=128 --out-dir=target/apalache/<M> docs/models/<M>.tla
```

The solver run belongs to the operator-invoked `model-check-manual` workflow.
Normal Cargo suites do not run the external checker. `--check-only` verifies
input identity; it does not prove model properties.

Native return codes are preserved in the artifact and mapped to evidence return
codes as follows: success `0 -> 0`; parse `150 -> 12`; typecheck `120 -> 12`;
counterexample `12 -> 13`; spec evaluation `75 -> 14`; system error `255 -> 14`;
timeout or incomplete output `-> 14`; model identity mismatch `-> 15`; tool
identity mismatch `-> 11`.

Evidence requires all six successful invocations plus the property lists, model
and configuration hashes, tool pin, constants, bound, arguments, and complete
outcome lines. Anything less remains blocked.
