# CONSTRAINTS.md

The repository guard register. It records the constraint ledger (CL-01..CL-23),
the formal model tool identity, and the proof inventory that gate `g20` and the
owner gates read. It references normative owners (`docs/contracts/`,
`docs/policies/`, `.outline/waterfall/BLUEPRINT.md` invariants INV-01..INV-12,
owner constants in code) and is never a second policy. When a row and its owner
disagree, the owner governs and the gate blocks until the row is corrected.

Every measurement cell below is `UNMEASURED`. Target values are contracts, not
results. Unknown is not false; a missing measurement blocks the owning task.
`BLOCKED` is a workflow state, not a verdict.

## Formal model tool identity

| Field | Value |
| --- | --- |
| Tool | `apalache-mc` 0.62.2 |
| Release | `https://github.com/apalache-mc/apalache/releases/tag/v0.62.2` |
| Archive | `apalache-0.62.2.zip`, SHA256 `7cfadf6e8c04c63f05ac907ec9541c66297005c8cb5efb1731f6a838dfc3fad2` |
| Jar | `lib/apalache.jar`, SHA256 `079b6c2320252469dcf79afec6886b8255d3dd1b34a9484433c88986752efaa8` |
| Sums file | `apalache.sha256sums.txt`; API `https://api.github.com/repos/apalache-mc/apalache/releases/tags/v0.62.2` (`assets[].digest`) |
| Java | `java -version` observed line: Java 26.0.2.1 |
| Install root | `${APALACHE_HOME}`, default `target/tools/apalache-0.62.2` (untracked) |
| Version check | `apalache-mc version` must print `0.62.2`; mismatch is skill rc 11 |
| Solver | `SMT_SOLVER=z3`; `JVM_ARGS` default `-Xmx4096m` (complete JVM option) |
| SMT encoding | `funArrays` (`--smt-encoding=funArrays`) |
| Step bound | K = 128 (`--length=128`); a verification bound, not a production limit |

The docker tag `ghcr.io/apalache-mc/apalache:main` is a moving branch tag and
is prohibited. `sha256sum -c` against the sums file must succeed before any run
is recorded here.

## Proof inventory

Models live in `docs/models/`. Each `.tla` exports exactly `Init`, `Next`,
`TypeOK`, `Safety`, `TransitionSafety`, `ConditionalProgress`; each `.cfg`
carries CONSTANTS, INIT, and NEXT only. Fairness is explicit LTL in the
antecedent of `ConditionalProgress`, never inside `Next`.

| model | .tla sha256 | .cfg sha256 | CONSTANT values | K | last recorded outcome | native rc | skill rc |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ChainAdmission | e82138365787f075f1ebe232e4c609cec47b515d29cd11d29fe7d35c6f522d83 | d9019ce0f244bde70e6fea34c99aff76c3f383bf9268630cab80e3f87506ce67 | EventBudget=12, JobSlots=12, MaxAttempts=4, CounterBound=1024, FrameBound=72, FactBound=36, ReqSlots=12 | 128 | temporal (ConditionalProgress): 16g and 64g rungs died of heap space in TemporalPass rewriting (64g: rc255 after 1893s, before State 0) — tool resource exhaustion, NOT a counterexample and NOT a verified pass. The 96g rung was killed at 82 GiB RSS by a stale v2 guard loop's obsolete 80 GiB trigger (avail 248 GiB; no genuine pressure) 16m before its comparison mark — UNTESTED, not falsified; relaunch in flight. chain-safety still in flight | 255 | 14 |
| PeerLeases | b3a50f1e4f95e635bfd992ffcacb2f17899ce3a3377b38fc7c11ad2051482d9a | 3b23777fb2dcdcee61ac81f29c06b99a33d140cef01fc5be8e1d5c71104aa7ea | Peer=P, S0, S1, G0, G1, R0, R1, F0, F1, D0, D1, CtrlCap=1, DataCap=1, InCap=1, OutCap=1, ExternalBudget=12 | 128 | temporal (ConditionalProgress) rc255 after 32248s: JVM ran out of heap space (max JVM memory 17179869184 = -Xmx16384m from detached-checks.sh) at Step 5 of --length=128 — tool resource exhaustion, NOT a counterexample and NOT a verified pass; outcome unverified per honest-failure rule; peer-safety (State 7) and chain-side runs still in flight | 255 | 14 |
| ProjectionMining | 1ffc603ff9a12de825ac663478d4c859215ebe842aef092208e42ed431dc2e43 | f4d7dacc59d1d9c7bd87328bb0114a74d4b133f3a7a2bfa2b519aa127e1939c4 | O, A, B, TxLookup, ScriptLive, ScriptHistory, J0, J1, Rw0..Rw2, X0, X1, ExternalBudget=12 | 128 | temporal (ConditionalProgress) rc255 after 7540s at 32 GiB: JVM ran out of heap space during Step-1 search (invariant checks passing at State 1) — tool resource exhaustion, NOT a counterexample and NOT a verified pass; heap rungs 16g and 32g falsified, higher rungs untested. proj-safety still in flight (.outline/formal-runs-20260910) | 255 | 14 |

Gate `g20` (`bin/bitcoin-rs/tests/gates/g20_formal_models.rs`) runs six
invocations per pass, three safety and three temporal:

```
apalache-mc check --config=docs/models/<M>.cfg --inv=TypeOK,Safety,TransitionSafety --length=128 --out-dir=target/apalache/<M> docs/models/<M>.tla
apalache-mc check --config=docs/models/<M>.cfg --temporal=ConditionalProgress --length=128 --out-dir=target/apalache/<M> docs/models/<M>.tla
```

Native to skill rc mapping, native rc preserved verbatim: `0 -> 0`; `150`
parse and `120` typecheck `-> 12`; `12` counterexample `-> 13`; `75`
spec-eval, `255` system error, timeout `-> 14`; hash divergence from this
inventory `-> 15`; tool identity mismatch `-> 11`. Evidence is rc 0 for all six
invocations plus the explicit property lists, model and config hashes, pin,
constants, K, argv, and outcome line. Anything less is `BLOCKED`.

Model to implementer gates: ChainAdmission gates T08, T11, T18; PeerLeases
gates T24; ProjectionMining gates T29, T35. A red model blocks the task, never
the reverse.

## Constraint ledger

Each row is diff-scoped unless its scope cell says project-wide. `checked-by`
is one exact command and the row's evidence entry point, not a replacement for
the other owner gates. T00 creates this register; T02 captures original
candidate baselines before production edits; owner gates append final values.

| ID | name | rule | checked-by | runs-at | scope | target | baseline | final | verdict | evidence identity |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| CL-01 | Complete coverage | T40 dependency closure reaches all 38 remaining tasks T00-T27, T29-T32, T35-T40, every remaining requirement R001-R023, R025-R034, R036-R064 has successful required command evidence, and MERKLE-ALL is closed; no partial-owner or exception shortcut counts as whole delivery. | `cargo test --locked -p bitcoin-rs --no-default-features --features fjall --test overhaul_release_profiles -- --nocapture` | G11; T40 closure | Project-wide delivery | Required true; plan internal dependencies and `REQUIREMENTS.csv` | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED |
| CL-02 | Strict-Rust mandatory | T16 strict-Rust cryptography succeeds before T17 default promotion; final comparator uses the strict candidate; missing strict evidence blocks promotion. | `cargo test --locked -p bitcoin-rs-script --test overhaul_native_crypto -- --nocapture` | G5, G11 | Project-wide validation closure; T16, T17, T40 | Required true; Approval effects, R048 | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED |
| CL-03 | Kernel independence | No `bitcoinkernel` in the production transitive graph; native candidate and independent oracle use separate `CARGO_TARGET_DIR` and independently identified artifacts. Preserve dependency-direction and default-validation checks. | `cargo test --locked -p bitcoin-rs --no-default-features --features fjall --test overhaul_default_closure -- --nocapture` | G5, G11 | Project-wide production dependency closure; T17, T40 | Required true; Verification 0/5, R004/R006/R049 | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED |
| CL-04 | 1 TB physical peak | Default unpruned fjall, indexes off, pinned full-tip stop: `conservative_high_water` and `PhysicalLedger::data_directory_allocated_bytes` prove actual physical peak, including transient allocations; physical bytes also do not exceed T02 baseline. Missing original-candidate high-water blocks T14 cut and regression proof. | `cargo test --locked -p bitcoin-rs --no-default-features --features fjall --test overhaul_storage_evidence -- --nocapture` | G1/T02 capture; G4/T14 pre-cut gate; G11/T39 final versus T02 | Project-wide full-tip physical truth; T02, T14, T39, T40 | Physical peak <= 1_000_000_000_000 decimal bytes and <= baseline; FP-02/FP-04, R052 | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED |
| CL-05 | Separate ledgers | Emit logical and physical ledgers separately; never sum them or use logical payload as allocated-storage truth. Budget and peak verdict derive from the physical ledger only. | `cargo test --locked -p bitcoin-rs --no-default-features --features fjall --test overhaul_storage_evidence -- --nocapture` | T02 capture; T14 pre-cut; G11/T39 | Diff: storage accounting and changed I/O; T14, T39 | Required true; FP-01 | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED |
| CL-06 | Parser/protocol equality | Independent native and oracle results agree on txids, wtxids, weight, positions, and Merkle flag; T15 has zero unexplained contextual or script mismatches. Preserve previously passing contracts. | `cargo test --locked -p bitcoin-rs-consensus --test overhaul_parse_parity -- --nocapture` | G3, G5; T02 baseline | Diff: parser, consensus, script and affected I/O; T06, T15 | Required true and no unexplained mismatches; R002/R005 | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED |
| CL-07 | Coherent views | Every mixed read carries a `chain_generation` token; a height-only cache is a defect. RPC, REST, ZMQ, Esplora, and backend projections preserve coherent authoritative snapshots. | `cargo test --locked -p bitcoin-rs --no-default-features --features fjall --test overhaul_core_api -- --nocapture` | G6, G8; T02 baseline | Diff: mixed reads and public projections; T22, T31, T32 | Required true; BLUEPRINT INV-05/INV-08 | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED |
| CL-08 | Single owners | Five-layer graph satisfies `g17`; one admission owner `MempoolGateway`, scheduler `P2pService`, mempool orphan owner, template owner `MiningCoordinator`, and index runtime owner. Projections are disposable and rebuildable, never alternate authority. | `cargo test --locked -p bitcoin-rs --no-default-features --features fjall --test overhaul_ownership -- --nocapture` | G2 and affected later owner gates | Diff: ownership and dependency cuts; T03, T18, T22, T24, T29, T35 | Required true; INV-02/INV-03, R012/R013/R046/R047 | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED |
| CL-09 | Immutable pins | `ReferenceSet` records independent source, binary, and corpus digests; pin toolchain `1.95.0` and `Cargo.lock` SHA-256. Candidate-derived expected answers are not independent references. | `cargo test --locked -p bitcoin-rs --no-default-features --features fjall --test overhaul_reference_set -- --nocapture` | G0 and every gate | Project-wide evidence and reference identity; T00 | Required true; T00, Verification 0, FP-03 | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED |
| CL-10 | Actual external consumers | The external miner over public GBT requires its owner-gate evidence. In-process shortcuts do not prove the consumer contract. | `cargo test --locked -p bitcoin-rs --no-default-features --features fjall --test overhaul_external_miner -- --nocapture` | G9; T02 existing-I/O baseline | Diff: external-miner contract; T36 | Required true; R043, Verification 4 | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED |
| CL-11 | Full-platform Merkle | Portable code compiles across the full matrix; record measured, compile-only, or unavailable status without inventing verdicts. Guard AVX2, x86 SHA, and ARM sha2; unsupported instructions never execute. Missing hardware blocks its performance proof, not its correctness obligation. | `cargo test --locked -p bitcoin-rs-consensus --test overhaul_hash_dispatch -- --nocapture` | G1/T02 per-target capture; G10/T37 versus T02 | Project-wide MERKLE-ALL platform matrix; T02, T37 | Required correctness true; matched per-target throughput >= baseline and cost/latency <= baseline; Verification 6 | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED |
| CL-12 | Explicit fresh replay | Increment owner-local `CURRENT_SCHEMA`; incompatible data refuses open with `incompatible_schema`. No translator or legacy reader. Fresh replay uses disposable candidate data, never an operator-data write or hidden repair. T14 authority cut requires original physical baseline first. | `cargo test --locked -p bitcoin-rs-node --no-default-features --features fjall --test overhaul_checkpoint_independence -- --nocapture` | G4; pre-cut T14 | Diff: authoritative format and open path; T12, T14 | Required true; Verification 0, Assumptions | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED |
| CL-13 | No old readers / shims | Each approved deletion cut displays its removed set; no re-export, alias, forwarding path, compatibility flag, or old reader preserves an approved-deleted symbol. Owner-local cuts cannot create a second policy or authority. | `cargo test --locked -p bitcoin-rs --no-default-features --features fjall --test overhaul_ownership -- --nocapture` | Every completed owner cut; G11 | Diff: approved deletions and dependents; T03-T40 | Required true; Approach anti-shim | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED |
| CL-14 | Bounded budgets | Every ingress, window, traversal, response, cache, journal, and rebuild has an owner and resolved byte, work, and time bounds. Include window bytes/inputs/coin/CPU/age; `MempoolLimits` cluster_count 64, size 101_000 vB, max_ancestors 25, max_total_bytes 300_000_000; `TX_RELAY_QUEUE_CAPACITY` 1024; `DEFAULT_ZMQ_HWM` 1_000; owner orphan quota and `PrefixScanLimit`. Capture RSS and retained-byte high-water for each affected existing surface. | `cargo test --locked -p bitcoin-rs --no-default-features --features fjall --test overhaul_resource_bounds -- --nocapture` | G1/T02; G3/G4/G6/G7/G10; T39 comparison | Diff: affected resource cells; T02, T06, T08, T13, T14, T20, T22, T25, T38, T39 | Usage <= actual resolved owner limits and applicable T02 baseline; INV-10 | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED |
| CL-15 | Four attempts / 16 000 sigops | Gateway retries exactly `MAX_ADMISSION_RETRIES` then returns `Busy`; `total_sigop_cost` <= `MAX_STANDARD_TX_SIGOPS_COST`. Resolve owner constants rather than adding knobs. | `cargo test --locked -p bitcoin-rs-mempool --test overhaul_admission_owner -- --nocapture` | G6; T02 existing-surface baseline | Diff: admission; T18 | Required true; retained constants 4 and 16_000, T18 | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED |
| CL-16 | Policy = Core 31.1 | Resolved `AdmissionPolicy` matches pinned policy: min-relay 1_000 sat/kvB, incremental 1_000, dust 3_000, datacarrier 83, `MAX_PACKAGE_COUNT` 25, max_replacement_evictions 100. Unresolved policy is a startup error; replacement, package, and TRUC evidence remains required. | `cargo test --locked -p bitcoin-rs-mempool --test overhaul_finality_policy -- --nocapture` | G6; T02 baseline | Diff: policy and replacement contracts; T19, T21 | Required true; `docs/policies/mempool-policy.md` | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED |
| CL-17 | Durable order | Append body/undo, sync, batch, durable completion, publication. `submitblock` succeeds only after durability; I/O failure never means success. `DurableHead.commit_id` is monotonic; backend atomicity and crash evidence are mandatory. | `cargo test --locked -p bitcoin-rs-node --no-default-features --features fjall --test overhaul_durable_head -- --nocapture` | G4; T02 baseline | Diff: durable write and publication surfaces; T09, T11, T12 | Required true; INV-04/INV-06 | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED |
| CL-18 | Exact inverse | Disconnect restores pre-connect coins, bookkeeping, and identity; missing undo fails closed. Streaming reorg and pruning leases preserve boundedness and the existing I/O baseline. | `cargo test --locked -p bitcoin-rs-node --no-default-features --features fjall --test overhaul_streaming_reorg -- --nocapture` | G4; T02 baseline | Diff: disconnect and reorg; T13 | Required true; INV-07, T13 | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED |
| CL-19 | Performance gain | Promotion requires median gain >= 1.05x, at least 3 alternating runs, each arm within 5% stability, improvement exceeding host noise, and identical result hashes. Capture original `sync_pipeline`, `chainstate_journal`, and `merkle` controls at T02; include microbenchmarks and full E2E product workloads. | `cargo test --locked -p bitcoin-rs --no-default-features --features fjall --test overhaul_resource_bounds -- --nocapture` | G1/T02; G10/T37 and T38 versus frozen controls | Diff: proposed optimizations and affected product paths; T02, T37, T38 | Gain threshold plus all non-regression predicates; Verification 6, R064 | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED |
| CL-20 | No regression | Every applicable apply-latency, cost, RSS, retained-byte, storage, p99, and throughput cell satisfies its baseline direction; preserve Boolean contracts. Hold script backend constant. 3% median and 5% p99 outer rejection caps never authorize degradation; uncertain noise comparisons remain blocked. | `cargo test --locked -p bitcoin-rs --no-default-features --features fjall --test overhaul_evidence -- --nocapture` | G1/T02; G3/G4/G10/G11; T14/T37/T38/T39 versus T02 | Diff: every affected measured surface; T02, T06, T08, T14, T37, T38, T39 | Cost/latency/bytes <= baseline; throughput >= baseline; R005/R064, Verification 6 | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED |
| CL-21 | No unapproved surface | A public boundary outside Approval effects stops the cut pending separate human approval. No unapproved limit, config, or crate beyond approved `crates/chainstate`. No writes to operator data; test and replay writes are confined to disposable isolated fixtures. | `cargo test --locked -p bitcoin-rs --no-default-features --features fjall --test overhaul_ownership -- --nocapture` | Every cut | Diff: all changed boundaries, dependencies, configuration and I/O | Required true; Approval effects | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED |
| CL-22 | Version/lock discipline | Approved workspace 0.4.0 to 0.5.0 release change and `Cargo.lock` update are atomic. Schema and projection versions stay owner-local; disposable projections never dictate authoritative schema. Commands use `--locked`. | `cargo test --locked -p bitcoin-rs --no-default-features --features fjall --test overhaul_release_profiles -- --nocapture` | G7, G11 | Diff: owner-local versions; project-wide release, lock, and dependency closure; T40 | Required true; `docs/policies/source-compatibility.md` section 4 | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED |
| CL-23 | Honest failure | Unavailable is not empty; unverified is not supported; unknown is not false. Skipped or unavailable proof blocks its gate with the missing identity recorded; numeric and Boolean fields remain UNMEASURED until measured. | `cargo test --locked -p bitcoin-rs --no-default-features --features fjall --test overhaul_evidence -- --nocapture` | All applicable gates | Diff: affected evidence and failure surfaces across all tasks | Required true; typed `Unavailable`/`BLOCKED`, INV-11, Verification 0 | UNMEASURED | UNMEASURED | UNMEASURED | UNMEASURED |

## Record discipline

- Preserve every CL row and its ID. Expand per surface, platform, or workload
  without renumbering. Each `checked-by` cell holds exactly one verbatim
  command; never concatenate commands or use shell ellipsis.
- Evidence identity attaches local transcript and raw-sample paths with
  digests, source and artifact hashes, lockfile, toolchain and features,
  harness and schema hashes, reference source, binary, and corpus digests,
  frozen workload, configuration, validation, and hardware identities, platform
  capability, stop height and hash, ledger accounting method, and baseline to
  final linkage. Record an absent-counterpart reason separately from a
  measurement; never invent a zero baseline.
- Subagents run no in-flight checks. The integrator runs fast type and gate
  checks inside an integrated owner boundary and the full applicable suite once
  per complete owner.
- Any missing, unavailable, unmeasurable, stale, unmatched, or unresolved
  applicable constraint blocks the owning task and dependent promotion. A
  Boolean false at baseline may become required true; unknown never supplies
  false; an existing true contract may not regress. An exception requires
  separate explicit human approval with a named normative owner, exact scope,
  reason, and expiry, recorded apart from measured verdicts.

## QA corpus importer setup contract

The versioned setup contract for `scripts/import-qa-assets.sh` is: a failure of
`git rev-parse` exits with status 19, a failure of the nightly `rustc` host
probe exits with status 17, a failure of `mktemp` exits with status 23, a disk
probe failure exits with status 7, and an insufficient-space check exits with
status 1. Every setup failure removes the temporary staging directory and does
not attempt the clone. `scripts/tests/test_import_qa_assets.py`
`SetupFailureTests` is the regression suite for this contract.
