# Hot-path attribution

This contract is the normative owner of product-domain wall time attribution.
The ledger file owns inventory, overlap groups, and dispositions.
This document does not record measured seconds.
Owners: method, this page (`HPA-01`..`HPA-13`).
Inventory and dispositions: `docs/benchmarks/hot-path-ledger.toml`.
Evidence tooling: `crates/node/benches/evidence.rs` and `tools/benchmark-campaign/`.
The 2.0x speed gate and the 36-cell denominator live in issues #33 and #45; this contract does not change the 36-cell count.

## Clauses

### `HPA-01`: Frozen 36-cell denominator
- A product cell is one coordinate of the frozen cartesian product.
- The product contains domains by corpora by native architectures by backends.
- Domains are `offline` full-validation chainstate construction, `p2p` controlled loopback initial sync, and `muhash` production full-UTXO MuHash RPC query.
- Corpora are `c150` and `cmodern`.
- Native architectures are `x86_64` and `arm64`.
- Backends are `fjall`, `rocksdb`, and `redb`.
- That cartesian product contains exactly 36 cells.
- Allocator variants, scalar or AVX2 builds, source forms, test networks, pruning experiments, and microbenchmarks are diagnostics, never cells.
- For `muhash`, the backend coordinate records how the identical committed state was constructed, checkpointed, reopened, and served.
- The live scan traverses the in-memory UTXO set.

### `HPA-02`: Frozen trial protocol
- Attribution MUST follow the statistical protocol frozen in #44: seven valid interleaved Core 31.1 and bitcoin-rs pairs per cell.
- The execution schedule MUST be hashed before execution.
- Testers MUST NOT use optional stopping.
- Testers MUST NOT use outcome-based rejection.
- Primary cell speed stays `median(C1..C7) / median(B1..B7)`.
- Attribution MUST NOT replace that ratio.
- Whole-run wall time is the external monotonic interval from the domain comparator (#46 offline, #35 P2P, #41 MuHash).
- Internal stage histograms MUST NOT supply or alter primary wall time.

### `HPA-03`: Frozen attribution noise floor
- Freeze the noise floor before admitting any attribution number.
- A cell bitcoin-rs noise floor is the observed range of its seven valid bitcoin-rs walls: `max(B1..B7) - min(B1..B7)`.
- A disable or neutralize delta is above noise only when its absolute value exceeds that range.
- An unclassified residual is above noise only when its absolute value exceeds that range.
- Until those seven walls exist, the floor is `unobserved`.
- An `unobserved` floor MUST NOT classify a cost as small.
- An `unobserved` floor MUST NOT hide a residual as within noise.
- Testers MUST NOT apply percentage, sigma, or IQR materiality rules after seeing data.

### `HPA-04`: Overlap-aware wall account
- Every ledger row MUST name a parent interval and a concurrency group.
- Nested child inclusive time MUST NOT be added to its parent.
- Parallel workers in one group contribute the group span, not the worker sum.
- A cell exclusive account is the overlap-aware union of exclusive leaves under `cell.wall`.
- The residual is `cell.wall` minus that union.
- Record the residual in its own field, never as `other`.
- Existing `metrics::histogram!` names in the ledger are diagnostic hooks.
- These hooks are nested intervals, not addends.

### `HPA-05`: One ledger
- `docs/benchmarks/hot-path-ledger.toml` is the only inventory of measured product hot paths, cost classes, known levers, and forbidden probes.
- Every recorded `Sample.path` MUST match a declared `paths.id`.
- Declared-path membership is owned by inventory review.
- The evidence tool validates accounting, not path names.
- The inventory MAY extend the reviewed minimum.
- Validating membership MUST NOT deduplicate samples or remove empty cells.
- A row records applicability, custody, wall contribution, disable or neutralize delta, overlap, affected cells, and disposition.
- Derive shared versus backend, corpus, domain, or architecture specific grouping from applicability, never a parallel table.
- A measured wall contribution or disable delta requires a custody digest.
- The default value is unmeasured.

### `HPA-06`: Forbidden product-weakening probes
- The following mutations MUST NOT supply a comparator result.
- Mutations MUST NOT skip scripts via assume-valid.
- Mutations MUST NOT skip Merkle or witness checks.
- Mutations MUST NOT use a dummy UTXO mutator.
- Mutations MUST NOT suppress undo or body writes.
- Mutations MUST NOT weaken durability.
- Mutations MUST NOT drop the MuHash stable-view lock.
- Mutations MUST NOT replace UTXO decode or MuHash arithmetic with constants.
- Mutations MUST NOT suppress checkpoint, recovery, or reopen work.
- A source-level disable experiment MUST preserve full validation, durable root, reopen, body/undo/index readiness, state commitment, and reorg-readiness.
- Otherwise, its `disable_delta` remains `blocked_pending_safe_probe` with disposition `blocked` (`HPA-07`).

### `HPA-07`: Disposition enum
- Every repeatable above-noise cost, and every named lever, MUST use exactly one disposition:
- `optimize`: cost is large enough to move a product cell; next step is a product-safe change plus fresh whole-workload remeasurement of every affected cell.
- `already_bounded`: measured, and either too small to move a cell or already at a measured optimum.
- `blocked`: a product-safe probe, host, corpus, or comparator is missing; the evidence field names the blocker.
- `rejected`: a product-safe probe or measurement refuted the lever; the evidence field names the result.
- `other` is not a disposition.
- Omission because a larger cost exists is not a disposition.
- Dismissal because a speed gate already exceeds the threshold is not a disposition.

### `HPA-08`: Residual honesty
- Every cell of the 36 cells MUST have a residual field.
- Record a residual as within the noise floor only after seven bitcoin-rs walls exist for that cell.
- Subtract the overlap-aware exclusive union from the whole-run wall before recording.
- `unmeasured` means that the residual is the whole unattributed wall.
- An `unmeasured` residual is not within noise.

### `HPA-09`: Diagnostics are not cells
- Criterion targets, allocator A or B arms, SIMD microbenchmarks, and historical campaign artifacts diagnose mechanisms.
- Diagnostics MUST NOT satisfy a product cell.
- Diagnostics MUST NOT be copied into the ledger as wall contribution without new product-cell custody.

### `HPA-10`: Campaign candidate rule
- A mechanism becomes an `optimize` candidate only under one condition.
- A product-safe disable or neutralize delta on total product wall MUST exceed the cell noise floor in `HPA-03`.
- Historical stage sums and isolated-stage speedups MUST NOT serve as that delta.

### `HPA-11`: Completeness does not close the speed gate
- Attribution completeness does not alter the fixed 36-cell speed denominator.
- No candidate MAY rely on weaker consensus, validation, durability, recovery, body availability, cache posture, or index posture.

### `HPA-12`: Evidence identity per sample
- The evidence `Ledger` schema lives in `crates/node/benches/evidence.rs`.
- The benchmark evidence tests and the hot-path ledger share this schema.
- Every sample MUST carry an identity tuple.
- The tuple includes artifact (binary or library hash) and configuration (feature set, backend, network, cache budget).
- The tuple includes corpus (stop hash, block count, validity class) and durability identity (flush mode, checkpoint policy, `CURRENT_SCHEMA`).
- A sample missing any of the four fields is inadmissible.
- Inadmissible samples MUST NOT fill a product cell or supply a promotion or regression verdict.
- Nested and concurrent intervals MUST NOT be summed.
- All repeated samples and empty or missing cells MUST stay in the ledger.
- Do not collapse or drop samples or cells.
- Local replay or a diagnostic fixture MUST NOT satisfy the live full-tip default-lane gate.

### `HPA-13`: Promotion and regression thresholds
- A product cell promotion requires a measured median win of at least 1.05x against the control arm.
- Promotion requires at least three alternating candidate and control runs.
- Each arm remains within the 5% stability rule.
- The improvement MUST exceed observed host noise.
- A 5% magnitude threshold alone is not enough.
- Non-target correctness-equivalent cells guard at no more than 3% median and no more than 5% p99 regression, with repeated runs and uncertainty.
- Average-only concealment is not allowed.
- Reports include p50, p95, p99, and max.
- Reports include CPU time, cycles and instructions, cache misses, allocations, bytes copied, RSS, and storage high-water.
- Testers never infer a trustworthy p99 from too few samples.
- Keep raw data alongside summaries.
- A microbenchmark and a product benchmark answer different questions.
- Only the product benchmark can fill a product cell.

## Evidence and checks

- `cargo test --locked -p bitcoin-rs-node --no-default-features --features fjall --bench evidence` checks missing identities, interval overlap, and repeated-sample retention.
- That command is a benchmark-tool test, not node correctness or a measurement.
- `tools/benchmark-campaign/` owns measured runs and product comparisons.
- Its tests validate evidence accounting, and only actual runs populate cells.
- Inventory review owns the declared matrix and attribution paths.
- Plain Rust tests do not freeze path names, candidate lists, or unmeasured cells.
- Removing those gates does not relax the measurement requirements above.

## Vocabulary

Terms used above are defined in [`../../CONCEPTS.md`](../../CONCEPTS.md):
product cell, noise floor, disposition.

## MuHash RPC campaign

Production full-UTXO comparator: `gettxoutsetinfo` owns arity.
`tools/benchmark-campaign/muhash_rpc.py` owns transport, spawn, and receipt identity.
Owners: `crates/rpc/src/handlers/chain.rs`, `tools/benchmark-campaign/muhash_rpc.py`.
Procedure: [muhash-rpc.md](../benchmarks/muhash-rpc.md).

### `MRPC-01`: Production triplet arity
- `gettxoutsetinfo` accepts at most three parameters.
- The measured call is `["muhash", null, false]`.
- A fourth positional argument MUST return `InvalidParams`.

### `MRPC-02`: Attested child owns the RPC connection
- Before writing `Authorization`, the client matches the connection unique ESTABLISHED loopback row in `/proc/<attested_pid>/fd` with matching starttime.
- The row is in `/proc/net/tcp` or `/proc/net/tcp6`.
- An earlier LISTEN snapshot is not send-time proof.

### `MRPC-03`: Spawned `{config}` is the pinned bytes
- Templates MUST include `{config}`.
- `run_campaign` copies pinned config with flags `O_EXCL` and `0o400`.
- The runner re-reads via `_read_regular_file`, re-hashes, and seals into memfd.
- The runner passes `/proc/self/fd/<n>`.
- The binary uses `MFD_EXEC`.
- The config uses `MFD_NOEXEC_SEAL`.
- On pre-6.3 kernels where flags return `EINVAL`, the code falls back to `MFD_ALLOW_SEALING`.
- Rename or write operations MUST NOT change daemon bytes.
- Receipts MUST keep FileRef identity.
- Proven by `gettxoutsetinfo_rejects_trailing_parameters`.
- Proven by `tools/benchmark-campaign/test_muhash_rpc.py`:
- `test_rpc_does_not_send_credentials_to_a_foreign_peer`
- `test_readiness_rejects_a_listener_the_child_does_not_own`
- `test_command_must_include_config_placeholder`
- `test_pinned_config_copy_ignores_later_operator_path_writes`
- `test_binary_snapshot_execs_and_config_snapshot_does_not`
- `test_snapshot_falls_back_when_exec_flags_are_einval`
- `test_verified_config_inode_survives_workspace_path_replace`
- `test_spawn_reads_verified_config_after_workspace_replace`
- `test_warm_campaign_agrees_across_all_backends`
