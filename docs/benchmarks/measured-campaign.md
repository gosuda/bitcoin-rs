# Measured campaign runner and analyzer

Runner: `tools/benchmark-campaign/measured_runner.py`. Analyzer: `tools/benchmark-campaign/measured_analyze.py`. Synthetic probe: `tools/benchmark-campaign/test_measured_campaign.py`. Counted sampler support: `tools/benchmark-support/measured_samples.rs`.

This page specifies the repository-owned harness, registration schema, statistical populations, counted-sampling protocol, and single-lever control trees for controlled per-lever `bitcoin-rs` performance campaigns. The general evidence and promotion rules remain in [`README.md`](README.md#acceptance-rule), [`docs/contracts/hot-path-attribution.md`](../contracts/hot-path-attribution.md), [`docs/contracts/test-evidence.md`](../contracts/test-evidence.md), and [`CONCEPTS.md`](../../CONCEPTS.md). This page defines how the measured-campaign tools enforce those rules; it does not register a campaign, record measurements, or weaken any existing threshold.

Status: `planned_not_executed`, as defined in [`README.md`](README.md#status-vocabulary). Packaging the harness and passing untimed or synthetic verification does not constitute a full-suite baseline, a campaign registration, or performance acceptance.

## CLI and verification boundary

The runner and analyzer live side by side in `tools/benchmark-campaign/` with zero third-party Python dependencies (Python `>= 3.11`; `uv` runs the documented offline synthetic probe; live validation and campaign runs require a Linux x86 host exposing `/proc/cpuinfo` `model name` and `os.sched_getaffinity(0)`, plus `taskset` and `perf` with permission to count `task-clock,cycles:u,instructions:u`).

```sh
# Validate registration schema, file hashes, live CPU affinity, and CPU model (launches nothing):
python3 tools/benchmark-campaign/measured_runner.py validate --registration /abs/path/to/registration.json

# Print the canonical 496-case execution schedule after live validation (launches nothing):
python3 tools/benchmark-campaign/measured_runner.py plan --registration /abs/path/to/registration.json

# Evaluate a completed campaign directory against the frozen statistical gates (launches nothing):
python3 tools/benchmark-campaign/measured_analyze.py \
  --registration /abs/path/to/registration.json \
  --results /abs/path/to/campaign_root/results.json \
  --manifest /abs/path/to/campaign_root/manifest.json

# Run the offline hermetic synthetic probe (default sibling paths, launches no workloads):
uv run --offline --no-project --script tools/benchmark-campaign/test_measured_campaign.py
```

Only `measured_runner.py run --registration /abs/path/to/registration.json` launches benchmark child processes, and it refuses to start unless `status` is `"registered"`, `campaign_root` does not yet exist, and every static and live check passes. `--help` on any subcommand exits without reading or launching measurements.

Rust benchmark binaries in the four campaign targets also expose untimed inspection and verification flags before Criterion starts:

- `--mrp-list-counted` prints the supported counted row IDs for that binary without constructing fixtures or collecting samples (supported on `insert_fill`, `candidate`, and `sync_pipeline`). On `insert_fill` and `candidate` each output line carries the literal `mrp_counted ` prefix before the row ID; on `sync_pipeline` each output line is the bare row ID with no prefix.
- `--mrp-verify-counted` runs each converted real unit once and checks the counted-sampler stopping arithmetic boundaries (`0` durations, exact-floor stopping, and overshoot) without emitting `MRP_COUNTED_SAMPLE` lines (supported on `insert_fill`, `candidate`, and `sync_pipeline`).
- `--mrp-verify` runs the untimed fixture, residency, oracle, and identity assertions for the target's rows without emitting campaign sample records (supported on all four campaign bench binaries, including `signature_verification`). On `sync_pipeline` it also prints the `corpus` and `node_identity` pin lines that [freeze-time capture](#freeze-time-capture) copies into the registration.
- `--list` lists ordinary Criterion benchmark IDs (`sync_pipeline --list` enters Criterion benchmark registration and also executes non-campaign timed proxy preludes; those printed timings are not campaign evidence).

Untimed `--mrp-verify`, `--mrp-verify-counted`, and `--mrp-list-counted` runs, `--list` inventories (including `sync_pipeline --list`'s non-campaign timed proxy preludes), and `test_measured_campaign.py` prove harness mechanics and rejection boundaries on synthetic fixtures. None of them collect campaign samples, supply frozen build or baseline receipts, or establish a performance verdict.

## Registration

A campaign starts from one complete operator-supplied registration JSON object. Neither `measured_runner.py` nor `measured_analyze.py` generates a registration, builds a source tree, or fabricates a receipt. Every path in the registration must be an absolute path on the measurement host, and every digest must be a lowercase 64-character hexadecimal SHA-256 string.

### Static and live validation entry points

`measured_runner.py` exposes two validators over one schema:

- `validate_registration(reg, check_output_absent=True)` is the static full-schema validator. It checks every key, row, inventory map, file hash, build receipt, and baseline evidence document against the real files on disk without querying caller CPU affinity or `/proc/cpuinfo`.
- `validate_live_registration(reg, check_output_absent=True)` runs `validate_registration` and then checks the live host: `host.cpu` must belong to `os.sched_getaffinity(0)`, and the `model name` parsed from the `/proc/cpuinfo` processor block for `host.cpu` (`read_cpu_model(host.cpu)`, with no first-block or echoed-label fallback) must equal `host.cpu_model`.

The `validate`, `plan`, and `run` subcommands call `validate_live_registration` (`plan` sets `check_output_absent=False`). `measured_analyze.py` states no registration rules of its own: it first binds its own executing file (`Path(__file__).resolve()` and fresh SHA-256 bytes, uncached on every call) to `scripts.analyzer`, then verifies `scripts.runner.sha256` against the exact bytes at `scripts.runner.path` before loading `validate_registration(reg, check_output_absent=False)` (cached only under that verified digest plus file path). Instead of checking the analyzer process's own CPU affinity, the analyzer binds every recorded case's `host_before` and `host_after` (`chosen_cpu`, `chosen_cpu_model`) and `command[:3]` (`["taskset", "-c", "<cpu>"]`) to `host.cpu` and `host.cpu_model`.

### Top-level registration keys

All 16 top-level keys are required. Any missing or unrecognized key (including retired keys such as `binary_fingerprints`) fails validation.

| Key | Shape | Requirement |
|---|---|---|
| `status` | string | Must equal `"registered"`. |
| `campaign_root` | string | Absolute output directory path. Must lie outside all five `source_roots`. `validate` and `run` require the path not to exist (`check_output_absent=True`); there is no resume, retry, or overwrite mode. |
| `host` | `{"cpu": int >= 0, "cpu_model": nonempty string}` | Target CPU core and exact `/proc/cpuinfo` `model name` for that processor block. Every case runs under `taskset -c <cpu>` and records `host_before` and `host_after`. |
| `timeout_seconds` | finite number `> 0` | Fixed per-case wall timeout in seconds. |
| `scripts` | `{"runner": {"path", "sha256"}, "analyzer": {"path", "sha256"}}` | `runner.path` must resolve to the executing `measured_runner.py`; `analyzer.path` must resolve to its sibling `measured_analyze.py` in the same directory. Both file hashes must match. |
| `source_roots` | `{tree: abs_dir}` for `candidate`, `control_T1`, `control_T2`, `control_T3`, `control_T4` | Five non-overlapping existing directories containing frozen source-only trees. Any `target` or `.git` entry, resolved root path with a path component named `target`, symlinked directory, symlink leaving the root, or non-regular file is refused. |
| `source_fingerprints` | `{tree: {relpath: sha256}}` | Per tree, the exact POSIX relative-path to SHA-256 map of every regular file in `source_roots[tree]`. No omitted, extra, or mismatched file is permitted. All five full-tree `identity_digest` values must be pairwise distinct. |
| `bench_fingerprints` | `{tree: {6 relpaths: sha256}}` | Per tree, the exact six common benchmark files: `crates/mempool/benches/insert_fill.rs`, `crates/mining/benches/candidate.rs`, `crates/node/benches/sync_pipeline.rs`, `crates/script/benches/signature_verification.rs`, `tools/benchmark-support/measured_samples.rs`, and `tools/benchmark-support/snapshot_order.rs`. Each hash must match the file in `source_roots[tree]`, and the map must be identical across all five trees. |
| `lock_fingerprints` | `{tree: {5 relpaths: sha256}}` | Per tree, the exact five workspace lockfiles: `Cargo.lock`, `fuzz/Cargo.lock`, `tools/ldk/Cargo.lock`, `tools/compact-filter-interop/Cargo.lock`, and `tools/stratum-sv2/template-provider/Cargo.lock`. Each hash must match the file in `source_roots[tree]`, and the map must be identical across all five trees. |
| `binaries` | `{10 keys: {"path", "sha256", "receipt": {"path", "sha256"}}}` | The ten compiled benchmark executables and their build receipts (see below). Every binary and receipt file must exist outside all `source_roots`, be pairwise distinct files on disk, and match its pinned SHA-256. Every binary must have execute permission (`os.X_OK`). |
| `source_baseline_evidence` | nonempty list of `{"path", "sha256"}` | Pinned JSON documents certifying a passed source baseline for the exact five-tree source digests and script digests (see below). Duplicate paths are refused. |
| `dependency_baseline_evidence` | nonempty list of `{"path", "sha256"}` | Pinned JSON documents certifying a passed dependency baseline for the exact five-tree lock digests (see below). Duplicate paths are refused. |
| `corpus` | `{"prefix_blocks", "tip_height", "funded_outputs", "background", "targets", "target_spends", "total_txs_per_target"}` | Nonnegative integers pinning the `block_to_template corpus:` summary line emitted on stdout by T2 and T3 node workloads. An operator-supplied freeze-time pin captured from untimed `--mrp-verify` logs before registration (see [Freeze-time capture](#freeze-time-capture)). |
| `node_identity` | `{"block_to_template_baseline": {...}, "template_render_baseline": {...}}` | Per-sample workload identity pins for T2 and T3 (see below). An operator-supplied freeze-time pin copied verbatim from untimed `--mrp-verify` logs before registration (see [Freeze-time capture](#freeze-time-capture)). |
| `targets` | `{"T1": {...}, "T2": {...}, "T3": {...}, "T4": {...}}` | Each target object has exact keys `{"control_tree": "control_T<n>", "rows": [...]}` matching the pinned 31-row inventory in exact order. |
| `schedule` | `{"target_order": ["T1", "T2", "T3", "T4"], "blocks": [...]}` | Canonical serialized target order and per-target block list: one `{"target": "T<n>", "kind": "zero"}` block followed by three `{"target": "T<n>", "kind": "measure"}` blocks for each target. |

### Identity digests, binary keys, build receipts, and baseline evidence

`identity_digest(files)` is the lowercase SHA-256 hex digest of `json.dumps(files, sort_keys=True, separators=(",", ":"))` encoded as UTF-8. A tree's `source_digest` is `identity_digest(source_fingerprints[tree])`; its `lock_digest` is `identity_digest(lock_fingerprints[tree])`.

The ten required keys in `binaries` are `<tree>/<bench_target>`:

- `candidate/insert_fill`, `candidate/candidate`, `candidate/sync_pipeline`, `candidate/signature_verification`
- `control_T1/insert_fill`, `control_T1/candidate`
- `control_T2/sync_pipeline`
- `control_T3/sync_pipeline`
- `control_T4/sync_pipeline`, `control_T4/signature_verification`

For every gated row (`acceptance`, `primary`, `guard_keep`, `connect_guard`), all binary keys that share a `bench_target` (`candidate/<bench>` and every gated `control_T<n>/<bench>`) must have pairwise distinct `sha256` digests. A control binary whose hash equals `candidate/<bench>` or another gated control on the same bench is rejected as a zero-delta or shared build. Diagnostic rows (`signature_verification/*`) and `report_only` rows do not require distinct binary hashes when a control lever does not touch their crate; their provenance is established by build receipts.

Each `binaries[key].receipt` JSON object must contain at least these fields with exact type-strict values (additional informational fields such as command lines, toolchain strings, log paths, or isolated output roots are allowed and ignored by the schema validator):

| Receipt field | Required value |
|---|---|
| `kind` | `"rbitcoin-mrp-build-receipt"` |
| `tree` | `<tree>` prefix of `key` |
| `bench_target` | `<bench_target>` suffix of `key` |
| `source_digest` | `identity_digest(source_fingerprints[tree])` |
| `bench_source_sha256` | `bench_fingerprints[tree][BENCH_SOURCES[bench_target]]` |
| `lock_digest` | `identity_digest(lock_fingerprints[tree])` |
| `binary_sha256` | `binaries[key].sha256` |
| `source_commit` | Exact-export trees only (`candidate`): lowercase 40-hex (SHA-1) or 64-hex (SHA-256) git commit the tree was exported from. Forbidden on derived controls. |
| `base_commit` | Derived controls only (`control_T1..control_T4`): lowercase 40- or 64-hex git commit the control was derived from; must equal the candidate `source_commit`. Forbidden on `candidate`. |
| `transform` | Derived controls only: nonempty single-lever derivation string naming the neutralized lever (distinct per control tree). Forbidden on `candidate`. |

Frozen trees remain source-only with no `.git` inside any root; provenance lives in these external receipts, never in the trees. Content hashes (`source_digest`, `bench_source_sha256`, `lock_digest`, `binary_sha256`) stay authoritative: provenance never substitutes for a digest check, and a base commit never identifies transformed contents. Every `candidate/*` receipt must share one `source_commit`; every control receipt's `base_commit` must equal it, with a distinct per-tree `transform`. Never invent a commit for a modified tree or claim a base commit identifies its transformed bytes.

Each entry in `source_baseline_evidence` and `dependency_baseline_evidence` must be a JSON object with exact required fields (additional informational fields are allowed):

| Evidence field | Required value |
|---|---|
| `kind` | `"rbitcoin-mrp-baseline-evidence"` |
| `role` | `"source"` in `source_baseline_evidence`; `"dependency"` in `dependency_baseline_evidence` |
| `result` | `"passed"` |
| `frozen_identity` | For `"source"`: `{"trees": {tree: source_digest for all 5 trees}, "scripts": {"runner": scripts.runner.sha256, "analyzer": scripts.analyzer.sha256}}`. For `"dependency"`: `{"trees": {tree: lock_digest for all 5 trees}}`. |

### Node identity and corpus pins

T2 and T3 standalone node workloads emit a corpus summary line (`block_to_template corpus: prefix_blocks=<prefix_blocks> tip_height=<tip_height> funded_outputs=<funded_outputs> background=<background> targets=<targets>x<target_spends> total_txs_per_target=<total_txs_per_target>`) that must match `corpus` field for field. Their per-sample JSON lines must match `node_identity`:

| Workload key | Required `node_identity` fields |
|---|---|
| `block_to_template_baseline` | `engine`: `"native"`; `tips`: list of exactly 13 distinct lowercase 64-hex block hashes (one per sample index `0..12`, since each warmup and measured sample connects its own target block); nonnegative ints `pool_txs`, `background_txs`, `pool_at_template`, `block_txs`, `block_noncoinbase`. |
| `template_render_baseline` | `engine`: `"native"`; `tip`: one lowercase 64-hex prefix tip hash (the tip never connects); nonnegative ints `tip_height`, `pool_txs`, `background_txs`, `pool_at_template`. (Each sample also carries a nonempty per-sample `longpollid`.) |

#### Freeze-time capture

`corpus` and `node_identity` are operator-supplied freeze-time pins. The runner and analyzer never derive them. They are never taken from a campaign's own `stdout.log`, and no standalone `block_to_template_baseline` run, `template_render_baseline` run, or `--mrp-counted` run is performed before registration to obtain them.

"Freeze-time capture" means running the existing untimed `--mrp-verify` once on each frozen `candidate/sync_pipeline`, `control_T2/sync_pipeline`, and `control_T3/sync_pipeline` executable with `BITCOIN_RS_VALIDATION_ENGINE=native`. These are the three executables that run the T2 and T3 node workloads. Capture from the exact executables that the registration will list under `binaries`, after they are built and before the registration is written; the SHA-256 in each retained `.binary.sha256` file must equal the `binaries[<tree>/sync_pipeline].sha256` that the registration pins, and rebuilding or replacing an executable invalidates its retained file set. `--mrp-verify` builds the corpus and runs the untimed T2 and T3 fixture units once each. It starts no Criterion run and no sample loop, and it prints no sample record or timing measurement.

```sh
# Untimed freeze-time pin capture (launches no campaign workload); repeat for candidate, control_T2, and control_T3, one retained file set each.
# The `if` guard preserves the child exit status under `set -e` (errexit): a failing verify still writes its exit file instead of aborting the shell.
BIN='/abs/path/to/frozen/<tree>-sync_pipeline'
OUT='/abs/path/to/retained-logs/<tree>-sync_pipeline-mrp-verify'
sha256sum "$BIN" > "$OUT.binary.sha256"
if env BITCOIN_RS_VALIDATION_ENGINE=native "$BIN" --mrp-verify > "$OUT.stdout.log" 2> "$OUT.stderr.log"; then
  printf '0\n' > "$OUT.exit"
else
  printf '%s\n' "$?" > "$OUT.exit"
fi
```

Accept a retained file set only if its `.exit` file contains `0` and the final line of its `.stdout.log` file is `mrp-verify: PASS`. The `.stdout.log` file holds only the executable's stdout; the operator appends no metadata to it, and a failing run still retains its stdout, stderr, and nonzero exit status as failure evidence. An accepted stdout log contains exactly one `block_to_template corpus:` line and exactly one `mrp-verify: node_identity ` line. The `node_identity` line is printed immediately before `mrp-verify: PASS`, after every verification assertion has passed. Retain all three file sets (stdout, stderr, exit status, and binary SHA-256 per executable) with the registration.

Transcribe the pins from an accepted stdout log:

- `corpus`: copy each field of the single `block_to_template corpus:` line into the key of the same name. `targets=<targets>x<target_spends>` carries two keys: `targets` is the number before the `x` and `target_spends` is the number after it. The static validator accepts any nonnegative integers, so a swapped pair passes `validate` and is caught only when node workload output is parsed during `run`.
- `node_identity`: copy the JSON object after `mrp-verify: node_identity ` verbatim; do not retype, reorder, or edit any value. It has exactly the two workload keys and inner keys in the table above: `tips` lists the target block hashes in corpus order (one per sample index) and `engine` is the label the samples report, which must be exactly `native`. It carries no `longpollid`, duration, or `bench`/`sample`/`warmup` key.

The `block_to_template corpus:` line and the `mrp-verify: node_identity ` line must be byte-identical in the stdout logs of all three executables. The registration holds one `corpus` and one `node_identity` per workload and cannot express per-binary pins, so on any mismatch stop. Do not choose one binary's values, edit a pin by hand, or register per-binary values.

`validate` and `plan` launch nothing, so they do not compare these pins with any executable's output. A pin that disagrees with an executable is detected only when node workload output is parsed during `run`. Compare the registration's `corpus` and `node_identity` against the retained stdout logs before registering.

### How the six benchmark sample identities map to registration and records

[`README.md`](README.md#required-identities-per-sample) is binding and requires six identities per sample: Artifact, Configuration, Corpus, Durability, Toolchain, and Hardware. In a measured campaign, individual Criterion `sample.json` files and `MRP_COUNTED_SAMPLE` stdout lines carry only timing arrays (`iters`/`times` or `unit_ns`/`unit_count`/`total_ns`) and row identifiers. The table below distinguishes the subset of fields validated directly by `measured_runner.py` and `measured_analyze.py` from the additional operator-retained configuration, durability, toolchain, and hardware metadata required by [`README.md`](README.md#required-identities-per-sample). Successful registration validation alone does not certify complete performance-acceptance evidence, and implied source state or timing splits never waive or substitute for the policy-required identities:

| Identity | Fields validated by `measured_runner.py` / `measured_analyze.py` and operator-retained metadata boundary |
|---|---|
| Artifact | Validated by tools: `source_fingerprints`, `bench_fingerprints`, `lock_fingerprints`, `scripts`, `binaries[key].sha256`, `binaries[key].receipt`, and per-case `binary_sha256_before` / `binary_sha256_after` re-hashed before and after each child invocation. |
| Configuration | Validated by tools: pinned row `argv` in `targets[T<n>].rows`, runner-enforced `BITCOIN_RS_VALIDATION_ENGINE=native` in every child environment, and `node_identity[*].engine == "native"` on T2/T3 stdout. Although frozen source and build provenance (`source_fingerprints`, `lock_fingerprints`, `binaries[key].receipt`) fix the compiled tree, the runner and analyzer do not independently capture or validate runtime fields for resolved `NodeConfig`, feature set, or allocator; those remain additional operator-retained metadata required by [`README.md`](README.md#required-identities-per-sample). |
| Corpus | Validated by tools: pinned `corpus` and `node_identity` objects in registration, verified against T2/T3 stdout (`node_corpus` and per-sample `identity`), plus deterministic in-bench fixture assertions verified by `--mrp-verify` / `--mrp-verify-counted`. |
| Durability | Validated by tools: frozen source, bench, and lock digests (`source_fingerprints`, `bench_fingerprints`, `lock_fingerprints`, `binaries[key].receipt`) and presence/shape of T2's per-unit `durable_sync_us` and `durable_commit_us` arrays. Those arrays are descriptive timing splits, not durability identity fields, and source hashes alone do not record runtime backend, batch mode (`write`, `write_deferred`, `write_durable`), or flush/sync posture; those remain additional operator-retained metadata required by [`README.md`](README.md#required-identities-per-sample). |
| Toolchain | Validated by tools: `lock_fingerprints` across all five trees, `dependency_baseline_evidence`, and the required digest fields (`source_digest`, `bench_source_sha256`, `lock_digest`, `binary_sha256`) in each `binaries[key].receipt`. Exact `rustc` version, edition, profile, and enabled feature strings in receipts or campaign records are not schema-enforced by the validator and remain operator-retained metadata required by [`README.md`](README.md#required-identities-per-sample). |
| Hardware | Validated by tools: registration `host.cpu` and `host.cpu_model`, enforced via `taskset -c <cpu>` and verified against live `/proc/cpuinfo`, `os.sched_getaffinity(0)`, and `/sys/devices/system/cpu` (`cpufreq`) in per-case `host_before` and `host_after`, plus `perf` counters (`task-clock`, `cycles:u`, `instructions:u`) in the separate per-case `perf` field, with raw CSV text in `perf_csv`. System memory, storage device, and OS kernel identity are not validated by the runner or analyzer and remain operator-retained metadata required by [`README.md`](README.md#required-identities-per-sample). |

### Pinned row inventory (31 rows: 17 Criterion, 12 counted, 2 node)

Each target's `rows` list must match the table below in exact order and exact field values. Every row contains:

- `id`: full benchmark or workload ID
- `kind`: `"criterion"`, `"counted"`, or `"node"`
- `role`: `"acceptance"`, `"guard_keep"`, `"primary"`, `"connect_guard"`, `"report_only"`, or `"diagnostic"`
- `bench_target`: `"insert_fill"`, `"candidate"`, `"sync_pipeline"`, or `"signature_verification"`
- `candidate_binary`: `"candidate/<bench_target>"`
- `control_binary`: `"control_T<n>/<bench_target>"`
- `argv`:
  - Criterion (`kind == "criterion"`): `["--bench", "--noplot", "--exact", <id>]`, plus `"samples": 10` and `"units_per_iter": 1` (or `64` for the four `signature_verification/*` rows).
  - Counted (`kind == "counted"`): `["--mrp-counted", <id>]`, plus `"samples": 10` and `"units_per_iter": 1`.
  - Node (`kind == "node"`): `["--bench", <id>, "--nocapture"]`, plus `"node_bench": <id>`.

| Target | Order | Row `id` | `kind` | `role` | `bench_target` | `units_per_iter` / `node_bench` |
|---|---:|---|---|---|---|---|
| T1 | 1..5 | `mempool_insert_entry/fill/{200,800,3200,12800,51200}` | `criterion` | `acceptance` | `insert_fill` | `units_per_iter: 1` |
| T1 | 6 | `mempool_insert_entry/fill/63-member-cluster` | `counted` | `report_only` | `insert_fill` | `units_per_iter: 1` |
| T1 | 7..11 | `assemble_candidate/end_to_end/{0,64,512,2048,20000}` | `criterion` | `report_only` | `candidate` | `units_per_iter: 1` |
| T1 | 12..13 | `assemble_candidate/end_to_end/{50000,100000}` | `criterion` | `guard_keep` | `candidate` | `units_per_iter: 1` |
| T1 | 14 | `assemble_candidate/end_to_end/chains/depth-25` | `criterion` | `report_only` | `candidate` | `units_per_iter: 1` |
| T1 | 15..20 | `mining_snapshot_operation/mining_snapshot/{64,512,2048,20000,50000,100000}` | `counted` | `report_only` | `candidate` | `units_per_iter: 1` |
| T1 | 21 | `mining_snapshot_operation/mining_snapshot/chains/depth-25` | `counted` | `report_only` | `candidate` | `units_per_iter: 1` |
| T1 | 22 | `indexed_selection_read_guard/read_guard/100000` | `counted` | `report_only` | `candidate` | `units_per_iter: 1` |
| T2 | 1 | `block_to_template_baseline` | `node` | `primary` | `sync_pipeline` | `node_bench: "block_to_template_baseline"` |
| T3 | 1 | `template_render_baseline` | `node` | `primary` | `sync_pipeline` | `node_bench: "template_render_baseline"` |
| T4 | 1 | `connect_admission_throughput/flat` | `counted` | `primary` | `sync_pipeline` | `units_per_iter: 1` |
| T4 | 2 | `connect_admitted_signed_spend_block/flat` | `counted` | `connect_guard` | `sync_pipeline` | `units_per_iter: 1` |
| T4 | 3 | `connect_unseen_signed_spend_block/flat` | `counted` | `connect_guard` | `sync_pipeline` | `units_per_iter: 1` |
| T4 | 4..7 | `signature_verification/{ecdsa,schnorr}/{hit,miss}` | `criterion` | `diagnostic` | `signature_verification` | `units_per_iter: 64` |

Before freezing a registration, confirm every Criterion ID with `--list` and every counted ID with `--mrp-list-counted` on the built executables (`insert_fill` and `candidate` list each counted ID with an `mrp_counted ` prefix; `sync_pipeline` lists each counted ID bare). The three T4 connect rows use the pinned `/flat` IDs from the table above and execute as `kind: "counted"` (`--mrp-counted`) rather than Criterion. No counted row is registered a second time as a Criterion row.

### Canonical schedule, execution guarantees, and regeneration rules

- **Schedule**: Targets run serially `T1 -> T2 -> T3 -> T4`. Each target runs 4 blocks of 4 visits (`16` visits per target, `31 * 16 = 496` cases total):
  - Block `0` (`kind: "zero"`): visits `candidate, zero, zero, candidate` (`v00..v03`). Both `"candidate"` and `"zero"` arms resolve to `row["candidate_binary"]` and its pinned hash. This measures same-binary host and visit noise on the target's workload without independent-build variation; there is no separate `zero` source tree or `zero` executable in the registration.
  - Blocks `1..3` (`kind: "measure"`): visits `candidate, control, control, candidate` (`v04..v15`, three ABBA blocks). `"candidate"` runs `candidate/<bench_target>`; `"control"` runs `control_T<n>/<bench_target>`.
  - Within every visit, all rows of that target run in their pinned table order. Only one benchmark child process is alive at a time; builds and tests must never run concurrently with measurements, and no host-setting changes are made for the campaign.
- **Per-case custody**: Each case writes to a fresh directory `<campaign_root>/<target>/v<visit:02d>-<arm>/<sanitized_row>/` (`exist_ok=False`), hashes the binary before and after execution, pins `BITCOIN_RS_VALIDATION_ENGINE=native`, sets a fresh `CRITERION_HOME` for Criterion rows, and launches `taskset -c <cpu> perf stat -x, -e task-clock,cycles:u,instructions:u -o <perf.csv> -- <binary> <argv...>`.
- **No retry, resume, or overwrite**: `cmd_run` creates `campaign_root` with `exist_ok=False`, flushes `results.json` and append-only `results.jsonl` after every case, kills the child process group with `SIGKILL` on timeout or interruption, and stops immediately on the first case error or binary hash mismatch. At completion or early stop it writes `manifest.json` (SHA-256 of every regular file under `campaign_root` except the manifest files) and `manifest.sha256`. The inventory rule is the runner's `runs_inventory`, shared by the writer and the analyzer through the hash-verified runner module: a symlink (including one named `manifest.json`) or any entry that is neither a regular file nor a directory is refused, never followed or skipped. A refused inventory raises `RegistrationError` before any hashing or writing, so `seal_manifest` reports `INVALID: manifest not written` on stderr and leaves the offending path untouched; any other `OSError` while hashing or writing reports the same way but may leave a partial manifest behind. Cancel keeps `130` and a case error keeps `1` regardless of the seal result; only a seal failure after all cases complete returns `1`. A missing or unverifiable manifest fails closed to `INCONCLUSIVE` in the analyzer.
- **Fresh registration after renaming or editing scripts**: Because `scripts.runner` and `scripts.analyzer` bind the exact resolved file paths and SHA-256 digests of `measured_runner.py` and `measured_analyze.py`, and `source_baseline_evidence[*].frozen_identity.scripts` pins those same digests, renaming, moving, or editing either Python script invalidates any prior registration JSON and source-baseline evidence document. After any script path or byte change, regenerate `source_baseline_evidence` and the registration JSON with the new paths and SHA-256 digests before running `validate`, `plan`, `run`, or `measured_analyze.py`.
- **Run honesty boundary**: File hashes, build receipts, `/proc/cpuinfo` checks, and analyzer self-binding catch stale labels, accidental edits, and relocated scripts; they are not cryptographic attestation against a dishonest operator editing raw files before hashing `manifest.json`. Raw-artifact custody and build isolation remain operator responsibilities.

## Statistics

All statistical gates live in `measured_analyze.py`. Every completeness, identity, manifest, schedule, execution, hash, raw-sample, frequency, or stability failure yields `verdict: "INCONCLUSIVE"`: never a win, never a partial promotion, and never a zero-value fallback.

### Sample normalization and visit populations

Console summaries and Criterion `estimates.json` files are never read. Every visit must produce exactly `10` measured normalized per-unit latency estimates in nanoseconds:

- **Criterion rows (`kind: "criterion"`)**: The runner requires a single `new/sample.json` under the case's `CRITERION_HOME` with `len(iters) == 10` and `len(times) == 10`. Criterion 0.8.2 writes `<id>/new/sample.json` and copies `new` to `base` on its default save baseline, so the search scopes to `**/new/sample.json` with an exactly-one match; `base/sample.json` never supplies campaign samples and `--discard-baseline` is forbidden because it suppresses the required `new` output. Every raw sample interval `times[i]` (the accumulated timed interval in nanoseconds, not per-iteration latency) must be `>= 1_000_000_000.0` ns (`1` s). Normalized sample estimates are `normalized_ns[i] = times[i] / iters[i] / units_per_iter`, where `units_per_iter` is `1` (`64` for `signature_verification/*`). Criterion rows configure Flat sampling, 10 samples, 1 s warmup time, and 20 s measurement time; the configured duration never excuses a raw `times[i] < 1e9` ns.
- **Counted rows (`kind: "counted"`)**: Each of the 10 measured `MRP_COUNTED_SAMPLE` objects (`sample` indices `1..10`, `warmup: false`) supplies integer `total_ns` (`>= 1_000_000_000` ns) and `unit_count` (`== len(unit_ns) > 0`). Normalized sample estimates are exact floating-point `normalized_ns[i] = total_ns / unit_count` (`units_per_iter` is `1`).
- **Node rows (`kind: "node"`)**: T2 (`block_to_template_baseline`) and T3 (`template_render_baseline`) emit 3 warmup JSON lines (`sample` `0..2`, `warmup: true`) and 10 measured JSON lines (`sample` `3..12`, `warmup: false`) on stdout. Each arm group carries `<arm>_ns` (`unit_ns` in T2), `<arm>_count` (`unit_count` in T2), and `<arm>_total_ns` (`total_ns` in T2), with exact integer-nanosecond sum `total == sum(units)`, `count == len(units) > 0`, and `total >= 2_000_000_000` ns (`2` s) on every warmup and measured sample (no service-arm exemption; legacy `*_us` / `*_mean_*` arm keys and any `mean` field are rejected). Zero individual unit durations are legal clock quantization and are never clamped when `count > 0` and `total > 0`. The per-sample estimate for an arm is `total / count` in nanoseconds:
  - T2 primary uses `tail_to_reply` (`unit_ns`, `unit_count`, `total_ns`), accompanied by six length-matched nonnegative integer microsecond component arrays (`apply_call_to_reply_us`, `durable_sync_us`, `durable_commit_us`, `on_connect_us`, `assembly_us`, `remainder_us`) and a nonempty `boundary` string.
  - T3 runs once per visit and supplies both the `rpc_hit` primary arm and the `rpc_miss` cold-guard arm from the same 10 measured sample records (`service_hit` and `service_hit2` are diagnostic). Every T3 sample must also carry `arc_reuse: true`, positive `selected_txs` with `rpc_txs == selected_txs`, nonnegative `selected_weight` and `rpc_data_bytes`, nonnegative timestamps satisfying `hit_curtime >= cold_curtime >= mintime`, and nonempty `longpollid`, `boundary_rpc_miss`, `boundary_service_hit`, and `boundary_rpc_hit` strings.

From the 10 normalized estimates of a visit:

- The **visit estimate** (`case_median_ns`) is the median of those 10 normalized estimates, and `case_std_ns` is their sample standard deviation (`statistics.stdev`). The analyzer recomputes both from the retained raw arrays and fails closed (`INCONCLUSIVE`) if the stored scalars differ (`rel_tol = 1e-9`) or if `case_std_ns` is negative or non-finite.
- Across the 3 measurement ABBA blocks (`12` visits), each measured arm (`candidate` and `control`) has **6 visit medians** in visit order. For each arm, `M` is the median of its 6 visit medians and `S` is the sample standard deviation (`statistics.stdev`) of its 6 visit medians.
- Across block `0` (`kind: "zero"`), the 4 same-binary visits (`candidate, zero, zero, candidate`) yield **4 zero-block visit medians** `z_0..z_3`. The observed zero-block noise spread is `zero_spread = max(z) / min(z) - 1`.

### Quality and stability gates (all fail closed to `INCONCLUSIVE`)

Every row, including `report_only` and `diagnostic` rows, must pass raw-sample validation and its duration floor. The statistical verdict gates below retain their stated role scope; counted sampling creates no exemption from a gate that applies to the row.

1. **Effective CPU frequency control (`FREQ_RATIO_MAX = 1.03`)**: For every gated row (`acceptance`, `primary`, `cold`, `guard_keep`, `connect_guard`), each case's effective CPU frequency is `cycles_u / task_clock_ms` from `perf.csv`. The ratio `max(median_A, median_B) / min(median_A, median_B)` must be `<= 1.03` in the zero block (`candidate` vs `zero`), across all 12 measurement visits (`candidate` vs `control`), and within each of the three measurement ABBA blocks `1`, `2`, and `3` individually.
2. **5% stability rule (`ARM_STABILITY_BAND = 0.05`)**: Applies to the governed non-`acceptance` gated roles (`primary`, `cold`, `guard_keep`, `connect_guard`), which is every gated row **except** T1 `acceptance` rows, in both measurement and zero blocks:
   - Within every visit (measurement and zero), all 10 normalized sample estimates `x_i` must lie within 5% of that visit's median `m`: `max_i |x_i - m| / m <= 0.05`.
   - Across visits, all 6 `candidate` visit medians must lie within 5% of `M_candidate`, all 6 `control` visit medians must lie within 5% of `M_control`, and all 4 zero-block visit medians must lie within 5% of their combined median.
3. **T1 singleton acceptance noise gates (`CASE_STDDEV_RATIO_MAX = 0.20`, `ARM_SPREAD_MAX = 1.15`)**: Applies only to T1 `acceptance` rows (`mempool_insert_entry/fill/{200,800,3200,12800,51200}`), in both measurement and zero blocks:
   - Every visit must satisfy `case_std_ns / case_median_ns <= 0.20`.
   - Each arm's visit-median ratio `max / min` must be strictly `< 1.15` (`candidate`, `control`, `zero-candidate`, and `zero-zero`).
   - These `0.20` / `1.15` bounds are never substituted for the 5% stability rule on `guard_keep`, `primary`, `cold`, or `connect_guard` rows.

### Promotion, non-regression, and per-target verdict rules

All campaign metrics are latencies in nanoseconds. Latency speedup is always control over candidate, computed from retained raw samples:

```text
win_ratio = M_control / M_candidate
latency_reduction = (M_control - M_candidate) / M_control
```

A gated keep/promotion requires all quality and frequency gates to pass **and**:

1. `win_ratio = M_control / M_candidate >= 1.05`, and
2. `latency_reduction > (S_candidate + S_control) / M_control` (`above_s_bound`), and
3. `latency_reduction > zero_spread` (`above_zero_spread`).

Both observed noise bounds must be exceeded (`above_zero_noise = above_s_bound and above_zero_spread`). No outlier filtering or adaptive threshold adjustment is permitted.

Per-target evaluation in `measured_analyze.py`:

- **T1 (mempool maintained cluster order)**:
  - If any `acceptance` or `guard_keep` row has a quality failure, T1 is `INCONCLUSIVE` (`keep = null`).
  - Otherwise, if any `acceptance` row (`fill/{200,800,3200,12800,51200}`) satisfies `M_candidate - M_control > S_candidate + S_control`, T1 is `REGRESSION` (`keep = false`).
  - Otherwise, T1 is `NON_REGRESSION_EVIDENCED`, and `keep` is `true` iff **both** in-campaign `guard_keep` rows (`assemble_candidate/end_to_end/50000` and `100000`, comparing `candidate` against `control_T1`) satisfy the promotion rule (`win_ratio >= 1.05` and `above_zero_noise`). All `report_only` rows (including `fill/63-member-cluster`, smaller `assemble_candidate` sizes, `mining_snapshot/*`, and `read_guard/100000`) are reported descriptively without gating.
- **T2 (staged-tip template preparation)**:
  - Evaluates `block_to_template_baseline` (`role: "primary"`). Any quality failure yields `INCONCLUSIVE` (`keep = null`).
  - If `M_candidate - M_control > S_candidate + S_control`, T2 is `REGRESSION` (`keep = false`).
  - Otherwise, on the verified measurement `control` records, the analyzer computes each sample's mean `assembly_us * 1000.0` (explicit microsecond-to-nanosecond conversion) and mean `tail_to_reply` in nanoseconds. If `median(assembly_ns) / median(tail_ns) < 0.05` (`AT_FLOOR_MAX`), T2 returns `verdict: "AT_FLOOR"` with `keep: false` (assembly is under 5% of control tail-to-reply latency, which is not a win and does not promote the lever).
  - Otherwise, T2 returns `NON_REGRESSION_EVIDENCED` with `keep: true` iff the promotion rule holds (`win_ratio >= 1.05` and `above_zero_noise`). Per-unit component arrays (`apply_call_to_reply_us`, `durable_sync_us`, `durable_commit_us`, `on_connect_us`, `assembly_us`, `remainder_us`) are summarized descriptively with no per-component acceptance gate.
- **T3 (stored transaction hex and signalling-rule cache)**:
  - Evaluates `template_render_baseline` primary (`rpc_hit`) and cold (`rpc_miss`, extracted as `template_render_baseline:cold` from the same visit records). Any quality failure on either arm yields `INCONCLUSIVE` (`keep = null`).
  - If either `rpc_hit` or `rpc_miss` has `M_candidate - M_control > S_candidate + S_control`, T3 is `REGRESSION` (`keep = false`).
  - Otherwise, T3 is `NON_REGRESSION_EVIDENCED` with `keep: true` iff `rpc_hit` satisfies the promotion rule (`win_ratio >= 1.05` and `above_zero_noise`). `service_hit` and `service_hit2` remain diagnostic.
- **T4 (admission-local signature cache)**:
  - Evaluates `connect_admission_throughput/flat` (`role: "primary"`) and the two `connect_guard` rows (`connect_admitted_signed_spend_block/flat` and `connect_unseen_signed_spend_block/flat`). Any quality failure on the primary or either guard row yields `INCONCLUSIVE` (`keep = null`).
  - If the primary row has `M_candidate - M_control > S_candidate + S_control`, T4 is `REGRESSION` (`keep = false`).
  - For each `connect_guard` row, the median regression is `(M_candidate - M_control) / M_control` and the p99 regression is `(p99_candidate - p99_control) / p99_control`. If either guard exceeds `GUARD_MEDIAN_MAX = 0.03` (3% median regression) or `GUARD_P99_MAX = 0.05` (5% p99 regression), T4 is `REGRESSION` (`keep = false`).
  - Otherwise, T4 is `NON_REGRESSION_EVIDENCED` with `keep: true` iff the primary row satisfies the promotion rule (`win_ratio >= 1.05` and `above_zero_noise`). The four `signature_verification/{ecdsa,schnorr}/{hit,miss}` rows are reported as `diagnostic`.

Overall campaign verdict: `INCONCLUSIVE` if any target is `INCONCLUSIVE`; else `REGRESSION` if any target is `REGRESSION`; else `NON_REGRESSION_EVIDENCED` with per-target `keep` flags in `reasons`.

### Percentile populations

Every analyzer output names its percentile population explicitly:

- **Criterion and counted rows**: `pooled[arm]` (`p50`, `p95`, `p99`, `max`, `n = 60`) is computed over the 60 pooled normalized sample estimates (`times[i]/iters[i]/units_per_iter` for Criterion; `total_ns/unit_count` for counted rows) across the 6 measurement visits of that arm, using linear interpolation at index `q * (n - 1)` (`0.99 * (n - 1)` for `p99`). T4 `connect_guard` p99 uses this sample-estimate percentile, never pooled raw `unit_ns` elements and never a claim of per-operation tail latency.
- **Node rows**: `pooled[arm]` is computed over concatenated raw `unit_ns` / `<arm>_ns` integer unit durations across the 6 measurement visits of that arm and is labeled descriptive only. This analyzer population is a pooled raw-unit descriptive summary and is distinct from the node harness `print_percentiles` population, which is per-sample means (`block_to_template_baseline` in `crates/node/benches/sync_pipeline.rs` pushes one mean per non-warmup sample and calls `print_percentiles` on those means).

Every verdict JSON records `metadata.authorities` as:

- `docs/benchmarks/measured-campaign.md#registration`
- `docs/benchmarks/measured-campaign.md#statistics`
- `docs/benchmarks/measured-campaign.md#counted-samples`
- `docs/benchmarks/measured-campaign.md#control-trees`
- `docs/benchmarks/README.md:Acceptance rule`
- `docs/contracts/hot-path-attribution.md:HPA-13`

## Counted samples

Criterion sizes iterations from warmup wall time, which includes untimed per-iteration setup and teardown (`iter_batched_ref` / `iter_custom`), but records only the timed span in `sample.json`. For benchmarks whose untimed setup or teardown dominates wall time, wall-time sizing can choose an iteration count whose recorded timed sum falls below the 1-second raw-interval floor.

To enforce the 1-second measured-work floor directly without pilots, guessed repeat multipliers, retries, or threshold waivers, the 12 rows with substantial untimed setup/teardown use `kind: "counted"`:

- T1 `insert_fill`: `mempool_insert_entry/fill/63-member-cluster`
- T1 `candidate`: `mining_snapshot_operation/mining_snapshot/{64,512,2048,20000,50000,100000}`, `mining_snapshot_operation/mining_snapshot/chains/depth-25`, and `indexed_selection_read_guard/read_guard/100000`
- T4 `sync_pipeline`: `connect_admission_throughput/flat`, `connect_admitted_signed_spend_block/flat`, and `connect_unseen_signed_spend_block/flat`

All other Criterion rows (`fill/{200,800,3200,12800,51200}`, `assemble_candidate/end_to_end/*`, and `signature_verification/*`) remain `kind: "criterion"`, and T2/T3 remain `kind: "node"`.

### Shared Rust sampler contract

`tools/benchmark-support/measured_samples.rs` is a std-only Rust module included via a relative `#[path]` attribute in `crates/mempool/benches/insert_fill.rs`, `crates/mining/benches/candidate.rs`, and `crates/node/benches/sync_pipeline.rs`. It introduces no new crate or dependency and is pinned in `bench_fingerprints` across all five source trees.

- **Public module surface**:
  - `pub(crate) fn run(row: &str, mut unit: impl FnMut() -> std::time::Duration)`
  - `pub(crate) fn verify_stopping_rule()`
- **Accumulation and stopping rule**: Each invocation of `run(row, unit)` emits 1 warmup sample (`sample: 0`, `warmup: true`) followed by 10 measured samples (`sample: 1..=10`, `warmup: false`). Within each sample (warmup and measured alike), the sampler repeatedly invokes `unit()` (one complete semantic unit with setup, teardown, and identity assertions on their existing sides of the timer), converts each returned `Duration` to a `u64` nanosecond count, accumulates `total_ns` with checked addition, and stops on the **first** completed unit where `total_ns >= 1_000_000_000` ns (`1` s). Zero individual `unit_ns` entries are legal (clock quantization) and are never clamped; `unit_count` and `total_ns` must both be positive. No division or floating-point rounding occurs in Rust.
- **CLI handling before Criterion**: Each owning bench intercepts `--mrp-counted <ROW_ID>`, `--mrp-list-counted`, and `--mrp-verify-counted` before Criterion initializes. Missing, extra, or unknown row arguments to `--mrp-counted` exit nonzero immediately without entering Criterion.

### Shared snapshot-order contract

`tools/benchmark-support/snapshot_order.rs` is the deduplicated chunk-order fingerprint shared by `crates/mempool/benches/insert_fill.rs` and `crates/mining/benches/candidate.rs`, included via a relative `#[path]` attribute in both benches. It introduces no new crate or dependency and is pinned in `bench_fingerprints` across all five source trees.

- **Public module surface**:
  - `pub(crate) const FNV_OFFSET: u64`
  - `pub(crate) fn fold_u64(state: u64, value: u64) -> u64`
  - `pub(crate) fn fold_bytes(state: u64, bytes: &[u8]) -> u64`
  - `pub(crate) fn snapshot_order_fingerprint(pool: &Mempool) -> u64`
  - `pub(crate) fn assert_snapshot_topological(pool: &Mempool)`
- **Equivalence**: moving these identical bodies here preserves every emitted fingerprint, output schema, and measured operation byte for byte. The fingerprint stays a diagnostic identity signal; structural assertions carry equivalence.

### Wire format and single-validator rule

Each counted sample is printed as one line on stdout: the literal prefix `MRP_COUNTED_SAMPLE ` (including one trailing ASCII space) followed by a compact JSON object with exact keys:

```json
{"bench":"<row_id>","sample":0,"warmup":true,"unit_ns":[1000000000],"unit_count":1,"total_ns":1000000000}
```

| Field | Rule |
|---|---|
| `bench` | Must equal the registered row `id`. |
| `sample` | Integer `0..10` in strict order (`0` for the single warmup line, `1..10` for the ten measured lines). |
| `warmup` | Boolean: `true` if and only if `sample == 0`; `false` for `sample` `1..10`. Warmup data never enters measured statistics. |
| `unit_ns` | Nonempty list of nonnegative `u64` integers (`0 <= x <= 2^64 - 1`). |
| `unit_count` | Integer equal to `len(unit_ns)`. |
| `total_ns` | Integer equal to `sum(unit_ns)` (`<= 2^64 - 1`), `>= 1_000_000_000`, and satisfying the first-crossing rule `total_ns - unit_ns[-1] < 1_000_000_000` (all completed units prior to the final unit summed to strictly less than `1` s). |

Auxiliary fixture diagnostics on stdout lines that do not start with `MRP_COUNTED_SAMPLE` are ignored by the parser and retained in `stdout.log`. Any line starting with `MRP_COUNTED_SAMPLE` that lacks the single space, carries invalid JSON, omits or adds keys, names the wrong `bench`, disorders or duplicates `sample` indices, violates `unit_count == len(unit_ns)` or `total_ns == sum(unit_ns)`, falls below `1_000_000_000` ns (warmup included), or violates the first-crossing stop rule raises `RegistrationError` and fails the case with `INCONCLUSIVE`.

Counted records in `results.json` store `counted_stdout_path`, `counted_warmups_seen: 1`, `counted_warmup_samples` (the retained raw warmup JSON object), `counted_samples` (the ten retained raw measured JSON objects), and neutral numeric fields `sample_iters` (`unit_count` values), `sample_times_ns` (`total_ns` values), `normalized_ns` (`total_ns / unit_count` floats), `case_median_ns`, and `case_std_ns` (`criterion_sample_path` remains `null`; counted output is never labeled a Criterion artifact). `measured_runner.py` owns `parse_counted_stdout`, `counted_case_fields`, and the single authoritative `validate_counted_samples` function, which `measured_analyze.py` invokes through the hash-verified runner module on the retained raw objects.

## Control trees

Under [`docs/contracts/hot-path-attribution.md`](../contracts/hot-path-attribution.md) (`HPA-10`), a per-target promotion requires a single-lever control that disables or neutralizes only the optimization under test while keeping all other optimizations, consensus rules, durability guarantees, and benchmark harnesses identical. A composite control that disables all levers at once confounds T1 mempool read order with T2/T3 template assembly and T4 mempool admission, and cannot attribute a per-target keep verdict.

The registration therefore requires five frozen source-only trees (`candidate`, `control_T1`, `control_T2`, `control_T3`, `control_T4`). Every tree must carry byte-identical copies of all six `bench_fingerprints` files and all five `lock_fingerprints` files, while all five full-tree `source_fingerprints` digests must be pairwise distinct.

### Single-lever control definitions

| Tree | Target | Single lever disabled / neutralized in the control tree | What remains identical to `candidate` |
|---|---|---|---|
| `candidate` | All (`T1..T4` candidate and `zero` visits) | None: full integrated candidate source tree. | All four levers enabled; serves both sides of every target's `zero` block and the `candidate` arm of every `measure` block. |
| `control_T1` | `T1` (`insert_fill`, `candidate`) | Disables maintained cluster-order upkeep on mempool mutation and restores owned, exact from-scratch chunk/order recomputation on the read paths (`chunks_by_feerate`, `chunks_after`, `mining_snapshot`, and eviction consumers in `crates/mempool/src/{pool.rs,chunk_index.rs,eviction.rs}` plus necessary read-path consumers), without interior mutation under a read lock and without doing both maintenance and recomputation. | Public observable transaction order, chunk boundaries, eviction, snapshot, removal-plan results, T2/T3/T4 levers, and all benchmark and lock files. |
| `control_T2` | `T2` (`sync_pipeline`) | Neutralizes only the installed staged-tip preparation closure (`set_tip_staged` in `crates/node/src/state/open.rs` becomes a no-op) while keeping the hook mechanism, chainstate seam, and worker compiled. | T1 maintained order, T3 stored hex and signalling cache, T4 admission signature cache, corpus geometry (fresh state per unit at the prefix tip), and all benchmark and lock files. |
| `control_T3` | `T3` (`sync_pipeline`) | Stores empty `data_hex` in `crates/mining/src/template.rs::candidate_transactions` (so `crates/rpc/src/handlers/mining.rs::render_template_transactions` serializes consensus bytes and hex per RPC reply) and makes `signalling_cache_get` in the mining coordinator return `None` unconditionally. | T1 maintained order, T2 staged-tip hook, T4 admission signature cache, fresh state per cold-miss sample, and all benchmark and lock files. |
| `control_T4` | `T4` (`sync_pipeline`, `signature_verification`) | Removes the per-admission `SignatureCache` construction in `crates/mempool/src/gateway.rs::verify_scripts` and passes `None` to `verify_transaction` on the mempool admission path (matching the block-connect path, which already passes `None`). | T1 maintained order, T2 staged-tip hook, T3 stored hex and signalling cache, `signature_verification` bench code, and all benchmark and lock files. |

### Operator preparation and isolated builds

This repository does not ship an automated control-tree generator or build wrapper. Preparing a campaign requires the operator to:

1. Construct the five clean source-only directories (`candidate` and `control_T1..control_T4`) outside the working checkout, with no `.git` or `target` directories inside any root, and copy the exact six `bench_fingerprints` files and five `lock_fingerprints` files identically into every tree.
2. Build the ten benchmark executables with each tree isolated in its own never-before-used Cargo target directory, build directory, and `TMPDIR` (and without `RUSTC_WRAPPER` cache sharing across trees), so compiler artifacts from one tree can never populate another tree's binary.
3. Run `--mrp-verify`, `--mrp-verify-counted`, `--mrp-list-counted`, and `--list` on the built binaries to confirm untimed invariants and exact row IDs before writing receipts (`sync_pipeline --list` also executes non-campaign timed proxy preludes whose printed timings are not campaign evidence). For the three `sync_pipeline` executables, use the retained capture run in step 4.
4. Capture the `corpus` and `node_identity` pins from the frozen executables, before writing the registration: run `--mrp-verify` with `BITCOIN_RS_VALIDATION_ENGINE=native` on `candidate/sync_pipeline`, `control_T2/sync_pipeline`, and `control_T3/sync_pipeline` using the [Freeze-time capture](#freeze-time-capture) file-set procedure; this retained run satisfies step 3 for those three executables, so step 3 requires no additional `--mrp-verify` run on them. Accept only file sets whose `.exit` file contains `0` and whose `.stdout.log` file ends with a final `mrp-verify: PASS` line; require the `block_to_template corpus:` and `mrp-verify: node_identity ` lines to be byte-identical across the three stdout logs; and retain the three file sets with the registration. The field mapping is in [Freeze-time capture](#freeze-time-capture). Never take these pins from measured campaign output.
5. Record the ten `rbitcoin-mrp-build-receipt` JSON files with external source-commit provenance (`candidate/*` carry the exact `source_commit`; each `control_T<n>/*` carries `base_commit` equal to it plus a distinct nonempty `transform` naming its single lever; content hashes stay authoritative), the passed `source_baseline_evidence` and `dependency_baseline_evidence` JSON files, and the registration JSON with `corpus` and `node_identity` transcribed from the step 4 stdout logs, then verify the package with `measured_runner.py validate --registration <path>` and `measured_runner.py plan --registration <path>`.
