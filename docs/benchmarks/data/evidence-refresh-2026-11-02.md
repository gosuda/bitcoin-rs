# Evidence refresh at `0c0975652` (2026-11-02)

Owner: [`docs/benchmarks/README.md`](../README.md) identity, acceptance and
status rules. This page records one evidence-refresh attempt on the integrated
head `0c0975652a637b7d6cc1aabd44adee06b0bb7e06` (local branch
`repair/invariants-and-formal-campaign`, unpushed; the remote head stays at
`74e9a8c2`). It records what ran, what is `BLOCKED` with the named missing
identity, and one gated C150 offline campaign that put the first seven
samples into the `offline.c150.x86_64.fjall` ledger cell without an
acceptance verdict.

## Host and storage identity

| Item | Value |
|---|---|
| Host | Intel(R) Xeon(R) Gold 6138 CPU @ 2.00GHz, 80 logical CPUs, Linux 7.0.0-42-generic |
| Memory | 754 GiB total |
| Bench storage | ZFS dataset `rpool/USERDATA/home_eq3uuw` mounted at `/home`, `compression=lz4` |
| Run records | `.outline/evidence/evidence-refresh-20261102/records/` (operator records, published result copies, verified tooling runs) |
| Campaign state | `/home/alpha/.omp/evidence-refresh-20261102/out/` (comparator custody copies and the 14 arm datadirs, removed on teardown) |
| Toolchain | stable pin from `rust-toolchain.toml`, `cargo --locked --offline`, `RUSTC_WRAPPER` unset |
| Candidate binary | sha256 `dd3997aa544a7669a40281222c0321351e843135d2c1f3862fb3b337c703dcf5` (`cargo build --release -p bitcoin-rs --no-default-features --features fjall`) |

The sandbox denies writes under `/home` except the repository tree and the
operator runtime directory `/home/alpha/.omp`; `/tmp` is tmpfs and cannot
host a durable state directory. The git worktree stays at
`/tmp/worktree_EvidenceRefresh`; preparation states used the repository
`.outline/evidence/` scratch on the same ZFS dataset the storage-footprint
page records, and the campaign arms ran under `/home/alpha/.omp` on that
dataset. `require_disk_backed_temp_dir` passes with `TMPDIR` under either
ZFS root.

## Load gate

A stray stress script held the host at 1-minute load about 250 for hours; it
was killed during this refresh. The load watch then recorded:

| Time (UTC) | 1-minute load | Note |
|---|---:|---|
| 09:03 | 252.56 | before the stress processes were killed |
| 09:13 | 45.48 | decay |
| 09:27 | 13.94 | residual builds finishing |
| 09:30 | 3.12 | campaign quiet-start |

Timed work started only after the 1-minute load fell below 8. Every number in
this page is either a gated run, a content fact, or is marked `Observed once,
not evidence`.

## Verified tier

All seven benchmark-campaign test suites pass under `umask 0002` and
`umask 022`, each file separately: `test_evidence`, `test_filesystem`,
`test_measured_campaign`, `test_muhash_rpc`, `test_offline_full_validation`,
`test_operator_identity`, `test_p2p_loopback`. Exit 0 in all 14 runs.

`scripts/check_book_links.py docs/book` reports no problems.

The CI `bench-smoke` compile set compiles clean from this head with
`cargo bench --locked --offline --no-run --profile quickstart`:

| Gate | Target |
|---|---|
| A | `-p bitcoin-rs`, features `rocksdb,fjall,redb,kernel` |
| B | `-p bitcoin-rs-utxo` |
| C | `-p bitcoin-rs-node --features fjall --bench chainstate_journal` |
| D | `cargo test -p bitcoin-rs-node --features fjall --bench evidence` |
| E | `-p bitcoin-rs-consensus --bench merkle` |
| F | `-p bitcoin-rs-utxo --features fjall --bench utxo_commit` |
| G | `-p bitcoin-rs-mining --bench candidate` |
| H | `-p bitcoin-rs-node --features fjall --bench sync_pipeline` |

Gate A needs `libclang` at build time for the RocksDB bindings; this host has
no `libclang.so.13` and the run supplied a symlink shim to `libclang-23` in a
private directory through `LD_LIBRARY_PATH`. The kernel C++ build compiles
with the system GCC.

Counted-row inventories match the frozen 31-row inventory:

| Binary | Result |
|---|---|
| `insert_fill --mrp-list-counted` | `mrp_counted mempool_insert_entry/fill/63-member-cluster`, exit 0 |
| `candidate --mrp-list-counted` | 8 rows: 5 `mining_snapshot_operation/mining_snapshot/{64,512,2048,20000,50000,100000}`, `chains/depth-25`, `indexed_selection_read_guard/read_guard/100000`, exit 0 |
| `sync_pipeline --mrp-list-counted` | 3 bare T4 rows `connect_admission_throughput/flat`, `connect_admitted_signed_spend_block/flat`, `connect_unseen_signed_spend_block/flat`, exit 0 |
| `signature_verification --list --noplot` | 4 rows `{ecdsa,schnorr}/{hit,miss}`, exit 0 |

One harness mechanics failure. `BITCOIN_RS_VALIDATION_ENGINE=native
sync_pipeline --mrp-verify` fails on this head:

```text
target connect failed: connect did not produce a committed outcome:
consensus: sigop cost 160088 exceeds max 80000
crates/node/benches/sync_pipeline.rs:2896
```

The fixture corpus line prints (`prefix_blocks=133 tip_height=132`), then the
T4 connect fixture refuses its own block. CI compiles this bench and never
runs it, so the failure is invisible to the compile gate. The retained failure
set (stdout, stderr, exit status, binary sha256) sits beside this page under
`.outline/evidence/evidence-refresh-20261102/records/mrp-verify/sync_pipeline/`.

## Full-validation parity at the frozen C150 tip (content facts, not a timed cell)

Two independent certified-state productions at height 150,000 agree on all
six content fields of `CORP-05`:

| Field | Core 31.1 | bitcoin-rs |
|---|---|---|
| height | 150,000 | 150,000 |
| bestblock | `0000000000000a3290f20e75860d505ce0e948a1d1d846bec7e39015d242884b` | same |
| txouts | 1,127,181 | 1,127,181 |
| total_amount_sat | 749,989,998,999,999 | 749,989,998,999,999 |
| muhash | `383a0b41ac28ddf6ac91723b41527fa64c0b54451cee5f2c4b3823ef92117116` | same |
| `utxo_hash_serialized_3` | `c9c0a3928001d21a20cff79ba4163b4f0d4b4b637f10da6313bc9d310680436a` | same |

`bodies_available` and `disconnect_ready` are true on both sides. The Core
state came from a `-loadblock` run of the staged C150 archive at
`assumevalid=0`; the bitcoin-rs state came from `offline_import.rs` at
`--assume-valid-height 0`. Both documents are retained under the run root.
The bitcoin-rs import took 11m49s wall while the 1-minute load sat between 27
and 34 with sibling builds in the 5-minute average; `Observed once, not
evidence` for the duration, and the parity fields above are content facts,
not timings. The operator identity bundle for the candidate binary is
`out/operator-identity-offline-import.json`.

## End-to-end offline campaign, C150, fjall (gated result, no acceptance verdict)

The first live comparator campaign ran on this head. Output:
`/home/alpha/.omp/evidence-refresh-20261102/out/offline-c150-fjall-result.json`
(`offline-full-validation-result-v1`, `result_sha256`
`ea355abdab58a7333c252846120e73fefa6dc3cd19987ad28179174c00abf067`), copied to
`records/published/offline-c150-fjall-result.json`. The Core arm binary is the
wrapper script `records/core-arm.py` (sha256
`f3ebaff59e9e947236ae6184505d41cbf654d05290fa5de4216fd81541d35cf8`) driving
the staged Core 31.1 `bitcoind` (sha256
`986e63b3c8770f08d0059820ad3dd085d1ab9e1bea23946c243f858a06888a08`); the
candidate arm is the release node binary (sha256
`dd3997aa544a7669a40281222c0321351e843135d2c1f3862fb3b337c703dcf5`). Campaign
window: 02:20:54Z to 04:11:45Z (1h50m51s), started at 1-minute load 3.48,
ended at 10.97 where the load is the campaign itself.

| Arm | wall p50 | wall p95 = p99 = max | CPU per arm | peak RSS per arm |
|---|---:|---:|---:|---:|
| Core `v31.1` | 109.504 s | 117.346 s | not attributed | not attributed |
| bitcoin-rs, fjall | 824.676 s | 881.600 s | 4754 to 4915 s | 0.60 to 0.72 GiB |

`candidate_over_core_p50_ratio` = 7.531. All comparator gates passed (arm
count, alternation, custody digests, exit 0 on all 14 arms, full validation,
indexes off, equal certified state). Wall spread is 11.71 percent for the
candidate arms and 12.57 percent for the Core arms, above the 5 percent
stability band of [`README.md`](../README.md#acceptance-rule), so the result
carries no acceptance verdict and no promotion. Per-sample intervals in the
ledger are anchored at zero and record the wall span of each arm; the
comparator enforces chronological arm order. The Core arm runs through the
wrapper, so its per-arm CPU and RSS fields measure the wrapper process and
attribute no Core resource cost; its wall still spans spawn to clean exit.

The ledger cell `offline.c150.x86_64.fjall` took its first seven samples
(the seven bitcoin-rs walls). First failure attempt: the same campaign ran
to completion against the repo scratch and then `publish_result` refused
the output ancestor (`output ancestor must not allow untrusted renames`)
because the repo tree is group-writable; the transient arms were cleaned up
with that refusal and no number from it survives. The rerun published under
`/home/alpha/.omp/evidence-refresh-20261102/out/` after
`chmod 0750 /home/alpha/.omp` (recorded in `records/mode-changes.log`,
restored on teardown).

## Blocked and unmeasured cells after this refresh

| Cell group | State | Missing identity |
|---|---|---|
| `offline.c150.x86_64.fjall` | measured 2026-11-02, gated result, no acceptance verdict | Result and identity bundle under `records/published/`; see the campaign section above |
| All 6 `cmodern` cells per domain | `BLOCKED` | Cmodern archive and manifest are gone; digests in `cell_defaults.residual_blocker` |
| All `arm64` cells | `BLOCKED` | No ARM64 measurement host |
| `muhash.c150.x86_64.fjall` | `BLOCKED` | The comparator hands `{rpc_bind}` and `{rpc_port}` as two argv tokens; the node accepts only `--rpc-bind <SocketAddr>` and rejects a bare IP (`invalid socket address syntax`), so the bitcoin-rs arm cannot listen on the comparator-allocated port. Verified on this head with the release binary; no code change was made in this refresh. |
| `muhash.c150.x86_64.{rocksdb,redb}` | `BLOCKED` | Same gap, plus those backends were not built |
| `offline.c150.x86_64.{rocksdb,redb}` | `BLOCKED` | Campaign not attempted for these backends; the fjall campaign owns this window |
| `p2p.*` product cells | `BLOCKED` | Live IBD has no stop-at-height flag and no shipped product lane (`#35`) |
| Measured-campaign rows (31) | `UNMEASURED` | No five-tree registration exists and the control trees are not built; T2/T3/T4 fixture units additionally fail at the sigop-cost check above |
| Criterion diagnostic benches | `UNMEASURED` | No quiet-host window was spent on non-gated diagnostic samples |

## What this refresh changes in the registers

The ledger keeps all 36 cells; `offline.c150.x86_64.fjall` took its first
seven samples and `cell_defaults` records the dated campaign and blocker
sentences. Claim pages keep their other `planned_not_executed` and
`BLOCKED` states. The retired historical C150 row on the end-to-end page was
removed because the gated replacement now exists. This page adds no
unlabeled number.
