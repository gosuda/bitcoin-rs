# Product-cell comparator lanes: fixture stability and live-arm capability (#650)

Residual-leg record for the comparator lanes the hot-path ledger names as
`residual_blocker`: #34 offline full validation, #35 P2P loopback, #41
MuHash RPC. Worktree `.outline/worktree/i650-comparators`, branch
`bench/comparators-650`, tree
`c97d1094f1564fa2e694b6d3b3734dc37e6d33ca`
(`origin/main`). Owner: `docs/contracts/hot-path-attribution.md`
(`HPA-01`..`HPA-13`). Nothing here fills a product cell, changes any
residual, or produces a noise floor under `HPA-03`; every ledger cell
stays empty and every numeric gate field stays UNMEASURED (`CL-23`).

## What ran: harness stability, three alternating repetitions

`tools/benchmark-campaign/comp_lanes.py`, the existing deterministic
fixture harness for #34/#35/#41, was run three times from the worktree
into separate, retained workspaces. The original set of three runs
executed from the root checkout (`/home/alpha/blockchain/btcrs`) was
discarded after a cwd-provenance review; the recorded set below is the
worktree set.

- Pinning: `numactl --physcpubind=0-7 --membind=0`, binding the harness
  and every child to NUMA node 0 physical cores 0–7 with local memory.
- Governor: `powersave`, **not** changed; no frequency isolation; shared
  CI-class host.
- Timestamps and 1/5/15-minute load at the start of each run:
  - pin1: 2026-09-13T02:00:07Z, load 5.13 / 6.32 / 7.34
  - pin2: 2026-09-13T02:00:16Z, load 6.33 / 6.55 / 7.40
  - pin3: 2026-09-13T02:00:27Z, load 6.22 / 6.52 / 7.38
- Host identity: `alpha-Precision-7920-Tower`, Intel Xeon Gold 6138
  2.00 GHz, 80 logical CPUs, 2 NUMA nodes; kernel Linux
  7.0.0-31-generic; 754 GiB RAM.
- Raw artifacts (lane report + `offline-result.json` + `p2p-result.json`
  with 14 arms per lane, config/manifest/fixture binary pins) retained at
  `/home/alpha/.omp/wt/i650c-comparators-runs-wt/pin{1,2,3}/`.

Every lane passed every correctness gate in all three runs (offline:
alternation, archive, arm count, durability, full validation, indexes
off, reopen, state equal; p2p: bytes, peer parameters, protocol, restart
state, schedule, state equal). #41 was reported `reachable` from
`shutil.which('bitcoind')` on the staged Core 31.1 oracle.

Observed within-run harness spread: nearest-rank p50 over the seven arm
walls of each role, with `max − min` as a percentage of the p50.

| Run | #34 core p50 (ns) | #34 core spread | #34 cand p50 (ns) | #34 cand spread | #35 core p50 (ns) | #35 core spread | #35 cand p50 (ns) | #35 cand spread |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| pin1 | 118,705,357 | 0.27% | 118,602,689 | 21.02% | 132,489,440 | 10.63% | 132,225,025 | 8.01% |
| pin2 | 118,396,164 | 13.98% | 109,858,329 | 14.82% | 132,763,448 | 8.41% | 132,186,577 | 3.27% |
| pin3 | 118,615,307 | 21.02% | 118,604,241 | 20.69% | 134,860,717 | 15.65% | 136,323,145 | 18.68% |

Across-run medians of the per-run p50s: #34 core 118,615,307 (range
0.26%); #34 candidate 118,602,689 (range 7.37%); #35 core 132,763,448
(range 1.79%); #35 candidate 132,225,025 (range 3.13%).

The within-run 7-arm spread frequently exceeds the 5% product-stability
band and two of the three runs exceed it for at least one role. This is
expected for a harness whose arms are ~0.11–0.13 s fixture process
spawns: the wall is dominated by scheduler placement, child subreaper
sweeps, and Python GC/startup jitter on a shared 80-CPU host, not by the
comparator's own per-pair work. It is **not** the `HPA-03` noise floor
of any product cell (`HPA-03` = `max(B1..B7) − min(B1..B7)` over seven
valid bitcoin-rs walls of a real corpus cell), and it is **not** a
product candidate/control comparison: both arms of each fixture pair are
the same program (p2p writes `core-node.py` and `candidate-node.py` from
one `_node_source`, `comp_lanes.py:142-144`; offline calls the same
fixture program for both roles), so a fixture ratio near 1.0 is a
plumbing check, not a product result (`HPA-09`). The `CL-19` stability
predicate (each arm within 5% of its own median, improvement exceeding
host noise) remains unexercised: no candidate/control product pair was
measured.

The 5%-stability failure of the harness itself is a useful negative
result: the host and fixture are too noisy to trust an unpinned,
short-arm measurement as a product cell floor, and a real C150/Cmodern
campaign would need pinned, isolated hardware and far longer arms to keep
within the `HPA-03` band.

## Why the live product-cell arms did not run

The #34 offline lane requires bitcoin-rs to apply a Core-framed archive
at `assume_valid_height 0` to the manifest stop height, then persist
bodies, undo, and the production checkpoint, and exit. The #41 lane
requires a bitcoin-rs node whose committed UTXO set at height 150,000
answers `gettxoutsetinfo` with the CORP-05 oracle values. The #35 P2P
lane requires a live loopback IBD between real Core 31.1 and bitcoin-rs
nodes. None of these can be started from the current tree:

- `bin/bitcoin-rs/src/cli.rs` (full CLI surface, lines 13–124) exposes
  no corpus, manifest, archive, blocks-dir, or stop-at-height flag; the
  binary routes only to `run` (P2P-driven node) and `measure_storage`
  (`bin/bitcoin-rs/src/main.rs:91-99`). `run()` is a signal wrapper
  around `lifecycle::startup::start_node`
  (`crates/node/src/run.rs:31-38`); there is no mainnet offline-replay
  entry and no way to halt at C150 or Cmodern height.
- `crates/node/src/import.rs:1-46` is an explicit "skeleton":
  `import_block` decodes one block and "synthetically" applies it; it is
  not wired to any archive source or CLI path.
- `gettxoutsetinfo` is implemented and can answer `muhash` for the
  current in-memory UTXO view
  (`crates/rpc/src/handlers/chain.rs:1027-1056`), but it refuses
  specific-height queries (`:1053-1056`) and there is no shipped offline
  path to place the node at the frozen tip with certified state.
- The P2P lane's product form (live loopback IBD between real nodes) is
  not shipped: `tools/benchmark-campaign/p2p_loopback.py` is a fixture
  harness with a scripted peer, and the historical `mainnet_prefix_replay`
  tool used for the June 150k processing-bound comparison was retired
  (`docs/solutions/best-practices/small-window-benchmarks-do-not-predict-at-scale-throughput.md`).
  A real `bitcoin-rs --connect <Core>` loopback IBD is possible in
  principle but has no stop-at-height, so it cannot stop exactly at
  C150/Cmodern tip, and the comparator also requires RPC-ready within
  `ARM_READY_TIMEOUT_NS = 10 s` (`tools/benchmark-campaign/muhash_rpc.py:48`),
  which requires pre-constructed state that the missing ingest path
  cannot supply.

Consequently no Core-vs-bitcoin-rs campaign was attempted: the candidate
arm cannot be placed at the frozen tip, and running the Core side alone
would produce the one-arm, no-counterpart evidence the contract refuses
(`CL-23`). This is a **capability/harness blocker, not a custody blocker**
(#34 and #35), and a **state-construction budget blocker, not an RPC
absence** (#41: the RPC is implemented; the state is constructible only
via a long IBD for which no stop-at-height or shipped harness exists).

## Staged custody (available, hash-pinned, unmeasured against)

Corpora and the Core oracle for the future live campaigns are staged
under `.outline/reference-corpus/reacquire-20260909T010602Z-a721110f/`
(verified by re-hash this session):

- `corpora/C150.archive.bin`, 602 MiB, file sha256
  `e47d6d7632005214e8ce255c64ac6be96fdb5a9de0868d79d3d4222a3967d60f`;
  `corpora/C150.manifest.json`, file sha256
  `64bc8156aafa23d68fe507c81a38f998df8c8e2bab0309727fc2e39f96a73b38`,
  logical `manifest_sha256` (in-document)
  `5eff01d897b6f3b39039d1ff7b9b4b0872a7a15463fa516b4cc7bfe7c001b91d`,
  150,001 entries, stop hash
  `0000000000000a3290f20e75860d505ce0e948a1d1d846bec7e39015d242884b`,
  genesis
  `000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f`
  (matches CORP-01/CORP-05 pins).
- `corpora/Cmodern.archive.bin`, 324 GiB; the acquisition record
  `corpora/acquisition-record.json` reports phase D-offline-Cmodern
  exported it. The file digest was not re-verified this session
  (re-hashing 324 GiB was not spent on an unmeasured leg).
- `tools/bitcoind`, Bitcoin Core 31.1 oracle, sha256
  `986e63b3c8770f08d0059820ad3dd085d1ab9e1bea23946c243f858a06888a08`,
  matching `scripts/install-bitcoind.sh` pin and the acquisition record.
  The `comp_lanes` reachability probe reports `reachable` with this
  path; that is "PATH-visible pinned oracle", not comparator custody.

The staged custody means the residual blocker is no longer "corpus
unavailable"; the remaining block is the missing candidate-arm state
construction and the unrun seven-pair product campaign.

## What remains residual, honestly

- All 36 product cells: `residual = "unmeasured"`, `custody = "none"`,
  `noise_floor = "unobserved"` (`HPA-03`, `HPA-08`; `cell_defaults` in
  `docs/benchmarks/hot-path-ledger.toml` is unchanged and gate-pinned by
  `bin/bitcoin-rs/tests/gates/g18_hot_path_ledger.rs`).
- The updated residual blocker names the real remaining block: the live
  product-cell campaign cannot start because bitcoin-rs has no offline
  archive ingest, no stop-at-height, and no shipped live-IBD product
  lane; corpora and the Core 31.1 oracle are staged and hash-pinned.
- `CL-19` predicates (≥3 alternating runs, ≥1.05x median, 5% arm
  stability, improvement exceeding host noise) remain UNMEASURED for
  every product cell. The fixture figures above are a harness-repeatability
  observation only; many within-run spreads exceed the 5% band, which
  confirms the shared host is unsuitable as a product cell floor.
- Per `CL-23`: unverified is not supported; unknown is not false. The
  three pinned repetitions, the reachability probe, the staged-custody
  digests, and the capability audit are the complete measured record of
  this leg.
